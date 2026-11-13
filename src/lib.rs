pub mod creation_rules;
pub mod discover;
pub mod report;
pub mod sops_meta;
pub mod unmanaged;

use report::{Check, Finding, Severity};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Scan every YAML file under `roots` and return all findings, sorted for
/// deterministic output (by file, then key path, then message).
///
/// `config_override` forces a specific `.sops.yaml`; otherwise every
/// `.sops.yaml`/`.sops.yml` found under each root's enclosing git repo (or
/// under the root itself, if it isn't in a git repo) is a candidate for
/// every file -- see `discover::find_config_search_root` and
/// `find_all_sops_configs` for why that's wider than just the scanned
/// paths themselves.
pub fn check(roots: &[impl AsRef<Path>], config_override: Option<&Path>) -> Vec<Finding> {
    let mut findings = Vec::new();
    let configs = load_configs(roots, config_override);

    for root in roots {
        let root = root.as_ref();
        for path in discover::find_yaml_files(root) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue; // not UTF-8 text; out of scope for a YAML linter
            };

            // Coverage depends only on the file's path, not on which
            // document inside it we're looking at -- check it once per
            // file, not once per document, so a multi-document file
            // doesn't get the same warning twice.
            let mut needs_coverage_check = false;

            // A plain `serde_yaml::from_str::<Value>` errors outright on a
            // `---`-separated multi-document stream, which is routine for
            // Kubernetes manifests -- silently skipping the whole file on
            // that error would mean a second or third document's plaintext
            // secret sails through unchecked. Iterating documents handles
            // both the single- and multi-document case uniformly.
            for (doc_index, doc) in serde_yaml::Deserializer::from_str(&text).enumerate() {
                let Ok(doc) = serde_yaml::Value::deserialize(doc) else {
                    if looks_secret_named(&path) {
                        findings.push(Finding {
                            file: path.clone(),
                            severity: Severity::Warning,
                            check: Check::NoCreationRule,
                            key_path: None,
                            message: format!(
                                "document {doc_index} couldn't be parsed as YAML, so it wasn't checked \
                                 (filename suggests this should be a secret)"
                            ),
                        });
                    }
                    continue;
                };

                let doc_path = |p: String| {
                    if doc_index == 0 {
                        p
                    } else {
                        format!("doc[{doc_index}].{p}")
                    }
                };

                if let Some(meta) = sops_meta::SopsMeta::from_doc(&doc) {
                    needs_coverage_check = true;
                    for escape in sops_meta::find_escapes(&doc, &meta) {
                        let key_path = doc_path(escape.path.clone());
                        findings.push(Finding {
                            file: path.clone(),
                            severity: Severity::Error,
                            check: Check::EscapedEncryption,
                            key_path: Some(key_path.clone()),
                            message: format!(
                                "{key_path} is plaintext, but SOPS's own metadata says this file encrypts it"
                            ),
                        });
                    }
                } else if unmanaged::looks_secret_like(&path, &doc) {
                    needs_coverage_check = true;
                    for leak in unmanaged::find_plaintext_leaks(&doc) {
                        let key_path = doc_path(leak.path.clone());
                        findings.push(Finding {
                            file: path.clone(),
                            severity: Severity::Error,
                            check: Check::NeverEncrypted,
                            key_path: Some(key_path.clone()),
                            message: format!(
                                "{key_path} is a plaintext secret in a file with no `sops:` block at all"
                            ),
                        });
                    }
                }
            }

            if needs_coverage_check {
                check_coverage(&path, &configs, &mut findings);
            }
        }
    }

    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.key_path.cmp(&b.key_path))
            .then_with(|| a.message.cmp(&b.message))
    });
    findings
}

/// Filename-only heuristic (no parsed content available yet, since parsing
/// is exactly what failed) for whether a parse failure is worth surfacing.
/// Deliberately narrow: plenty of ordinary `.yaml` files in a GitOps repo
/// are actually Helm templates with Go template syntax (`{{ .Values.x }}`),
/// which isn't valid YAML either, and warning on every one of those would
/// drown out the signal. A file literally named like a secret failing to
/// parse is a much higher-confidence thing to flag.
fn looks_secret_named(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().contains("secret"))
}

/// One `.sops.yaml`'s rules, paired with the directory `path_regex` in it is
/// relative to (that file's own directory, matching real SOPS semantics).
struct Config {
    path: PathBuf,
    dir: PathBuf,
    rules: Vec<creation_rules::CreationRule>,
}

fn load_configs(roots: &[impl AsRef<Path>], config_override: Option<&Path>) -> Vec<Config> {
    let config_paths: Vec<PathBuf> = match config_override {
        Some(p) => vec![p.to_path_buf()],
        None => {
            let mut search_roots: Vec<PathBuf> = roots
                .iter()
                .map(|r| discover::find_config_search_root(r.as_ref()))
                .collect();
            search_roots.sort();
            search_roots.dedup();

            let mut paths: Vec<PathBuf> = search_roots
                .iter()
                .flat_map(|root| discover::find_all_sops_configs(root))
                .collect();
            paths.sort();
            paths.dedup();
            paths
        }
    };

    config_paths
        .into_iter()
        .filter_map(|path| {
            let rules = creation_rules::load(&path).ok()?;
            let dir = path.parent()?;
            // Canonicalize so this is always comparable against the scanned
            // file's own canonicalized path in `check_coverage`, regardless
            // of whether this came from a relative scan root, an absolute
            // `find_config_search_root` result, or a relative `--config`.
            let dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
            Some(Config { path, dir, rules })
        })
        .collect()
}

fn check_coverage(path: &Path, configs: &[Config], findings: &mut Vec<Finding>) {
    if configs.is_empty() {
        findings.push(Finding {
            file: path.to_path_buf(),
            severity: Severity::Warning,
            check: Check::NoCreationRule,
            key_path: None,
            message: "no .sops.yaml found anywhere in this file's repo; nothing would encrypt \
                      it today"
                .to_string(),
        });
        return;
    }

    // Canonicalize before diffing: `config.dir` is always canonical (see
    // `load_configs`), and a plain `strip_prefix` would fail whenever the
    // file isn't literally inside it -- but real SOPS (and `--config`
    // pointed at a sibling tree, which this repo's own docs do on purpose)
    // computes a true relative path, `../`s included, and matches that.
    let canonical_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let covered = configs.iter().any(|config| {
        pathdiff::diff_paths(&canonical_path, &config.dir)
            .is_some_and(|rel| creation_rules::is_covered(&config.rules, &rel.to_string_lossy()))
    });

    if !covered {
        findings.push(Finding {
            file: path.to_path_buf(),
            severity: Severity::Warning,
            check: Check::NoCreationRule,
            key_path: None,
            message: format!(
                "no creation_rule in any of {} matches this path; re-encrypting today would \
                 leave it in plaintext",
                configs
                    .iter()
                    .map(|c| c.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }
}
