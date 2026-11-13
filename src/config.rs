use crate::creation_rules;
use crate::discover;
use crate::report::{Check, Finding, Severity};
use std::path::{Path, PathBuf};

/// One `.sops.yaml`'s rules, paired with the directory `path_regex` in it is
/// relative to (that file's own directory, matching real SOPS semantics).
pub struct Config {
    path: PathBuf,
    dir: PathBuf,
    rules: Vec<creation_rules::CreationRule>,
}

/// Loads every candidate `.sops.yaml`/`.sops.yml` for `roots` (or just
/// `config_override`, if given). Returns the configs that loaded
/// successfully, plus a finding for each one that didn't -- a config that
/// fails to load isn't silently treated as "no config exists"; coverage
/// results built from an incomplete config set are worth flagging on their
/// own.
pub fn load_configs(
    roots: &[impl AsRef<Path>],
    config_override: Option<&Path>,
) -> (Vec<Config>, Vec<Finding>) {
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

    let mut configs = Vec::new();
    let mut findings = Vec::new();

    for path in config_paths {
        // Canonicalize the config file itself *before* taking its parent,
        // not after: `Path::new(".sops.yaml").parent()` is `Some("")`, and
        // `""` isn't treated as "current directory" by `canonicalize` or
        // `pathdiff` -- it silently broke coverage for a bare relative
        // `--config .sops.yaml`. Canonicalizing first means `dir` always
        // comes from an absolute path, which never has an empty parent.
        let canonical = match std::fs::canonicalize(&path) {
            Ok(c) => c,
            Err(e) => {
                findings.push(config_load_error(
                    path,
                    format!("couldn't read this .sops.yaml: {e}"),
                ));
                continue;
            }
        };
        let rules = match creation_rules::load(&canonical) {
            Ok(r) => r,
            Err(e) => {
                findings.push(config_load_error(
                    path,
                    format!("couldn't parse this .sops.yaml: {e}"),
                ));
                continue;
            }
        };
        // `canonical` is an absolute path to a file, so it always has a
        // parent in practice; the `else` arm exists only to satisfy the
        // type checker for the theoretical root-as-config-file case.
        let Some(dir) = canonical.parent() else {
            continue;
        };
        configs.push(Config {
            path,
            dir: dir.to_path_buf(),
            rules,
        });
    }

    (configs, findings)
}

fn config_load_error(path: PathBuf, message: String) -> Finding {
    Finding {
        file: path,
        severity: Severity::Error,
        check: Check::ConfigLoadError,
        doc_index: None,
        key_path: None,
        key_path_segments: None,
        message,
    }
}

/// Checks whether `path` is covered by some creation rule in `configs`,
/// pushing a warning finding onto `findings` if not (or if there were no
/// configs to check against at all).
pub fn check_coverage(path: &Path, configs: &[Config], findings: &mut Vec<Finding>) {
    if configs.is_empty() {
        findings.push(Finding {
            file: path.to_path_buf(),
            severity: Severity::Warning,
            check: Check::NoCreationRule,
            doc_index: None,
            key_path: None,
            key_path_segments: None,
            message: "no .sops.yaml found anywhere in this file's repo; nothing would encrypt \
                      it today"
                .to_string(),
        });
        return;
    }

    // Canonicalize before diffing: `config.dir` is always canonical (see
    // above), and a plain `strip_prefix` would fail whenever the file
    // isn't literally inside it -- but real SOPS (and `--config` pointed
    // at a sibling tree, which this repo's own docs do on purpose)
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
            doc_index: None,
            key_path: None,
            key_path_segments: None,
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
