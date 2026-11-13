pub mod creation_rules;
pub mod discover;
pub mod report;
pub mod sops_meta;
pub mod unmanaged;

use report::{Check, Finding, Severity};
use std::path::Path;

/// Scan every YAML file under `roots` and return all findings.
///
/// `config_override` forces a specific `.sops.yaml`; otherwise every
/// `.sops.yaml`/`.sops.yml` found under `roots` is a candidate for every
/// file (see `discover::find_all_sops_configs` for why).
pub fn check(roots: &[impl AsRef<Path>], config_override: Option<&Path>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for root in roots {
        let root = root.as_ref();
        let configs = load_configs(root, config_override);

        for path in discover::find_yaml_files(root) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue; // not UTF-8 text; out of scope for a YAML linter
            };
            let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
                continue; // not valid YAML; some other tool's problem
            };

            if let Some(meta) = sops_meta::SopsMeta::from_doc(&doc) {
                for escape in sops_meta::find_escapes(&doc, &meta) {
                    findings.push(Finding {
                        file: path.clone(),
                        severity: Severity::Error,
                        check: Check::EscapedEncryption,
                        key_path: Some(escape.path.clone()),
                        message: format!(
                            "{} is plaintext, but SOPS's own metadata says this file encrypts it",
                            escape.path
                        ),
                    });
                }
                check_coverage(&path, &configs, &mut findings);
            } else if unmanaged::looks_secret_like(&path, &doc) {
                for leak in unmanaged::find_plaintext_leaks(&doc) {
                    findings.push(Finding {
                        file: path.clone(),
                        severity: Severity::Error,
                        check: Check::NeverEncrypted,
                        key_path: Some(leak.path.clone()),
                        message: format!(
                            "{} is a plaintext secret in a file with no `sops:` block at all",
                            leak.path
                        ),
                    });
                }
                check_coverage(&path, &configs, &mut findings);
            }
        }
    }

    findings
}

/// One `.sops.yaml`'s rules, paired with the directory `path_regex` in it is
/// relative to (that file's own directory, matching real SOPS semantics).
struct Config {
    path: std::path::PathBuf,
    dir: std::path::PathBuf,
    rules: Vec<creation_rules::CreationRule>,
}

fn load_configs(root: &Path, config_override: Option<&Path>) -> Vec<Config> {
    let config_paths = match config_override {
        Some(p) => vec![p.to_path_buf()],
        None => discover::find_all_sops_configs(root),
    };
    config_paths
        .into_iter()
        .filter_map(|path| {
            let rules = creation_rules::load(&path).ok()?;
            let dir = path.parent()?.to_path_buf();
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
            message: "no .sops.yaml found anywhere under the scanned root; nothing would \
                      encrypt this file today"
                .to_string(),
        });
        return;
    }

    // A plain `strip_prefix` would fail whenever the file isn't literally
    // inside the config's directory -- but real SOPS (and `--config`
    // pointed at a sibling tree, which this repo's own docs do on purpose)
    // computes a true relative path, `../`s included, and matches that.
    let covered = configs.iter().any(|config| {
        pathdiff::diff_paths(path, &config.dir)
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
