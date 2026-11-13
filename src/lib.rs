pub mod config;
pub mod creation_rules;
pub mod discover;
pub mod report;
pub mod sops_meta;
pub mod unmanaged;

use report::{Check, Finding, Severity};
use serde::Deserialize;
use std::path::Path;

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
    let (configs, mut findings) = config::load_configs(roots, config_override);

    for root in roots {
        let root = root.as_ref();
        for path in discover::find_yaml_files(root) {
            findings.extend(check_file(&path, &configs));
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

/// Checks one file against the three checks, given the configs already
/// loaded for this run. Split out from `check()` so the per-file logic
/// (multi-document handling, which check family applies, when coverage
/// needs checking at all) is unit-testable without going through the CLI.
fn check_file(path: &Path, configs: &[config::Config]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            // Not UTF-8 text, or unreadable -- out of scope for a YAML
            // linter either way, but worth a word if the name says this
            // should have been a secret (same filename-only heuristic as
            // an unparseable document below, since we don't even have
            // content to check for a `kind: Secret` yet).
            if unmanaged::filename_suggests_secret(path) {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    severity: Severity::Warning,
                    check: Check::UnparseableDocument,
                    doc_index: None,
                    key_path: None,
                    key_path_segments: None,
                    message: format!(
                        "couldn't be read as text ({e}), so it wasn't checked (filename \
                         suggests this should be a secret)"
                    ),
                });
            }
            return findings;
        }
    };

    // Coverage depends only on the file's path, not on which document
    // inside it we're looking at -- check it once per file, not once per
    // document, so a multi-document file doesn't get the same warning
    // twice.
    let mut needs_coverage_check = false;

    // A plain `serde_yaml::from_str::<Value>` errors outright on a
    // `---`-separated multi-document stream, which is routine for
    // Kubernetes manifests -- silently skipping the whole file on that
    // error would mean a second or third document's plaintext secret
    // sails through unchecked. Iterating documents handles both the
    // single- and multi-document case uniformly.
    //
    // CAUTION, verified directly: on some malformed input (an unterminated
    // flow collection, e.g. `this: [is not, valid yaml`), serde_yaml's
    // `Deserializer` iterator doesn't advance at all -- it yields the same
    // error forever and never ends the stream. A single `---`-free
    // malformed file can hang this loop indefinitely with no progress and
    // no panic, which is a real DoS risk for anything that runs this
    // unattended (CI, a pre-commit hook). Bailing out after a few
    // consecutive failures bounds that to a few microseconds of wasted
    // work regardless of why parsing is stuck.
    let mut consecutive_failures: u32 = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 3;

    for (doc_index, doc) in serde_yaml::Deserializer::from_str(&text).enumerate() {
        let Ok(doc) = serde_yaml::Value::deserialize(doc) else {
            consecutive_failures += 1;
            if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    severity: Severity::Warning,
                    check: Check::UnparseableDocument,
                    doc_index: Some(doc_index),
                    key_path: None,
                    key_path_segments: None,
                    message: format!(
                        "gave up after {MAX_CONSECUTIVE_FAILURES} documents in a row failed to \
                         parse; the rest of this file wasn't checked"
                    ),
                });
                break;
            }
            if unmanaged::filename_suggests_secret(path) {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    severity: Severity::Warning,
                    check: Check::UnparseableDocument,
                    doc_index: Some(doc_index),
                    key_path: None,
                    key_path_segments: None,
                    message: format!(
                        "document {doc_index} couldn't be parsed as YAML, so it wasn't checked \
                         (filename suggests this should be a secret)"
                    ),
                });
            }
            continue;
        };
        consecutive_failures = 0;

        // A human-readable location prefix for this document -- only
        // worth mentioning when there's more than one document to
        // disambiguate between; `doc_index` on the `Finding` itself is
        // the machine-readable version, always set.
        let doc_prefix = if doc_index == 0 {
            String::new()
        } else {
            format!("document {doc_index}, ")
        };

        if let Some(meta) = sops_meta::SopsMeta::from_doc(&doc) {
            needs_coverage_check = true;

            if !meta.invalid_fields().is_empty() {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    severity: Severity::Warning,
                    check: Check::InvalidSopsMetadata,
                    doc_index: Some(doc_index),
                    key_path: None,
                    key_path_segments: None,
                    message: format!(
                        "{doc_prefix}sops metadata has an invalid field ({}); treating every \
                         value as if it must be encrypted, which may cause false positives",
                        meta.invalid_fields().join(", ")
                    ),
                });
            }

            for escape in sops_meta::find_escapes(&doc, &meta) {
                let message = format!(
                    "{doc_prefix}{} is plaintext, but SOPS's own metadata says this file encrypts it",
                    escape.path
                );
                findings.push(Finding {
                    file: path.to_path_buf(),
                    severity: Severity::Error,
                    check: Check::EscapedEncryption,
                    doc_index: Some(doc_index),
                    key_path: Some(escape.path),
                    key_path_segments: Some(escape.key_path),
                    message,
                });
            }
        } else if unmanaged::looks_secret_like(path, &doc) {
            needs_coverage_check = true;

            for leak in unmanaged::find_plaintext_leaks(&doc) {
                let message = format!(
                    "{doc_prefix}{} is a plaintext secret in a file with no `sops:` block at all",
                    leak.path
                );
                findings.push(Finding {
                    file: path.to_path_buf(),
                    severity: Severity::Error,
                    check: Check::NeverEncrypted,
                    doc_index: Some(doc_index),
                    key_path: Some(leak.path),
                    key_path_segments: Some(leak.key_path),
                    message,
                });
            }
        }
    }

    if needs_coverage_check {
        config::check_coverage(path, configs, &mut findings);
    }

    findings
}
