pub mod config;
pub mod creation_rules;
pub mod discover;
pub mod git;
pub mod report;
pub mod sops_meta;
pub mod unmanaged;

use anyhow::Result;
use report::{Check, Finding, Severity};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// Scan every YAML file under `roots`, sorted for deterministic output.
///
/// `config_override` forces a specific `.sops.yaml`; otherwise every
/// `.sops.yaml`/`.sops.yml` in each root's enclosing git repo is a
/// candidate for every file -- see `discover::find_config_search_root`.
pub fn check(roots: &[impl AsRef<Path>], config_override: Option<&Path>) -> Vec<Finding> {
    let (configs, mut findings) = config::load_configs(roots, config_override);

    for root in roots {
        let root = root.as_ref();
        for path in discover::find_yaml_files(root) {
            findings.extend(check_file(&path, &configs));
        }
    }

    sort_findings(&mut findings);
    findings
}

/// Checks every staged (index) YAML file against its index content, not
/// whatever's on disk -- what a pre-commit hook actually wants. Configs
/// are still read from the working tree.
pub fn check_staged(config_override: Option<&Path>) -> Result<Vec<Finding>> {
    let roots = ["."];
    let (configs, mut findings) = config::load_configs(&roots, config_override);

    for path in git::staged_yaml_paths()? {
        let Some(text) = git::show_staged(&path)? else {
            continue; // not UTF-8 text; out of scope for a YAML linter
        };
        let path = Path::new(&path);
        let (file_findings, needs_coverage_check) = check_content(path, &text, None);
        findings.extend(file_findings);
        if needs_coverage_check {
            config::check_coverage(path, &configs, &mut findings);
        }
    }

    sort_findings(&mut findings);
    Ok(findings)
}

/// Checks every YAML blob ever added or modified by a commit in
/// `rev_range` (e.g. `"HEAD"` or `"origin/main..HEAD"`) -- catches a
/// secret committed plaintext and later "fixed" but still in history.
/// Never checks coverage: not meaningful for a blob that may not even
/// exist at its old path anymore.
pub fn check_git_history(rev_range: &str) -> Result<Vec<Finding>> {
    let blobs = git::list_historical_yaml_blobs(rev_range)?;

    let mut by_oid: HashMap<&str, Vec<&git::HistoricalBlob>> = HashMap::new();
    for blob in &blobs {
        by_oid.entry(blob.oid.as_str()).or_default().push(blob);
    }
    let oids: Vec<String> = by_oid.keys().map(|oid| oid.to_string()).collect();
    let contents = git::cat_file_batch(&oids)?;

    let mut findings = Vec::new();
    for (oid, text) in &contents {
        // Several commits can share one OID (identical content, e.g. a
        // revert); check once per OID, tag every commit that introduced
        // it. `.get(..).into_iter().flatten()` over indexing: a lookup
        // miss should skip, not panic.
        for blob in by_oid.get(oid.as_str()).into_iter().flatten() {
            let (content_findings, _needs_coverage_check) =
                check_content(Path::new(&blob.path), text, Some(&blob.commit));
            findings.extend(content_findings);
        }
    }

    sort_findings(&mut findings);
    Ok(findings)
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then_with(|| a.key_path.cmp(&b.key_path))
            .then_with(|| a.message.cmp(&b.message))
            .then_with(|| a.commit.cmp(&b.commit))
    });
}

/// Checks one file on disk against the three checks, given the configs
/// already loaded for this run.
fn check_file(path: &Path, configs: &[config::Config]) -> Vec<Finding> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            // Not UTF-8, or unreadable -- out of scope, but worth a word
            // if the name says this should've been a secret.
            return if unmanaged::filename_suggests_secret(path) {
                vec![Finding::new(
                    path,
                    Severity::Warning,
                    Check::UnparseableDocument,
                    format!(
                        "couldn't be read as text ({e}), so it wasn't checked (filename \
                         suggests this should be a secret)"
                    ),
                )]
            } else {
                Vec::new()
            };
        }
    };

    let (mut findings, needs_coverage_check) = check_content(path, &text, None);
    if needs_coverage_check {
        config::check_coverage(path, configs, &mut findings);
    }
    findings
}

/// Runs the content-only checks against `text` at `path`, tagging
/// findings with `commit` if given. Returns findings plus whether
/// coverage should be checked separately (needs filesystem access this
/// function doesn't do).
fn check_content(path: &Path, text: &str, commit: Option<&str>) -> (Vec<Finding>, bool) {
    let mut findings = Vec::new();
    let mut needs_coverage_check = false;

    // Iterating documents handles both single- and multi-document YAML.
    // CAUTION, verified directly: on some malformed input (e.g. `this:
    // [is not, valid yaml`), serde_yaml's Deserializer iterator never
    // advances -- it yields the same error forever. Bailing out after a
    // few consecutive failures bounds that to microseconds.
    let mut consecutive_failures: u32 = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 3;

    for (doc_index, doc) in serde_yaml::Deserializer::from_str(text).enumerate() {
        let Ok(doc) = serde_yaml::Value::deserialize(doc) else {
            consecutive_failures += 1;
            if consecutive_failures > MAX_CONSECUTIVE_FAILURES {
                findings.push(tag(
                    Finding::new(
                        path,
                        Severity::Warning,
                        Check::UnparseableDocument,
                        format!(
                            "gave up after {MAX_CONSECUTIVE_FAILURES} documents in a row \
                                 failed to parse; the rest of this file wasn't checked"
                        ),
                    )
                    .with_doc_index(doc_index),
                    commit,
                ));
                break;
            }
            if unmanaged::filename_suggests_secret(path) {
                findings.push(tag(
                    Finding::new(
                        path,
                        Severity::Warning,
                        Check::UnparseableDocument,
                        format!(
                            "document {doc_index} couldn't be parsed as YAML, so it wasn't \
                                 checked (filename suggests this should be a secret)"
                        ),
                    )
                    .with_doc_index(doc_index),
                    commit,
                ));
            }
            continue;
        };
        consecutive_failures = 0;

        // Only worth a prefix once there's more than one document;
        // `doc_index` on the `Finding` is the machine-readable version.
        let doc_prefix = if doc_index == 0 {
            String::new()
        } else {
            format!("document {doc_index}, ")
        };

        if let Some(meta) = sops_meta::SopsMeta::from_doc(&doc) {
            needs_coverage_check = true;

            if !meta.invalid_fields().is_empty() {
                findings.push(tag(
                    Finding::new(
                        path,
                        Severity::Warning,
                        Check::InvalidSopsMetadata,
                        format!(
                            "{doc_prefix}sops metadata has an invalid field ({}); treating \
                                 every value as if it must be encrypted, which may cause false \
                                 positives",
                            meta.invalid_fields().join(", ")
                        ),
                    )
                    .with_doc_index(doc_index),
                    commit,
                ));
            }

            for escape in sops_meta::find_escapes(&doc, &meta) {
                let message = format!(
                    "{doc_prefix}{} is plaintext, but SOPS's own metadata says this file encrypts it",
                    escape.path
                );
                findings.push(tag(
                    Finding::new(path, Severity::Error, Check::EscapedEncryption, message)
                        .with_doc_index(doc_index)
                        .with_key_path(escape.path, escape.key_path),
                    commit,
                ));
            }
        } else if unmanaged::looks_secret_like(path, &doc) {
            needs_coverage_check = true;

            for leak in unmanaged::find_plaintext_leaks(&doc) {
                let message = format!(
                    "{doc_prefix}{} is a plaintext secret in a file with no `sops:` block at all",
                    leak.path
                );
                findings.push(tag(
                    Finding::new(path, Severity::Error, Check::NeverEncrypted, message)
                        .with_doc_index(doc_index)
                        .with_key_path(leak.path, leak.key_path),
                    commit,
                ));
            }
        }
    }

    (findings, needs_coverage_check)
}

fn tag(finding: Finding, commit: Option<&str>) -> Finding {
    match commit {
        Some(c) => finding.with_commit(c),
        None => finding,
    }
}
