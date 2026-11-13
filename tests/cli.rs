use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::path::Path;

fn fixtures_path() -> &'static str {
    "tests/fixtures"
}

fn run_git(repo: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(repo)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn init_test_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    run_git(dir.path(), &["init", "-q"]);
    run_git(dir.path(), &["config", "user.email", "test@example.com"]);
    run_git(dir.path(), &["config", "user.name", "Test"]);
    dir
}

#[test]
fn flags_an_escaped_secret() {
    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(fixtures_path())
        .assert()
        .failure()
        .stdout(contains("secret-escaped.yaml").and(contains("stringData.token")));
}

#[test]
fn flags_a_file_that_never_went_through_sops() {
    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(fixtures_path())
        .assert()
        .failure()
        .stdout(contains("secret-plaintext.yaml").and(contains("no `sops:` block at all")));
}

#[test]
fn warns_on_a_path_no_creation_rule_covers() {
    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(fixtures_path())
        .assert()
        .stdout(contains("secret-uncovered.yaml").and(contains("no creation_rule")));
}

#[test]
fn does_not_flag_a_properly_encrypted_file() {
    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(fixtures_path())
        .assert()
        .stdout(contains("secret-good.yaml").not());
}

#[test]
fn strict_mode_turns_warnings_into_failures() {
    Command::cargo_bin("sops-lint")
        .unwrap()
        .args([fixtures_path(), "--strict"])
        .assert()
        .failure();
}

#[test]
fn single_file_invocation_still_finds_the_repo_wide_config() {
    // This is exactly how the pre-commit hook invokes it: one staged
    // filename, not a directory. `find_all_sops_configs` only searches
    // *under* the given root, so scanning a lone file used to come back
    // with zero configs found -- flagging a perfectly encrypted file.
    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg("tests/fixtures/apps/dev/whoami/secret-good.yaml")
        .assert()
        .success()
        .stdout(contains("no findings"));
}

#[test]
fn multi_document_yaml_is_checked_past_the_first_document() {
    // Own tempdir, not a bare tempfile in the shared OS temp root -- a
    // concurrent test's .sops.yaml could get picked up by the fallback
    // search otherwise (happened once while writing this).
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("multidoc.yaml");
    std::fs::write(
        &file_path,
        b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: harmless\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: oops\nstringData:\n  token: plaintext-in-the-second-document\n",
    )
    .unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(&file_path)
        .assert()
        .failure()
        .stdout(contains("document 1, stringData.token").and(contains("no `sops:` block at all")));
}

#[test]
fn bare_relative_config_filename_is_matched_correctly() {
    // Regression: a bare relative `--config .sops.yaml` used to resolve
    // to an uncanonicalized "" parent, breaking every coverage check.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".sops.yaml"),
        "creation_rules:\n  - path_regex: ^apps/.*\\.yaml$\n    age: age1exampleexampleexampleexampleexampleexampleexampleexamplex\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("apps/dev")).unwrap();
    std::fs::write(
        dir.path().join("apps/dev/secret.yaml"),
        "kind: Secret\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
    )
    .unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(dir.path())
        .args(["--config", ".sops.yaml", "apps/dev/secret.yaml"])
        .assert()
        .success()
        .stdout(contains("no creation_rule").not());
}

#[test]
fn broken_config_is_reported_instead_of_silently_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("broken.sops.yaml");
    std::fs::write(&config_path, "creation_rules: [this is not a valid rule").unwrap();
    std::fs::write(
        dir.path().join("secret.yaml"),
        "kind: Secret\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
    )
    .unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            dir.path().join("secret.yaml").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stdout(contains("couldn't parse this .sops.yaml"));
}

#[test]
fn json_output_is_a_versioned_object_not_a_bare_array() {
    // A bare top-level array can never gain a field later without breaking
    // every existing parser; locking this down as `{"version": N,
    // "findings": [...]}` is exactly the kind of thing that's cheap to
    // get right before release and expensive to change after.
    let output = Command::cargo_bin("sops-lint")
        .unwrap()
        .args([fixtures_path(), "--format", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report.is_object());
    assert_eq!(report["version"], 1);

    let findings = report["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    let escape = findings
        .iter()
        .find(|f| f["check"] == "escaped_encryption")
        .expect("an escaped_encryption finding");
    assert_eq!(escape["severity"], "error");
    assert_eq!(escape["doc_index"], 0);
    assert_eq!(escape["key_path"], "stringData.token");
    assert_eq!(
        escape["key_path_segments"],
        serde_json::json!(["stringData", "token"])
    );
}

#[test]
fn unparseable_document_in_secret_named_file_is_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("secret.yaml");
    std::fs::write(&file_path, b"this: [is not, valid yaml").unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(&file_path)
        .assert()
        .success() // a warning alone doesn't fail without --strict
        .stdout(contains("couldn't be parsed as YAML"));
}

#[test]
fn invalid_encrypted_regex_is_a_warning_not_silent() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("secret.yaml");
    std::fs::write(
        &file_path,
        "kind: Secret\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: \"(unterminated\"\n  version: 3.8.1\n",
    )
    .unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(&file_path)
        .assert()
        .stdout(contains("invalid field").and(contains("false positives")));
}

#[test]
fn staged_mode_checks_the_index_not_the_working_tree() {
    let dir = init_test_repo();
    let repo = dir.path();

    std::fs::write(
        repo.join("secret.yaml"),
        "kind: Secret\nstringData:\n  token: plaintext-in-the-index\n",
    )
    .unwrap();
    run_git(repo, &["add", "secret.yaml"]);

    // Overwrite the working tree -- if --staged read this instead of the
    // index, it would report nothing.
    std::fs::write(repo.join("secret.yaml"), "kind: ConfigMap\n").unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(repo)
        .arg("--staged")
        .assert()
        .failure()
        .stdout(contains("no `sops:` block at all"));
}

#[test]
fn staged_mode_outside_a_git_repo_is_a_tooling_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap(); // deliberately NOT a git repo
    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(dir.path())
        .arg("--staged")
        .assert()
        .code(2)
        .stderr(contains("sops-lint:"));
}

#[test]
fn git_history_finds_a_secret_that_was_later_removed() {
    let dir = init_test_repo();
    let repo = dir.path();

    std::fs::write(
        repo.join("secret.yaml"),
        "kind: Secret\nstringData:\n  token: leaked-long-ago\n",
    )
    .unwrap();
    run_git(repo, &["add", "secret.yaml"]);
    run_git(repo, &["commit", "-q", "-m", "oops, plaintext secret"]);

    run_git(repo, &["rm", "-q", "secret.yaml"]);
    run_git(repo, &["commit", "-q", "-m", "remove the leaked secret"]);

    // Working tree is clean -- the point of the feature is catching this.
    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(repo)
        .assert()
        .success()
        .stdout(contains("no findings"));

    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(repo)
        .arg("--git-history")
        .assert()
        .failure()
        .stdout(contains("no `sops:` block at all"));
}

#[test]
fn git_history_respects_an_explicit_rev_range() {
    let dir = init_test_repo();
    let repo = dir.path();

    std::fs::write(
        repo.join("secret.yaml"),
        "kind: Secret\nstringData:\n  token: leaked-in-first-commit\n",
    )
    .unwrap();
    run_git(repo, &["add", "secret.yaml"]);
    run_git(repo, &["commit", "-q", "-m", "first"]);

    std::fs::write(repo.join("harmless.yaml"), "kind: ConfigMap\n").unwrap();
    run_git(repo, &["add", "harmless.yaml"]);
    run_git(repo, &["commit", "-q", "-m", "second"]);

    // A range excluding the first commit shouldn't see its secret.
    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(repo)
        .args(["--git-history=HEAD~1..HEAD"])
        .assert()
        .success()
        .stdout(contains("no findings"));

    // The default (bare flag, no explicit range) covers all of HEAD's history.
    Command::cargo_bin("sops-lint")
        .unwrap()
        .current_dir(repo)
        .arg("--git-history")
        .assert()
        .failure()
        .stdout(contains("secret.yaml"));
}
