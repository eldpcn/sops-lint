use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::io::Write;

fn fixtures_path() -> &'static str {
    "tests/fixtures"
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
    let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    f.write_all(
        b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: harmless\n---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: oops\nstringData:\n  token: plaintext-in-the-second-document\n",
    )
    .unwrap();

    Command::cargo_bin("sops-lint")
        .unwrap()
        .arg(f.path())
        .assert()
        .failure()
        .stdout(contains("doc[1].stringData.token").and(contains("no `sops:` block at all")));
}

#[test]
fn bare_relative_config_filename_is_matched_correctly() {
    // Regression for a real bug: `Path::new(".sops.yaml").parent()` is
    // `Some("")`, and canonicalizing the *parent* of a bare relative
    // `--config` filename (rather than the config file itself first) left
    // `config.dir` as an uncanonicalized "", which made every coverage
    // check compare against the wrong base path. Build a self-contained
    // tree so the regex only matches if the relative-path math is right.
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
fn json_output_is_a_valid_array_of_findings() {
    let output = Command::cargo_bin("sops-lint")
        .unwrap()
        .args([fixtures_path(), "--format", "json"])
        .output()
        .unwrap();
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!findings.is_empty());
    let escape = findings
        .iter()
        .find(|f| f["check"] == "escaped_encryption")
        .expect("an escaped_encryption finding");
    assert_eq!(escape["severity"], "error");
    assert_eq!(escape["key_path"], "stringData.token");
}
