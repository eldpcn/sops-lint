use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

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
