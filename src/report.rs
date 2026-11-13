use serde::Serialize;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
        }
    }
}

/// Which check produced a finding; stable identifiers for machine
/// consumption (`--format json`), independent of the human-readable
/// `message` wording.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    EscapedEncryption,
    NeverEncrypted,
    NoCreationRule,
    /// A document inside a secret-named file couldn't be parsed as YAML at
    /// all, so it wasn't checked for either of the above.
    UnparseableDocument,
    /// A `.sops.yaml` (explicit `--config`, or one found during discovery)
    /// couldn't be read or parsed, so coverage results may be incomplete.
    ConfigLoadError,
}

#[derive(Serialize)]
pub struct Finding {
    pub file: PathBuf,
    pub severity: Severity,
    pub check: Check,
    /// The dotted key path the finding is about, when there is one (both
    /// secret checks have one; the coverage check doesn't).
    pub key_path: Option<String>,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}: {}",
            self.file.display(),
            self.severity,
            self.message
        )
    }
}

/// Exit code for CI: nonzero if there's an error, or (with `strict`) a warning.
pub fn exit_code(findings: &[Finding], strict: bool) -> i32 {
    let bad = findings
        .iter()
        .any(|f| f.severity == Severity::Error || (strict && f.severity == Severity::Warning));
    i32::from(bad)
}
