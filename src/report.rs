use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq)]
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

pub struct Finding {
    pub file: PathBuf,
    pub severity: Severity,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.file.display(), self.severity, self.message)
    }
}

/// Exit code for CI: nonzero if there's an error, or (with `strict`) a warning.
pub fn exit_code(findings: &[Finding], strict: bool) -> i32 {
    let bad = findings
        .iter()
        .any(|f| f.severity == Severity::Error || (strict && f.severity == Severity::Warning));
    i32::from(bad)
}
