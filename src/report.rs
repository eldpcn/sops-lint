use serde::{Serialize, Serializer};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
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
/// `message` wording. `#[non_exhaustive]` because a future release adding
/// a check (e.g. recipient drift) shouldn't be a breaking change for a
/// library consumer matching on this.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Check {
    EscapedEncryption,
    NeverEncrypted,
    NoCreationRule,
    /// A document (or, if unreadable, a whole file) in a secret-named path
    /// couldn't be parsed as YAML at all, so it wasn't checked for either
    /// of the above.
    UnparseableDocument,
    /// A `.sops.yaml` (explicit `--config`, or one found during discovery)
    /// couldn't be read or parsed, so coverage results may be incomplete.
    ConfigLoadError,
    /// A file's own `sops:` block sets `encrypted_regex` or
    /// `unencrypted_regex` to something that doesn't compile as a regex,
    /// so coverage fell back to "encrypt everything" for that document --
    /// which can produce false positives on fields that were always
    /// meant to stay plaintext.
    InvalidSopsMetadata,
}

/// One finding. `#[non_exhaustive]`: constructing or exhaustively matching
/// this outside the crate shouldn't be possible, so a future field or
/// variant addition isn't a breaking change for a library consumer.
#[derive(Serialize)]
#[non_exhaustive]
pub struct Finding {
    #[serde(serialize_with = "serialize_path_lossy")]
    pub file: PathBuf,
    pub severity: Severity,
    pub check: Check,
    /// 0-based index of the document within the file this finding is
    /// about, for a `---`-separated multi-document YAML stream. `None` for
    /// findings that aren't about any one document (coverage, or a config
    /// load failure).
    pub doc_index: Option<usize>,
    /// The key path the finding is about, dotted for display (e.g.
    /// `stringData.token`). Ambiguous on its own for a real Kubernetes
    /// secret -- keys like `tls.crt` or `.dockerconfigjson` contain dots
    /// too -- so machine consumers should use `key_path_segments` instead.
    pub key_path: Option<String>,
    /// The same key path as `key_path`, as the actual unambiguous
    /// sequence of map keys from the document root.
    pub key_path_segments: Option<Vec<String>>,
    pub message: String,
}

/// `PathBuf`'s own `Serialize` requires valid UTF-8 and errors otherwise --
/// which `serde_json::to_string` would propagate as a hard failure for a
/// file reached through a non-UTF-8 directory component. A lint findings
/// report should never refuse to print because of what a path is spelled
/// with; fall back to a lossy rendering instead.
fn serialize_path_lossy<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&path.to_string_lossy())
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

/// `--format json`'s top-level shape. Deliberately an object, never a bare
/// array: a bare array can't gain a field later (e.g. a schema version, or
/// a summary count) without breaking every existing parser, while an
/// object can.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Report<'a> {
    pub version: u32,
    pub findings: &'a [Finding],
}

impl<'a> Report<'a> {
    pub fn new(findings: &'a [Finding]) -> Self {
        Report {
            version: SCHEMA_VERSION,
            findings,
        }
    }
}

/// Exit code for CI: nonzero if there's an error, or (with `strict`) a warning.
pub fn exit_code(findings: &[Finding], strict: bool) -> u8 {
    let bad = findings
        .iter()
        .any(|f| f.severity == Severity::Error || (strict && f.severity == Severity::Warning));
    u8::from(bad)
}
