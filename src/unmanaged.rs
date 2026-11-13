use serde_yaml::Value;
use std::path::Path;

/// Heuristic for "this file should probably be SOPS-managed", used only on
/// files that have no `sops:` block at all (see `sops_meta`). Deliberately
/// conservative: false negatives (a secret we miss) are expected and
/// documented in the README; false positives on ordinary config are the
/// worse failure mode for a linter people run in CI.
pub fn looks_secret_like(path: &Path, doc: &Value) -> bool {
    let kind_is_secret = doc
        .as_mapping()
        .and_then(|m| m.get("kind"))
        .and_then(Value::as_str)
        .is_some_and(|k| k == "Secret");

    let name_says_secret = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().contains("secret"));

    kind_is_secret || name_says_secret
}

/// A plaintext leak found in a file that was never passed through SOPS.
pub struct Leak {
    pub path: String,
}

/// Flags non-empty leaves under `data`/`stringData` -- the two fields the
/// repo's own convention (and plain Kubernetes `Secret` semantics) say must
/// never appear outside SOPS's `ENC[...]` form. A file with neither key
/// present yields no findings here; see the README for why that's a known
/// blind spot rather than a bug.
pub fn find_plaintext_leaks(doc: &Value) -> Vec<Leak> {
    let mut leaks = Vec::new();
    let Some(mapping) = doc.as_mapping() else {
        return leaks;
    };
    for field in ["data", "stringData"] {
        let Some(Value::Mapping(payload)) = mapping.get(field) else {
            continue;
        };
        for (key, value) in payload {
            let Some(key) = key.as_str() else { continue };
            let non_empty = match value {
                Value::String(s) => !s.is_empty(),
                Value::Null => false,
                _ => true,
            };
            if non_empty {
                leaks.push(Leak {
                    path: format!("{field}.{key}"),
                });
            }
        }
    }
    leaks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn parse(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn kind_secret_is_secret_like() {
        let doc = parse("kind: Secret\n");
        assert!(looks_secret_like(&PathBuf::from("foo.yaml"), &doc));
    }

    #[test]
    fn filename_convention_is_secret_like() {
        let doc = parse("kind: ConfigMap\n");
        assert!(looks_secret_like(&PathBuf::from("secret-db.yaml"), &doc));
    }

    #[test]
    fn ordinary_file_is_not_secret_like() {
        let doc = parse("kind: ConfigMap\n");
        assert!(!looks_secret_like(&PathBuf::from("app-config.yaml"), &doc));
    }

    #[test]
    fn plaintext_stringdata_is_a_leak() {
        let doc = parse("kind: Secret\nstringData:\n  token: shh\n");
        let leaks = find_plaintext_leaks(&doc);
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].path, "stringData.token");
    }

    #[test]
    fn empty_value_is_not_a_leak() {
        let doc = parse("kind: Secret\nstringData:\n  token: \"\"\n");
        assert!(find_plaintext_leaks(&doc).is_empty());
    }
}
