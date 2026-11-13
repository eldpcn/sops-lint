use regex::Regex;
use serde_yaml::Value;

/// The subset of a file's own `sops:` metadata block that determines which
/// values SOPS actually encrypted. SOPS stores this in the file itself at
/// encryption time, so a file is self-describing: we don't need
/// `.sops.yaml` to know what *this* file's author intended to be covered.
pub struct SopsMeta {
    encrypted_regex: Option<Regex>,
    unencrypted_regex: Option<Regex>,
    encrypted_suffix: Option<String>,
    unencrypted_suffix: Option<String>,
    /// `encrypted_regex`/`unencrypted_regex` field names whose value
    /// didn't compile as a regex. When non-empty, `covers_path` fell back
    /// to "encrypt everything" for every leaf in this document, which can
    /// false-positive on fields that were always meant to stay plaintext;
    /// callers should surface this rather than trusting escape results
    /// silently.
    invalid_fields: Vec<String>,
}

impl SopsMeta {
    /// Returns `None` if `doc` has no `sops:` block, i.e. it isn't SOPS-managed at all.
    pub fn from_doc(doc: &Value) -> Option<Self> {
        let sops = doc.as_mapping()?.get("sops")?.as_mapping()?;
        let str_field = |k: &str| sops.get(k).and_then(Value::as_str).map(str::to_owned);

        let mut invalid_fields = Vec::new();
        let mut regex_field = |k: &str| {
            let s = str_field(k)?;
            match Regex::new(&s) {
                Ok(re) => Some(re),
                Err(e) => {
                    invalid_fields.push(format!("{k}: {e}"));
                    None
                }
            }
        };
        let encrypted_regex = regex_field("encrypted_regex");
        let unencrypted_regex = regex_field("unencrypted_regex");

        Some(SopsMeta {
            encrypted_regex,
            unencrypted_regex,
            encrypted_suffix: str_field("encrypted_suffix"),
            unencrypted_suffix: str_field("unencrypted_suffix"),
            invalid_fields,
        })
    }

    pub fn invalid_fields(&self) -> &[String] {
        &self.invalid_fields
    }

    /// Whether SOPS encrypts a leaf reached by this chain of map keys, root
    /// to parent (not including the leaf's own value).
    ///
    /// Matches real SOPS's `shouldBeEncrypted` (`sops.go`): it tests *every*
    /// key along the path, not just the immediate one, and a match anywhere
    /// in the chain covers the leaf -- so `spec.stringData.token` is covered
    /// by `encrypted_regex: ^(data|stringData)$` even though `spec` itself
    /// doesn't match. (Array indices aren't included: they aren't key names
    /// a regex/suffix is meant to match against.)
    ///
    /// SOPS allows at most one of the four selectors; precedence here only
    /// matters for a malformed file that sets more than one.
    pub fn covers_path(&self, key_path: &[String]) -> bool {
        if let Some(re) = &self.encrypted_regex {
            return key_path.iter().any(|k| re.is_match(k));
        }
        if let Some(re) = &self.unencrypted_regex {
            return !key_path.iter().any(|k| re.is_match(k));
        }
        if let Some(suffix) = &self.encrypted_suffix {
            return key_path.iter().any(|k| k.ends_with(suffix.as_str()));
        }
        if let Some(suffix) = &self.unencrypted_suffix {
            return !key_path.iter().any(|k| k.ends_with(suffix.as_str()));
        }
        // No selector configured: SOPS's default is to encrypt every leaf.
        true
    }
}

/// A leaf value SOPS should have encrypted but didn't.
pub struct Escape {
    /// Dotted path from the document root, for display (e.g. `stringData.token`).
    pub path: String,
    /// The same path as the actual sequence of map keys -- unambiguous,
    /// unlike `path`, for a key that itself contains a literal dot
    /// (`tls.crt` is one key in a real Kubernetes TLS secret, not two).
    pub key_path: Vec<String>,
}

pub fn find_escapes(doc: &Value, meta: &SopsMeta) -> Vec<Escape> {
    let mut escapes = Vec::new();
    let Some(mapping) = doc.as_mapping() else {
        return escapes;
    };
    let mut key_path = Vec::new();
    for (key, value) in mapping {
        let Some(key) = key.as_str() else { continue };
        if key == "sops" {
            continue;
        }
        key_path.push(key.to_string());
        walk(key.to_string(), &mut key_path, value, meta, &mut escapes);
        key_path.pop();
    }
    escapes
}

fn walk(
    display_path: String,
    key_path: &mut Vec<String>,
    value: &Value,
    meta: &SopsMeta,
    escapes: &mut Vec<Escape>,
) {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                if let Some(k) = k.as_str() {
                    key_path.push(k.to_string());
                    walk(format!("{display_path}.{k}"), key_path, v, meta, escapes);
                    key_path.pop();
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                // The enclosing keys already in `key_path` still apply to
                // every element; the index itself isn't a key name to match.
                walk(format!("{display_path}[{i}]"), key_path, v, meta, escapes);
            }
        }
        Value::String(s) => {
            // An empty string is never a leak -- there's nothing in it to
            // encrypt in the first place, covered or not.
            if !s.is_empty() && !is_sops_ciphertext(s) && meta.covers_path(key_path) {
                escapes.push(Escape {
                    path: display_path,
                    key_path: key_path.clone(),
                });
            }
        }
        Value::Null => {} // nothing to leak
        // A bare number/bool at a covered leaf also means SOPS never touched it:
        // ordinary SOPS output always rewrites leaves to `ENC[...]` strings.
        _ => {
            if meta.covers_path(key_path) {
                escapes.push(Escape {
                    path: display_path,
                    key_path: key_path.clone(),
                });
            }
        }
    }
}

fn is_sops_ciphertext(s: &str) -> bool {
    s.starts_with("ENC[") && s.ends_with(']')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Value {
        serde_yaml::from_str(yaml).unwrap()
    }

    #[test]
    fn no_sops_block_is_not_managed() {
        let doc = parse("kind: Secret\nstringData:\n  token: plain\n");
        assert!(SopsMeta::from_doc(&doc).is_none());
    }

    #[test]
    fn default_policy_encrypts_everything() {
        let doc = parse("stringData:\n  token: plaintext-leak\nsops:\n  version: 3.8.1\n");
        let meta = SopsMeta::from_doc(&doc).unwrap();
        let escapes = find_escapes(&doc, &meta);
        assert_eq!(escapes.len(), 1);
        assert_eq!(escapes[0].path, "stringData.token");
        assert_eq!(escapes[0].key_path, vec!["stringData", "token"]);
    }

    #[test]
    fn encrypted_regex_scopes_coverage() {
        let doc = parse(
            "kind: Secret\nmetadata:\n  name: foo\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        assert!(find_escapes(&doc, &meta).is_empty());
    }

    #[test]
    fn leaf_outside_encrypted_regex_not_flagged() {
        // `metadata.name` isn't covered by encrypted_regex, so a plaintext
        // value there is intentional, not an escape.
        let doc = parse(
            "metadata:\n  name: plain-and-fine\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        assert!(find_escapes(&doc, &meta).is_empty());
    }

    #[test]
    fn unrelated_key_with_secret_shaped_name_not_flagged() {
        // `annotations.token` -- neither "annotations" nor "token" matches
        // `^(data|stringData)$`, so this really is outside SOPS's own
        // stated policy, not an escape. (Unlike the nested case below,
        // there's no path component here that matches the regex at all.)
        let doc = parse(
            "annotations:\n  token: oops-plaintext\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        assert!(find_escapes(&doc, &meta).is_empty());
    }

    #[test]
    fn match_several_levels_deep_still_covers() {
        // Real SOPS checks every key along the path, not just the top-level
        // one (verified against `shouldBeEncrypted` in sops.go) -- so
        // `spec.stringData.token` is covered by `encrypted_regex:
        // ^(data|stringData)$` even though the top-level key `spec` itself
        // doesn't match.
        let doc = parse(
            "spec:\n  stringData:\n    token: this-should-have-been-encrypted\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        let escapes = find_escapes(&doc, &meta);
        assert_eq!(escapes.len(), 1);
        assert_eq!(escapes[0].path, "spec.stringData.token");
        assert_eq!(escapes[0].key_path, vec!["spec", "stringData", "token"]);
    }

    #[test]
    fn dotted_key_name_is_one_segment_not_two() {
        // A real Kubernetes TLS secret has a literal key named `tls.crt` --
        // one map key containing a dot, not two nested keys. The display
        // `path` can't tell these apart, but `key_path` must.
        let doc = parse(
            "stringData:\n  tls.crt: plaintext-cert\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        let escapes = find_escapes(&doc, &meta);
        assert_eq!(escapes.len(), 1);
        assert_eq!(escapes[0].key_path, vec!["stringData", "tls.crt"]);
    }

    #[test]
    fn invalid_encrypted_regex_is_reported_not_silent() {
        // An unparseable `encrypted_regex` used to silently fall back to
        // "encrypt everything" with no indication anything was wrong.
        let doc = parse(
            "stringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: \"(unterminated\"\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        assert_eq!(meta.invalid_fields().len(), 1);
        assert!(meta.invalid_fields()[0].starts_with("encrypted_regex: "));
    }
}
