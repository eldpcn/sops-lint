use regex::Regex;
use serde_yaml::Value;

/// The subset of a file's own `sops:` metadata block that determines which
/// top-level keys SOPS actually encrypted. SOPS stores this in the file
/// itself at encryption time, so a file is self-describing: we don't need
/// `.sops.yaml` to know what *this* file's author intended to be covered.
pub struct SopsMeta {
    encrypted_regex: Option<Regex>,
    unencrypted_regex: Option<Regex>,
    encrypted_suffix: Option<String>,
    unencrypted_suffix: Option<String>,
}

impl SopsMeta {
    /// Returns `None` if `doc` has no `sops:` block, i.e. it isn't SOPS-managed at all.
    pub fn from_doc(doc: &Value) -> Option<Self> {
        let sops = doc.as_mapping()?.get("sops")?.as_mapping()?;
        let str_field = |k: &str| sops.get(k).and_then(Value::as_str).map(str::to_owned);
        let regex_field = |k: &str| str_field(k).and_then(|s| Regex::new(&s).ok());

        Some(SopsMeta {
            encrypted_regex: regex_field("encrypted_regex"),
            unencrypted_regex: regex_field("unencrypted_regex"),
            encrypted_suffix: str_field("encrypted_suffix"),
            unencrypted_suffix: str_field("unencrypted_suffix"),
        })
    }

    /// Whether SOPS encrypts everything under this top-level key.
    ///
    /// SOPS allows at most one of the four selectors; precedence here only
    /// matters for a malformed file that sets more than one.
    pub fn covers(&self, key: &str) -> bool {
        if let Some(re) = &self.encrypted_regex {
            return re.is_match(key);
        }
        if let Some(re) = &self.unencrypted_regex {
            return !re.is_match(key);
        }
        if let Some(suffix) = &self.encrypted_suffix {
            return key.ends_with(suffix.as_str());
        }
        if let Some(suffix) = &self.unencrypted_suffix {
            return !key.ends_with(suffix.as_str());
        }
        // No selector configured: SOPS's default is to encrypt every leaf.
        true
    }
}

/// A leaf value SOPS should have encrypted but didn't, identified by its
/// dotted path from the document root (e.g. `stringData.token`).
pub struct Escape {
    pub path: String,
}

pub fn find_escapes(doc: &Value, meta: &SopsMeta) -> Vec<Escape> {
    let mut escapes = Vec::new();
    let Some(mapping) = doc.as_mapping() else {
        return escapes;
    };
    for (key, value) in mapping {
        let Some(key) = key.as_str() else { continue };
        if key == "sops" || !meta.covers(key) {
            continue;
        }
        walk(key.to_string(), value, &mut escapes);
    }
    escapes
}

fn walk(path: String, value: &Value, escapes: &mut Vec<Escape>) {
    match value {
        Value::Mapping(map) => {
            for (k, v) in map {
                if let Some(k) = k.as_str() {
                    walk(format!("{path}.{k}"), v, escapes);
                }
            }
        }
        Value::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                walk(format!("{path}[{i}]"), v, escapes);
            }
        }
        Value::String(s) => {
            if !is_sops_ciphertext(s) {
                escapes.push(Escape { path });
            }
        }
        Value::Null => {} // nothing to leak
        // A bare number/bool at a covered leaf also means SOPS never touched it:
        // ordinary SOPS output always rewrites leaves to `ENC[...]` strings.
        _ => escapes.push(Escape { path }),
    }
}

fn is_sops_ciphertext(s: &str) -> bool {
    s.is_empty() || (s.starts_with("ENC[") && s.ends_with(']'))
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
    fn new_key_outside_regex_with_secret_escapes() {
        // Someone added `annotations.token` expecting coverage, but the
        // file's own encrypted_regex only matches `data`/`stringData` --
        // this is exactly the bug class this tool exists to catch. It's
        // invisible to this per-file check (annotations isn't "covered",
        // so by definition nothing under it is an "escape" here); it's
        // the generic-secret-scan check (deferred, see README) that would
        // need to catch this one. Documented via this test as a known gap.
        let doc = parse(
            "annotations:\n  token: oops-plaintext\nstringData:\n  token: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  encrypted_regex: ^(data|stringData)$\n  version: 3.8.1\n",
        );
        let meta = SopsMeta::from_doc(&doc).unwrap();
        assert!(find_escapes(&doc, &meta).is_empty());
    }
}
