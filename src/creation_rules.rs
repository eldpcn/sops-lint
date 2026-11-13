use anyhow::{Context, Result};
use regex::Regex;
use std::path::Path;

/// One `creation_rules[]` entry from `.sops.yaml`. Only `path_regex` matters
/// for coverage checking; key-provider fields are irrelevant here.
pub struct CreationRule {
    /// `None` means the rule has no `path_regex`, which in real SOPS acts as
    /// a catch-all (matches every path) -- almost always the last rule.
    path_regex: Option<Regex>,
}

impl CreationRule {
    fn matches(&self, rel_path: &str) -> bool {
        match &self.path_regex {
            Some(re) => re.is_match(rel_path),
            None => true,
        }
    }
}

pub fn load(sops_yaml_path: &Path) -> Result<Vec<CreationRule>> {
    let text = std::fs::read_to_string(sops_yaml_path)
        .with_context(|| format!("reading {}", sops_yaml_path.display()))?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)
        .with_context(|| format!("parsing {}", sops_yaml_path.display()))?;

    let rules = doc
        .get("creation_rules")
        .and_then(serde_yaml::Value::as_sequence)
        .cloned()
        .unwrap_or_default();

    rules
        .into_iter()
        .map(|rule| {
            let path_regex = rule
                .get("path_regex")
                .and_then(serde_yaml::Value::as_str)
                .map(Regex::new)
                .transpose()
                .context("invalid path_regex in .sops.yaml")?;
            Ok(CreationRule { path_regex })
        })
        .collect()
}

/// Whether `rel_path` (relative to the directory containing `.sops.yaml`)
/// would be encrypted by *some* creation rule today.
///
/// Note: real SOPS matches `path_regex` against the path relative to
/// `.sops.yaml`'s own directory, and rules are otherwise unordered for
/// matching purposes (the first match wins for *which* rule applies, but
/// coverage only cares whether any rule matches at all).
pub fn is_covered(rules: &[CreationRule], rel_path: &str) -> bool {
    rules.iter().any(|r| r.matches(rel_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_sops_yaml(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn path_matching_a_rule_is_covered() {
        let f = write_sops_yaml(
            "creation_rules:\n  - path_regex: apps/.*/secret.*\\.yaml$\n    age: age1xxx\n",
        );
        let rules = load(f.path()).unwrap();
        assert!(is_covered(&rules, "apps/dev/foo/secret.yaml"));
        assert!(!is_covered(&rules, "apps/dev/foo/config.yaml"));
    }

    #[test]
    fn rule_with_no_path_regex_is_a_catchall() {
        let f = write_sops_yaml("creation_rules:\n  - age: age1xxx\n");
        let rules = load(f.path()).unwrap();
        assert!(is_covered(&rules, "anything/at/all.yaml"));
    }
}
