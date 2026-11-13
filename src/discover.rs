use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// YAML files under `root`, honoring `.gitignore` (so build output, vendored
/// charts, etc. aren't scanned) via the same crate ripgrep uses.
pub fn find_yaml_files(root: &Path) -> Vec<PathBuf> {
    WalkBuilder::new(root)
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .map(|entry| entry.into_path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            )
        })
        .collect()
}

/// Every `.sops.yaml`/`.sops.yml` anywhere under `root`.
///
/// SOPS's own default discovery walks *up* from the file being encrypted.
/// We deliberately don't reproduce that: in practice, repos with more than
/// one `.sops.yaml` tend to keep each one wherever is convenient and always
/// pass `--config` explicitly rather than relying on discovery (this repo's
/// own `nixos/.sops.yaml` says exactly that in a comment) -- so a config
/// file is routinely a sibling, not an ancestor, of the files it governs.
/// Scanning the whole tree and treating every config as a candidate for
/// every file is the heuristic that actually matches that usage; see the
/// README for the false-positive this replaced.
pub fn find_all_sops_configs(root: &Path) -> Vec<PathBuf> {
    WalkBuilder::new(root)
        .hidden(false) // `.sops.yaml` is itself a dotfile; don't let the default hidden-file filter eat it
        .build()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_some_and(|t| t.is_file()))
        .map(|entry| entry.into_path())
        .filter(|path| {
            matches!(
                path.file_name().and_then(|n| n.to_str()),
                Some(".sops.yaml") | Some(".sops.yml")
            )
        })
        .collect()
}

/// Nearest ancestor containing `.git` (directory or file, so worktrees and
/// submodules count too), starting from `start` itself if it's a directory
/// or from its parent if it's a file. Falls back to that same starting
/// directory if no `.git` is found anywhere above it.
///
/// `find_all_sops_configs` only searches *under* whatever root it's given --
/// fine for `sops-lint .`, but a pre-commit hook invokes `sops-lint
/// path/to/one/secret.yaml`, where "under that root" is just the file
/// itself, so a perfectly covered file would otherwise come back with no
/// configs found at all. Widening the search to the whole repo is what
/// actually matches how a shared `.sops.yaml` gets used in practice.
pub fn find_config_search_root(start: &Path) -> PathBuf {
    let start_dir: PathBuf = if start.is_dir() {
        start.to_path_buf()
    } else {
        start.parent().map(Path::to_path_buf).unwrap_or_default()
    };

    // Canonicalize before walking up: `Path::new("tests").parent()` is
    // `Some("")`, and an empty path isn't treated as "current directory"
    // by every API that takes one -- better to never produce it at all.
    let absolute = std::fs::canonicalize(&start_dir).unwrap_or_else(|_| start_dir.clone());

    let mut dir = Some(absolute.as_path());
    while let Some(d) = dir {
        if d.join(".git").exists() {
            return d.to_path_buf();
        }
        dir = d.parent();
    }
    start_dir
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_nearest_git_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::create_dir_all(dir.path().join("sub/deep")).unwrap();
        let file = dir.path().join("sub/deep/secret.yaml");
        std::fs::write(&file, "").unwrap();

        let expected = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(find_config_search_root(&file), expected);
    }

    #[test]
    fn falls_back_to_the_starting_directory_when_no_git_found() {
        // A tempdir under the OS temp root has no `.git` ancestor (unless
        // the OS temp root itself is inside a git checkout, which it never
        // legitimately is) -- this exercises the "walked all the way up
        // and found nothing" path rather than the happy path above.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("secret.yaml");
        std::fs::write(&file, "").unwrap();

        let expected = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(find_config_search_root(&file), expected);
    }
}
