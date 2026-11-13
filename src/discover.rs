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
