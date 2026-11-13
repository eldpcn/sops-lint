use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// A linter that understands SOPS: catches secrets that escaped encryption
/// and files SOPS wouldn't actually cover.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Directories or files to scan (default: current directory). Ignored
    /// with --staged or --git-history.
    #[arg(default_value = ".", conflicts_with_all = ["staged", "git_history"])]
    paths: Vec<PathBuf>,

    /// Use only this .sops.yaml, instead of every .sops.yaml/.sops.yml
    /// found in each scanned path's git repository. Has no effect with
    /// --git-history, which never checks coverage.
    #[arg(long, conflicts_with = "git_history")]
    config: Option<PathBuf>,

    /// Treat warnings (e.g. no creation_rule covers a file) as failures too.
    #[arg(long)]
    strict: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Check git's staged (index) content instead of the working tree --
    /// what would actually be committed if `git commit` ran right now.
    /// For a pre-commit hook.
    #[arg(long, conflicts_with = "git_history")]
    staged: bool,

    /// Check every YAML blob ever added or modified by a commit in this
    /// range (default when the flag is given with no value: HEAD, i.e.
    /// the current branch's whole history). Catches a secret that was
    /// committed plaintext and later "fixed" but is still in history.
    /// Coverage (no_creation_rule) is never checked in this mode.
    #[arg(long, num_args = 0..=1, default_missing_value = "HEAD")]
    git_history: Option<String>,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let findings = if args.staged {
        match sops_lint::check_staged(args.config.as_deref()) {
            Ok(findings) => findings,
            Err(e) => return tooling_error(&e),
        }
    } else if let Some(range) = &args.git_history {
        match sops_lint::check_git_history(range) {
            Ok(findings) => findings,
            Err(e) => return tooling_error(&e),
        }
    } else {
        sops_lint::check(&args.paths, args.config.as_deref())
    };

    match args.format {
        Format::Text => {
            for finding in &findings {
                println!("{finding}");
            }
            if findings.is_empty() {
                println!("sops-lint: no findings");
            }
        }
        Format::Json => {
            let report = sops_lint::report::Report::new(&findings);
            // Never fails: `file` serializes via a lossy-UTF-8 helper.
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("a Report always serializes")
            );
        }
    }

    ExitCode::from(sops_lint::report::exit_code(&findings, args.strict))
}

/// Distinct from exit code 1 (findings exist): this means sops-lint
/// itself couldn't run (no git, not a repo, ...).
fn tooling_error(e: &anyhow::Error) -> ExitCode {
    eprintln!("sops-lint: {e:#}");
    ExitCode::from(2)
}
