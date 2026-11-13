use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// A linter that understands SOPS: catches secrets that escaped encryption
/// and files SOPS wouldn't actually cover.
#[derive(Parser)]
struct Args {
    /// Directories or files to scan (default: current directory).
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Use this .sops.yaml instead of looking for the nearest one per file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Treat warnings (e.g. no creation_rule covers a file) as failures too.
    #[arg(long)]
    strict: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let findings = sops_lint::check(&args.paths, args.config.as_deref());

    for finding in &findings {
        println!("{finding}");
    }
    if findings.is_empty() {
        println!("sops-lint: no findings");
    }

    ExitCode::from(sops_lint::report::exit_code(&findings, args.strict) as u8)
}
