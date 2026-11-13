use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

/// A linter that understands SOPS: catches secrets that escaped encryption
/// and files SOPS wouldn't actually cover.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Directories or files to scan (default: current directory).
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Use only this .sops.yaml, instead of every .sops.yaml/.sops.yml found
    /// in each scanned path's git repository.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Treat warnings (e.g. no creation_rule covers a file) as failures too.
    #[arg(long)]
    strict: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Format {
    Text,
    Json,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let findings = sops_lint::check(&args.paths, args.config.as_deref());

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
            // `expect`: every field on `Report`/`Finding` either always
            // serializes (enums, Option<String/usize/Vec<String>>) or is
            // explicitly made to (the `file: PathBuf` field is serialized
            // via a lossy-UTF-8 helper, not PathBuf's own impl, precisely
            // so this can't fail on a non-UTF-8 path).
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("a Report always serializes")
            );
        }
    }

    ExitCode::from(sops_lint::report::exit_code(&findings, args.strict))
}
