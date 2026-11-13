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
            // `expect`: Finding only contains strings/paths/enums, all of
            // which always serialize.
            println!(
                "{}",
                serde_json::to_string_pretty(&findings).expect("findings are always serializable")
            );
        }
    }

    ExitCode::from(sops_lint::report::exit_code(&findings, args.strict) as u8)
}
