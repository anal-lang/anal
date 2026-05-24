//! Command-line interface for the ANAL programming language.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "anal", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Execute an .anal file.
    Run { file: PathBuf },
    /// Parse and validate an .anal file without executing it.
    Probe { file: PathBuf },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Run { file } => {
            anyhow::bail!("`anal run` is not yet implemented ({})", file.display());
        }
        Cmd::Probe { file } => {
            anyhow::bail!("`anal probe` is not yet implemented ({})", file.display());
        }
    }
}
