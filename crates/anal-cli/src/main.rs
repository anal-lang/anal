//! Command-line interface for the ANAL programming language.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anal_core::{compile, AnalError, VM};
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (path, is_probe) = match &cli.cmd {
        Cmd::Run { file } => (file.clone(), false),
        Cmd::Probe { file } => (file.clone(), true),
    };

    let source = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not read {}: {e}", path.display());
            return ExitCode::FAILURE;
        }
    };

    let result: Result<(), AnalError> = if is_probe {
        compile(&source).map(|_| ())
    } else {
        compile(&source).and_then(|code| {
            let mut vm = VM::new();
            vm.execute(&code)
        })
    };

    match result {
        Ok(()) => {
            if is_probe {
                println!("{}: OK", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            print_anal_error(&path, &source, &err);
            ExitCode::FAILURE
        }
    }
}

fn print_anal_error(path: &Path, source: &str, err: &AnalError) {
    let path_str = path.display().to_string();
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    if err.render(&path_str, source, &mut lock).is_err() {
        // Fallback if ariadne fails for any reason.
        let _ = writeln!(lock, "error[{code}]: {err}", code = err.code());
    }
}
