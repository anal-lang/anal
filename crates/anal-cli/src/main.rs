//! Command-line interface for the ANAL programming language.

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
    let result = match cli.cmd {
        Cmd::Run { file } => run(&file),
        Cmd::Probe { file } => probe(&file),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path) -> anyhow::Result<()> {
    let source = read_source(path)?;
    let code = compile(&source).map_err(|e| render(path, &source, e))?;
    let mut vm = VM::new();
    vm.execute(&code).map_err(|e| render(path, &source, e))?;
    Ok(())
}

fn probe(path: &Path) -> anyhow::Result<()> {
    let source = read_source(path)?;
    compile(&source).map_err(|e| render(path, &source, e))?;
    println!("{}: OK", path.display());
    Ok(())
}

fn read_source(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("could not read {}: {e}", path.display()))
}

/// Render an [`AnalError`] with the source location annotated.
fn render(path: &Path, source: &str, err: AnalError) -> anyhow::Error {
    let (line, col) = locate(source, err.span().start);
    anyhow::anyhow!(
        "error[{code}]: {err}\n  at {path}:{line}:{col}",
        code = err.code(),
        path = path.display(),
    )
}

/// 1-based (line, column) for a byte offset into `source`.
fn locate(source: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in source.char_indices() {
        if i >= byte_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}
