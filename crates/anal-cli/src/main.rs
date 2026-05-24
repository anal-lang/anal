//! Command-line interface for the ANAL programming language.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anal_core::{compile, AnalError, VM};
use clap::{ArgAction, Parser, Subcommand};

const LONG_ABOUT: &str = "anal — the reference interpreter for the Append-oriented, \
Narrow-access Language.\n\nData arrives. In order. With consent.";

#[derive(Parser)]
#[command(
    name = "anal",
    version,
    about = "Reference interpreter for the ANAL programming language",
    long_about = LONG_ABOUT,
    disable_version_flag = true,
)]
struct Cli {
    /// Suppress non-essential output (e.g. PROBE success lines).
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    /// Print extra detail about what the interpreter is doing.
    #[arg(short, long, global = true, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Disable ANSI colour in diagnostics. Auto-detected for non-TTY output;
    /// also honours `NO_COLOR` (https://no-color.org).
    #[arg(long, global = true)]
    no_color: bool,

    /// Print version information and exit.
    #[arg(short = 'V', long)]
    version: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Execute an .anal file.
    Run {
        /// Path to the .anal source file to execute.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Parse and validate an .anal file without executing it.
    Probe {
        /// Path to the .anal source file to validate.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Print version and build information.
    Version,
}

#[derive(Clone, Copy)]
struct Flags {
    quiet: bool,
    verbose: bool,
    no_color: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let flags = Flags {
        quiet: cli.quiet,
        verbose: cli.verbose,
        no_color: cli.no_color,
    };

    if cli.version {
        print_version();
        return ExitCode::SUCCESS;
    }

    let Some(cmd) = cli.cmd else {
        eprintln!("EVACUATE: no command — try `anal --help` or `anal run <FILE>`.");
        return ExitCode::FAILURE;
    };

    match cmd {
        Cmd::Version => {
            print_version();
            ExitCode::SUCCESS
        }
        Cmd::Run { file } => run(&file, flags),
        Cmd::Probe { file } => probe(&file, flags),
    }
}

fn run(path: &Path, flags: Flags) -> ExitCode {
    let source = match read_source(path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if flags.verbose {
        eprintln!("INGEST {} ({} bytes)", path.display(), source.len());
    }

    match compile(&source).and_then(|code| {
        let mut vm = VM::new();
        vm.execute(&code)
    }) {
        Ok(()) => {
            if flags.verbose {
                eprintln!("EXIT 0");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            print_anal_error(path, &source, &err, flags);
            ExitCode::FAILURE
        }
    }
}

fn probe(path: &Path, flags: Flags) -> ExitCode {
    let source = match read_source(path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    match compile(&source) {
        Ok(_) => {
            if !flags.quiet {
                let mark = if use_color(std::io::stdout().is_terminal(), flags) {
                    "\x1b[32m✓\x1b[0m"
                } else {
                    "OK"
                };
                println!("{mark} {} — PROBE clean.", path.display());
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            print_anal_error(path, &source, &err, flags);
            ExitCode::FAILURE
        }
    }
}

fn read_source(path: &Path) -> Result<String, ExitCode> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("EVACUATE: cannot INGEST {} — no such file.", path.display());
            Err(ExitCode::FAILURE)
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "EVACUATE: cannot INGEST {} — permission denied.",
                path.display()
            );
            Err(ExitCode::FAILURE)
        }
        Err(e) => {
            eprintln!("EVACUATE: cannot INGEST {} — {e}.", path.display());
            Err(ExitCode::FAILURE)
        }
    }
}

fn print_anal_error(path: &Path, source: &str, err: &AnalError, flags: Flags) {
    let path_str = path.display().to_string();
    let stderr = std::io::stderr();
    let color = use_color(stderr.is_terminal(), flags);
    let mut lock = stderr.lock();
    if err.render(&path_str, source, color, &mut lock).is_err() {
        let _ = writeln!(lock, "error[{code}]: {err}", code = err.code());
    }
}

/// Decide whether ANSI colour should be emitted.
///
/// Honours, in order: `--no-color`, the `NO_COLOR` env var (any non-empty
/// value disables), then the TTY status of the target stream.
fn use_color(is_tty: bool, flags: Flags) -> bool {
    if flags.no_color {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    is_tty
}

fn print_version() {
    let version = env!("CARGO_PKG_VERSION");
    let sha = env!("ANAL_BUILD_SHA");
    let target = env!("ANAL_BUILD_TARGET");
    println!("anal {version} ({sha}, {target})");
    println!("the reference interpreter for the Append-oriented, Narrow-access Language.");
}
