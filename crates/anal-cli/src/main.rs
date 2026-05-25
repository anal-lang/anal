//! Command-line interface for the ANAL programming language.

mod op_help;
mod repl;

use std::fs::OpenOptions;
use std::io::{BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anal_core::{
    compile, hash_source, AnalError, BoxedLedger, Instr, LedgerOpTag, LedgerReader, LedgerSink, Op,
    Program, Span, VM,
};
use clap::{ArgAction, Parser, Subcommand};
use std::collections::HashMap;

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
    /// also honours `NO_COLOR` (<https://no-color.org>).
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
        /// Append one record per destructive op to a .sphlog audit
        /// ledger. The file is created on first record; if it already
        /// exists the run is rejected to keep ledger / source pairs
        /// one-to-one.
        #[arg(long, value_name = "PATH")]
        ledger: Option<PathBuf>,
        /// Run in `--hard` mode: no ambient filesystem authority.
        /// `INGEST` and `EVACUATE` raise `OUTSIDE` (E019) unless the
        /// program has authorised the exact target through `REQUEST`.
        #[arg(long)]
        hard: bool,
    },
    /// Parse and validate an .anal file without executing it.
    Probe {
        /// Path to the .anal source file to validate.
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// Verify a .sphlog audit ledger against its source file.
    ///
    /// Reads the ledger, walks its hash chain, and confirms every record
    /// names a destructive op at the recorded span in the source. Exits
    /// 0 when the ledger is intact and the source matches.
    Audit {
        /// Path to the .sphlog file produced by an earlier `anal run --ledger`.
        #[arg(value_name = "LEDGER")]
        ledger: PathBuf,
        /// Path to the source file the ledger was recorded against.
        #[arg(value_name = "SOURCE")]
        source: PathBuf,
    },
    /// Print version and build information.
    Version,
}

#[derive(Clone, Copy)]
pub(crate) struct Flags {
    pub(crate) quiet: bool,
    pub(crate) verbose: bool,
    pub(crate) no_color: bool,
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
        return start_default(flags);
    };

    match cmd {
        Cmd::Version => {
            print_version();
            ExitCode::SUCCESS
        }
        Cmd::Run { file, ledger, hard } => run(&file, ledger.as_deref(), hard, flags),
        Cmd::Probe { file } => probe(&file, flags),
        Cmd::Audit { ledger, source } => audit(&ledger, &source, flags),
    }
}

/// Dispatch when no subcommand was given.
///
/// If stdin is a TTY, start the interactive REPL. If stdin is a pipe
/// or redirected file, read the whole thing as an ANAL script and
/// execute it — matching the standard `python` / `node` behaviour.
fn start_default(flags: Flags) -> ExitCode {
    if std::io::stdin().is_terminal() {
        match repl::run(flags) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("EVACUATE: REPL error — {e}.");
                ExitCode::FAILURE
            }
        }
    } else {
        let mut source = String::new();
        if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut source) {
            eprintln!("EVACUATE: cannot INGEST stdin — {e}.");
            return ExitCode::FAILURE;
        }
        execute_source(&source, "<stdin>", flags)
    }
}

/// Compile and run an in-memory source string. Shared by piped-stdin
/// execution and the `:load` meta-command sketches.
fn execute_source(source: &str, source_id: &str, flags: Flags) -> ExitCode {
    match compile(source).and_then(|code| {
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
            let path = Path::new(source_id);
            print_anal_error(path, source, &err, flags);
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path, ledger_path: Option<&Path>, hard: bool, flags: Flags) -> ExitCode {
    let source = match read_source(path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if flags.verbose {
        eprintln!("INGEST {} ({} bytes)", path.display(), source.len());
    }

    let code = match compile(&source) {
        Ok(c) => c,
        Err(err) => {
            print_anal_error(path, &source, &err, flags);
            return ExitCode::FAILURE;
        }
    };

    let mut vm = VM::new();

    if hard {
        vm.enable_hard_mode();
        if flags.verbose {
            eprintln!("HARD MODE engaged — no ambient filesystem authority.");
        }
    }

    if let Some(ledger_path) = ledger_path {
        match open_ledger(ledger_path, &source) {
            Ok(sink) => vm.attach_ledger(Some(sink)),
            Err(code) => return code,
        }
        if flags.verbose {
            eprintln!(
                "LEDGER {} (recording destructive ops)",
                ledger_path.display()
            );
        }
    }

    let result = vm.execute(&code);

    // Flush the ledger before reporting status so trailing records
    // are durable even when the run failed mid-program.
    if let Some(sink) = vm.ledger_mut() {
        if let Err(e) = sink.flush() {
            eprintln!("LEDGER: flush failed — {e}.");
            return ExitCode::FAILURE;
        }
    }

    match result {
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

/// Open a fresh .sphlog file for writing. Refuses to overwrite an
/// existing ledger — pairing one ledger with one run keeps the audit
/// story simple. The header (magic, version, source hash) is written
/// immediately; subsequent records are appended by the VM as they fire.
fn open_ledger(ledger_path: &Path, source: &str) -> Result<BoxedLedger, ExitCode> {
    if ledger_path.exists() {
        eprintln!(
            "LEDGER: refuses to overwrite existing ledger {}.",
            ledger_path.display(),
        );
        eprintln!("        delete it, or choose a fresh path.");
        return Err(ExitCode::FAILURE);
    }
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(ledger_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("LEDGER: cannot open {} — {e}.", ledger_path.display());
            return Err(ExitCode::FAILURE);
        }
    };
    let writer: Box<dyn Write> = Box::new(BufWriter::new(file));
    match LedgerSink::new(writer, hash_source(source)) {
        Ok(sink) => Ok(sink),
        Err(e) => {
            eprintln!("LEDGER: cannot write header — {e}.");
            Err(ExitCode::FAILURE)
        }
    }
}

fn audit(ledger_path: &Path, source_path: &Path, flags: Flags) -> ExitCode {
    let source = match read_source(source_path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let file = match std::fs::File::open(ledger_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("LEDGER: cannot open {} — {e}.", ledger_path.display());
            return ExitCode::FAILURE;
        }
    };

    let mut reader = match LedgerReader::open(std::io::BufReader::new(file)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("LEDGER: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Cheapest correctness check first: does the source hash on the
    // ledger match the source we were handed? If not, the ledger and
    // source belong to different runs and the audit is meaningless.
    if reader.source_hash() != hash_source(&source) {
        let err = AnalError::LedgerDrift;
        print_anal_error(source_path, &source, &err, flags);
        return ExitCode::FAILURE;
    }

    // Compile the source so we can map spans back to destructive ops.
    let program = match compile(&source) {
        Ok(p) => p,
        Err(err) => {
            print_anal_error(source_path, &source, &err, flags);
            return ExitCode::FAILURE;
        }
    };
    let destructive = collect_destructive_ops(&program);

    let mut count = 0u64;
    loop {
        let record = match reader.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) => {
                // Map a ledger-format error into the typed AnalError
                // family when we can; otherwise surface it plainly.
                use anal_core::LedgerError;
                let err = match e {
                    LedgerError::BrokenChain { seq, .. } => AnalError::BrokenChain { seq },
                    other => {
                        eprintln!("LEDGER: {other}");
                        return ExitCode::FAILURE;
                    }
                };
                print_anal_error(source_path, &source, &err, flags);
                return ExitCode::FAILURE;
            }
        };
        let span = Span {
            start: record.span_start as usize,
            end: record.span_end as usize,
        };
        match destructive.get(&span) {
            Some(source_op) if *source_op == record.op => {
                count += 1;
            }
            Some(source_op) => {
                let err = AnalError::LedgerGap {
                    seq: record.seq,
                    ledger_op: record.op.name(),
                    source_op: source_op.name(),
                    span,
                };
                print_anal_error(source_path, &source, &err, flags);
                return ExitCode::FAILURE;
            }
            None => {
                let err = AnalError::LedgerGap {
                    seq: record.seq,
                    ledger_op: record.op.name(),
                    source_op: "(no destructive op at this span)",
                    span,
                };
                print_anal_error(source_path, &source, &err, flags);
                return ExitCode::FAILURE;
            }
        }
    }

    if !flags.quiet {
        let mark = if use_color(std::io::stdout().is_terminal(), flags) {
            "\x1b[32m✓\x1b[0m"
        } else {
            "OK"
        };
        println!(
            "{mark} {} — {count} record(s) verified against {}.",
            ledger_path.display(),
            source_path.display(),
        );
    }
    ExitCode::SUCCESS
}

/// Walk `program` and collect every destructive op's span, paired with
/// its ledger tag. The audit uses this to confirm each ledger record's
/// (span, op) matches the source.
fn collect_destructive_ops(program: &Program) -> HashMap<Span, LedgerOpTag> {
    let mut out = HashMap::new();
    walk_block(&program.main, &mut out);
    for body in program.passages.values() {
        walk_block(body, &mut out);
    }
    out
}

fn walk_block(code: &[Instr], out: &mut HashMap<Span, LedgerOpTag>) {
    for instr in code {
        let tag = match instr.op {
            Op::Insert { .. } => Some(LedgerOpTag::Insert),
            Op::Extract(_) => Some(LedgerOpTag::Extract),
            Op::Flush => Some(LedgerOpTag::Flush),
            Op::Bufset => Some(LedgerOpTag::Bufset),
            Op::Store(_) => Some(LedgerOpTag::Store),
            Op::Evacuate(_) => Some(LedgerOpTag::EvacuateOverwrite),
            _ => None,
        };
        if let Some(t) = tag {
            out.insert(instr.span, t);
        }
        if let Op::Push(anal_core::Value::Bloc(body)) = &instr.op {
            walk_block(body, out);
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
pub(crate) fn use_color(is_tty: bool, flags: Flags) -> bool {
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
