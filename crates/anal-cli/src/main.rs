//! Command-line interface for the ANAL programming language.

mod op_help;
mod repl;

use std::fs::OpenOptions;
use std::io::{BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anal_core::{
    compile, hash_source, AnalError, BoxedLedger, Instr, LedgerOpTag, LedgerReader, LedgerRecord,
    LedgerSink, Op, Program, Span, VM,
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
        /// Also record arming ops (`PREP`, `CONSENT`, `CLENCH`,
        /// `RELEASE`, `RELAX`) to the ledger. No effect without
        /// `--ledger`. Produces a complete consent trail instead of
        /// only the destructive acts.
        #[arg(long, requires = "ledger")]
        ledger_verbose: bool,
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
        /// After verification, print one line per record: seq, timestamp,
        /// op, file:line:col, pre-op stack shape. The ledger is read-only;
        /// this only affects what `anal audit` prints.
        #[arg(long)]
        examine: bool,
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
        Cmd::Run {
            file,
            ledger,
            ledger_verbose,
            hard,
        } => run(&file, ledger.as_deref(), ledger_verbose, hard, flags),
        Cmd::Probe { file } => probe(&file, flags),
        Cmd::Audit {
            ledger,
            source,
            examine,
        } => audit(&ledger, &source, examine, flags),
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

fn run(
    path: &Path,
    ledger_path: Option<&Path>,
    ledger_verbose: bool,
    hard: bool,
    flags: Flags,
) -> ExitCode {
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
        let sink = match open_ledger(ledger_path, &source) {
            Ok(mut s) => {
                if ledger_verbose {
                    s.enable_verbose();
                }
                s
            }
            Err(code) => return code,
        };
        vm.attach_ledger(Some(sink));
        if flags.verbose {
            let mode = if ledger_verbose {
                "verbose"
            } else {
                "destructive ops only"
            };
            eprintln!("LEDGER {} ({mode})", ledger_path.display());
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

fn audit(ledger_path: &Path, source_path: &Path, examine: bool, flags: Flags) -> ExitCode {
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
    let loggable = collect_loggable_ops(&program);

    // Collect verified records as we walk. Holding them lets
    // `--examine` print without re-reading the file; the cost is
    // O(records) memory, which is fine for any realistic audit.
    let mut records: Vec<LedgerRecord> = Vec::new();
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
        match loggable.get(&span) {
            Some(source_op) if *source_op == record.op => {
                records.push(record);
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
                    source_op: "(no loggable op at this span)",
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
            "{mark} {} — {} record(s) verified against {}.",
            ledger_path.display(),
            records.len(),
            source_path.display(),
        );
    }

    if examine {
        print_examined_records(&records, source_path, &source);
    }

    ExitCode::SUCCESS
}

/// Pretty-print every verified ledger record. Called after audit
/// succeeds, so we know each record is decodable and consistent with
/// the source. Columns: seq, timestamp, op, file:line:col, pre-op
/// stack shape. Output is plain text (no ANSI) so it pipes cleanly.
fn print_examined_records(records: &[LedgerRecord], source_path: &Path, source: &str) {
    if records.is_empty() {
        return;
    }
    let line_starts = build_line_starts(source);
    let source_name = source_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| source_path.display().to_string());

    // Format every row first so we can compute consistent column widths.
    let rows: Vec<(String, String, String, String, String)> = records
        .iter()
        .map(|r| {
            let (line, col) = byte_offset_to_line_col(&line_starts, r.span_start as usize);
            (
                format!("{}", r.seq),
                format_iso8601_utc(r.ts_micros),
                r.op.name().to_string(),
                format!("{source_name}:{line}:{col}"),
                format_stack_shape(&r.top_types, r.stack_depth),
            )
        })
        .collect();

    let widths = column_widths(&rows, &["seq", "timestamp", "op", "location", "stack"]);

    println!();
    println!(
        "  {:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  stack",
        "seq",
        "timestamp",
        "op",
        "location",
        w0 = widths[0],
        w1 = widths[1],
        w2 = widths[2],
        w3 = widths[3],
    );
    println!(
        "  {}  {}  {}  {}  {}",
        "─".repeat(widths[0]),
        "─".repeat(widths[1]),
        "─".repeat(widths[2]),
        "─".repeat(widths[3]),
        "─".repeat(widths[4]),
    );
    for (seq, ts, op, loc, stack) in &rows {
        println!(
            "  {:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}  {}",
            seq,
            ts,
            op,
            loc,
            stack,
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2],
            w3 = widths[3],
        );
    }
}

/// Width per column = max(header, max cell width).
fn column_widths(
    rows: &[(String, String, String, String, String)],
    headers: &[&str; 5],
) -> [usize; 5] {
    let mut w = [0usize; 5];
    for (i, h) in headers.iter().enumerate() {
        w[i] = h.chars().count();
    }
    for (a, b, c, d, e) in rows {
        w[0] = w[0].max(a.chars().count());
        w[1] = w[1].max(b.chars().count());
        w[2] = w[2].max(c.chars().count());
        w[3] = w[3].max(d.chars().count());
        w[4] = w[4].max(e.chars().count());
    }
    w
}

/// Vector of byte offsets at which each line starts. Index 0 is 0
/// (start of file); subsequent entries are byte offsets just past each
/// '\n'. Lets `byte_offset_to_line_col` binary-search a span back to
/// a (line, col) pair.
fn build_line_starts(source: &str) -> Vec<usize> {
    let mut out = vec![0usize];
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            out.push(i + 1);
        }
    }
    out
}

/// 1-based (line, col) for a byte offset. Col is measured in bytes
/// from the start of the line (matches what `ariadne` does, which is
/// what the rest of the diagnostics already show).
fn byte_offset_to_line_col(line_starts: &[usize], offset: usize) -> (usize, usize) {
    // Find the last line_start that is <= offset.
    let idx = match line_starts.binary_search(&offset) {
        Ok(i) => i,
        Err(i) => i.saturating_sub(1),
    };
    let line = idx + 1;
    let col = offset - line_starts[idx] + 1;
    (line, col)
}

/// Convert micros-since-unix-epoch into "YYYY-MM-DDTHH:MM:SS.uuuuuuZ".
/// No dependency on `chrono` or `time` — the audit timestamp is a
/// small surface and we already control the format on the writer side.
fn format_iso8601_utc(ts_micros: i64) -> String {
    if ts_micros < 0 {
        return "(pre-epoch)".to_string();
    }
    let total_secs = ts_micros / 1_000_000;
    let micros = (ts_micros % 1_000_000) as u32;
    let secs_in_day = (total_secs % 86_400) as u32;
    let days_since_epoch = total_secs / 86_400;
    let (hour, rem) = (secs_in_day / 3600, secs_in_day % 3600);
    let (minute, second) = (rem / 60, rem % 60);
    let (y, mo, d) = days_since_epoch_to_ymd(days_since_epoch);
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z",)
}

/// Convert days since 1970-01-01 to (year, month, day), Gregorian.
/// Algorithm from Hinnant's date library (public domain), adapted.
fn days_since_epoch_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// Render the recorded top-of-stack types as a bracketed list, with
/// the actual depth appended when more slots existed than were
/// captured (e.g. `[INT, INT, INT, INT, ...] depth=12`).
fn format_stack_shape(top_types: &[anal_core::LedgerTypeTag], depth: u32) -> String {
    let names: Vec<&str> = top_types.iter().map(|t| t.name()).collect();
    let depth = depth as usize;
    if depth == top_types.len() {
        format!("[{}]", names.join(", "))
    } else {
        format!("[{}, ...] depth={depth}", names.join(", "))
    }
}

/// Walk `program` and collect every loggable op's span, paired with
/// its ledger tag. The audit uses this to confirm each ledger record's
/// (span, op) matches the source. Covers both destructive ops (always
/// loggable) and arming ops (only loggable under `--ledger-verbose`,
/// but the audit doesn't know which mode produced the ledger, so it
/// accepts either).
fn collect_loggable_ops(program: &Program) -> HashMap<Span, LedgerOpTag> {
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
            // Destructive (always logged).
            Op::Insert { .. } => Some(LedgerOpTag::Insert),
            Op::Extract(_) => Some(LedgerOpTag::Extract),
            Op::Flush => Some(LedgerOpTag::Flush),
            Op::Bufset => Some(LedgerOpTag::Bufset),
            Op::Store(_) => Some(LedgerOpTag::Store),
            Op::Evacuate(_) => Some(LedgerOpTag::EvacuateOverwrite),
            // Arming (only present under --ledger-verbose).
            Op::Prep => Some(LedgerOpTag::Prep),
            Op::Consent => Some(LedgerOpTag::Consent),
            Op::Clench => Some(LedgerOpTag::Clench),
            Op::Release => Some(LedgerOpTag::Release),
            Op::Relax => Some(LedgerOpTag::Relax),
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
