//! # Interactive REPL
//!
//! A line-at-a-time front end for the ANAL interpreter. The REPL
//! parses, type-checks, and runs each fragment against state that
//! persists across lines — a single [`Session`] for the abstract
//! stack and passage table, a single [`VM`] for the runtime stack
//! and consent latches.
//!
//! Multi-line constructs (`PASSAGE`/`EXIT`, `[`/`]`, `DILATE`/
//! `CONSTRICT`) are detected by counting opens and closes; if a
//! line leaves anything unbalanced, the prompt switches to a
//! continuation form (`....>`) and reads more input until the
//! buffer is syntactically complete.
//!
//! Meta-commands begin with `:` to keep them unambiguously distinct
//! from ANAL syntax — see [`META_HELP`] for the list.
//!
//! Errors are rendered through the existing `ariadne`-based reporter
//! (one fragment per source id), and any fragment that fails to
//! parse, fails to check, or errors mid-execution leaves the
//! session's *abstract* stack untouched. The runtime stack reflects
//! whatever the VM actually did before the error fired.
//!
//! The loop is split in two for testability: [`ReplState`] holds
//! everything that persists between lines and exposes a synchronous
//! [`ReplState::feed_line`] method that takes a single input line
//! and a writer; [`run`] wraps that with `rustyline` for terminal
//! use. Tests drive `ReplState` directly.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use anal_core::check::Ty;
use anal_core::{is_unfinished, AnalError, Session, VM};
use rustyline::error::ReadlineError;
use rustyline::{Config, DefaultEditor};

use crate::Flags;

const BANNER_TITLE: &str = concat!(
    "ANAL v",
    env!("CARGO_PKG_VERSION"),
    " — interactive session."
);
const BANNER_BODY: &str = "\
The stack persists. PASSAGEs persist. Latches persist.
Type `:help` for guidance, `:reset` to clear the stack, or `:quit` to leave.";

const PROMPT_MAIN: &str = "anal> ";
const PROMPT_CONT: &str = "....> ";

const META_HELP: &str = "\
Meta-commands (type them at the prompt, with the leading colon):

  :help, :?       Show this message.
  :stack, :s      Print the current runtime stack.
  :shape          Print the abstract (type) stack — what the checker sees.
  :passages       List all defined passages.
  :reset          Clear the stack, latches, and every defined passage.
  :load <FILE>    Read a file and execute it in this session.
  :quit, :q       Leave the session. Ctrl-D also exits.

Anything not beginning with `:` is parsed as ANAL.
Multi-line constructs (PASSAGE/EXIT, DILATE/CONSTRICT, [ ]) are
detected automatically; the prompt becomes `....>` until the
construct closes.

ANAL does not explain. It permits.";

/// Outcome of [`ReplState::feed_line`] — tells the driver whether to
/// keep reading, switch to the continuation prompt, or exit.
#[derive(Debug, PartialEq, Eq)]
pub enum LineOutcome {
    /// The line was processed (or rejected). Show the main prompt
    /// next.
    Ready,
    /// The line opened or extended a multi-line construct. Show the
    /// continuation prompt and read another line.
    Continued,
    /// User asked to quit (`:quit`, `:q`, `:exit`).
    Quit,
}

/// All REPL state that persists between input lines.
pub struct ReplState {
    pub session: Session,
    pub vm: VM,
    pub flags: Flags,
    /// Accumulated source for an in-progress multi-line construct.
    /// Empty when the next line will start a fresh fragment.
    pub buffer: String,
    /// Number of fragments processed — used as a stable id when
    /// rendering errors so the diagnostic header is unique per
    /// fragment.
    pub fragment_no: usize,
}

impl ReplState {
    pub fn new(flags: Flags) -> Self {
        Self {
            session: Session::new(),
            vm: VM::new(),
            flags,
            buffer: String::new(),
            fragment_no: 0,
        }
    }

    /// Process one line of REPL input. Writes any output to `out`,
    /// any error to `err`. Returns what the driver should do next.
    pub fn feed_line<W1: Write, W2: Write>(
        &mut self,
        line: &str,
        out: &mut W1,
        err: &mut W2,
    ) -> LineOutcome {
        // Meta-commands and empty lines are only meaningful at the
        // start of a fragment. Mid-block, the colon would have to
        // parse as ANAL (which it cannot), so we let it through and
        // let the parser report it.
        if self.buffer.is_empty() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return LineOutcome::Ready;
            }
            if let Some(meta) = parse_meta(trimmed, err) {
                return self.handle_meta(meta, out, err);
            }
        }

        if !self.buffer.is_empty() {
            self.buffer.push('\n');
        }
        self.buffer.push_str(line);

        if is_unfinished(&self.buffer) {
            return LineOutcome::Continued;
        }

        let source = std::mem::take(&mut self.buffer);
        self.fragment_no += 1;
        let source_id = format!("<repl:{}>", self.fragment_no);
        self.run_fragment(&source, &source_id, out, err);
        LineOutcome::Ready
    }

    /// The prompt the driver should show next.
    pub fn prompt(&self) -> String {
        if !self.buffer.is_empty() {
            return PROMPT_CONT.to_string();
        }
        let mut tags = Vec::new();
        if self.vm.prep_armed() {
            tags.push("PREP".to_string());
        }
        if self.vm.consent_armed() {
            tags.push("CONSENT".to_string());
        }
        let depth = self.vm.clench_depth();
        if depth == 1 {
            tags.push("CLENCH".to_string());
        } else if depth > 1 {
            tags.push(format!("CLENCHx{depth}"));
        }
        if tags.is_empty() {
            PROMPT_MAIN.to_string()
        } else {
            format!("anal ({})> ", tags.join(" "))
        }
    }

    /// Clear an in-progress multi-line buffer. Used by the driver
    /// on Ctrl-C.
    pub fn cancel_buffer(&mut self) -> bool {
        let had_buffer = !self.buffer.is_empty();
        self.buffer.clear();
        had_buffer
    }

    /// Compile, check, and execute a fragment. Renders any error;
    /// success prints the resulting runtime stack (unless `--quiet`).
    ///
    /// `out` receives both the program's `EXPEL`/`DISCHARGE` output
    /// and the post-fragment stack summary; `err` receives `PROBE`
    /// output and any rendered error. In the rustyline driver these
    /// are the process stdout/stderr; in tests they are buffers.
    fn run_fragment<W1: Write, W2: Write>(
        &mut self,
        source: &str,
        source_id: &str,
        out: &mut W1,
        err: &mut W2,
    ) {
        // The sticky ABORT flag from a previous fragment would
        // silently kill this one — clear it before each fragment so
        // each line gets a fair shot.
        self.vm.clear_abort();

        let program = match self.session.feed(source) {
            Ok(p) => p,
            Err(e) => {
                render_error(source_id, source, &e, self.flags, err);
                return;
            }
        };

        // Use the pluggable-I/O path (`run`, not `execute`) so the
        // REPL controls where program output goes. `RECEIVE` and
        // bare `HOLD` still read from the real stdin — the user
        // typing into the prompt is the natural input source.
        let stdin = std::io::stdin();
        let mut input = std::io::BufReader::new(stdin.lock());
        if let Err(e) = self.vm.run(&program, &mut input, out, err) {
            render_error(source_id, source, &e, self.flags, err);
            return;
        }

        if !self.flags.quiet {
            print_stack(self.vm.stack(), out);
        }
    }

    fn handle_meta<W1: Write, W2: Write>(
        &mut self,
        meta: Meta,
        out: &mut W1,
        err: &mut W2,
    ) -> LineOutcome {
        match meta {
            Meta::Help => {
                let _ = writeln!(out, "{META_HELP}");
            }
            Meta::Quit => return LineOutcome::Quit,
            Meta::Stack => print_stack(self.vm.stack(), out),
            Meta::Shape => print_shape(self.session.stack_shape(), out),
            Meta::Passages => {
                let names = self.session.passage_names();
                if names.is_empty() {
                    let _ = writeln!(out, "(no passages defined)");
                } else {
                    for name in names {
                        let _ = writeln!(out, "PASSAGE {name}");
                    }
                }
            }
            Meta::Reset => {
                self.session.reset();
                self.vm.reset();
                let _ = writeln!(out, "(session reset)");
            }
            Meta::Load(path) => match std::fs::read_to_string(&path) {
                Ok(source) => {
                    self.fragment_no += 1;
                    let source_id = path.display().to_string();
                    self.run_fragment(&source, &source_id, out, err);
                }
                Err(e) => {
                    let _ = writeln!(err, "EVACUATE: cannot INGEST {} — {e}.", path.display());
                }
            },
        }
        LineOutcome::Ready
    }
}

// ── Rustyline driver ──────────────────────────────────────────

/// Run the REPL until the user quits or stdin closes.
///
/// This is the rustyline wrapper around [`ReplState`]. The logic
/// lives in [`ReplState::feed_line`]; this function just supplies
/// line editing, history, and the print loop.
pub fn run(flags: Flags) -> anyhow::Result<()> {
    print_banner();

    let config = Config::builder().auto_add_history(true).build();
    let mut editor = DefaultEditor::with_config(config)?;
    let history_path = history_file_path();
    if let Some(path) = history_path.as_ref() {
        // Loading history is best-effort — a missing file is fine
        // on first run, and a malformed one is not worth crashing
        // the REPL over.
        let _ = editor.load_history(path);
    }

    let mut state = ReplState::new(flags);
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    loop {
        let prompt = state.prompt();
        match editor.readline(&prompt) {
            Ok(line) => {
                let mut out = stdout.lock();
                let mut err = stderr.lock();
                match state.feed_line(&line, &mut out, &mut err) {
                    LineOutcome::Ready | LineOutcome::Continued => {}
                    LineOutcome::Quit => break,
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C — abandon any partial buffer, show the
                // prompt again. Matches Python's behaviour; quitting
                // is explicit, via :quit or EOF.
                if state.cancel_buffer() {
                    eprintln!("(input cleared)");
                } else {
                    eprintln!("(type `:quit` to leave)");
                }
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => return Err(e.into()),
        }
    }

    if let Some(path) = history_path.as_ref() {
        let _ = editor.save_history(path);
    }
    println!("EXIT");
    Ok(())
}

fn print_banner() {
    println!("{BANNER_TITLE}");
    println!("{BANNER_BODY}");
    println!();
}

// ── Output helpers ────────────────────────────────────────────

/// Print the runtime stack on one line. Long stacks are abbreviated
/// in the middle so the REPL output stays scannable.
fn print_stack<W: Write>(stack: &[anal_core::Value], out: &mut W) {
    if stack.is_empty() {
        let _ = writeln!(out, "[]");
        return;
    }
    const MAX_SHOWN: usize = 8;
    let rendered: Vec<String> = if stack.len() <= MAX_SHOWN {
        stack.iter().map(|v| format!("{v}")).collect()
    } else {
        let head_count = MAX_SHOWN / 2;
        let tail_count = MAX_SHOWN - head_count - 1;
        let elided = stack.len() - head_count - tail_count;
        let head = stack.iter().take(head_count).map(|v| format!("{v}"));
        let tail = stack
            .iter()
            .skip(stack.len() - tail_count)
            .map(|v| format!("{v}"));
        head.chain(std::iter::once(format!("… ({elided} more)")))
            .chain(tail)
            .collect()
    };
    let _ = writeln!(out, "[{}]", rendered.join(", "));
}

fn print_shape<W: Write>(shape: &[Ty], out: &mut W) {
    if shape.is_empty() {
        let _ = writeln!(out, "[]");
        return;
    }
    let names: Vec<&str> = shape.iter().map(ty_name).collect();
    let _ = writeln!(out, "[{}]", names.join(", "));
}

fn ty_name(t: &Ty) -> &'static str {
    match t {
        Ty::Int => "INT",
        Ty::Float => "FLOAT",
        Ty::Str => "STRING",
        Ty::Bool => "BOOL",
        Ty::Bloc => "BLOC",
        Ty::Top => "<any>",
    }
}

fn render_error<W: Write>(
    source_id: &str,
    source: &str,
    err: &AnalError,
    flags: Flags,
    sink: &mut W,
) {
    let stderr = std::io::stderr();
    let color = crate::use_color(stderr.is_terminal(), flags);
    if err.render(source_id, source, color, sink).is_err() {
        let _ = writeln!(sink, "error[{code}]: {err}", code = err.code());
    }
}

// ── Meta-command parsing ──────────────────────────────────────

enum Meta {
    Help,
    Quit,
    Stack,
    Shape,
    Passages,
    Reset,
    Load(PathBuf),
}

fn parse_meta<W: Write>(line: &str, err: &mut W) -> Option<Meta> {
    if !line.starts_with(':') {
        return None;
    }
    let mut parts = line[1..].splitn(2, char::is_whitespace);
    let cmd = parts.next()?;
    let rest = parts.next().map(str::trim).unwrap_or("");
    Some(match cmd {
        "help" | "?" => Meta::Help,
        "quit" | "q" | "exit" => Meta::Quit,
        "stack" | "s" => Meta::Stack,
        "shape" => Meta::Shape,
        "passages" => Meta::Passages,
        "reset" => Meta::Reset,
        "load" => {
            if rest.is_empty() {
                let _ = writeln!(err, ":load expects a file path");
                Meta::Help
            } else {
                Meta::Load(PathBuf::from(rest))
            }
        }
        other => {
            let _ = writeln!(err, "unknown meta-command `:{other}` (try `:help`)");
            Meta::Help
        }
    })
}

// ── History file location ─────────────────────────────────────

/// Resolve the path used for command history persistence.
///
/// Prefers `$ANAL_HISTORY` if set. Otherwise falls back to
/// `$HOME/.anal_history` on Unix-likes and
/// `%USERPROFILE%/.anal_history` on Windows. Returns `None` if
/// neither is available — in which case history simply doesn't
/// persist between sessions.
fn history_file_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ANAL_HISTORY") {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    Some(PathBuf::from(home).join(".anal_history"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_flags() -> Flags {
        Flags {
            quiet: false,
            verbose: false,
            no_color: true,
        }
    }

    /// Drive a sequence of input lines and collect stdout. Returns
    /// (final state, stdout-as-string, stderr-as-string).
    fn drive(lines: &[&str]) -> (ReplState, String, String) {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        for line in lines {
            state.feed_line(line, &mut out, &mut err);
        }
        (
            state,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn empty_line_is_a_no_op() {
        let (state, out, err) = drive(&[""]);
        assert_eq!(out, "");
        assert_eq!(err, "");
        assert!(state.session.stack_shape().is_empty());
    }

    #[test]
    fn simple_arithmetic_prints_stack() {
        let (_state, out, _err) = drive(&["PUSH 1", "PUSH 2", "ADD"]);
        // Each line prints the stack after running.
        assert_eq!(out, "[1]\n[1, 2]\n[3]\n");
    }

    #[test]
    fn discharge_prints_value_and_leaves_stack_empty() {
        let (_state, out, _err) = drive(&["PUSH 42", "DISCHARGE"]);
        // PUSH 42 → "[42]\n"; DISCHARGE → "42\n[]\n"
        assert_eq!(out, "[42]\n42\n[]\n");
    }

    #[test]
    fn multiline_passage_continues_until_exit() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();

        let r1 = state.feed_line("PASSAGE square:", &mut out, &mut err);
        assert_eq!(r1, LineOutcome::Continued);
        let r2 = state.feed_line("  DUP MUL", &mut out, &mut err);
        assert_eq!(r2, LineOutcome::Continued);
        let r3 = state.feed_line("EXIT", &mut out, &mut err);
        assert_eq!(r3, LineOutcome::Ready);

        // Passage definition itself produces no main bytecode, so no
        // stack output is printed.
        assert_eq!(String::from_utf8(out.clone()).unwrap(), "[]\n");
        assert_eq!(state.session.passage_names(), vec!["square"]);

        // Now invoke it.
        state.feed_line("PUSH 9 ENTER square", &mut out, &mut err);
        let combined = String::from_utf8(out).unwrap();
        assert!(combined.ends_with("[81]\n"), "got: {combined:?}");
    }

    #[test]
    fn multiline_bloc_continues_until_close() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let r1 = state.feed_line("PUSH 1 IF_TIGHT [", &mut out, &mut err);
        assert_eq!(r1, LineOutcome::Continued);
        let r2 = state.feed_line("PUSH \"yes\" DISCHARGE", &mut out, &mut err);
        assert_eq!(r2, LineOutcome::Continued);
        let r3 = state.feed_line("]", &mut out, &mut err);
        assert_eq!(r3, LineOutcome::Ready);
        let combined = String::from_utf8(out).unwrap();
        assert!(combined.contains("yes\n"), "got: {combined:?}");
    }

    #[test]
    fn type_error_leaves_session_untouched() {
        let (state, out, err) = drive(&["PUSH 1 PUSH 2", "PUSH \"hi\" ADD"]);
        // First line succeeds; second line is a static MISMATCH.
        assert!(out.starts_with("[1, 2]\n"));
        assert!(err.contains("MISMATCH"), "stderr: {err:?}");
        // Session state should reflect the *first* line only — the
        // bad fragment is rejected before it can disturb the stack.
        assert_eq!(state.session.stack_shape().len(), 2);
    }

    #[test]
    fn quit_returns_quit_outcome() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let r = state.feed_line(":quit", &mut out, &mut err);
        assert_eq!(r, LineOutcome::Quit);
    }

    #[test]
    fn quit_aliases() {
        for cmd in &[":q", ":quit", ":exit"] {
            let mut state = ReplState::new(no_flags());
            let mut out = Vec::new();
            let mut err = Vec::new();
            let r = state.feed_line(cmd, &mut out, &mut err);
            assert_eq!(r, LineOutcome::Quit, "alias `{cmd}` did not quit");
        }
    }

    #[test]
    fn reset_clears_both_session_and_vm() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        state.feed_line("PASSAGE p: PUSH 1 EXIT", &mut out, &mut err);
        state.feed_line("PUSH 5", &mut out, &mut err);
        state.feed_line(":reset", &mut out, &mut err);
        assert!(state.session.passage_names().is_empty());
        assert!(state.session.stack_shape().is_empty());
        assert!(state.vm.stack().is_empty());
    }

    #[test]
    fn passages_meta_lists_defined_passages() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        state.feed_line("PASSAGE a: PUSH 1 EXIT", &mut out, &mut err);
        state.feed_line("PASSAGE b: PUSH 2 EXIT", &mut out, &mut err);
        out.clear();
        state.feed_line(":passages", &mut out, &mut err);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("PASSAGE a"));
        assert!(s.contains("PASSAGE b"));
    }

    #[test]
    fn unknown_meta_command_reports_and_continues() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        let r = state.feed_line(":nopelimit", &mut out, &mut err);
        assert_eq!(r, LineOutcome::Ready);
        let err_s = String::from_utf8(err).unwrap();
        assert!(err_s.contains("unknown meta-command"));
    }

    #[test]
    fn prompt_reflects_latch_state() {
        let mut state = ReplState::new(no_flags());
        assert_eq!(state.prompt(), "anal> ");

        let mut out = Vec::new();
        let mut err = Vec::new();
        state.feed_line("PREP", &mut out, &mut err);
        assert_eq!(state.prompt(), "anal (PREP)> ");

        state.feed_line("RELAX", &mut out, &mut err);
        assert_eq!(state.prompt(), "anal> ");

        state.feed_line("CONSENT CLENCH", &mut out, &mut err);
        assert_eq!(state.prompt(), "anal (CONSENT CLENCH)> ");
    }

    #[test]
    fn prompt_shows_continuation_when_mid_block() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        state.feed_line("PASSAGE p:", &mut out, &mut err);
        assert_eq!(state.prompt(), "....> ");
        state.feed_line("EXIT", &mut out, &mut err);
        assert_eq!(state.prompt(), "anal> ");
    }

    #[test]
    fn cancel_buffer_returns_true_when_mid_block() {
        let mut state = ReplState::new(no_flags());
        let mut out = Vec::new();
        let mut err = Vec::new();
        state.feed_line("PASSAGE p:", &mut out, &mut err);
        assert!(state.cancel_buffer());
        assert_eq!(state.prompt(), "anal> ");
    }

    #[test]
    fn cancel_buffer_returns_false_when_idle() {
        let mut state = ReplState::new(no_flags());
        assert!(!state.cancel_buffer());
    }

    #[test]
    fn abort_in_one_fragment_does_not_kill_session() {
        // ABORT sets the sticky aborted flag. Without clear_abort
        // between fragments, the next line would silently no-op.
        let (state, out, _err) = drive(&["PUSH 1 DISCHARGE ABORT", "PUSH 2 DISCHARGE"]);
        // First line: "1\n[]\n" (DISCHARGE, then empty stack, then ABORT)
        // Second line: "2\n[]\n" (must run, proving abort was cleared)
        assert!(out.contains("\n2\n"), "second line did not run: {out:?}");
        assert_eq!(state.session.stack_shape().len(), 0);
    }
}
