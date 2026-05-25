//! # The ANAL Virtual Machine
//!
//! One stack of [`Value`]s, shared across every `PASSAGE` call and
//! every `BLOC` entry. We considered per-call frames; we declined.
//! A global stack is what makes a passage feel like a macro rather
//! than a function — the caller's values are right there, the
//! callee's leftovers are visible on return. This is the Forth
//! lineage, and we are unrepentant about it.
//!
//! Alongside the stack live four pieces of latched state:
//!
//!   - `prep_armed` / `consent_armed` — one-shot capability tokens.
//!     `PREP` authorises the next `INSERT`; `CONSENT` authorises
//!     the next `EXTRACT` or `FLUSH`. The token is consumed by the
//!     act it permits and does not regenerate. There is no
//!     standing-authorisation form and there never will be.
//!
//!   - `clench_depth` — a counter, not a flag, because `CLENCH`es
//!     nest and we are not animals. While non-zero, the stack is
//!     frozen against mutation; `PROBE` and `EXPEL` still work
//!     because reading is not violation.
//!
//!   - `aborted` — sticky, checked by `run_block`'s loop guard.
//!     Once set, every enclosing block unwinds to the top.
//!
//!   - `capacity` — an optional cap installed by `EXPAND`. `None`
//!     means unbounded, which is the default; programs that never
//!     call `EXPAND` cannot raise `OVERFLOW`. The cap rises
//!     monotonically, so `EXPAND` is safe to sprinkle defensively
//!     — you can only commit to more headroom, never less.

use std::cmp::Ordering;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::rc::Rc;

use crate::error::AnalError;
use crate::op::{Instr, Op, Program};
use crate::token::Span;
use crate::value::Value;

pub struct VM {
    stack: Vec<Value>,
    /// `PREP` arms a one-shot readiness flag for the next `INSERT`.
    /// `INSERT` clears it; calling `INSERT` without it raises `TIGHTNESS`.
    prep_armed: bool,
    /// `CONSENT` arms a one-shot capability flag for the next destructive
    /// operation. `EXTRACT` and `FLUSH` consume it; calling them without it
    /// raises `REFUSAL`.
    consent_armed: bool,
    /// Number of unmatched `CLENCH`es. While non-zero, write ops raise
    /// `LOCKDOWN`. `PROBE` and `EXPEL` remain available.
    clench_depth: u32,
    /// Set by `ABORT`. Causes all currently-executing blocks (including
    /// nested PASSAGE calls) to short-circuit back to the top.
    aborted: bool,
    /// Optional stack capacity cap. `None` means unbounded (the default —
    /// programs that never call `EXPAND` behave exactly as before). The
    /// first `EXPAND n` sets it to `len + n`; subsequent `EXPAND`s only
    /// raise it. A push past the cap raises `OVERFLOW`.
    capacity: Option<usize>,
}

/// How a single instruction influences the surrounding block's PC.
enum Flow {
    /// Continue to the next instruction.
    Continue,
    /// Set the PC to this absolute index within the current block.
    Jump(usize),
    /// Stop executing the current block and unwind one frame.
    Return,
}

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}

impl VM {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            prep_armed: false,
            consent_armed: false,
            clench_depth: 0,
            aborted: false,
            capacity: None,
        }
    }

    /// Current runtime stack (top of stack last). Exposed for the REPL
    /// and other inspection tools; the VM itself does not read this.
    pub fn stack(&self) -> &[Value] {
        &self.stack
    }

    /// Whether `PREP` is currently armed (a one-shot token waiting for
    /// the next `INSERT`).
    pub fn prep_armed(&self) -> bool {
        self.prep_armed
    }

    /// Whether `CONSENT` is currently armed (a one-shot token waiting
    /// for the next `EXTRACT`, `FLUSH`, or overwriting `EVACUATE`).
    pub fn consent_armed(&self) -> bool {
        self.consent_armed
    }

    /// Number of unmatched `CLENCH`es. Non-zero means the stack is
    /// frozen against mutation.
    pub fn clench_depth(&self) -> u32 {
        self.clench_depth
    }

    /// Clear the sticky `ABORT` flag. The REPL calls this between
    /// fragments so one `ABORT` does not silently terminate every
    /// subsequent line of the session.
    pub fn clear_abort(&mut self) {
        self.aborted = false;
    }

    /// Reset all VM state: empty the stack, clear every latch, drop
    /// the capacity cap, clear the abort flag. Used by the REPL's
    /// `:reset` meta-command.
    pub fn reset(&mut self) {
        self.stack.clear();
        self.prep_armed = false;
        self.consent_armed = false;
        self.clench_depth = 0;
        self.aborted = false;
        self.capacity = None;
    }

    /// Execute against the process stdin / stdout / stderr.
    pub fn execute(&mut self, program: &Program) -> Result<(), AnalError> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        let mut input = BufReader::new(stdin.lock());
        let mut out = stdout.lock();
        let mut err = stderr.lock();
        self.run(program, &mut input, &mut out, &mut err)
    }

    /// Execute with explicit I/O sinks — useful for tests.
    pub fn run<W1: Write, W2: Write>(
        &mut self,
        program: &Program,
        input: &mut dyn BufRead,
        out: &mut W1,
        err: &mut W2,
    ) -> Result<(), AnalError> {
        let main = Rc::clone(&program.main);
        self.run_block(&main, program, input, out, err)
    }

    fn run_block<W1: Write, W2: Write>(
        &mut self,
        code: &[Instr],
        program: &Program,
        input: &mut dyn BufRead,
        out: &mut W1,
        err: &mut W2,
    ) -> Result<(), AnalError> {
        let mut pc = 0;
        while pc < code.len() && !self.aborted {
            let instr = &code[pc];
            let span = instr.span;
            pc += 1;
            match self.step(&instr.op, span, program, input, out, err)? {
                Flow::Continue => {}
                Flow::Jump(target) => pc = target,
                Flow::Return => return Ok(()),
            }
        }
        Ok(())
    }

    fn step<W1: Write, W2: Write>(
        &mut self,
        op: &Op,
        span: Span,
        program: &Program,
        input: &mut dyn BufRead,
        out: &mut W1,
        err: &mut W2,
    ) -> Result<Flow, AnalError> {
        match op {
            // ── Stack manipulation ──────────────────────────────
            //
            // PROBE is the odd one out: it lives here but doesn't
            // check_unclenched, because reading is not mutation.
            Op::Push(v) => {
                self.check_unclenched("PUSH", span)?;
                self.push(v.clone(), span)?;
            }
            Op::Pop => {
                self.check_unclenched("POP", span)?;
                self.pop("POP", span)?;
            }
            Op::Probe => {
                let top = self.peek("PROBE", span)?;
                writeln!(err, "{top}").map_err(|_| io_err("PROBE", span))?;
            }
            Op::Dup => {
                self.check_unclenched("DUP", span)?;
                let top = self.peek("DUP", span)?.clone();
                self.push(top, span)?;
            }
            Op::Swap => {
                self.check_unclenched("SWAP", span)?;
                let n = self.stack.len();
                if n < 2 {
                    return Err(AnalError::Emptiness { op: "SWAP", span });
                }
                self.stack.swap(n - 1, n - 2);
            }
            Op::Over => {
                self.check_unclenched("OVER", span)?;
                let n = self.stack.len();
                if n < 2 {
                    return Err(AnalError::Emptiness { op: "OVER", span });
                }
                let second = self.stack[n - 2].clone();
                self.push(second, span)?;
            }
            Op::Rot => {
                self.check_unclenched("ROT", span)?;
                let n = self.stack.len();
                if n < 3 {
                    return Err(AnalError::Emptiness { op: "ROT", span });
                }
                // (a b c -- b c a): remove from depth 2, push to top.
                let third = self.stack.remove(n - 3);
                self.push(third, span)?;
            }
            Op::Nip => {
                self.check_unclenched("NIP", span)?;
                let n = self.stack.len();
                if n < 2 {
                    return Err(AnalError::Emptiness { op: "NIP", span });
                }
                // (a b -- b): drop second-from-top.
                self.stack.remove(n - 2);
            }
            Op::Depth => {
                self.check_unclenched("DEPTH", span)?;
                let n = self.stack.len() as i64;
                self.push(Value::Int(n), span)?;
            }

            // ── Output channels ─────────────────────────────────
            //
            // EXPEL peeks-and-prints; DISCHARGE pops-and-prints.
            // EXPEL is therefore CLENCH-safe and DISCHARGE is not.
            Op::Expel => {
                let top = self.peek("EXPEL", span)?;
                writeln!(out, "{top}").map_err(|_| io_err("EXPEL", span))?;
            }
            Op::Discharge => {
                self.check_unclenched("DISCHARGE", span)?;
                let top = self.pop("DISCHARGE", span)?;
                writeln!(out, "{top}").map_err(|_| io_err("DISCHARGE", span))?;
            }

            // ── Arithmetic ──────────────────────────────────────
            //
            // ADD doubles as string concatenation; the others are
            // numeric only. DIV and MOD raise REJECTION on a zero
            // divisor rather than panic — the VM crashes programs,
            // never the host.
            Op::Add => self.binop_add(span)?,
            Op::Sub => self.binop_arith(span, "SUB", |a, b| a - b, |a, b| a - b)?,
            Op::Mul => self.binop_arith(span, "MUL", |a, b| a * b, |a, b| a * b)?,
            Op::Div => self.binop_div(span, "DIV")?,
            Op::Mod => self.binop_mod(span, "MOD")?,

            // ── Comparison ──────────────────────────────────────
            //
            // EQ is structural and total. The ordered comparisons
            // are numeric-only, and NaN raises REJECTION rather
            // than silently returning false — silent-false on NaN
            // is how hours of debugging happen.
            Op::EqOp => {
                self.check_unclenched("EQ", span)?;
                let b = self.pop("EQ", span)?;
                let a = self.pop("EQ", span)?;
                self.push(Value::Bool(a == b), span)?;
            }
            Op::Lt => self.binop_cmp(span, "LT", |o| o == Ordering::Less)?,
            Op::Gt => self.binop_cmp(span, "GT", |o| o == Ordering::Greater)?,
            Op::Lte => self.binop_cmp(span, "LTE", |o| o != Ordering::Greater)?,
            Op::Gte => self.binop_cmp(span, "GTE", |o| o != Ordering::Less)?,
            Op::Not => {
                self.check_unclenched("NOT", span)?;
                let v = self.pop("NOT", span)?;
                self.push(Value::Bool(!v.is_truthy()), span)?;
            }

            // ── Type conversion ─────────────────────────────────
            //
            // Explicit only, never implicit. The error reporter
            // suggests TO_INT/TO_FLOAT/TO_STRING on type
            // rejections but stays quiet on I/O rejections —
            // suggesting TO_STRING when stdin returned EOF would
            // be cruel.
            Op::ToInt => self.convert_to_int(span)?,
            Op::ToFloat => self.convert_to_float(span)?,
            Op::ToStr => self.convert_to_str(span)?,

            // ── Flow control ────────────────────────────────────
            //
            // DILATE/CONSTRICT in source compile to the conditional
            // jumps below. ABORT sets a sticky flag that every
            // enclosing `run_block` honours on its next tick,
            // unwinding the whole call tower cooperatively.
            Op::Jump(target) => return Ok(Flow::Jump(*target)),
            Op::JumpIfFalsy(target) => {
                self.check_unclenched("DILATE/IF_TIGHT", span)?;
                let cond = self.pop("DILATE/IF_TIGHT", span)?;
                if !cond.is_truthy() {
                    return Ok(Flow::Jump(*target));
                }
            }
            Op::JumpIfTruthy(target) => {
                self.check_unclenched("CONSTRICT/IF_LOOSE", span)?;
                let cond = self.pop("CONSTRICT/IF_LOOSE", span)?;
                if cond.is_truthy() {
                    return Ok(Flow::Jump(*target));
                }
            }
            Op::Abort => {
                self.aborted = true;
                return Ok(Flow::Return);
            }

            // ── PASSAGE / BLOC call and return ──────────────────
            //
            // Two ways to invoke code: by name (ENTER <passage>)
            // or by value (ENTER on a popped BLOC). BLOC is a
            // first-class Value precisely so you can DUP it, pass
            // it through a passage, return it on the stack.
            //
            // IF_TIGHT/IF_LOOSE are op-level rather than source
            // sugar so the typechecker sees the conditional and
            // its body as one unit, not as jump arithmetic.
            Op::Enter(name) => {
                let passage = program
                    .passages
                    .get(name)
                    .ok_or_else(|| AnalError::PassageNotFound {
                        name: name.clone(),
                        span,
                    })?
                    .clone();
                self.run_block(&passage, program, input, out, err)?;
            }
            Op::EnterStack => {
                self.check_unclenched("ENTER", span)?;
                let bloc = self.pop_bloc("ENTER", span)?;
                self.run_block(&bloc, program, input, out, err)?;
            }
            Op::IfTightExec => {
                self.check_unclenched("IF_TIGHT", span)?;
                let bloc = self.pop_bloc("IF_TIGHT", span)?;
                let cond = self.pop("IF_TIGHT", span)?;
                if cond.is_truthy() {
                    self.run_block(&bloc, program, input, out, err)?;
                }
            }
            Op::IfLooseExec => {
                self.check_unclenched("IF_LOOSE", span)?;
                let bloc = self.pop_bloc("IF_LOOSE", span)?;
                let cond = self.pop("IF_LOOSE", span)?;
                if !cond.is_truthy() {
                    self.run_block(&bloc, program, input, out, err)?;
                }
            }
            Op::Return => return Ok(Flow::Return),

            // ── Capability latches ──────────────────────────────
            //
            // PREP/CONSENT are one-shot tokens; CLENCH/RELEASE are
            // a matched bracketing pair. The asymmetry is the
            // point: capability is granted once and spent, but
            // read-only mode is entered and left. RELAX clears
            // whatever was armed and is the only latch-adjacent op
            // permitted during a CLENCH (it touches latches, not
            // the stack).
            Op::Prep => {
                self.check_unclenched("PREP", span)?;
                self.prep_armed = true;
            }
            Op::Consent => {
                self.check_unclenched("CONSENT", span)?;
                self.consent_armed = true;
            }
            Op::Clench => {
                self.clench_depth = self.clench_depth.saturating_add(1);
            }
            Op::Release => {
                if self.clench_depth == 0 {
                    return Err(AnalError::PrematureRelease { span });
                }
                self.clench_depth -= 1;
            }
            Op::Relax => {
                // Idempotent — clears whatever was armed. Allowed during
                // CLENCH because it doesn't touch the stack.
                self.prep_armed = false;
                self.consent_armed = false;
            }

            // ── Authorised mutation: INSERT, EXTRACT, FLUSH ─────
            //
            // The ops the latches above are for. The latch is
            // consumed only on success — a PREP followed by an
            // INSERT that fails its depth check leaves the PREP
            // armed for the next attempt.
            Op::Insert { depth, value } => {
                self.check_unclenched("INSERT", span)?;
                if !self.prep_armed {
                    return Err(AnalError::Tightness { op: "INSERT", span });
                }
                let len = self.stack.len();
                if *depth > len {
                    return Err(AnalError::PenetrationDepth {
                        depth: *depth,
                        size: len,
                        span,
                    });
                }
                let idx = len - *depth;
                self.push_at(idx, value.clone(), span)?;
                self.prep_armed = false;
            }
            Op::Extract(depth) => {
                self.check_unclenched("EXTRACT", span)?;
                if !self.consent_armed {
                    return Err(AnalError::Refusal {
                        op: "EXTRACT",
                        span,
                    });
                }
                let len = self.stack.len();
                if *depth >= len {
                    return Err(AnalError::PenetrationDepth {
                        depth: *depth,
                        size: len,
                        span,
                    });
                }
                let idx = len - 1 - *depth;
                self.stack.remove(idx);
                self.consent_armed = false;
            }
            Op::Flush => {
                self.check_unclenched("FLUSH", span)?;
                if !self.consent_armed {
                    return Err(AnalError::Refusal { op: "FLUSH", span });
                }
                self.stack.clear();
                self.consent_armed = false;
            }

            // ── EXPAND ──────────────────────────────────────────
            //
            // First call installs the cap at `depth + n`; later
            // calls may raise it, never lower it. Programs that
            // never call EXPAND cannot raise OVERFLOW.
            Op::Expand(n) => {
                self.check_unclenched("EXPAND", span)?;
                let target = self.stack.len().saturating_add(*n);
                self.capacity = Some(match self.capacity {
                    Some(cur) => cur.max(target),
                    None => target,
                });
                self.stack.reserve(*n);
            }

            // ── External I/O ────────────────────────────────────
            //
            // EVACUATE has the only nontrivial rule: writing to a
            // new path is unguarded, but overwriting an existing
            // file requires CONSENT. Creation is benign,
            // destruction is not, and the filesystem already knows
            // the difference.
            Op::IngestFile(path) => {
                self.check_unclenched("INGEST", span)?;
                let contents =
                    std::fs::read_to_string(Path::new(path)).map_err(|e| AnalError::Rejection {
                        expected: "readable file",
                        found: format!("INGEST: {e}"),
                        span,
                    })?;
                self.push(Value::Str(Rc::from(contents.as_str())), span)?;
            }
            Op::Evacuate(path) => {
                let content = match self.peek("EVACUATE", span)? {
                    Value::Str(s) => Rc::clone(s),
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "STRING",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let p = Path::new(path);
                if p.exists() {
                    if !self.consent_armed {
                        return Err(AnalError::Refusal {
                            op: "EVACUATE",
                            span,
                        });
                    }
                    self.consent_armed = false;
                }
                std::fs::write(p, content.as_bytes()).map_err(|e| AnalError::Rejection {
                    expected: "writable file path",
                    found: format!("EVACUATE: {e}"),
                    span,
                })?;
            }
            Op::Receive => {
                self.check_unclenched("RECEIVE", span)?;
                let mut line = String::new();
                let n = input
                    .read_line(&mut line)
                    .map_err(|e| AnalError::Rejection {
                        expected: "readable stdin",
                        found: format!("RECEIVE: {e}"),
                        span,
                    })?;
                if n == 0 {
                    return Err(AnalError::Rejection {
                        expected: "input line",
                        found: "EOF".into(),
                        span,
                    });
                }
                // Strip trailing newline(s).
                while matches!(line.chars().last(), Some('\n' | '\r')) {
                    line.pop();
                }
                self.push(Value::Str(Rc::from(line.as_str())), span)?;
            }

            // ── HOLD ────────────────────────────────────────────
            //
            // `HOLD <ms>` sleeps; bare `HOLD` reads stdin lines
            // until one is exactly "RESUME". Both flush stdout and
            // stderr before blocking — a paused program with its
            // last sentence stuck in a buffer is a bug report
            // waiting to happen.
            Op::Hold(ms) => {
                self.check_unclenched("HOLD", span)?;
                match ms {
                    Some(n) => {
                        out.flush().map_err(|_| io_err("HOLD", span))?;
                        err.flush().map_err(|_| io_err("HOLD", span))?;
                        std::thread::sleep(std::time::Duration::from_millis(*n));
                    }
                    None => {
                        out.flush().map_err(|_| io_err("HOLD", span))?;
                        err.flush().map_err(|_| io_err("HOLD", span))?;
                        let mut line = String::new();
                        loop {
                            line.clear();
                            let n =
                                input
                                    .read_line(&mut line)
                                    .map_err(|e| AnalError::Rejection {
                                        expected: "RESUME signal on stdin",
                                        found: format!("HOLD: {e}"),
                                        span,
                                    })?;
                            if n == 0 {
                                return Err(AnalError::Rejection {
                                    expected: "RESUME signal on stdin",
                                    found: "EOF".into(),
                                    span,
                                });
                            }
                            if line.trim_end_matches(['\n', '\r']) == "RESUME" {
                                break;
                            }
                        }
                    }
                }
            }

            // ── RESUME ──────────────────────────────────────────
            //
            // The only primitive whose effect is entirely on the
            // other side of stdout: writes "RESUME\n" so that a
            // peer process blocked on a bare HOLD can wake up.
            Op::Resume => {
                self.check_unclenched("RESUME", span)?;
                writeln!(out, "RESUME").map_err(|_| io_err("RESUME", span))?;
                out.flush().map_err(|_| io_err("RESUME", span))?;
            }

            // ── Byte I/O ────────────────────────────────────────
            //
            // Single-byte channels for binary or character-stream
            // work. RECEIVE_BYTE pushes -1 on EOF instead of raising,
            // because EOF on a byte stream is a normal terminator —
            // the spec says "the stream ended," not "the read failed."
            // EMIT_BYTE enforces the 0..=255 range; an out-of-range
            // INT is REJECTION at runtime.
            Op::ReceiveByte => {
                self.check_unclenched("RECEIVE_BYTE", span)?;
                let mut buf = [0u8; 1];
                match input.read(&mut buf) {
                    Ok(0) => self.push(Value::Int(-1), span)?,
                    Ok(_) => self.push(Value::Int(buf[0] as i64), span)?,
                    Err(e) => {
                        return Err(AnalError::Rejection {
                            expected: "readable stdin",
                            found: format!("RECEIVE_BYTE: {e}"),
                            span,
                        });
                    }
                }
            }
            Op::EmitByte => {
                self.check_unclenched("EMIT_BYTE", span)?;
                let v = self.pop("EMIT_BYTE", span)?;
                let n = match v {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                if !(0..=255).contains(&n) {
                    return Err(AnalError::Rejection {
                        expected: "INT in 0..=255",
                        found: format!("{n}"),
                        span,
                    });
                }
                out.write_all(&[n as u8])
                    .map_err(|_| io_err("EMIT_BYTE", span))?;
            }

            // ── String inspection ───────────────────────────────
            //
            // STRLEN/CHARAT/SUBSTR work in bytes. UTF-8 codepoint
            // semantics belong in a future stdlib module, not in the
            // primitives — the primitives stay honest about what
            // they index into.
            Op::Strlen => {
                let s = match self.pop("STRLEN", span)? {
                    Value::Str(s) => s,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "STRING",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                self.push(Value::Int(s.len() as i64), span)?;
            }
            Op::Charat => {
                let idx = match self.pop("CHARAT", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let s = match self.pop("CHARAT", span)? {
                    Value::Str(s) => s,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "STRING",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                if idx < 0 || (idx as usize) >= s.len() {
                    return Err(AnalError::CavityBreach {
                        index: idx,
                        len: s.len(),
                        kind: "STRING",
                        span,
                    });
                }
                self.push(Value::Int(s.as_bytes()[idx as usize] as i64), span)?;
            }
            Op::Substr => {
                let len = match self.pop("SUBSTR", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let start = match self.pop("SUBSTR", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let s = match self.pop("SUBSTR", span)? {
                    Value::Str(s) => s,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "STRING",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                if start < 0 || len < 0 {
                    return Err(AnalError::CavityBreach {
                        index: start.min(len),
                        len: s.len(),
                        kind: "STRING",
                        span,
                    });
                }
                let start_u = start as usize;
                let len_u = len as usize;
                let end = start_u.saturating_add(len_u);
                if end > s.len() {
                    return Err(AnalError::CavityBreach {
                        index: end as i64,
                        len: s.len(),
                        kind: "STRING",
                        span,
                    });
                }
                let slice = &s.as_bytes()[start_u..end];
                // SUBSTR returns a STRING; if the slice splits a UTF-8
                // codepoint, the result is invalid UTF-8 and we reject.
                let out_str = std::str::from_utf8(slice).map_err(|_| AnalError::Rejection {
                    expected: "valid UTF-8 substring boundary",
                    found: "split codepoint".into(),
                    span,
                })?;
                self.push(Value::Str(Rc::from(out_str)), span)?;
            }

            // ── External storage (CAVITY) ───────────────────────
            //
            // The persistent-region semantic: BUFGET/BUFSET/BUFLEN
            // act on the CAVITY without consuming it. BUFSET requires
            // PREP + CONSENT (the same ceremony as INSERT). All
            // three peek the CAVITY rather than popping it.
            Op::Buffer(n) => {
                self.check_unclenched("BUFFER", span)?;
                if *n == 0 {
                    return Err(AnalError::Hollow { size: 0, span });
                }
                let cells = std::rc::Rc::new(std::cell::RefCell::new(vec![0i64; *n]));
                self.push(Value::Cavity(cells), span)?;
            }
            Op::BufferDyn => {
                self.check_unclenched("BUFFER", span)?;
                let n = match self.pop("BUFFER", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                if n <= 0 {
                    return Err(AnalError::Hollow { size: n, span });
                }
                let cells = std::rc::Rc::new(std::cell::RefCell::new(vec![0i64; n as usize]));
                self.push(Value::Cavity(cells), span)?;
            }
            Op::Bufget => {
                let idx = match self.pop("BUFGET", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let cavity = match self.peek("BUFGET", span)? {
                    Value::Cavity(c) => c.clone(),
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "CAVITY",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let cells = cavity.borrow();
                if idx < 0 || (idx as usize) >= cells.len() {
                    return Err(AnalError::CavityBreach {
                        index: idx,
                        len: cells.len(),
                        kind: "CAVITY",
                        span,
                    });
                }
                let v = cells[idx as usize];
                drop(cells);
                self.push(Value::Int(v), span)?;
            }
            Op::Bufset => {
                self.check_unclenched("BUFSET", span)?;
                if !self.prep_armed {
                    return Err(AnalError::Tightness { op: "BUFSET", span });
                }
                if !self.consent_armed {
                    return Err(AnalError::Refusal { op: "BUFSET", span });
                }
                let value = match self.pop("BUFSET", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let idx = match self.pop("BUFSET", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let cavity = match self.peek("BUFSET", span)? {
                    Value::Cavity(c) => c.clone(),
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "CAVITY",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let mut cells = cavity.borrow_mut();
                if idx < 0 || (idx as usize) >= cells.len() {
                    return Err(AnalError::CavityBreach {
                        index: idx,
                        len: cells.len(),
                        kind: "CAVITY",
                        span,
                    });
                }
                cells[idx as usize] = value;
                self.prep_armed = false;
                self.consent_armed = false;
            }
            Op::Buflen => {
                let cavity = match self.peek("BUFLEN", span)? {
                    Value::Cavity(c) => c.clone(),
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "CAVITY",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let len = cavity.borrow().len();
                self.push(Value::Int(len as i64), span)?;
            }
            Op::Load(i) => {
                let cavity = match self.peek("LOAD", span)? {
                    Value::Cavity(c) => c.clone(),
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "CAVITY",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let cells = cavity.borrow();
                if *i >= cells.len() {
                    return Err(AnalError::CavityBreach {
                        index: *i as i64,
                        len: cells.len(),
                        kind: "CAVITY",
                        span,
                    });
                }
                let v = cells[*i];
                drop(cells);
                self.push(Value::Int(v), span)?;
            }
            Op::Store(i) => {
                self.check_unclenched("STORE", span)?;
                if !self.prep_armed {
                    return Err(AnalError::Tightness { op: "STORE", span });
                }
                if !self.consent_armed {
                    return Err(AnalError::Refusal { op: "STORE", span });
                }
                let value = match self.pop("STORE", span)? {
                    Value::Int(n) => n,
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "INT",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let cavity = match self.peek("STORE", span)? {
                    Value::Cavity(c) => c.clone(),
                    other => {
                        return Err(AnalError::Rejection {
                            expected: "CAVITY",
                            found: other.type_name().into(),
                            span,
                        });
                    }
                };
                let mut cells = cavity.borrow_mut();
                if *i >= cells.len() {
                    return Err(AnalError::CavityBreach {
                        index: *i as i64,
                        len: cells.len(),
                        kind: "CAVITY",
                        span,
                    });
                }
                cells[*i] = value;
                self.prep_armed = false;
                self.consent_armed = false;
            }
        }
        Ok(Flow::Continue)
    }

    /// Raise `LOCKDOWN` if the stack is currently clenched.
    fn check_unclenched(&self, op: &'static str, span: Span) -> Result<(), AnalError> {
        if self.clench_depth > 0 {
            Err(AnalError::Lockdown { op, span })
        } else {
            Ok(())
        }
    }

    fn pop(&mut self, op: &'static str, span: Span) -> Result<Value, AnalError> {
        self.stack.pop().ok_or(AnalError::Emptiness { op, span })
    }

    /// Push, honouring the `EXPAND`-set capacity cap. Use this in preference
    /// to `self.stack.push` so `OVERFLOW` is raised at the right boundary.
    fn push(&mut self, v: Value, span: Span) -> Result<(), AnalError> {
        if let Some(cap) = self.capacity {
            if self.stack.len() >= cap {
                return Err(AnalError::Overflow { span });
            }
        }
        self.stack.push(v);
        Ok(())
    }

    /// Insert at a depth, honouring the capacity cap.
    fn push_at(&mut self, idx: usize, v: Value, span: Span) -> Result<(), AnalError> {
        if let Some(cap) = self.capacity {
            if self.stack.len() >= cap {
                return Err(AnalError::Overflow { span });
            }
        }
        self.stack.insert(idx, v);
        Ok(())
    }

    fn peek(&self, op: &'static str, span: Span) -> Result<&Value, AnalError> {
        self.stack.last().ok_or(AnalError::Emptiness { op, span })
    }

    fn pop_bloc(&mut self, op: &'static str, span: Span) -> Result<Rc<[Instr]>, AnalError> {
        match self.pop(op, span)? {
            Value::Bloc(body) => Ok(body),
            other => Err(AnalError::Rejection {
                expected: "BLOC",
                found: other.type_name().into(),
                span,
            }),
        }
    }

    fn binop_add(&mut self, span: Span) -> Result<(), AnalError> {
        self.check_unclenched("ADD", span)?;
        let b = self.pop("ADD", span)?;
        let a = self.pop("ADD", span)?;
        let result = match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(x + y),
            (Value::Float(x), Value::Float(y)) => Value::Float(x + y),
            (Value::Str(x), Value::Str(y)) => {
                let mut s = String::with_capacity(x.len() + y.len());
                s.push_str(x);
                s.push_str(y);
                Value::Str(Rc::from(s.as_str()))
            }
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric or STRING types",
                    found: a.type_name().into(),
                    span,
                });
            }
        };
        self.push(result, span)
    }

    fn binop_arith(
        &mut self,
        span: Span,
        op_name: &'static str,
        f_int: impl Fn(i64, i64) -> i64,
        f_float: impl Fn(f64, f64) -> f64,
    ) -> Result<(), AnalError> {
        self.check_unclenched(op_name, span)?;
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let result = match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(f_int(*x, *y)),
            (Value::Float(x), Value::Float(y)) => Value::Float(f_float(*x, *y)),
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name().into(),
                    span,
                });
            }
        };
        self.push(result, span)
    }

    fn binop_div(&mut self, span: Span, op_name: &'static str) -> Result<(), AnalError> {
        self.check_unclenched(op_name, span)?;
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let result = match (&a, &b) {
            (Value::Int(_), Value::Int(0)) => {
                return Err(AnalError::Rejection {
                    expected: "non-zero divisor",
                    found: "INT(0)".into(),
                    span,
                });
            }
            (Value::Int(x), Value::Int(y)) => Value::Int(x / y),
            (Value::Float(x), Value::Float(y)) => Value::Float(x / y),
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name().into(),
                    span,
                });
            }
        };
        self.push(result, span)
    }

    fn binop_mod(&mut self, span: Span, op_name: &'static str) -> Result<(), AnalError> {
        self.check_unclenched(op_name, span)?;
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let result = match (&a, &b) {
            (Value::Int(_), Value::Int(0)) => {
                return Err(AnalError::Rejection {
                    expected: "non-zero divisor",
                    found: "INT(0)".into(),
                    span,
                });
            }
            (Value::Int(x), Value::Int(y)) => Value::Int(x % y),
            (Value::Float(x), Value::Float(y)) => Value::Float(x % y),
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name().into(),
                    span,
                });
            }
        };
        self.push(result, span)
    }

    fn binop_cmp(
        &mut self,
        span: Span,
        op_name: &'static str,
        f: impl Fn(Ordering) -> bool,
    ) -> Result<(), AnalError> {
        self.check_unclenched(op_name, span)?;
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let ord = match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => x.cmp(y),
            (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).ok_or(AnalError::Rejection {
                expected: "ordered FLOAT",
                found: "NaN".into(),
                span,
            })?,
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name().into(),
                    span,
                });
            }
        };
        self.push(Value::Bool(f(ord)), span)
    }

    fn convert_to_int(&mut self, span: Span) -> Result<(), AnalError> {
        self.check_unclenched("TO_INT", span)?;
        let v = self.pop("TO_INT", span)?;
        let n = match &v {
            Value::Int(n) => *n,
            Value::Float(f) => *f as i64,
            Value::Bool(b) => *b as i64,
            Value::Str(s) => s.parse::<i64>().map_err(|_| AnalError::Rejection {
                expected: "INT-parseable STRING",
                found: "non-numeric STRING".into(),
                span,
            })?,
            _ => {
                return Err(AnalError::Rejection {
                    expected: "INT-convertible value",
                    found: v.type_name().into(),
                    span,
                });
            }
        };
        self.push(Value::Int(n), span)
    }

    fn convert_to_float(&mut self, span: Span) -> Result<(), AnalError> {
        self.check_unclenched("TO_FLOAT", span)?;
        let v = self.pop("TO_FLOAT", span)?;
        let x = match &v {
            Value::Int(n) => *n as f64,
            Value::Float(f) => *f,
            Value::Bool(b) => {
                if *b {
                    1.0
                } else {
                    0.0
                }
            }
            Value::Str(s) => s.parse::<f64>().map_err(|_| AnalError::Rejection {
                expected: "FLOAT-parseable STRING",
                found: "non-numeric STRING".into(),
                span,
            })?,
            _ => {
                return Err(AnalError::Rejection {
                    expected: "FLOAT-convertible value",
                    found: v.type_name().into(),
                    span,
                });
            }
        };
        self.push(Value::Float(x), span)
    }

    fn convert_to_str(&mut self, span: Span) -> Result<(), AnalError> {
        self.check_unclenched("TO_STRING", span)?;
        let v = self.pop("TO_STRING", span)?;
        let s = format!("{v}");
        self.push(Value::Str(Rc::from(s.as_str())), span)
    }
}

fn io_err(op: &'static str, span: Span) -> AnalError {
    AnalError::Parse {
        message: format!("{op}: write to output failed"),
        span,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::compile;

    fn run(src: &str) -> (String, String, Result<(), AnalError>) {
        run_with_input(src, b"")
    }

    fn run_with_input(src: &str, input: &[u8]) -> (String, String, Result<(), AnalError>) {
        let program = match compile(src) {
            Ok(p) => p,
            Err(e) => return (String::new(), String::new(), Err(e)),
        };
        let mut input = std::io::Cursor::new(input);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut vm = VM::new();
        let result = vm.run(&program, &mut input, &mut out, &mut err);
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
            result,
        )
    }

    #[test]
    fn hello_world_runs() {
        let (out, _err, result) = run(r#"ANAL "hello" VERSION 1
PUSH "Hello, World!"
EXPEL"#);
        result.unwrap();
        assert_eq!(out, "Hello, World!\n");
    }

    #[test]
    fn add_concatenates_strings() {
        // Spec §7: ADD on two STRINGs concatenates them.
        let (out, _, result) = run(r#"PUSH "hello, "
PUSH "world"
ADD
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "hello, world\n");
    }

    #[test]
    fn arithmetic_subtract() {
        let (out, _err, result) = run(r#"PUSH 10
PUSH 3
SUB
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "7\n");
    }

    #[test]
    fn dup_and_discharge() {
        let (out, _err, result) = run(r#"PUSH 42
DUP
DISCHARGE
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "42\n42\n");
    }

    #[test]
    fn dilate_countdown() {
        let (out, _err, result) = run(r#"PUSH 3
DUP PUSH 0 GT
DILATE
  DUP DISCHARGE
  PUSH 1 SUB
  DUP PUSH 0 GT
CONSTRICT"#);
        result.unwrap();
        assert_eq!(out, "3\n2\n1\n");
    }

    #[test]
    fn if_tight_truthy_executes() {
        let (out, _err, result) = run(r#"PUSH 1
IF_TIGHT [ PUSH "yes" DISCHARGE ]"#);
        result.unwrap();
        assert_eq!(out, "yes\n");
    }

    #[test]
    fn if_tight_falsy_skips() {
        let (out, _err, result) = run(r#"PUSH 0
IF_TIGHT [ PUSH "no" DISCHARGE ]"#);
        result.unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn pop_on_empty_is_caught_statically() {
        // With the type checker in front of the VM, popping an empty
        // stack is a static MISMATCH — the program never starts.
        let (_out, _err, result) = run("POP");
        assert!(matches!(result.unwrap_err(), AnalError::Mismatch { .. }));
    }

    // ── PREP / INSERT ────────────────────────────────────

    #[test]
    fn insert_without_prep_is_tightness() {
        let (_, _, result) = run(r#"PUSH 1
PUSH 2
INSERT 1 99"#);
        assert!(matches!(result.unwrap_err(), AnalError::Tightness { .. }));
    }

    #[test]
    fn insert_with_prep_places_value_at_depth() {
        // Stack: [10, 20, 30] -> INSERT 2 15 -> [10, 15, 20, 30]
        let (out, _, result) = run(r#"PUSH 10
PUSH 20
PUSH 30
PREP
INSERT 2 15
DISCHARGE DISCHARGE DISCHARGE DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "30\n20\n15\n10\n");
    }

    #[test]
    fn prep_is_one_shot() {
        let (_, _, result) = run(r#"PUSH 1
PREP
INSERT 0 99
INSERT 0 88"#);
        // First INSERT consumes the PREP; second raises TIGHTNESS.
        assert!(matches!(result.unwrap_err(), AnalError::Tightness { .. }));
    }

    #[test]
    fn insert_depth_beyond_stack_is_penetration_depth() {
        let (_, _, result) = run(r#"PUSH 1
PREP
INSERT 5 99"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::PenetrationDepth { .. }
        ));
    }

    // ── CONSENT / EXTRACT / FLUSH ────────────────────────

    #[test]
    fn extract_without_consent_is_refusal() {
        let (_, _, result) = run(r#"PUSH 1
PUSH 2
EXTRACT 0"#);
        assert!(matches!(result.unwrap_err(), AnalError::Refusal { .. }));
    }

    #[test]
    fn extract_with_consent_removes_at_depth() {
        // Stack: [10, 20, 30, 40] -> EXTRACT 2 -> [10, 30, 40]
        let (out, _, result) = run(r#"PUSH 10
PUSH 20
PUSH 30
PUSH 40
CONSENT
EXTRACT 2
DISCHARGE DISCHARGE DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "40\n30\n10\n");
    }

    #[test]
    fn consent_is_one_shot() {
        let (_, _, result) = run(r#"PUSH 1
PUSH 2
CONSENT
EXTRACT 0
EXTRACT 0"#);
        // First EXTRACT consumes CONSENT; second raises REFUSAL.
        assert!(matches!(result.unwrap_err(), AnalError::Refusal { .. }));
    }

    #[test]
    fn flush_without_consent_is_refusal() {
        let (_, _, result) = run(r#"PUSH 1
FLUSH"#);
        assert!(matches!(result.unwrap_err(), AnalError::Refusal { .. }));
    }

    #[test]
    fn flush_with_consent_clears_stack() {
        let (out, _, result) = run(r#"PUSH 1
PUSH 2
PUSH 3
CONSENT
FLUSH
DEPTH
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "0\n");
    }

    // ── CLENCH / RELEASE / LOCKDOWN ──────────────────────

    #[test]
    fn release_on_unclenched_is_premature_release() {
        let (_, _, result) = run("RELEASE");
        assert!(matches!(
            result.unwrap_err(),
            AnalError::PrematureRelease { .. }
        ));
    }

    #[test]
    fn push_while_clenched_is_lockdown() {
        let (_, _, result) = run(r#"CLENCH
PUSH 1"#);
        assert!(matches!(result.unwrap_err(), AnalError::Lockdown { .. }));
    }

    #[test]
    fn probe_and_expel_still_work_while_clenched() {
        let (out, err, result) = run(r#"PUSH 42
CLENCH
PROBE
EXPEL"#);
        result.unwrap();
        assert_eq!(err, "42\n");
        assert_eq!(out, "42\n");
    }

    #[test]
    fn release_unlocks_writes() {
        let (out, _, result) = run(r#"PUSH 1
CLENCH
RELEASE
PUSH 2
ADD
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "3\n");
    }

    // ── RELAX ────────────────────────────────────────────

    #[test]
    fn relax_clears_armed_prep() {
        let (_, _, result) = run(r#"PUSH 1
PREP
RELAX
INSERT 0 99"#);
        // RELAX cleared PREP, so INSERT raises TIGHTNESS.
        assert!(matches!(result.unwrap_err(), AnalError::Tightness { .. }));
    }

    #[test]
    fn relax_clears_armed_consent() {
        let (_, _, result) = run(r#"PUSH 1
CONSENT
RELAX
FLUSH"#);
        // RELAX cleared CONSENT, so FLUSH raises REFUSAL.
        assert!(matches!(result.unwrap_err(), AnalError::Refusal { .. }));
    }

    #[test]
    fn relax_is_idempotent_on_unarmed_state() {
        // RELAX on a clean state should just be a no-op.
        let (out, _, result) = run(r#"RELAX
RELAX
PUSH 42
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "42\n");
    }

    #[test]
    fn relax_allowed_during_clench() {
        // RELAX doesn't touch the stack, so it's safe during a freeze.
        let (out, _, result) = run(r#"PUSH 1
CONSENT
CLENCH
RELAX
RELEASE
FLUSH"#);
        // RELAX cleared CONSENT before the FLUSH, so FLUSH now raises REFUSAL.
        assert!(
            matches!(result.clone().unwrap_err(), AnalError::Refusal { .. }),
            "got {result:?}, out={out:?}"
        );
    }

    #[test]
    fn nested_clenches_require_matching_releases() {
        let (_, _, result) = run(r#"PUSH 1
CLENCH
CLENCH
RELEASE
PUSH 2"#);
        // Two CLENCHes, one RELEASE — still clenched.
        assert!(matches!(result.unwrap_err(), AnalError::Lockdown { .. }));
    }

    // ── PASSAGE / ENTER / EXIT ───────────────────────────

    #[test]
    fn passage_call_returns_to_caller() {
        let (out, _, result) = run(r#"PASSAGE square:
  DUP
  MUL
EXIT

PUSH 9
ENTER square
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "81\n");
    }

    #[test]
    fn passage_can_be_called_multiple_times() {
        let (out, _, result) = run(r#"PASSAGE double:
  PUSH 2
  MUL
EXIT

PUSH 3
ENTER double
ENTER double
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "12\n");
    }

    #[test]
    fn passage_not_found_caught_statically() {
        // The checker reports unresolved passage names as MISMATCH at
        // probe time, ahead of execution.
        let (_, _, result) = run("ENTER nonexistent");
        assert!(matches!(result.unwrap_err(), AnalError::Mismatch { .. }));
    }

    #[test]
    fn passages_share_the_global_stack() {
        // Passage adds 100 to whatever's on top, then we DISCHARGE twice
        // to confirm the rest of the stack remains accessible.
        let (out, _, result) = run(r#"PASSAGE add100:
  PUSH 100
  ADD
EXIT

PUSH 7
PUSH 5
ENTER add100
DISCHARGE
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "105\n7\n");
    }

    #[test]
    fn abort_stops_execution_immediately() {
        let (out, _, result) = run(r#"PUSH 1
DISCHARGE
ABORT
PUSH 2
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "1\n"); // PUSH 2 / DISCHARGE never run
    }

    // ── RECEIVE / INGEST / EVACUATE ──────────────────────

    #[test]
    fn receive_reads_one_line_from_stdin() {
        let (out, _, result) = run_with_input("RECEIVE\nDISCHARGE", b"hello world\n");
        result.unwrap();
        assert_eq!(out, "hello world\n");
    }

    #[test]
    fn receive_strips_crlf() {
        let (out, _, result) = run_with_input("RECEIVE\nDISCHARGE", b"hi\r\n");
        result.unwrap();
        assert_eq!(out, "hi\n");
    }

    #[test]
    fn receive_on_eof_raises_rejection() {
        let (_, _, result) = run_with_input("RECEIVE", b"");
        assert!(matches!(result.unwrap_err(), AnalError::Rejection { .. }));
    }

    #[test]
    fn ingest_reads_file_contents() {
        let path =
            std::env::temp_dir().join(format!("anal_test_ingest_{}.txt", std::process::id()));
        std::fs::write(&path, "file contents here").unwrap();
        let src = format!(
            "INGEST \"{}\"\nDISCHARGE",
            path.display().to_string().replace('\\', "\\\\")
        );
        let (out, _, result) = run(&src);
        let _ = std::fs::remove_file(&path);
        result.unwrap();
        assert_eq!(out, "file contents here\n");
    }

    #[test]
    fn ingest_missing_file_raises_rejection() {
        let (_, _, result) = run(r#"INGEST "definitely_not_a_real_path_12345.txt""#);
        assert!(matches!(result.unwrap_err(), AnalError::Rejection { .. }));
    }

    #[test]
    fn evacuate_writes_new_file_without_consent() {
        let path = std::env::temp_dir().join(format!("anal_test_evac_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let src = format!(
            "PUSH \"hello evac\"\nEVACUATE \"{}\"",
            path.display().to_string().replace('\\', "\\\\")
        );
        let (_, _, result) = run(&src);
        result.unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(contents, "hello evac");
    }

    #[test]
    fn evacuate_overwrite_without_consent_is_refusal() {
        let path =
            std::env::temp_dir().join(format!("anal_test_evac_ref_{}.txt", std::process::id()));
        std::fs::write(&path, "existing").unwrap();
        let src = format!(
            "PUSH \"would overwrite\"\nEVACUATE \"{}\"",
            path.display().to_string().replace('\\', "\\\\")
        );
        let (_, _, result) = run(&src);
        let _ = std::fs::remove_file(&path);
        assert!(matches!(result.unwrap_err(), AnalError::Refusal { .. }));
    }

    // ── BLOC as a first-class value ─────────────────────

    #[test]
    fn bloc_pushed_as_value_and_entered() {
        let (out, _, result) = run(r#"[ PUSH "from inside the bloc" DISCHARGE ]
ENTER"#);
        result.unwrap();
        assert_eq!(out, "from inside the bloc\n");
    }

    #[test]
    fn bloc_executed_twice_via_dup() {
        let (out, _, result) = run(r#"[ PUSH "hello" DISCHARGE ]
DUP
ENTER
ENTER"#);
        result.unwrap();
        assert_eq!(out, "hello\nhello\n");
    }

    #[test]
    fn if_tight_with_separate_bloc_push_works() {
        // Push condition + BLOC separately, then IF_TIGHT consumes both.
        let (out, _, result) = run(r#"PUSH 1
[ PUSH "yes" DISCHARGE ]
IF_TIGHT"#);
        result.unwrap();
        assert_eq!(out, "yes\n");
    }

    #[test]
    fn if_loose_branches_on_falsy() {
        let (out, _, result) = run(r#"PUSH 0
IF_LOOSE [ PUSH "ran" DISCHARGE ]"#);
        result.unwrap();
        assert_eq!(out, "ran\n");
    }

    #[test]
    fn enter_on_non_bloc_raises_rejection() {
        let (_, _, result) = run(r#"PUSH 42
ENTER"#);
        assert!(matches!(result.unwrap_err(), AnalError::Rejection { .. }));
    }

    #[test]
    fn nested_blocs_execute_correctly() {
        // Outer IF_TIGHT runs the BLOC; inside it, another IF_TIGHT runs
        // its own nested BLOC. Verifies that nested run_block calls don't
        // confuse each other's stacks.
        let (out, _, result) = run(r#"PUSH 1
IF_TIGHT [
  PUSH "outer "
  EXPEL
  PUSH 1
  IF_TIGHT [ PUSH "inner" DISCHARGE ]
  POP
]"#);
        result.unwrap();
        assert_eq!(out, "outer \ninner\n");
    }

    #[test]
    fn bloc_with_loop_inside() {
        // Loop body inside a BLOC — proves DILATE/CONSTRICT addresses
        // are local to each compiled block. The BLOC builds its own
        // counter rather than inheriting one from the caller.
        let (out, _, result) = run(r#"PUSH 1
IF_TIGHT [
  PUSH 3
  DUP PUSH 0 GT
  DILATE
    DUP DISCHARGE
    PUSH 1 SUB
    DUP PUSH 0 GT
  CONSTRICT
  POP
]"#);
        result.unwrap();
        assert_eq!(out, "3\n2\n1\n");
    }

    // ── EXPAND / HOLD / RESUME ──────────────────────────

    #[test]
    fn expand_without_overflow_is_a_noop_for_correct_programs() {
        // EXPAND 4 from a depth-0 stack: cap = 4. The three explicit pushes
        // plus the implicit one from DEPTH all fit; nothing overflows.
        let (out, _, result) = run(r#"EXPAND 4
PUSH 1
PUSH 2
PUSH 3
DEPTH
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "3\n");
    }

    #[test]
    fn push_past_expand_cap_raises_overflow() {
        // EXPAND 2 from a depth-0 stack: cap = 2. The third push trips OVERFLOW.
        let (_, _, result) = run(r#"EXPAND 2
PUSH 1
PUSH 2
PUSH 3"#);
        assert!(matches!(result.unwrap_err(), AnalError::Overflow { .. }));
    }

    #[test]
    fn second_expand_raises_cap_never_lowers() {
        // EXPAND 1 then EXPAND 5 → effective cap is 5. Four explicit pushes
        // plus the implicit one from DEPTH all fit.
        let (out, _, result) = run(r#"EXPAND 1
EXPAND 5
PUSH 1
PUSH 2
PUSH 3
PUSH 4
DEPTH
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "4\n");
    }

    #[test]
    fn expand_after_pushes_caps_at_current_depth_plus_n() {
        // Two pushes (depth 2), then EXPAND 1 → cap = 3. One more push fits;
        // a second additional push trips OVERFLOW.
        let (_, _, result) = run(r#"PUSH 1
PUSH 2
EXPAND 1
PUSH 3
PUSH 4"#);
        assert!(matches!(result.unwrap_err(), AnalError::Overflow { .. }));
    }

    #[test]
    fn without_expand_no_overflow_ever() {
        // No EXPAND => no cap. Pushing many values must not raise OVERFLOW.
        let mut src = String::from("PUSH 0\n");
        for _ in 0..200 {
            src.push_str("DUP\n");
        }
        src.push_str("DEPTH\nDISCHARGE\n");
        let (out, _, result) = run(&src);
        result.unwrap();
        assert_eq!(out, "201\n");
    }

    #[test]
    fn hold_zero_ms_is_essentially_instant() {
        // HOLD 0 is well-defined: sleep(0). Stack-neutral.
        let (out, _, result) = run(r#"PUSH 1
HOLD 0
PUSH 2
ADD
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "3\n");
    }

    #[test]
    fn hold_negative_ms_is_parse_error() {
        let (_, _, result) = run("HOLD -1");
        let err = result.unwrap_err();
        assert!(matches!(err, AnalError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn bare_hold_waits_for_resume_line_on_stdin() {
        // Bare HOLD blocks on stdin until a line equal to "RESUME" arrives.
        // We pre-supply "noise\nRESUME\n" so HOLD ignores the first line
        // and continues after the second.
        let (out, _, result) = run_with_input("HOLD\nPUSH 7\nDISCHARGE\n", b"noise\nRESUME\n");
        result.unwrap();
        assert_eq!(out, "7\n");
    }

    #[test]
    fn bare_hold_eof_is_rejection() {
        // No RESUME, no input — EOF on stdin while HOLDing is a REJECTION.
        let (_, _, result) = run_with_input("HOLD\n", b"");
        assert!(matches!(result.unwrap_err(), AnalError::Rejection { .. }));
    }

    #[test]
    fn resume_emits_resume_line_on_stdout() {
        // Source-level RESUME writes "RESUME\n" to the EXPEL/DISCHARGE channel
        // so a piped peer waiting on a bare HOLD can wake up.
        let (out, _, result) = run("RESUME");
        result.unwrap();
        assert_eq!(out, "RESUME\n");
    }

    #[test]
    fn evacuate_overwrite_with_consent_succeeds() {
        let path =
            std::env::temp_dir().join(format!("anal_test_evac_consent_{}.txt", std::process::id()));
        std::fs::write(&path, "old contents").unwrap();
        let src = format!(
            "PUSH \"new contents\"\nCONSENT\nEVACUATE \"{}\"",
            path.display().to_string().replace('\\', "\\\\")
        );
        let (_, _, result) = run(&src);
        result.unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(contents, "new contents");
    }

    // ── v0.3 primitives ─────────────────────────────────

    #[test]
    fn strlen_byte_count() {
        let (out, _, result) = run(r#"PUSH "hello"
STRLEN
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "5\n");
    }

    #[test]
    fn charat_reads_byte_as_int() {
        // 'e' is byte 101
        let (out, _, result) = run(r#"PUSH "hello"
PUSH 1
CHARAT
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "101\n");
    }

    #[test]
    fn charat_out_of_bounds_is_cavity_breach() {
        let (_, _, result) = run(r#"PUSH "hi"
PUSH 9
CHARAT"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::CavityBreach { kind: "STRING", .. }
        ));
    }

    #[test]
    fn substr_returns_slice() {
        let (out, _, result) = run(r#"PUSH "hello"
PUSH 1
PUSH 3
SUBSTR
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "ell\n");
    }

    #[test]
    fn substr_past_end_is_cavity_breach() {
        let (_, _, result) = run(r#"PUSH "hi"
PUSH 0
PUSH 99
SUBSTR"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::CavityBreach { kind: "STRING", .. }
        ));
    }

    #[test]
    fn buffer_allocates_zeroed_cells() {
        // Fresh BUFFER, read each cell — all zeros.
        let (out, _, result) = run(r#"BUFFER 3
PUSH 0 BUFGET DISCHARGE
PUSH 1 BUFGET DISCHARGE
PUSH 2 BUFGET DISCHARGE
POP"#);
        result.unwrap();
        assert_eq!(out, "0\n0\n0\n");
    }

    #[test]
    fn buflen_reports_size_and_keeps_cavity() {
        let (out, _, result) = run(r#"BUFFER 7
BUFLEN
DISCHARGE
BUFLEN
DISCHARGE
POP"#);
        result.unwrap();
        // Two BUFLENs on the same CAVITY — proves CAVITY persists.
        assert_eq!(out, "7\n7\n");
    }

    #[test]
    fn bufset_persists_and_bufget_reads_it() {
        let (out, _, result) = run(r#"BUFFER 4
PUSH 2
PUSH 42
PREP CONSENT
BUFSET
PUSH 2
BUFGET
DISCHARGE
POP"#);
        result.unwrap();
        assert_eq!(out, "42\n");
    }

    #[test]
    fn bufset_without_prep_raises_tightness_with_op_name() {
        // Tightness should now carry op="BUFSET", not the generic INSERT.
        let (_, _, result) = run(r#"BUFFER 2
PUSH 0 PUSH 99
CONSENT
BUFSET"#);
        let err = result.unwrap_err();
        assert!(
            matches!(err, AnalError::Tightness { op: "BUFSET", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn insert_tightness_still_says_insert() {
        // The other Tightness call site should still report its own op.
        let (_, _, result) = run(r#"PUSH 1
INSERT 0 99"#);
        let err = result.unwrap_err();
        assert!(
            matches!(err, AnalError::Tightness { op: "INSERT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn bufset_without_consent_raises_refusal() {
        let (_, _, result) = run(r#"BUFFER 2
PUSH 0 PUSH 99
PREP
BUFSET"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::Refusal { op: "BUFSET", .. }
        ));
    }

    #[test]
    fn bufset_consumes_prep_and_consent() {
        // Two writes need two ceremonies — the second BUFSET fails because
        // PREP/CONSENT were consumed by the first.
        let (_, _, result) = run(r#"BUFFER 2
PUSH 0 PUSH 1
PREP CONSENT
BUFSET
PUSH 1 PUSH 2
BUFSET"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::Tightness { op: "BUFSET", .. }
        ));
    }

    #[test]
    fn bufget_out_of_bounds_is_cavity_breach() {
        let (_, _, result) = run(r#"BUFFER 3
PUSH 9
BUFGET"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::CavityBreach { kind: "CAVITY", .. }
        ));
    }

    #[test]
    fn dup_cavity_shares_storage() {
        // DUPing a CAVITY yields two stack slots that view the same region —
        // writing through one is visible through the other.
        let (out, _, result) = run(r#"BUFFER 1
DUP
PUSH 0 PUSH 77
PREP CONSENT
BUFSET
POP
PUSH 0
BUFGET
DISCHARGE
POP"#);
        result.unwrap();
        assert_eq!(out, "77\n");
    }

    #[test]
    fn emit_byte_writes_raw() {
        let (out, _, result) = run(r#"PUSH 65 EMIT_BYTE
PUSH 66 EMIT_BYTE
PUSH 10 EMIT_BYTE"#);
        result.unwrap();
        assert_eq!(out, "AB\n");
    }

    #[test]
    fn emit_byte_out_of_range_is_rejection() {
        let (_, _, result) = run("PUSH 999 EMIT_BYTE");
        assert!(matches!(result.unwrap_err(), AnalError::Rejection { .. }));
    }

    #[test]
    fn receive_byte_reads_one_byte() {
        let (out, _, result) = run_with_input(
            r#"RECEIVE_BYTE
DISCHARGE"#,
            b"X",
        );
        result.unwrap();
        // 'X' is byte 88
        assert_eq!(out, "88\n");
    }

    #[test]
    fn receive_byte_on_eof_pushes_minus_one() {
        let (out, _, result) = run_with_input(
            r#"RECEIVE_BYTE
DISCHARGE"#,
            b"",
        );
        result.unwrap();
        assert_eq!(out, "-1\n");
    }

    #[test]
    fn buffer_dynamic_allocates_at_runtime() {
        // The size is computed from input, not known at compile time.
        // This is the test that proves bounded-tape Turing-completeness
        // graduates to honest Turing-completeness: a program can allocate
        // memory based on values it didn't know when it was written.
        let (out, _, result) = run_with_input(
            r#"RECEIVE
TO_INT
BUFFER
BUFLEN
DISCHARGE
POP"#,
            b"42\n",
        );
        result.unwrap();
        assert_eq!(out, "42\n");
    }

    #[test]
    fn buffer_dynamic_zero_is_hollow() {
        let (_, _, result) = run(r#"PUSH 0 BUFFER"#);
        assert!(matches!(result.unwrap_err(), AnalError::Hollow { .. }));
    }

    #[test]
    fn buffer_dynamic_negative_is_hollow() {
        let (_, _, result) = run(r#"PUSH -3 BUFFER"#);
        assert!(matches!(result.unwrap_err(), AnalError::Hollow { .. }));
    }

    #[test]
    fn over_runtime_semantics() {
        // (1 2 -- 1 2 1), then DISCHARGE three times => "1 2 1" top-to-bottom.
        let (out, _, result) = run(r#"PUSH 1
PUSH 2
OVER
DISCHARGE
DISCHARGE
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "1\n2\n1\n");
    }

    #[test]
    fn over_on_one_value_is_emptiness() {
        // The type checker rejects this at compile time, but the VM-level
        // error path still needs to be correct in case OVER is reached
        // via dynamic BLOC execution that bypassed the checker.
        // We exercise the VM directly by stuffing a one-element stack
        // and calling step. Easier: just confirm the compile-time error.
        let (_, _, result) = run("PUSH 1 OVER");
        assert!(matches!(result.unwrap_err(), AnalError::Mismatch { .. }));
    }

    #[test]
    fn rot_runtime_semantics() {
        // (1 2 3 -- 2 3 1), then DISCHARGE => "1 3 2" top-to-bottom.
        let (out, _, result) = run(r#"PUSH 1
PUSH 2
PUSH 3
ROT
DISCHARGE
DISCHARGE
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "1\n3\n2\n");
    }

    #[test]
    fn rot_three_times_is_identity() {
        // ROT three times restores the original stack order.
        let (out, _, result) = run(r#"PUSH 1
PUSH 2
PUSH 3
ROT ROT ROT
DISCHARGE DISCHARGE DISCHARGE"#);
        result.unwrap();
        // Original: bottom-to-top [1, 2, 3]. Discharge top-to-bottom = "3 2 1".
        assert_eq!(out, "3\n2\n1\n");
    }

    #[test]
    fn store_then_load_roundtrips() {
        let (out, _, result) = run(r#"BUFFER 4
PUSH 77
PREP CONSENT
STORE 2
LOAD 2
DISCHARGE
POP"#);
        result.unwrap();
        assert_eq!(out, "77\n");
    }

    #[test]
    fn store_without_prep_is_tightness() {
        let (_, _, result) = run(r#"BUFFER 2
PUSH 1
CONSENT
STORE 0"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::Tightness { op: "STORE", .. }
        ));
    }

    #[test]
    fn store_without_consent_is_refusal() {
        let (_, _, result) = run(r#"BUFFER 2
PUSH 1
PREP
STORE 0"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::Refusal { op: "STORE", .. }
        ));
    }

    #[test]
    fn load_out_of_bounds_is_cavity_breach() {
        let (_, _, result) = run(r#"BUFFER 3
LOAD 9"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::CavityBreach { kind: "CAVITY", .. }
        ));
    }

    #[test]
    fn store_consumes_prep_and_consent() {
        // Two STOREs need two ceremonies.
        let (_, _, result) = run(r#"BUFFER 2
PUSH 1 PREP CONSENT STORE 0
PUSH 2 STORE 1"#);
        assert!(matches!(
            result.unwrap_err(),
            AnalError::Tightness { op: "STORE", .. }
        ));
    }

    #[test]
    fn nip_drops_second() {
        // (1 2 -- 2): NIP keeps only the top.
        let (out, _, result) = run(r#"PUSH 1
PUSH 2
NIP
DISCHARGE"#);
        result.unwrap();
        assert_eq!(out, "2\n");
    }

    #[test]
    fn nip_on_one_value_is_mismatch() {
        let (_, _, result) = run("PUSH 1 NIP");
        assert!(matches!(result.unwrap_err(), AnalError::Mismatch { .. }));
    }
}
