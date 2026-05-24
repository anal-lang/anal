//! Stack-based virtual machine — executes a compiled [`Vec<Instr>`].
//!
//! There is one global stack of [`Value`]s. The PC is advanced before each
//! op runs, so jump ops simply overwrite it. I/O channels are injectable
//! to keep the VM testable: `PROBE` writes to stderr (the inspection
//! channel), `EXPEL` and `DISCHARGE` write to stdout.

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
        }
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
            // ── stack ───────────────────────────────────
            Op::Push(v) => {
                self.check_unclenched("PUSH", span)?;
                self.stack.push(v.clone());
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
                self.stack.push(top);
            }
            Op::Swap => {
                self.check_unclenched("SWAP", span)?;
                let n = self.stack.len();
                if n < 2 {
                    return Err(AnalError::Emptiness { op: "SWAP", span });
                }
                self.stack.swap(n - 1, n - 2);
            }
            Op::Depth => {
                self.check_unclenched("DEPTH", span)?;
                self.stack.push(Value::Int(self.stack.len() as i64));
            }

            // ── I/O ─────────────────────────────────────
            Op::Expel => {
                let top = self.peek("EXPEL", span)?;
                writeln!(out, "{top}").map_err(|_| io_err("EXPEL", span))?;
            }
            Op::Discharge => {
                self.check_unclenched("DISCHARGE", span)?;
                let top = self.pop("DISCHARGE", span)?;
                writeln!(out, "{top}").map_err(|_| io_err("DISCHARGE", span))?;
            }

            // ── arithmetic ──────────────────────────────
            Op::Add => self.binop_arith(span, "ADD", |a, b| a + b, |a, b| a + b)?,
            Op::Sub => self.binop_arith(span, "SUB", |a, b| a - b, |a, b| a - b)?,
            Op::Mul => self.binop_arith(span, "MUL", |a, b| a * b, |a, b| a * b)?,
            Op::Div => self.binop_div(span, "DIV")?,
            Op::Mod => self.binop_mod(span, "MOD")?,

            // ── comparison ──────────────────────────────
            Op::EqOp => {
                self.check_unclenched("EQ", span)?;
                let b = self.pop("EQ", span)?;
                let a = self.pop("EQ", span)?;
                self.stack.push(Value::Bool(a == b));
            }
            Op::Lt => self.binop_cmp(span, "LT", |o| o == Ordering::Less)?,
            Op::Gt => self.binop_cmp(span, "GT", |o| o == Ordering::Greater)?,
            Op::Lte => self.binop_cmp(span, "LTE", |o| o != Ordering::Greater)?,
            Op::Gte => self.binop_cmp(span, "GTE", |o| o != Ordering::Less)?,
            Op::Not => {
                self.check_unclenched("NOT", span)?;
                let v = self.pop("NOT", span)?;
                self.stack.push(Value::Bool(!v.is_truthy()));
            }

            // ── conversion ──────────────────────────────
            Op::ToInt => self.convert_to_int(span)?,
            Op::ToFloat => self.convert_to_float(span)?,
            Op::ToStr => self.convert_to_str(span)?,

            // ── flow control ────────────────────────────
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

            // ── PASSAGE call/return ─────────────────────
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
            Op::Return => return Ok(Flow::Return),

            // ── PREP / CONSENT / CLENCH / RELEASE ───────
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

            // ── INSERT / EXTRACT / FLUSH ────────────────
            Op::Insert { depth, value } => {
                self.check_unclenched("INSERT", span)?;
                if !self.prep_armed {
                    return Err(AnalError::Tightness { span });
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
                self.stack.insert(idx, value.clone());
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

            // ── EXPAND: spec'd as "grow buffer". Vec grows on demand,
            //    so we treat EXPAND as a no-op past argument validation.
            Op::Expand(_n) => {
                self.check_unclenched("EXPAND", span)?;
            }

            // ── INGEST / EVACUATE / RECEIVE ─────────────
            Op::IngestFile(path) => {
                self.check_unclenched("INGEST", span)?;
                let contents =
                    std::fs::read_to_string(Path::new(path)).map_err(|e| AnalError::Rejection {
                        expected: "readable file",
                        found: format!("INGEST: {e}"),
                        span,
                    })?;
                self.stack.push(Value::Str(Rc::from(contents.as_str())));
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
                self.stack.push(Value::Str(Rc::from(line.as_str())));
            }

            // ── still pending in v0.2 ───────────────────
            Op::Hold(_) | Op::Resume => {
                return Err(AnalError::Parse {
                    message: format!("VM: op {op:?} not yet implemented in v0.1"),
                    span,
                });
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

    fn peek(&self, op: &'static str, span: Span) -> Result<&Value, AnalError> {
        self.stack.last().ok_or(AnalError::Emptiness { op, span })
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
        self.stack.push(result);
        Ok(())
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
        self.stack.push(result);
        Ok(())
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
        self.stack.push(result);
        Ok(())
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
        self.stack.push(Value::Bool(f(ord)));
        Ok(())
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
        self.stack.push(Value::Int(n));
        Ok(())
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
        self.stack.push(Value::Float(x));
        Ok(())
    }

    fn convert_to_str(&mut self, span: Span) -> Result<(), AnalError> {
        self.check_unclenched("TO_STRING", span)?;
        let v = self.pop("TO_STRING", span)?;
        let s = format!("{v}");
        self.stack.push(Value::Str(Rc::from(s.as_str())));
        Ok(())
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
    fn pop_on_empty_is_emptiness() {
        let (_out, _err, result) = run("POP");
        assert!(matches!(result.unwrap_err(), AnalError::Emptiness { .. }));
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
    fn passage_not_found_raises_error() {
        let (_, _, result) = run("ENTER nonexistent");
        assert!(matches!(
            result.unwrap_err(),
            AnalError::PassageNotFound { .. }
        ));
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
}
