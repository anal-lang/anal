//! Stack-based virtual machine — executes a compiled [`Vec<Instr>`].
//!
//! There is one global stack of [`Value`]s. The PC is advanced before each
//! op runs, so jump ops simply overwrite it. I/O channels are injectable
//! to keep the VM testable: `PROBE` writes to stderr (the inspection
//! channel), `EXPEL` and `DISCHARGE` write to stdout.

use std::cmp::Ordering;
use std::io::{self, Write};
use std::rc::Rc;

use crate::error::AnalError;
use crate::op::{Instr, Op};
use crate::token::Span;
use crate::value::Value;

pub struct VM {
    stack: Vec<Value>,
    pc: usize,
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
            pc: 0,
        }
    }

    /// Execute against the process stdout / stderr.
    pub fn execute(&mut self, code: &[Instr]) -> Result<(), AnalError> {
        let stdout = io::stdout();
        let stderr = io::stderr();
        let mut out = stdout.lock();
        let mut err = stderr.lock();
        self.run(code, &mut out, &mut err)
    }

    /// Execute with explicit I/O sinks — useful for tests.
    pub fn run<W1: Write, W2: Write>(
        &mut self,
        code: &[Instr],
        out: &mut W1,
        err: &mut W2,
    ) -> Result<(), AnalError> {
        while self.pc < code.len() {
            let instr = &code[self.pc];
            let span = instr.span;
            self.pc += 1;
            self.step(&instr.op, span, out, err)?;
        }
        Ok(())
    }

    fn step<W1: Write, W2: Write>(
        &mut self,
        op: &Op,
        span: Span,
        out: &mut W1,
        err: &mut W2,
    ) -> Result<(), AnalError> {
        match op {
            // ── stack ───────────────────────────────────
            Op::Push(v) => self.stack.push(v.clone()),
            Op::Pop => {
                self.pop("POP", span)?;
            }
            Op::Probe => {
                let top = self.peek("PROBE", span)?;
                writeln!(err, "{top}").map_err(|_| io_err("PROBE", span))?;
            }
            Op::Dup => {
                let top = self.peek("DUP", span)?.clone();
                self.stack.push(top);
            }
            Op::Swap => {
                let n = self.stack.len();
                if n < 2 {
                    return Err(AnalError::Emptiness { op: "SWAP", span });
                }
                self.stack.swap(n - 1, n - 2);
            }
            Op::Depth => self.stack.push(Value::Int(self.stack.len() as i64)),

            // ── I/O ─────────────────────────────────────
            Op::Expel => {
                let top = self.peek("EXPEL", span)?;
                writeln!(out, "{top}").map_err(|_| io_err("EXPEL", span))?;
            }
            Op::Discharge => {
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
                let b = self.pop("EQ", span)?;
                let a = self.pop("EQ", span)?;
                self.stack.push(Value::Bool(a == b));
            }
            Op::Lt => self.binop_cmp(span, "LT", |o| o == Ordering::Less)?,
            Op::Gt => self.binop_cmp(span, "GT", |o| o == Ordering::Greater)?,
            Op::Lte => self.binop_cmp(span, "LTE", |o| o != Ordering::Greater)?,
            Op::Gte => self.binop_cmp(span, "GTE", |o| o != Ordering::Less)?,
            Op::Not => {
                let v = self.pop("NOT", span)?;
                self.stack.push(Value::Bool(!v.is_truthy()));
            }

            // ── conversion ──────────────────────────────
            Op::ToInt => self.convert_to_int(span)?,
            Op::ToFloat => self.convert_to_float(span)?,
            Op::ToStr => self.convert_to_str(span)?,

            // ── flow control ────────────────────────────
            Op::Jump(target) => self.pc = *target,
            Op::JumpIfFalsy(target) => {
                let cond = self.pop("DILATE/IF_TIGHT", span)?;
                if !cond.is_truthy() {
                    self.pc = *target;
                }
            }
            Op::JumpIfTruthy(target) => {
                let cond = self.pop("CONSTRICT/IF_LOOSE", span)?;
                if cond.is_truthy() {
                    self.pc = *target;
                }
            }
            Op::Abort => {
                self.pc = usize::MAX;
            }

            // ── spec'd but not yet implemented ──────────
            Op::Insert { .. }
            | Op::Extract(_)
            | Op::Flush
            | Op::Prep
            | Op::Clench
            | Op::Release
            | Op::Consent
            | Op::Expand(_)
            | Op::Hold(_)
            | Op::Resume
            | Op::Receive
            | Op::IngestFile
            | Op::Evacuate
            | Op::Enter(_)
            | Op::Return => {
                return Err(AnalError::Parse {
                    message: format!("VM: op {op:?} not yet implemented in v0.1"),
                    span,
                });
            }
        }
        Ok(())
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
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let result = match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => Value::Int(f_int(*x, *y)),
            (Value::Float(x), Value::Float(y)) => Value::Float(f_float(*x, *y)),
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name(),
                    span,
                });
            }
        };
        self.stack.push(result);
        Ok(())
    }

    fn binop_div(&mut self, span: Span, op_name: &'static str) -> Result<(), AnalError> {
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let result = match (&a, &b) {
            (Value::Int(_), Value::Int(0)) => {
                return Err(AnalError::Rejection {
                    expected: "non-zero divisor",
                    found: "INT(0)",
                    span,
                });
            }
            (Value::Int(x), Value::Int(y)) => Value::Int(x / y),
            (Value::Float(x), Value::Float(y)) => Value::Float(x / y),
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name(),
                    span,
                });
            }
        };
        self.stack.push(result);
        Ok(())
    }

    fn binop_mod(&mut self, span: Span, op_name: &'static str) -> Result<(), AnalError> {
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let result = match (&a, &b) {
            (Value::Int(_), Value::Int(0)) => {
                return Err(AnalError::Rejection {
                    expected: "non-zero divisor",
                    found: "INT(0)",
                    span,
                });
            }
            (Value::Int(x), Value::Int(y)) => Value::Int(x % y),
            (Value::Float(x), Value::Float(y)) => Value::Float(x % y),
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name(),
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
        let b = self.pop(op_name, span)?;
        let a = self.pop(op_name, span)?;
        let ord = match (&a, &b) {
            (Value::Int(x), Value::Int(y)) => x.cmp(y),
            (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).ok_or(AnalError::Rejection {
                expected: "ordered FLOAT",
                found: "NaN",
                span,
            })?,
            _ => {
                return Err(AnalError::Rejection {
                    expected: "matching numeric types",
                    found: a.type_name(),
                    span,
                });
            }
        };
        self.stack.push(Value::Bool(f(ord)));
        Ok(())
    }

    fn convert_to_int(&mut self, span: Span) -> Result<(), AnalError> {
        let v = self.pop("TO_INT", span)?;
        let n = match &v {
            Value::Int(n) => *n,
            Value::Float(f) => *f as i64,
            Value::Bool(b) => *b as i64,
            Value::Str(s) => s.parse::<i64>().map_err(|_| AnalError::Rejection {
                expected: "INT-parseable STRING",
                found: "non-numeric STRING",
                span,
            })?,
            _ => {
                return Err(AnalError::Rejection {
                    expected: "INT-convertible value",
                    found: v.type_name(),
                    span,
                });
            }
        };
        self.stack.push(Value::Int(n));
        Ok(())
    }

    fn convert_to_float(&mut self, span: Span) -> Result<(), AnalError> {
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
                found: "non-numeric STRING",
                span,
            })?,
            _ => {
                return Err(AnalError::Rejection {
                    expected: "FLOAT-convertible value",
                    found: v.type_name(),
                    span,
                });
            }
        };
        self.stack.push(Value::Float(x));
        Ok(())
    }

    fn convert_to_str(&mut self, span: Span) -> Result<(), AnalError> {
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
        let code = match compile(src) {
            Ok(c) => c,
            Err(e) => return (String::new(), String::new(), Err(e)),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut vm = VM::new();
        let result = vm.run(&code, &mut out, &mut err);
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
}
