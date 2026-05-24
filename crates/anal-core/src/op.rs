//! Bytecode operation codes and instructions.
//!
//! The compilation pipeline currently emits a flat `Vec<Instr>` rather than
//! a separate intermediate AST — the language is simple enough that the
//! parser doubles as a code generator. Each [`Instr`] carries the [`Span`]
//! of the source token it originated from, so the VM can surface useful
//! error spans even after compilation.

use std::collections::HashMap;
use std::rc::Rc;

use crate::token::Span;
use crate::value::Value;

/// A complete compiled ANAL program: the main entry-point bytecode plus
/// any [`PASSAGE`](Op::Enter)-declared subroutines.
///
/// Bodies are stored behind `Rc` so the VM can keep cheap references to
/// the currently-executing block in its call stack.
#[derive(Debug, Clone)]
pub struct Program {
    pub main: Rc<[Instr]>,
    pub passages: HashMap<String, Rc<[Instr]>>,
}

/// One bytecode instruction in compiled form.
#[derive(Debug, Clone, PartialEq)]
pub struct Instr {
    pub op: Op,
    pub span: Span,
}

impl Instr {
    pub fn new(op: Op, span: Span) -> Self {
        Self { op, span }
    }
}

/// The set of operations recognised by the VM.
///
/// Variants that are spec'd but not yet executable raise a generic error
/// at runtime; the parser accepts them so source files stay valid as the
/// implementation fills in.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    // ── Stack ─────────────────────────────────────────
    /// Push a literal value onto the stack.
    Push(Value),
    Pop,
    /// Print the top of stack without removing it.
    Probe,
    Dup,
    Swap,
    /// Push the current stack depth as an INT.
    Depth,
    /// Remove a value from `depth` positions below the top. Requires CONSENT.
    Extract(usize),
    /// Insert a value `depth` positions below the top. Requires PREP.
    Insert {
        depth: usize,
        value: Value,
    },
    /// Clear the entire stack. Requires CONSENT.
    Flush,

    // ── Control / state ───────────────────────────────
    Prep,
    Clench,
    Release,
    Consent,
    Expand(usize),
    Hold(Option<u64>),
    Resume,

    // ── I/O ───────────────────────────────────────────
    Expel,
    Discharge,
    /// Read one line from stdin and push it as a STRING (newline stripped).
    Receive,
    /// Read the file at the given path and push its contents as a STRING.
    IngestFile(String),
    /// Write the top of stack to the given path. Does not POP. Overwrites.
    /// Requires CONSENT if the file already exists.
    Evacuate(String),

    // ── Flow control (jumps are resolved offsets) ─────
    Jump(usize),
    JumpIfFalsy(usize),
    JumpIfTruthy(usize),
    /// Call into a passage by name (resolved at compile time in v0.2).
    Enter(String),
    /// Return from the current passage.
    Return,
    /// Terminate the program immediately.
    Abort,

    // ── Arithmetic ────────────────────────────────────
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // ── Comparison ────────────────────────────────────
    EqOp,
    Lt,
    Gt,
    Lte,
    Gte,
    Not,

    // ── Conversion ────────────────────────────────────
    ToInt,
    ToFloat,
    ToStr,
}
