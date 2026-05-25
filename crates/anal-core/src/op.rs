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
    /// Copy the second-from-top value to the top: `(a b -- a b a)`.
    Over,
    /// Rotate the third-from-top value to the top: `(a b c -- b c a)`.
    Rot,
    /// Drop the second-from-top value: `(a b -- b)`. Equivalent to
    /// `SWAP POP` but read-flat as a single op.
    Nip,
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
    /// Clear any armed PREP / CONSENT flags. Idempotent.
    /// ANAL forgives forgetting.
    Relax,
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
    /// Read one raw byte from stdin and PUSH it as an INT (0..=255), or -1
    /// on EOF. Pairs with [`Op::EmitByte`].
    ReceiveByte,
    /// POP an INT in 0..=255 and write it to stdout as a single raw byte.
    EmitByte,

    // ── String inspection ─────────────────────────────
    /// POP a STRING and PUSH its byte length as an INT.
    Strlen,
    /// POP an INT index and a STRING; PUSH the byte at that index as an
    /// INT in 0..=255. Out-of-bounds raises CAVITY_BREACH.
    Charat,
    /// POP an INT length, INT start, and STRING; PUSH the substring of
    /// `length` bytes starting at `start`. Out-of-bounds raises
    /// CAVITY_BREACH.
    Substr,

    // ── External storage (CAVITY) ─────────────────────
    /// Allocate a new CAVITY of `n` INT cells (all zero) and PUSH it.
    /// `n` is a compile-time literal; a non-positive `n` raises HOLLOW.
    Buffer(usize),
    /// Allocate a new CAVITY whose size is POPped from the stack as an
    /// INT and PUSH it. A non-positive size raises HOLLOW at runtime.
    /// Pair-form of [`Op::Buffer`] — same op, the size came from the
    /// stack instead of the source. Matches the [`Op::Hold`] precedent.
    BufferDyn,
    /// POP an INT index, read the cell of the CAVITY one position below
    /// it, and PUSH the result. The CAVITY remains on the stack.
    Bufget,
    /// POP an INT value and an INT index; write the value into the cell
    /// of the CAVITY one position below them. The CAVITY remains on the
    /// stack. Requires PREP and CONSENT.
    Bufset,
    /// Read the cell count of the CAVITY at the top of the stack and
    /// PUSH it as an INT. The CAVITY remains on the stack.
    Buflen,
    /// Compile-time-indexed read: peek the CAVITY on top of the stack,
    /// read cell `i`, PUSH the INT. The CAVITY remains. Sugar for the
    /// common case where the index is fixed by the program; for a
    /// runtime index, use [`Op::Bufget`].
    Load(usize),
    /// Compile-time-indexed write: POP an INT value, peek the CAVITY
    /// on top of the stack, write `cells[i] := value`. The CAVITY
    /// remains. Requires PREP and CONSENT, same as [`Op::Bufset`].
    Store(usize),

    // ── Flow control (jumps are resolved offsets) ─────
    Jump(usize),
    JumpIfFalsy(usize),
    JumpIfTruthy(usize),
    /// Call into a passage by name.
    Enter(String),
    /// Pop a BLOC from the stack and execute it.
    EnterStack,
    /// Pop a BLOC and a condition. If condition is truthy, run the BLOC.
    IfTightExec,
    /// Pop a BLOC and a condition. If condition is falsy, run the BLOC.
    IfLooseExec,
    /// Return from the current passage or BLOC.
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
