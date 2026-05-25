//! # Static type checker
//!
//! Runs between [`crate::parser::compile`] and the VM, and refuses
//! any program whose stack shape it cannot reconcile. The checker
//! walks bytecode with an *abstract stack* — a sequence of [`Ty`]
//! values — and applies each op's typing rule. A rule that cannot
//! be satisfied raises [`AnalError::Mismatch`] at the offending
//! span, so programs that would have raised `REJECTION` at runtime
//! now fail before they start.
//!
//! ## What it tracks
//!
//! - Element types (INT, FLOAT, STR, BOOL, BLOC), plus [`Ty::Top`] for
//!   "some value, type unknown" — used to keep checking past a branch merge
//!   where the two arms disagree.
//! - Stack *shape* (depth) — at every point we know the minimum depth and
//!   refuse pops that would underflow.
//!
//! ## What it does not track
//!
//! - Concrete values. `PUSH 0 DIV` is well-typed even though the VM will
//!   reject it at runtime. The checker is about types, not values.
//!
//! ## What it also tracks — the consent effect
//!
//! Alongside the abstract stack, the checker walks an [`Effect`] — the
//! abstract counterpart of the runtime latches held on `VM`
//! (`prep_armed`, `consent_armed`, `clench_depth`). A destructive op
//! (`INSERT`, `EXTRACT`, `FLUSH`, `BUFSET`, `STORE`) raises its
//! existing `TIGHTNESS` / `REFUSAL` / `LOCKDOWN` variant at probe time
//! when the checker can prove the precondition is not met on every
//! path that reaches the op.
//!
//! Each latch is a three-valued [`Latch`] (`Unarmed`, `Armed`, `Top`).
//! `Top` is the join of disagreeing branches — "armed on one path,
//! unarmed on another, so we cannot prove either." A destructive op
//! requires `Armed`; both `Unarmed` and `Top` are rejected. `clench_depth`
//! is an `Option<u32>`: `Some(n)` when every path agrees, `None` when
//! arms disagree (treated as unknown, so any LOCKDOWN check fails).
//!
//! At an `IF_TIGHT`/`IF_LOOSE` merge the arm-ran effect is joined into
//! the outer effect. At a `DILATE` back-edge the entry effect is
//! joined with the body-exit effect, since the loop may run zero or
//! more times. The join is associative and commutative, so loop order
//! does not matter.
//!
//! ## Control flow
//!
//! `IF_TIGHT [ ... ]` and `IF_LOOSE [ ... ]` are compiled as
//! `Push(Bloc) ; IfTightExec`. The checker treats the bloc body as a
//! *conditionally-executed* sub-walk: it checks both "ran" and "didn't run"
//! arms and merges the resulting stacks slot-by-slot. Conflicting types
//! collapse to [`Ty::Top`].
//!
//! `DILATE ... CONSTRICT` is checked by walking the body once and demanding
//! that, after popping the loop condition, the stack shape at the start of
//! the body equals the shape at the back-edge.
//!
//! `PASSAGE`s are re-checked at every call site against the
//! caller's actual stack. This buys us ad-hoc polymorphism for
//! free — `PASSAGE square: DUP MUL EXIT` works on either INTs or
//! FLOATs because the body sees the real types on each call. No
//! generics machinery, no inference; just walk it again.

use std::collections::{HashMap, HashSet};

use crate::error::AnalError;
use crate::op::{Instr, Op, Program};
use crate::token::Span;
use crate::value::Value;

/// Static element type. Mirrors [`Value::type_name`] plus a `Top` for
/// "unknown — could be anything, do not match against it strictly."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Int,
    Float,
    Str,
    Bool,
    Bloc,
    Cavity,
    Top,
}

impl Ty {
    fn name(self) -> &'static str {
        match self {
            Ty::Int => "INT",
            Ty::Float => "FLOAT",
            Ty::Str => "STRING",
            Ty::Bool => "BOOL",
            Ty::Bloc => "BLOC",
            Ty::Cavity => "CAVITY",
            Ty::Top => "<any>",
        }
    }

    /// Two types unify (for merge/branch joining) if they are equal, or if
    /// either is `Top` — `Top` absorbs anything.
    fn merge(a: Ty, b: Ty) -> Ty {
        if a == b {
            a
        } else {
            Ty::Top
        }
    }
}

/// Three-valued latch state for the static consent effect.
///
/// `Unarmed` and `Armed` mirror the runtime booleans precisely;
/// `Top` represents "different on different paths, so unknown."
/// Destructive ops require `Armed` and reject `Top` the same way
/// they reject `Unarmed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Latch {
    #[default]
    Unarmed,
    Armed,
    Top,
}

impl Latch {
    /// Lattice join. Equal inputs are preserved; disagreement raises to `Top`.
    fn join(a: Latch, b: Latch) -> Latch {
        match (a, b) {
            (Latch::Unarmed, Latch::Unarmed) => Latch::Unarmed,
            (Latch::Armed, Latch::Armed) => Latch::Armed,
            _ => Latch::Top,
        }
    }

    fn is_armed(self) -> bool {
        matches!(self, Latch::Armed)
    }
}

/// Abstract consent state — the static counterpart of the runtime
/// latches held on `VM` (`prep_armed`, `consent_armed`, `clench_depth`).
///
/// Each latch is a [`Latch`]; `clench_depth` is `Some(n)` when every
/// reaching path agrees on the depth and `None` when paths disagree
/// (treated as unknown). Joined at control-flow merges via
/// [`Effect::join_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effect {
    prep: Latch,
    consent: Latch,
    clench_depth: Option<u32>,
}

impl Default for Effect {
    fn default() -> Self {
        Self {
            prep: Latch::Unarmed,
            consent: Latch::Unarmed,
            clench_depth: Some(0),
        }
    }
}

impl Effect {
    /// Join `other` into `self`. Latches join via the [`Latch`] lattice;
    /// `clench_depth` is preserved when both paths agree on the depth
    /// and otherwise collapses to `None` (unknown).
    fn join_with(&mut self, other: &Effect) {
        self.prep = Latch::join(self.prep, other.prep);
        self.consent = Latch::join(self.consent, other.consent);
        self.clench_depth = match (self.clench_depth, other.clench_depth) {
            (Some(a), Some(b)) if a == b => Some(a),
            _ => None,
        };
    }
}

fn ty_of(value: &Value) -> Ty {
    match value {
        Value::Int(_) => Ty::Int,
        Value::Float(_) => Ty::Float,
        Value::Str(_) => Ty::Str,
        Value::Bool(_) => Ty::Bool,
        Value::Bloc(_) => Ty::Bloc,
        Value::Cavity(_) => Ty::Cavity,
    }
}

/// Entry point. Walks the program's main body — including any PASSAGE
/// calls — and returns `Ok(())` if every op's typing rule is satisfied.
pub fn check_program(program: &Program) -> Result<(), AnalError> {
    let mut ctx = Ctx::new(program);
    let mut stack: Vec<Ty> = Vec::new();
    let mut effect = Effect::default();
    ctx.check_block(&program.main, &mut stack, &mut effect)?;
    Ok(())
}

/// Incremental check used by the REPL: walks `code` against an existing
/// `stack` (mutated in place), the supplied `passages` table, and the
/// REPL's persistent effect state.
///
/// On success, `stack` and `effect` reflect the abstract state after
/// running the fragment. On failure, both are restored to their
/// pre-fragment values — the REPL convention is that a rejected line
/// changes nothing.
pub fn check_fragment(
    code: &[Instr],
    passages: &HashMap<String, std::rc::Rc<[Instr]>>,
    stack: &mut Vec<Ty>,
    effect: &mut Effect,
) -> Result<(), AnalError> {
    let stack_snapshot = stack.clone();
    let effect_snapshot = *effect;
    let mut ctx = Ctx {
        passages,
        on_stack: HashSet::new(),
    };
    match ctx.check_block(code, stack, effect) {
        Ok(()) => Ok(()),
        Err(e) => {
            *stack = stack_snapshot;
            *effect = effect_snapshot;
            Err(e)
        }
    }
}

/// Shared context for a single check pass. Holds the passage table and a
/// recursion-guard set so a cyclic `ENTER` doesn't blow the call stack.
struct Ctx<'a> {
    passages: &'a HashMap<String, std::rc::Rc<[Instr]>>,
    /// Names of passages currently mid-check, for cycle detection.
    on_stack: HashSet<String>,
}

impl<'a> Ctx<'a> {
    fn new(program: &'a Program) -> Self {
        Self {
            passages: &program.passages,
            on_stack: HashSet::new(),
        }
    }

    /// Walk a straight-line code block, applying each op's typing rule
    /// and updating the abstract consent effect. Loops and conditional
    /// BLOC execution are handled internally.
    fn check_block(
        &mut self,
        code: &[Instr],
        stack: &mut Vec<Ty>,
        effect: &mut Effect,
    ) -> Result<(), AnalError> {
        let mut pc = 0;
        // The most-recently-pushed BLOC body, if the immediately-prior
        // instruction was `Push(Bloc(...))`. This lets us look inside the
        // BLOC when it is consumed by IfTightExec/IfLooseExec/EnterStack
        // and type-check the conditional arm.
        let mut last_pushed_bloc: Option<std::rc::Rc<[Instr]>> = None;

        while pc < code.len() {
            let instr = &code[pc];
            let span = instr.span;
            // Default: forget the cached bloc. Each branch that wants to
            // preserve it sets `last_pushed_bloc` again.
            let just_pushed_bloc = last_pushed_bloc.take();

            match &instr.op {
                // ── opening of a DILATE loop ──
                Op::JumpIfFalsy(target) => {
                    // Two-step strategy: snapshot the stack as it enters the
                    // loop body (after popping the condition), walk the body
                    // once, and compare the result. The condition must be on
                    // top of the stack at entry; the body must reproduce
                    // that same shape (with a fresh condition on top) by
                    // the time the back-edge fires.
                    pop_any(stack, "DILATE/IF_TIGHT", span)?;
                    let body_start = pc + 1;
                    let body_end = *target - 1; // JumpIfTruthy sits at *target - 1
                    let snapshot = stack.clone();
                    // Loop may run zero or more times: walk the body on a
                    // fresh effect copy, then join with the entry effect to
                    // model "ran" vs "skipped." This means arming inside the
                    // body does not survive past the back-edge unless it was
                    // also armed before the loop.
                    let entry_effect = *effect;
                    let mut body_effect = *effect;
                    self.check_block(&code[body_start..body_end], stack, &mut body_effect)?;
                    // The back-edge pops the condition once more.
                    pop_expect(stack, &[Ty::Top], "DILATE back-edge", span)?;
                    if *stack != snapshot {
                        return Err(AnalError::Mismatch {
                            message: format!(
                                "DILATE body must leave the stack the same shape it found it (entered with {}, exits with {})",
                                shape(&snapshot),
                                shape(stack),
                            ),
                            span,
                        });
                    }
                    *effect = entry_effect;
                    effect.join_with(&body_effect);
                    pc = *target;
                }

                // The closing JumpIfTruthy is consumed by the loop handler
                // above; if we hit one standalone, the loop_stack is
                // unbalanced — but the parser already rejects that, so
                // reaching it here would be a bug.
                Op::JumpIfTruthy(_) => {
                    return Err(AnalError::Mismatch {
                        message: "unbalanced loop back-edge — internal".into(),
                        span,
                    });
                }

                Op::Jump(target) => pc = *target,

                // ── conditional BLOC exec ──
                Op::IfTightExec | Op::IfLooseExec => {
                    pop_expect(stack, &[Ty::Bloc, Ty::Top], "IF_TIGHT/IF_LOOSE", span)?;
                    pop_any(stack, "IF_TIGHT/IF_LOOSE", span)?;
                    // If we know the BLOC body (it was pushed inline as a
                    // literal), walk it on a copy of the stack and effect.
                    // Stacks merge slot-by-slot (conflicting types → Top);
                    // effects join via the Latch lattice (arm-ran vs
                    // arm-skipped). Latch agreement is preserved; disagreement
                    // raises to Top, which destructive ops reject.
                    if let Some(body) = just_pushed_bloc.as_ref() {
                        let mut ran = stack.clone();
                        let mut ran_effect = *effect;
                        self.check_block(body, &mut ran, &mut ran_effect)?;
                        merge_into(stack, &ran, span)?;
                        effect.join_with(&ran_effect);
                    }
                    // Otherwise the BLOC came from a dynamic source (e.g.
                    // built by DUP earlier); we cannot inspect its body
                    // and leave the outer stack as-is.
                }

                Op::EnterStack => {
                    pop_expect(stack, &[Ty::Bloc, Ty::Top], "ENTER", span)?;
                    // If we know the BLOC body inline, run its effect
                    // straight into the outer stack (unconditional call).
                    if let Some(body) = just_pushed_bloc.as_ref() {
                        let body = body.clone();
                        self.check_block(&body, stack, effect)?;
                    }
                }

                Op::Enter(name) => {
                    let body = self.passages.get(name).ok_or_else(|| AnalError::Mismatch {
                        message: format!("no passage named `{name}`"),
                        span,
                    })?;
                    if self.on_stack.contains(name) {
                        // Recursive passage: we can't fixed-point its
                        // shape without iteration. Punt: assume the
                        // passage leaves the stack unchanged.
                    } else {
                        self.on_stack.insert(name.clone());
                        let body = body.clone();
                        let result = self.check_block(&body, stack, effect);
                        self.on_stack.remove(name);
                        result?;
                    }
                }

                Op::Return => return Ok(()),

                Op::Abort => return Ok(()),

                // ── stack ops ──
                Op::Push(v) => {
                    stack.push(ty_of(v));
                    // Cache the BLOC body so the next IF_TIGHT/IF_LOOSE/
                    // ENTER consumer can peek at it.
                    if let Value::Bloc(body) = v {
                        last_pushed_bloc = Some(body.clone());
                    }
                }
                Op::Pop => {
                    pop_any(stack, "POP", span)?;
                }
                Op::Probe => {
                    require_nonempty(stack, "PROBE", span)?;
                }
                Op::Dup => {
                    let top = *peek(stack, "DUP", span)?;
                    stack.push(top);
                }
                Op::Swap => {
                    if stack.len() < 2 {
                        return Err(AnalError::Mismatch {
                            message: "SWAP needs at least two values on the stack".into(),
                            span,
                        });
                    }
                    let n = stack.len();
                    stack.swap(n - 1, n - 2);
                }
                Op::Over => {
                    if stack.len() < 2 {
                        return Err(AnalError::Mismatch {
                            message: "OVER needs at least two values on the stack".into(),
                            span,
                        });
                    }
                    let second = stack[stack.len() - 2];
                    stack.push(second);
                }
                Op::Rot => {
                    if stack.len() < 3 {
                        return Err(AnalError::Mismatch {
                            message: "ROT needs at least three values on the stack".into(),
                            span,
                        });
                    }
                    let n = stack.len();
                    // (a b c -- b c a): remove element at depth 2, push to top.
                    let third = stack.remove(n - 3);
                    stack.push(third);
                }
                Op::Nip => {
                    if stack.len() < 2 {
                        return Err(AnalError::Mismatch {
                            message: "NIP needs at least two values on the stack".into(),
                            span,
                        });
                    }
                    let n = stack.len();
                    // (a b -- b): drop the second-from-top.
                    stack.remove(n - 2);
                }
                Op::Depth => stack.push(Ty::Int),
                Op::Extract(_) => {
                    // EXTRACT removes one value; we don't know its type
                    // statically (it's at a depth), so just shrink shape.
                    require_consent(effect, "EXTRACT", span)?;
                    require_unclenched(effect, "EXTRACT", span)?;
                    pop_any(stack, "EXTRACT", span)?;
                    effect.consent = Latch::Unarmed;
                }
                Op::Insert { value, .. } => {
                    // INSERT places a value at a depth without consuming
                    // anything from the top.
                    require_prep(effect, "INSERT", span)?;
                    require_unclenched(effect, "INSERT", span)?;
                    stack.push(ty_of(value));
                    effect.prep = Latch::Unarmed;
                }
                Op::Flush => {
                    require_consent(effect, "FLUSH", span)?;
                    require_unclenched(effect, "FLUSH", span)?;
                    stack.clear();
                    effect.consent = Latch::Unarmed;
                }

                // ── consent / capacity / pause ──
                Op::Prep => {
                    require_unclenched(effect, "PREP", span)?;
                    effect.prep = Latch::Armed;
                }
                Op::Consent => {
                    require_unclenched(effect, "CONSENT", span)?;
                    effect.consent = Latch::Armed;
                }
                Op::Relax => {
                    // Idempotent and allowed during CLENCH (touches latches,
                    // not the stack); mirrors the VM.
                    effect.prep = Latch::Unarmed;
                    effect.consent = Latch::Unarmed;
                }
                Op::Clench => {
                    effect.clench_depth = effect.clench_depth.map(|d| d.saturating_add(1));
                }
                Op::Release => match effect.clench_depth {
                    Some(0) => return Err(AnalError::PrematureRelease { span }),
                    Some(n) => effect.clench_depth = Some(n - 1),
                    // Depth is unknown (paths disagreed). Cannot rule out
                    // a RELEASE from depth 0 on some path; reject.
                    None => return Err(AnalError::PrematureRelease { span }),
                },
                Op::Expand(_) | Op::Hold(_) | Op::Resume => {
                    // EXPAND/HOLD/RESUME do call check_unclenched at runtime,
                    // but they aren't part of the consent story; leave the
                    // LOCKDOWN check at runtime for now.
                }

                // ── I/O ──
                Op::Expel => {
                    require_nonempty(stack, "EXPEL", span)?;
                }
                Op::Discharge => {
                    pop_any(stack, "DISCHARGE", span)?;
                }
                Op::Receive => stack.push(Ty::Str),
                Op::IngestFile(_) => stack.push(Ty::Str),
                Op::Evacuate(_) => {
                    let top = peek(stack, "EVACUATE", span)?;
                    if !matches!(top, Ty::Str | Ty::Top) {
                        return Err(AnalError::Mismatch {
                            message: format!(
                                "EVACUATE expects a STRING on top, found {}",
                                top.name()
                            ),
                            span,
                        });
                    }
                }

                // REQUEST: ( target:STR kind:STR -- granted:BOOL )
                Op::Request => {
                    pop_expect(stack, &[Ty::Str], "REQUEST kind", span)?;
                    pop_expect(stack, &[Ty::Str], "REQUEST target", span)?;
                    stack.push(Ty::Bool);
                }

                // ── arithmetic ──
                Op::Add => {
                    let b = pop_any(stack, "ADD", span)?;
                    let a = pop_any(stack, "ADD", span)?;
                    let result = match (a, b) {
                        (Ty::Int, Ty::Int) => Ty::Int,
                        (Ty::Float, Ty::Float) => Ty::Float,
                        (Ty::Str, Ty::Str) => Ty::Str,
                        (Ty::Top, _) | (_, Ty::Top) => Ty::Top,
                        _ => {
                            return Err(AnalError::Mismatch {
                                message: format!(
                                    "ADD expects matching INT/FLOAT/STRING operands, found {} + {}",
                                    a.name(),
                                    b.name(),
                                ),
                                span,
                            });
                        }
                    };
                    stack.push(result);
                }
                Op::Sub | Op::Mul | Op::Div | Op::Mod => {
                    let op_name = match instr.op {
                        Op::Sub => "SUB",
                        Op::Mul => "MUL",
                        Op::Div => "DIV",
                        Op::Mod => "MOD",
                        _ => unreachable!(),
                    };
                    let b = pop_any(stack, op_name, span)?;
                    let a = pop_any(stack, op_name, span)?;
                    let result = match (a, b) {
                        (Ty::Int, Ty::Int) => Ty::Int,
                        (Ty::Float, Ty::Float) => Ty::Float,
                        (Ty::Top, _) | (_, Ty::Top) => Ty::Top,
                        _ => {
                            return Err(AnalError::Mismatch {
                                message: format!(
                                    "{op_name} expects matching numeric operands, found {} and {}",
                                    a.name(),
                                    b.name(),
                                ),
                                span,
                            });
                        }
                    };
                    stack.push(result);
                }

                // ── comparison ──
                Op::EqOp => {
                    pop_any(stack, "EQ", span)?;
                    pop_any(stack, "EQ", span)?;
                    stack.push(Ty::Bool);
                }
                Op::Lt | Op::Gt | Op::Lte | Op::Gte => {
                    let op_name = match instr.op {
                        Op::Lt => "LT",
                        Op::Gt => "GT",
                        Op::Lte => "LTE",
                        Op::Gte => "GTE",
                        _ => unreachable!(),
                    };
                    let b = pop_any(stack, op_name, span)?;
                    let a = pop_any(stack, op_name, span)?;
                    match (a, b) {
                        (Ty::Int, Ty::Int)
                        | (Ty::Float, Ty::Float)
                        | (Ty::Top, _)
                        | (_, Ty::Top) => {}
                        _ => {
                            return Err(AnalError::Mismatch {
                                message: format!(
                                    "{op_name} expects matching numeric operands, found {} and {}",
                                    a.name(),
                                    b.name(),
                                ),
                                span,
                            });
                        }
                    }
                    stack.push(Ty::Bool);
                }
                Op::Not => {
                    pop_any(stack, "NOT", span)?;
                    stack.push(Ty::Bool);
                }

                // ── conversion ──
                Op::ToInt => {
                    pop_any(stack, "TO_INT", span)?;
                    stack.push(Ty::Int);
                }
                Op::ToFloat => {
                    pop_any(stack, "TO_FLOAT", span)?;
                    stack.push(Ty::Float);
                }
                Op::ToStr => {
                    pop_any(stack, "TO_STRING", span)?;
                    stack.push(Ty::Str);
                }

                // ── byte I/O ──
                Op::ReceiveByte => stack.push(Ty::Int),
                Op::EmitByte => {
                    pop_expect(stack, &[Ty::Int], "EMIT_BYTE", span)?;
                }

                // ── string inspection ──
                Op::Strlen => {
                    pop_expect(stack, &[Ty::Str], "STRLEN", span)?;
                    stack.push(Ty::Int);
                }
                Op::Charat => {
                    pop_expect(stack, &[Ty::Int], "CHARAT", span)?;
                    pop_expect(stack, &[Ty::Str], "CHARAT", span)?;
                    stack.push(Ty::Int);
                }
                Op::Substr => {
                    pop_expect(stack, &[Ty::Int], "SUBSTR", span)?;
                    pop_expect(stack, &[Ty::Int], "SUBSTR", span)?;
                    pop_expect(stack, &[Ty::Str], "SUBSTR", span)?;
                    stack.push(Ty::Str);
                }

                // ── external storage ──
                // BUFFER allocates a fresh CAVITY and pushes it.
                // The literal form is stack-shape neutral on entry;
                // the dynamic form pops an INT size first.
                Op::Buffer(_) => stack.push(Ty::Cavity),
                Op::BufferDyn => {
                    pop_expect(stack, &[Ty::Int], "BUFFER", span)?;
                    stack.push(Ty::Cavity);
                }
                // BUFGET: pop INT index, peek CAVITY below it, push the
                // read INT *above* the CAVITY. Net effect: index consumed,
                // INT result pushed; CAVITY untouched.
                Op::Bufget => {
                    pop_expect(stack, &[Ty::Int], "BUFGET", span)?;
                    let below = peek(stack, "BUFGET", span)?;
                    if !matches!(below, Ty::Cavity | Ty::Top) {
                        return Err(AnalError::Mismatch {
                            message: format!(
                                "BUFGET expects a CAVITY below the index, found {}",
                                below.name()
                            ),
                            span,
                        });
                    }
                    stack.push(Ty::Int);
                }
                // BUFSET: pop INT value, INT index, leaving CAVITY on top.
                // CAVITY must be there; we don't pop it.
                Op::Bufset => {
                    require_prep(effect, "BUFSET", span)?;
                    require_consent(effect, "BUFSET", span)?;
                    require_unclenched(effect, "BUFSET", span)?;
                    pop_expect(stack, &[Ty::Int], "BUFSET", span)?;
                    pop_expect(stack, &[Ty::Int], "BUFSET", span)?;
                    let below = peek(stack, "BUFSET", span)?;
                    if !matches!(below, Ty::Cavity | Ty::Top) {
                        return Err(AnalError::Mismatch {
                            message: format!(
                                "BUFSET expects a CAVITY below the index and value, found {}",
                                below.name()
                            ),
                            span,
                        });
                    }
                    effect.prep = Latch::Unarmed;
                    effect.consent = Latch::Unarmed;
                }
                // BUFLEN: peek CAVITY, push INT above it.
                Op::Buflen => {
                    let top = peek(stack, "BUFLEN", span)?;
                    if !matches!(top, Ty::Cavity | Ty::Top) {
                        return Err(AnalError::Mismatch {
                            message: format!(
                                "BUFLEN expects a CAVITY on top, found {}",
                                top.name()
                            ),
                            span,
                        });
                    }
                    stack.push(Ty::Int);
                }
                // LOAD <i>: peek CAVITY, push INT.
                Op::Load(_) => {
                    let top = peek(stack, "LOAD", span)?;
                    if !matches!(top, Ty::Cavity | Ty::Top) {
                        return Err(AnalError::Mismatch {
                            message: format!("LOAD expects a CAVITY on top, found {}", top.name()),
                            span,
                        });
                    }
                    stack.push(Ty::Int);
                }
                // STORE <i>: pop INT value, peek CAVITY beneath.
                Op::Store(_) => {
                    require_prep(effect, "STORE", span)?;
                    require_consent(effect, "STORE", span)?;
                    require_unclenched(effect, "STORE", span)?;
                    pop_expect(stack, &[Ty::Int], "STORE", span)?;
                    let below = peek(stack, "STORE", span)?;
                    if !matches!(below, Ty::Cavity | Ty::Top) {
                        return Err(AnalError::Mismatch {
                            message: format!(
                                "STORE expects a CAVITY below the value, found {}",
                                below.name()
                            ),
                            span,
                        });
                    }
                    effect.prep = Latch::Unarmed;
                    effect.consent = Latch::Unarmed;
                }
            }

            // Op::JumpIfFalsy and Op::Jump set pc directly; everything else
            // advances by one.
            if !matches!(&instr.op, Op::JumpIfFalsy(_) | Op::Jump(_)) {
                pc += 1;
            }
        }
        Ok(())
    }
}

// ── helpers ────────────────────────────────────────────

fn require_prep(effect: &Effect, op: &'static str, span: Span) -> Result<(), AnalError> {
    if effect.prep.is_armed() {
        Ok(())
    } else {
        Err(AnalError::Tightness { op, span })
    }
}

fn require_consent(effect: &Effect, op: &'static str, span: Span) -> Result<(), AnalError> {
    if effect.consent.is_armed() {
        Ok(())
    } else {
        Err(AnalError::Refusal { op, span })
    }
}

/// Rejects when the checker cannot prove `clench_depth == 0`. `None`
/// (paths disagree) is treated the same as a known nonzero depth — both
/// mean "we cannot rule out a CLENCH on some path that reaches here."
fn require_unclenched(effect: &Effect, op: &'static str, span: Span) -> Result<(), AnalError> {
    if effect.clench_depth == Some(0) {
        Ok(())
    } else {
        Err(AnalError::Lockdown { op, span })
    }
}

fn require_nonempty(stack: &[Ty], op: &'static str, span: Span) -> Result<(), AnalError> {
    if stack.is_empty() {
        Err(AnalError::Mismatch {
            message: format!("{op} on an empty stack"),
            span,
        })
    } else {
        Ok(())
    }
}

fn peek<'s>(stack: &'s [Ty], op: &'static str, span: Span) -> Result<&'s Ty, AnalError> {
    stack.last().ok_or_else(|| AnalError::Mismatch {
        message: format!("{op} on an empty stack"),
        span,
    })
}

fn pop_any(stack: &mut Vec<Ty>, op: &'static str, span: Span) -> Result<Ty, AnalError> {
    stack.pop().ok_or_else(|| AnalError::Mismatch {
        message: format!("{op} on an empty stack"),
        span,
    })
}

/// Pop a value and require it to match one of the expected types. `Ty::Top`
/// matches anything; passing `&[Ty::Top]` means "any value at all."
fn pop_expect(
    stack: &mut Vec<Ty>,
    expected: &[Ty],
    op: &'static str,
    span: Span,
) -> Result<Ty, AnalError> {
    let v = pop_any(stack, op, span)?;
    if v == Ty::Top || expected.contains(&Ty::Top) || expected.contains(&v) {
        Ok(v)
    } else {
        let names: Vec<&str> = expected.iter().map(|t| t.name()).collect();
        Err(AnalError::Mismatch {
            message: format!("{op} expected {}, found {}", names.join(" or "), v.name()),
            span,
        })
    }
}

/// Merge `arm` (the "branch ran" stack) into `stack` (the "branch skipped"
/// stack). Both started from the same outer stack, so the bottom slots are
/// shared history. Per-slot conflicts collapse to `Ty::Top`. Differing
/// depths are allowed: the merged stack keeps the *shorter* depth, since
/// slots beyond that point only existed in one arm and the runtime might
/// not have them. This matches the spec voice — types matter, but FLUSH
/// and other depth-changers are permitted to run conditionally.
fn merge_into(stack: &mut Vec<Ty>, arm: &[Ty], _span: Span) -> Result<(), AnalError> {
    let common = stack.len().min(arm.len());
    for i in 0..common {
        stack[i] = Ty::merge(stack[i], arm[i]);
    }
    stack.truncate(common);
    Ok(())
}

fn shape(stack: &[Ty]) -> String {
    if stack.is_empty() {
        "empty".into()
    } else {
        let names: Vec<&str> = stack.iter().map(|t| t.name()).collect();
        format!("[{}]", names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::compile;

    fn check_err(src: &str) -> AnalError {
        compile(src).expect_err("expected MISMATCH")
    }

    fn check_ok(src: &str) {
        compile(src).expect("expected program to type-check");
    }

    #[test]
    fn pop_on_empty_stack_is_mismatch() {
        let err = check_err("POP");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn add_int_and_string_is_mismatch() {
        let err = check_err(
            r#"PUSH "hi"
PUSH 1
ADD"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn add_two_strings_type_checks_and_runs() {
        // String concat is allowed by the spec and by the checker.
        check_ok(
            r#"PUSH "hello, "
PUSH "world"
ADD"#,
        );
    }

    #[test]
    fn sub_on_strings_is_mismatch() {
        // Only ADD is overloaded onto strings; SUB/MUL/DIV/MOD are numeric.
        let err = check_err(
            r#"PUSH "a"
PUSH "b"
SUB"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn lt_on_string_and_int_is_mismatch() {
        let err = check_err(
            r#"PUSH "a"
PUSH 1
LT"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn passage_polymorphism_works_per_call_site() {
        // Same `square` works on INT and FLOAT — the checker re-walks the
        // passage body at each call.
        check_ok(
            r#"PASSAGE square:
  DUP
  MUL
EXIT

PUSH 9
ENTER square

PUSH 3.14
ENTER square"#,
        );
    }

    #[test]
    fn passage_on_wrong_type_is_mismatch() {
        // square needs two of the same type after DUP; STRING * STRING
        // fails because MUL doesn't accept strings.
        let err = check_err(
            r#"PASSAGE square:
  DUP
  MUL
EXIT

PUSH "hi"
ENTER square"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn unknown_passage_is_mismatch() {
        let err = check_err("ENTER nope");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn if_tight_with_flush_passes() {
        // FLUSH inside IF_TIGHT changes the stack depth in one arm but
        // not the other; the checker permits this and merges to the
        // shorter common prefix.
        check_ok(
            r#"PUSH 1
PUSH 2
PUSH 3
PUSH 1
IF_TIGHT [
  CONSENT
  FLUSH
]"#,
        );
    }

    #[test]
    fn if_tight_arms_must_agree_for_subsequent_consumer() {
        // The "ran" arm pushes 42, the "skipped" arm pushes nothing. The
        // merge keeps the common prefix (empty), so a DISCHARGE after the
        // IF_TIGHT is statically empty and rejected. To pop a value
        // unconditionally after IF_TIGHT, push it on both paths — or
        // unconditionally before/after the construct.
        let err = check_err(
            r#"PUSH 1
IF_TIGHT [ PUSH 42 ]
DISCHARGE"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn if_tight_with_unconditional_pre_and_post_passes() {
        // Push a value, then conditionally do something stack-neutral, then
        // discharge it. The unconditional structure passes.
        check_ok(
            r#"PUSH 42
PUSH 1
IF_TIGHT [ PUSH "ran" DISCHARGE ]
DISCHARGE"#,
        );
    }

    #[test]
    fn dilate_body_preserving_shape_passes() {
        // The countdown pattern: each iteration pushes a fresh condition.
        check_ok(
            r#"PUSH 5
DUP PUSH 0 GT
DILATE
  DUP DISCHARGE
  PUSH 1 SUB
  DUP PUSH 0 GT
CONSTRICT
POP"#,
        );
    }

    #[test]
    fn to_string_then_concat() {
        // TO_STRING converts; concat with ADD works.
        check_ok(
            r#"PUSH "value: "
PUSH 42
TO_STRING
ADD
DISCHARGE"#,
        );
    }

    #[test]
    fn receive_pushes_a_string() {
        // RECEIVE always pushes STRING. Caller must TO_INT to do math.
        check_ok(
            r#"RECEIVE
TO_INT
PUSH 1
ADD"#,
        );
    }

    #[test]
    fn receive_without_to_int_then_add_is_mismatch() {
        let err = check_err(
            r#"RECEIVE
PUSH 1
ADD"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn swap_on_one_value_is_mismatch() {
        let err = check_err(
            r#"PUSH 1
SWAP"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn over_copies_second_to_top() {
        // OVER: (a b -- a b a). After PUSH 1 PUSH 2 OVER, stack is [1, 2, 1],
        // so three DISCHARGEs in a row work.
        check_ok(
            r#"PUSH 1
PUSH 2
OVER
DISCHARGE
DISCHARGE
DISCHARGE"#,
        );
    }

    #[test]
    fn over_with_less_than_two_is_mismatch() {
        let err = check_err("PUSH 1 OVER");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn rot_lifts_third_to_top() {
        // ROT: (a b c -- b c a). Three pushes then ROT then three DISCHARGEs.
        check_ok(
            r#"PUSH 1
PUSH 2
PUSH 3
ROT
DISCHARGE
DISCHARGE
DISCHARGE"#,
        );
    }

    #[test]
    fn rot_with_less_than_three_is_mismatch() {
        let err = check_err(
            r#"PUSH 1
PUSH 2
ROT"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn nip_drops_second() {
        check_ok(
            r#"PUSH 1
PUSH 2
NIP
DISCHARGE"#,
        );
    }

    #[test]
    fn nip_on_one_value_is_mismatch() {
        let err = check_err("PUSH 1 NIP");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    // ── v0.3 primitives ──

    #[test]
    fn strlen_pops_string_pushes_int() {
        check_ok(
            r#"PUSH "hi"
STRLEN
PUSH 1
ADD"#,
        );
    }

    #[test]
    fn strlen_on_int_is_mismatch() {
        let err = check_err("PUSH 42 STRLEN");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn charat_takes_string_then_int() {
        check_ok(
            r#"PUSH "hi"
PUSH 0
CHARAT
EMIT_BYTE"#,
        );
    }

    #[test]
    fn charat_with_swapped_args_is_mismatch() {
        // CHARAT wants STRING below, INT on top. Reversed: top is STRING,
        // INT is below — checker should reject.
        let err = check_err(
            r#"PUSH 0
PUSH "hi"
CHARAT"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn substr_returns_string() {
        check_ok(
            r#"PUSH "hello"
PUSH 1
PUSH 3
SUBSTR
DISCHARGE"#,
        );
    }

    #[test]
    fn buffer_pushes_cavity_and_buflen_keeps_it() {
        // BUFFER -> [CAVITY], BUFLEN -> [CAVITY, INT], so we can still
        // POP the CAVITY afterwards. If BUFLEN consumed the CAVITY,
        // POP would underflow (no static error since POP accepts any
        // type, but stack-shape would be wrong for a later op).
        check_ok(
            r#"BUFFER 4
BUFLEN
DISCHARGE
POP"#,
        );
    }

    #[test]
    fn bufget_keeps_cavity_returns_int() {
        // After BUFGET we expect [CAVITY, INT]. Discharge the INT,
        // then POP the CAVITY — both should typecheck.
        check_ok(
            r#"BUFFER 4
PUSH 0
BUFGET
DISCHARGE
POP"#,
        );
    }

    #[test]
    fn bufget_on_string_is_mismatch() {
        let err = check_err(
            r#"PUSH "hi"
PUSH 0
BUFGET"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn bufset_keeps_cavity() {
        // After BUFSET, the CAVITY remains; we should be able to
        // BUFGET it back without error.
        check_ok(
            r#"BUFFER 4
PUSH 2 PUSH 42
PREP CONSENT
BUFSET
PUSH 2
BUFGET
DISCHARGE
POP"#,
        );
    }

    #[test]
    fn bufset_without_cavity_underneath_is_mismatch() {
        // BUFSET expects a CAVITY below the index and value. Here
        // there's an INT instead.
        let err = check_err(
            r#"PUSH 99
PUSH 0 PUSH 1
PREP CONSENT
BUFSET"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn buflen_on_int_is_mismatch() {
        let err = check_err("PUSH 1 BUFLEN");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn receive_byte_pushes_int() {
        check_ok(
            r#"RECEIVE_BYTE
PUSH 1
ADD
DISCHARGE"#,
        );
    }

    #[test]
    fn emit_byte_requires_int() {
        let err = check_err(
            r#"PUSH "hi"
EMIT_BYTE"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn hollow_buffer_zero_is_parse_error() {
        // BUFFER 0 should be rejected at parse time, not at runtime.
        let err = compile("BUFFER 0").unwrap_err();
        assert!(matches!(err, AnalError::Hollow { .. }), "got {err:?}");
    }

    #[test]
    fn buffer_dynamic_pops_int_size() {
        // Bare BUFFER (no literal) takes its size from the stack at
        // runtime. Typecheck: it pops one INT and pushes a CAVITY.
        check_ok(
            r#"PUSH 16
BUFFER
BUFLEN
DISCHARGE
POP"#,
        );
    }

    #[test]
    fn buffer_dynamic_with_string_size_is_mismatch() {
        let err = check_err(
            r#"PUSH "nope"
BUFFER"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn load_pushes_int_keeps_cavity() {
        // LOAD <i>: peeks CAVITY, pushes INT. After it, [CAVITY, INT].
        check_ok(
            r#"BUFFER 4
LOAD 2
DISCHARGE
POP"#,
        );
    }

    #[test]
    fn load_on_int_is_mismatch() {
        let err = check_err("PUSH 1 LOAD 0");
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn store_pops_value_keeps_cavity() {
        // STORE <i>: pops INT value, peeks CAVITY. After: [CAVITY].
        check_ok(
            r#"BUFFER 4
PUSH 99
PREP CONSENT
STORE 2
LOAD 2
DISCHARGE
POP"#,
        );
    }

    #[test]
    fn store_without_cavity_is_mismatch() {
        let err = check_err(
            r#"PUSH 0
PUSH 99
PREP CONSENT
STORE 0"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    #[test]
    fn store_with_string_value_is_mismatch() {
        let err = check_err(
            r#"BUFFER 4
PUSH "nope"
PREP CONSENT
STORE 0"#,
        );
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
    }

    // ── consent effect: static enforcement of PREP/CONSENT/CLENCH ──

    #[test]
    fn insert_without_prep_is_tightness_at_probe_time() {
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
INSERT 1 99"#,
        );
        assert!(
            matches!(err, AnalError::Tightness { op: "INSERT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn extract_without_consent_is_refusal_at_probe_time() {
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
EXTRACT 1"#,
        );
        assert!(
            matches!(err, AnalError::Refusal { op: "EXTRACT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn flush_without_consent_is_refusal_at_probe_time() {
        let err = check_err(
            r#"PUSH 1 PUSH 2
FLUSH"#,
        );
        assert!(
            matches!(err, AnalError::Refusal { op: "FLUSH", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn prep_is_one_shot_in_the_checker_too() {
        // After INSERT consumes PREP, a second INSERT without re-priming
        // must be rejected statically — same one-shot semantics as the VM.
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
PREP
INSERT 1 99
INSERT 1 88"#,
        );
        assert!(
            matches!(err, AnalError::Tightness { op: "INSERT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn consent_is_one_shot_in_the_checker_too() {
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
CONSENT
EXTRACT 1
EXTRACT 0"#,
        );
        assert!(
            matches!(err, AnalError::Refusal { op: "EXTRACT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn bufset_needs_both_prep_and_consent_statically() {
        // PREP alone is not enough for BUFSET — it also needs CONSENT.
        let err = check_err(
            r#"BUFFER 4
PUSH 0 PUSH 42
PREP
BUFSET"#,
        );
        assert!(
            matches!(err, AnalError::Refusal { op: "BUFSET", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn store_needs_both_prep_and_consent_statically() {
        let err = check_err(
            r#"BUFFER 4
PUSH 42
CONSENT
STORE 0"#,
        );
        assert!(
            matches!(err, AnalError::Tightness { op: "STORE", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn insert_during_clench_is_lockdown_at_probe_time() {
        // Even with PREP armed, an INSERT inside a CLENCH must be rejected
        // statically — same LOCKDOWN the VM raises at runtime.
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
PREP
CLENCH
INSERT 1 99"#,
        );
        assert!(
            matches!(err, AnalError::Lockdown { op: "INSERT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn release_on_unclenched_is_premature_release_at_probe_time() {
        let err = check_err("RELEASE");
        assert!(
            matches!(err, AnalError::PrematureRelease { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn matched_clench_release_allows_subsequent_insert() {
        check_ok(
            r#"PUSH 1 PUSH 2 PUSH 3
CLENCH
RELEASE
PREP
INSERT 1 99"#,
        );
    }

    #[test]
    fn relax_clears_arming_in_the_checker() {
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
PREP
RELAX
INSERT 1 99"#,
        );
        assert!(
            matches!(err, AnalError::Tightness { op: "INSERT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn relax_allowed_during_clench_in_the_checker() {
        // RELAX is the only latch-adjacent op the VM permits while CLENCHed.
        // The static checker must agree.
        check_ok(
            r#"CLENCH
RELAX
RELEASE"#,
        );
    }

    #[test]
    fn passage_threads_arming_to_caller() {
        // A passage that arms PREP and returns should let the caller INSERT
        // without re-priming. The checker re-walks the passage body at the
        // call site, so the post-call effect carries PREP=armed.
        check_ok(
            r#"PASSAGE arm: PREP EXIT
PUSH 1 PUSH 2 PUSH 3
ENTER arm
INSERT 1 99"#,
        );
    }

    #[test]
    fn arming_inside_if_tight_does_not_survive_the_merge() {
        // Conservative merge: even though PREP is armed inside the IF_TIGHT
        // arm, the static checker assumes the arm may not have run and
        // treats PREP as unarmed after the merge.
        let err = check_err(
            r#"PUSH 1
IF_TIGHT [ PREP ]
PUSH 1 PUSH 2 PUSH 3
INSERT 1 99"#,
        );
        assert!(
            matches!(err, AnalError::Tightness { op: "INSERT", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn arming_in_both_arms_survives_an_if_loose_split() {
        // PREP armed before the IF, the arm RELAXes and re-PREPs (still
        // Armed at arm-exit); the skipped path keeps PREP=Armed too.
        // Join: Armed ⊔ Armed = Armed. INSERT after is legal.
        check_ok(
            r#"PUSH 1 PUSH 2 PUSH 3
PREP
PUSH 0
IF_LOOSE [
  RELAX
  PREP
]
INSERT 1 99"#,
        );
    }

    #[test]
    fn matched_clench_release_inside_if_tight_survives_the_merge() {
        // Both paths exit with clench_depth = 0 (the arm CLENCHes and
        // RELEASEs back); join preserves Some(0). A destructive op
        // after is fine.
        check_ok(
            r#"PUSH 1 PUSH 2 PUSH 3
PUSH 1
IF_TIGHT [
  CLENCH
  RELEASE
]
PREP
INSERT 1 99"#,
        );
    }

    #[test]
    fn unbalanced_clench_inside_if_tight_is_lockdown_after_the_merge() {
        // The arm CLENCHes without RELEASE, so its exit depth is 1; the
        // skipped path has depth 0. Join is None ("unknown"). A subsequent
        // PREP cannot prove the stack is unclenched and raises LOCKDOWN.
        let err = check_err(
            r#"PUSH 1
IF_TIGHT [ CLENCH ]
PREP"#,
        );
        assert!(
            matches!(err, AnalError::Lockdown { op: "PREP", .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn arming_and_consuming_inside_the_same_if_tight_works() {
        // The canonical consent_dialog.anal pattern: PREP, INSERT, all inside
        // a single conditional arm. The arm is self-contained, so the
        // collapse at merge has nothing to collapse.
        check_ok(
            r#"PUSH 1 PUSH 2 PUSH 3
PUSH 1
IF_TIGHT [
  PREP
  INSERT 1 99
]"#,
        );
    }

    #[test]
    fn arming_before_a_loop_that_does_not_touch_it_survives() {
        // The body never disarms PREP, so it stays Armed on both the
        // skipped and ran paths; the join preserves Armed. INSERT is
        // legal after the loop.
        check_ok(
            r#"PUSH 1 PUSH 2 PUSH 3
PREP
PUSH 0
DILATE
  PUSH 0
CONSTRICT
INSERT 1 99"#,
        );
    }

    #[test]
    fn arming_before_a_loop_that_clears_it_does_not_survive() {
        // The body RELAXes, which clears PREP back to Unarmed. Joining
        // the entry effect (PREP=Armed) with the body-exit effect
        // (PREP=Unarmed) gives Top, and the subsequent INSERT is
        // rejected.
        let err = check_err(
            r#"PUSH 1 PUSH 2 PUSH 3
PREP
PUSH 0
DILATE
  RELAX
  PUSH 0
CONSTRICT
INSERT 1 99"#,
        );
        assert!(
            matches!(err, AnalError::Tightness { op: "INSERT", .. }),
            "got {err:?}"
        );
    }
}
