//! Static type checker — runs between [`crate::parser::compile`] and the
//! VM and refuses any program whose stack shape it cannot reconcile.
//!
//! The checker walks bytecode, maintaining an *abstract stack* — a sequence
//! of [`Ty`] values — and applies each op's typing rule. A typing rule that
//! cannot be satisfied raises [`AnalError::Mismatch`]. Programs that run
//! today and would have raised `REJECTION` at runtime now fail at probe
//! time, with the same span.
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
//! - PREP / CONSENT / CLENCH state. Those are effects, not types; they
//!   stay as runtime checks for now.
//! - Concrete values. `PUSH 0 DIV` is well-typed even though the VM will
//!   reject it at runtime. The checker is about types, not values.
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
//! `PASSAGE`s are re-checked at every call site against the caller's actual
//! stack — this gives us simple ad-hoc polymorphism (so `PASSAGE square:
//! DUP MUL EXIT` works on either INTs or FLOATs) without a real generics
//! system.

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

fn ty_of(value: &Value) -> Ty {
    match value {
        Value::Int(_) => Ty::Int,
        Value::Float(_) => Ty::Float,
        Value::Str(_) => Ty::Str,
        Value::Bool(_) => Ty::Bool,
        Value::Bloc(_) => Ty::Bloc,
    }
}

/// Entry point. Walks the program's main body — including any PASSAGE
/// calls — and returns `Ok(())` if every op's typing rule is satisfied.
pub fn check_program(program: &Program) -> Result<(), AnalError> {
    let mut ctx = Ctx::new(program);
    let mut stack: Vec<Ty> = Vec::new();
    ctx.check_block(&program.main, &mut stack)?;
    Ok(())
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

    /// Walk a straight-line code block, applying each op's typing rule.
    /// Loops and conditional BLOC execution are handled internally.
    fn check_block(&mut self, code: &[Instr], stack: &mut Vec<Ty>) -> Result<(), AnalError> {
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
                    self.check_block(&code[body_start..body_end], stack)?;
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
                    // literal), walk it on a copy of the stack and merge:
                    // arm-ran vs arm-didn't-run. Conflicting slots collapse
                    // to Ty::Top.
                    if let Some(body) = just_pushed_bloc.as_ref() {
                        let mut ran = stack.clone();
                        self.check_block(body, &mut ran)?;
                        merge_into(stack, &ran, span)?;
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
                        self.check_block(&body, stack)?;
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
                        let result = self.check_block(&body, stack);
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
                Op::Depth => stack.push(Ty::Int),
                Op::Extract(_) => {
                    // EXTRACT removes one value; we don't know its type
                    // statically (it's at a depth), so just shrink shape.
                    pop_any(stack, "EXTRACT", span)?;
                }
                Op::Insert { value, .. } => {
                    // INSERT places a value at a depth without consuming
                    // anything from the top.
                    stack.push(ty_of(value));
                }
                Op::Flush => stack.clear(),

                // ── consent / capacity / pause (stack-neutral, no-op for types) ──
                Op::Prep
                | Op::Consent
                | Op::Relax
                | Op::Clench
                | Op::Release
                | Op::Expand(_)
                | Op::Hold(_)
                | Op::Resume => {}

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
}
