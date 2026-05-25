//! # Interactive sessions
//!
//! A [`Session`] is the type-checking half of a REPL. It owns the
//! abstract stack and the cumulative passage table, so each new
//! fragment of source can be parsed, checked against the current
//! state, and handed back as a [`Program`] ready for the VM.
//!
//! The runtime stack and latch state live on the [`crate::VM`]; the
//! REPL keeps both side by side. The convention on failure is total:
//! if a fragment fails to parse or fails to type-check, the session
//! is untouched — neither the passage table nor the abstract stack
//! moves. The REPL then runs the resulting [`Program`] through the
//! VM, and if *that* fails, the VM's stack is also unaffected for
//! any op that errored before mutating.
//!
//! On success, both the abstract stack and the passage table advance
//! by exactly what the fragment did, so the next call to
//! [`Session::feed`] sees the new shape.

use std::collections::HashMap;
use std::rc::Rc;

use crate::check::{check_fragment, Ty};
use crate::error::AnalError;
use crate::op::{Instr, Program};
use crate::parser::compile_fragment;

/// Persistent type-check state for an interactive ANAL session.
///
/// One `Session` corresponds to one REPL — fragments fed in
/// sequence build up the abstract stack and passage table.
pub struct Session {
    /// Passages defined so far. Re-defining a name replaces the
    /// previous body, matching the REPL's interactive expectation.
    passages: HashMap<String, Rc<[Instr]>>,
    /// Abstract type stack — mirrors the runtime stack shape.
    abstract_stack: Vec<Ty>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        Self {
            passages: HashMap::new(),
            abstract_stack: Vec::new(),
        }
    }

    /// Parse and type-check `source` as a REPL fragment.
    ///
    /// On success: the abstract stack is advanced, any new passages
    /// are merged into the session table, and the returned
    /// [`Program`] is ready for the VM. The returned `Program`'s
    /// `passages` field contains the *full* session table, so any
    /// previously-defined passage is callable from the new fragment.
    ///
    /// On failure: the session state is unchanged.
    pub fn feed(&mut self, source: &str) -> Result<Program, AnalError> {
        let fragment = compile_fragment(source)?;

        // For the check pass we need the *merged* passage table —
        // any name the fragment introduces should be callable from
        // the fragment itself. We build a temporary merged view
        // without committing it to the session yet, so a check
        // failure leaves `self.passages` untouched.
        let mut merged = self.passages.clone();
        for (name, body) in &fragment.passages {
            merged.insert(name.clone(), body.clone());
        }

        check_fragment(&fragment.main, &merged, &mut self.abstract_stack)?;

        // Check passed — commit the new passages.
        self.passages = merged;

        let program = Program {
            main: Rc::from(fragment.main.into_boxed_slice()),
            passages: self.passages.clone(),
        };
        Ok(program)
    }

    /// Current abstract stack shape (top of stack last).
    pub fn stack_shape(&self) -> &[Ty] {
        &self.abstract_stack
    }

    /// Names of all passages currently defined, sorted alphabetically.
    pub fn passage_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.passages.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Drop all session state: forget every passage, clear the
    /// abstract stack. The VM-side state must be reset separately.
    pub fn reset(&mut self) {
        self.passages.clear();
        self.abstract_stack.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_pushes_advance_the_stack() {
        let mut s = Session::new();
        s.feed("PUSH 1").unwrap();
        s.feed("PUSH 2").unwrap();
        assert_eq!(s.stack_shape(), &[Ty::Int, Ty::Int]);
    }

    #[test]
    fn feed_arithmetic_collapses_the_stack() {
        let mut s = Session::new();
        s.feed("PUSH 1 PUSH 2 ADD").unwrap();
        assert_eq!(s.stack_shape(), &[Ty::Int]);
    }

    #[test]
    fn feed_type_error_leaves_stack_untouched() {
        let mut s = Session::new();
        s.feed("PUSH 1 PUSH 2").unwrap();
        let before = s.stack_shape().to_vec();
        let err = s.feed(r#"PUSH "hi" ADD"#).unwrap_err();
        assert!(matches!(err, AnalError::Mismatch { .. }), "got {err:?}");
        assert_eq!(s.stack_shape(), &before[..]);
    }

    #[test]
    fn feed_passage_persists_and_is_callable_next_line() {
        let mut s = Session::new();
        s.feed("PASSAGE square: DUP MUL EXIT").unwrap();
        assert_eq!(s.passage_names(), vec!["square"]);
        s.feed("PUSH 9 ENTER square").unwrap();
        assert_eq!(s.stack_shape(), &[Ty::Int]);
    }

    #[test]
    fn feed_passage_redefinition_replaces() {
        let mut s = Session::new();
        s.feed("PASSAGE p: PUSH 1 EXIT").unwrap();
        s.feed("PASSAGE p: PUSH 2 EXIT").unwrap();
        s.feed("ENTER p").unwrap();
        assert_eq!(s.stack_shape(), &[Ty::Int]);
    }

    #[test]
    fn feed_passage_self_reference_in_same_fragment_works() {
        // A passage defined and called inside the same fragment
        // must see itself in the table during the check pass.
        let mut s = Session::new();
        s.feed("PASSAGE p: PUSH 1 EXIT  PUSH 5 ENTER p").unwrap();
        assert_eq!(s.stack_shape(), &[Ty::Int, Ty::Int]);
    }

    #[test]
    fn reset_clears_everything() {
        let mut s = Session::new();
        s.feed("PASSAGE p: PUSH 1 EXIT  PUSH 1 PUSH 2").unwrap();
        s.reset();
        assert!(s.passage_names().is_empty());
        assert!(s.stack_shape().is_empty());
    }

    #[test]
    fn feed_returns_program_with_full_passage_table() {
        // Old passages must remain in the returned Program so the
        // VM can call into them from the new fragment's main body.
        let mut s = Session::new();
        s.feed("PASSAGE square: DUP MUL EXIT").unwrap();
        let prog = s.feed("PUSH 9 ENTER square").unwrap();
        assert!(prog.passages.contains_key("square"));
    }
}
