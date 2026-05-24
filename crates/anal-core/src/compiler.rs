//! Compiler — lowering from [`ast`](crate::ast) to [`op::Instr`](crate::op).
//!
//! Reserved namespace. The v0.1 reference implementation merges
//! parsing and code generation into [`crate::parser`]; there is
//! currently no separate compiler stage to host here.
//!
//! This module is the planned home of the bytecode emitter once the
//! self-hosted `analc` (ANAL compiling ANAL into `.sph`) needs a Rust
//! counterpart for bootstrap and verification.

#![doc(hidden)]
