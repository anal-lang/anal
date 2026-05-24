//! Abstract syntax tree for ANAL programs.
//!
//! Reserved namespace. The v0.1 pipeline lowers directly from parser
//! to bytecode without a separate AST stage — the language is currently
//! simple enough that the parser doubles as a code generator (see
//! [`crate::op`]).
//!
//! A real AST will land here when the eventual self-hosted compiler
//! (`analc`, written in ANAL) needs a target data structure it can
//! produce from `.anal` source and consume to emit `.sph` bytecode.

#![doc(hidden)]
