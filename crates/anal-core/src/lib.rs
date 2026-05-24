//! Reference implementation core for the ANAL programming language.
//!
//! ANAL: Append-oriented, Narrow-access Language. A stack-based,
//! strongly-typed programming language with consent-enforced
//! destructive operations.
//!
//! The compilation pipeline is:
//!
//! ```text
//! source text
//!     -> [`lexer`]    -> Vec<Spanned<Token>>
//!     -> [`parser`]   -> [`ast::Program`]
//!     -> [`compiler`] -> Vec<[`op::Instruction`]>
//!     -> [`vm::VM`]   -> side effects + final stack state
//! ```
//!
//! See <https://github.com/anal-lang/anal> for the language specification.

pub mod ast;
pub mod compiler;
pub mod error;
pub mod lexer;
pub mod op;
pub mod parser;
pub mod token;
pub mod value;
pub mod vm;
