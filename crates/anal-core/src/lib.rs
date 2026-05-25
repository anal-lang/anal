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
//!     -> [`lexer::lex`]   -> Vec<Spanned<Token>>
//!     -> [`parser::compile`] -> Program (bytecode)
//!     -> [`check::check_program`] -> static MISMATCH or pass
//!     -> [`vm::VM::execute`] -> side effects + final stack state
//! ```
//!
//! See <https://github.com/anal-lang/anal> for the language specification.

pub mod ast;
pub mod check;
pub mod compiler;
pub mod error;
pub mod ledger;
pub mod lexer;
pub mod op;
pub mod parser;
pub mod session;
pub mod token;
pub mod value;
pub mod vm;

pub use error::AnalError;
pub use ledger::{
    hash_source, LedgerError, LedgerReader, LedgerRecord, LedgerSink, OpTag as LedgerOpTag,
    TypeTag as LedgerTypeTag,
};
pub use op::{Instr, Op, Program};
pub use parser::{compile, compile_fragment, is_unfinished, Fragment};
pub use session::Session;
pub use token::Span;
pub use value::Value;
pub use vm::{BoxedLedger, VM};
