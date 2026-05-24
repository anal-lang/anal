//! Runtime values: INT, FLOAT, STRING, BOOL, BLOC.
//!
//! Strings and blocs are reference-counted so that `DUP` and stack copies
//! are cheap. ANAL is strongly typed; conversions are explicit (`TO_INT`,
//! `TO_FLOAT`, `TO_STRING`). The VM never coerces implicitly.

use std::fmt;
use std::rc::Rc;

use crate::op::Instr;

#[derive(Debug, Clone)]
pub enum Value {
    Int(i64),
    Float(f64),
    Str(Rc<str>),
    Bool(bool),
    Bloc(Rc<[Instr]>),
}

impl Value {
    /// Static name of the type, for error messages.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "INT",
            Value::Float(_) => "FLOAT",
            Value::Str(_) => "STRING",
            Value::Bool(_) => "BOOL",
            Value::Bloc(_) => "BLOC",
        }
    }

    /// Truthiness for `IF_TIGHT`, `IF_LOOSE`, and `DILATE` / `CONSTRICT`.
    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Int(n) => *n != 0,
            Value::Float(f) => *f != 0.0 && !f.is_nan(),
            Value::Str(s) => !s.is_empty(),
            Value::Bool(b) => *b,
            Value::Bloc(_) => true,
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Float(a), Value::Float(b)) => a == b,
            (Value::Str(a), Value::Str(b)) => a == b,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Bloc(a), Value::Bloc(b)) => Rc::ptr_eq(a, b),
            // Different variants never compare equal — strong typing.
            _ => false,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(n) => write!(f, "{n}"),
            // Debug formatting on f64 always emits a decimal point,
            // so 3.0 prints as `3.0` and 3.14 as `3.14`. That matches
            // ANAL's "float literals must contain a decimal point" rule.
            Value::Float(x) => write!(f, "{x:?}"),
            Value::Str(s) => write!(f, "{s}"),
            Value::Bool(true) => write!(f, "TRUE"),
            Value::Bool(false) => write!(f, "FALSE"),
            Value::Bloc(_) => write!(f, "[bloc]"),
        }
    }
}
