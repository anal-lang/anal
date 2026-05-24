//! Error types and reporting.
//!
//! Every spec'd ANAL runtime error is a typed variant on [`AnalError`].
//! Each carries enough context to identify the offending source location.
//! The current rendering is plain text via `thiserror::Display`; richer
//! source-mapped output (via `ariadne`) lands once the surface area
//! stabilises.

use crate::token::Span;

#[derive(Debug, Clone, thiserror::Error)]
pub enum AnalError {
    #[error("TIGHTNESS: INSERT attempted without prior PREP")]
    Tightness { span: Span },

    #[error("EMPTINESS: {op} on an empty stack")]
    Emptiness { op: &'static str, span: Span },

    #[error("OVERFLOW: stack capacity exceeded")]
    Overflow { span: Span },

    #[error("REFUSAL: {op} requires CONSENT")]
    Refusal { op: &'static str, span: Span },

    #[error("LOCKDOWN: {op} attempted on a CLENCHed stack")]
    Lockdown { op: &'static str, span: Span },

    #[error("PENETRATION_DEPTH: depth {depth} exceeds stack size {size}")]
    PenetrationDepth {
        depth: usize,
        size: usize,
        span: Span,
    },

    #[error("REJECTION: expected {expected}, found {found}")]
    Rejection {
        expected: &'static str,
        found: &'static str,
        span: Span,
    },

    #[error("PREMATURE_RELEASE: RELEASE called on an unclenched stack")]
    PrematureRelease { span: Span },

    #[error("CASING: keyword `{keyword}` must be uppercase")]
    Casing { keyword: String, span: Span },

    #[error("FOREIGN_BODY: unrecognised token `{token}`")]
    ForeignBody { token: String, span: Span },

    #[error("RUPTURE: unclosed DILATE block")]
    Rupture { span: Span },

    #[error("PASSAGE_NOT_FOUND: no passage named `{name}`")]
    PassageNotFound { name: String, span: Span },

    #[error("PARSE: {message}")]
    Parse { message: String, span: Span },
}

impl AnalError {
    /// Spec'd error code, e.g. `"E001"` for `TIGHTNESS`.
    /// `PARSE` is internal scaffolding and reports `"E000"`.
    pub fn code(&self) -> &'static str {
        match self {
            AnalError::Tightness { .. } => "E001",
            AnalError::Emptiness { .. } => "E002",
            AnalError::Overflow { .. } => "E003",
            AnalError::Refusal { .. } => "E004",
            AnalError::Lockdown { .. } => "E005",
            AnalError::PenetrationDepth { .. } => "E006",
            AnalError::Rejection { .. } => "E007",
            AnalError::PrematureRelease { .. } => "E008",
            AnalError::Casing { .. } => "E009",
            AnalError::ForeignBody { .. } => "E010",
            AnalError::Rupture { .. } => "E011",
            AnalError::PassageNotFound { .. } => "E012",
            AnalError::Parse { .. } => "E000",
        }
    }

    pub fn span(&self) -> Span {
        match self {
            AnalError::Tightness { span }
            | AnalError::Emptiness { span, .. }
            | AnalError::Overflow { span }
            | AnalError::Refusal { span, .. }
            | AnalError::Lockdown { span, .. }
            | AnalError::PenetrationDepth { span, .. }
            | AnalError::Rejection { span, .. }
            | AnalError::PrematureRelease { span }
            | AnalError::Casing { span, .. }
            | AnalError::ForeignBody { span, .. }
            | AnalError::Rupture { span }
            | AnalError::PassageNotFound { span, .. }
            | AnalError::Parse { span, .. } => *span,
        }
    }
}
