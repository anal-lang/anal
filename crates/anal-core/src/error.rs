//! Error types and reporting.
//!
//! Every spec'd ANAL runtime error is a typed variant on [`AnalError`].
//! Each carries enough context to identify the offending source location
//! and renders through `ariadne` for compiler-quality output: a labelled
//! squiggle under the offending token, a help line, and a spec-voice note.

use std::io::Write;

use ariadne::{Color, Config, Label, Report, ReportKind, Source};

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
        found: String,
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

    /// Render the error as a compiler-quality diagnostic — labelled
    /// squiggle, help, and spec-voice note — into `out`.
    ///
    /// `source_id` is the file path (or `"<stdin>"` etc.) shown in the
    /// header; `source` is the full source text the span indexes into.
    /// `color` toggles ANSI escapes; pass `false` when writing to a
    /// non-tty sink.
    pub fn render<W: Write>(
        &self,
        source_id: &str,
        source: &str,
        color: bool,
        out: &mut W,
    ) -> std::io::Result<()> {
        let span = self.span();
        let range = span.start..span.end;
        let primary = Color::Red;
        let title = self.title();

        let mut builder = Report::build(ReportKind::Error, source_id, range.start)
            .with_code(self.code())
            .with_config(Config::default().with_color(color))
            .with_message(title);

        let label = Label::new((source_id, range))
            .with_message(self.label_message())
            .with_color(primary);
        builder = builder.with_label(label);

        if let Some(help) = self.help_text() {
            builder = builder.with_help(help);
        }
        if let Some(note) = self.note_text() {
            builder = builder.with_note(note);
        }

        builder
            .finish()
            .write((source_id, Source::from(source)), out)
    }

    fn title(&self) -> &'static str {
        match self {
            AnalError::Tightness { .. } => "TIGHTNESS",
            AnalError::Emptiness { .. } => "EMPTINESS",
            AnalError::Overflow { .. } => "OVERFLOW",
            AnalError::Refusal { .. } => "REFUSAL",
            AnalError::Lockdown { .. } => "LOCKDOWN",
            AnalError::PenetrationDepth { .. } => "PENETRATION_DEPTH",
            AnalError::Rejection { .. } => "REJECTION",
            AnalError::PrematureRelease { .. } => "PREMATURE_RELEASE",
            AnalError::Casing { .. } => "CASING",
            AnalError::ForeignBody { .. } => "FOREIGN_BODY",
            AnalError::Rupture { .. } => "RUPTURE",
            AnalError::PassageNotFound { .. } => "PASSAGE_NOT_FOUND",
            AnalError::Parse { .. } => "PARSE",
        }
    }

    fn label_message(&self) -> String {
        match self {
            AnalError::Tightness { .. } => "INSERT attempted without prior PREP".into(),
            AnalError::Emptiness { op, .. } => format!("{op} on an empty stack"),
            AnalError::Overflow { .. } => "stack capacity exceeded".into(),
            AnalError::Refusal { op, .. } => format!("{op} requires CONSENT"),
            AnalError::Lockdown { op, .. } => format!("{op} attempted on a CLENCHed stack"),
            AnalError::PenetrationDepth { depth, size, .. } => {
                format!("depth {depth} exceeds stack size {size}")
            }
            AnalError::Rejection {
                expected, found, ..
            } => {
                format!("expected {expected}, found {found}")
            }
            AnalError::PrematureRelease { .. } => "RELEASE on an unclenched stack".into(),
            AnalError::Casing { keyword, .. } => format!("`{keyword}` must be uppercase"),
            AnalError::ForeignBody { token, .. } => format!("unrecognised token `{token}`"),
            AnalError::Rupture { .. } => "DILATE block was never closed".into(),
            AnalError::PassageNotFound { name, .. } => format!("no passage named `{name}`"),
            AnalError::Parse { message, .. } => message.clone(),
        }
    }

    fn help_text(&self) -> Option<String> {
        match self {
            AnalError::Tightness { .. } => Some("add `PREP` immediately before this line".into()),
            AnalError::Overflow { .. } => Some("use `EXPAND <n>` proactively".into()),
            AnalError::Refusal { .. } => Some("add `CONSENT` immediately before this line".into()),
            AnalError::Lockdown { .. } => {
                Some("`RELEASE` the stack first, or move this op outside the CLENCH".into())
            }
            AnalError::Rejection { .. } => {
                Some("use `TO_INT`, `TO_FLOAT`, or `TO_STRING` to convert explicitly".into())
            }
            AnalError::Casing { keyword, .. } => {
                Some(format!("write `{}`", keyword.to_uppercase()))
            }
            AnalError::Rupture { .. } => Some("add `CONSTRICT` to close this block".into()),
            AnalError::PassageNotFound { name, .. } => {
                Some(format!("declare it with `PASSAGE {name}:` ... `EXIT`"))
            }
            _ => None,
        }
    }

    fn note_text(&self) -> Option<&'static str> {
        match self {
            AnalError::Tightness { .. } => {
                Some("always prepare. ANAL does not stretch on demand.")
            }
            AnalError::Emptiness { .. } => {
                Some("ANAL has no concept of nothing. POP, PROBE, and DISCHARGE all require a value.")
            }
            AnalError::Overflow { .. } => Some("ANAL grows when asked, not in a panic."),
            AnalError::Refusal { .. } => Some(
                "ANAL does not assume ongoing consent. Each destructive op needs its own.",
            ),
            AnalError::Lockdown { .. } => Some(
                "write operations are forbidden while the stack is clenched. PROBE and EXPEL remain available.",
            ),
            AnalError::PenetrationDepth { .. } => Some("you cannot reach below the bottom."),
            AnalError::Rejection { .. } => {
                Some("ANAL is strongly typed. Implicit conversion is not offered.")
            }
            AnalError::PrematureRelease { .. } => Some("there is nothing to release."),
            AnalError::Casing { .. } => Some("ANAL is case-sensitive. Keywords are uppercase."),
            AnalError::ForeignBody { .. } => Some("ANAL does not accept what it does not know."),
            AnalError::Rupture { .. } => Some("ANAL does not leave things open."),
            _ => None,
        }
    }
}
