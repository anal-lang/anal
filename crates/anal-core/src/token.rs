//! Tokens emitted by the lexer, plus the [`Span`] and [`Spanned`] types
//! used to track source positions for error reporting.

use logos::Logos;

/// A byte range in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub const fn dummy() -> Self {
        Self { start: 0, end: 0 }
    }
}

impl From<std::ops::Range<usize>> for Span {
    fn from(r: std::ops::Range<usize>) -> Self {
        Self {
            start: r.start,
            end: r.end,
        }
    }
}

impl From<Span> for std::ops::Range<usize> {
    fn from(s: Span) -> Self {
        s.start..s.end
    }
}

/// A value paired with the [`Span`] it was parsed from.
#[derive(Debug, Clone)]
pub struct Spanned<T> {
    pub node: T,
    pub span: Span,
}

impl<T> Spanned<T> {
    pub fn new(node: T, span: Span) -> Self {
        Self { node, span }
    }
}

/// Tokens emitted by the ANAL lexer.
///
/// Whitespace and `;` line comments are skipped. Keyword tokens are exact
/// matches against the uppercase forms specified by the language; any other
/// alphanumeric run is an [`Ident`](Token::Ident). The parser is responsible
/// for noticing that a lowercase identifier matches the case-insensitive
/// form of a keyword and raising a `CASING` error.
#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r\n]+")]
#[logos(skip r";[^\n]*")]
pub enum Token {
    // ── Header ────────────────────────────────────────
    #[token("ANAL")]
    Anal,
    #[token("VERSION")]
    Version,
    #[token("INGEST")]
    Ingest,

    // ── Stack ─────────────────────────────────────────
    #[token("PUSH")]
    Push,
    #[token("POP")]
    Pop,
    #[token("PROBE")]
    Probe,
    #[token("INSERT")]
    Insert,
    #[token("EXTRACT")]
    Extract,
    #[token("SWAP")]
    Swap,
    #[token("DUP")]
    Dup,
    #[token("DEPTH")]
    Depth,
    #[token("FLUSH")]
    Flush,

    // ── Control / state ───────────────────────────────
    #[token("PREP")]
    Prep,
    #[token("CLENCH")]
    Clench,
    #[token("RELEASE")]
    Release,
    #[token("CONSENT")]
    Consent,
    #[token("EXPAND")]
    Expand,
    #[token("HOLD")]
    Hold,
    #[token("RESUME")]
    Resume,

    // ── I/O ───────────────────────────────────────────
    #[token("RECEIVE")]
    Receive,
    #[token("EXPEL")]
    Expel,
    #[token("DISCHARGE")]
    Discharge,
    #[token("EVACUATE")]
    Evacuate,

    // ── Flow ──────────────────────────────────────────
    #[token("DILATE")]
    Dilate,
    #[token("CONSTRICT")]
    Constrict,
    #[token("IF_TIGHT")]
    IfTight,
    #[token("IF_LOOSE")]
    IfLoose,
    #[token("PASSAGE")]
    Passage,
    #[token("ENTER")]
    Enter,
    #[token("EXIT")]
    Exit,
    #[token("ABORT")]
    Abort,

    // ── Arithmetic / comparison ───────────────────────
    #[token("ADD")]
    Add,
    #[token("SUB")]
    Sub,
    #[token("MUL")]
    Mul,
    #[token("DIV")]
    Div,
    #[token("MOD")]
    Mod,
    #[token("EQ")]
    EqOp,
    #[token("LT")]
    Lt,
    #[token("GT")]
    Gt,
    #[token("LTE")]
    Lte,
    #[token("GTE")]
    Gte,
    #[token("NOT")]
    Not,

    // ── Conversion ────────────────────────────────────
    #[token("TO_INT")]
    ToInt,
    #[token("TO_FLOAT")]
    ToFloat,
    #[token("TO_STRING")]
    ToStr,

    // ── Bool literals ─────────────────────────────────
    #[token("TRUE")]
    True,
    #[token("FALSE")]
    False,

    // ── Literals with payload ─────────────────────────
    #[regex(r"-?[0-9]+\.[0-9]+", |lex| lex.slice().parse::<f64>().ok())]
    Float(f64),

    #[regex(r"-?[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    Int(i64),

    #[regex(r#""([^"\\]|\\.)*""#, |lex| unescape(&lex.slice()[1..lex.slice().len()-1]))]
    Str(String),

    #[regex(r"[A-Za-z_][A-Za-z_0-9]*", |lex| lex.slice().to_string())]
    Ident(String),

    // ── Structural ────────────────────────────────────
    #[token("[")]
    LBracket,
    #[token("]")]
    RBracket,
    #[token(":")]
    Colon,
}

/// Resolve `\n`, `\t`, `\r`, `\\`, and `\"` escapes inside a string literal.
/// Returns `None` if an unknown escape is encountered.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => out.push('\r'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}
