//! Lexer — turns ANAL source text into a stream of [`Token`]s with
//! attached [`Span`] information.

use logos::Logos;

use crate::error::AnalError;
use crate::token::{Span, Spanned, Token};

/// Tokenise an ANAL source string.
///
/// Whitespace and `;` line comments are dropped. Anything that doesn't
/// match any token rule surfaces as a `FOREIGN_BODY` error. Lowercase
/// keywords are lexed as plain identifiers and detected by the parser,
/// where they become `CASING` errors.
pub fn lex(source: &str) -> Result<Vec<Spanned<Token>>, AnalError> {
    let mut lex = Token::lexer(source);
    let mut out = Vec::new();
    while let Some(result) = lex.next() {
        let span: Span = lex.span().into();
        match result {
            Ok(tok) => out.push(Spanned::new(tok, span)),
            Err(_) => {
                return Err(AnalError::ForeignBody {
                    token: lex.slice().to_string(),
                    span,
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lex_hello_program() {
        let src = r#"ANAL "hello" VERSION 1
            PUSH "Hello, World!"
            EXPEL"#;
        let toks = lex(src).expect("lex should succeed");
        let kinds: Vec<_> = toks
            .iter()
            .map(|s| std::mem::discriminant(&s.node))
            .collect();
        // We expect: Anal, Str, Version, Int, Push, Str, Expel
        assert_eq!(kinds.len(), 7);
    }

    #[test]
    fn lex_skips_comments() {
        let src = "; this is a comment\nPUSH 42";
        let toks = lex(src).expect("lex should succeed");
        assert_eq!(toks.len(), 2);
        assert!(matches!(toks[0].node, Token::Push));
        assert!(matches!(toks[1].node, Token::Int(42)));
    }

    #[test]
    fn lex_handles_string_escapes() {
        let toks = lex(r#"PUSH "line1\nline2""#).expect("lex should succeed");
        assert_eq!(toks.len(), 2);
        match &toks[1].node {
            Token::Str(s) => assert_eq!(s, "line1\nline2"),
            other => panic!("expected Str, got {other:?}"),
        }
    }

    #[test]
    fn lex_foreign_body_for_unknown_punctuation() {
        let err = lex("PUSH @42").unwrap_err();
        assert!(matches!(err, AnalError::ForeignBody { .. }));
    }
}
