//! Parser — turns a token stream into a flat bytecode [`Vec<Instr>`].
//!
//! The language is small enough that the parser doubles as a code generator,
//! so there is no separate AST module yet. Control flow (`DILATE`/`CONSTRICT`,
//! `IF_TIGHT`/`IF_LOOSE`) is compiled to forward and backward jumps with
//! target addresses patched as blocks close.
//!
//! Note on `IF_TIGHT [ ... ]`: the spec describes `[ ... ]` as a first-class
//! `BLOC` value. For v0.1 the brackets are treated as a parse-time block
//! delimiter only — proper `BLOC`-as-value semantics arrive with `PASSAGE`
//! support in v0.2.

use std::rc::Rc;

use crate::error::AnalError;
use crate::op::{Instr, Op};
use crate::token::{Span, Spanned, Token};
use crate::value::Value;

/// Lex + parse a complete ANAL source string into bytecode.
pub fn compile(source: &str) -> Result<Vec<Instr>, AnalError> {
    let tokens = crate::lexer::lex(source)?;
    let mut p = Parser::new(&tokens);
    p.parse_program()?;
    Ok(p.instrs)
}

struct Parser<'a> {
    tokens: &'a [Spanned<Token>],
    pos: usize,
    instrs: Vec<Instr>,
    /// (address of JumpIfFalsy to patch, address of body start).
    loop_stack: Vec<(usize, usize)>,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Spanned<Token>]) -> Self {
        Self {
            tokens,
            pos: 0,
            instrs: Vec::new(),
            loop_stack: Vec::new(),
        }
    }

    fn peek_kind(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|s| &s.node)
    }

    fn advance(&mut self) -> Option<Spanned<Token>> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn emit(&mut self, op: Op, span: Span) {
        self.instrs.push(Instr::new(op, span));
    }

    fn parse_program(&mut self) -> Result<(), AnalError> {
        self.parse_header_and_ingests()?;
        while self.peek_kind().is_some() {
            self.parse_statement()?;
        }
        if let Some((jump_addr, _)) = self.loop_stack.last() {
            return Err(AnalError::Rupture {
                span: self.instrs[*jump_addr].span,
            });
        }
        Ok(())
    }

    /// Header form: `ANAL "<name>" VERSION <int>` followed by any number of
    /// `INGEST "<path>"` declarations. Both are parsed-and-ignored at v0.1.
    fn parse_header_and_ingests(&mut self) -> Result<(), AnalError> {
        if matches!(self.peek_kind(), Some(Token::Anal)) {
            let _anal = self.advance();
            let name = self.advance().ok_or_else(|| AnalError::Parse {
                message: "ANAL header expects a string name".into(),
                span: Span::dummy(),
            })?;
            if !matches!(name.node, Token::Str(_)) {
                return Err(AnalError::Parse {
                    message: "ANAL header expects a string name".into(),
                    span: name.span,
                });
            }
            let ver_kw = self.advance().ok_or_else(|| AnalError::Parse {
                message: "ANAL header expects VERSION".into(),
                span: name.span,
            })?;
            if !matches!(ver_kw.node, Token::Version) {
                return Err(AnalError::Parse {
                    message: "ANAL header expects VERSION".into(),
                    span: ver_kw.span,
                });
            }
            let ver_num = self.advance().ok_or_else(|| AnalError::Parse {
                message: "VERSION expects an integer".into(),
                span: ver_kw.span,
            })?;
            if !matches!(ver_num.node, Token::Int(_)) {
                return Err(AnalError::Parse {
                    message: "VERSION expects an integer".into(),
                    span: ver_num.span,
                });
            }
        }
        while matches!(self.peek_kind(), Some(Token::Ingest)) {
            let ingest = self.advance().unwrap();
            let path = self.advance().ok_or_else(|| AnalError::Parse {
                message: "INGEST expects a string path".into(),
                span: ingest.span,
            })?;
            if !matches!(path.node, Token::Str(_)) {
                return Err(AnalError::Parse {
                    message: "INGEST expects a string path".into(),
                    span: path.span,
                });
            }
        }
        Ok(())
    }

    fn parse_statement(&mut self) -> Result<(), AnalError> {
        let tok = self
            .advance()
            .expect("caller checked peek_kind().is_some()");
        let span = tok.span;
        match tok.node {
            // ── PUSH literal ───────────────────────────
            Token::Push => {
                let value = self.parse_literal(span)?;
                self.emit(Op::Push(value), span);
            }

            // ── Simple stack ops ───────────────────────
            Token::Pop => self.emit(Op::Pop, span),
            Token::Probe => self.emit(Op::Probe, span),
            Token::Dup => self.emit(Op::Dup, span),
            Token::Swap => self.emit(Op::Swap, span),
            Token::Depth => self.emit(Op::Depth, span),

            // ── I/O ────────────────────────────────────
            Token::Expel => self.emit(Op::Expel, span),
            Token::Discharge => self.emit(Op::Discharge, span),

            // ── Arithmetic ─────────────────────────────
            Token::Add => self.emit(Op::Add, span),
            Token::Sub => self.emit(Op::Sub, span),
            Token::Mul => self.emit(Op::Mul, span),
            Token::Div => self.emit(Op::Div, span),
            Token::Mod => self.emit(Op::Mod, span),

            // ── Comparison ─────────────────────────────
            Token::EqOp => self.emit(Op::EqOp, span),
            Token::Lt => self.emit(Op::Lt, span),
            Token::Gt => self.emit(Op::Gt, span),
            Token::Lte => self.emit(Op::Lte, span),
            Token::Gte => self.emit(Op::Gte, span),
            Token::Not => self.emit(Op::Not, span),

            // ── Conversion ─────────────────────────────
            Token::ToInt => self.emit(Op::ToInt, span),
            Token::ToFloat => self.emit(Op::ToFloat, span),
            Token::ToStr => self.emit(Op::ToStr, span),

            // ── ABORT ──────────────────────────────────
            Token::Abort => self.emit(Op::Abort, span),

            // ── DILATE / CONSTRICT ─────────────────────
            Token::Dilate => {
                let jump_addr = self.instrs.len();
                self.emit(Op::JumpIfFalsy(0), span);
                let body_start = self.instrs.len();
                self.loop_stack.push((jump_addr, body_start));
            }
            Token::Constrict => {
                let (jump_addr, body_start) =
                    self.loop_stack.pop().ok_or_else(|| AnalError::Parse {
                        message: "CONSTRICT without matching DILATE".into(),
                        span,
                    })?;
                self.emit(Op::JumpIfTruthy(body_start), span);
                let end_addr = self.instrs.len();
                if let Op::JumpIfFalsy(ref mut target) = self.instrs[jump_addr].op {
                    *target = end_addr;
                }
            }

            // ── IF_TIGHT / IF_LOOSE [ ... ] ────────────
            Token::IfTight => self.parse_conditional_block(true, span)?,
            Token::IfLoose => self.parse_conditional_block(false, span)?,

            // ── CASING: lowercase form of a known keyword ─
            Token::Ident(name) => {
                if name != name.to_uppercase() && is_known_keyword(&name.to_uppercase()) {
                    return Err(AnalError::Casing {
                        keyword: name,
                        span,
                    });
                }
                return Err(AnalError::Parse {
                    message: format!("unexpected identifier `{name}`"),
                    span,
                });
            }

            // ── Header keywords appearing mid-program ──
            Token::Anal | Token::Version | Token::Ingest => {
                return Err(AnalError::Parse {
                    message: "header keywords are only valid before the body".into(),
                    span,
                });
            }

            // ── Spec'd but not yet supported in v0.1 ───
            other @ (Token::Insert
            | Token::Extract
            | Token::Flush
            | Token::Prep
            | Token::Clench
            | Token::Release
            | Token::Consent
            | Token::Expand
            | Token::Hold
            | Token::Resume
            | Token::Receive
            | Token::Evacuate
            | Token::Passage
            | Token::Enter
            | Token::Exit) => {
                return Err(AnalError::Parse {
                    message: format!("{other:?} is not yet implemented"),
                    span,
                });
            }

            // ── Stray literals / structural tokens ─────
            other => {
                return Err(AnalError::Parse {
                    message: format!("unexpected token: {other:?}"),
                    span,
                });
            }
        }
        Ok(())
    }

    fn parse_literal(&mut self, push_span: Span) -> Result<Value, AnalError> {
        let tok = self.advance().ok_or_else(|| AnalError::Parse {
            message: "PUSH expects a literal value".into(),
            span: push_span,
        })?;
        match tok.node {
            Token::Int(n) => Ok(Value::Int(n)),
            Token::Float(x) => Ok(Value::Float(x)),
            Token::Str(s) => Ok(Value::Str(Rc::from(s.as_str()))),
            Token::True => Ok(Value::Bool(true)),
            Token::False => Ok(Value::Bool(false)),
            other => Err(AnalError::Parse {
                message: format!("PUSH expects a literal value, found {other:?}"),
                span: tok.span,
            }),
        }
    }

    fn parse_conditional_block(&mut self, on_truthy: bool, kw_span: Span) -> Result<(), AnalError> {
        match self.peek_kind() {
            Some(Token::LBracket) => {
                self.advance();
            }
            _ => {
                return Err(AnalError::Parse {
                    message: "IF_TIGHT/IF_LOOSE expects `[`".into(),
                    span: kw_span,
                });
            }
        }
        let jump_addr = self.instrs.len();
        let skip_op = if on_truthy {
            Op::JumpIfFalsy(0)
        } else {
            Op::JumpIfTruthy(0)
        };
        self.emit(skip_op, kw_span);

        loop {
            match self.peek_kind() {
                Some(Token::RBracket) => {
                    self.advance();
                    break;
                }
                Some(_) => self.parse_statement()?,
                None => {
                    return Err(AnalError::Parse {
                        message: "expected `]` to close conditional block".into(),
                        span: kw_span,
                    });
                }
            }
        }

        let after_body = self.instrs.len();
        match &mut self.instrs[jump_addr].op {
            Op::JumpIfFalsy(target) | Op::JumpIfTruthy(target) => *target = after_body,
            _ => unreachable!("we just emitted a JumpIfFalsy/JumpIfTruthy"),
        }
        Ok(())
    }
}

fn is_known_keyword(uppercased: &str) -> bool {
    matches!(
        uppercased,
        "ANAL"
            | "VERSION"
            | "INGEST"
            | "PUSH"
            | "POP"
            | "PROBE"
            | "INSERT"
            | "EXTRACT"
            | "SWAP"
            | "DUP"
            | "DEPTH"
            | "FLUSH"
            | "PREP"
            | "CLENCH"
            | "RELEASE"
            | "CONSENT"
            | "EXPAND"
            | "HOLD"
            | "RESUME"
            | "RECEIVE"
            | "EXPEL"
            | "DISCHARGE"
            | "EVACUATE"
            | "DILATE"
            | "CONSTRICT"
            | "IF_TIGHT"
            | "IF_LOOSE"
            | "PASSAGE"
            | "ENTER"
            | "EXIT"
            | "ABORT"
            | "ADD"
            | "SUB"
            | "MUL"
            | "DIV"
            | "MOD"
            | "EQ"
            | "LT"
            | "GT"
            | "LTE"
            | "GTE"
            | "NOT"
            | "TO_INT"
            | "TO_FLOAT"
            | "TO_STRING"
            | "TRUE"
            | "FALSE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_hello_world() {
        let code = compile(
            r#"PUSH "Hello, World!"
EXPEL"#,
        )
        .unwrap();
        assert_eq!(code.len(), 2);
        assert!(matches!(code[0].op, Op::Push(Value::Str(_))));
        assert!(matches!(code[1].op, Op::Expel));
    }

    #[test]
    fn compile_with_header() {
        let code = compile(
            r#"ANAL "hi" VERSION 1
PUSH 42
DISCHARGE"#,
        )
        .unwrap();
        assert_eq!(code.len(), 2);
    }

    #[test]
    fn casing_error_for_lowercase_keyword() {
        let err = compile("push 1").unwrap_err();
        assert!(matches!(err, AnalError::Casing { .. }), "got {err:?}");
    }

    #[test]
    fn rupture_error_for_unclosed_dilate() {
        let err = compile("DILATE PUSH 1").unwrap_err();
        assert!(matches!(err, AnalError::Rupture { .. }), "got {err:?}");
    }
}
