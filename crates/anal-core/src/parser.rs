//! # Parser
//!
//! Tokens in, bytecode out. For the bootstrap, parsing and code
//! generation are fused into a single pass — there is no AST stage
//! between them. This is a deliberate v0.x shortcut, not the
//! long-term shape: the [`crate::ast`] and [`crate::compiler`]
//! namespaces are reserved for the eventual split, when `analc`
//! (the self-hosted compiler, ANAL compiling ANAL into `.sph`
//! bytecode) needs a target data structure the Rust side can also
//! produce and consume for bootstrap and verification. Until then,
//! the parser does both jobs.
//!
//! Control flow is compiled in place: `DILATE`/`CONSTRICT` becomes
//! a forward jump past the body plus a backward jump to the
//! condition, with the forward target patched when `CONSTRICT`
//! arrives. `IF_TIGHT [ ... ]` and `IF_LOOSE [ ... ]` are sugar —
//! the inline `[ ... ]` is parsed into a `BLOC` value, pushed, then
//! immediately consumed by the conditional exec op. The same
//! `[ ... ]` may also appear standalone (a BLOC literal pushed to
//! the stack like any other value), which is what lets a passage
//! return executable code.
//!
//! PASSAGE bodies compile into their own instruction streams — a
//! fresh accumulator, a fresh loop stack — so a `DILATE` inside a
//! passage must balance independently of the main body.

use std::collections::HashMap;
use std::rc::Rc;

use crate::error::AnalError;
use crate::op::{Instr, Op, Program};
use crate::token::{Span, Spanned, Token};
use crate::value::Value;

/// Lex, parse, and type-check a complete ANAL source string into a
/// compiled [`Program`] ready for the VM. Static type errors surface as
/// [`AnalError::Mismatch`] before any code runs.
pub fn compile(source: &str) -> Result<Program, AnalError> {
    let tokens = crate::lexer::lex(source)?;
    let mut p = Parser::new(&tokens);
    p.parse_program()?;
    let program = Program {
        main: Rc::from(p.instrs.into_boxed_slice()),
        passages: p
            .passages
            .into_iter()
            .map(|(name, body)| (name, Rc::from(body.into_boxed_slice())))
            .collect(),
    };
    crate::check::check_program(&program)?;
    Ok(program)
}

/// Output of [`compile_fragment`]: the fragment's main bytecode and
/// any new passages it declared.
pub struct Fragment {
    /// Bytecode for the fragment's top-level statements.
    pub main: Vec<Instr>,
    /// Newly-defined passages from this fragment, keyed by name.
    pub passages: HashMap<String, Rc<[Instr]>>,
}

/// Lex and parse a REPL fragment — any interleaving of statements and
/// `PASSAGE` declarations, with no header. The type check is *not*
/// performed here; callers (typically [`crate::Session`]) run the
/// incremental checker against their own persistent abstract stack.
pub fn compile_fragment(source: &str) -> Result<Fragment, AnalError> {
    let tokens = crate::lexer::lex(source)?;
    let mut p = Parser::new(&tokens);
    p.parse_fragment()?;
    let passages = p
        .passages
        .into_iter()
        .map(|(name, body)| (name, Rc::from(body.into_boxed_slice())))
        .collect();
    Ok(Fragment {
        main: p.instrs,
        passages,
    })
}

/// Quick syntactic check: does `source` end with an unclosed block?
///
/// Used by the REPL to decide whether to switch to a continuation
/// prompt after a line is entered. Counts opens vs. closes for
/// `PASSAGE`/`EXIT`, `[`/`]`, and `DILATE`/`CONSTRICT`. A lex error
/// is treated as "not unfinished" so the REPL surfaces the real error
/// rather than silently swallowing the line.
///
/// This is a lightweight syntactic guess — it does *not* run the
/// full parser. A buffer that looks balanced here may still fail to
/// parse for other reasons; that is fine, the REPL reports those
/// errors normally.
pub fn is_unfinished(source: &str) -> bool {
    use crate::token::Token;
    let Ok(tokens) = crate::lexer::lex(source) else {
        return false;
    };
    let mut passage_depth: i32 = 0;
    let mut bracket_depth: i32 = 0;
    let mut dilate_depth: i32 = 0;
    for t in &tokens {
        match &t.node {
            Token::Passage => passage_depth += 1,
            Token::Exit => passage_depth -= 1,
            Token::LBracket => bracket_depth += 1,
            Token::RBracket => bracket_depth -= 1,
            Token::Dilate => dilate_depth += 1,
            Token::Constrict => dilate_depth -= 1,
            _ => {}
        }
    }
    passage_depth > 0 || bracket_depth > 0 || dilate_depth > 0
}

struct Parser<'a> {
    tokens: &'a [Spanned<Token>],
    pos: usize,
    instrs: Vec<Instr>,
    passages: HashMap<String, Vec<Instr>>,
    /// (address of JumpIfFalsy to patch, address of body start).
    loop_stack: Vec<(usize, usize)>,
}

impl<'a> Parser<'a> {
    fn new(tokens: &'a [Spanned<Token>]) -> Self {
        Self {
            tokens,
            pos: 0,
            instrs: Vec::new(),
            passages: HashMap::new(),
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
        while matches!(self.peek_kind(), Some(Token::Passage)) {
            self.parse_passage()?;
        }
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

    /// Fragment-mode parsing for the REPL. Accepts any interleaving of
    /// `PASSAGE` declarations and statements at the top level — no
    /// header, no enforced ordering. Statements accumulate into
    /// `self.instrs` (the fragment's main body); each `PASSAGE` adds
    /// to `self.passages`.
    fn parse_fragment(&mut self) -> Result<(), AnalError> {
        while self.peek_kind().is_some() {
            if matches!(self.peek_kind(), Some(Token::Passage)) {
                self.parse_passage()?;
            } else {
                self.parse_statement()?;
            }
        }
        if let Some((jump_addr, _)) = self.loop_stack.last() {
            return Err(AnalError::Rupture {
                span: self.instrs[*jump_addr].span,
            });
        }
        Ok(())
    }

    /// Parse a `PASSAGE name: ... EXIT` declaration. The body is compiled
    /// into its own instruction stream, terminated with `Return`, and
    /// stored in the passages table for the VM to call into.
    fn parse_passage(&mut self) -> Result<(), AnalError> {
        let passage_kw = self.advance().expect("caller checked PASSAGE");
        let passage_span = passage_kw.span;

        let name_tok = self.advance().ok_or_else(|| AnalError::Parse {
            message: "PASSAGE expects a name".into(),
            span: passage_span,
        })?;
        let name = match name_tok.node {
            Token::Ident(n) => n,
            other => {
                return Err(AnalError::Parse {
                    message: format!("PASSAGE expects an identifier name, found {other:?}"),
                    span: name_tok.span,
                });
            }
        };

        let colon = self.advance().ok_or_else(|| AnalError::Parse {
            message: "PASSAGE name must be followed by `:`".into(),
            span: name_tok.span,
        })?;
        if !matches!(colon.node, Token::Colon) {
            return Err(AnalError::Parse {
                message: "PASSAGE name must be followed by `:`".into(),
                span: colon.span,
            });
        }

        // Swap our main accumulator out so the passage body collects into a
        // fresh Vec. The loop_stack is reset too — control flow inside a
        // passage must balance independently of the main body.
        let saved_instrs = std::mem::take(&mut self.instrs);
        let saved_loops = std::mem::take(&mut self.loop_stack);

        let exit_span = loop {
            match self.peek_kind() {
                Some(Token::Exit) => {
                    let exit = self.advance().unwrap();
                    break exit.span;
                }
                Some(_) => self.parse_statement()?,
                None => {
                    return Err(AnalError::Parse {
                        message: format!("PASSAGE `{name}` was never closed with EXIT"),
                        span: passage_span,
                    });
                }
            }
        };

        if let Some((jump_addr, _)) = self.loop_stack.last() {
            return Err(AnalError::Rupture {
                span: self.instrs[*jump_addr].span,
            });
        }

        self.emit(Op::Return, exit_span);

        let body = std::mem::replace(&mut self.instrs, saved_instrs);
        self.loop_stack = saved_loops;

        self.passages.insert(name, body);
        Ok(())
    }

    /// Header form: `ANAL "<name>" VERSION <int>` followed by any
    /// number of `INGEST "<path>"` import declarations. The imports
    /// are parsed and ignored — the module system arrives later.
    ///
    /// `INGEST` only means "import" when an `ANAL` header precedes
    /// it. A bare `INGEST "path"` at the top of a file is a body
    /// statement that reads the named file at runtime.
    fn parse_header_and_ingests(&mut self) -> Result<(), AnalError> {
        if !matches!(self.peek_kind(), Some(Token::Anal)) {
            return Ok(());
        }
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
            Token::Over => self.emit(Op::Over, span),
            Token::Rot => self.emit(Op::Rot, span),
            Token::Nip => self.emit(Op::Nip, span),
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

            // ── IF_TIGHT / IF_LOOSE ────────────────────
            //
            // With an inline `[ ... ]`: push the BLOC, then exec.
            // Without: consume whatever BLOC is already on top.
            Token::IfTight => {
                self.parse_inline_bloc_if_present(span)?;
                self.emit(Op::IfTightExec, span);
            }
            Token::IfLoose => {
                self.parse_inline_bloc_if_present(span)?;
                self.emit(Op::IfLooseExec, span);
            }

            // ── Standalone `[ ... ]` — a BLOC literal value ──
            Token::LBracket => {
                let body = self.parse_bloc_body(span)?;
                self.emit(Op::Push(Value::Bloc(body)), span);
            }

            // ── PREP / CONSENT / CLENCH / RELEASE / RELAX ──
            Token::Prep => self.emit(Op::Prep, span),
            Token::Consent => self.emit(Op::Consent, span),
            Token::Clench => self.emit(Op::Clench, span),
            Token::Release => self.emit(Op::Release, span),
            Token::Relax => self.emit(Op::Relax, span),

            // ── FLUSH ──────────────────────────────────
            Token::Flush => self.emit(Op::Flush, span),

            // ── INSERT <depth> <value> ─────────────────
            Token::Insert => {
                let depth = self.parse_uint_operand("INSERT depth", span)?;
                let value = self.parse_literal(span)?;
                self.emit(Op::Insert { depth, value }, span);
            }

            // ── EXTRACT <depth> ────────────────────────
            Token::Extract => {
                let depth = self.parse_uint_operand("EXTRACT depth", span)?;
                self.emit(Op::Extract(depth), span);
            }

            // ── EXPAND <n> ─────────────────────────────
            Token::Expand => {
                let n = self.parse_uint_operand("EXPAND amount", span)?;
                self.emit(Op::Expand(n), span);
            }

            // ── HOLD ───────────────────────────────────
            //
            // With a non-negative INT: sleep that many ms. Without:
            // block until a RESUME signal arrives on stdin.
            Token::Hold => {
                let ms = match self.peek_kind() {
                    Some(Token::Int(n)) if *n >= 0 => {
                        let n = *n as u64;
                        self.advance();
                        Some(n)
                    }
                    Some(Token::Int(_)) => {
                        return Err(AnalError::Parse {
                            message: "HOLD ms must be non-negative".into(),
                            span,
                        });
                    }
                    _ => None,
                };
                self.emit(Op::Hold(ms), span);
            }

            // ── RESUME ─────────────────────────────────
            Token::Resume => self.emit(Op::Resume, span),

            // ── ENTER ──────────────────────────────────
            //
            // `ENTER <name>` calls a named PASSAGE; bare `ENTER`
            // pops a BLOC from the stack and runs it.
            Token::Enter => match self.peek_kind() {
                Some(Token::Ident(_)) => {
                    let name_tok = self.advance().unwrap();
                    let Token::Ident(name) = name_tok.node else {
                        unreachable!()
                    };
                    self.emit(Op::Enter(name), span);
                }
                _ => self.emit(Op::EnterStack, span),
            },

            // ── PASSAGE / EXIT outside their valid positions ──
            Token::Passage => {
                return Err(AnalError::Parse {
                    message: "PASSAGE declarations must appear before the main body".into(),
                    span,
                });
            }
            Token::Exit => {
                return Err(AnalError::Parse {
                    message: "EXIT is only valid inside a PASSAGE body".into(),
                    span,
                });
            }

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

            // ── INGEST "path" — body form reads a file ─
            Token::Ingest => {
                let path = self.parse_string_operand("INGEST path", span)?;
                self.emit(Op::IngestFile(path), span);
            }

            // ── EVACUATE "path" — write top of stack to file ──
            Token::Evacuate => {
                let path = self.parse_string_operand("EVACUATE path", span)?;
                self.emit(Op::Evacuate(path), span);
            }

            // ── RECEIVE — read one line from stdin ─────
            Token::Receive => self.emit(Op::Receive, span),

            // ── REQUEST — capability ask (--hard mode) ──
            Token::Request => self.emit(Op::Request, span),

            // ── Byte I/O ───────────────────────────────
            Token::ReceiveByte => self.emit(Op::ReceiveByte, span),
            Token::EmitByte => self.emit(Op::EmitByte, span),

            // ── String inspection ──────────────────────
            Token::Strlen => self.emit(Op::Strlen, span),
            Token::Charat => self.emit(Op::Charat, span),
            Token::Substr => self.emit(Op::Substr, span),

            // ── External storage (CAVITY) ──────────────
            //
            // Two forms, matching the HOLD precedent:
            //   `BUFFER <n>`  — n is a compile-time INT literal; HOLLOW
            //                   for non-positive n is caught at parse.
            //   bare `BUFFER` — pop an INT from the stack at runtime
            //                   and use it as the size; HOLLOW raised
            //                   at runtime if the popped value is ≤ 0.
            Token::Buffer => match self.peek_kind() {
                Some(Token::Int(_)) => {
                    let n = self.parse_uint_operand("BUFFER size", span)?;
                    if n == 0 {
                        return Err(AnalError::Hollow { size: 0, span });
                    }
                    self.emit(Op::Buffer(n), span);
                }
                _ => self.emit(Op::BufferDyn, span),
            },
            Token::Bufget => self.emit(Op::Bufget, span),
            Token::Bufset => self.emit(Op::Bufset, span),
            Token::Buflen => self.emit(Op::Buflen, span),

            // ── LOAD <i> / STORE <i> ──────────────────
            //
            // Compile-time-indexed sugar for the cavity-as-locals
            // pattern. Same semantics as BUFGET/BUFSET with the
            // index inlined into the op — the runtime ceremony is
            // unchanged (STORE still requires PREP + CONSENT).
            Token::Load => {
                let i = self.parse_uint_operand("LOAD index", span)?;
                self.emit(Op::Load(i), span);
            }
            Token::Store => {
                let i = self.parse_uint_operand("STORE index", span)?;
                self.emit(Op::Store(i), span);
            }

            // ── Header-only keywords appearing mid-program ──
            Token::Anal | Token::Version => {
                return Err(AnalError::Parse {
                    message: "header keywords are only valid before the body".into(),
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

    fn parse_string_operand(&mut self, what: &str, kw_span: Span) -> Result<String, AnalError> {
        let tok = self.advance().ok_or_else(|| AnalError::Parse {
            message: format!("{what} expects a string literal"),
            span: kw_span,
        })?;
        match tok.node {
            Token::Str(s) => Ok(s),
            other => Err(AnalError::Parse {
                message: format!("{what} expects a string literal, found {other:?}"),
                span: tok.span,
            }),
        }
    }

    fn parse_uint_operand(&mut self, what: &str, kw_span: Span) -> Result<usize, AnalError> {
        let tok = self.advance().ok_or_else(|| AnalError::Parse {
            message: format!("{what} expects a non-negative integer"),
            span: kw_span,
        })?;
        match tok.node {
            Token::Int(n) if n >= 0 => Ok(n as usize),
            Token::Int(_) => Err(AnalError::Parse {
                message: format!("{what} must be non-negative"),
                span: tok.span,
            }),
            other => Err(AnalError::Parse {
                message: format!("{what} expects an integer literal, found {other:?}"),
                span: tok.span,
            }),
        }
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

    /// If the next token is `[`, parse it as a BLOC literal and emit a
    /// `Push(Bloc)` so the inline `IF_TIGHT [ ... ]` form puts the BLOC on
    /// the stack just before the consumer op runs. If `[` is not next,
    /// this is a no-op — the BLOC is assumed to already be on the stack.
    fn parse_inline_bloc_if_present(&mut self, kw_span: Span) -> Result<(), AnalError> {
        if matches!(self.peek_kind(), Some(Token::LBracket)) {
            self.advance();
            let body = self.parse_bloc_body(kw_span)?;
            self.emit(Op::Push(Value::Bloc(body)), kw_span);
        }
        Ok(())
    }

    /// Compile the body of a BLOC literal (everything between `[` and `]`)
    /// into a fresh instruction stream. The opening `[` is assumed to be
    /// already consumed.
    fn parse_bloc_body(&mut self, open_span: Span) -> Result<Rc<[Instr]>, AnalError> {
        let saved_instrs = std::mem::take(&mut self.instrs);
        let saved_loops = std::mem::take(&mut self.loop_stack);

        loop {
            match self.peek_kind() {
                Some(Token::RBracket) => {
                    self.advance();
                    break;
                }
                Some(_) => self.parse_statement()?,
                None => {
                    return Err(AnalError::Parse {
                        message: "BLOC literal `[` was never closed with `]`".into(),
                        span: open_span,
                    });
                }
            }
        }

        if let Some((jump_addr, _)) = self.loop_stack.last() {
            return Err(AnalError::Rupture {
                span: self.instrs[*jump_addr].span,
            });
        }

        let body = std::mem::replace(&mut self.instrs, saved_instrs);
        self.loop_stack = saved_loops;
        Ok(Rc::from(body.into_boxed_slice()))
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
            | "OVER"
            | "ROT"
            | "NIP"
            | "DEPTH"
            | "FLUSH"
            | "PREP"
            | "CLENCH"
            | "RELEASE"
            | "CONSENT"
            | "RELAX"
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
            | "RECEIVE_BYTE"
            | "EMIT_BYTE"
            | "STRLEN"
            | "CHARAT"
            | "SUBSTR"
            | "BUFFER"
            | "BUFGET"
            | "BUFSET"
            | "BUFLEN"
            | "LOAD"
            | "STORE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_hello_world() {
        let program = compile(
            r#"PUSH "Hello, World!"
EXPEL"#,
        )
        .unwrap();
        assert_eq!(program.main.len(), 2);
        assert!(matches!(program.main[0].op, Op::Push(Value::Str(_))));
        assert!(matches!(program.main[1].op, Op::Expel));
        assert!(program.passages.is_empty());
    }

    #[test]
    fn compile_with_header() {
        let program = compile(
            r#"ANAL "hi" VERSION 1
PUSH 42
DISCHARGE"#,
        )
        .unwrap();
        assert_eq!(program.main.len(), 2);
    }

    #[test]
    fn compile_with_passage() {
        let program = compile(
            r#"PASSAGE square:
  DUP
  MUL
EXIT

PUSH 9
ENTER square
DISCHARGE"#,
        )
        .unwrap();
        assert_eq!(program.passages.len(), 1);
        assert!(program.passages.contains_key("square"));
        // The main body should contain ENTER and DISCHARGE.
        assert_eq!(program.main.len(), 3);
        assert!(matches!(program.main[1].op, Op::Enter(ref n) if n == "square"));
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

    #[test]
    fn is_unfinished_detects_open_passage() {
        assert!(is_unfinished("PASSAGE p: PUSH 1"));
        assert!(!is_unfinished("PASSAGE p: PUSH 1 EXIT"));
    }

    #[test]
    fn is_unfinished_detects_open_bracket() {
        assert!(is_unfinished("PUSH 1 IF_TIGHT [ PUSH 2"));
        assert!(!is_unfinished("PUSH 1 IF_TIGHT [ PUSH 2 ]"));
    }

    #[test]
    fn is_unfinished_detects_open_dilate() {
        assert!(is_unfinished("PUSH 1 DILATE PUSH 2"));
        assert!(!is_unfinished("PUSH 1 DILATE PUSH 2 CONSTRICT"));
    }

    #[test]
    fn is_unfinished_nested() {
        assert!(is_unfinished("PASSAGE p: PUSH 1 IF_TIGHT ["));
        assert!(!is_unfinished("PASSAGE p: PUSH 1 IF_TIGHT [ ] EXIT"));
    }

    #[test]
    fn is_unfinished_complete_program() {
        assert!(!is_unfinished("PUSH 1 PUSH 2 ADD DISCHARGE"));
    }

    #[test]
    fn is_unfinished_empty_and_whitespace() {
        assert!(!is_unfinished(""));
        assert!(!is_unfinished("   \n\t  "));
    }
}
