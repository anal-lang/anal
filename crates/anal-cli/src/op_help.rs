//! Catalogue of ANAL ops and REPL meta-commands, with one-line
//! descriptions used by both the tab-completer and `:help <op>`.
//!
//! The voice is the spec's: brief, indicative, no apology. Anything
//! that needs more than a sentence belongs in the language
//! specification, not here.

/// One entry in the op catalogue.
pub struct OpDoc {
    /// Canonical (uppercase) name as it appears in source.
    pub name: &'static str,
    /// One-line description, no trailing newline.
    pub doc: &'static str,
}

/// Every op the parser accepts. Kept in spec order so `:help` reads
/// in the same shape as the reference.
pub const OPS: &[OpDoc] = &[
    // ── Stack ─────────────────────────────────────────
    OpDoc { name: "PUSH",      doc: "Push a literal INT, FLOAT, STRING, or BOOL onto the stack." },
    OpDoc { name: "POP",       doc: "Discard the top of the stack." },
    OpDoc { name: "DUP",       doc: "Duplicate the top of the stack." },
    OpDoc { name: "SWAP",      doc: "Exchange the top two values." },
    OpDoc { name: "OVER",      doc: "Copy the second-from-top value to the top: (a b -- a b a)." },
    OpDoc { name: "ROT",       doc: "Rotate the third-from-top value to the top: (a b c -- b c a)." },
    OpDoc { name: "NIP",       doc: "Drop the second-from-top value: (a b -- b). Equivalent to SWAP POP." },
    OpDoc { name: "DEPTH",     doc: "Push the current stack depth as an INT." },
    OpDoc { name: "PROBE",     doc: "Print the top of the stack to stderr without removing it." },
    OpDoc { name: "INSERT",    doc: "INSERT <depth> <value>. Insert below the top. Requires PREP." },
    OpDoc { name: "EXTRACT",   doc: "EXTRACT <depth>. Remove a value below the top. Requires CONSENT." },
    OpDoc { name: "FLUSH",     doc: "Clear the entire stack. Requires CONSENT." },

    // ── Control / state ───────────────────────────────
    OpDoc { name: "PREP",      doc: "Arm the one-shot latch that authorises the next INSERT." },
    OpDoc { name: "CONSENT",   doc: "Arm the one-shot latch that authorises the next destructive op." },
    OpDoc { name: "RELAX",     doc: "Clear any armed PREP / CONSENT latches. Idempotent." },
    OpDoc { name: "CLENCH",    doc: "Open a section in which destructive ops are refused regardless of CONSENT." },
    OpDoc { name: "RELEASE",   doc: "Close the most recent CLENCH section." },
    OpDoc { name: "EXPAND",    doc: "EXPAND <n>. Reserve stack capacity for <n> values. Pushing past it raises OVERFLOW." },
    OpDoc { name: "HOLD",      doc: "HOLD [<ms>]. Pause execution for <ms>, or until a RESUME line on stdin if omitted." },
    OpDoc { name: "RESUME",    doc: "Sent on stdin to a HOLDing program to release it. Not a source-level op." },

    // ── I/O ───────────────────────────────────────────
    OpDoc { name: "EXPEL",       doc: "Print the top of the stack to stdout, no newline, and POP." },
    OpDoc { name: "DISCHARGE",   doc: "Print the top of the stack to stdout with a newline, and POP." },
    OpDoc { name: "RECEIVE",     doc: "Read one line from stdin and push it as a STRING (newline stripped)." },
    OpDoc { name: "RECEIVE_BYTE", doc: "Read one raw byte from stdin and push it as an INT (0..=255), or -1 on EOF." },
    OpDoc { name: "EMIT_BYTE",   doc: "Pop an INT in 0..=255 and write it to stdout as a single raw byte." },
    OpDoc { name: "INGEST",      doc: "INGEST \"<path>\". Read the file and push its contents as a STRING. Gated by `read` capability under --hard." },
    OpDoc { name: "EVACUATE",    doc: "EVACUATE \"<path>\". Write the top of the stack to the file. Requires CONSENT if it exists; gated by `write` capability under --hard." },
    OpDoc { name: "REQUEST",     doc: "Pop a STRING kind and a STRING target; push a BOOL grant. Kinds: \"read\", \"write\", \"net\". Prompts under --hard, auto-grants in soft mode." },

    // ── String inspection ─────────────────────────────
    OpDoc { name: "STRLEN",    doc: "Pop a STRING and push its byte length as an INT." },
    OpDoc { name: "CHARAT",    doc: "Pop an INT index and a STRING; push the byte at that index as an INT in 0..=255." },
    OpDoc { name: "SUBSTR",    doc: "Pop an INT length, INT start, and STRING; push the substring of length bytes from start." },

    // ── External storage (CAVITY) ─────────────────────
    OpDoc { name: "BUFFER",    doc: "BUFFER <n>. Allocate a CAVITY of <n> INT cells, or bare BUFFER to take the size from the stack." },
    OpDoc { name: "BUFGET",    doc: "Pop an INT index; read the cell of the CAVITY beneath it and push the INT. CAVITY remains." },
    OpDoc { name: "BUFSET",    doc: "Pop an INT value and an INT index; write to the CAVITY beneath. Requires PREP and CONSENT." },
    OpDoc { name: "BUFLEN",    doc: "Push the cell count of the CAVITY on top of the stack as an INT. CAVITY remains." },
    OpDoc { name: "LOAD",      doc: "LOAD <i>. Read cell <i> of the CAVITY on top and push the INT. CAVITY remains." },
    OpDoc { name: "STORE",     doc: "STORE <i>. Pop an INT and write it to cell <i> of the CAVITY beneath. Requires PREP and CONSENT." },

    // ── Flow ──────────────────────────────────────────
    OpDoc { name: "DILATE",    doc: "Open a loop. Pop a BOOL each iteration; CONSTRICT closes the loop." },
    OpDoc { name: "CONSTRICT", doc: "Close the most recent DILATE." },
    OpDoc { name: "IF_TIGHT",  doc: "Pop a BOOL and a BLOC. Run the BLOC when the BOOL is truthy." },
    OpDoc { name: "IF_LOOSE",  doc: "Pop a BOOL and a BLOC. Run the BLOC when the BOOL is falsy." },
    OpDoc { name: "PASSAGE",   doc: "PASSAGE <name>: ... EXIT. Define a callable subroutine." },
    OpDoc { name: "ENTER",     doc: "ENTER <name> — call a PASSAGE. With no name, pop a BLOC and execute it." },
    OpDoc { name: "EXIT",      doc: "Return from the current PASSAGE or BLOC." },
    OpDoc { name: "ABORT",     doc: "Terminate the program immediately." },

    // ── Arithmetic / comparison ───────────────────────
    OpDoc { name: "ADD",       doc: "Pop two numbers and push the sum. On two STRINGs: concatenate." },
    OpDoc { name: "SUB",       doc: "Pop two numbers and push the difference." },
    OpDoc { name: "MUL",       doc: "Pop two numbers and push the product." },
    OpDoc { name: "DIV",       doc: "Pop two numbers and push the quotient. Integer division on two INTs." },
    OpDoc { name: "MOD",       doc: "Pop two INTs and push the remainder." },
    OpDoc { name: "EQ",        doc: "Pop two values and push TRUE when they are equal." },
    OpDoc { name: "LT",        doc: "Pop two numbers and push TRUE when the second is less than the first." },
    OpDoc { name: "GT",        doc: "Pop two numbers and push TRUE when the second is greater than the first." },
    OpDoc { name: "LTE",       doc: "Pop two numbers and push TRUE when the second is less than or equal." },
    OpDoc { name: "GTE",       doc: "Pop two numbers and push TRUE when the second is greater than or equal." },
    OpDoc { name: "NOT",       doc: "Pop a BOOL and push its inverse." },

    // ── Conversion ────────────────────────────────────
    OpDoc { name: "TO_INT",    doc: "Convert the top of the stack to INT, or fail with REJECTION." },
    OpDoc { name: "TO_FLOAT",  doc: "Convert the top of the stack to FLOAT, or fail with REJECTION." },
    OpDoc { name: "TO_STRING", doc: "Convert the top of the stack to STRING." },

    // ── Literals ──────────────────────────────────────
    OpDoc { name: "TRUE",      doc: "The BOOL literal TRUE." },
    OpDoc { name: "FALSE",     doc: "The BOOL literal FALSE." },
];

/// REPL meta-commands, in display order.
pub const METAS: &[OpDoc] = &[
    OpDoc {
        name: ":help",
        doc:
            ":help [<op>]. With no argument, list meta-commands. With an op, print its description.",
    },
    OpDoc {
        name: ":stack",
        doc: "Print the current runtime stack.",
    },
    OpDoc {
        name: ":shape",
        doc: "Print the abstract (type) stack — what the checker sees.",
    },
    OpDoc {
        name: ":passages",
        doc: "List all defined passages.",
    },
    OpDoc {
        name: ":trace",
        doc: ":trace [on|off|toggle]. Show the abstract-stack delta after every fragment.",
    },
    OpDoc {
        name: ":reset",
        doc: "Clear the stack, latches, and every defined passage.",
    },
    OpDoc {
        name: ":load",
        doc: ":load <FILE>. Read a file and execute it in this session.",
    },
    OpDoc {
        name: ":quit",
        doc: "Leave the session. Ctrl-D also exits.",
    },
];

/// Look up an op's doc by name, case-insensitive on the input.
/// Matches both the canonical name and a leading colon for metas.
pub fn lookup(name: &str) -> Option<&'static OpDoc> {
    let upper = name.to_ascii_uppercase();
    if let Some(stripped) = upper.strip_prefix(':') {
        // Allow `:help :load` or `:help load` — both find `:load`.
        let want = format!(":{}", stripped.to_ascii_lowercase());
        return METAS.iter().find(|m| m.name.eq_ignore_ascii_case(&want));
    }
    OPS.iter().find(|o| o.name == upper)
}

/// All op names, for completion.
pub fn op_names() -> impl Iterator<Item = &'static str> {
    OPS.iter().map(|o| o.name)
}

/// All meta-command names (with leading colon), for completion.
pub fn meta_names() -> impl Iterator<Item = &'static str> {
    METAS.iter().map(|m| m.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_op_is_unique() {
        let mut names: Vec<&str> = op_names().collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate op name in catalogue");
    }

    #[test]
    fn lookup_finds_canonical_op() {
        assert_eq!(lookup("PUSH").map(|o| o.name), Some("PUSH"));
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert_eq!(lookup("push").map(|o| o.name), Some("PUSH"));
        assert_eq!(lookup("Push").map(|o| o.name), Some("PUSH"));
    }

    #[test]
    fn lookup_finds_meta_with_or_without_colon() {
        assert_eq!(lookup(":reset").map(|o| o.name), Some(":reset"));
        // Bare `reset` is not an op — meta-commands need their colon.
        assert_eq!(lookup("reset").map(|o| o.name), None);
        assert_eq!(lookup(":RESET").map(|o| o.name), Some(":reset"));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup("HUGS").is_none());
    }

    #[test]
    fn catalogue_covers_every_lexer_keyword() {
        // Every op-shaped keyword the lexer recognises. Keep in sync
        // with the `#[token("...")]` rules in crates/anal-core/src/token.rs;
        // when a new op lands there, add it here AND to OPS above.
        for kw in [
            // stack
            "PUSH",
            "POP",
            "DUP",
            "SWAP",
            "OVER",
            "ROT",
            "NIP",
            "DEPTH",
            "PROBE",
            "INSERT",
            "EXTRACT",
            "FLUSH",
            // consent / state
            "PREP",
            "CONSENT",
            "RELAX",
            "CLENCH",
            "RELEASE",
            "EXPAND",
            "HOLD",
            "RESUME",
            // I/O
            "EXPEL",
            "DISCHARGE",
            "RECEIVE",
            "RECEIVE_BYTE",
            "EMIT_BYTE",
            "INGEST",
            "EVACUATE",
            "REQUEST",
            // string inspection
            "STRLEN",
            "CHARAT",
            "SUBSTR",
            // external storage
            "BUFFER",
            "BUFGET",
            "BUFSET",
            "BUFLEN",
            "LOAD",
            "STORE",
            // flow
            "DILATE",
            "CONSTRICT",
            "IF_TIGHT",
            "IF_LOOSE",
            "PASSAGE",
            "ENTER",
            "EXIT",
            "ABORT",
            // arithmetic / comparison
            "ADD",
            "SUB",
            "MUL",
            "DIV",
            "MOD",
            "EQ",
            "LT",
            "GT",
            "LTE",
            "GTE",
            "NOT",
            // conversion
            "TO_INT",
            "TO_FLOAT",
            "TO_STRING",
            // bool literals
            "TRUE",
            "FALSE",
        ] {
            assert!(lookup(kw).is_some(), "op `{kw}` missing from catalogue");
        }
    }
}
