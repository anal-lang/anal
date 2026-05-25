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
    OpDoc { name: "EXPEL",     doc: "Print the top of the stack to stdout, no newline, and POP." },
    OpDoc { name: "DISCHARGE", doc: "Print the top of the stack to stdout with a newline, and POP." },
    OpDoc { name: "RECEIVE",   doc: "Read one line from stdin and push it as a STRING (newline stripped)." },
    OpDoc { name: "INGEST",    doc: "INGEST \"<path>\". Read the file and push its contents as a STRING." },
    OpDoc { name: "EVACUATE",  doc: "EVACUATE \"<path>\". Write the top of the stack to the file. Requires CONSENT if it exists." },

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
        assert_eq!(lookup(":load").map(|o| o.name), Some(":load"));
        assert_eq!(lookup("load").map(|o| o.name), None); // bare `load` is not an op
        assert_eq!(lookup(":LOAD").map(|o| o.name), Some(":load"));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup("HUGS").is_none());
    }

    #[test]
    fn catalogue_covers_every_lexer_keyword() {
        // Spot-check the keywords that the lexer actually recognises
        // as ops. If a new op lands in the lexer, this test reminds
        // us to document it here.
        for kw in [
            "PUSH",
            "POP",
            "DUP",
            "SWAP",
            "DEPTH",
            "PROBE",
            "INSERT",
            "EXTRACT",
            "FLUSH",
            "PREP",
            "CONSENT",
            "RELAX",
            "CLENCH",
            "RELEASE",
            "EXPAND",
            "HOLD",
            "RESUME",
            "EXPEL",
            "DISCHARGE",
            "RECEIVE",
            "INGEST",
            "EVACUATE",
            "DILATE",
            "CONSTRICT",
            "IF_TIGHT",
            "IF_LOOSE",
            "PASSAGE",
            "ENTER",
            "EXIT",
            "ABORT",
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
            "TO_INT",
            "TO_FLOAT",
            "TO_STRING",
            "TRUE",
            "FALSE",
        ] {
            assert!(lookup(kw).is_some(), "op `{kw}` missing from catalogue");
        }
    }
}
