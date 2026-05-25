//! # The .sphlog audit ledger
//!
//! A binary, append-only, hash-chained record of every destructive
//! operation a program performs. Written by the VM when invoked with
//! a ledger sink; read by `anal audit` to verify what was done and
//! that the log has not been edited.
//!
//! ## File layout
//!
//! Header (40 bytes):
//!
//! | offset | size | field        | notes                                |
//! |--------|------|--------------|--------------------------------------|
//! | 0      | 4    | magic        | b"SPHL"                              |
//! | 4      | 1    | version      | 0x01                                 |
//! | 5      | 3    | reserved     | zero                                 |
//! | 8      | 32   | source_hash  | blake3 of source file at run time    |
//!
//! Record (72 bytes, repeated until EOF):
//!
//! | offset | size | field        | notes                                |
//! |--------|------|--------------|--------------------------------------|
//! | 0      | 8    | seq          | u64 LE, 0-based                      |
//! | 8      | 8    | ts_micros    | i64 LE, unix epoch microseconds      |
//! | 16     | 1    | op_tag       | see [`OpTag`]                        |
//! | 17     | 1    | reserved     | zero                                 |
//! | 18     | 4    | span_start   | u32 LE, byte offset into source      |
//! | 22     | 4    | span_end     | u32 LE, byte offset into source      |
//! | 26     | 4    | stack_depth  | u32 LE, depth *before* the op fired  |
//! | 30     | 1    | top_n        | 0..=4, types recorded                |
//! | 31     | 4    | top_types    | first `top_n` are valid (see TypeTag)|
//! | 35     | 5    | reserved     | zero, pad to 40                      |
//! | 40     | 32   | prev_hash    | this_hash of the prior record;       |
//! |        |      |              | all zeros for the first record       |
//!
//! `this_hash` is then computed as `blake3(bytes 0..72)`, where bytes
//! 40..72 are the `prev_hash` we just wrote. It is *not* stored in the
//! record; readers recompute it on the fly. This keeps records fixed-
//! size and makes the chain self-validating: an editor who changes a
//! past record invalidates every subsequent `prev_hash`.
//!
//! All integers are little-endian. There is no record count in the
//! header; readers iterate until EOF.

use std::io::{self, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAGIC: [u8; 4] = *b"SPHL";
pub const VERSION: u8 = 0x01;
pub const HEADER_SIZE: usize = 40;
pub const RECORD_SIZE: usize = 72;

/// Tag byte identifying which destructive op fired. Stable across
/// versions — new ops append to the list rather than reordering.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpTag {
    Insert = 1,
    Extract = 2,
    Flush = 3,
    Bufset = 4,
    Store = 5,
    /// EVACUATE only logs when it overwrites an existing file —
    /// the case that requires CONSENT.
    EvacuateOverwrite = 6,
}

impl OpTag {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => OpTag::Insert,
            2 => OpTag::Extract,
            3 => OpTag::Flush,
            4 => OpTag::Bufset,
            5 => OpTag::Store,
            6 => OpTag::EvacuateOverwrite,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            OpTag::Insert => "INSERT",
            OpTag::Extract => "EXTRACT",
            OpTag::Flush => "FLUSH",
            OpTag::Bufset => "BUFSET",
            OpTag::Store => "STORE",
            OpTag::EvacuateOverwrite => "EVACUATE",
        }
    }
}

/// Tag byte for one of the runtime value types. Recorded for the top
/// `top_n` slots of the stack at op-fire time, so an audit can verify
/// not just "what op ran" but "with what shape underneath it."
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeTag {
    Int = 1,
    Float = 2,
    Str = 3,
    Bool = 4,
    Bloc = 5,
    Cavity = 6,
}

impl TypeTag {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => TypeTag::Int,
            2 => TypeTag::Float,
            3 => TypeTag::Str,
            4 => TypeTag::Bool,
            5 => TypeTag::Bloc,
            6 => TypeTag::Cavity,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            TypeTag::Int => "INT",
            TypeTag::Float => "FLOAT",
            TypeTag::Str => "STRING",
            TypeTag::Bool => "BOOL",
            TypeTag::Bloc => "BLOC",
            TypeTag::Cavity => "CAVITY",
        }
    }
}

/// Maximum number of top-of-stack types recorded per entry. Anything
/// deeper is left untracked — the depth field still records the full
/// count, but only the top four types are persisted. Four is enough to
/// disambiguate the common destructive-op shapes (e.g. BUFSET wants
/// CAVITY, INT, INT below the value) without inflating record size.
pub const TOP_TYPES_CAPACITY: usize = 4;

/// A single decoded ledger entry. Constructed by the VM at op-fire time
/// and consumed by [`LedgerSink::write`]; reconstructed by [`LedgerReader`]
/// during audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRecord {
    pub seq: u64,
    pub ts_micros: i64,
    pub op: OpTag,
    pub span_start: u32,
    pub span_end: u32,
    /// Depth of the stack immediately *before* the op fired.
    pub stack_depth: u32,
    /// Types of the top `top_types.len()` slots, top of stack first.
    /// Capped at [`TOP_TYPES_CAPACITY`].
    pub top_types: Vec<TypeTag>,
}

/// Errors produced when reading or verifying a ledger file. Distinct
/// from the language's runtime errors — these are file-format failures.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("ledger I/O: {0}")]
    Io(#[from] io::Error),

    #[error("ledger header is too short ({0} bytes; expected at least {HEADER_SIZE})")]
    HeaderTruncated(usize),

    #[error("ledger magic does not match (expected {expected:?}, found {found:?})")]
    BadMagic { expected: [u8; 4], found: [u8; 4] },

    #[error("ledger version {0} is not supported by this build")]
    UnsupportedVersion(u8),

    #[error("ledger record {seq} is truncated ({got} bytes; expected {RECORD_SIZE})")]
    RecordTruncated { seq: u64, got: usize },

    #[error("ledger record {seq} carries unknown op tag {tag:#04x}")]
    UnknownOp { seq: u64, tag: u8 },

    #[error("ledger record {seq} carries unknown type tag {tag:#04x} at slot {slot}")]
    UnknownType { seq: u64, tag: u8, slot: usize },

    #[error(
        "ledger record {seq} records top_n={top_n}, which exceeds the cap of {TOP_TYPES_CAPACITY}"
    )]
    TooManyTopTypes { seq: u64, top_n: u8 },

    #[error("ledger record {seq} has out-of-order seq number (expected {expected})")]
    SeqOutOfOrder { seq: u64, expected: u64 },

    #[error(
        "ledger chain broken at record {seq}: prev_hash does not match this_hash of record {prior}"
    )]
    BrokenChain { seq: u64, prior: u64 },
}

/// Streaming writer. Holds the running `prev_hash` and increments `seq`
/// for each entry. Wraps any `Write`; for files, callers should hand it
/// a `BufWriter<File>` opened in append mode.
pub struct LedgerSink<W: Write> {
    out: W,
    next_seq: u64,
    prev_hash: [u8; 32],
}

impl<W: Write> LedgerSink<W> {
    /// Create a new sink. Writes the header immediately. `source_hash`
    /// should be the blake3 of the source file the program was loaded
    /// from; `anal audit` will compare it to the source it is asked to
    /// verify against and refuse the pair if they disagree.
    pub fn new(mut out: W, source_hash: [u8; 32]) -> io::Result<Self> {
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&MAGIC);
        header[4] = VERSION;
        // bytes 5..8 are reserved (already zero)
        header[8..40].copy_from_slice(&source_hash);
        out.write_all(&header)?;
        Ok(Self {
            out,
            next_seq: 0,
            prev_hash: [0u8; 32],
        })
    }

    /// Append a record. Fills in `seq` and `ts_micros` from the sink's
    /// own state, hash-chains it onto the prior record, and writes the
    /// fixed-size record to the underlying writer.
    pub fn record(
        &mut self,
        op: OpTag,
        span_start: u32,
        span_end: u32,
        stack_depth: u32,
        top_types: &[TypeTag],
    ) -> io::Result<u64> {
        let seq = self.next_seq;
        let ts_micros = now_micros();
        let bytes = encode_record(
            seq,
            ts_micros,
            op,
            span_start,
            span_end,
            stack_depth,
            top_types,
            &self.prev_hash,
        );
        self.out.write_all(&bytes)?;
        self.prev_hash = blake3::hash(&bytes).into();
        self.next_seq += 1;
        Ok(seq)
    }

    /// Flush the underlying writer. Callers should invoke this before
    /// program shutdown if the sink wraps a buffered file, otherwise
    /// trailing records may be lost on a crash.
    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Number of records written so far.
    pub fn count(&self) -> u64 {
        self.next_seq
    }
}

/// Streaming reader. Validates the header on construction; subsequent
/// calls to [`LedgerReader::next_record`] decode one record at a time
/// and verify the hash chain incrementally.
#[derive(Debug)]
pub struct LedgerReader<R: Read> {
    src: R,
    next_seq: u64,
    prev_hash: [u8; 32],
    source_hash: [u8; 32],
}

impl<R: Read> LedgerReader<R> {
    /// Read and validate the header.
    pub fn open(mut src: R) -> Result<Self, LedgerError> {
        let mut header = [0u8; HEADER_SIZE];
        let got = read_full_or_short(&mut src, &mut header)?;
        if got < HEADER_SIZE {
            return Err(LedgerError::HeaderTruncated(got));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&header[0..4]);
        if magic != MAGIC {
            return Err(LedgerError::BadMagic {
                expected: MAGIC,
                found: magic,
            });
        }
        let version = header[4];
        if version != VERSION {
            return Err(LedgerError::UnsupportedVersion(version));
        }
        let mut source_hash = [0u8; 32];
        source_hash.copy_from_slice(&header[8..40]);
        Ok(Self {
            src,
            next_seq: 0,
            prev_hash: [0u8; 32],
            source_hash,
        })
    }

    /// blake3 of the source the ledger was recorded against.
    pub fn source_hash(&self) -> [u8; 32] {
        self.source_hash
    }

    /// Decode the next record. Returns `Ok(None)` at clean EOF;
    /// returns `Err` on truncation, chain mismatch, or malformed fields.
    pub fn next_record(&mut self) -> Result<Option<LedgerRecord>, LedgerError> {
        let mut buf = [0u8; RECORD_SIZE];
        let got = read_full_or_short(&mut self.src, &mut buf)?;
        if got == 0 {
            return Ok(None);
        }
        if got < RECORD_SIZE {
            return Err(LedgerError::RecordTruncated {
                seq: self.next_seq,
                got,
            });
        }
        let record = decode_record(self.next_seq, &buf)?;
        // Verify the chain: the prev_hash baked into this record must
        // match the this_hash we computed for the prior record (which
        // we stashed in self.prev_hash).
        let mut prev_in_record = [0u8; 32];
        prev_in_record.copy_from_slice(&buf[40..72]);
        if prev_in_record != self.prev_hash {
            return Err(LedgerError::BrokenChain {
                seq: record.seq,
                prior: record.seq.saturating_sub(1),
            });
        }
        // Advance the chain: this_hash for the next record's prev_hash.
        self.prev_hash = blake3::hash(&buf).into();
        self.next_seq = record.seq + 1;
        Ok(Some(record))
    }
}

// ── encoding helpers ────────────────────────────────────

// Eight arguments is a lot, but they're all primitive scalars destined
// for fixed byte offsets — bundling them into a struct would only push
// the same field count one layer further in.
#[allow(clippy::too_many_arguments)]
fn encode_record(
    seq: u64,
    ts_micros: i64,
    op: OpTag,
    span_start: u32,
    span_end: u32,
    stack_depth: u32,
    top_types: &[TypeTag],
    prev_hash: &[u8; 32],
) -> [u8; RECORD_SIZE] {
    let mut buf = [0u8; RECORD_SIZE];
    buf[0..8].copy_from_slice(&seq.to_le_bytes());
    buf[8..16].copy_from_slice(&ts_micros.to_le_bytes());
    buf[16] = op as u8;
    // buf[17] reserved
    buf[18..22].copy_from_slice(&span_start.to_le_bytes());
    buf[22..26].copy_from_slice(&span_end.to_le_bytes());
    buf[26..30].copy_from_slice(&stack_depth.to_le_bytes());
    let top_n = top_types.len().min(TOP_TYPES_CAPACITY) as u8;
    buf[30] = top_n;
    for (i, t) in top_types.iter().take(TOP_TYPES_CAPACITY).enumerate() {
        buf[31 + i] = *t as u8;
    }
    // buf[31 + top_n .. 40] left zero (pad + reserved)
    buf[40..72].copy_from_slice(prev_hash);
    buf
}

fn decode_record(expected_seq: u64, buf: &[u8; RECORD_SIZE]) -> Result<LedgerRecord, LedgerError> {
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&buf[0..8]);
    let seq = u64::from_le_bytes(seq_bytes);
    if seq != expected_seq {
        return Err(LedgerError::SeqOutOfOrder {
            seq,
            expected: expected_seq,
        });
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&buf[8..16]);
    let ts_micros = i64::from_le_bytes(ts_bytes);
    let op = OpTag::from_byte(buf[16]).ok_or(LedgerError::UnknownOp { seq, tag: buf[16] })?;
    let mut span_start_bytes = [0u8; 4];
    span_start_bytes.copy_from_slice(&buf[18..22]);
    let span_start = u32::from_le_bytes(span_start_bytes);
    let mut span_end_bytes = [0u8; 4];
    span_end_bytes.copy_from_slice(&buf[22..26]);
    let span_end = u32::from_le_bytes(span_end_bytes);
    let mut depth_bytes = [0u8; 4];
    depth_bytes.copy_from_slice(&buf[26..30]);
    let stack_depth = u32::from_le_bytes(depth_bytes);
    let top_n = buf[30];
    if top_n as usize > TOP_TYPES_CAPACITY {
        return Err(LedgerError::TooManyTopTypes { seq, top_n });
    }
    let mut top_types = Vec::with_capacity(top_n as usize);
    for i in 0..top_n as usize {
        let tag_byte = buf[31 + i];
        let tag = TypeTag::from_byte(tag_byte).ok_or(LedgerError::UnknownType {
            seq,
            tag: tag_byte,
            slot: i,
        })?;
        top_types.push(tag);
    }
    Ok(LedgerRecord {
        seq,
        ts_micros,
        op,
        span_start,
        span_end,
        stack_depth,
        top_types,
    })
}

/// Read up to `buf.len()` bytes. Returns the number actually read.
/// 0 means EOF before any byte; a value < buf.len() means truncation
/// mid-read. Distinguishes "no bytes there at all" from "started but
/// stopped early," which the caller uses to tell EOF from a torn write.
fn read_full_or_short<R: Read>(src: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match src.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn now_micros() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// Convenience: hash a source string the same way the writer hashes
/// the input file. Audit callers use this to verify ledger/source pairs.
pub fn hash_source(src: &str) -> [u8; 32] {
    blake3::hash(src.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn dummy_source_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        h
    }

    #[test]
    fn round_trip_one_record() {
        let mut buf = Vec::new();
        let src_hash = dummy_source_hash();
        let mut sink = LedgerSink::new(&mut buf, src_hash).unwrap();
        sink.record(
            OpTag::Flush,
            100,
            105,
            3,
            &[TypeTag::Int, TypeTag::Int, TypeTag::Int],
        )
        .unwrap();
        sink.flush().unwrap();

        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        assert_eq!(reader.source_hash(), src_hash);
        let r = reader.next_record().unwrap().unwrap();
        assert_eq!(r.seq, 0);
        assert_eq!(r.op, OpTag::Flush);
        assert_eq!(r.span_start, 100);
        assert_eq!(r.span_end, 105);
        assert_eq!(r.stack_depth, 3);
        assert_eq!(r.top_types, vec![TypeTag::Int, TypeTag::Int, TypeTag::Int]);
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn round_trip_many_records() {
        let mut buf = Vec::new();
        let mut sink = LedgerSink::new(&mut buf, dummy_source_hash()).unwrap();
        for i in 0..32u32 {
            sink.record(OpTag::Insert, i * 10, i * 10 + 5, i, &[TypeTag::Int])
                .unwrap();
        }
        sink.flush().unwrap();

        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        for expected_seq in 0..32u64 {
            let r = reader.next_record().unwrap().unwrap();
            assert_eq!(r.seq, expected_seq);
            assert_eq!(r.op, OpTag::Insert);
            assert_eq!(r.stack_depth, expected_seq as u32);
        }
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn truncated_top_types_capped_at_capacity() {
        // Even if we hand the sink more than TOP_TYPES_CAPACITY, only
        // the first four are persisted (and top_n reports four).
        let mut buf = Vec::new();
        let mut sink = LedgerSink::new(&mut buf, dummy_source_hash()).unwrap();
        sink.record(
            OpTag::Bufset,
            0,
            6,
            10,
            &[
                TypeTag::Int,
                TypeTag::Int,
                TypeTag::Cavity,
                TypeTag::Bool,
                TypeTag::Float,
                TypeTag::Str,
            ],
        )
        .unwrap();
        sink.flush().unwrap();

        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        let r = reader.next_record().unwrap().unwrap();
        assert_eq!(r.top_types.len(), TOP_TYPES_CAPACITY);
        assert_eq!(
            r.top_types,
            vec![TypeTag::Int, TypeTag::Int, TypeTag::Cavity, TypeTag::Bool],
        );
    }

    #[test]
    fn empty_top_types_round_trips() {
        let mut buf = Vec::new();
        let mut sink = LedgerSink::new(&mut buf, dummy_source_hash()).unwrap();
        sink.record(OpTag::Flush, 0, 5, 0, &[]).unwrap();
        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        let r = reader.next_record().unwrap().unwrap();
        assert!(r.top_types.is_empty());
    }

    #[test]
    fn header_truncated_is_an_error() {
        let mut short = Vec::new();
        short.extend_from_slice(&MAGIC);
        short.push(VERSION);
        // Stop mid-header.
        let err = LedgerReader::open(Cursor::new(&short)).unwrap_err();
        assert!(
            matches!(err, LedgerError::HeaderTruncated(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn bad_magic_is_an_error() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(b"NOPE");
        buf[4] = VERSION;
        let err = LedgerReader::open(Cursor::new(&buf)).unwrap_err();
        assert!(matches!(err, LedgerError::BadMagic { .. }), "got {err:?}");
    }

    #[test]
    fn unsupported_version_is_an_error() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = 0x99;
        let err = LedgerReader::open(Cursor::new(&buf)).unwrap_err();
        assert!(
            matches!(err, LedgerError::UnsupportedVersion(0x99)),
            "got {err:?}"
        );
    }

    #[test]
    fn edited_past_record_breaks_the_chain() {
        // Write three records, flip a bit in the middle one, read back.
        // The next record's prev_hash will not match.
        let mut buf = Vec::new();
        let mut sink = LedgerSink::new(&mut buf, dummy_source_hash()).unwrap();
        sink.record(OpTag::Insert, 0, 5, 1, &[TypeTag::Int])
            .unwrap();
        sink.record(OpTag::Insert, 10, 15, 2, &[TypeTag::Int])
            .unwrap();
        sink.record(OpTag::Insert, 20, 25, 3, &[TypeTag::Int])
            .unwrap();

        // The second record sits at offset HEADER_SIZE + RECORD_SIZE.
        // Flip a depth byte (offset 26 within the record).
        let target = HEADER_SIZE + RECORD_SIZE + 26;
        buf[target] ^= 0xff;

        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        // Record 0 reads clean (its prev_hash is genesis-zeros, matches).
        let r0 = reader.next_record().unwrap().unwrap();
        assert_eq!(r0.seq, 0);
        // Record 1 reads but its bytes have been edited; reader does
        // not verify content correctness, only the chain. So r1 itself
        // is decodable, but r2's prev_hash will fail to match the new
        // this_hash of (edited) r1.
        let _ = reader.next_record().unwrap().unwrap();
        let err = reader.next_record().unwrap_err();
        assert!(
            matches!(err, LedgerError::BrokenChain { seq: 2, prior: 1 }),
            "got {err:?}"
        );
    }

    #[test]
    fn truncated_record_is_an_error() {
        let mut buf = Vec::new();
        let mut sink = LedgerSink::new(&mut buf, dummy_source_hash()).unwrap();
        sink.record(OpTag::Flush, 0, 5, 1, &[TypeTag::Int]).unwrap();
        // Drop the last 10 bytes of the record.
        buf.truncate(buf.len() - 10);

        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        let err = reader.next_record().unwrap_err();
        assert!(
            matches!(err, LedgerError::RecordTruncated { seq: 0, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_op_tag_is_an_error() {
        let mut buf = Vec::new();
        let mut sink = LedgerSink::new(&mut buf, dummy_source_hash()).unwrap();
        sink.record(OpTag::Flush, 0, 5, 1, &[TypeTag::Int]).unwrap();
        // Overwrite the op_tag byte (offset 16 within the record).
        let target = HEADER_SIZE + 16;
        buf[target] = 0xfe;

        let mut reader = LedgerReader::open(Cursor::new(&buf)).unwrap();
        let err = reader.next_record().unwrap_err();
        assert!(
            matches!(err, LedgerError::UnknownOp { tag: 0xfe, .. }),
            "got {err:?}"
        );
    }
}
