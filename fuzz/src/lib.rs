//! Structure-aware inputs shared by the round-trip fuzz targets.
//!
//! Raw `&[u8]` is the right input for the *decoders* (they parse bytes
//! directly), but it is a poor fit for the *encoders*: a round-trip target fed
//! random bytes spends almost all its time on incompressible noise and on
//! reference/target pairs that share no spans, so the match finder never fires.
//! These `#[derive(Arbitrary)]` types let libFuzzer mutate valid, *related*
//! structure instead, which is where structure-aware fuzzing pays off.

use arbitrary::Arbitrary;
use msdelta::pa30::{Codec, CreateOptions, FormatVersion};

/// Upper bound on a generated buffer, to keep memory and run time sane.
const MAX_BYTES: usize = 1 << 20;

/// One structural edit applied to the reference to derive the target. Keeping
/// the target related to the reference is what makes the delta encoder's match
/// finder fire; two independent random buffers almost never share long matches.
#[derive(Arbitrary, Debug)]
pub enum Edit {
    /// Copy a span of the reference (offset and length resolved modulo the
    /// reference length, so they are always in bounds).
    CopyRef { off: u16, len: u16 },
    /// Insert literal bytes that need not appear in the reference.
    Literal(Vec<u8>),
}

/// Which codec / format-version combination to encode with.
#[derive(Arbitrary, Debug)]
pub enum CodecChoice {
    Pa30PseudoLzx,
    Pa30BsDiff,
    Pa31PseudoLzx,
}

/// A reference buffer plus a recipe for a target derived from it.
#[derive(Arbitrary, Debug)]
pub struct RoundTrip {
    pub reference: Vec<u8>,
    pub edits: Vec<Edit>,
    pub codec: CodecChoice,
}

impl RoundTrip {
    /// Materialize the target buffer from the reference and the edit list. Each
    /// append is clamped to the room left under [`MAX_BYTES`], so the buffer is
    /// capped without ever allocating past it.
    pub fn target(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for edit in &self.edits {
            let room = MAX_BYTES - out.len();
            if room == 0 {
                break;
            }
            match edit {
                Edit::CopyRef { off, len } => {
                    if self.reference.is_empty() {
                        continue;
                    }
                    let start = (*off as usize) % self.reference.len();
                    let max = self.reference.len() - start;
                    let take = ((*len as usize) % (max + 1)).min(room);
                    out.extend_from_slice(&self.reference[start..start + take]);
                }
                Edit::Literal(bytes) => out.extend_from_slice(&bytes[..bytes.len().min(room)]),
            }
        }
        out
    }

    /// The encoder options selected by `codec`.
    pub fn create_options(&self) -> CreateOptions {
        let opts = CreateOptions::new();
        match self.codec {
            CodecChoice::Pa30PseudoLzx => opts.codec(Codec::PseudoLzx).version(FormatVersion::PA30),
            CodecChoice::Pa30BsDiff => opts.codec(Codec::BsDiff).version(FormatVersion::PA30),
            CodecChoice::Pa31PseudoLzx => opts.codec(Codec::PseudoLzx).version(FormatVersion::PA31),
        }
    }
}

/// A run of plaintext biased toward the structures the LZMS codecs care about.
#[derive(Arbitrary, Debug)]
pub enum Chunk {
    /// Arbitrary literal bytes.
    Literal(Vec<u8>),
    /// A long run of one byte (exercises long-match / run handling).
    Run { byte: u8, len: u16 },
    /// A repeated block (exercises rep-matches across distances).
    Repeat { block: Vec<u8>, times: u8 },
    /// An arithmetic sequence (exercises delta-friendly paths).
    Arith { start: u8, step: u8, len: u16 },
}

/// Structured plaintext for the LZMS round-trip targets.
#[derive(Arbitrary, Debug)]
pub struct Plaintext(pub Vec<Chunk>);

impl Plaintext {
    /// Materialize the plaintext bytes. Each append is clamped to the room left
    /// under [`MAX_BYTES`], so the buffer is capped without allocating past it.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in &self.0 {
            let room = MAX_BYTES - out.len();
            if room == 0 {
                break;
            }
            match chunk {
                Chunk::Literal(b) => out.extend_from_slice(&b[..b.len().min(room)]),
                Chunk::Run { byte, len } => {
                    out.resize(out.len() + (*len as usize).min(room), *byte);
                }
                Chunk::Repeat { block, times } => {
                    for _ in 0..*times {
                        let room = MAX_BYTES - out.len();
                        if room == 0 {
                            break;
                        }
                        out.extend_from_slice(&block[..block.len().min(room)]);
                    }
                }
                Chunk::Arith { start, step, len } => {
                    let mut v = *start;
                    out.extend((0..(*len as usize).min(room)).map(|_| {
                        let b = v;
                        v = v.wrapping_add(*step);
                        b
                    }));
                }
            }
        }
        out
    }
}
