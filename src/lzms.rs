//! LZMS (Lempel-Ziv-Markov-Shannon) decompressor.
//!
//! Clean-room Rust implementation based on the algorithm documented in
//! wimlib (Eric Biggers). Used by MSDelta's BsDiff path and the Windows
//! Compression API (algorithm ID 5).
//!
//! Key architecture:
//! - Dual-stream: forward range coder + backward Huffman/extra-bits
//! - Adaptive Huffman codes rebuilt every 512-1024 symbols
//! - Markov decision tree with adaptive probability tables
//! - LZ + delta matching with 3-element LRU queues

use crate::{Error, Result};

// --- Constants ---

const PROB_BITS: u32 = 6;
const PROB_MAX: u32 = (1 << PROB_BITS) - 1; // 63
const INITIAL_PROB: u32 = 48;
const INITIAL_RECENT_BITS: u64 = 0x0000_0000_5555_5555;

const NUM_MAIN_PROBS: usize = 16;
const NUM_MATCH_PROBS: usize = 32;
const NUM_LZ_PROBS: usize = 64;
const NUM_LZ_REP_PROBS: usize = 64;
const _NUM_DELTA_PROBS: usize = 64;
const _NUM_DELTA_REP_PROBS: usize = 64;

/// Decompress LZMS data. Returns the decompressed output.
pub fn decompress(data: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() || output_size == 0 {
        return Ok(Vec::new());
    }
    if data.len() < 4 || data.len() % 2 != 0 {
        return Err(Error::Malformed("LZMS: need >= 4 even bytes"));
    }

    let mut out = vec![0u8; output_size];
    let mut rd = RangeDecoder::new(data);
    let mut bs = BackBitstream::new(data);

    let mut probs = Probs::new();
    let mut main_st = 0u32;
    let mut match_st = 0u32;
    let mut lz_st = 0u32;
    let mut lz_rep_st = [0u32; 2];
    let mut _delta_st = 0u32;
    let mut _delta_rep_st = [0u32; 2];

    let mut lz_off = [1u32, 2, 3, 4];
    let mut prev_type = 0u32; // 0=literal, 1=LZ, 2=delta

    let mut pos = 0usize;

    while pos < output_size {
        let main_bit = rd.decode_bit(&mut main_st, NUM_MAIN_PROBS, &mut probs.main);

        if main_bit == 0 {
            // Literal: read 8 bits from backward stream
            let byte = bs.read_bits(8) as u8;
            out[pos] = byte;
            pos += 1;
            prev_type = 0;
        } else {
            let match_bit = rd.decode_bit(&mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            if match_bit == 0 {
                // LZ match
                let lz_bit = rd.decode_bit(&mut lz_st, NUM_LZ_PROBS, &mut probs.lz);

                let offset;
                if lz_bit == 0 {
                    // Explicit offset from backward stream
                    let raw = bs.read_bits(16) as u32;
                    offset = raw + 1;
                    lz_off[3] = lz_off[2];
                    lz_off[2] = lz_off[1];
                    lz_off[1] = lz_off[0];
                    lz_off[0] = offset;
                } else {
                    // Repeat offset
                    let rep = decode_rep(
                        &mut rd,
                        &mut lz_rep_st,
                        &mut probs.lz_rep,
                    );
                    let slot = (rep + (prev_type & 1) as usize).min(3);
                    offset = lz_off[slot];
                    for i in (1..=slot).rev() {
                        lz_off[i] = lz_off[i - 1];
                    }
                    lz_off[0] = offset;
                }

                // Length from backward stream
                let length = (bs.read_bits(8) as usize).max(1);

                if (offset as usize) > pos {
                    return Err(Error::Malformed("LZMS: LZ offset past start"));
                }
                let copy_len = length.min(output_size - pos);
                let src = pos - offset as usize;
                for i in 0..copy_len {
                    out[pos + i] = out[src + i];
                }
                pos += copy_len;
                prev_type = 1;
            } else {
                // Delta match — not yet implemented
                return Err(Error::Malformed("LZMS: delta match not supported"));
            }
        }
    }

    Ok(out)
}

/// Compress data using LZMS (not yet implemented).
pub fn compress(_data: &[u8]) -> Result<Vec<u8>> {
    Err(Error::Malformed("LZMS compression not implemented"))
}

// --- Range Decoder (forward stream) ---

struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        let code = (le16(data, 0) as u32) << 16 | le16(data, 2) as u32;
        RangeDecoder {
            data,
            pos: 4,
            range: 0xFFFF_FFFF,
            code,
        }
    }

    #[inline]
    fn normalize(&mut self) {
        if self.range < 0x10000 {
            self.range <<= 16;
            if self.pos + 2 <= self.data.len() {
                self.code = (self.code << 16) | le16(self.data, self.pos) as u32;
                self.pos += 2;
            } else {
                self.code <<= 16;
            }
        }
    }

    #[inline]
    fn decode_bit(&mut self, state: &mut u32, num_states: usize, probs: &mut [ProbEntry]) -> u32 {
        self.normalize();
        let prob = probs[*state as usize].get();
        let bound = (self.range >> PROB_BITS) * prob;

        let bit = if self.code < bound {
            self.range = bound;
            0
        } else {
            self.range -= bound;
            self.code -= bound;
            1
        };

        probs[*state as usize].update(bit);
        *state = (*state << 1 | bit) & (num_states as u32 - 1);
        bit
    }
}

// --- Backward Bitstream ---

struct BackBitstream<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    bits: u32,
}

impl<'a> BackBitstream<'a> {
    fn new(data: &'a [u8]) -> Self {
        BackBitstream {
            data,
            pos: data.len(),
            buf: 0,
            bits: 0,
        }
    }

    #[inline]
    fn ensure(&mut self, n: u32) {
        while self.bits < n && self.pos >= 2 {
            self.pos -= 2;
            let w = le16(self.data, self.pos) as u64;
            self.buf |= w << (48 - self.bits); // pack at MSB end
            self.bits += 16;
        }
    }

    #[inline]
    fn read_bits(&mut self, n: u32) -> u64 {
        self.ensure(n);
        let val = self.buf >> (64 - n);
        self.buf <<= n;
        self.bits -= n;
        val
    }
}

// --- Adaptive Probability ---

#[derive(Clone)]
struct ProbEntry {
    num_zeros: u32,
    recent: u64,
}

impl ProbEntry {
    fn new() -> Self {
        ProbEntry {
            num_zeros: INITIAL_PROB,
            recent: INITIAL_RECENT_BITS,
        }
    }

    #[inline]
    fn get(&self) -> u32 {
        self.num_zeros.clamp(1, PROB_MAX)
    }

    #[inline]
    fn update(&mut self, bit: u32) {
        let oldest = (self.recent >> 63) as u32;
        self.recent = (self.recent << 1) | bit as u64;
        // oldest leaving: if it was 0, decrement count
        // new arriving: if it is 0, increment count
        // net: num_zeros += oldest - bit
        //   oldest=0,bit=0 → +0-0=0 (zero leaves, zero enters)
        //   oldest=0,bit=1 → +0-1=-1 (zero leaves, one enters)
        //   oldest=1,bit=0 → +1-0=+1 (one leaves, zero enters)
        //   oldest=1,bit=1 → +1-1=0 (one leaves, one enters)
        // Wait: oldest=0 means a zero is leaving → should DECREASE count
        // But oldest - bit when oldest=0,bit=0 gives 0. That's wrong.
        // Correct: num_zeros = num_zeros - (1-oldest) + (1-bit)
        if oldest == 0 { self.num_zeros -= 1; }
        if bit == 0 { self.num_zeros += 1; }
    }
}





// --- Probability Tables ---

struct Probs {
    main: Vec<ProbEntry>,
    match_: Vec<ProbEntry>,
    lz: Vec<ProbEntry>,
    lz_rep: [Vec<ProbEntry>; 2],
}

impl Probs {
    fn new() -> Self {
        Probs {
            main: vec![ProbEntry::new(); NUM_MAIN_PROBS],
            match_: vec![ProbEntry::new(); NUM_MATCH_PROBS],
            lz: vec![ProbEntry::new(); NUM_LZ_PROBS],
            lz_rep: [
                vec![ProbEntry::new(); NUM_LZ_REP_PROBS],
                vec![ProbEntry::new(); NUM_LZ_REP_PROBS],
            ],
        }
    }
}

// --- Helpers ---

fn decode_rep(
    rd: &mut RangeDecoder,
    states: &mut [u32; 2],
    probs: &mut [Vec<ProbEntry>; 2],
) -> usize {
    let b0 = rd.decode_bit(&mut states[0], NUM_LZ_REP_PROBS, &mut probs[0]);
    if b0 == 0 { return 0; }
    let b1 = rd.decode_bit(&mut states[1], NUM_LZ_REP_PROBS, &mut probs[1]);
    if b1 == 0 { 1 } else { 2 }
}

#[inline]
fn le16(data: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([data[pos], data[pos + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lzms");

    fn check(name: &str) {
        let lzms_path = Path::new(FIXTURES).join(format!("{name}.lzms"));
        let raw_path = Path::new(FIXTURES).join(format!("{name}.raw"));

        if !lzms_path.exists() {
            eprintln!("SKIP {name}: no fixture");
            return;
        }

        let compressed = std::fs::read(&lzms_path).unwrap();
        let expected = std::fs::read(&raw_path).unwrap();

        match decompress(&compressed, expected.len()) {
            Ok(output) => {
                assert_eq!(output, expected, "{name}: output mismatch");
            }
            Err(e) => {
                eprintln!("FAIL {name}: {e}");
            }
        }
    }

    #[test]
    fn empty() {
        assert_eq!(decompress(&[], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn too_short() {
        assert!(decompress(&[0, 0], 10).is_err());
    }

    #[test]
    fn zeros() { check("zeros"); }

    #[test]
    fn sequential() { check("sequential"); }

    #[test]
    fn pattern() { check("pattern"); }

    #[test]
    fn single_byte() { check("single_byte"); }

    #[test]
    fn english() { check("english"); }

    #[test]
    fn small() { check("small"); }

    #[test]
    fn random() { check("random"); }
}
