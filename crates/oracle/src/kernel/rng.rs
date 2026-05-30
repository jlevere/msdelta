//! A tiny deterministic PRNG for reproducible case generation.
//!
//! Generation must be a pure function of an explicit seed so any run, and any
//! single case within it, can be reproduced exactly off-lab. We use SplitMix64
//! (the seeding RNG from the xoshiro family): trivial, fast, no dependency, and
//! no entropy source.

/// SplitMix64 deterministic generator.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seed the generator.
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..n` (uniform enough for test generation). Returns 0 for
    /// `n == 0`.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// A value in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        debug_assert!(lo <= hi);
        lo + self.below(hi - lo + 1)
    }

    /// Fill `buf` with pseudo-random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            for (b, r) in chunk.iter_mut().zip(bytes) {
                *b = r;
            }
        }
    }

    /// True with probability `num/den`.
    pub fn chance(&mut self, num: u32, den: u32) -> bool {
        debug_assert!(den != 0);
        (self.next_u64() as u32) % den < num
    }
}

/// Derive a sub-seed for a named stream, so two categories generated from the
/// same global seed do not produce correlated cases. FNV-1a of the label mixed
/// into the seed.
pub fn derive_seed(seed: u64, label: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in label.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    seed ^ h
}
