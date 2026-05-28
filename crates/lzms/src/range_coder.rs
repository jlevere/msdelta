use super::adaptive::le16;

pub(super) const PROB_BITS: u32 = 6;
pub(super) const PROB_MAX: u32 = (1 << PROB_BITS) - 1;
pub(super) const PROB_DENOMINATOR: u32 = 1 << PROB_BITS;
pub(super) const INITIAL_PROB: u32 = 48;
pub(super) const INITIAL_RECENT_BITS: u64 = 0x0000_0000_5555_5555;

/// Fixed-point scale for the cost-based parser: one bit costs `1 << COST_SHIFT`
/// units, so fractional bit costs are representable. Matches the scaling used
/// by wimlib's LZMS optimizer (`COST_SHIFT = 6`); the analogous LZMA/zstd
/// coders use 1/16- and 1/256-bit units respectively.
pub(super) const COST_SHIFT: u32 = 6;

/// `BIT_COST[i]` is the cost of coding a bit whose modeled probability is
/// `i / 64`, i.e. `round(-log2(i / 64) * 2^COST_SHIFT)`. Index 0 and the
/// denominator are clamped inward (a coded bit never has probability 0 or 1).
/// Built once; the range coder reads it to price decision bits.
pub(super) static BIT_COST: std::sync::LazyLock<[u32; (PROB_DENOMINATOR + 1) as usize]> =
    std::sync::LazyLock::new(|| {
        std::array::from_fn(|i| {
            let num = (i as u32).clamp(1, PROB_DENOMINATOR - 1);
            let p = num as f64 / PROB_DENOMINATOR as f64;
            (-p.log2() * (1u32 << COST_SHIFT) as f64).round() as u32
        })
    });

pub(super) const NUM_MAIN_PROBS: usize = 16;
pub(super) const NUM_MATCH_PROBS: usize = 32;
pub(super) const NUM_LZ_PROBS: usize = 64;
pub(super) const NUM_LZ_REP_PROBS: usize = 64;
pub(super) const NUM_DELTA_PROBS: usize = 64;
pub(super) const NUM_DELTA_REP_PROBS: usize = 64;

// --- Range Encoder (forward stream, writes LE16 to front of buffer) ---

pub(super) struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u16,
    cache_count: u32,
    first: bool,
    output: Vec<u8>,
}

impl RangeEncoder {
    pub(super) fn new() -> Self {
        RangeEncoder {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_count: 0,
            first: true,
            output: Vec::new(),
        }
    }

    fn emit(&mut self, word: u16) {
        self.output.push(word as u8);
        self.output.push((word >> 8) as u8);
    }

    #[inline]
    fn shift_low(&mut self) {
        let overflow = (self.low >> 32) != 0;
        if self.low < 0xFFFF_0000 || overflow {
            if !self.first {
                self.emit(self.cache.wrapping_add(overflow as u16));
                let fill = if overflow { 0u16 } else { 0xFFFFu16 };
                for _ in 0..self.cache_count {
                    self.emit(fill);
                }
            }
            self.first = false;
            self.cache = ((self.low >> 16) & 0xFFFF) as u16;
            self.cache_count = 0;
        } else {
            self.cache_count += 1;
        }
        self.low = (self.low & 0xFFFF) << 16;
        self.range <<= 16;
    }

    #[inline]
    fn normalize(&mut self) {
        while self.range < 0x10000 {
            self.shift_low();
        }
    }

    pub(super) fn encode_bit(
        &mut self,
        bit: u32,
        state: &mut u32,
        num_states: usize,
        probs: &mut [ProbEntry],
    ) {
        self.normalize();
        let prob = probs[*state as usize].get();
        let bound = (self.range >> PROB_BITS) * prob;
        if bit == 0 {
            self.range = bound;
        } else {
            self.low += bound as u64;
            self.range -= bound;
        }
        probs[*state as usize].update(bit);
        *state = (*state << 1 | bit) & (num_states as u32 - 1);
    }

    pub(super) fn finish(&mut self, out: &mut Vec<u8>) {
        for _ in 0..4 {
            self.shift_low();
        }
        out.splice(0..0, self.output.drain(..));
    }
}

// --- Range Decoder (forward stream, reads LE16 from front of buffer) ---

pub(super) struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        let hi = le16(data, 0) as u32;
        let lo = le16(data, 2) as u32;
        RangeDecoder {
            data,
            pos: 4,
            range: 0xFFFF_FFFF,
            code: (hi << 16) | lo,
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
    pub(super) fn decode_bit(
        &mut self,
        state: &mut u32,
        num_states: usize,
        probs: &mut [ProbEntry],
    ) -> u32 {
        self.normalize();
        let prob = probs[*state as usize].get();
        let bound = (self.range >> PROB_BITS) * prob;
        let bit;
        if self.code < bound {
            self.range = bound;
            bit = 0;
        } else {
            self.range -= bound;
            self.code -= bound;
            bit = 1;
        }
        probs[*state as usize].update(bit);
        *state = (*state << 1 | bit) & (num_states as u32 - 1);
        bit
    }
}

// --- Adaptive Probability Entry (64-bit sliding window) ---

#[derive(Clone)]
pub(super) struct ProbEntry {
    num_zeros: u32,
    recent: u64,
}

impl ProbEntry {
    pub(super) fn new() -> Self {
        ProbEntry {
            num_zeros: INITIAL_PROB,
            recent: INITIAL_RECENT_BITS,
        }
    }

    #[inline]
    pub(super) fn get(&self) -> u32 {
        self.num_zeros.clamp(1, PROB_MAX)
    }

    /// Cost (in `1/2^COST_SHIFT`-bit units) of range-coding a 0 in this
    /// context: `-log2(P(0))`, `P(0) = num_zeros / 64`.
    #[inline]
    pub(super) fn cost0(&self) -> u32 {
        BIT_COST[self.num_zeros.min(PROB_DENOMINATOR) as usize]
    }

    /// Cost of range-coding a 1: `-log2(1 - P(0))`, from the complementary
    /// table entry.
    #[inline]
    pub(super) fn cost1(&self) -> u32 {
        BIT_COST[(PROB_DENOMINATOR - self.num_zeros.min(PROB_DENOMINATOR)) as usize]
    }

    #[inline]
    pub(super) fn update(&mut self, bit: u32) {
        let oldest = (self.recent >> 63) as u32;
        self.recent = (self.recent << 1) | bit as u64;
        if oldest == 0 {
            self.num_zeros -= 1;
        }
        if bit == 0 {
            self.num_zeros += 1;
        }
    }
}

/// Per-class adaptive probability tables. All sizes are compile-time
/// constants, so these are fixed-size arrays held inline (no per-chunk heap
/// allocation); a fresh `ProbTables` is created for each independent LZMS
/// stream.
pub(super) struct ProbTables {
    pub(super) main: [ProbEntry; NUM_MAIN_PROBS],
    pub(super) match_: [ProbEntry; NUM_MATCH_PROBS],
    pub(super) lz: [ProbEntry; NUM_LZ_PROBS],
    pub(super) lz_rep: [[ProbEntry; NUM_LZ_REP_PROBS]; 2],
    pub(super) delta: [ProbEntry; NUM_DELTA_PROBS],
    pub(super) delta_rep: [[ProbEntry; NUM_DELTA_REP_PROBS]; 2],
}

impl ProbTables {
    pub(super) fn new() -> Self {
        fn table<const N: usize>() -> [ProbEntry; N] {
            std::array::from_fn(|_| ProbEntry::new())
        }
        ProbTables {
            main: table(),
            match_: table(),
            lz: table(),
            lz_rep: [table(), table()],
            delta: table(),
            delta_rep: [table(), table()],
        }
    }
}
