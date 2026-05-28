use super::adaptive::le16;

pub(super) const PROB_BITS: u32 = 6;
pub(super) const PROB_MAX: u32 = (1 << PROB_BITS) - 1;
pub(super) const INITIAL_PROB: u32 = 48;
pub(super) const INITIAL_RECENT_BITS: u64 = 0x0000_0000_5555_5555;

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

pub(super) struct ProbTables {
    pub(super) main: Vec<ProbEntry>,
    pub(super) match_: Vec<ProbEntry>,
    pub(super) lz: Vec<ProbEntry>,
    pub(super) lz_rep: [Vec<ProbEntry>; 2],
    pub(super) delta: Vec<ProbEntry>,
    pub(super) delta_rep: [Vec<ProbEntry>; 2],
}

impl ProbTables {
    pub(super) fn new() -> Self {
        ProbTables {
            main: vec![ProbEntry::new(); NUM_MAIN_PROBS],
            match_: vec![ProbEntry::new(); NUM_MATCH_PROBS],
            lz: vec![ProbEntry::new(); NUM_LZ_PROBS],
            lz_rep: [
                vec![ProbEntry::new(); NUM_LZ_REP_PROBS],
                vec![ProbEntry::new(); NUM_LZ_REP_PROBS],
            ],
            delta: vec![ProbEntry::new(); NUM_DELTA_PROBS],
            delta_rep: [
                vec![ProbEntry::new(); NUM_DELTA_REP_PROBS],
                vec![ProbEntry::new(); NUM_DELTA_REP_PROBS],
            ],
        }
    }
}
