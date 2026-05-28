use crate::Error;
use crate::Result;

pub(super) const MAX_CODEWORD_LEN: u32 = 15;
pub(super) const TABLE_BITS: u32 = 10;
pub(super) const TABLE_SIZE: usize = 1 << TABLE_BITS;
pub(super) const ENTRY_OVERFLOW: u16 = 0x8000;

// --- Backward Bitstream (reads LE16 from back of buffer, MSB-first) ---

pub(crate) struct BackBits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    bits: u32,
}

impl<'a> BackBits<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        BackBits {
            data,
            pos: data.len(),
            buf: 0,
            bits: 0,
        }
    }

    #[inline]
    pub(crate) fn ensure(&mut self, n: u32) {
        while self.bits < n && self.pos >= 2 {
            self.pos -= 2;
            let w = le16(self.data, self.pos) as u64;
            self.buf |= w << (48 - self.bits);
            self.bits += 16;
        }
    }

    #[inline]
    pub(super) fn peek(&self, n: u32) -> u32 {
        (self.buf >> (64 - n)) as u32
    }

    #[inline]
    pub(super) fn consume(&mut self, n: u32) {
        self.buf <<= n;
        // On a truncated/malformed stream `ensure` can leave fewer than `n`
        // bits buffered; `peek` already zero-fills those, so saturate here
        // rather than underflow. A well-formed stream never asks past its end.
        self.bits = self.bits.saturating_sub(n);
    }

    #[inline]
    pub(crate) fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        self.ensure(n);
        let val = self.peek(n);
        self.consume(n);
        val
    }
}

// --- Backward bitstream writer (writes LE16 to end of buffer, MSB-first) ---

pub(super) struct BackBitsWriter {
    buf: u64,
    bits: u32,
    output: Vec<u8>,
}

impl BackBitsWriter {
    pub(super) fn new() -> Self {
        BackBitsWriter {
            buf: 0,
            bits: 0,
            output: Vec::new(),
        }
    }

    pub(super) fn write_bits(&mut self, val: u32, n: u32) {
        self.buf = (self.buf << n) | (val as u64);
        self.bits += n;
        while self.bits >= 16 {
            self.bits -= 16;
            let word = (self.buf >> self.bits) as u16;
            self.output.push(word as u8);
            self.output.push((word >> 8) as u8);
            self.buf &= (1u64 << self.bits) - 1;
        }
    }

    pub(super) fn finish(&self, out: &mut Vec<u8>) {
        if self.bits > 0 {
            let word = (self.buf << (16 - self.bits)) as u16;
            out.push(word as u8);
            out.push((word >> 8) as u8);
        }
        for chunk in self.output.chunks(2).rev() {
            out.extend_from_slice(chunk);
        }
    }
}

// --- Adaptive Huffman Code ---
//
// 10-bit direct lookup table with binary overflow tree for longer codes.
// Rebuilt periodically from accumulated symbol frequencies.
// After each rebuild, frequencies are halved: freq = (freq >> 1) + 1.

pub(super) struct AdaptiveCode {
    rebuild_freq: u32,
    freqs: Vec<u32>,
    countdown: u32,
    direct: Vec<u16>,
    overflow: Vec<[u16; 2]>,
    codes: Vec<u32>,
    lens: Vec<u8>,
    // Reused across every rebuild so Huffman-length computation allocates once,
    // not on each `rebuild()` (called every `rebuild_freq` symbols).
    code_scratch: CodeLenScratch,
}

impl AdaptiveCode {
    pub(super) fn new(num_syms: usize, rebuild_freq: u32) -> Self {
        let mut code = AdaptiveCode {
            rebuild_freq,
            freqs: vec![1; num_syms],
            countdown: rebuild_freq,
            direct: vec![0; TABLE_SIZE],
            overflow: Vec::new(),
            codes: vec![0; num_syms],
            lens: vec![0; num_syms],
            code_scratch: CodeLenScratch::default(),
        };
        if num_syms > 0 {
            code.rebuild();
        }
        code
    }

    fn rebuild(&mut self) {
        // Move the scratch out so `build_*` can take `&mut self` while we hold a
        // shared borrow of the computed lengths; restore it afterward. The empty
        // placeholder allocates nothing, and the scratch keeps its capacity.
        let mut scratch = std::mem::take(&mut self.code_scratch);
        scratch.compute(&self.freqs);
        self.build_tables(&scratch.lens);
        self.build_codes(&scratch.lens);
        self.code_scratch = scratch;
    }

    fn build_codes(&mut self, lens: &[u8]) {
        let mut count = [0u32; MAX_CODEWORD_LEN as usize + 1];
        for &l in lens {
            if l > 0 {
                count[l as usize] += 1;
            }
        }
        let mut next_code = [0u32; MAX_CODEWORD_LEN as usize + 1];
        let mut code = 0u32;
        for bits in 1..=MAX_CODEWORD_LEN as usize {
            code = (code + count[bits - 1]) << 1;
            next_code[bits] = code;
        }
        self.lens.fill(0);
        self.codes.fill(0);
        for (sym, &len) in lens.iter().enumerate() {
            if len == 0 {
                continue;
            }
            self.lens[sym] = len;
            self.codes[sym] = next_code[len as usize];
            next_code[len as usize] += 1;
        }
    }

    fn build_tables(&mut self, lens: &[u8]) {
        self.direct.fill(0);
        self.overflow.clear();

        let mut count = [0u32; MAX_CODEWORD_LEN as usize + 1];
        for &l in lens {
            if l > 0 {
                count[l as usize] += 1;
            }
        }

        let mut next_code = [0u32; MAX_CODEWORD_LEN as usize + 1];
        let mut code = 0u32;
        for bits in 1..=MAX_CODEWORD_LEN as usize {
            code = (code + count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for (sym, &len) in lens.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let c = next_code[len as usize];
            next_code[len as usize] += 1;

            if (len as u32) <= TABLE_BITS {
                let shift = TABLE_BITS - len as u32;
                let base = c << shift;
                let fill = 1u32 << shift;
                let entry = ((sym as u16) << 4) | len as u16;
                for i in 0..fill {
                    self.direct[(base + i) as usize] = entry;
                }
            } else {
                let prefix = (c >> (len as u32 - TABLE_BITS)) as usize;
                let suffix_len = len as u32 - TABLE_BITS;
                let suffix = c & ((1 << suffix_len) - 1);

                let root = if self.direct[prefix] == 0 {
                    let idx = self.overflow.len();
                    self.overflow.push([0; 2]);
                    self.direct[prefix] = ENTRY_OVERFLOW | idx as u16;
                    idx
                } else {
                    (self.direct[prefix] & !ENTRY_OVERFLOW) as usize
                };

                let mut node = root;
                for bit_pos in (1..suffix_len).rev() {
                    let bit = ((suffix >> bit_pos) & 1) as usize;
                    let child = self.overflow[node][bit];
                    if child == 0 {
                        let idx = self.overflow.len();
                        self.overflow.push([0; 2]);
                        self.overflow[node][bit] = ENTRY_OVERFLOW | idx as u16;
                        node = idx;
                    } else {
                        node = (child & !ENTRY_OVERFLOW) as usize;
                    }
                }
                let last_bit = (suffix & 1) as usize;
                self.overflow[node][last_bit] = ((sym as u16) << 4) | len as u16;
            }
        }
    }

    pub(super) fn encode_symbol(&mut self, sym: usize, bs: &mut BackBitsWriter) {
        let len = self.lens[sym] as u32;
        let code = self.codes[sym];
        if len > 0 {
            bs.write_bits(code, len);
        }
        self.freqs[sym] += 1;
        self.countdown -= 1;
        if self.countdown == 0 {
            for f in &mut self.freqs {
                *f = (*f >> 1) + 1;
            }
            self.rebuild();
            self.countdown = self.rebuild_freq;
        }
    }

    pub(super) fn decode_symbol(&mut self, bs: &mut BackBits) -> Result<usize> {
        bs.ensure(MAX_CODEWORD_LEN);
        let peek = bs.peek(TABLE_BITS);
        let entry = self.direct[peek as usize];

        let sym;
        if entry & ENTRY_OVERFLOW != 0 {
            bs.consume(TABLE_BITS);
            let mut idx = (entry & !ENTRY_OVERFLOW) as usize;
            loop {
                let bit = bs.read_bits(1) as usize;
                let child = self.overflow[idx][bit];
                if child & ENTRY_OVERFLOW != 0 {
                    idx = (child & !ENTRY_OVERFLOW) as usize;
                } else if child != 0 {
                    sym = (child >> 4) as usize;
                    break;
                } else {
                    return Err(Error::Malformed("LZMS: invalid huffman overflow"));
                }
            }
        } else if entry != 0 {
            let len = (entry & 0xF) as u32;
            sym = (entry >> 4) as usize;
            bs.consume(len);
        } else {
            return Err(Error::Malformed("LZMS: invalid huffman code"));
        }

        if sym >= self.freqs.len() {
            return Err(Error::Malformed("LZMS: huffman symbol out of range"));
        }
        self.freqs[sym] += 1;
        self.countdown -= 1;
        if self.countdown == 0 {
            for f in &mut self.freqs {
                *f = (*f >> 1) + 1;
            }
            self.rebuild();
            self.countdown = self.rebuild_freq;
        }

        Ok(sym)
    }
}

// --- Huffman tree construction ---
//
// Standard two-queue merge with depth limiting to MAX_CODEWORD_LEN.
// If any code exceeds the limit, halve all frequencies and retry.

/// Pick the smaller-frequency front of the two merge queues (leaves `q1`,
/// internal nodes `q2`), advancing the chosen cursor. Ties and the queue-empty
/// cases match the original two-queue merge exactly.
fn pick_min(
    freq: &[u32],
    q2: &[usize],
    q1: &mut usize,
    q2f: &mut usize,
    num_leaves: usize,
) -> usize {
    let q1_avail = *q1 < num_leaves;
    let q2_avail = *q2f < q2.len();
    if !q2_avail || (q1_avail && freq[*q1] <= freq[q2[*q2f]]) {
        let i = *q1;
        *q1 += 1;
        i
    } else {
        let i = q2[*q2f];
        *q2f += 1;
        i
    }
}

/// Reusable working buffers for [`CodeLenScratch::compute`]. Held by each
/// `AdaptiveCode` and reused across every rebuild so the Huffman-length
/// computation does not heap-allocate per call. `lens` holds the result.
#[derive(Default)]
pub(super) struct CodeLenScratch {
    lens: Vec<u8>,
    active: Vec<(u32, u16)>,
    freq: Vec<u32>,
    children: Vec<[usize; 2]>,
    is_leaf: Vec<bool>,
    q2: Vec<usize>,
    depth: Vec<u32>,
    stack: Vec<(usize, u32)>,
}

impl CodeLenScratch {
    /// Compute canonical Huffman codeword lengths for `freqs` into `self.lens`
    /// (length-limited to `MAX_CODEWORD_LEN` via the standard two-queue merge,
    /// halving frequencies and retrying if the limit is exceeded). All working
    /// state is reused from `self`; the result is byte-identical to a fresh
    /// allocation.
    fn compute(&mut self, freqs: &[u32]) {
        let n = freqs.len();
        self.lens.clear();
        self.lens.resize(n, 0);

        self.active.clear();
        for (i, &f) in freqs.iter().enumerate() {
            if f > 0 {
                self.active.push((f, i as u16));
            }
        }

        match self.active.len() {
            0 => return,
            1 => {
                self.lens[self.active[0].1 as usize] = 1;
                return;
            }
            _ => {}
        }

        loop {
            self.active
                .sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

            let num = self.active.len();
            let total = 2 * num - 1;
            self.freq.clear();
            self.freq.resize(total, 0);
            self.children.clear();
            self.children.resize(total, [0; 2]);
            self.is_leaf.clear();
            self.is_leaf.resize(total, true);

            for (i, &(f, _)) in self.active.iter().enumerate() {
                self.freq[i] = f;
            }

            let mut q1 = 0usize;
            self.q2.clear();
            let mut q2_front = 0usize;
            let mut next = num;

            for _ in 0..num - 1 {
                // Pick the smaller of the two queue fronts, twice. Inlined as
                // blocks (not a closure) so each shared read of self.freq /
                // self.q2 ends before the self.freq/self.q2 mutations below;
                // q1/q2_front stay locals.
                let left = pick_min(&self.freq, &self.q2, &mut q1, &mut q2_front, num);
                let right = pick_min(&self.freq, &self.q2, &mut q1, &mut q2_front, num);
                self.freq[next] = self.freq[left].saturating_add(self.freq[right]);
                self.children[next] = [left, right];
                self.is_leaf[next] = false;
                self.q2.push(next);
                next += 1;
            }

            let root = next - 1;
            self.depth.clear();
            self.depth.resize(total, 0);
            self.stack.clear();
            self.stack.push((root, 0u32));
            let mut max_depth = 0u32;
            while let Some((node, d)) = self.stack.pop() {
                self.depth[node] = d;
                if self.is_leaf[node] {
                    max_depth = max_depth.max(d);
                } else {
                    self.stack.push((self.children[node][0], d + 1));
                    self.stack.push((self.children[node][1], d + 1));
                }
            }

            if max_depth <= MAX_CODEWORD_LEN {
                self.lens.fill(0);
                for i in 0..num {
                    self.lens[self.active[i].1 as usize] = self.depth[i] as u8;
                }
                return;
            }

            for item in &mut self.active {
                item.0 = (item.0 + 1) >> 1;
            }
        }
    }
}

#[inline]
pub(super) fn le16(data: &[u8], pos: usize) -> u16 {
    u16::from_le_bytes([data[pos], data[pos + 1]])
}
