use crate::{Error, Result};

mod tables;

const PROB_BITS: u32 = 6;
const PROB_MAX: u32 = (1 << PROB_BITS) - 1;
const INITIAL_PROB: u32 = 48;
const INITIAL_RECENT_BITS: u64 = 0x0000_0000_5555_5555;

const NUM_MAIN_PROBS: usize = 16;
const NUM_MATCH_PROBS: usize = 32;
const NUM_LZ_PROBS: usize = 64;
const NUM_LZ_REP_PROBS: usize = 64;
const NUM_DELTA_PROBS: usize = 64;
const NUM_DELTA_REP_PROBS: usize = 64;

const MAX_CODEWORD_LEN: u32 = 15;
const TABLE_BITS: u32 = 10;
const TABLE_SIZE: usize = 1 << TABLE_BITS;

const COMPRESSION_API_MAGIC: u32 = 0xC0E5_510A;
const COMPRESSION_API_HEADER_SIZE: usize = 24;

/// Decompress a Windows Compression API (cabinet.dll) LZMS-wrapped buffer.
///
/// This is the format produced by `Compress()` with `COMPRESS_ALGORITHM_LZMS`
/// and consumed by msdelta.dll's `LzmsCodec::Decompress`. It consists of a
/// 24-byte header followed by chunk-size + compressed-data pairs.
pub fn decompress_compression_api(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < COMPRESSION_API_HEADER_SIZE + 4 {
        return Err(Error::Malformed("LZMS: compression API buffer too short"));
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != COMPRESSION_API_MAGIC {
        return Err(Error::Malformed("LZMS: bad compression API magic"));
    }
    let uncompressed_size = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    let chunk_compressed = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;
    let payload_start = COMPRESSION_API_HEADER_SIZE + 4;
    let payload_end = payload_start + chunk_compressed;
    if payload_end > data.len() {
        return Err(Error::Truncated);
    }
    if chunk_compressed == uncompressed_size {
        return Ok(data[payload_start..payload_end].to_vec());
    }
    decompress(&data[payload_start..payload_end], uncompressed_size)
}

/// Compress data into the Windows Compression API (cabinet.dll) LZMS format.
///
/// Produces the same format that `decompress_compression_api` reads:
/// 24-byte header + chunk-size + LZMS-compressed payload.
pub fn compress_compression_api(data: &[u8]) -> Result<Vec<u8>> {
    let compressed = compress(data)?;
    let payload = if compressed.len() < data.len() { &compressed } else { data };
    let mut out = Vec::with_capacity(COMPRESSION_API_HEADER_SIZE + 4 + payload.len());
    out.extend_from_slice(&COMPRESSION_API_MAGIC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decompress a raw LZMS bitstream.
pub fn decompress(data: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() || output_size == 0 {
        return Ok(Vec::new());
    }
    if data.len() < 4 || data.len() % 2 != 0 {
        return Err(Error::Malformed("LZMS: need >= 4 even bytes"));
    }

    let mut out = vec![0u8; output_size];
    let mut rc = RangeDecoder::new(data);
    let mut bs = BackBits::new(data);

    let num_offset_syms = tables::num_offset_slots(output_size as u32);

    let mut literal_code = AdaptiveCode::new(256, 1024);
    let mut lz_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut length_code = AdaptiveCode::new(54, 512);
    let mut delta_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut delta_power_code = AdaptiveCode::new(8, 512);

    let mut main_st = 0u32;
    let mut match_st = 0u32;
    let mut lz_st = 0u32;
    let mut lz_rep_st = [0u32; 2];
    let mut delta_st = 0u32;
    let mut delta_rep_st = [0u32; 2];

    let mut probs = ProbTables::new();

    let mut lz_queue: [u32; 4] = [1, 2, 3, 4];
    let mut delta_queue: [(u32, u32); 4] = [(1, 0), (2, 0), (3, 0), (4, 0)];
    let mut prev_type: u32 = 0;
    let mut pos = 0usize;

    while pos < output_size {
        let main_bit = rc.decode_bit(&mut main_st, NUM_MAIN_PROBS, &mut probs.main);

        if main_bit == 0 {
            let sym = literal_code.decode_symbol(&mut bs)?;
            out[pos] = sym as u8;
            pos += 1;
            prev_type = 0;
        } else {
            let match_bit =
                rc.decode_bit(&mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            if match_bit == 0 {
                let lz_bit = rc.decode_bit(&mut lz_st, NUM_LZ_PROBS, &mut probs.lz);

                let offset;
                if lz_bit == 0 {
                    let slot = lz_offset_code.decode_symbol(&mut bs)?;
                    offset = tables::decode_offset(slot, &mut bs);
                    queue_push(&mut lz_queue, offset);
                } else {
                    let rep = decode_rep(
                        &mut rc, &mut lz_rep_st, &mut probs.lz_rep,
                    );
                    let adj = (rep + (prev_type & 1) as usize).min(3);
                    offset = lz_queue[adj];
                    queue_mtf(&mut lz_queue, adj);
                }

                let len_slot = length_code.decode_symbol(&mut bs)?;
                let length = tables::decode_length(len_slot, &mut bs) as usize;

                if (offset as usize) > pos {
                    return Err(Error::Malformed("LZMS: LZ offset past start"));
                }
                let n = length.min(output_size - pos);
                let src = pos - offset as usize;
                for i in 0..n {
                    out[pos + i] = out[src + i];
                }
                pos += n;
                prev_type = 1;
            } else {
                let delta_bit =
                    rc.decode_bit(&mut delta_st, NUM_DELTA_PROBS, &mut probs.delta);

                let power;
                let raw_offset;
                if delta_bit == 0 {
                    power = delta_power_code.decode_symbol(&mut bs)? as u32;
                    raw_offset = tables::decode_offset(
                        delta_offset_code.decode_symbol(&mut bs)?,
                        &mut bs,
                    );
                    queue_push_pair(&mut delta_queue, (raw_offset, power));
                } else {
                    let rep = decode_rep(
                        &mut rc, &mut delta_rep_st, &mut probs.delta_rep,
                    );
                    let adj = (rep + ((prev_type >> 1) & 1) as usize).min(3);
                    let pair = delta_queue[adj];
                    raw_offset = pair.0;
                    power = pair.1;
                    queue_mtf_pair(&mut delta_queue, adj);
                }

                let length = tables::decode_length(
                    length_code.decode_symbol(&mut bs)?,
                    &mut bs,
                ) as usize;

                let span = 1usize << power;
                let offset = (raw_offset as usize)
                    .checked_shl(power)
                    .filter(|&o| o >> power == raw_offset as usize)
                    .ok_or(Error::Malformed("LZMS: delta offset overflow"))?;

                if offset.checked_add(span).is_none_or(|sum| sum > pos) {
                    return Err(Error::Malformed("LZMS: delta offset/span past start"));
                }
                let n = length.min(output_size - pos);
                for i in 0..n {
                    let s = pos + i - offset;
                    out[pos + i] = out[s]
                        .wrapping_add(out[pos + i - span])
                        .wrapping_sub(out[s - span]);
                }
                pos += n;
                prev_type = 2;
            }
        }
    }

    x86_filter(&mut out);
    Ok(out)
}

const X86_ID_WINDOW_SIZE: i32 = 65535;
const X86_MAX_TRANSLATION_OFFSET: i32 = 1023;

fn x86_filter(data: &mut [u8]) {
    x86_filter_impl(data, true);
}

fn x86_filter_impl(data: &mut [u8], undo: bool) {
    let size = data.len() as i32;
    if size <= 17 {
        return;
    }

    let mut last_x86_pos: i32 = -X86_MAX_TRANSLATION_OFFSET - 1;
    let mut last_target_usages = vec![-X86_ID_WINDOW_SIZE - 1i32; 65536];

    let mut i: i32 = 1;
    let limit = size - 16;

    while i < limit {
        let opcode = data[i as usize];
        let (nbytes, max_off) = match opcode {
            0xE8 => (1, X86_MAX_TRANSLATION_OFFSET >> 1),
            0x48 | 0x4C => {
                let modrm = data[(i + 2) as usize];
                let op = data[(i + 1) as usize];
                if (modrm & 0x07) == 0x05
                    && (op == 0x8D || (op == 0x8B && (opcode & 0x04) == 0 && (modrm & 0xF0) == 0))
                {
                    (3, X86_MAX_TRANSLATION_OFFSET)
                } else {
                    i += 1;
                    continue;
                }
            }
            0xFF if data[(i + 1) as usize] == 0x15 => {
                (2, X86_MAX_TRANSLATION_OFFSET)
            }
            0xF0
                if data[(i + 1) as usize] == 0x83
                    && (data[(i + 2) as usize] & 0x07) == 0x05 =>
            {
                (3, X86_MAX_TRANSLATION_OFFSET)
            }
            0xE9 => {
                i += 5;
                continue;
            }
            _ => {
                i += 1;
                continue;
            }
        };

        let p = (i + nbytes) as usize;
        let active = i - last_x86_pos <= max_off;
        if undo && active {
            let n = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
            data[p..p + 4].copy_from_slice(&n.wrapping_sub(i as u32).to_le_bytes());
        }
        let target16 = (i as u16).wrapping_add(u16::from_le_bytes(
            data[p..p + 2].try_into().unwrap(),
        ));
        if !undo && active {
            let n = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
            data[p..p + 4].copy_from_slice(&n.wrapping_add(i as u32).to_le_bytes());
        }
        let end_pos = i + nbytes + 3;
        if end_pos - last_target_usages[target16 as usize] <= X86_ID_WINDOW_SIZE {
            last_x86_pos = end_pos;
        }
        last_target_usages[target16 as usize] = end_pos;
        i = end_pos + 1;
    }
}

/// Compress data using LZMS with greedy LZ matching.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut filtered = data.to_vec();
    x86_filter_impl(&mut filtered, false);

    let num_offset_syms = tables::num_offset_slots(filtered.len() as u32);

    let mut rc = RangeEncoder::new();
    let mut bs = BackBitsWriter::new();

    let mut literal_code = AdaptiveCode::new(256, 1024);
    let mut lz_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut length_code = AdaptiveCode::new(54, 512);

    let mut main_st = 0u32;
    let mut match_st = 0u32;
    let mut lz_st = 0u32;
    let mut lz_rep_st = [0u32; 2];
    let mut probs = ProbTables::new();
    let mut lz_queue: [u32; 4] = [1, 2, 3, 4];
    let mut prev_type: u32 = 0;

    let d = &filtered;
    let mut pos = 0usize;

    // Hash chain for match finding (4-byte hash)
    const HASH_BITS: usize = 16;
    let mut head = vec![0u32; 1 << HASH_BITS];
    let mut chain = vec![0u32; d.len()];

    while pos < d.len() {
        let (match_offset, match_len) = if pos + 3 < d.len() {
            let h = hash4(d, pos) & ((1 << HASH_BITS) - 1);
            let mut best_len = 0u32;
            let mut best_off = 0u32;

            // Check LRU queue first
            for qi in 0..4usize {
                let adj = (qi + (prev_type & 1) as usize).min(3);
                let off = lz_queue[adj] as usize;
                if off > 0 && off <= pos {
                    let ml = match_length(d, pos - off, pos, d.len());
                    if ml > best_len && ml >= 2 {
                        best_len = ml;
                        best_off = off as u32;
                    }
                }
            }

            // Check hash chain
            let mut prev = head[h] as usize;
            let mut steps = 0;
            while prev > 0 && steps < 32 {
                let off = pos - prev;
                if off > 0 {
                    let ml = match_length(d, prev, pos, d.len());
                    if ml > best_len {
                        best_len = ml;
                        best_off = off as u32;
                    }
                }
                prev = chain[prev] as usize;
                steps += 1;
            }

            chain[pos] = head[h];
            head[h] = pos as u32;

            (best_off, best_len)
        } else {
            (0, 0)
        };
        if match_len >= 3 {
            // Encode LZ match
            rc.encode_bit(1, &mut main_st, NUM_MAIN_PROBS, &mut probs.main);
            rc.encode_bit(0, &mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            // Check if offset is in the 3 accessible LRU positions
            // (4th entry is overflow, can't be encoded as repeat)
            let rep_idx = {
                let adj_base = (prev_type & 1) as usize;
                let mut found = None;
                for rep in 0..3usize {
                    let adj = (rep + adj_base).min(3);
                    if lz_queue[adj] == match_offset {
                        found = Some((rep, adj));
                        break;
                    }
                }
                found
            };

            if let Some((rep, adj)) = rep_idx {
                rc.encode_bit(1, &mut lz_st, NUM_LZ_PROBS, &mut probs.lz);
                match rep {
                    0 => rc.encode_bit(0, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]),
                    1 => {
                        rc.encode_bit(1, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]);
                        rc.encode_bit(0, &mut lz_rep_st[1], NUM_DELTA_REP_PROBS, &mut probs.lz_rep[1]);
                    }
                    _ => {
                        rc.encode_bit(1, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]);
                        rc.encode_bit(1, &mut lz_rep_st[1], NUM_DELTA_REP_PROBS, &mut probs.lz_rep[1]);
                    }
                }
                queue_mtf(&mut lz_queue, adj);
            } else {
                // Explicit offset: symbol THEN extra bits
                rc.encode_bit(0, &mut lz_st, NUM_LZ_PROBS, &mut probs.lz);
                let off_slot = tables::find_offset_slot(match_offset);
                lz_offset_code.encode_symbol(off_slot, &mut bs);
                tables::encode_offset_extra(match_offset, off_slot, &mut bs);
                queue_push(&mut lz_queue, match_offset);
            }

            let len_slot = tables::find_length_slot(match_len);
            length_code.encode_symbol(len_slot, &mut bs);
            tables::encode_length_extra(match_len, len_slot, &mut bs);

            pos += match_len as usize;
            prev_type = 1;
        } else {
            // Encode literal
            if pos + 3 < d.len() {
                let h = hash4(d, pos) & ((1 << HASH_BITS) - 1);
                if chain[pos] == 0 && head[h] == 0 {
                    chain[pos] = head[h];
                    head[h] = pos as u32;
                }
            }
            rc.encode_bit(0, &mut main_st, NUM_MAIN_PROBS, &mut probs.main);
            literal_code.encode_symbol(d[pos] as usize, &mut bs);
            pos += 1;
            prev_type = 0;
        }
    }

    let mut out = Vec::new();
    rc.finish(&mut out);
    bs.finish(&mut out);

    if out.len() % 2 != 0 {
        out.push(0);
    }

    Ok(out)
}

fn hash4(data: &[u8], pos: usize) -> usize {
    let v = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    (v.wrapping_mul(0x1E35A7BD) >> 16) as usize
}

fn match_length(data: &[u8], src: usize, dst: usize, limit: usize) -> u32 {
    let max = (limit - dst).min(1046) as u32;
    let mut len = 0u32;
    while len < max && data[src + len as usize] == data[dst + len as usize] {
        len += 1;
    }
    len
}

// --- Range Encoder (forward stream, writes LE16 to front of buffer) ---

struct RangeEncoder {
    low: u64,
    range: u32,
    cache: u16,
    cache_count: u32,
    first: bool,
    output: Vec<u8>,
}

impl RangeEncoder {
    fn new() -> Self {
        RangeEncoder {
            low: 0, range: 0xFFFF_FFFF,
            cache: 0, cache_count: 0, first: true,
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
                    self.emit(fill.wrapping_add(overflow as u16));
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

    fn encode_bit(
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

    fn finish(&mut self, out: &mut Vec<u8>) {
        for _ in 0..4 {
            self.shift_low();
        }
        out.splice(0..0, self.output.drain(..));
    }
}

// --- Backward bitstream writer (writes LE16 to end of buffer, MSB-first) ---

struct BackBitsWriter {
    buf: u64,
    bits: u32,
    output: Vec<u8>,
}

impl BackBitsWriter {
    fn new() -> Self {
        BackBitsWriter { buf: 0, bits: 0, output: Vec::new() }
    }

    fn write_bits(&mut self, val: u32, n: u32) {
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

    fn finish(&self, out: &mut Vec<u8>) {
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

fn decode_rep(
    rc: &mut RangeDecoder,
    st: &mut [u32; 2],
    probs: &mut [Vec<ProbEntry>; 2],
) -> usize {
    let b0 = rc.decode_bit(&mut st[0], NUM_LZ_REP_PROBS, &mut probs[0]);
    if b0 == 0 { return 0; }
    let b1 = rc.decode_bit(&mut st[1], NUM_DELTA_REP_PROBS, &mut probs[1]);
    if b1 == 0 { 1 } else { 2 }
}

fn queue_push(q: &mut [u32; 4], val: u32) {
    q[3] = q[2]; q[2] = q[1]; q[1] = q[0]; q[0] = val;
}

fn queue_mtf(q: &mut [u32; 4], idx: usize) {
    let val = q[idx];
    for i in (1..=idx).rev() { q[i] = q[i - 1]; }
    q[0] = val;
}

fn queue_push_pair(q: &mut [(u32, u32); 4], val: (u32, u32)) {
    q[3] = q[2]; q[2] = q[1]; q[1] = q[0]; q[0] = val;
}

fn queue_mtf_pair(q: &mut [(u32, u32); 4], idx: usize) {
    let val = q[idx];
    for i in (1..=idx).rev() { q[i] = q[i - 1]; }
    q[0] = val;
}

// --- Range Decoder (forward stream, reads LE16 from front of buffer) ---

struct RangeDecoder<'a> {
    data: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(data: &'a [u8]) -> Self {
        let hi = le16(data, 0) as u32;
        let lo = le16(data, 2) as u32;
        RangeDecoder { data, pos: 4, range: 0xFFFF_FFFF, code: (hi << 16) | lo }
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
    fn decode_bit(
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

// --- Backward Bitstream (reads LE16 from back of buffer, MSB-first) ---

pub(crate) struct BackBits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    bits: u32,
}

impl<'a> BackBits<'a> {
    fn new(data: &'a [u8]) -> Self {
        BackBits { data, pos: data.len(), buf: 0, bits: 0 }
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
    fn peek(&self, n: u32) -> u32 {
        (self.buf >> (64 - n)) as u32
    }

    #[inline]
    fn consume(&mut self, n: u32) {
        self.buf <<= n;
        self.bits -= n;
    }

    #[inline]
    pub(crate) fn read_bits(&mut self, n: u32) -> u32 {
        if n == 0 { return 0; }
        self.ensure(n);
        let val = self.peek(n);
        self.consume(n);
        val
    }
}

// --- Adaptive Probability Entry (64-bit sliding window) ---

#[derive(Clone)]
struct ProbEntry {
    num_zeros: u32,
    recent: u64,
}

impl ProbEntry {
    fn new() -> Self {
        ProbEntry { num_zeros: INITIAL_PROB, recent: INITIAL_RECENT_BITS }
    }

    #[inline]
    fn get(&self) -> u32 {
        self.num_zeros.clamp(1, PROB_MAX)
    }

    #[inline]
    fn update(&mut self, bit: u32) {
        let oldest = (self.recent >> 63) as u32;
        self.recent = (self.recent << 1) | bit as u64;
        if oldest == 0 { self.num_zeros -= 1; }
        if bit == 0 { self.num_zeros += 1; }
    }
}

struct ProbTables {
    main: Vec<ProbEntry>,
    match_: Vec<ProbEntry>,
    lz: Vec<ProbEntry>,
    lz_rep: [Vec<ProbEntry>; 2],
    delta: Vec<ProbEntry>,
    delta_rep: [Vec<ProbEntry>; 2],
}

impl ProbTables {
    fn new() -> Self {
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

// --- Adaptive Huffman Code ---
//
// 10-bit direct lookup table with binary overflow tree for longer codes.
// Rebuilt periodically from accumulated symbol frequencies.
// After each rebuild, frequencies are halved: freq = (freq >> 1) + 1.

struct AdaptiveCode {
    rebuild_freq: u32,
    freqs: Vec<u32>,
    countdown: u32,
    direct: Vec<u16>,
    overflow: Vec<[u16; 2]>,
    codes: Vec<u32>,
    lens: Vec<u8>,
}

const ENTRY_OVERFLOW: u16 = 0x8000;

impl AdaptiveCode {
    fn new(num_syms: usize, rebuild_freq: u32) -> Self {
        let mut code = AdaptiveCode {
            rebuild_freq,
            freqs: vec![1; num_syms],
            countdown: rebuild_freq,
            direct: vec![0; TABLE_SIZE],
            overflow: Vec::new(),
            codes: vec![0; num_syms],
            lens: vec![0; num_syms],
        };
        if num_syms > 0 {
            code.rebuild();
        }
        code
    }

    fn rebuild(&mut self) {
        let lens = compute_code_lengths(&self.freqs);
        self.build_tables(&lens);
        self.build_codes(&lens);
    }

    fn build_codes(&mut self, lens: &[u8]) {
        let mut count = [0u32; MAX_CODEWORD_LEN as usize + 1];
        for &l in lens {
            if l > 0 { count[l as usize] += 1; }
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
            if len == 0 { continue; }
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
            if l > 0 { count[l as usize] += 1; }
        }

        let mut next_code = [0u32; MAX_CODEWORD_LEN as usize + 1];
        let mut code = 0u32;
        for bits in 1..=MAX_CODEWORD_LEN as usize {
            code = (code + count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        for (sym, &len) in lens.iter().enumerate() {
            if len == 0 { continue; }
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

    fn encode_symbol(&mut self, sym: usize, bs: &mut BackBitsWriter) {
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

    fn decode_symbol(&mut self, bs: &mut BackBits) -> Result<usize> {
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

fn compute_code_lengths(freqs: &[u32]) -> Vec<u8> {
    let n = freqs.len();
    let mut lens = vec![0u8; n];

    let mut active: Vec<(u32, u16)> = freqs
        .iter()
        .enumerate()
        .filter(|(_, &f)| f > 0)
        .map(|(i, &f)| (f, i as u16))
        .collect();

    match active.len() {
        0 => return lens,
        1 => {
            lens[active[0].1 as usize] = 1;
            return lens;
        }
        _ => {}
    }

    loop {
        active.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

        let num = active.len();
        let total = 2 * num - 1;
        let mut freq = vec![0u32; total];
        let mut children: Vec<[usize; 2]> = vec![[0; 2]; total];
        let mut is_leaf = vec![true; total];

        for (i, &(f, _)) in active.iter().enumerate() {
            freq[i] = f;
        }

        let mut q1 = 0usize;
        let mut q2: Vec<usize> = Vec::with_capacity(num);
        let mut q2_front = 0usize;
        let mut next = num;

        for _ in 0..num - 1 {
            let pick = |q1: &mut usize, q2: &[usize], q2f: &mut usize, freq: &[u32], nl: usize| -> usize {
                let q1_avail = *q1 < nl;
                let q2_avail = *q2f < q2.len();
                if !q2_avail || (q1_avail && freq[*q1] <= freq[q2[*q2f]]) {
                    let i = *q1; *q1 += 1; i
                } else {
                    let i = q2[*q2f]; *q2f += 1; i
                }
            };
            let left = pick(&mut q1, &q2, &mut q2_front, &freq, num);
            let right = pick(&mut q1, &q2, &mut q2_front, &freq, num);
            freq[next] = freq[left].saturating_add(freq[right]);
            children[next] = [left, right];
            is_leaf[next] = false;
            q2.push(next);
            next += 1;
        }

        let root = next - 1;
        let mut depth = vec![0u32; total];
        let mut stack = vec![(root, 0u32)];
        let mut max_depth = 0u32;
        while let Some((node, d)) = stack.pop() {
            depth[node] = d;
            if is_leaf[node] {
                max_depth = max_depth.max(d);
            } else {
                stack.push((children[node][0], d + 1));
                stack.push((children[node][1], d + 1));
            }
        }

        if max_depth <= MAX_CODEWORD_LEN {
            lens.fill(0);
            for i in 0..num {
                lens[active[i].1 as usize] = depth[i] as u8;
            }
            return lens;
        }

        for item in &mut active {
            item.0 = (item.0 + 1) >> 1;
        }
    }
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

        if !lzms_path.exists() { return; }

        let compressed = std::fs::read(&lzms_path).unwrap();
        let expected = std::fs::read(&raw_path).unwrap();

        match decompress_compression_api(&compressed) {
            Ok(output) => {
                assert_eq!(output.len(), expected.len(), "{name}: size mismatch");
                for (i, (&got, &want)) in output.iter().zip(expected.iter()).enumerate() {
                    if got != want {
                        panic!(
                            "{name}: first diff at byte {i}: got {got:#04x}, want {want:#04x}"
                        );
                    }
                }
            }
            Err(e) => panic!("{name}: decode failed: {e}"),
        }
    }

    #[test] fn zeros() { check("zeros"); }
    #[test] fn sequential() { check("sequential"); }
    #[test] fn pattern() { check("pattern"); }
    #[test] fn single_byte() { check("single_byte"); }
    #[test] fn english() { check("english"); }
    #[test] fn small() { check("small"); }
    #[test] fn random() { check("random"); }

    #[test]
    fn x86_filter_roundtrip() {
        let mut data = vec![0x90u8; 256];
        // Three E8 (call relative) instructions targeting the same address.
        // The first pair activates the heuristic (sets last_x86_pos).
        // The third instruction is then within max_trans_offset and gets translated.
        // target = position + 1 (opcode size) + relative_offset
        // All three target address 120: offsets are 109, 99, 89
        data[10] = 0xE8;
        data[11..15].copy_from_slice(&109u32.to_le_bytes());
        data[20] = 0xE8;
        data[21..25].copy_from_slice(&99u32.to_le_bytes());
        data[30] = 0xE8;
        data[31..35].copy_from_slice(&89u32.to_le_bytes());

        let original = data.clone();

        x86_filter_impl(&mut data, false);
        assert_ne!(data, original, "x86 filter should modify data with repeated call targets");

        x86_filter_impl(&mut data, true);
        assert_eq!(data, original, "x86 filter roundtrip failed");
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let original = b"Hello, this is a test of LZMS compression roundtrip!";
        let compressed = compress(original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_decompress_zeros() {
        let original = vec![0u8; 256];
        let compressed = compress(&original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_decompress_sequential() {
        let original: Vec<u8> = (0..=255).collect();
        let compressed = compress(&original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_decompress_large() {
        let original: Vec<u8> = (0..4096).map(|i| (i * 7 + 13) as u8).collect();
        let compressed = compress(&original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compression_api_roundtrip() {
        let original = b"Compression API wrapper roundtrip test data with some repetition repetition";
        let wrapped = compress_compression_api(original).unwrap();
        assert!(wrapped.len() >= COMPRESSION_API_HEADER_SIZE + 4);
        let magic = u32::from_le_bytes(wrapped[0..4].try_into().unwrap());
        assert_eq!(magic, COMPRESSION_API_MAGIC);
        let recovered = decompress_compression_api(&wrapped).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn compression_api_roundtrip_large() {
        let original: Vec<u8> = (0..8192).map(|i| (i * 3 + 7) as u8).collect();
        let wrapped = compress_compression_api(&original).unwrap();
        let recovered = decompress_compression_api(&wrapped).unwrap();
        assert_eq!(recovered, original);
    }
}
