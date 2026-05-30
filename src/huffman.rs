//! Left-leaning canonical Huffman decoder/encoder for PseudoLzx.
//!
//! Decode-side: CTZ-based table lookup. One cache line per symbol decode.
//! Encode-side: precomputed bit-reversed canonical codes.

use crate::bitstream::{BitReader, BitWriter};
use crate::{Error, Result};

const MAX_CODE_LEN: u8 = 16;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    mask: u32,
    offset: u32,
}

/// Packed decode entry: symbol ID + code length in one u32.
/// Avoids a serial dependency chain in the hot decode path.
#[derive(Debug, Clone, Copy, Default)]
struct DecodeEntry {
    symbol: u16,
    len: u8,
}

/// Huffman table for both decoding and encoding.
///
/// Decode hot path touches only `slots` (inline, 256 bytes) and `entries`
/// (one heap vec, ~2-8 KB). Encode touches `codes` + `lengths`.
#[derive(Debug)]
pub struct HuffmanTable {
    slots: [Slot; 32],
    entries: Vec<DecodeEntry>,
    /// Code lengths per symbol. Public for CompositeFormat serialization.
    pub lengths: Vec<u8>,
    /// Bit-reversed canonical codes per symbol (encode only).
    codes: Vec<u32>,
}

impl HuffmanTable {
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self> {
        let num_symbols = code_lengths.len();
        if num_symbols == 0 {
            return Ok(Self::empty());
        }

        let max_len = *code_lengths.iter().max().unwrap_or(&0);
        if max_len > MAX_CODE_LEN {
            return Err(Error::Malformed("huffman code length exceeds maximum"));
        }
        if max_len == 0 {
            return Ok(HuffmanTable {
                slots: [Slot::default(); 32],
                entries: Vec::new(),
                lengths: code_lengths.to_vec(),
                codes: vec![0; num_symbols],
            });
        }

        // Count symbols per length
        let mut count = vec![0u32; max_len as usize + 1];
        for &l in code_lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;

        // Compute base codes (from high to low, matching msdelta CalculateCodes)
        let mut base_code = vec![0u32; max_len as usize + 1];
        let mut acc = 0u32;
        for len in (1..=max_len as usize).rev() {
            base_code[len] = acc;
            acc = (acc + count[len]) >> 1;
        }

        // Assign bit-reversed codes
        let mut codes = vec![0u32; num_symbols];
        let mut assigned = base_code;
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let canonical = assigned[len as usize];
            assigned[len as usize] += 1;
            let mut reversed = 0u32;
            let mut c = canonical;
            for _ in 0..len {
                reversed = (reversed << 1) | (c & 1);
                c >>= 1;
            }
            codes[sym] = reversed;
        }

        // Build CTZ-indexed decode table
        let mut max_extra = [0u32; 32];
        let mut max_slot_used: usize = 0;

        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 || codes[sym] == 0 {
                continue;
            }
            let ctz = codes[sym].trailing_zeros() as usize;
            let extra = len as u32 - ctz as u32 - 1;
            if extra > max_extra[ctz] {
                max_extra[ctz] = extra;
            }
            if ctz > max_slot_used {
                max_slot_used = ctz;
            }
        }

        let mut slots = [Slot::default(); 32];
        let mut total_entries = 0u32;
        for (i, slot) in slots[..=max_slot_used].iter_mut().enumerate() {
            let mask = if max_extra[i] == 0 {
                0
            } else {
                (1u32 << max_extra[i]) - 1
            };
            *slot = Slot {
                mask,
                offset: total_entries,
            };
            total_entries += mask + 1;
        }
        for slot in &mut slots[(max_slot_used + 1)..] {
            *slot = Slot {
                mask: 0,
                offset: total_entries,
            };
        }

        // Fill decode entries (merged symbol + length)
        let mut entries = vec![DecodeEntry::default(); (total_entries + 1) as usize];

        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 || codes[sym] == 0 {
                continue;
            }
            let code = codes[sym];
            let ctz = code.trailing_zeros();
            let extra = len as u32 - ctz - 1;
            let shifted = code >> (ctz + 1);
            let slot = &slots[ctz as usize];
            let base = (shifted & slot.mask) + slot.offset;
            let fill = 1u32 << (max_extra[ctz as usize] - extra);
            let stride = 1u32 << extra;
            for f in 0..fill {
                entries[(base + f * stride) as usize] = DecodeEntry {
                    symbol: sym as u16,
                    len,
                };
            }
        }

        // Handle code=0 symbol
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len > 0 && codes[sym] == 0 {
                entries[total_entries as usize] = DecodeEntry {
                    symbol: sym as u16,
                    len,
                };
                break;
            }
        }

        Ok(HuffmanTable {
            slots,
            entries,
            codes,
            lengths: code_lengths.to_vec(),
        })
    }

    fn empty() -> Self {
        HuffmanTable {
            slots: [Slot::default(); 32],
            entries: Vec::new(),
            lengths: Vec::new(),
            codes: Vec::new(),
        }
    }

    /// Build from symbol frequencies with length limit.
    pub fn from_frequencies(freqs: &[u32], max_len: u8) -> Result<Self> {
        let n = freqs.len();
        if n == 0 {
            return Self::from_lengths(&[]);
        }

        let active: Vec<usize> = (0..n).filter(|&i| freqs[i] > 0).collect();
        if active.is_empty() {
            return Self::from_lengths(&vec![0u8; n]);
        }
        if active.len() == 1 {
            // A lone length-1 code is INCOMPLETE (Kraft sum = 2^(max-1)); msdelta
            // rejects incomplete trees. Add a phantom length-1 leaf on another
            // symbol so the canonical code is complete. The phantom never
            // appears in the symbol stream (its frequency is 0).
            let mut lengths = vec![0u8; n];
            lengths[active[0]] = 1;
            if let Some(phantom) = (0..n).find(|&i| i != active[0]) {
                lengths[phantom] = 1;
            }
            return Self::from_lengths(&lengths);
        }

        // Build Huffman tree
        let mut nodes: Vec<(u64, Option<usize>, Option<usize>)> = Vec::new();
        let mut heap: std::collections::BinaryHeap<std::cmp::Reverse<(u64, usize)>> =
            std::collections::BinaryHeap::new();

        for &sym in &active {
            let idx = nodes.len();
            nodes.push((freqs[sym] as u64, None, None));
            heap.push(std::cmp::Reverse((freqs[sym] as u64, idx)));
        }

        while heap.len() > 1 {
            let std::cmp::Reverse((f1, i1)) = heap.pop().unwrap();
            let std::cmp::Reverse((f2, i2)) = heap.pop().unwrap();
            let idx = nodes.len();
            nodes.push((f1 + f2, Some(i1), Some(i2)));
            heap.push(std::cmp::Reverse((f1 + f2, idx)));
        }

        // Raw (uncapped) depth per tree node. Active symbols are the first
        // `active.len()` nodes, so node_depth[i] is active[i]'s depth.
        let mut node_depth = vec![0u32; nodes.len()];
        let root = heap.pop().unwrap().0 .1;
        let mut stack = vec![(root, 0u32)];
        while let Some((node, depth)) = stack.pop() {
            node_depth[node] = depth;
            let (_, left, right) = nodes[node];
            if let (Some(l), Some(r)) = (left, right) {
                stack.push((l, depth + 1));
                stack.push((r, depth + 1));
            }
        }

        // Length-limit to `max_len` while keeping the code COMPLETE. A naive
        // per-symbol `min(depth, max_len)` cap leaves an over- or
        // under-subscribed tree, which our decoder tolerates but msdelta rejects
        // with ERROR_INVALID_DATA. We work on the count-per-length (`bl_count`)
        // and repair the Kraft sum to exactly 2^max_len by moving leaves between
        // adjacent lengths (each move preserves the total leaf count, so the
        // assignment below still consumes exactly active.len() symbols).
        let ml = max_len as usize;
        let mut bl_count = vec![0u32; ml + 1];
        for i in 0..active.len() {
            bl_count[node_depth[i].min(max_len as u32) as usize] += 1;
        }

        let target = 1i64 << ml;
        let scaled = |bl: &[u32]| -> i64 { (1..=ml).map(|l| (bl[l] as i64) << (ml - l)).sum() };

        // Over-subscribed (Kraft > target): lengthen a code (move leaf L -> L+1,
        // which reduces Kraft by 2^(ml-L-1)). Prefer the largest reduction that
        // does not undershoot; otherwise make progress with the smallest step.
        for _ in 0..1_000_000 {
            let k = scaled(&bl_count);
            if k <= target {
                break;
            }
            let excess = k - target;
            let l = (1..ml)
                .find(|&l| bl_count[l] > 0 && (1i64 << (ml - l - 1)) <= excess)
                .or_else(|| (1..ml).rev().find(|&l| bl_count[l] > 0));
            match l {
                Some(l) => {
                    bl_count[l] -= 1;
                    bl_count[l + 1] += 1;
                }
                None => break,
            }
        }
        // Under-subscribed (Kraft < target): shorten a code (move leaf L -> L-1,
        // raising Kraft by 2^(ml-L)). Powers of two => this converges exactly.
        for _ in 0..1_000_000 {
            let k = scaled(&bl_count);
            if k >= target {
                break;
            }
            let deficit = target - k;
            let l = (2..=ml)
                .rev()
                .find(|&l| bl_count[l] > 0 && (1i64 << (ml - l)) <= deficit)
                .or_else(|| (2..=ml).find(|&l| bl_count[l] > 0));
            match l {
                Some(l) => {
                    bl_count[l] -= 1;
                    bl_count[l - 1] += 1;
                }
                None => break,
            }
        }

        // Assign the resulting length distribution to symbols, shortest codes to
        // the most frequent (canonical + optimal); stable tie-break by index.
        let mut order = active.clone();
        order.sort_by(|&a, &b| freqs[b].cmp(&freqs[a]).then(a.cmp(&b)));
        let mut depths = vec![0u8; n];
        let mut next = order.into_iter();
        for (len, &cnt) in bl_count.iter().enumerate().skip(1) {
            for _ in 0..cnt {
                if let Some(sym) = next.next() {
                    depths[sym] = len as u8;
                }
            }
        }

        Self::from_lengths(&depths)
    }

    /// Decode one symbol. Hot path: one table lookup, one consume.
    ///
    /// Caller should `refill()` before calling. After refill, the accumulator
    /// has 56+ bits — enough for any Huffman code (max 16 bits).
    #[inline]
    pub fn read_symbol(&self, reader: &mut BitReader) -> Result<u16> {
        if self.entries.is_empty() {
            return Err(Error::Malformed("empty huffman table"));
        }

        reader.ensure_bits(16.min(reader.remaining()))?;
        let accum = reader.peek(reader.buffered().min(32)) as u32;

        let with_sentinel = accum | 0x8000_0000;
        let ctz = with_sentinel.trailing_zeros();

        let slot = &self.slots[ctz as usize];
        let shifted = if ctz >= 31 {
            0
        } else {
            with_sentinel >> (ctz + 1)
        };
        let idx = ((shifted & slot.mask) + slot.offset) as usize;

        if idx >= self.entries.len() {
            return Err(Error::Malformed("huffman table index out of bounds"));
        }

        let entry = self.entries[idx];
        if entry.len == 0 {
            return Err(Error::Malformed("decoded symbol has zero length"));
        }

        // One load for both symbol and length — no serial dependency
        reader.consume_unchecked(entry.len as u32);
        Ok(entry.symbol)
    }

    /// Encode one symbol.
    #[inline]
    pub fn write_symbol(&self, writer: &mut BitWriter, sym: u16) {
        let len = self.lengths[sym as usize];
        debug_assert!(len > 0, "cannot write symbol with zero length");
        let code = self.codes[sym as usize];
        writer.write_bits(code as u64, len as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat_code_lengths(count: usize) -> Vec<u8> {
        if count == 0 {
            return Vec::new();
        }
        if count <= 2 {
            return vec![1; count];
        }
        let bits_needed = (count - 1).ilog2() as u8 + 1;
        let full_count = 1usize << bits_needed;
        let short_count = full_count - count;
        let mut lengths = Vec::with_capacity(count);
        lengths.extend(std::iter::repeat_n(bits_needed - 1, short_count));
        lengths.extend(std::iter::repeat_n(bits_needed, count - short_count));
        lengths
    }

    #[test]
    fn build_flat_600() {
        let lengths = flat_code_lengths(600);
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        assert!(!table.entries.is_empty());
    }

    #[test]
    fn build_flat_256() {
        let lengths = flat_code_lengths(256);
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        assert!(!table.entries.is_empty());
    }

    #[test]
    fn build_flat_16() {
        let lengths = flat_code_lengths(16);
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        assert!(!table.entries.is_empty());
    }

    #[test]
    fn decode_uniform_256() {
        let lengths = vec![8u8; 256];
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        let data = [0x00, 0x00, 0x00, 0x00];
        let mut reader = BitReader::new(&data).unwrap();
        let sym = table.read_symbol(&mut reader).unwrap();
        assert_eq!(lengths[sym as usize], 8);
    }

    /// Kraft sum scaled to 2^max_len. A complete canonical code has
    /// `kraft == 1 << max_len`; an all-zero (empty) table has 0.
    fn kraft(lengths: &[u8], max_len: u8) -> u64 {
        lengths
            .iter()
            .filter(|&&d| d > 0)
            .map(|&d| 1u64 << (max_len - d))
            .sum()
    }

    #[test]
    fn from_frequencies_always_complete() {
        let max_len = 15u8;
        let target = 1u64 << max_len;

        // A battery of adversarial frequency patterns. Every one must yield a
        // COMPLETE canonical code (msdelta rejects incomplete trees), or an
        // all-zero table when there are no active symbols.
        let mut cases: Vec<(&str, Vec<u32>)> = vec![
            ("single_at_0", {
                let mut v = vec![0u32; 8];
                v[0] = 5;
                v
            }),
            ("single_at_5", {
                let mut v = vec![0u32; 8];
                v[5] = 5;
                v
            }),
            ("two", vec![3, 7, 0, 0]),
            ("flat8", vec![1; 8]),
            ("flat7", vec![1; 7]),
            ("flat600", vec![1; 600]),
        ];
        // Skewed distribution over 600 symbols that forces depths past the
        // 15-bit cap (Fibonacci-like frequencies => deep Huffman tree).
        let mut fib = vec![0u32; 600];
        let (mut a, mut b) = (1u32, 1u32);
        for f in fib.iter_mut() {
            *f = a;
            let n = a.saturating_add(b);
            a = b;
            b = n;
        }
        cases.push(("fib600_capped", fib));

        for (name, freqs) in cases {
            let t = HuffmanTable::from_frequencies(&freqs, max_len).unwrap();
            let k = kraft(&t.lengths, max_len);
            let active = freqs.iter().filter(|&&f| f > 0).count();
            if active == 0 {
                assert_eq!(k, 0, "{name}: expected empty table");
            } else {
                assert_eq!(
                    k, target,
                    "{name}: incomplete/over canonical code (kraft={k}, want {target})"
                );
            }
        }
    }

    #[test]
    fn from_frequencies_basic() {
        let freqs = [10u32, 5, 3, 1];
        let table = HuffmanTable::from_frequencies(&freqs, 15).unwrap();
        assert_eq!(table.lengths.len(), 4);
        assert!(table.lengths.iter().all(|&l| l > 0 && l <= 15));
        assert!(table.lengths[0] <= table.lengths[3]);
    }

    #[test]
    fn from_frequencies_single() {
        let freqs = [0u32, 0, 5, 0];
        let table = HuffmanTable::from_frequencies(&freqs, 15).unwrap();
        // The active symbol gets a length-1 code, plus one phantom length-1 leaf
        // so the canonical code is COMPLETE (msdelta rejects incomplete trees).
        assert_eq!(table.lengths[2], 1);
        assert_eq!(table.lengths.iter().filter(|&&l| l == 1).count(), 2);
        assert_eq!(kraft(&table.lengths, 15), 1 << 15);
    }

    #[test]
    fn huffman_write_read_roundtrip() {
        let freqs = [100u32, 50, 25, 10, 5, 2, 1, 1];
        let table = HuffmanTable::from_frequencies(&freqs, 15).unwrap();

        let mut writer = BitWriter::new();
        for sym in 0..8u16 {
            if table.lengths[sym as usize] > 0 {
                table.write_symbol(&mut writer, sym);
            }
        }
        let data = writer.finish();

        let mut reader = BitReader::new(&data).unwrap();
        for sym in 0..8u16 {
            if table.lengths[sym as usize] > 0 {
                let decoded = table.read_symbol(&mut reader).unwrap();
                assert_eq!(decoded, sym, "round-trip failed for symbol {sym}");
            }
        }
    }

    #[test]
    fn huffman_write_read_256_symbols() {
        let freqs: Vec<u32> = (0..256).map(|i| (256 - i) as u32).collect();
        let table = HuffmanTable::from_frequencies(&freqs, 15).unwrap();

        let mut writer = BitWriter::new();
        let test_symbols: Vec<u16> = (0..256).map(|x| x as u16).collect();
        for &sym in &test_symbols {
            table.write_symbol(&mut writer, sym);
        }
        let data = writer.finish();

        let mut reader = BitReader::new(&data).unwrap();
        for &expected in &test_symbols {
            let got = table.read_symbol(&mut reader).unwrap();
            assert_eq!(got, expected);
        }
    }
}
