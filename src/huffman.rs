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
            let mut lengths = vec![0u8; n];
            lengths[active[0]] = 1;
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

        // Compute depths (u32 to avoid overflow for deep trees)
        let mut node_depth = vec![0u32; nodes.len()];
        let root = heap.pop().unwrap().0 .1;
        let mut stack = vec![(root, 0u32)];
        let mut depths = vec![0u8; n];
        while let Some((node, depth)) = stack.pop() {
            node_depth[node] = depth;
            let (_, left, right) = nodes[node];
            if let (Some(l), Some(r)) = (left, right) {
                stack.push((l, depth + 1));
                stack.push((r, depth + 1));
            }
        }
        for (i, &sym) in active.iter().enumerate() {
            depths[sym] = node_depth[i].min(max_len as u32) as u8;
        }

        // Cap and fix Kraft inequality
        loop {
            let kraft: u64 = depths
                .iter()
                .filter(|&&d| d > 0)
                .map(|&d| 1u64 << (max_len - d))
                .sum();
            if kraft <= 1u64 << max_len {
                break;
            }
            if let Some(longest) = depths.iter_mut().filter(|d| **d > 0).max() {
                if *longest > 1 {
                    *longest -= 1;
                }
            } else {
                break;
            }
        }
        loop {
            let kraft: u64 = depths
                .iter()
                .filter(|&&d| d > 0)
                .map(|&d| 1u64 << (max_len - d))
                .sum();
            if kraft >= 1u64 << max_len {
                break;
            }
            if let Some(shortest) = depths.iter_mut().filter(|d| **d > 0).min() {
                if *shortest < max_len {
                    *shortest += 1;
                } else {
                    break;
                }
            } else {
                break;
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
        assert_eq!(table.lengths[2], 1);
        assert_eq!(table.lengths[0], 0);
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
