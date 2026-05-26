//! Left-leaning canonical Huffman decoder for PseudoLzx.
//!
//! The Huffman codes are bit-reversed (LSB-first) to match the bitstream's
//! LSB-first ordering. The decoder uses a CTZ-based lookup: the position of
//! the lowest set bit in the bit-reversed code determines the code length,
//! and the bits above it index into a per-length symbol table.
//!
//! PDB-confirmed: `statichuffman::Codes`, `statichuffman::DecoderTable`.

use crate::bitstream::{BitReader, BitWriter};
use crate::{Error, Result};

const MAX_CODE_LEN: u8 = 16;

/// Slot in the CTZ-indexed lookup table.
#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    mask: u32,
    offset: u32,
}

/// CTZ-based Huffman decoder matching the msdelta.dll implementation.
#[derive(Debug)]
pub struct HuffmanTable {
    slots: [Slot; 32],
    symbols: Vec<u16>,
    /// Code lengths per symbol (index = symbol, value = bit length).
    pub lengths: Vec<u8>,
    /// Bit-reversed canonical codes per symbol (for encoding).
    codes: Vec<u32>,
}

impl HuffmanTable {
    pub fn from_lengths(code_lengths: &[u8]) -> Result<Self> {
        let num_symbols = code_lengths.len();
        if num_symbols == 0 {
            return Ok(HuffmanTable {
                slots: [Slot::default(); 32],
                symbols: Vec::new(),
                lengths: Vec::new(),
                codes: Vec::new(),
            });
        }

        let max_len = *code_lengths.iter().max().unwrap_or(&0);
        if max_len > MAX_CODE_LEN {
            return Err(Error::Malformed("huffman code length exceeds maximum"));
        }
        if max_len == 0 {
            return Ok(HuffmanTable {
                slots: [Slot::default(); 32],
                symbols: Vec::new(),
                lengths: code_lengths.to_vec(),
                codes: vec![0; num_symbols],
            });
        }

        // Step 1: Count symbols per length
        let mut count = vec![0u32; max_len as usize + 1];
        for &l in code_lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;

        // Step 2: compute base codes per length (from high to low).
        // Matches decompiled CalculateCodes exactly.
        let mut base_code = vec![0u32; max_len as usize + 1];
        {
            let mut acc = 0u32;
            for len in (1..=max_len as usize).rev() {
                base_code[len] = acc;
                acc = (acc + count[len]) >> 1;
            }
        }

        // Step 3: Assign bit-reversed codes to each symbol
        let mut codes = vec![0u32; num_symbols];
        let mut assigned_code = base_code.clone();
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let canonical = assigned_code[len as usize];
            assigned_code[len as usize] += 1;

            // Bit-reverse the canonical code
            let mut reversed = 0u32;
            let mut c = canonical;
            for _ in 0..len {
                reversed = (reversed << 1) | (c & 1);
                c >>= 1;
            }
            codes[sym] = reversed;
        }

        // Step 4: Build the CTZ-indexed decoder table
        // For each bit position (CTZ value), track the maximum
        // number of extra bits needed above that position.
        let mut max_extra = [0u32; 32];
        let mut max_slot_used: usize = 0;

        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 || codes[sym] == 0 {
                continue;
            }
            let code = codes[sym];
            let ctz = code.trailing_zeros() as usize;
            let extra = (len as u32) - (ctz as u32) - 1;
            if ctz < 32 {
                if extra > max_extra[ctz] {
                    max_extra[ctz] = extra;
                }
                if ctz > max_slot_used {
                    max_slot_used = ctz;
                }
            }
        }

        // Compute table sizes and offsets
        let mut slots = [Slot::default(); 32];
        let mut total_entries = 0u32;
        for i in 0..=max_slot_used {
            let mask = if max_extra[i] == 0 {
                0
            } else {
                (1u32 << max_extra[i]) - 1
            };
            slots[i] = Slot {
                mask,
                offset: total_entries,
            };
            total_entries += mask + 1;
        }
        // Fill remaining slots
        for slot in &mut slots[(max_slot_used + 1)..] {
            *slot = Slot {
                mask: 0,
                offset: total_entries,
            };
        }

        // Allocate symbol array and fill
        let mut symbols = vec![0u16; (total_entries + 1) as usize];

        for (sym, &len) in code_lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = codes[sym];
            if code == 0 && len > 0 {
                continue;
            }
            let ctz = code.trailing_zeros();
            let shifted = code >> (ctz + 1);
            let slot = &slots[ctz as usize];
            let _idx = (shifted & slot.mask) + slot.offset;
            let extra = (len as u32) - ctz - 1;
            let fill_count = 1u32 << (max_extra[ctz as usize] - extra);
            let base = (shifted & slot.mask) + slot.offset;
            let stride = 1u32 << extra;
            for f in 0..fill_count {
                symbols[(base + f * stride) as usize] = sym as u16;
            }
        }

        // Handle code=0 symbol (the single symbol with the lowest canonical value)
        for (sym, &len) in code_lengths.iter().enumerate() {
            if len > 0 && codes[sym] == 0 {
                symbols[total_entries as usize] = sym as u16;
                break;
            }
        }

        Ok(HuffmanTable {
            slots,
            symbols,
            codes,
            lengths: code_lengths.to_vec(),
        })
    }

    /// Build a Huffman table from symbol frequencies with length limit.
    ///
    /// Uses a simple approach: standard Huffman tree construction, then cap
    /// any code lengths that exceed `max_len` by redistributing.
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

        // Build Huffman tree using a priority queue (min-heap by frequency)
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

        // Compute depths via DFS from root (use u32 to avoid overflow for deep trees)
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

        // Cap lengths at max_len
        for d in &mut depths {
            if *d > max_len {
                *d = max_len;
            }
        }

        // Kraft inequality fix: ensure the code lengths form a valid prefix code.
        // If capping created an invalid tree, shorten some codes.
        loop {
            let kraft: u64 = depths
                .iter()
                .filter(|&&d| d > 0)
                .map(|&d| 1u64 << (max_len - d))
                .sum();
            let target = 1u64 << max_len;
            if kraft <= target {
                break;
            }
            // Find the longest code and shorten it by 1
            if let Some(longest) = depths.iter_mut().filter(|d| **d > 0).max() {
                if *longest > 1 {
                    *longest -= 1;
                }
            } else {
                break;
            }
        }

        // If Kraft sum is less than target, lengthen shortest codes
        loop {
            let kraft: u64 = depths
                .iter()
                .filter(|&&d| d > 0)
                .map(|&d| 1u64 << (max_len - d))
                .sum();
            let target = 1u64 << max_len;
            if kraft >= target {
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

    /// Encode one symbol to the bitstream.
    ///
    /// Writes the bit-reversed canonical code for the given symbol.
    pub fn write_symbol(&self, writer: &mut BitWriter, sym: u16) {
        let len = self.lengths[sym as usize];
        debug_assert!(len > 0, "cannot write symbol with zero length");
        let code = self.codes[sym as usize];
        writer.write_bits(code as u64, len as u32);
    }

    /// Compare fast CTZ decode with brute-force to detect table errors.
    #[cfg(test)]
    pub fn validate_decode(&self, reader: &mut BitReader) -> Result<(u16, Option<u16>)> {
        let avail = reader.remaining().min(32);
        reader.ensure_bits(avail)?;

        // Save state, do CTZ decode
        let saved_accum = reader.peek(avail);

        // CTZ decode
        let accum32 = saved_accum as u32;
        let ws = accum32 | 0x8000_0000;
        let ctz = ws.trailing_zeros();
        let slot = &self.slots[ctz as usize];
        let shifted = if ctz >= 31 { 0 } else { ws >> (ctz + 1) };
        let idx = ((shifted & slot.mask) + slot.offset) as usize;
        let ctz_sym = if idx < self.symbols.len() {
            self.symbols[idx]
        } else {
            0xFFFF
        };

        // Brute-force
        let codes = calculate_codes_from_lengths(&self.lengths);
        let mut bf_sym = None;
        for (sym, &len) in self.lengths.iter().enumerate() {
            if len == 0 { continue; }
            let code = codes[sym];
            let mask = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
            if (saved_accum & mask) == code as u64 {
                bf_sym = Some(sym as u16);
                break;
            }
        }

        // Consume via CTZ result
        if self.lengths[ctz_sym as usize] > 0 {
            reader.consume_bits(self.lengths[ctz_sym as usize] as u32)?;
        } else {
            reader.consume_bits(1)?;
        }

        Ok((ctz_sym, bf_sym))
    }

    /// Brute-force decode: check each symbol's code against accumulator.
    /// Used for validation only.
    #[cfg(test)]
    pub fn read_symbol_bruteforce(&self, reader: &mut BitReader) -> Result<u16> {
        let avail = reader.remaining().min(32);
        if avail == 0 {
            return Err(Error::Malformed("no bits"));
        }
        reader.ensure_bits(avail)?;
        let accum = reader.peek(avail);

        let codes = calculate_codes_from_lengths(&self.lengths);

        for (sym, &len) in self.lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let code = codes[sym];
            let mask = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
            if (accum & mask) == code as u64 {
                reader.consume_bits(len as u32)?;
                return Ok(sym as u16);
            }
        }
        Err(Error::Malformed("no huffman code matched"))
    }

    /// Decode one symbol from the bitstream.
    /// Decode one symbol. Caller should have called `reader.refill()` recently.
    #[inline]
    pub fn read_symbol(&self, reader: &mut BitReader) -> Result<u16> {
        if self.symbols.is_empty() {
            return Err(Error::Malformed("empty huffman table"));
        }

        // Ensure we have enough bits for the longest possible code (16 bits).
        // After a refill() we typically have 56+ bits, so this is usually a no-op.
        // Ensure at least 16 bits (max Huffman code length) or whatever is left.
        reader.ensure_bits(16.min(reader.remaining()))?;
        let accum = reader.peek(reader.buffered().min(32)) as u32;

        let with_sentinel = accum | 0x8000_0000;
        let ctz = with_sentinel.trailing_zeros();

        let slot = &self.slots[ctz as usize];
        let shifted = if ctz >= 31 { 0 } else { with_sentinel >> (ctz + 1) };
        let idx = ((shifted & slot.mask) + slot.offset) as usize;

        if idx >= self.symbols.len() {
            return Err(Error::Malformed("huffman table index out of bounds"));
        }

        let sym = self.symbols[idx];
        let len = self.lengths[sym as usize];
        if len == 0 {
            return Err(Error::Malformed("decoded symbol has zero length"));
        }

        reader.consume_unchecked(len as u32);
        Ok(sym)
    }
}

#[cfg(test)]
fn calculate_codes_from_lengths(lengths: &[u8]) -> Vec<u32> {
    let n = lengths.len();
    let max_len = *lengths.iter().max().unwrap_or(&0);
    if max_len == 0 {
        return vec![0; n];
    }
    let mut count = vec![0u32; max_len as usize + 1];
    for &l in lengths {
        count[l as usize] += 1;
    }
    let mut base_code = vec![0u32; max_len as usize + 1];
    let mut acc = 0u32;
    for length in (1..=max_len as usize).rev() {
        base_code[length] = acc;
        acc = (acc + count[length]) >> 1;
    }
    let mut codes = vec![0u32; n];
    let mut assigned = base_code;
    for (sym, &len) in lengths.iter().enumerate() {
        if len == 0 {
            continue;
        }
        let canonical = assigned[len as usize];
        assigned[len as usize] += 1;
        let mut rev = 0u32;
        let mut c = canonical;
        for _ in 0..len {
            rev = (rev << 1) | (c & 1);
            c >>= 1;
        }
        codes[sym] = rev;
    }
    codes
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
        for _ in 0..short_count {
            lengths.push(bits_needed - 1);
        }
        for _ in short_count..count {
            lengths.push(bits_needed);
        }
        lengths
    }

    #[test]
    fn build_flat_600() {
        let lengths = flat_code_lengths(600);
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        assert!(!table.symbols.is_empty());
    }

    #[test]
    fn build_flat_256() {
        let lengths = flat_code_lengths(256);
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        assert!(!table.symbols.is_empty());
    }

    #[test]
    fn build_flat_16() {
        let lengths = flat_code_lengths(16);
        let table = HuffmanTable::from_lengths(&lengths).unwrap();
        assert!(!table.symbols.is_empty());
    }

    #[test]
    fn decode_uniform_256() {
        let lengths = vec![8u8; 256];
        let table = HuffmanTable::from_lengths(&lengths).unwrap();

        // 4 bytes: padding=0 (3 bits), then at least 8 bits for a symbol
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
        // Most frequent symbol should have shortest code
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
