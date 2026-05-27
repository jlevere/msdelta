//! Compression internals for the PseudoLzx codec.

use crate::bitstream::BitWriter;
use crate::huffman::HuffmanTable;
use crate::{Error, Result};

use super::format::{
    SegmentTables,
    MAIN_SYMBOLS, LENGTH_SYMBOLS, ALIGNED_SYMBOLS, PRETREE_SYMBOLS, TOTAL_LENGTHS,
};
use super::ops::{RAW_OFFSET_BASE, OFFSET_BIAS};
use super::format::{SOURCE_COPY, LRU_BASE};

/// Core compression implementation. Produces a bitstream that `decompress`
/// (and msdelta.dll) can decode.
pub(super) fn compress_inner(reference: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    let ref_len = reference.len();

    // Two-pass: first find all symbols and collect frequencies, then
    // build optimal Huffman tables and encode.

    // Build a combined buffer for match finding: [reference | target]
    let mut combined = Vec::with_capacity(ref_len + target.len());
    combined.extend_from_slice(reference);
    combined.extend_from_slice(target);

    // Hash table for match finding (hash of 3-byte sequences -> position)
    let hash_bits = 16;
    let hash_size = 1usize << hash_bits;
    let hash_mask = hash_size - 1;
    let mut hash_table = vec![u32::MAX; hash_size];
    let mut hash_chain = vec![u32::MAX; combined.len()];

    fn hash3(data: &[u8], pos: usize) -> usize {
        if pos + 2 >= data.len() {
            return 0;
        }
        let h = (data[pos] as usize) | ((data[pos + 1] as usize) << 8) | ((data[pos + 2] as usize) << 16);
        (h.wrapping_mul(0x9E3779B1)) >> 16
    }

    // Index the reference into the hash chain
    for (i, chain_entry) in hash_chain[..ref_len.saturating_sub(2)].iter_mut().enumerate() {
        let h = hash3(&combined, i) & hash_mask;
        *chain_entry = hash_table[h];
        hash_table[h] = i as u32;
    }

    // Collect symbols (literals and matches)
    struct MatchSymbol {
        raw_offset: u32,
        length: u32,
    }

    let mut symbols: Vec<MatchSymbol> = Vec::new();
    let mut lru: [i64; 3] = [0; 3];
    let mut i = 0;

    while i < target.len() {
        let combined_pos = ref_len + i;

        // Try to find a match
        let mut best_len = 0u32;
        let mut best_offset: u32 = 0;

        if i + 2 < target.len() {
            let h = hash3(&combined, combined_pos) & hash_mask;
            let mut chain_pos = hash_table[h];
            let mut chain_depth = 0;

            while chain_pos != u32::MAX && chain_depth < 128 {
                let cp = chain_pos as usize;
                let mut match_len = 0u32;
                while i + (match_len as usize) < target.len()
                    && cp + (match_len as usize) < combined.len()
                    && combined[cp + (match_len as usize)] == combined[combined_pos + (match_len as usize)]
                {
                    match_len += 1;
                    if match_len >= 1024 {
                        break;
                    }
                }

                if match_len >= 3 && match_len > best_len {
                    let distance = (combined_pos - cp) as i64;
                    best_len = match_len;

                    // Encode offset
                    if cp < ref_len && distance == ref_len as i64 {
                        best_offset = SOURCE_COPY;
                    } else if lru[0] == distance {
                        best_offset = LRU_BASE;
                    } else if lru[1] == distance {
                        best_offset = LRU_BASE + 1;
                    } else if lru[2] == distance {
                        best_offset = LRU_BASE + 2;
                    } else {
                        best_offset = distance as u32 + RAW_OFFSET_BASE;
                    }
                }

                chain_pos = hash_chain[cp];
                chain_depth += 1;
            }

            // Update hash
            hash_chain[combined_pos] = hash_table[h];
            hash_table[h] = combined_pos as u32;
        }

        if best_len >= 2 && match_fits_table(best_offset) {
            symbols.push(MatchSymbol {
                raw_offset: best_offset,
                length: best_len,
            });

            // Update LRU
            let distance = if best_offset == SOURCE_COPY {
                ref_len as i64
            } else if (LRU_BASE..LRU_BASE + 3).contains(&best_offset) {
                lru[(best_offset - LRU_BASE) as usize]
            } else {
                (best_offset - RAW_OFFSET_BASE) as i64
            };
            if lru[0] != distance {
                let old_1 = lru[1];
                lru[1] = lru[0];
                lru[0] = distance;
                if old_1 != distance {
                    lru[2] = old_1;
                }
            }

            // Add intermediate positions to hash
            for j in 1..best_len as usize {
                let p = combined_pos + j;
                if p + 2 < combined.len() {
                    let h2 = hash3(&combined, p) & hash_mask;
                    hash_chain[p] = hash_table[h2];
                    hash_table[h2] = p as u32;
                }
            }

            i += best_len as usize;
        } else {
            symbols.push(MatchSymbol {
                raw_offset: target[i] as u32,
                length: 1,
            });
            i += 1;
        }
    }

    // Pass 1: collect symbol frequencies
    let mut main_freq = vec![0u32; MAIN_SYMBOLS];
    let mut len_freq = vec![0u32; LENGTH_SYMBOLS];
    let mut aligned_freq = vec![0u32; ALIGNED_SYMBOLS];

    for sym in &symbols {
        if sym.length == 1 && sym.raw_offset < 256 {
            main_freq[sym.raw_offset as usize] += 1;
        } else {
            let (offset_slot, _, needs_aligned) =
                compute_symbol_info(sym.raw_offset, sym.length);
            let length_slot = compute_length_slot(sym.length);
            let main_sym = ((0x100 + (offset_slot << 3)) | length_slot) as usize;
            if main_sym < MAIN_SYMBOLS {
                main_freq[main_sym] += 1;
            }
            if length_slot == 0 {
                let len_sym = compute_length_extra(sym.length);
                if (len_sym as usize) < LENGTH_SYMBOLS {
                    len_freq[len_sym as usize] += 1;
                }
            }
            if needs_aligned {
                let aligned = (sym.raw_offset.wrapping_sub(RAW_OFFSET_BASE)) & 0xF;
                aligned_freq[aligned as usize] += 1;
            }
        }
    }

    // Ensure at least 2 symbols have nonzero frequency for valid Huffman
    for freq in [&mut main_freq, &mut len_freq, &mut aligned_freq] {
        let nonzero = freq.iter().filter(|&&f| f > 0).count();
        if nonzero < 2 {
            for (i, f) in freq.iter_mut().enumerate() {
                if *f == 0 && nonzero + (i > 0) as usize >= 2 {
                    break;
                }
                if *f == 0 {
                    *f = 1;
                }
            }
        }
    }

    // Build custom Huffman tables from frequencies
    let tables = SegmentTables {
        main: HuffmanTable::from_frequencies(&main_freq, 15)?,
        lengths: HuffmanTable::from_frequencies(&len_freq, 15)?,
        aligned: HuffmanTable::from_frequencies(&aligned_freq, 15)?,
    };

    // Pass 2: encode
    let mut writer = BitWriter::new();

    // Rift table: empty
    writer.write_bits(0, 1);

    // CompositeFormat: complex mode (0 = complex, 1 = simple)
    writer.write_bits(0, 1);

    // Write complex format: 1 segment, boundary at ref_len
    write_composite_format(&mut writer, &tables, ref_len as u64)?;

    // Encode symbols
    for sym in &symbols {
        if sym.length == 1 && sym.raw_offset < 256 {
            tables.main.write_symbol(&mut writer, sym.raw_offset as u16);
        } else {
            encode_match(&tables, &mut writer, sym.raw_offset, sym.length)?;
        }
    }

    Ok(writer.finish())
}

pub(super) fn write_composite_format(
    writer: &mut BitWriter,
    tables: &SegmentTables,
    boundary: u64,
) -> Result<()> {
    // 1 segment
    writer.write_i64(1);
    // Segment boundary
    writer.write_i64(boundary as i64);

    // Pre-tree: 39 symbols, each with 4-bit code length
    // Build the compression lengths array (872 bytes = main + length + aligned)
    let mut all_lengths = Vec::with_capacity(TOTAL_LENGTHS);
    all_lengths.extend_from_slice(&tables.main.lengths);
    all_lengths.extend_from_slice(&tables.lengths.lengths);
    all_lengths.extend_from_slice(&tables.aligned.lengths);

    let prev_lengths = vec![0u8; TOTAL_LENGTHS];
    let pretree_syms = encode_compression_lengths(&all_lengths, &prev_lengths);

    let mut pretree_freq = [0u32; PRETREE_SYMBOLS];
    for &(sym, _) in &pretree_syms {
        pretree_freq[sym as usize] += 1;
    }

    let pretree = HuffmanTable::from_frequencies(&pretree_freq, 15)?;

    for i in 0..PRETREE_SYMBOLS {
        writer.write_bits(pretree.lengths[i] as u64, 4);
    }

    for &(sym, extra) in &pretree_syms {
        pretree.write_symbol(writer, sym);
        if let Some((val, bits)) = extra {
            writer.write_bits(val as u64, bits);
        }
    }

    Ok(())
}

fn encode_compression_lengths(
    lengths: &[u8],
    prev: &[u8],
) -> Vec<(u16, Option<(u32, u32)>)> {
    let mut syms = Vec::new();
    let mut i = 0;

    while i < lengths.len() {
        // Try run-length: repeat of previous value from prev[]
        if i + 3 < lengths.len() {
            let mut run = 0;
            while i + run < lengths.len() && lengths[i + run] == prev[i + run] && run < 127 {
                run += 1;
            }
            if run >= 4 {
                let (sym_base, extra) = encode_run_count(run);
                syms.push((sym_base + 8 + 23, extra));
                i += run;
                continue;
            }
        }

        // Try run-length: repeat of result[i-1]
        if i > 0 {
            let fill = lengths[i - 1];
            let mut run = 0;
            while i + run < lengths.len() && lengths[i + run] == fill && run < 127 {
                run += 1;
            }
            if run >= 4 {
                let (sym_base, extra) = encode_run_count(run);
                syms.push((sym_base + 23, extra));
                i += run;
                continue;
            }
        }

        // Try delta from previous
        let diff = lengths[i] as i16 - prev[i] as i16;
        match diff {
            1 => { syms.push((17, None)); i += 1; continue; }
            2 => { syms.push((18, None)); i += 1; continue; }
            3 => { syms.push((19, None)); i += 1; continue; }
            -1 => { syms.push((20, None)); i += 1; continue; }
            -2 => { syms.push((21, None)); i += 1; continue; }
            -3 => { syms.push((22, None)); i += 1; continue; }
            _ => {}
        }

        // Raw code length
        syms.push((lengths[i] as u16, None));
        i += 1;
    }

    syms
}

fn encode_run_count(count: usize) -> (u16, Option<(u32, u32)>) {
    match count {
        1 => (0, None),
        2 => (1, None),
        3 => (2, None),
        4..=7 => (3, Some(((count - 4) as u32, 2))),
        8..=15 => (4, Some(((count - 8) as u32, 3))),
        16..=31 => (5, Some(((count - 16) as u32, 4))),
        32..=63 => (6, Some(((count - 32) as u32, 5))),
        _ => (7, Some(((count - 64).min(63) as u32, 6))),
    }
}

pub(super) fn compute_symbol_info(raw_offset: u32, _length: u32) -> (u32, u32, bool) {
    // Returns (offset_slot, extra_bits_count, needs_aligned_table)
    if raw_offset == SOURCE_COPY {
        return (3, 0, false);
    }
    if (LRU_BASE..LRU_BASE + 3).contains(&raw_offset) {
        return (raw_offset - 0x53FFD, 0, false);
    }
    if raw_offset >= RAW_OFFSET_BASE {
        let dist = raw_offset - RAW_OFFSET_BASE;
        if dist <= 3 {
            return (dist + 7, 0, false);
        }
        for try_adj in 4..64u32 {
            let base = (try_adj & 1) + 2;
            let half = (try_adj >> 1) - 1;
            if half < 4 {
                let shifted = base << half;
                if dist >= shifted && dist < shifted + (1u32 << half) {
                    return (try_adj + 7, half, false);
                }
            } else {
                let high_bits = half - 4;
                let base_val = if high_bits > 0 { base << high_bits } else { base };
                let max_high = if high_bits > 0 { (1u32 << high_bits) - 1 } else { 0 };
                let min = base_val << 4;
                let max = ((base_val | max_high) << 4) | 15;
                if dist >= min && dist <= max {
                    return (try_adj + 7, high_bits, true);
                }
            }
        }
        return (7, 0, false); // fallback
    }
    (0, 0, false)
}

pub(super) fn compute_length_slot(length: u32) -> u32 {
    if length > 1 && length - 1 <= 7 {
        length - 1
    } else {
        0
    }
}

pub(super) fn compute_length_extra(length: u32) -> u16 {
    let len_sym = (length - 1).saturating_sub(7);
    if len_sym > 0 && len_sym <= 255 { len_sym as u16 } else { 0 }
}

pub(super) fn match_fits_table(raw_offset: u32) -> bool {
    if raw_offset < 0x100 || raw_offset == SOURCE_COPY
        || (LRU_BASE..LRU_BASE + 3).contains(&raw_offset)
    {
        return true;
    }
    if raw_offset >= RAW_OFFSET_BASE {
        let dist = raw_offset - RAW_OFFSET_BASE;
        if dist == 0 { return false; }
        let slot = if dist <= 3 {
            dist + 7
        } else {
            let high = 31 - dist.leading_zeros();
            let adj = 2 * high + ((dist >> (high - 1)) & 1);
            adj + 7
        };
        let main_sym = 0x100 + (slot << 3);
        return main_sym < MAIN_SYMBOLS as u32;
    }
    if raw_offset < SOURCE_COPY {
        return true;
    }
    true
}

pub(super) fn encode_match(
    tables: &SegmentTables,
    writer: &mut BitWriter,
    raw_offset: u32,
    length: u32,
) -> Result<()> {
    // Compute offset slot and prepare extra bits
    let offset_slot: u32;
    let mut offset_extra = [(0u64, 0u32); 2]; // (value, bits), max 2 entries
    let mut n_extra = 0usize;

    if raw_offset == SOURCE_COPY {
        offset_slot = 3;
    } else if (LRU_BASE..LRU_BASE + 3).contains(&raw_offset) {
        offset_slot = raw_offset - 0x53FFD;
    } else if raw_offset >= RAW_OFFSET_BASE {
        let dist = raw_offset - RAW_OFFSET_BASE;

        if dist == 0 {
            return Err(Error::Malformed("zero distance not supported"));
        }

        let mut found = false;
        let mut adj = 0u32;

        if dist <= 3 {
            adj = dist;
            found = true;
        } else {
            for try_adj in 4..64u32 {
                let base = (try_adj & 1) + 2;
                let half = (try_adj >> 1) - 1;
                if half < 4 {
                    let shifted = base << half;
                    if dist >= shifted && dist < shifted + (1u32 << half) {
                        adj = try_adj;
                        let extra = dist - shifted;
                        if half > 0 {
                            offset_extra[n_extra] = (extra as u64, half); n_extra += 1;
                        }
                        found = true;
                        break;
                    }
                } else {
                    let high_bits = half - 4;
                    let base_val = if high_bits > 0 { base << high_bits } else { base };
                    let max_high = if high_bits > 0 { (1u32 << high_bits) - 1 } else { 0 };
                    let min = base_val << 4;
                    let max = ((base_val | max_high) << 4) | 15;
                    if dist >= min && dist <= max {
                        adj = try_adj;
                        if high_bits > 0 {
                            let high = (dist >> 4) & max_high;
                            offset_extra[n_extra] = (high as u64, high_bits); n_extra += 1;
                        }
                        offset_extra[n_extra] = (u64::MAX, 0); n_extra += 1; // sentinel: use aligned table
                        found = true;
                        break;
                    }
                }
            }
        }

        if !found {
            return Err(Error::Malformed("could not encode distance"));
        }
        offset_slot = adj + 7;
    } else {
        // Signed offset: raw_offset encodes distance via OFFSET_BIAS
        let signed_dist = raw_offset as i32 - OFFSET_BIAS as i32;

        // Slot 0: 14-bit range [-0x2000, 0x1FFF]
        if (-0x2000..0x2000).contains(&signed_dist) {
            offset_slot = 0;
            let raw14 = (signed_dist + 0x2000) as u32;
            offset_extra[n_extra] = (raw14 as u64, 14); n_extra += 1;
        }
        // Slot 1: 16-bit range [-0xA000, -0x2001] u [0x2000, 0x5FFF]
        else if (-0xA000..0x6000).contains(&signed_dist) {
            offset_slot = 1;
            let raw16 = if signed_dist < -0x2000 {
                (signed_dist + 0xA000) as u32
            } else {
                (signed_dist + 0x6000) as u32
            };
            offset_extra[n_extra] = (raw16 as u64, 16); n_extra += 1;
        }
        // Slot 2: 18-bit range
        else {
            offset_slot = 2;
            let raw18 = if signed_dist >= 0x6000 {
                (signed_dist + 0x16000) as u32
            } else {
                (signed_dist + 0x2A000) as u32
            };
            offset_extra[n_extra] = ((raw18 & 0x3FFFF) as u64, 18); n_extra += 1;
        }
    };

    // Compute length encoding
    let length_slot: u32;
    let length_extra: Option<u16>;
    if length > 1 && length - 1 <= 7 {
        length_slot = length - 1;
        length_extra = None;
    } else {
        length_slot = 0;
        let len_sym = (length - 1).saturating_sub(7);
        if len_sym > 0 && len_sym <= 255 {
            length_extra = Some(len_sym as u16);
        } else {
            length_extra = Some(0); // symbol 0 triggers ReadNumber path
        }
    }

    // Verify main symbol is in range
    let main_sym = ((0x100 + (offset_slot << 3)) | length_slot) as u16;
    if main_sym as usize >= tables.main.lengths.len() {
        return Err(Error::Malformed("main symbol out of range"));
    }

    // Write main symbol
    tables.main.write_symbol(writer, main_sym);

    // Write offset extra bits
    for &(val, bits) in &offset_extra[..n_extra] {
        if val == u64::MAX {
            // Sentinel: write aligned symbol from the distance's low 4 bits
            let aligned = (raw_offset - RAW_OFFSET_BASE) & 0xF;
            tables.aligned.write_symbol(writer, aligned as u16);
        } else if bits > 0 {
            writer.write_bits(val, bits);
        }
    }

    // Write length extra
    if let Some(len_sym) = length_extra {
        tables.lengths.write_symbol(writer, len_sym);
        if len_sym == 0 {
            let big_len = (length - 1).saturating_sub(7);
            if big_len < 256 {
                // Should have used direct symbol, not ReadNumber
                // This shouldn't happen due to the check above
            }
            writer.write_u32_number(big_len.max(256));
        }
    }

    Ok(())
}
