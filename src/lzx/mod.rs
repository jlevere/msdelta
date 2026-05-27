//! PseudoLzx compressor and decompressor for PA30 patches.
//!
//! Not standard LZX or LZX Delta. Key differences:
//! - Left-leaning canonical Huffman codes
//! - 3-element LRU queue for recent offsets
//! - Rift-table-aware source-window copies
//!
//! PDB-confirmed class names: `Decompressor`, `CompositeFormat`, `CompressionFormat`,
//! `CompressionLengths`, `RiftTable`, `OffsetRiftTable`.

pub mod ops;
pub mod rift;

use crate::bitstream::{BitReader, BitWriter};
use crate::huffman::HuffmanTable;
use self::ops::{SOURCE_COPY_RAW, LRU_BASE_RAW, RAW_OFFSET_BASE, OFFSET_BIAS};
use self::rift::RiftTable;
use crate::{Error, Result};

// Aliases for the raw wire constants used throughout this module
const SOURCE_COPY: u32 = SOURCE_COPY_RAW;
const LRU_BASE: u32 = LRU_BASE_RAW;

const MAIN_SYMBOLS: usize = 600;
const LENGTH_SYMBOLS: usize = 256;
const ALIGNED_SYMBOLS: usize = 16;
const TOTAL_LENGTHS: usize = MAIN_SYMBOLS + LENGTH_SYMBOLS + ALIGNED_SYMBOLS;
const PRETREE_SYMBOLS: usize = 39;

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

struct SegmentTables {
    main: HuffmanTable,
    lengths: HuffmanTable,
    aligned: HuffmanTable,
}

impl SegmentTables {
    fn from_flat() -> Result<Self> {
        Ok(SegmentTables {
            main: HuffmanTable::from_lengths(&flat_code_lengths(MAIN_SYMBOLS))?,
            lengths: HuffmanTable::from_lengths(&flat_code_lengths(LENGTH_SYMBOLS))?,
            aligned: HuffmanTable::from_lengths(&flat_code_lengths(ALIGNED_SYMBOLS))?,
        })
    }

    fn from_lengths(all_lengths: &[u8]) -> Result<Self> {
        if all_lengths.len() != TOTAL_LENGTHS {
            return Err(Error::Malformed("wrong total compression lengths"));
        }
        let main = HuffmanTable::from_lengths(&all_lengths[..MAIN_SYMBOLS])?;
        let lengths = HuffmanTable::from_lengths(
            &all_lengths[MAIN_SYMBOLS..MAIN_SYMBOLS + LENGTH_SYMBOLS],
        )?;
        let aligned = HuffmanTable::from_lengths(
            &all_lengths[MAIN_SYMBOLS + LENGTH_SYMBOLS..],
        )?;
        Ok(SegmentTables { main, lengths, aligned })
    }
}

struct CompositeFormat {
    segments: Vec<SegmentTables>,
    boundaries: Vec<u64>,
}

fn read_composite_format(reader: &mut BitReader) -> Result<CompositeFormat> {
    let num_segments = reader.read_i64()? as usize;
    if num_segments == 0 || num_segments > 1024 {
        return Err(Error::Malformed("invalid segment count"));
    }

    let mut boundaries = Vec::with_capacity(num_segments);
    let mut acc = 0i64;
    for _ in 0..num_segments {
        let delta = reader.read_i64()?;
        acc += delta;
        boundaries.push(acc as u64);
    }

    // Read pre-tree: 39 symbols, each with a 4-bit code length
    let mut pretree_lengths = [0u8; PRETREE_SYMBOLS];
    for l in &mut pretree_lengths {
        *l = reader.read_bits(4)? as u8;
    }
    let pretree = HuffmanTable::from_lengths(&pretree_lengths)?;

    // Previous lengths start as all zeros (Reset(true) in the decompiled code).
    // The flat code is only used for simple mode.
    let mut prev_lengths = vec![0u8; TOTAL_LENGTHS];

    let mut segments = Vec::with_capacity(num_segments);
    for _ in 0..num_segments {
        let lengths = read_compression_lengths(reader, &pretree, &prev_lengths)?;
        let tables = SegmentTables::from_lengths(&lengths)?;
        prev_lengths = lengths;
        segments.push(tables);
    }

    Ok(CompositeFormat {
        segments,
        boundaries,
    })
}

/// Read 872 delta-encoded compression lengths using the pre-tree.
///
/// Pre-tree symbol meanings (from CompressionLengths::Read):
/// 0-16:   raw code length
/// 17-19:  increment from previous (+1, +2, +3)
/// 20-22:  decrement from previous (-1, -2, -3)
/// 23+:    run-length with variable count
fn read_compression_lengths(
    reader: &mut BitReader,
    pretree: &HuffmanTable,
    prev: &[u8],
) -> Result<Vec<u8>> {
    let mut result = vec![0u8; TOTAL_LENGTHS];
    let mut i = 0;

    while i < TOTAL_LENGTHS {
        let sym = pretree.read_symbol(reader)? as u32;

        if sym <= 16 {
            result[i] = sym as u8;
            i += 1;
        } else if sym < 23 {
            // Delta from previous
            let delta = sym - 17;
            let new_len = if delta < 3 {
                prev[i].wrapping_add(delta as u8 + 1)
            } else {
                prev[i].wrapping_sub(delta as u8 - 2)
            };
            result[i] = new_len;
            i += 1;
        } else {
            // Run-length
            let run_sym = sym - 23;
            let run_slot = run_sym & 7;
            let run_count = if run_slot < 3 {
                (run_slot + 1) as usize
            } else {
                let extra_bits = run_slot - 1;
                let extra = reader.read_bits(extra_bits)? as u32;
                let count = (1u32 << extra_bits) | extra;
                count as usize
            };

            if i + run_count > TOTAL_LENGTHS {
                return Err(Error::Malformed("run-length exceeds total lengths"));
            }

            let fill_value = if run_sym < 8 {
                if i == 0 {
                    return Err(Error::Malformed("run-length at start of lengths"));
                }
                result[i - 1]
            } else {
                prev[i]
            };

            for j in 0..run_count {
                let src = if run_sym >= 8 {
                    prev[i + j]
                } else {
                    fill_value
                };
                result[i + j] = src;
            }
            i += run_count;
        }
    }

    for &l in &result {
        if l > 16 {
            return Err(Error::Malformed("code length exceeds maximum"));
        }
    }

    Ok(result)
}

/// Decompress a PseudoLzx patch.
pub fn decompress(reference: &[u8], patch_data: &[u8], target_size: usize) -> Result<Vec<u8>> {
    decompress_with_rift(reference, patch_data, target_size, None)
}

/// Decompress with an optional caller-provided rift table (from PE preprocessing).
pub fn decompress_with_rift(
    reference: &[u8],
    patch_data: &[u8],
    target_size: usize,
    caller_rift: Option<&RiftTable>,
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(target_size);
    decompress_into(reference, patch_data, target_size, caller_rift, &mut output)?;
    Ok(output)
}

/// Decompress into a provided buffer. Core implementation shared by
/// `decompress` and `decompress_partial`.
fn decompress_into(
    reference: &[u8],
    patch_data: &[u8],
    target_size: usize,
    caller_rift: Option<&RiftTable>,
    output: &mut Vec<u8>,
) -> Result<()> {
    if patch_data.is_empty() {
        return if target_size == 0 {
            Ok(())
        } else {
            Err(Error::Malformed("empty patch data for non-zero target"))
        };
    }

    let mut reader = BitReader::new(patch_data)?;

    let mut rift = RiftTable::from_reader(&mut reader)?;

    // Merge with caller-provided rift (from PE preprocessing)
    if let Some(cr) = caller_rift {
        for e in &cr.entries {
            rift.entries.push(*e);
        }
    }

    // Add boundary entry at source_size (as ApplyForward does in msdelta.dll)
    let ref_len = reference.len();
    rift.entries.push(rift::RiftEntry { source: ref_len as i64, target: 0 });
    rift.entries.sort_by_key(|e| e.source);
    let ort = rift::OffsetRiftTable::from_rift_table(&rift);

    let cf_simple = reader.read_bits(1)? != 0;
    let format = if cf_simple {
        CompositeFormat {
            segments: vec![SegmentTables::from_flat()?],
            boundaries: vec![u64::MAX],
        }
    } else {
        read_composite_format(&mut reader)?
    };

    let mut seg_idx = 0;
    output.reserve(target_size);
    let mut lru: [i64; 3] = [0; 3];
    let mut pos: u64 = ref_len as u64;
    let end: u64 = pos + target_size as u64;

    while pos < end {
        if reader.remaining() == 0 {
            return Err(Error::Malformed("bitstream exhausted before target filled"));
        }

        while seg_idx + 1 < format.segments.len()
            && format
                .boundaries
                .get(seg_idx + 1)
                .is_some_and(|&b| pos >= b)
        {
            seg_idx += 1;
        }
        let tables = &format.segments[seg_idx];

        let (raw_offset, match_len) = read_symbol(tables, &mut reader)?;

        if match_len == 1 && raw_offset < 256 {
            output.push(raw_offset as u8);
            pos += 1;
            continue;
        }
        let copy_len = (match_len as u64).min(end - pos);

        let rift_offset = ort.offset_at(pos as i64);
        let distance: i64;
        if raw_offset == SOURCE_COPY {
            distance = -rift_offset;
        } else if raw_offset < SOURCE_COPY {
            distance = raw_offset as i64 - OFFSET_BIAS as i64 - rift_offset;
        } else if (LRU_BASE..LRU_BASE + 3).contains(&raw_offset) {
            distance = lru[(raw_offset - LRU_BASE) as usize];
        } else {
            distance = (raw_offset - RAW_OFFSET_BASE) as i64;
        }

        // LRU update runs for ALL match types (decompiled Run's LAB_1800278aa).
        if lru[0] != distance {
            let old_1 = lru[1];
            lru[1] = lru[0];
            lru[0] = distance;
            if old_1 != distance {
                lru[2] = old_1;
            }
        }

        let src_start = (pos as i64 - distance) as u64;
        if src_start + copy_len <= ref_len as u64 {
            // Entire copy from reference — bulk copy
            let start = src_start as usize;
            let end = start + copy_len as usize;
            if end > reference.len() {
                return Err(Error::Malformed("source copy out of reference bounds"));
            }
            output.extend_from_slice(&reference[start..end]);
            pos += copy_len;
        } else if src_start >= ref_len as u64 {
            // Entire copy from output — may overlap (like LZ back-reference)
            let out_start = (src_start - ref_len as u64) as usize;
            if out_start >= output.len() {
                    return Err(Error::Malformed("back-reference out of output bounds"));
            }
            if out_start + (copy_len as usize) <= output.len() {
                // Non-overlapping: bulk copy via extend_from_within
                let start = out_start;
                let len = copy_len as usize;
                output.extend_from_within(start..start + len);
            } else {
                // Overlapping: byte-by-byte (LZ repeat pattern)
                for _ in 0..copy_len {
                    let idx = (pos as i64 - distance) as u64 - ref_len as u64;
                    let byte = output[idx as usize];
                    output.push(byte);
                    pos += 1;
                }
                continue; // pos already advanced
            }
            pos += copy_len;
        } else {
            // Copy spans reference/output boundary — split
            let ref_bytes = (ref_len as u64 - src_start) as usize;
            let out_bytes = copy_len as usize - ref_bytes;
            output.extend_from_slice(&reference[src_start as usize..ref_len]);
            for i in 0..out_bytes {
                if i >= output.len() {
                    return Err(Error::Malformed("back-reference out of output bounds"));
                }
                output.push(output[i]);
            }
            pos += copy_len;
        }
    }

    if output.len() != target_size {
        return Err(Error::Malformed("output size mismatch"));
    }

    Ok(())
}

/// Compress `target` as a PseudoLzx patch against `reference`.
///
/// Produces a bitstream that `decompress` (and msdelta.dll) can decode.
/// Uses simple-mode (flat Huffman tables, single segment) for format
/// compatibility without needing custom Huffman tree serialization.
pub fn compress(reference: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    let ref_len = reference.len();

    // Two-pass: first find all symbols, then encode.
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

        if best_len >= 2 {
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

fn write_composite_format(
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

    // For the pre-tree, we use a simple encoding: write each length as a raw symbol.
    // The pre-tree itself encodes how lengths are stored. Symbols 0-16 = raw lengths.
    // We compute pre-tree frequencies from the actual lengths.
    let mut pretree_freq = [0u32; PRETREE_SYMBOLS];
    for &l in &all_lengths {
        pretree_freq[l as usize] += 1;
    }

    // Build pre-tree from frequencies (max length 15)
    let pretree = HuffmanTable::from_frequencies(&pretree_freq, 15)?;

    // Write 39 pre-tree lengths (4 bits each)
    for i in 0..PRETREE_SYMBOLS {
        writer.write_bits(pretree.lengths[i] as u64, 4);
    }

    // Write compression lengths using the pre-tree
    // For simplicity, write each as a raw symbol (no delta encoding, no run-length).
    // Previous lengths are all zeros (initial state).
    for &l in &all_lengths {
        pretree.write_symbol(writer, l as u16);
    }

    Ok(())
}

fn compute_symbol_info(raw_offset: u32, _length: u32) -> (u32, u32, bool) {
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

fn compute_length_slot(length: u32) -> u32 {
    if length > 1 && length - 1 <= 7 {
        length - 1
    } else {
        0
    }
}

fn compute_length_extra(length: u32) -> u16 {
    let len_sym = (length - 1).saturating_sub(7);
    if len_sym > 0 && len_sym <= 255 { len_sym as u16 } else { 0 }
}

fn encode_match(
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
        if signed_dist >= -0x2000 && signed_dist < 0x2000 {
            offset_slot = 0;
            let raw14 = (signed_dist + 0x2000) as u32;
            offset_extra[n_extra] = (raw14 as u64, 14); n_extra += 1;
        }
        // Slot 1: 16-bit range [-0xA000, -0x2001] ∪ [0x2000, 0x5FFF]
        else if signed_dist >= -0xA000 && signed_dist < 0x6000 {
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

/// Like `decompress`, but returns partial output on error for debugging.
pub fn decompress_partial(
    reference: &[u8],
    patch_data: &[u8],
    target_size: usize,
) -> (Vec<u8>, Option<Error>) {
    let mut output = Vec::new();
    match decompress_into(reference, patch_data, target_size, None, &mut output) {
        Ok(()) => (output, None),
        Err(e) => (output, Some(e)),
    }
}

/// Read one symbol, returning (raw_offset, length).
/// For literals: (byte_value, 1).
/// For matches: (encoded_offset, match_length).
#[inline]
fn read_symbol(tables: &SegmentTables, reader: &mut BitReader) -> Result<(u32, u32)> {
    let raw = tables.main.read_symbol(reader)?;

    if raw < 0x100 {
        return Ok((raw as u32, 1));
    }
    let idx = (raw - 0x100) as u32;
    let length_slot = idx & 7;
    let offset_slot = idx >> 3;


    let offset = decode_offset(offset_slot, tables, reader)?;


    let length = if length_slot == 0 {
        let len_sym = tables.lengths.read_symbol(reader)?;
        if len_sym == 0 {
            let big_len = reader.read_u32_number()?;
            if big_len < 256 {
                return Err(Error::Malformed("ReadNumber returned value < 256"));
            }
            big_len + 7
        } else {
            len_sym as u32 + 7
        }
    } else {
        length_slot
    };

    Ok((offset, length + 1))
}

#[inline]
fn decode_offset(slot: u32, tables: &SegmentTables, reader: &mut BitReader) -> Result<u32> {
    if slot < 3 {
        let adjusted = match slot {
            0 => {
                let raw = reader.read_bits(14)? as i32;
                (raw & 0x3FFF) - 0x2000
            }
            1 => {
                let raw = reader.read_bits(16)? as u32;
                if raw < 0x8000 {
                    raw as i32 - 0xA000i32
                } else {
                    raw as i32 - 0x6000i32
                }
            }
            2 => {
                let raw = reader.read_bits(18)? as u32;
                if raw >= 0x20000 {
                    raw as i32 - 0x16000i32
                } else {
                    raw as i32 - 0x2A000i32
                }
            }
            _ => unreachable!(),
        };
        Ok((adjusted + OFFSET_BIAS as i32) as u32)
    } else if slot < 7 {
        Ok(slot + 0x53FFD)
    } else {
        let adj_slot = slot - 7;
        let extra_val = decode_extra_value(adj_slot, reader)?;

        if extra_val > 63 {
            return Err(Error::Malformed("offset extra value too large"));
        }

        let dist = if extra_val <= 3 {
            extra_val
        } else {
            let base = ((extra_val & 1) + 2) as u32;
            let half = (extra_val >> 1) - 1;

            if half < 4 {
                let shifted = base << half;
                let extra = if half == 0 {
                    0
                } else {
                    reader.read_bits(half)? as u32
                };
                shifted | extra
            } else {
                let high_bits = half - 4;
                let mut val = base;
                if high_bits > 0 {
                    let extra = reader.read_bits(high_bits)? as u32;
                    val = (val << high_bits) | extra;
                }
                let aligned = tables.aligned.read_symbol(reader)? as u32;
                (val << 4) | aligned
            }
        };

        Ok(dist + RAW_OFFSET_BASE)
    }
}

#[inline]
fn decode_extra_value(adj_slot: u32, reader: &mut BitReader) -> Result<u32> {
    if adj_slot != 0 {
        return Ok(adj_slot);
    }
    let result = if reader.read_bits(1)? == 0 {
        let val = reader.read_bits(2)? as u32;
        val + 0x24
    } else if reader.read_bits(1)? == 0 {
        let val = reader.read_bits(3)? as u32;
        val + 4 + 0x24
    } else {
        let val = reader.read_bits(4)? as u32;
        val + 8 + 4 + 0x24
    };
    if std::env::var("LZX_DEBUG").is_ok() {
        eprintln!("  decode_extra_value(0) = {result}");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_match_source_copy() {
        let tables = SegmentTables::from_flat().unwrap();
        let mut w = BitWriter::new();
        w.write_bits(0, 1); // rift
        w.write_bits(1, 1); // simple mode
        encode_match(&tables, &mut w, SOURCE_COPY, 30).unwrap();
        let data = w.finish();

        let mut r = BitReader::new(&data).unwrap();
        r.read_bits(1).unwrap(); // rift
        r.read_bits(1).unwrap(); // simple
        let (off, len) = read_symbol(&tables, &mut r).unwrap();
        assert_eq!(off, SOURCE_COPY);
        assert_eq!(len, 30);
    }

    #[test]
    fn encode_decode_match_lru() {
        let tables = SegmentTables::from_flat().unwrap();
        for lru_idx in 0..3u32 {
            let mut w = BitWriter::new();
            w.write_bits(0, 2);
            encode_match(&tables, &mut w, LRU_BASE + lru_idx, 5).unwrap();
            let data = w.finish();
            let mut r = BitReader::new(&data).unwrap();
            r.read_bits(2).unwrap();
            let (off, len) = read_symbol(&tables, &mut r).unwrap();
            assert_eq!(off, LRU_BASE + lru_idx, "LRU {lru_idx}");
            assert_eq!(len, 5);
        }
    }

    #[test]
    fn encode_decode_match_small_dist() {
        let tables = SegmentTables::from_flat().unwrap();
        for dist in [1u32, 2, 3, 4, 5, 10, 15, 20, 31] {
            let raw_off = dist + RAW_OFFSET_BASE;
            let mut w = BitWriter::new();
            w.write_bits(0, 2);
            encode_match(&tables, &mut w, raw_off, 3).unwrap();
            let data = w.finish();
            let mut r = BitReader::new(&data).unwrap();
            r.read_bits(2).unwrap();
            let (got_off, got_len) = read_symbol(&tables, &mut r).unwrap();
            assert_eq!(got_off, raw_off, "dist={dist}: offset mismatch");
            assert_eq!(got_len, 3, "dist={dist}: length mismatch");
        }
    }

    #[test]
    fn encode_decode_match_medium_dist() {
        let tables = SegmentTables::from_flat().unwrap();
        for dist in [32u32, 47, 48, 63, 64, 100, 127, 200, 500, 1000, 5000, 9000] {
            let raw_off = dist + RAW_OFFSET_BASE;
            let mut w = BitWriter::new();
            w.write_bits(0, 2);
            let result = encode_match(&tables, &mut w, raw_off, 3);
            if let Err(e) = result {
                panic!("encode failed for dist={dist}: {e}");
            }
            let data = w.finish();
            let mut r = BitReader::new(&data).unwrap();
            r.read_bits(2).unwrap();
            let (got_off, got_len) = read_symbol(&tables, &mut r).unwrap();
            assert_eq!(got_off, raw_off, "dist={dist}: offset mismatch");
            assert_eq!(got_len, 3, "dist={dist}: length mismatch");
        }
    }

    #[test]
    fn flat_codes_256() {
        let lengths = flat_code_lengths(256);
        assert_eq!(lengths.len(), 256);
        assert!(lengths.iter().all(|&l| l == 8));
    }

    #[test]
    fn flat_codes_600() {
        let lengths = flat_code_lengths(600);
        assert_eq!(lengths.len(), 600);
        let short = lengths.iter().filter(|&&l| l == 9).count();
        let long = lengths.iter().filter(|&&l| l == 10).count();
        assert_eq!(short, 424);
        assert_eq!(long, 176);
    }

    #[test]
    fn flat_codes_16() {
        let lengths = flat_code_lengths(16);
        assert_eq!(lengths.len(), 16);
        assert!(lengths.iter().all(|&l| l == 4));
    }
}
