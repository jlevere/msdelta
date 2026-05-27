//! Decompression internals for the PseudoLzx codec.

use crate::bitstream::BitReader;
use crate::huffman::HuffmanTable;
use crate::{Error, Result};

use super::format::{
    CompositeFormat, SegmentTables,
    PRETREE_SYMBOLS, TOTAL_LENGTHS,
};
use super::ops::{OFFSET_BIAS, RAW_OFFSET_BASE};
use super::format::{SOURCE_COPY, LRU_BASE};
use super::rift;

pub(super) fn read_composite_format(reader: &mut BitReader) -> Result<CompositeFormat> {
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

    if std::env::var("LZX_SEG_DEBUG").is_ok() {
        eprintln!("LZX: {num_segments} segments, boundaries={boundaries:?}");
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
pub(super) fn read_compression_lengths(
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

/// Core decompression implementation shared by `decompress` and `decompress_partial`.
pub(super) fn decompress_into(
    reference: &[u8],
    patch_data: &[u8],
    target_size: usize,
    caller_rift: Option<&rift::RiftTable>,
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

    let mut rift_table = rift::RiftTable::from_reader(&mut reader)?;

    // Merge with caller-provided rift (from PE preprocessing)
    if let Some(cr) = caller_rift {
        for e in &cr.entries {
            rift_table.entries.push(*e);
        }
    }

    // Add boundary entry at source_size (as ApplyForward does in msdelta.dll)
    let ref_len = reference.len();
    rift_table.entries.push(rift::RiftEntry { source: ref_len as i64, target: 0 });
    rift_table.entries.sort_by_key(|e| e.source);
    let ort = rift::OffsetRiftTable::from_rift_table(&rift_table);

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
        if src_start.checked_add(copy_len).is_some_and(|end| end <= ref_len as u64) {
            // Entire copy from reference -- bulk copy
            let start = src_start as usize;
            let end = start + copy_len as usize;
            if end > reference.len() {
                return Err(Error::Malformed("source copy out of reference bounds"));
            }
            output.extend_from_slice(&reference[start..end]);
            pos += copy_len;
        } else if src_start >= ref_len as u64 {
            // Entire copy from output -- may overlap (like LZ back-reference)
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
            // Copy spans reference/output boundary -- split
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

/// Read one symbol, returning (raw_offset, length).
/// For literals: (byte_value, 1).
/// For matches: (encoded_offset, match_length).
#[inline]
pub(super) fn read_symbol(tables: &SegmentTables, reader: &mut BitReader) -> Result<(u32, u32)> {
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
    Ok(result)
}
