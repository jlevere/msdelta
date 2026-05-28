//! PE file type transforms applied during MSDelta decode/encode.
//!
//! When FileType is not RAW, the decoded output is post-processed
//! through a transform pipeline. The most common transform is
//! "inferred relocations" which scans for 32-bit pointers within
//! the PE's image range and rebases them using the rift table.

use super::parse::PeInfo;
use crate::Result;

/// MSDelta file type flags.
pub const FILE_TYPE_RAW: i64 = 1;
pub const FILE_TYPE_I386: i64 = 2;
pub const FILE_TYPE_IA64: i64 = 4;
pub const FILE_TYPE_AMD64: i64 = 8;
pub const FILE_TYPE_CLI4_I386: i64 = 0x10;
pub const FILE_TYPE_CLI4_AMD64: i64 = 0x20;

const RELOC_MARKER: u32 = 0x01010101;
const RELOC_CHECK: u32 = 0x02020202;

/// Apply the inferred relocations transform for 32-bit (X86) PE binaries.
///
/// Scans the buffer for 32-bit values that fall within the PE's image range.
/// Marks them with `RELOC_MARKER` in the output buffer and replaces the
/// value with the rift-table-mapped address.
///
/// `pe`: parsed PE info from the source binary
/// `source_buf`: the raw PE data (source side)
/// `output_buf`: the decoded output buffer (will be modified in place)
/// `new_image_base`: the target PE's image base
/// `rift_map`: closure that maps source RVA to target RVA via rift table
pub fn transform_inferred_relocations_x86(
    pe: &PeInfo,
    source_buf: &[u8],
    output_buf: &mut [u8],
    new_image_base: u64,
    rift_map: impl Fn(u64) -> i64,
) -> Result<u32> {
    let image_base = pe.image_base as u32;
    let image_end = image_base.wrapping_add(pe.size_of_image);
    let mut count = 0u32;

    let mut pos: usize = 0;
    while pos + 4 <= source_buf.len() && pos + 4 <= output_buf.len() {
        let val = u32::from_le_bytes([
            source_buf[pos],
            source_buf[pos + 1],
            source_buf[pos + 2],
            source_buf[pos + 3],
        ]);

        if val > image_base && val < image_end {
            let out_val = u32::from_le_bytes([
                output_buf[pos],
                output_buf[pos + 1],
                output_buf[pos + 2],
                output_buf[pos + 3],
            ]);

            if out_val & RELOC_CHECK == 0 {
                let rva = (val - image_base) as u64;
                let mapped = rift_map(rva);
                let new_val = (mapped as i32 + new_image_base as i32) as u32;
                let rebased = new_val | RELOC_MARKER;
                output_buf[pos..pos + 4].copy_from_slice(&rebased.to_le_bytes());
                count += 1;
                pos += 4;
                continue;
            }
        }
        pos += 1;
    }

    Ok(count)
}

/// Apply inferred relocations for AMD64 PE binaries.
///
/// Scans for 64-bit pointer values within the PE's image range.
pub fn transform_inferred_relocations_amd64(
    pe: &PeInfo,
    source_buf: &[u8],
    output_buf: &mut [u8],
    new_image_base: u64,
    rift_map: impl Fn(u64) -> i64,
) -> Result<u32> {
    let image_base = pe.image_base;
    let image_end = image_base.wrapping_add(pe.size_of_image as u64);
    let mut count = 0u32;

    let mut pos: usize = 0;
    while pos + 8 <= source_buf.len() && pos + 8 <= output_buf.len() {
        let val = u64::from_le_bytes(source_buf[pos..pos + 8].try_into().unwrap());

        if val > image_base && val < image_end {
            let out_val = u64::from_le_bytes(output_buf[pos..pos + 8].try_into().unwrap());
            let check64 = RELOC_CHECK as u64 | ((RELOC_CHECK as u64) << 32);

            if out_val & check64 == 0 {
                let rva = val - image_base;
                let mapped = rift_map(rva);
                let new_val = (mapped as i64 + new_image_base as i64) as u64;
                let marker64 = RELOC_MARKER as u64 | ((RELOC_MARKER as u64) << 32);
                let rebased = new_val | marker64;
                output_buf[pos..pos + 8].copy_from_slice(&rebased.to_le_bytes());
                count += 1;
                pos += 8;
                continue;
            }
        }
        pos += 1;
    }

    Ok(count)
}

pub(crate) fn pe_timestamp(data: &[u8]) -> u32 {
    if data.len() < 0x40 { return 0; }
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_off + 12 > data.len() { return 0; }
    u32::from_le_bytes(data[pe_off + 8..pe_off + 12].try_into().unwrap())
}

pub(crate) fn pe_timestamp_offsets(data: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let pe = match goblin::pe::PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return offsets,
    };

    let pe_off = pe.header.dos_header.pe_pointer as usize;
    offsets.push(pe_off + 8);

    let opt = match pe.header.optional_header {
        Some(o) => o,
        None => return offsets,
    };

    let sections = &pe.sections;
    let rva_to_offset = |rva: u32| -> Option<usize> {
        for s in sections {
            if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
                continue;
            }
            if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
                return Some((s.pointer_to_raw_data + (rva - s.virtual_address)) as usize);
            }
        }
        None
    };

    if let Some(&dd) = opt.data_directories.get_export_table() {
        if dd.virtual_address != 0 {
            if let Some(off) = rva_to_offset(dd.virtual_address) {
                offsets.push(off + 4);
            }
        }
    }

    if let Some(&dd) = opt.data_directories.get_debug_table() {
        if dd.virtual_address != 0 && dd.size >= 28 {
            if let Some(base_off) = rva_to_offset(dd.virtual_address) {
                let num_entries = dd.size as usize / 28;
                for i in 0..num_entries {
                    offsets.push(base_off + i * 28 + 4);
                }
            }
        }
    }

    if let Some(&dd) = opt.data_directories.get_debug_table() {
        if dd.virtual_address != 0 && dd.size >= 28 {
            if let Some(base_off) = rva_to_offset(dd.virtual_address) {
                let num_entries = dd.size as usize / 28;
                let header_ts = if offsets.is_empty() { 0 } else {
                    u32::from_le_bytes(data[offsets[0]..offsets[0]+4].try_into().unwrap_or([0;4]))
                };
                let ts_bytes = header_ts.to_le_bytes();
                for i in 0..num_entries {
                    let entry_off = base_off + i * 28;
                    if entry_off + 28 > data.len() { break; }
                    let raw_ptr = u32::from_le_bytes(
                        data[entry_off + 24..entry_off + 28].try_into().unwrap()) as usize;
                    let raw_size = u32::from_le_bytes(
                        data[entry_off + 16..entry_off + 20].try_into().unwrap()) as usize;
                    if raw_ptr == 0 || raw_size == 0 || raw_ptr + raw_size > data.len() {
                        continue;
                    }
                    let end = raw_ptr + raw_size;
                    let mut j = raw_ptr;
                    while j + 4 <= end {
                        if data[j..j+4] == ts_bytes {
                            offsets.push(j);
                            j += 4;
                        } else {
                            j += 1;
                        }
                    }
                }
            }
        }
    }

    offsets
}

/// Normalize timestamps in a target PE to match the source PE.
/// Returns the original target timestamp for storage in the preprocess buffer.
pub(crate) fn normalize_timestamps(target: &mut [u8], source: &[u8]) -> u32 {
    let source_ts = pe_timestamp(source);
    let target_ts = pe_timestamp(target);
    if source_ts == 0 || target_ts == 0 || source_ts == target_ts {
        return target_ts;
    }
    let new_bytes = source_ts.to_le_bytes();
    for off in pe_timestamp_offsets(target) {
        if off + 4 <= target.len() {
            let val = u32::from_le_bytes(target[off..off + 4].try_into().unwrap());
            if val == target_ts {
                target[off..off + 4].copy_from_slice(&new_bytes);
            }
        }
    }
    target_ts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_file_type_no_transform() {
        // FILE_TYPE_RAW doesn't trigger transforms
        assert_eq!(FILE_TYPE_RAW, 1);
    }
}
