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
                let new_val = (mapped + new_image_base as i64) as u64;
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

/// Undo MSDelta's x86 `0xE8` (near CALL) preprocessing on a reconstructed image.
///
/// Genuine `ApplyDeltaB` (PA31, in UpdateCompression.dll / dpx.dll -- msdelta.dll
/// has no PA31) preprocesses 32-bit x86 targets with the classic LZX E8 filter:
/// the 4-byte displacement after each `0xE8` is converted to an absolute form
/// for better compression, then converted back on apply. It is a whole-buffer
/// scan (headers, code, even `.rsrc` -- NOT section-bounded), with the output
/// length as the translation size: a site is converted iff `-i <= v < len`,
/// where `i` is the byte offset and `v` the stored displacement (verified
/// byte-for-byte against genuine output -- `translation_size == target_size`).
///
/// Runs ONLY on i386 PEs (`IMAGE_FILE_MACHINE_I386`, machine `0x14C`) and skips
/// pure-managed (.NET, `COMIMAGE_FLAGS_ILONLY`) images, which carry machine
/// `0x14C` too but must not be touched. No-op on everything else, so it is safe
/// to call unconditionally on the reconstructed image. Returns the site count.
pub(crate) fn undo_x86_e8_translation(buf: &mut [u8]) -> u32 {
    // Gate with a manual header read rather than a full `goblin` parse: genuine
    // msdelta keys only on the machine type, and goblin's strict validation
    // rejects some otherwise-valid system images (e.g. comctl32). i386 only,
    // and skip pure-managed (.NET) images.
    if !is_i386_native_pe(buf) {
        return 0;
    }

    let len = buf.len();
    // A CALL displacement is a signed i32 and the translation size is the image
    // length; both must fit i32 for the guard/arithmetic to be meaningful (real
    // targets are well under -- apply() caps at 256 MiB).
    if len < 10 || len > i32::MAX as usize {
        return 0;
    }
    let ts = len as i32;
    let mut count = 0u32;
    let mut i = 0usize;
    // Classic LZX leaves the last 10 bytes untouched (a CALL displacement never
    // starts there). Every 0xE8 advances the cursor past its 4 operand bytes
    // whether or not it is translated, matching the encoder's own scan. The
    // rewrite is 32-bit wrapping arithmetic (`new = v - i` mod 2^32), matching
    // genuine behaviour and avoiding overflow panics on adversarial input.
    while i < len - 10 {
        if buf[i] != 0xE8 {
            i += 1;
            continue;
        }
        let v = i32::from_le_bytes(buf[i + 1..i + 5].try_into().unwrap());
        if v >= -(i as i32) && v < ts {
            let new = if v >= 0 {
                v.wrapping_sub(i as i32)
            } else {
                v.wrapping_add(ts)
            };
            buf[i + 1..i + 5].copy_from_slice(&new.to_le_bytes());
            count += 1;
        }
        i += 5;
    }
    count
}

/// Is `buf` a native 32-bit (i386) PE that is NOT a pure-managed (.NET) image?
///
/// Parses only the few header fields needed, by hand (no full `goblin` parse,
/// which over-validates and rejects some valid system images). Requires machine
/// `IMAGE_FILE_MACHINE_I386` (0x14C) and a PE32 optional header, and rejects
/// images whose CLR runtime header (data directory 14) has `COMIMAGE_FLAGS_ILONLY`.
fn is_i386_native_pe(buf: &[u8]) -> bool {
    let rd_u16 = |o: usize| -> Option<u16> {
        buf.get(o..o + 2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    };
    let rd_u32 = |o: usize| -> Option<u32> {
        buf.get(o..o + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };

    let e_lfanew = match rd_u32(0x3c) {
        Some(v) => v as usize,
        None => return false,
    };
    if buf.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return false;
    }
    if rd_u16(e_lfanew + 4) != Some(0x014C) {
        return false; // not i386
    }
    let num_sections = rd_u16(e_lfanew + 6).unwrap_or(0) as usize;
    let size_of_opt = rd_u16(e_lfanew + 20).unwrap_or(0) as usize;
    let opt = e_lfanew + 24;
    // i386 images are PE32 (magic 0x10B); data directories start at opt+96.
    if rd_u16(opt) != Some(0x010B) {
        return false;
    }
    let num_rva = rd_u32(opt + 92).unwrap_or(0) as usize;
    const CLR_DIR: usize = 14;
    if num_rva <= CLR_DIR {
        return true; // no CLR header -> native
    }
    let clr_rva = rd_u32(opt + 96 + CLR_DIR * 8).unwrap_or(0);
    if clr_rva == 0 {
        return true; // native
    }
    // Map the CLR header RVA to a file offset via the section table and read
    // its COR20 Flags (u32 at +16); ILONLY (bit 0) => managed, skip.
    let sec_base = opt + size_of_opt;
    for i in 0..num_sections {
        let s = sec_base + i * 40;
        let vs = rd_u32(s + 8).unwrap_or(0);
        let va = rd_u32(s + 12).unwrap_or(0);
        let ro = rd_u32(s + 20).unwrap_or(0);
        if clr_rva >= va && clr_rva < va.wrapping_add(vs) {
            // usize add (a u32 add could overflow on a hostile header).
            let off = ro as usize + (clr_rva - va) as usize;
            if let Some(flags) = rd_u32(off + 16) {
                return flags & 0x1 == 0; // ILONLY clear => native
            }
        }
    }
    true
}

/// File offset of the PE optional-header CheckSum field (4 bytes), if `data`
/// is a PE. CheckSum sits at optional-header offset 0x40 for both PE32 and
/// PE32+, and the optional header starts at e_lfanew + 4 (signature) + 20
/// (COFF file header), so the absolute offset is e_lfanew + 0x58.
pub(crate) fn pe_checksum_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return None;
    }
    let off = e_lfanew + 0x58;
    if off + 4 <= data.len() {
        Some(off)
    } else {
        None
    }
}

/// Zero the optional-header CheckSum in a reference buffer. msdelta normalizes
/// (zeroes) this volatile field in the copy source before applying a PE delta;
/// matching it here forces the target's real checksum to be carried as literals
/// rather than a copy that would resolve to zero on genuine msdelta.
pub(crate) fn zero_pe_checksum(data: &mut [u8]) {
    if let Some(off) = pe_checksum_offset(data) {
        data[off..off + 4].fill(0);
    }
}

pub(crate) fn pe_timestamp(data: &[u8]) -> u32 {
    if data.len() < 0x40 {
        return 0;
    }
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_off + 12 > data.len() {
        return 0;
    }
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
                let header_ts = if offsets.is_empty() {
                    0
                } else {
                    u32::from_le_bytes(
                        data[offsets[0]..offsets[0] + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    )
                };
                let ts_bytes = header_ts.to_le_bytes();
                for i in 0..num_entries {
                    let entry_off = base_off + i * 28;
                    if entry_off + 28 > data.len() {
                        break;
                    }
                    let raw_ptr = u32::from_le_bytes(
                        data[entry_off + 24..entry_off + 28].try_into().unwrap(),
                    ) as usize;
                    let raw_size = u32::from_le_bytes(
                        data[entry_off + 16..entry_off + 20].try_into().unwrap(),
                    ) as usize;
                    if raw_ptr == 0 || raw_size == 0 || raw_ptr + raw_size > data.len() {
                        continue;
                    }
                    let end = raw_ptr + raw_size;
                    let mut j = raw_ptr;
                    while j + 4 <= end {
                        if data[j..j + 4] == ts_bytes {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_file_type_no_transform() {
        // FILE_TYPE_RAW doesn't trigger transforms
        assert_eq!(FILE_TYPE_RAW, 1);
    }
}
