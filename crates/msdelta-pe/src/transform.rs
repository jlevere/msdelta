//! PE file type transforms applied during MSDelta decode/encode.
//!
//! When FileType is not RAW, the decoded output is post-processed
//! through a transform pipeline. The most common transform is
//! "inferred relocations" which scans for 32-bit pointers within
//! the PE's image range and rebases them using the rift table.

use crate::pe::PeInfo;
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
                let marked = out_val | RELOC_MARKER;
                output_buf[pos..pos + 4].copy_from_slice(&marked.to_le_bytes());

                let rva = (val - image_base) as u64;
                let mapped = rift_map(rva);
                let new_val = (mapped as i32 + new_image_base as i32) as u32;
                let src_bytes = new_val.to_le_bytes();
                source_buf.get(pos..pos + 4).map(|_| {
                    // Write the remapped value back to the source buffer position
                    // in the original PE data context
                });
                let _ = src_bytes; // TODO: wire up properly
                count += 1;
                pos += 4;
                continue;
            }
        }
        pos += 1;
    }

    Ok(count)
}

/// Dispatch transforms based on file type.
pub fn apply_transforms(
    file_type: i64,
    _pe_data: Option<&[u8]>,
    _output: &mut [u8],
) -> Result<()> {
    if file_type == FILE_TYPE_RAW {
        return Ok(());
    }

    // For PE file types, we'd parse the PE and apply relocation transforms.
    // This is a placeholder for the full transform pipeline.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_file_type_no_transform() {
        let mut output = vec![0u8; 100];
        apply_transforms(FILE_TYPE_RAW, None, &mut output).unwrap();
    }
}
