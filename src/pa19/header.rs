//! PA19 patch header decoder.
//!
//! The PA19 header contains patch metadata immediately after the magic.
//! Fields are mostly fixed-width little-endian integers.

use crate::{Error, Result};
use super::PatchHeader;

/// Decode the PA19 patch header.
pub fn decode(patch: &[u8]) -> Result<PatchHeader> {
    if patch.len() < 28 {
        return Err(Error::Truncated);
    }

    let flags = u32_le(patch, 4);
    let old_file_size = u32_le(patch, 8);
    let old_file_crc = u32_le(patch, 12);
    let new_file_size = u32_le(patch, 16);
    let new_file_crc = u32_le(patch, 20);

    // LZX window size is encoded in bits 24-27 of flags, or a separate field
    // The exact layout depends on the patch version flags
    let lzx_window_size = if flags & 4 != 0 {
        // Extended header
        if patch.len() < 32 {
            return Err(Error::Truncated);
        }
        let exp = u32_le(patch, 24);
        if exp > 31 {
            return Err(Error::Pa19(format!("invalid LZX window exponent: {exp}")));
        }
        1u32 << exp
    } else {
        0x20000 // default 128KB window
    };

    let interleave_count = if flags & 8 != 0 {
        if patch.len() < 36 {
            return Err(Error::Truncated);
        }
        u32_le(patch, 28)
    } else {
        0
    };

    Ok(PatchHeader {
        old_file_size,
        old_file_crc,
        new_file_size,
        new_file_crc,
        flags,
        lzx_window_size,
        interleave_count,
    })
}

/// Compute the offset where the LZX data begins (after header + interleave entries).
pub fn header_size(patch: &[u8]) -> Result<usize> {
    let hdr = decode(patch)?;
    let mut offset = 24usize; // magic(4) + flags(4) + sizes(16)

    if hdr.flags & 4 != 0 {
        offset += 4; // window size field
    }
    if hdr.flags & 8 != 0 {
        offset += 4; // interleave count
        offset += hdr.interleave_count as usize * 12; // each entry is 12 bytes
    }

    if offset > patch.len() {
        return Err(Error::Truncated);
    }
    Ok(offset)
}

fn u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}
