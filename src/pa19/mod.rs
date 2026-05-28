//! PA19 legacy binary patch format codec.
//!
//! PA19 is the older Microsoft binary patch format used before PA30.
//! It uses standard Microsoft LZX compression (same as CAB files)
//! with source-byte-addition delta encoding.
//!
//! The format is implemented in `mspatcha.dll` (decoder) and
//! `mspatchc.dll` (encoder) on Windows.
//!
//! Key differences from PA30:
//! - Uses standard LZX (not PseudoLzx)
//! - Simpler header format (no bitstream encoding for header fields)
//! - CRC32 integrity checking (not MD5/SHA)
//! - E8 call instruction transform for x86 code

#![forbid(unsafe_code)]

use crate::{Error, Result};

pub const MAGIC: &[u8; 4] = b"PA19";

pub(crate) mod header;
pub(crate) mod lzx;

/// PA19 patch header.
#[derive(Debug, Clone)]
pub struct PatchHeader {
    /// Size of the old (source) file.
    pub old_file_size: u32,
    /// CRC32 of the old file.
    pub old_file_crc: u32,
    /// Size of the new (target) file.
    pub new_file_size: u32,
    /// Raw CRC32 register value of the new file (before final XOR with 0xFFFFFFFF).
    pub new_file_crc: u32,
    /// Flags controlling patch application.
    pub flags: u32,
    /// LZX window size for decompression.
    pub lzx_window_size: u32,
    /// Number of interleave entries.
    pub interleave_count: u32,
}

/// Apply a PA19 patch to produce the new file from old file + patch data.
pub fn apply(old_file: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    if patch.len() < 4 || &patch[..4] != MAGIC {
        return Err(Error::Malformed("PA19: bad magic"));
    }

    let hdr = header::decode(patch)?;

    if old_file.len() != hdr.old_file_size as usize {
        return Err(Error::Pa19(format!(
            "old file size mismatch: expected {}, got {}",
            hdr.old_file_size,
            old_file.len()
        )));
    }

    // The LZX-compressed delta data starts after the header
    let delta_offset = header::header_size(patch)?;
    let lzx_data = &patch[delta_offset..];

    // Decompress using LZX
    let new_file = lzx::decompress_delta(
        old_file,
        lzx_data,
        hdr.new_file_size as usize,
        hdr.lzx_window_size,
    )?;

    let mut new_file = new_file;
    if hdr.flags & 2 != 0 {
        e8_transform_decode(&mut new_file);
    }

    let crc = crc32(&new_file);
    if crc != hdr.new_file_crc {
        return Err(Error::Malformed("PA19: CRC mismatch"));
    }

    Ok(new_file)
}

/// Reverse the E8 (CALL relative) instruction transform applied during PA19 compression.
///
/// Standard LZX E8 processing: for each 0xE8 byte in the first 32KB, the following
/// 4-byte relative offset is converted from absolute to relative form.
fn e8_transform_decode(data: &mut [u8]) {
    let file_size = data.len() as i32;
    let limit = data.len().min(32768);
    let mut i = 0;
    while i + 5 <= limit {
        if data[i] == 0xE8 {
            let abs_offset = i32::from_le_bytes(data[i + 1..i + 5].try_into().unwrap());
            let rel_offset = if abs_offset >= 0 && abs_offset < file_size {
                abs_offset - i as i32
            } else if abs_offset.wrapping_neg() <= i as i32 {
                abs_offset + file_size
            } else {
                i += 1;
                continue;
            };
            data[i + 1..i + 5].copy_from_slice(&rel_offset.to_le_bytes());
            i += 5;
        } else {
            i += 1;
        }
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_value() {
        let data = b"Hello, World!";
        let crc = crc32(data);
        // Our crc32 returns the raw register (no final XOR).
        // Standard CRC32 of "Hello, World!" = 0xEC4AC3D0
        // Raw register = !0xEC4AC3D0 = 0x13B53C2F
        assert_eq!(!crc, 0xEC4AC3D0);
    }

    #[test]
    fn detect_pa19_magic() {
        let data = b"PA19rest";
        assert_eq!(&data[..4], MAGIC);
    }
}
