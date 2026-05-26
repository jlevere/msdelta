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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("PA19: input too short")]
    Truncated,
    #[error("PA19: bad magic")]
    BadMagic,
    #[error("PA19: CRC mismatch")]
    CrcMismatch,
    #[error("PA19: {0}")]
    Format(String),
    #[error("PA19: LZX decompression failed: {0}")]
    Lzx(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub const MAGIC: &[u8; 4] = b"PA19";

pub mod header;
pub mod lzx;

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
        return Err(Error::BadMagic);
    }

    let hdr = header::decode(patch)?;

    if old_file.len() != hdr.old_file_size as usize {
        return Err(Error::Format(format!(
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

    // Verify CRC. The header stores the raw CRC register value (ones' complement
    // of the standard finalized CRC32). Our crc32() also returns the raw register.
    let crc = crc32(&new_file);
    if crc != hdr.new_file_crc {
        return Err(Error::CrcMismatch);
    }

    Ok(new_file)
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
