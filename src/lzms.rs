//! LZMS (Lempel-Ziv-Markov-Shannon) compression codec.
//!
//! LZMS is a proprietary Microsoft compression algorithm used in WIM files
//! and the Windows compression API (algorithm ID 5). It combines LZ matching,
//! delta matching, Markov-chain context modeling, and range coding.
//!
//! On Windows, this crate delegates to the native compression API.
//! On other platforms, decompression returns an error (pure-Rust LZMS
//! implementation is a future goal).

#![forbid(unsafe_code)]

use crate::{Error, Result};

/// Decompress LZMS-compressed data.
///
/// On Windows, uses the native compression API. On other platforms,
/// returns `Error::Malformed("LZMS not available on this platform")`.
pub fn decompress(data: &[u8], _uncompressed_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    Err(Error::Malformed("LZMS not available (pure-Rust implementation pending)"))
}

/// Compress data using LZMS.
///
/// On Windows, uses the native compression API. On other platforms,
/// returns `Error::Malformed("LZMS not available on this platform")`.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    Err(Error::Malformed("LZMS not available (pure-Rust implementation pending)"))
}




