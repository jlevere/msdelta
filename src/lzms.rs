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
pub fn decompress(data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    #[cfg(windows)]
    {
        decompress_windows(data, uncompressed_size)
    }

    #[cfg(not(windows))]
    {
        let _ = uncompressed_size;
        Err(Error::Malformed("LZMS not available on this platform"))
    }
}

/// Compress data using LZMS.
///
/// On Windows, uses the native compression API. On other platforms,
/// returns `Error::Malformed("LZMS not available on this platform")`.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    #[cfg(windows)]
    {
        compress_windows(data)
    }

    #[cfg(not(windows))]
    {
        Err(Error::Malformed("LZMS not available on this platform"))
    }
}

#[cfg(windows)]
fn decompress_windows(data: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    use windows::Win32::Storage::Compression::*;

    let mut handle = COMPRESSOR_HANDLE::default();
    let ok = unsafe {
        CreateDecompressor(COMPRESS_ALGORITHM_LZMS, None, &mut handle)
    };
    if !ok.as_bool() {
        return Err(Error::Malformed("LZMS CreateDecompressor failed"));
    }

    let mut output = vec![0u8; uncompressed_size];
    let mut actual_size = 0usize;
    let ok = unsafe {
        Decompress(
            handle,
            Some(data),
            Some(&mut output),
            Some(&mut actual_size),
        )
    };

    unsafe { CloseDecompressor(handle) };

    if !ok.as_bool() {
        return Err(Error::Malformed("LZMS Decompress failed"));
    }

    output.truncate(actual_size);
    Ok(output)
}

#[cfg(windows)]
fn compress_windows(data: &[u8]) -> Result<Vec<u8>> {
    use windows::Win32::Storage::Compression::*;

    let mut handle = COMPRESSOR_HANDLE::default();
    let ok = unsafe {
        CreateCompressor(COMPRESS_ALGORITHM_LZMS, None, &mut handle)
    };
    if !ok.as_bool() {
        return Err(Error::Malformed("LZMS CreateCompressor failed"));
    }

    // First call to get size
    let mut compressed_size = 0usize;
    unsafe {
        Compress(handle, Some(data), None, &mut compressed_size);
    };

    let mut output = vec![0u8; compressed_size];
    let mut actual_size = 0usize;
    let ok = unsafe {
        Compress(
            handle,
            Some(data),
            Some(&mut output),
            &mut actual_size,
        )
    };

    unsafe { CloseCompressor(handle) };

    if !ok.as_bool() {
        return Err(Error::Malformed("LZMS Compress failed"));
    }

    output.truncate(actual_size);
    Ok(output)
}
