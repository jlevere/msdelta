//! Microsoft LZX delta decompression for PA19 patches.
//!
//! Uses the `lzxd` crate which implements the LZXD (LZX Delta) variant
//! used in Microsoft's binary patch format.

use crate::{Error, Result};

/// Decompress a PA19 LZX delta and apply it to the source.
///
/// The LZX-compressed data decompresses to the target file directly,
/// using the source (old file) as the reference window.
pub fn decompress_delta(
    _source: &[u8],
    lzx_data: &[u8],
    target_size: usize,
    window_size: u32,
) -> Result<Vec<u8>> {
    if lzx_data.is_empty() {
        if target_size == 0 {
            return Ok(Vec::new());
        }
        return Err(Error::Pa19("empty LZX data for non-zero target".into()));
    }

    let ws = match window_size {
        0x8000 => lzxd::WindowSize::KB32,
        0x10000 => lzxd::WindowSize::KB64,
        0x20000 => lzxd::WindowSize::KB128,
        other => {
            return Err(Error::Pa19(format!(
                "unsupported LZX window size: {other:#x}"
            )));
        }
    };
    let mut decoder = lzxd::Lzxd::new(ws);

    let result = decoder
        .decompress_next(lzx_data, target_size)
        .map_err(|e| Error::Pa19(format!("LZX decode: {e}")))?;

    Ok(result.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_empty_output() {
        let result = decompress_delta(&[], &[], 0, 0x20000);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn empty_input_nonzero_target_errors() {
        let result = decompress_delta(&[], &[], 100, 0x20000);
        assert!(result.is_err());
    }
}
