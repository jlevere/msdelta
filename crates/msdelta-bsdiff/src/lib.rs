//! BsDiff binary delta codec for MSDelta's PlaybackReverse path.
//!
//! This is a custom bsdiff variant used when FileTypeSet has bit 0x100.
//! The patch format uses 3-tuple blocks: (add_length, insert_length, seek_distance).
//! The patch data may be LZMS-compressed before being passed to bspatch.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("bspatch error: {0}")]
    Patch(&'static str),
    #[error("bspatch: unexpected end of patch data")]
    Truncated,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Apply a bsdiff patch to produce the target from source + patch data.
///
/// The patch data is a stream of 3-tuple blocks:
/// - 3x 8-byte signed integers: (add_length, insert_length, seek_distance)
/// - `add_length` bytes of diff data (added to source bytes)
/// - `insert_length` bytes of literal data (inserted directly)
///
/// The seek_distance advances the source pointer for the next block.
pub fn bspatch(source: &[u8], target_size: usize, patch_data: &[u8]) -> Result<Vec<u8>> {
    let mut target = vec![0u8; target_size];
    let mut patch_pos: usize = 0;
    let mut old_pos: i64 = 0;
    let mut new_pos: usize = 0;

    while new_pos < target_size {
        // Read 3 control values (8 bytes each, signed)
        if patch_pos + 24 > patch_data.len() {
            return Err(Error::Truncated);
        }

        let add_len = read_i64(&patch_data[patch_pos..])? as usize;
        patch_pos += 8;
        let insert_len = read_i64(&patch_data[patch_pos..])? as usize;
        patch_pos += 8;
        let seek_dist = read_i64(&patch_data[patch_pos..])?;
        patch_pos += 8;

        if add_len > 0x7FFFFFFF || insert_len > 0x7FFFFFFF {
            return Err(Error::Patch("control value too large"));
        }
        if new_pos + add_len > target_size {
            return Err(Error::Patch("add_len exceeds target size"));
        }

        // Read add_len bytes of diff data
        if patch_pos + add_len > patch_data.len() {
            return Err(Error::Truncated);
        }
        for i in 0..add_len {
            let src_idx = old_pos + i as i64;
            let src_byte = if src_idx >= 0 && (src_idx as usize) < source.len() {
                source[src_idx as usize]
            } else {
                0
            };
            target[new_pos + i] = patch_data[patch_pos + i].wrapping_add(src_byte);
        }
        patch_pos += add_len;
        new_pos += add_len;

        // Read insert_len bytes of literal data
        if new_pos + insert_len > target_size {
            return Err(Error::Patch("insert_len exceeds target size"));
        }
        if patch_pos + insert_len > patch_data.len() {
            return Err(Error::Truncated);
        }
        target[new_pos..new_pos + insert_len]
            .copy_from_slice(&patch_data[patch_pos..patch_pos + insert_len]);
        patch_pos += insert_len;
        new_pos += insert_len;

        old_pos += seek_dist + add_len as i64;
    }

    Ok(target)
}

/// Read a signed 64-bit integer in bsdiff encoding.
///
/// 8 bytes, little-endian magnitude with sign in high bit of last byte (byte[7]).
fn read_i64(data: &[u8]) -> Result<i64> {
    if data.len() < 8 {
        return Err(Error::Truncated);
    }
    let sign = data[7] & 0x80 != 0;
    let magnitude = ((data[7] as u64 & 0x7F) << 48)
        | ((data[6] as u64) << 40)
        | ((data[5] as u64) << 32)
        | ((data[4] as u64) << 24)
        | ((data[3] as u64) << 16)
        | ((data[2] as u64) << 8)
        | (data[1] as u64);
    // Byte 0 is the LSB
    let val = magnitude * 256 + data[0] as u64;
    Ok(if sign { -(val as i64) } else { val as i64 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bspatch_identity() {
        // Patch that copies source unchanged
        let source = b"Hello World";
        let target_size = source.len();

        // Control: add_len=11, insert_len=0, seek_dist=0
        // Diff: 11 zero bytes (add 0 to each source byte)
        let mut patch = Vec::new();
        patch.extend_from_slice(&encode_i64(11));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&[0u8; 11]); // diff = zeros

        let result = bspatch(source, target_size, &patch).unwrap();
        assert_eq!(result, source);
    }

    #[test]
    fn bspatch_modify_one_byte() {
        let source = b"Hello World";
        let target_size = source.len();

        // Change byte 5 from ' ' to '-'
        let mut patch = Vec::new();
        patch.extend_from_slice(&encode_i64(11));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&encode_i64(0));
        let mut diff = vec![0u8; 11];
        diff[5] = b'-'.wrapping_sub(b' '); // diff for the changed byte
        patch.extend_from_slice(&diff);

        let result = bspatch(source, target_size, &patch).unwrap();
        assert_eq!(result, b"Hello-World");
    }

    #[test]
    fn bspatch_insert_data() {
        let source = b"AB";
        let target_size = 5;

        // Block 1: add_len=2 (copy source), insert_len=3 (insert "XYZ"), seek=0
        let mut patch = Vec::new();
        patch.extend_from_slice(&encode_i64(2));
        patch.extend_from_slice(&encode_i64(3));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&[0, 0]); // diff = zeros (copy AB)
        patch.extend_from_slice(b"XYZ"); // insert

        let result = bspatch(source, target_size, &patch).unwrap();
        assert_eq!(result, b"ABXYZ");
    }

    fn encode_i64(val: i64) -> [u8; 8] {
        let (magnitude, sign) = if val < 0 {
            ((-val) as u64, true)
        } else {
            (val as u64, false)
        };
        let mut buf = [0u8; 8];
        buf[0] = (magnitude & 0xFF) as u8;
        buf[1] = ((magnitude >> 8) & 0xFF) as u8;
        buf[2] = ((magnitude >> 16) & 0xFF) as u8;
        buf[3] = ((magnitude >> 24) & 0xFF) as u8;
        buf[4] = ((magnitude >> 32) & 0xFF) as u8;
        buf[5] = ((magnitude >> 40) & 0xFF) as u8;
        buf[6] = ((magnitude >> 48) & 0xFF) as u8;
        buf[7] = ((magnitude >> 56) & 0x7F) as u8;
        if sign {
            buf[7] |= 0x80;
        }
        buf
    }
}
