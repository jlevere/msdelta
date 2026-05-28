//! PseudoLzx compressor and decompressor for PA30 patches.
//!
//! Not standard LZX or LZX Delta. Key differences:
//! - Left-leaning canonical Huffman codes
//! - 3-element LRU queue for recent offsets
//! - Rift-table-aware source-window copies
//!
//! PDB-confirmed class names: `Decompressor`, `CompositeFormat`, `CompressionFormat`,
//! `CompressionLengths`, `RiftTable`, `OffsetRiftTable`.

pub mod ops;
pub mod rift;
mod format;
mod decode;
mod encode;

use self::rift::RiftTable;
use crate::Result;

/// Decompress a PseudoLzx patch.
pub fn decompress(reference: &[u8], patch_data: &[u8], target_size: usize) -> Result<Vec<u8>> {
    decompress_with_rift(reference, patch_data, target_size, None)
}

/// Decompress with an optional caller-provided rift table (from PE preprocessing).
pub fn decompress_with_rift(
    reference: &[u8],
    patch_data: &[u8],
    target_size: usize,
    caller_rift: Option<&RiftTable>,
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(target_size);
    decode::decompress_into(reference, patch_data, target_size, caller_rift, &mut output)?;
    Ok(output)
}

/// Like `decompress`, but returns partial output on error for debugging.
pub fn decompress_partial(
    reference: &[u8],
    patch_data: &[u8],
    target_size: usize,
) -> (Vec<u8>, Option<crate::Error>) {
    let mut output = Vec::new();
    match decode::decompress_into(reference, patch_data, target_size, None, &mut output) {
        Ok(()) => (output, None),
        Err(e) => (output, Some(e)),
    }
}

/// Compress `target` as a PseudoLzx patch against `reference`.
///
/// Produces a bitstream that `decompress` (and msdelta.dll) can decode.
pub fn compress(reference: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    encode::compress_inner(reference, target, None)
}

/// Compress with a rift table embedded in the patch bitstream.
pub fn compress_with_rift(reference: &[u8], target: &[u8], rift: &RiftTable) -> Result<Vec<u8>> {
    encode::compress_inner(reference, target, Some(rift))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitstream::{BitReader, BitWriter};
    use self::format::{flat_code_lengths, SegmentTables, SOURCE_COPY, LRU_BASE};
    use self::ops::RAW_OFFSET_BASE;

    #[test]
    fn encode_decode_match_source_copy() {
        let tables = SegmentTables::from_flat().unwrap();
        let mut w = BitWriter::new();
        w.write_bits(0, 1); // rift
        w.write_bits(1, 1); // simple mode
        encode::encode_match(&tables, &mut w, SOURCE_COPY, 30).unwrap();
        let data = w.finish();

        let mut r = BitReader::new(&data).unwrap();
        r.read_bits(1).unwrap(); // rift
        r.read_bits(1).unwrap(); // simple
        let (off, len) = decode::read_symbol(&tables, &mut r).unwrap();
        assert_eq!(off, SOURCE_COPY);
        assert_eq!(len, 30);
    }

    #[test]
    fn encode_decode_match_lru() {
        let tables = SegmentTables::from_flat().unwrap();
        for lru_idx in 0..3u32 {
            let mut w = BitWriter::new();
            w.write_bits(0, 2);
            encode::encode_match(&tables, &mut w, LRU_BASE + lru_idx, 5).unwrap();
            let data = w.finish();
            let mut r = BitReader::new(&data).unwrap();
            r.read_bits(2).unwrap();
            let (off, len) = decode::read_symbol(&tables, &mut r).unwrap();
            assert_eq!(off, LRU_BASE + lru_idx, "LRU {lru_idx}");
            assert_eq!(len, 5);
        }
    }

    #[test]
    fn encode_decode_match_small_dist() {
        let tables = SegmentTables::from_flat().unwrap();
        for dist in [1u32, 2, 3, 4, 5, 10, 15, 20, 31] {
            let raw_off = dist + RAW_OFFSET_BASE;
            let mut w = BitWriter::new();
            w.write_bits(0, 2);
            encode::encode_match(&tables, &mut w, raw_off, 3).unwrap();
            let data = w.finish();
            let mut r = BitReader::new(&data).unwrap();
            r.read_bits(2).unwrap();
            let (got_off, got_len) = decode::read_symbol(&tables, &mut r).unwrap();
            assert_eq!(got_off, raw_off, "dist={dist}: offset mismatch");
            assert_eq!(got_len, 3, "dist={dist}: length mismatch");
        }
    }

    #[test]
    fn encode_decode_match_medium_dist() {
        let tables = SegmentTables::from_flat().unwrap();
        for dist in [32u32, 47, 48, 63, 64, 100, 127, 200, 500, 1000, 5000, 9000] {
            let raw_off = dist + RAW_OFFSET_BASE;
            let mut w = BitWriter::new();
            w.write_bits(0, 2);
            let result = encode::encode_match(&tables, &mut w, raw_off, 3);
            if let Err(e) = result {
                panic!("encode failed for dist={dist}: {e}");
            }
            let data = w.finish();
            let mut r = BitReader::new(&data).unwrap();
            r.read_bits(2).unwrap();
            let (got_off, got_len) = decode::read_symbol(&tables, &mut r).unwrap();
            assert_eq!(got_off, raw_off, "dist={dist}: offset mismatch");
            assert_eq!(got_len, 3, "dist={dist}: length mismatch");
        }
    }

    #[test]
    fn flat_codes_256() {
        let lengths = flat_code_lengths(256);
        assert_eq!(lengths.len(), 256);
        assert!(lengths.iter().all(|&l| l == 8));
    }

    #[test]
    fn flat_codes_600() {
        let lengths = flat_code_lengths(600);
        assert_eq!(lengths.len(), 600);
        let short = lengths.iter().filter(|&&l| l == 9).count();
        let long = lengths.iter().filter(|&&l| l == 10).count();
        assert_eq!(short, 424);
        assert_eq!(long, 176);
    }

    #[test]
    fn flat_codes_16() {
        let lengths = flat_code_lengths(16);
        assert_eq!(lengths.len(), 16);
        assert!(lengths.iter().all(|&l| l == 4));
    }
}
