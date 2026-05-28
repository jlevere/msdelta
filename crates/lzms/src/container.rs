//! Windows Compression API (cabinet.dll) LZMS container framing.
//!
//! This is the wrapper produced by `Compress()` with `COMPRESS_ALGORITHM_LZMS`
//! and consumed by `Decompress()` / msdelta.dll's `LzmsCodec::Decompress`. The
//! framing lives in cabinet.dll's `CompressOrDecompress`; the inner per-chunk
//! LZMS bitstream is handled by [`super::compress`] / [`super::decompress`].
//!
//! On-disk layout (all integers little-endian):
//!
//! ```text
//! [0x00] u32  magic            = 0xC0E5510A
//! [0x04] u16  header_size      = 0x18 (24); first chunk record starts here
//! [0x06] u8   header_crc       = low byte of CRC-32 over [0..6) then [7..header_size)
//! [0x07] u8   algorithm        = COMPRESS_ALGORITHM_LZMS (5)
//! [0x08] u64  uncompressed_total
//! [0x10] u32  chunk_size       = min(uncompressed_total, 64 MiB)
//! [0x14] u32  flags            = 0; bit 0 selects the chunk-record format
//! [0x18] ... repeated num_chunks times: [u32 compressed_size][compressed_size bytes]
//! ```
//!
//! Each chunk's uncompressed size is implicit: `chunk_size` for every chunk
//! except the last, which carries the remainder. A chunk whose recorded
//! compressed size equals its uncompressed size is stored verbatim (the LZMS
//! encoder never emits a compressed chunk that is not strictly smaller than its
//! input). Every chunk is a fully independent LZMS stream: all coder state
//! resets at each boundary, which falls out naturally from calling the
//! per-chunk codec afresh.

use crate::{compress, decompress, Error, Result};

const MAGIC: u32 = 0xC0E5_510A;
const HEADER_SIZE: usize = 24;
const ALGORITHM_LZMS: u8 = 5;

/// Container chunk size: `min(total, 64 MiB)`. cabinet.dll splits the input
/// into chunks of this many uncompressed bytes (`CompressOrDecompress`).
const MAX_CHUNK: usize = 0x0400_0000;

// --- RtlComputeCrc32: standard reflected CRC-32 (poly 0xEDB88320). Each call
// inverts the incoming seed and the outgoing result (`crc = ~seed; ...; ~crc`),
// so a single call equals the conventional zlib CRC-32 and chaining two spans
// reconstructs one continuous CRC across them. The header CRC uses this to
// cover [0..6) then [7..header_size), skipping its own byte at offset 6. ---

const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// `RtlComputeCrc32(seed, data)` — continue a reflected CRC-32 from `seed`.
fn crc32(seed: u32, data: &[u8]) -> u32 {
    let mut crc = !seed;
    for &b in data {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ b as u32) & 0xFF) as usize];
    }
    !crc
}

/// Low byte of the header CRC: CRC-32 over bytes `[0..6)`, continued over
/// `[7..header_size)`, skipping the CRC byte itself at offset 6.
fn header_crc(header: &[u8]) -> u8 {
    let crc = crc32(0, &header[0..6]);
    let crc = crc32(crc, &header[7..header.len()]);
    crc as u8
}

/// Decompress a Windows Compression API (cabinet.dll) LZMS-wrapped buffer.
///
/// Handles the full multi-chunk container: the input is split into chunks of
/// `chunk_size` uncompressed bytes, each stored either as an independent LZMS
/// stream or verbatim (when incompressible). Decoding stops once the declared
/// `uncompressed_total` has been produced.
pub fn decompress_compression_api(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_SIZE {
        return Err(Error::Malformed("LZMS: compression API buffer too short"));
    }
    if u32::from_le_bytes(data[0..4].try_into().unwrap()) != MAGIC {
        return Err(Error::Malformed("LZMS: bad compression API magic"));
    }

    let header_size = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
    if header_size < HEADER_SIZE || header_size > data.len() {
        return Err(Error::Malformed("LZMS: bad header size"));
    }
    if header_crc(&data[..header_size]) != data[6] {
        return Err(Error::Malformed("LZMS: bad header CRC"));
    }
    if data[7] != ALGORITHM_LZMS {
        return Err(Error::Malformed("LZMS: not an LZMS container"));
    }

    let uncompressed_total = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    if uncompressed_total == 0 {
        return Ok(Vec::new());
    }
    let chunk_size = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(data[20..24].try_into().unwrap());
    if chunk_size == 0 || chunk_size > MAX_CHUNK {
        return Err(Error::Malformed("LZMS: bad chunk size"));
    }
    // The encoder only ever emits mode 0 (bare u32 compressed-size prefix per
    // chunk). Mode 1 (8-byte prefix with an explicit uncompressed size) is not
    // produced by cabinet.dll; reject it rather than guess at the layout.
    if flags & 1 != 0 {
        return Err(Error::Malformed("LZMS: unsupported chunk-record mode"));
    }

    // Reserve generously but never trust `uncompressed_total` blindly: a
    // malformed header can claim terabytes. The Vec still grows as real chunks
    // decode, so a lying total just fails with `Truncated` when input runs out.
    let mut out = Vec::with_capacity(uncompressed_total.min(MAX_CHUNK));
    let mut cursor = header_size;
    while out.len() < uncompressed_total {
        if cursor + 4 > data.len() {
            return Err(Error::Truncated);
        }
        let compressed_size =
            u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if compressed_size == 0 {
            return Err(Error::Malformed("LZMS: zero-length chunk"));
        }
        let chunk_uncompressed = chunk_size.min(uncompressed_total - out.len());
        let chunk_end = cursor
            .checked_add(compressed_size)
            .filter(|&e| e <= data.len())
            .ok_or(Error::Truncated)?;
        let payload = &data[cursor..chunk_end];

        if compressed_size == chunk_uncompressed {
            // Stored verbatim: the chunk was incompressible.
            out.extend_from_slice(payload);
        } else if compressed_size > chunk_uncompressed {
            return Err(Error::Malformed("LZMS: chunk larger than its plaintext"));
        } else {
            let decoded = decompress(payload, chunk_uncompressed)?;
            out.extend_from_slice(&decoded);
        }
        cursor = chunk_end;
    }

    Ok(out)
}

/// Compress data into the Windows Compression API (cabinet.dll) LZMS format.
///
/// Produces a multi-chunk container decodable by [`decompress_compression_api`]
/// and by Windows. Input larger than 64 MiB is split into chunks; each chunk is
/// compressed independently and stored verbatim if it does not shrink.
pub fn compress_compression_api(data: &[u8]) -> Result<Vec<u8>> {
    compress_with_chunk_size(data, MAX_CHUNK)
}

/// Compress with an explicit container chunk size. cabinet.dll always uses
/// `min(total, 64 MiB)`; smaller sizes exist only to exercise the multi-chunk
/// paths in tests without allocating 64 MiB buffers.
///
/// Note: Windows' decoder additionally requires a single chunk (`total ==
/// chunk_size`) when `chunk_size < 0x8000`, so a `chunk_size` below 32 KiB is
/// not generally interoperable for multi-chunk output.
fn compress_with_chunk_size(data: &[u8], max_chunk: usize) -> Result<Vec<u8>> {
    let total = data.len();
    let chunk_size = total.min(max_chunk);

    let mut out = Vec::with_capacity(HEADER_SIZE + total / 2 + 16);
    out.extend_from_slice(&MAGIC.to_le_bytes());
    out.extend_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    out.push(0); // header_crc, filled in below
    out.push(ALGORITHM_LZMS);
    out.extend_from_slice(&(total as u64).to_le_bytes());
    out.extend_from_slice(&(chunk_size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags / mode 0
    debug_assert_eq!(out.len(), HEADER_SIZE);

    if total > 0 {
        for chunk in data.chunks(chunk_size) {
            let compressed = compress(chunk)?;
            let payload: &[u8] = if compressed.len() < chunk.len() {
                &compressed
            } else {
                chunk // incompressible: store verbatim
            };
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(payload);
        }
    }

    out[6] = header_crc(&out[..HEADER_SIZE]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        // Standard reflected CRC-32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32(0, b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn header_crc_matches_real_fixtures() {
        // Header bytes lifted from real cabinet.dll output (tests/fixtures/lzms).
        // (uncompressed_total, chunk_size, expected crc byte)
        let cases: &[(u32, u8)] = &[
            (0x0000_0800, 0xBB), // random.lzms
            (0x0000_0040, 0x4C), // small.lzms
            (0x0000_1000, 0xDA), // zeros.lzms
            (0x0000_0400, 0x2B), // sequential.lzms
        ];
        for &(size, want) in cases {
            let mut h = [0u8; HEADER_SIZE];
            h[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            h[4..6].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
            h[7] = ALGORITHM_LZMS;
            h[8..12].copy_from_slice(&size.to_le_bytes());
            h[16..20].copy_from_slice(&size.to_le_bytes()); // chunk_size == total
            assert_eq!(header_crc(&h), want, "crc mismatch for size {size:#x}");
        }
    }

    #[test]
    fn roundtrip_empty() {
        let wrapped = compress_compression_api(b"").unwrap();
        assert_eq!(decompress_compression_api(&wrapped).unwrap(), b"");
    }

    #[test]
    fn roundtrip_small() {
        let original = b"Compression API wrapper roundtrip with some repetition repetition";
        let wrapped = compress_compression_api(original).unwrap();
        assert_eq!(header_crc(&wrapped[..HEADER_SIZE]), wrapped[6]);
        assert_eq!(decompress_compression_api(&wrapped).unwrap(), original);
    }

    /// Drive the multi-chunk paths with a small chunk size so we cover interior
    /// chunks plus a short remainder last chunk without a 64 MiB buffer.
    #[test]
    fn roundtrip_multichunk_compressible() {
        let chunk = 0x8000usize; // 32 KiB, the smallest interoperable size
        let original: Vec<u8> = (0..chunk * 3 + 1234)
            .map(|i| b"the quick brown fox "[i % 20])
            .collect();
        let wrapped = compress_with_chunk_size(&original, chunk).unwrap();

        // Header must declare our chunk size and produce > 1 record.
        assert_eq!(
            u32::from_le_bytes(wrapped[16..20].try_into().unwrap()) as usize,
            chunk
        );
        assert!(wrapped.len() > HEADER_SIZE);
        assert_eq!(decompress_compression_api(&wrapped).unwrap(), original);
    }

    /// A multi-chunk stream where some chunks are incompressible (stored
    /// verbatim) and others compress — exercises per-chunk passthrough.
    #[test]
    fn roundtrip_multichunk_mixed_passthrough() {
        let chunk = 0x8000usize;
        let mut original = Vec::new();
        // Chunk 0: highly compressible.
        original.extend(std::iter::repeat_n(b'A', chunk));
        // Chunk 1: incompressible (pseudo-random), stored verbatim.
        original.extend((0..chunk).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        // Chunk 2 (last): short, compressible remainder.
        original.extend(std::iter::repeat_n(b'Z', 500));

        let wrapped = compress_with_chunk_size(&original, chunk).unwrap();
        assert_eq!(decompress_compression_api(&wrapped).unwrap(), original);
    }

    #[test]
    fn rejects_corrupt_header() {
        let mut wrapped = compress_compression_api(b"some data to wrap up nicely").unwrap();
        wrapped[6] ^= 0xFF; // clobber the CRC byte
        assert!(matches!(
            decompress_compression_api(&wrapped),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let wrapped =
            compress_compression_api(b"another buffer with repetition repetition").unwrap();
        let truncated = &wrapped[..wrapped.len() - 1];
        assert!(decompress_compression_api(truncated).is_err());
    }

    /// Fuzz regression: a header with a valid CRC but an absurd
    /// `uncompressed_total` must not trigger a giant allocation. It should fail
    /// cleanly (the declared total is unbacked by input).
    #[test]
    fn fuzz_regression_huge_total_no_panic() {
        let crash = [
            0x0a, 0x51, 0xe5, 0xc0, 0x28, 0x00, 0x2c, 0x05, 0xb2, 0xb3, 0x00, 0x00, 0x00, 0x2c,
            0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x00, 0xff, 0xb0,
            0xff, 0x09, 0x00,
        ];
        // Must not panic/abort; result is an error either way.
        assert!(decompress_compression_api(&crash).is_err());
    }
}
