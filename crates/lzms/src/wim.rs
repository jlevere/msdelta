//! WIM LZMS resource framing — both the non-solid and solid layouts.
//!
//! LZMS appears in WIM/ESD files in two distinct framings, both wrapping the
//! same per-chunk LZMS bitstream ([`crate::compress`] / [`crate::decompress`])
//! and both independent of the self-describing Compression API container
//! ([`crate::container`]):
//!
//! - **Non-solid** ([`decompress_wim`] / [`compress_wim`]): a chunk-*offset*
//!   table of `N-1` entries followed by the chunk data. The chunk size and
//!   total uncompressed size live in WIM metadata outside the resource. This is
//!   what `wimlib --compress=LZMS` emits.
//! - **Solid** ([`decompress_wim_solid`] / [`compress_wim_solid`]): a 16-byte
//!   header (uncompressed size, chunk size, compression format) followed by a
//!   chunk-*size* table of `N` entries and the chunk data. This is what
//!   Microsoft's `DISM /Compress:recovery` (and wimgapi solid/ESD export)
//!   produces. The layout here was reverse-engineered from genuine
//!   `wimgapi.dll` output (Windows Server 2025) and is validated byte-for-byte
//!   against it in the tests.
//!
//! In both framings every chunk is an independent LZMS stream, so all coder
//! state resets at each boundary — automatic here since each chunk is a
//! separate codec call. A chunk whose on-disk length equals its uncompressed
//! length is stored verbatim (the encoder's incompressible fallback).

use crate::{compress, decompress, Error, Result};

/// Compression-format id used in the solid-resource header (the value
/// Microsoft writes for LZMS).
const SOLID_FORMAT_LZMS: u32 = 3;

/// Last-chunk uncompressed length: the remainder, or a full chunk when the
/// total divides evenly.
fn last_chunk_len(uncompressed_size: usize, chunk_size: usize) -> usize {
    let rem = uncompressed_size % chunk_size;
    if rem == 0 {
        chunk_size
    } else {
        rem
    }
}

/// Expand one on-disk chunk into `out`. `chunk` is the raw bytes; `out_len` is
/// its uncompressed length. A chunk stored verbatim (`chunk.len() == out_len`)
/// is copied; otherwise it is LZMS-decoded.
fn expand_chunk(chunk: &[u8], out_len: usize, out: &mut Vec<u8>) -> Result<()> {
    if chunk.len() == out_len {
        out.extend_from_slice(chunk);
    } else if chunk.len() > out_len {
        return Err(Error::Malformed(
            "LZMS: WIM chunk larger than its plaintext",
        ));
    } else {
        out.extend_from_slice(&decompress(chunk, out_len)?);
    }
    Ok(())
}

/// Compress one chunk for a WIM resource, returning the bytes to store: the
/// LZMS stream if it shrinks, otherwise the verbatim chunk.
fn compress_chunk(chunk: &[u8]) -> Result<Vec<u8>> {
    let compressed = compress(chunk)?;
    if compressed.len() < chunk.len() {
        Ok(compressed)
    } else {
        Ok(chunk.to_vec())
    }
}

// --- Non-solid framing: chunk-offset table -------------------------------

/// Decompress a non-solid WIM LZMS resource (chunk-offset table + chunks).
///
/// `resource` is the raw on-disk resource bytes; `chunk_size` and
/// `uncompressed_size` come from the WIM header and the resource's blob-table
/// entry. Table entries are 4 bytes, or 8 if the resource is >= 4 GiB on disk,
/// matching wimlib's reader.
pub fn decompress_wim(
    resource: &[u8],
    chunk_size: usize,
    uncompressed_size: usize,
) -> Result<Vec<u8>> {
    if uncompressed_size == 0 {
        return Ok(Vec::new());
    }
    if chunk_size == 0 {
        return Err(Error::Malformed("LZMS: WIM chunk size is zero"));
    }

    let num_chunks = uncompressed_size.div_ceil(chunk_size);
    let entry_bytes = if resource.len() >= (1usize << 32) {
        8
    } else {
        4
    };
    let table_bytes = (num_chunks - 1) * entry_bytes;
    if table_bytes > resource.len() {
        return Err(Error::Malformed("LZMS: WIM chunk table doesn't fit"));
    }

    let (table, chunk_data) = resource.split_at(table_bytes);

    let mut offsets = Vec::with_capacity(num_chunks + 1);
    offsets.push(0usize);
    for i in 0..num_chunks - 1 {
        let off = if entry_bytes == 8 {
            u64::from_le_bytes(table[i * 8..i * 8 + 8].try_into().unwrap()) as usize
        } else {
            u32::from_le_bytes(table[i * 4..i * 4 + 4].try_into().unwrap()) as usize
        };
        offsets.push(off);
    }
    offsets.push(chunk_data.len());

    let mut out = Vec::with_capacity(uncompressed_size);
    for i in 0..num_chunks {
        let start = offsets[i];
        let end = offsets[i + 1];
        if end < start || end > chunk_data.len() {
            return Err(Error::Malformed("LZMS: bad WIM chunk offset"));
        }
        let out_len = if i + 1 < num_chunks {
            chunk_size
        } else {
            last_chunk_len(uncompressed_size, chunk_size)
        };
        expand_chunk(&chunk_data[start..end], out_len, &mut out)?;
    }

    Ok(out)
}

/// Compress data into a non-solid WIM LZMS resource (chunk-offset table +
/// chunks) using the given `chunk_size`. Decodable by [`decompress_wim`] with
/// the same `chunk_size` and an `uncompressed_size` of `data.len()`.
pub fn compress_wim(data: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
    if chunk_size == 0 {
        return Err(Error::Malformed("LZMS: WIM chunk size is zero"));
    }
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let num_chunks = data.len().div_ceil(chunk_size);
    let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(num_chunks);
    for chunk in data.chunks(chunk_size) {
        payloads.push(compress_chunk(chunk)?);
    }

    let data_bytes: usize = payloads.iter().map(Vec::len).sum();
    let mut entry_bytes = 4;
    if (num_chunks - 1) * entry_bytes + data_bytes >= (1usize << 32) {
        entry_bytes = 8;
    }

    let mut out = Vec::with_capacity((num_chunks - 1) * entry_bytes + data_bytes);
    let mut cumulative = 0usize;
    for payload in &payloads[..num_chunks - 1] {
        cumulative += payload.len();
        if entry_bytes == 8 {
            out.extend_from_slice(&(cumulative as u64).to_le_bytes());
        } else {
            out.extend_from_slice(&(cumulative as u32).to_le_bytes());
        }
    }
    for payload in &payloads {
        out.extend_from_slice(payload);
    }

    Ok(out)
}

// --- Solid framing: 16-byte header + chunk-size table --------------------

const SOLID_HEADER_SIZE: usize = 16;

/// Decompress a solid WIM LZMS resource (the `DISM /Compress:recovery` / ESD
/// layout). The resource is self-describing:
///
/// ```text
/// [u64 uncompressed_size][u32 chunk_size][u32 format=3]   16-byte header
/// [u32 compressed_size] * num_chunks                       chunk-size table
/// [chunk 0][chunk 1] ... [chunk N-1]                       concatenated data
/// ```
///
/// `num_chunks = ceil(uncompressed_size / chunk_size)`.
pub fn decompress_wim_solid(resource: &[u8]) -> Result<Vec<u8>> {
    if resource.len() < SOLID_HEADER_SIZE {
        return Err(Error::Malformed("LZMS: solid resource too short"));
    }
    let uncompressed_size = u64::from_le_bytes(resource[0..8].try_into().unwrap()) as usize;
    let chunk_size = u32::from_le_bytes(resource[8..12].try_into().unwrap()) as usize;
    let format = u32::from_le_bytes(resource[12..16].try_into().unwrap());
    if format != SOLID_FORMAT_LZMS {
        return Err(Error::Malformed("LZMS: solid resource is not LZMS"));
    }
    if uncompressed_size == 0 {
        return Ok(Vec::new());
    }
    if chunk_size == 0 {
        return Err(Error::Malformed("LZMS: solid chunk size is zero"));
    }

    let num_chunks = uncompressed_size.div_ceil(chunk_size);
    let table_bytes = num_chunks
        .checked_mul(4)
        .ok_or(Error::Malformed("LZMS: solid chunk count overflow"))?;
    let data_start = SOLID_HEADER_SIZE
        .checked_add(table_bytes)
        .filter(|&s| s <= resource.len())
        .ok_or(Error::Malformed("LZMS: solid chunk table doesn't fit"))?;

    let table = &resource[SOLID_HEADER_SIZE..data_start];
    let chunk_data = &resource[data_start..];

    let mut out = Vec::with_capacity(uncompressed_size);
    let mut cursor = 0usize;
    for i in 0..num_chunks {
        let compressed_size =
            u32::from_le_bytes(table[i * 4..i * 4 + 4].try_into().unwrap()) as usize;
        let end = cursor
            .checked_add(compressed_size)
            .filter(|&e| e <= chunk_data.len())
            .ok_or(Error::Truncated)?;
        let out_len = if i + 1 < num_chunks {
            chunk_size
        } else {
            last_chunk_len(uncompressed_size, chunk_size)
        };
        expand_chunk(&chunk_data[cursor..end], out_len, &mut out)?;
        cursor = end;
    }

    Ok(out)
}

/// Compress data into a solid WIM LZMS resource using the given `chunk_size`
/// (Microsoft uses 64 MiB). Produces the self-describing layout read by
/// [`decompress_wim_solid`].
pub fn compress_wim_solid(data: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
    if chunk_size == 0 {
        return Err(Error::Malformed("LZMS: solid chunk size is zero"));
    }

    let mut out = Vec::with_capacity(SOLID_HEADER_SIZE + data.len() / 2 + 16);
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&(chunk_size as u32).to_le_bytes());
    out.extend_from_slice(&SOLID_FORMAT_LZMS.to_le_bytes());

    if data.is_empty() {
        return Ok(out);
    }

    let mut payloads: Vec<Vec<u8>> = Vec::new();
    for chunk in data.chunks(chunk_size) {
        payloads.push(compress_chunk(chunk)?);
    }
    for payload in &payloads {
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    }
    for payload in &payloads {
        out.extend_from_slice(payload);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonsolid_roundtrip() {
        for (data, cs) in [
            (vec![], 4096usize),
            (b"a small WIM resource repetition repetition".to_vec(), 4096),
            (
                (0..10_000usize)
                    .map(|i| b"WIM chunk data "[i % 15])
                    .collect(),
                4096,
            ),
        ] {
            let resource = compress_wim(&data, cs).unwrap();
            assert_eq!(decompress_wim(&resource, cs, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn solid_roundtrip() {
        let mut data = Vec::new();
        data.extend(std::iter::repeat_n(b'A', 4096));
        data.extend((0..4096u64).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8));
        data.extend(std::iter::repeat_n(b'Z', 100));
        let resource = compress_wim_solid(&data, 4096).unwrap();
        assert_eq!(decompress_wim_solid(&resource).unwrap(), data);
    }

    #[test]
    fn solid_rejects_non_lzms_format() {
        let mut res = vec![0u8; 16];
        res[0..8].copy_from_slice(&10u64.to_le_bytes());
        res[8..12].copy_from_slice(&4096u32.to_le_bytes());
        res[12..16].copy_from_slice(&2u32.to_le_bytes()); // LZX, not LZMS
        assert!(decompress_wim_solid(&res).is_err());
    }

    #[test]
    fn rejects_zero_chunk_size() {
        assert!(decompress_wim(b"\x00\x00\x00\x00", 0, 10).is_err());
    }
}
