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

use std::ops::RangeInclusive;

use crate::{compress, decompress, Error, Result};

/// Compression-format id used in the solid-resource header (the value
/// Microsoft writes for LZMS).
const SOLID_FORMAT_LZMS: u32 = 3;

/// Upper bound on the up-front output-buffer preallocation. A single LZMS
/// stream decodes at most one 64 MiB chunk, so capping the initial capacity
/// here keeps a bogus header-declared total from triggering a giant
/// allocation; the buffer still grows as further chunks decode.
const MAX_WIM_CAPACITY: usize = 0x0400_0000;

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

    // `num_chunks` is bounded by the table fitting in `resource`, so this is
    // safe to size up front.
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

    // `uncompressed_size` is attacker-controlled out-of-band metadata; cap the
    // preallocation at one chunk (64 MiB max) so a bogus total can't OOM. The
    // buffer still grows as chunks decode.
    let mut out = Vec::with_capacity(uncompressed_size.min(MAX_WIM_CAPACITY));
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

    // `uncompressed_size` comes straight from the resource header; with a large
    // `chunk_size` the chunk table stays small, so a bogus total would otherwise
    // request an enormous allocation. Cap at one chunk (64 MiB max); the buffer
    // grows as chunks decode.
    let mut out = Vec::with_capacity(uncompressed_size.min(MAX_WIM_CAPACITY));
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

/// Parsed solid-resource framing — the 16-byte header plus the
/// chunk-*size* table, without any chunk data.
///
/// This lets a caller that holds only a `Read + Seek` over the resource
/// (e.g. a WIM/ESD reader) decode an arbitrary plaintext byte range
/// without materializing the whole — often multi-GB — solid blob. Each
/// chunk is an independent LZMS stream, so only the chunks covering the
/// requested range need to be read and decoded.
///
/// Typical flow for a streaming reader:
/// 1. read the 16-byte header, call [`SolidLayout::table_len`] to learn
///    the full header+table size;
/// 2. read that many bytes, call [`SolidLayout::parse`];
/// 3. [`SolidLayout::chunks_for`] the wanted plaintext range, then for
///    each index seek to [`SolidLayout::chunk_on_disk`], read it, and
///    decode with [`decompress_wim_chunk`];
/// 4. concatenate the decoded chunks and slice off the leading/trailing
///    partial bytes (`off - first_chunk * chunk_size` .. `+ len`).
///
/// Callers holding the whole resource in memory can skip the dance and
/// use [`decompress_wim_solid_range`].
#[derive(Debug, Clone)]
pub struct SolidLayout {
    uncompressed_size: u64,
    chunk_size: u32,
    /// Per-chunk on-disk (compressed) sizes; `len() == num_chunks`.
    chunk_compressed: Vec<u32>,
    /// Byte offset of chunk 0 within the resource (== header + table).
    data_start: u64,
}

impl SolidLayout {
    /// Total bytes of the solid header + chunk-size table, derived from
    /// the 16-byte header alone. Read this many bytes, then call
    /// [`SolidLayout::parse`]. `header` must be at least 16 bytes.
    pub fn table_len(header: &[u8]) -> Result<usize> {
        if header.len() < SOLID_HEADER_SIZE {
            return Err(Error::Truncated);
        }
        let uncompressed_size = u64::from_le_bytes(header[0..8].try_into().unwrap()) as usize;
        let chunk_size = u32::from_le_bytes(header[8..12].try_into().unwrap()) as usize;
        let format = u32::from_le_bytes(header[12..16].try_into().unwrap());
        if format != SOLID_FORMAT_LZMS {
            return Err(Error::Malformed("LZMS: solid resource is not LZMS"));
        }
        if uncompressed_size == 0 {
            return Ok(SOLID_HEADER_SIZE);
        }
        if chunk_size == 0 {
            return Err(Error::Malformed("LZMS: solid chunk size is zero"));
        }
        let num_chunks = uncompressed_size.div_ceil(chunk_size);
        let table = num_chunks
            .checked_mul(4)
            .ok_or(Error::Malformed("LZMS: solid chunk count overflow"))?;
        SOLID_HEADER_SIZE
            .checked_add(table)
            .ok_or(Error::Malformed("LZMS: solid chunk table overflow"))
    }

    /// Parse the solid header and chunk-size table. `prefix` must hold at
    /// least [`SolidLayout::table_len`] bytes (the header followed by the
    /// full chunk-size table); any trailing chunk data is ignored.
    pub fn parse(prefix: &[u8]) -> Result<Self> {
        let need = Self::table_len(prefix)?;
        if prefix.len() < need {
            return Err(Error::Truncated);
        }
        let uncompressed_size = u64::from_le_bytes(prefix[0..8].try_into().unwrap());
        let chunk_size = u32::from_le_bytes(prefix[8..12].try_into().unwrap());
        let num_chunks = (need - SOLID_HEADER_SIZE) / 4;
        let mut chunk_compressed = Vec::with_capacity(num_chunks);
        for i in 0..num_chunks {
            let off = SOLID_HEADER_SIZE + i * 4;
            chunk_compressed.push(u32::from_le_bytes(prefix[off..off + 4].try_into().unwrap()));
        }
        Ok(SolidLayout {
            uncompressed_size,
            chunk_size,
            chunk_compressed,
            data_start: need as u64,
        })
    }

    /// Total uncompressed (plaintext) length of the solid blob.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Plaintext chunk size (every chunk but the last expands to this).
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Number of chunks in the blob.
    pub fn num_chunks(&self) -> usize {
        self.chunk_compressed.len()
    }

    /// Uncompressed length of chunk `i`. Panics if `i >= num_chunks`.
    pub fn chunk_plain_len(&self, i: usize) -> usize {
        assert!(i < self.chunk_compressed.len(), "chunk index out of range");
        let cs = self.chunk_size as usize;
        if i + 1 < self.chunk_compressed.len() {
            cs
        } else {
            last_chunk_len(self.uncompressed_size as usize, cs)
        }
    }

    /// On-disk location of chunk `i`: `(byte offset within the resource,
    /// compressed length)`. Panics if `i >= num_chunks`.
    pub fn chunk_on_disk(&self, i: usize) -> (u64, usize) {
        assert!(i < self.chunk_compressed.len(), "chunk index out of range");
        let mut off = self.data_start;
        for c in &self.chunk_compressed[..i] {
            off += *c as u64;
        }
        (off, self.chunk_compressed[i] as usize)
    }

    /// Inclusive range of chunk indices covering the plaintext byte range
    /// `[off, off + len)`. Errors if the range falls outside the blob.
    pub fn chunks_for(&self, off: u64, len: u64) -> Result<RangeInclusive<usize>> {
        let end = off
            .checked_add(len)
            .filter(|&e| e <= self.uncompressed_size)
            .ok_or(Error::Malformed("LZMS: solid range out of bounds"))?;
        if len == 0 {
            return Err(Error::Malformed("LZMS: empty solid range"));
        }
        let cs = self.chunk_size as u64;
        let first = (off / cs) as usize;
        let last = ((end - 1) / cs) as usize;
        Ok(first..=last)
    }
}

/// Decode one solid chunk: `chunk` is the raw on-disk bytes,
/// `plain_len` its uncompressed length (from
/// [`SolidLayout::chunk_plain_len`]). A chunk stored verbatim
/// (`chunk.len() == plain_len`) is copied; otherwise it is LZMS-decoded.
pub fn decompress_wim_chunk(chunk: &[u8], plain_len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(plain_len.min(MAX_WIM_CAPACITY));
    expand_chunk(chunk, plain_len, &mut out)?;
    Ok(out)
}

/// Decode the plaintext byte range `[off, off + len)` out of a solid
/// resource held entirely in memory, decoding only the chunks that
/// cover it. For callers that don't want the whole resource in memory,
/// drive [`SolidLayout`] over a `Read + Seek` instead.
pub fn decompress_wim_solid_range(resource: &[u8], off: u64, len: u64) -> Result<Vec<u8>> {
    let layout = SolidLayout::parse(resource)?;
    let range = layout.chunks_for(off, len)?;
    let first = *range.start();

    let mut decoded: Vec<u8> = Vec::new();
    for i in range {
        let (coff, clen) = layout.chunk_on_disk(i);
        let coff = coff as usize;
        let end = coff
            .checked_add(clen)
            .filter(|&e| e <= resource.len())
            .ok_or(Error::Truncated)?;
        expand_chunk(
            &resource[coff..end],
            layout.chunk_plain_len(i),
            &mut decoded,
        )?;
    }

    let skip = (off - first as u64 * layout.chunk_size as u64) as usize;
    let want = len as usize;
    decoded
        .get(skip..skip + want)
        .map(<[u8]>::to_vec)
        .ok_or(Error::Truncated)
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

    /// A multi-chunk solid: every plaintext sub-range decoded via the
    /// range reader must match the same slice of the full decode, and the
    /// range reader must only need the chunks that actually cover it.
    #[test]
    fn solid_range_matches_full_decode() {
        // ~5 chunks at chunk_size 4096. Mix of compressible runs and
        // pseudo-random bytes so chunks differ and some may store verbatim.
        let mut data = Vec::new();
        data.extend(std::iter::repeat_n(b'A', 4096)); // chunk 0: highly compressible
        data.extend((0..4096u64).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)); // 1
        data.extend(std::iter::repeat_n(b'Q', 4096)); // 2
        data.extend((0..4096u64).map(|i| (i.wrapping_mul(40503) >> 7) as u8)); // 3
        data.extend(std::iter::repeat_n(b'Z', 1000)); // 4 (partial)
        let resource = compress_wim_solid(&data, 4096).unwrap();
        let full = decompress_wim_solid(&resource).unwrap();
        assert_eq!(full, data);

        let layout = SolidLayout::parse(&resource).unwrap();
        assert_eq!(layout.num_chunks(), 5);
        assert_eq!(layout.uncompressed_size(), data.len() as u64);

        // Cases that hit single chunks, chunk boundaries, multi-chunk
        // spans, the partial last chunk, and the full blob.
        let cases = [
            (0u64, 10u64),
            (0, 4096),     // exactly chunk 0
            (4090, 12),    // straddles chunk 0/1 boundary
            (4096, 4096),  // exactly chunk 1
            (5000, 9000),  // spans chunks 1..3
            (16384, 1000), // the whole partial last chunk
            (16384 + 999, 1),
            (0, data.len() as u64), // entire blob
        ];
        for (off, len) in cases {
            let got = decompress_wim_solid_range(&resource, off, len).unwrap();
            assert_eq!(
                got,
                &data[off as usize..(off + len) as usize],
                "range ({off}, {len}) mismatch"
            );
            // chunks_for must be tight: it should never include a chunk
            // beyond the one containing the last requested byte.
            let r = layout.chunks_for(off, len).unwrap();
            assert_eq!(*r.start(), (off / 4096) as usize);
            assert_eq!(*r.end(), ((off + len - 1) / 4096) as usize);
        }
    }

    #[test]
    fn solid_layout_chunk_offsets_are_consistent() {
        let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let resource = compress_wim_solid(&data, 4096).unwrap();
        let layout = SolidLayout::parse(&resource).unwrap();

        // chunk_on_disk offsets are contiguous and end at the resource end;
        // chunk_plain_len sums to the uncompressed total.
        let mut expected_off = layout.data_start;
        let mut plain_total = 0usize;
        for i in 0..layout.num_chunks() {
            let (off, clen) = layout.chunk_on_disk(i);
            assert_eq!(off, expected_off, "chunk {i} offset");
            expected_off += clen as u64;
            plain_total += layout.chunk_plain_len(i);
        }
        assert_eq!(expected_off, resource.len() as u64);
        assert_eq!(plain_total, data.len());
    }

    #[test]
    fn solid_range_rejects_out_of_bounds() {
        let data: Vec<u8> = vec![7u8; 5000];
        let resource = compress_wim_solid(&data, 4096).unwrap();
        assert!(decompress_wim_solid_range(&resource, 4000, 2000).is_err()); // past end
        assert!(decompress_wim_solid_range(&resource, 0, 0).is_err()); // empty
    }

    #[test]
    fn solid_table_len_matches_parse() {
        let data: Vec<u8> = vec![3u8; 10_000];
        let resource = compress_wim_solid(&data, 4096).unwrap();
        // table_len computed from the 16-byte header alone equals the
        // data_start the full parse arrives at.
        let need = SolidLayout::table_len(&resource[..SOLID_HEADER_SIZE]).unwrap();
        let layout = SolidLayout::parse(&resource).unwrap();
        assert_eq!(need as u64, layout.data_start);
        assert_eq!(need, SOLID_HEADER_SIZE + 3 * 4); // ceil(10000/4096) = 3 chunks
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

    /// A solid header declaring a huge uncompressed size with an equally huge
    /// chunk size yields a single-entry chunk table, so it fits in a tiny
    /// resource yet would request a multi-terabyte preallocation. Must fail
    /// cleanly without aborting on the allocation.
    #[test]
    fn solid_huge_uncompressed_size_does_not_oom() {
        // A chunk size >= the total collapses to a single chunk, so the table is
        // just one 4-byte entry and the 20-byte resource is well-formed up to the
        // preallocation. With the cap removed this would request 1 TiB.
        let mut res = vec![0u8; SOLID_HEADER_SIZE + 4];
        res[0..8].copy_from_slice(&(1u64 << 40).to_le_bytes()); // 1 TiB total
        res[8..12].copy_from_slice(&u32::MAX.to_le_bytes()); // chunk >= total -> 1 chunk
        res[12..16].copy_from_slice(&SOLID_FORMAT_LZMS.to_le_bytes());
        // Single table entry of compressed_size 0 -> empty chunk; rejected by the
        // decode/verbatim length check, but only after the (now capped) alloc.
        assert!(decompress_wim_solid(&res).is_err());
    }

    /// The non-solid reader takes its total uncompressed size as a parameter;
    /// a huge value with a huge chunk size yields a single chunk (empty table),
    /// so it must not preallocate the full declared total.
    #[test]
    fn nonsolid_huge_uncompressed_size_does_not_oom() {
        // num_chunks = 1 -> table_bytes = 0, so the empty resource fits. The
        // preallocation must be capped so this returns (Ok or Err) rather than
        // aborting on a multi-terabyte allocation.
        let res: &[u8] = &[];
        let _ = decompress_wim(res, 1usize << 40, 1usize << 40);
    }
}
