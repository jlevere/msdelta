//! Reverse-delta decode: the "reversal data" / `ReversePatchFormat` body that a
//! PA30/PA31 delta carries when `file_type_set & 0x100` is set (the
//! `ApplyReversalData` path in `msdelta.dll` / `UpdateCompression.dll`).
//!
//! A reverse delta reconstructs the *source* buffer from the *target* buffer it
//! was diffed against. In `ApplyDeltaB` terms the caller's reference buffer is the
//! target (the patched/new file) and the produced output is the source (the base).
//!
//! Reverse-engineered (clean-room) from the decompiled
//! `ReversePatchFormat`/`ApplyReversalDataComponent` family:
//! - container: `[u32 magic "PRSM"][u32 count]` then a sequence of sections, read
//!   until the bit reader is exhausted (the count is informational; the genuine
//!   loop terminates on bit-exhaustion -- `ReadNextReversePatchSection`).
//! - each section is a length-prefixed buffer holding `[u32 payloadType][payload]`:
//!   - type 0 (`UnpackLzxData`/`ReverseLzx`): a `RiftTable` plus one length per
//!     entry; each entry copies `len` bytes from `target[right]` to `out[left]`.
//!     Reconstructs the regions of the source that are identical to the target
//!     (possibly at shifted offsets).
//!   - type 1 (`UnpackDeletes`/`ReverseDeletes`): a `RiftTable` plus a deleted-bytes
//!     blob; each entry copies `right` bytes from the blob cursor to `out[left]`.
//!     Re-inserts source bytes absent from the target.
//!   - type 2 (`UnpackPatches`): a `RiftTable`; applied in reverse, each entry sets
//!     the single byte `out[left] = right`. Individual differing bytes.
//!
//! The `RiftTable` here reuses the same encoding as the LZX preprocess rift
//! (`crate::lzx::rift`): a presence bit, two `IntFormat` Huffman trees, then
//! cumulative `(left, right)` deltas, sorted by `left`. Per entry the table's
//! `source` field is `left` and `target` is `right`.

use crate::bitstream::BitReader;
use crate::lzx::rift::{IntFormat, RiftTable};
use crate::{Error, Result};

const PRSM_MAGIC: u32 = 0x4d53_5250;

/// Reconstruct the source buffer from `target` (the reference) and the reversal
/// data, producing `source_size` bytes.
pub(crate) fn apply_reversal(
    target: &[u8],
    reversal_data: &[u8],
    source_size: usize,
) -> Result<Vec<u8>> {
    let mut reader = BitReader::new(reversal_data)?;

    let magic = reader.read_bits(32)? as u32;
    if magic != PRSM_MAGIC {
        return Err(Error::Malformed("reverse delta: missing PRSM magic"));
    }
    let _count = reader.read_bits(32)?; // informational; loop terminates on exhaustion

    let mut out = vec![0u8; source_size];

    while reader.remaining() > 0 {
        let section = reader.read_buffer()?;
        let mut sr = BitReader::new(&section)?;
        let payload_type = sr.read_bits(32)?;
        match payload_type {
            0 => apply_copy(&mut sr, target, &mut out)?,
            1 => apply_deletes(&mut sr, &mut out)?,
            2 => apply_patches(&mut sr, &mut out)?,
            _ => return Err(Error::Malformed("reverse delta: invalid payload type")),
        }
    }

    Ok(out)
}

/// Bounds-safe `[start, start+len)` as a `usize` range, or `None` if `start`/`len`
/// are negative or the range overruns `buf_len`.
fn checked_range(start: i64, len: i64, buf_len: usize) -> Option<(usize, usize)> {
    if start < 0 || len < 0 {
        return None;
    }
    let start = usize::try_from(start).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = start.checked_add(len)?;
    if end > buf_len {
        return None;
    }
    Some((start, end))
}

/// Type 0: copy runs out of the target into the reconstructed source.
fn apply_copy(sr: &mut BitReader, target: &[u8], out: &mut [u8]) -> Result<()> {
    let _discard = sr.read_bits(32)?;
    let rift = RiftTable::from_reader(sr)?;

    // One length per rift entry, via the default (un-serialized) IntFormat. Read
    // after the whole table; paired with the sorted entries by index.
    let fmt = IntFormat::init_default()?;
    let mut lengths = Vec::with_capacity(rift.entries.len());
    for _ in 0..rift.entries.len() {
        lengths.push(fmt.read_number(sr)?);
    }

    for (entry, &len) in rift.entries.iter().zip(&lengths) {
        let left = entry.source; // dest offset in source-being-rebuilt
        let right = entry.target; // source offset in target
        // Clamp the run to both buffers (the genuine ReverseLzx silently truncates).
        let max_len = len
            .min(out.len() as i64 - left.max(0))
            .min(target.len() as i64 - right.max(0));
        if max_len <= 0 {
            continue;
        }
        let (Some((ds, de)), Some((ss, se))) = (
            checked_range(left, max_len, out.len()),
            checked_range(right, max_len, target.len()),
        ) else {
            continue;
        };
        out[ds..de].copy_from_slice(&target[ss..se]);
    }
    Ok(())
}

/// Type 1: re-insert deleted runs from a (possibly compressed) byte blob.
fn apply_deletes(sr: &mut BitReader, out: &mut [u8]) -> Result<()> {
    let _discard = sr.read_bits(32)?;
    let compressed = sr.read_bits(32)? != 0;
    let rift = RiftTable::from_reader(sr)?;
    let blob = sr.read_buffer()?;

    // Compressed deletes are a Compression API container (algorithm XPRESS_HUFF).
    let blob = if compressed {
        crate::xpress::decompress_container(&blob)?
    } else {
        blob
    };

    let mut cursor = 0usize;
    for entry in &rift.entries {
        let left = entry.source; // dest offset in source
        let count = entry.target; // run length
        if count < 0 {
            return Err(Error::Malformed("reverse delta: negative delete length"));
        }
        let count = count as usize;
        let src_end = cursor
            .checked_add(count)
            .filter(|&e| e <= blob.len())
            .ok_or(Error::Malformed("reverse delta: delete blob overrun"))?;
        let Some((ds, de)) = checked_range(left, count as i64, out.len()) else {
            return Err(Error::Malformed("reverse delta: delete dest out of range"));
        };
        out[ds..de].copy_from_slice(&blob[cursor..src_end]);
        cursor = src_end;
    }
    Ok(())
}

/// Type 2: single-byte literal patches, applied in reverse entry order.
fn apply_patches(sr: &mut BitReader, out: &mut [u8]) -> Result<()> {
    let _discard = sr.read_bits(32)?;
    let rift = RiftTable::from_reader(sr)?;
    for entry in rift.entries.iter().rev() {
        if entry.source >= 0 && (entry.source as usize) < out.len() {
            out[entry.source as usize] = entry.target as u8;
        }
    }
    Ok(())
}
