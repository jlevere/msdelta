//! Rift table: address remapping between reference and target for PE deltas.
//!
//! A rift table contains (source_offset, target_offset) pairs that tell
//! the decompressor how to map virtual addresses when copying from the
//! reference buffer. For non-PE (RAW) deltas, the rift table is empty.
//!
//! PDB-confirmed: `RiftTable`, `IntFormat`, `OffsetRiftTable`.

use crate::bitstream::BitReader;
use crate::huffman::HuffmanTable;
use crate::{Error, Result};

const INT_FORMAT_SYMBOLS: usize = 252;
const INT_FORMAT_HALF: usize = 126;

/// A rift table entry: maps source position to target position.
#[derive(Debug, Clone, Copy)]
pub struct RiftEntry {
    pub source: i64,
    pub target: i64,
}

/// Parsed rift table.
#[derive(Debug, Clone)]
pub struct RiftTable {
    pub entries: Vec<RiftEntry>,
}

impl RiftTable {
    /// Parse a rift table from the bitstream.
    ///
    /// Format: 1-bit flag (0=empty, 1=has entries).
    /// If non-empty: two IntFormat Huffman trees, then delta-encoded entries.
    pub fn from_reader(reader: &mut BitReader) -> Result<Self> {
        let has_entries = reader.read_bits(1)? != 0;
        if !has_entries {
            return Ok(RiftTable {
                entries: Vec::new(),
            });
        }

        if std::env::var("RIFT_DEBUG").is_ok() {
            eprintln!("  rift: parsing IntFormats, {} bits remaining", reader.remaining());
        }
        let fmt_src = IntFormat::from_reader(reader)?;
        if std::env::var("RIFT_DEBUG").is_ok() {
            eprintln!("  rift: after fmt_src, {} bits remaining", reader.remaining());
        }
        let fmt_dst = IntFormat::from_reader(reader)?;
        if std::env::var("RIFT_DEBUG").is_ok() {
            eprintln!("  rift: after fmt_dst, {} bits remaining", reader.remaining());
        }

        let count = reader.read_i64()?;
        if std::env::var("RIFT_DEBUG").is_ok() {
            eprintln!("  rift: flag=1, count={count}, remaining={}", reader.remaining());
        }
        if !(0..=0x0FFFFFFFFFFFFFFF).contains(&count) {
            return Err(Error::Malformed("rift table entry count out of range"));
        }
        let count = count as usize;

        let mut entries = Vec::with_capacity(count.min(1_000_000));
        let mut src_acc: i64 = 0;
        let mut dst_acc: i64 = 0;

        for _ in 0..count {
            let src_delta = fmt_src.read_number(reader)?;
            src_acc += src_delta;
            let dst_delta = fmt_dst.read_number(reader)?;
            dst_acc += dst_delta;
            entries.push(RiftEntry {
                source: src_acc,
                target: dst_acc + src_acc,
            });
        }

        entries.sort_by_key(|e| e.source);

        Ok(RiftTable { entries })
    }

    /// Look up the rift offset for a given source position.
    ///
    /// Returns the offset to add to the source position to get the
    /// target position, based on the rift table entries.
    pub fn map(&self, source_pos: i64) -> i64 {
        if self.entries.is_empty() {
            return 0;
        }

        // Binary search for the entry covering this position
        match self.entries.binary_search_by_key(&source_pos, |e| e.source) {
            Ok(idx) => self.entries[idx].target - self.entries[idx].source,
            Err(0) => 0,
            Err(idx) => {
                let e = &self.entries[idx - 1];
                e.target - e.source
            }
        }
    }
}

/// Accelerated rift offset lookup for the LZX decompressor.
///
/// Each entry maps a position range to a rift offset. For a given position,
/// the offset tells the decompressor how to adjust copy operations.
///
/// Translated from `OffsetRiftTable<unsigned __int64>::Init` in msdelta.dll.
pub struct OffsetRiftTable {
    entries: Vec<(i64, i64)>, // (position, offset) sorted by position
}

impl OffsetRiftTable {
    /// Build from a RiftTable.
    ///
    /// The boundary entry {source=ref_len, target=0} is expected to already
    /// be in the rift table (added by the caller before this call).
    pub fn from_rift_table(rift: &RiftTable) -> Self {
        if rift.entries.is_empty() {
            return OffsetRiftTable { entries: vec![(0, 0)] };
        }

        // Offset = entry.target - entry.source
        // For from_reader entries: target is absolute, so this gives the displacement
        // For boundary entry {ref_len, 0}: gives 0 - ref_len = -ref_len
        let initial = {
            let last = rift.entries.last().unwrap();
            last.target - last.source
        };

        let mut entries = Vec::with_capacity(rift.entries.len() + 1);
        entries.push((0i64, initial));
        for e in &rift.entries {
            entries.push((e.source, e.target - e.source));
        }
        OffsetRiftTable { entries }
    }

    /// Look up the rift offset for a position.
    pub fn offset_at(&self, pos: i64) -> i64 {
        match self.entries.binary_search_by_key(&pos, |&(p, _)| p) {
            Ok(i) => self.entries[i].1,
            Err(0) => self.entries[0].1,
            Err(i) => self.entries[i - 1].1,
        }
    }
}

/// IntFormat: Huffman-coded signed integer encoding.
///
/// 252 symbols split into two ranges:
/// - 0..125: positive values
/// - 126..251: negative values (symbol - 126 gives magnitude)
///
/// Values > 3 have extra bits read via the base/half scheme.
struct IntFormat {
    table: HuffmanTable,
}

impl IntFormat {
    /// Parse from bitstream. Decompiled from IntFormat::FromBitReader (1800470f0).
    ///
    /// Format: 3 mode bytes + explicit code lengths + default length.
    ///   byte1: count of explicit positive symbol lengths (0..126)
    ///   byte2: count of explicit negative symbol lengths (0..126)
    ///   byte3: count of "default fill" symbols
    /// Then byte1 + byte2 code lengths (4 bits each), plus 1 default length.
    /// Remaining symbols are filled with the default length (decrementing).
    fn from_reader(reader: &mut BitReader) -> Result<Self> {
        let num_pos = reader.read_bits(8)? as usize;
        let num_neg = reader.read_bits(8)? as usize;
        let num_default = reader.read_bits(8)? as usize;

        if num_pos > INT_FORMAT_HALF || num_neg > INT_FORMAT_HALF {
            return Err(Error::Malformed("IntFormat mode out of range"));
        }
        if num_default > INT_FORMAT_SYMBOLS - num_pos - num_neg {
            return Err(Error::Malformed("IntFormat default count overflow"));
        }

        let mut lengths = vec![0u8; INT_FORMAT_SYMBOLS];

        // Read explicit positive code lengths
        for l in &mut lengths[..num_pos] {
            *l = (reader.read_bits(4)? as u8).wrapping_add(1);
        }

        // Read explicit negative code lengths
        for l in &mut lengths[INT_FORMAT_HALF..INT_FORMAT_HALF + num_neg] {
            *l = (reader.read_bits(4)? as u8).wrapping_add(1);
        }

        // Read default length for remaining symbols
        let default_len = (reader.read_bits(4)? as u8).wrapping_add(1);
        if default_len > 16 {
            return Err(Error::Malformed("IntFormat code length > 16"));
        }

        // Fill remaining positive symbols
        {
            let mut len = default_len;
            let mut remaining = num_default;
            #[allow(clippy::needless_range_loop)]
            for i in num_pos..INT_FORMAT_HALF {
                if remaining == 0 {
                    len = len.saturating_sub(1);
                    remaining = INT_FORMAT_SYMBOLS - num_pos - num_neg - i;
                }
                lengths[i] = len;
                remaining = remaining.saturating_sub(1);
            }
        }

        // Fill remaining negative symbols
        {
            let mut len = default_len;
            let mut remaining = num_default.saturating_sub(INT_FORMAT_HALF - num_pos);
            #[allow(clippy::needless_range_loop)]
            for i in (INT_FORMAT_HALF + num_neg)..INT_FORMAT_SYMBOLS {
                if remaining == 0 {
                    len = len.saturating_sub(1);
                    remaining = INT_FORMAT_HALF - (i - INT_FORMAT_HALF);
                }
                lengths[i] = len;
                remaining = remaining.saturating_sub(1);
            }
        }

        let table = HuffmanTable::from_lengths(&lengths)?;
        Ok(IntFormat { table })
    }

    fn read_number(&self, reader: &mut BitReader) -> Result<i64> {
        let sym = self.table.read_symbol(reader)? as u32;

        let (magnitude_idx, is_negative) = if sym < INT_FORMAT_HALF as u32 {
            (sym, false)
        } else {
            (sym - INT_FORMAT_HALF as u32, true)
        };

        let value = if magnitude_idx <= 3 {
            magnitude_idx as i64
        } else {
            let half = (magnitude_idx >> 1) - 1;
            let base = (magnitude_idx & 1) as i64 + 2;
            let extra = reader.read_bits(half)? as i64;
            (base << half) | extra
        };

        if is_negative {
            Ok(!value) // bitwise NOT = -(value + 1)
        } else {
            Ok(value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_rift_table() {
        // 3-bit padding + 1 bit = 0 (empty)
        let data = [0x00, 0x00];
        let mut reader = BitReader::new(&data).unwrap();
        let table = RiftTable::from_reader(&mut reader).unwrap();
        assert!(table.entries.is_empty());
    }

    #[test]
    fn empty_rift_map() {
        let table = RiftTable {
            entries: Vec::new(),
        };
        assert_eq!(table.map(0), 0);
        assert_eq!(table.map(1000), 0);
    }
}
