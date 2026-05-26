//! Rift table: address remapping between reference and target for PE deltas.
//!
//! A rift table contains (source_offset, target_offset) pairs that tell
//! the decompressor how to map virtual addresses when copying from the
//! reference buffer. For non-PE (RAW) deltas, the rift table is empty.
//!
//! PDB-confirmed: `RiftTable`, `IntFormat`, `OffsetRiftTable`.

use msdelta_bitstream::bitstream::BitReader;
use msdelta_bitstream::huffman::HuffmanTable;
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

        let fmt_src = IntFormat::from_reader(reader)?;
        let fmt_dst = IntFormat::from_reader(reader)?;

        let count = reader.read_i64()?;
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
    fn from_reader(reader: &mut BitReader) -> Result<Self> {
        // Read 8-bit "mode" byte
        let mode = reader.read_bits(8)? as u8;

        let mut lengths = vec![0u8; INT_FORMAT_SYMBOLS];

        if mode == 0 {
            // All symbols have the same length
            let uniform_len = reader.read_bits(4)? as u8;
            lengths.fill(uniform_len);
        } else if (mode as usize) <= INT_FORMAT_HALF {
            // Only first `mode` positive and `mode` negative symbols are used
            let active = mode as usize;
            for l in &mut lengths[..active] {
                *l = reader.read_bits(4)? as u8;
            }
            for l in &mut lengths[INT_FORMAT_HALF..INT_FORMAT_HALF + active] {
                *l = reader.read_bits(4)? as u8;
            }
        } else {
            return Err(Error::Malformed("IntFormat mode out of range"));
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
