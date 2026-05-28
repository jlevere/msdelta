//! Rift table: address remapping between reference and target for PE deltas.
//!
//! A rift table contains (source_offset, target_offset) pairs that tell
//! the decompressor how to map virtual addresses when copying from the
//! reference buffer. For non-PE (RAW) deltas, the rift table is empty.
//!
//! PDB-confirmed: `RiftTable`, `IntFormat`, `OffsetRiftTable`.

use crate::bitstream::{BitReader, BitWriter};
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

        let fmt_src = IntFormat::from_reader(reader)?;
        let fmt_dst = IntFormat::from_reader(reader)?;

        let count = reader.read_i64()?;
        // Each entry reads at least one bit per encoded number, so a well-formed
        // table can never claim more entries than there are bits left in the
        // stream. Reject anything larger instead of allocating on an
        // attacker-controlled count: without this bound a crafted delta drives
        // an unbounded `Vec` growth (multi-GB OOM), since the bit reader yields
        // zero past end-of-stream rather than erroring.
        if count < 0 || count as u64 > u64::from(reader.remaining()) {
            return Err(Error::Malformed(
                "rift table entry count exceeds available input",
            ));
        }
        let count = count as usize;

        let mut entries = Vec::with_capacity(count);
        let mut src_acc: i64 = 0;
        let mut dst_acc: i64 = 0;

        for _ in 0..count {
            let src_delta = fmt_src.read_number(reader)?;
            src_acc = src_acc.wrapping_add(src_delta);
            let dst_delta = fmt_dst.read_number(reader)?;
            dst_acc = dst_acc.wrapping_add(dst_delta);
            entries.push(RiftEntry {
                source: src_acc,
                target: dst_acc.wrapping_add(src_acc),
            });
        }

        entries.sort_by_key(|e| e.source);

        Ok(RiftTable { entries })
    }

    /// Serialize a rift table to the bitstream.
    pub fn to_writer(&self, writer: &mut BitWriter) {
        if self.entries.is_empty() {
            writer.write_bits(0, 1);
            return;
        }
        writer.write_bits(1, 1);

        let mut src_deltas = Vec::with_capacity(self.entries.len());
        let mut dst_deltas = Vec::with_capacity(self.entries.len());
        let mut src_acc: i64 = 0;
        let mut dst_acc: i64 = 0;
        for e in &self.entries {
            let sd = e.source - src_acc;
            src_acc = e.source;
            let target_delta = (e.target - e.source) - dst_acc;
            dst_acc = e.target - e.source;
            src_deltas.push(sd);
            dst_deltas.push(target_delta);
        }

        let fmt_src = IntFormat::from_values(&src_deltas);
        let fmt_dst = IntFormat::from_values(&dst_deltas);

        fmt_src.to_writer(writer);
        fmt_dst.to_writer(writer);
        writer.write_i64(self.entries.len() as i64);

        for (sd, dd) in src_deltas.iter().zip(dst_deltas.iter()) {
            fmt_src.write_number(writer, *sd);
            fmt_dst.write_number(writer, *dd);
        }
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
            return OffsetRiftTable {
                entries: vec![(0, 0)],
            };
        }

        // Offset = entry.target - entry.source
        // For from_reader entries: target is absolute, so this gives the displacement
        // For boundary entry {ref_len, 0}: gives 0 - ref_len = -ref_len
        let initial = {
            let last = rift.entries.last().unwrap();
            last.target.wrapping_sub(last.source)
        };

        let mut entries = Vec::with_capacity(rift.entries.len() + 1);
        entries.push((0i64, initial));
        for e in &rift.entries {
            entries.push((e.source, e.target.wrapping_sub(e.source)));
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
    num_pos: usize,
    num_neg: usize,
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
                    remaining = (INT_FORMAT_SYMBOLS - num_pos - num_neg).saturating_sub(i);
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
                    remaining = INT_FORMAT_HALF.saturating_sub(i - INT_FORMAT_HALF);
                }
                lengths[i] = len;
                remaining = remaining.saturating_sub(1);
            }
        }

        let table = HuffmanTable::from_lengths(&lengths)?;
        Ok(IntFormat {
            table,
            num_pos,
            num_neg,
        })
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

    fn value_to_symbol(value: i64) -> (u32, u64, u32) {
        let (magnitude, is_neg) = if value < 0 {
            (!value as u64, true)
        } else {
            (value as u64, false)
        };

        let (sym_idx, extra_val, extra_bits) = if magnitude <= 3 {
            (magnitude as u32, 0u64, 0u32)
        } else {
            let high_bit = 63 - magnitude.leading_zeros();
            let half = high_bit - 1;
            let base_bit = (magnitude >> half) & 1;
            let sym_idx = 2 * (half + 1) + base_bit as u32;
            let extra_val = magnitude & ((1u64 << half) - 1);
            (sym_idx, extra_val, half)
        };

        let symbol = if is_neg {
            sym_idx + INT_FORMAT_HALF as u32
        } else {
            sym_idx
        };
        (symbol, extra_val, extra_bits)
    }

    fn from_values(values: &[i64]) -> Self {
        let mut freqs = vec![1u32; INT_FORMAT_SYMBOLS];
        for &v in values {
            let (sym, _, _) = Self::value_to_symbol(v);
            freqs[sym as usize] += 1;
        }

        let max_len: u8 = 15;
        let table = HuffmanTable::from_frequencies(&freqs, max_len).unwrap_or_else(|_| {
            let uniform = vec![8u8; INT_FORMAT_SYMBOLS];
            HuffmanTable::from_lengths(&uniform).unwrap()
        });

        IntFormat {
            table,
            num_pos: INT_FORMAT_HALF,
            num_neg: INT_FORMAT_HALF,
        }
    }

    fn to_writer(&self, writer: &mut BitWriter) {
        writer.write_bits(INT_FORMAT_HALF as u64, 8); // num_pos = 126 (all explicit)
        writer.write_bits(INT_FORMAT_HALF as u64, 8); // num_neg = 126 (all explicit)
        writer.write_bits(0u64, 8); // num_default = 0

        for i in 0..INT_FORMAT_HALF {
            let len = self.table.lengths[i].max(1);
            writer.write_bits((len - 1) as u64, 4);
        }
        for i in INT_FORMAT_HALF..INT_FORMAT_SYMBOLS {
            let len = self.table.lengths[i].max(1);
            writer.write_bits((len - 1) as u64, 4);
        }
        writer.write_bits(0u64, 4); // default_len (unused but required by format)
    }

    fn write_number(&self, writer: &mut BitWriter, value: i64) {
        let (symbol, extra_val, extra_bits) = Self::value_to_symbol(value);
        self.table.write_symbol(writer, symbol as u16);
        if extra_bits > 0 {
            writer.write_bits(extra_val, extra_bits);
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
    fn rift_table_roundtrip_empty() {
        let table = RiftTable {
            entries: Vec::new(),
        };
        let mut w = BitWriter::new();
        table.to_writer(&mut w);
        let data = w.finish();
        let mut r = BitReader::new(&data).unwrap();
        let decoded = RiftTable::from_reader(&mut r).unwrap();
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn rift_table_roundtrip_single() {
        let table = RiftTable {
            entries: vec![RiftEntry {
                source: 100,
                target: 200,
            }],
        };
        let mut w = BitWriter::new();
        table.to_writer(&mut w);
        let data = w.finish();
        let mut r = BitReader::new(&data).unwrap();
        let decoded = RiftTable::from_reader(&mut r).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].source, 100);
        assert_eq!(decoded.entries[0].target, 200);
    }

    #[test]
    fn rift_table_roundtrip_multiple() {
        let table = RiftTable {
            entries: vec![
                RiftEntry {
                    source: 0,
                    target: 0,
                },
                RiftEntry {
                    source: 0x1000,
                    target: 0x2000,
                },
                RiftEntry {
                    source: 0x5000,
                    target: 0x5800,
                },
                RiftEntry {
                    source: 0x10000,
                    target: 0x10000,
                },
            ],
        };
        let mut w = BitWriter::new();
        table.to_writer(&mut w);
        let data = w.finish();
        let mut r = BitReader::new(&data).unwrap();
        let decoded = RiftTable::from_reader(&mut r).unwrap();
        assert_eq!(decoded.entries.len(), table.entries.len());
        for (a, b) in decoded.entries.iter().zip(table.entries.iter()) {
            assert_eq!(a.source, b.source, "source mismatch");
            assert_eq!(a.target, b.target, "target mismatch");
        }
    }

    #[test]
    fn rift_table_roundtrip_negative_deltas() {
        let table = RiftTable {
            entries: vec![
                RiftEntry {
                    source: 100,
                    target: 50,
                },
                RiftEntry {
                    source: 200,
                    target: 180,
                },
                RiftEntry {
                    source: 300,
                    target: 350,
                },
            ],
        };
        let mut w = BitWriter::new();
        table.to_writer(&mut w);
        let data = w.finish();
        let mut r = BitReader::new(&data).unwrap();
        let decoded = RiftTable::from_reader(&mut r).unwrap();
        assert_eq!(decoded.entries.len(), 3);
        for (a, b) in decoded.entries.iter().zip(table.entries.iter()) {
            assert_eq!(a.source, b.source);
            assert_eq!(a.target, b.target);
        }
    }

    #[test]
    fn int_format_value_symbol_roundtrip() {
        for &val in &[
            0i64, 1, 2, 3, 4, 5, 7, 8, 15, 16, 100, 1000, 65535, -1, -2, -3, -4, -100, -65536,
        ] {
            let (sym, extra, ebits) = IntFormat::value_to_symbol(val);
            assert!(
                (sym as usize) < INT_FORMAT_SYMBOLS,
                "symbol {sym} out of range for value {val}"
            );
            let is_neg = sym >= INT_FORMAT_HALF as u32;
            let mag_idx = if is_neg {
                sym - INT_FORMAT_HALF as u32
            } else {
                sym
            };
            let reconstructed = if mag_idx <= 3 {
                mag_idx as i64
            } else {
                let half = (mag_idx >> 1) - 1;
                let base = (mag_idx & 1) as i64 + 2;
                (base << half) | extra as i64
            };
            let result = if is_neg {
                !reconstructed
            } else {
                reconstructed
            };
            assert_eq!(
                result, val,
                "roundtrip failed for {val}: sym={sym} extra={extra} ebits={ebits}"
            );
        }
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
