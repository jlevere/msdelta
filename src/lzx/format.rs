//! Constants and shared types for the PseudoLzx codec.

use crate::huffman::HuffmanTable;
use crate::{Error, Result};

pub(super) const MAIN_SYMBOLS: usize = 600;
pub(super) const LENGTH_SYMBOLS: usize = 256;
pub(super) const ALIGNED_SYMBOLS: usize = 16;
pub(super) const TOTAL_LENGTHS: usize = MAIN_SYMBOLS + LENGTH_SYMBOLS + ALIGNED_SYMBOLS;
pub(super) const PRETREE_SYMBOLS: usize = 39;

// Aliases for the raw wire constants used throughout this module
pub(super) const SOURCE_COPY: u32 = super::ops::SOURCE_COPY_RAW;
pub(super) const LRU_BASE: u32 = super::ops::LRU_BASE_RAW;

pub(super) fn flat_code_lengths(count: usize) -> Vec<u8> {
    if count == 0 {
        return Vec::new();
    }
    if count <= 2 {
        return vec![1; count];
    }
    let bits_needed = (count - 1).ilog2() as u8 + 1;
    let full_count = 1usize << bits_needed;
    let short_count = full_count - count;
    let mut lengths = Vec::with_capacity(count);
    for _ in 0..short_count {
        lengths.push(bits_needed - 1);
    }
    for _ in short_count..count {
        lengths.push(bits_needed);
    }
    lengths
}

pub(super) struct SegmentTables {
    pub(super) main: HuffmanTable,
    pub(super) lengths: HuffmanTable,
    pub(super) aligned: HuffmanTable,
}

impl SegmentTables {
    pub(super) fn from_flat() -> Result<Self> {
        Ok(SegmentTables {
            main: HuffmanTable::from_lengths(&flat_code_lengths(MAIN_SYMBOLS))?,
            lengths: HuffmanTable::from_lengths(&flat_code_lengths(LENGTH_SYMBOLS))?,
            aligned: HuffmanTable::from_lengths(&flat_code_lengths(ALIGNED_SYMBOLS))?,
        })
    }

    pub(super) fn from_lengths(all_lengths: &[u8]) -> Result<Self> {
        if all_lengths.len() != TOTAL_LENGTHS {
            return Err(Error::Malformed("wrong total compression lengths"));
        }
        let main = HuffmanTable::from_lengths(&all_lengths[..MAIN_SYMBOLS])?;
        let lengths = HuffmanTable::from_lengths(
            &all_lengths[MAIN_SYMBOLS..MAIN_SYMBOLS + LENGTH_SYMBOLS],
        )?;
        let aligned = HuffmanTable::from_lengths(
            &all_lengths[MAIN_SYMBOLS + LENGTH_SYMBOLS..],
        )?;
        Ok(SegmentTables { main, lengths, aligned })
    }
}

pub(super) struct CompositeFormat {
    pub(super) segments: Vec<SegmentTables>,
    pub(super) boundaries: Vec<u64>,
}
