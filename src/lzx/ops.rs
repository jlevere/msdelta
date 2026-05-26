//! Match operations — the intermediate representation between
//! parsing and encoding in the PseudoLzx codec.
//!
//! Both the compressor and decompressor work with `MatchOp` values.
//! The compressor produces them from match finding, the decompressor
//! reads them from the bitstream. This makes both sides independently
//! testable and the format structure explicit.

/// A single operation in the PseudoLzx compressed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOp {
    /// Emit a literal byte.
    Literal(u8),
    /// Copy `length` bytes from a source at the given offset.
    Copy {
        offset: CopyOffset,
        length: u32,
    },
}

/// Where a copy operation reads from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOffset {
    /// Copy from the reference buffer at the same virtual position.
    /// Encoded as offset slot 3 (SOURCE_COPY = 0x54000).
    SourceCopy,
    /// Reuse a recent offset from the 3-element LRU queue.
    /// Index 0 = most recent, 1, 2.
    Lru(u8),
    /// Copy from a specific distance back in the virtual buffer.
    /// The distance is positive: `source_pos = current_pos - distance`.
    Distance(i64),
}

/// Wire-level constants for offset encoding.
pub(crate) const SOURCE_COPY_RAW: u32 = 0x54000;
pub(crate) const LRU_BASE_RAW: u32 = 0x54001;
pub(crate) const RAW_OFFSET_BASE: u32 = 0x54003;
pub(crate) const OFFSET_BIAS: u32 = 0x2a000;

impl CopyOffset {
    /// Convert from the raw wire offset value to a typed CopyOffset.
    pub fn from_raw(raw: u32) -> Self {
        if raw == SOURCE_COPY_RAW {
            CopyOffset::SourceCopy
        } else if (LRU_BASE_RAW..LRU_BASE_RAW + 3).contains(&raw) {
            CopyOffset::Lru((raw - LRU_BASE_RAW) as u8)
        } else if raw >= RAW_OFFSET_BASE {
            CopyOffset::Distance((raw - RAW_OFFSET_BASE) as i64)
        } else {
            // Signed offset (slots 0-2): raw_offset - OFFSET_BIAS
            CopyOffset::Distance(raw as i64 - OFFSET_BIAS as i64)
        }
    }

    /// Convert to the raw wire offset value for encoding.
    pub fn to_raw(&self, _ref_len: usize) -> u32 {
        match self {
            CopyOffset::SourceCopy => SOURCE_COPY_RAW,
            CopyOffset::Lru(idx) => LRU_BASE_RAW + *idx as u32,
            CopyOffset::Distance(dist) => {
                if *dist >= 0 {
                    *dist as u32 + RAW_OFFSET_BASE
                } else {
                    (*dist + OFFSET_BIAS as i64) as u32
                }
            }
        }
    }

    /// Resolve to the actual signed distance for copying.
    pub fn resolve(&self, lru: &[i64; 3], ref_len: usize) -> i64 {
        match self {
            CopyOffset::SourceCopy => ref_len as i64,
            CopyOffset::Lru(idx) => lru[*idx as usize],
            CopyOffset::Distance(d) => *d,
        }
    }

    /// Whether this offset should update the LRU queue.
    pub fn updates_lru(&self) -> bool {
        // All offset types update the LRU (confirmed from decompiled Run)
        true
    }
}

/// 3-element LRU queue for recent copy distances.
#[derive(Debug, Clone)]
pub struct LruQueue {
    entries: [i64; 3],
}

impl LruQueue {
    pub fn new() -> Self {
        LruQueue { entries: [0; 3] }
    }

    pub fn get(&self) -> &[i64; 3] {
        &self.entries
    }

    /// Update the LRU with a new distance, promoting it to front.
    pub fn update(&mut self, distance: i64) {
        if self.entries[0] != distance {
            let old_1 = self.entries[1];
            self.entries[1] = self.entries[0];
            self.entries[0] = distance;
            if old_1 != distance {
                self.entries[2] = old_1;
            }
        }
    }
}

impl Default for LruQueue {
    fn default() -> Self {
        Self::new()
    }
}
