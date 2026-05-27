use crate::lzms::BackBits;

// Offset slot base values extracted from cabinet.dll (verified against wimlib).
// Generated from group definitions: (num_slots, extra_bits) pairs.
const OFFSET_GROUPS: &[(u32, u32)] = &[
    (8, 0), (9, 2), (7, 3), (10, 4), (15, 5), (15, 6),
    (20, 7), (20, 8), (30, 9), (33, 10), (40, 11), (42, 12),
    (45, 13), (60, 14), (73, 15), (80, 16), (85, 17), (95, 18),
    (105, 19), (6, 20), (1, 30),
];

// Length slot base values from cabinet.dll / wimlib lzms_length_slot_base.
// These are NOT generated from groups -- the pattern differs from the offset table.
const LENGTH_BASES: [u32; 55] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 31, 33, 35, 39,
    43, 47, 51, 55, 59, 67, 75, 83, 91, 107, 123, 139, 155, 171, 203, 235,
    299, 427, 683, 1195, 2219, 67755, 0x4001_08AB,
];

const LENGTH_EXTRA: [u8; 54] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 6,
    7, 8, 9, 10, 16, 30,
];

const MAX_OFFSET_SLOTS: usize = 799;

struct OffsetTable {
    bases: Vec<u32>,
}

impl OffsetTable {
    fn generate() -> Self {
        let mut bases = Vec::with_capacity(MAX_OFFSET_SLOTS + 1);
        let mut val = 1u32;
        for &(count, eb) in OFFSET_GROUPS {
            let range = 1u32 << eb;
            for _ in 0..count {
                bases.push(val);
                val = val.saturating_add(range);
            }
        }
        bases.push(0x7FFF_FFFF);
        OffsetTable { bases }
    }

    fn extra_bits(&self, slot: usize) -> u32 {
        let range = self.bases[slot + 1] - self.bases[slot];
        if range <= 1 { 0 } else { 31 - range.leading_zeros() }
    }
}

static OFFSET_TABLE: std::sync::LazyLock<OffsetTable> =
    std::sync::LazyLock::new(OffsetTable::generate);

pub fn num_offset_slots(output_size: u32) -> usize {
    if output_size < 2 { return 0; }
    let t = &OFFSET_TABLE;
    let mut n = 1;
    while n < t.bases.len() - 1 && t.bases[n] < output_size {
        n += 1;
    }
    n
}

pub fn decode_offset(slot: usize, bs: &mut BackBits) -> u32 {
    let t = &OFFSET_TABLE;
    let base = t.bases[slot];
    let eb = t.extra_bits(slot);
    if eb == 0 { return base; }
    base + bs.read_bits(eb)
}

pub fn decode_length(slot: usize, bs: &mut BackBits) -> u32 {
    let base = LENGTH_BASES[slot];
    let eb = LENGTH_EXTRA[slot] as u32;
    if eb == 0 { return base; }
    base + bs.read_bits(eb)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_table_matches_dll() {
        let t = &*OFFSET_TABLE;
        assert_eq!(t.bases.len(), MAX_OFFSET_SLOTS + 1);
        assert_eq!(t.bases[0], 1);
        assert_eq!(t.bases[8], 9);
        assert_eq!(t.bases[9], 13);
        assert_eq!(t.bases[24], 101);
        assert_eq!(*t.bases.last().unwrap(), 0x7FFF_FFFF);
    }

    #[test]
    fn length_table_matches_dll() {
        assert_eq!(LENGTH_BASES[0], 1);
        assert_eq!(LENGTH_BASES[25], 26);
        assert_eq!(LENGTH_BASES[26], 27);
        assert_eq!(LENGTH_BASES[27], 29);
        assert_eq!(LENGTH_BASES[53], 67755);
        assert_eq!(LENGTH_EXTRA[25], 0);
        assert_eq!(LENGTH_EXTRA[26], 1);
        assert_eq!(LENGTH_EXTRA[53], 30);
    }
}
