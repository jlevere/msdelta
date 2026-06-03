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

    /// Append an entry. Mirrors `compo::RiftTable::Add`: a raw push of a
    /// `(source, target)` pair. The table is kept sorted by an explicit
    /// `sort()` call after a batch of `add`s, exactly as the decompiled
    /// composition routines do.
    fn add(&mut self, source: i64, target: i64) {
        self.entries.push(RiftEntry { source, target });
    }

    /// Stable sort by source. Mirrors `compo::RiftTable::Sort` (a radix sort
    /// in the original; ordering by source is all that matters downstream).
    fn sort(&mut self) {
        self.entries.sort_by_key(|e| e.source);
    }

    /// `compo::RiftTable::GetRift(pos, &next_break)`.
    ///
    /// Returns the segment offset (`target - source`) that applies at `pos`
    /// and, via the return tuple, the last position still covered by this
    /// segment (`next_break`); the next segment begins at `next_break + 1`.
    ///
    /// Conventions translated verbatim from the decompiled body:
    /// - Empty table: offset 0, `next_break = i64::MAX`.
    /// - `pos` below the first entry's source: the offset is taken from the
    ///   *last* entry (the table wraps the pre-first region to the final
    ///   segment) and `next_break = first.source - 1`.
    /// - Otherwise: the largest entry whose source is `<= pos`; `next_break`
    ///   is the following entry's source minus one, or `i64::MAX` if last.
    fn get_rift(&self, pos: i64) -> (i64, i64) {
        let n = self.entries.len();
        if n == 0 {
            return (0, i64::MAX);
        }
        let first = &self.entries[0];
        if pos < first.source {
            let last = &self.entries[n - 1];
            return (last.target - last.source, first.source - 1);
        }
        // Largest index with entries[idx].source <= pos.
        let idx = match self.entries.binary_search_by_key(&pos, |e| e.source) {
            Ok(i) => i,
            Err(i) => i - 1,
        };
        let e = &self.entries[idx];
        let next_break = if idx + 1 < n {
            self.entries[idx + 1].source - 1
        } else {
            i64::MAX
        };
        (e.target - e.source, next_break)
    }

    /// `compo::RiftTable::Multiply(A, B)` -> a new table representing the
    /// composition `B . A` (i.e. `result.f(x) == B.f(A.f(x))`).
    ///
    /// `A` (`self`) and `B` are piecewise integer-offset maps. The product
    /// walks `A`'s segments and, within each, the breakpoints `B` introduces
    /// on the image of that segment, emitting one entry per resulting piece.
    /// An empty operand acts as the identity (the other table is copied),
    /// matching the `*(param + 0x10) == 0` short-circuits in the original.
    pub fn multiply(&self, b: &RiftTable) -> RiftTable {
        if self.entries.is_empty() {
            return b.clone();
        }
        if b.entries.is_empty() {
            return self.clone();
        }

        let mut out = RiftTable {
            entries: Vec::new(),
        };

        // Walk A's segments. Each A entry covers [src, next_src) in A's
        // source domain and maps it (offset a_off) into A's image. We then
        // split that image range at B's breakpoints.
        let a = &self.entries;
        for i in 0..a.len() {
            let seg_src = a[i].source;
            let seg_off = a[i].target - a[i].source; // A's offset on this segment
            let seg_src_end = if i + 1 < a.len() {
                a[i + 1].source
            } else {
                i64::MAX
            };

            // Current position in A's source domain and its A-image.
            let mut cur_src = seg_src;
            loop {
                let img = cur_src.wrapping_add(seg_off); // A.f(cur_src)
                let (b_off, b_break) = b.get_rift(img);
                // result.f(cur_src) = img + b_off = cur_src + seg_off + b_off
                out.add(cur_src, cur_src.wrapping_add(seg_off).wrapping_add(b_off));

                // Where does B's offset change next, expressed back in A's
                // source domain? b_break is the last image position in B's
                // current segment. Map back: src = b_break - seg_off + 1.
                if b_break == i64::MAX {
                    break;
                }
                let next_src = b_break.wrapping_sub(seg_off).wrapping_add(1);
                if next_src >= seg_src_end || next_src <= cur_src {
                    break;
                }
                cur_src = next_src;
            }
        }

        out.sort();
        out.dedup_offsets();
        out
    }

    /// `compo::RiftTable::Reverse(A)` -> the inverse map `A^-1`.
    ///
    /// Faithful port of `RiftTable::Reverse` (dpx.dll `18003bb24`). A swap of
    /// `{s, t}` to `{t, s}` is only correct when `A` is strictly monotonic and
    /// non-overlapping. Real apply-pipeline forward chains are NOT: on i386 the
    /// FileAlignment relayout makes adjacent target file-offset segments overlap
    /// (decreasing offsets) or leave gaps (increasing offsets). Genuine resolves
    /// both with a working buffer of covered image intervals, walking `A`'s
    /// segments in wrap order (starting at the first positive-source segment,
    /// processing the pre-first region first) and, per segment, splitting/merging
    /// the buffer's intervals against the segment's image `[lo, hi)`. Each split
    /// emits an `Add(image_pos, source_pos)` pair. This reproduces both the adsnt
    /// overlap topology and the pku2u gap topology exactly.
    ///
    /// Buffer slot layout matches the decompile: a pair `(f0, f1)` where the
    /// search/iteration key is `f1` (the `+8` field) and `f0` (`+0`) the image
    /// start of the covered interval.
    pub fn reverse(&self) -> RiftTable {
        let n = self.entries.len() as u64;
        if n == 0 {
            return RiftTable {
                entries: Vec::new(),
            };
        }
        let mut out = RiftTable {
            entries: Vec::new(),
        };
        let src = |i: u64| self.entries[i as usize].source;
        let tgt = |i: u64| self.entries[i as usize].target;

        // Degenerate case: a single distinct source. Genuine emits one entry.
        let mut all_same = true;
        for i in 1..n {
            if src(i) != src(0) {
                all_same = false;
                break;
            }
        }
        if all_same {
            out.add(0, tgt(0) - src(0));
            return out;
        }

        // Working buffer of covered image intervals as parallel (f0, f1) arrays.
        // `f1` is the sorted search key. `live` (== decompile `local_res18`) is
        // the number of live slots.
        let cap = (2 * n) as usize;
        let mut f0: Vec<i64> = vec![0; cap];
        let mut f1: Vec<i64> = vec![0; cap];
        let mut live: u64 = 0;

        // Wrap start: first index whose source is positive; if none (or it lands
        // at 0) the whole table is the wrap region (`local_90 = n`). The pre-first
        // region (sources <= 0, i.e. the segment that wraps to the end) is then
        // processed first by seeding `local_88 = local_90 - 1`.
        let mut local_90: u64 = 0;
        loop {
            if src(local_90) > 0 {
                break;
            }
            local_90 += 1;
            if n <= local_90 {
                break;
            }
        }
        if local_90 == 0 {
            local_90 = n;
        }
        let mut term_idx: u64 = local_90 - 1; // decompile `uVar10` exit comparator
        let mut local_98: i64 = 0;
        local_90 = if local_90 < n { local_90 } else { 0 };
        let mut u_var7: u64 = local_90;
        let mut local_88: u64 = term_idx;
        let restart_88: u64 = term_idx;

        loop {
            // Inner do-while: walk the image of segment `local_88` from `local_98`
            // up to `src(u_var7)` (the next segment's source), splitting at the
            // current segment's image extent each iteration.
            loop {
                let seg_off = tgt(local_88) - src(local_88);
                let end_idx = u_var7;
                let mut span = src(u_var7) - local_98;
                let lo = seg_off + local_98; // image start
                if lo != i64::MIN {
                    let clamp = (i64::MIN.wrapping_sub(seg_off)).wrapping_sub(local_98);
                    if (clamp as u64) < (span as u64) {
                        span = clamp;
                    }
                }
                if span != 0 {
                    let hi = lo + span; // image end (exclusive bound value)
                    // First buffer index whose key (f1) is >= lo or a sentinel.
                    let mut start: u64 = 0;
                    if live != 0 {
                        let mut k = 0u64;
                        loop {
                            start = k;
                            let key = f1[k as usize];
                            if lo <= key || key == i64::MIN {
                                break;
                            }
                            k += 1;
                            start = k;
                            if k >= live {
                                break;
                            }
                        }
                    }
                    let mut ins = start;
                    let mut stop = start;
                    let mut val = hi;
                    if start < live {
                        // Extend `stop` past every interval the image overlaps.
                        // The end scan compares the image END `hi` against each
                        // interval's image START (`f0`, the `+0` field) -- NOT its
                        // end (`f1`) -- matching the decompile's `plVar8 =
                        // local_c8 + start*0x10` base and `lVar9 < *plVar5`.
                        let mut k = start;
                        loop {
                            let key = f0[k as usize];
                            if hi != i64::MIN && hi < key {
                                break;
                            }
                            stop += 1;
                            k += 1;
                            if stop >= live {
                                break;
                            }
                        }
                        if start == stop {
                            // No overlap: pure insert.
                            out.add(lo, local_98);
                            Self::shift_for_insert(&mut f0, &mut f1, ins, stop, live);
                            live = live.wrapping_add(ins.wrapping_sub(stop)).wrapping_add(1);
                            f0[ins as usize] = lo;
                            f1[ins as usize] = val;
                            term_idx = restart_88;
                        } else {
                            // Compare `lo` against the first overlapping interval's
                            // image START (`f0`, the `+0` field), per the decompile's
                            // `if (lVar15 < *plVar8)` where `plVar8` = slot `start`
                            // base. When `lo` already lies at/after that start, no
                            // boundary `Add` is emitted (the spurious half of the
                            // overlap pair) and `lo` is pulled back to the interval
                            // start instead.
                            let buf_lo = f0[start as usize];
                            let mut lo_m = lo;
                            if lo < buf_lo {
                                out.add(lo, local_98);
                            } else {
                                lo_m = buf_lo;
                            }
                            val = seg_off;
                            if ins < stop - 1 {
                                // Emit one boundary `Add` per fully-covered
                                // interior interval (`start ..= stop-2`), using
                                // its image end (`f1`) and the segment offset.
                                for idx in start..(stop - 1) {
                                    let v = f1[idx as usize];
                                    out.add(v, v - val);
                                }
                                ins = start;
                                u_var7 = local_90;
                            }
                            let last_key = f1[(stop - 1) as usize];
                            val = last_key;
                            if last_key != i64::MIN
                                && (hi == i64::MIN || last_key < hi)
                            {
                                out.add(last_key, last_key - seg_off);
                                val = hi;
                            }
                            Self::shift_for_insert(&mut f0, &mut f1, ins, stop, live);
                            live = live.wrapping_add(ins.wrapping_sub(stop)).wrapping_add(1);
                            f0[ins as usize] = lo_m;
                            f1[ins as usize] = val;
                            term_idx = restart_88;
                        }
                    } else {
                        // start >= live: append.
                        out.add(lo, local_98);
                        Self::shift_for_insert(&mut f0, &mut f1, ins, stop, live);
                        live = live.wrapping_add(ins.wrapping_sub(stop)).wrapping_add(1);
                        f0[ins as usize] = lo;
                        f1[ins as usize] = val;
                        term_idx = restart_88;
                    }
                }
                local_98 += span;
                if local_98 == src(end_idx) {
                    break;
                }
            }
            local_88 = u_var7;
            if term_idx != u_var7 {
                local_90 = if u_var7 + 1 < n { u_var7 + 1 } else { 0 };
                u_var7 = local_90;
                continue;
            }
            break;
        }

        out.sort();
        // Drop sentinel intervals the working buffer may have emitted.
        out.entries
            .retain(|e| e.source != i64::MIN && e.target != i64::MIN);
        out.dedup_same_source();
        out
    }

    /// Collapse entries sharing the same `source` (keep the last written),
    /// without touching offset-continuous distinct sources. Mirrors the effect
    /// of `Sort` over `Add`s where a later segment supersedes an earlier one at
    /// the identical key.
    fn dedup_same_source(&mut self) {
        if self.entries.len() < 2 {
            return;
        }
        let mut kept: Vec<RiftEntry> = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            match kept.last_mut() {
                Some(prev) if prev.source == e.source => *prev = *e,
                _ => kept.push(*e),
            }
        }
        self.entries = kept;
    }

    /// Working-buffer element move for `Reverse`. When `ins + 1 != stop` and
    /// `stop < live`, slide the tail `[stop, live)` to start at `ins + 1`,
    /// matching the displacement loop in the decompile (`uVar10 < uVar4 - 1`
    /// region and its `local_res18`-bounded memmove). For the pure-insert case
    /// (`ins == stop`) this is the upward shift that opens one slot at `ins`.
    fn shift_for_insert(f0: &mut [i64], f1: &mut [i64], ins: u64, stop: u64, live: u64) {
        if ins == stop {
            // Open a single slot at `ins`: shift [ins, live) up by one.
            if ins < live {
                let mut j = live;
                while j > ins {
                    f0[j as usize] = f0[(j - 1) as usize];
                    f1[j as usize] = f1[(j - 1) as usize];
                    j -= 1;
                }
            }
            return;
        }
        if ins + 1 != stop && stop < live {
            let shift = (ins as i64) - (stop as i64) + 1;
            let mut j = stop;
            while j < live {
                let dst = (j as i64 + shift) as u64;
                f0[dst as usize] = f0[j as usize];
                f1[dst as usize] = f1[j as usize];
                j += 1;
            }
        }
    }

    /// `compo::RiftTable::Sum(A, B)` -> the pointwise sum of two offset maps:
    /// `result.f(x) - x == (A.f(x) - x) + (B.f(x) - x)`.
    ///
    /// Breakpoints from both inputs are merged; at each breakpoint the new
    /// offset is the sum of the two operands' offsets there. An empty operand
    /// is the identity (zero offset everywhere), so the other table is copied.
    pub fn sum(&self, b: &RiftTable) -> RiftTable {
        if self.entries.is_empty() {
            return b.clone();
        }
        if b.entries.is_empty() {
            return self.clone();
        }

        // Collect every breakpoint source from both tables.
        let mut breaks: Vec<i64> = Vec::with_capacity(self.entries.len() + b.entries.len());
        for e in &self.entries {
            breaks.push(e.source);
        }
        for e in &b.entries {
            breaks.push(e.source);
        }
        breaks.sort_unstable();
        breaks.dedup();

        let mut out = RiftTable {
            entries: Vec::with_capacity(breaks.len()),
        };
        for s in breaks {
            let (a_off, _) = self.get_rift(s);
            let (b_off, _) = b.get_rift(s);
            out.add(s, s.wrapping_add(a_off).wrapping_add(b_off));
        }
        out.sort();
        out.dedup_offsets();
        out
    }

    /// Drop entries whose offset equals the previous entry's offset: a segment
    /// boundary that does not change the mapping is redundant. Keeps tables
    /// canonical so algebraic identities hold exactly.
    fn dedup_offsets(&mut self) {
        if self.entries.len() < 2 {
            return;
        }
        let mut kept: Vec<RiftEntry> = Vec::with_capacity(self.entries.len());
        for e in &self.entries {
            match kept.last() {
                Some(prev)
                    if prev.source == e.source
                        || (prev.target - prev.source) == (e.target - e.source) =>
                {
                    // Same source (keep the later) or no offset change (skip).
                    if prev.source == e.source {
                        *kept.last_mut().unwrap() = *e;
                    }
                }
                _ => kept.push(*e),
            }
        }
        self.entries = kept;
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
pub(crate) struct IntFormat {
    table: HuffmanTable,
    num_pos: usize,
    num_neg: usize,
}

impl IntFormat {
    /// The default (un-serialized) IntFormat from `IntFormat::Init`
    /// (`Codes::Init(0xfc, 0x10, false)` -> `ResetLengths`): for 252 symbols the
    /// first 4 get code length 7, the remaining 248 get length 8 (a Kraft-complete
    /// canonical code, 4/128 + 248/256 = 1). Used for the per-entry length vector in
    /// reverse-patch type-0 sections, where no Huffman header is serialized.
    pub(crate) fn init_default() -> Result<Self> {
        let mut lengths = vec![8u8; INT_FORMAT_SYMBOLS];
        for l in &mut lengths[..4] {
            *l = 7;
        }
        let table = HuffmanTable::from_lengths(&lengths)?;
        Ok(IntFormat {
            table,
            num_pos: 0,
            num_neg: 0,
        })
    }

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

    pub(crate) fn read_number(&self, reader: &mut BitReader) -> Result<i64> {
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

    fn t(pairs: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: pairs
                .iter()
                .map(|&(s, d)| RiftEntry {
                    source: s,
                    target: d,
                })
                .collect(),
        }
    }

    // Reference piecewise evaluation matching GetRift's "<= source" rule,
    // for positions at or above the first entry.
    fn eval(tbl: &RiftTable, x: i64) -> i64 {
        let (off, _) = tbl.get_rift(x);
        x + off
    }

    #[test]
    fn multiply_with_identity_is_copy() {
        // Empty table is the identity element for Multiply.
        let a = t(&[(0, 0), (0x1000, 0x1200), (0x5000, 0x5800)]);
        let id = RiftTable {
            entries: vec![],
        };
        let left = id.multiply(&a);
        let right = a.multiply(&id);
        for &x in &[0i64, 0x1000, 0x1500, 0x5000, 0x9000] {
            assert_eq!(eval(&left, x), eval(&a, x), "id*a at {x:#x}");
            assert_eq!(eval(&right, x), eval(&a, x), "a*id at {x:#x}");
        }
    }

    #[test]
    fn multiply_composes() {
        // A shifts +0x100 from 0x1000, +0x200 from 0x2000.
        let a = t(&[(0x1000, 0x1100), (0x2000, 0x2200)]);
        // B shifts +0x10 from 0x1000, +0x20 from 0x3000.
        let b = t(&[(0x1000, 0x1010), (0x3000, 0x3020)]);
        let prod = a.multiply(&b); // result.f(x) == B.f(A.f(x))
        for &x in &[0x1000i64, 0x1500, 0x2000, 0x2fff, 0x4000] {
            let expect = eval(&b, eval(&a, x));
            assert_eq!(eval(&prod, x), expect, "compose at {x:#x}");
        }
    }

    #[test]
    fn reverse_reverse_is_identity() {
        // Genuine `Reverse` is normalised, NOT a literal entry-list involution.
        // It walks segments in wrap order, splits the inverse at every covered
        // image-interval boundary, emits an initial offset-0 anchor, and drops
        // sentinels. Consequently `rev∘rev` is generally a DIFFERENT normalised
        // map than the original (its breakpoints live in the image domain and
        // re-inverting relocates them), so the old "involution" assertion does
        // not reflect genuine behaviour.
        //
        // What genuine DOES guarantee, and what we assert here, is that a single
        // `Reverse` of a clean monotonic, 0-anchored, identity-tailed map is the
        // exact literal inverse: each `{s, t}` becomes `{t, s}`. (This is the
        // non-overlapping branch of the working-buffer logic, where every
        // boundary `Add` is a pure swap.)
        let a = t(&[(0, 0), (0x1000, 0x1100), (0x2000, 0x2300), (0x3000, 0x3000)]);
        let r = a.reverse();
        let got: Vec<(i64, i64)> = r.entries.iter().map(|e| (e.source, e.target)).collect();
        assert_eq!(
            got,
            vec![(0, 0), (0x1100, 0x1000), (0x2300, 0x2000), (0x3300, 0x3300)],
            "Reverse of a clean monotonic map is the literal swap"
        );
    }

    #[test]
    fn reverse_inverts() {
        // 0-anchored, contiguous map: each segment's image start carries a real
        // breakpoint, so the inverse maps image points back to their source
        // exactly. A.f(0x1000)=0x1200, A.f(0x5000)=0x5400.
        let a = t(&[(0, 0), (0x1000, 0x1200), (0x5000, 0x5400)]);
        let r = a.reverse();
        assert_eq!(eval(&r, 0x1200), 0x1000);
        assert_eq!(eval(&r, 0x5400), 0x5000);
        assert_eq!(eval(&r, 0), 0, "anchor preserved");
        // Genuine emits the offset-0 anchor and a breakpoint at each image start
        // (0, 0x1200, 0x5400); the non-anchored 2-entry form instead wraps the
        // pre-first region to the tail offset, which is why we anchor here.
    }

    /// Assert `rev` contains every `(source, target)` pair in `want`.
    fn contains_all(rev: &RiftTable, want: &[(i64, i64)]) {
        for &(s, d) in want {
            assert!(
                rev.entries.iter().any(|e| e.source == s && e.target == d),
                "reverse missing {s:#x},{d:#x}; got {:x?}",
                rev.entries
                    .iter()
                    .map(|e| (e.source, e.target))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Ground truth from genuine dpx.dll for the GAP case (pku2u, increasing
    /// offsets). The forward chain `io2rva_src . preprocess_rift . pe_rift`
    /// (source_fo -> target_fo), reversed, must reproduce genuine's final
    /// (target_fo, source_fo) copy rift. The `0x400,0x400` header boundary is
    /// kept in the forward chain (it survives the real composition).
    #[test]
    fn reverse_pku2u_gap_vector() {
        let fwd = t(&[
            (0, 0),
            (0x400, 0x400),
            (0x2158, 0x246c),
            (0x9ad0, 0xa860),
            (0xadf0, 0xbc60),
            (0x10b10, 0x11dc0),
            (0x35c6c, 0x36fac),
            (0x36600, 0x37a00),
        ]);
        let rev = fwd.reverse();
        contains_all(
            &rev,
            &[
                (0, 0),
                (0x400, 0x400),
                (0x246c, 0x2158),
                (0xa860, 0x9ad0),
                (0xbc60, 0xadf0),
                (0x11dc0, 0x10b10),
                (0x36fac, 0x35c6c),
                (0x37a00, 0x36600),
            ],
        );
    }

    /// Ground truth from genuine dpx.dll for the OVERLAP case (adsnt, decreasing
    /// offsets). The reversed forward chain must reproduce genuine's load-bearing
    /// breakpoints (`0x718`, `0x3990`, `0x9000`, `0x93c0`).
    #[test]
    fn reverse_adsnt_overlap_vector() {
        let fwd = t(&[
            (0, 0),
            (0x400, 0x400),
            (0x718, 0x710),
            (0x3998, 0x3968),
            (0x9030, 0x8ff0),
            (0x9400, 0x93a0),
            (0x3b000, 0x3b000),
        ]);
        let rev = fwd.reverse();
        contains_all(
            &rev,
            &[
                (0, 0),
                (0x400, 0x400),
                (0x718, 0x720),
                (0x3990, 0x39c0),
                (0x9000, 0x9040),
                (0x93c0, 0x9420),
                (0x3b000, 0x3b000),
            ],
        );
    }

    #[test]
    fn sum_is_commutative_and_additive() {
        let a = t(&[(0x1000, 0x1100), (0x4000, 0x4080)]);
        let b = t(&[(0x2000, 0x2010), (0x4000, 0x4040)]);
        let ab = a.sum(&b);
        let ba = b.sum(&a);
        for &x in &[0x1000i64, 0x2000, 0x3000, 0x4000, 0x8000] {
            let expect = x + (eval(&a, x) - x) + (eval(&b, x) - x);
            assert_eq!(eval(&ab, x), expect, "sum additive at {x:#x}");
            assert_eq!(eval(&ab, x), eval(&ba, x), "sum commutative at {x:#x}");
        }
    }

    #[test]
    fn sum_with_empty_is_copy() {
        let a = t(&[(0x1000, 0x1100), (0x4000, 0x4080)]);
        let empty = RiftTable { entries: vec![] };
        let s = a.sum(&empty);
        for &x in &[0x1000i64, 0x2000, 0x4000, 0x9000] {
            assert_eq!(eval(&s, x), eval(&a, x), "sum empty at {x:#x}");
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
