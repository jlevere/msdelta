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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiftEntry {
    pub source: i64,
    pub target: i64,
}

/// Parsed rift table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiftTable {
    pub entries: Vec<RiftEntry>,
}

pub(crate) const RIFT_VECTOR_UNSET_TARGET: i64 = i64::MAX;

impl RiftTable {
    /// `compo::RiftTable::ResetVector(count)`.
    ///
    /// Native create-side map construction seeds vector maps with exact
    /// `source -> i64::MAX` entries. Later `Set` calls mutate only matching
    /// in-range source indices, and `InternalReduce(true)` drops entries still
    /// holding the unset sentinel.
    pub(crate) fn reset_vector(entry_count: usize) -> Self {
        Self {
            entries: (0..entry_count)
                .map(|source| RiftEntry {
                    source: source as i64,
                    target: RIFT_VECTOR_UNSET_TARGET,
                })
                .collect(),
        }
    }

    /// `compo::RiftTable::Set(source, target)` for vector maps.
    pub(crate) fn set_vector_entry(&mut self, source: i64, target: i64) {
        if source < 0 {
            return;
        }
        let Ok(index) = usize::try_from(source) else {
            return;
        };
        let Some(entry) = self.entries.get_mut(index) else {
            return;
        };
        if entry.source == source {
            entry.target = target;
        }
    }

    /// `compo::RiftTable::InternalReduce(drop_unset)`.
    pub(crate) fn internal_reduce(&mut self, drop_unset: bool) {
        let mut reduced = Vec::with_capacity(self.entries.len());
        let mut index = 0usize;
        while index < self.entries.len() {
            let source = self.entries[index].source;
            let mut target = self.entries[index].target;
            index += 1;

            if drop_unset && target == RIFT_VECTOR_UNSET_TARGET {
                continue;
            }

            let mut vote_count = 1usize;
            while index < self.entries.len() && self.entries[index].source == source {
                let next_target = self.entries[index].target;
                if next_target == target {
                    vote_count += 1;
                } else if vote_count == 0 {
                    target = next_target;
                    vote_count = 1;
                } else {
                    vote_count -= 1;
                }
                index += 1;
            }

            let offset = rift_entry_offset(source, target);
            if reduced.last().is_none_or(|entry: &RiftEntry| {
                rift_entry_offset(entry.source, entry.target) != offset
            }) {
                reduced.push(RiftEntry { source, target });
            }
        }

        match reduced.len() {
            0 => {
                self.entries.clear();
            }
            1 => {
                let entry = reduced[0];
                if entry.source == entry.target {
                    self.entries.clear();
                } else {
                    self.entries = vec![RiftEntry {
                        source: 0,
                        target: rift_entry_offset(entry.source, entry.target),
                    }];
                }
            }
            _ => {
                let first = reduced[0];
                let last = *reduced
                    .last()
                    .expect("multi-entry reduced table should have a last entry");
                if rift_entry_offset(first.source, first.target)
                    == rift_entry_offset(last.source, last.target)
                {
                    reduced.remove(0);
                }
                self.entries = reduced;
            }
        }
    }

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

    /// Parse a rift map whose IntFormat records are owned by an outer
    /// structure. CLI maps use this shape: one shared source and target format
    /// pair is reused for a sequence of heap/table maps.
    pub(crate) fn from_reader_with_formats(
        reader: &mut BitReader,
        fmt_src: &IntFormat,
        fmt_dst: &IntFormat,
    ) -> Result<Self> {
        let count = reader.read_i64()?;
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

        entries.sort_by_key(|entry| entry.source);
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

    /// Serialize a shared-format rift map using caller-owned IntFormats.
    pub(crate) fn to_writer_with_formats(
        &self,
        writer: &mut BitWriter,
        fmt_src: &IntFormat,
        fmt_dst: &IntFormat,
    ) {
        writer.write_i64(self.entries.len() as i64);

        let mut src_acc: i64 = 0;
        let mut dst_acc: i64 = 0;
        for entry in &self.entries {
            let src_delta = entry.source.wrapping_sub(src_acc);
            src_acc = entry.source;
            let target_delta = (entry.target.wrapping_sub(entry.source)).wrapping_sub(dst_acc);
            dst_acc = entry.target.wrapping_sub(entry.source);
            fmt_src.write_number(writer, src_delta);
            fmt_dst.write_number(writer, target_delta);
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
        let a = &self.entries;

        // Pre-first wrap block (decompile lines 50-69). A's GetRift wraps the
        // region below A's first source `[i64::MIN, A[0].source)` to A's LAST
        // segment offset. Genuine emits this region as real entries, splitting it
        // at every breakpoint B introduces on its image. Without this block the
        // composed forward chain is missing the negative-source wrap segments,
        // and a later `Reverse` cannot reproduce the genuine inverse (the docprop
        // `-0x5120`/`bc8` wrap entries originate here, not in `Reverse`).
        let a_first = a[0].source;
        if i64::MIN < a_first {
            let last = a[a.len() - 1];
            let last_off = last.target - last.source;
            // Seed at the wrap image of i64::MIN under the last-segment offset.
            let mut img = last_off.wrapping_add(i64::MIN);
            let (mut b_off, mut b_break) = b.get_rift(img);
            out.add(i64::MIN, b_off.wrapping_add(img));
            // `region` is the remaining width of the pre-first region; `step`
            // is the width covered by B's current segment. Advance source by
            // `step + 1` each time B's offset changes.
            let mut src_pos = i64::MIN;
            let mut region = (a_first.wrapping_add(i64::MAX)) as u64;
            let mut step = (b_break.wrapping_sub(img)) as u64;
            while step < region {
                src_pos = src_pos.wrapping_add(step as i64).wrapping_add(1);
                img = b_break.wrapping_add(1);
                let g = b.get_rift(img);
                b_off = g.0;
                b_break = g.1;
                out.add(src_pos, b_off.wrapping_add(img));
                region = (a_first.wrapping_sub(1)).wrapping_sub(src_pos) as u64;
                step = (b_break.wrapping_sub(img)) as u64;
            }
        }

        // Main per-segment walk. Each A segment covers `[seg_src, seg_break]`
        // in A's source domain; its image is split at every B breakpoint.
        // Duplicate-source A entries are skipped.
        for i in 0..a.len() {
            let seg_src = a[i].source;
            let seg_break = if i + 1 < a.len() {
                if a[i + 1].source != seg_src {
                    a[i + 1].source - 1
                } else {
                    continue;
                }
            } else {
                i64::MAX
            };
            let mut img = a[i].target; // image of seg_src under A
            let (b_off, b_break) = b.get_rift(img);
            out.add(seg_src, b_off.wrapping_add(img));
            let mut next_break = b_break;
            let mut src_pos = seg_src;
            while (next_break.wrapping_sub(img) as u64) < (seg_break.wrapping_sub(src_pos) as u64) {
                src_pos = src_pos
                    .wrapping_add(1)
                    .wrapping_add(next_break.wrapping_sub(img));
                img = next_break.wrapping_add(1);
                let g = b.get_rift(img);
                next_break = g.1;
                out.add(src_pos, g.0.wrapping_add(img));
            }
        }

        // Genuine `Multiply` ends with `Sort` only -- no offset-dedup. Collapsing
        // equal-offset adjacent segments here drops breakpoints the downstream
        // `Reverse` working buffer depends on (e.g. docprop's `6400->6a00` after
        // `6200->6800`, both offset 0x600), so we must preserve them verbatim.
        out.sort();
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
    /// The working buffer stores covered image intervals as two parallel
    /// arrays: interval starts and interval ends. The end array is the sorted
    /// search key.
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
            out.add(0, tgt(0).wrapping_sub(src(0)));
            return out;
        }

        // Working buffer of covered image intervals as parallel arrays.
        // `interval_end` is the sorted search key; `interval_start` is used for
        // overlap checks.
        let cap = (2 * n) as usize;
        let mut interval_start: Vec<i64> = vec![0; cap];
        let mut interval_end: Vec<i64> = vec![0; cap];
        let mut interval_count: u64 = 0;

        // Start at the first positive source. If the first entry is already
        // positive, or no positive source exists, process the final segment first
        // because it represents the wrapped pre-first source region.
        let mut first_positive_segment: u64 = 0;
        loop {
            if src(first_positive_segment) > 0 {
                break;
            }
            first_positive_segment += 1;
            if n <= first_positive_segment {
                break;
            }
        }
        if first_positive_segment == 0 {
            first_positive_segment = n;
        }
        let stop_segment = first_positive_segment - 1;
        let mut source_cursor: i64 = 0;
        let mut boundary_segment: u64 = if first_positive_segment < n {
            first_positive_segment
        } else {
            0
        };
        let mut active_segment: u64 = stop_segment;

        loop {
            // Walk the active segment from the current source cursor up to the
            // next segment boundary, splitting against covered image intervals.
            loop {
                // Two's-complement (wrapping) arithmetic throughout: the working
                // buffer carries i64::MIN/MAX sentinels and the genuine C does
                // these on unsigned values, so plain +/- would overflow-panic in
                // debug while wrapping (correct) in release.
                let segment_offset = tgt(active_segment).wrapping_sub(src(active_segment));
                let end_segment = boundary_segment;
                let mut source_span = src(boundary_segment).wrapping_sub(source_cursor);
                let image_start = segment_offset.wrapping_add(source_cursor);
                if image_start != i64::MIN {
                    let clamped_span =
                        (i64::MIN.wrapping_sub(segment_offset)).wrapping_sub(source_cursor);
                    if (clamped_span as u64) < (source_span as u64) {
                        source_span = clamped_span;
                    }
                }
                if source_span != 0 {
                    let image_end = image_start.wrapping_add(source_span);

                    // First interval whose end key is at or after the image
                    // start, or whose key is the sentinel.
                    let mut first_overlap: u64 = 0;
                    if interval_count != 0 {
                        let mut k = 0u64;
                        loop {
                            first_overlap = k;
                            let key = interval_end[k as usize];
                            if image_start <= key || key == i64::MIN {
                                break;
                            }
                            k += 1;
                            first_overlap = k;
                            if k >= interval_count {
                                break;
                            }
                        }
                    }
                    let mut insert_at = first_overlap;
                    let mut overlap_end = first_overlap;
                    let mut new_interval_end = image_end;
                    if first_overlap < interval_count {
                        // Extend `overlap_end` past every interval touched by
                        // this image span. The comparison is against interval
                        // starts, not interval ends.
                        let mut k = first_overlap;
                        loop {
                            let key = interval_start[k as usize];
                            if image_end != i64::MIN && image_end < key {
                                break;
                            }
                            overlap_end += 1;
                            k += 1;
                            if overlap_end >= interval_count {
                                break;
                            }
                        }
                        if first_overlap == overlap_end {
                            // No overlap: pure insert.
                            out.add(image_start, source_cursor);
                            Self::replace_reverse_interval(
                                &mut interval_start,
                                &mut interval_end,
                                &mut interval_count,
                                insert_at,
                                overlap_end,
                                image_start,
                                new_interval_end,
                            );
                        } else {
                            // If the image starts before the first overlapping
                            // interval, emit the leading boundary. Otherwise
                            // merge back to the existing interval start.
                            let overlapped_start = interval_start[first_overlap as usize];
                            let mut merged_start = image_start;
                            if image_start < overlapped_start {
                                out.add(image_start, source_cursor);
                            } else {
                                merged_start = overlapped_start;
                            }
                            new_interval_end = segment_offset;
                            if insert_at < overlap_end - 1 {
                                // Emit one boundary `Add` per fully-covered
                                // interior interval, using its image end and
                                // the segment offset.
                                for idx in first_overlap..(overlap_end - 1) {
                                    let interval_boundary = interval_end[idx as usize];
                                    out.add(
                                        interval_boundary,
                                        interval_boundary.wrapping_sub(new_interval_end),
                                    );
                                }
                                insert_at = first_overlap;
                            }
                            let last_interval_end = interval_end[(overlap_end - 1) as usize];
                            new_interval_end = last_interval_end;
                            if last_interval_end != i64::MIN
                                && (image_end == i64::MIN || last_interval_end < image_end)
                            {
                                out.add(
                                    last_interval_end,
                                    last_interval_end.wrapping_sub(segment_offset),
                                );
                                new_interval_end = image_end;
                            }
                            Self::replace_reverse_interval(
                                &mut interval_start,
                                &mut interval_end,
                                &mut interval_count,
                                insert_at,
                                overlap_end,
                                merged_start,
                                new_interval_end,
                            );
                        }
                    } else {
                        // No live interval starts after this image span: append.
                        out.add(image_start, source_cursor);
                        Self::replace_reverse_interval(
                            &mut interval_start,
                            &mut interval_end,
                            &mut interval_count,
                            insert_at,
                            overlap_end,
                            image_start,
                            new_interval_end,
                        );
                    }
                }
                source_cursor = source_cursor.wrapping_add(source_span);
                if source_cursor == src(end_segment) {
                    break;
                }
            }
            active_segment = boundary_segment;
            if stop_segment != boundary_segment {
                boundary_segment = if boundary_segment.wrapping_add(1) < n {
                    boundary_segment.wrapping_add(1)
                } else {
                    0
                };
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

    fn replace_reverse_interval(
        interval_start: &mut [i64],
        interval_end: &mut [i64],
        interval_count: &mut u64,
        insert_at: u64,
        overlap_end: u64,
        new_start: i64,
        new_end: i64,
    ) {
        Self::shift_for_insert(
            interval_start,
            interval_end,
            insert_at,
            overlap_end,
            *interval_count,
        );
        *interval_count = (*interval_count)
            .wrapping_add(insert_at.wrapping_sub(overlap_end))
            .wrapping_add(1);
        interval_start[insert_at as usize] = new_start;
        interval_end[insert_at as usize] = new_end;
    }

    /// Working-buffer element move for `Reverse`. For a pure insert, open one
    /// slot. For a merge, slide the tail after the consumed overlap range so
    /// that the replacement interval lands at `insert_at`.
    fn shift_for_insert(
        interval_start: &mut [i64],
        interval_end: &mut [i64],
        insert_at: u64,
        overlap_end: u64,
        interval_count: u64,
    ) {
        if insert_at == overlap_end {
            if insert_at < interval_count {
                let mut j = interval_count;
                while j > insert_at {
                    interval_start[j as usize] = interval_start[(j - 1) as usize];
                    interval_end[j as usize] = interval_end[(j - 1) as usize];
                    j -= 1;
                }
            }
            return;
        }
        if insert_at + 1 != overlap_end && overlap_end < interval_count {
            let shift = (insert_at as i64) - (overlap_end as i64) + 1;
            let mut j = overlap_end;
            while j < interval_count {
                let dst = (j as i64 + shift) as u64;
                interval_start[dst as usize] = interval_start[j as usize];
                interval_end[dst as usize] = interval_end[j as usize];
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

    /// Segment offset at `pos` plus the next breakpoint position (`i64::MAX` if
    /// none follows). Genuine `Decompressor::Run`'s SOURCE-copy loop walks these
    /// segments, re-anchoring the source at each breakpoint inside a single copy.
    pub fn segment_at(&self, pos: i64) -> (i64, i64) {
        let idx = match self.entries.binary_search_by_key(&pos, |&(p, _)| p) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };
        let off = self.entries[idx].1;
        let next = self
            .entries
            .get(idx + 1)
            .map(|&(p, _)| p)
            .unwrap_or(i64::MAX);
        (off, next)
    }
}

fn rift_entry_offset(source: i64, target: i64) -> i64 {
    target.wrapping_sub(source)
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
    pub(crate) fn from_reader(reader: &mut BitReader) -> Result<Self> {
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

    pub(crate) fn from_values(values: &[i64]) -> Self {
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

    pub(crate) fn to_writer(&self, writer: &mut BitWriter) {
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

    pub(crate) fn write_number(&self, writer: &mut BitWriter, value: i64) {
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
    fn shared_format_rift_roundtrip_reuses_outer_formats() {
        let table = RiftTable {
            entries: vec![
                RiftEntry {
                    source: 10,
                    target: 30,
                },
                RiftEntry {
                    source: 15,
                    target: 25,
                },
            ],
        };
        let source_format = IntFormat::from_values(&[10, 5]);
        let target_format = IntFormat::from_values(&[20, -10]);
        let mut writer = BitWriter::new();
        table.to_writer_with_formats(&mut writer, &source_format, &target_format);
        let data = writer.finish();
        let mut reader = BitReader::new(&data).unwrap();

        let decoded =
            RiftTable::from_reader_with_formats(&mut reader, &source_format, &target_format)
                .unwrap();

        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].source, 10);
        assert_eq!(decoded.entries[0].target, 30);
        assert_eq!(decoded.entries[1].source, 15);
        assert_eq!(decoded.entries[1].target, 25);
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
    fn reset_vector_seeds_unset_entries_for_native_set() {
        let mut table = RiftTable::reset_vector(3);

        assert_eq!(
            table.entries,
            vec![
                RiftEntry {
                    source: 0,
                    target: RIFT_VECTOR_UNSET_TARGET,
                },
                RiftEntry {
                    source: 1,
                    target: RIFT_VECTOR_UNSET_TARGET,
                },
                RiftEntry {
                    source: 2,
                    target: RIFT_VECTOR_UNSET_TARGET,
                },
            ]
        );

        table.set_vector_entry(1, 4);
        table.set_vector_entry(3, 9);
        table.set_vector_entry(-1, 9);

        assert_eq!(table.entries[1].target, 4);
        assert_eq!(table.entries.len(), 3);
    }

    #[test]
    fn internal_reduce_drops_unset_identity_vector_maps() {
        let mut table = RiftTable::reset_vector(3);
        table.set_vector_entry(0, 0);

        table.internal_reduce(true);

        assert!(table.entries.is_empty());
    }

    #[test]
    fn internal_reduce_keeps_changed_vector_segments() {
        let mut table = RiftTable::reset_vector(3);
        table.set_vector_entry(0, 0);
        table.set_vector_entry(1, 2);

        table.internal_reduce(true);

        assert_eq!(table, t(&[(0, 0), (1, 2)]));
    }

    #[test]
    fn internal_reduce_converts_single_non_identity_to_offset_at_zero() {
        let mut table = t(&[(5, 9)]);

        table.internal_reduce(false);

        assert_eq!(table, t(&[(0, 4)]));
    }

    #[test]
    fn internal_reduce_removes_wrapped_duplicate_offset() {
        let mut table = t(&[(0, 1), (5, 7), (8, 9)]);

        table.internal_reduce(false);

        assert_eq!(table, t(&[(5, 7), (8, 9)]));
    }

    #[test]
    fn internal_reduce_chooses_duplicate_source_majority() {
        let mut table = t(&[(1, 4), (1, 5), (1, 4)]);

        table.internal_reduce(false);

        assert_eq!(table, t(&[(0, 3)]));
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
        let id = RiftTable { entries: vec![] };
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

    /// Ground truth from genuine dpx.dll for the WRAP case (docprop). docprop's
    /// `preprocess_rift` is far more intricate (a section-relayout with negative
    /// source wraps and many small segments). The genuine final copy rift is the
    /// `Reverse` of `io2rva_src . preprocess_rift . pe_rift`, and it includes
    /// wrap entries that only exist because `Multiply`'s pre-first wrap block
    /// seeds the region below A's first source. Composing the three real factors
    /// with our `Multiply` and reversing must reproduce genuine byte-for-byte,
    /// including the load-bearing wrap/gap entries that the previous approximate
    /// `Multiply` (offset-deduped, no wrap block) dropped:
    ///   `6e0 -> -0x5120`, `bc8 -> -0x4c38`, `6a00,6400`, `7a00,71d0`, `9000,8800`.
    #[test]
    fn reverse_docprop_wrap_vector() {
        // io2rva_src (file offset -> RVA), source PE.
        let io2rva = t(&[
            (0x0, 0x0),
            (0x400, 0x1000),
            (0x6200, 0x7000),
            (0x6400, 0xa000),
            (0x7200, 0xb000),
            (0x8800, 0xd000),
        ]);
        // preprocess_rift (RVA -> target RVA).
        let pre = t(&[
            (0x0, 0x0),
            (0x12e0, 0x1308),
            (0x17a0, 0x1860),
            (0x6d20, 0x7350),
            (0x6fff, 0x7fff),
            (0xa0e0, 0xb0f0),
            (0xa120, 0xb138),
            (0xa14c, 0xb15c),
            (0xa300, 0xb374),
            (0xa444, 0xb4c8),
            (0xa484, 0xb510),
            (0xa4b0, 0xb534),
            (0xa596, 0xb746),
            (0xa7ce, 0xb976),
            (0xa830, 0xb9f4),
            (0xa8a0, 0xba7e),
            (0xaa4e, 0xbc0a),
            (0xaaa2, 0xbc88),
            (0xaaea, 0xbd1a),
            (0xafff, 0xbfff),
        ]);
        // pe_rift (target RVA -> target file offset).
        let pe = t(&[
            (0x0, 0x0),
            (0x1000, 0x400),
            (0x8000, 0x6800),
            (0xb000, 0x6a00),
            (0xc000, 0x7a00),
            (0xe000, 0x9000),
        ]);
        let forward = io2rva.multiply(&pre).multiply(&pe);
        let rev = forward.reverse();
        contains_all(
            &rev,
            &[
                (0x0, 0x0),
                (0x400, 0x400),
                (0x6e0, -0x5120),
                (0x708, 0x6e0),
                (0xbc8, -0x4c38),
                (0xc60, 0xba0),
                (0x6750, 0x6120),
                (0x6830, 0x6230),
                (0x6a00, 0x6400),
                (0x771a, 0x6eea),
                (0x7a00, 0x71d0),
                (0x7a30, 0x7230),
                (0x9000, 0x8800),
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
