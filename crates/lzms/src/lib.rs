//! Pure-Rust encoder and decoder for Microsoft's LZMS compression format.
//!
//! LZMS is the algorithm behind the Windows Compression API
//! (`COMPRESS_ALGORITHM_LZMS` in `cabinet.dll`), and it also underlies WIM
//! image compression and the LZMS-wrapped payloads inside MSDelta patches.
//! This crate has no dependencies and reads or writes both the raw bitstream
//! ([`decompress`] / [`compress`]) and the Compression API container
//! ([`decompress_compression_api`] / [`compress_compression_api`]).
//!
//! ```
//! let original = b"LZMS roundtrip with some repetition repetition repetition";
//! let wrapped = lzms::compress_compression_api(original).unwrap();
//! let recovered = lzms::decompress_compression_api(&wrapped).unwrap();
//! assert_eq!(recovered, original);
//! ```

#![forbid(unsafe_code)]

/// Errors produced while decoding or encoding an LZMS stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before a complete stream could be read.
    Truncated,
    /// The stream was structurally invalid; the message names the failed check.
    Malformed(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("input too short"),
            Error::Malformed(msg) => write!(f, "malformed LZMS stream: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, Error>;

mod adaptive;
mod container;
mod range_coder;
mod tables;
mod wim;
mod x86_filter;

use adaptive::{AdaptiveCode, BackBits, BackBitsWriter};
use range_coder::{
    ProbEntry, ProbTables, RangeDecoder, RangeEncoder, COST_SHIFT, NUM_DELTA_PROBS,
    NUM_DELTA_REP_PROBS, NUM_LZ_PROBS, NUM_LZ_REP_PROBS, NUM_MAIN_PROBS, NUM_MATCH_PROBS,
};
use x86_filter::{x86_filter, x86_filter_impl};

pub use container::{compress_compression_api, decompress_compression_api};
pub use wim::{
    compress_wim, compress_wim_solid, decompress_wim, decompress_wim_chunk, decompress_wim_solid,
    decompress_wim_solid_range, SolidLayout,
};

/// Decompress a raw LZMS bitstream.
pub fn decompress(data: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() || output_size == 0 {
        return Ok(Vec::new());
    }
    // A single LZMS stream decodes one container chunk, which cabinet.dll caps
    // at 64 MiB; reject anything larger as malformed (and a decode-bomb guard).
    if output_size > 0x0400_0000 {
        return Err(Error::Malformed(
            "LZMS: output size exceeds 64 MiB chunk limit",
        ));
    }
    if data.len() < 4 || data.len() % 2 != 0 {
        return Err(Error::Malformed("LZMS: need >= 4 even bytes"));
    }

    let mut out = vec![0u8; output_size];
    let mut rc = RangeDecoder::new(data);
    let mut bs = BackBits::new(data);

    let num_offset_syms = tables::num_offset_slots(output_size as u32);

    let mut literal_code = AdaptiveCode::new(256, 1024);
    let mut lz_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut length_code = AdaptiveCode::new(54, 512);
    let mut delta_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut delta_power_code = AdaptiveCode::new(8, 512);

    let mut main_st = 0u32;
    let mut match_st = 0u32;
    let mut lz_st = 0u32;
    let mut lz_rep_st = [0u32; 2];
    let mut delta_st = 0u32;
    let mut delta_rep_st = [0u32; 2];

    let mut probs = ProbTables::new();

    let mut lz_queue: [u32; 4] = [1, 2, 3, 4];
    let mut delta_queue: [(u32, u32); 4] = [(1, 0), (2, 0), (3, 0), (4, 0)];
    let mut prev_type: u32 = 0;
    let mut pos = 0usize;

    while pos < output_size {
        let main_bit = rc.decode_bit(&mut main_st, NUM_MAIN_PROBS, &mut probs.main);

        if main_bit == 0 {
            let sym = literal_code.decode_symbol(&mut bs)?;
            out[pos] = sym as u8;
            pos += 1;
            prev_type = 0;
        } else {
            let match_bit = rc.decode_bit(&mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            if match_bit == 0 {
                let lz_bit = rc.decode_bit(&mut lz_st, NUM_LZ_PROBS, &mut probs.lz);

                let offset;
                if lz_bit == 0 {
                    let slot = lz_offset_code.decode_symbol(&mut bs)?;
                    offset = tables::decode_offset(slot, &mut bs);
                    queue_push(&mut lz_queue, offset);
                } else {
                    let rep = decode_rep(&mut rc, &mut lz_rep_st, &mut probs.lz_rep);
                    let adj = (rep + (prev_type & 1) as usize).min(3);
                    offset = lz_queue[adj];
                    queue_mtf(&mut lz_queue, adj);
                }

                let len_slot = length_code.decode_symbol(&mut bs)?;
                let length = tables::decode_length(len_slot, &mut bs) as usize;

                if (offset as usize) > pos {
                    return Err(Error::Malformed("LZMS: LZ offset past start"));
                }
                let n = length.min(output_size - pos);
                let src = pos - offset as usize;
                let off = offset as usize;
                if off >= n {
                    // Non-overlapping: one memmove instead of a checked byte loop.
                    out.copy_within(src..src + n, pos);
                } else {
                    // Overlapping run: replicate the `off`-byte pattern, doubling
                    // the copied span each step so every copy is a memmove
                    // (O(log n) copies even for offset 1).
                    out.copy_within(src..src + off, pos);
                    let mut done = off;
                    while done < n {
                        let chunk = (n - done).min(done);
                        out.copy_within(pos..pos + chunk, pos + done);
                        done += chunk;
                    }
                }
                pos += n;
                prev_type = 1;
            } else {
                let delta_bit = rc.decode_bit(&mut delta_st, NUM_DELTA_PROBS, &mut probs.delta);

                let power;
                let raw_offset;
                if delta_bit == 0 {
                    power = delta_power_code.decode_symbol(&mut bs)? as u32;
                    raw_offset =
                        tables::decode_offset(delta_offset_code.decode_symbol(&mut bs)?, &mut bs);
                    queue_push_pair(&mut delta_queue, (raw_offset, power));
                } else {
                    let rep = decode_rep(&mut rc, &mut delta_rep_st, &mut probs.delta_rep);
                    let adj = (rep + ((prev_type >> 1) & 1) as usize).min(3);
                    let pair = delta_queue[adj];
                    raw_offset = pair.0;
                    power = pair.1;
                    queue_mtf_pair(&mut delta_queue, adj);
                }

                let length =
                    tables::decode_length(length_code.decode_symbol(&mut bs)?, &mut bs) as usize;

                let span = 1usize << power;
                let offset = (raw_offset as usize)
                    .checked_shl(power)
                    .filter(|&o| o >> power == raw_offset as usize)
                    .ok_or(Error::Malformed("LZMS: delta offset overflow"))?;

                if offset.checked_add(span).is_none_or(|sum| sum > pos) {
                    return Err(Error::Malformed("LZMS: delta offset/span past start"));
                }
                let n = length.min(output_size - pos);
                for i in 0..n {
                    let s = pos + i - offset;
                    out[pos + i] = out[s]
                        .wrapping_add(out[pos + i - span])
                        .wrapping_sub(out[s - span]);
                }
                pos += n;
                prev_type = 2;
            }
        }
    }

    x86_filter(&mut out);
    Ok(out)
}

/// Longest match the encoder will emit. The format permits up to
/// `LZMS_MAX_MATCH_LENGTH` (1073809578); chunks are at most 64 MiB, so this
/// bound is never the limiting factor in practice but keeps a single match
/// length within what the length-slot table can encode.
const MAX_MATCH_LEN: u32 = 1 << 26;

/// Compress data using LZMS with greedy LZ matching.
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let mut filtered = data.to_vec();
    x86_filter_impl(&mut filtered, false);

    let num_offset_syms = tables::num_offset_slots(filtered.len() as u32);

    let mut rc = RangeEncoder::new();
    let mut bs = BackBitsWriter::new();

    let mut literal_code = AdaptiveCode::new(256, 1024);
    let mut lz_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut length_code = AdaptiveCode::new(54, 512);
    let mut delta_offset_code = AdaptiveCode::new(num_offset_syms, 1024);
    let mut delta_power_code = AdaptiveCode::new(8, 512);

    let mut main_st = 0u32;
    let mut match_st = 0u32;
    let mut lz_st = 0u32;
    let mut lz_rep_st = [0u32; 2];
    let mut delta_st = 0u32;
    let mut delta_rep_st = [0u32; 2];
    let mut probs = ProbTables::new();
    let mut lz_queue: [u32; 4] = [1, 2, 3, 4];
    let mut delta_queue: [(u32, u32); 4] = [(1, 0), (2, 0), (3, 0), (4, 0)];
    let mut prev_type: u32 = 0;

    let d = &filtered;
    let mut pos = 0usize;

    // Hash chain for match finding (4-byte hash)
    const HASH_BITS: usize = 16;
    let mut head = vec![0u32; 1 << HASH_BITS];
    let mut chain = vec![0u32; d.len()];

    // Delta-match finder: one hash table per power over the 3-byte difference
    // signature `d[i] - d[i-span]`, keyed by `i mod span` so a hit is
    // span-aligned (the byte offset must be a multiple of `span = 1 << power`).
    // Each signature bucket is `DELTA_WAYS`-way set-associative (a ring indexed
    // by `pos & (DELTA_WAYS-1)`) to keep several recent candidate offsets
    // without a per-position chain. This replaces the former brute-force
    // `power x window x extend` scan; the offset is no longer windowed because
    // the cost model now rejects deltas that are not worth their offset cost.
    // Slots store `pos + 1` (0 = empty).
    const DELTA_HASH_BITS: u32 = 13;
    const DELTA_WAYS: usize = 8;
    let dh_size = 1usize << DELTA_HASH_BITS;
    let mut delta_head = vec![0u32; dh_size * 8 * DELTA_WAYS];

    while pos < d.len() {
        let (match_offset, match_len) = if pos + 3 < d.len() {
            let h = hash4(d, pos) & ((1 << HASH_BITS) - 1);
            let mut best_len = 0u32;
            let mut best_off = 0u32;

            // Check LRU queue first
            for qi in 0..4usize {
                let adj = (qi + (prev_type & 1) as usize).min(3);
                let off = lz_queue[adj] as usize;
                if off > 0 && off <= pos {
                    let ml = match_length(d, pos - off, pos, d.len());
                    if ml > best_len && ml >= 2 {
                        best_len = ml;
                        best_off = off as u32;
                    }
                }
            }

            // Check hash chain
            let mut prev = head[h] as usize;
            let mut steps = 0;
            while prev > 0 && steps < 32 {
                let off = pos - prev;
                if off > 0 {
                    let ml = match_length(d, prev, pos, d.len());
                    if ml > best_len {
                        best_len = ml;
                        best_off = off as u32;
                    }
                }
                prev = chain[prev] as usize;
                steps += 1;
            }

            chain[pos] = head[h];
            head[h] = pos as u32;

            (best_off, best_len)
        } else {
            (0, 0)
        };

        // Delta match: probe the per-power signature hash for candidate sources
        // at the full (span-aligned) offset range. Correctness comes from
        // verifying and extending at the exact offset we will encode
        // (`raw_off << power`); the cost model decides whether to use the
        // result over an LZ match.
        let mut delta_len = 0u32;
        let mut delta_offset = 0u32;
        let mut delta_power = 0u32;
        // Delta search is expensive (8 powers x associative probe per position)
        // and rarely beats a usable LZ match, so only run it where LZ found
        // nothing usable (match_len < 3) -- which is exactly the delta-favorable
        // data (e.g. strided/incrementing) where deltas matter.
        if match_len < 3 && pos + 2 < d.len() {
            for power in 0..8u32 {
                let span = 1usize << power;
                if span > pos {
                    break;
                }
                let base = ((power as usize) * dh_size + delta_sig(d, pos, span, DELTA_HASH_BITS))
                    * DELTA_WAYS;
                for way in 0..DELTA_WAYS {
                    let cand = delta_head[base + way];
                    if cand == 0 {
                        continue;
                    }
                    let off = pos - (cand - 1) as usize;
                    if off == 0 || off % span != 0 {
                        continue;
                    }
                    let raw_off = (off >> power) as u32;
                    let mut ml = 0u32;
                    while pos + (ml as usize) < d.len() && ml < MAX_MATCH_LEN {
                        let p = pos + ml as usize;
                        let s = p - off;
                        if p < span || s < span {
                            break;
                        }
                        let expected = d[s].wrapping_add(d[p - span]).wrapping_sub(d[s - span]);
                        if d[p] != expected {
                            break;
                        }
                        ml += 1;
                    }
                    if ml > delta_len && ml >= 3 {
                        delta_len = ml;
                        delta_offset = raw_off;
                        delta_power = power;
                    }
                }
                delta_head[base + (pos & (DELTA_WAYS - 1))] = (pos + 1) as u32;
            }
        }

        // Cost-based selection (units: 1/2^COST_SHIFT bit). Price each candidate
        // match as it would be encoded (explicit form) under the current
        // adaptive state, pick the cheaper per covered byte, then gate it
        // against coding the same span as literals. This makes every decision
        // cost-driven: the match finder may surface far/expensive deltas, but a
        // match is taken only when it actually beats the literal alternative,
        // which is what lets the delta search run unwindowed without bloating
        // literal-heavy data.
        let (use_delta, take_match) = {
            let length_cost = |len: u32| -> u32 {
                let slot = tables::find_length_slot(len);
                (length_code.code_len(slot) + tables::length_slot_extra_bits(slot)) << COST_SHIFT
            };
            let lit_cost = |byte: u8| -> u32 {
                probs.main[main_st as usize].cost0()
                    + (literal_code.code_len(byte as usize) << COST_SHIFT)
            };
            let lz_cost = (match_len >= 3).then(|| {
                let slot = tables::find_offset_slot(match_offset);
                probs.main[main_st as usize].cost1()
                    + probs.match_[match_st as usize].cost0()
                    + probs.lz[lz_st as usize].cost0()
                    + ((lz_offset_code.code_len(slot) + tables::offset_slot_extra_bits(slot))
                        << COST_SHIFT)
                    + length_cost(match_len)
            });
            let delta_cost = (delta_len >= 3).then(|| {
                let slot = tables::find_offset_slot(delta_offset);
                probs.main[main_st as usize].cost1()
                    + probs.match_[match_st as usize].cost1()
                    + probs.delta[delta_st as usize].cost0()
                    + (delta_power_code.code_len(delta_power as usize) << COST_SHIFT)
                    + ((delta_offset_code.code_len(slot) + tables::offset_slot_extra_bits(slot))
                        << COST_SHIFT)
                    + length_cost(delta_len)
            });
            // Pick the better match by cost per byte (cross-multiplied).
            let chosen = match (lz_cost, delta_cost) {
                (Some(l), Some(dc)) => {
                    if (dc as u64) * (match_len as u64) < (l as u64) * (delta_len as u64) {
                        Some((true, dc, delta_len))
                    } else {
                        Some((false, l, match_len))
                    }
                }
                (Some(l), None) => Some((false, l, match_len)),
                (None, Some(dc)) => Some((true, dc, delta_len)),
                (None, None) => None,
            };
            match chosen {
                Some((is_delta, cost, len)) => {
                    let lits: u32 = (0..len as usize)
                        .map(|k| lit_cost(d[pos + k]))
                        .fold(0u32, u32::saturating_add);
                    (is_delta, cost < lits)
                }
                None => (false, false),
            }
        };

        if take_match && use_delta {
            // Encode delta match
            rc.encode_bit(1, &mut main_st, NUM_MAIN_PROBS, &mut probs.main);
            rc.encode_bit(1, &mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            let rep_idx = {
                let adj_base = ((prev_type >> 1) & 1) as usize;
                let mut found = None;
                for rep in 0..3usize {
                    let adj = (rep + adj_base).min(3);
                    if delta_queue[adj] == (delta_offset, delta_power) {
                        found = Some((rep, adj));
                        break;
                    }
                }
                found
            };

            if let Some((rep, adj)) = rep_idx {
                rc.encode_bit(1, &mut delta_st, NUM_DELTA_PROBS, &mut probs.delta);
                match rep {
                    0 => rc.encode_bit(
                        0,
                        &mut delta_rep_st[0],
                        NUM_LZ_REP_PROBS,
                        &mut probs.delta_rep[0],
                    ),
                    1 => {
                        rc.encode_bit(
                            1,
                            &mut delta_rep_st[0],
                            NUM_LZ_REP_PROBS,
                            &mut probs.delta_rep[0],
                        );
                        rc.encode_bit(
                            0,
                            &mut delta_rep_st[1],
                            NUM_DELTA_REP_PROBS,
                            &mut probs.delta_rep[1],
                        );
                    }
                    _ => {
                        rc.encode_bit(
                            1,
                            &mut delta_rep_st[0],
                            NUM_LZ_REP_PROBS,
                            &mut probs.delta_rep[0],
                        );
                        rc.encode_bit(
                            1,
                            &mut delta_rep_st[1],
                            NUM_DELTA_REP_PROBS,
                            &mut probs.delta_rep[1],
                        );
                    }
                }
                queue_mtf_pair(&mut delta_queue, adj);
            } else {
                rc.encode_bit(0, &mut delta_st, NUM_DELTA_PROBS, &mut probs.delta);
                delta_power_code.encode_symbol(delta_power as usize, &mut bs);
                let off_slot = tables::find_offset_slot(delta_offset);
                delta_offset_code.encode_symbol(off_slot, &mut bs);
                tables::encode_offset_extra(delta_offset, off_slot, &mut bs);
                queue_push_pair(&mut delta_queue, (delta_offset, delta_power));
            }

            let len_slot = tables::find_length_slot(delta_len);
            length_code.encode_symbol(len_slot, &mut bs);
            tables::encode_length_extra(delta_len, len_slot, &mut bs);

            pos += delta_len as usize;
            prev_type = 2;
        } else if take_match {
            // Encode LZ match (cost-gated; match_len >= 3 guaranteed here)
            rc.encode_bit(1, &mut main_st, NUM_MAIN_PROBS, &mut probs.main);
            rc.encode_bit(0, &mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            // Check if offset is in the 3 accessible LRU positions
            // (4th entry is overflow, can't be encoded as repeat)
            let rep_idx = {
                let adj_base = (prev_type & 1) as usize;
                let mut found = None;
                for rep in 0..3usize {
                    let adj = (rep + adj_base).min(3);
                    if lz_queue[adj] == match_offset {
                        found = Some((rep, adj));
                        break;
                    }
                }
                found
            };

            if let Some((rep, adj)) = rep_idx {
                rc.encode_bit(1, &mut lz_st, NUM_LZ_PROBS, &mut probs.lz);
                match rep {
                    0 => {
                        rc.encode_bit(0, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0])
                    }
                    1 => {
                        rc.encode_bit(1, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]);
                        rc.encode_bit(
                            0,
                            &mut lz_rep_st[1],
                            NUM_DELTA_REP_PROBS,
                            &mut probs.lz_rep[1],
                        );
                    }
                    _ => {
                        rc.encode_bit(1, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]);
                        rc.encode_bit(
                            1,
                            &mut lz_rep_st[1],
                            NUM_DELTA_REP_PROBS,
                            &mut probs.lz_rep[1],
                        );
                    }
                }
                queue_mtf(&mut lz_queue, adj);
            } else {
                // Explicit offset: symbol THEN extra bits
                rc.encode_bit(0, &mut lz_st, NUM_LZ_PROBS, &mut probs.lz);
                let off_slot = tables::find_offset_slot(match_offset);
                lz_offset_code.encode_symbol(off_slot, &mut bs);
                tables::encode_offset_extra(match_offset, off_slot, &mut bs);
                queue_push(&mut lz_queue, match_offset);
            }

            let len_slot = tables::find_length_slot(match_len);
            length_code.encode_symbol(len_slot, &mut bs);
            tables::encode_length_extra(match_len, len_slot, &mut bs);

            pos += match_len as usize;
            prev_type = 1;
        } else {
            rc.encode_bit(0, &mut main_st, NUM_MAIN_PROBS, &mut probs.main);
            literal_code.encode_symbol(d[pos] as usize, &mut bs);
            pos += 1;
            prev_type = 0;
        }
    }

    let mut out = Vec::new();
    rc.finish(&mut out);
    bs.finish(&mut out);

    if out.len() % 2 != 0 {
        out.push(0);
    }

    Ok(out)
}

fn hash4(data: &[u8], pos: usize) -> usize {
    let v = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
    (v.wrapping_mul(0x1E35A7BD) >> 16) as usize
}

/// Hash the 3-byte difference signature `d[i] - d[i-span]` at position `i` for
/// a delta match of the given `span`, mixing in `i mod span` so positions only
/// collide when their byte offset is a multiple of `span`. Requires `i >= span`
/// and `i + 2 < d.len()`.
fn delta_sig(d: &[u8], i: usize, span: usize, bits: u32) -> usize {
    let a = d[i].wrapping_sub(d[i - span]) as u32;
    let b = d[i + 1].wrapping_sub(d[i + 1 - span]) as u32;
    let c = d[i + 2].wrapping_sub(d[i + 2 - span]) as u32;
    let residue = (i & (span - 1)) as u32;
    let v = (a | (b << 8) | (c << 16)) ^ residue.wrapping_mul(0x9E37_79B1);
    (v.wrapping_mul(0x85EB_CA77) >> (32 - bits)) as usize
}

fn match_length(data: &[u8], src: usize, dst: usize, limit: usize) -> u32 {
    let max = (limit - dst).min(MAX_MATCH_LEN as usize) as u32;
    let mut len = 0u32;
    while len < max && data[src + len as usize] == data[dst + len as usize] {
        len += 1;
    }
    len
}

fn decode_rep<const N: usize>(
    rc: &mut RangeDecoder,
    st: &mut [u32; 2],
    probs: &mut [[ProbEntry; N]; 2],
) -> usize {
    let b0 = rc.decode_bit(&mut st[0], NUM_LZ_REP_PROBS, &mut probs[0]);
    if b0 == 0 {
        return 0;
    }
    let b1 = rc.decode_bit(&mut st[1], NUM_DELTA_REP_PROBS, &mut probs[1]);
    if b1 == 0 {
        1
    } else {
        2
    }
}

fn queue_push(q: &mut [u32; 4], val: u32) {
    q[3] = q[2];
    q[2] = q[1];
    q[1] = q[0];
    q[0] = val;
}

fn queue_mtf(q: &mut [u32; 4], idx: usize) {
    let val = q[idx];
    for i in (1..=idx).rev() {
        q[i] = q[i - 1];
    }
    q[0] = val;
}

fn queue_push_pair(q: &mut [(u32, u32); 4], val: (u32, u32)) {
    q[3] = q[2];
    q[2] = q[1];
    q[1] = q[0];
    q[0] = val;
}

fn queue_mtf_pair(q: &mut [(u32, u32); 4], idx: usize) {
    let val = q[idx];
    for i in (1..=idx).rev() {
        q[i] = q[i - 1];
    }
    q[0] = val;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lzms");

    fn check(name: &str) {
        let lzms_path = Path::new(FIXTURES).join(format!("{name}.lzms"));
        let raw_path = Path::new(FIXTURES).join(format!("{name}.raw"));

        if !lzms_path.exists() {
            return;
        }

        let compressed = std::fs::read(&lzms_path).unwrap();
        let expected = std::fs::read(&raw_path).unwrap();

        match decompress_compression_api(&compressed) {
            Ok(output) => {
                assert_eq!(output.len(), expected.len(), "{name}: size mismatch");
                for (i, (&got, &want)) in output.iter().zip(expected.iter()).enumerate() {
                    if got != want {
                        panic!("{name}: first diff at byte {i}: got {got:#04x}, want {want:#04x}");
                    }
                }
            }
            Err(e) => panic!("{name}: decode failed: {e}"),
        }
    }

    #[test]
    fn zeros() {
        check("zeros");
    }
    #[test]
    fn sequential() {
        check("sequential");
    }
    #[test]
    fn pattern() {
        check("pattern");
    }
    #[test]
    fn single_byte() {
        check("single_byte");
    }
    #[test]
    fn english() {
        check("english");
    }
    #[test]
    fn small() {
        check("small");
    }
    #[test]
    fn random() {
        check("random");
    }

    #[test]
    fn x86_filter_roundtrip() {
        let mut data = vec![0x90u8; 256];
        // Three E8 (call relative) instructions targeting the same address.
        // The first pair activates the heuristic (sets last_x86_pos).
        // The third instruction is then within max_trans_offset and gets translated.
        // target = position + 1 (opcode size) + relative_offset
        // All three target address 120: offsets are 109, 99, 89
        data[10] = 0xE8;
        data[11..15].copy_from_slice(&109u32.to_le_bytes());
        data[20] = 0xE8;
        data[21..25].copy_from_slice(&99u32.to_le_bytes());
        data[30] = 0xE8;
        data[31..35].copy_from_slice(&89u32.to_le_bytes());

        let original = data.clone();

        x86_filter_impl(&mut data, false);
        assert_ne!(
            data, original,
            "x86 filter should modify data with repeated call targets"
        );

        x86_filter_impl(&mut data, true);
        assert_eq!(data, original, "x86 filter roundtrip failed");
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let original = b"Hello, this is a test of LZMS compression roundtrip!";
        let compressed = compress(original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_decompress_zeros() {
        let original = vec![0u8; 256];
        let compressed = compress(&original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_decompress_sequential() {
        let original: Vec<u8> = (0..=255).collect();
        let compressed = compress(&original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn compress_decompress_large() {
        let original: Vec<u8> = (0..4096).map(|i| (i * 7 + 13) as u8).collect();
        let compressed = compress(&original).unwrap();
        let decompressed = decompress(&compressed, original.len()).unwrap();
        assert_eq!(decompressed, original);
    }

    /// Long runs must encode as single long matches (cap raised well past the
    /// old 1046) and round-trip exactly.
    #[test]
    fn compress_decompress_long_run() {
        let original = vec![0xABu8; 200_000];
        let compressed = compress(&original).unwrap();
        // A 200 KB constant run should collapse to a handful of bytes.
        assert!(
            compressed.len() < 64,
            "expected tiny output, got {}",
            compressed.len()
        );
        assert_eq!(decompress(&compressed, original.len()).unwrap(), original);
    }

    /// Data with a strided arithmetic structure exercises delta matches across
    /// multiple powers (search widened to the full 0..8 alphabet).
    /// Fuzz regression: a malformed raw stream that exhausts the backward
    /// bitstream must not panic (was `attempt to subtract with overflow` in
    /// `BackBits::consume`). Missing bits are zero-extended.
    #[test]
    fn fuzz_regression_bitstream_underflow_no_panic() {
        let crash = [0xde, 0x06, 0xde, 0xde, 0xde, 0x06, 0x06, 0x0a];
        let size =
            u32::from_le_bytes([crash[0], crash[1], crash[2], crash[3]]) as usize % (1 << 20);
        // Must terminate without panicking; output correctness is not asserted
        // for malformed input.
        let _ = decompress(&crash[4..], size);
    }

    #[test]
    fn compress_decompress_delta_favorable() {
        let original: Vec<u8> = (0..20_000u32)
            .map(|i| (i.wrapping_mul(3) >> 1) as u8)
            .collect();
        let compressed = compress(&original).unwrap();
        assert_eq!(decompress(&compressed, original.len()).unwrap(), original);
    }

    /// A larger mixed buffer (literals + repeats + structure) to shake out the
    /// widened match finder end to end.
    #[test]
    fn compress_decompress_mixed_large() {
        let mut original = Vec::new();
        for block in 0..64u32 {
            original.extend(std::iter::repeat_n((block & 0xFF) as u8, 1000));
            original.extend((0..1000u32).map(|i| (i.wrapping_mul(block + 1)) as u8));
        }
        let compressed = compress(&original).unwrap();
        assert_eq!(decompress(&compressed, original.len()).unwrap(), original);
    }

    #[test]
    fn compression_api_roundtrip() {
        let original =
            b"Compression API wrapper roundtrip test data with some repetition repetition";
        let wrapped = compress_compression_api(original).unwrap();
        let recovered = decompress_compression_api(&wrapped).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn compression_api_roundtrip_large() {
        let original: Vec<u8> = (0..8192).map(|i| (i * 3 + 7) as u8).collect();
        let wrapped = compress_compression_api(&original).unwrap();
        let recovered = decompress_compression_api(&wrapped).unwrap();
        assert_eq!(recovered, original);
    }
}
