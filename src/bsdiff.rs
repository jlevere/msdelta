//! BsDiff binary delta codec for MSDelta's PlaybackReverse path.
//!
//! This is a custom bsdiff variant used when FileTypeSet has bit 0x100.
//! The patch format uses 3-tuple blocks: (add_length, insert_length, seek_distance).
//! The patch data may be LZMS-compressed before being passed to bspatch.

#![forbid(unsafe_code)]

use crate::{Error, Result};

/// Apply a bsdiff patch to produce the target from source + patch data.
///
/// The patch data is a stream of 3-tuple blocks:
/// - 3x 8-byte signed integers: (add_length, insert_length, seek_distance)
/// - `add_length` bytes of diff data (added to source bytes)
/// - `insert_length` bytes of literal data (inserted directly)
///
/// The seek_distance advances the source pointer for the next block.
pub fn bspatch(source: &[u8], target_size: usize, patch_data: &[u8]) -> Result<Vec<u8>> {
    if target_size > 64 * 1024 * 1024 {
        return Err(Error::Malformed("bspatch: target size exceeds 256 MB limit"));
    }
    let mut target = vec![0u8; target_size];
    let mut patch_pos: usize = 0;
    let mut old_pos: i64 = 0;
    let mut new_pos: usize = 0;

    while new_pos < target_size {
        // Read 3 control values (8 bytes each, signed)
        if patch_pos + 24 > patch_data.len() {
            return Err(Error::Truncated);
        }

        let add_len = read_i64(&patch_data[patch_pos..])? as usize;
        patch_pos += 8;
        let insert_len = read_i64(&patch_data[patch_pos..])? as usize;
        patch_pos += 8;
        let seek_dist = read_i64(&patch_data[patch_pos..])?;
        patch_pos += 8;

        if add_len > 0x7FFFFFFF || insert_len > 0x7FFFFFFF {
            return Err(Error::Malformed("control value too large"));
        }
        if new_pos + add_len > target_size {
            return Err(Error::Malformed("add_len exceeds target size"));
        }

        // Read add_len bytes of diff data
        if patch_pos + add_len > patch_data.len() {
            return Err(Error::Truncated);
        }
        for i in 0..add_len {
            let src_idx = old_pos + i as i64;
            let src_byte = if src_idx >= 0 && (src_idx as usize) < source.len() {
                source[src_idx as usize]
            } else {
                0
            };
            target[new_pos + i] = patch_data[patch_pos + i].wrapping_add(src_byte);
        }
        patch_pos += add_len;
        new_pos += add_len;

        // Read insert_len bytes of literal data
        if new_pos + insert_len > target_size {
            return Err(Error::Malformed("insert_len exceeds target size"));
        }
        if patch_pos + insert_len > patch_data.len() {
            return Err(Error::Truncated);
        }
        target[new_pos..new_pos + insert_len]
            .copy_from_slice(&patch_data[patch_pos..patch_pos + insert_len]);
        patch_pos += insert_len;
        new_pos += insert_len;

        old_pos += seek_dist + add_len as i64;
    }

    Ok(target)
}

/// Read a signed 64-bit integer in bsdiff encoding.
///
/// 8 bytes, little-endian magnitude with sign in high bit of last byte (byte[7]).
fn read_i64(data: &[u8]) -> Result<i64> {
    if data.len() < 8 {
        return Err(Error::Truncated);
    }
    let sign = data[7] & 0x80 != 0;
    let magnitude = ((data[7] as u64 & 0x7F) << 48)
        | ((data[6] as u64) << 40)
        | ((data[5] as u64) << 32)
        | ((data[4] as u64) << 24)
        | ((data[3] as u64) << 16)
        | ((data[2] as u64) << 8)
        | (data[1] as u64);
    // Byte 0 is the LSB
    let val = magnitude * 256 + data[0] as u64;
    Ok(if sign { -(val as i64) } else { val as i64 })
}

fn write_i64(buf: &mut Vec<u8>, val: i64) {
    let (magnitude, sign) = if val < 0 {
        ((val as u64).wrapping_neg(), true)
    } else {
        (val as u64, false)
    };
    buf.push((magnitude & 0xFF) as u8);
    buf.push(((magnitude >> 8) & 0xFF) as u8);
    buf.push(((magnitude >> 16) & 0xFF) as u8);
    buf.push(((magnitude >> 24) & 0xFF) as u8);
    buf.push(((magnitude >> 32) & 0xFF) as u8);
    buf.push(((magnitude >> 40) & 0xFF) as u8);
    buf.push(((magnitude >> 48) & 0xFF) as u8);
    let hi = ((magnitude >> 56) & 0x7F) as u8 | if sign { 0x80 } else { 0 };
    buf.push(hi);
}

/// Create a bsdiff patch from source and target buffers.
///
/// The returned patch data can be decoded by `bspatch`.
pub fn bscreate(source: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    if target.is_empty() {
        return Ok(Vec::new());
    }

    let sa = suffix_array(source);
    let mut patch = Vec::new();
    let mut scan: usize = 0;
    let mut last_scan: usize = 0;
    let mut last_pos: i64 = 0;
    let mut last_offset: i64 = 0;
    let min_match = 8usize;

    while scan < target.len() {
        scan += 1;
        let mut best_len = 0usize;
        let mut best_pos = 0usize;

        while scan < target.len() {
            let (pos, len) = find_match(&sa, source, &target[scan..]);
            best_pos = pos;
            best_len = len;

            let mut old_score = 0usize;
            for i in 0..best_len.min(target.len() - scan) {
                let sp = scan as i64 + last_offset + i as i64;
                if sp >= 0 && (sp as usize) < source.len()
                    && source[sp as usize] == target[scan + i]
                {
                    old_score += 1;
                }
            }
            if best_len > old_score + min_match {
                break;
            }
            scan += 1;
        }

        if scan >= target.len() {
            break;
        }

        // Forward extension from last match: how many bytes from last_scan
        // are better explained by the previous offset than the new match?
        let mut lens_f = 0usize;
        {
            let mut s = 0i64;
            let mut best_s = 0i64;
            for i in 0..(scan - last_scan) {
                let j = last_scan + i;
                let sp = last_pos + i as i64;
                if sp >= 0 && (sp as usize) < source.len()
                    && source[sp as usize] == target[j]
                {
                    s += 1;
                }
                if s * 2 > (i + 1) as i64 && s > best_s {
                    best_s = s;
                    lens_f = i + 1;
                }
            }
        }

        // Backward extension from new match
        let mut lenb = 0usize;
        {
            let mut s = 0i64;
            let mut best_s = 0i64;
            let limit = scan.saturating_sub(last_scan + lens_f);
            for i in 1..=limit {
                let j = scan - i;
                let sp = best_pos as i64 - i as i64;
                if sp >= 0 && (sp as usize) < source.len()
                    && source[sp as usize] == target[j]
                {
                    s += 1;
                }
                if s * 2 > i as i64 && s > best_s {
                    best_s = s;
                    lenb = i;
                }
            }
        }

        let add_len = lens_f;
        let insert_start = last_scan + lens_f;
        let insert_end = scan - lenb;
        let insert_len = insert_end.saturating_sub(insert_start);

        write_i64(&mut patch, add_len as i64);
        write_i64(&mut patch, insert_len as i64);
        let new_pos = best_pos as i64 - lenb as i64;
        let seek = new_pos - (last_pos + add_len as i64);
        write_i64(&mut patch, seek);

        for i in 0..add_len {
            let j = last_scan + i;
            let sp = last_pos + i as i64;
            let src_byte = if sp >= 0 && (sp as usize) < source.len() {
                source[sp as usize]
            } else {
                0
            };
            patch.push(target[j].wrapping_sub(src_byte));
        }

        if insert_len > 0 {
            patch.extend_from_slice(&target[insert_start..insert_start + insert_len]);
        }

        last_scan = scan - lenb;
        last_pos = new_pos;
        last_offset = best_pos as i64 - scan as i64;
        scan = last_scan + best_len;
    }

    if last_scan < target.len() {
        let add_len = target.len() - last_scan;
        write_i64(&mut patch, add_len as i64);
        write_i64(&mut patch, 0);
        write_i64(&mut patch, 0);
        for i in 0..add_len {
            let sp = last_pos + i as i64;
            let src_byte = if sp >= 0 && (sp as usize) < source.len() {
                source[sp as usize]
            } else {
                0
            };
            patch.push(target[last_scan + i].wrapping_sub(src_byte));
        }
    }

    Ok(patch)
}

fn suffix_array(data: &[u8]) -> Vec<i64> {
    let n = data.len();
    if n == 0 {
        return vec![];
    }

    let mut sa: Vec<i64> = (0..n as i64).collect();
    let mut rank: Vec<i64> = data.iter().map(|&b| b as i64).collect();
    let mut tmp: Vec<i64> = vec![0; n];
    let mut k = 1usize;

    while k < n {
        let r = rank.clone();
        let kk = k;
        sa.sort_by(|&a, &b| {
            let ra = r[a as usize];
            let rb = r[b as usize];
            if ra != rb {
                return ra.cmp(&rb);
            }
            let ra2 = if (a as usize) + kk < n { r[(a as usize) + kk] } else { -1 };
            let rb2 = if (b as usize) + kk < n { r[(b as usize) + kk] } else { -1 };
            ra2.cmp(&rb2)
        });

        tmp[sa[0] as usize] = 0;
        for i in 1..n {
            let prev = sa[i - 1] as usize;
            let curr = sa[i] as usize;
            let same = r[prev] == r[curr]
                && ((prev + kk >= n && curr + kk >= n)
                    || (prev + kk < n && curr + kk < n
                        && r[prev + kk] == r[curr + kk]));
            tmp[curr] = tmp[prev] + if same { 0 } else { 1 };
        }
        rank.copy_from_slice(&tmp);
        if rank[sa[n - 1] as usize] as usize == n - 1 {
            break;
        }
        k *= 2;
    }

    sa
}

fn find_match(sa: &[i64], source: &[u8], target: &[u8]) -> (usize, usize) {
    if sa.is_empty() || target.is_empty() {
        return (0, 0);
    }

    let n = sa.len();
    let mut lo = 0usize;
    let mut hi = n - 1;
    let mut best_pos = 0usize;
    let mut best_len = 0usize;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let pos = sa[mid] as usize;
        let ml = match_len(source, pos, target, 0);
        if ml > best_len {
            best_len = ml;
            best_pos = pos;
        }
        if compare_at(source, pos, target) == std::cmp::Ordering::Less {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    for &idx in &[lo, lo.saturating_sub(1)] {
        if idx < n {
            let pos = sa[idx] as usize;
            let ml = match_len(source, pos, target, 0);
            if ml > best_len {
                best_len = ml;
                best_pos = pos;
            }
        }
    }

    (best_pos, best_len)
}

fn match_len(a: &[u8], apos: usize, b: &[u8], bpos: usize) -> usize {
    let max = (a.len() - apos).min(b.len() - bpos);
    let mut i = 0;
    while i < max && a[apos + i] == b[bpos + i] {
        i += 1;
    }
    i
}

fn compare_at(source: &[u8], pos: usize, target: &[u8]) -> std::cmp::Ordering {
    let slen = source.len() - pos;
    let cmp_len = slen.min(target.len());
    match source[pos..pos + cmp_len].cmp(&target[..cmp_len]) {
        std::cmp::Ordering::Equal => slen.cmp(&target.len()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bspatch_identity() {
        // Patch that copies source unchanged
        let source = b"Hello World";
        let target_size = source.len();

        // Control: add_len=11, insert_len=0, seek_dist=0
        // Diff: 11 zero bytes (add 0 to each source byte)
        let mut patch = Vec::new();
        patch.extend_from_slice(&encode_i64(11));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&[0u8; 11]); // diff = zeros

        let result = bspatch(source, target_size, &patch).unwrap();
        assert_eq!(result, source);
    }

    #[test]
    fn bspatch_modify_one_byte() {
        let source = b"Hello World";
        let target_size = source.len();

        // Change byte 5 from ' ' to '-'
        let mut patch = Vec::new();
        patch.extend_from_slice(&encode_i64(11));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&encode_i64(0));
        let mut diff = vec![0u8; 11];
        diff[5] = b'-'.wrapping_sub(b' '); // diff for the changed byte
        patch.extend_from_slice(&diff);

        let result = bspatch(source, target_size, &patch).unwrap();
        assert_eq!(result, b"Hello-World");
    }

    #[test]
    fn bspatch_insert_data() {
        let source = b"AB";
        let target_size = 5;

        // Block 1: add_len=2 (copy source), insert_len=3 (insert "XYZ"), seek=0
        let mut patch = Vec::new();
        patch.extend_from_slice(&encode_i64(2));
        patch.extend_from_slice(&encode_i64(3));
        patch.extend_from_slice(&encode_i64(0));
        patch.extend_from_slice(&[0, 0]); // diff = zeros (copy AB)
        patch.extend_from_slice(b"XYZ"); // insert

        let result = bspatch(source, target_size, &patch).unwrap();
        assert_eq!(result, b"ABXYZ");
    }

    fn encode_i64(val: i64) -> Vec<u8> {
        let mut buf = Vec::new();
        write_i64(&mut buf, val);
        buf
    }

    #[test]
    fn bscreate_identity() {
        let source = b"Hello World";
        let patch = bscreate(source, source).unwrap();
        let result = bspatch(source, source.len(), &patch).unwrap();
        assert_eq!(result, source);
    }

    #[test]
    fn bscreate_single_change() {
        let source = b"Hello World!!!";
        let target = b"Hello-World!!!";
        let patch = bscreate(source, target).unwrap();
        let result = bspatch(source, target.len(), &patch).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn bscreate_completely_different() {
        let source = b"AAAAAAAAAA";
        let target = b"ZZZZZZZZZZ";
        let patch = bscreate(source, target).unwrap();
        let result = bspatch(source, target.len(), &patch).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn bscreate_empty_source() {
        let source = b"";
        let target = b"new content";
        let patch = bscreate(source, target).unwrap();
        let result = bspatch(source, target.len(), &patch).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn bscreate_empty_target() {
        let source = b"some data";
        let target = b"";
        let patch = bscreate(source, target).unwrap();
        let result = bspatch(source, target.len(), &patch).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn bscreate_pa30_like() {
        let reference = b"Hello, this is a reference buffer with some repeated content. Hello again!";
        let target = b"Hello, this is a modified buffer with some repeated content. Goodbye!";
        let patch = bscreate(reference, target).unwrap();
        let result = bspatch(reference, target.len(), &patch).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn bscreate_repetitive_data() {
        let source: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let mut target = source.clone();
        target[500] = 0xFF;
        target[501] = 0xFE;
        let patch = bscreate(&source, &target).unwrap();
        let result = bspatch(&source, target.len(), &patch).unwrap();
        assert_eq!(result, target);
    }
}
