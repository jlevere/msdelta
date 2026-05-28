use crate::{Error, Result};

mod adaptive;
mod range_coder;
mod tables;
mod x86_filter;

use adaptive::{AdaptiveCode, BackBits, BackBitsWriter};
use range_coder::{
    ProbEntry, ProbTables, RangeDecoder, RangeEncoder,
    NUM_DELTA_PROBS, NUM_DELTA_REP_PROBS, NUM_LZ_PROBS, NUM_LZ_REP_PROBS,
    NUM_MAIN_PROBS, NUM_MATCH_PROBS,
};
use x86_filter::{x86_filter, x86_filter_impl};

const COMPRESSION_API_MAGIC: u32 = 0xC0E5_510A;
const COMPRESSION_API_HEADER_SIZE: usize = 24;

/// Decompress a Windows Compression API (cabinet.dll) LZMS-wrapped buffer.
///
/// This is the format produced by `Compress()` with `COMPRESS_ALGORITHM_LZMS`
/// and consumed by msdelta.dll's `LzmsCodec::Decompress`. It consists of a
/// 24-byte header followed by chunk-size + compressed-data pairs.
pub fn decompress_compression_api(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < COMPRESSION_API_HEADER_SIZE + 4 {
        return Err(Error::Malformed("LZMS: compression API buffer too short"));
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != COMPRESSION_API_MAGIC {
        return Err(Error::Malformed("LZMS: bad compression API magic"));
    }
    let uncompressed_size = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    let chunk_compressed = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;
    let payload_start = COMPRESSION_API_HEADER_SIZE + 4;
    let payload_end = payload_start + chunk_compressed;
    if payload_end > data.len() {
        return Err(Error::Truncated);
    }
    if chunk_compressed == uncompressed_size {
        return Ok(data[payload_start..payload_end].to_vec());
    }
    decompress(&data[payload_start..payload_end], uncompressed_size)
}

/// Compress data into the Windows Compression API (cabinet.dll) LZMS format.
///
/// Produces the same format that `decompress_compression_api` reads:
/// 24-byte header + chunk-size + LZMS-compressed payload.
pub fn compress_compression_api(data: &[u8]) -> Result<Vec<u8>> {
    let compressed = compress(data)?;
    let payload = if compressed.len() < data.len() { &compressed } else { data };
    let mut out = Vec::with_capacity(COMPRESSION_API_HEADER_SIZE + 4 + payload.len());
    out.extend_from_slice(&COMPRESSION_API_MAGIC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decompress a raw LZMS bitstream.
pub fn decompress(data: &[u8], output_size: usize) -> Result<Vec<u8>> {
    if data.is_empty() || output_size == 0 {
        return Ok(Vec::new());
    }
    if output_size > 64 * 1024 * 1024 {
        return Err(Error::Malformed("LZMS: output size exceeds 256 MB limit"));
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
            let match_bit =
                rc.decode_bit(&mut match_st, NUM_MATCH_PROBS, &mut probs.match_);

            if match_bit == 0 {
                let lz_bit = rc.decode_bit(&mut lz_st, NUM_LZ_PROBS, &mut probs.lz);

                let offset;
                if lz_bit == 0 {
                    let slot = lz_offset_code.decode_symbol(&mut bs)?;
                    offset = tables::decode_offset(slot, &mut bs);
                    queue_push(&mut lz_queue, offset);
                } else {
                    let rep = decode_rep(
                        &mut rc, &mut lz_rep_st, &mut probs.lz_rep,
                    );
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
                for i in 0..n {
                    out[pos + i] = out[src + i];
                }
                pos += n;
                prev_type = 1;
            } else {
                let delta_bit =
                    rc.decode_bit(&mut delta_st, NUM_DELTA_PROBS, &mut probs.delta);

                let power;
                let raw_offset;
                if delta_bit == 0 {
                    power = delta_power_code.decode_symbol(&mut bs)? as u32;
                    raw_offset = tables::decode_offset(
                        delta_offset_code.decode_symbol(&mut bs)?,
                        &mut bs,
                    );
                    queue_push_pair(&mut delta_queue, (raw_offset, power));
                } else {
                    let rep = decode_rep(
                        &mut rc, &mut delta_rep_st, &mut probs.delta_rep,
                    );
                    let adj = (rep + ((prev_type >> 1) & 1) as usize).min(3);
                    let pair = delta_queue[adj];
                    raw_offset = pair.0;
                    power = pair.1;
                    queue_mtf_pair(&mut delta_queue, adj);
                }

                let length = tables::decode_length(
                    length_code.decode_symbol(&mut bs)?,
                    &mut bs,
                ) as usize;

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

        // Try delta match: find (offset, power) where the difference pattern matches
        let mut delta_len = 0u32;
        let mut delta_offset = 0u32;
        let mut delta_power = 0u32;
        if pos >= 2 {
            for power in 0..3u32 {
                let span = 1usize << power;
                if span > pos { break; }
                for try_off in 1..pos.min(32) {
                    let off = try_off << power;
                    if off + span > pos { continue; }
                    let mut ml = 0u32;
                    while pos + (ml as usize) < d.len() && ml < 1046 {
                        let p = pos + ml as usize;
                        let s = p - off;
                        if p < span || s < span { break; }
                        let expected = d[s]
                            .wrapping_add(d[p - span])
                            .wrapping_sub(d[s - span]);
                        if d[p] != expected { break; }
                        ml += 1;
                    }
                    if ml > delta_len && ml >= 3 {
                        delta_len = ml;
                        delta_offset = try_off as u32;
                        delta_power = power;
                    }
                }
            }
        }

        let use_delta = delta_len > match_len + 1;

        if use_delta {
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
                    0 => rc.encode_bit(0, &mut delta_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.delta_rep[0]),
                    1 => {
                        rc.encode_bit(1, &mut delta_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.delta_rep[0]);
                        rc.encode_bit(0, &mut delta_rep_st[1], NUM_DELTA_REP_PROBS, &mut probs.delta_rep[1]);
                    }
                    _ => {
                        rc.encode_bit(1, &mut delta_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.delta_rep[0]);
                        rc.encode_bit(1, &mut delta_rep_st[1], NUM_DELTA_REP_PROBS, &mut probs.delta_rep[1]);
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
        } else if match_len >= 3 {
            // Encode LZ match
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
                    0 => rc.encode_bit(0, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]),
                    1 => {
                        rc.encode_bit(1, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]);
                        rc.encode_bit(0, &mut lz_rep_st[1], NUM_DELTA_REP_PROBS, &mut probs.lz_rep[1]);
                    }
                    _ => {
                        rc.encode_bit(1, &mut lz_rep_st[0], NUM_LZ_REP_PROBS, &mut probs.lz_rep[0]);
                        rc.encode_bit(1, &mut lz_rep_st[1], NUM_DELTA_REP_PROBS, &mut probs.lz_rep[1]);
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

fn match_length(data: &[u8], src: usize, dst: usize, limit: usize) -> u32 {
    let max = (limit - dst).min(1046) as u32;
    let mut len = 0u32;
    while len < max && data[src + len as usize] == data[dst + len as usize] {
        len += 1;
    }
    len
}

fn decode_rep(
    rc: &mut RangeDecoder,
    st: &mut [u32; 2],
    probs: &mut [Vec<ProbEntry>; 2],
) -> usize {
    let b0 = rc.decode_bit(&mut st[0], NUM_LZ_REP_PROBS, &mut probs[0]);
    if b0 == 0 { return 0; }
    let b1 = rc.decode_bit(&mut st[1], NUM_DELTA_REP_PROBS, &mut probs[1]);
    if b1 == 0 { 1 } else { 2 }
}

fn queue_push(q: &mut [u32; 4], val: u32) {
    q[3] = q[2]; q[2] = q[1]; q[1] = q[0]; q[0] = val;
}

fn queue_mtf(q: &mut [u32; 4], idx: usize) {
    let val = q[idx];
    for i in (1..=idx).rev() { q[i] = q[i - 1]; }
    q[0] = val;
}

fn queue_push_pair(q: &mut [(u32, u32); 4], val: (u32, u32)) {
    q[3] = q[2]; q[2] = q[1]; q[1] = q[0]; q[0] = val;
}

fn queue_mtf_pair(q: &mut [(u32, u32); 4], idx: usize) {
    let val = q[idx];
    for i in (1..=idx).rev() { q[i] = q[i - 1]; }
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

        if !lzms_path.exists() { return; }

        let compressed = std::fs::read(&lzms_path).unwrap();
        let expected = std::fs::read(&raw_path).unwrap();

        match decompress_compression_api(&compressed) {
            Ok(output) => {
                assert_eq!(output.len(), expected.len(), "{name}: size mismatch");
                for (i, (&got, &want)) in output.iter().zip(expected.iter()).enumerate() {
                    if got != want {
                        panic!(
                            "{name}: first diff at byte {i}: got {got:#04x}, want {want:#04x}"
                        );
                    }
                }
            }
            Err(e) => panic!("{name}: decode failed: {e}"),
        }
    }

    #[test] fn zeros() { check("zeros"); }
    #[test] fn sequential() { check("sequential"); }
    #[test] fn pattern() { check("pattern"); }
    #[test] fn single_byte() { check("single_byte"); }
    #[test] fn english() { check("english"); }
    #[test] fn small() { check("small"); }
    #[test] fn random() { check("random"); }

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
        assert_ne!(data, original, "x86 filter should modify data with repeated call targets");

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

    #[test]
    fn compression_api_roundtrip() {
        let original = b"Compression API wrapper roundtrip test data with some repetition repetition";
        let wrapped = compress_compression_api(original).unwrap();
        assert!(wrapped.len() >= COMPRESSION_API_HEADER_SIZE + 4);
        let magic = u32::from_le_bytes(wrapped[0..4].try_into().unwrap());
        assert_eq!(magic, COMPRESSION_API_MAGIC);
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
