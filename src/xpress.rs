//! LZXPRESS Huffman (MS-XCA "LZ77+Huffman") decompression, plus the Windows
//! Compression API (`cabinet.dll`) container that wraps it.
//!
//! Used by reverse deltas: type-1 ("deletes") sections store their byte payload
//! as a `0xC0E5510A` Compression API container with algorithm
//! `COMPRESS_ALGORITHM_XPRESS_HUFF` (4). The container framing matches the LZMS
//! one in `crates/lzms` (24-byte header + `[u32 csize][data]` chunks); only the
//! per-chunk codec differs.
//!
//! XPRESS Huffman (MS-XCA section 2.2): each chunk is a sequence of 64 KiB
//! blocks. Every block starts with a 256-byte table of 512 4-bit Huffman code
//! lengths (byte `i` -> symbol `2i` low nibble, `2i+1` high nibble), followed by
//! a bitstream consumed MSB-first from 16-bit little-endian words. Symbols
//! 0..255 are literals; 256..511 encode a match: low nibble = length code, next
//! nibble = number of extra distance bits. Extended lengths (low nibble 15) are
//! read as raw little-endian integers from the byte cursor; the distance's extra
//! bits then follow in the bitstream. The byte cursor is advanced only by whole
//! 16-bit word pulls and these raw reads, which keeps it exact across blocks --
//! the next block's table simply begins at the current cursor.

use crate::{Error, Result};

const CONTAINER_MAGIC: u32 = 0xC0E5_510A;
const CONTAINER_HEADER: usize = 24;
const ALGORITHM_XPRESS_HUFF: u8 = 4;
const MAX_CHUNK: usize = 0x0400_0000;

const NUM_SYMBOLS: usize = 512;
const BLOCK_SIZE: usize = 0x10000;
const MIN_MATCH: usize = 3;

/// Decompress a Windows Compression API container holding XPRESS_HUFF chunks.
pub(crate) fn decompress_container(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < CONTAINER_HEADER {
        return Err(Error::Malformed("xpress: container too short"));
    }
    if u32::from_le_bytes(data[0..4].try_into().unwrap()) != CONTAINER_MAGIC {
        return Err(Error::Malformed("xpress: bad container magic"));
    }
    let header_size = u16::from_le_bytes(data[4..6].try_into().unwrap()) as usize;
    if header_size < CONTAINER_HEADER || header_size > data.len() {
        return Err(Error::Malformed("xpress: bad header size"));
    }
    if data[7] != ALGORITHM_XPRESS_HUFF {
        return Err(Error::Malformed("xpress: not an XPRESS_HUFF container"));
    }
    let uncompressed_total = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;
    if uncompressed_total == 0 {
        return Ok(Vec::new());
    }
    let chunk_size = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
    if chunk_size == 0 || chunk_size > MAX_CHUNK {
        return Err(Error::Malformed("xpress: bad chunk size"));
    }

    let mut out = Vec::with_capacity(uncompressed_total.min(MAX_CHUNK));
    let mut cursor = header_size;
    while out.len() < uncompressed_total {
        if cursor + 4 > data.len() {
            return Err(Error::Truncated);
        }
        let compressed_size =
            u32::from_le_bytes(data[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if compressed_size == 0 {
            return Err(Error::Malformed("xpress: zero-length chunk"));
        }
        let chunk_uncompressed = chunk_size.min(uncompressed_total - out.len());
        let end = cursor
            .checked_add(compressed_size)
            .filter(|&e| e <= data.len())
            .ok_or(Error::Truncated)?;
        let payload = &data[cursor..end];

        if compressed_size == chunk_uncompressed {
            out.extend_from_slice(payload); // stored verbatim (incompressible)
        } else if compressed_size > chunk_uncompressed {
            return Err(Error::Malformed("xpress: chunk larger than plaintext"));
        } else {
            decompress_block_stream(payload, chunk_uncompressed, &mut out)?;
        }
        cursor = end;
    }
    Ok(out)
}

/// Decompress raw XPRESS Huffman data of known output size into `out`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decompress(input: &[u8], out_size: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(out_size);
    decompress_block_stream(input, out_size, &mut out)?;
    Ok(out)
}

// --- Raw reads on an absolute byte cursor. The XPRESS Huffman stream interleaves
// 16-bit bit-buffer refills with raw little-endian integers (extended lengths);
// both advance the same cursor, so the per-block table boundary is exactly the
// cursor position. ---

fn read_u8(input: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *input.get(*pos).ok_or(Error::Truncated)?;
    *pos += 1;
    Ok(b)
}

fn read_u16(input: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 2 > input.len() {
        return Err(Error::Truncated);
    }
    let v = u16::from_le_bytes([input[*pos], input[*pos + 1]]) as u32;
    *pos += 2;
    Ok(v)
}

fn read_u32(input: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > input.len() {
        return Err(Error::Truncated);
    }
    let v = u32::from_le_bytes([input[*pos], input[*pos + 1], input[*pos + 2], input[*pos + 3]]);
    *pos += 4;
    Ok(v)
}

/// Refill the accumulator with the next 16-bit word (or a trailing byte at the
/// very end). Called only when exactly 16 bits remain, so the cursor never runs
/// ahead of the bits actually consumed.
fn pull(input: &[u8], pos: &mut usize, bits: &mut u32, remaining: &mut i32) -> Result<()> {
    if *pos + 1 < input.len() {
        let w = read_u16(input, pos)?;
        *bits = (*bits << 16) | w;
        *remaining += 16;
    } else if *pos < input.len() {
        let b = read_u8(input, pos)? as u32;
        *bits = (*bits << 8) | b;
        *remaining += 8;
    } else {
        return Err(Error::Truncated);
    }
    Ok(())
}

/// Build the tree-walk decode table from a 256-byte (512 nibble) code-length
/// header. Decoding walks one bit at a time: `index = (index << 1) + bit + 1`;
/// `0xFFFF` marks an internal node, otherwise the low 9 bits hold the symbol.
fn build_table(table_bytes: &[u8]) -> Result<Vec<u16>> {
    // Pack each present symbol as (len << 9) | symbol so a plain ascending sort
    // orders by (length, symbol) -- the canonical-code order.
    let mut syms: Vec<u16> = Vec::with_capacity(NUM_SYMBOLS);
    for (i, &b) in table_bytes[..256].iter().enumerate() {
        let even = (b & 0x0F) as u16;
        let odd = (b >> 4) as u16;
        if even != 0 {
            syms.push((even << 9) | (i as u16 * 2));
        }
        if odd != 0 {
            syms.push((odd << 9) | (i as u16 * 2 + 1));
        }
    }
    syms.sort_unstable();

    let mut table = vec![0xFFFFu16; 1 << 16];
    let mut code: u32 = 0;
    let mut prev_len: u16 = 0;
    for s in syms {
        let len = s >> 9;
        let sym = s & 511;
        code <<= len - prev_len;
        prev_len = len;
        let mut index = 0usize;
        for bp in (0..len).rev() {
            let bit = ((code >> bp) & 1) as usize;
            index = (index << 1) + bit + 1;
            if index >= table.len() {
                return Err(Error::Malformed("xpress: code too long"));
            }
        }
        table[index] = sym;
        code += 1;
    }
    Ok(table)
}

/// Decode one or more 64 KiB XPRESS Huffman blocks into `out`, appending exactly
/// `out_size` bytes.
fn decompress_block_stream(input: &[u8], out_size: usize, out: &mut Vec<u8>) -> Result<()> {
    let target = out.len() + out_size;
    let mut pos = 0usize;

    while out.len() < target {
        if pos + 256 > input.len() {
            return Err(Error::Truncated);
        }
        let table = build_table(&input[pos..pos + 256])?;
        pos += 256;

        // Prime 32 bits from two 16-bit words; the stream is read MSB-first.
        let hi = read_u16(input, &mut pos)?;
        let lo = read_u16(input, &mut pos)?;
        let mut bits: u32 = (hi << 16) | lo;
        let mut remaining: i32 = 32;

        let block_end = (out.len() + BLOCK_SIZE).min(target);
        let mut index = 0usize;
        let mut length = 0usize;
        let mut distance = 0usize;
        let mut dist_bits = 0i32;

        while out.len() < block_end {
            if remaining == 16 {
                pull(input, &mut pos, &mut bits, &mut remaining)?;
            }
            remaining -= 1;
            let b = ((bits >> remaining) & 1) as usize;

            if length == 0 {
                // Walk the Huffman tree one bit at a time.
                index = (index << 1) + b + 1;
                if index >= table.len() {
                    return Err(Error::Malformed("xpress: bad code index"));
                }
                let entry = table[index];
                if entry == 0xFFFF {
                    continue; // internal node; need more bits
                }
                let symbol = (entry & 511) as usize;
                index = 0;
                if symbol < 256 {
                    out.push(symbol as u8);
                    continue;
                }
                // Match: low nibble = length code, high nibble = #distance bits.
                dist_bits = ((symbol >> 4) & 15) as i32;
                distance = 1usize << dist_bits;
                length = symbol & 15;
                if length == 15 {
                    length += read_u8(input, &mut pos)? as usize;
                    if length == 255 + 15 {
                        length = read_u16(input, &mut pos)? as usize;
                        if length == 0 {
                            length = read_u32(input, &mut pos)? as usize;
                        }
                    }
                }
                length += MIN_MATCH;
            } else {
                // Pulling the match's extra distance bits, one per iteration.
                dist_bits -= 1;
                distance |= b << dist_bits;
            }

            if dist_bits == 0 && length != 0 {
                if distance == 0 || distance > out.len() {
                    return Err(Error::Malformed("xpress: match offset out of range"));
                }
                // Byte-by-byte (ranges may overlap when distance < length).
                let start = out.len() - distance;
                for i in 0..length {
                    let v = out[start + i];
                    out.push(v);
                }
                length = 0;
                distance = 0;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod vector_test {
    // Genuine XPRESS_HUFF container + plaintext captured from a real WinSxS reverse
    // diff (gitignored under notes/; redistribution of MS bytes). Skips when absent.
    #[test]
    fn genuine_vector() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/notes/genuine-samples/xpress");
        let blob = match std::fs::read(format!("{dir}/blob.bin")) {
            Ok(b) => b,
            Err(_) => return,
        };
        let expected = std::fs::read(format!("{dir}/plain.bin")).unwrap();
        let out = super::decompress_container(&blob).expect("decompress");
        let first_diff = out.iter().zip(&expected).position(|(a, b)| a != b);
        if let Some(d) = first_diff {
            panic!(
                "first diff at byte {d}; got {:02x?} want {:02x?}",
                &out[d..(d + 12).min(out.len())],
                &expected[d..(d + 12).min(expected.len())]
            );
        }
        assert_eq!(out.len(), expected.len(), "size (prefix matched)");
    }
}
