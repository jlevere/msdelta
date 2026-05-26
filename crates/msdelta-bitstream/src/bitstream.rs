//! LSB-first bitstream reader and writer for PA30 delta headers and patch data.
//!
//! Mirrors the `BitReader`/`BitWriter` classes in `UpdateCompression.dll`
//! (confirmed via PDB symbols). Both use u64 accumulators with 32-bit word
//! flushing/refilling.

use crate::{Error, Result};

/// LSB-first bitstream reader over a byte slice.
///
/// Bits are consumed from the least-significant end of a 64-bit accumulator.
/// The accumulator is refilled in 32-bit chunks for efficiency, with a
/// tail-byte path for the final 1-3 bytes.
#[derive(Debug)]
pub struct BitReader<'a> {
    /// Remaining aligned 4-byte words.
    words: &'a [u8],
    /// Tail bytes after the last aligned word boundary.
    tail: &'a [u8],
    /// Bit accumulator, LSB-first.
    accum: u64,
    /// Number of valid bits in `accum`.
    bits: u32,
    /// Padding bits in the final byte (0-7), read from the stream header.
    padding: u32,
}

impl<'a> BitReader<'a> {
    /// Create a new BitReader from a byte slice.
    ///
    /// The first 3 bits of the stream encode the number of padding bits in
    /// the final byte. This constructor reads and consumes those 3 bits.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::Truncated);
        }

        let padding_bits = (data[0] & 7) as u32;

        let total_bits = data.len() as u64 * 8;
        if total_bits < 3 + padding_bits as u64 {
            return Err(Error::Truncated);
        }

        let aligned_end = data.len() & !3;
        let (word_bytes, tail) = data.split_at(aligned_end);

        let mut reader = BitReader {
            words: word_bytes,
            tail,
            accum: 0,
            bits: 0,
            padding: padding_bits,
        };

        reader.seek(0);
        reader.consume(3)?;

        Ok(reader)
    }

    /// Total usable bits remaining (accounting for final-byte padding).
    pub fn remaining(&self) -> u32 {
        let unloaded_bytes = self.words.len() as u32 + self.tail.len() as u32;
        let unloaded_bits = unloaded_bytes * 8;
        let padding = if self.tail.is_empty() && self.words.is_empty() {
            0
        } else {
            self.padding
        };
        self.bits + unloaded_bits - padding
    }

    /// Read exactly `n` bits (0..=64) as a u64, LSB-first.
    pub fn read_bits(&mut self, n: u32) -> Result<u64> {
        if n == 0 {
            return Ok(0);
        }
        if n > 64 {
            return Err(Error::Malformed("cannot read more than 64 bits at once"));
        }
        self.ensure(n)?;
        let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        let val = self.accum & mask;
        self.consume(n)?;
        Ok(val)
    }

    /// Peek at the lowest `n` bits without consuming.
    pub fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= self.bits && n <= 64);
        if n == 0 {
            return 0;
        }
        let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        self.accum & mask
    }

    /// Peek at `n` bits, bit-reversed (MSB-first) for canonical Huffman lookup.
    ///
    /// The Huffman table is indexed by the code read MSB-first, but our
    /// accumulator stores bits LSB-first. This reverses the bit order of
    /// the peeked value so the table lookup works correctly.
    pub fn peek_msb(&self, n: u32) -> u32 {
        debug_assert!(n <= self.bits && n <= 32);
        let raw = (self.accum & ((1u64 << n) - 1)) as u32;
        raw.reverse_bits() >> (32 - n)
    }

    /// Ensure at least `n` bits are available (public for Huffman).
    pub fn ensure_bits(&mut self, n: u32) -> Result<()> {
        self.ensure(n)
    }

    /// Consume `n` bits (public for Huffman).
    pub fn consume_bits(&mut self, n: u32) -> Result<()> {
        self.consume(n)
    }

    /// Read a variable-length 64-bit integer (IntFunctions::ReadBit encoding).
    ///
    /// Encoding: unary prefix of `nibbles` zero-bits + 1-bit, then
    /// `(nibbles + 1) * 4` value bits, LSB-first. No implicit high bit.
    /// Max nibbles = 15 (64 value bits).
    pub fn read_i64(&mut self) -> Result<i64> {
        let want = 17.min(self.remaining());
        self.ensure(want)?;

        let sentinel = self.accum | 0x1_0000;
        let nibbles = sentinel.trailing_zeros();

        if nibbles == 16 {
            return Err(Error::InvalidVarInt);
        }

        let prefix_len = nibbles + 1;
        let value_bits = (nibbles + 1) * 4;
        let total = prefix_len + value_bits;

        if total > 64 {
            return self.read_i64_wide(nibbles);
        }

        self.ensure(total)?;

        self.shift_out(prefix_len);

        let mask = if value_bits == 64 {
            u64::MAX
        } else {
            (1u64 << value_bits) - 1
        };
        let val = self.accum & mask;
        self.shift_out(value_bits);

        Ok(val as i64)
    }

    /// Slow path for i64 values where prefix + value > 64 bits in the accumulator.
    fn read_i64_wide(&mut self, nibbles: u32) -> Result<i64> {
        let prefix_len = nibbles + 1;
        self.ensure(prefix_len)?;
        self.shift_out(prefix_len);

        let value_bits = (nibbles + 1) * 4;

        if value_bits <= 32 {
            let val = self.read_bits(value_bits)?;
            return Ok(val as i64);
        }

        let low = self.read_bits(32)?;
        let high_bits = value_bits - 32;
        let high = self.read_bits(high_bits)?;
        Ok((high << 32 | low) as i64)
    }

    /// Read a variable-length 32-bit integer (BitReader::ReadNumber encoding).
    ///
    /// Encoding: unary prefix, then `nibbles + 8` value bits, plus an implicit
    /// high bit at position `nibbles + 8`. Minimum value is 256.
    pub fn read_u32_number(&mut self) -> Result<u32> {
        let want = 32.min(self.remaining());
        self.ensure(want)?;

        if self.accum & 0xFFFF_FFFF == 0 {
            return Err(Error::InvalidVarInt);
        }

        let nibbles = (self.accum as u32).trailing_zeros();
        if nibbles > 23 {
            return Err(Error::InvalidVarInt);
        }

        let prefix_len = nibbles + 1;
        let value_bits = nibbles + 8;

        self.ensure(prefix_len + value_bits)?;
        self.shift_out(prefix_len);

        let mask = (1u64 << value_bits) - 1;
        let raw = (self.accum & mask) as u32;
        self.shift_out(value_bits);

        Ok((1u32 << value_bits) | raw)
    }

    /// Read a buffer: size (via read_i64) + align to byte boundary + raw bytes.
    pub fn read_buffer(&mut self) -> Result<Vec<u8>> {
        let size = self.read_i64()?;
        if size < 0 {
            return Err(Error::Malformed("negative buffer size"));
        }
        let size = size as usize;

        self.align_to_byte();

        if size == 0 {
            return Ok(Vec::new());
        }

        // After align_to_byte, the accumulator has 0 or 8/16/24 bits.
        // Drain them first, then bulk-copy from the underlying byte stream.
        let mut buf = Vec::with_capacity(size);
        let mut remaining = size;

        // Drain any bits in the accumulator
        while remaining > 0 && self.bits >= 8 {
            buf.push((self.accum & 0xFF) as u8);
            self.shift_out(8);
            remaining -= 1;
        }

        // Bulk copy from word/tail slices
        let from_words = remaining.min(self.words.len());
        if from_words > 0 {
            buf.extend_from_slice(&self.words[..from_words]);
            self.words = &self.words[from_words..];
            remaining -= from_words;
        }
        let from_tail = remaining.min(self.tail.len());
        if from_tail > 0 {
            buf.extend_from_slice(&self.tail[..from_tail]);
            self.tail = &self.tail[from_tail..];
            remaining -= from_tail;
        }

        if remaining > 0 {
            return Err(Error::BitstreamExhausted {
                needed: (remaining * 8) as u32,
                available: 0,
            });
        }

        Ok(buf)
    }

    /// Skip to the next byte boundary by discarding 0-7 bits.
    pub fn align_to_byte(&mut self) {
        let discard = self.bits % 8;
        if discard > 0 {
            self.shift_out(discard);
        }
    }

    /// Ensure at least `n` bits are available in the accumulator.
    fn ensure(&mut self, n: u32) -> Result<()> {
        while self.bits < n {
            if !self.refill() {
                if self.bits < n {
                    return Err(Error::BitstreamExhausted {
                        needed: n,
                        available: self.bits,
                    });
                }
            }
        }
        Ok(())
    }

    /// Consume `n` bits from the accumulator.
    fn consume(&mut self, n: u32) -> Result<()> {
        self.ensure(n)?;
        self.shift_out(n);
        Ok(())
    }

    /// Shift out `n` bits from the low end of the accumulator.
    fn shift_out(&mut self, n: u32) {
        debug_assert!(n <= self.bits);
        if n == 64 {
            self.accum = 0;
        } else {
            self.accum >>= n;
        }
        self.bits -= n;
    }

    /// Try to refill the accumulator from words or tail bytes.
    /// Returns true if any bits were added.
    fn refill(&mut self) -> bool {
        if self.words.len() >= 4 {
            let word = u32::from_le_bytes([
                self.words[0],
                self.words[1],
                self.words[2],
                self.words[3],
            ]);
            self.words = &self.words[4..];
            self.accum |= (word as u64) << self.bits;
            self.bits += 32;
            return true;
        }

        // Remaining bytes from words (0-3) + tail bytes
        let remaining_words = self.words;
        let tail = self.tail;
        if remaining_words.is_empty() && tail.is_empty() {
            return false;
        }

        let mut val: u64 = 0;
        let mut loaded_bits: u32 = 0;
        for &b in remaining_words.iter().chain(tail.iter()) {
            val |= (b as u64) << loaded_bits;
            loaded_bits += 8;
        }
        loaded_bits = loaded_bits.saturating_sub(self.padding);
        self.accum |= val << self.bits;
        self.bits += loaded_bits;

        self.words = &[];
        self.tail = &[];
        loaded_bits > 0
    }

    /// Reset accumulator and trigger initial refill. Only used at construction.
    fn seek(&mut self, _byte_offset: usize) {
        self.accum = 0;
        self.bits = 0;
    }
}

/// LSB-first bitstream writer, symmetric to `BitReader`.
///
/// Accumulates bits in a u64, flushing 32-bit words to an output buffer.
/// The first 3 bits of the stream encode the padding count for the final byte.
#[derive(Debug)]
pub struct BitWriter {
    buf: Vec<u8>,
    accum: u64,
    bits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        let mut w = BitWriter {
            buf: Vec::new(),
            accum: 0,
            bits: 0,
        };
        w.write_bits(0, 3);
        w
    }

    /// Write the low `n` bits of `val` (LSB-first), 0 <= n <= 64.
    pub fn write_bits(&mut self, val: u64, n: u32) {
        debug_assert!(n <= 64);
        if n == 0 {
            return;
        }
        let masked = if n == 64 { val } else { val & ((1u64 << n) - 1) };
        if self.bits + n > 64 {
            let low_n = 64 - self.bits;
            let low_mask = if low_n == 64 { u64::MAX } else { (1u64 << low_n) - 1 };
            self.accum |= (masked & low_mask) << self.bits;
            self.bits = 64;
            self.flush();
            self.accum = masked >> low_n;
            self.bits = n - low_n;
        } else {
            self.accum |= masked << self.bits;
            self.bits += n;
        }
        self.flush();
    }

    /// Write a variable-length 64-bit integer (IntFunctions::WriteBit encoding).
    ///
    /// Symmetric to `BitReader::read_i64`.
    pub fn write_i64(&mut self, val: i64) {
        let v = val as u64;
        let high = (v >> 32) as u32;

        if high == 0 {
            let low = v as u32;
            let nibbles = if low == 0 {
                0
            } else {
                let top = (low >> 1) | low | 1;
                (31 - top.leading_zeros()) / 4
            };
            self.write_bits(1u64 << nibbles, nibbles + 1);
            self.write_bits(low as u64, (nibbles + 1) * 4);
        } else {
            let top = (high >> 1) | high;
            let highest = 31 - top.leading_zeros();
            let nibbles = highest / 4;
            let high_value_bits = (highest & !3) + 4;
            self.write_bits(1u64 << (nibbles + 8), nibbles + 9);
            self.write_bits(v & 0xFFFF_FFFF, 32);
            self.write_bits(high as u64, high_value_bits);
        }
    }

    /// Write a variable-length 32-bit integer (BitReader::ReadNumber encoding).
    ///
    /// Value must be >= 256. Writes unary prefix + (nibbles+8) value bits with
    /// implicit high bit.
    pub fn write_u32_number(&mut self, val: u32) {
        debug_assert!(val >= 256);
        let bit_pos = 31 - val.leading_zeros();
        let nibbles = bit_pos.saturating_sub(8);
        let value_bits = nibbles + 8;
        self.write_bits(1u64 << nibbles, nibbles + 1);
        let mask = (1u64 << value_bits) - 1;
        self.write_bits((val as u64) & mask, value_bits);
    }

    /// Write a buffer: size (via write_i64) + align to byte boundary + raw bytes.
    ///
    /// Symmetric to `BitReader::read_buffer`.
    pub fn write_buffer(&mut self, data: &[u8]) {
        self.write_i64(data.len() as i64);
        self.align_to_byte();
        // After alignment, bits is a multiple of 8. Flush to get to a
        // clean byte boundary, then bulk-append the data.
        self.flush();
        if self.bits == 0 {
            self.buf.extend_from_slice(data);
        } else {
            // Accumulator has residual bits — write byte-by-byte
            for &b in data {
                self.write_bits(b as u64, 8);
            }
        }
    }

    /// Pad to the next byte boundary with zero bits.
    pub fn align_to_byte(&mut self) {
        let pad = (8 - (self.bits % 8)) % 8;
        if pad > 0 {
            self.write_bits(0, pad);
        }
    }

    /// Finalize the bitstream and return the output buffer.
    ///
    /// Patches the 3-bit padding count in the first byte and flushes
    /// remaining bits.
    pub fn finish(mut self) -> Vec<u8> {
        let pad = (8 - (self.bits % 8)) % 8;
        if pad > 0 {
            self.write_bits(0, pad);
        }
        self.flush_final();

        if !self.buf.is_empty() {
            self.buf[0] = (self.buf[0] & !7) | (pad as u8 & 7);
        }

        self.buf
    }

    fn flush(&mut self) {
        while self.bits >= 32 {
            let word = self.accum as u32;
            self.buf.extend_from_slice(&word.to_le_bytes());
            self.accum >>= 32;
            self.bits -= 32;
        }
    }

    fn flush_final(&mut self) {
        while self.bits > 0 {
            self.buf.push(self.accum as u8);
            self.accum >>= 8;
            self.bits = self.bits.saturating_sub(8);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_bits_basic() {
        // 0xAB = 10101011, LSB-first bits: 1,1,0,1,0,1,0,1
        // But first 3 bits are padding count.
        // padding = 0b011 = 3
        // Remaining bits: 1,0,1,0,1 (from the rest of 0xAB)
        let data = [0xAB];
        let r = BitReader::new(&data).unwrap();
        // After consuming 3 padding bits, we have 8 - 3 - 3(padding from end) = 2 usable bits
        // Actually: total = 8 bits, padding = 3 (from last byte), consumed 3 for header
        // remaining = 8 - 3 - 3 = 2
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn read_i64_small_value() {
        // Value=1, ReadBit encoding: prefix '1' (nibbles=0), value 0001 (4 bits LSB)
        // Padding header: 000 (3 bits), then stream: 1 1000
        // Byte LSB-first: bits 0-7 = 0,0,0,1,1,0,0,0 = 0x18
        let data = [0x18];
        let mut r = BitReader::new(&data).unwrap();
        let val = r.read_i64().unwrap();
        assert_eq!(val, 1);
    }

    #[test]
    fn smallest_fixture_header_fields() {
        // PA30 bitstream from smallest fixture (offset 12 onward)
        let bitstream = [
            0x18, 0x03, 0x02, 0x00, 0x08, 0x3f, 0x23, 0x04, 0x01, 0x9a, 0x00,
        ];
        let mut r = BitReader::new(&bitstream).unwrap();

        let file_type_set = r.read_i64().unwrap();
        assert_eq!(file_type_set, 1, "FileTypeSet should be 1 (RAW)");

        let file_type = r.read_i64().unwrap();
        assert_eq!(file_type, 1, "FileType should be 1 (RAW)");

        let flags = r.read_i64().unwrap();
        assert_eq!(flags, 0x20000, "Flags should be 0x20000");

        let target_size = r.read_i64().unwrap();
        assert_eq!(target_size, 415, "TargetSize should be 415");

        let hash_alg = r.read_i64().unwrap();
        assert_eq!(hash_alg, 0, "HashAlgId should be 0");
    }

    // --- BitWriter tests ---

    #[test]
    fn writer_roundtrip_bits() {
        let mut w = BitWriter::new();
        w.write_bits(0b1101, 4);
        w.write_bits(0xFF, 8);
        w.write_bits(0, 3);
        let data = w.finish();

        let mut r = BitReader::new(&data).unwrap();
        assert_eq!(r.read_bits(4).unwrap(), 0b1101);
        assert_eq!(r.read_bits(8).unwrap(), 0xFF);
        assert_eq!(r.read_bits(3).unwrap(), 0);
    }

    #[test]
    fn writer_roundtrip_i64() {
        for &val in &[0i64, 1, 42, 255, 256, 1000, 65535, 0x20000, 0x7FFF_FFFF, 0x1_0000_0000] {
            let mut w = BitWriter::new();
            w.write_i64(val);
            let data = w.finish();

            let mut r = BitReader::new(&data).unwrap();
            let got = r.read_i64().unwrap();
            assert_eq!(got, val, "round-trip failed for {val}");
        }
    }

    #[test]
    fn writer_roundtrip_buffer() {
        let payload = b"Hello, PA30!";
        let mut w = BitWriter::new();
        w.write_buffer(payload);
        let data = w.finish();

        let mut r = BitReader::new(&data).unwrap();
        let got = r.read_buffer().unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn writer_roundtrip_header_fields() {
        let mut w = BitWriter::new();
        w.write_i64(1);       // FileTypeSet
        w.write_i64(1);       // FileType
        w.write_i64(0x20000); // Flags
        w.write_i64(415);     // TargetSize
        w.write_i64(0);       // HashAlgId
        w.write_buffer(&[]);  // empty hash
        w.write_buffer(&[]);  // empty preprocess
        let data = w.finish();

        let mut r = BitReader::new(&data).unwrap();
        assert_eq!(r.read_i64().unwrap(), 1);
        assert_eq!(r.read_i64().unwrap(), 1);
        assert_eq!(r.read_i64().unwrap(), 0x20000);
        assert_eq!(r.read_i64().unwrap(), 415);
        assert_eq!(r.read_i64().unwrap(), 0);
        assert!(r.read_buffer().unwrap().is_empty());
        assert!(r.read_buffer().unwrap().is_empty());
    }

    #[test]
    fn writer_roundtrip_u32_number() {
        for &val in &[256u32, 300, 511, 512, 1000, 4096, 65535, 0x7FFF_FFFF] {
            let mut w = BitWriter::new();
            w.write_u32_number(val);
            let data = w.finish();

            let mut r = BitReader::new(&data).unwrap();
            let got = r.read_u32_number().unwrap();
            assert_eq!(got, val, "u32_number round-trip failed for {val}");
        }
    }

    #[test]
    fn writer_multiple_values() {
        let mut w = BitWriter::new();
        w.write_i64(42);
        w.write_i64(9066);
        w.write_buffer(b"test");
        w.write_i64(0);
        let data = w.finish();

        let mut r = BitReader::new(&data).unwrap();
        assert_eq!(r.read_i64().unwrap(), 42);
        assert_eq!(r.read_i64().unwrap(), 9066);
        assert_eq!(r.read_buffer().unwrap(), b"test");
        assert_eq!(r.read_i64().unwrap(), 0);
    }
}
