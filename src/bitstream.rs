//! LSB-first bitstream reader and writer for PA30 delta headers and patch data.
//!
//! The reader uses a 64-bit accumulator with batched refills: one unaligned
//! 8-byte load guarantees at least 56 usable bits, allowing multiple Huffman
//! symbol decodes per refill with zero intermediate checks.

use crate::{Error, Result};

/// LSB-first bitstream reader.
///
/// Hot path: `refill()` → `peek()` → `consume()`, repeated.
/// A single `refill()` guarantees ≥56 bits, enough for 3+ Huffman symbols.
#[derive(Debug)]
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    accum: u64,
    bits: u32,
    total_usable_bits: u64,
    bits_consumed: u64,
}

impl<'a> BitReader<'a> {
    /// Create a BitReader. First 3 bits encode padding count for the final byte.
    pub fn new(data: &'a [u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::Truncated);
        }

        let padding = (data[0] & 7) as u32;
        let total_bits = data.len() as u64 * 8;
        if total_bits < 3 + padding as u64 {
            return Err(Error::Truncated);
        }

        let mut reader = BitReader {
            data,
            pos: 0,
            accum: 0,
            bits: 0,
            total_usable_bits: total_bits - padding as u64,
            bits_consumed: 0,
        };

        reader.refill();
        // Consume the 3-bit padding header (counts toward bits_consumed)
        reader.consume_unchecked(3);

        Ok(reader)
    }

    /// Bits remaining in the stream (including accumulator + unloaded data).
    #[inline]
    pub fn remaining(&self) -> u32 {
        (self.total_usable_bits - self.bits_consumed) as u32
    }

    /// Bits currently loaded in the accumulator (available for peek without refill).
    #[inline]
    pub fn buffered(&self) -> u32 {
        self.bits
    }

    /// Load bytes into the accumulator until it has ≥56 bits (or data is exhausted).
    #[inline]
    pub fn refill(&mut self) {
        if self.pos + 8 <= self.data.len() {
            // Fast path: unaligned 64-bit load
            let bytes = &self.data[self.pos..self.pos + 8];
            let word = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            let shift = self.bits;
            self.accum |= word << shift;
            let loaded = 64 - shift;
            let byte_advance = (loaded / 8) as usize;
            self.pos += byte_advance;
            self.bits += byte_advance as u32 * 8;
        } else {
            // Slow path: byte-at-a-time for tail
            while self.bits <= 56 && self.pos < self.data.len() {
                self.accum |= (self.data[self.pos] as u64) << self.bits;
                self.pos += 1;
                self.bits += 8;
            }
        }
    }

    /// Peek at the low `n` bits without consuming. Caller must ensure enough bits.
    #[inline]
    pub fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= self.bits);
        if n == 0 { return 0; }
        self.accum & ((1u64 << n) - 1)
    }

    /// Consume `n` bits from the accumulator. No refill, no bounds check.
    #[inline]
    pub fn consume_unchecked(&mut self, n: u32) {
        self.accum >>= n;
        self.bits -= n;
        self.bits_consumed += n as u64;
    }

    /// Ensure at least `n` bits are available, refilling if needed.
    #[inline]
    pub fn ensure_bits(&mut self, n: u32) -> Result<()> {
        if self.bits < n {
            self.refill();
            if self.bits < n {
                return Err(Error::BitstreamExhausted {
                    needed: n,
                    available: self.bits,
                });
            }
        }
        Ok(())
    }

    /// Consume `n` bits (public, checked).
    #[inline]
    pub fn consume_bits(&mut self, n: u32) -> Result<()> {
        self.ensure_bits(n)?;
        self.consume_unchecked(n);
        Ok(())
    }

    /// Read exactly `n` bits (0..=64) as a u64.
    #[inline]
    pub fn read_bits(&mut self, n: u32) -> Result<u64> {
        if n == 0 {
            return Ok(0);
        }
        if n <= 56 {
            self.ensure_bits(n)?;
            let val = self.accum & ((1u64 << n) - 1);
            self.consume_unchecked(n);
            return Ok(val);
        }
        // Wide read: split into two
        self.ensure_bits(32)?;
        let low = self.accum & 0xFFFF_FFFF;
        self.consume_unchecked(32);
        let high_bits = n - 32;
        self.ensure_bits(high_bits)?;
        let high = self.accum & ((1u64 << high_bits) - 1);
        self.consume_unchecked(high_bits);
        Ok(low | (high << 32))
    }

    /// Read a variable-length 64-bit integer (IntFunctions::ReadBit encoding).
    pub fn read_i64(&mut self) -> Result<i64> {
        let want = 17.min(self.remaining());
        self.ensure_bits(want)?;

        let sentinel = self.accum | 0x1_0000;
        let nibbles = sentinel.trailing_zeros();

        if nibbles == 16 {
            return Err(Error::InvalidVarInt);
        }

        let prefix_len = nibbles + 1;
        let value_bits = (nibbles + 1) * 4;
        let total = prefix_len + value_bits;

        if total > 56 {
            return self.read_i64_wide(nibbles);
        }

        self.ensure_bits(total)?;
        self.consume_unchecked(prefix_len);

        let mask = if value_bits == 64 {
            u64::MAX
        } else {
            (1u64 << value_bits) - 1
        };
        let val = self.accum & mask;
        self.consume_unchecked(value_bits);

        Ok(val as i64)
    }

    fn read_i64_wide(&mut self, nibbles: u32) -> Result<i64> {
        let prefix_len = nibbles + 1;
        self.ensure_bits(prefix_len)?;
        self.consume_unchecked(prefix_len);

        let value_bits = (nibbles + 1) * 4;
        if value_bits <= 32 {
            return Ok(self.read_bits(value_bits)? as i64);
        }

        let low = self.read_bits(32)?;
        let high = self.read_bits(value_bits - 32)?;
        Ok((high << 32 | low) as i64)
    }

    /// Read a variable-length 32-bit integer (BitReader::ReadNumber encoding).
    /// Value is always ≥ 256.
    pub fn read_u32_number(&mut self) -> Result<u32> {
        let want = 32.min(self.remaining());
        self.ensure_bits(want)?;

        if self.accum & 0xFFFF_FFFF == 0 {
            return Err(Error::InvalidVarInt);
        }

        let nibbles = (self.accum as u32).trailing_zeros();
        if nibbles > 23 {
            return Err(Error::InvalidVarInt);
        }

        let prefix_len = nibbles + 1;
        let value_bits = nibbles + 8;

        self.ensure_bits(prefix_len + value_bits)?;
        self.consume_unchecked(prefix_len);

        let mask = (1u64 << value_bits) - 1;
        let raw = (self.accum & mask) as u32;
        self.consume_unchecked(value_bits);

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

        // Drain accumulator bits first
        let mut buf = Vec::with_capacity(size);
        let mut remaining = size;

        while remaining > 0 && self.bits >= 8 {
            buf.push((self.accum & 0xFF) as u8);
            self.consume_unchecked(8);
            remaining -= 1;
        }

        // Bulk copy from underlying data
        let available = self.data.len() - self.pos;
        let bulk = remaining.min(available);
        if bulk > 0 {
            buf.extend_from_slice(&self.data[self.pos..self.pos + bulk]);
            self.pos += bulk;
            self.bits_consumed += bulk as u64 * 8;
            remaining -= bulk;
        }

        if remaining > 0 {
            return Err(Error::BitstreamExhausted {
                needed: (remaining * 8) as u32,
                available: 0,
            });
        }

        Ok(buf)
    }

    /// Skip to the next byte boundary.
    #[inline]
    pub fn align_to_byte(&mut self) {
        let discard = self.bits % 8;
        if discard > 0 {
            self.consume_unchecked(discard);
        }
    }
}

/// LSB-first bitstream writer.
///
/// Accumulates bits in a u64, flushing 32-bit words to an output buffer.
#[derive(Debug, Default)]
pub struct BitWriter {
    buf: Vec<u8>,
    accum: u64,
    bits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        let mut w = BitWriter::default();
        w.write_bits(0, 3); // padding placeholder
        w
    }

    #[inline]
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

    pub fn write_u32_number(&mut self, val: u32) {
        debug_assert!(val >= 256);
        let bit_pos = 31 - val.leading_zeros();
        let nibbles = bit_pos.saturating_sub(8);
        let value_bits = nibbles + 8;
        self.write_bits(1u64 << nibbles, nibbles + 1);
        let mask = (1u64 << value_bits) - 1;
        self.write_bits((val as u64) & mask, value_bits);
    }

    pub fn write_buffer(&mut self, data: &[u8]) {
        self.write_i64(data.len() as i64);
        self.align_to_byte();
        self.flush();
        if self.bits == 0 {
            self.buf.extend_from_slice(data);
        } else {
            for &b in data {
                self.write_bits(b as u64, 8);
            }
        }
    }

    #[inline]
    pub fn align_to_byte(&mut self) {
        let pad = (8 - (self.bits % 8)) % 8;
        if pad > 0 {
            self.write_bits(0, pad);
        }
    }

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

    #[inline]
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
        let data = [0xAB];
        let r = BitReader::new(&data).unwrap();
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn read_i64_small_value() {
        let data = [0x18];
        let mut r = BitReader::new(&data).unwrap();
        assert_eq!(r.read_i64().unwrap(), 1);
    }

    #[test]
    fn smallest_fixture_header_fields() {
        let bitstream = [
            0x18, 0x03, 0x02, 0x00, 0x08, 0x3f, 0x23, 0x04, 0x01, 0x9a, 0x00,
        ];
        let mut r = BitReader::new(&bitstream).unwrap();
        assert_eq!(r.read_i64().unwrap(), 1);
        assert_eq!(r.read_i64().unwrap(), 1);
        assert_eq!(r.read_i64().unwrap(), 0x20000);
        assert_eq!(r.read_i64().unwrap(), 415);
        assert_eq!(r.read_i64().unwrap(), 0);
    }

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
            assert_eq!(r.read_i64().unwrap(), val, "round-trip failed for {val}");
        }
    }

    #[test]
    fn writer_roundtrip_buffer() {
        let payload = b"Hello, PA30!";
        let mut w = BitWriter::new();
        w.write_buffer(payload);
        let data = w.finish();
        let mut r = BitReader::new(&data).unwrap();
        assert_eq!(r.read_buffer().unwrap(), payload);
    }

    #[test]
    fn writer_roundtrip_header_fields() {
        let mut w = BitWriter::new();
        w.write_i64(1);
        w.write_i64(1);
        w.write_i64(0x20000);
        w.write_i64(415);
        w.write_i64(0);
        w.write_buffer(&[]);
        w.write_buffer(&[]);
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
            assert_eq!(r.read_u32_number().unwrap(), val, "u32_number round-trip failed for {val}");
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
