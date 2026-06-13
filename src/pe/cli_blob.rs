//! CLI signature blob helpers used by managed metadata transforms.

use crate::{Error, Result};

pub(crate) fn read_compressed_u32(input: &[u8]) -> Result<(u32, usize)> {
    let Some(&first) = input.first() else {
        return Err(Error::Truncated);
    };

    if first & 0x80 == 0 {
        return Ok((first as u32, 1));
    }

    if first & 0xc0 == 0x80 {
        let bytes = input.get(..2).ok_or(Error::Truncated)?;
        let value = (((bytes[0] & 0x3f) as u32) << 8) | bytes[1] as u32;
        return Ok((value, 2));
    }

    if first & 0xe0 == 0xc0 {
        let bytes = input.get(..4).ok_or(Error::Truncated)?;
        let value = (((bytes[0] & 0x1f) as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | bytes[3] as u32;
        return Ok((value, 4));
    }

    Err(Error::Malformed(
        "reserved CLI compressed unsigned integer prefix",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_one_byte_compressed_integer_boundaries() {
        assert_eq!(read_compressed_u32(&[0x00]).unwrap(), (0, 1));
        assert_eq!(read_compressed_u32(&[0x7f]).unwrap(), (0x7f, 1));
        assert_eq!(read_compressed_u32(&[0x2a, 0xff]).unwrap(), (0x2a, 1));
    }

    #[test]
    fn reads_two_byte_compressed_integer_boundaries() {
        assert_eq!(read_compressed_u32(&[0x80, 0x80]).unwrap(), (0x80, 2));
        assert_eq!(read_compressed_u32(&[0xbf, 0xff]).unwrap(), (0x3fff, 2));
    }

    #[test]
    fn reads_four_byte_compressed_integer_boundaries() {
        assert_eq!(
            read_compressed_u32(&[0xc0, 0x00, 0x40, 0x00]).unwrap(),
            (0x4000, 4)
        );
        assert_eq!(
            read_compressed_u32(&[0xdf, 0xff, 0xff, 0xff]).unwrap(),
            (0x1fff_ffff, 4)
        );
    }

    #[test]
    fn rejects_truncated_and_reserved_encodings() {
        assert!(matches!(read_compressed_u32(&[]), Err(Error::Truncated)));
        assert!(matches!(
            read_compressed_u32(&[0x80]),
            Err(Error::Truncated)
        ));
        assert!(matches!(
            read_compressed_u32(&[0xc0, 0x00, 0x00]),
            Err(Error::Truncated)
        ));
        assert!(matches!(
            read_compressed_u32(&[0xe0, 0x00, 0x00, 0x00]),
            Err(Error::Malformed(_))
        ));
        assert!(matches!(
            read_compressed_u32(&[0xff, 0xff, 0xff, 0xff]),
            Err(Error::Malformed(_))
        ));
    }
}
