//! PA30/PA31 header types and parsing.

use crate::bitstream::BitReader;
use crate::{Error, Result};

pub(super) const PA30_MAGIC: &[u8; 4] = b"PA30";
pub(super) const PA31_MAGIC: &[u8; 4] = b"PA31";
pub const MAGIC: &[u8; 4] = PA30_MAGIC;
/// PA19 magic. Legacy format using standard LZX (mspatcha.dll/mspatchc.dll).
/// Dispatched to the msdelta-pa19 crate for decoding.
pub(super) const PA19_MAGIC: &[u8; 4] = b"PA19";
pub(super) const FILETIME_OFFSET: usize = 4;
pub(super) const BITSTREAM_OFFSET: usize = 12;
const MAX_HASH_LEN: usize = 33;

/// Delta format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatVersion {
    PA19,
    PA30,
    PA31,
}

/// PA30/PA31 delta header, corresponding to `_DELTA_HEADER_INFO_EX` in msdelta.
#[derive(Debug, Clone)]
pub struct Header {
    /// Which format version this delta uses.
    pub version: FormatVersion,
    /// FILETIME embedded in the delta (100ns intervals since 1601-01-01).
    pub target_file_time: u64,
    /// Set of file types the creator was willing to try.
    pub file_type_set: i64,
    /// Actual file type selected during creation.
    pub file_type: i64,
    /// Flags controlling preprocessing transforms.
    pub flags: i64,
    /// Size of the decompressed target in bytes.
    pub target_size: i64,
    /// Hash algorithm ID (0 = none, 0x8003 = MD5).
    pub hash_alg_id: i32,
    /// Hash of the target output (empty if hash_alg_id is 0).
    pub target_hash: Vec<u8>,
    /// PA31 extension fields (None for PA30).
    pub pa31_extra: Option<Pa31Extra>,
}

/// Extra fields present in PA31 but not PA30.
#[derive(Debug, Clone)]
pub struct Pa31Extra {
    pub field1: i32,
    pub field2: i32,
    pub field3: i32,
    pub extra_hash: Vec<u8>,
}

/// Parsed PA30 delta: header + preprocess data + compressed patch data.
#[derive(Debug)]
pub struct ParsedDelta {
    pub header: Header,
    /// File-type-specific preprocessing data (empty for RAW file type).
    pub preprocess: Vec<u8>,
    /// The compressed PseudoLzx patch data.
    pub patch_data: Vec<u8>,
}

/// Parse a PA30 delta header from raw delta bytes.
///
/// Returns the header and a `Delta` that holds a reference to the raw data
/// for subsequent decompression.
pub fn parse_header(delta: &[u8]) -> Result<Header> {
    if delta.len() < BITSTREAM_OFFSET {
        return Err(Error::Truncated);
    }

    let magic = &delta[..4];
    if magic == PA19_MAGIC {
        let pa19_hdr = crate::pa19::header::decode(delta)?;
        return Ok(Header {
            version: FormatVersion::PA19,
            target_file_time: 0,
            file_type_set: 1,
            file_type: 1,
            flags: pa19_hdr.flags as i64,
            target_size: pa19_hdr.new_file_size as i64,
            hash_alg_id: 0,
            target_hash: Vec::new(),
            pa31_extra: None,
        });
    }

    let version = if magic == PA30_MAGIC {
        FormatVersion::PA30
    } else if magic == PA31_MAGIC {
        FormatVersion::PA31
    } else {
        return Err(Error::BadMagic {
            expected: PA30_MAGIC,
            got: magic.to_vec(),
        });
    };

    let target_file_time = u64::from_le_bytes(
        delta[FILETIME_OFFSET..FILETIME_OFFSET + 8]
            .try_into()
            .expect("slice is exactly 8 bytes"),
    );

    let bitstream_data = &delta[BITSTREAM_OFFSET..];
    let mut outer_reader = BitReader::new(bitstream_data)?;

    // For PA31, the PA30 fields are in a sub-buffer. For PA30, they're inline.
    let sub_buf = if version == FormatVersion::PA31 {
        Some(outer_reader.read_buffer()?)
    } else {
        None
    };
    let mut sub_reader;
    let reader: &mut BitReader = if let Some(ref buf) = sub_buf {
        sub_reader = BitReader::new(buf)?;
        &mut sub_reader
    } else {
        &mut outer_reader
    };

    let file_type_set = reader.read_i64()?;
    let file_type = reader.read_i64()?;
    let flags = reader.read_i64()?;
    let target_size = reader.read_i64()?;
    let hash_alg_id = reader.read_i64()? as i32;
    let target_hash = reader.read_buffer()?;

    if target_hash.len() > MAX_HASH_LEN {
        return Err(Error::HashTooLarge {
            size: target_hash.len(),
            max: MAX_HASH_LEN,
        });
    }

    if target_size < 0 {
        return Err(Error::Malformed("negative target size"));
    }

    let pa31_extra = if version == FormatVersion::PA31 {
        let f1 = reader.read_i64()? as i32;
        let f2 = reader.read_i64()? as i32;
        let f3 = reader.read_i64()? as i32;
        let extra_hash = reader.read_buffer()?;
        if extra_hash.len() > MAX_HASH_LEN {
            return Err(Error::HashTooLarge {
                size: extra_hash.len(),
                max: MAX_HASH_LEN,
            });
        }
        Some(Pa31Extra {
            field1: f1,
            field2: f2,
            field3: f3,
            extra_hash,
        })
    } else {
        None
    };

    Ok(Header {
        version,
        target_file_time,
        file_type_set,
        file_type,
        flags,
        target_size,
        hash_alg_id,
        target_hash,
        pa31_extra,
    })
}

/// Parse a complete PA30/PA31 delta: header, preprocess buffer, and patch data.
pub fn parse(delta: &[u8]) -> Result<ParsedDelta> {
    if delta.len() < BITSTREAM_OFFSET {
        return Err(Error::Truncated);
    }

    let magic = &delta[..4];
    if magic == PA19_MAGIC {
        return Err(Error::Malformed("PA19 does not use ParsedDelta format"));
    }

    let version = if magic == PA30_MAGIC {
        FormatVersion::PA30
    } else if magic == PA31_MAGIC {
        FormatVersion::PA31
    } else {
        return Err(Error::BadMagic {
            expected: PA30_MAGIC,
            got: magic.to_vec(),
        });
    };

    let bitstream_data = &delta[BITSTREAM_OFFSET..];
    let mut outer_reader = BitReader::new(bitstream_data)?;

    // For PA31, the header fields are inside a sub-buffer. Read it and
    // parse the header from inside. The preprocess/patch buffers come
    // from the outer reader AFTER the sub-buffer.
    if version == FormatVersion::PA31 {
        let _sub_buf = outer_reader.read_buffer()?;
        // Header fields are inside sub_buf — already parsed by parse_header.
        // Outer reader is now positioned after the sub-buffer.
    } else {
        // For PA30, header fields are inline in the outer stream.
        // Skip past them to reach preprocess and patch data.
        outer_reader.read_i64()?; // FileTypeSet
        outer_reader.read_i64()?; // FileType
        outer_reader.read_i64()?; // Flags
        outer_reader.read_i64()?; // TargetSize
        outer_reader.read_i64()?; // HashAlgId
        outer_reader.read_buffer()?; // TargetHash
    }

    let header = parse_header(delta)?;
    let preprocess = outer_reader.read_buffer()?;
    let patch_data = outer_reader.read_buffer()?;

    Ok(ParsedDelta {
        header,
        preprocess,
        patch_data,
    })
}
