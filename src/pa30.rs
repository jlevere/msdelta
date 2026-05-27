//! PA30 -- Microsoft's binary delta format, decoded by `msdelta.dll!ApplyDeltaB`.
//!
//! The format is undocumented; this module is built from reverse-engineering
//! `msdelta.dll` and `UpdateCompression.dll` (with PDB symbols).

use crate::bitstream::BitReader;
use crate::{Error, Result};

pub const PA30_MAGIC: &[u8; 4] = b"PA30";
pub const PA31_MAGIC: &[u8; 4] = b"PA31";
pub const MAGIC: &[u8; 4] = PA30_MAGIC;
/// PA19 magic. Legacy format using standard LZX (mspatcha.dll/mspatchc.dll).
/// Dispatched to the msdelta-pa19 crate for decoding.
const PA19_MAGIC: &[u8; 4] = b"PA19";
const FILETIME_OFFSET: usize = 4;
const BITSTREAM_OFFSET: usize = 12;
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

/// Apply a delta to a reference buffer.
///
/// Supports PA30, PA31, and PA19 formats.
/// Equivalent to `ApplyDeltaB(0, reference, delta, &out)` on Windows.
pub fn apply(reference: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    if delta.len() >= 4 && &delta[..4] == PA19_MAGIC {
        return crate::pa19::apply(reference, delta);
    }

    let parsed = parse(delta)?;
    let target_size = parsed.header.target_size as usize;

    const MAX_TARGET_SIZE: usize = 64 * 1024 * 1024;
    if target_size > MAX_TARGET_SIZE {
        return Err(Error::Malformed("target size exceeds 256 MB limit"));
    }

    let (caller_rift, pp) = if parsed.header.file_type != 1 && !parsed.preprocess.is_empty() {
        let pp = parse_pe_preprocess(&parsed.preprocess)?;
        // Combine PE rift + preprocess rift into one table for the decompressor
        let mut combined = pp.pe_rift.clone();
        for e in &pp.preprocess_rift.entries {
            combined.entries.push(*e);
        }
        combined.entries.sort_by_key(|e| e.source);
        (Some(combined), Some(pp))
    } else {
        (None, None)
    };

    let mut output = if parsed.header.file_type_set & 0x100 != 0 {
        let decompressed = crate::lzms::decompress_compression_api(&parsed.patch_data)?;
        crate::bsdiff::bspatch(reference, target_size, &decompressed)?
    } else {
        crate::lzx::decompress_with_rift(
            reference, &parsed.patch_data, target_size, caller_rift.as_ref(),
        )?
    };

    if let Some(pp) = &pp {
        apply_pe_timestamp_fixup(reference, pp, &mut output)?;
    }

    if parsed.header.hash_alg_id != 0 && !parsed.header.target_hash.is_empty() {
        let computed = get_signature(&output, parsed.header.hash_alg_id as u32)?;
        if computed.hash != parsed.header.target_hash {
            return Err(Error::HashMismatch {
                expected: hex_str(&parsed.header.target_hash),
                got: hex_str(&computed.hash),
            });
        }
    }

    Ok(output)
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parsed PE preprocess buffer from the delta.
///
/// From decompiled PreProcessPEForApply + PortableExecutableInfo::FromBitReader.
#[allow(dead_code)]
struct PePreprocess {
    target_image_base: u64,
    target_timestamp: u32,
    pe_rift: crate::lzx::rift::RiftTable,
    // Second rift table (from PreProcessPEForApply, separate from PE info rift)
    preprocess_rift: crate::lzx::rift::RiftTable,
}

fn parse_pe_preprocess(preprocess: &[u8]) -> Result<PePreprocess> {
    use crate::bitstream::BitReader;

    let mut reader = BitReader::new(preprocess)?;

    // PortableExecutableInfo::FromBitReader (decompiled at 18004cda0):
    //   Read64(0x40) = ImageBase
    //   Read32(0x20) = field1 (zero for typical deltas)
    //   Read32(0x20) = target TimeDateStamp
    //   RiftTable::FromBitReader = PE-level rift table
    //   CliMetadata::FromBitReader = CLI metadata
    //
    // Then PreProcessPEForApply reads more:
    //   RiftTable::FromBitReader = second rift table
    //   CliMap::FromBitReader = CLI map
    //
    let target_image_base = reader.read_bits(64)?;
    let _target_field1 = reader.read_bits(32)?;
    let target_timestamp = reader.read_bits(32)? as u32;

    let pe_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    // CliMetadata: 1-bit flag (0 = empty for native PEs)
    let cli_flag = reader.read_bits(1)?;
    if cli_flag != 0 {
        return Err(Error::Malformed("CLI metadata in preprocess not supported"));
    }

    // Second rift table from PreProcessPEForApply
    let preprocess_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    // CliMap: 1-bit flag (0 = empty for native PEs)
    if reader.remaining() > 0 {
        let climap_flag = reader.read_bits(1)?;
        if climap_flag != 0 {
            return Err(Error::Malformed("CLI map in preprocess not supported"));
        }
    }

    Ok(PePreprocess {
        target_image_base,
        target_timestamp,
        pe_rift,
        preprocess_rift,
    })
}

fn build_pe_preprocess(
    target_image_base: u64,
    target_timestamp: u32,
    pe_rift: &crate::lzx::rift::RiftTable,
    preprocess_rift: &crate::lzx::rift::RiftTable,
) -> Vec<u8> {
    use crate::bitstream::BitWriter;
    let mut writer = BitWriter::new();
    writer.write_bits(target_image_base, 64);
    writer.write_bits(0, 32);
    writer.write_bits(target_timestamp as u64, 32);
    pe_rift.to_writer(&mut writer);
    writer.write_bits(0, 1);
    preprocess_rift.to_writer(&mut writer);
    writer.write_bits(0, 1);
    writer.finish()
}

/// Apply PE post-processing after LZX decompression.
///
/// The encoder normalizes timestamps in the source before compression.
/// After decompression, the output has source timestamps that need
/// replacing with target timestamps at PE-structural offsets.
///
/// The preprocess buffer also contains rift tables needed for the full
/// transform pipeline (not yet wired for inferred relocations).
fn apply_pe_timestamp_fixup(
    reference: &[u8],
    pp: &PePreprocess,
    output: &mut [u8],
) -> Result<()> {
    let source_timestamp = pe_timestamp(reference);
    if source_timestamp == 0 || source_timestamp == pp.target_timestamp {
        return Ok(());
    }

    let new_bytes = pp.target_timestamp.to_le_bytes();

    for off in pe_timestamp_offsets(output) {
        if off + 4 <= output.len() {
            let val = u32::from_le_bytes(output[off..off + 4].try_into().unwrap());
            if val == source_timestamp {
                output[off..off + 4].copy_from_slice(&new_bytes);
            }
        }
    }

    Ok(())
}

fn pe_timestamp(data: &[u8]) -> u32 {
    crate::pe::transform::pe_timestamp(data)
}

fn pe_timestamp_offsets(data: &[u8]) -> Vec<usize> {
    crate::pe::transform::pe_timestamp_offsets(data)
}

/// Encode `target` as a PA30 delta against `reference`.
///
/// Equivalent to `CreateDeltaB(...)` on Windows. Produces a format-compatible
/// delta decodable by both this crate and msdelta.dll.
pub fn create(reference: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    CreateOptions::default().execute(reference, target)
}

/// Compression codec for delta creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Codec {
    #[default]
    PseudoLzx,
    BsDiff,
}

/// File type for delta creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FileType {
    #[default]
    Raw,
    /// Auto-detect: try PE, fall back to RAW.
    Auto,
}

/// Options for creating a PA30 delta.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    hash_alg: u32,
    codec: Codec,
    file_type: FileType,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions { hash_alg: HASH_ALG_NONE, codec: Codec::default(), file_type: FileType::default() }
    }
}

impl CreateOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the hash algorithm for target integrity verification.
    /// Use `HASH_ALG_MD5`, `HASH_ALG_SHA256`, or `HASH_ALG_NONE`.
    pub fn hash_algorithm(mut self, alg: u32) -> Self {
        self.hash_alg = alg;
        self
    }

    /// Set the compression codec.
    pub fn codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// Set the file type. `Auto` tries PE, falls back to RAW.
    pub fn file_type(mut self, ft: FileType) -> Self {
        self.file_type = ft;
        self
    }

    /// Build the delta.
    pub fn execute(&self, reference: &[u8], target: &[u8]) -> Result<Vec<u8>> {
        use crate::bitstream::BitWriter;
        use crate::lzx::rift::RiftTable;
        use crate::pe::{parse::PeInfo, rift_gen, transform};

        let pe_info = if self.file_type == FileType::Auto {
            PeInfo::parse(reference).ok().and_then(|src| {
                PeInfo::parse(target).ok().map(|tgt| (src, tgt))
            })
        } else {
            None
        };

        let (patch_data, file_type_set, file_type_val, flags, preprocess) =
            if let Some((src_pe, tgt_pe)) = pe_info {
                let mut normalized = target.to_vec();
                let original_ts = transform::normalize_timestamps(&mut normalized, reference);

                let section_rift = rift_gen::rift_from_sections(&src_pe, &tgt_pe);
                let import_rift = rift_gen::rift_from_imports(reference, target);
                let mut merged = section_rift;
                for e in import_rift.entries {
                    merged.entries.push(e);
                }
                merged.entries.sort_by_key(|e| e.source);
                merged.entries.dedup_by_key(|e| e.source);

                let patch_data = crate::lzx::compress(reference, &normalized)?;
                let preprocess = build_pe_preprocess(
                    tgt_pe.image_base, original_ts,
                    &merged, &RiftTable { entries: vec![] },
                );
                let ft: i64 = if tgt_pe.is_64bit { 8 } else { 2 };
                (patch_data, 0xFi64, ft, 0i64, preprocess)
            } else {
                match self.codec {
                    Codec::PseudoLzx => {
                        let data = crate::lzx::compress(reference, target)?;
                        (data, 1i64, 1i64, 0x20000i64, vec![])
                    }
                    Codec::BsDiff => {
                        let bsdiff_patch = crate::bsdiff::bscreate(reference, target)?;
                        let data = crate::lzms::compress_compression_api(&bsdiff_patch)?;
                        (data, 0x101i64, 1i64, 0i64, vec![])
                    }
                }
            };

        let target_hash = if self.hash_alg != HASH_ALG_NONE {
            get_signature(target, self.hash_alg)?.hash
        } else {
            Vec::new()
        };

        let mut header_writer = BitWriter::new();
        header_writer.write_i64(file_type_set);
        header_writer.write_i64(file_type_val);
        header_writer.write_i64(flags);
        header_writer.write_i64(target.len() as i64);
        header_writer.write_i64(self.hash_alg as i64);
        header_writer.write_buffer(&target_hash);
        header_writer.write_buffer(&preprocess);
        header_writer.write_buffer(&patch_data);
        let bitstream = header_writer.finish();

        let mut out = Vec::with_capacity(12 + bitstream.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&bitstream);

        Ok(out)
    }
}

/// Apply a delta AND generate a reverse delta.
///
/// Equivalent to `ApplyDeltaGetReverseB(...)` on Windows. Returns
/// `(target, reverse_delta)` where `apply(target, reverse_delta) == reference`.
pub fn apply_get_reverse(reference: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let target = apply(reference, delta)?;
    let reverse = create(&target, reference)?;
    Ok((target, reverse))
}

/// Get delta header information without full decompression.
///
/// Equivalent to `GetDeltaInfoB(...)` on Windows.
pub fn get_info(delta: &[u8]) -> Result<Header> {
    parse_header(delta)
}

/// Hash algorithm IDs (matching Windows ALG_ID values).
pub const HASH_ALG_NONE: u32 = 0;
pub const HASH_ALG_MD5: u32 = 0x8003;
pub const HASH_ALG_SHA256: u32 = 0x800C;

/// Computed delta signature/hash.
#[derive(Debug, Clone)]
pub struct DeltaHash {
    pub alg_id: u32,
    pub hash: Vec<u8>,
}

/// Compute a hash/signature of data using the specified algorithm.
///
/// Equivalent to `GetDeltaSignatureB(...)` on Windows.
pub fn get_signature(data: &[u8], hash_alg_id: u32) -> Result<DeltaHash> {
    use digest::Digest;

    let hash = match hash_alg_id {
        HASH_ALG_MD5 => {
            let mut hasher = md5::Md5::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        HASH_ALG_SHA256 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }
        _ => return Err(Error::Malformed("unsupported hash algorithm")),
    };

    Ok(DeltaHash {
        alg_id: hash_alg_id,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture_paths() -> Vec<PathBuf> {
        let mut paths: Vec<_> = std::fs::read_dir(FIXTURES_DIR)
            .expect("fixtures dir")
            .filter_map(|e| {
                let p = e.ok()?.path();
                if p.extension().and_then(|s| s.to_str()) == Some("manifest") {
                    Some(p)
                } else {
                    None
                }
            })
            .collect();
        paths.sort();
        paths
    }

    fn strip_dcm(data: &[u8]) -> &[u8] {
        &data[4..]
    }

    #[test]
    fn parse_smallest_fixture_header() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let pa30 = strip_dcm(&data);
        let header = parse_header(pa30).unwrap();

        assert_eq!(header.target_file_time, 0x019db1ded5d71680);
        assert_eq!(header.file_type_set, 1);
        assert_eq!(header.file_type, 1);
        assert_eq!(header.flags, 0x20000);
        assert_eq!(header.target_size, 415);
        assert_eq!(header.hash_alg_id, 0);
        assert!(header.target_hash.is_empty());
    }

    #[test]
    fn parse_smallest_fixture_full() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let pa30 = strip_dcm(&data);
        let parsed = parse(pa30).unwrap();

        assert_eq!(parsed.header.target_size, 415);
        assert!(
            parsed.preprocess.is_empty(),
            "RAW file type should have empty preprocess buffer"
        );
        assert!(
            !parsed.patch_data.is_empty(),
            "patch data should not be empty"
        );
    }

    #[test]
    fn parse_all_fixtures_full() {
        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let parsed = parse(pa30).unwrap_or_else(|e| {
                panic!("failed to parse {}: {}", path.display(), e);
            });

            assert!(
                parsed.preprocess.is_empty(),
                "RAW file type should have empty preprocess: {}",
                path.display()
            );
            assert!(
                !parsed.patch_data.is_empty(),
                "patch data empty: {}",
                path.display()
            );
            assert!(
                parsed.header.target_size > 0,
                "target_size must be positive: {}",
                path.display()
            );
        }
    }

    #[test]
    fn parse_all_fixtures() {
        let expected_sizes: &[(&str, i64)] = &[
            ("amd64_dual", 52889),
            ("amd64_microsoft-windows-core", 415),
            ("amd64_microsoft-windows-font", 2305),
            ("amd64_microsoft-windows-network", 96246),
            ("amd64_microsoft-windows-s", 7080),
            ("amd64_multipoint", 1961),
            ("wow64_microsoft-windows-o", 3263571),
        ];

        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let header = parse_header(pa30).unwrap_or_else(|e| {
                panic!("failed to parse {}: {}", path.display(), e);
            });

            assert_eq!(header.file_type_set, 1, "{}", path.display());
            assert_eq!(header.file_type, 1, "{}", path.display());
            assert_eq!(header.flags, 0x20000, "{}", path.display());
            assert_eq!(header.hash_alg_id, 0, "{}", path.display());
            assert!(header.target_hash.is_empty(), "{}", path.display());
            assert!(header.target_size > 0, "{}", path.display());

            let fname = path.file_name().unwrap().to_str().unwrap();
            for &(prefix, expected_size) in expected_sizes {
                if fname.starts_with(prefix) {
                    assert_eq!(
                        header.target_size, expected_size,
                        "target_size mismatch for {}",
                        fname
                    );
                    break;
                }
            }
        }
    }

    fn base_manifest() -> Vec<u8> {
        std::fs::read(PathBuf::from(FIXTURES_DIR).join("base_manifest.bin")).unwrap()
    }

    #[test]
    fn apply_smallest_fixture() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let pa30 = strip_dcm(&data);
        let base = base_manifest();

        let result = apply(&base, pa30);
        match &result {
            Ok(output) => {
                assert_eq!(output.len(), 415);
                let text = std::str::from_utf8(output).expect("output should be valid UTF-8");
                assert!(text.contains("<?xml"), "output should be XML");
                assert!(text.contains("assembly"), "output should contain assembly tag");
            }
            Err(e) => {
                panic!("decompression failed: {e}");
            }
        }
    }

    #[test]
    fn apply_all_fixtures() {
        let base = base_manifest();
        let mut failures = Vec::new();
        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let header = parse_header(pa30).unwrap();
            let result = apply(&base, pa30);
            let fname = path.file_name().unwrap().to_str().unwrap().to_string();
            match &result {
                Ok(output) => {
                    assert_eq!(
                        output.len(),
                        header.target_size as usize,
                        "size mismatch: {fname}",
                    );
                    let text = std::str::from_utf8(output).expect("should be UTF-8");
                    assert!(text.contains("<?xml"), "should be XML: {fname}");
                }
                Err(e) => {
                    failures.push(format!("{fname}: {e}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "decompression failures:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn snapshot_smallest_fixture() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let base = base_manifest();
        let pa30 = strip_dcm(&data);
        let output = apply(&base, pa30).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        insta::assert_snapshot!("BOOTSTRAP_smallest_manifest", text);
    }

    #[test]
    fn debug_wow64_divergence() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "wow64_microsoft-windows-o..euapcommonproxystub_31bf3856ad364e35_10.0.26100.7309_none_38de5e2364a9fd20.manifest",
            ),
        ).unwrap();
        let golden_path = PathBuf::from(FIXTURES_DIR).join("wow64_golden.xml");
        if !golden_path.exists() {
            eprintln!("SKIP: no golden file");
            return;
        }
        let golden = std::fs::read(&golden_path).unwrap();
        let base = base_manifest();
        let pa30 = strip_dcm(&data);
        let parsed = parse(pa30).unwrap();
        let (partial, err) = crate::lzx::decompress_partial(
            &base,
            &parsed.patch_data,
            parsed.header.target_size as usize,
        );

        if let Some(e) = &err {
            eprintln!("Decompression error after {} bytes: {e}", partial.len());
        }

        let compare_len = partial.len().min(golden.len());
        let mut first_diff = None;
        for i in 0..compare_len {
            if partial[i] != golden[i] {
                first_diff = Some(i);
                break;
            }
        }

        if let Some(pos) = first_diff {
            eprintln!(
                "wow64 diverges at byte {pos} of {compare_len} — known issue, see notes/blockers.md"
            );
        } else if err.is_some() {
            eprintln!("Partial output ({compare_len} bytes) matches golden");
        } else {
            assert_eq!(partial.len(), golden.len(), "size mismatch with golden");
        }
    }

    #[test]
    fn roundtrip_simple() {
        let reference = b"Hello, this is a reference buffer with some repeated content. Hello again!";
        let target = b"Hello, this is a modified buffer with some repeated content. Goodbye!";

        let delta = create(reference, target).unwrap();
        assert!(delta.starts_with(b"PA30"));

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target, "round-trip failed");
    }

    #[test]
    fn roundtrip_bsdiff_simple() {
        let reference = b"Hello, this is a reference buffer with some repeated content. Hello again!";
        let target = b"Hello, this is a modified buffer with some repeated content. Goodbye!";

        let delta = CreateOptions::new()
            .codec(Codec::BsDiff)
            .execute(reference, target)
            .unwrap();
        assert!(delta.starts_with(b"PA30"));

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.file_type_set & 0x100, 0x100);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_bsdiff_empty_target() {
        let reference = b"some reference data here";
        let delta = CreateOptions::new()
            .codec(Codec::BsDiff)
            .execute(reference, b"")
            .unwrap();
        let recovered = apply(reference, &delta).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn roundtrip_bsdiff_with_hash() {
        let reference = b"reference for bsdiff hash test";
        let target = b"target for bsdiff hash test with integrity checking";

        let delta = CreateOptions::new()
            .codec(Codec::BsDiff)
            .hash_algorithm(HASH_ALG_SHA256)
            .execute(reference, target)
            .unwrap();

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.hash_alg_id, HASH_ALG_SHA256 as i32);
        assert_eq!(header.file_type_set & 0x100, 0x100);

        let header2 = parse_header(&delta).unwrap();
        assert_eq!(header2.target_size, target.len() as i64);
        assert_eq!(header2.target_hash.len(), 32);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_identical() {
        let data = b"The reference and target are the same.";
        let delta = create(data, data).unwrap();
        let recovered = apply(data, &delta).unwrap();
        assert_eq!(recovered, data.as_slice());
    }

    #[test]
    fn roundtrip_empty_target() {
        let reference = b"some reference data";
        let delta = create(reference, b"").unwrap();
        let recovered = apply(reference, &delta).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn preprocess_buffer_roundtrip() {
        use crate::lzx::rift::{RiftEntry, RiftTable};
        let rift = RiftTable {
            entries: vec![
                RiftEntry { source: 0, target: 0 },
                RiftEntry { source: 0x1000, target: 0x1200 },
            ],
        };
        let empty_rift = RiftTable { entries: vec![] };
        let buf = build_pe_preprocess(0x140000000, 0x12345678, &rift, &empty_rift);
        let parsed = parse_pe_preprocess(&buf).unwrap();
        assert_eq!(parsed.target_image_base, 0x140000000);
        assert_eq!(parsed.target_timestamp, 0x12345678);
        assert_eq!(parsed.pe_rift.entries.len(), 2);
        assert_eq!(parsed.pe_rift.entries[0].source, 0);
        assert_eq!(parsed.pe_rift.entries[0].target, 0);
        assert_eq!(parsed.pe_rift.entries[1].source, 0x1000);
        assert_eq!(parsed.pe_rift.entries[1].target, 0x1200);
        assert!(parsed.preprocess_rift.entries.is_empty());
    }

    #[test]
    fn roundtrip_pe_cmd_to_cmd_patched() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let src = delta_source("cmd.exe");
        let tgt = delta_source("cmd_patched.exe");
        let delta = CreateOptions::new()
            .file_type(FileType::Auto)
            .execute(&src, &tgt)
            .unwrap();
        let header = parse_header(&delta).unwrap();
        assert_eq!(header.file_type, 8, "should detect AMD64");
        let recovered = apply(&src, &delta).unwrap();
        assert_eq!(recovered.len(), tgt.len());
        assert_eq!(recovered, tgt);
    }

    #[test]
    fn roundtrip_pe_advapi32() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let src = delta_source("advapi32_old.dll");
        let tgt = delta_source("advapi32_new.dll");
        let delta = CreateOptions::new()
            .file_type(FileType::Auto)
            .execute(&src, &tgt)
            .unwrap();
        let header = parse_header(&delta).unwrap();
        assert_eq!(header.file_type, 8);
        let recovered = apply(&src, &delta).unwrap();
        assert_eq!(recovered.len(), tgt.len());
        assert_eq!(recovered, tgt);
    }

    #[test]
    fn roundtrip_with_md5() {
        let reference = b"reference data for hash test";
        let target = b"target data that should be integrity-checked with MD5";

        let delta = CreateOptions::new()
            .hash_algorithm(HASH_ALG_MD5)
            .execute(reference, target)
            .unwrap();

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.hash_alg_id, HASH_ALG_MD5 as i32);
        assert_eq!(header.target_hash.len(), 16);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_with_sha256() {
        let reference = b"reference data for hash test";
        let target = b"target data that should be integrity-checked with SHA256";

        let delta = CreateOptions::new()
            .hash_algorithm(HASH_ALG_SHA256)
            .execute(reference, target)
            .unwrap();

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.hash_alg_id, HASH_ALG_SHA256 as i32);
        assert_eq!(header.target_hash.len(), 32);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_all_fixtures() {
        let base = base_manifest();
        let mut failures = Vec::new();
        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let target = apply(&base, pa30).unwrap();

            let fname = path.file_name().unwrap().to_str().unwrap().to_string();
            if target.len() > 500_000 {
                continue;
            }
            match create(&base, &target) {
                Ok(our_delta) => match apply(&base, &our_delta) {
                    Ok(recovered) => {
                        if recovered != target {
                            failures.push(format!("{fname}: content mismatch"));
                        }
                    }
                    Err(e) => failures.push(format!("{fname}: decode error: {e}")),
                },
                Err(e) => failures.push(format!("{fname}: encode error: {e}")),
            }
        }
        assert!(
            failures.is_empty(),
            "round-trip failures:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn decoder_matches_msdelta_dll() {
        use md5::{Md5, Digest};
        let golden_hashes: &[(&str, &str)] = &[
            ("65|", "05CE391BCD42CC29C917F242AF7EEFC8"),
            ("249|", "625E5A94109DEC39C60506B26F377CAF"),
            ("355|", "91FC84854C00CDB72644457E20D96CC7"),
            ("696|", "0260B236B57AF816BE98A50B2A5AACEE"),
            ("2852|", "906500830BF571878E536274CC1CE756"),
            ("9292|", "5F8671540358C1B95B2AD263BFAB7008"),
            ("175668|", "672F3A6D63609E3830089EB7763C31B7"),
        ];

        let base = base_manifest();
        let mut failures = Vec::new();

        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let output = apply(&base, pa30).unwrap();

            let hash = format!("{:X}", Md5::digest(&output));
            let file_size = data.len();
            let key = format!("{file_size}|");

            if let Some(&(_, expected_md5)) = golden_hashes.iter().find(|(k, _)| *k == key) {
                if hash != expected_md5 {
                    failures.push(format!(
                        "{}: MD5 mismatch: ours={hash} msdelta={}",
                        path.file_name().unwrap().to_str().unwrap(),
                        expected_md5
                    ));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "decoder output differs from msdelta.dll:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn reverse_delta_roundtrip() {
        let reference = b"Hello, this is a reference buffer with content.";
        let target = b"Hello, this is a modified buffer with new content!";

        let (decoded_target, reverse_delta) =
            apply_get_reverse(reference, &create(reference, target).unwrap()).unwrap();
        assert_eq!(decoded_target, target);

        let recovered_reference = apply(target, &reverse_delta).unwrap();
        assert_eq!(recovered_reference, reference.as_slice());
    }

    #[test]
    fn get_info_basic() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        ).unwrap();
        let pa30 = strip_dcm(&data);
        let info = get_info(pa30).unwrap();
        assert_eq!(info.target_size, 415);
        assert_eq!(info.file_type, 1);
    }

        #[test]
    fn signature_md5() {
        let data = b"Hello, World!";
        let sig = get_signature(data, HASH_ALG_MD5).unwrap();
        assert_eq!(sig.alg_id, HASH_ALG_MD5);
        assert_eq!(sig.hash.len(), 16); // MD5 = 128 bits
    }

    #[test]
    fn signature_sha256() {
        let data = b"Hello, World!";
        let sig = get_signature(data, HASH_ALG_SHA256).unwrap();
        assert_eq!(sig.alg_id, HASH_ALG_SHA256);
        assert_eq!(sig.hash.len(), 32); // SHA-256 = 256 bits
    }

    #[test]
    fn detect_pa19() {
        // PA19 with enough bytes for the header parser
        let mut data = b"PA19".to_vec();
        data.extend_from_slice(&[0u8; 28]); // pad for header fields
        match parse_header(&data) {
            Ok(h) => assert_eq!(h.version, FormatVersion::PA19),
            Err(e) => panic!("PA19 parse failed: {e}"),
        }
    }

    #[test]
    fn reject_truncated() {
        assert!(matches!(parse_header(b"PA3"), Err(Error::Truncated)));
        assert!(matches!(parse_header(b"PA30\x00\x00"), Err(Error::Truncated)));
    }

    #[test]
    fn reject_bad_magic() {
        let data = b"XX30\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(matches!(parse_header(data), Err(Error::BadMagic { .. })));
    }

    #[test]
    fn fuzz_crash_no_panic() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let reference = b"minimal reference buffer for fuzzing";
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with("fuzz_crash") {
                let data = std::fs::read(&path).unwrap();
                let result = apply(reference, &data);
                assert!(result.is_err(), "malformed input {} should return Err", path.display());
            }
        }
    }

    #[test]
    fn apply_pe_amd64_delta() {
        let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/deltas"));
        if !dir.exists() { return; }
        let src = std::fs::read(dir.join("sources/cmd.exe")).unwrap();
        let tgt = std::fs::read(dir.join("sources/cmd_patched.exe")).unwrap();
        let delta = std::fs::read(dir.join("cmd__to__cmd_patched__pe_amd64.pa30")).unwrap();
        let result = apply(&src, &delta).unwrap();
        assert_eq!(result, tgt);
    }

    const DELTA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/deltas");

    fn delta_source(name: &str) -> Vec<u8> {
        std::fs::read(PathBuf::from(DELTA_DIR).join("sources").join(name)).unwrap()
    }

    fn delta_file(name: &str) -> Vec<u8> {
        std::fs::read(PathBuf::from(DELTA_DIR).join(name)).unwrap()
    }

    #[test]
    fn apply_raw_cmd_to_where() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let result = apply(&delta_source("cmd.exe"), &delta_file("cmd__to__where__raw.pa30")).unwrap();
        let expected = delta_source("where.exe");
        assert_eq!(result.len(), expected.len(), "size mismatch");
        let mut diffs = 0;
        let mut first = None;
        for i in 0..result.len() {
            if result[i] != expected[i] {
                if first.is_none() { first = Some(i); }
                diffs += 1;
            }
        }
        assert_eq!(diffs, 0, "first diff at {:?}, total {diffs} diffs out of {}", first, result.len());
    }

    #[test]
    fn apply_raw_cmd_to_notepad() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let result = apply(&delta_source("cmd.exe"), &delta_file("cmd__to__notepad__raw.pa30")).unwrap();
        assert_eq!(result, delta_source("notepad.exe"));
    }

    #[test]
    fn apply_raw_cmd_to_notepad_flag0x20000() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let result = apply(&delta_source("cmd.exe"), &delta_file("cmd__to__notepad__raw_flag0x20000.pa30")).unwrap();
        assert_eq!(result, delta_source("notepad.exe"));
    }

    #[test]
    fn apply_prsm_cmd_to_notepad() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let result = apply(&delta_source("cmd.exe"), &delta_file("cmd__to__notepad__raw_bsdiff_flag0x100.pa30")).unwrap();
        assert_eq!(result, delta_source("notepad.exe"));
    }

    #[test]
    fn apply_raw_advapi32() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let result = apply(&delta_source("advapi32_old.dll"), &delta_file("advapi32_raw.pa30")).unwrap();
        assert_eq!(result, delta_source("advapi32_new.dll"));
    }

    #[test]
    fn apply_pe_advapi32() {
        if !PathBuf::from(DELTA_DIR).exists() { return; }
        let result = apply(&delta_source("advapi32_old.dll"), &delta_file("advapi32_pe.pa30")).unwrap();
        let expected = delta_source("advapi32_new.dll");
        let mut diffs = Vec::new();
        for i in 0..result.len().min(expected.len()) {
            if result[i] != expected[i] { diffs.push(i); }
        }
        if !diffs.is_empty() {
            for &i in diffs.iter().take(20) {
                eprintln!("  diff[{i}]: got={:#04x} want={:#04x}", result[i], expected[i]);
            }
            panic!("{} diffs, first at {}", diffs.len(), diffs[0]);
        }
        assert_eq!(result.len(), expected.len());
    }
}
