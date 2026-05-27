//! PA30 delta encoder.

use crate::Result;

use super::header::{FormatVersion, PA30_MAGIC, PA31_MAGIC};
use super::preprocess::build_pe_preprocess;
use super::signature::{get_signature, HASH_ALG_NONE};

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
    version: FormatVersion,
}

impl Default for CreateOptions {
    fn default() -> Self {
        CreateOptions {
            hash_alg: HASH_ALG_NONE,
            codec: Codec::default(),
            file_type: FileType::default(),
            version: FormatVersion::PA30,
        }
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

    /// Set the format version (PA30 or PA31).
    pub fn version(mut self, v: FormatVersion) -> Self {
        self.version = v;
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
                let export_rift = rift_gen::rift_from_exports(reference, target);
                let mut merged = section_rift;
                for e in import_rift.entries {
                    merged.entries.push(e);
                }
                for e in export_rift.entries {
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

        let magic = match self.version {
            FormatVersion::PA31 => PA31_MAGIC,
            _ => PA30_MAGIC,
        };

        let mut outer_writer = BitWriter::new();

        if self.version == FormatVersion::PA31 {
            let mut header_writer = BitWriter::new();
            header_writer.write_i64(file_type_set);
            header_writer.write_i64(file_type_val);
            header_writer.write_i64(flags);
            header_writer.write_i64(target.len() as i64);
            header_writer.write_i64(self.hash_alg as i64);
            header_writer.write_buffer(&target_hash);
            // PA31 extra fields
            header_writer.write_i64(0); // field1
            header_writer.write_i64(0); // field2
            header_writer.write_i64(0); // field3
            header_writer.write_buffer(&[]); // extra_hash
            let header_buf = header_writer.finish();
            outer_writer.write_buffer(&header_buf);
        } else {
            outer_writer.write_i64(file_type_set);
            outer_writer.write_i64(file_type_val);
            outer_writer.write_i64(flags);
            outer_writer.write_i64(target.len() as i64);
            outer_writer.write_i64(self.hash_alg as i64);
            outer_writer.write_buffer(&target_hash);
        }

        outer_writer.write_buffer(&preprocess);
        outer_writer.write_buffer(&patch_data);
        let bitstream = outer_writer.finish();

        let mut out = Vec::with_capacity(12 + bitstream.len());
        out.extend_from_slice(magic);
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
    let target = super::apply(reference, delta)?;
    let reverse = create(&target, reference)?;
    Ok((target, reverse))
}

/// Get delta header information without full decompression.
///
/// Equivalent to `GetDeltaInfoB(...)` on Windows.
pub fn get_info(delta: &[u8]) -> Result<super::header::Header> {
    super::header::parse_header(delta)
}
