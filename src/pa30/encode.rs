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
            PeInfo::parse(reference)
                .ok()
                .zip(PeInfo::parse(target).ok())
        } else {
            None
        };

        let (patch_data, file_type_set, file_type_val, flags, preprocess) =
            if let Some((src_pe, tgt_pe)) = pe_info {
                let _ = &src_pe;
                // Do NOT normalize timestamps: diff the raw target so its real
                // timestamps are carried in the patch (as literals where they
                // differ from the reference). msdelta's apply then emits the
                // target timestamps directly. (Our decoder's timestamp fixup is
                // retained for decoding genuine *normalized* deltas, where it's
                // needed; on our own un-normalized deltas it is a no-op because
                // those offsets already hold the target timestamp.)

                // Genuine msdelta uses the *reference* image's section
                // RVA->file-offset map as the rift (verified byte-exact), carried
                // in the preprocess (not the patch). The LZX encoder consumes it to
                // pick rift-relative offsets; long copies that start at a low
                // position span whole sections.
                let merged = rift_gen::pe_section_rift(reference);

                // msdelta zeroes the optional-header CheckSum in the copy source;
                // diffing against the zeroed reference makes the target's real
                // checksum fall out as literals instead of a copy that resolves to
                // zero on genuine msdelta.
                let mut ref_norm = reference.to_vec();
                transform::zero_pe_checksum(&mut ref_norm);

                let patch_data = crate::lzx::compress_with_rift(&ref_norm, target, &merged)?;
                let _ = tgt_pe.checksum;
                let preprocess = build_pe_preprocess(
                    tgt_pe.image_base,
                    0, // field1 (restores to opt-header+0x70); 0 matches genuine for cmd
                    tgt_pe.timestamp,
                    &merged,
                    &RiftTable { entries: vec![] },
                );
                let ft: i64 = if tgt_pe.is_64bit { 8 } else { 2 };
                // flags=0xe63e: the PE transform-config bitmask genuine msdelta
                // emits for AMD64 PE deltas; its apply requires it to drive
                // rift-based decode of the patch.
                (patch_data, 0xFi64, ft, 0xe63ei64, preprocess)
            } else {
                match self.codec {
                    Codec::PseudoLzx => {
                        let data = crate::lzx::compress(reference, target)?;
                        // flags=0x20000 matches genuine WinSxS DCM manifests. (Tested:
                        // flags is NOT the complex-mode reject cause -- both 0 and
                        // 0x20000 are accepted by apply; the reject is in the patch body.)
                        (data, 1i64, 1i64, 0x20000i64, vec![])
                    }
                    Codec::BsDiff => {
                        // msdelta's "bsdiff" path (CreateDeltaB with SetFlags=0x100)
                        // does NOT emit a distinct bsdiff container. Verified against
                        // genuine msdelta.dll (Win Server 2025, build 26100): the patch
                        // bytes are identical for SetFlags 0 vs 0x100 across small, tiny,
                        // and pathological scattered-byte diffs -- only the header `flags`
                        // bit changes. The codec is always LZX. So the MS-compatible form
                        // is the normal LZX patch with file_type_set=1, file_type=1, and
                        // the 0x100 flag bit set.
                        let data = crate::lzx::compress(reference, target)?;
                        (data, 1i64, 1i64, 0x100i64, vec![])
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

/// Get extended delta info including PA31 fields.
///
/// Equivalent to `GetDeltaInfoExB(...)` on UpdateCompression.dll.
/// Returns the same Header struct — PA31 extra fields are in `pa31_extra`.
pub fn get_info_ex(delta: &[u8]) -> Result<super::header::Header> {
    super::header::parse_header(delta)
}
