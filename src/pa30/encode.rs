//! PA30 delta encoder.

use crate::pe::parse::PeInfo;
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
        use crate::pe::{rift_gen, transform};

        let pe_info = if self.file_type == FileType::Auto {
            PeInfo::parse(reference)
                .ok()
                .zip(PeInfo::parse(target).ok())
                .and_then(|(src_pe, tgt_pe)| {
                    create_pe_file_type(&src_pe, &tgt_pe).map(|ft| (src_pe, tgt_pe, ft))
                })
        } else {
            None
        };

        let (patch_data, file_type_set, file_type_val, flags, preprocess) =
            if let Some((_src_pe, tgt_pe, ft)) = pe_info {
                // Genuine encode diffs the target against T(source): the reference
                // transformed exactly as PreProcessPEForApply does on decode, so the
                // LZX copy/literal split is defined against the SAME bytes the decoder
                // later copies from. The old path diffed against a merely
                // checksum-zeroed reference and never built T(source), so any copy
                // pointing at a byte the decoder rewrites decoded wrong (the 250
                // non-reconstructing deltas the encode oracle measured). We mirror the
                // decode path (build_transformed_source + build_pe_copy_rift) and
                // round-trip the preprocess so encode and decode share an identical
                // PePreprocess -- which guarantees the delta reconstructs regardless of
                // how close the rift/flags are to genuine.
                //
                // Architecture-correct transform-selection flags: genuine i386 deltas
                // carry 0xe1fe, amd64 carry 0xe63e (measured across the bulk corpus;
                // we hardcoded 0xe63e for both before).
                let flags: i64 = if tgt_pe.is_64bit { 0xe63e } else { 0xe1fe };
                // pe_rift slot = the TARGET image's section RVA->file-offset map (the
                // copy-rift builder consumes it). preprocess_rift is empty for now, so
                // the transforms remap RVAs by identity and T(source) carries only the
                // structural header rewrites (target timestamp / image base) -- correct
                // and symmetric, though not yet a genuine rift. Closing the rift +
                // match-finder gap to reach byte-exact is the follow-up the encode
                // oracle tracks.
                let pe_rift = rift_gen::pe_section_rift(target);
                let preprocess = build_pe_preprocess(
                    tgt_pe.image_base,
                    0, // field1 (opt-header CheckSum); 0 makes apply emit a zeroed checksum
                    tgt_pe.timestamp,
                    &pe_rift,
                    &RiftTable { entries: vec![] },
                );
                // Round-trip the preprocess so we hold the exact struct the decoder
                // parses, then build T(source) and the copy rift from it.
                let pp = super::preprocess::parse_pe_preprocess(&preprocess)?;
                let mut tsource = reference.to_vec();
                transform::zero_pe_checksum(&mut tsource);
                if let Ok(src_pe) = crate::pe::parse::PeInfo::parse_lenient(&tsource) {
                    transform::build_transformed_source(
                        &mut tsource,
                        &src_pe,
                        &pp.preprocess_rift,
                        flags as u64,
                        pp.target_info.image_base,
                        pp.target_info.time_date_stamp,
                    );
                }
                let empty_cli_rift = RiftTable { entries: vec![] };
                let copy_rift =
                    super::build_pe_copy_rift_with_cli_rift(reference, &pp, &empty_cli_rift);
                let patch_data = crate::lzx::compress_with_rift(&tsource, target, &copy_rift)?;
                (patch_data, 0xFi64, ft, flags, preprocess)
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

fn create_pe_file_type(source: &PeInfo, target: &PeInfo) -> Option<i64> {
    if source.machine != target.machine {
        return None;
    }
    target.machine.supported_create_file_type()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::parse::PeMachine;

    fn pe(machine: PeMachine) -> PeInfo {
        PeInfo {
            image_base: 0x140000000,
            size_of_image: 0x1000,
            timestamp: 0,
            checksum: 0,
            is_64bit: matches!(
                machine,
                PeMachine::Amd64 | PeMachine::Arm64 | PeMachine::Ia64
            ),
            machine,
            sections: vec![],
            data_directories: vec![],
        }
    }

    #[test]
    fn create_pe_file_type_requires_matching_supported_machine() {
        assert_eq!(
            create_pe_file_type(&pe(PeMachine::I386), &pe(PeMachine::I386)),
            Some(0x2)
        );
        assert_eq!(
            create_pe_file_type(&pe(PeMachine::Amd64), &pe(PeMachine::Amd64)),
            Some(0x8)
        );
        assert_eq!(
            create_pe_file_type(&pe(PeMachine::I386), &pe(PeMachine::Amd64)),
            None
        );
        assert_eq!(
            create_pe_file_type(&pe(PeMachine::Ia64), &pe(PeMachine::Ia64)),
            None
        );
        assert_eq!(
            create_pe_file_type(&pe(PeMachine::Arm64), &pe(PeMachine::Arm64)),
            None
        );
    }
}
