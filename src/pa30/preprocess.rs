//! PE preprocessing for PA30 deltas.

use crate::Result;

/// Parsed PE preprocess buffer from the delta.
///
/// From decompiled PreProcessPEForApply + PortableExecutableInfo::FromBitReader.
#[allow(dead_code)]
pub(crate) struct PePreprocess {
    pub(crate) target_image_base: u64,
    pub(crate) target_field1: u32,
    pub(crate) target_timestamp: u32,
    pub(crate) pe_rift: crate::lzx::rift::RiftTable,
    pub(crate) target_cli_metadata: crate::pe::cli::metadata::CliMetadataBitstreamRecord,
    // Second rift table (from PreProcessPEForApply, separate from PE info rift)
    pub(crate) preprocess_rift: crate::lzx::rift::RiftTable,
    pub(crate) cli_map: crate::pe::cli::map::CliMapModel,
}

impl PePreprocess {
    pub(crate) fn has_managed_cli_state(&self) -> bool {
        !self.target_cli_metadata.is_empty() || !self.cli_map.is_empty()
    }
}

pub(crate) fn parse_pe_preprocess(preprocess: &[u8]) -> Result<PePreprocess> {
    use crate::bitstream::BitReader;

    let mut reader = BitReader::new(preprocess)?;

    // PortableExecutableInfo::FromBitReader (decompiled at 18004cda0):
    //   Read64(0x40) = ImageBase
    //   Read32(0x20) = field1 (zero for typical deltas)
    //   Read32(0x20) = target TimeDateStamp
    //   RiftTable::FromBitReader = PE-level rift table
    //   CliMetadata::FromBitReader = structured CLI metadata
    //
    // Then PreProcessPEForApply reads more:
    //   RiftTable::FromBitReader = second rift table
    //   CliMap::FromBitReader = structured CLI map
    //
    let target_image_base = reader.read_bits(64)?;
    let target_field1 = reader.read_bits(32)? as u32;
    let target_timestamp = reader.read_bits(32)? as u32;

    let pe_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    let target_cli_metadata = crate::pe::cli::metadata::read_cli_metadata_bitstream(
        &mut reader,
        crate::pe::cli::schema::CliSchemaFlavor::Classic,
    )?;

    // Second rift table from PreProcessPEForApply
    let preprocess_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    let cli_map = if reader.remaining() > 0 {
        crate::pe::cli::map::read_cli_map_bitstream(&mut reader)?
    } else {
        crate::pe::cli::map::CliMapModel::default()
    };

    Ok(PePreprocess {
        target_image_base,
        target_field1,
        target_timestamp,
        pe_rift,
        target_cli_metadata,
        preprocess_rift,
        cli_map,
    })
}

pub(crate) fn build_pe_preprocess(
    target_image_base: u64,
    target_checksum: u32,
    target_timestamp: u32,
    pe_rift: &crate::lzx::rift::RiftTable,
    preprocess_rift: &crate::lzx::rift::RiftTable,
) -> Vec<u8> {
    use crate::bitstream::BitWriter;
    let mut writer = BitWriter::new();
    writer.write_bits(target_image_base, 64);
    // field1 = optional-header CheckSum. msdelta zeroes the checksum in the patch
    // domain and restores it from here on apply; leaving this 0 makes genuine
    // msdelta emit a zeroed checksum (a 4-byte divergence at opt-header+0x40).
    writer.write_bits(target_checksum as u64, 32);
    writer.write_bits(target_timestamp as u64, 32);
    pe_rift.to_writer(&mut writer);
    crate::pe::cli::metadata::write_cli_metadata_bitstream(
        &mut writer,
        &crate::pe::cli::metadata::CliMetadataBitstreamRecord::empty(
            crate::pe::cli::schema::CliSchemaFlavor::Classic,
        ),
    );
    preprocess_rift.to_writer(&mut writer);
    crate::pe::cli::map::write_cli_map_bitstream(
        &mut writer,
        &crate::pe::cli::map::CliMapModel::default(),
    );
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
pub(crate) fn apply_pe_timestamp_fixup(
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

#[cfg(test)]
mod genuine_pe_tests {
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/deltas"
        ))
    }

    /// Our PE encoder must reproduce the genuine msdelta delta's transform
    /// header: file type, flags, and -- crucially -- the exact preprocess
    /// (image_base, field1, timestamp, and the section rift entries). The
    /// genuine deltas in tests/fixtures/deltas/genuine/ are real CreateDeltaB
    /// output (Win Server 2025, build 26100).
    fn assert_matches_genuine(genuine_name: &str, src_name: &str, tgt_name: &str) {
        let d = dir();
        let gpath = d.join("genuine").join(genuine_name);
        if !gpath.exists() {
            return; // fixtures not present in this checkout
        }
        let genuine = std::fs::read(&gpath).unwrap();
        let src = std::fs::read(d.join("sources").join(src_name)).unwrap();
        let tgt = std::fs::read(d.join("sources").join(tgt_name)).unwrap();

        let ours = crate::pa30::CreateOptions::new()
            .file_type(crate::pa30::FileType::Auto)
            .execute(&src, &tgt)
            .unwrap();

        let g = crate::pa30::parse(&genuine).unwrap();
        let o = crate::pa30::parse(&ours).unwrap();

        assert_eq!(
            o.header.file_type_set, g.header.file_type_set,
            "file_type_set"
        );
        assert_eq!(o.header.file_type, g.header.file_type, "file_type");
        assert_eq!(o.header.flags, g.header.flags, "flags (expect 0xe63e)");

        let gp = super::parse_pe_preprocess(&g.preprocess).unwrap();
        let op = super::parse_pe_preprocess(&o.preprocess).unwrap();
        assert_eq!(op.target_image_base, gp.target_image_base, "image_base");
        assert_eq!(op.target_field1, gp.target_field1, "preprocess field1");
        assert_eq!(op.target_timestamp, gp.target_timestamp, "timestamp");
        assert_eq!(
            op.pe_rift.entries.len(),
            gp.pe_rift.entries.len(),
            "rift entry count"
        );
        for (i, (a, b)) in op
            .pe_rift
            .entries
            .iter()
            .zip(gp.pe_rift.entries.iter())
            .enumerate()
        {
            assert_eq!(a.source, b.source, "rift[{i}].source");
            assert_eq!(a.target, b.target, "rift[{i}].target");
        }

        // And our own decoder must round-trip our delta back to the target.
        assert_eq!(crate::pa30::apply(&src, &ours).unwrap(), tgt, "round-trip");
    }

    #[test]
    fn pe_cmd_matches_genuine() {
        assert_matches_genuine("cmd_pe_genuine.pa30", "cmd.exe", "cmd_patched.exe");
    }

    #[test]
    fn pe_advapi32_matches_genuine() {
        assert_matches_genuine(
            "advapi32_pe_genuine.pa30",
            "advapi32_old.dll",
            "advapi32_new.dll",
        );
    }
}
