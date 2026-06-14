//! PE preprocessing for PA30 deltas.

use crate::pe::cli::context::{ManagedPeInfoBitstream, TransformContextManaged};
use crate::pe::cli::metadata::CliMetadataModel;
use crate::pe::cli::schema::CliSchemaFlavor;
use crate::Result;

/// Parsed PE preprocess buffer from the delta.
///
/// From decompiled PreProcessPEForApply + PortableExecutableInfo::FromBitReader.
#[allow(dead_code)]
pub(crate) struct PePreprocess {
    pub(crate) target_info: ManagedPeInfoBitstream,
    // Second rift table (from PreProcessPEForApply, separate from PE info rift)
    pub(crate) preprocess_rift: crate::lzx::rift::RiftTable,
    pub(crate) cli_map: crate::pe::cli::map::CliMapModel,
}

impl PePreprocess {
    pub(crate) fn has_managed_cli_state(&self) -> bool {
        self.target_info.has_target_metadata() || !self.cli_map.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn managed_transform_context(
        &self,
        source_metadata: CliMetadataModel,
    ) -> Result<TransformContextManaged> {
        TransformContextManaged::new(
            self.target_info.flavor,
            source_metadata,
            self.target_info.clone(),
            self.preprocess_rift.clone(),
            self.cli_map.clone(),
        )
    }
}

pub(crate) fn parse_pe_preprocess(preprocess: &[u8]) -> Result<PePreprocess> {
    parse_pe_preprocess_for_flavor(preprocess, CliSchemaFlavor::Classic)
}

#[allow(dead_code)]
pub(crate) fn parse_cli4_pe_preprocess(preprocess: &[u8]) -> Result<PePreprocess> {
    parse_pe_preprocess_for_flavor(preprocess, CliSchemaFlavor::Cli4)
}

fn parse_pe_preprocess_for_flavor(
    preprocess: &[u8],
    flavor: CliSchemaFlavor,
) -> Result<PePreprocess> {
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

    let target_cli_metadata =
        crate::pe::cli::metadata::read_cli_metadata_bitstream(&mut reader, flavor)?;

    // Second rift table from PreProcessPEForApply
    let preprocess_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    let cli_map = if reader.remaining() > 0 {
        crate::pe::cli::map::read_cli_map_bitstream(&mut reader)?
    } else {
        crate::pe::cli::map::CliMapModel::default()
    };

    Ok(PePreprocess {
        target_info: ManagedPeInfoBitstream::new(
            flavor,
            target_image_base,
            target_field1,
            target_timestamp,
            pe_rift,
            target_cli_metadata,
        )?,
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
        &crate::pe::cli::metadata::CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
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
    if source_timestamp == 0 || source_timestamp == pp.target_info.time_date_stamp {
        return Ok(());
    }

    let new_bytes = pp.target_info.time_date_stamp.to_le_bytes();

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
mod tests {
    use crate::bitstream::BitWriter;
    use crate::lzx::rift::{RiftEntry, RiftTable};
    use crate::pe::cli::context::ManagedPeInfoBitstream;
    use crate::pe::cli::map::CliMapModel;
    use crate::pe::cli::metadata::{
        parse_cli_metadata_from_pe, write_cli4_metadata_bitstream, CliMetadataBitstreamRecord,
        CliMetadataBitstreamStream, CliMetadataBitstreamStreams, CliMetadataModel, CliStream,
        CliStreamSet,
    };
    use crate::pe::cli::schema::{CliSchemaFlavor, CodedIndexKind, HeapIndexWidths};
    use std::path::PathBuf;

    const MANAGED_NATIVE_CASES: &[&str] = &[
        "cli-const-string",
        "cli-add-method",
        "cli-generics-signature",
        "cli-custom-attribute",
        "cli-resource",
        "cli-platform-x64",
        "cli-properties-events",
        "cli-interface-impl",
        "cli-constructor-token-boundary",
        "cli-static-constructor-token-boundary",
        "cli-constructor-user-string-boundary",
        "cli-exception-switch",
        "cli-pinvoke-module",
        "cli-nested-struct-enum-array",
    ];

    fn empty_source_metadata() -> CliMetadataModel {
        CliMetadataModel {
            flavor: CliSchemaFlavor::Classic,
            metadata_rva: 0x2000,
            metadata_file_offset: 0x400,
            metadata_size: 0x100,
            version: "v4.0.30319".to_owned(),
            streams: CliStreamSet {
                strings: None,
                user_strings: None,
                blob: None,
                guid: None,
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: 0x400,
                    size: 24,
                },
            },
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 0,
            sorted_table_mask: 0,
            row_counts: [0; 64],
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        }
    }

    fn managed_native_corpus_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atoms/ManagedNativeCorpus"
        ))
    }

    #[test]
    fn builds_managed_transform_context_from_preprocess_state() {
        let target_info = ManagedPeInfoBitstream::new(
            CliSchemaFlavor::Classic,
            0x140000000,
            0x2222,
            0x12345678,
            RiftTable {
                entries: vec![RiftEntry {
                    source: 0x2000,
                    target: 0x600,
                }],
            },
            CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
        )
        .unwrap();
        let preprocess_rift = RiftTable {
            entries: vec![RiftEntry {
                source: 0x2000,
                target: 0x3000,
            }],
        };
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x01] = RiftTable {
            entries: vec![RiftEntry {
                source: 1,
                target: 2,
            }],
        };
        let preprocess = super::PePreprocess {
            target_info,
            preprocess_rift: preprocess_rift.clone(),
            cli_map: cli_map.clone(),
        };

        let context = preprocess
            .managed_transform_context(empty_source_metadata())
            .unwrap();

        assert_eq!(context.flavor, CliSchemaFlavor::Classic);
        assert_eq!(context.target_info.image_base, 0x140000000);
        assert_eq!(context.used_rift, preprocess_rift);
        assert_eq!(context.cli_map, cli_map);
        assert!(context.has_cli_state());

        let token_map = context.cli_map.coded_token_map().unwrap();
        assert_eq!(
            token_map
                .map_coded_token((1 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            (2 << 2) | 1
        );
    }

    #[test]
    fn cli4_managed_preprocess_parses_target_metadata_and_map() {
        let pe_rift = RiftTable {
            entries: vec![RiftEntry {
                source: 0x200,
                target: 0x1000,
            }],
        };
        let preprocess_rift = RiftTable {
            entries: vec![RiftEntry {
                source: 0x300,
                target: 0x2000,
            }],
        };
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x06] = RiftTable {
            entries: vec![RiftEntry {
                source: 1,
                target: 3,
            }],
        };
        let mut row_counts = [0u32; 64];
        row_counts[0x06] = 2;
        let target_metadata = CliMetadataBitstreamRecord {
            flavor: CliSchemaFlavor::Cli4,
            present: true,
            metadata_file_offset: 0x100,
            metadata_size: 0x400,
            metadata_rva: 0x2000,
            stream_count: 5,
            stream_headers_end: 0x160,
            streams: CliMetadataBitstreamStreams {
                strings: CliMetadataBitstreamStream {
                    file_offset: 0x200,
                    size: 0x20,
                },
                user_strings: CliMetadataBitstreamStream {
                    file_offset: 0,
                    size: 0,
                },
                blob: CliMetadataBitstreamStream {
                    file_offset: 0x230,
                    size: 0x20,
                },
                guid: CliMetadataBitstreamStream {
                    file_offset: 0x260,
                    size: 0x10,
                },
                tables: CliMetadataBitstreamStream {
                    file_offset: 0x180,
                    size: 0x100,
                },
            },
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 1 << 0x06,
            row_counts,
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        };

        let mut writer = BitWriter::new();
        writer.write_bits(0x1800_0000u64, 64);
        writer.write_bits(0x4444, 32);
        writer.write_bits(0x5566_7788, 32);
        pe_rift.to_writer(&mut writer);
        write_cli4_metadata_bitstream(&mut writer, &target_metadata).unwrap();
        preprocess_rift.to_writer(&mut writer);
        crate::pe::cli::map::write_cli_map_bitstream(&mut writer, &cli_map);

        let parsed = super::parse_cli4_pe_preprocess(&writer.finish()).unwrap();

        assert_eq!(parsed.target_info.flavor, CliSchemaFlavor::Cli4);
        assert_eq!(parsed.target_info.image_base, 0x1800_0000);
        assert_eq!(parsed.target_info.checksum, 0x4444);
        assert_eq!(parsed.target_info.time_date_stamp, 0x5566_7788);
        assert_eq!(parsed.target_info.target_rva_to_file_offset, pe_rift);
        assert_eq!(parsed.preprocess_rift, preprocess_rift);
        assert_eq!(parsed.cli_map, cli_map);
        assert_eq!(
            parsed.target_info.target_metadata.flavor,
            CliSchemaFlavor::Cli4
        );
        assert_eq!(parsed.target_info.target_metadata.row_sizes[0x06], 14);
        assert_eq!(
            parsed.target_info.target_metadata.table_file_offsets[0x06],
            Some(0x19c)
        );
        assert!(parsed.has_managed_cli_state());
    }

    #[test]
    fn classic_managed_preprocess_context_builds_from_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_target_metadata = 0usize;
        let mut cases_with_cli_map = 0usize;

        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = super::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse classic managed preprocess");
            let source_metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");

            let context = preprocess
                .managed_transform_context(source_metadata)
                .expect("build managed transform context");

            assert_eq!(context.flavor, CliSchemaFlavor::Classic, "{case}");
            cases_with_target_metadata += usize::from(context.target_info.has_target_metadata());
            cases_with_cli_map += usize::from(!context.cli_map.is_empty());
        }

        assert!(
            cases_with_target_metadata > 0,
            "managed corpus should cover target metadata records"
        );
        assert!(
            cases_with_cli_map > 0,
            "managed corpus should cover CLI map records"
        );
    }
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
        assert_eq!(
            op.target_info.image_base, gp.target_info.image_base,
            "image_base"
        );
        assert_eq!(
            op.target_info.checksum, gp.target_info.checksum,
            "preprocess field1"
        );
        assert_eq!(
            op.target_info.time_date_stamp, gp.target_info.time_date_stamp,
            "timestamp"
        );
        assert_eq!(
            op.target_info.target_rva_to_file_offset.entries.len(),
            gp.target_info.target_rva_to_file_offset.entries.len(),
            "rift entry count"
        );
        for (i, (a, b)) in op
            .target_info
            .target_rva_to_file_offset
            .entries
            .iter()
            .zip(gp.target_info.target_rva_to_file_offset.entries.iter())
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
