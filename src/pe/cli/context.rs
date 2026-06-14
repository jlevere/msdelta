//! Typed managed PE preprocessing context.

use crate::lzx::rift::RiftTable;
use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::metadata::{CliMetadataBitstreamRecord, CliMetadataModel};
use crate::pe::cli::schema::CliSchemaFlavor;
use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedPeInfoBitstream {
    pub(crate) flavor: CliSchemaFlavor,
    pub(crate) image_base: u64,
    pub(crate) checksum: u32,
    pub(crate) time_date_stamp: u32,
    pub(crate) target_rva_to_file_offset: RiftTable,
    pub(crate) target_metadata: CliMetadataBitstreamRecord,
}

impl ManagedPeInfoBitstream {
    pub(crate) fn new(
        flavor: CliSchemaFlavor,
        image_base: u64,
        checksum: u32,
        time_date_stamp: u32,
        target_rva_to_file_offset: RiftTable,
        target_metadata: CliMetadataBitstreamRecord,
    ) -> Result<Self> {
        if target_metadata.flavor != flavor {
            return Err(Error::Malformed(
                "managed PE info: target metadata flavor mismatch",
            ));
        }
        Ok(Self {
            flavor,
            image_base,
            checksum,
            time_date_stamp,
            target_rva_to_file_offset,
            target_metadata,
        })
    }

    pub(crate) fn has_target_metadata(&self) -> bool {
        !self.target_metadata.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransformContextManaged {
    pub(crate) flavor: CliSchemaFlavor,
    pub(crate) source_metadata: CliMetadataModel,
    pub(crate) target_info: ManagedPeInfoBitstream,
    pub(crate) used_rift: RiftTable,
    pub(crate) cli_map: CliMapModel,
}

impl TransformContextManaged {
    pub(crate) fn new(
        flavor: CliSchemaFlavor,
        source_metadata: CliMetadataModel,
        target_info: ManagedPeInfoBitstream,
        used_rift: RiftTable,
        cli_map: CliMapModel,
    ) -> Result<Self> {
        if source_metadata.flavor != flavor {
            return Err(Error::Malformed(
                "managed transform context: source metadata flavor mismatch",
            ));
        }
        if target_info.flavor != flavor {
            return Err(Error::Malformed(
                "managed transform context: target metadata flavor mismatch",
            ));
        }
        Ok(Self {
            flavor,
            source_metadata,
            target_info,
            used_rift,
            cli_map,
        })
    }

    pub(crate) fn has_cli_state(&self) -> bool {
        self.target_info.has_target_metadata() || !self.cli_map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::RiftEntry;
    use crate::pe::cli::metadata::{CliStream, CliStreamSet};
    use crate::pe::cli::schema::HeapIndexWidths;

    fn empty_rift() -> RiftTable {
        RiftTable {
            entries: Vec::new(),
        }
    }

    fn non_empty_cli_map() -> CliMapModel {
        CliMapModel {
            strings: RiftTable {
                entries: vec![RiftEntry {
                    source: 0x10,
                    target: 0x20,
                }],
            },
            ..CliMapModel::default()
        }
    }

    fn source_metadata(flavor: CliSchemaFlavor) -> CliMetadataModel {
        CliMetadataModel {
            flavor,
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

    #[test]
    fn managed_pe_info_rejects_metadata_flavor_mismatch() {
        let err = ManagedPeInfoBitstream::new(
            CliSchemaFlavor::Cli4,
            0x140000000,
            0,
            0x12345678,
            empty_rift(),
            CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
        )
        .unwrap_err();

        assert!(matches!(err, Error::Malformed(message) if message.contains("flavor mismatch")));
    }

    #[test]
    fn transform_context_validates_source_and_target_flavors() {
        let target_info = ManagedPeInfoBitstream::new(
            CliSchemaFlavor::Classic,
            0x140000000,
            0,
            0x12345678,
            empty_rift(),
            CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
        )
        .unwrap();

        let err = TransformContextManaged::new(
            CliSchemaFlavor::Cli4,
            source_metadata(CliSchemaFlavor::Classic),
            target_info,
            empty_rift(),
            CliMapModel::default(),
        )
        .unwrap_err();

        assert!(
            matches!(err, Error::Malformed(message) if message.contains("source metadata flavor mismatch"))
        );
    }

    #[test]
    fn transform_context_reports_cli_state_from_target_metadata_or_map() {
        let target_info = ManagedPeInfoBitstream::new(
            CliSchemaFlavor::Classic,
            0x140000000,
            0,
            0x12345678,
            empty_rift(),
            CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
        )
        .unwrap();
        let context = TransformContextManaged::new(
            CliSchemaFlavor::Classic,
            source_metadata(CliSchemaFlavor::Classic),
            target_info,
            empty_rift(),
            CliMapModel::default(),
        )
        .unwrap();

        assert!(!context.has_cli_state());

        let context = TransformContextManaged::new(
            CliSchemaFlavor::Classic,
            source_metadata(CliSchemaFlavor::Classic),
            context.target_info,
            empty_rift(),
            non_empty_cli_map(),
        )
        .unwrap();

        assert!(context.has_cli_state());
    }
}
