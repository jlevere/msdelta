//! CLI metadata table and signature blob source transforms.

use crate::lzx::rift::RiftTable;
use crate::pe::cli::blob::read_compressed_u32;
use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::metadata::{CliMetadataModel, CliStream};
use crate::pe::cli::schema::{
    column_width, signature_kind_for_table, table_schema, CliSchemaFlavor, ColumnKind, HeapKind,
    SignatureKind,
};
use crate::pe::cli::signature::{
    transform_field_signature_blob, transform_method_signature_blob,
    transform_property_signature_blob, transform_type_spec_blob,
};
use crate::{Error, Result};
use std::collections::BTreeSet;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliMetadataTransformStats {
    pub(crate) index_rewrites: usize,
    pub(crate) rva_rewrites: usize,
    pub(crate) signature_blob_rewrites: usize,
}

pub(crate) fn transform_cli_metadata(
    image: &mut [u8],
    metadata: &CliMetadataModel,
    cli_map: &CliMapModel,
) -> CliMetadataTransformStats {
    let empty_rva_map = RiftTable {
        entries: Vec::new(),
    };
    transform_cli_metadata_with_rva_map(image, metadata, cli_map, &empty_rva_map)
}

pub(crate) fn transform_cli_metadata_with_rva_map(
    image: &mut [u8],
    metadata: &CliMetadataModel,
    cli_map: &CliMapModel,
    rva_map: &RiftTable,
) -> CliMetadataTransformStats {
    let token_map = cli_map.coded_token_map().ok();
    let mut signature_blobs = BTreeSet::new();
    let mut stats = CliMetadataTransformStats::default();

    for table_id in 0..64u8 {
        let Some(schema) = table_schema(table_id) else {
            continue;
        };
        let row_count = metadata.row_counts[table_id as usize] as usize;
        if row_count == 0 {
            continue;
        }
        let row_size = metadata.row_sizes[table_id as usize] as usize;
        if row_size == 0 {
            continue;
        }
        let Some(table_file_offset) = metadata.table_file_offsets[table_id as usize] else {
            continue;
        };

        for row_index in 0..row_count {
            let Some(row_delta) = row_index.checked_mul(row_size) else {
                continue;
            };
            let Some(row_start) = table_file_offset.checked_add(row_delta) else {
                continue;
            };
            let mut column_offset = 0usize;
            for column in schema.columns {
                let width =
                    column_width(column.kind, &metadata.row_counts, metadata.heap_widths) as usize;
                let Some(cell_offset) = row_start.checked_add(column_offset) else {
                    break;
                };
                let Some(value) = read_index(image, cell_offset, width) else {
                    break;
                };

                // A blob-heap column whose table carries a remappable signature
                // (per the genuine column-descriptor kinds) -- queue it for the
                // signature walk after the table pass.
                if value != 0
                    && matches!(column.kind, ColumnKind::Heap(HeapKind::Blob))
                    && signature_kind_for_table(table_id)
                        .is_some_and(|k| k != SignatureKind::NoTypeRemap)
                {
                    signature_blobs.insert((table_id, value));
                }

                let mapped = match column.kind {
                    ColumnKind::Heap(HeapKind::Strings) => map_index(&cli_map.strings, value),
                    ColumnKind::Heap(HeapKind::Guid) => map_index(&cli_map.guid, value),
                    ColumnKind::Heap(HeapKind::Blob) => map_index(&cli_map.blob, value),
                    ColumnKind::Table(target_table) => {
                        map_index(&cli_map.tables[target_table as usize], value)
                    }
                    ColumnKind::Coded(kind) => token_map
                        .as_ref()
                        .and_then(|map| map.map_coded_token(value, kind).ok())
                        .unwrap_or(value),
                    ColumnKind::Rva => map_index(rva_map, value),
                    ColumnKind::U8 | ColumnKind::U16 | ColumnKind::U32 => value,
                };

                if mapped != value && write_index(image, cell_offset, width, mapped) {
                    if matches!(column.kind, ColumnKind::Rva) {
                        stats.rva_rewrites += 1;
                    } else {
                        stats.index_rewrites += 1;
                    }
                }

                column_offset += width;
            }
        }
    }

    for (table_id, blob_offset) in signature_blobs {
        stats.signature_blob_rewrites += transform_signature_blob_at_source_offset(
            image,
            metadata,
            cli_map,
            table_id,
            blob_offset,
        );
    }

    stats
}

pub(crate) fn transform_cli4_metadata(
    image: &mut [u8],
    metadata: &CliMetadataModel,
    cli_map: &CliMapModel,
) -> Result<CliMetadataTransformStats> {
    if metadata.flavor != CliSchemaFlavor::Cli4 {
        return Err(Error::Malformed(
            "CLI4 metadata transform: source metadata flavor mismatch",
        ));
    }

    Ok(transform_cli_metadata(image, metadata, cli_map))
}

/// `IMAGE_CEE_CS_CALLCONV_FIELD` -- a MemberRef whose signature starts with this
/// is a field reference, otherwise a method reference (ECMA-335 II.23.2.3/.4).
const CALLCONV_FIELD: u8 = 0x06;

fn transform_signature_blob_at_source_offset(
    image: &mut [u8],
    metadata: &CliMetadataModel,
    cli_map: &CliMapModel,
    table_id: u8,
    blob_offset: u32,
) -> usize {
    let Some(stream) = metadata.streams.blob else {
        return 0;
    };
    let Some(blob) = blob_value_mut(image, stream, blob_offset) else {
        return 0;
    };
    match signature_kind_for_table(table_id) {
        Some(SignatureKind::FieldSig) => transform_field_signature_blob(blob, cli_map),
        Some(SignatureKind::MethodSig) => transform_method_signature_blob(blob, cli_map),
        Some(SignatureKind::MemberRefSig) => transform_member_ref_signature_blob(blob, cli_map),
        // KNOWN MISMATCH: genuine walks StandAloneSig with its own kind-9 grammar
        // (LocalVarSig: `0x07 count locals`); we currently reuse the method-sig
        // walk. Fixing this is part of the per-kind blob walker (see
        // managed-tail-diagnosis). Left as-is to preserve current decode results.
        Some(SignatureKind::StandAloneSig) => transform_method_signature_blob(blob, cli_map),
        Some(SignatureKind::PropertySig) => transform_property_signature_blob(blob, cli_map),
        Some(SignatureKind::TypeSpecSig) => transform_type_spec_blob(blob, cli_map),
        Some(SignatureKind::NoTypeRemap) | None => 0,
    }
}

fn transform_member_ref_signature_blob(blob: &mut [u8], cli_map: &CliMapModel) -> usize {
    if blob.first().copied() == Some(CALLCONV_FIELD) {
        transform_field_signature_blob(blob, cli_map)
    } else {
        transform_method_signature_blob(blob, cli_map)
    }
}

fn blob_value_mut(image: &mut [u8], stream: CliStream, offset: u32) -> Option<&mut [u8]> {
    let stream_start = stream.file_offset;
    let stream_end = stream_start
        .checked_add(stream.size as usize)?
        .min(image.len());
    let blob_start = stream_start.checked_add(offset as usize)?;
    if blob_start >= stream_end {
        return None;
    }
    let (len, prefix_len) = read_compressed_u32(image.get(blob_start..stream_end)?).ok()?;
    let value_start = blob_start.checked_add(prefix_len)?;
    let value_end = value_start.checked_add(len as usize)?;
    if value_end > stream_end {
        return None;
    }
    image.get_mut(value_start..value_end)
}

fn map_index(rift: &RiftTable, value: u32) -> u32 {
    if value == 0 {
        return 0;
    }
    i64::from(value).wrapping_add(rift.map(i64::from(value))) as u32
}

fn read_index(image: &[u8], offset: usize, width: usize) -> Option<u32> {
    match width {
        1 => image.get(offset).copied().map(u32::from),
        2 => image
            .get(offset..offset + 2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()) as u32),
        4 => image
            .get(offset..offset + 4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap())),
        _ => None,
    }
}

fn write_index(image: &mut [u8], offset: usize, width: usize, value: u32) -> bool {
    match width {
        1 if value <= u8::MAX as u32 => {
            if let Some(slot) = image.get_mut(offset) {
                *slot = value as u8;
                return true;
            }
            false
        }
        2 if value <= u16::MAX as u32 => {
            if let Some(slot) = image.get_mut(offset..offset + 2) {
                slot.copy_from_slice(&(value as u16).to_le_bytes());
                return true;
            }
            false
        }
        4 => {
            if let Some(slot) = image.get_mut(offset..offset + 4) {
                slot.copy_from_slice(&value.to_le_bytes());
                return true;
            }
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::{RiftEntry, RiftTable};
    use crate::pe::cli::metadata::{CliMetadataModel, CliStreamSet};
    use crate::pe::cli::schema::{row_size, HeapIndexWidths};

    struct MetadataTransformFixture {
        metadata: CliMetadataModel,
        image: Vec<u8>,
        cli_map: CliMapModel,
        blob_start: usize,
    }

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    fn put_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn read_u16(image: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap())
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn read_u32(image: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
    }

    fn test_metadata_model() -> CliMetadataModel {
        let heap_widths = HeapIndexWidths {
            strings: 2,
            guid: 2,
            blob: 2,
        };
        let mut row_counts = [0u32; 64];
        row_counts[0x02] = 1;
        row_counts[0x06] = 1;
        let mut row_sizes = [0u32; 64];
        row_sizes[0x02] = row_size(0x02, &row_counts, heap_widths).unwrap() as u32;
        row_sizes[0x06] = row_size(0x06, &row_counts, heap_widths).unwrap() as u32;
        let mut table_file_offsets = [None; 64];
        table_file_offsets[0x02] = Some(0x20);
        table_file_offsets[0x06] = Some(0x00);

        CliMetadataModel {
            flavor: CliSchemaFlavor::Classic,
            metadata_rva: 0,
            metadata_file_offset: 0,
            metadata_size: 0x180,
            version: "v4.0.30319".to_owned(),
            streams: CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0x80,
                    size: 0x20,
                }),
                user_strings: None,
                blob: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0x100,
                    size: 0x40,
                }),
                guid: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0xc0,
                    size: 0x20,
                }),
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: 0,
                    size: 0x60,
                },
            },
            heap_widths,
            valid_table_mask: (1 << 0x02) | (1 << 0x06),
            sorted_table_mask: 0,
            row_counts,
            row_sizes,
            table_file_offsets,
        }
    }

    fn metadata_transform_fixture(flavor: CliSchemaFlavor) -> MetadataTransformFixture {
        let mut metadata = test_metadata_model();
        metadata.flavor = flavor;
        let mut image = vec![0u8; 0x180];

        put_u32(&mut image, 0x00, 0x2066); // MethodDef.Rva
        put_u16(&mut image, 0x08, 3); // MethodDef.Name
        put_u16(&mut image, 0x0a, 1); // MethodDef.Signature
        put_u16(&mut image, 0x0c, 1); // MethodDef.ParamList

        put_u16(&mut image, 0x24, 3); // TypeDef.Name
        put_u16(&mut image, 0x28, (3 << 2) | 1); // TypeDef.Extends: TypeRef RID 3
        put_u16(&mut image, 0x2a, 1); // TypeDef.FieldList
        put_u16(&mut image, 0x2c, 1); // TypeDef.MethodList

        let blob_start = 0x101;
        image[blob_start] = 5;
        image[blob_start + 1..blob_start + 6].copy_from_slice(&[
            0x00,
            0x01,
            0x01,
            0x12,
            (3 << 2) | 1,
        ]);

        let mut table_maps = CliMapModel::default().tables;
        table_maps[0x01] = rift(&[(3, 7)]);
        table_maps[0x04] = rift(&[(1, 4)]);
        table_maps[0x06] = rift(&[(1, 6)]);
        table_maps[0x08] = rift(&[(1, 2)]);
        let cli_map = CliMapModel {
            strings: rift(&[(3, 7)]),
            blob: rift(&[(1, 5)]),
            tables: table_maps,
            ..CliMapModel::default()
        };

        MetadataTransformFixture {
            metadata,
            image,
            cli_map,
            blob_start,
        }
    }

    fn assert_fixture_was_transformed(
        image: &[u8],
        blob_start: usize,
        stats: CliMetadataTransformStats,
    ) {
        assert!(stats.index_rewrites >= 6);
        assert_eq!(stats.signature_blob_rewrites, 1);
        assert_eq!(read_u32(image, 0x00), 0x2066);
        assert_eq!(read_u16(image, 0x08), 7);
        assert_eq!(read_u16(image, 0x0a), 5);
        assert_eq!(read_u16(image, 0x0c), 2);
        assert_eq!(read_u16(image, 0x24), 7);
        assert_eq!(read_u16(image, 0x28), (7 << 2) | 1);
        assert_eq!(read_u16(image, 0x2a), 4);
        assert_eq!(read_u16(image, 0x2c), 6);
        assert_eq!(image[blob_start + 5], (7 << 2) | 1);
    }

    #[test]
    fn transforms_metadata_indices_and_source_signature_blob() {
        let mut fixture = metadata_transform_fixture(CliSchemaFlavor::Classic);

        let stats = transform_cli_metadata(&mut fixture.image, &fixture.metadata, &fixture.cli_map);

        assert_fixture_was_transformed(&fixture.image, fixture.blob_start, stats);
    }

    #[test]
    fn transforms_metadata_rva_columns_with_supplied_rva_map() {
        let mut fixture = metadata_transform_fixture(CliSchemaFlavor::Classic);
        let rva_map = rift(&[(0x2066, 0x2067)]);

        let stats = transform_cli_metadata_with_rva_map(
            &mut fixture.image,
            &fixture.metadata,
            &fixture.cli_map,
            &rva_map,
        );

        assert_eq!(stats.rva_rewrites, 1);
        assert_eq!(read_u32(&fixture.image, 0x00), 0x2067);
    }

    #[test]
    fn cli4_metadata_transform_runs_through_cli4_model() {
        let mut fixture = metadata_transform_fixture(CliSchemaFlavor::Cli4);

        let stats =
            transform_cli4_metadata(&mut fixture.image, &fixture.metadata, &fixture.cli_map)
                .unwrap();

        assert_fixture_was_transformed(&fixture.image, fixture.blob_start, stats);
    }

    #[test]
    fn cli4_metadata_transform_rejects_classic_model() {
        let mut fixture = metadata_transform_fixture(CliSchemaFlavor::Classic);

        let err = transform_cli4_metadata(&mut fixture.image, &fixture.metadata, &fixture.cli_map)
            .unwrap_err();

        assert!(matches!(
            err,
            Error::Malformed("CLI4 metadata transform: source metadata flavor mismatch")
        ));
    }
}
