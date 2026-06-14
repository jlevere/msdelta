//! CLI compression-rift producers.

use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::metadata::{
    CliMetadataBitstreamRecord, CliMetadataBitstreamStream, CliMetadataModel, CliStream,
};
use crate::pe::cli::schema::{column_width, table_schema, HeapIndexWidths};

const CLI_MAP_SOURCE_SENTINEL: i64 = u32::MAX as i64;

#[derive(Debug, Clone, Copy)]
pub(crate) struct CliTableWidthRiftLayout<'a> {
    pub(crate) table_id: u8,
    pub(crate) source_table_file_offset: i64,
    pub(crate) target_table_file_offset: i64,
    pub(crate) source_row_count: u32,
    pub(crate) source_row_size: u32,
    pub(crate) target_row_size: u32,
    pub(crate) source_row_counts: &'a [u32; 64],
    pub(crate) target_row_counts: &'a [u32; 64],
    pub(crate) source_heap_widths: HeapIndexWidths,
    pub(crate) target_heap_widths: HeapIndexWidths,
    pub(crate) source_widening_fill_offset: i64,
}

pub(crate) fn build_cli_heap_rift(
    source_heap_file_offset: usize,
    target_heap_file_offset: u32,
    heap_map: &RiftTable,
) -> RiftTable {
    let mut entries = Vec::new();
    append_cli_heap_rift_entries(
        &mut entries,
        source_heap_file_offset as i64,
        i64::from(target_heap_file_offset),
        heap_map,
    );
    sorted_rift(entries)
}

pub(crate) fn build_cli_heap_compression_rift(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) -> RiftTable {
    if target_metadata.is_empty() {
        return empty_rift();
    }

    let mut entries = Vec::new();
    append_cli_heap_compression_rift_entries(
        &mut entries,
        source_metadata,
        target_metadata,
        cli_map,
    );
    sorted_rift(entries)
}

pub(crate) fn build_cli_table_rift(
    source_table_file_offset: usize,
    target_table_file_offset: usize,
    source_row_size: u32,
    target_row_size: u32,
    table_map: &RiftTable,
) -> RiftTable {
    let mut entries = Vec::new();
    append_cli_table_rift_entries(
        &mut entries,
        source_table_file_offset as i64,
        target_table_file_offset as i64,
        source_row_size,
        target_row_size,
        table_map,
    );
    sorted_rift(entries)
}

/// Build only the table-rift entries caused by metadata column width changes.
///
/// Widened target columns need a source-side fill offset for the inserted bytes.
/// The full native path derives that from the transformed source buffer, so the
/// caller must supply it instead of inferring it from metadata bounds.
pub(crate) fn build_cli_table_width_hole_rift(
    layout: CliTableWidthRiftLayout<'_>,
    table_map: &RiftTable,
) -> RiftTable {
    let mut entries = Vec::new();
    append_cli_table_width_hole_entries(&mut entries, layout, table_map);
    sorted_rift(entries)
}

pub(crate) fn build_cli_compression_rift(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) -> RiftTable {
    build_cli_compression_rift_impl(source_metadata, target_metadata, cli_map, None)
}

pub(crate) fn build_cli_compression_rift_with_source_fill_offset(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    source_widening_fill_offset: i64,
) -> RiftTable {
    build_cli_compression_rift_impl(
        source_metadata,
        target_metadata,
        cli_map,
        Some(source_widening_fill_offset),
    )
}

fn build_cli_compression_rift_impl(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
    source_widening_fill_offset: Option<i64>,
) -> RiftTable {
    if target_metadata.is_empty() {
        return empty_rift();
    }

    let mut entries = Vec::new();
    append_cli_heap_compression_rift_entries(
        &mut entries,
        source_metadata,
        target_metadata,
        cli_map,
    );
    append_optional_guid_table(
        &mut entries,
        source_metadata.streams.guid,
        target_metadata.streams.guid,
        &cli_map.guid,
    );

    for table_id in 0..64usize {
        let Some(source_table_file_offset) = source_metadata.table_file_offsets[table_id] else {
            continue;
        };
        let Some(target_table_file_offset) = target_metadata.table_file_offsets[table_id] else {
            continue;
        };
        append_cli_table_rift_entries(
            &mut entries,
            source_table_file_offset as i64,
            target_table_file_offset as i64,
            source_metadata.row_sizes[table_id],
            target_metadata.row_sizes[table_id],
            &cli_map.tables[table_id],
        );
        if let Some(source_widening_fill_offset) = source_widening_fill_offset {
            append_cli_table_width_hole_entries(
                &mut entries,
                CliTableWidthRiftLayout {
                    table_id: table_id as u8,
                    source_table_file_offset: source_table_file_offset as i64,
                    target_table_file_offset: target_table_file_offset as i64,
                    source_row_count: source_metadata.row_counts[table_id],
                    source_row_size: source_metadata.row_sizes[table_id],
                    target_row_size: target_metadata.row_sizes[table_id],
                    source_row_counts: &source_metadata.row_counts,
                    target_row_counts: &target_metadata.row_counts,
                    source_heap_widths: source_metadata.heap_widths,
                    target_heap_widths: target_metadata.heap_widths,
                    source_widening_fill_offset,
                },
                &cli_map.tables[table_id],
            );
        }
    }
    sorted_rift(entries)
}

fn append_cli_heap_compression_rift_entries(
    entries: &mut Vec<RiftEntry>,
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataBitstreamRecord,
    cli_map: &CliMapModel,
) {
    append_optional_heap_stream(
        entries,
        source_metadata.streams.strings,
        target_metadata.streams.strings,
        &cli_map.strings,
    );
    append_optional_heap_stream(
        entries,
        source_metadata.streams.user_strings,
        target_metadata.streams.user_strings,
        &cli_map.user_strings,
    );
    append_optional_heap_stream(
        entries,
        source_metadata.streams.blob,
        target_metadata.streams.blob,
        &cli_map.blob,
    );
}

fn append_optional_heap_stream(
    entries: &mut Vec<RiftEntry>,
    source_stream: Option<CliStream>,
    target_stream: CliMetadataBitstreamStream,
    heap_map: &RiftTable,
) {
    let Some(source_stream) = source_stream else {
        return;
    };
    if target_stream.size == 0 {
        return;
    }
    append_cli_heap_rift_entries(
        entries,
        source_stream.file_offset as i64,
        i64::from(target_stream.file_offset),
        heap_map,
    );
}

fn append_cli_heap_rift_entries(
    entries: &mut Vec<RiftEntry>,
    source_heap_file_offset: i64,
    target_heap_file_offset: i64,
    heap_map: &RiftTable,
) {
    if heap_map.entries.is_empty() {
        entries.push(RiftEntry {
            source: target_heap_file_offset,
            target: source_heap_file_offset,
        });
        return;
    }

    for entry in &heap_map.entries {
        if entry.source > CLI_MAP_SOURCE_SENTINEL {
            break;
        }
        entries.push(RiftEntry {
            source: target_heap_file_offset.wrapping_add(entry.target),
            target: source_heap_file_offset.wrapping_add(entry.source),
        });
    }
}

fn append_optional_guid_table(
    entries: &mut Vec<RiftEntry>,
    source_stream: Option<CliStream>,
    target_stream: CliMetadataBitstreamStream,
    guid_map: &RiftTable,
) {
    let Some(source_stream) = source_stream else {
        return;
    };
    if target_stream.size == 0 {
        return;
    }
    append_cli_table_rift_entries(
        entries,
        source_stream.file_offset as i64,
        i64::from(target_stream.file_offset),
        16,
        16,
        guid_map,
    );
}

fn append_cli_table_rift_entries(
    entries: &mut Vec<RiftEntry>,
    source_table_file_offset: i64,
    target_table_file_offset: i64,
    source_row_size: u32,
    target_row_size: u32,
    table_map: &RiftTable,
) {
    if source_row_size == 0 || target_row_size == 0 {
        return;
    }

    if table_map.entries.is_empty() {
        entries.push(RiftEntry {
            source: target_table_file_offset,
            target: source_table_file_offset,
        });
        return;
    }

    for entry in &table_map.entries {
        if entry.source > CLI_MAP_SOURCE_SENTINEL {
            break;
        }
        let source = table_row_file_offset(
            source_table_file_offset,
            i64::from(source_row_size),
            entry.source,
        );
        let target = table_row_file_offset(
            target_table_file_offset,
            i64::from(target_row_size),
            entry.target,
        );
        entries.push(RiftEntry {
            source: target,
            target: source,
        });
    }
}

fn append_cli_table_width_hole_entries(
    entries: &mut Vec<RiftEntry>,
    layout: CliTableWidthRiftLayout<'_>,
    table_map: &RiftTable,
) {
    if layout.source_row_count == 0 || layout.source_row_size == 0 || layout.target_row_size == 0 {
        return;
    }

    let Some(schema) = table_schema(layout.table_id) else {
        return;
    };

    let mut source_column_offset = 0i64;
    let mut target_column_offset = 0i64;
    for (column_index, column) in schema.columns.iter().enumerate() {
        let source_width = column_width(
            column.kind,
            layout.source_row_counts,
            layout.source_heap_widths,
        );
        let target_width = column_width(
            column.kind,
            layout.target_row_counts,
            layout.target_heap_widths,
        );
        let has_following_column = column_index + 1 < schema.columns.len();

        match (source_width, target_width) {
            (2, 4) => append_cli_table_widened_column_entries(
                entries,
                layout,
                table_map,
                source_column_offset,
                target_column_offset,
                has_following_column,
            ),
            (4, 2) if has_following_column => append_cli_table_narrowed_column_entries(
                entries,
                layout,
                table_map,
                source_column_offset,
                target_column_offset,
            ),
            _ => {}
        }

        source_column_offset = source_column_offset.wrapping_add(i64::from(source_width));
        target_column_offset = target_column_offset.wrapping_add(i64::from(target_width));
    }
}

fn append_cli_table_widened_column_entries(
    entries: &mut Vec<RiftEntry>,
    layout: CliTableWidthRiftLayout<'_>,
    table_map: &RiftTable,
    source_column_offset: i64,
    target_column_offset: i64,
    has_following_column: bool,
) {
    for source_rid in 1..=layout.source_row_count {
        let source_rid = i64::from(source_rid);
        let target_rid = map_cli_table_rid(table_map, source_rid);
        let source_column_file_offset = table_row_file_offset(
            layout.source_table_file_offset,
            i64::from(layout.source_row_size),
            source_rid,
        )
        .wrapping_add(source_column_offset);
        let target_column_file_offset = table_row_file_offset(
            layout.target_table_file_offset,
            i64::from(layout.target_row_size),
            target_rid,
        )
        .wrapping_add(target_column_offset);

        entries.push(RiftEntry {
            source: target_column_file_offset.wrapping_add(2),
            target: layout.source_widening_fill_offset,
        });
        if has_following_column {
            entries.push(RiftEntry {
                source: target_column_file_offset.wrapping_add(4),
                target: source_column_file_offset.wrapping_add(2),
            });
        }
    }
}

fn append_cli_table_narrowed_column_entries(
    entries: &mut Vec<RiftEntry>,
    layout: CliTableWidthRiftLayout<'_>,
    table_map: &RiftTable,
    source_column_offset: i64,
    target_column_offset: i64,
) {
    for source_rid in 1..=layout.source_row_count {
        let source_rid = i64::from(source_rid);
        let target_rid = map_cli_table_rid(table_map, source_rid);
        let source_column_file_offset = table_row_file_offset(
            layout.source_table_file_offset,
            i64::from(layout.source_row_size),
            source_rid,
        )
        .wrapping_add(source_column_offset);
        let target_column_file_offset = table_row_file_offset(
            layout.target_table_file_offset,
            i64::from(layout.target_row_size),
            target_rid,
        )
        .wrapping_add(target_column_offset);

        entries.push(RiftEntry {
            source: target_column_file_offset.wrapping_add(2),
            target: source_column_file_offset.wrapping_add(4),
        });
    }
}

fn map_cli_table_rid(table_map: &RiftTable, source_rid: i64) -> i64 {
    if table_map.entries.is_empty() {
        return source_rid;
    }

    let entry = match table_map
        .entries
        .binary_search_by_key(&source_rid, |entry| entry.source)
    {
        Ok(index) => table_map.entries[index],
        Err(0) => *table_map
            .entries
            .last()
            .expect("non-empty table map should have a last entry"),
        Err(index) => table_map.entries[index - 1],
    };
    source_rid.wrapping_add(entry.target.wrapping_sub(entry.source))
}

fn table_row_file_offset(table_file_offset: i64, row_size: i64, rid: i64) -> i64 {
    if rid <= 0 {
        table_file_offset.wrapping_add(rid)
    } else {
        table_file_offset.wrapping_add(rid.wrapping_sub(1).wrapping_mul(row_size))
    }
}

fn sorted_rift(mut entries: Vec<RiftEntry>) -> RiftTable {
    entries.sort_by_key(|entry| entry.source);
    RiftTable { entries }
}

const fn empty_rift() -> RiftTable {
    RiftTable {
        entries: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cli::metadata::{
        parse_cli_metadata_from_pe, CliMetadataBitstreamStream, CliMetadataBitstreamStreams,
        CliStreamSet,
    };
    use crate::pe::cli::schema::{row_size, CliSchemaFlavor, HeapIndexWidths};
    use std::path::PathBuf;

    const MANAGED_NATIVE_CASES: &[&str] = &[
        "cli-const-string",
        "cli-add-method",
        "cli-generics-signature",
        "cli-custom-attribute",
        "cli-resource",
        "cli-platform-x64",
    ];

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    fn pairs(table: &RiftTable) -> Vec<(i64, i64)> {
        table
            .entries
            .iter()
            .map(|entry| (entry.source, entry.target))
            .collect()
    }

    fn eval(table: &RiftTable, target_file_offset: i64) -> i64 {
        target_file_offset.wrapping_add(table.map(target_file_offset))
    }

    fn managed_native_corpus_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atoms/ManagedNativeCorpus"
        ))
    }

    const fn narrow_heap_widths() -> HeapIndexWidths {
        HeapIndexWidths {
            strings: 2,
            guid: 2,
            blob: 2,
        }
    }

    #[test]
    fn heap_rift_empty_map_adds_base_mapping() {
        let table = build_cli_heap_rift(0x1000, 0x3000, &rift(&[]));

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000)]);
        assert_eq!(eval(&table, 0x3010), 0x1010);
    }

    #[test]
    fn heap_rift_converts_heap_relative_map_to_file_offsets() {
        let table =
            build_cli_heap_rift(0x1000, 0x3000, &rift(&[(0, 0), (0x64, 0x6a), (0x74, 0x85)]));

        assert_eq!(
            pairs(&table),
            vec![(0x3000, 0x1000), (0x306a, 0x1064), (0x3085, 0x1074)]
        );
        assert_eq!(eval(&table, 0x306a), 0x1064);
        assert_eq!(eval(&table, 0x3070), 0x106a);
    }

    #[test]
    fn heap_rift_stops_at_native_source_sentinel() {
        let table = build_cli_heap_rift(
            0x1000,
            0x3000,
            &rift(&[(0, 0), (0x20, 0x30), (0x1_0000_0000, 0x40)]),
        );

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000), (0x3030, 0x1020)]);
    }

    #[test]
    fn table_rift_empty_map_adds_base_mapping() {
        let table = build_cli_table_rift(0x1000, 0x3000, 10, 10, &rift(&[]));

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000)]);
        assert_eq!(eval(&table, 0x3005), 0x1005);
    }

    #[test]
    fn table_rift_converts_rids_to_row_file_offsets() {
        let table = build_cli_table_rift(0x1000, 0x3000, 10, 12, &rift(&[(0, 0), (3, 4), (7, 8)]));

        assert_eq!(
            pairs(&table),
            vec![(0x3000, 0x1000), (0x3024, 0x1014), (0x3054, 0x103c)]
        );
        assert_eq!(eval(&table, 0x3026), 0x1016);
    }

    #[test]
    fn table_rift_stops_at_native_source_sentinel() {
        let table = build_cli_table_rift(
            0x1000,
            0x3000,
            10,
            10,
            &rift(&[(0, 0), (2, 4), (0x1_0000_0000, 9)]),
        );

        assert_eq!(pairs(&table), vec![(0x3000, 0x1000), (0x301e, 0x100a)]);
    }

    #[test]
    fn table_width_hole_rift_adds_widened_nonterminal_column_entries() {
        let heap_widths = narrow_heap_widths();
        let mut source_row_counts = [0; 64];
        let mut target_row_counts = [0; 64];
        source_row_counts[0x02] = 3;
        target_row_counts[0x02] = 4;
        target_row_counts[0x04] = 1 << 16;
        let source_row_size = row_size(0x02, &source_row_counts, heap_widths).unwrap() as u32;
        let target_row_size = row_size(0x02, &target_row_counts, heap_widths).unwrap() as u32;

        let table = build_cli_table_width_hole_rift(
            CliTableWidthRiftLayout {
                table_id: 0x02,
                source_table_file_offset: 0x1000,
                target_table_file_offset: 0x3000,
                source_row_count: source_row_counts[0x02],
                source_row_size,
                target_row_size,
                source_row_counts: &source_row_counts,
                target_row_counts: &target_row_counts,
                source_heap_widths: heap_widths,
                target_heap_widths: heap_widths,
                source_widening_fill_offset: 0x9000,
            },
            &rift(&[(0, 0), (2, 3)]),
        );

        assert_eq!(
            pairs(&table),
            vec![
                (0x300c, 0x9000),
                (0x300e, 0x100c),
                (0x302c, 0x9000),
                (0x302e, 0x101a),
                (0x303c, 0x9000),
                (0x303e, 0x1028),
            ]
        );
    }

    #[test]
    fn table_width_hole_rift_adds_narrowed_nonterminal_column_entries() {
        let heap_widths = narrow_heap_widths();
        let mut source_row_counts = [0; 64];
        let mut target_row_counts = [0; 64];
        source_row_counts[0x02] = 2;
        source_row_counts[0x04] = 1 << 16;
        target_row_counts[0x02] = 4;
        let source_row_size = row_size(0x02, &source_row_counts, heap_widths).unwrap() as u32;
        let target_row_size = row_size(0x02, &target_row_counts, heap_widths).unwrap() as u32;

        let table = build_cli_table_width_hole_rift(
            CliTableWidthRiftLayout {
                table_id: 0x02,
                source_table_file_offset: 0x1000,
                target_table_file_offset: 0x3000,
                source_row_count: source_row_counts[0x02],
                source_row_size,
                target_row_size,
                source_row_counts: &source_row_counts,
                target_row_counts: &target_row_counts,
                source_heap_widths: heap_widths,
                target_heap_widths: heap_widths,
                source_widening_fill_offset: 0x9000,
            },
            &rift(&[(0, 0), (2, 4)]),
        );

        assert_eq!(pairs(&table), vec![(0x300c, 0x100e), (0x3036, 0x101e)]);
    }

    #[test]
    fn table_width_hole_rift_uses_fill_without_resume_for_terminal_widening() {
        let heap_widths = narrow_heap_widths();
        let mut source_row_counts = [0; 64];
        let mut target_row_counts = [0; 64];
        source_row_counts[0x02] = 2;
        target_row_counts[0x02] = 2;
        target_row_counts[0x06] = 1 << 16;
        let source_row_size = row_size(0x02, &source_row_counts, heap_widths).unwrap() as u32;
        let target_row_size = row_size(0x02, &target_row_counts, heap_widths).unwrap() as u32;

        let table = build_cli_table_width_hole_rift(
            CliTableWidthRiftLayout {
                table_id: 0x02,
                source_table_file_offset: 0x1000,
                target_table_file_offset: 0x3000,
                source_row_count: source_row_counts[0x02],
                source_row_size,
                target_row_size,
                source_row_counts: &source_row_counts,
                target_row_counts: &target_row_counts,
                source_heap_widths: heap_widths,
                target_heap_widths: heap_widths,
                source_widening_fill_offset: 0x9000,
            },
            &rift(&[]),
        );

        assert_eq!(pairs(&table), vec![(0x300e, 0x9000), (0x301e, 0x9000)]);
    }

    #[test]
    fn table_width_hole_rift_skips_terminal_narrowing() {
        let heap_widths = narrow_heap_widths();
        let mut source_row_counts = [0; 64];
        let mut target_row_counts = [0; 64];
        source_row_counts[0x02] = 2;
        source_row_counts[0x06] = 1 << 16;
        target_row_counts[0x02] = 2;
        let source_row_size = row_size(0x02, &source_row_counts, heap_widths).unwrap() as u32;
        let target_row_size = row_size(0x02, &target_row_counts, heap_widths).unwrap() as u32;

        let table = build_cli_table_width_hole_rift(
            CliTableWidthRiftLayout {
                table_id: 0x02,
                source_table_file_offset: 0x1000,
                target_table_file_offset: 0x3000,
                source_row_count: source_row_counts[0x02],
                source_row_size,
                target_row_size,
                source_row_counts: &source_row_counts,
                target_row_counts: &target_row_counts,
                source_heap_widths: heap_widths,
                target_heap_widths: heap_widths,
                source_widening_fill_offset: 0x9000,
            },
            &rift(&[]),
        );

        assert!(table.entries.is_empty());
    }

    #[test]
    fn heap_compression_rift_composes_strings_user_strings_and_blob_streams() {
        let source_metadata = source_metadata_model();
        let target_metadata = target_metadata_record();
        let cli_map = CliMapModel {
            strings: rift(&[(0, 0), (0x20, 0x28)]),
            user_strings: rift(&[]),
            blob: rift(&[(0, 0), (0x10, 0x18)]),
            ..CliMapModel::default()
        };

        let table = build_cli_heap_compression_rift(&source_metadata, &target_metadata, &cli_map);

        assert_eq!(
            pairs(&table),
            vec![
                (0x6000, 0x5000),
                (0x6028, 0x5020),
                (0x6200, 0x5100),
                (0x6400, 0x5300),
                (0x6418, 0x5310),
            ]
        );
    }

    #[test]
    fn heap_compression_rift_is_empty_without_target_metadata() {
        let table = build_cli_heap_compression_rift(
            &source_metadata_model(),
            &CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic),
            &CliMapModel::default(),
        );

        assert!(table.entries.is_empty());
    }

    #[test]
    fn cli_compression_rift_composes_heap_guid_and_table_rifts() {
        let source_metadata = source_metadata_with_tables();
        let target_metadata = target_metadata_with_tables();
        let mut cli_map = CliMapModel {
            strings: rift(&[(0, 0), (0x20, 0x28)]),
            blob: rift(&[(0, 0), (0x10, 0x18)]),
            guid: rift(&[(0, 0), (2, 3)]),
            ..CliMapModel::default()
        };
        cli_map.tables[0x02] = rift(&[(0, 0), (2, 3)]);

        let table = build_cli_compression_rift(&source_metadata, &target_metadata, &cli_map);

        assert_eq!(
            pairs(&table),
            vec![
                (0x6000, 0x5000),
                (0x6028, 0x5020),
                (0x6200, 0x5100),
                (0x6400, 0x5300),
                (0x6418, 0x5310),
                (0x6500, 0x5400),
                (0x6520, 0x5410),
                (0x6600, 0x5500),
                (0x6618, 0x550a),
            ]
        );
    }

    #[test]
    fn cli_compression_rift_with_source_fill_offset_composes_width_holes() {
        let heap_widths = narrow_heap_widths();
        let mut source_metadata = source_metadata_model();
        source_metadata.heap_widths = heap_widths;
        source_metadata.valid_table_mask = 1 << 0x02;
        source_metadata.row_counts[0x02] = 2;
        source_metadata.row_sizes[0x02] =
            row_size(0x02, &source_metadata.row_counts, heap_widths).unwrap() as u32;
        source_metadata.table_file_offsets[0x02] = Some(0x5500);

        let mut target_metadata = target_metadata_record();
        target_metadata.streams.strings.size = 0;
        target_metadata.streams.user_strings.size = 0;
        target_metadata.streams.blob.size = 0;
        target_metadata.heap_widths = heap_widths;
        target_metadata.valid_table_mask = (1 << 0x02) | (1 << 0x04);
        target_metadata.row_counts[0x02] = 2;
        target_metadata.row_counts[0x04] = 1 << 16;
        target_metadata.row_sizes[0x02] =
            row_size(0x02, &target_metadata.row_counts, heap_widths).unwrap() as u32;
        target_metadata.table_file_offsets[0x02] = Some(0x6600);

        let table = build_cli_compression_rift_with_source_fill_offset(
            &source_metadata,
            &target_metadata,
            &CliMapModel::default(),
            0x9900,
        );

        assert_eq!(
            pairs(&table),
            vec![
                (0x6600, 0x5500),
                (0x660c, 0x9900),
                (0x660e, 0x550c),
                (0x661c, 0x9900),
                (0x661e, 0x551a),
            ]
        );
    }

    #[test]
    fn heap_compression_rift_builds_from_managed_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_heap_rift = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse classic managed preprocess");
            if !preprocess.target_info.has_target_metadata() {
                continue;
            }
            let source_metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");

            let table = build_cli_heap_compression_rift(
                &source_metadata,
                &preprocess.target_info.target_metadata,
                &preprocess.cli_map,
            );
            if table.entries.is_empty() {
                continue;
            }

            cases_with_heap_rift += 1;
            assert!(
                table
                    .entries
                    .windows(2)
                    .all(|window| window[0].source <= window[1].source),
                "{case}: heap compression rift should be sorted"
            );
            assert!(
                table
                    .entries
                    .iter()
                    .all(|entry| entry.source >= 0 && entry.target >= 0),
                "{case}: heap compression rift should stay in file-offset domain"
            );
        }

        assert!(
            cases_with_heap_rift > 0,
            "managed corpus should include at least one non-empty heap compression rift"
        );
    }

    #[test]
    fn cli_compression_rift_builds_from_managed_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_cli_rift = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse classic managed preprocess");
            if !preprocess.target_info.has_target_metadata() {
                continue;
            }
            let source_metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");

            let table = build_cli_compression_rift(
                &source_metadata,
                &preprocess.target_info.target_metadata,
                &preprocess.cli_map,
            );
            if table.entries.is_empty() {
                continue;
            }

            cases_with_cli_rift += 1;
            assert!(
                table
                    .entries
                    .windows(2)
                    .all(|window| window[0].source <= window[1].source),
                "{case}: CLI compression rift should be sorted"
            );
            assert!(
                table
                    .entries
                    .iter()
                    .all(|entry| entry.source >= 0 && entry.target >= 0),
                "{case}: CLI compression rift should stay in file-offset domain"
            );
        }

        assert!(
            cases_with_cli_rift > 0,
            "managed corpus should include at least one non-empty CLI compression rift"
        );
    }

    fn source_metadata_model() -> CliMetadataModel {
        CliMetadataModel {
            flavor: CliSchemaFlavor::Classic,
            metadata_rva: 0x2000,
            metadata_file_offset: 0x4000,
            metadata_size: 0x1000,
            version: "v4.0.30319".to_owned(),
            streams: CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0x1000,
                    file_offset: 0x5000,
                    size: 0x80,
                }),
                user_strings: Some(CliStream {
                    metadata_offset: 0x1100,
                    file_offset: 0x5100,
                    size: 0x40,
                }),
                blob: Some(CliStream {
                    metadata_offset: 0x1300,
                    file_offset: 0x5300,
                    size: 0x60,
                }),
                guid: None,
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: 0x4000,
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

    fn target_metadata_record() -> CliMetadataBitstreamRecord {
        CliMetadataBitstreamRecord {
            flavor: CliSchemaFlavor::Classic,
            present: true,
            metadata_file_offset: 0x5000,
            metadata_size: 0x1200,
            metadata_rva: 0x3000,
            stream_count: 5,
            stream_headers_end: 0x100,
            streams: CliMetadataBitstreamStreams {
                strings: CliMetadataBitstreamStream {
                    file_offset: 0x6000,
                    size: 0x90,
                },
                user_strings: CliMetadataBitstreamStream {
                    file_offset: 0x6200,
                    size: 0x40,
                },
                blob: CliMetadataBitstreamStream {
                    file_offset: 0x6400,
                    size: 0x80,
                },
                guid: CliMetadataBitstreamStream {
                    file_offset: 0,
                    size: 0,
                },
                tables: CliMetadataBitstreamStream {
                    file_offset: 0x5000,
                    size: 24,
                },
            },
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 0,
            row_counts: [0; 64],
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        }
    }

    fn source_metadata_with_tables() -> CliMetadataModel {
        let mut model = source_metadata_model();
        model.streams.guid = Some(CliStream {
            metadata_offset: 0x1400,
            file_offset: 0x5400,
            size: 0x20,
        });
        model.valid_table_mask = 1 << 0x02;
        model.row_counts[0x02] = 4;
        model.row_sizes[0x02] = 10;
        model.table_file_offsets[0x02] = Some(0x5500);
        model
    }

    fn target_metadata_with_tables() -> CliMetadataBitstreamRecord {
        let mut record = target_metadata_record();
        record.streams.guid = CliMetadataBitstreamStream {
            file_offset: 0x6500,
            size: 0x30,
        };
        record.valid_table_mask = 1 << 0x02;
        record.row_counts[0x02] = 5;
        record.row_sizes[0x02] = 12;
        record.table_file_offsets[0x02] = Some(0x6600);
        record
    }
}
