//! Create-side CLI map producers.

use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::cli::metadata::{CliColumnValue, CliMetadataModel};
use crate::pe::cli::schema::{table_schema, ColumnKind, HeapKind};
use crate::{Error, Result};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliStringsHeapMatchStats {
    pub(crate) source_strings: usize,
    pub(crate) target_strings: usize,
    pub(crate) matched_strings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliStringsHeapMap {
    pub(crate) rift: RiftTable,
    pub(crate) stats: CliStringsHeapMatchStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliBlobAndRvaMapStats {
    pub(crate) mapped_blob_columns: usize,
    pub(crate) mapped_rva_columns: usize,
    pub(crate) skipped_unmapped_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliBlobAndRvaMaps {
    pub(crate) blob: RiftTable,
    pub(crate) rvas: RiftTable,
    pub(crate) stats: CliBlobAndRvaMapStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliSequenceTableSpec {
    pub(crate) table_id: u8,
    pub(crate) child_name_column: &'static str,
    pub(crate) owner_table_id: u8,
    pub(crate) owner_list_column: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliSequenceTableMapStats {
    pub(crate) owner_sequences: usize,
    pub(crate) mapped_rows: usize,
    pub(crate) skipped_owner_rows: usize,
    pub(crate) missing_string_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliSequenceTableMap {
    pub(crate) table_id: u8,
    pub(crate) rift: RiftTable,
    pub(crate) stats: CliSequenceTableMapStats,
}

pub(crate) const CLI_SEQUENCE_TABLE_SPECS: &[CliSequenceTableSpec] = &[
    CliSequenceTableSpec {
        table_id: 0x04,
        child_name_column: "Name",
        owner_table_id: 0x02,
        owner_list_column: "FieldList",
    },
    CliSequenceTableSpec {
        table_id: 0x06,
        child_name_column: "Name",
        owner_table_id: 0x02,
        owner_list_column: "MethodList",
    },
    CliSequenceTableSpec {
        table_id: 0x08,
        child_name_column: "Name",
        owner_table_id: 0x06,
        owner_list_column: "ParamList",
    },
    CliSequenceTableSpec {
        table_id: 0x14,
        child_name_column: "Name",
        owner_table_id: 0x12,
        owner_list_column: "EventList",
    },
    CliSequenceTableSpec {
        table_id: 0x17,
        child_name_column: "Name",
        owner_table_id: 0x15,
        owner_list_column: "PropertyList",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StringsHeapEntry<'a> {
    offset: u32,
    value: &'a [u8],
}

pub(crate) fn build_cli_strings_heap_map_from_metadata(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
) -> Result<CliStringsHeapMap> {
    let Some(source_stream) = source_metadata.streams.strings else {
        return Ok(empty_strings_heap_map());
    };
    let Some(target_stream) = target_metadata.streams.strings else {
        return Ok(empty_strings_heap_map());
    };

    let source_end = source_stream
        .file_offset
        .checked_add(source_stream.size as usize)
        .ok_or(Error::Malformed("CLI #Strings heap: source range overflow"))?;
    let target_end = target_stream
        .file_offset
        .checked_add(target_stream.size as usize)
        .ok_or(Error::Malformed("CLI #Strings heap: target range overflow"))?;
    let source_heap = source_image
        .get(source_stream.file_offset..source_end)
        .ok_or(Error::Truncated)?;
    let target_heap = target_image
        .get(target_stream.file_offset..target_end)
        .ok_or(Error::Truncated)?;

    build_cli_strings_heap_map(source_heap, target_heap)
}

pub(crate) fn build_cli_strings_heap_map(
    source_heap: &[u8],
    target_heap: &[u8],
) -> Result<CliStringsHeapMap> {
    let source_entries = parse_strings_heap_entries(source_heap)?;
    let target_entries = parse_strings_heap_entries(target_heap)?;
    let mut target_offsets_by_value = BTreeMap::<&[u8], u32>::new();
    for entry in &target_entries {
        target_offsets_by_value
            .entry(entry.value)
            .or_insert(entry.offset);
    }

    let mut entries = Vec::new();
    if !source_entries.is_empty() || !target_entries.is_empty() {
        entries.push(RiftEntry {
            source: 0,
            target: 0,
        });
    }

    let mut matched_strings = 0usize;
    for source in &source_entries {
        let Some(&target_offset) = target_offsets_by_value.get(source.value) else {
            continue;
        };
        entries.push(RiftEntry {
            source: i64::from(source.offset),
            target: i64::from(target_offset),
        });
        matched_strings += 1;
    }

    entries.sort_by_key(|entry| entry.source);
    entries.dedup_by_key(|entry| entry.source);

    Ok(CliStringsHeapMap {
        rift: RiftTable { entries },
        stats: CliStringsHeapMatchStats {
            source_strings: source_entries.len(),
            target_strings: target_entries.len(),
            matched_strings,
        },
    })
}

pub(crate) fn build_cli_sequence_table_map(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
    strings_map: &RiftTable,
    owner_table_map: &RiftTable,
    child_table_map: &RiftTable,
    table_id: u8,
) -> Result<CliSequenceTableMap> {
    let spec = cli_sequence_table_spec(table_id)
        .ok_or(Error::Malformed("CLI sequence map: unsupported table"))?;
    let mut rift = child_table_map.clone();
    let mut stats = CliSequenceTableMapStats {
        owner_sequences: 0,
        mapped_rows: 0,
        skipped_owner_rows: 0,
        missing_string_rows: 0,
    };

    if owner_table_map.entries.is_empty() || child_table_map.entries.is_empty() {
        return Ok(CliSequenceTableMap {
            table_id,
            rift,
            stats,
        });
    }

    let source_owner_count = source_metadata.row_counts[spec.owner_table_id as usize];
    let target_owner_count = target_metadata.row_counts[spec.owner_table_id as usize];
    let source_child_count = source_metadata.row_counts[spec.table_id as usize];
    let target_child_count = target_metadata.row_counts[spec.table_id as usize];
    if source_owner_count == 0 || source_child_count == 0 || target_child_count == 0 {
        return Ok(CliSequenceTableMap {
            table_id,
            rift,
            stats,
        });
    }

    let mut target_names = vec![0u32; target_child_count as usize + 1];
    for target_rid in 1..=target_child_count {
        let row = target_metadata.table_row_by_id(target_image, spec.table_id, target_rid)?;
        target_names[target_rid as usize] =
            string_column_offset(row.column(spec.child_name_column)?)?;
    }

    for source_owner_rid in 1..=source_owner_count {
        let Some(target_owner_rid) = exact_rift_target_value(owner_table_map, source_owner_rid)
        else {
            stats.skipped_owner_rows += 1;
            continue;
        };
        if target_owner_rid == 0 || target_owner_rid > target_owner_count {
            stats.skipped_owner_rows += 1;
            continue;
        }

        let source_start = sequence_list_start(
            source_image,
            source_metadata,
            spec.owner_table_id,
            source_owner_rid,
            spec.owner_list_column,
        )?;
        let target_start = sequence_list_start(
            target_image,
            target_metadata,
            spec.owner_table_id,
            target_owner_rid,
            spec.owner_list_column,
        )?;
        let source_end = sequence_list_end(
            source_image,
            source_metadata,
            spec.owner_table_id,
            source_owner_rid,
            source_owner_count,
            source_child_count,
            spec.owner_list_column,
        )?;
        let target_end = sequence_list_end(
            target_image,
            target_metadata,
            spec.owner_table_id,
            target_owner_rid,
            target_owner_count,
            target_child_count,
            spec.owner_list_column,
        )?;

        if source_start == 0
            || target_start == 0
            || source_start >= source_end
            || target_start >= target_end
            || source_start > source_child_count
            || target_start > target_child_count
        {
            stats.skipped_owner_rows += 1;
            continue;
        }

        stats.owner_sequences += 1;
        for source_child_rid in source_start..source_end {
            if exact_rift_target_value(&rift, source_child_rid).is_some() {
                break;
            }

            let source_row =
                source_metadata.table_row_by_id(source_image, spec.table_id, source_child_rid)?;
            let source_name = string_column_offset(source_row.column(spec.child_name_column)?)?;
            let Some(target_name) = exact_rift_target_value(strings_map, source_name) else {
                stats.missing_string_rows += 1;
                continue;
            };

            for target_child_rid in target_start..target_end {
                if target_names[target_child_rid as usize] == target_name {
                    set_rift_entry(&mut rift, source_child_rid, target_child_rid);
                    target_names[target_child_rid as usize] = 0;
                    stats.mapped_rows += 1;
                    break;
                }
            }
        }
    }

    rift.entries.sort_by_key(|entry| entry.source);
    Ok(CliSequenceTableMap {
        table_id,
        rift,
        stats,
    })
}

pub(crate) fn build_cli_blob_and_rva_maps(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
    table_maps: &[RiftTable; 64],
) -> Result<CliBlobAndRvaMaps> {
    let mut blob_entries = vec![RiftEntry {
        source: 0,
        target: 0,
    }];
    let mut rva_entries = Vec::new();
    let mut stats = CliBlobAndRvaMapStats {
        mapped_blob_columns: 0,
        mapped_rva_columns: 0,
        skipped_unmapped_rows: 0,
    };

    for table_id in 0..64u8 {
        let Some(schema) = table_schema(table_id) else {
            continue;
        };
        let table_map = &table_maps[table_id as usize];
        if table_map.entries.is_empty() {
            continue;
        }

        let source_row_count = source_metadata.row_counts[table_id as usize];
        if source_row_count == 0 {
            continue;
        }
        let target_row_count = target_metadata.row_counts[table_id as usize];

        for source_rid in 1..=source_row_count {
            let Some(target_rid) = exact_table_target_rid(table_map, source_rid) else {
                stats.skipped_unmapped_rows += 1;
                continue;
            };
            if target_rid == 0 || target_rid > target_row_count {
                stats.skipped_unmapped_rows += 1;
                continue;
            }

            let source_row = source_metadata.table_row_by_id(source_image, table_id, source_rid)?;
            let target_row = target_metadata.table_row_by_id(target_image, table_id, target_rid)?;

            for (column_index, column) in schema.columns.iter().enumerate() {
                match column.kind {
                    ColumnKind::Heap(HeapKind::Blob) => {
                        let source_offset =
                            blob_column_offset(source_row.column_by_index(column_index)?)?;
                        let target_offset =
                            blob_column_offset(target_row.column_by_index(column_index)?)?;
                        if source_offset == 0 || target_offset == 0 {
                            continue;
                        }
                        blob_entries.push(RiftEntry {
                            source: i64::from(source_offset),
                            target: i64::from(target_offset),
                        });
                        stats.mapped_blob_columns += 1;
                    }
                    ColumnKind::Rva => {
                        let source_rva =
                            rva_column_value(source_row.column_by_index(column_index)?)?;
                        let target_rva =
                            rva_column_value(target_row.column_by_index(column_index)?)?;
                        if source_rva == 0 || target_rva == 0 {
                            continue;
                        }
                        rva_entries.push(RiftEntry {
                            source: i64::from(source_rva),
                            target: i64::from(target_rva),
                        });
                        stats.mapped_rva_columns += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    blob_entries.sort_by_key(|entry| entry.source);
    rva_entries.sort_by_key(|entry| entry.source);

    Ok(CliBlobAndRvaMaps {
        blob: RiftTable {
            entries: blob_entries,
        },
        rvas: RiftTable {
            entries: rva_entries,
        },
        stats,
    })
}

fn exact_table_target_rid(table_map: &RiftTable, source_rid: u32) -> Option<u32> {
    exact_rift_target_value(table_map, source_rid)
}

fn exact_rift_target_value(table_map: &RiftTable, source: u32) -> Option<u32> {
    let entry = table_map
        .entries
        .iter()
        .find(|entry| entry.source == i64::from(source))?;
    u32::try_from(entry.target).ok()
}

fn set_rift_entry(rift: &mut RiftTable, source: u32, target: u32) {
    if let Some(entry) = rift
        .entries
        .iter_mut()
        .find(|entry| entry.source == i64::from(source))
    {
        entry.target = i64::from(target);
    } else {
        rift.entries.push(RiftEntry {
            source: i64::from(source),
            target: i64::from(target),
        });
    }
}

fn blob_column_offset(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::Heap {
            kind: HeapKind::Blob,
            offset,
        } => Ok(offset),
        _ => Err(Error::Malformed("CLI map create: expected #Blob column")),
    }
}

fn string_column_offset(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::Heap {
            kind: HeapKind::Strings,
            offset,
        } => Ok(offset),
        _ => Err(Error::Malformed(
            "CLI sequence map: expected #Strings column",
        )),
    }
}

fn rva_column_value(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::Rva(value) => Ok(value),
        _ => Err(Error::Malformed("CLI map create: expected RVA column")),
    }
}

fn sequence_list_start(
    image: &[u8],
    metadata: &CliMetadataModel,
    owner_table_id: u8,
    owner_rid: u32,
    owner_list_column: &str,
) -> Result<u32> {
    let row = metadata.table_row_by_id(image, owner_table_id, owner_rid)?;
    table_column_rid(row.column(owner_list_column)?)
}

fn sequence_list_end(
    image: &[u8],
    metadata: &CliMetadataModel,
    owner_table_id: u8,
    owner_rid: u32,
    owner_count: u32,
    child_count: u32,
    owner_list_column: &str,
) -> Result<u32> {
    let child_end = child_count.checked_add(1).ok_or(Error::Malformed(
        "CLI sequence map: child row count overflow",
    ))?;
    if owner_rid >= owner_count {
        return Ok(child_end);
    }

    let next = sequence_list_start(
        image,
        metadata,
        owner_table_id,
        owner_rid + 1,
        owner_list_column,
    )?;
    if next == 0 || next > child_end {
        Ok(child_end)
    } else {
        Ok(next)
    }
}

fn table_column_rid(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::Table { rid, .. } => Ok(rid.map_or(0, |rid| rid.get())),
        _ => Err(Error::Malformed("CLI sequence map: expected table column")),
    }
}

fn cli_sequence_table_spec(table_id: u8) -> Option<CliSequenceTableSpec> {
    CLI_SEQUENCE_TABLE_SPECS
        .iter()
        .copied()
        .find(|spec| spec.table_id == table_id)
}

fn empty_strings_heap_map() -> CliStringsHeapMap {
    CliStringsHeapMap {
        rift: RiftTable {
            entries: Vec::new(),
        },
        stats: CliStringsHeapMatchStats {
            source_strings: 0,
            target_strings: 0,
            matched_strings: 0,
        },
    }
}

fn parse_strings_heap_entries(heap: &[u8]) -> Result<Vec<StringsHeapEntry<'_>>> {
    let mut entries = Vec::new();
    let mut cursor = 1usize;

    while cursor < heap.len() {
        let Some(relative_end) = heap[cursor..].iter().position(|&byte| byte == 0) else {
            return Err(Error::Malformed("CLI #Strings heap: unterminated value"));
        };
        if relative_end != 0 {
            entries.push(StringsHeapEntry {
                offset: cursor as u32,
                value: &heap[cursor..cursor + relative_end],
            });
        }
        cursor = cursor
            .checked_add(relative_end)
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::Malformed("CLI #Strings heap: offset overflow"))?;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cli::metadata::{CliMetadataModel, CliStream, CliStreamSet};
    use crate::pe::cli::schema::{row_size, CliSchemaFlavor, HeapIndexWidths};

    fn pairs(table: &RiftTable) -> Vec<(i64, i64)> {
        table
            .entries
            .iter()
            .map(|entry| (entry.source, entry.target))
            .collect()
    }

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    #[test]
    fn strings_heap_map_matches_exact_values_by_offset() {
        let source = b"\0Alpha\0Beta\0Gamma\0";
        let target = b"\0Gamma\0Alpha\0Delta\0Beta\0";

        let map = build_cli_strings_heap_map(source, target).unwrap();

        assert_eq!(map.stats.source_strings, 3);
        assert_eq!(map.stats.target_strings, 4);
        assert_eq!(map.stats.matched_strings, 3);
        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 7), (7, 19), (12, 1)]);
    }

    #[test]
    fn strings_heap_map_uses_first_target_duplicate() {
        let source = b"\0Name\0";
        let target = b"\0Other\0Name\0Name\0";

        let map = build_cli_strings_heap_map(source, target).unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 7)]);
    }

    #[test]
    fn strings_heap_map_ignores_empty_interior_values() {
        let source = b"\0A\0\0B\0";
        let target = b"\0B\0A\0";

        let map = build_cli_strings_heap_map(source, target).unwrap();

        assert_eq!(map.stats.source_strings, 2);
        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 3), (4, 1)]);
    }

    #[test]
    fn strings_heap_map_rejects_unterminated_values() {
        assert!(matches!(
            build_cli_strings_heap_map(b"\0Name", b"\0Name\0"),
            Err(Error::Malformed("CLI #Strings heap: unterminated value"))
        ));
    }

    #[test]
    fn strings_heap_map_reads_heap_ranges_from_metadata() {
        let source = b"aaaa\0One\0Two\0zzzz".to_vec();
        let target = b"bbbb\0Two\0One\0yyyy".to_vec();
        let source_metadata = metadata_with_strings(4, 9);
        let target_metadata = metadata_with_strings(4, 9);

        let map = build_cli_strings_heap_map_from_metadata(
            &source,
            &source_metadata,
            &target,
            &target_metadata,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 5), (5, 1)]);
    }

    #[test]
    fn blob_and_rva_map_follows_exact_table_maps() {
        let heap_widths = narrow_heap_widths();
        let source_row_size = row_size(0x06, &method_rows(1), heap_widths).unwrap();
        let target_row_size = row_size(0x06, &method_rows(2), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u32(&mut source_image, 0x20, 0x2100);
        put_u16(&mut source_image, 0x2a, 1);
        put_u16(&mut source_image, 0x2c, 1);
        put_u32(&mut target_image, 0x30 + target_row_size, 0x2400);
        put_u16(&mut target_image, 0x30 + target_row_size + 10, 4);
        put_u16(&mut target_image, 0x30 + target_row_size + 12, 1);

        let source_metadata = metadata_with_table(0x06, 1, source_row_size as u32, 0x20);
        let target_metadata = metadata_with_table(0x06, 2, target_row_size as u32, 0x30);
        let mut table_maps = empty_table_maps();
        table_maps[0x06] = rift(&[(0, 0), (1, 2)]);

        let maps = build_cli_blob_and_rva_maps(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
            &table_maps,
        )
        .unwrap();

        assert_eq!(pairs(&maps.blob), vec![(0, 0), (1, 4)]);
        assert_eq!(pairs(&maps.rvas), vec![(0x2100, 0x2400)]);
        assert_eq!(maps.stats.mapped_blob_columns, 1);
        assert_eq!(maps.stats.mapped_rva_columns, 1);
        assert_eq!(maps.stats.skipped_unmapped_rows, 0);
    }

    #[test]
    fn blob_and_rva_map_skips_unmapped_and_zero_rows() {
        let heap_widths = narrow_heap_widths();
        let row_size = row_size(0x06, &method_rows(2), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u32(&mut source_image, 0x20, 0x2100);
        put_u16(&mut source_image, 0x2a, 1);
        put_u32(&mut source_image, 0x20 + row_size, 0x2200);
        put_u16(&mut source_image, 0x20 + row_size + 10, 7);
        put_u32(&mut target_image, 0x30, 0);
        put_u16(&mut target_image, 0x3a, 0);

        let source_metadata = metadata_with_table(0x06, 2, row_size as u32, 0x20);
        let target_metadata = metadata_with_table(0x06, 1, row_size as u32, 0x30);
        let mut table_maps = empty_table_maps();
        table_maps[0x06] = rift(&[(0, 0), (1, 1)]);

        let maps = build_cli_blob_and_rva_maps(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
            &table_maps,
        )
        .unwrap();

        assert_eq!(pairs(&maps.blob), vec![(0, 0)]);
        assert!(maps.rvas.entries.is_empty());
        assert_eq!(maps.stats.mapped_blob_columns, 0);
        assert_eq!(maps.stats.mapped_rva_columns, 0);
        assert_eq!(maps.stats.skipped_unmapped_rows, 1);
    }

    #[test]
    fn blob_and_rva_map_does_not_treat_plain_u32_as_rva() {
        let heap_widths = narrow_heap_widths();
        let mut row_counts = [0u32; 64];
        row_counts[0x02] = 1;
        let row_size = row_size(0x02, &row_counts, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u32(&mut source_image, 0x20, 0x1234);
        put_u32(&mut target_image, 0x30, 0x5678);

        let source_metadata = metadata_with_table(0x02, 1, row_size as u32, 0x20);
        let target_metadata = metadata_with_table(0x02, 1, row_size as u32, 0x30);
        let mut table_maps = empty_table_maps();
        table_maps[0x02] = rift(&[(0, 0), (1, 1)]);

        let maps = build_cli_blob_and_rva_maps(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
            &table_maps,
        )
        .unwrap();

        assert_eq!(pairs(&maps.blob), vec![(0, 0)]);
        assert!(maps.rvas.entries.is_empty());
    }

    #[test]
    fn blob_and_rva_map_rejects_truncated_rows() {
        let heap_widths = narrow_heap_widths();
        let row_size = row_size(0x06, &method_rows(1), heap_widths).unwrap();
        let source_image = vec![0u8; 0x24];
        let target_image = vec![0u8; 0x80];
        let source_metadata = metadata_with_table(0x06, 1, row_size as u32, 0x20);
        let target_metadata = metadata_with_table(0x06, 1, row_size as u32, 0x30);
        let mut table_maps = empty_table_maps();
        table_maps[0x06] = rift(&[(0, 0), (1, 1)]);

        assert!(matches!(
            build_cli_blob_and_rva_maps(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
                &table_maps,
            ),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn sequence_table_map_matches_children_by_owner_range_and_mapped_name() {
        let heap_widths = narrow_heap_widths();
        let source_type_rows = typedef_rows(1);
        let source_method_rows = method_rows(2);
        let target_type_rows = typedef_rows(1);
        let target_method_rows = method_rows(2);
        let type_row_size = row_size(0x02, &source_type_rows, heap_widths).unwrap();
        let method_row_size = row_size(0x06, &source_method_rows, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x100];
        let mut target_image = vec![0u8; 0x140];

        put_u16(&mut source_image, 0x2c, 1);
        put_u16(&mut target_image, 0x6c, 1);
        put_u16(&mut source_image, 0x88, 10);
        put_u16(&mut source_image, 0x88 + method_row_size, 20);
        put_u16(&mut target_image, 0xa8, 200);
        put_u16(&mut target_image, 0xa8 + method_row_size, 100);

        let source_metadata = metadata_with_tables(&[
            (0x02, 1, type_row_size as u32, 0x20),
            (0x06, 2, method_row_size as u32, 0x80),
        ]);
        let target_metadata = metadata_with_tables(&[
            (
                0x02,
                1,
                row_size(0x02, &target_type_rows, heap_widths).unwrap() as u32,
                0x60,
            ),
            (
                0x06,
                2,
                row_size(0x06, &target_method_rows, heap_widths).unwrap() as u32,
                0xa0,
            ),
        ]);

        let map = build_cli_sequence_table_map(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
            &rift(&[(0, 0), (10, 100), (20, 200)]),
            &rift(&[(0, 0), (1, 1)]),
            &rift(&[(0, 0)]),
            0x06,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 2), (2, 1)]);
        assert_eq!(map.stats.owner_sequences, 1);
        assert_eq!(map.stats.mapped_rows, 2);
        assert_eq!(map.stats.skipped_owner_rows, 0);
    }

    #[test]
    fn sequence_table_map_stops_when_child_row_is_already_mapped() {
        let heap_widths = narrow_heap_widths();
        let type_row_size = row_size(0x02, &typedef_rows(1), heap_widths).unwrap();
        let method_row_size = row_size(0x06, &method_rows(2), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x100];
        let mut target_image = vec![0u8; 0x140];

        put_u16(&mut source_image, 0x2c, 1);
        put_u16(&mut target_image, 0x6c, 1);
        put_u16(&mut source_image, 0x88, 10);
        put_u16(&mut source_image, 0x88 + method_row_size, 20);
        put_u16(&mut target_image, 0xa8, 100);
        put_u16(&mut target_image, 0xa8 + method_row_size, 200);

        let source_metadata = metadata_with_tables(&[
            (0x02, 1, type_row_size as u32, 0x20),
            (0x06, 2, method_row_size as u32, 0x80),
        ]);
        let target_metadata = metadata_with_tables(&[
            (0x02, 1, type_row_size as u32, 0x60),
            (0x06, 2, method_row_size as u32, 0xa0),
        ]);

        let map = build_cli_sequence_table_map(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
            &rift(&[(0, 0), (10, 100), (20, 200)]),
            &rift(&[(0, 0), (1, 1)]),
            &rift(&[(0, 0), (1, 1)]),
            0x06,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 1)]);
        assert_eq!(map.stats.mapped_rows, 0);
    }

    #[test]
    fn sequence_table_map_tracks_missing_string_mappings() {
        let heap_widths = narrow_heap_widths();
        let type_row_size = row_size(0x02, &typedef_rows(1), heap_widths).unwrap();
        let method_row_size = row_size(0x06, &method_rows(1), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x100];
        let mut target_image = vec![0u8; 0x120];

        put_u16(&mut source_image, 0x2c, 1);
        put_u16(&mut target_image, 0x6c, 1);
        put_u16(&mut source_image, 0x88, 10);
        put_u16(&mut target_image, 0xa8, 100);

        let source_metadata = metadata_with_tables(&[
            (0x02, 1, type_row_size as u32, 0x20),
            (0x06, 1, method_row_size as u32, 0x80),
        ]);
        let target_metadata = metadata_with_tables(&[
            (0x02, 1, type_row_size as u32, 0x60),
            (0x06, 1, method_row_size as u32, 0xa0),
        ]);

        let map = build_cli_sequence_table_map(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
            &rift(&[(0, 0)]),
            &rift(&[(0, 0), (1, 1)]),
            &rift(&[(0, 0)]),
            0x06,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0)]);
        assert_eq!(map.stats.missing_string_rows, 1);
    }

    fn metadata_with_strings(file_offset: usize, size: u32) -> CliMetadataModel {
        metadata_with_streams(
            CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0,
                    file_offset,
                    size,
                }),
                user_strings: None,
                blob: None,
                guid: None,
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: 0,
                    size: 0,
                },
            },
            [0; 64],
            [0; 64],
            [None; 64],
        )
    }

    fn metadata_with_table(
        table_id: usize,
        row_count: u32,
        row_size: u32,
        table_file_offset: usize,
    ) -> CliMetadataModel {
        let mut row_counts = [0u32; 64];
        row_counts[table_id] = row_count;
        let mut row_sizes = [0u32; 64];
        row_sizes[table_id] = row_size;
        let mut table_file_offsets = [None; 64];
        table_file_offsets[table_id] = Some(table_file_offset);

        metadata_with_streams(
            CliStreamSet {
                strings: None,
                user_strings: None,
                blob: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0x60,
                    size: 0x10,
                }),
                guid: None,
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: table_file_offset,
                    size: row_count * row_size,
                },
            },
            row_counts,
            row_sizes,
            table_file_offsets,
        )
    }

    fn metadata_with_tables(tables: &[(usize, u32, u32, usize)]) -> CliMetadataModel {
        let mut row_counts = [0u32; 64];
        let mut row_sizes = [0u32; 64];
        let mut table_file_offsets = [None; 64];
        let mut tables_size = 0u32;
        let mut tables_start = usize::MAX;
        for &(table_id, row_count, row_size, table_file_offset) in tables {
            row_counts[table_id] = row_count;
            row_sizes[table_id] = row_size;
            table_file_offsets[table_id] = Some(table_file_offset);
            tables_size = tables_size.saturating_add(row_count.saturating_mul(row_size));
            tables_start = tables_start.min(table_file_offset);
        }

        metadata_with_streams(
            CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0,
                    size: 0,
                }),
                user_strings: None,
                blob: None,
                guid: None,
                tables: CliStream {
                    metadata_offset: 0,
                    file_offset: tables_start,
                    size: tables_size,
                },
            },
            row_counts,
            row_sizes,
            table_file_offsets,
        )
    }

    fn metadata_with_streams(
        streams: CliStreamSet,
        row_counts: [u32; 64],
        row_sizes: [u32; 64],
        table_file_offsets: [Option<usize>; 64],
    ) -> CliMetadataModel {
        CliMetadataModel {
            flavor: CliSchemaFlavor::Classic,
            metadata_rva: 0,
            metadata_file_offset: 0,
            metadata_size: 0,
            version: "v4.0.30319".to_owned(),
            streams,
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 0,
            sorted_table_mask: 0,
            row_counts,
            row_sizes,
            table_file_offsets,
        }
    }

    const fn narrow_heap_widths() -> HeapIndexWidths {
        HeapIndexWidths {
            strings: 2,
            guid: 2,
            blob: 2,
        }
    }

    fn method_rows(row_count: u32) -> [u32; 64] {
        let mut row_counts = [0u32; 64];
        row_counts[0x06] = row_count;
        row_counts
    }

    fn typedef_rows(row_count: u32) -> [u32; 64] {
        let mut row_counts = [0u32; 64];
        row_counts[0x02] = row_count;
        row_counts
    }

    fn empty_table_maps() -> [RiftTable; 64] {
        std::array::from_fn(|_| rift(&[]))
    }

    fn put_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
