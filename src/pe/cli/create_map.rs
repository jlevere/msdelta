//! Create-side CLI map producers.

use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::cli::metadata::CliMetadataModel;
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
    use crate::pe::cli::schema::{CliSchemaFlavor, HeapIndexWidths};

    fn pairs(table: &RiftTable) -> Vec<(i64, i64)> {
        table
            .entries
            .iter()
            .map(|entry| (entry.source, entry.target))
            .collect()
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

    fn metadata_with_strings(file_offset: usize, size: u32) -> CliMetadataModel {
        CliMetadataModel {
            flavor: CliSchemaFlavor::Classic,
            metadata_rva: 0,
            metadata_file_offset: 0,
            metadata_size: 0,
            version: "v4.0.30319".to_owned(),
            streams: CliStreamSet {
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
}
