//! Create-side CLI map producers.

use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::cli::blob::read_compressed_u32;
use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::metadata::{CliColumnValue, CliMetadataModel};
use crate::pe::cli::schema::{
    coded_index_schema, table_schema, CliSchemaFlavor, ColumnKind, HeapKind,
};
use crate::{Error, Result};
use std::collections::{BTreeMap, VecDeque};

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
pub(crate) struct CliTableSeedStats {
    pub(crate) seeded_table_maps: usize,
    pub(crate) seeded_guid_map: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliTripletKeyColumn {
    MappedString(&'static str),
    MappedTable(&'static str),
    MappedCoded(&'static str),
    RawU16(&'static str),
    RawU32(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliTripletTableSpec {
    pub(crate) table_id: u8,
    pub(crate) key_columns: &'static [CliTripletKeyColumn],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliTripletTableMapStats {
    pub(crate) source_rows: usize,
    pub(crate) target_rows: usize,
    pub(crate) mapped_rows: usize,
    pub(crate) missing_source_key_rows: usize,
    pub(crate) missing_target_key_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliTripletTableMap {
    pub(crate) table_id: u8,
    pub(crate) rift: RiftTable,
    pub(crate) stats: CliTripletTableMapStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliMapRunStep {
    Triplet(u8),
    Sequence(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliMapFromPeStats {
    pub(crate) seeds: CliTableSeedStats,
    pub(crate) strings: CliStringsHeapMatchStats,
    pub(crate) user_strings: CliStringsHeapMatchStats,
    pub(crate) triplet_maps: Vec<CliTripletTableMapStatsByTable>,
    pub(crate) sequence_maps: Vec<CliSequenceTableMapStatsByTable>,
    pub(crate) blob_and_rva: CliBlobAndRvaMapStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliTripletTableMapStatsByTable {
    pub(crate) table_id: u8,
    pub(crate) stats: CliTripletTableMapStats,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliSequenceTableMapStatsByTable {
    pub(crate) table_id: u8,
    pub(crate) stats: CliSequenceTableMapStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliMapFromPeResult {
    pub(crate) cli_map: CliMapModel,
    pub(crate) rvas: RiftTable,
    pub(crate) stats: CliMapFromPeStats,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliTripletSpecialContext {
    None,
    TypeDef {
        source_enclosing_by_nested: Vec<Option<u32>>,
        target_enclosing_by_nested: Vec<Option<u32>>,
    },
    TypeRef,
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

pub(crate) const CLI_TRIPLET_TABLE_ORDER: &[u8] = &[
    0x20, 0x23, 0x00, 0x1a, 0x02, 0x01, 0x0a, 0x12, 0x15, 0x0b, 0x0d, 0x0e, 0x0f, 0x10, 0x18, 0x1c,
    0x1d, 0x26, 0x28, 0x2a, 0x2b, 0x2c, 0x0c,
];

pub(crate) const CLI_MAP_RUN_STEPS: &[CliMapRunStep] = &[
    CliMapRunStep::Triplet(0x20),
    CliMapRunStep::Triplet(0x23),
    CliMapRunStep::Triplet(0x00),
    CliMapRunStep::Triplet(0x1a),
    CliMapRunStep::Triplet(0x02),
    CliMapRunStep::Sequence(0x04),
    CliMapRunStep::Sequence(0x06),
    CliMapRunStep::Sequence(0x08),
    CliMapRunStep::Triplet(0x01),
    CliMapRunStep::Triplet(0x0a),
    CliMapRunStep::Triplet(0x12),
    CliMapRunStep::Sequence(0x14),
    CliMapRunStep::Triplet(0x15),
    CliMapRunStep::Sequence(0x17),
    CliMapRunStep::Triplet(0x0b),
    CliMapRunStep::Triplet(0x0d),
    CliMapRunStep::Triplet(0x0e),
    CliMapRunStep::Triplet(0x0f),
    CliMapRunStep::Triplet(0x10),
    CliMapRunStep::Triplet(0x18),
    CliMapRunStep::Triplet(0x1c),
    CliMapRunStep::Triplet(0x1d),
    CliMapRunStep::Triplet(0x26),
    CliMapRunStep::Triplet(0x28),
    CliMapRunStep::Triplet(0x2a),
    CliMapRunStep::Triplet(0x2b),
    CliMapRunStep::Triplet(0x2c),
    CliMapRunStep::Triplet(0x0c),
];

const TRIPLET_STRING_KEY_TAG: u32 = 0x8000_0000;

const TRIPLET_ASSEMBLY_KEYS: &[CliTripletKeyColumn] = &[CliTripletKeyColumn::MappedString("Name")];
const TRIPLET_ASSEMBLY_REF_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedString("Name")];
const TRIPLET_MODULE_KEYS: &[CliTripletKeyColumn] = &[CliTripletKeyColumn::MappedString("Name")];
const TRIPLET_MODULE_REF_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedString("Name")];
const TRIPLET_TYPE_DEF_KEYS: &[CliTripletKeyColumn] = &[
    CliTripletKeyColumn::MappedString("Name"),
    CliTripletKeyColumn::MappedString("Namespace"),
];
const TRIPLET_TYPE_REF_KEYS: &[CliTripletKeyColumn] = &[
    CliTripletKeyColumn::MappedString("Name"),
    CliTripletKeyColumn::MappedString("Namespace"),
];
const TRIPLET_MEMBER_REF_KEYS: &[CliTripletKeyColumn] = &[
    CliTripletKeyColumn::MappedString("Name"),
    CliTripletKeyColumn::MappedCoded("Class"),
];
const TRIPLET_EVENT_MAP_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedTable("Parent")];
const TRIPLET_PROPERTY_MAP_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedTable("Parent")];
const TRIPLET_CONSTANT_KEYS: &[CliTripletKeyColumn] = &[CliTripletKeyColumn::MappedCoded("Parent")];
const TRIPLET_FIELD_MARSHAL_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedCoded("Parent")];
const TRIPLET_DECL_SECURITY_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedCoded("Parent")];
const TRIPLET_CLASS_LAYOUT_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedTable("Parent")];
const TRIPLET_FIELD_LAYOUT_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedTable("Field")];
const TRIPLET_METHOD_SEMANTICS_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedTable("Method")];
const TRIPLET_IMPL_MAP_KEYS: &[CliTripletKeyColumn] = &[
    CliTripletKeyColumn::MappedString("ImportName"),
    CliTripletKeyColumn::MappedCoded("MemberForwarded"),
];
const TRIPLET_FIELD_RVA_KEYS: &[CliTripletKeyColumn] = &[CliTripletKeyColumn::MappedTable("Field")];
const TRIPLET_FILE_KEYS: &[CliTripletKeyColumn] = &[CliTripletKeyColumn::MappedString("Name")];
const TRIPLET_MANIFEST_RESOURCE_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedString("Name")];
const TRIPLET_GENERIC_PARAM_KEYS: &[CliTripletKeyColumn] = &[
    CliTripletKeyColumn::MappedString("Name"),
    CliTripletKeyColumn::MappedCoded("Owner"),
];
const TRIPLET_METHOD_SPEC_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedCoded("Method")];
const TRIPLET_GENERIC_PARAM_CONSTRAINT_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedTable("Owner")];
const TRIPLET_CUSTOM_ATTRIBUTE_KEYS: &[CliTripletKeyColumn] =
    &[CliTripletKeyColumn::MappedCoded("Parent")];

pub(crate) const CLI_TRIPLET_TABLE_SPECS: &[CliTripletTableSpec] = &[
    CliTripletTableSpec {
        table_id: 0x20,
        key_columns: TRIPLET_ASSEMBLY_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x23,
        key_columns: TRIPLET_ASSEMBLY_REF_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x00,
        key_columns: TRIPLET_MODULE_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x1a,
        key_columns: TRIPLET_MODULE_REF_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x02,
        key_columns: TRIPLET_TYPE_DEF_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x01,
        key_columns: TRIPLET_TYPE_REF_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x0a,
        key_columns: TRIPLET_MEMBER_REF_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x12,
        key_columns: TRIPLET_EVENT_MAP_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x15,
        key_columns: TRIPLET_PROPERTY_MAP_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x0b,
        key_columns: TRIPLET_CONSTANT_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x0d,
        key_columns: TRIPLET_FIELD_MARSHAL_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x0e,
        key_columns: TRIPLET_DECL_SECURITY_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x0f,
        key_columns: TRIPLET_CLASS_LAYOUT_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x10,
        key_columns: TRIPLET_FIELD_LAYOUT_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x18,
        key_columns: TRIPLET_METHOD_SEMANTICS_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x1c,
        key_columns: TRIPLET_IMPL_MAP_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x1d,
        key_columns: TRIPLET_FIELD_RVA_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x26,
        key_columns: TRIPLET_FILE_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x28,
        key_columns: TRIPLET_MANIFEST_RESOURCE_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x2a,
        key_columns: TRIPLET_GENERIC_PARAM_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x2b,
        key_columns: TRIPLET_METHOD_SPEC_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x2c,
        key_columns: TRIPLET_GENERIC_PARAM_CONSTRAINT_KEYS,
    },
    CliTripletTableSpec {
        table_id: 0x0c,
        key_columns: TRIPLET_CUSTOM_ATTRIBUTE_KEYS,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StringsHeapEntry<'a> {
    offset: u32,
    value: &'a [u8],
}

#[derive(Clone, Copy)]
pub(crate) struct CliMapInputs<'a> {
    source_image: &'a [u8],
    source_metadata: &'a CliMetadataModel,
    target_image: &'a [u8],
    target_metadata: &'a CliMetadataModel,
}

pub(crate) fn build_cli_map_from_metadata(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
) -> Result<CliMapFromPeResult> {
    let strings_map = build_cli_strings_heap_map_from_metadata(
        source_image,
        source_metadata,
        target_image,
        target_metadata,
    )?;
    let user_strings_map = build_cli_user_strings_heap_map_from_metadata(
        source_image,
        source_metadata,
        target_image,
        target_metadata,
    )?;

    let mut cli_map = CliMapModel {
        strings: strings_map.rift,
        user_strings: user_strings_map.rift,
        ..CliMapModel::default()
    };
    let seed_stats = seed_cli_map_tables(source_metadata, target_metadata, &mut cli_map);
    let mut triplet_maps = Vec::new();
    let mut sequence_maps = Vec::new();
    let inputs = CliMapInputs {
        source_image,
        source_metadata,
        target_image,
        target_metadata,
    };

    for step in CLI_MAP_RUN_STEPS {
        match *step {
            CliMapRunStep::Triplet(table_id) => {
                let spec = cli_triplet_table_spec(table_id)
                    .ok_or(Error::Malformed("CLI map create: unknown triplet step"))?;
                let table_map = build_cli_triplet_table_map(
                    inputs,
                    &cli_map.strings,
                    &cli_map.tables,
                    &cli_map.tables[table_id as usize],
                    spec,
                )?;
                cli_map.tables[table_id as usize] = table_map.rift;
                triplet_maps.push(CliTripletTableMapStatsByTable {
                    table_id,
                    stats: table_map.stats,
                });
            }
            CliMapRunStep::Sequence(table_id) => {
                let spec = cli_sequence_table_spec(table_id)
                    .ok_or(Error::Malformed("CLI map create: unknown sequence step"))?;
                let table_map = build_cli_sequence_table_map(
                    inputs,
                    &cli_map.strings,
                    &cli_map.tables[spec.owner_table_id as usize],
                    &cli_map.tables[table_id as usize],
                    table_id,
                )?;
                cli_map.tables[table_id as usize] = table_map.rift;
                sequence_maps.push(CliSequenceTableMapStatsByTable {
                    table_id,
                    stats: table_map.stats,
                });
            }
        }
    }

    let blob_and_rva_maps = build_cli_blob_and_rva_maps(
        source_image,
        source_metadata,
        target_image,
        target_metadata,
        &cli_map.tables,
    )?;
    cli_map.blob = blob_and_rva_maps.blob;
    reduce_cli_map_from_metadata(&mut cli_map);

    Ok(CliMapFromPeResult {
        cli_map,
        rvas: blob_and_rva_maps.rvas,
        stats: CliMapFromPeStats {
            seeds: seed_stats,
            strings: strings_map.stats,
            user_strings: user_strings_map.stats,
            triplet_maps,
            sequence_maps,
            blob_and_rva: blob_and_rva_maps.stats,
        },
    })
}

pub(crate) fn build_classic_cli_map_from_metadata(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
) -> Result<CliMapFromPeResult> {
    require_metadata_flavor(
        source_metadata,
        CliSchemaFlavor::Classic,
        "classic CLI map create: source metadata flavor mismatch",
    )?;
    require_metadata_flavor(
        target_metadata,
        CliSchemaFlavor::Classic,
        "classic CLI map create: target metadata flavor mismatch",
    )?;
    build_cli_map_from_metadata(source_image, source_metadata, target_image, target_metadata)
}

pub(crate) fn build_cli4_map_from_metadata(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
) -> Result<CliMapFromPeResult> {
    require_metadata_flavor(
        source_metadata,
        CliSchemaFlavor::Cli4,
        "CLI4 map create: source metadata flavor mismatch",
    )?;
    require_metadata_flavor(
        target_metadata,
        CliSchemaFlavor::Cli4,
        "CLI4 map create: target metadata flavor mismatch",
    )?;
    build_cli_map_from_metadata(source_image, source_metadata, target_image, target_metadata)
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

pub(crate) fn build_cli_user_strings_heap_map_from_metadata(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
) -> Result<CliStringsHeapMap> {
    let Some(source_stream) = source_metadata.streams.user_strings else {
        return Ok(empty_strings_heap_map());
    };
    let Some(target_stream) = target_metadata.streams.user_strings else {
        return Ok(empty_strings_heap_map());
    };

    let source_end = source_stream
        .file_offset
        .checked_add(source_stream.size as usize)
        .ok_or(Error::Malformed("CLI #US heap: source range overflow"))?;
    let target_end = target_stream
        .file_offset
        .checked_add(target_stream.size as usize)
        .ok_or(Error::Malformed("CLI #US heap: target range overflow"))?;
    let source_heap = source_image
        .get(source_stream.file_offset..source_end)
        .ok_or(Error::Truncated)?;
    let target_heap = target_image
        .get(target_stream.file_offset..target_end)
        .ok_or(Error::Truncated)?;

    build_cli_user_strings_heap_map(source_heap, target_heap)
}

pub(crate) fn build_cli_strings_heap_map(
    source_heap: &[u8],
    target_heap: &[u8],
) -> Result<CliStringsHeapMap> {
    let source_entries = parse_strings_heap_entries(source_heap)?;
    let target_entries = parse_strings_heap_entries(target_heap)?;
    build_cli_heap_map(
        &source_entries,
        &target_entries,
        !source_heap.is_empty() || !target_heap.is_empty(),
    )
}

pub(crate) fn build_cli_user_strings_heap_map(
    source_heap: &[u8],
    target_heap: &[u8],
) -> Result<CliStringsHeapMap> {
    let source_entries = parse_user_strings_heap_entries(source_heap)?;
    let target_entries = parse_user_strings_heap_entries(target_heap)?;
    build_cli_heap_map(
        &source_entries,
        &target_entries,
        !source_heap.is_empty() || !target_heap.is_empty(),
    )
}

fn build_cli_heap_map(
    source_entries: &[StringsHeapEntry<'_>],
    target_entries: &[StringsHeapEntry<'_>],
    include_zero_entry: bool,
) -> Result<CliStringsHeapMap> {
    let mut target_offsets_by_value = BTreeMap::<&[u8], u32>::new();
    for entry in target_entries {
        target_offsets_by_value
            .entry(entry.value)
            .or_insert(entry.offset);
    }

    let mut entries = Vec::new();
    if include_zero_entry {
        entries.push(RiftEntry {
            source: 0,
            target: 0,
        });
    }

    let mut matched_strings = 0usize;
    for source in source_entries {
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
    inputs: CliMapInputs<'_>,
    strings_map: &RiftTable,
    owner_table_map: &RiftTable,
    child_table_map: &RiftTable,
    table_id: u8,
) -> Result<CliSequenceTableMap> {
    let source_image = inputs.source_image;
    let source_metadata = inputs.source_metadata;
    let target_image = inputs.target_image;
    let target_metadata = inputs.target_metadata;
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

pub(crate) fn build_cli_triplet_table_map(
    inputs: CliMapInputs<'_>,
    strings_map: &RiftTable,
    table_maps: &[RiftTable; 64],
    initial_table_map: &RiftTable,
    spec: CliTripletTableSpec,
) -> Result<CliTripletTableMap> {
    let source_image = inputs.source_image;
    let source_metadata = inputs.source_metadata;
    let target_image = inputs.target_image;
    let target_metadata = inputs.target_metadata;
    let mut rift = initial_table_map.clone();
    let source_row_count = source_metadata.row_counts[spec.table_id as usize];
    let target_row_count = target_metadata.row_counts[spec.table_id as usize];
    let mut stats = CliTripletTableMapStats {
        source_rows: source_row_count as usize,
        target_rows: target_row_count as usize,
        mapped_rows: 0,
        missing_source_key_rows: 0,
        missing_target_key_rows: 0,
    };

    if initial_table_map.entries.is_empty() || source_row_count == 0 || target_row_count == 0 {
        return Ok(CliTripletTableMap {
            table_id: spec.table_id,
            rift,
            stats,
        });
    }

    let special_context = triplet_special_context(
        source_image,
        source_metadata,
        target_image,
        target_metadata,
        spec.table_id,
    )?;

    let mut targets_by_key = BTreeMap::<Vec<u32>, VecDeque<u32>>::new();
    for target_rid in 1..=target_row_count {
        let row = target_metadata.table_row_by_id(target_image, spec.table_id, target_rid)?;
        let Some(key) = triplet_target_key(row, target_rid, spec.key_columns, &special_context)?
        else {
            stats.missing_target_key_rows += 1;
            continue;
        };
        targets_by_key.entry(key).or_default().push_back(target_rid);
    }

    for source_rid in 1..=source_row_count {
        let row = source_metadata.table_row_by_id(source_image, spec.table_id, source_rid)?;
        let Some(key) = triplet_source_key(
            row,
            source_rid,
            spec.key_columns,
            strings_map,
            &rift,
            table_maps,
            &special_context,
        )?
        else {
            stats.missing_source_key_rows += 1;
            continue;
        };
        let Some(targets) = targets_by_key.get_mut(&key) else {
            continue;
        };
        let Some(target_rid) = targets.pop_front() else {
            continue;
        };
        set_rift_entry(&mut rift, source_rid, target_rid);
        stats.mapped_rows += 1;
    }

    rift.entries.sort_by_key(|entry| entry.source);
    Ok(CliTripletTableMap {
        table_id: spec.table_id,
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
                            source: metadata_adjusted_rva(source_metadata, source_rva),
                            target: metadata_adjusted_rva(target_metadata, target_rva),
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

fn seed_cli_map_tables(
    source_metadata: &CliMetadataModel,
    target_metadata: &CliMetadataModel,
    cli_map: &mut CliMapModel,
) -> CliTableSeedStats {
    let mut seeded_table_maps = 0usize;
    for table_id in 0..64usize {
        if source_metadata.row_counts[table_id] != 0 && target_metadata.row_counts[table_id] != 0 {
            cli_map.tables[table_id] =
                RiftTable::reset_vector(source_metadata.row_counts[table_id] as usize + 1);
            cli_map.tables[table_id].set_vector_entry(0, 0);
            seeded_table_maps += 1;
        }
    }

    let seeded_guid_map = guid_stream_item_count(source_metadata) != 0
        && guid_stream_item_count(target_metadata) != 0;
    if seeded_guid_map {
        cli_map.guid =
            RiftTable::reset_vector(guid_stream_item_count(source_metadata) as usize + 1);
        cli_map.guid.set_vector_entry(0, 0);
    }

    CliTableSeedStats {
        seeded_table_maps,
        seeded_guid_map,
    }
}

fn guid_stream_item_count(metadata: &CliMetadataModel) -> u32 {
    metadata.streams.guid.map_or(0, |stream| stream.size / 16)
}

fn reduce_cli_map_from_metadata(cli_map: &mut CliMapModel) {
    cli_map.strings.internal_reduce(false);
    cli_map.user_strings.internal_reduce(false);
    cli_map.blob.internal_reduce(false);
    cli_map.guid.internal_reduce(true);
    for table in &mut cli_map.tables {
        table.internal_reduce(true);
    }
}

fn require_metadata_flavor(
    metadata: &CliMetadataModel,
    expected: CliSchemaFlavor,
    error: &'static str,
) -> Result<()> {
    if metadata.flavor != expected {
        return Err(Error::Malformed(error));
    }
    Ok(())
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

fn triplet_special_context(
    source_image: &[u8],
    source_metadata: &CliMetadataModel,
    target_image: &[u8],
    target_metadata: &CliMetadataModel,
    table_id: u8,
) -> Result<CliTripletSpecialContext> {
    match table_id {
        0x01 => Ok(CliTripletSpecialContext::TypeRef),
        0x02 => Ok(CliTripletSpecialContext::TypeDef {
            source_enclosing_by_nested: nested_class_enclosing_by_nested(
                source_image,
                source_metadata,
            )?,
            target_enclosing_by_nested: nested_class_enclosing_by_nested(
                target_image,
                target_metadata,
            )?,
        }),
        _ => Ok(CliTripletSpecialContext::None),
    }
}

fn nested_class_enclosing_by_nested(
    image: &[u8],
    metadata: &CliMetadataModel,
) -> Result<Vec<Option<u32>>> {
    let type_count = metadata.row_counts[0x02];
    let mut enclosing_by_nested = vec![None; type_count as usize + 1];
    let nested_count = metadata.row_counts[0x29];
    for nested_rid in 1..=nested_count {
        let row = metadata.table_row_by_id(image, 0x29, nested_rid)?;
        let nested_class = table_column_rid(row.column("NestedClass")?)?;
        let enclosing_class = table_column_rid(row.column("EnclosingClass")?)?;
        if nested_class != 0
            && nested_class <= type_count
            && enclosing_class != 0
            && enclosing_class <= type_count
        {
            enclosing_by_nested[nested_class as usize] = Some(enclosing_class);
        }
    }
    Ok(enclosing_by_nested)
}

fn triplet_source_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
    rid: u32,
    columns: &[CliTripletKeyColumn],
    strings_map: &RiftTable,
    current_table_map: &RiftTable,
    table_maps: &[RiftTable; 64],
    special_context: &CliTripletSpecialContext,
) -> Result<Option<Vec<u32>>> {
    match special_context {
        CliTripletSpecialContext::None => {}
        CliTripletSpecialContext::TypeDef {
            source_enclosing_by_nested,
            ..
        } => {
            return typedef_triplet_source_key(
                row,
                rid,
                source_enclosing_by_nested,
                strings_map,
                current_table_map,
            );
        }
        CliTripletSpecialContext::TypeRef => {
            return typeref_triplet_source_key(row, strings_map, current_table_map);
        }
    }

    let mut key = Vec::with_capacity(columns.len());
    for column in columns {
        let Some(value) =
            triplet_source_key_value(row.column(column.name())?, *column, strings_map, table_maps)?
        else {
            return Ok(None);
        };
        key.push(value);
    }
    Ok(Some(key))
}

fn triplet_target_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
    rid: u32,
    columns: &[CliTripletKeyColumn],
    special_context: &CliTripletSpecialContext,
) -> Result<Option<Vec<u32>>> {
    match special_context {
        CliTripletSpecialContext::None => {}
        CliTripletSpecialContext::TypeDef {
            target_enclosing_by_nested,
            ..
        } => {
            return typedef_triplet_target_key(row, rid, target_enclosing_by_nested);
        }
        CliTripletSpecialContext::TypeRef => {
            return typeref_triplet_target_key(row);
        }
    }

    let mut key = Vec::with_capacity(columns.len());
    for column in columns {
        let Some(value) = triplet_target_key_value(row.column(column.name())?, *column)? else {
            return Ok(None);
        };
        key.push(value);
    }
    Ok(Some(key))
}

fn typedef_triplet_source_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
    rid: u32,
    enclosing_by_nested: &[Option<u32>],
    strings_map: &RiftTable,
    current_table_map: &RiftTable,
) -> Result<Option<Vec<u32>>> {
    let Some(name) =
        exact_rift_target_value(strings_map, string_column_offset(row.column("Name")?)?)
    else {
        return Ok(None);
    };
    let second_key =
        if let Some(enclosing_rid) = enclosing_by_nested.get(rid as usize).copied().flatten() {
            exact_rift_target_value(current_table_map, enclosing_rid)
        } else {
            mapped_tagged_string_key(row, "Namespace", strings_map)?
        };
    let Some(second_key) = second_key else {
        return Ok(None);
    };
    Ok(Some(vec![name, second_key]))
}

fn typedef_triplet_target_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
    rid: u32,
    enclosing_by_nested: &[Option<u32>],
) -> Result<Option<Vec<u32>>> {
    let name = string_column_offset(row.column("Name")?)?;
    let second_key = match enclosing_by_nested.get(rid as usize).copied().flatten() {
        Some(enclosing_rid) => enclosing_rid,
        None => tagged_string_key(string_column_offset(row.column("Namespace")?)?),
    };
    Ok(Some(vec![name, second_key]))
}

fn typeref_triplet_source_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
    strings_map: &RiftTable,
    current_table_map: &RiftTable,
) -> Result<Option<Vec<u32>>> {
    let Some(name) =
        exact_rift_target_value(strings_map, string_column_offset(row.column("Name")?)?)
    else {
        return Ok(None);
    };
    let second_key =
        if let Some(owner_rid) = typeref_resolution_scope_owner(row.column("ResolutionScope")?)? {
            exact_rift_target_value(current_table_map, owner_rid)
        } else {
            mapped_tagged_string_key(row, "Namespace", strings_map)?
        };
    let Some(second_key) = second_key else {
        return Ok(None);
    };
    Ok(Some(vec![name, second_key]))
}

fn typeref_triplet_target_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
) -> Result<Option<Vec<u32>>> {
    let name = string_column_offset(row.column("Name")?)?;
    let second_key = match typeref_resolution_scope_owner(row.column("ResolutionScope")?)? {
        Some(owner_rid) => owner_rid,
        None => tagged_string_key(string_column_offset(row.column("Namespace")?)?),
    };
    Ok(Some(vec![name, second_key]))
}

fn typeref_resolution_scope_owner(value: CliColumnValue) -> Result<Option<u32>> {
    match value {
        CliColumnValue::Coded { raw, .. } if raw & 0x3 == 0x3 => Ok(Some(raw >> 2)),
        CliColumnValue::Coded { .. } => Ok(None),
        _ => Err(Error::Malformed(
            "CLI triplet map: expected TypeRef ResolutionScope coded column",
        )),
    }
}

fn mapped_tagged_string_key(
    row: crate::pe::cli::metadata::CliTableRow<'_>,
    column: &str,
    strings_map: &RiftTable,
) -> Result<Option<u32>> {
    let source_offset = string_column_offset(row.column(column)?)?;
    Ok(exact_rift_target_value(strings_map, source_offset).map(tagged_string_key))
}

fn tagged_string_key(offset: u32) -> u32 {
    offset | TRIPLET_STRING_KEY_TAG
}

fn triplet_source_key_value(
    value: CliColumnValue,
    column: CliTripletKeyColumn,
    strings_map: &RiftTable,
    table_maps: &[RiftTable; 64],
) -> Result<Option<u32>> {
    match column {
        CliTripletKeyColumn::MappedString(_) => Ok(exact_rift_target_value(
            strings_map,
            string_column_offset(value)?,
        )),
        CliTripletKeyColumn::MappedTable(_) => {
            let (table_id, rid) = table_column_target(value)?;
            let Some(rid) = rid else {
                return Ok(Some(0));
            };
            Ok(exact_rift_target_value(&table_maps[table_id as usize], rid))
        }
        CliTripletKeyColumn::MappedCoded(_) => map_coded_triplet_source_value(value, table_maps),
        CliTripletKeyColumn::RawU16(_) => Ok(Some(u16_column_value(value)?)),
        CliTripletKeyColumn::RawU32(_) => Ok(Some(u32_column_value(value)?)),
    }
}

fn triplet_target_key_value(
    value: CliColumnValue,
    column: CliTripletKeyColumn,
) -> Result<Option<u32>> {
    match column {
        CliTripletKeyColumn::MappedString(_) => Ok(Some(string_column_offset(value)?)),
        CliTripletKeyColumn::MappedTable(_) => Ok(Some(table_column_rid(value)?)),
        CliTripletKeyColumn::MappedCoded(_) => Ok(Some(coded_column_raw(value)?)),
        CliTripletKeyColumn::RawU16(_) => Ok(Some(u16_column_value(value)?)),
        CliTripletKeyColumn::RawU32(_) => Ok(Some(u32_column_value(value)?)),
    }
}

fn map_coded_triplet_source_value(
    value: CliColumnValue,
    table_maps: &[RiftTable; 64],
) -> Result<Option<u32>> {
    let CliColumnValue::Coded {
        kind,
        raw,
        table,
        rid,
    } = value
    else {
        return Err(Error::Malformed("CLI triplet map: expected coded column"));
    };
    let Some(table) = table else {
        return Ok(Some(raw));
    };
    let Some(rid) = rid else {
        return Ok(Some(0));
    };
    let Some(mapped_rid) = exact_rift_target_value(&table_maps[table.get() as usize], rid.get())
    else {
        return Ok(None);
    };
    let schema = coded_index_schema(kind);
    let tag_mask = (1u32 << schema.tag_bits) - 1;
    Ok(Some((mapped_rid << schema.tag_bits) | (raw & tag_mask)))
}

fn table_column_target(value: CliColumnValue) -> Result<(u8, Option<u32>)> {
    match value {
        CliColumnValue::Table { table, rid } => Ok((table.get(), rid.map(|rid| rid.get()))),
        _ => Err(Error::Malformed("CLI triplet map: expected table column")),
    }
}

fn coded_column_raw(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::Coded { raw, .. } => Ok(raw),
        _ => Err(Error::Malformed("CLI triplet map: expected coded column")),
    }
}

fn u16_column_value(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::U16(value) => Ok(u32::from(value)),
        _ => Err(Error::Malformed("CLI triplet map: expected u16 column")),
    }
}

fn u32_column_value(value: CliColumnValue) -> Result<u32> {
    match value {
        CliColumnValue::U32(value) | CliColumnValue::Rva(value) => Ok(value),
        _ => Err(Error::Malformed("CLI triplet map: expected u32 column")),
    }
}

impl CliTripletKeyColumn {
    const fn name(self) -> &'static str {
        match self {
            Self::MappedString(name)
            | Self::MappedTable(name)
            | Self::MappedCoded(name)
            | Self::RawU16(name)
            | Self::RawU32(name) => name,
        }
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

fn metadata_adjusted_rva(metadata: &CliMetadataModel, rva: u32) -> i64 {
    i64::from(metadata.metadata_rva) + i64::from(rva)
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

fn cli_triplet_table_spec(table_id: u8) -> Option<CliTripletTableSpec> {
    CLI_TRIPLET_TABLE_SPECS
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

fn parse_user_strings_heap_entries(heap: &[u8]) -> Result<Vec<StringsHeapEntry<'_>>> {
    let mut entries = Vec::new();
    let mut cursor = 0usize;

    while cursor < heap.len() {
        let (payload_len, header_len) = match read_compressed_u32(&heap[cursor..]) {
            Ok(value) => value,
            Err(Error::Truncated) => break,
            Err(Error::Malformed(_)) => {
                cursor += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        let record_len = header_len
            .checked_add(payload_len as usize)
            .ok_or(Error::Malformed("CLI #US heap: record length overflow"))?;
        if record_len == 0 {
            return Err(Error::Malformed("CLI #US heap: zero-length record"));
        }
        let record_end = match cursor.checked_add(record_len) {
            Some(end) if end <= heap.len() => end,
            _ => {
                cursor += 1;
                continue;
            }
        };
        if record_len != 1 {
            entries.push(StringsHeapEntry {
                offset: cursor as u32,
                value: &heap[cursor..record_end],
            });
        }
        cursor = record_end;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cli::metadata::{CliMetadataModel, CliStream, CliStreamSet};
    use crate::pe::cli::schema::{
        row_size, CliSchemaFlavor, ColumnKind, HeapIndexWidths, HeapKind,
    };

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

    fn map_inputs<'a>(
        source_image: &'a [u8],
        source_metadata: &'a CliMetadataModel,
        target_image: &'a [u8],
        target_metadata: &'a CliMetadataModel,
    ) -> CliMapInputs<'a> {
        CliMapInputs {
            source_image,
            source_metadata,
            target_image,
            target_metadata,
        }
    }

    #[test]
    fn triplet_table_specs_follow_native_run_order() {
        let spec_order = CLI_TRIPLET_TABLE_SPECS
            .iter()
            .map(|spec| spec.table_id)
            .collect::<Vec<_>>();
        let run_triplet_order = CLI_MAP_RUN_STEPS
            .iter()
            .filter_map(|step| match step {
                CliMapRunStep::Triplet(table_id) => Some(*table_id),
                CliMapRunStep::Sequence(_) => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(CLI_TRIPLET_TABLE_ORDER, spec_order.as_slice());
        assert_eq!(CLI_TRIPLET_TABLE_ORDER, run_triplet_order.as_slice());
        assert_eq!(
            spec_order,
            vec![
                0x20, 0x23, 0x00, 0x1a, 0x02, 0x01, 0x0a, 0x12, 0x15, 0x0b, 0x0d, 0x0e, 0x0f, 0x10,
                0x18, 0x1c, 0x1d, 0x26, 0x28, 0x2a, 0x2b, 0x2c, 0x0c,
            ]
        );
    }

    #[test]
    fn cli_map_run_steps_interleave_sequences_like_native_run() {
        assert_eq!(
            CLI_MAP_RUN_STEPS,
            &[
                CliMapRunStep::Triplet(0x20),
                CliMapRunStep::Triplet(0x23),
                CliMapRunStep::Triplet(0x00),
                CliMapRunStep::Triplet(0x1a),
                CliMapRunStep::Triplet(0x02),
                CliMapRunStep::Sequence(0x04),
                CliMapRunStep::Sequence(0x06),
                CliMapRunStep::Sequence(0x08),
                CliMapRunStep::Triplet(0x01),
                CliMapRunStep::Triplet(0x0a),
                CliMapRunStep::Triplet(0x12),
                CliMapRunStep::Sequence(0x14),
                CliMapRunStep::Triplet(0x15),
                CliMapRunStep::Sequence(0x17),
                CliMapRunStep::Triplet(0x0b),
                CliMapRunStep::Triplet(0x0d),
                CliMapRunStep::Triplet(0x0e),
                CliMapRunStep::Triplet(0x0f),
                CliMapRunStep::Triplet(0x10),
                CliMapRunStep::Triplet(0x18),
                CliMapRunStep::Triplet(0x1c),
                CliMapRunStep::Triplet(0x1d),
                CliMapRunStep::Triplet(0x26),
                CliMapRunStep::Triplet(0x28),
                CliMapRunStep::Triplet(0x2a),
                CliMapRunStep::Triplet(0x2b),
                CliMapRunStep::Triplet(0x2c),
                CliMapRunStep::Triplet(0x0c),
            ]
        );
    }

    #[test]
    fn triplet_table_specs_match_native_key_matrix() {
        let expected: &[(u8, &[CliTripletKeyColumn])] = &[
            (0x20, &[CliTripletKeyColumn::MappedString("Name")]),
            (0x23, &[CliTripletKeyColumn::MappedString("Name")]),
            (0x00, &[CliTripletKeyColumn::MappedString("Name")]),
            (0x1a, &[CliTripletKeyColumn::MappedString("Name")]),
            (
                0x02,
                &[
                    CliTripletKeyColumn::MappedString("Name"),
                    CliTripletKeyColumn::MappedString("Namespace"),
                ],
            ),
            (
                0x01,
                &[
                    CliTripletKeyColumn::MappedString("Name"),
                    CliTripletKeyColumn::MappedString("Namespace"),
                ],
            ),
            (
                0x0a,
                &[
                    CliTripletKeyColumn::MappedString("Name"),
                    CliTripletKeyColumn::MappedCoded("Class"),
                ],
            ),
            (0x12, &[CliTripletKeyColumn::MappedTable("Parent")]),
            (0x15, &[CliTripletKeyColumn::MappedTable("Parent")]),
            (0x0b, &[CliTripletKeyColumn::MappedCoded("Parent")]),
            (0x0d, &[CliTripletKeyColumn::MappedCoded("Parent")]),
            (0x0e, &[CliTripletKeyColumn::MappedCoded("Parent")]),
            (0x0f, &[CliTripletKeyColumn::MappedTable("Parent")]),
            (0x10, &[CliTripletKeyColumn::MappedTable("Field")]),
            (0x18, &[CliTripletKeyColumn::MappedTable("Method")]),
            (
                0x1c,
                &[
                    CliTripletKeyColumn::MappedString("ImportName"),
                    CliTripletKeyColumn::MappedCoded("MemberForwarded"),
                ],
            ),
            (0x1d, &[CliTripletKeyColumn::MappedTable("Field")]),
            (0x26, &[CliTripletKeyColumn::MappedString("Name")]),
            (0x28, &[CliTripletKeyColumn::MappedString("Name")]),
            (
                0x2a,
                &[
                    CliTripletKeyColumn::MappedString("Name"),
                    CliTripletKeyColumn::MappedCoded("Owner"),
                ],
            ),
            (0x2b, &[CliTripletKeyColumn::MappedCoded("Method")]),
            (0x2c, &[CliTripletKeyColumn::MappedTable("Owner")]),
            (0x0c, &[CliTripletKeyColumn::MappedCoded("Parent")]),
        ];

        for &(table_id, key_columns) in expected {
            let spec = cli_triplet_table_spec(table_id).unwrap();
            assert_eq!(spec.key_columns, key_columns, "table {table_id:#x}");
        }
        assert!(cli_triplet_table_spec(0x29).is_none());
    }

    #[test]
    fn triplet_table_specs_reference_typed_schema_columns() {
        for spec in CLI_TRIPLET_TABLE_SPECS {
            let schema = table_schema(spec.table_id).unwrap();
            for key_column in spec.key_columns {
                let column = schema
                    .columns
                    .iter()
                    .find(|column| column.name == key_column.name())
                    .unwrap_or_else(|| {
                        panic!("{} missing key column {}", schema.name, key_column.name())
                    });
                match (key_column, column.kind) {
                    (CliTripletKeyColumn::MappedString(_), ColumnKind::Heap(HeapKind::Strings))
                    | (CliTripletKeyColumn::MappedTable(_), ColumnKind::Table(_))
                    | (CliTripletKeyColumn::MappedCoded(_), ColumnKind::Coded(_))
                    | (CliTripletKeyColumn::RawU16(_), ColumnKind::U16)
                    | (CliTripletKeyColumn::RawU32(_), ColumnKind::U32 | ColumnKind::Rva) => {}
                    _ => panic!(
                        "{}.{} has incompatible kind {:?}",
                        schema.name, column.name, column.kind
                    ),
                }
            }
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
    fn strings_heap_map_keeps_zero_for_present_empty_heap() {
        let map = build_cli_strings_heap_map(b"\0", b"\0").unwrap();

        assert_eq!(map.stats.source_strings, 0);
        assert_eq!(map.stats.target_strings, 0);
        assert_eq!(pairs(&map.rift), vec![(0, 0)]);
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
    fn user_strings_heap_map_matches_compressed_records() {
        let source = b"\0\x03A\0\0\x03B\0\0";
        let target = b"\0\x03B\0\0\x03A\0\0";

        let map = build_cli_user_strings_heap_map(source, target).unwrap();

        assert_eq!(map.stats.source_strings, 2);
        assert_eq!(map.stats.target_strings, 2);
        assert_eq!(map.stats.matched_strings, 2);
        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 5), (5, 1)]);
    }

    #[test]
    fn user_strings_heap_map_skips_malformed_records_like_native_scanner() {
        let source = b"\0\xe0\x03A\0\0\x80";
        let target = b"\0\x03A\0\0";

        let map = build_cli_user_strings_heap_map(source, target).unwrap();

        assert_eq!(map.stats.source_strings, 1);
        assert_eq!(map.stats.target_strings, 1);
        assert_eq!(pairs(&map.rift), vec![(0, 0), (2, 1)]);
    }

    #[test]
    fn user_strings_heap_map_reads_heap_ranges_from_metadata() {
        let source = b"aaaa\0\x03A\0\0\x03B\0\0zzzz".to_vec();
        let target = b"bbbb\0\x03B\0\0\x03A\0\0yyyy".to_vec();
        let source_metadata = metadata_with_user_strings(4, 9);
        let target_metadata = metadata_with_user_strings(4, 9);

        let map = build_cli_user_strings_heap_map_from_metadata(
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
    fn blob_and_rva_map_adds_metadata_rva_base_like_native() {
        let heap_widths = narrow_heap_widths();
        let row_size = row_size(0x06, &method_rows(1), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u32(&mut source_image, 0x20, 0x100);
        put_u16(&mut source_image, 0x2a, 1);
        put_u32(&mut target_image, 0x30, 0x180);
        put_u16(&mut target_image, 0x3a, 1);

        let source_metadata =
            with_metadata_rva(metadata_with_table(0x06, 1, row_size as u32, 0x20), 0x2000);
        let target_metadata =
            with_metadata_rva(metadata_with_table(0x06, 1, row_size as u32, 0x30), 0x3000);
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

        assert_eq!(pairs(&maps.rvas), vec![(0x2100, 0x3180)]);
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
    fn cli_map_from_metadata_composes_native_run_order_atoms() {
        let heap_widths = narrow_heap_widths();
        let mut row_counts = [0u32; 64];
        row_counts[0x02] = 1;
        row_counts[0x06] = 1;
        let type_row_size = row_size(0x02, &row_counts, heap_widths).unwrap();
        let method_row_size = row_size(0x06, &row_counts, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x140];
        let mut target_image = vec![0u8; 0x160];

        source_image[0x00..0x0d].copy_from_slice(b"\0Type\0Method\0");
        source_image[0x20..0x25].copy_from_slice(b"\0\x03A\0\0");
        target_image[0x00..0x0d].copy_from_slice(b"\0Method\0Type\0");
        target_image[0x20..0x25].copy_from_slice(b"\0\x03A\0\0");

        put_u16(&mut source_image, 0x64, 1);
        put_u16(&mut source_image, 0x66, 0);
        put_u16(&mut source_image, 0x6c, 1);
        put_u16(&mut target_image, 0x84, 8);
        put_u16(&mut target_image, 0x86, 0);
        put_u16(&mut target_image, 0x8c, 1);

        put_u32(&mut source_image, 0xa0, 0x2100);
        put_u16(&mut source_image, 0xa8, 6);
        put_u16(&mut source_image, 0xaa, 3);
        put_u16(&mut target_image, 0xc0, 0x2400);
        put_u16(&mut target_image, 0xc8, 1);
        put_u16(&mut target_image, 0xca, 5);

        let source_metadata = metadata_with_streams_and_tables(
            CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0x00,
                    size: 0x0d,
                }),
                user_strings: Some(CliStream {
                    metadata_offset: 0x20,
                    file_offset: 0x20,
                    size: 0x05,
                }),
                blob: Some(CliStream {
                    metadata_offset: 0x30,
                    file_offset: 0x30,
                    size: 0x10,
                }),
                guid: None,
                tables: CliStream {
                    metadata_offset: 0x60,
                    file_offset: 0x60,
                    size: type_row_size as u32 + method_row_size as u32,
                },
            },
            &row_counts,
            &[
                (0x02, type_row_size as u32, 0x60),
                (0x06, method_row_size as u32, 0xa0),
            ],
        );
        let target_metadata = metadata_with_streams_and_tables(
            CliStreamSet {
                strings: Some(CliStream {
                    metadata_offset: 0,
                    file_offset: 0x00,
                    size: 0x0d,
                }),
                user_strings: Some(CliStream {
                    metadata_offset: 0x20,
                    file_offset: 0x20,
                    size: 0x05,
                }),
                blob: Some(CliStream {
                    metadata_offset: 0x30,
                    file_offset: 0x30,
                    size: 0x10,
                }),
                guid: None,
                tables: CliStream {
                    metadata_offset: 0x80,
                    file_offset: 0x80,
                    size: type_row_size as u32 + method_row_size as u32,
                },
            },
            &row_counts,
            &[
                (0x02, type_row_size as u32, 0x80),
                (0x06, method_row_size as u32, 0xc0),
            ],
        );

        let result = build_cli_map_from_metadata(
            &source_image,
            &source_metadata,
            &target_image,
            &target_metadata,
        )
        .unwrap();

        assert_eq!(pairs(&result.cli_map.strings), vec![(0, 0), (1, 8), (6, 1)]);
        assert!(result.cli_map.user_strings.entries.is_empty());
        assert!(result.cli_map.tables[0x02].entries.is_empty());
        assert!(result.cli_map.tables[0x06].entries.is_empty());
        assert_eq!(pairs(&result.cli_map.blob), vec![(0, 0), (3, 5)]);
        assert_eq!(pairs(&result.rvas), vec![(0x2100, 0x2400)]);
        assert_eq!(result.stats.seeds.seeded_table_maps, 2);
        assert!(!result.stats.seeds.seeded_guid_map);
        assert_eq!(result.stats.strings.matched_strings, 2);
        assert_eq!(result.stats.user_strings.matched_strings, 1);
        assert_eq!(
            stats_for_triplet(&result.stats.triplet_maps, 0x02).mapped_rows,
            1
        );
        assert_eq!(
            stats_for_sequence(&result.stats.sequence_maps, 0x06).mapped_rows,
            1
        );
        assert_eq!(result.stats.blob_and_rva.mapped_blob_columns, 1);
        assert_eq!(result.stats.blob_and_rva.mapped_rva_columns, 1);
    }

    #[test]
    fn classic_cli_map_wrapper_requires_classic_metadata() {
        let source = b"\0A\0".to_vec();
        let target = b"\0A\0".to_vec();
        let source_metadata = with_flavor(metadata_with_strings(0, 3), CliSchemaFlavor::Cli4);
        let target_metadata = metadata_with_strings(0, 3);

        assert!(matches!(
            build_classic_cli_map_from_metadata(
                &source,
                &source_metadata,
                &target,
                &target_metadata,
            ),
            Err(Error::Malformed(
                "classic CLI map create: source metadata flavor mismatch"
            ))
        ));
    }

    #[test]
    fn cli4_map_wrapper_reuses_composition_for_cli4_metadata() {
        let source = b"\0A\0".to_vec();
        let target = b"\0B\0A\0".to_vec();
        let source_metadata = with_flavor(metadata_with_strings(0, 3), CliSchemaFlavor::Cli4);
        let target_metadata = with_flavor(metadata_with_strings(0, 5), CliSchemaFlavor::Cli4);

        let result =
            build_cli4_map_from_metadata(&source, &source_metadata, &target, &target_metadata)
                .unwrap();

        assert_eq!(pairs(&result.cli_map.strings), vec![(0, 0), (1, 3)]);
        assert_eq!(result.stats.strings.matched_strings, 1);
    }

    #[test]
    fn cli4_map_wrapper_rejects_classic_metadata() {
        let source = b"\0A\0".to_vec();
        let target = b"\0A\0".to_vec();
        let source_metadata = metadata_with_strings(0, 3);
        let target_metadata = with_flavor(metadata_with_strings(0, 3), CliSchemaFlavor::Cli4);

        assert!(matches!(
            build_cli4_map_from_metadata(&source, &source_metadata, &target, &target_metadata),
            Err(Error::Malformed(
                "CLI4 map create: source metadata flavor mismatch"
            ))
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
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
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
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
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
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0)]),
            &rift(&[(0, 0), (1, 1)]),
            &rift(&[(0, 0)]),
            0x06,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0)]);
        assert_eq!(map.stats.missing_string_rows, 1);
    }

    #[test]
    fn triplet_table_map_matches_rows_by_mapped_string_keys() {
        const TYPEDEF_TRIPLET: CliTripletTableSpec = CliTripletTableSpec {
            table_id: 0x02,
            key_columns: &[
                CliTripletKeyColumn::MappedString("Name"),
                CliTripletKeyColumn::MappedString("Namespace"),
            ],
        };
        let heap_widths = narrow_heap_widths();
        let row_size = row_size(0x02, &typedef_rows(2), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u16(&mut source_image, 0x24, 10);
        put_u16(&mut source_image, 0x26, 20);
        put_u16(&mut source_image, 0x24 + row_size, 11);
        put_u16(&mut source_image, 0x26 + row_size, 21);
        put_u16(&mut target_image, 0x34, 101);
        put_u16(&mut target_image, 0x36, 201);
        put_u16(&mut target_image, 0x34 + row_size, 100);
        put_u16(&mut target_image, 0x36 + row_size, 200);

        let source_metadata = metadata_with_table(0x02, 2, row_size as u32, 0x20);
        let target_metadata = metadata_with_table(0x02, 2, row_size as u32, 0x30);
        let table_maps = empty_table_maps();

        let map = build_cli_triplet_table_map(
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0), (10, 100), (11, 101), (20, 200), (21, 201)]),
            &table_maps,
            &rift(&[(0, 0)]),
            TYPEDEF_TRIPLET,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 2), (2, 1)]);
        assert_eq!(map.stats.mapped_rows, 2);
        assert_eq!(map.stats.missing_source_key_rows, 0);
    }

    #[test]
    fn triplet_table_map_matches_rows_by_mapped_table_keys() {
        const NESTED_CLASS_TRIPLET: CliTripletTableSpec = CliTripletTableSpec {
            table_id: 0x29,
            key_columns: &[
                CliTripletKeyColumn::MappedTable("NestedClass"),
                CliTripletKeyColumn::MappedTable("EnclosingClass"),
            ],
        };
        let heap_widths = narrow_heap_widths();
        let mut row_counts = [0u32; 64];
        row_counts[0x02] = 2;
        row_counts[0x29] = 1;
        let row_size = row_size(0x29, &row_counts, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u16(&mut source_image, 0x20, 1);
        put_u16(&mut source_image, 0x22, 2);
        put_u16(&mut target_image, 0x30, 2);
        put_u16(&mut target_image, 0x32, 1);

        let source_metadata = metadata_with_rows(&row_counts, &[(0x29, row_size as u32, 0x20)]);
        let target_metadata = metadata_with_rows(&row_counts, &[(0x29, row_size as u32, 0x30)]);
        let mut table_maps = empty_table_maps();
        table_maps[0x02] = rift(&[(0, 0), (1, 2), (2, 1)]);

        let map = build_cli_triplet_table_map(
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0)]),
            &table_maps,
            &rift(&[(0, 0)]),
            NESTED_CLASS_TRIPLET,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 1)]);
        assert_eq!(map.stats.mapped_rows, 1);
    }

    #[test]
    fn triplet_table_map_matches_rows_by_mapped_coded_keys() {
        let heap_widths = narrow_heap_widths();
        let mut row_counts = [0u32; 64];
        row_counts[0x06] = 2;
        row_counts[0x2b] = 1;
        let row_size = row_size(0x2b, &row_counts, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u16(&mut source_image, 0x20, 1 << 1);
        put_u16(&mut target_image, 0x30, 2 << 1);

        let source_metadata = metadata_with_rows(&row_counts, &[(0x2b, row_size as u32, 0x20)]);
        let target_metadata = metadata_with_rows(&row_counts, &[(0x2b, row_size as u32, 0x30)]);
        let mut table_maps = empty_table_maps();
        table_maps[0x06] = rift(&[(0, 0), (1, 2)]);

        let map = build_cli_triplet_table_map(
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0)]),
            &table_maps,
            &rift(&[(0, 0)]),
            cli_triplet_table_spec(0x2b).unwrap(),
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 1)]);
        assert_eq!(map.stats.mapped_rows, 1);
    }

    #[test]
    fn triplet_table_map_matches_typedef_rows_by_mapped_nested_owner() {
        let heap_widths = narrow_heap_widths();
        let mut row_counts = [0u32; 64];
        row_counts[0x02] = 2;
        row_counts[0x29] = 1;
        let typedef_row_size = row_size(0x02, &row_counts, heap_widths).unwrap();
        let nested_row_size = row_size(0x29, &row_counts, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x100];
        let mut target_image = vec![0u8; 0x120];

        put_u16(&mut source_image, 0x24, 10);
        put_u16(&mut source_image, 0x26, 20);
        put_u16(&mut source_image, 0x24 + typedef_row_size, 11);
        put_u16(&mut source_image, 0x26 + typedef_row_size, 30);
        put_u16(&mut target_image, 0x44, 101);
        put_u16(&mut target_image, 0x46, 999);
        put_u16(&mut target_image, 0x44 + typedef_row_size, 100);
        put_u16(&mut target_image, 0x46 + typedef_row_size, 200);

        put_u16(&mut source_image, 0x80, 2);
        put_u16(&mut source_image, 0x82, 1);
        put_u16(&mut target_image, 0xa0, 1);
        put_u16(&mut target_image, 0xa2, 2);

        let source_metadata = metadata_with_rows(
            &row_counts,
            &[
                (0x02, typedef_row_size as u32, 0x20),
                (0x29, nested_row_size as u32, 0x80),
            ],
        );
        let target_metadata = metadata_with_rows(
            &row_counts,
            &[
                (0x02, typedef_row_size as u32, 0x40),
                (0x29, nested_row_size as u32, 0xa0),
            ],
        );
        let mut table_maps = empty_table_maps();
        table_maps[0x02] = rift(&[(0, 0)]);

        let map = build_cli_triplet_table_map(
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0), (10, 100), (11, 101), (20, 200), (30, 300)]),
            &table_maps,
            &rift(&[(0, 0)]),
            cli_triplet_table_spec(0x02).unwrap(),
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 2), (2, 1)]);
        assert_eq!(map.stats.mapped_rows, 2);
    }

    #[test]
    fn triplet_table_map_matches_typeref_rows_by_mapped_self_scope_owner() {
        let heap_widths = narrow_heap_widths();
        let mut row_counts = [0u32; 64];
        row_counts[0x01] = 2;
        let row_size = row_size(0x01, &row_counts, heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u16(&mut source_image, 0x20, 0);
        put_u16(&mut source_image, 0x22, 10);
        put_u16(&mut source_image, 0x24, 20);
        put_u16(&mut source_image, 0x20 + row_size, (1 << 2) | 3);
        put_u16(&mut source_image, 0x22 + row_size, 11);
        put_u16(&mut source_image, 0x24 + row_size, 30);
        put_u16(&mut target_image, 0x40, (2 << 2) | 3);
        put_u16(&mut target_image, 0x42, 101);
        put_u16(&mut target_image, 0x44, 999);
        put_u16(&mut target_image, 0x40 + row_size, 0);
        put_u16(&mut target_image, 0x42 + row_size, 100);
        put_u16(&mut target_image, 0x44 + row_size, 200);

        let source_metadata = metadata_with_rows(&row_counts, &[(0x01, row_size as u32, 0x20)]);
        let target_metadata = metadata_with_rows(&row_counts, &[(0x01, row_size as u32, 0x40)]);
        let mut table_maps = empty_table_maps();
        table_maps[0x01] = rift(&[(0, 0)]);

        let map = build_cli_triplet_table_map(
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0), (10, 100), (11, 101), (20, 200), (30, 300)]),
            &table_maps,
            &rift(&[(0, 0)]),
            cli_triplet_table_spec(0x01).unwrap(),
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0), (1, 2), (2, 1)]);
        assert_eq!(map.stats.mapped_rows, 2);
    }

    #[test]
    fn triplet_table_map_tracks_missing_source_keys() {
        const TYPEDEF_TRIPLET: CliTripletTableSpec = CliTripletTableSpec {
            table_id: 0x02,
            key_columns: &[CliTripletKeyColumn::MappedString("Name")],
        };
        let heap_widths = narrow_heap_widths();
        let row_size = row_size(0x02, &typedef_rows(1), heap_widths).unwrap();
        let mut source_image = vec![0u8; 0x80];
        let mut target_image = vec![0u8; 0x80];

        put_u16(&mut source_image, 0x24, 10);
        put_u16(&mut target_image, 0x34, 100);

        let source_metadata = metadata_with_table(0x02, 1, row_size as u32, 0x20);
        let target_metadata = metadata_with_table(0x02, 1, row_size as u32, 0x30);
        let table_maps = empty_table_maps();

        let map = build_cli_triplet_table_map(
            map_inputs(
                &source_image,
                &source_metadata,
                &target_image,
                &target_metadata,
            ),
            &rift(&[(0, 0)]),
            &table_maps,
            &rift(&[(0, 0)]),
            TYPEDEF_TRIPLET,
        )
        .unwrap();

        assert_eq!(pairs(&map.rift), vec![(0, 0)]);
        assert_eq!(map.stats.missing_source_key_rows, 1);
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

    fn metadata_with_user_strings(file_offset: usize, size: u32) -> CliMetadataModel {
        metadata_with_streams(
            CliStreamSet {
                strings: None,
                user_strings: Some(CliStream {
                    metadata_offset: 0,
                    file_offset,
                    size,
                }),
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

    fn metadata_with_rows(
        row_counts: &[u32; 64],
        tables: &[(usize, u32, usize)],
    ) -> CliMetadataModel {
        let mut row_sizes = [0u32; 64];
        let mut table_file_offsets = [None; 64];
        let mut tables_size = 0u32;
        let mut tables_start = usize::MAX;
        for &(table_id, row_size, table_file_offset) in tables {
            row_sizes[table_id] = row_size;
            table_file_offsets[table_id] = Some(table_file_offset);
            tables_size = tables_size.saturating_add(row_counts[table_id].saturating_mul(row_size));
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
            *row_counts,
            row_sizes,
            table_file_offsets,
        )
    }

    fn metadata_with_streams_and_tables(
        streams: CliStreamSet,
        row_counts: &[u32; 64],
        tables: &[(usize, u32, usize)],
    ) -> CliMetadataModel {
        let mut row_sizes = [0u32; 64];
        let mut table_file_offsets = [None; 64];
        for &(table_id, row_size, table_file_offset) in tables {
            row_sizes[table_id] = row_size;
            table_file_offsets[table_id] = Some(table_file_offset);
        }

        metadata_with_streams(streams, *row_counts, row_sizes, table_file_offsets)
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

    fn with_flavor(mut metadata: CliMetadataModel, flavor: CliSchemaFlavor) -> CliMetadataModel {
        metadata.flavor = flavor;
        metadata
    }

    fn with_metadata_rva(mut metadata: CliMetadataModel, metadata_rva: u32) -> CliMetadataModel {
        metadata.metadata_rva = metadata_rva;
        metadata
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

    fn stats_for_triplet(
        stats: &[CliTripletTableMapStatsByTable],
        table_id: u8,
    ) -> CliTripletTableMapStats {
        stats
            .iter()
            .find(|stats| stats.table_id == table_id)
            .map(|stats| stats.stats)
            .unwrap()
    }

    fn stats_for_sequence(
        stats: &[CliSequenceTableMapStatsByTable],
        table_id: u8,
    ) -> CliSequenceTableMapStats {
        stats
            .iter()
            .find(|stats| stats.table_id == table_id)
            .map(|stats| stats.stats)
            .unwrap()
    }
}
