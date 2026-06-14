//! CLI metadata coded-token RID remapping.

use crate::bitstream::{BitReader, BitWriter};
use crate::lzx::rift::{IntFormat, RiftTable};
use crate::pe::cli_schema::{coded_index_schema, table_schema, CodedIndexKind, TABLE_SENTINEL};
use crate::{Error as DeltaError, Result};
use thiserror::Error;

pub(crate) type CliMapResult<T> = std::result::Result<T, CliCodedTokenMapError>;
pub(crate) const CLI_CODED_TOKEN_EXACT_MISS: u32 = u32::MAX;
const CLI_TABLE_MAP_COUNT: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliCodedToken {
    pub(crate) kind: CodedIndexKind,
    pub(crate) table_id: u8,
    pub(crate) tag: u32,
    pub(crate) rid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum CliCodedTokenMapError {
    #[error("CLI coded token {kind:?}: invalid tag {tag}")]
    InvalidTag { kind: CodedIndexKind, tag: u32 },

    #[error("CLI coded token map: invalid metadata table id {table_id:#04x}")]
    InvalidTableId { table_id: u8 },

    #[error(
        "CLI coded token map: invalid mapped RID {mapped_rid} for table {table_id:#04x} source RID {source_rid}"
    )]
    InvalidMappedRid {
        table_id: u8,
        source_rid: u32,
        mapped_rid: u32,
    },

    #[error(
        "CLI coded token map: mapped RID {mapped_rid} is out of range for table {table_id:#04x} source RID {source_rid}"
    )]
    MappedRidOutOfRange {
        table_id: u8,
        source_rid: u32,
        mapped_rid: i64,
    },

    #[error(
        "CLI coded token map: invalid RID map entry for table {table_id:#04x}: {map_source}->{map_target}"
    )]
    InvalidRidMapEntry {
        table_id: u8,
        map_source: i64,
        map_target: i64,
    },

    #[error(
        "CLI coded token {kind:?}: RID {rid} for table {table_id:#04x} exceeds {tag_bits} tag-bit encoding"
    )]
    RidOverflow {
        kind: CodedIndexKind,
        table_id: u8,
        rid: u32,
        tag_bits: u8,
    },

    #[error(
        "CLI coded token {kind:?}: reassembly overflow for table {table_id:#04x}, RID {rid}, tag {tag}"
    )]
    ReassemblyOverflow {
        kind: CodedIndexKind,
        table_id: u8,
        rid: u32,
        tag: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliRidMap {
    entries: Vec<CliRidMapEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliRidMapEntry {
    pub(crate) source: u32,
    pub(crate) target: u32,
}

impl CliRidMap {
    pub(crate) fn new(mapped_rids: Vec<u32>) -> Self {
        Self::from_entries(mapped_rids.into_iter().enumerate().map(|(index, target)| {
            CliRidMapEntry {
                source: index as u32 + 1,
                target,
            }
        }))
    }

    pub(crate) fn from_entries(entries: impl IntoIterator<Item = CliRidMapEntry>) -> Self {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.source);
        let mut deduped: Vec<CliRidMapEntry> = Vec::with_capacity(entries.len());
        for entry in entries {
            match deduped.last_mut() {
                Some(previous) if previous.source == entry.source => *previous = entry,
                _ => deduped.push(entry),
            }
        }
        Self { entries: deduped }
    }

    fn from_rift_table(table_id: u8, rift: &RiftTable) -> CliMapResult<Self> {
        let mut entries = Vec::with_capacity(rift.entries.len());
        for entry in &rift.entries {
            let source = u32::try_from(entry.source).map_err(|_| {
                CliCodedTokenMapError::InvalidRidMapEntry {
                    table_id,
                    map_source: entry.source,
                    map_target: entry.target,
                }
            })?;
            let target = u32::try_from(entry.target).map_err(|_| {
                CliCodedTokenMapError::InvalidRidMapEntry {
                    table_id,
                    map_source: entry.source,
                    map_target: entry.target,
                }
            })?;
            entries.push(CliRidMapEntry { source, target });
        }
        Ok(Self::from_entries(entries))
    }

    fn map_rid(&self, table_id: u8, source_rid: u32) -> CliMapResult<u32> {
        if source_rid == 0 || self.entries.is_empty() {
            return Ok(source_rid);
        }

        let entry = match self
            .entries
            .binary_search_by_key(&source_rid, |entry| entry.source)
        {
            Ok(index) => self.entries[index],
            Err(0) => return Ok(source_rid),
            Err(index) => self.entries[index - 1],
        };
        apply_rid_offset(table_id, source_rid, entry)
    }

    fn map_rid_exact(&self, source_rid: u32) -> Option<u32> {
        if source_rid == 0 || self.entries.is_empty() {
            return Some(source_rid);
        }
        self.entries
            .binary_search_by_key(&source_rid, |entry| entry.source)
            .ok()
            .map(|index| self.entries[index].target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliCodedTokenMap {
    table_maps: [Option<CliRidMap>; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliMapModel {
    pub(crate) strings: RiftTable,
    pub(crate) user_strings: RiftTable,
    pub(crate) blob: RiftTable,
    pub(crate) guid: RiftTable,
    pub(crate) tables: [RiftTable; CLI_TABLE_MAP_COUNT],
}

impl CliMapModel {
    pub(crate) fn is_empty(&self) -> bool {
        self.strings.entries.is_empty()
            && self.user_strings.entries.is_empty()
            && self.blob.entries.is_empty()
            && self.guid.entries.is_empty()
            && self.tables.iter().all(|table| table.entries.is_empty())
    }

    pub(crate) fn coded_token_map(&self) -> CliMapResult<CliCodedTokenMap> {
        let mut token_map = CliCodedTokenMap::new();
        for (table_id, rift) in self.tables.iter().enumerate() {
            if rift.entries.is_empty() {
                continue;
            }
            let table_id = table_id as u8;
            if table_schema(table_id).is_none() {
                continue;
            }
            token_map.set_table_map(table_id, CliRidMap::from_rift_table(table_id, rift)?)?;
        }
        Ok(token_map)
    }
}

impl Default for CliMapModel {
    fn default() -> Self {
        Self {
            strings: empty_rift_table(),
            user_strings: empty_rift_table(),
            blob: empty_rift_table(),
            guid: empty_rift_table(),
            tables: std::array::from_fn(|_| empty_rift_table()),
        }
    }
}

pub(crate) fn read_cli_map_bitstream(reader: &mut BitReader<'_>) -> Result<CliMapModel> {
    let present = reader.read_bits(1)? != 0;
    if !present {
        return Ok(CliMapModel::default());
    }

    let heap_source_format = IntFormat::from_reader(reader)?;
    let heap_target_format = IntFormat::from_reader(reader)?;
    let table_source_format = IntFormat::from_reader(reader)?;
    let table_target_format = IntFormat::from_reader(reader)?;

    let strings =
        RiftTable::from_reader_with_formats(reader, &heap_source_format, &heap_target_format)?;
    let user_strings =
        RiftTable::from_reader_with_formats(reader, &heap_source_format, &heap_target_format)?;
    let blob =
        RiftTable::from_reader_with_formats(reader, &heap_source_format, &heap_target_format)?;
    let guid =
        RiftTable::from_reader_with_formats(reader, &table_source_format, &table_target_format)?;
    let mut parsed_tables = Vec::with_capacity(CLI_TABLE_MAP_COUNT);
    for _ in 0..CLI_TABLE_MAP_COUNT {
        parsed_tables.push(RiftTable::from_reader_with_formats(
            reader,
            &table_source_format,
            &table_target_format,
        )?);
    }
    let tables = parsed_tables
        .try_into()
        .map_err(|_| DeltaError::Malformed("CLI map table count mismatch"))?;

    Ok(CliMapModel {
        strings,
        user_strings,
        blob,
        guid,
        tables,
    })
}

pub(crate) fn write_cli_map_bitstream(writer: &mut BitWriter, model: &CliMapModel) {
    if model.is_empty() {
        writer.write_bits(0, 1);
        return;
    }

    writer.write_bits(1, 1);

    let (heap_source_values, heap_target_values) =
        collect_rift_deltas([&model.strings, &model.user_strings, &model.blob]);
    let (table_source_values, table_target_values) =
        collect_rift_deltas(std::iter::once(&model.guid).chain(model.tables.iter()));

    let heap_source_format = IntFormat::from_values(&heap_source_values);
    let heap_target_format = IntFormat::from_values(&heap_target_values);
    let table_source_format = IntFormat::from_values(&table_source_values);
    let table_target_format = IntFormat::from_values(&table_target_values);

    heap_source_format.to_writer(writer);
    heap_target_format.to_writer(writer);
    table_source_format.to_writer(writer);
    table_target_format.to_writer(writer);

    model
        .strings
        .to_writer_with_formats(writer, &heap_source_format, &heap_target_format);
    model
        .user_strings
        .to_writer_with_formats(writer, &heap_source_format, &heap_target_format);
    model
        .blob
        .to_writer_with_formats(writer, &heap_source_format, &heap_target_format);
    model
        .guid
        .to_writer_with_formats(writer, &table_source_format, &table_target_format);
    for table in &model.tables {
        table.to_writer_with_formats(writer, &table_source_format, &table_target_format);
    }
}

impl CliCodedTokenMap {
    pub(crate) fn new() -> Self {
        Self {
            table_maps: std::array::from_fn(|_| None),
        }
    }

    pub(crate) fn with_table_map(
        mut self,
        table_id: u8,
        mapped_rids: Vec<u32>,
    ) -> CliMapResult<Self> {
        self.set_table_map(table_id, CliRidMap::new(mapped_rids))?;
        Ok(self)
    }

    pub(crate) fn with_table_entries(
        mut self,
        table_id: u8,
        entries: impl IntoIterator<Item = CliRidMapEntry>,
    ) -> CliMapResult<Self> {
        self.set_table_map(table_id, CliRidMap::from_entries(entries))?;
        Ok(self)
    }

    pub(crate) fn set_table_map(&mut self, table_id: u8, rid_map: CliRidMap) -> CliMapResult<()> {
        if table_schema(table_id).is_none() {
            return Err(CliCodedTokenMapError::InvalidTableId { table_id });
        }
        self.table_maps[table_id as usize] = Some(rid_map);
        Ok(())
    }

    pub(crate) fn map_coded_token(&self, raw: u32, kind: CodedIndexKind) -> CliMapResult<u32> {
        let token = split_coded_token(raw, kind)?;
        if token.table_id == TABLE_SENTINEL {
            return Ok(raw);
        }
        if token.rid == 0 {
            return reassemble_coded_token(token.kind, token.table_id, token.tag, 0);
        }

        let Some(rid_map) = &self.table_maps[token.table_id as usize] else {
            return reassemble_coded_token(token.kind, token.table_id, token.tag, token.rid);
        };

        let mapped_rid = rid_map.map_rid(token.table_id, token.rid)?;
        if mapped_rid == 0 {
            return Err(CliCodedTokenMapError::InvalidMappedRid {
                table_id: token.table_id,
                source_rid: token.rid,
                mapped_rid,
            });
        }

        reassemble_coded_token(token.kind, token.table_id, token.tag, mapped_rid)
    }

    pub(crate) fn map_coded_token_exact(
        &self,
        raw: u32,
        kind: CodedIndexKind,
    ) -> CliMapResult<u32> {
        let token = split_coded_token(raw, kind)?;
        if token.table_id == TABLE_SENTINEL {
            return Ok(raw);
        }
        if token.rid == 0 {
            return reassemble_coded_token(token.kind, token.table_id, token.tag, 0);
        }

        let Some(rid_map) = &self.table_maps[token.table_id as usize] else {
            return reassemble_coded_token(token.kind, token.table_id, token.tag, token.rid);
        };

        let Some(mapped_rid) = rid_map.map_rid_exact(token.rid) else {
            return Ok(CLI_CODED_TOKEN_EXACT_MISS);
        };
        if mapped_rid == 0 {
            return Err(CliCodedTokenMapError::InvalidMappedRid {
                table_id: token.table_id,
                source_rid: token.rid,
                mapped_rid,
            });
        }

        reassemble_coded_token(token.kind, token.table_id, token.tag, mapped_rid)
    }
}

impl Default for CliCodedTokenMap {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn map_coded_token(
    raw: u32,
    kind: CodedIndexKind,
    token_map: &CliCodedTokenMap,
) -> CliMapResult<u32> {
    token_map.map_coded_token(raw, kind)
}

pub(crate) fn map_coded_token_exact(
    raw: u32,
    kind: CodedIndexKind,
    token_map: &CliCodedTokenMap,
) -> CliMapResult<u32> {
    token_map.map_coded_token_exact(raw, kind)
}

pub(crate) fn split_coded_token(raw: u32, kind: CodedIndexKind) -> CliMapResult<CliCodedToken> {
    let schema = coded_index_schema(kind);
    let tag_mask = tag_mask(schema.tag_bits);
    let tag = raw & tag_mask;
    let table_id = schema
        .tag_to_table
        .get(tag as usize)
        .copied()
        .ok_or(CliCodedTokenMapError::InvalidTag { kind, tag })?;

    Ok(CliCodedToken {
        kind,
        table_id,
        tag,
        rid: raw >> schema.tag_bits,
    })
}

pub(crate) fn reassemble_coded_token(
    kind: CodedIndexKind,
    table_id: u8,
    tag: u32,
    rid: u32,
) -> CliMapResult<u32> {
    let schema = coded_index_schema(kind);
    let expected_table = schema
        .tag_to_table
        .get(tag as usize)
        .copied()
        .filter(|&table_id| table_id == TABLE_SENTINEL || table_schema(table_id).is_some());
    if expected_table != Some(table_id) {
        return Err(CliCodedTokenMapError::InvalidTag { kind, tag });
    }
    let max_rid = u32::MAX >> schema.tag_bits;
    if rid > max_rid {
        return Err(CliCodedTokenMapError::RidOverflow {
            kind,
            table_id,
            rid,
            tag_bits: schema.tag_bits,
        });
    }

    if table_id == TABLE_SENTINEL {
        return Ok((rid << schema.tag_bits) + tag);
    }

    let shifted = rid.checked_shl(schema.tag_bits.into()).ok_or(
        CliCodedTokenMapError::ReassemblyOverflow {
            kind,
            table_id,
            rid,
            tag,
        },
    )?;
    shifted
        .checked_add(tag)
        .ok_or(CliCodedTokenMapError::ReassemblyOverflow {
            kind,
            table_id,
            rid,
            tag,
        })
}

fn tag_mask(tag_bits: u8) -> u32 {
    (1u32 << tag_bits) - 1
}

fn empty_rift_table() -> RiftTable {
    RiftTable {
        entries: Vec::new(),
    }
}

fn collect_rift_deltas<'a>(
    tables: impl IntoIterator<Item = &'a RiftTable>,
) -> (Vec<i64>, Vec<i64>) {
    let mut source_deltas = Vec::new();
    let mut target_deltas = Vec::new();

    for table in tables {
        let mut source_acc: i64 = 0;
        let mut target_acc: i64 = 0;
        for entry in &table.entries {
            let source_delta = entry.source.wrapping_sub(source_acc);
            source_acc = entry.source;
            let target_delta = (entry.target.wrapping_sub(entry.source)).wrapping_sub(target_acc);
            target_acc = entry.target.wrapping_sub(entry.source);
            source_deltas.push(source_delta);
            target_deltas.push(target_delta);
        }
    }

    (source_deltas, target_deltas)
}

fn apply_rid_offset(table_id: u8, source_rid: u32, entry: CliRidMapEntry) -> CliMapResult<u32> {
    let mapped = i64::from(source_rid) + (i64::from(entry.target) - i64::from(entry.source));
    u32::try_from(mapped).map_err(|_| CliCodedTokenMapError::MappedRidOutOfRange {
        table_id,
        source_rid,
        mapped_rid: mapped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::{IntFormat, RiftEntry, RiftTable};
    use crate::pe::cli_schema::CODED_INDEXES;
    use serde::Deserialize;
    use std::path::Path;

    const TYPE_DEF: u8 = 0x02;
    const TYPE_REF: u8 = 0x01;
    const PARAM: u8 = 0x08;
    const METHOD_DEF: u8 = 0x06;

    #[test]
    fn parses_absent_cli_map_as_empty_model() {
        let mut writer = BitWriter::new();
        writer.write_bits(0, 1);
        let data = writer.finish();
        let mut reader = BitReader::new(&data).unwrap();

        let model = read_cli_map_bitstream(&mut reader).unwrap();

        assert!(model.is_empty());
    }

    #[test]
    fn parses_present_cli_map_with_all_empty_maps() {
        let data = present_empty_cli_map();
        let mut reader = BitReader::new(&data).unwrap();

        let model = read_cli_map_bitstream(&mut reader).unwrap();

        assert!(model.is_empty());
    }

    #[test]
    fn roundtrips_heap_table_and_guid_maps() {
        let mut model = CliMapModel::default();
        model.strings = rift(&[(3, 7), (8, 9)]);
        model.blob = rift(&[(0x20, 0x28)]);
        model.guid = rift(&[(1, 3)]);
        model.tables[TYPE_REF as usize] = rift(&[(5, 9), (10, 20)]);

        let decoded = roundtrip_cli_map(&model);

        assert_entries(&decoded.strings, &[(3, 7), (8, 9)]);
        assert!(decoded.user_strings.entries.is_empty());
        assert_entries(&decoded.blob, &[(0x20, 0x28)]);
        assert_entries(&decoded.guid, &[(1, 3)]);
        assert_entries(&decoded.tables[TYPE_REF as usize], &[(5, 9), (10, 20)]);
    }

    #[test]
    fn parsed_table_maps_feed_coded_token_mapping() {
        let mut model = CliMapModel::default();
        model.tables[TYPE_REF as usize] = rift(&[(5, 9), (10, 20)]);

        let token_map = roundtrip_cli_map(&model).coded_token_map().unwrap();

        assert_eq!(
            token_map
                .map_coded_token((7 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            (11 << 2) | 1
        );
        assert_eq!(
            token_map
                .map_coded_token_exact((7 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            CLI_CODED_TOKEN_EXACT_MISS
        );
        assert_eq!(
            token_map
                .map_coded_token_exact((10 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            (20 << 2) | 1
        );
    }

    #[test]
    fn rejects_invalid_cli_map_int_format() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        writer.write_bits(127, 8);
        writer.write_bits(0, 8);
        writer.write_bits(0, 8);
        let data = writer.finish();
        let mut reader = BitReader::new(&data).unwrap();

        assert!(matches!(
            read_cli_map_bitstream(&mut reader),
            Err(crate::Error::Malformed("IntFormat mode out of range"))
        ));
    }

    #[test]
    fn rejects_shared_map_count_larger_than_remaining_bits() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        let format = IntFormat::from_values(&[]);
        format.to_writer(&mut writer);
        format.to_writer(&mut writer);
        format.to_writer(&mut writer);
        format.to_writer(&mut writer);
        writer.write_i64(1000);
        let data = writer.finish();
        let mut reader = BitReader::new(&data).unwrap();

        assert!(matches!(
            read_cli_map_bitstream(&mut reader),
            Err(crate::Error::Malformed(
                "rift table entry count exceeds available input"
            ))
        ));
    }

    #[test]
    fn cli_map_bitstream_matches_win26100_stage_fixture_objects() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/FridaStageCapture/cli-map-win26100");
        let object_dir = fixture.join("objects");
        let blob_dir = fixture.join("blobs");
        if !object_dir.exists() {
            return;
        }

        let mut paths = std::fs::read_dir(&object_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(paths.len(), 50);

        let mut empty = 0usize;
        let mut non_empty = 0usize;
        for path in paths {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let native: NativeCliMapRecord = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
            assert_eq!(native.record_type, "CliMapBitstreamRecord");
            assert_eq!(native.native_layout, "msdelta-win26100-compo-cli-map-v1");

            let expected = native_to_cli_map_model(&native, &path);
            if expected.is_empty() {
                empty += 1;
            } else {
                non_empty += 1;
            }

            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_else(|| {
                    panic!("fixture object path has no UTF-8 stem: {}", path.display())
                });
            let blob_path = blob_dir.join(format!("{stem}-reader-bitstream.bin"));
            let bytes = std::fs::read(&blob_path)
                .unwrap_or_else(|error| panic!("read {}: {error}", blob_path.display()));
            let mut reader = BitReader::new(&bytes).unwrap();
            let parsed = read_cli_map_bitstream(&mut reader).unwrap_or_else(|error| {
                panic!(
                    "parse native reader bitstream for {}: {error}",
                    blob_path.display()
                )
            });
            assert_eq!(reader.remaining(), 0, "{} left unread bits", path.display());
            assert_eq!(parsed, expected, "{}", path.display());

            let mut writer = BitWriter::new();
            write_cli_map_bitstream(&mut writer, &expected);
            let encoded = writer.finish();
            let mut encoded_reader = BitReader::new(&encoded).unwrap();
            let reparsed = read_cli_map_bitstream(&mut encoded_reader).unwrap_or_else(|error| {
                panic!(
                    "parse Rust writer bitstream for {}: {error}",
                    blob_path.display()
                )
            });
            assert_eq!(
                reparsed,
                expected,
                "writer output should decode back to the native map model {}",
                blob_path.display()
            );
            if expected.is_empty() {
                assert_eq!(
                    encoded,
                    bytes,
                    "empty map writer should reproduce native absent-map bitstream {}",
                    blob_path.display()
                );
            }
        }

        assert!(empty > 0, "stage fixture should include empty maps");
        assert!(non_empty > 0, "stage fixture should include non-empty maps");
    }

    #[test]
    fn splits_typedef_or_ref_tokens() {
        let token = split_coded_token((7 << 2) | 1, CodedIndexKind::TypeDefOrRef).unwrap();

        assert_eq!(
            token,
            CliCodedToken {
                kind: CodedIndexKind::TypeDefOrRef,
                table_id: TYPE_REF,
                tag: 1,
                rid: 7,
            }
        );
    }

    #[test]
    fn rejects_invalid_tag() {
        assert!(matches!(
            split_coded_token(3, CodedIndexKind::TypeDefOrRef),
            Err(CliCodedTokenMapError::InvalidTag {
                kind: CodedIndexKind::TypeDefOrRef,
                tag: 3,
            })
        ));
    }

    #[test]
    fn every_coded_index_descriptor_splits_and_reassembles_valid_tags() {
        for schema in CODED_INDEXES {
            for (tag, &table_id) in schema.tag_to_table.iter().enumerate() {
                let raw = (3 << schema.tag_bits) | tag as u32;
                let token = split_coded_token(raw, schema.kind).unwrap();

                assert_eq!(token.kind, schema.kind);
                assert_eq!(token.table_id, table_id);
                assert_eq!(token.tag, tag as u32);
                assert_eq!(token.rid, 3);
                assert_eq!(
                    reassemble_coded_token(token.kind, token.table_id, token.tag, token.rid)
                        .unwrap(),
                    raw
                );
            }
        }
    }

    #[test]
    fn preserves_sentinel_table_tags_as_identity() {
        let map = CliCodedTokenMap::new();
        let raw = (12 << 3) | 4;
        let token = split_coded_token(raw, CodedIndexKind::CustomAttributeType).unwrap();

        assert_eq!(token.table_id, TABLE_SENTINEL);
        assert_eq!(
            map.map_coded_token(raw, CodedIndexKind::CustomAttributeType)
                .unwrap(),
            raw
        );
        assert_eq!(
            map.map_coded_token_exact(raw, CodedIndexKind::CustomAttributeType)
                .unwrap(),
            raw
        );
    }

    #[test]
    fn preserves_null_rid_without_looking_up_map() {
        let map = CliCodedTokenMap::new()
            .with_table_map(TYPE_REF, Vec::new())
            .unwrap();

        assert_eq!(
            map.map_coded_token(1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            1
        );
    }

    #[test]
    fn preserves_rid_when_no_table_map_exists() {
        let map = CliCodedTokenMap::new();
        let raw = (9 << 2) | 2;

        assert_eq!(
            map.map_coded_token(raw, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            raw
        );
    }

    #[test]
    fn maps_typedef_or_ref_rid() {
        let map = CliCodedTokenMap::new()
            .with_table_map(TYPE_REF, vec![1, 2, 3, 4, 5, 6, 19])
            .unwrap();

        assert_eq!(
            map.map_coded_token((7 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            (19 << 2) | 1
        );
    }

    #[test]
    fn maps_piecewise_rid_offsets_without_exact_entry() {
        let map = CliCodedTokenMap::new()
            .with_table_entries(
                TYPE_REF,
                [
                    CliRidMapEntry {
                        source: 5,
                        target: 9,
                    },
                    CliRidMapEntry {
                        source: 10,
                        target: 20,
                    },
                ],
            )
            .unwrap();

        assert_eq!(
            map.map_coded_token((7 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            (11 << 2) | 1
        );
    }

    #[test]
    fn exact_mapping_requires_source_rid_entry() {
        let map = CliCodedTokenMap::new()
            .with_table_entries(
                TYPE_REF,
                [
                    CliRidMapEntry {
                        source: 5,
                        target: 9,
                    },
                    CliRidMapEntry {
                        source: 10,
                        target: 20,
                    },
                ],
            )
            .unwrap();

        assert_eq!(
            map.map_coded_token_exact((5 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            (9 << 2) | 1
        );
        assert_eq!(
            map.map_coded_token_exact((7 << 2) | 1, CodedIndexKind::TypeDefOrRef)
                .unwrap(),
            CLI_CODED_TOKEN_EXACT_MISS
        );
    }

    #[test]
    fn maps_has_constant_rid() {
        let map = CliCodedTokenMap::new()
            .with_table_map(PARAM, vec![1, 2, 6])
            .unwrap();

        assert_eq!(
            map.map_coded_token((3 << 2) | 1, CodedIndexKind::HasConstant)
                .unwrap(),
            (6 << 2) | 1
        );
    }

    #[test]
    fn maps_has_custom_attribute_rid() {
        let map = CliCodedTokenMap::new()
            .with_table_map(METHOD_DEF, vec![1, 2, 3, 4, 5, 6, 7, 8, 44])
            .unwrap();

        assert_eq!(
            map.map_coded_token(9 << 5, CodedIndexKind::HasCustomAttribute)
                .unwrap(),
            44 << 5
        );
    }

    #[test]
    fn exact_map_preserves_rid_when_no_table_map_exists() {
        let map = CliCodedTokenMap::new()
            .with_table_map(TYPE_DEF, vec![4])
            .unwrap();

        assert_eq!(
            map.map_coded_token_exact(3 << 2, CodedIndexKind::HasConstant)
                .unwrap(),
            3 << 2
        );
    }

    #[test]
    fn rejects_zero_mapped_non_null_rid() {
        let map = CliCodedTokenMap::new()
            .with_table_map(TYPE_DEF, vec![0])
            .unwrap();

        assert!(matches!(
            map.map_coded_token(1 << 2, CodedIndexKind::TypeDefOrRef),
            Err(CliCodedTokenMapError::InvalidMappedRid {
                table_id: TYPE_DEF,
                source_rid: 1,
                mapped_rid: 0,
            })
        ));
    }

    #[test]
    fn rejects_rid_that_cannot_be_reassembled() {
        let too_large = (u32::MAX >> 2) + 1;
        let map = CliCodedTokenMap::new()
            .with_table_map(TYPE_DEF, vec![too_large])
            .unwrap();

        assert!(matches!(
            map.map_coded_token(1 << 2, CodedIndexKind::TypeDefOrRef),
            Err(CliCodedTokenMapError::RidOverflow {
                kind: CodedIndexKind::TypeDefOrRef,
                table_id: TYPE_DEF,
                rid,
                tag_bits: 2,
            }) if rid == too_large
        ));
    }

    fn present_empty_cli_map() -> Vec<u8> {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        let format = IntFormat::from_values(&[]);
        format.to_writer(&mut writer);
        format.to_writer(&mut writer);
        format.to_writer(&mut writer);
        format.to_writer(&mut writer);
        for _ in 0..68 {
            writer.write_i64(0);
        }
        writer.finish()
    }

    fn roundtrip_cli_map(model: &CliMapModel) -> CliMapModel {
        let mut writer = BitWriter::new();
        write_cli_map_bitstream(&mut writer, model);
        let data = writer.finish();
        let mut reader = BitReader::new(&data).unwrap();
        read_cli_map_bitstream(&mut reader).unwrap()
    }

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    fn assert_entries(table: &RiftTable, expected: &[(i64, i64)]) {
        let actual = table
            .entries
            .iter()
            .map(|entry| (entry.source, entry.target))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    #[derive(Debug, Deserialize)]
    struct NativeCliMapRecord {
        #[serde(rename = "type")]
        record_type: String,
        native_layout: String,
        strings: NativeRiftTable,
        user_strings: NativeRiftTable,
        blob: NativeRiftTable,
        guid: NativeRiftTable,
        tables: Vec<NativeRiftTable>,
    }

    #[derive(Debug, Deserialize)]
    struct NativeRiftTable {
        entries: Vec<NativeRiftEntry>,
        sorted: bool,
    }

    #[derive(Debug, Deserialize)]
    struct NativeRiftEntry {
        source: i64,
        target: i64,
    }

    fn native_to_cli_map_model(native: &NativeCliMapRecord, path: &Path) -> CliMapModel {
        assert_eq!(
            native.tables.len(),
            CLI_TABLE_MAP_COUNT,
            "{} should have {CLI_TABLE_MAP_COUNT} CLI table maps",
            path.display()
        );
        let mut tables = std::array::from_fn(|index| native_rift(&native.tables[index], path));
        for (index, table) in tables.iter_mut().enumerate() {
            table.entries.sort_by_key(|entry| entry.source);
            assert_eq!(
                table.entries,
                native_rift(&native.tables[index], path).entries,
                "{} table {index} should already be sorted by source",
                path.display()
            );
        }

        CliMapModel {
            strings: native_rift(&native.strings, path),
            user_strings: native_rift(&native.user_strings, path),
            blob: native_rift(&native.blob, path),
            guid: native_rift(&native.guid, path),
            tables,
        }
    }

    fn native_rift(native: &NativeRiftTable, path: &Path) -> RiftTable {
        assert!(
            native.sorted,
            "{} native rift table should be sorted",
            path.display()
        );
        RiftTable {
            entries: native
                .entries
                .iter()
                .map(|entry| RiftEntry {
                    source: entry.source,
                    target: entry.target,
                })
                .collect(),
        }
    }
}
