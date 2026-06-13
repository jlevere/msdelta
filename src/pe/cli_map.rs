//! CLI metadata coded-token RID remapping.

use crate::pe::cli_schema::{coded_index_schema, table_schema, CodedIndexKind, TABLE_SENTINEL};
use thiserror::Error;

pub(crate) type CliMapResult<T> = std::result::Result<T, CliCodedTokenMapError>;
pub(crate) const CLI_CODED_TOKEN_EXACT_MISS: u32 = u32::MAX;

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
    use crate::pe::cli_schema::CODED_INDEXES;

    const TYPE_DEF: u8 = 0x02;
    const TYPE_REF: u8 = 0x01;
    const PARAM: u8 = 0x08;
    const METHOD_DEF: u8 = 0x06;

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
}
