//! Strongly typed CLR metadata token primitives.
//!
//! The managed transforms should operate on table ids, RIDs, and metadata
//! tokens through these types instead of passing raw bytes and magic masks.

use crate::{Error, Result};
use std::num::NonZeroU32;

pub(crate) const METADATA_TOKEN_TYPE_SHIFT: u32 = 24;
pub(crate) const METADATA_TOKEN_RID_MASK: u32 = 0x00ff_ffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MetadataTableId(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MetadataRid(NonZeroU32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct MetadataToken {
    table: MetadataTableId,
    rid: MetadataRid,
}

impl MetadataTableId {
    pub(crate) const MAX_TABLE_ID: u8 = 0x3f;

    pub(crate) const fn new_unchecked(value: u8) -> Self {
        Self(value)
    }

    pub(crate) fn new(value: u8) -> Result<Self> {
        if value <= Self::MAX_TABLE_ID {
            Ok(Self(value))
        } else {
            Err(Error::Malformed("CLI metadata token: invalid table id"))
        }
    }

    pub(crate) const fn get(self) -> u8 {
        self.0
    }

    pub(crate) const fn token_type(self) -> u32 {
        (self.0 as u32) << METADATA_TOKEN_TYPE_SHIFT
    }
}

impl MetadataRid {
    pub(crate) const MAX_RID: u32 = METADATA_TOKEN_RID_MASK;

    pub(crate) fn new(value: u32) -> Result<Self> {
        let Some(value) = NonZeroU32::new(value) else {
            return Err(Error::Malformed("CLI metadata token: RID is zero"));
        };
        if value.get() <= Self::MAX_RID {
            Ok(Self(value))
        } else {
            Err(Error::Malformed("CLI metadata token: RID is too large"))
        }
    }

    pub(crate) const fn get(self) -> u32 {
        self.0.get()
    }
}

impl MetadataToken {
    pub(crate) fn new(table: MetadataTableId, rid: MetadataRid) -> Self {
        Self { table, rid }
    }

    pub(crate) fn from_raw(raw: u32) -> Result<Self> {
        let table = MetadataTableId::new((raw >> METADATA_TOKEN_TYPE_SHIFT) as u8)?;
        let rid = MetadataRid::new(raw & METADATA_TOKEN_RID_MASK)?;
        Ok(Self { table, rid })
    }

    pub(crate) const fn table(self) -> MetadataTableId {
        self.table
    }

    pub(crate) const fn rid(self) -> MetadataRid {
        self.rid
    }

    pub(crate) const fn to_raw(self) -> u32 {
        self.table.token_type() | self.rid.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_token_roundtrips_raw_value() {
        let token = MetadataToken::from_raw(0x0600_0007).unwrap();

        assert_eq!(token.table().get(), 0x06);
        assert_eq!(token.rid().get(), 7);
        assert_eq!(token.to_raw(), 0x0600_0007);
    }

    #[test]
    fn metadata_token_rejects_zero_rid() {
        assert!(matches!(
            MetadataToken::from_raw(0x0600_0000),
            Err(Error::Malformed("CLI metadata token: RID is zero"))
        ));
    }

    #[test]
    fn metadata_token_rejects_large_rid() {
        assert!(matches!(
            MetadataRid::new(0x0100_0000),
            Err(Error::Malformed("CLI metadata token: RID is too large"))
        ));
    }

    #[test]
    fn metadata_table_id_rejects_non_metadata_table() {
        assert!(matches!(
            MetadataTableId::new(0x40),
            Err(Error::Malformed("CLI metadata token: invalid table id"))
        ));
    }
}
