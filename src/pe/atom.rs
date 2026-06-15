//! The transform-atom trait, metadata, and registry.
//!
//! Each PE source transform is a zero-sized type implementing [`Transform`] in
//! its own module, carrying its own [`AtomMeta`]. A unit test asserts that
//! every *registered* transform's structural columns match its row in
//! `docs/feature-atoms.tsv`, so a migrated atom and its registry row cannot
//! silently disagree.
//!
//! This is one direction of the eventual generate-from-code contract: it checks
//! the atoms that have been migrated, not yet the whole file (un-migrated rows
//! and rows-without-code are still only guarded by `tests/feature_atoms_
//! registry.rs`). Status, apply policy, oracle level, and proof stay
//! registry-owned until the re-rail plan's Phase 2 derives them from oracle
//! results. Transforms are migrated out of `transform.rs` one at a time;
//! `PdataX64` is the first.

use super::parse::PeInfo;
use crate::lzx::rift::RiftTable;

/// The structural identity of an atom: the registry columns derived from code,
/// not from oracle results.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AtomMeta {
    pub id: &'static str,
    pub layer: &'static str,
    pub kind: &'static str,
    pub file_types: &'static str,
    /// `g_transformsMap` selection bit, AND'd against the delta header flag word.
    pub flag_mask: u64,
    pub native_reference: &'static str,
}

/// The mutable state a source transform operates over while building T(source).
/// Fields are added as atoms that need them migrate behind the trait.
pub(crate) struct SourceCtx<'a> {
    /// The image buffer, transformed in place from source to T(source).
    pub buf: &'a mut [u8],
    pub pe: &'a PeInfo,
    pub rift: &'a RiftTable,
}

/// One PE source transform: `source -> T(source)`, applied in place.
///
/// The same transform runs on both the create and apply pipelines (genuine
/// `PreProcessPEForApply` is shared), so it has a single direction; the
/// bidirectional validation in the re-rail plan is a property of the pipeline,
/// not a method pair on this trait.
pub(crate) trait Transform {
    fn meta(&self) -> AtomMeta;
    fn apply(&self, ctx: &mut SourceCtx<'_>);
}

/// The registered transforms, kept in `g_transformsMap` order (ascending flag
/// bit). [`run_registered`] preserves this order, and its call site in
/// `build_transformed_source` runs *after* the not-yet-migrated inline
/// transforms -- so atoms must be migrated in suffix order (highest flag bits
/// first) for the composed order to stay correct. Today only `PdataX64` (the
/// last bit, `0x400`) is registered, so the rule holds trivially.
pub(crate) const TRANSFORMS: &[&dyn Transform] = &[&super::x64::PdataX64];

/// Run every registered transform whose flag bit is set, in registry order,
/// building T(source) in place.
pub(crate) fn run_registered(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, flags: u64) {
    let mut ctx = SourceCtx { buf, pe, rift };
    for transform in TRANSFORMS {
        if flags & transform.meta().flag_mask != 0 {
            transform.apply(&mut ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &str = include_str!("../../docs/feature-atoms.tsv");

    /// For a migrated atom, the code is the source of truth for its structural
    /// columns. If a registered transform's row drifts -- a renamed flag mask, a
    /// moved layer, a deleted row -- this fails, so the registry cannot silently
    /// disagree with the code that implements that atom.
    #[test]
    fn registered_transforms_match_registry_structural_columns() {
        for transform in TRANSFORMS {
            let meta = transform.meta();
            let row = REGISTRY
                .lines()
                .find(|line| line.split('\t').next() == Some(meta.id))
                .unwrap_or_else(|| {
                    panic!(
                        "{} is registered in code but absent from feature-atoms.tsv",
                        meta.id
                    )
                });
            let cols: Vec<&str> = row.split('\t').collect();
            assert_eq!(cols[1], meta.layer, "{}: layer", meta.id);
            assert_eq!(cols[2], meta.kind, "{}: kind", meta.id);
            assert_eq!(cols[3], meta.file_types, "{}: file_types", meta.id);
            assert_eq!(
                cols[4],
                format!("0x{:x}", meta.flag_mask),
                "{}: flag_mask",
                meta.id
            );
            assert_eq!(
                cols[5], meta.native_reference,
                "{}: native_reference",
                meta.id
            );
        }
    }
}
