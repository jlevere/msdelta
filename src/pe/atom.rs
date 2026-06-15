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
//! results. Every native PE source transform is now registered here; the next
//! step is folding their bodies into per-atom modules and generating the
//! registry from code.

use super::parse::{PeInfo, PeMachine};
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

// msdelta file-type sets shared by atoms of the same layer, so the strings (which
// the registry test checks against the TSV) live in one place.
pub(crate) const PE_FILE_TYPES: &str = "0x2,0x4,0x8,0x10,0x20,0x40,0x80";
pub(crate) const X86_FILE_TYPES: &str = "0x2,0x10";
pub(crate) const X64_FILE_TYPES: &str = "0x8,0x20";

/// The mutable state a source transform operates over while building T(source).
pub(crate) struct SourceCtx<'a> {
    /// The image buffer, transformed in place from source to T(source).
    pub buf: &'a mut [u8],
    pub pe: &'a PeInfo,
    pub rift: &'a RiftTable,
    /// Per-file-offset copy-provenance marker (bit 0 = owned by an earlier
    /// transform). The RVA-field transforms claim into it; the i386 instruction
    /// passes consult it so they never rewrite bytes a literal already supplied.
    pub marker: &'a mut [u8],
    /// The TARGET image base, written into fields that store absolute VAs.
    pub target_base: u64,
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
/// bit), which is the order genuine `PreProcessPEForApply` runs them. The mix
/// that actually runs is gated per delta by the header flag word and per image
/// by architecture (see [`applies_to_machine`]): an i386 image runs MarkNonExe,
/// the RVA-field transforms, then the jmp/call passes; an amd64 image runs the
/// RVA-field transforms, then DisasmX64 before PdataX64 (the disasm driver reads
/// the still-source-domain `.pdata` Begin/End RVAs to locate functions).
pub(crate) const TRANSFORMS: &[&dyn Transform] = &[
    &super::transform::MarkNonExe,           // 0x2
    &super::transform::TransformImports,     // 0x4
    &super::transform::TransformExports,     // 0x8
    &super::transform::TransformResources,   // 0x10
    &super::transform::TransformRelocations, // 0x20
    &super::transform::RelativeJmpsX86,      // 0x80
    &super::transform::RelativeCallsX86,     // 0x100
    &super::transform::DisasmX64,            // 0x200
    &super::x64::PdataX64,                   // 0x400
];

/// Whether a transform applies to this image's architecture. Derived from the
/// atom's `layer`: `x86` transforms run only on i386, `x64` only on amd64, and
/// `pe`-layer (architecture-agnostic) transforms run on any native image. This
/// keeps an arch-mismatched flag bit in an untrusted delta from running a
/// transform that would corrupt the image.
fn applies_to_machine(layer: &str, pe: &PeInfo) -> bool {
    match layer {
        // Architecture-agnostic PE-structure transforms run on any native image.
        "pe" => true,
        "x86" => matches!(pe.machine, PeMachine::I386),
        "x64" => matches!(pe.machine, PeMachine::Amd64),
        "arm" => matches!(pe.machine, PeMachine::ArmNt),
        "arm64" => matches!(pe.machine, PeMachine::Arm64),
        // A non-architectural layer must never reach dispatch; rather than run an
        // atom on the wrong machine, do not run it. `registered_layers_are_
        // architectural` guards that no such layer is ever registered.
        _ => false,
    }
}

/// Run every registered transform whose flag bit is set and whose architecture
/// matches, in registry order, building T(source) in place.
pub(crate) fn run_registered(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    marker: &mut [u8],
    target_base: u64,
    flags: u64,
) {
    let mut ctx = SourceCtx {
        buf,
        pe,
        rift,
        marker,
        target_base,
    };
    for transform in TRANSFORMS {
        let meta = transform.meta();
        if flags & meta.flag_mask != 0 && applies_to_machine(meta.layer, pe) {
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
    /// Every registered transform's layer must be one `applies_to_machine`
    /// treats as architectural; otherwise it would hit the `_ => false` arm and
    /// silently never run. This stops a future non-arch layer from quietly
    /// disabling an atom.
    #[test]
    fn registered_layers_are_architectural() {
        for transform in TRANSFORMS {
            let meta = transform.meta();
            assert!(
                matches!(meta.layer, "pe" | "x86" | "x64" | "arm" | "arm64"),
                "{} has non-architectural layer {}; applies_to_machine would never run it",
                meta.id,
                meta.layer
            );
        }
    }

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
