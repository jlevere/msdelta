//! Typed PE address domains.
//!
//! Most byte-level bugs in the transform pipeline come from mixing the address
//! domains -- source RVA, target RVA, source file offset, target file offset --
//! which are all just `u32`/`usize` to the compiler, so a `+` or `as` between
//! two of them compiles and silently lands the wrong byte. These newtypes make
//! the domains distinct types, with conversions only through named functions
//! (the rift maps a source RVA to a target RVA), so a domain mismatch is a
//! compile error.
//!
//! This module currently types the RVA domains, where the rift conversion lives.
//! File-offset domains stay bare `usize` until an atom that mixes them migrates
//! behind the [`Transform`](super::atom::Transform) trait and needs the guard.

use crate::lzx::rift::RiftTable;

/// A relative virtual address in the SOURCE image's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SrcRva(pub u32);

/// A relative virtual address in the TARGET image's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TgtRva(pub u32);

/// `MapRva`: map a source RVA to its target RVA through the (coarse) rift.
/// Piecewise: `rva + (target-source)` of the bracketing entry; identity when
/// empty. Mirrors `TransformBase::MapRva` (dpx 0x180041998). The `i64` form
/// serves the transforms that take RVA differences; [`map_rva`] is the typed
/// wrapper for the in-place field remaps.
#[inline]
pub(crate) fn map_rva_i64(rift: &RiftTable, rva: i64) -> i64 {
    rva + rift.map(rva)
}

/// Map a source-domain RVA to its target-domain RVA. The only sanctioned
/// `SrcRva -> TgtRva` conversion.
pub(crate) fn map_rva(rift: &RiftTable, src: SrcRva) -> TgtRva {
    TgtRva(map_rva_i64(rift, i64::from(src.0)) as u32)
}
