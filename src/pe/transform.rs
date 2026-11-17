//! PE file type transforms applied during MSDelta decode/encode.
//!
//! For PE deltas, the source image is transformed before LZX reconstruction.
//! The selected passes remap structural fields and instruction operands into
//! the target address domain; header fixups also run on the reconstructed output.

use super::atom::{AtomMeta, ClassicCliSource, SourceCtx, Transform};
use super::markers::mark_non_executable;
#[cfg(test)]
use super::parse::PeMachine;
use super::parse::{DataDirectoryKind, PeHeaderLayout, PeInfo, PeOptionalHeaderKind};
use super::relocations::transform_source_relocs;
use crate::pe::cli::metadata::CliMetadataModel;
use crate::pe::cli::method::{cli_method_bodies, CliMethodBody};
use crate::Result;

/// MSDelta file type flags.
pub const FILE_TYPE_RAW: i64 = 1;
pub const FILE_TYPE_I386: i64 = 2;
pub const FILE_TYPE_IA64: i64 = 4;
pub const FILE_TYPE_AMD64: i64 = 8;
pub const FILE_TYPE_CLI4_I386: i64 = 0x10;
pub const FILE_TYPE_CLI4_AMD64: i64 = 0x20;
pub const FILE_TYPE_CLI4_ARM: i64 = 0x40;
pub const FILE_TYPE_CLI4_ARM64: i64 = 0x80;

/// Header transform-selection flag bits: the word genuine PreProcessPEForApply
/// ANDs against `g_transformsMap`, one bit per transform, in transform-graph
/// order. Replaces scattered bare hex; values are the genuine bit positions.
pub(crate) mod transform_flags {
    pub(crate) const MARK_NON_EXE: u64 = 0x2;
    pub(crate) const IMPORTS: u64 = 0x4;
    pub(crate) const EXPORTS: u64 = 0x8;
    pub(crate) const RESOURCES: u64 = 0x10;
    pub(crate) const RELOCATIONS: u64 = 0x20;
    pub(crate) const SMASH_LOCK_PREFIXES_X86: u64 = 0x40;
    pub(crate) const RELATIVE_JMPS_X86: u64 = 0x80;
    pub(crate) const RELATIVE_CALLS_X86: u64 = 0x100;
    pub(crate) const DISASM_X64: u64 = 0x200;
    pub(crate) const PDATA_X64: u64 = 0x400;
    /// Runs first: reset bound imports + mark `.idata` writable.
    pub(crate) const PE_UNBINDER: u64 = 0x2000;
    /// Classic-CLI managed: remap metadata tokens in IL method bodies.
    pub(crate) const CLI_DISASM: u64 = 0x4000;
    /// Classic-CLI managed: remap metadata-table + signature-blob coded indexes.
    pub(crate) const CLI_METADATA: u64 = 0x8000;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedBranch {
    ClassicCli,
    Cli4,
}

pub(crate) fn managed_branch_for_file_type(file_type: i64) -> Option<ManagedBranch> {
    match file_type {
        FILE_TYPE_I386 | FILE_TYPE_IA64 | FILE_TYPE_AMD64 => Some(ManagedBranch::ClassicCli),
        FILE_TYPE_CLI4_I386 | FILE_TYPE_CLI4_AMD64 | FILE_TYPE_CLI4_ARM | FILE_TYPE_CLI4_ARM64 => {
            Some(ManagedBranch::Cli4)
        }
        _ => None,
    }
}

const RELOC_MARKER: u32 = 0x01010101;
const RELOC_CHECK: u32 = 0x02020202;

/// Upper bound on the import-descriptor walk (a malformed table without a
/// null terminator must not loop unboundedly).
const MAX_IMPORT_DESCRIPTORS: usize = 4096;

use crate::lzx::rift::RiftTable;
// The canonical RVA mapper lives with the typed address domains in `pe::addr`.
use super::addr::{map_rva_i64 as map_rva, SrcRva};

/// Claim `len` bytes at file offset `fo` in the transform marker (bit 0 = owned),
/// so a later instruction pass does not also rewrite them.
fn mark_bytes(marker: &mut [u8], fo: usize, len: usize) {
    for m in marker.iter_mut().skip(fo).take(len) {
        *m |= 1;
    }
}

/// Map the 4-byte RVA at file offset `fo` through the rift in place (`new = rva +
/// rift.map(rva)`), then claim its bytes in the marker. The shared per-RVA-field
/// primitive for the import/export/(resource) transforms.
fn map_rva_field(buf: &mut [u8], marker: &mut [u8], fo: usize, rift: &RiftTable) {
    let v = crate::pe::structs::read_u32(buf, fo) as i64;
    if v != 0 {
        crate::pe::structs::write_u32(buf, fo, (v + rift.map(v)) as u32);
    }
    mark_bytes(marker, fo, 4);
}

fn rva_to_file_off(pe: &PeInfo, rva: i64) -> Option<usize> {
    pe.rva_to_file_offset(u32::try_from(rva).ok()?)
}

/// Build `T(source)`: the source image transformed exactly as genuine
/// `ApplyDeltaB`'s `PreProcessPEForApply` transforms it before the LZX copy
/// stage, so copies land bit-identical to genuine. `buf` is a clone of the
/// reference; `pe` is parsed from the original source; `rift` is the delta's (coarse) preprocess rift; `flags` is the
/// header transform-selection word. Transforms run in `g_transformsMap` order
/// (relocations, then jmps, then calls), each consulting/updating a per-file-
/// offset marker so a later transform never rewrites bytes an earlier one owns.
pub(crate) fn build_transformed_source(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    flags: u64,
    target_base: u64,
    target_timestamp: u32,
) {
    build_transformed_source_with_cli(buf, pe, rift, flags, target_base, target_timestamp, None);
}

pub(crate) fn build_transformed_source_with_cli(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    flags: u64,
    target_base: u64,
    target_timestamp: u32,
    cli: Option<ClassicCliSource<'_>>,
) {
    // PeUnbinder (flag bit 13, runs first in PreProcessPEForApply before the
    // transform executor): reset bound imports and mark .idata writable.
    if flags & transform_flags::PE_UNBINDER != 0 {
        #[cfg(test)]
        crate::pa30::pipeline_tests::record_buffer("PeUnbinder", "before", buf, None);
        unbind_pe(buf, pe);
        #[cfg(test)]
        crate::pa30::pipeline_tests::record_buffer("PeUnbinder", "after", buf, None);
    }
    // Run the registered source transforms in g_transformsMap order, each gated
    // by its header flag bit and the image architecture (see pe::atom). Running
    // on the SOURCE (producing T(source)) is the only correct architecture: the
    // LZX copy/literal split was defined against genuine's T(source), so a copy
    // reads the transformed byte while a literal already carries the target byte
    // -- a post-decode remap could not tell them apart and would double-apply
    // the rift on literal-provided fields (e.g. comctl32 amd64 .pdata
    // UnwindData). The marker carries structural ownership so a later i386
    // instruction pass never rewrites bytes an earlier transform owns.
    let mut marker = vec![0u8; buf.len()];
    crate::pe::atom::run_registered_with_cli(buf, pe, rift, &mut marker, target_base, flags, cli);
    // Header normalization follows the source transformations. Those passes
    // must still see the source image base, timestamp, and checksum.
    #[cfg(test)]
    crate::pa30::pipeline_tests::record_buffer("PeImageBase", "before", buf, None);
    set_header_image_base(buf, target_base);
    #[cfg(test)]
    crate::pa30::pipeline_tests::record_buffer("PeImageBase", "after", buf, None);
    #[cfg(test)]
    crate::pa30::pipeline_tests::record_buffer("PeTimeStamp", "before", buf, None);
    set_header_timestamp(buf, target_timestamp);
    #[cfg(test)]
    crate::pa30::pipeline_tests::record_buffer("PeTimeStamp", "after", buf, None);
    #[cfg(test)]
    crate::pa30::pipeline_tests::record_buffer("ZeroPeChecksum", "before", buf, None);
    zero_pe_checksum(buf);
    #[cfg(test)]
    crate::pa30::pipeline_tests::record_buffer("ZeroPeChecksum", "after", buf, None);
}

// Transform-atom adapters. Each is a zero-sized type registered in `pe::atom`;
// its `apply` is the boundary into the implementation function below. (The
// `meta()` structural columns are checked against `feature-atoms.tsv` by the
// registry test.) The bodies stay as free functions for now; folding them into
// the trait method and out into per-atom modules is the next cleanup.

/// `MarkNonExe` (mask `0x2`, runs first): mark PE structural ranges and
/// non-executable section data before instruction transformations.
pub(crate) struct MarkNonExe;
impl Transform for MarkNonExe {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "MarkNonExe",
            layer: "pe",
            kind: "source_transform",
            file_types: crate::pe::atom::PE_FILE_TYPES,
            flag_mask: transform_flags::MARK_NON_EXE,
            native_reference: "MarkNonExe::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        mark_non_executable(ctx.buf, ctx.pe, ctx.marker);
        if let Some(cli) = ctx.cli {
            // Native classic CLI ownership excludes the final MethodDef row,
            // just like its IL transform. General method enumeration remains
            // inclusive; this boundary belongs to the MSDelta stage.
            let method_limit =
                cli.metadata.row_counts[crate::pe::cli::schema::table::METHOD_DEF as usize];
            for body in cli_method_bodies(ctx.buf, ctx.pe, cli.metadata)
                .into_iter()
                .filter(|body| body.rid < method_limit)
            {
                mark_marker_range(ctx.marker, body.file_offset, body.total_size, 3);
            }
        }
    }
}

/// `TransformImports` (mask `0x4`): map the import descriptor and thunk RVAs.
pub(crate) struct TransformImports;
impl Transform for TransformImports {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "TransformImports",
            layer: "pe",
            kind: "source_transform",
            file_types: crate::pe::atom::PE_FILE_TYPES,
            flag_mask: transform_flags::IMPORTS,
            native_reference: "TransformImports::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_source_imports(ctx.buf, ctx.pe, ctx.rift, ctx.marker, ctx.target_base);
    }
}

/// `TransformExports` (mask `0x8`): map the export address/name-pointer RVAs.
pub(crate) struct TransformExports;
impl Transform for TransformExports {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "TransformExports",
            layer: "pe",
            kind: "source_transform",
            file_types: crate::pe::atom::PE_FILE_TYPES,
            flag_mask: transform_flags::EXPORTS,
            native_reference: "TransformExports::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_source_exports(ctx.buf, ctx.pe, ctx.rift, ctx.marker);
    }
}

/// `TransformResources` (mask `0x10`): recursively remap the resource-dir RVAs.
pub(crate) struct TransformResources;
impl Transform for TransformResources {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "TransformResources",
            layer: "pe",
            kind: "source_transform",
            file_types: crate::pe::atom::PE_FILE_TYPES,
            flag_mask: transform_flags::RESOURCES,
            native_reference: "TransformResources::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_source_resources(ctx.buf, ctx.pe, ctx.rift, ctx.marker);
    }
}

/// `TransformRelocations` (mask `0x20`): rebuild the base-relocation blocks and
/// remap each pointed-to operand.
pub(crate) struct TransformRelocations;
impl Transform for TransformRelocations {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "TransformRelocations",
            layer: "pe",
            kind: "source_transform",
            file_types: crate::pe::atom::PE_FILE_TYPES,
            flag_mask: transform_flags::RELOCATIONS,
            native_reference: "TransformRelocations::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        if super::inferred_relocations::uses_inferred_relocations(ctx.buf, ctx.pe) {
            super::inferred_relocations::transform(
                ctx.buf,
                ctx.pe,
                ctx.rift,
                ctx.marker,
                ctx.target_base,
            );
        } else {
            transform_source_relocs(ctx.buf, ctx.pe, ctx.rift, ctx.marker, ctx.target_base);
        }
    }
}

pub(crate) struct SmashLockPrefixesX86;
impl Transform for SmashLockPrefixesX86 {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "SmashLockPrefixesX86",
            layer: "x86",
            kind: "source_transform",
            file_types: crate::pe::atom::X86_FILE_TYPES,
            flag_mask: transform_flags::SMASH_LOCK_PREFIXES_X86,
            native_reference: "SmashLockPrefixesI386::InternalProcess",
        }
    }

    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        super::lock_prefixes::smash_lock_prefixes(ctx.buf, ctx.pe);
    }
}

/// `RelativeJmpsX86` (mask `0x80`, i386): remap `0xE9` jmp displacements over
/// bytes copied from the (transformed) source.
pub(crate) struct RelativeJmpsX86;
impl Transform for RelativeJmpsX86 {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "RelativeJmpsX86",
            layer: "x86",
            kind: "source_transform",
            file_types: crate::pe::atom::X86_FILE_TYPES,
            flag_mask: transform_flags::RELATIVE_JMPS_X86,
            native_reference: "RelativeJmpsX86::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_source_jmps_i386(ctx.buf, ctx.pe, ctx.rift, ctx.marker);
    }
}

/// `RelativeCallsX86` (mask `0x100`, i386): remap `0xE8` call displacements.
pub(crate) struct RelativeCallsX86;
impl Transform for RelativeCallsX86 {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "RelativeCallsX86",
            layer: "x86",
            kind: "source_transform",
            file_types: crate::pe::atom::X86_FILE_TYPES,
            flag_mask: transform_flags::RELATIVE_CALLS_X86,
            native_reference: "RelativeCallsX86::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_source_calls_i386(ctx.buf, ctx.pe, ctx.rift, ctx.marker);
    }
}

/// `DisasmX64` (mask `0x200`, amd64): remap RIP-relative disp32 / rel32
/// operands. Runs before `PdataX64`, which reads the source-domain `.pdata`
/// Begin/End RVAs to locate functions.
pub(crate) struct DisasmX64;
impl Transform for DisasmX64 {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "DisasmX64",
            layer: "x64",
            kind: "source_transform",
            file_types: crate::pe::atom::X64_FILE_TYPES,
            flag_mask: transform_flags::DISASM_X64,
            native_reference: "TransformDisasmX64::Run",
        }
    }
    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_disasm_x64(ctx.buf, ctx.pe, ctx.rift);
    }
}

/// Write the TARGET image base into the source header's `ImageBase` field, the
/// way genuine `PreProcessPEForApply` does after running the transform executor
/// (`SectionHelper::SetImageBase64`/`SetImageBase32`). The LZX copy/literal split
/// was defined against this T(source), so when source and target image bases
/// differ (e.g. a rebased binary), the field must already hold the target value
/// here -- otherwise a copy that reads it lands the stale source base.
fn set_header_image_base(buf: &mut [u8], target_base: u64) {
    let Ok(layout) = PeHeaderLayout::parse(buf) else {
        return;
    };
    let Some(offset) = layout.image_base_offset() else {
        return;
    };
    match layout.optional_header_kind {
        PeOptionalHeaderKind::Pe32Plus if offset + 8 <= buf.len() => {
            buf[offset..offset + 8].copy_from_slice(&target_base.to_le_bytes());
        }
        PeOptionalHeaderKind::Pe32 if offset + 4 <= buf.len() => {
            buf[offset..offset + 4].copy_from_slice(&(target_base as u32).to_le_bytes());
        }
        _ => {}
    };
}

/// Write the target COFF `TimeDateStamp` into the PE `FileHeader`, as
/// `PreProcessPEForApply` does.
fn set_header_timestamp(buf: &mut [u8], ts: u32) {
    let Ok(layout) = PeHeaderLayout::parse(buf) else {
        return;
    };
    let Some(offset) = layout.timestamp_offset() else {
        return;
    };
    if offset + 4 <= buf.len() {
        buf[offset..offset + 4].copy_from_slice(&ts.to_le_bytes());
    };
}

/// `PeUnbinder::Unbind` (dpx 0x18003d8d8), run by `PreProcessPEForApply` before
/// the transform executor when header flag bit 13 is set. Resets bound imports
/// so a delta diffed against an unbound image applies cleanly: for each import
/// descriptor with a non-zero `TimeDateStamp`, zero the stamp + `ForwarderChain`
/// and copy the ILT (`OriginalFirstThunk`) over the IAT (`FirstThunk`); then mark
/// the `.idata` section writable (Characteristics |= MEM_WRITE|MEM_READ). (The
/// bound-import *directory* clear is omitted; none of our fixtures carry one.)
fn unbind_pe(buf: &mut [u8], pe: &PeInfo) {
    use crate::pe::structs::{self, ImageImportDescriptor, ImageSectionHeader};

    let ptr = if pe.is_64bit { 8usize } else { 4 };

    // Unbind each bound import descriptor (non-zero TimeDateStamp): clear the
    // stamp + forwarder chain and copy the ILT (OriginalFirstThunk) over the IAT
    // (FirstThunk), restoring the unbound thunk array.
    if let Some(imports) = pe.data_directory(DataDirectoryKind::Import) {
        if imports.rva != 0 {
            if let Some(desc0) = rva_to_file_off(pe, imports.rva as i64) {
                for di in 0..MAX_IMPORT_DESCRIPTORS {
                    let dfo = desc0 + di * size_of::<ImageImportDescriptor>();
                    let Some(d) = structs::read::<ImageImportDescriptor>(buf, dfo) else {
                        break;
                    };
                    if d.original_first_thunk.get() == 0
                        && d.name.get() == 0
                        && d.first_thunk.get() == 0
                    {
                        break; // null-terminator descriptor
                    }
                    if d.time_date_stamp.get() == 0 {
                        continue; // not bound
                    }
                    if let Some(m) = structs::view_mut::<ImageImportDescriptor>(buf, dfo) {
                        m.time_date_stamp.set(0);
                        m.forwarder_chain.set(0);
                    }
                    let (Some(ilt), Some(iat)) = (
                        rva_to_file_off(pe, d.original_first_thunk.get() as i64),
                        rva_to_file_off(pe, d.first_thunk.get() as i64),
                    ) else {
                        continue;
                    };
                    let mut k = 0usize;
                    loop {
                        let (s, dst) = (ilt + k * ptr, iat + k * ptr);
                        if s + ptr > buf.len() || dst + ptr > buf.len() {
                            break;
                        }
                        let thunk = if pe.is_64bit {
                            structs::read_u64(buf, s)
                        } else {
                            structs::read_u32(buf, s) as u64
                        };
                        if thunk == 0 {
                            break; // end of thunk array
                        }
                        buf.copy_within(s..s + ptr, dst);
                        k += 1;
                    }
                }
            }
        }
    }

    // Mark the .idata section writable (Characteristics |= MEM_WRITE|MEM_READ).
    if let Some((table, count)) = structs::section_table(buf) {
        for i in 0..count {
            let sh = table + i * ImageSectionHeader::SIZE;
            if let Some(hdr) = structs::view_mut::<ImageSectionHeader>(buf, sh) {
                if hdr.name_eq(b".idata") {
                    let c = hdr.characteristics.get() | structs::SCN_MEM_WRITE_READ;
                    hdr.characteristics.set(c);
                }
            }
        }
    }
}

/// `TransformImports` (dpx, g_transformsMap mask 0x4): map the import
/// directory's RVA fields and thunk-array entries through the rift. Per
/// descriptor: walk the ILT (OriginalFirstThunk) and IAT (FirstThunk) -- each
/// by-name thunk holds an IMAGE_IMPORT_BY_NAME RVA to map (by-ordinal entries,
/// high bit set, are skipped); a BOUND IAT (TimeDateStamp != 0) holds absolute
/// VAs mapped like relocations. Then map the descriptor's
/// OriginalFirstThunk/Name/FirstThunk fields. Handles both PE32 (4-byte thunks,
/// ordinal flag bit 31) and PE32+ (8-byte thunks, ordinal flag bit 63); the
/// descriptor layout and its RVA fields are identical across both.
fn transform_source_imports(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    marker: &mut [u8],
    target_base: u64,
) {
    use crate::pe::structs::{self, ImageImportDescriptor};
    use std::mem::offset_of;

    let ptr = if pe.is_64bit { 8usize } else { 4 };
    let ordinal_flag: u64 = if pe.is_64bit { 1 << 63 } else { 1 << 31 };
    let image_base = pe.image_base as i64;
    let header_extent = header_file_extent(buf);
    let imports = match pe.data_directory(DataDirectoryKind::Import) {
        Some(value) if value.rva != 0 => value,
        _ => return,
    };
    let Some(desc0) = rva_to_file_off(pe, imports.rva as i64) else {
        return;
    };

    for di in 0..MAX_IMPORT_DESCRIPTORS {
        let dfo = desc0 + di * size_of::<ImageImportDescriptor>();
        let Some(d) = structs::read::<ImageImportDescriptor>(buf, dfo) else {
            break;
        };
        let (oft, tds, name, ft) = (
            d.original_first_thunk.get(),
            d.time_date_stamp.get(),
            d.name.get(),
            d.first_thunk.get(),
        );
        if oft == 0 && name == 0 && ft == 0 {
            break; // null-terminator descriptor
        }
        // Walk a pointer-sized thunk array. `bound` => a bound IAT holding
        // absolute VAs (mapped like relocations); otherwise each by-name entry is
        // an IMAGE_IMPORT_BY_NAME RVA and by-ordinal entries (high bit) are slots.
        let walk = |buf: &mut [u8], marker: &mut [u8], arr_rva: u32, bound: bool| {
            let Some(base) = (arr_rva != 0)
                .then(|| rva_to_file_off(pe, arr_rva as i64))
                .flatten()
            else {
                return;
            };
            let mut k = 0usize;
            loop {
                let fo = base + k * ptr;
                if fo + ptr > buf.len() {
                    break;
                }
                let v = if pe.is_64bit {
                    structs::read_u64(buf, fo)
                } else {
                    structs::read_u32(buf, fo) as u64
                };
                if v == 0 {
                    break; // end of thunk array
                }
                if bound && tds != 0 {
                    let r = v as i64 - image_base;
                    let nv = (target_base as i64)
                        .wrapping_add(r)
                        .wrapping_add(rift.map(r)) as u64;
                    if pe.is_64bit {
                        structs::write_u64(buf, fo, nv);
                    } else {
                        structs::write_u32(buf, fo, nv as u32);
                    }
                } else if v & ordinal_flag == 0 {
                    // by-name: low 32 bits are the IMAGE_IMPORT_BY_NAME RVA (a
                    // 32-bit RVA even in an 8-byte PE32+ thunk; high dword zero).
                    if let Some(name_range) =
                        import_name_file_range(buf, pe, SrcRva(v as u32), header_extent)
                    {
                        marker[name_range].fill(3);
                        map_rva_field(buf, marker, fo, rift);
                    }
                }
                // Every nonzero slot is structural, including ordinals and
                // invalid name references. The zero terminator is not claimed.
                marker[fo..fo + ptr].fill(3);
                k += 1;
            }
        };
        walk(buf, marker, oft, false);
        walk(buf, marker, ft, tds != 0);
        // The descriptor's own RVA fields: Name, OriginalFirstThunk, FirstThunk.
        map_rva_field(
            buf,
            marker,
            dfo + offset_of!(ImageImportDescriptor, name),
            rift,
        );
        map_rva_field(
            buf,
            marker,
            dfo + offset_of!(ImageImportDescriptor, original_first_thunk),
            rift,
        );
        map_rva_field(
            buf,
            marker,
            dfo + offset_of!(ImageImportDescriptor, first_thunk),
            rift,
        );
    }
}

/// Locate an import's hint, name, and terminating NUL within the same
/// file-backed PE range. Native lookup requires four available bytes even for
/// an empty name; a NUL in the next section cannot validate this reference.
fn import_name_file_range(
    buf: &[u8],
    pe: &PeInfo,
    name: SrcRva,
    header_extent: usize,
) -> Option<std::ops::Range<usize>> {
    let (start, end) = if (name.0 as usize) < header_extent {
        (name.0 as usize, header_extent)
    } else {
        pe.sections.iter().find_map(|section| {
            let relative = name.0.checked_sub(section.virtual_address)?;
            if relative >= section.raw_size {
                return None;
            }
            let available = section.raw_size - relative;
            let start = (section.raw_offset as usize).checked_add(relative as usize)?;
            let end = start.checked_add(available as usize)?.min(buf.len());
            Some((start, end))
        })?
    };
    if end.checked_sub(start)? < 4 {
        return None;
    }
    let name_len = buf
        .get(start + 2..end)?
        .iter()
        .position(|&byte| byte == 0)?;
    Some(start..start + 3 + name_len)
}

/// `TransformExports` (dpx, g_transformsMap mask 0x8): map the export
/// directory's RVA fields and its AddressOfFunctions / AddressOfNames RVA
/// arrays through the rift, marking the bytes. comctl32's export table lives in
/// `.text`, so these are the residual `.text` RVAs after calls/jmps.
fn transform_source_exports(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, marker: &mut [u8]) {
    use crate::pe::structs::{self, ImageExportDirectory};
    use std::mem::offset_of;

    let exports = match pe.data_directory(DataDirectoryKind::Export) {
        Some(value) if value.rva != 0 => value,
        _ => return,
    };
    let Some(dfo) = rva_to_file_off(pe, exports.rva as i64) else {
        return;
    };
    let Some(ed) = structs::read::<ImageExportDirectory>(buf, dfo) else {
        return;
    };

    // The two RVA arrays: AddressOfFunctions[NumberOfFunctions] and
    // AddressOfNames[NumberOfNames]. (The ordinal array holds u16 ordinals, not
    // RVAs, so it is not mapped.)
    for (arr_rva, count) in [
        (ed.address_of_functions.get(), ed.number_of_functions.get()),
        (ed.address_of_names.get(), ed.number_of_names.get()),
    ] {
        if arr_rva != 0 {
            if let Some(base) = rva_to_file_off(pe, arr_rva as i64) {
                for i in 0..count as usize {
                    map_rva_field(buf, marker, base + i * 4, rift);
                }
            }
        }
    }
    // The directory's own RVA fields.
    for off in [
        offset_of!(ImageExportDirectory, name),
        offset_of!(ImageExportDirectory, address_of_functions),
        offset_of!(ImageExportDirectory, address_of_names),
        offset_of!(ImageExportDirectory, address_of_name_ordinals),
    ] {
        map_rva_field(buf, marker, dfo + off, rift);
    }
}

/// `TransformResources` (dpx, g_transformsMap mask 0x10): recursively walk the
/// resource-directory tree and re-base every offset that points within the
/// resource block. All subdirectory/data offsets and string-name offsets are
/// expressed RELATIVE to the resource directory base (`dirbase`), so each is
/// mapped as `new = MapRva(dirbase + off) - MapRva(dirbase)` -- the dirbase
/// component cancels, leaving the segment movement of the pointed-to byte.
/// Mirrors `TransformResources::Run` (0x1800a8190) + `TransformRecursive`
/// (0x18004170c) on the apply path, where `MapRva` ignores the site argument and
/// returns `rva + rift.map(rva)`. `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` is
/// treated as dirbase-relative here, matching genuine `GetEntryData`.
fn transform_source_resources(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, marker: &mut [u8]) {
    let resources = match pe.data_directory(DataDirectoryKind::Resource) {
        Some(value) if value.rva != 0 => value,
        _ => return,
    };
    let Some(base_fo) = rva_to_file_off(pe, resources.rva as i64) else {
        return;
    };
    let dirbase = resources.rva as i64;
    let base_map = map_rva(rift, dirbase);
    let end = (base_fo + resources.size as usize).min(buf.len());

    use crate::pe::structs::{self, ImageResourceDirectoryEntry as ResEntry};
    use std::mem::offset_of;
    // IMAGE_RESOURCE_DIRECTORY: 16-byte header, then entries. The high bit of an
    // entry's name / offset_to_data marks a string name / subdirectory; the low
    // 31 bits are an offset relative to the resource directory base.
    const RES_DIR_HEADER: usize = 0x10;
    const HIGH_BIT: u32 = 0x8000_0000;
    const OFFSET_MASK: u32 = 0x7fff_ffff;
    let entry_size = size_of::<ResEntry>();

    // Map a dirbase-relative offset `off` through the rift, returning the new
    // dirbase-relative offset: MapRva(dirbase+off) - MapRva(dirbase).
    let remap = |off: i64| -> u32 { (map_rva(rift, dirbase + off) - base_map) as u32 };

    // Iterative tree walk over an explicit stack of directory file offsets, with
    // a visited set guarding against cyclic/malformed offsets.
    let mut stack: Vec<usize> = vec![base_fo];
    let mut visited = std::collections::HashSet::new();
    while let Some(dir_fo) = stack.pop() {
        if !visited.insert(dir_fo) {
            continue;
        }
        if dir_fo < base_fo || dir_fo + RES_DIR_HEADER > end {
            continue;
        }
        // NumberOfNamedEntries (+0xc) + NumberOfIdEntries (+0xe).
        let count = structs::read_u16(buf, dir_fo + 0xc) as usize
            + structs::read_u16(buf, dir_fo + 0xe) as usize;
        // Clamp to the entries that actually fit before `end`.
        let count = count.min(end.saturating_sub(dir_fo + RES_DIR_HEADER) / entry_size);
        for i in 0..count {
            let efo = dir_fo + RES_DIR_HEADER + i * entry_size;
            let Some(e) = structs::read::<ResEntry>(buf, efo) else {
                break;
            };
            let off_field = e.offset_to_data.get();
            if off_field & HIGH_BIT != 0 {
                // Subdirectory: recurse, then map the offset field (low 31 bits).
                let child_fo = base_fo + (off_field & OFFSET_MASK) as usize;
                // GetEntryDirectoryRecord guards: child within [base, end] and
                // strictly after this entry.
                if child_fo + RES_DIR_HEADER <= end && child_fo > efo {
                    stack.push(child_fo);
                }
                let nv = HIGH_BIT | (remap((off_field & OFFSET_MASK) as i64) & OFFSET_MASK);
                structs::write_u32(buf, efo + offset_of!(ResEntry, offset_to_data), nv);
                mark_bytes(marker, efo + offset_of!(ResEntry, offset_to_data), 4);
            } else {
                // Leaf: locate the IMAGE_RESOURCE_DATA_ENTRY (dirbase-relative)
                // and re-base its OffsetToData field (a full RVA).
                let data_fo = base_fo + (off_field & OFFSET_MASK) as usize;
                if data_fo >= base_fo && data_fo + 0x10 <= end {
                    let otd = structs::read_u32(buf, data_fo) as i64;
                    structs::write_u32(buf, data_fo, remap(otd));
                    mark_bytes(marker, data_fo, 4);
                }
            }
            // Name field: a string-offset name (high bit set) is dirbase-relative.
            let name_field = e.name.get();
            if name_field & HIGH_BIT != 0 {
                let nv = HIGH_BIT | (remap((name_field & OFFSET_MASK) as i64) & OFFSET_MASK);
                structs::write_u32(buf, efo + offset_of!(ResEntry, name), nv);
                mark_bytes(marker, efo + offset_of!(ResEntry, name), 4);
            }
        }
    }
}

pub(crate) fn build_cli_mark_non_exe_marker_map(
    buf: &[u8],
    pe: &PeInfo,
    metadata: &CliMetadataModel,
) -> Vec<u8> {
    let mut marker = vec![0u8; buf.len()];
    mark_non_executable(buf, pe, &mut marker);
    mark_cli_method_bodies(buf, pe, metadata, &mut marker);
    marker
}

pub(crate) fn mark_cli_method_bodies(
    buf: &[u8],
    pe: &PeInfo,
    metadata: &CliMetadataModel,
    marker: &mut [u8],
) -> Vec<CliMethodBody> {
    let bodies = cli_method_bodies(buf, pe, metadata);
    for body in &bodies {
        mark_marker_range(marker, body.file_offset, body.total_size, 3);
    }
    bodies
}

fn mark_marker_range(marker: &mut [u8], start: usize, len: usize, value: u8) {
    let Some(end) = start.checked_add(len) else {
        return;
    };
    let end = end.min(marker.len());
    if start >= end {
        return;
    }
    for byte in &mut marker[start..end] {
        *byte |= value;
    }
}

fn header_file_extent(buf: &[u8]) -> usize {
    PeHeaderLayout::parse(buf)
        .ok()
        .and_then(|layout| layout.size_of_headers_offset())
        .and_then(|offset| buf.get(offset..offset + 4))
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
        .unwrap_or(0)
        .min(buf.len())
}

/// Resolve a branch destination to the source file byte whose ownership is
/// checked. Native branch transforms use SizeOfRawData, including raw padding,
/// rather than the section's virtual extent. A virtual-only tail has no marker
/// byte, even when its numeric RVA happens to be a valid file offset.
fn branch_target_file_offset(
    pe: &PeInfo,
    target: SrcRva,
    header_extent: usize,
    file_len: usize,
) -> Option<usize> {
    if target.0 == 0 || target.0 >= pe.size_of_image {
        return None;
    }
    let offset = if (target.0 as usize) < header_extent {
        target.0 as usize
    } else {
        pe.sections.iter().find_map(|section| {
            let relative = target.0.checked_sub(section.virtual_address)?;
            (relative < section.raw_size)
                .then(|| (section.raw_offset as usize).checked_add(relative as usize))
                .flatten()
        })?
    };
    (offset != 0 && offset < file_len).then_some(offset)
}

/// `RelativeCallsX86::Run` apply pass (dpx 0x180040a00) on the source: rewrite
/// 0xE8 rel32 displacements through the rift, skipping any whose instruction
/// bytes or target are marker-owned.
fn transform_source_calls_i386(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, marker: &[u8]) {
    let header_extent = header_file_extent(buf);
    for sec in &pe.sections {
        if sec.characteristics & crate::pe::structs::SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let sraw = sec.raw_offset as usize;
        let slen = sec.virtual_size.min(sec.raw_size) as usize;
        let send = (sraw + slen).min(buf.len());
        if send < 5 {
            continue;
        }
        let mut i = sraw;
        while i + 5 <= send {
            if buf[i] != 0xE8 {
                i += 1;
                continue;
            }
            // All 5 instruction bytes must be marker-free.
            if (0..5).any(|k| marker[i + k] & 1 != 0) {
                i += 1;
                continue;
            }
            let site_end = (sec.virtual_address + (i - sraw) as u32).wrapping_add(5);
            let orig = i32::from_le_bytes(buf[i + 1..i + 5].try_into().unwrap());
            let target = site_end.wrapping_add(orig as u32);
            let Some(target_offset) =
                branch_target_file_offset(pe, SrcRva(target), header_extent, buf.len())
            else {
                i += 1;
                continue;
            };
            if marker[target_offset] & 1 != 0 {
                i += 1;
                continue;
            }
            let new_disp = (map_rva(rift, target as i64) - map_rva(rift, site_end as i64)) as i32;
            if new_disp != orig {
                buf[i + 1..i + 5].copy_from_slice(&new_disp.to_le_bytes());
            }
            i += 5;
        }
    }
}

/// `RelativeJmpsX86::Run` apply pass (dpx 0x180040f10) on the source: 0xE9 near
/// jmp and 0F 8x near Jcc whose displacement does not already fit a signed byte.
/// Remaps the displacement and collapses to the short form (`EB`/`7x`) when the
/// new displacement fits a byte.
fn transform_source_jmps_i386(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, marker: &[u8]) {
    let header_extent = header_file_extent(buf);
    for sec in &pe.sections {
        if sec.characteristics & crate::pe::structs::SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let sraw = sec.raw_offset as usize;
        let slen = sec.virtual_size.min(sec.raw_size) as usize;
        let send = (sraw + slen).min(buf.len());
        if send < 5 {
            continue;
        }
        let mut i = sraw;
        while i + 5 <= send {
            // disp-opcode byte index `d` and whether short-collapse is allowed.
            let (d, mut can_short) = if buf[i] == 0xE9 {
                (i, true)
            } else if buf[i] == 0x0F && (buf[i + 1] & 0xF0) == 0x80 {
                (i + 1, true)
            } else {
                i += 1;
                continue;
            };
            // For 0F 8x, the preceding 0F byte must be unmarked to back-patch it.
            if buf[d] != 0xE9 && d >= 1 && marker[d - 1] & 1 != 0 {
                can_short = false;
            }
            // The 5 bytes from the disp-opcode must be marker-free.
            if d + 5 > buf.len() || (0..5).any(|k| marker[d + k] & 1 != 0) {
                i += 1;
                continue;
            }
            let orig = i32::from_le_bytes(buf[d + 1..d + 5].try_into().unwrap()) as i64;
            // Only near forms whose disp does NOT already fit a signed byte.
            if (orig + 0x80) as u64 <= 0xFF {
                i += 1;
                continue;
            }
            let site_end = (sec.virtual_address + (d - sraw) as u32).wrapping_add(5);
            let target = site_end.wrapping_add(orig as u32);
            let Some(target_offset) =
                branch_target_file_offset(pe, SrcRva(target), header_extent, buf.len())
            else {
                i += 1;
                continue;
            };
            if marker[target_offset] & 1 != 0 {
                i += 1;
                continue;
            }
            let new_disp = (map_rva(rift, target as i64) - map_rva(rift, site_end as i64)) as i32;
            if can_short && ((new_disp as i64 + 0x80) as u64) < 0x100 {
                // collapse to short form
                if buf[d] == 0xE9 {
                    buf[d] = 0xEB;
                    buf[d + 1] = new_disp as u8;
                } else {
                    buf[d - 1] = (buf[d] & 0x0F) | 0x70;
                    buf[d] = new_disp as u8;
                }
            } else if new_disp as i64 != orig {
                buf[d + 1..d + 5].copy_from_slice(&new_disp.to_le_bytes());
            }
            i = d + 4 + 1;
        }
    }
}

/// Apply the inferred relocations transform for 32-bit (X86) PE binaries.
///
/// This legacy helper is not used by PA30 apply. The native-compatible source
/// stage lives in `pe::inferred_relocations`, which keeps ownership bits in a
/// separate marker buffer and scans the native post-header range.
///
/// Scans the buffer for 32-bit values that fall within the PE's image range.
/// Marks them with `RELOC_MARKER` in the output buffer and replaces the
/// value with the rift-table-mapped address.
///
/// `pe`: parsed PE info from the source binary
/// `source_buf`: the raw PE data (source side)
/// `output_buf`: the decoded output buffer (will be modified in place)
/// `new_image_base`: the target PE's image base
/// `rift_map`: closure that maps source RVA to target RVA via rift table
pub fn transform_inferred_relocations_x86(
    pe: &PeInfo,
    source_buf: &[u8],
    output_buf: &mut [u8],
    new_image_base: u64,
    rift_map: impl Fn(u64) -> i64,
) -> Result<u32> {
    let image_base = pe.image_base as u32;
    let image_end = image_base.wrapping_add(pe.size_of_image);
    let mut count = 0u32;

    let mut pos: usize = 0;
    while pos + 4 <= source_buf.len() && pos + 4 <= output_buf.len() {
        let val = u32::from_le_bytes([
            source_buf[pos],
            source_buf[pos + 1],
            source_buf[pos + 2],
            source_buf[pos + 3],
        ]);

        if val > image_base && val < image_end {
            let out_val = u32::from_le_bytes([
                output_buf[pos],
                output_buf[pos + 1],
                output_buf[pos + 2],
                output_buf[pos + 3],
            ]);

            if out_val & RELOC_CHECK == 0 {
                let rva = (val - image_base) as u64;
                let mapped = rift_map(rva);
                let new_val = (mapped as i32 + new_image_base as i32) as u32;
                let rebased = new_val | RELOC_MARKER;
                output_buf[pos..pos + 4].copy_from_slice(&rebased.to_le_bytes());
                count += 1;
                pos += 4;
                continue;
            }
        }
        pos += 1;
    }

    Ok(count)
}

/// Apply inferred relocations for AMD64 PE binaries.
///
/// This legacy helper is not registered in the PA30 apply pipeline and has no
/// native stage proof equivalent to the I386 implementation.
///
/// Scans for 64-bit pointer values within the PE's image range.
pub fn transform_inferred_relocations_amd64(
    pe: &PeInfo,
    source_buf: &[u8],
    output_buf: &mut [u8],
    new_image_base: u64,
    rift_map: impl Fn(u64) -> i64,
) -> Result<u32> {
    let image_base = pe.image_base;
    let image_end = image_base.wrapping_add(pe.size_of_image as u64);
    let mut count = 0u32;

    let mut pos: usize = 0;
    while pos + 8 <= source_buf.len() && pos + 8 <= output_buf.len() {
        let val = u64::from_le_bytes(source_buf[pos..pos + 8].try_into().unwrap());

        if val > image_base && val < image_end {
            let out_val = u64::from_le_bytes(output_buf[pos..pos + 8].try_into().unwrap());
            let check64 = RELOC_CHECK as u64 | ((RELOC_CHECK as u64) << 32);

            if out_val & check64 == 0 {
                let rva = val - image_base;
                let mapped = rift_map(rva);
                let new_val = (mapped + new_image_base as i64) as u64;
                let marker64 = RELOC_MARKER as u64 | ((RELOC_MARKER as u64) << 32);
                let rebased = new_val | marker64;
                output_buf[pos..pos + 8].copy_from_slice(&rebased.to_le_bytes());
                count += 1;
                pos += 8;
                continue;
            }
        }
        pos += 1;
    }

    Ok(count)
}

// --- AMD64 DisasmX64 transform (g_transformsMap mask 0x200) -----------------
//
// The amd64 `.text` (and any executable range covered by `.pdata`) carries
// RIP-relative disp32 operands and rel32 branch displacements. When the patch
// relays out the image, the bytes those displacements point at move; genuine
// `ApplyDeltaB`'s `TransformDisasmX64` apply pass rewrites each such 4-byte
// field so it still points at the right (target-layout) location.
//
// The pass is driven by `.pdata` enumeration -- it does NOT sweep `.text`
// blindly. For each `RUNTIME_FUNCTION` `[BeginAddress, EndAddress)` (RVAs), it
// length-disassembles forward instruction-by-instruction. For every
// instruction that ends in a RIP-relative disp32 (ModRM mod=00 rm=101) or a
// rel32 branch (E8/E9, 0F 8x), the disp32 is remapped:
//
//   next_rva = instr_start_rva + instr_total_len   (x64 RIP base = END of insn)
//   new_disp = MapRva(next_rva + old_disp) - MapRva(next_rva)
//
// where `MapRva(rva) = rva + rift.map(rva)`. No rift entries are added on apply.

/// Result of one length-disassembly step over an amd64 instruction.
struct DisasmInsn {
    /// Total instruction length in bytes (0 => decode error / truncated).
    len: u8,
    /// Byte offset (within the instruction) of the 4-byte field to remap.
    field_off: u8,
    /// True when the instruction carries a remappable rel32/RIP-relative disp32.
    remap: bool,
}

/// Per-opcode "operand kind" classifying ModRM/displacement handling.
/// Index 0..256 = 1-byte opcodes; the 0F-escaped map is selected separately.
/// Values mirror the `iVar12` table in `DisassemblerAmd64` (dpx 0x180044b58):
/// 0 = no ModRM, 1 = invalid, 2 = ModRM, 3 = moffs (disp32/disp64 by addr-size),
/// 4 = rel8 (1 trailing byte, no ModRM), 5 = rel32 (4 trailing bytes, REMAP).
const MODRM_1B: [u8; 256] = [
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 2, 1, 1, 1, 1, 0, 2, 0, 2, 0, 0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1,
    3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 2, 2, 2, 2, 1, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2,
    4, 4, 4, 4, 0, 0, 0, 0, 5, 5, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 2,
];

/// 0F-escaped ModRM/operand kinds (`iVar12` table at base 0x100).
const MODRM_0F: [u8; 256] = [
    2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 2, 2,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    0, 0, 0, 2, 2, 2, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1,
];

/// Immediate-size kind per 1-byte opcode (`iVar17` table at base 0x200).
/// 0 = none, 1 = imm8, 2 = imm16/32 (operand-size sensitive), 3 = moffs-addr,
/// 4 = imm16/32/64 (MOV imm, REX.W => imm64), 5 = imm16/32 + reljmp marker,
/// 6/7 = group F6/F7 (imm present only for /0 /1 = TEST).
const IMM_1B: [u8; 256] = [
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4,
    1, 1, 2, 0, 0, 0, 1, 5, 3, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Immediate-size kind per 0F-escaped opcode (`iVar17` table at base 0x300).
const IMM_0F: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Length-disassemble one amd64 instruction at `code[0..]`.
///
/// Returns the total length, the offset of the remappable disp32 field (only
/// meaningful when `remap` is true) and whether such a field is present. A
/// `len == 0` result signals truncation/decode failure (caller stops the run).
/// This mirrors `DisassemblerAmd64::Disassemble` (dpx 0x1800a35c8): it is a
/// pure length decoder that also flags the single 4-byte RIP-relative/rel32
/// field genuine `TransformDisasmX64` rewrites. Only that field matters; all
/// other displacement/immediate forms are length-only.
fn disasm_amd64(code: &[u8]) -> DisasmInsn {
    let avail = code.len().min(15);
    if avail == 0 {
        return DisasmInsn {
            len: 0,
            field_off: 0xff,
            remap: false,
        };
    }
    // Genuine `Disassemble` never returns length 0 on a non-empty buffer: on any
    // truncation / unknown-opcode (`break`), it returns the bytes consumed so
    // far and the driver advances by that, re-decoding the rest as fresh
    // instructions (no remap). `stop!` mirrors that: emit the consumed length,
    // no remappable field.
    macro_rules! stop {
        ($pos:expr) => {
            return DisasmInsn {
                len: $pos as u8,
                field_off: 0xff,
                remap: false,
            }
        };
    }
    // Legacy prefixes.
    let mut pos = 0usize;
    let mut opsize16 = false; // 0x66
    let mut addrsize32 = false; // 0x67
    while pos < avail {
        match code[pos] {
            0x66 => opsize16 = true,
            0x67 => addrsize32 = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0xf0 | 0xf2 | 0xf3 => {}
            _ => break,
        }
        pos += 1;
    }
    if pos >= avail {
        stop!(pos);
    }
    // Optional REX byte (only the immediately-preceding one counts).
    let mut rex_w = false;
    if code[pos] & 0xf0 == 0x40 {
        rex_w = code[pos] & 0x08 != 0;
        pos += 1;
        if pos >= avail {
            stop!(pos);
        }
        // A second 0x40..0x4f here is not a REX -- genuine code stops (a REX must
        // immediately precede the opcode); the length stays at the first REX.
        if code[pos] & 0xf0 == 0x40 {
            stop!(pos);
        }
    }
    // Opcode: 1-byte, or 0F-escaped 2-byte. (0F 38 / 0F 3A three-byte maps fall
    // through the 0F table; their ModRM/immediate forms are length-equivalent
    // to a normal 0F ModRM op for the purposes of this decoder, matching the
    // genuine table which assigns them ModRM kind 2 / no-immediate.)
    let (modrm_kind, imm_kind) = if code[pos] == 0x0f {
        pos += 1;
        if pos >= avail {
            stop!(pos);
        }
        let op = code[pos] as usize;
        (MODRM_0F[op], IMM_0F[op])
    } else {
        let op = code[pos] as usize;
        (MODRM_1B[op], IMM_1B[op])
    };
    pos += 1; // consume opcode byte

    // Unknown opcode (table kind 1): genuine code stops here with the length at
    // the end of the opcode, no operands, no remap.
    if modrm_kind == 1 {
        stop!(pos);
    }

    // `field_off`/`remap` describe the single remappable 4-byte field;
    // `group_has_imm` tracks whether an F6/F7 group op carries an immediate.
    let mut field_off = 0xffu8;
    let mut remap = false;
    let mut group_has_imm = false;

    // ModRM decode.
    match modrm_kind {
        2 => {
            if pos >= avail {
                stop!(pos);
            }
            let modrm = code[pos];
            pos += 1;
            let md = modrm >> 6;
            let rm = modrm & 7;
            // For the F6/F7 group, the reg field selects the operation: only
            // /0 and /1 (TEST) carry an immediate.
            let reg = (modrm >> 3) & 7;
            group_has_imm = reg == 0 || reg == 1;
            if md == 3 {
                // register-direct: no displacement/SIB.
            } else if rm == 5 && md == 0 {
                // RIP-relative disp32 -- the remap target.
                if avail - pos < 4 {
                    stop!(pos);
                }
                remap = true;
                field_off = pos as u8;
                pos += 4;
            } else if rm == 4 {
                // SIB byte.
                if pos >= avail {
                    stop!(pos);
                }
                let sib = code[pos];
                pos += 1;
                if md == 0 {
                    if sib & 7 == 5 {
                        // base=101 + mod=00 => disp32 (absolute, not remapped).
                        if avail - pos < 4 {
                            stop!(pos);
                        }
                        pos += 4;
                    }
                } else if md == 1 {
                    if pos >= avail {
                        stop!(pos);
                    }
                    pos += 1; // disp8
                } else {
                    // md == 2
                    if avail - pos < 4 {
                        stop!(pos);
                    }
                    pos += 4; // disp32
                }
            } else if md == 1 {
                if pos >= avail {
                    stop!(pos);
                }
                pos += 1; // disp8
            } else if md == 2 {
                if avail - pos < 4 {
                    stop!(pos);
                }
                pos += 4; // disp32
            }
        }
        3 => {
            // moffs (MOV AL/eAX, [moffs]): address-size sized direct offset.
            let n = if addrsize32 { 4 } else { 8 };
            if avail - pos < n {
                stop!(pos);
            }
            pos += n;
        }
        4 => {
            // rel8 (Jcc/LOOP/JMP short): 1 trailing byte, not remapped.
            if pos >= avail {
                stop!(pos);
            }
            pos += 1;
        }
        5 => {
            // rel32 branch (E8/E9, 0F 8x): the remap target.
            if avail - pos < 4 {
                stop!(pos);
            }
            remap = true;
            field_off = pos as u8;
            pos += 4;
        }
        _ => {}
    }

    // Immediate.
    match imm_kind {
        1 => {
            if pos >= avail {
                stop!(pos);
            }
            pos += 1;
        }
        2 | 5 => {
            // imm16 with 0x66, else imm32.
            let n = if opsize16 { 2 } else { 4 };
            if avail - pos < n {
                stop!(pos);
            }
            pos += n;
        }
        3 => {
            // moffs address-immediate (A0..A3): handled as the operand above;
            // genuine code emits no additional immediate here.
        }
        4 => {
            // MOV imm: imm64 with REX.W, imm16 with 0x66, else imm32.
            let n = if rex_w {
                8
            } else if opsize16 {
                2
            } else {
                4
            };
            if avail - pos < n {
                stop!(pos);
            }
            pos += n;
        }
        // F6 group: imm8 only for TEST (/0 /1).
        6 if group_has_imm => {
            if pos >= avail {
                stop!(pos);
            }
            pos += 1;
        }
        // F7 group: imm16/32 only for TEST (/0 /1).
        7 if group_has_imm => {
            let n = if opsize16 { 2 } else { 4 };
            if avail - pos < n {
                stop!(pos);
            }
            pos += n;
        }
        _ => {}
    }

    DisasmInsn {
        len: pos as u8,
        field_off,
        remap,
    }
}

/// `TransformDisasmX64` apply pass (dpx, g_transformsMap mask 0x200,
/// `PeMachine::Amd64`). Driven by `.pdata` (the exception directory, data dir
/// index 3):
/// each `RUNTIME_FUNCTION` `[BeginAddress, EndAddress)` RVA range is
/// length-disassembled forward in `output` (target layout) and every
/// RIP-relative disp32 / rel32 displacement is remapped through the preprocess
/// `rift` so it still resolves to the right target byte. No-op when the rift is
/// empty (no relayout) or there is no `.pdata`. Returns the count of fields
/// rewritten.
pub(crate) fn transform_disasm_x64(output: &mut [u8], pe: &PeInfo, rift: &RiftTable) -> u32 {
    if rift.entries.is_empty() {
        return 0;
    }
    use crate::pe::structs::{self, RuntimeFunction};
    let Some(pdata) = pe.data_directory(DataDirectoryKind::Exception) else {
        return 0;
    };
    if pdata.rva == 0 || (pdata.size as usize) < size_of::<RuntimeFunction>() {
        return 0;
    }
    let Some(pdata_off) = rva_to_file_off(pe, pdata.rva as i64) else {
        return 0;
    };
    let n_funcs = pdata.size as usize / size_of::<RuntimeFunction>();
    let mut changed = 0u32;
    for i in 0..n_funcs {
        let ent = pdata_off + i * size_of::<RuntimeFunction>();
        let Some(rf) = structs::read::<RuntimeFunction>(output, ent) else {
            break;
        };
        let begin = rf.begin.get() as i64;
        let end = rf.end.get() as i64;
        if begin == 0 || end <= begin {
            continue;
        }
        let Some(func_off) = rva_to_file_off(pe, begin) else {
            continue;
        };
        let mut rva = begin;
        let mut off = func_off;
        while rva < end {
            let remaining = (end - rva) as usize;
            let avail_file = output.len().saturating_sub(off);
            if avail_file == 0 {
                break;
            }
            let window = remaining.min(avail_file).min(15);
            let insn = disasm_amd64(&output[off..off + window]);
            if insn.len == 0 {
                break; // decode error -- stop this function run
            }
            let len = insn.len as i64;
            if insn.remap {
                let fpos = off + insn.field_off as usize;
                if fpos + 4 <= output.len() {
                    let old_disp =
                        i32::from_le_bytes(output[fpos..fpos + 4].try_into().unwrap()) as i64;
                    let next_rva = rva + len;
                    let base = map_rva(rift, next_rva);
                    let mapped = map_rva(rift, next_rva + old_disp);
                    let new_disp = mapped - base;
                    if new_disp != old_disp {
                        output[fpos..fpos + 4].copy_from_slice(&(new_disp as i32).to_le_bytes());
                        changed += 1;
                    }
                }
            }
            rva += len;
            off += insn.len as usize;
        }
    }
    changed
}

/// Undo the whole-buffer E8 translation selected by header flag bit 0.
///
/// This output stage is independent of the PE machine and file type. It scans
/// the first 1 GiB, including a complete five-byte instruction at the end.
/// Every E8 consumes its four operand bytes, even when the operand is outside
/// the translation range. Returns the number of translated sites.
pub(crate) fn undo_x86_e8_translation(buf: &mut [u8]) -> u32 {
    let scan_len = buf.len().min(0x4000_0000);
    let translation_size = scan_len as i32;
    let mut count = 0;
    let mut position = 0;
    while position + 5 <= scan_len {
        if buf[position] != 0xE8 {
            position += 1;
            continue;
        }
        let operand = i32::from_le_bytes(buf[position + 1..position + 5].try_into().unwrap());
        if operand.wrapping_add(position as i32) >= 0 && operand < translation_size {
            let displacement = if operand < 0 {
                operand.wrapping_add(translation_size)
            } else {
                operand.wrapping_sub(position as i32)
            };
            buf[position + 1..position + 5].copy_from_slice(&displacement.to_le_bytes());
            count += 1;
        }
        position += 5;
    }
    count
}

/// Is `buf` a managed (.NET / CLI) PE image -- one carrying a CLR runtime
/// header (data directory 14, `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`)? Such
/// images (regular assemblies, `.winmd`, resource satellites) are transformed
/// through the CLI metadata/disasm pipeline, which this crate does not implement.
/// Screening here -- on the reference image, before touching the (CLI-shaped and
/// differently-framed) preprocess stream -- lets `apply` reject them cleanly with
/// `Error::Unsupported` instead of failing deep in the bitstream parser.
///
/// Hand-parses just the header (no `goblin`, which over-validates some genuine
/// system images), handling both PE32 and PE32+. Returns false for anything not
/// a well-formed PE with a non-empty data directory 14.
pub(crate) fn is_managed_pe(buf: &[u8]) -> bool {
    let Ok(layout) = PeHeaderLayout::parse(buf) else {
        return false;
    };
    layout
        .data_directory(buf, DataDirectoryKind::ClrRuntimeHeader)
        .is_some_and(|directory| directory.rva != 0)
}

/// File offset of the PE optional-header CheckSum field (4 bytes), if `data`
/// is a PE.
pub(crate) fn pe_checksum_offset(data: &[u8]) -> Option<usize> {
    let layout = PeHeaderLayout::parse(data).ok()?;
    let offset = layout.checksum_offset()?;
    if offset + 4 <= data.len() {
        Some(offset)
    } else {
        None
    }
}

/// Zero the optional-header CheckSum in a reference buffer. msdelta normalizes
/// (zeroes) this volatile field in the copy source before applying a PE delta;
/// matching it here forces the target's real checksum to be carried as literals
/// rather than a copy that would resolve to zero on genuine msdelta.
pub(crate) fn zero_pe_checksum(data: &mut [u8]) {
    if let Some(off) = pe_checksum_offset(data) {
        data[off..off + 4].fill(0);
    }
}

pub(crate) fn pe_timestamp(data: &[u8]) -> u32 {
    let Ok(layout) = PeHeaderLayout::parse(data) else {
        return 0;
    };
    let Some(offset) = layout.timestamp_offset() else {
        return 0;
    };
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub(crate) fn pe_timestamp_offsets(data: &[u8]) -> Vec<usize> {
    use crate::pe::structs::{self, dir, ImageDebugDirectory, PeView};
    use std::mem::offset_of;

    let mut offsets = Vec::new();
    let Some(pe) = PeView::parse(data) else {
        return offsets;
    };

    // COFF FileHeader.TimeDateStamp.
    if let Ok(layout) = PeHeaderLayout::parse(data) {
        if let Some(timestamp_offset) = layout.timestamp_offset() {
            offsets.push(timestamp_offset);
        }
    } else {
        offsets.push(pe.pe_header_offset() + 8);
    }

    // Export directory TimeDateStamp (+4 into IMAGE_EXPORT_DIRECTORY).
    if let Some(exp) = pe.data_directory(dir::EXPORT) {
        if exp.virtual_address.get() != 0 {
            if let Some(off) = pe.rva_to_offset(exp.virtual_address.get()) {
                offsets.push(off + 4);
            }
        }
    }

    // Debug directory: an array of IMAGE_DEBUG_DIRECTORY entries, each carrying a
    // TimeDateStamp that mirrors the header's.
    const DBG: usize = size_of::<ImageDebugDirectory>();
    if let Some(dbg) = pe.data_directory(dir::DEBUG) {
        let (dva, dsize) = (dbg.virtual_address.get(), dbg.size.get());
        if dva != 0 && dsize as usize >= DBG {
            if let Some(base_off) = pe.rva_to_offset(dva) {
                let num_entries = dsize as usize / DBG;
                let time_date_stamp = offset_of!(ImageDebugDirectory, time_date_stamp);
                for i in 0..num_entries {
                    offsets.push(base_off + i * DBG + time_date_stamp);
                }

                // Some debug formats embed copies of the header timestamp in the
                // raw data each entry points at; record those occurrences too.
                let header_ts = offsets.first().map_or(0, |&o| structs::read_u32(data, o));
                let ts_bytes = header_ts.to_le_bytes();
                for i in 0..num_entries {
                    let Some(entry) =
                        structs::read::<ImageDebugDirectory>(data, base_off + i * DBG)
                    else {
                        break;
                    };
                    let raw_size = entry.size_of_data.get() as usize;
                    let raw_ptr = entry.pointer_to_raw_data.get() as usize;
                    if raw_ptr == 0 || raw_size == 0 || raw_ptr + raw_size > data.len() {
                        continue;
                    }
                    let end = raw_ptr + raw_size;
                    let mut j = raw_ptr;
                    while j + 4 <= end {
                        if data[j..j + 4] == ts_bytes {
                            offsets.push(j);
                            j += 4;
                        } else {
                            j += 1;
                        }
                    }
                }
            }
        }
    }

    offsets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cli::metadata::parse_cli_metadata_from_pe;
    use crate::pe::cli::method::cli_method_bodies;
    use crate::pe::cli::schema::CliSchemaFlavor;
    use std::path::PathBuf;

    const MANAGED_NATIVE_CASES: &[&str] = &[
        "cli-const-string",
        "cli-add-method",
        "cli-generics-signature",
        "cli-custom-attribute",
        "cli-resource",
        "cli-platform-x64",
        "cli-properties-events",
        "cli-interface-impl",
        "cli-constructor-token-boundary",
        "cli-static-constructor-token-boundary",
        "cli-constructor-user-string-boundary",
        "cli-exception-switch",
        "cli-pinvoke-module",
        "cli-nested-struct-enum-array",
    ];

    fn managed_native_corpus_dir() -> PathBuf {
        PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/atoms/ManagedNativeCorpus"
        ))
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_transform_pe(
        pe32_plus: bool,
        machine: PeMachine,
        clr_flags: Option<u32>,
    ) -> Vec<u8> {
        let mut image = vec![0u8; 0x1000];
        put_u32(&mut image, 0x3c, 0x80);
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut image, 0x84, machine.raw());
        put_u16(&mut image, 0x86, 1);
        put_u32(&mut image, 0x88, 0x1234_5678);
        put_u16(&mut image, 0x94, if pe32_plus { 0xf0 } else { 0xe0 });

        let opt = 0x98usize;
        let optional_kind = if pe32_plus {
            PeOptionalHeaderKind::Pe32Plus
        } else {
            PeOptionalHeaderKind::Pe32
        };
        let directory_base = opt + optional_kind.data_directories_relative_offset();
        put_u32(
            &mut image,
            opt + optional_kind.size_of_image_relative_offset(),
            0x3000,
        );
        put_u32(
            &mut image,
            opt + optional_kind.checksum_relative_offset(),
            0xfeed_beef,
        );
        put_u32(
            &mut image,
            opt + optional_kind.number_of_rva_and_sizes_relative_offset(),
            DataDirectoryKind::COUNT as u32,
        );
        if pe32_plus {
            put_u16(&mut image, opt, PeOptionalHeaderKind::PE32_PLUS_MAGIC);
            put_u64(
                &mut image,
                opt + optional_kind.image_base_relative_offset(),
                0x0000_0001_4000_0000,
            );
        } else {
            put_u16(&mut image, opt, PeOptionalHeaderKind::PE32_MAGIC);
            put_u32(
                &mut image,
                opt + optional_kind.image_base_relative_offset(),
                0x0040_0000,
            );
        };

        if let Some(flags) = clr_flags {
            let clr_dir = directory_base + DataDirectoryKind::ClrRuntimeHeader.index() * 8;
            put_u32(&mut image, clr_dir, 0x2000);
            put_u32(&mut image, clr_dir + 4, 0x48);
            put_u32(&mut image, 0x200 + 0x10, flags);
        }

        let section = opt + if pe32_plus { 0xf0 } else { 0xe0 };
        image[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut image, section + 8, 0x1000);
        put_u32(&mut image, section + 12, 0x2000);
        put_u32(&mut image, section + 16, 0x1000);
        put_u32(&mut image, section + 20, 0x200);
        put_u32(&mut image, section + 36, 0x6000_0020);
        image
    }

    #[test]
    fn raw_file_type_no_transform() {
        // FILE_TYPE_RAW doesn't trigger transforms
        assert_eq!(FILE_TYPE_RAW, 1);
    }

    #[test]
    fn pe_header_layout_drives_header_fixups() {
        let mut image = synthetic_transform_pe(true, PeMachine::Amd64, None);

        assert_eq!(pe_timestamp(&image), 0x1234_5678);
        assert_eq!(pe_checksum_offset(&image), Some(0xd8));

        zero_pe_checksum(&mut image);
        assert_eq!(&image[0xd8..0xdc], &[0, 0, 0, 0]);

        set_header_timestamp(&mut image, 0xaabb_ccdd);
        assert_eq!(&image[0x88..0x8c], &0xaabb_ccddu32.to_le_bytes());

        set_header_image_base(&mut image, 0x0000_0001_5000_0000);
        assert_eq!(&image[0xb0..0xb8], &0x0000_0001_5000_0000u64.to_le_bytes());
    }

    #[test]
    fn managed_probe_uses_header_layout() {
        let native = synthetic_transform_pe(false, PeMachine::I386, None);
        assert!(!is_managed_pe(&native));

        let il_only = synthetic_transform_pe(false, PeMachine::I386, Some(1));
        assert!(is_managed_pe(&il_only));

        let mixed_mode = synthetic_transform_pe(false, PeMachine::I386, Some(0));
        assert!(is_managed_pe(&mixed_mode));
    }

    #[test]
    fn managed_file_type_branch_matches_native_cli4_split() {
        for file_type in [FILE_TYPE_I386, FILE_TYPE_IA64, FILE_TYPE_AMD64] {
            assert_eq!(
                managed_branch_for_file_type(file_type),
                Some(ManagedBranch::ClassicCli),
                "file_type {file_type:#x} should use the classic CLI branch"
            );
        }

        for file_type in [
            FILE_TYPE_CLI4_I386,
            FILE_TYPE_CLI4_AMD64,
            FILE_TYPE_CLI4_ARM,
            FILE_TYPE_CLI4_ARM64,
        ] {
            assert_eq!(
                managed_branch_for_file_type(file_type),
                Some(ManagedBranch::Cli4),
                "file_type {file_type:#x} should use the CLI4 branch"
            );
        }

        for file_type in [FILE_TYPE_RAW, 0, 0x100, -1] {
            assert_eq!(
                managed_branch_for_file_type(file_type),
                None,
                "file_type {file_type:#x} is not a managed PE branch"
            );
        }
    }

    #[test]
    fn cli_mark_non_exe_marker_map_marks_method_bodies_from_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_methods = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let source = std::fs::read(root.join(case).join("source.dll"))
                .expect("read managed source fixture");
            let pe = PeInfo::parse_lenient(&source).expect("parse managed source PE");
            let metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");
            let bodies = cli_method_bodies(&source, &pe, &metadata);
            if bodies.is_empty() {
                continue;
            }

            cases_with_methods += 1;
            let marker = build_cli_mark_non_exe_marker_map(&source, &pe, &metadata);
            for body in bodies {
                let end = body.file_offset + body.total_size;
                assert!(
                    marker[body.file_offset..end]
                        .iter()
                        .all(|byte| byte & 3 == 3),
                    "{case}: MethodDef RID {} body range should be method-marked",
                    body.rid
                );
            }
        }

        assert!(
            cases_with_methods > 0,
            "managed corpus should include markable CLI method bodies"
        );
    }

    /// Pin the amd64 length-disassembler against the representative opcode forms
    /// the `.pdata`-driven DisasmX64 pass walks: RIP-relative CALL/LEA/MOV (the
    /// remap sites), rel32 branches, multi-byte NOP padding, SIB/disp forms and
    /// MOV-imm64. `(len, field_off, remap)` must match exactly or the pass
    /// desyncs over a function range.
    #[test]
    fn disasm_amd64_forms() {
        let c = |b: &[u8]| {
            let i = disasm_amd64(b);
            (i.len, i.field_off, i.remap)
        };
        // CALL [rip+disp32]: FF /2, modrm 15 (mod00 rm101). len 6, disp at +2.
        assert_eq!(c(&[0xff, 0x15, 0x00, 0x10, 0x00, 0x00]), (6, 2, true));
        // REX.W LEA rsi,[rip+disp32]: 48 8d 35 ... len 7, disp at +3.
        assert_eq!(c(&[0x48, 0x8d, 0x35, 0, 0, 0, 0]), (7, 3, true));
        // 4c 8d 25 (LEA r12,[rip+disp32]) len 7.
        assert_eq!(c(&[0x4c, 0x8d, 0x25, 0, 0, 0, 0]), (7, 3, true));
        // MOV [rip+disp32], imm32: C7 05 disp32 imm32. len 10, disp at +2.
        assert_eq!(c(&[0xc7, 0x05, 0, 0, 0, 0, 1, 0, 0, 0]), (10, 2, true));
        // rel32 CALL E8: len 5, field at +1, remap.
        assert_eq!(c(&[0xe8, 0, 0, 0, 0]), (5, 1, true));
        // rel32 JMP E9.
        assert_eq!(c(&[0xe9, 0, 0, 0, 0]), (5, 1, true));
        // 0F 8x near Jcc (rel32): len 6, field at +2, remap.
        assert_eq!(c(&[0x0f, 0x84, 0, 0, 0, 0]), (6, 2, true));
        // rel8 short JMP EB: len 2, no remap.
        assert_eq!(c(&[0xeb, 0x00]), (2, 0xff, false));
        // 5-byte multi-byte NOP 0F 1F 44 00 00 (table kind 1 stops after opcode,
        // length 2; the driver re-decodes the 44 00 00 tail).
        assert_eq!(c(&[0x0f, 0x1f, 0x44, 0x00, 0x00]).0, 2);
        // PUSH rbp under REX (40 55): len 2, no operands.
        assert_eq!(c(&[0x40, 0x55]), (2, 0xff, false));
        // REX.W MOV rax, imm64 (48 B8 + imm64): len 10.
        assert_eq!(c(&[0x48, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8]), (10, 0xff, false));
        // MOV r/m,reg with SIB+disp32 (48 89 84 24 disp32): len 8.
        assert_eq!(c(&[0x48, 0x89, 0x84, 0x24, 0, 0, 0, 0]), (8, 0xff, false));
        // SUB rsp, imm32 (48 81 ec imm32): len 7.
        assert_eq!(c(&[0x48, 0x81, 0xec, 0, 0, 0, 0]), (7, 0xff, false));
        // A plain reg-direct XOR (48 33 c4): len 3.
        assert_eq!(c(&[0x48, 0x33, 0xc4]), (3, 0xff, false));
    }
}
