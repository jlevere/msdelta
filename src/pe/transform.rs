//! PE file type transforms applied during MSDelta decode/encode.
//!
//! When FileType is not RAW, the decoded output is post-processed
//! through a transform pipeline. The most common transform is
//! "inferred relocations" which scans for 32-bit pointers within
//! the PE's image range and rebases them using the rift table.

use super::parse::PeInfo;
use crate::Result;

/// MSDelta file type flags.
pub const FILE_TYPE_RAW: i64 = 1;
pub const FILE_TYPE_I386: i64 = 2;
pub const FILE_TYPE_IA64: i64 = 4;
pub const FILE_TYPE_AMD64: i64 = 8;
pub const FILE_TYPE_CLI4_I386: i64 = 0x10;
pub const FILE_TYPE_CLI4_AMD64: i64 = 0x20;

const RELOC_MARKER: u32 = 0x01010101;
const RELOC_CHECK: u32 = 0x02020202;

use crate::lzx::rift::RiftTable;

/// `MapRva`: map a source RVA to its target RVA through the (coarse) rift.
/// Piecewise: `rva + (target-source)` of the bracketing entry; identity when
/// empty. Mirrors `TransformBase::MapRva` (dpx 0x180041998).
#[inline]
fn map_rva(rift: &RiftTable, rva: i64) -> i64 {
    rva + rift.map(rva)
}

fn first_section_rva(pe: &PeInfo) -> i64 {
    pe.sections
        .iter()
        .map(|s| s.virtual_address as i64)
        .min()
        .unwrap_or(0)
}

fn rva_to_file_off(pe: &PeInfo, rva: i64) -> Option<usize> {
    pe.sections
        .iter()
        .find(|s| {
            rva >= s.virtual_address as i64
                && rva < (s.virtual_address + s.virtual_size.max(s.raw_size)) as i64
        })
        .map(|s| (s.raw_offset as i64 + (rva - s.virtual_address as i64)) as usize)
}

/// Build `T(source)`: the source image transformed exactly as genuine
/// `ApplyDeltaB`'s `PreProcessPEForApply` transforms it before the LZX copy
/// stage, so copies land bit-identical to genuine. `buf` is a clone of the
/// reference with the optional-header CheckSum already zeroed; `pe` is parsed
/// from it; `rift` is the delta's (coarse) preprocess rift; `flags` is the
/// header transform-selection word. Transforms run in `g_transformsMap` order
/// (relocations, then jmps, then calls), each consulting/updating a per-file-
/// offset marker so a later transform never rewrites bytes an earlier one owns.
pub(crate) fn build_transformed_source(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, flags: u64) {
    if pe.is_64bit {
        return; // i386 source transforms only (this path); x64 handled elsewhere
    }
    let mut marker = vec![0u8; buf.len()];
    if flags & 0x2 != 0 {
        mark_non_executable(buf, pe, &mut marker);
    }
    if flags & 0x8 != 0 {
        transform_source_exports(buf, pe, rift, &mut marker);
    }
    if flags & 0x20 != 0 {
        transform_source_relocs_i386(buf, pe, rift, &mut marker);
    }
    if flags & 0x80 != 0 {
        transform_source_jmps_i386(buf, pe, rift, &marker);
    }
    if flags & 0x100 != 0 {
        transform_source_calls_i386(buf, pe, rift, &marker);
    }
}

/// `TransformExports` (dpx, g_transformsMap mask 0x8): map the export
/// directory's RVA fields and its AddressOfFunctions / AddressOfNames RVA
/// arrays through the rift, marking the bytes. comctl32's export table lives in
/// `.text`, so these are the residual `.text` RVAs after calls/jmps.
fn transform_source_exports(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, marker: &mut [u8]) {
    let (exp_rva, _exp_size) = match pe.data_directories.first().copied() {
        Some(v) if v.0 != 0 => v,
        _ => return,
    };
    let Some(dir) = rva_to_file_off(pe, exp_rva as i64) else {
        return;
    };
    if dir + 0x28 > buf.len() {
        return;
    }
    let rd = |b: &[u8], o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
    // Map the RVA stored at file offset `fo` in place, and mark its 4 bytes.
    let map_field = |buf: &mut [u8], marker: &mut [u8], fo: usize| {
        if fo + 4 > buf.len() {
            return;
        }
        let v = rd(buf, fo) as i64;
        if v != 0 {
            let nv = (v + rift.map(v)) as u32;
            buf[fo..fo + 4].copy_from_slice(&nv.to_le_bytes());
        }
        for b in 0..4 {
            marker[fo + b] |= 1;
        }
    };

    let n_funcs = rd(buf, dir + 0x14);
    let n_names = rd(buf, dir + 0x18);
    let aof = rd(buf, dir + 0x1c);
    let aon = rd(buf, dir + 0x20);

    // AddressOfFunctions[]: NumberOfFunctions RVAs.
    if aof != 0 {
        if let Some(base) = rva_to_file_off(pe, aof as i64) {
            for i in 0..n_funcs as usize {
                map_field(buf, marker, base + i * 4);
            }
        }
    }
    // AddressOfNames[]: NumberOfNames name-string RVAs.
    if aon != 0 {
        if let Some(base) = rva_to_file_off(pe, aon as i64) {
            for i in 0..n_names as usize {
                map_field(buf, marker, base + i * 4);
            }
        }
    }
    // The directory's own RVA fields: Name, AddressOfFunctions, AddressOfNames,
    // AddressOfNameOrdinals. (Base/counts and the ordinal array are not RVAs.)
    map_field(buf, marker, dir + 0x0c);
    map_field(buf, marker, dir + 0x1c);
    map_field(buf, marker, dir + 0x20);
    map_field(buf, marker, dir + 0x24);
}

/// `MarkNonExe` (dpx, g_transformsMap mask 0x2, runs first): mark every byte
/// that is NOT inside an executable section. The instruction transforms then
/// rewrite a relative branch only when its target is UNMARKED (i.e. lands in
/// executable code) -- this is what rejects the false-positive 0xE8/0xE9 bytes
/// embedded in data/operands whose bogus target lands outside code.
fn mark_non_executable(buf: &[u8], pe: &PeInfo, marker: &mut [u8]) {
    for m in marker.iter_mut() {
        *m |= 1;
    }
    for sec in &pe.sections {
        if sec.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let a = sec.raw_offset as usize;
        let end = (a + sec.virtual_size.min(sec.raw_size) as usize).min(buf.len());
        for m in &mut marker[a..end] {
            *m &= !1;
        }
    }
}

/// `TransformRelocations` apply pass on the source (dpx `ReadRelocationEntries`
/// 0x18003f6a0): rewrite each relocation's pointed-to operand through the rift
/// and mark its bytes so the instruction transforms skip them.
fn transform_source_relocs_i386(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    marker: &mut [u8],
) {
    let image_base = pe.image_base as i64;
    let (reloc_rva, reloc_size) = match pe.data_directories.get(5).copied() {
        Some(v) if v.0 != 0 => v,
        _ => return,
    };
    let Some(base) = rva_to_file_off(pe, reloc_rva as i64) else {
        return;
    };
    let blocks_end = (base + reloc_size as usize).min(buf.len());

    // Collected entries for the block rebuild: (mapped location RVA, type, extra).
    let mut entries: Vec<(u32, u16, u16)> = Vec::new();

    let mut bo = base;
    while bo + 8 <= blocks_end {
        let page = u32::from_le_bytes(buf[bo..bo + 4].try_into().unwrap()) as i64;
        let blk = u32::from_le_bytes(buf[bo + 4..bo + 8].try_into().unwrap()) as usize;
        if blk < 8 || bo + blk > blocks_end {
            break;
        }
        let n = (blk - 8) / 2;
        let mut j = 0;
        while j < n {
            let eo = bo + 8 + j * 2;
            let e = u16::from_le_bytes(buf[eo..eo + 2].try_into().unwrap());
            let typ = e >> 12;
            if typ == 0 {
                break; // type-0 padding terminates the block (not a real entry)
            }
            let offset = (e & 0xfff) as i64;
            let loc_rva = page + offset;
            // The rebuilt block entry stores the MAPPED location RVA.
            let mapped_loc = (loc_rva + rift.map(loc_rva)) as u32;
            let mut extra = 0u16;
            let mut kept = typ;
            if let Some(op_fo) = rva_to_file_off(pe, loc_rva) {
                match typ {
                    3 => {
                        // HIGHLOW: rewrite the 32-bit operand, mark 4 bytes.
                        if op_fo + 4 <= buf.len() {
                            let v = i32::from_le_bytes(buf[op_fo..op_fo + 4].try_into().unwrap())
                                as i64;
                            let nv = (v + rift.map(v - image_base)) as i32;
                            buf[op_fo..op_fo + 4].copy_from_slice(&nv.to_le_bytes());
                            for b in 0..4 {
                                marker[op_fo + b] |= 1;
                            }
                        }
                    }
                    1 | 2 => {
                        for b in 0..2 {
                            if op_fo + b < marker.len() {
                                marker[op_fo + b] |= 1;
                            }
                        }
                    }
                    4 => {
                        // HIGHADJ consumes the following u16 as its extra field.
                        for b in 0..2 {
                            if op_fo + b < marker.len() {
                                marker[op_fo + b] |= 1;
                            }
                        }
                        if j + 1 < n {
                            let xo = bo + 8 + (j + 1) * 2;
                            extra = u16::from_le_bytes(buf[xo..xo + 2].try_into().unwrap());
                        }
                        j += 1;
                    }
                    _ => kept = 0,
                }
            }
            entries.push((mapped_loc, kept, extra));
            j += 1;
        }
        bo += blk;
    }

    rebuild_reloc_blocks(buf, pe, reloc_rva, reloc_size, base, &mut entries);
}

/// Regenerate the base-relocation directory in place from the collected,
/// rift-mapped entries. Mirrors `WriteRelocationEntries` (dpx 0x18004048c):
/// stable-sort ascending by mapped location RVA, regroup by 4 KiB page, each
/// `u16 = type<<12 | (rva & 0xfff)` (HIGHADJ followed by its extra u16), pad
/// each block to a 4-byte boundary with a zero `u16` when the entry count is
/// odd, recompute `SizeOfBlock`, all within the `.reloc` section extent.
fn rebuild_reloc_blocks(
    buf: &mut [u8],
    pe: &PeInfo,
    reloc_rva: u32,
    reloc_size: u32,
    base: usize,
    entries: &mut [(u32, u16, u16)],
) {
    entries.sort_by_key(|e| e.0);

    // Budget = bytes of `.reloc` from the dir start to the section end
    // (VirtualSize, even), clamped to at least the data-directory size.
    let extent = pe
        .sections
        .iter()
        .find(|s| {
            reloc_rva >= s.virtual_address
                && reloc_rva < s.virtual_address + s.virtual_size.max(s.raw_size)
        })
        .map(|s| s.virtual_address + s.virtual_size - reloc_rva)
        .unwrap_or(reloc_size)
        .max(reloc_size);
    let limit = (base + (extent & !1) as usize).min(buf.len());

    let mut out = base;
    let mut i = 0usize;
    while out + 8 <= limit && i < entries.len() {
        let page = entries[i].0 & 0xffff_f000;
        let header = out;
        out += 8;
        let body_start = out;
        while out + 2 <= limit && i < entries.len() && (entries[i].0 & 0xffff_f000) == page {
            let (rva, typ, extra) = entries[i];
            let e = (typ << 12) | (rva & 0xfff) as u16;
            buf[out..out + 2].copy_from_slice(&e.to_le_bytes());
            out += 2;
            if typ == 4 && out + 2 <= limit {
                buf[out..out + 2].copy_from_slice(&extra.to_le_bytes());
                out += 2;
            }
            i += 1;
        }
        if ((out - body_start) / 2) % 2 == 1 && out + 2 <= limit {
            buf[out..out + 2].copy_from_slice(&0u16.to_le_bytes());
            out += 2;
        }
        let size = (out - header) as u32;
        buf[header..header + 4].copy_from_slice(&page.to_le_bytes());
        buf[header + 4..header + 8].copy_from_slice(&size.to_le_bytes());
    }
}

/// Is `target` (a source RVA, UNSIGNED) a reachable relative-branch
/// destination? Mirrors `RelativeCallsX86::Run`: nonzero, below `SizeOfImage`,
/// and either below the first section or inside one. Unsigned throughout, so a
/// wrapped (negative) displacement becomes a huge RVA and is rejected.
fn branch_target_reachable(pe: &PeInfo, target: u32) -> bool {
    target != 0
        && target < pe.size_of_image
        && ((target as i64) < first_section_rva(pe)
            || pe.sections.iter().any(|s| {
                target >= s.virtual_address
                    && target < s.virtual_address + s.virtual_size.max(s.raw_size)
            }))
}

/// Marker index for a branch target: rebased to a file offset when it lands in
/// a section, else the RVA itself (matches the decompiled `uVar9`).
fn target_marker_index(pe: &PeInfo, target: u32) -> i64 {
    if (target as i64) < first_section_rva(pe) {
        target as i64
    } else {
        rva_to_file_off(pe, target as i64)
            .map(|f| f as i64)
            .unwrap_or(target as i64)
    }
}

fn marker_set(marker: &[u8], idx: i64) -> bool {
    idx >= 0 && (idx as usize) < marker.len() && marker[idx as usize] & 1 != 0
}

/// `RelativeCallsX86::Run` apply pass (dpx 0x180040a00) on the source: rewrite
/// 0xE8 rel32 displacements through the rift, skipping any whose instruction
/// bytes or target are marker-owned.
fn transform_source_calls_i386(buf: &mut [u8], pe: &PeInfo, rift: &RiftTable, marker: &[u8]) {
    for sec in &pe.sections {
        if sec.characteristics & 0x2000_0000 == 0 {
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
            if !branch_target_reachable(pe, target) {
                i += 1;
                continue;
            }
            if marker_set(marker, target_marker_index(pe, target)) {
                i += 1;
                continue;
            }
            let new_disp =
                (map_rva(rift, target as i64) - map_rva(rift, site_end as i64)) as i32;
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
    for sec in &pe.sections {
        if sec.characteristics & 0x2000_0000 == 0 {
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
            if !branch_target_reachable(pe, target) {
                i += 1;
                continue;
            }
            if marker_set(marker, target_marker_index(pe, target)) {
                i += 1;
                continue;
            }
            let new_disp =
                (map_rva(rift, target as i64) - map_rva(rift, site_end as i64)) as i32;
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

/// Remap the RVA fields of every `.pdata` `RUNTIME_FUNCTION` through a rift.
///
/// AMD64 `.pdata` is an array of 12-byte `RUNTIME_FUNCTION`s
/// (`BeginAddress`, `EndAddress`, `UnwindData` — all RVAs). When the patch
/// relays out the image, the addresses these point at move; genuine
/// `ApplyDeltaB`'s `RiftTransformPdataAmd64` apply pass rewrites each field in
/// place by mapping its RVA through the composed rift (the same `source-RVA ->
/// target-RVA` map carried by the preprocess rift; an offset of `target -
/// source` per segment, `GetNewRvaFromRiftTable`-style).
///
/// The rift maps SOURCE RVAs to TARGET RVAs. `rift.map(rva)` returns the
/// segment offset; the new value is `rva + offset`. Returns the count of
/// fields changed. No-op when the rift is empty.
pub(crate) fn remap_pdata_rvas(
    output: &mut [u8],
    pdata_file_off: u32,
    pdata_size: u32,
    rift: &crate::lzx::rift::RiftTable,
) -> u32 {
    if rift.entries.is_empty() || pdata_file_off == 0 || pdata_size == 0 {
        return 0;
    }
    // `pdata_file_off` is the on-disk file offset of `.pdata` in `output`
    // (the caller translates the exception-directory RVA through the section
    // table). The field *values* are RVAs and are mapped through `rift`.
    let start = pdata_file_off as usize;
    let end = start.saturating_add(pdata_size as usize).min(output.len());
    let mut changed = 0u32;
    let mut off = start;
    while off + 12 <= end {
        for field in 0..3 {
            let p = off + field * 4;
            let rva = u32::from_le_bytes(output[p..p + 4].try_into().unwrap());
            if rva == 0 {
                continue;
            }
            let delta = rift.map(rva as i64);
            if delta != 0 {
                let new = (rva as i64 + delta) as u32;
                output[p..p + 4].copy_from_slice(&new.to_le_bytes());
                changed += 1;
            }
        }
        off += 12;
    }
    changed
}

/// Undo MSDelta's x86 `0xE8` (near CALL) preprocessing on a reconstructed image.
///
/// Genuine `ApplyDeltaB` (PA31, in UpdateCompression.dll / dpx.dll -- msdelta.dll
/// has no PA31) preprocesses 32-bit x86 targets with the classic LZX E8 filter:
/// the 4-byte displacement after each `0xE8` is converted to an absolute form
/// for better compression, then converted back on apply. It is a whole-buffer
/// scan (headers, code, even `.rsrc` -- NOT section-bounded), with the output
/// length as the translation size: a site is converted iff `-i <= v < len`,
/// where `i` is the byte offset and `v` the stored displacement (verified
/// byte-for-byte against genuine output -- `translation_size == target_size`).
///
/// Runs ONLY on i386 PEs (`IMAGE_FILE_MACHINE_I386`, machine `0x14C`) and skips
/// pure-managed (.NET, `COMIMAGE_FLAGS_ILONLY`) images, which carry machine
/// `0x14C` too but must not be touched. No-op on everything else, so it is safe
/// to call unconditionally on the reconstructed image. Returns the site count.
///
/// `apply()` calls this only when header flag bit 0 is set (genuine ApplyDeltaB's
/// transform-selection flag for E8x86) -- that gate, not the i386-PE check here,
/// is what keeps it off resource-only PEs the encoder did not transform.
pub(crate) fn undo_x86_e8_translation(buf: &mut [u8]) -> u32 {
    // Gate with a manual header read rather than a full `goblin` parse: genuine
    // msdelta keys only on the machine type, and goblin's strict validation
    // rejects some otherwise-valid system images (e.g. comctl32). i386 only,
    // and skip pure-managed (.NET) images.
    if !is_i386_native_pe(buf) {
        return 0;
    }

    let len = buf.len();
    // A CALL displacement is a signed i32 and the translation size is the image
    // length; both must fit i32 for the guard/arithmetic to be meaningful (real
    // targets are well under -- apply() caps at 256 MiB).
    if len < 10 || len > i32::MAX as usize {
        return 0;
    }
    let ts = len as i32;
    let mut count = 0u32;
    let mut i = 0usize;
    // Classic LZX leaves the last 10 bytes untouched (a CALL displacement never
    // starts there). Every 0xE8 advances the cursor past its 4 operand bytes
    // whether or not it is translated, matching the encoder's own scan. The
    // rewrite is 32-bit wrapping arithmetic (`new = v - i` mod 2^32), matching
    // genuine behaviour and avoiding overflow panics on adversarial input.
    while i < len - 10 {
        if buf[i] != 0xE8 {
            i += 1;
            continue;
        }
        let v = i32::from_le_bytes(buf[i + 1..i + 5].try_into().unwrap());
        if v >= -(i as i32) && v < ts {
            let new = if v >= 0 {
                v.wrapping_sub(i as i32)
            } else {
                v.wrapping_add(ts)
            };
            buf[i + 1..i + 5].copy_from_slice(&new.to_le_bytes());
            count += 1;
        }
        i += 5;
    }
    count
}

/// Is `buf` a native 32-bit (i386) PE that is NOT a pure-managed (.NET) image?
///
/// Parses only the few header fields needed, by hand (no full `goblin` parse,
/// which over-validates and rejects some valid system images). Requires machine
/// `IMAGE_FILE_MACHINE_I386` (0x14C) and a PE32 optional header, and rejects
/// images whose CLR runtime header (data directory 14) has `COMIMAGE_FLAGS_ILONLY`.
fn is_i386_native_pe(buf: &[u8]) -> bool {
    let rd_u16 = |o: usize| -> Option<u16> {
        buf.get(o..o + 2)
            .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
    };
    let rd_u32 = |o: usize| -> Option<u32> {
        buf.get(o..o + 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    };

    let e_lfanew = match rd_u32(0x3c) {
        Some(v) => v as usize,
        None => return false,
    };
    if buf.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return false;
    }
    if rd_u16(e_lfanew + 4) != Some(0x014C) {
        return false; // not i386
    }
    let num_sections = rd_u16(e_lfanew + 6).unwrap_or(0) as usize;
    let size_of_opt = rd_u16(e_lfanew + 20).unwrap_or(0) as usize;
    let opt = e_lfanew + 24;
    // i386 images are PE32 (magic 0x10B); data directories start at opt+96.
    if rd_u16(opt) != Some(0x010B) {
        return false;
    }
    let num_rva = rd_u32(opt + 92).unwrap_or(0) as usize;
    const CLR_DIR: usize = 14;
    if num_rva <= CLR_DIR {
        return true; // no CLR header -> native
    }
    let clr_rva = rd_u32(opt + 96 + CLR_DIR * 8).unwrap_or(0);
    if clr_rva == 0 {
        return true; // native
    }
    // Map the CLR header RVA to a file offset via the section table and read
    // its COR20 Flags (u32 at +16); ILONLY (bit 0) => managed, skip.
    let sec_base = opt + size_of_opt;
    for i in 0..num_sections {
        let s = sec_base + i * 40;
        let vs = rd_u32(s + 8).unwrap_or(0);
        let va = rd_u32(s + 12).unwrap_or(0);
        let ro = rd_u32(s + 20).unwrap_or(0);
        if clr_rva >= va && clr_rva < va.wrapping_add(vs) {
            // usize add (a u32 add could overflow on a hostile header).
            let off = ro as usize + (clr_rva - va) as usize;
            if let Some(flags) = rd_u32(off + 16) {
                return flags & 0x1 == 0; // ILONLY clear => native
            }
        }
    }
    true
}

/// File offset of the PE optional-header CheckSum field (4 bytes), if `data`
/// is a PE. CheckSum sits at optional-header offset 0x40 for both PE32 and
/// PE32+, and the optional header starts at e_lfanew + 4 (signature) + 20
/// (COFF file header), so the absolute offset is e_lfanew + 0x58.
pub(crate) fn pe_checksum_offset(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if data.get(e_lfanew..e_lfanew + 4) != Some(b"PE\0\0") {
        return None;
    }
    let off = e_lfanew + 0x58;
    if off + 4 <= data.len() {
        Some(off)
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
    if data.len() < 0x40 {
        return 0;
    }
    let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_off + 12 > data.len() {
        return 0;
    }
    u32::from_le_bytes(data[pe_off + 8..pe_off + 12].try_into().unwrap())
}

pub(crate) fn pe_timestamp_offsets(data: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let pe = match goblin::pe::PE::parse(data) {
        Ok(pe) => pe,
        Err(_) => return offsets,
    };

    let pe_off = pe.header.dos_header.pe_pointer as usize;
    offsets.push(pe_off + 8);

    let opt = match pe.header.optional_header {
        Some(o) => o,
        None => return offsets,
    };

    let sections = &pe.sections;
    let rva_to_offset = |rva: u32| -> Option<usize> {
        for s in sections {
            if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
                continue;
            }
            if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
                return Some((s.pointer_to_raw_data + (rva - s.virtual_address)) as usize);
            }
        }
        None
    };

    if let Some(&dd) = opt.data_directories.get_export_table() {
        if dd.virtual_address != 0 {
            if let Some(off) = rva_to_offset(dd.virtual_address) {
                offsets.push(off + 4);
            }
        }
    }

    if let Some(&dd) = opt.data_directories.get_debug_table() {
        if dd.virtual_address != 0 && dd.size >= 28 {
            if let Some(base_off) = rva_to_offset(dd.virtual_address) {
                let num_entries = dd.size as usize / 28;
                for i in 0..num_entries {
                    offsets.push(base_off + i * 28 + 4);
                }
            }
        }
    }

    if let Some(&dd) = opt.data_directories.get_debug_table() {
        if dd.virtual_address != 0 && dd.size >= 28 {
            if let Some(base_off) = rva_to_offset(dd.virtual_address) {
                let num_entries = dd.size as usize / 28;
                let header_ts = if offsets.is_empty() {
                    0
                } else {
                    u32::from_le_bytes(
                        data[offsets[0]..offsets[0] + 4]
                            .try_into()
                            .unwrap_or([0; 4]),
                    )
                };
                let ts_bytes = header_ts.to_le_bytes();
                for i in 0..num_entries {
                    let entry_off = base_off + i * 28;
                    if entry_off + 28 > data.len() {
                        break;
                    }
                    let raw_ptr = u32::from_le_bytes(
                        data[entry_off + 24..entry_off + 28].try_into().unwrap(),
                    ) as usize;
                    let raw_size = u32::from_le_bytes(
                        data[entry_off + 16..entry_off + 20].try_into().unwrap(),
                    ) as usize;
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

    #[test]
    fn raw_file_type_no_transform() {
        // FILE_TYPE_RAW doesn't trigger transforms
        assert_eq!(FILE_TYPE_RAW, 1);
    }
}
