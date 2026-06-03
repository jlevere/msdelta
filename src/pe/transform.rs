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
pub(crate) fn build_transformed_source(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    flags: u64,
    target_base: u64,
) {
    if pe.is_64bit {
        // amd64 source transforms, in g_transformsMap order: DisasmX64 (0x200)
        // then PdataX64 (0x400). Running them on the SOURCE (producing T(source))
        // is the only correct architecture: the LZX copy/literal split was
        // defined against genuine's T(source), so a copy reads the transformed
        // byte and a literal already carries the target byte -- a post-decode
        // remap could not distinguish the two and double-applied the rift on
        // literal-provided fields (e.g. comctl32 amd64 .pdata UnwindData).
        // DisasmX64 must precede PdataX64: its driver reads the (still source-
        // domain) .pdata Begin/End RVAs to locate functions.
        // g_transformsMap order: Imports (0x4), Exports (0x8), Resources (0x10),
        // Relocations (0x20), then DisasmX64 (0x200), PdataX64 (0x400). The
        // marker only gates the i386 instruction passes, so it is unused here.
        let mut marker = vec![0u8; buf.len()];
        if flags & 0x4 != 0 {
            transform_source_imports(buf, pe, rift, &mut marker, target_base);
        }
        if flags & 0x8 != 0 {
            transform_source_exports(buf, pe, rift, &mut marker);
        }
        if flags & 0x10 != 0 {
            transform_source_resources(buf, pe, rift, &mut marker);
        }
        if flags & 0x20 != 0 {
            transform_source_relocs(buf, pe, rift, &mut marker, target_base);
        }
        if flags & 0x200 != 0 {
            transform_disasm_x64(buf, pe, rift);
        }
        if flags & 0x400 != 0 {
            const EXCEPTION_DIR: usize = 3;
            if let Some(&(pdata_rva, pdata_size)) = pe.data_directories.get(EXCEPTION_DIR) {
                if pdata_rva != 0 {
                    if let Some(pdata_fo) = rva_to_file_off(pe, pdata_rva as i64) {
                        remap_pdata_rvas(buf, pdata_fo as u32, pdata_size, rift);
                    }
                }
            }
        }
        set_header_image_base(buf, target_base, true);
        return;
    }
    let mut marker = vec![0u8; buf.len()];
    if flags & 0x2 != 0 {
        mark_non_executable(buf, pe, &mut marker);
    }
    if flags & 0x4 != 0 {
        transform_source_imports(buf, pe, rift, &mut marker, target_base);
    }
    if flags & 0x8 != 0 {
        transform_source_exports(buf, pe, rift, &mut marker);
    }
    if flags & 0x10 != 0 {
        transform_source_resources(buf, pe, rift, &mut marker);
    }
    if flags & 0x20 != 0 {
        transform_source_relocs(buf, pe, rift, &mut marker, target_base);
    }
    if flags & 0x80 != 0 {
        transform_source_jmps_i386(buf, pe, rift, &marker);
    }
    if flags & 0x100 != 0 {
        transform_source_calls_i386(buf, pe, rift, &marker);
    }
    set_header_image_base(buf, target_base, false);
}

/// Write the TARGET image base into the source header's `ImageBase` field, the
/// way genuine `PreProcessPEForApply` does after running the transform executor
/// (`SectionHelper::SetImageBase64`/`SetImageBase32`). The LZX copy/literal split
/// was defined against this T(source), so when source and target image bases
/// differ (e.g. a rebased binary), the field must already hold the target value
/// here -- otherwise a copy that reads it lands the stale source base.
/// PE32+ stores an 8-byte ImageBase at optional-header offset 0x18; PE32 a
/// 4-byte ImageBase at offset 0x1c.
fn set_header_image_base(buf: &mut [u8], target_base: u64, is_64bit: bool) {
    let Some(e) = buf
        .get(0x3c..0x40)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
    else {
        return;
    };
    if buf.get(e..e + 4) != Some(b"PE\0\0") {
        return;
    }
    let opt = e + 24;
    if is_64bit {
        if opt + 0x20 <= buf.len() {
            buf[opt + 0x18..opt + 0x20].copy_from_slice(&target_base.to_le_bytes());
        }
    } else if opt + 0x20 <= buf.len() {
        buf[opt + 0x1c..opt + 0x20].copy_from_slice(&(target_base as u32).to_le_bytes());
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
    let ptr = if pe.is_64bit { 8usize } else { 4 };
    let ordinal_flag: u64 = if pe.is_64bit { 1 << 63 } else { 1 << 31 };
    let image_base = pe.image_base as i64;
    let (imp_rva, _imp_size) = match pe.data_directories.get(1).copied() {
        Some(v) if v.0 != 0 => v,
        _ => return,
    };
    let Some(desc0) = rva_to_file_off(pe, imp_rva as i64) else {
        return;
    };
    let rd = |b: &[u8], o: usize| -> u32 {
        b.get(o..o + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0)
    };
    // Map the RVA stored at file offset `fo` in place, mark 4 bytes.
    let map_rva_field = |buf: &mut [u8], marker: &mut [u8], fo: usize| {
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

    let mut di = 0usize;
    loop {
        let dfo = desc0 + di * 0x14;
        if dfo + 0x14 > buf.len() {
            break;
        }
        let oft = rd(buf, dfo);
        let tds = rd(buf, dfo + 4);
        let name = rd(buf, dfo + 0xc);
        let ft = rd(buf, dfo + 0x10);
        if oft == 0 && name == 0 && ft == 0 {
            break; // null terminator descriptor
        }
        // Read a pointer-sized thunk (4 or 8 bytes) at file offset `fo`.
        let rd_thunk = |b: &[u8], fo: usize| -> u64 {
            if pe.is_64bit {
                b.get(fo..fo + 8)
                    .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
                    .unwrap_or(0)
            } else {
                b.get(fo..fo + 4)
                    .map(|s| u32::from_le_bytes(s.try_into().unwrap()) as u64)
                    .unwrap_or(0)
            }
        };
        // Walk a thunk array at `arr_rva`. `bound` => bound IAT (VAs).
        let walk = |buf: &mut [u8], marker: &mut [u8], arr_rva: u32, bound: bool| {
            if arr_rva == 0 {
                return;
            }
            let Some(base) = rva_to_file_off(pe, arr_rva as i64) else {
                return;
            };
            let mut k = 0usize;
            loop {
                let fo = base + k * ptr;
                if fo + ptr > buf.len() {
                    break;
                }
                let v = rd_thunk(buf, fo);
                if v == 0 {
                    break;
                }
                if bound && tds != 0 {
                    // bound: absolute VA -> map (VA - sourceBase) as RVA, then
                    // relinearize against the TARGET image base. Pointer-sized.
                    let r = v as i64 - image_base;
                    let nv = (target_base as i64)
                        .wrapping_add(r)
                        .wrapping_add(rift.map(r)) as u64;
                    if pe.is_64bit {
                        buf[fo..fo + 8].copy_from_slice(&nv.to_le_bytes());
                    } else {
                        buf[fo..fo + 4].copy_from_slice(&(nv as u32).to_le_bytes());
                    }
                    for b in 0..ptr {
                        marker[fo + b] |= 1;
                    }
                } else if v & ordinal_flag == 0 {
                    // by-name: the low 32 bits are the IMAGE_IMPORT_BY_NAME RVA
                    // (a 32-bit RVA even in an 8-byte PE32+ thunk; high dword 0).
                    map_rva_field(buf, marker, fo);
                    if pe.is_64bit {
                        for b in 4..8 {
                            marker[fo + b] |= 1;
                        }
                    }
                } else {
                    // by-ordinal: not an RVA, but still claim the slot.
                    for b in 0..ptr {
                        marker[fo + b] |= 1;
                    }
                }
                k += 1;
            }
        };
        walk(buf, marker, oft, false);
        walk(buf, marker, ft, tds != 0);
        // The descriptor's own RVA fields.
        map_rva_field(buf, marker, dfo + 0x0c);
        map_rva_field(buf, marker, dfo);
        map_rva_field(buf, marker, dfo + 0x10);
        di += 1;
        if di > 4096 {
            break;
        }
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
    let (rsrc_rva, rsrc_size) = match pe.data_directories.get(2).copied() {
        Some(v) if v.0 != 0 => v,
        _ => return,
    };
    let Some(base_fo) = rva_to_file_off(pe, rsrc_rva as i64) else {
        return;
    };
    let dirbase = rsrc_rva as i64;
    let base_map = map_rva(rift, dirbase); // MapRva(dirbase): the uVar3 subtractor.
    let end = (base_fo + rsrc_size as usize).min(buf.len());

    let rd = |b: &[u8], o: usize| -> u32 {
        b.get(o..o + 4)
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
            .unwrap_or(0)
    };
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
        // Need the 16-byte IMAGE_RESOURCE_DIRECTORY header in range.
        if dir_fo < base_fo || dir_fo + 0x10 > end {
            continue;
        }
        let named = u16::from_le_bytes(buf[dir_fo + 0xc..dir_fo + 0xe].try_into().unwrap()) as usize;
        let ids = u16::from_le_bytes(buf[dir_fo + 0xe..dir_fo + 0x10].try_into().unwrap()) as usize;
        let mut count = named + ids;
        // Clamp to the entries that actually fit before `end`.
        let max_entries = end.saturating_sub(dir_fo + 0x10) / 8;
        if count > max_entries {
            count = max_entries;
        }
        for i in 0..count {
            let efo = dir_fo + 0x10 + i * 8;
            let off_field = rd(buf, efo + 4);
            if off_field & 0x8000_0000 != 0 {
                // Subdirectory: recurse, then map the offset field (low 31 bits).
                let child_rel = (off_field & 0x7fff_ffff) as usize;
                let child_fo = base_fo + child_rel;
                // GetEntryDirectoryRecord guards: child must lie within
                // [base, end] and strictly after this entry.
                if child_fo + 0x10 <= end && child_fo > efo {
                    stack.push(child_fo);
                }
                let nv = remap(child_rel as i64) & 0x7fff_ffff;
                let merged = (off_field & 0x8000_0000) | nv;
                buf[efo + 4..efo + 8].copy_from_slice(&merged.to_le_bytes());
                for b in 4..8 {
                    marker[efo + b] |= 1;
                }
            } else {
                // Leaf: locate the IMAGE_RESOURCE_DATA_ENTRY (dirbase-relative)
                // and re-base its OffsetToData field.
                let data_fo = base_fo + (off_field & 0x7fff_ffff) as usize;
                if data_fo >= base_fo && data_fo + 0x10 <= end {
                    let otd = rd(buf, data_fo) as i64;
                    let nv = remap(otd);
                    buf[data_fo..data_fo + 4].copy_from_slice(&nv.to_le_bytes());
                    for b in 0..4 {
                        marker[data_fo + b] |= 1;
                    }
                }
            }
            // Name field: a string-offset name (high bit set) is dirbase-relative.
            let name_field = rd(buf, efo);
            if name_field & 0x8000_0000 != 0 {
                let nv = remap((name_field & 0x7fff_ffff) as i64) & 0x7fff_ffff;
                let merged = (name_field & 0x8000_0000) | nv;
                buf[efo..efo + 4].copy_from_slice(&merged.to_le_bytes());
                for b in 0..4 {
                    marker[efo + b] |= 1;
                }
            }
        }
    }
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
/// and mark its bytes so the instruction transforms skip them. Handles both
/// type 3 (HIGHLOW, 32-bit -- i386) and type 10 (DIR64, 64-bit -- amd64); a PE
/// carries one or the other. The block rebuild is type-agnostic.
fn transform_source_relocs(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    marker: &mut [u8],
    target_base: u64,
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
                            // Map the pointed-to RVA, relinearize on TARGET base.
                            let r = v - image_base;
                            let nv = (target_base as i64 + r + rift.map(r)) as i32;
                            buf[op_fo..op_fo + 4].copy_from_slice(&nv.to_le_bytes());
                            for b in 0..4 {
                                marker[op_fo + b] |= 1;
                            }
                        }
                    }
                    10 => {
                        // DIR64: rewrite the 64-bit operand, mark 8 bytes.
                        if op_fo + 8 <= buf.len() {
                            let v = i64::from_le_bytes(buf[op_fo..op_fo + 8].try_into().unwrap());
                            let r = v - image_base;
                            let nv = (target_base as i64)
                                .wrapping_add(r)
                                .wrapping_add(rift.map(r))
                                as u64;
                            buf[op_fo..op_fo + 8].copy_from_slice(&nv.to_le_bytes());
                            for b in 0..8 {
                                if op_fo + b < marker.len() {
                                    marker[op_fo + b] |= 1;
                                }
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
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
    2, 2, 2, 2, 0, 0, 1, 1, 2, 2, 2, 2, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 2, 1, 1, 1, 1, 0, 2, 0, 2, 0, 0, 0, 0,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    2, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1,
    3, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 0, 0, 1, 1, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0,
    2, 2, 2, 2, 1, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2,
    4, 4, 4, 4, 0, 0, 0, 0, 5, 5, 1, 4, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0, 0, 2, 2,
];

/// 0F-escaped ModRM/operand kinds (`iVar12` table at base 0x100).
const MODRM_0F: [u8; 256] = [
    2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1, 2, 0, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2,
    0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 0, 1, 1, 1, 1, 1, 1, 2, 2,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    0, 0, 0, 2, 2, 2, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1,
];

/// Immediate-size kind per 1-byte opcode (`iVar17` table at base 0x200).
/// 0 = none, 1 = imm8, 2 = imm16/32 (operand-size sensitive), 3 = moffs-addr,
/// 4 = imm16/32/64 (MOV imm, REX.W => imm64), 5 = imm16/32 + reljmp marker,
/// 6/7 = group F6/F7 (imm present only for /0 /1 = TEST).
const IMM_1B: [u8; 256] = [
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
    0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 1, 1, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 5, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 5, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4,
    1, 1, 2, 0, 0, 0, 1, 5, 3, 0, 2, 0, 0, 1, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Immediate-size kind per 0F-escaped opcode (`iVar17` table at base 0x300).
const IMM_0F: [u8; 256] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
    0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
        return DisasmInsn { len: 0, field_off: 0xff, remap: false };
    }
    // Genuine `Disassemble` never returns length 0 on a non-empty buffer: on any
    // truncation / unknown-opcode (`break`), it returns the bytes consumed so
    // far and the driver advances by that, re-decoding the rest as fresh
    // instructions (no remap). `stop!` mirrors that: emit the consumed length,
    // no remappable field.
    macro_rules! stop {
        ($pos:expr) => {
            return DisasmInsn { len: $pos as u8, field_off: 0xff, remap: false }
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
    let modrm_kind;
    let imm_kind;
    if code[pos] == 0x0f {
        pos += 1;
        if pos >= avail {
            stop!(pos);
        }
        let op = code[pos] as usize;
        modrm_kind = MODRM_0F[op];
        imm_kind = IMM_0F[op];
    } else {
        let op = code[pos] as usize;
        modrm_kind = MODRM_1B[op];
        imm_kind = IMM_1B[op];
    }
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

    DisasmInsn { len: pos as u8, field_off, remap }
}

/// `TransformDisasmX64` apply pass (dpx, g_transformsMap mask 0x200, machine
/// 0x8664). Driven by `.pdata` (the exception directory, data dir index 3):
/// each `RUNTIME_FUNCTION` `[BeginAddress, EndAddress)` RVA range is
/// length-disassembled forward in `output` (target layout) and every
/// RIP-relative disp32 / rel32 displacement is remapped through the preprocess
/// `rift` so it still resolves to the right target byte. No-op when the rift is
/// empty (no relayout) or there is no `.pdata`. Returns the count of fields
/// rewritten.
pub(crate) fn transform_disasm_x64(
    output: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
) -> u32 {
    if rift.entries.is_empty() {
        return 0;
    }
    const EXCEPTION_DIR: usize = 3;
    let Some(&(pdata_rva, pdata_size)) = pe.data_directories.get(EXCEPTION_DIR) else {
        return 0;
    };
    if pdata_rva == 0 || pdata_size < 12 {
        return 0;
    }
    let Some(pdata_off) = rva_to_file_off(pe, pdata_rva as i64) else {
        return 0;
    };
    let n_funcs = (pdata_size / 12) as usize;
    let mut changed = 0u32;
    for i in 0..n_funcs {
        let ent = pdata_off + i * 12;
        if ent + 12 > output.len() {
            break;
        }
        let begin = u32::from_le_bytes(output[ent..ent + 4].try_into().unwrap()) as i64;
        let end = u32::from_le_bytes(output[ent + 4..ent + 8].try_into().unwrap()) as i64;
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
                        output[fpos..fpos + 4]
                            .copy_from_slice(&(new_disp as i32).to_le_bytes());
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
