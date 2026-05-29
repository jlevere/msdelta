//! Rift table generation from comparing two PE binaries.

use super::parse::PeInfo;
use crate::lzx::rift::{RiftEntry, RiftTable};

/// Build the PE rift table the way genuine msdelta.dll does: the *source*
/// (reference) image's RVA -> file-offset map. One entry per section,
/// `{source: VirtualAddress, target: PointerToRawData}`, preceded by a
/// `{0, 0}` header entry.
///
/// Confirmed byte-exact against genuine `CreateDeltaB` output (Win Server 2025,
/// build 26100): for cmd.exe the 9 entries are exactly headers + the 8 section
/// `(VA -> RawPtr)` pairs (e.g. .pdata 0x61000 -> 0x45000). msdelta's apply
/// uses this map to translate between the in-memory RVA view (where absolute
/// pointers live) and the on-disk file layout the patch is computed over.
pub fn pe_section_rift(reference: &[u8]) -> RiftTable {
    let mut entries = vec![RiftEntry { source: 0, target: 0 }];

    if let Ok(pe) = goblin::pe::PE::parse(reference) {
        for s in &pe.sections {
            if s.virtual_address == 0 || s.pointer_to_raw_data == 0 {
                continue;
            }
            entries.push(RiftEntry {
                source: s.virtual_address as i64,
                target: s.pointer_to_raw_data as i64,
            });
        }
    }

    entries.sort_by_key(|e| e.source);
    entries.dedup_by_key(|e| e.source);
    RiftTable { entries }
}

/// Generate a rift table from section header alignment between two PEs.
///
/// Matches sections by name and creates entries where the virtual address
/// differs between source and target. Also matches data directory entries.
pub fn rift_from_sections(source: &PeInfo, target: &PeInfo) -> RiftTable {
    let mut entries = Vec::new();

    for src_sec in &source.sections {
        for tgt_sec in &target.sections {
            if src_sec.name == tgt_sec.name
                && src_sec.virtual_address > 0
                && tgt_sec.virtual_address > 0
                && src_sec.virtual_address != tgt_sec.virtual_address
            {
                entries.push(RiftEntry {
                    source: src_sec.virtual_address as i64 - 1,
                    target: tgt_sec.virtual_address as i64 - 1,
                });
                break;
            }
        }
    }

    let dd_count = source
        .data_directories
        .len()
        .min(target.data_directories.len());
    for i in 0..dd_count {
        let (src_rva, src_size) = source.data_directories[i];
        let (tgt_rva, tgt_size) = target.data_directories[i];
        if src_rva > 0 && src_size > 0 && tgt_rva > 0 && tgt_size > 0 && src_rva != tgt_rva {
            entries.push(RiftEntry {
                source: src_rva as i64,
                target: tgt_rva as i64,
            });
        }
    }

    entries.sort_by_key(|e| e.source);
    entries.dedup_by_key(|e| e.source);
    RiftTable { entries }
}

/// Generate a rift table from import descriptor matching between two PEs.
///
/// Matches import descriptors by DLL name and creates entries for the
/// import descriptor RVA, DLL name RVA, and IAT RVA.
pub fn rift_from_imports(source_data: &[u8], target_data: &[u8]) -> RiftTable {
    let mut entries = Vec::new();

    let src_pe = match goblin::pe::PE::parse(source_data) {
        Ok(pe) => pe,
        Err(_) => return RiftTable { entries },
    };
    let tgt_pe = match goblin::pe::PE::parse(target_data) {
        Ok(pe) => pe,
        Err(_) => return RiftTable { entries },
    };

    let src_imports = &src_pe.imports;
    let tgt_imports = &tgt_pe.imports;

    for src_imp in src_imports {
        for tgt_imp in tgt_imports {
            if src_imp.dll == tgt_imp.dll {
                if src_imp.offset != 0 && tgt_imp.offset != 0 && src_imp.offset != tgt_imp.offset {
                    entries.push(RiftEntry {
                        source: src_imp.offset as i64,
                        target: tgt_imp.offset as i64,
                    });
                }
                break;
            }
        }
    }

    entries.sort_by_key(|e| e.source);
    entries.dedup_by_key(|e| e.source);
    RiftTable { entries }
}

/// Generate rift entries from export directory matching.
pub fn rift_from_exports(source_data: &[u8], target_data: &[u8]) -> RiftTable {
    let mut entries = Vec::new();

    let src_pe = match goblin::pe::PE::parse(source_data) {
        Ok(pe) => pe,
        Err(_) => return RiftTable { entries },
    };
    let tgt_pe = match goblin::pe::PE::parse(target_data) {
        Ok(pe) => pe,
        Err(_) => return RiftTable { entries },
    };

    let src_exports = &src_pe.exports;
    let tgt_exports = &tgt_pe.exports;

    for src_exp in src_exports {
        if let Some(src_name) = src_exp.name {
            for tgt_exp in tgt_exports {
                if tgt_exp.name == Some(src_name) {
                    if let (Some(src_off), Some(tgt_off)) = (src_exp.offset, tgt_exp.offset) {
                        if src_off != tgt_off {
                            entries.push(RiftEntry {
                                source: src_off as i64,
                                target: tgt_off as i64,
                            });
                        }
                    }
                    break;
                }
            }
        }
    }

    entries.sort_by_key(|e| e.source);
    entries.dedup_by_key(|e| e.source);
    RiftTable { entries }
}

/// Generate rift entries from resource directory structure.
///
/// Compares resource directory RVAs between source and target PEs.
pub fn rift_from_resources(source: &PeInfo, target: &PeInfo) -> RiftTable {
    let mut entries = Vec::new();
    const RESOURCE_DIR_IDX: usize = 2;
    if RESOURCE_DIR_IDX < source.data_directories.len()
        && RESOURCE_DIR_IDX < target.data_directories.len()
    {
        let (src_rva, src_size) = source.data_directories[RESOURCE_DIR_IDX];
        let (tgt_rva, tgt_size) = target.data_directories[RESOURCE_DIR_IDX];
        if src_rva > 0 && src_size > 0 && tgt_rva > 0 && tgt_size > 0 && src_rva != tgt_rva {
            entries.push(RiftEntry {
                source: src_rva as i64 - 1,
                target: tgt_rva as i64 - 1,
            });
        }
    }
    entries.sort_by_key(|e| e.source);
    RiftTable { entries }
}

/// Generate rift entries from exception/pdata directory.
///
/// Compares pdata (exception handler) directory RVAs between PEs.
pub fn rift_from_pdata(source: &PeInfo, target: &PeInfo) -> RiftTable {
    let mut entries = Vec::new();
    const EXCEPTION_DIR_IDX: usize = 3;
    if EXCEPTION_DIR_IDX < source.data_directories.len()
        && EXCEPTION_DIR_IDX < target.data_directories.len()
    {
        let (src_rva, src_size) = source.data_directories[EXCEPTION_DIR_IDX];
        let (tgt_rva, tgt_size) = target.data_directories[EXCEPTION_DIR_IDX];
        if src_rva > 0 && src_size > 0 && tgt_rva > 0 && tgt_size > 0 && src_rva != tgt_rva {
            entries.push(RiftEntry {
                source: src_rva as i64 - 1,
                target: tgt_rva as i64 - 1,
            });
        }
    }
    entries.sort_by_key(|e| e.source);
    RiftTable { entries }
}

/// Generate rift entries from per-thunk import matching.
///
/// Matches individual imported functions by name within each DLL,
/// creating rift entries for each IAT slot that moves.
pub fn rift_from_import_thunks(source_data: &[u8], target_data: &[u8]) -> RiftTable {
    let mut entries = Vec::new();

    let src_pe = match goblin::pe::PE::parse(source_data) {
        Ok(pe) => pe,
        Err(_) => return RiftTable { entries },
    };
    let tgt_pe = match goblin::pe::PE::parse(target_data) {
        Ok(pe) => pe,
        Err(_) => return RiftTable { entries },
    };

    for src_imp in &src_pe.imports {
        for tgt_imp in &tgt_pe.imports {
            if src_imp.dll == tgt_imp.dll && src_imp.name == tgt_imp.name {
                if src_imp.offset != 0 && tgt_imp.offset != 0 && src_imp.offset != tgt_imp.offset {
                    entries.push(RiftEntry {
                        source: src_imp.offset as i64,
                        target: tgt_imp.offset as i64,
                    });
                }
                break;
            }
        }
    }

    entries.sort_by_key(|e| e.source);
    entries.dedup_by_key(|e| e.source);
    RiftTable { entries }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rift_from_sections_identical_pe() {
        let pe = PeInfo {
            image_base: 0x140000000,
            size_of_image: 0x50000,
            timestamp: 0x12345678,
            checksum: 0,
            is_64bit: true,
            sections: vec![super::super::parse::SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x10000,
                raw_offset: 0x400,
                raw_size: 0x10000,
                characteristics: 0,
            }],
            data_directories: vec![],
        };
        let rift = rift_from_sections(&pe, &pe);
        assert!(rift.entries.is_empty(), "identical PEs produce empty rift");
    }

    #[test]
    fn rift_from_sections_shifted() {
        let source = PeInfo {
            image_base: 0x140000000,
            size_of_image: 0x50000,
            timestamp: 0x11111111,
            checksum: 0,
            is_64bit: true,
            sections: vec![super::super::parse::SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x10000,
                raw_offset: 0x400,
                raw_size: 0x10000,
                characteristics: 0,
            }],
            data_directories: vec![],
        };
        let target = PeInfo {
            image_base: 0x140000000,
            size_of_image: 0x60000,
            timestamp: 0x22222222,
            checksum: 0,
            is_64bit: true,
            sections: vec![super::super::parse::SectionInfo {
                name: ".text".to_string(),
                virtual_address: 0x2000,
                virtual_size: 0x10000,
                raw_offset: 0x600,
                raw_size: 0x10000,
                characteristics: 0,
            }],
            data_directories: vec![],
        };
        let rift = rift_from_sections(&source, &target);
        let text_entry = rift.entries.iter().find(|e| e.source == 0xFFF).unwrap();
        assert_eq!(text_entry.target, 0x1FFF);
    }
}
