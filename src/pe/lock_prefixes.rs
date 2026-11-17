use super::addr::SrcRva as SourceRva;
use super::parse::{DataDirectoryKind, PeHeaderLayout, PeInfo, PeMachine, PeOptionalHeaderKind};
use super::structs::{self, ImageOptionalHeader32};
use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The 64-byte PE32 load-config prefix accepted by the native lock pass.
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
struct LoadConfig32 {
    size: U32,
    timestamp: U32,
    major_version: U16,
    minor_version: U16,
    global_flags_clear: U32,
    global_flags_set: U32,
    critical_section_timeout: U32,
    decommit_free_block_threshold: U32,
    decommit_total_free_threshold: U32,
    lock_prefix_table: U32,
    maximum_allocation_size: U32,
    virtual_memory_threshold: U32,
    process_affinity_mask: U32,
    process_heap_flags: U32,
    csd_version: U16,
    dependent_load_flags: U16,
    edit_list: U32,
    security_cookie: U32,
}

#[derive(Clone, Copy)]
struct SourceFileOffset(usize);

struct MappedExtent {
    offset: SourceFileOffset,
    available: usize,
}

fn map_source_rva(
    pe: &PeInfo,
    header_size: u32,
    file_size: usize,
    rva: SourceRva,
) -> Option<MappedExtent> {
    let (offset, available) = if rva.0 < header_size {
        (rva.0, header_size - rva.0)
    } else {
        pe.sections.iter().find_map(|section| {
            let end = section.virtual_address.checked_add(section.raw_size)?;
            if rva.0 >= end {
                return None;
            }
            let displacement = rva.0.checked_sub(section.virtual_address)?;
            Some((
                section.raw_offset.checked_add(displacement)?,
                section.raw_size - displacement,
            ))
        })?
    };
    let offset = offset as usize;
    if offset == 0 || offset >= file_size {
        return None;
    }
    Some(MappedExtent {
        offset: SourceFileOffset(offset),
        available: (available as usize).min(file_size - offset),
    })
}

/// Restore the x86 LOCK opcode at sites listed by the load-config VA table.
/// This pass has no relocation-map or ownership-marker input: the table and
/// its entries contain source absolute addresses, not target RVAs.
pub(crate) fn smash_lock_prefixes(image: &mut [u8], pe: &PeInfo) -> usize {
    if pe.machine != PeMachine::I386 {
        return 0;
    }
    let Ok(layout) = PeHeaderLayout::parse(image) else {
        return 0;
    };
    if layout.optional_header_kind != PeOptionalHeaderKind::Pe32 {
        return 0;
    }
    let Some(optional) =
        structs::read::<ImageOptionalHeader32>(image, layout.optional_header_offset)
    else {
        return 0;
    };
    let Some(directory) = pe.data_directory(DataDirectoryKind::LoadConfig) else {
        return 0;
    };
    if directory.rva == 0 {
        return 0;
    }
    let header_size = optional.size_of_headers.get();
    let directory_offset = map_source_rva(pe, header_size, image.len(), SourceRva(directory.rva))
        .map_or(directory.rva as usize, |extent| extent.offset.0);
    let available = image
        .len()
        .saturating_sub(directory_offset)
        .min(directory.size as usize);
    if available < size_of::<LoadConfig32>() {
        return 0;
    }
    let Some(config) = structs::read::<LoadConfig32>(image, directory_offset) else {
        return 0;
    };
    let table_va = config.lock_prefix_table.get();
    if table_va == 0 {
        return 0;
    }
    let source_base = optional.image_base.get();
    let table_rva = SourceRva(table_va.wrapping_sub(source_base));
    let Some(table) = map_source_rva(pe, header_size, image.len(), table_rva) else {
        return 0;
    };
    let mut changed = 0;
    for index in 0..table.available / size_of::<u32>() {
        let entry_offset = table.offset.0 + index * size_of::<u32>();
        let site_va = structs::read_u32(image, entry_offset);
        if site_va == 0 {
            break;
        }
        let site_rva = SourceRva(site_va.wrapping_sub(source_base));
        let Some(site) = map_source_rva(pe, header_size, image.len(), site_rva) else {
            continue;
        };
        // Native's additional eligibility check compares a file offset against
        // the raw start and virtual end. Preserve that observable quirk; using
        // the raw end changes the raw-after-virtual native fixture.
        let eligible = pe.sections.iter().any(|section| {
            section.raw_offset as usize <= site.offset.0
                && site.offset.0
                    < section.virtual_address.wrapping_add(section.virtual_size) as usize
        });
        if eligible && image[site.offset.0] != 0xf0 {
            image[site.offset.0] = 0xf0;
            changed += 1;
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    const CASES: &[(&str, usize)] = &[
        ("mixed-targets", 3),
        ("raw-boundary", 1),
        ("absent-table", 0),
        ("short-directory", 0),
        ("raw-after-virtual", 1),
    ];

    fn read(case: &str, name: &str) -> Vec<u8> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/LockPrefixesNative");
        std::fs::read(root.join(case).join(name)).unwrap()
    }

    #[test]
    fn load_config_layout_matches_pe32() {
        assert_eq!(size_of::<LoadConfig32>(), 0x40);
        assert_eq!(std::mem::offset_of!(LoadConfig32, lock_prefix_table), 0x20);
    }

    #[test]
    fn lock_prefix_stage_matches_native() {
        for &(case, expected_changes) in CASES {
            let metadata: serde_json::Value =
                serde_json::from_slice(&read(case, "capture.json")).unwrap();
            assert_eq!(
                metadata["dll_sha256"],
                "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
            );
            assert_eq!(metadata["transform_rva"], 0x11d90);
            assert_eq!(metadata["uninstrumented_output_equal"], true);
            for (name, expected) in metadata["artifact_sha256"].as_object().unwrap() {
                let actual: String = Sha256::digest(read(case, name))
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(actual, expected.as_str().unwrap(), "{case}/{name}");
            }
            for (name, field) in [
                ("base.bin", "source_sha256"),
                ("target.bin", "target_sha256"),
                ("native.pa30", "delta_sha256"),
            ] {
                let actual: String = Sha256::digest(read(case, name))
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(actual, metadata[field].as_str().unwrap(), "{case}/{name}");
            }
            let mut before = read(case, "before.bin");
            let pe = PeInfo::parse_lenient(&before).unwrap();
            assert_eq!(
                smash_lock_prefixes(&mut before, &pe),
                expected_changes,
                "{case}"
            );
            assert_eq!(before, read(case, "after.bin"), "{case}");
        }
    }
}
