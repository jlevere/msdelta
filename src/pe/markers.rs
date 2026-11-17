//! Ownership ranges for the first PE preprocessing stage.

use super::parse::{DataDirectoryKind, PeHeaderLayout, PeInfo};
use super::structs::SCN_MEM_EXECUTE;

const NON_EXECUTABLE: u8 = 1;
const STRUCTURAL: u8 = 3;

/// Mark section and directory ownership in an initially zeroed marker buffer.
/// CLI method bodies are marked separately after this common PE stage.
///
/// Executable raw padding and gaps remain unowned. Directory addresses use the
/// native directory resolver's raw-backed RVA mapping, followed by its bounded
/// file-offset fallback, including for the certificate-directory slot.
pub(crate) fn mark_non_executable(buf: &[u8], pe: &PeInfo, marker: &mut [u8]) {
    let file_len = buf.len().min(marker.len());
    let marker = &mut marker[..file_len];
    for section in &pe.sections {
        if section.characteristics & SCN_MEM_EXECUTE == 0 {
            if let Some(range) = section.clipped_raw_range(file_len) {
                marker[range].fill(NON_EXECUTABLE);
            }
        }
    }

    let Ok(layout) = PeHeaderLayout::parse(buf) else {
        return;
    };
    let header_size = layout
        .size_of_headers_offset()
        .and_then(|offset| buf.get(offset..)?.get(..4))
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four-byte field")) as usize)
        .unwrap_or(0)
        .min(file_len);
    marker[..header_size].fill(STRUCTURAL);

    for &(address, size) in pe
        .data_directories
        .iter()
        .take(layout.number_of_rva_and_sizes.min(DataDirectoryKind::COUNT))
    {
        if address == 0 || size == 0 {
            continue;
        }
        let offset = directory_offset(pe, address, header_size)
            .filter(|&offset| offset != 0)
            .unwrap_or(address as usize);
        if offset < file_len {
            let count = (size as usize).min(file_len - offset);
            marker[offset..offset + count].fill(STRUCTURAL);
        }
    }
}

fn directory_offset(pe: &PeInfo, address: u32, header_size: usize) -> Option<usize> {
    if (address as usize) < header_size {
        return Some(address as usize);
    }
    pe.sections.iter().find_map(|section| {
        let within_section = address.checked_sub(section.virtual_address)?;
        if within_section >= section.raw_size {
            return None;
        }
        section
            .raw_offset
            .checked_add(within_section)
            .map(|offset| offset as usize)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn ownership_matches_native_composed_pe_snapshots() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms");
        for (family, name) in [
            ("PePipelineNative", "x86-backed-executable"),
            ("PePipelineNative", "x86-header-gap"),
            ("PePipelineNative", "x86-raw-padding"),
            ("PePipelineNative", "x86-virtual-tail-file-alias"),
            ("PePipelineNative", "x86-virtual-tail-outside-file"),
            ("PePipelineExistingNative", "x64-rva-moved"),
            ("PePipelineExistingNative", "x64-rva-preserved"),
        ] {
            let case = root.join(family).join(name);
            let source = std::fs::read(case.join("stage-00-mark-non-exe-before.bin")).unwrap();
            let after = std::fs::read(case.join("stage-00-mark-non-exe-after.bin")).unwrap();
            let mut marker =
                std::fs::read(case.join("stage-00-mark-non-exe-marker-before.bin")).unwrap();
            let expected =
                std::fs::read(case.join("stage-00-mark-non-exe-marker-after.bin")).unwrap();
            assert!(marker.iter().all(|&value| value == 0), "{name}");
            let pe = PeInfo::parse_lenient(&source).unwrap();
            mark_non_executable(&source, &pe, &mut marker);
            assert_eq!(marker, expected, "{name}");
            assert_eq!(source, after, "ownership must not change PE bytes: {name}");
        }
    }

    #[test]
    fn native_managed_ownership_visits_full_bodies_except_final_method_row() {
        use crate::pe::cli::metadata::parse_cli_metadata_from_pe_info;
        use crate::pe::cli::method::cli_method_bodies;
        use crate::pe::cli::schema::{table, CliSchemaFlavor};

        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/PePipelineExistingNative");
        for name in [
            "cli-interface-impl",
            "cli-constructor-token-boundary",
            "cli-constructor-user-string-boundary",
            "cli-static-constructor-token-boundary",
        ] {
            let case = root.join(name);
            let source = std::fs::read(case.join("stage-00-mark-non-exe-before.bin")).unwrap();
            let expected =
                std::fs::read(case.join("stage-00-mark-non-exe-marker-after.bin")).unwrap();
            let pe = PeInfo::parse_lenient(&source).unwrap();
            let metadata =
                parse_cli_metadata_from_pe_info(&source, &pe, CliSchemaFlavor::Classic).unwrap();
            let bodies = cli_method_bodies(&source, &pe, &metadata);
            let limit = metadata.row_counts[table::METHOD_DEF as usize];
            let mut marker = vec![0; source.len()];
            mark_non_executable(&source, &pe, &mut marker);
            for body in bodies.iter().filter(|body| body.rid < limit) {
                marker[body.file_offset..body.file_offset + body.total_size].fill(STRUCTURAL);
            }
            assert_eq!(marker, expected, "native full method ownership: {name}");
            let final_body = bodies.iter().find(|body| body.rid == limit).unwrap();
            let final_range =
                final_body.file_offset..final_body.file_offset + final_body.total_size;
            assert!(
                marker[final_range.clone()]
                    .iter()
                    .any(|&byte| byte != STRUCTURAL),
                "final method must distinguish the loop bound: {name}"
            );
            marker[final_range].fill(STRUCTURAL);
            assert_ne!(
                marker, expected,
                "inclusive final-row ownership is incorrect: {name}"
            );
        }
    }

    #[test]
    fn malformed_section_ranges_are_clipped_to_available_markers() {
        let source = include_bytes!(
            "../../tests/fixtures/atoms/PePipelineNative/x86-backed-executable/source.bin"
        );
        let mut pe = PeInfo::parse_lenient(source).unwrap();
        pe.sections[0].characteristics = 0;
        pe.sections[0].raw_offset = u32::MAX;
        pe.sections[0].raw_size = u32::MAX;
        pe.data_directories.fill((u32::MAX, u32::MAX));
        let mut marker = [0; 17];
        mark_non_executable(source, &pe, &mut marker);
        assert_eq!(marker, [STRUCTURAL; 17]);
    }
}
