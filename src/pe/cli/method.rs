//! CLR method-body enumeration helpers.

use crate::pe::cli::metadata::{CliColumnValue, CliMetadataModel};
use crate::pe::parse::{PeInfo, SectionInfo};

const METHOD_DEF_TABLE_ID: usize = 0x06;
const METHOD_HEADER_TINY_FORMAT: u8 = 0x02;
const METHOD_HEADER_FAT_FORMAT: u8 = 0x03;
const METHOD_HEADER_MORE_SECTS: u16 = 0x0008;
const METHOD_EXTRA_SECTION_FAT: u8 = 0x40;
const METHOD_EXTRA_SECTION_MORE_SECTS: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliMethodBody {
    pub(crate) rid: u32,
    pub(crate) rva: u32,
    pub(crate) file_offset: usize,
    pub(crate) header_size: usize,
    pub(crate) code_size: usize,
    pub(crate) total_size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliMethodBodyLayout {
    pub(crate) header_size: usize,
    pub(crate) code_size: usize,
    pub(crate) total_size: usize,
}

pub(crate) fn cli_method_bodies(
    image: &[u8],
    pe: &PeInfo,
    metadata: &CliMetadataModel,
) -> Vec<CliMethodBody> {
    let row_count = metadata.row_counts[METHOD_DEF_TABLE_ID];
    let mut bodies = Vec::new();

    for rid in 1..=row_count {
        if let Some(body) = cli_method_body(image, pe, metadata, rid) {
            bodies.push(body);
        }
    }

    bodies
}

pub(crate) fn cli_method_body(
    image: &[u8],
    pe: &PeInfo,
    metadata: &CliMetadataModel,
    rid: u32,
) -> Option<CliMethodBody> {
    let row = metadata
        .table_row_by_id(image, METHOD_DEF_TABLE_ID as u8, rid)
        .ok()?;
    let rva = match row.column("Rva").ok()? {
        CliColumnValue::Rva(rva) if rva != 0 => rva,
        _ => return None,
    };
    let (file_offset, available) = method_rva_to_file_offset(pe, rva)?;
    let layout = parse_cli_method_body_layout(image, file_offset, available)?;

    Some(CliMethodBody {
        rid,
        rva,
        file_offset,
        header_size: layout.header_size,
        code_size: layout.code_size,
        total_size: layout.total_size,
    })
}

pub(crate) fn parse_cli_method_body_layout(
    image: &[u8],
    file_offset: usize,
    available: usize,
) -> Option<CliMethodBodyLayout> {
    let remaining = image.len().checked_sub(file_offset)?.min(available);
    let first = *image.get(file_offset)?;

    match first & 0x03 {
        METHOD_HEADER_TINY_FORMAT => {
            let code_size = (first >> 2) as usize;
            let total_size = 1usize.checked_add(code_size)?;
            (total_size <= remaining).then_some(CliMethodBodyLayout {
                header_size: 1,
                code_size,
                total_size,
            })
        }
        METHOD_HEADER_FAT_FORMAT => {
            if remaining < 12 {
                return None;
            }

            let flags_and_size =
                u16::from_le_bytes([image[file_offset], image[file_offset.checked_add(1)?]]);
            let header_size = ((flags_and_size >> 12) as usize).checked_mul(4)?;
            if header_size < 12 || header_size > remaining {
                return None;
            }

            let code_size = u32::from_le_bytes(
                image
                    .get(file_offset.checked_add(4)?..file_offset.checked_add(8)?)?
                    .try_into()
                    .ok()?,
            ) as usize;
            let mut total_size = header_size.checked_add(code_size)?;
            if total_size > remaining {
                return None;
            }

            if flags_and_size & METHOD_HEADER_MORE_SECTS != 0 {
                total_size = method_body_size_with_extra_sections(
                    image,
                    file_offset,
                    total_size,
                    remaining,
                )?;
            }

            Some(CliMethodBodyLayout {
                header_size,
                code_size,
                total_size,
            })
        }
        _ => None,
    }
}

fn method_rva_to_file_offset(pe: &PeInfo, rva: u32) -> Option<(usize, usize)> {
    let section = raw_backed_section_containing_rva(pe, rva)?;
    let delta = rva.checked_sub(section.virtual_address)?;
    let file_offset = section.raw_offset.checked_add(delta)? as usize;
    let available = section.raw_size.checked_sub(delta)? as usize;
    Some((file_offset, available))
}

fn raw_backed_section_containing_rva(pe: &PeInfo, rva: u32) -> Option<&SectionInfo> {
    pe.sections.iter().find(|section| {
        section.raw_size != 0
            && rva >= section.virtual_address
            && rva < section.virtual_address.saturating_add(section.raw_size)
    })
}

fn method_body_size_with_extra_sections(
    image: &[u8],
    file_offset: usize,
    body_without_sections: usize,
    remaining: usize,
) -> Option<usize> {
    let mut cursor = align4(body_without_sections)?;
    loop {
        if cursor.checked_add(4)? > remaining {
            return None;
        }

        let section_offset = file_offset.checked_add(cursor)?;
        let kind = *image.get(section_offset)?;
        let data_size = if kind & METHOD_EXTRA_SECTION_FAT != 0 {
            let bytes =
                image.get(section_offset.checked_add(1)?..section_offset.checked_add(4)?)?;
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as usize
        } else {
            *image.get(section_offset.checked_add(1)?)? as usize
        };
        let section_size = 4usize.checked_add(data_size)?;
        let next = cursor.checked_add(section_size)?;
        if next > remaining {
            return None;
        }

        if kind & METHOD_EXTRA_SECTION_MORE_SECTS == 0 {
            return Some(next);
        }
        cursor = align4(next)?;
    }
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::cli::metadata::parse_cli_metadata_from_pe;
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

    #[test]
    fn parses_tiny_method_body_layout() {
        let image = [0x0eu8, 0xaa, 0xbb, 0xcc];
        let layout = parse_cli_method_body_layout(&image, 0, image.len()).unwrap();

        assert_eq!(
            layout,
            CliMethodBodyLayout {
                header_size: 1,
                code_size: 3,
                total_size: 4,
            }
        );
    }

    #[test]
    fn parses_fat_method_body_layout() {
        let mut image = [0u8; 24];
        image[0..2].copy_from_slice(&0x3003u16.to_le_bytes());
        image[4..8].copy_from_slice(&5u32.to_le_bytes());

        let layout = parse_cli_method_body_layout(&image, 0, image.len()).unwrap();

        assert_eq!(
            layout,
            CliMethodBodyLayout {
                header_size: 12,
                code_size: 5,
                total_size: 17,
            }
        );
    }

    #[test]
    fn parses_fat_method_body_with_extra_sections() {
        let mut image = [0u8; 32];
        image[0..2].copy_from_slice(&0x300bu16.to_le_bytes());
        image[4..8].copy_from_slice(&3u32.to_le_bytes());
        image[16] = 0x01;
        image[17] = 4;

        let layout = parse_cli_method_body_layout(&image, 0, image.len()).unwrap();

        assert_eq!(
            layout,
            CliMethodBodyLayout {
                header_size: 12,
                code_size: 3,
                total_size: 24,
            }
        );
    }

    #[test]
    fn rejects_truncated_method_body_layouts() {
        assert!(parse_cli_method_body_layout(&[0x0e, 0xaa], 0, 2).is_none());

        let mut image = [0u8; 12];
        image[0..2].copy_from_slice(&0x3003u16.to_le_bytes());
        image[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(parse_cli_method_body_layout(&image, 0, image.len()).is_none());
    }

    #[test]
    fn method_bodies_build_from_managed_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_methods = 0usize;
        let mut total_methods = 0usize;
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
            total_methods += bodies.len();
            for body in bodies {
                assert!(body.header_size > 0, "{case}: method has header");
                assert!(
                    body.file_offset + body.total_size <= source.len(),
                    "{case}: method body should fit in file"
                );
                assert!(
                    body.header_size + body.code_size <= body.total_size,
                    "{case}: total method body size should cover header and IL"
                );
            }
        }

        assert!(
            cases_with_methods > 0,
            "managed corpus should include method-body rows"
        );
        assert!(
            total_methods > 0,
            "managed corpus should expose method bodies"
        );
    }
}
