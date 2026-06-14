//! CLR IL token remapping used by the managed disassembly transform.

use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::metadata::{CliColumnValue, CliMetadataModel};
use crate::pe::cli::method::cli_method_bodies;
use crate::pe::cli::schema::{CliSchemaFlavor, HeapKind};
use crate::pe::cli::tokens::StringsHeapOffset;
use crate::pe::parse::PeInfo;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IlOperand {
    None,
    Fixed(usize),
    Switch,
    Token,
}

pub(crate) fn transform_cli_disasm_tokens(
    image: &mut [u8],
    pe: &PeInfo,
    metadata: &CliMetadataModel,
    cli_map: &CliMapModel,
) -> usize {
    let bodies = cli_method_bodies(image, pe, metadata);
    let mut rewrites = 0usize;

    for body in bodies {
        // Native-created managed deltas reuse constructor operand bytes under
        // different token-table tags; remapping constructor RIDs corrupts those
        // copy sources.
        if is_constructor_body(image, metadata, body.rid) {
            continue;
        }
        let code_start = body.file_offset.saturating_add(body.header_size);
        let Some(code_end) = code_start.checked_add(body.code_size) else {
            continue;
        };
        if code_end > image.len() {
            continue;
        }
        rewrites += transform_il_tokens(&mut image[code_start..code_end], cli_map);
    }

    rewrites
}

pub(crate) fn transform_cli4_disasm_tokens(
    image: &mut [u8],
    pe: &PeInfo,
    metadata: &CliMetadataModel,
    cli_map: &CliMapModel,
) -> Result<usize> {
    if metadata.flavor != CliSchemaFlavor::Cli4 {
        return Err(Error::Malformed(
            "CLI4 disasm transform: source metadata flavor mismatch",
        ));
    }

    Ok(transform_cli_disasm_tokens(image, pe, metadata, cli_map))
}

pub(crate) fn transform_il_tokens(il: &mut [u8], cli_map: &CliMapModel) -> usize {
    let mut rewrites = 0usize;
    let mut cursor = 0usize;

    while cursor < il.len() {
        let opcode = il[cursor];
        cursor += 1;
        let operand = if opcode == 0xfe {
            let Some(&second) = il.get(cursor) else {
                break;
            };
            cursor += 1;
            two_byte_operand(second)
        } else {
            one_byte_operand(opcode)
        };

        match operand {
            IlOperand::None => {}
            IlOperand::Fixed(len) => {
                let Some(next) = cursor.checked_add(len) else {
                    break;
                };
                if next > il.len() {
                    break;
                }
                cursor = next;
            }
            IlOperand::Switch => {
                let Some(count_end) = cursor.checked_add(4) else {
                    break;
                };
                let Some(count_bytes) = il.get(cursor..count_end) else {
                    break;
                };
                let count = u32::from_le_bytes(count_bytes.try_into().unwrap()) as usize;
                let Some(target_bytes) = count.checked_mul(4) else {
                    break;
                };
                let Some(next) = count_end.checked_add(target_bytes) else {
                    break;
                };
                if next > il.len() {
                    break;
                }
                cursor = next;
            }
            IlOperand::Token => {
                let Some(next) = cursor.checked_add(4) else {
                    break;
                };
                let Some(raw_bytes) = il.get(cursor..next) else {
                    break;
                };
                let raw = u32::from_le_bytes(raw_bytes.try_into().unwrap());
                let mapped = map_metadata_or_user_string_token(raw, cli_map);
                if mapped != raw {
                    il[cursor..next].copy_from_slice(&mapped.to_le_bytes());
                    rewrites += 1;
                }
                cursor = next;
            }
        }
    }

    rewrites
}

fn map_metadata_or_user_string_token(raw: u32, cli_map: &CliMapModel) -> u32 {
    let table_id = (raw >> 24) as u8;
    let rid = raw & 0x00ff_ffff;
    let mapped_rid = match table_id {
        0x00..=0x3f => map_rid(&cli_map.tables[table_id as usize], rid),
        0x70 => map_rid(&cli_map.user_strings, rid),
        _ => rid,
    };
    (u32::from(table_id) << 24) | (mapped_rid & 0x00ff_ffff)
}

fn map_rid(rift: &crate::lzx::rift::RiftTable, rid: u32) -> u32 {
    i64::from(rid).wrapping_add(rift.map(i64::from(rid))) as u32
}

fn is_constructor_body(image: &[u8], metadata: &CliMetadataModel, method_rid: u32) -> bool {
    let Ok(row) = metadata.table_row_by_id(image, 0x06, method_rid) else {
        return false;
    };
    let Ok(CliColumnValue::Heap {
        kind: HeapKind::Strings,
        offset,
    }) = row.column("Name")
    else {
        return false;
    };
    matches!(
        metadata.strings(image, StringsHeapOffset::new(offset)),
        Ok(".ctor" | ".cctor")
    )
}

fn one_byte_operand(opcode: u8) -> IlOperand {
    match opcode {
        0x0e..=0x13 | 0x1f | 0x2b..=0x37 | 0xde => IlOperand::Fixed(1),
        0x20 | 0x22 | 0x38..=0x44 | 0xdd => IlOperand::Fixed(4),
        0x21 | 0x23 => IlOperand::Fixed(8),
        0x45 => IlOperand::Switch,
        0x27..=0x29
        | 0x6f..=0x75
        | 0x79
        | 0x7b..=0x81
        | 0x8c
        | 0x8d
        | 0x8f
        | 0xa3..=0xa5
        | 0xc2
        | 0xc6
        | 0xd0 => IlOperand::Token,
        _ => IlOperand::None,
    }
}

fn two_byte_operand(opcode: u8) -> IlOperand {
    match opcode {
        0x09..=0x0e => IlOperand::Fixed(2),
        0x12 | 0x19 => IlOperand::Fixed(1),
        0x06 | 0x07 | 0x15 | 0x16 | 0x1c => IlOperand::Token,
        _ => IlOperand::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::{RiftEntry, RiftTable};
    use crate::pe::cli::metadata::parse_cli_metadata_from_pe;
    use crate::pe::cli::method::cli_method_bodies;
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

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    #[test]
    fn remaps_metadata_and_user_string_tokens() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x02] = rift(&[(3, 7)]);
        cli_map.user_strings = rift(&[(5, 9)]);
        let mut il = vec![
            0x8c, 0x03, 0x00, 0x00, 0x02, // box TypeDef RID 3
            0x72, 0x05, 0x00, 0x00, 0x70, // ldstr #US RID 5
        ];

        let rewrites = transform_il_tokens(&mut il, &cli_map);

        assert_eq!(rewrites, 2);
        assert_eq!(&il[1..5], &0x0200_0007u32.to_le_bytes());
        assert_eq!(&il[6..10], &0x7000_0009u32.to_le_bytes());
    }

    #[test]
    fn remaps_two_byte_token_operands() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x06] = rift(&[(2, 12)]);
        let mut il = vec![
            0xfe, 0x06, 0x02, 0x00, 0x00, 0x06, // ldftn MethodDef RID 2
        ];

        let rewrites = transform_il_tokens(&mut il, &cli_map);

        assert_eq!(rewrites, 1);
        assert_eq!(&il[2..6], &0x0600_000cu32.to_le_bytes());
    }

    #[test]
    fn skips_switch_targets_before_resuming_scan() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x02] = rift(&[(1, 4)]);
        let mut il = vec![
            0x45, 0x02, 0x00, 0x00, 0x00, // switch count 2
            0x11, 0x11, 0x11, 0x11, // target 0
            0x22, 0x22, 0x22, 0x22, // target 1
            0x74, 0x01, 0x00, 0x00, 0x02, // castclass TypeDef RID 1
        ];

        let rewrites = transform_il_tokens(&mut il, &cli_map);

        assert_eq!(rewrites, 1);
        assert_eq!(&il[14..18], &0x0200_0004u32.to_le_bytes());
    }

    #[test]
    fn truncated_operands_stop_current_scan() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x02] = rift(&[(1, 4)]);
        let mut il = vec![0x74, 0x01, 0x00];

        let rewrites = transform_il_tokens(&mut il, &cli_map);

        assert_eq!(rewrites, 0);
        assert_eq!(il, vec![0x74, 0x01, 0x00]);
    }

    #[test]
    fn cli_disasm_transform_preserves_constructor_bodies() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let case_dir = root.join("cli-interface-impl");
        let source =
            std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
        let delta = std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
        let pe = PeInfo::parse_lenient(&source).expect("parse managed source PE");
        let metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
            .expect("parse source CLI metadata");
        let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
        let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
            .expect("parse managed preprocess");
        let mut transformed = source.clone();

        transform_cli_disasm_tokens(&mut transformed, &pe, &metadata, &preprocess.cli_map);

        let mut constructors = 0usize;
        for body in cli_method_bodies(&source, &pe, &metadata) {
            if !is_constructor_body(&source, &metadata, body.rid) {
                continue;
            }
            constructors += 1;
            let code_start = body.file_offset + body.header_size;
            let code_end = code_start + body.code_size;
            assert_eq!(
                &transformed[code_start..code_end],
                &source[code_start..code_end],
                "constructor body RID {} should not be token-remapped",
                body.rid
            );
        }

        assert!(
            constructors > 0,
            "fixture should include a constructor body"
        );
    }

    #[test]
    fn cli_disasm_transform_runs_on_managed_native_corpus() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_methods = 0usize;
        let mut cases_with_rewrites = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let pe = PeInfo::parse_lenient(&source).expect("parse managed source PE");
            let metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
                .expect("parse source CLI metadata");
            let bodies = cli_method_bodies(&source, &pe, &metadata);
            if bodies.is_empty() {
                continue;
            }
            cases_with_methods += 1;

            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse managed preprocess");
            let mut transformed = source.clone();
            let rewrites =
                transform_cli_disasm_tokens(&mut transformed, &pe, &metadata, &preprocess.cli_map);
            if rewrites > 0 {
                cases_with_rewrites += 1;
                assert_ne!(
                    transformed, source,
                    "{case}: reported rewrites should mutate the source image"
                );
            }
        }

        assert!(
            cases_with_methods > 0,
            "managed corpus should include CLI method bodies"
        );
        assert!(
            cases_with_rewrites > 0,
            "managed corpus should include at least one IL token rewrite"
        );
    }

    #[test]
    fn cli4_disasm_transform_runs_through_cli4_metadata_model() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let mut cases_with_methods = 0usize;
        let mut cases_with_rewrites = 0usize;
        for case in MANAGED_NATIVE_CASES {
            let case_dir = root.join(case);
            let source =
                std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
            let delta =
                std::fs::read(case_dir.join("delta.pa30")).expect("read managed delta fixture");
            let pe = PeInfo::parse_lenient(&source).expect("parse managed source PE");
            let metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Cli4)
                .expect("parse source CLI4 metadata");
            let bodies = cli_method_bodies(&source, &pe, &metadata);
            if bodies.is_empty() {
                continue;
            }
            cases_with_methods += 1;

            let parsed = crate::pa30::parse(&delta).expect("parse managed delta");
            let preprocess = crate::pa30::preprocess::parse_pe_preprocess(&parsed.preprocess)
                .expect("parse managed preprocess");
            let mut transformed = source.clone();
            let rewrites =
                transform_cli4_disasm_tokens(&mut transformed, &pe, &metadata, &preprocess.cli_map)
                    .unwrap();
            if rewrites > 0 {
                cases_with_rewrites += 1;
                assert_ne!(
                    transformed, source,
                    "{case}: reported CLI4 rewrites should mutate the source image"
                );
            }
        }

        assert!(
            cases_with_methods > 0,
            "managed corpus should include CLI method bodies for CLI4 wrapper coverage"
        );
        assert!(
            cases_with_rewrites > 0,
            "managed corpus should include at least one CLI4 wrapper token rewrite"
        );
    }

    #[test]
    fn cli4_disasm_transform_rejects_classic_metadata_model() {
        let root = managed_native_corpus_dir();
        if !root.exists() {
            return;
        }

        let case_dir = root.join(MANAGED_NATIVE_CASES[0]);
        let source =
            std::fs::read(case_dir.join("source.dll")).expect("read managed source fixture");
        let pe = PeInfo::parse_lenient(&source).expect("parse managed source PE");
        let metadata = parse_cli_metadata_from_pe(&source, CliSchemaFlavor::Classic)
            .expect("parse source CLI metadata");
        let mut transformed = source.clone();

        let err =
            transform_cli4_disasm_tokens(&mut transformed, &pe, &metadata, &CliMapModel::default())
                .unwrap_err();

        assert!(matches!(
            err,
            Error::Malformed("CLI4 disasm transform: source metadata flavor mismatch")
        ));
    }
}
