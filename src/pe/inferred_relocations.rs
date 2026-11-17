//! Classic I386 source-pointer inference when no relocation location resolves.

use super::addr::{SrcRva, TgtRva};
use super::parse::{DataDirectoryKind, PeHeaderLayout, PeInfo, PeMachine, PeOptionalHeaderKind};
use super::structs::{self, ImageOptionalHeader32};
use crate::lzx::rift::RiftTable;

const POINTER_SIZE: usize = size_of::<u32>();
const STRUCTURAL_OWNERSHIP: u8 = 2;
const CLAIMED_POINTER: u8 = 1;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InferredRelocationStats {
    pub candidates: usize,
    pub structurally_owned: usize,
    pub accepted: usize,
    pub changed: usize,
}

/// The native wrapper selects inference by resolved relocation file location,
/// independently of directory size. Directory resolution permits a bounded
/// numeric file-offset fallback after raw-backed RVA resolution fails.
pub(crate) fn uses_inferred_relocations(buf: &[u8], pe: &PeInfo) -> bool {
    if pe.machine != PeMachine::I386 {
        return false;
    }
    let Ok(layout) = PeHeaderLayout::parse(buf) else {
        return false;
    };
    if layout.optional_header_kind != PeOptionalHeaderKind::Pe32 {
        return false;
    }
    let Some(optional) = structs::read::<ImageOptionalHeader32>(buf, layout.optional_header_offset)
    else {
        return false;
    };
    let address = pe
        .data_directory(DataDirectoryKind::BaseRelocation)
        .map_or(0, |directory| directory.rva);
    if address == 0 {
        return true;
    }
    let headers = (optional.size_of_headers.get() as usize).min(buf.len());
    let mapped = if (address as usize) < headers {
        Some(address as usize)
    } else {
        pe.sections.iter().find_map(|section| {
            let end = section.virtual_address.checked_add(section.raw_size)?;
            if address >= end {
                return None;
            }
            let displacement = address.checked_sub(section.virtual_address)?;
            section
                .raw_offset
                .checked_add(displacement)
                .map(|offset| offset as usize)
        })
    };
    if mapped.is_some_and(|offset| offset != 0) {
        return false;
    }
    // Only the numeric-offset fallback is bounded here. A nonzero resolved
    // location must not silently select inference if its extent is malformed.
    address as usize >= buf.len()
}

/// Infer absolute 32-bit source addresses throughout the post-header file.
/// Ownership bit 1 protects structural fields; bit 0 alone does not block a
/// candidate in data. Claim bits belong to the separate marker buffer.
pub(crate) fn transform(
    buf: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    marker: &mut [u8],
    target_base: u64,
) -> InferredRelocationStats {
    let mut stats = InferredRelocationStats::default();
    if pe.machine != PeMachine::I386 {
        return stats;
    }
    let Ok(layout) = PeHeaderLayout::parse(buf) else {
        return stats;
    };
    if layout.optional_header_kind != PeOptionalHeaderKind::Pe32 {
        return stats;
    }
    let Some(optional) = structs::read::<ImageOptionalHeader32>(buf, layout.optional_header_offset)
    else {
        return stats;
    };
    let source_base = optional.image_base.get();
    let image_end = source_base.wrapping_add(optional.size_of_image.get());
    let mut position = optional.size_of_headers.get() as usize;
    let end = buf.len().min(marker.len()).saturating_sub(POINTER_SIZE);
    // Native deliberately excludes the final complete word. An address-shaped
    // candidate consumes four bytes even when ownership prevents rewriting.
    while position < end {
        let word = structs::read_u32(buf, position);
        if source_base < word && word < image_end {
            stats.candidates += 1;
            let ownership = &mut marker[position..position + POINTER_SIZE];
            if ownership
                .iter()
                .any(|byte| byte & STRUCTURAL_OWNERSHIP != 0)
            {
                stats.structurally_owned += 1;
            } else {
                let source_rva = SrcRva(word.wrapping_sub(source_base));
                let target_rva = map_source_rva(rift, source_rva);
                let value = (target_base as u32).wrapping_add(target_rva.0);
                stats.accepted += 1;
                stats.changed += usize::from(value != word);
                structs::write_u32(buf, position, value);
                for byte in ownership {
                    *byte |= CLAIMED_POINTER;
                }
            }
            position += POINTER_SIZE;
        } else {
            position += 1;
        }
    }
    stats
}

// Native RVA lookup uses the final interval before the first anchor. Keep this
// policy local instead of changing the generic RiftTable::map contract.
fn map_source_rva(rift: &RiftTable, source: SrcRva) -> TgtRva {
    let upper = rift
        .entries
        .partition_point(|entry| entry.source <= i64::from(source.0));
    let selected = if upper == 0 {
        rift.entries.last()
    } else {
        rift.entries.get(upper - 1)
    };
    let delta = selected.map_or(0, |entry| entry.target.wrapping_sub(entry.source) as u32);
    TgtRva(source.0.wrapping_add(delta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::RiftEntry;
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::path::Path;

    #[test]
    fn source_inference_matches_native_bytes_and_ownership() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/InferredRelocationsNative");
        let provenance: Value =
            serde_json::from_slice(&std::fs::read(root.join("provenance.json")).unwrap()).unwrap();
        assert_eq!(
            provenance["dll_sha256"],
            "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
        );
        assert_eq!(provenance["native_stage_rva"], 0x12140);
        for (name, accepted) in [("x86-tail-4", 7), ("x86-tail-5", 8)] {
            let case = root.join(name);
            for (file, expected) in provenance["cases"][name].as_object().unwrap() {
                assert_eq!(
                    Sha256::digest(std::fs::read(case.join(file)).unwrap())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>(),
                    expected.as_str().unwrap()
                );
            }
            let stages: Value =
                serde_json::from_slice(&std::fs::read(case.join("stages.json")).unwrap()).unwrap();
            let stage = stages["stages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|stage| stage["name"] == "inferred-i386")
                .unwrap();
            let prefix = format!("stage-{:02}-inferred-i386", stage["id"].as_u64().unwrap());
            let read =
                |suffix: &str| std::fs::read(case.join(format!("{prefix}-{suffix}.bin"))).unwrap();
            let mut bytes = read("before");
            let mut marker = read("marker-before");
            let raw_rift = read("rift");
            assert_eq!(raw_rift.len() % 16, 0);
            let rift = RiftTable {
                entries: raw_rift
                    .chunks_exact(16)
                    .map(|pair| RiftEntry {
                        source: i64::from_le_bytes(pair[..8].try_into().unwrap()),
                        target: i64::from_le_bytes(pair[8..].try_into().unwrap()),
                    })
                    .collect(),
            };
            let pe = PeInfo::parse_lenient(&bytes).unwrap();
            assert!(uses_inferred_relocations(&bytes, &pe));
            let stats = transform(
                &mut bytes,
                &pe,
                &rift,
                &mut marker,
                stage["target_base"].as_u64().unwrap(),
            );
            assert_eq!(bytes, read("after"), "{name}: source bytes");
            assert_eq!(marker, read("marker-after"), "{name}: ownership");
            assert_eq!(stats.accepted, accepted);
            assert_eq!(stats.changed, accepted);
            assert_eq!(stats.structurally_owned, 1);
            assert_eq!(stats.candidates, accepted + 1);
        }
    }

    #[test]
    fn complete_pipeline_matches_native_with_inferred_source_pointers() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/InferredRelocationsNative");
        for name in ["x86-tail-4", "x86-tail-5"] {
            crate::pa30::pipeline_tests::assert_captured_native_pipeline(&root.join(name));
        }
    }

    #[test]
    fn native_patch_reuses_inferred_pointer_bytes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/InferredRelocationsNative");
        let mut reports = Vec::new();
        for name in ["x86-tail-4", "x86-tail-5"] {
            let case = root.join(name);
            let read = |file: &str| std::fs::read(case.join(file)).unwrap();
            let stages: Value = serde_json::from_slice(&read("stages.json")).unwrap();
            let stage = stages["stages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|stage| stage["name"] == "inferred-i386")
                .unwrap();
            let prefix = format!("stage-{:02}-inferred-i386", stage["id"].as_u64().unwrap());
            let before = read(&format!("{prefix}-before.bin"));
            let after = read(&format!("{prefix}-after.bin"));
            let changed: std::collections::BTreeSet<usize> = before
                .iter()
                .zip(&after)
                .enumerate()
                .filter_map(|(offset, (a, b))| (a != b).then_some(offset))
                .collect();
            let transformed = read("transformed-source.bin");
            let raw_rift = read("caller-rift.bin");
            assert_eq!(raw_rift.len() % 16, 0);
            let caller = RiftTable {
                entries: raw_rift
                    .chunks_exact(16)
                    .map(|pair| RiftEntry {
                        source: i64::from_le_bytes(pair[..8].try_into().unwrap()),
                        target: i64::from_le_bytes(pair[8..].try_into().unwrap()),
                    })
                    .collect(),
            };
            let parsed = crate::pa30::parse(&read("delta.pa30")).unwrap();
            let (output, origins) = crate::lzx::decompress_with_copy_source(
                &transformed,
                &parsed.patch_data,
                parsed.header.target_size as usize,
                Some(&caller),
            )
            .unwrap();
            assert_eq!(output, read("decompressed-target.bin"));
            let mut reused = std::collections::BTreeSet::new();
            for (target, origin) in origins.iter().enumerate() {
                if let Ok(source) = usize::try_from(*origin) {
                    assert_eq!(output[target], transformed[source]);
                    if changed.contains(&source) {
                        reused.insert(source);
                    }
                }
            }
            assert_eq!(reused.len(), 13, "{name}: normalized bytes actually reused");
            let input: Value = serde_json::from_slice(&read("input.json")).unwrap();
            let mut sites = Vec::new();
            for site in input["target_sites"].as_array().unwrap() {
                if !matches!(
                    site["category"].as_str(),
                    Some("code-pointer" | "data-pointer")
                ) {
                    continue;
                }
                let offset = site["file_offset"].as_u64().unwrap() as usize;
                let word_origins = &origins[offset..offset + POINTER_SIZE];
                let source_site = input["source_sites"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|source| source["name"] == site["name"])
                    .unwrap();
                let source_offset = source_site["file_offset"].as_i64().unwrap();
                assert_eq!(
                    word_origins,
                    &[
                        source_offset,
                        source_offset + 1,
                        source_offset + 2,
                        source_offset + 3
                    ],
                    "{name}: {}",
                    site["name"]
                );
                let changed_origins: Vec<_> = word_origins
                    .iter()
                    .filter_map(|origin| {
                        usize::try_from(*origin)
                            .ok()
                            .filter(|source| changed.contains(source))
                    })
                    .collect();
                assert!(!changed_origins.is_empty(), "{name}: {}", site["name"]);
                sites.push(serde_json::json!({"name": site["name"], "target_offset": offset,
                    "reference_offsets": word_origins, "changed_reference_offsets": changed_origins}));
            }
            reports.push(serde_json::json!({"case": name, "changed_source_bytes": changed,
                "distinct_changed_source_bytes_reused": reused.len(), "reused_changed_source_bytes": reused,
                "pointer_sites": sites}));
        }
        if let Some(path) = std::env::var_os("MSDELTA_INFERRED_REUSE_REPORT") {
            std::fs::write(path, serde_json::to_vec_pretty(&reports).unwrap()).unwrap();
        }
    }

    #[test]
    fn dispatch_uses_resolved_location_not_directory_size() {
        let source = include_bytes!(
            "../../tests/fixtures/atoms/InferredRelocationsNative/x86-tail-4/source.bin"
        );
        let mut pe = PeInfo::parse_lenient(source).unwrap();
        let slot = DataDirectoryKind::BaseRelocation.index();
        for (address, size, inferred) in [
            (0, 0, true),
            (0, 64, true),
            (0x2000, 0, false),
            (0x2000, 16, false),
            (0x500, 0, false),
            (0x50, 0, false),
            (0xfffffff0, 16, true),
        ] {
            pe.data_directories[slot] = (address, size);
            assert_eq!(
                uses_inferred_relocations(source, &pe),
                inferred,
                "address={address:#x}, size={size}"
            );
        }
        // Static native dispatch contract: a mapped nonzero location remains
        // resolved even beyond EOF; malformed ranges must not enable inference.
        pe.data_directories[slot] = (pe.sections[0].virtual_address, 16);
        pe.sections[0].raw_offset = 0xffff_ff00;
        assert!(!uses_inferred_relocations(source, &pe));
        pe.machine = PeMachine::Amd64;
        assert!(!uses_inferred_relocations(source, &pe));
    }

    #[test]
    fn blocked_candidate_consumes_word_and_short_markers_are_bounded() {
        let mut bytes = include_bytes!(
            "../../tests/fixtures/atoms/InferredRelocationsNative/x86-tail-4/source.bin"
        )
        .to_vec();
        let layout = PeHeaderLayout::parse(&bytes).unwrap();
        let start = 0x200;
        bytes[start..].fill(0);
        structs::write_u32(&mut bytes, layout.image_base_offset().unwrap(), 0);
        structs::write_u32(&mut bytes, start, 0x2100);
        structs::write_u32(&mut bytes, start + 8, 0x100);
        let pe = PeInfo::parse_lenient(&bytes).unwrap();
        let rift = RiftTable {
            entries: Vec::new(),
        };
        let mut marker = vec![0; bytes.len()];
        marker[start] = STRUCTURAL_OWNERSHIP;
        marker[start + 8..start + 12].fill(CLAIMED_POINTER);
        let stats = transform(&mut bytes, &pe, &rift, &mut marker, 0x1000_0000);
        // Starting at start+1 would find a second address-shaped value 0x21,
        // with no structural ownership. Native consumes the blocked word.
        assert_eq!(stats.candidates, 2);
        assert_eq!(stats.structurally_owned, 1);
        assert_eq!(stats.accepted, 1);
        assert_eq!(structs::read_u32(&bytes, start), 0x2100);
        assert_eq!(structs::read_u32(&bytes, start + 8), 0x1000_0100);
        let unchanged = bytes.clone();
        assert_eq!(
            transform(&mut bytes, &pe, &rift, &mut [], 0),
            InferredRelocationStats::default()
        );
        assert_eq!(bytes, unchanged);
        structs::write_u32(&mut bytes, layout.image_base_offset().unwrap(), 0xffff_f000);
        let pe = PeInfo::parse_lenient(&bytes).unwrap();
        assert_eq!(
            transform(&mut bytes, &pe, &rift, &mut marker, 0),
            InferredRelocationStats::default()
        );
    }

    #[test]
    fn native_mapping_uses_last_interval_before_first_and_wraps() {
        let empty = RiftTable { entries: vec![] };
        assert_eq!(map_source_rva(&empty, SrcRva(3)), TgtRva(3));
        let rift = RiftTable {
            entries: vec![
                RiftEntry {
                    source: 10,
                    target: 20,
                },
                RiftEntry {
                    source: 30,
                    target: 5,
                },
            ],
        };
        assert_eq!(
            map_source_rva(&rift, SrcRva(3)),
            TgtRva(3u32.wrapping_sub(25))
        );
        assert_eq!(map_source_rva(&rift, SrcRva(10)), TgtRva(20));
        assert_eq!(map_source_rva(&rift, SrcRva(30)), TgtRva(5));
    }
}
