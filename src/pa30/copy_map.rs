use super::preprocess::PePreprocess;
use crate::lzx::rift::{RiftEntry, RiftTable};
use crate::pe::addr::{SrcRva, TgtRva};
use crate::pe::parse::PeInfo;
use std::marker::PhantomData;

// Domain tags prevent composing two numerically similar but incompatible maps.
struct SourceFileOffsets;
struct TargetFileOffsets;
struct CallerPositions;

struct AddressMap<From, To> {
    table: RiftTable,
    domains: PhantomData<fn(From) -> To>,
}

impl<From, To> AddressMap<From, To> {
    fn new(table: RiftTable) -> Self {
        Self {
            table,
            domains: PhantomData,
        }
    }

    fn then<Next>(self, next: AddressMap<To, Next>) -> AddressMap<From, Next> {
        AddressMap::new(self.table.multiply(&next.table))
    }

    // Native Reverse selects intervals when the forward map has overlaps or
    // gaps. It is not a pointwise swap, nor an assertion that the map is bijective.
    fn native_reverse(self) -> AddressMap<To, From> {
        AddressMap::new(self.table.reverse())
    }
}

impl AddressMap<TargetFileOffsets, SourceFileOffsets> {
    fn merge_cli(self, cli: Self) -> Self {
        Self::new(merge_rift_entries(&self.table, &cli.table))
    }

    fn into_caller_positions(
        self,
        reference_len: usize,
    ) -> AddressMap<CallerPositions, SourceFileOffsets> {
        let caller_origin = AddressMap::<CallerPositions, TargetFileOffsets>::new(RiftTable {
            entries: vec![RiftEntry {
                source: reference_len as i64,
                target: 0,
            }],
        });
        // Apply's graph composes the reference-size origin with the complete
        // copy map, then reduces equal-displacement intervals. Doing only a
        // key shift leaves redundant wrap anchors and mishandles the identity.
        let mut caller = caller_origin.then(self);
        caller.table.internal_reduce(false);
        caller
    }
}

#[cfg(test)]
pub(super) fn build_pe_copy_rift(reference: &[u8], pp: &PePreprocess) -> RiftTable {
    build_pe_copy_rift_with_cli_rift(
        reference,
        pp,
        &RiftTable {
            entries: Vec::new(),
        },
    )
}

pub(super) fn build_pe_copy_rift_with_cli_rift(
    reference: &[u8],
    pp: &PePreprocess,
    cli_rift: &RiftTable,
) -> RiftTable {
    let Some(copy_map) = compose_copy_map(reference, pp) else {
        return legacy_unparsed_reference_map(pp);
    };
    copy_map
        .merge_cli(AddressMap::new(cli_rift.clone()))
        .into_caller_positions(reference.len())
        .table
}

fn compose_copy_map(
    reference: &[u8],
    pp: &PePreprocess,
) -> Option<AddressMap<TargetFileOffsets, SourceFileOffsets>> {
    let source_pe = PeInfo::parse_lenient(reference).ok()?;
    let source_layout = AddressMap::<SourceFileOffsets, SrcRva>::new(build_pe_io2rva(&source_pe));
    let relocated_rvas = AddressMap::<SrcRva, TgtRva>::new(pp.preprocess_rift.clone());
    let target_layout = AddressMap::<TgtRva, TargetFileOffsets>::new(
        pp.target_info.target_rva_to_file_offset.clone(),
    );

    // Compose the complete forward chain before native interval reversal:
    // source file -> source RVA -> target RVA -> target file.
    // Target-file overlaps/gaps are resolved by reversing this whole chain.
    Some(
        source_layout
            .then(relocated_rvas)
            .then(target_layout)
            .native_reverse(),
    )
}

#[cfg(test)]
pub(super) fn build_pe_copy_rift_unfolded(
    reference: &[u8],
    pp: &PePreprocess,
) -> Option<RiftTable> {
    Some(compose_copy_map(reference, pp)?.table)
}

// Preserve the existing unparseable-reference compatibility path during this
// extraction. Its mixed-domain concatenation is not covered by the typed PE
// composition contract and must not be treated as native-verified behavior.
fn legacy_unparsed_reference_map(pp: &PePreprocess) -> RiftTable {
    let mut combined = pp.target_info.target_rva_to_file_offset.clone();
    combined
        .entries
        .extend_from_slice(&pp.preprocess_rift.entries);
    combined.entries.sort_by_key(|entry| entry.source);
    combined
}

#[cfg(test)]
pub(super) fn fold_target_to_source_rift_for_decompressor(
    reference_len: usize,
    target_to_source: &RiftTable,
) -> RiftTable {
    AddressMap::<TargetFileOffsets, SourceFileOffsets>::new(target_to_source.clone())
        .into_caller_positions(reference_len)
        .table
}

pub(super) fn merge_rift_entries(a: &RiftTable, b: &RiftTable) -> RiftTable {
    // Preserve all breakpoints and equal-key ordering. The CLI map overlays
    // file-offset intervals; this merge is not function composition or addition
    // of numeric RVA displacements.
    let mut entries = Vec::with_capacity(a.entries.len() + b.entries.len());
    entries.extend_from_slice(&a.entries);
    entries.extend_from_slice(&b.entries);
    entries.sort_by_key(|entry| entry.source);
    RiftTable { entries }
}

pub(super) fn build_pe_io2rva(pe: &PeInfo) -> RiftTable {
    let mut entries = vec![RiftEntry {
        source: 0,
        target: 0,
    }];
    for section in &pe.sections {
        if section.virtual_address == 0 || section.raw_offset == 0 {
            continue;
        }
        entries.push(RiftEntry {
            source: i64::from(section.raw_offset),
            target: i64::from(section.virtual_address),
        });
    }
    // These are piecewise displacement anchors, not bounded section ranges.
    // Keep every anchor, including adjacent anchors with equal displacement.
    entries.sort_by_key(|entry| entry.source);
    RiftTable { entries }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const NATIVE_CASES: &[&str] = &[
        "x86-rva-moved",
        "x86-rva-preserved",
        "x64-rva-moved",
        "x64-rva-preserved",
    ];

    #[derive(Deserialize)]
    struct Capture {
        schema: u32,
        dll_sha256: String,
        decompress_rva: u32,
        sum_rva: u32,
        reference_size: usize,
        target_size: usize,
        original_source_size: usize,
        folded: bool,
        artifact_sha256: BTreeMap<String, String>,
        uninstrumented_output_equal: bool,
        decompress_source_unchanged: bool,
    }

    fn native_file(case: &str, name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/Pa30CopyNative")
            .join(case)
            .join(name);
        std::fs::read(path).unwrap()
    }

    fn native_rift(case: &str, name: &str) -> RiftTable {
        let bytes = native_file(case, name);
        assert_eq!(bytes.len() % 16, 0);
        RiftTable {
            entries: bytes
                .chunks_exact(16)
                .map(|pair| RiftEntry {
                    source: i64::from_le_bytes(pair[..8].try_into().unwrap()),
                    target: i64::from_le_bytes(pair[8..].try_into().unwrap()),
                })
                .collect(),
        }
    }

    #[test]
    fn copy_maps_match_native_decompressor_boundary() {
        for case in NATIVE_CASES {
            let capture: Capture =
                serde_json::from_slice(&native_file(case, "capture.json")).unwrap();
            assert_eq!(capture.schema, 1);
            assert_eq!(
                capture.dll_sha256,
                "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
            );
            assert_eq!(capture.decompress_rva, 0x7b40);
            assert_eq!(capture.sum_rva, 0x1ce10);
            assert!(
                capture.folded
                    && capture.uninstrumented_output_equal
                    && capture.decompress_source_unchanged
            );
            for (name, expected) in &capture.artifact_sha256 {
                let actual: String = Sha256::digest(native_file(case, name))
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(&actual, expected, "{case}/{name}");
            }
            let source = native_file(case, "source.bin");
            assert_eq!(source.len(), capture.original_source_size);
            let parsed = super::super::parse(&native_file(case, "delta.pa30")).unwrap();
            let preprocess =
                super::super::preprocess::parse_pe_preprocess(&parsed.preprocess).unwrap();
            let caller = build_pe_copy_rift(&source, &preprocess);
            let native_caller = native_rift(case, "caller-rift.bin");
            assert_eq!(caller, native_caller, "{case}: complete caller map");
            let mut reader = crate::bitstream::BitReader::new(&parsed.patch_data).unwrap();
            let patch_rift = RiftTable::from_reader(&mut reader).unwrap();
            assert_eq!(
                patch_rift,
                native_rift(case, "patch-rift.bin"),
                "{case}: patch-local map"
            );
            assert_eq!(
                merge_rift_entries(&patch_rift, &caller),
                native_rift(case, "merged-rift.bin"),
                "{case}: merged decompressor map"
            );
            let transformed = native_file(case, "transformed-source.bin");
            assert_eq!(transformed.len(), capture.reference_size);
            // Raw-file layout changes are independent of whether RVAs moved.
            // The target's .data and .reloc resolve to their source file ranges;
            // the inserted gap is deliberately outside the source-copy domain.
            let caller_position = |offset| (capture.reference_size + offset) as i64;
            assert_eq!(
                mapped_position(&native_caller, caller_position(0x620)),
                0x420
            );
            assert_eq!(
                mapped_position(&native_caller, caller_position(0x1800)),
                0x1400
            );
            assert!(mapped_position(&native_caller, caller_position(0x400)) < 0);
            let decoded = crate::lzx::decompress_with_rift(
                &transformed,
                &parsed.patch_data,
                capture.target_size,
                Some(&caller),
            )
            .unwrap();
            assert_eq!(
                decoded,
                native_file(case, "decompressed-target.bin"),
                "{case}: copy-stage output"
            );
        }
    }

    fn table(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    fn mapped_position(table: &RiftTable, input: i64) -> i64 {
        let upper = table.entries.partition_point(|entry| entry.source <= input);
        let Some(entry) = upper
            .checked_sub(1)
            .and_then(|index| table.entries.get(index))
            .or_else(|| table.entries.last())
        else {
            return input;
        };
        input.wrapping_add(entry.target.wrapping_sub(entry.source))
    }

    fn source_index(table: &RiftTable, target_offset: usize, source_len: usize) -> Option<usize> {
        let mapped = mapped_position(table, i64::try_from(target_offset).ok()?);
        let index = usize::try_from(mapped).ok()?;
        (index < source_len).then_some(index)
    }

    #[test]
    fn composed_domains_resolve_moved_sections() {
        let source_layout =
            AddressMap::<SourceFileOffsets, SrcRva>::new(table(&[(0, 0), (0x200, 0x1000)]));
        let rvas = AddressMap::<SrcRva, TgtRva>::new(table(&[(0, 0), (0x1000, 0x3000)]));
        let target_layout =
            AddressMap::<TgtRva, TargetFileOffsets>::new(table(&[(0, 0), (0x3000, 0x400)]));
        let forward = source_layout.then(rvas).then(target_layout);
        assert_eq!(mapped_position(&forward.table, 0x220), 0x420);
        let reverse = forward.native_reverse();
        assert_eq!(source_index(&reverse.table, 0x420, 0x800), Some(0x220));
    }

    #[test]
    fn caller_origin_shift_does_not_clamp_out_of_domain_destinations() {
        let map = table(&[(0, -4), (8, 12)]);
        let folded = fold_target_to_source_rift_for_decompressor(16, &map);
        assert_eq!(mapped_position(&folded, 16), -4);
        assert_eq!(mapped_position(&folded, 20), 0);
        assert_eq!(mapped_position(&folded, 27), 15);
        assert_eq!(mapped_position(&folded, 28), 16);
    }

    #[test]
    fn caller_origin_composition_reduces_equal_displacement_anchors() {
        let unfolded = table(&[(0, 0), (0x200, 0x200), (0x400, 0x200)]);
        let folded = fold_target_to_source_rift_for_decompressor(0x1000, &unfolded);
        assert_eq!(mapped_position(&folded, 0x1420), 0x220);
        assert_eq!(folded, table(&[(0x1000, 0), (0x1400, 0x200)]));
    }
}
