use super::addr::{SrcRva, TgtRva};
use super::parse::{DataDirectoryKind, PeHeaderLayout, PeInfo, PeOptionalHeaderKind};
use super::structs::{
    self, ImageBaseRelocation, ImageOptionalHeader32, ImageOptionalHeader64, ImageSectionHeader,
};
use crate::lzx::rift::RiftTable;
use std::ops::Range;

const PAGE_MASK: u32 = 0xffff_f000;
const PAGE_OFFSET_MASK: u32 = 0xfff;
const BLOCK_HEADER_SIZE: usize = size_of::<ImageBaseRelocation>();

#[derive(Clone, Copy)]
struct SourceFileOffset(usize);

enum Operand {
    HalfWord,
    Pointer32,
    Pointer64,
}

#[derive(Clone, Copy)]
enum RelocationKind {
    High,
    Low,
    HighLow,
    HighAdj(u16),
    Dir64,
    Discarded,
}

impl RelocationKind {
    fn tag(self) -> u16 {
        match self {
            Self::High => 1,
            Self::Low => 2,
            Self::HighLow => 3,
            Self::HighAdj(_) => 4,
            Self::Dir64 => 10,
            Self::Discarded => 0,
        }
    }
}

struct TargetRelocation {
    location: TgtRva,
    kind: RelocationKind,
}

struct RelocationDirectory {
    readable: Range<usize>,
    writable: Range<usize>,
}

impl RelocationDirectory {
    fn from_pe(pe: &PeInfo, bytes: &[u8]) -> Option<Self> {
        let directory = pe.data_directory(DataDirectoryKind::BaseRelocation)?;
        if directory.rva == 0 {
            return None;
        }
        let layout = PeHeaderLayout::parse(bytes).ok()?;
        // Native directory resolution also accepts an unmapped RVA as a raw
        // file offset. This fallback belongs to directories, not block pages.
        let start = source_file_offset(bytes, layout, SrcRva(directory.rva))
            .map_or(directory.rva as usize, |offset| offset.0);
        if start >= bytes.len() {
            return None;
        }
        let readable_size = (directory.size as usize).min(bytes.len() - start);
        // Extra write capacity comes only from the first section whose full
        // eight-byte name matches native's ASCII bit-folded `.reloc` name.
        // A differently named section does not donate its raw padding.
        let extra_capacity = raw_sections(bytes, layout)
            .find(|section| section.name.map(|byte| byte | 0x20) == *b".reloc  ")
            .and_then(|section| {
                let raw_start = section.pointer_to_raw_data.get() as usize;
                let raw_end = raw_start.checked_add(section.size_of_raw_data.get() as usize)?;
                (raw_start..raw_end)
                    .contains(&start)
                    .then(|| raw_end - start)
            })
            .unwrap_or(0);
        let capacity = extra_capacity.max(readable_size).min(bytes.len() - start) & !1;
        Some(Self {
            readable: start..start + readable_size,
            writable: start..start + capacity,
        })
    }
}

fn raw_sections(
    bytes: &[u8],
    layout: PeHeaderLayout,
) -> impl Iterator<Item = ImageSectionHeader> + '_ {
    (0..layout.number_of_sections)
        .filter_map(move |index| structs::read(bytes, layout.section_header_offset(index)?))
}

fn source_file_offset(
    bytes: &[u8],
    layout: PeHeaderLayout,
    rva: SrcRva,
) -> Option<SourceFileOffset> {
    let header_size = match layout.optional_header_kind {
        PeOptionalHeaderKind::Pe32 => {
            structs::read::<ImageOptionalHeader32>(bytes, layout.optional_header_offset)?
                .size_of_headers
                .get()
        }
        PeOptionalHeaderKind::Pe32Plus => {
            structs::read::<ImageOptionalHeader64>(bytes, layout.optional_header_offset)?
                .size_of_headers
                .get()
        }
    } as usize;
    let offset = if (rva.0 as usize) < header_size.min(bytes.len()) {
        rva.0 as usize
    } else {
        raw_sections(bytes, layout).find_map(|section| {
            let start = section.virtual_address.get();
            let end = start.checked_add(section.size_of_raw_data.get())?;
            if !(start..end).contains(&rva.0) {
                return None;
            }
            section
                .pointer_to_raw_data
                .get()
                .checked_add(rva.0 - start)
                .map(|offset| offset as usize)
        })?
    };
    // Zero is native's unmapped sentinel, including a block page RVA of zero.
    (offset != 0).then_some(SourceFileOffset(offset))
}

// Relocation RVAs use unsigned 32-bit arithmetic, including rift deltas.
// The final rift entry supplies the wraparound interval before the first entry.
fn map_location(rift: &RiftTable, source: SrcRva) -> TgtRva {
    let upper = rift
        .entries
        .partition_point(|entry| entry.source <= i64::from(source.0));
    let entry = upper
        .checked_sub(1)
        .and_then(|index| rift.entries.get(index))
        .or_else(|| rift.entries.last());
    let displacement = entry.map_or(0, |entry| {
        (entry.target as u32).wrapping_sub(entry.source as u32)
    });
    TgtRva(source.0.wrapping_add(displacement))
}

fn rewrite_operand(
    bytes: &mut [u8],
    marker: &mut [u8],
    offset: SourceFileOffset,
    operand: Operand,
    pe: &PeInfo,
    rift: &RiftTable,
    target_base: u64,
) {
    let width = match operand {
        Operand::HalfWord => 2,
        Operand::Pointer32 => 4,
        Operand::Pointer64 => 8,
    };
    let Some(end) = offset.0.checked_add(width) else {
        return;
    };
    // Ownership is recorded only for a complete operand, never a partial one.
    if end > bytes.len() || end > marker.len() {
        return;
    }
    marker[offset.0..end].iter_mut().for_each(|byte| *byte |= 1);
    if matches!(operand, Operand::HalfWord) {
        return;
    }
    // Both HIGHLOW and DIR64 derive the RVA from the low 32 bits. DIR64
    // changes the width of the reconstructed VA, not the RVA address domain.
    let source = SrcRva(structs::read_u32(bytes, offset.0).wrapping_sub(pe.image_base as u32));
    let target = map_location(rift, source);
    let target_va = target_base.wrapping_add(u64::from(target.0));
    if width == 8 {
        structs::write_u64(bytes, offset.0, target_va);
    } else {
        structs::write_u32(bytes, offset.0, target_va as u32);
    }
}

pub(super) fn transform_source_relocs(
    bytes: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
    marker: &mut [u8],
    target_base: u64,
) {
    let Some(directory) = RelocationDirectory::from_pe(pe, bytes) else {
        return;
    };
    let Ok(layout) = PeHeaderLayout::parse(bytes) else {
        return;
    };
    let mut records = Vec::new();
    let mut block_offset = directory.readable.start;
    while block_offset + BLOCK_HEADER_SIZE <= directory.readable.end {
        let Some(block) = structs::read::<ImageBaseRelocation>(bytes, block_offset) else {
            break;
        };
        let block_size = block.size_of_block.get() as usize;
        if block_size < BLOCK_HEADER_SIZE || block_size > directory.readable.end - block_offset {
            break;
        }
        let page = SrcRva(block.page_rva.get());
        // Native resolves the page once, then adds each within-page offset.
        // It does not independently resolve each operand through section lookup.
        let page_offset = source_file_offset(bytes, layout, page);
        if let Some(page_offset) = page_offset {
            let end = block_offset + block_size;
            let mut cursor = block_offset + BLOCK_HEADER_SIZE;
            while cursor + 2 <= end {
                let encoded = structs::read_u16(bytes, cursor);
                cursor += 2;
                let tag = encoded >> 12;
                // This is MSDelta's normalization rule, not PE loader semantics.
                if tag == 0 {
                    break;
                }
                let within_page = u32::from(encoded) & PAGE_OFFSET_MASK;
                let location = SrcRva(page.0.wrapping_add(within_page));
                let operand =
                    SourceFileOffset((page_offset.0 as u32).wrapping_add(within_page) as usize);
                let kind = match tag {
                    1 => RelocationKind::High,
                    2 => RelocationKind::Low,
                    3 => RelocationKind::HighLow,
                    4 if cursor + 2 <= end => {
                        let extra = structs::read_u16(bytes, cursor);
                        cursor += 2;
                        RelocationKind::HighAdj(extra)
                    }
                    10 => RelocationKind::Dir64,
                    _ => RelocationKind::Discarded,
                };
                let encoding = match tag {
                    1 | 2 | 4 => Some(Operand::HalfWord),
                    3 => Some(Operand::Pointer32),
                    10 => Some(Operand::Pointer64),
                    _ => None,
                };
                if let Some(encoding) = encoding {
                    rewrite_operand(bytes, marker, operand, encoding, pe, rift, target_base);
                }
                records.push(TargetRelocation {
                    location: map_location(rift, location),
                    kind,
                });
            }
        }
        block_offset += block_size;
    }
    records.sort_by_key(|record| record.location.0);
    write_blocks(bytes, directory.writable, &records);
}

fn write_blocks(bytes: &mut [u8], writable: Range<usize>, records: &[TargetRelocation]) {
    let mut output = writable.start;
    let mut index = 0;
    while output + BLOCK_HEADER_SIZE <= writable.end && index < records.len() {
        let page = records[index].location.0 & PAGE_MASK;
        let header = output;
        output += BLOCK_HEADER_SIZE;
        let body_start = output;
        while output + 2 <= writable.end
            && index < records.len()
            && records[index].location.0 & PAGE_MASK == page
        {
            let record = &records[index];
            structs::write_u16(
                bytes,
                output,
                record.kind.tag() << 12 | (record.location.0 & PAGE_OFFSET_MASK) as u16,
            );
            output += 2;
            if let RelocationKind::HighAdj(extra) = record.kind {
                if output + 2 <= writable.end {
                    structs::write_u16(bytes, output, extra);
                    output += 2;
                }
            }
            index += 1;
        }
        if (output - body_start) % 4 != 0 && output + 2 <= writable.end {
            structs::write_u16(bytes, output, 0);
            output += 2;
        }
        if let Some(block) = structs::view_mut::<ImageBaseRelocation>(bytes, header) {
            block.page_rva.set(page);
            block.size_of_block.set((output - header) as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::RiftEntry;
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    const CASES: &[&str] = &[
        "x86",
        "x64",
        "x64-external",
        "x86-mixed",
        "x86-missing-highadj",
        "x86-padding",
        "x86-unmapped-page",
        "x86-short-operand",
        "x86-short-block",
        "x86-oversized-block",
        "x86-duplicate",
        "x86-renamed",
        "x86-raw-directory",
        "x86-header-page",
        "x86-name-suffix",
        "x86-name-spaces",
        "x86-regroup",
        "x86-regroup-tight",
        "x86-executable",
        "x86-short-operand-executable",
    ];

    #[derive(Deserialize)]
    struct Capture {
        schema: u32,
        dll_sha256: String,
        harness_sha256: String,
        delta_origin: String,
        observation_scope: String,
        artifact_sha256: BTreeMap<String, String>,
        transform_rva: u32,
        source_sha256: String,
        delta_sha256: String,
        target_sha256: String,
        target_base: u64,
        directory_offset: usize,
        directory_size: usize,
        directory_capacity: usize,
        rift_count: usize,
        used_count: usize,
        uninstrumented_output_equal: bool,
    }

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/atoms/RelocationsNative")
    }

    fn read(case: &str, name: &str) -> Vec<u8> {
        std::fs::read(root().join(case).join(name)).unwrap()
    }

    fn assert_bytes(case: &str, actual: &[u8], expected: &[u8]) {
        let differences: Vec<_> = actual
            .iter()
            .zip(expected)
            .enumerate()
            .filter(|(_, (actual, expected))| actual != expected)
            .map(|(offset, (actual, expected))| {
                format!("{offset:#x}: {actual:02x} != {expected:02x}")
            })
            .take(12)
            .collect();
        assert!(
            actual == expected,
            "{case}: lengths {} / {}; {}",
            actual.len(),
            expected.len(),
            differences.join(", ")
        );
    }

    #[test]
    fn relocation_stage_matches_native_captures() {
        for case in CASES {
            let metadata: Capture = serde_json::from_slice(&read(case, "capture.json")).unwrap();
            assert_eq!(metadata.schema, 1);
            assert_eq!(
                metadata.dll_sha256,
                "ac96e0c3bfd052c3391a49e5fe4586969fb032a920b9f564dadffd8b5f4358eb"
            );
            assert_eq!(metadata.transform_rva, 0x25a40);
            assert!(metadata.uninstrumented_output_equal);
            assert_eq!(metadata.harness_sha256.len(), 64);
            assert_eq!(metadata.delta_origin, "native CreateDeltaB");
            assert_eq!(metadata.observation_scope, "synchronous caller thread");
            assert_eq!(metadata.artifact_sha256.len(), 7);
            for name in [
                "before.bin",
                "after.bin",
                "marker-before.bin",
                "marker-after.bin",
                "rift.bin",
                "used-before.bin",
                "used-after.bin",
            ] {
                let actual: String = Sha256::digest(read(case, name))
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(actual, metadata.artifact_sha256[name], "{case}/{name}");
            }
            for (name, expected) in [
                ("base.bin", metadata.source_sha256),
                ("native.pa30", metadata.delta_sha256),
                ("target.bin", metadata.target_sha256),
            ] {
                let actual: String = Sha256::digest(read(case, name))
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                assert_eq!(actual, expected, "{case}/{name}");
            }
            let mut bytes = read(case, "before.bin");
            let pe = PeInfo::parse_lenient(&bytes).unwrap();
            let directory = RelocationDirectory::from_pe(&pe, &bytes).unwrap();
            assert_eq!(
                directory.readable,
                metadata.directory_offset..metadata.directory_offset + metadata.directory_size
            );
            assert_eq!(directory.writable.len(), metadata.directory_capacity);
            let mut marker = read(case, "marker-before.bin");
            assert_eq!(marker.len(), bytes.len());
            let encoded_rift = read(case, "rift.bin");
            assert_eq!(encoded_rift.len(), metadata.rift_count * 16);
            // Apply captures have no caller-provided map-usage bitmap. These
            // fixtures establish buffer/marker behavior, not create-side tracking.
            assert_eq!(metadata.used_count, 0);
            assert!(read(case, "used-before.bin").is_empty());
            assert!(read(case, "used-after.bin").is_empty());
            let rift = RiftTable {
                entries: encoded_rift
                    .chunks_exact(16)
                    .map(|pair| RiftEntry {
                        source: i64::from_le_bytes(pair[..8].try_into().unwrap()),
                        target: i64::from_le_bytes(pair[8..].try_into().unwrap()),
                    })
                    .collect(),
            };
            transform_source_relocs(&mut bytes, &pe, &rift, &mut marker, metadata.target_base);
            assert_bytes(case, &bytes, &read(case, "after.bin"));
            assert_bytes(case, &marker, &read(case, "marker-after.bin"));
        }
    }

    #[test]
    fn native_relocation_deltas_decode_to_the_original_targets() {
        for case in CASES {
            let target = crate::pa30::apply(&read(case, "base.bin"), &read(case, "native.pa30"))
                .unwrap_or_else(|error| panic!("{case}: {error}"));
            assert_bytes(case, &target, &read(case, "target.bin"));
        }
    }

    #[test]
    fn native_captures_explain_pointer_and_directory_domains() {
        let before = read("x86", "before.bin");
        let after = read("x86", "after.bin");
        // .data moves from source RVA 0x2000 to target RVA 0x3000. The
        // operand stays at source file offset 0x420 while its VA changes.
        assert_eq!(structs::read_u32(&before, 0x420), 0x8000_2100);
        assert_eq!(structs::read_u32(&after, 0x420), 0x8000_3100);
        assert_eq!(structs::read_u32(&before, 0x1400), 0x2000);
        assert_eq!(structs::read_u32(&after, 0x1400), 0x3000);
        assert_eq!(structs::read_u16(&after, 0x1408), 0x3020);

        let before = read("x64-external", "before.bin");
        let after = read("x64-external", "after.bin");
        assert_eq!(structs::read_u64(&before, 0x420), 0x101_4000_2100);
        assert_eq!(structs::read_u64(&after, 0x420), 0x2_4000_3100);

        let after = read("x86-missing-highadj", "after.bin");
        assert_eq!(structs::read_u16(&after, 0x1408), 0x0020);
        let marker = read("x86-missing-highadj", "marker-after.bin");
        assert_eq!(&marker[0x420..0x422], &[1, 1]);

        let before = read("x86-executable", "marker-before.bin");
        let after = read("x86-executable", "marker-after.bin");
        assert_eq!(&before[0x420..0x424], &[0; 4]);
        assert_eq!(&after[0x420..0x424], &[1; 4]);
        let before = read("x86-short-operand-executable", "marker-before.bin");
        let after = read("x86-short-operand-executable", "marker-after.bin");
        assert_eq!(before[0x15ff], 0);
        assert_eq!(after[0x15ff], 0);

        // A 0x1100 RVA shift moves the final two entries onto another page.
        // The source directory grows from 16 to 24 bytes using raw padding.
        let after = read("x86-regroup", "after.bin");
        assert_eq!(structs::read_u32(&after, 0x1400), 0x3000);
        assert_eq!(structs::read_u32(&after, 0x1404), 12);
        assert_eq!(structs::read_u32(&after, 0x140c), 0x4000);
        assert_eq!(structs::read_u32(&after, 0x1410), 12);
        // The identical directory in .fixups has only its declared 16-byte
        // capacity. A second header cannot fit; the remaining source tail stays.
        let before = read("x86-regroup-tight", "before.bin");
        let after = read("x86-regroup-tight", "after.bin");
        assert_eq!(structs::read_u32(&after, 0x1404), 12);
        assert_eq!(&before[0x140c..], &after[0x140c..]);
    }
}
