//! Native AMD64 PE transform atoms.

use super::addr::{map_rva, SrcRva};
use super::atom::{AtomMeta, SourceCtx, Transform};
use super::parse::{DataDirectoryKind, PeInfo};
use crate::lzx::rift::RiftTable;
use crate::pe::structs::{read_u32, write_u32, RuntimeFunction};
use std::mem::size_of;

/// `PdataX64` (`g_transformsMap` mask `0x400`): remap the AMD64 `.pdata`
/// exception directory -- each `RUNTIME_FUNCTION`'s three RVAs and the first
/// flagged unwind-info handler slot -- from source to target address space.
pub(crate) struct PdataX64;

impl Transform for PdataX64 {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "PdataX64",
            layer: "x64",
            kind: "source_transform",
            file_types: "0x8,0x20",
            flag_mask: 0x400,
            native_reference: "TransformPdataX64::Run",
        }
    }

    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        transform_pdata_x64(ctx.buf, ctx.pe, ctx.rift);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PdataX64Stats {
    pub(crate) records_seen: usize,
    pub(crate) runtime_function_fields_seen: usize,
    pub(crate) runtime_function_fields_remapped: usize,
    pub(crate) unwind_info_slots_seen: usize,
    pub(crate) unwind_info_slots_remapped: usize,
    pub(crate) truncated_tail_bytes: usize,
}

/// Apply the AMD64 `.pdata` source transform through the PE exception directory.
///
/// The exception directory points at an array of 12-byte `RUNTIME_FUNCTION`
/// records. Each record contains three source-domain RVAs: `BeginAddress`,
/// `EndAddress`, and `UnwindData`. The transform maps each nonzero RVA through
/// the preprocess rift and writes the target-domain RVA back in place. If
/// `UnwindData` points outside `.pdata` to flagged unwind info, the first
/// 4-byte RVA slot after the unwind-code array is mapped before the
/// `UnwindData` field itself is rewritten.
pub(crate) fn transform_pdata_x64(
    image: &mut [u8],
    pe: &PeInfo,
    rift: &RiftTable,
) -> PdataX64Stats {
    let Some(pdata) = pe.data_directory(DataDirectoryKind::Exception) else {
        return PdataX64Stats::default();
    };
    if pdata.is_empty() {
        return PdataX64Stats::default();
    }
    let Some(pdata_file_offset) = pe.rva_to_file_offset(pdata.rva) else {
        return PdataX64Stats::default();
    };
    transform_pdata_x64_range_impl(
        image,
        pdata_file_offset,
        pdata.size as usize,
        rift,
        Some(pe),
    )
}

/// Apply the AMD64 `.pdata` source transform to a known file range.
pub(crate) fn transform_pdata_x64_range(
    image: &mut [u8],
    pdata_file_offset: usize,
    pdata_size: usize,
    rift: &RiftTable,
) -> PdataX64Stats {
    transform_pdata_x64_range_impl(image, pdata_file_offset, pdata_size, rift, None)
}

fn transform_pdata_x64_range_impl(
    image: &mut [u8],
    pdata_file_offset: usize,
    pdata_size: usize,
    rift: &RiftTable,
    pe: Option<&PeInfo>,
) -> PdataX64Stats {
    if rift.entries.is_empty() || pdata_file_offset == 0 || pdata_size == 0 {
        return PdataX64Stats::default();
    }

    let record_size = size_of::<RuntimeFunction>();
    let available_size = image.len().saturating_sub(pdata_file_offset);
    let clamped_size = pdata_size.min(available_size);
    let record_bytes = clamped_size - (clamped_size % record_size);
    let mut stats = PdataX64Stats {
        truncated_tail_bytes: pdata_size.saturating_sub(record_bytes),
        ..PdataX64Stats::default()
    };

    let end = pdata_file_offset + record_bytes;
    let mut offset = pdata_file_offset;
    while offset < end {
        stats.records_seen += 1;
        let unwind_rva = read_u32(image, offset + 8);
        if let Some(pe) = pe {
            transform_unwind_info_slot(
                image,
                pe,
                pdata_file_offset,
                pdata_size,
                unwind_rva,
                rift,
                &mut stats,
            );
        }
        for field_offset in [offset, offset + 4, offset + 8] {
            stats.runtime_function_fields_seen += 1;
            let rva = read_u32(image, field_offset);
            if rva == 0 {
                continue;
            }
            let target = map_rva(rift, SrcRva(rva));
            if target.0 != rva {
                write_u32(image, field_offset, target.0);
                stats.runtime_function_fields_remapped += 1;
            }
        }
        offset += record_size;
    }

    stats
}

fn transform_unwind_info_slot(
    image: &mut [u8],
    pe: &PeInfo,
    pdata_file_offset: usize,
    pdata_size: usize,
    unwind_rva: u32,
    rift: &RiftTable,
    stats: &mut PdataX64Stats,
) {
    let Some(unwind_info_offset) = unwind_info_file_offset(pe, unwind_rva) else {
        return;
    };
    if !unwind_info_is_outside_pdata(unwind_info_offset, pdata_file_offset, pdata_size) {
        return;
    }
    let Some(header_end) = unwind_info_offset.checked_add(4) else {
        return;
    };
    let Some(header) = image.get(unwind_info_offset..header_end) else {
        return;
    };
    let flags = header[0] & 0x38;
    if flags == 0 {
        return;
    }

    let code_count = header[2] as usize;
    let slot_delta = 4 + ((code_count + 1) >> 1) * 4;
    let Some(slot_offset) = unwind_info_offset.checked_add(slot_delta) else {
        return;
    };
    let Some(slot_end) = slot_offset.checked_add(4) else {
        return;
    };
    if slot_end > image.len() {
        return;
    }

    stats.unwind_info_slots_seen += 1;
    let rva = u32::from_le_bytes(image[slot_offset..slot_end].try_into().unwrap());
    if rva == 0 {
        return;
    }
    let target = map_rva(rift, SrcRva(rva));
    if target.0 != rva {
        image[slot_offset..slot_end].copy_from_slice(&target.0.to_le_bytes());
        stats.unwind_info_slots_remapped += 1;
    }
}

fn unwind_info_file_offset(pe: &PeInfo, unwind_rva: u32) -> Option<usize> {
    if unwind_rva == 0 {
        return None;
    }
    if pe
        .first_section_rva()
        .is_some_and(|first_section_rva| unwind_rva < first_section_rva)
    {
        return Some(unwind_rva as usize);
    }
    pe.rva_to_file_offset(unwind_rva)
}

fn unwind_info_is_outside_pdata(
    unwind_info_offset: usize,
    pdata_file_offset: usize,
    pdata_size: usize,
) -> bool {
    let pdata_end = pdata_file_offset.saturating_add(pdata_size);
    unwind_info_offset < pdata_file_offset || unwind_info_offset > pdata_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::RiftEntry;
    use crate::pe::parse::{PeMachine, SectionInfo};

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn read_u32(image: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap())
    }

    fn put_runtime_function(
        image: &mut [u8],
        offset: usize,
        begin: u32,
        end: u32,
        unwind_data: u32,
    ) {
        put_u32(image, offset, begin);
        put_u32(image, offset + 4, end);
        put_u32(image, offset + 8, unwind_data);
    }

    fn pdata_pe() -> PeInfo {
        PeInfo {
            image_base: 0x0000_0001_4000_0000,
            size_of_image: 0x5000,
            timestamp: 0,
            checksum: 0,
            is_64bit: true,
            machine: PeMachine::Amd64,
            sections: vec![SectionInfo {
                name: ".pdata".to_owned(),
                virtual_address: 0x3000,
                virtual_size: 0x40,
                raw_offset: 0x40,
                raw_size: 0x40,
                characteristics: 0x4000_0040,
            }],
            data_directories: vec![(0, 0); DataDirectoryKind::COUNT],
        }
    }

    #[test]
    fn pdata_x64_range_remaps_runtime_function_rvas() {
        let mut image = vec![0u8; 0x80];
        put_runtime_function(&mut image, 0x10, 0x1000, 0x1010, 0x2000);
        put_runtime_function(&mut image, 0x1c, 0, 0x3000, 0x3010);

        let stats = transform_pdata_x64_range(
            &mut image,
            0x10,
            0x18,
            &rift(&[(0x1000, 0x1100), (0x2000, 0x2200), (0x3000, 0x2f00)]),
        );

        assert_eq!(
            stats,
            PdataX64Stats {
                records_seen: 2,
                runtime_function_fields_seen: 6,
                runtime_function_fields_remapped: 5,
                unwind_info_slots_seen: 0,
                unwind_info_slots_remapped: 0,
                truncated_tail_bytes: 0,
            }
        );
        assert_eq!(read_u32(&image, 0x10), 0x1100);
        assert_eq!(read_u32(&image, 0x14), 0x1110);
        assert_eq!(read_u32(&image, 0x18), 0x2200);
        assert_eq!(read_u32(&image, 0x1c), 0);
        assert_eq!(read_u32(&image, 0x20), 0x2f00);
        assert_eq!(read_u32(&image, 0x24), 0x2f10);
    }

    #[test]
    fn pdata_x64_range_clamps_partial_tail_bytes() {
        let mut image = vec![0u8; 0x30];
        put_runtime_function(&mut image, 0x10, 0x1000, 0x1010, 0x1020);
        put_u32(&mut image, 0x1c, 0x2000);

        let stats = transform_pdata_x64_range(
            &mut image,
            0x10,
            0x11,
            &rift(&[(0x1000, 0x1100), (0x2000, 0x2100)]),
        );

        assert_eq!(
            stats,
            PdataX64Stats {
                records_seen: 1,
                runtime_function_fields_seen: 3,
                runtime_function_fields_remapped: 3,
                unwind_info_slots_seen: 0,
                unwind_info_slots_remapped: 0,
                truncated_tail_bytes: 5,
            }
        );
        assert_eq!(
            read_u32(&image, 0x1c),
            0x2000,
            "partial trailing records are not rewritten"
        );
    }

    #[test]
    fn pdata_x64_range_preserves_existing_empty_and_zero_offset_behavior() {
        let mut image = vec![0u8; 0x30];
        put_runtime_function(&mut image, 0x00, 0x1000, 0x1010, 0x1020);
        put_runtime_function(&mut image, 0x10, 0x1000, 0x1010, 0x1020);

        assert_eq!(
            transform_pdata_x64_range(&mut image, 0x10, 0x0c, &rift(&[])),
            PdataX64Stats::default()
        );
        assert_eq!(
            transform_pdata_x64_range(&mut image, 0, 0x0c, &rift(&[(0x1000, 0x1100)])),
            PdataX64Stats::default()
        );
        assert_eq!(read_u32(&image, 0x00), 0x1000);
        assert_eq!(read_u32(&image, 0x10), 0x1000);
    }

    #[test]
    fn pdata_x64_uses_exception_directory_range_from_pe() {
        let mut pe = pdata_pe();
        pe.data_directories[DataDirectoryKind::Exception.index()] = (0x3000, 0x0c);
        let mut image = vec![0u8; 0x100];
        put_runtime_function(&mut image, 0x40, 0x3000, 0x3010, 0x3020);

        let stats = transform_pdata_x64(&mut image, &pe, &rift(&[(0x3000, 0x3200)]));

        assert_eq!(stats.records_seen, 1);
        assert_eq!(stats.runtime_function_fields_remapped, 3);
        assert_eq!(read_u32(&image, 0x40), 0x3200);
        assert_eq!(read_u32(&image, 0x44), 0x3210);
        assert_eq!(read_u32(&image, 0x48), 0x3220);
    }

    #[test]
    fn pdata_x64_noops_without_exception_directory() {
        let pe = pdata_pe();
        let mut image = vec![0u8; 0x100];
        put_runtime_function(&mut image, 0x40, 0x3000, 0x3010, 0x3020);

        let stats = transform_pdata_x64(&mut image, &pe, &rift(&[(0x3000, 0x3200)]));

        assert_eq!(stats, PdataX64Stats::default());
        assert_eq!(read_u32(&image, 0x40), 0x3000);
    }

    #[test]
    fn pdata_x64_remaps_handler_slot_in_unwind_info_outside_pdata() {
        let mut pe = pdata_pe();
        pe.sections.push(SectionInfo {
            name: ".xdata".to_owned(),
            virtual_address: 0x4000,
            virtual_size: 0x40,
            raw_offset: 0x80,
            raw_size: 0x40,
            characteristics: 0x4000_0040,
        });
        pe.data_directories[DataDirectoryKind::Exception.index()] = (0x3000, 0x0c);
        let mut image = vec![0u8; 0x100];
        put_runtime_function(&mut image, 0x40, 0x3000, 0x3010, 0x4000);
        image[0x80] = 0x09;
        image[0x82] = 2;
        put_u32(&mut image, 0x88, 0x5000);

        let stats = transform_pdata_x64(
            &mut image,
            &pe,
            &rift(&[(0x3000, 0x3100), (0x4000, 0x4200), (0x5000, 0x5300)]),
        );

        assert_eq!(stats.records_seen, 1);
        assert_eq!(stats.runtime_function_fields_remapped, 3);
        assert_eq!(stats.unwind_info_slots_seen, 1);
        assert_eq!(stats.unwind_info_slots_remapped, 1);
        assert_eq!(read_u32(&image, 0x48), 0x4200);
        assert_eq!(read_u32(&image, 0x88), 0x5300);
    }

    #[test]
    fn pdata_x64_skips_unwind_info_slot_inside_pdata() {
        let mut pe = pdata_pe();
        pe.data_directories[DataDirectoryKind::Exception.index()] = (0x3000, 0x24);
        let mut image = vec![0u8; 0x100];
        put_runtime_function(&mut image, 0x40, 0x3000, 0x3010, 0x3018);
        image[0x58] = 0x09;
        image[0x5a] = 2;
        put_u32(&mut image, 0x60, 0);

        let stats = transform_pdata_x64(
            &mut image,
            &pe,
            &rift(&[(0x3000, 0x3100), (0x5000, 0x5300)]),
        );

        assert_eq!(stats.unwind_info_slots_seen, 0);
        assert_eq!(read_u32(&image, 0x60), 0);
    }
}
