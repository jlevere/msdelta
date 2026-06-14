//! Minimal PE parser extracting the fields needed for MSDelta transforms.

use crate::pe::structs::PeView;
use crate::{Error, Result};
use std::ops::Range;

/// Parsed PE metadata needed for delta transforms.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub image_base: u64,
    pub size_of_image: u32,
    pub timestamp: u32,
    /// Optional-header CheckSum field. msdelta's PE transform zeroes this in the
    /// patch domain and restores it from the preprocess on apply.
    pub checksum: u32,
    pub is_64bit: bool,
    pub sections: Vec<SectionInfo>,
    pub data_directories: Vec<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl SectionInfo {
    /// Logical RVA span used by msdelta section mapping.
    ///
    /// Native PE transforms commonly accept RVAs up to
    /// `max(VirtualSize, SizeOfRawData)` from the section start. The resulting
    /// file offset can point into raw padding; callers still need to bounds
    /// check against the actual file buffer before reading.
    pub fn logical_rva_size(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }

    pub fn rva_range(&self) -> Option<Range<u32>> {
        let size = self.logical_rva_size();
        if size == 0 {
            return None;
        }
        let end = self.virtual_address.checked_add(size)?;
        Some(self.virtual_address..end)
    }

    pub fn raw_range(&self) -> Option<Range<usize>> {
        if self.raw_size == 0 {
            return None;
        }
        let start = self.raw_offset as usize;
        let end = start.checked_add(self.raw_size as usize)?;
        Some(start..end)
    }

    pub fn clipped_raw_range(&self, file_len: usize) -> Option<Range<usize>> {
        let range = self.raw_range()?;
        let start = range.start.min(file_len);
        let end = range.end.min(file_len);
        (start < end).then_some(start..end)
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        self.rva_range().is_some_and(|range| range.contains(&rva))
    }

    pub fn contains_file_offset(&self, offset: usize) -> bool {
        self.raw_range()
            .is_some_and(|range| range.contains(&offset))
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        if self.raw_size == 0 || !self.contains_rva(rva) {
            return None;
        }
        let delta = rva.checked_sub(self.virtual_address)?;
        let offset = self.raw_offset.checked_add(delta)?;
        Some(offset as usize)
    }

    pub fn file_offset_to_rva(&self, offset: usize) -> Option<u32> {
        let range = self.raw_range()?;
        if !range.contains(&offset) {
            return None;
        }
        let delta = u32::try_from(offset - range.start).ok()?;
        self.virtual_address.checked_add(delta)
    }
}

impl PeInfo {
    /// Parse PE headers from a byte buffer.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let pe = goblin::pe::PE::parse(data).map_err(|_| Error::Malformed("invalid PE"))?;

        let header = &pe.header;
        let opt = header
            .optional_header
            .ok_or(Error::Malformed("PE: no optional header"))?;

        let is_64bit = opt.standard_fields.magic == goblin::pe::optional_header::MAGIC_64;
        let image_base = opt.windows_fields.image_base;
        let size_of_image = opt.windows_fields.size_of_image;
        let timestamp = header.coff_header.time_date_stamp;
        let checksum = opt.windows_fields.check_sum;

        let mut data_directories = vec![(0u32, 0u32); 16];
        for (dtype, dd) in opt.data_directories.dirs() {
            let idx = dtype as usize;
            if idx < 16 {
                data_directories[idx] = (dd.virtual_address, dd.size);
            }
        }

        let sections = pe
            .sections
            .iter()
            .map(|s| {
                let name = String::from_utf8_lossy(
                    &s.name[..s.name.iter().position(|&b| b == 0).unwrap_or(8)],
                )
                .to_string();
                SectionInfo {
                    name,
                    virtual_address: s.virtual_address,
                    virtual_size: s.virtual_size,
                    raw_offset: s.pointer_to_raw_data,
                    raw_size: s.size_of_raw_data,
                    characteristics: s.characteristics,
                }
            })
            .collect();

        Ok(PeInfo {
            image_base,
            size_of_image,
            timestamp,
            checksum,
            is_64bit,
            sections,
            data_directories,
        })
    }

    /// Parse PE headers by hand, without goblin's strict validation.
    ///
    /// goblin rejects some otherwise-valid system images (e.g. comctl32) that
    /// the i386 transform pass must still process; this reads only the fields
    /// the transforms need (image base, size, sections, data directories) by
    /// walking the headers directly. Supports PE32 and PE32+.
    pub fn parse_lenient(data: &[u8]) -> Result<Self> {
        let pe = PeView::parse(data).ok_or(Error::Malformed("PE: bad headers"))?;

        let data_directories = (0..16)
            .map(|i| {
                pe.data_directory(i)
                    .map(|d| (d.virtual_address.get(), d.size.get()))
                    .unwrap_or((0, 0))
            })
            .collect();

        let sections = pe
            .sections()
            .map(|s| {
                let len = s.name.iter().position(|&b| b == 0).unwrap_or(8);
                SectionInfo {
                    name: String::from_utf8_lossy(&s.name[..len]).into_owned(),
                    virtual_size: s.virtual_size.get(),
                    virtual_address: s.virtual_address.get(),
                    raw_size: s.size_of_raw_data.get(),
                    raw_offset: s.pointer_to_raw_data.get(),
                    characteristics: s.characteristics.get(),
                }
            })
            .collect();

        Ok(PeInfo {
            image_base: pe.image_base(),
            size_of_image: pe.size_of_image(),
            timestamp: pe.timestamp(),
            checksum: pe.check_sum(),
            is_64bit: pe.is_64bit(),
            sections,
            data_directories,
        })
    }

    /// The `(VirtualAddress, Size)` of data directory `idx` (see
    /// [`crate::pe::structs::dir`]) if it is present *and* non-empty (RVA != 0).
    /// Returns `None` for an absent or zero-RVA directory -- the "is this
    /// directory actually here?" gate every transform applies before mapping it.
    pub fn data_dir(&self, idx: usize) -> Option<(u32, u32)> {
        self.data_directories.get(idx).copied().filter(|v| v.0 != 0)
    }

    /// Check if a virtual address falls within this PE's image range.
    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.image_base && va < self.image_base + self.size_of_image as u64
    }

    pub fn first_section_rva(&self) -> Option<u32> {
        self.sections
            .iter()
            .filter_map(|section| section.rva_range().map(|range| range.start))
            .min()
    }

    pub fn section_containing_rva(&self, rva: u32) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|section| section.contains_rva(rva))
    }

    pub fn section_containing_file_offset(&self, offset: usize) -> Option<&SectionInfo> {
        self.sections
            .iter()
            .find(|section| section.contains_file_offset(offset))
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        self.section_containing_rva(rva)?.rva_to_file_offset(rva)
    }

    pub fn file_offset_to_rva(&self, offset: usize) -> Option<u32> {
        self.section_containing_file_offset(offset)?
            .file_offset_to_rva(offset)
    }

    pub fn same_file_section(&self, a: usize, b: usize) -> bool {
        self.section_containing_file_offset(a)
            .is_some_and(|section| section.contains_file_offset(b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_pe() {
        // A minimal PE that goblin can parse isn't easy to construct.
        // Test with an actual PE if available.
        let pe_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../reference/msdelta.dll");
        if let Ok(data) = std::fs::read(pe_path) {
            let info = PeInfo::parse(&data).unwrap();
            assert!(info.image_base > 0);
            assert!(info.size_of_image > 0);
            assert!(!info.sections.is_empty());
            assert!(info.is_64bit);
        }
    }

    fn section(name: &str, rva: u32, virtual_size: u32, raw: u32, raw_size: u32) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_address: rva,
            virtual_size,
            raw_offset: raw,
            raw_size,
            characteristics: 0,
        }
    }

    fn pe_with_sections(sections: Vec<SectionInfo>) -> PeInfo {
        PeInfo {
            image_base: 0x140000000,
            size_of_image: 0x9000,
            timestamp: 0,
            checksum: 0,
            is_64bit: true,
            sections,
            data_directories: vec![],
        }
    }

    #[test]
    fn section_maps_rva_through_logical_span() {
        let text = section(".text", 0x1000, 0x180, 0x400, 0x200);

        assert_eq!(text.logical_rva_size(), 0x200);
        assert_eq!(text.rva_range(), Some(0x1000..0x1200));
        assert_eq!(text.raw_range(), Some(0x400..0x600));
        assert_eq!(text.rva_to_file_offset(0x1000), Some(0x400));
        assert_eq!(text.rva_to_file_offset(0x11ff), Some(0x5ff));
        assert_eq!(text.rva_to_file_offset(0x1200), None);
        assert_eq!(text.file_offset_to_rva(0x400), Some(0x1000));
        assert_eq!(text.file_offset_to_rva(0x5ff), Some(0x11ff));
        assert_eq!(text.file_offset_to_rva(0x600), None);
    }

    #[test]
    fn section_maps_raw_padding_when_virtual_size_is_smaller() {
        let rdata = section(".rdata", 0x2000, 0x180, 0x800, 0x200);

        assert!(rdata.contains_rva(0x21ff));
        assert_eq!(rdata.rva_to_file_offset(0x21ff), Some(0x9ff));
        assert_eq!(rdata.rva_to_file_offset(0x2200), None);
    }

    #[test]
    fn zero_raw_section_has_rva_span_but_no_file_mapping() {
        let bss = section(".bss", 0x3000, 0x100, 0, 0);

        assert!(bss.contains_rva(0x3000));
        assert_eq!(bss.raw_range(), None);
        assert_eq!(bss.rva_to_file_offset(0x3000), None);
        assert_eq!(bss.file_offset_to_rva(0), None);
    }

    #[test]
    fn pe_section_lookup_preserves_address_domains() {
        let pe = pe_with_sections(vec![
            section(".text", 0x1000, 0x200, 0x400, 0x200),
            section(".rdata", 0x3000, 0x100, 0x800, 0x200),
        ]);

        assert_eq!(pe.first_section_rva(), Some(0x1000));
        assert_eq!(pe.rva_to_file_offset(0x3050), Some(0x850));
        assert_eq!(pe.file_offset_to_rva(0x850), Some(0x3050));
        assert_eq!(pe.section_containing_rva(0x3050).unwrap().name, ".rdata");
        assert_eq!(
            pe.section_containing_file_offset(0x450).unwrap().name,
            ".text"
        );
        assert!(pe.same_file_section(0x400, 0x5ff));
        assert!(!pe.same_file_section(0x400, 0x800));
    }

    #[test]
    fn clipped_raw_range_bounds_sections_to_file_length() {
        let text = section(".text", 0x1000, 0x200, 0x400, 0x200);

        assert_eq!(text.clipped_raw_range(0x1000), Some(0x400..0x600));
        assert_eq!(text.clipped_raw_range(0x500), Some(0x400..0x500));
        assert_eq!(text.clipped_raw_range(0x300), None);
    }
}
