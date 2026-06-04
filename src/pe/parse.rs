//! Minimal PE parser extracting the fields needed for MSDelta transforms.

use crate::pe::structs::PeView;
use crate::{Error, Result};

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

    /// Check if a virtual address falls within this PE's image range.
    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.image_base && va < self.image_base + self.size_of_image as u64
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
}
