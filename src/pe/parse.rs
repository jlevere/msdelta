//! Minimal PE parser extracting the fields needed for MSDelta transforms.

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
        let rd16 = |o: usize| -> u16 {
            data.get(o..o + 2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0)
        };
        let rd32 = |o: usize| -> u32 {
            data.get(o..o + 4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0)
        };
        let rd64 = |o: usize| -> u64 {
            data.get(o..o + 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                .unwrap_or(0)
        };

        if data.len() < 0x40 {
            return Err(Error::Malformed("PE: too small"));
        }
        let e = rd32(0x3c) as usize;
        if data.get(e..e + 4) != Some(b"PE\0\0") {
            return Err(Error::Malformed("PE: bad signature"));
        }
        let num_sections = rd16(e + 6) as usize;
        let size_of_opt = rd16(e + 20) as usize;
        let timestamp = rd32(e + 8);
        let opt = e + 24;
        let magic = rd16(opt);
        let is_64bit = magic == 0x20b;
        if magic != 0x10b && magic != 0x20b {
            return Err(Error::Malformed("PE: bad optional magic"));
        }
        // PE32: ImageBase u32 @ opt+28, NumberOfRvaAndSizes @ opt+92, dirs @ opt+96.
        // PE32+: ImageBase u64 @ opt+24, NumberOfRvaAndSizes @ opt+108, dirs @ opt+112.
        let (image_base, size_of_image, check_sum, num_rva, dir_base) = if is_64bit {
            (
                rd64(opt + 24),
                rd32(opt + 56),
                rd32(opt + 64),
                rd32(opt + 108),
                opt + 112,
            )
        } else {
            (
                rd32(opt + 28) as u64,
                rd32(opt + 56),
                rd32(opt + 64),
                rd32(opt + 92),
                opt + 96,
            )
        };

        let mut data_directories = vec![(0u32, 0u32); 16];
        for (i, slot) in data_directories
            .iter_mut()
            .enumerate()
            .take((num_rva as usize).min(16))
        {
            let d = dir_base + i * 8;
            *slot = (rd32(d), rd32(d + 4));
        }

        let sec_base = opt + size_of_opt;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_base + i * 40;
            if s + 40 > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(
                &data[s..s + 8][..data[s..s + 8].iter().position(|&b| b == 0).unwrap_or(8)],
            )
            .to_string();
            sections.push(SectionInfo {
                name,
                virtual_size: rd32(s + 8),
                virtual_address: rd32(s + 12),
                raw_size: rd32(s + 16),
                raw_offset: rd32(s + 20),
                characteristics: rd32(s + 36),
            });
        }

        Ok(PeInfo {
            image_base,
            size_of_image,
            timestamp,
            checksum: check_sum,
            is_64bit,
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
