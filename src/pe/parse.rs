//! Minimal PE parser extracting the fields needed for MSDelta transforms.

use crate::pe::structs::PeView;
use crate::{Error, Result};
use std::ops::Range;

const DOS_E_LFANEW_OFFSET: usize = 0x3c;
const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE_SIGNATURE_SIZE: usize = 4;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;

fn read_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    data.get(offset..end)?.try_into().ok()
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(read_array(data, offset)?))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(read_array(data, offset)?))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(read_array(data, offset)?))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeMachine {
    I386,
    Ia64,
    Amd64,
    ArmNt,
    Arm64,
    Unknown(u16),
}

impl PeMachine {
    pub const I386_RAW: u16 = 0x014c;
    pub const IA64_RAW: u16 = 0x0200;
    pub const AMD64_RAW: u16 = 0x8664;
    pub const ARMNT_RAW: u16 = 0x01c4;
    pub const ARM64_RAW: u16 = 0xaa64;

    pub const fn from_raw(raw: u16) -> Self {
        match raw {
            Self::I386_RAW => Self::I386,
            Self::IA64_RAW => Self::Ia64,
            Self::AMD64_RAW => Self::Amd64,
            Self::ARMNT_RAW => Self::ArmNt,
            Self::ARM64_RAW => Self::Arm64,
            value => Self::Unknown(value),
        }
    }

    pub const fn raw(self) -> u16 {
        match self {
            Self::I386 => Self::I386_RAW,
            Self::Ia64 => Self::IA64_RAW,
            Self::Amd64 => Self::AMD64_RAW,
            Self::ArmNt => Self::ARMNT_RAW,
            Self::Arm64 => Self::ARM64_RAW,
            Self::Unknown(value) => value,
        }
    }

    pub const fn classic_msdelta_file_type(self) -> Option<i64> {
        match self {
            Self::I386 => Some(0x2),
            Self::Ia64 => Some(0x4),
            Self::Amd64 => Some(0x8),
            _ => None,
        }
    }

    pub const fn cli4_msdelta_file_type(self) -> Option<i64> {
        match self {
            Self::I386 => Some(0x10),
            Self::Amd64 => Some(0x20),
            Self::ArmNt => Some(0x40),
            Self::Arm64 => Some(0x80),
            _ => None,
        }
    }

    pub const fn supported_create_file_type(self) -> Option<i64> {
        match self {
            Self::I386 | Self::Amd64 => self.classic_msdelta_file_type(),
            _ => None,
        }
    }
}

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
    pub machine: PeMachine,
    pub sections: Vec<SectionInfo>,
    pub data_directories: Vec<(u32, u32)>,
}

/// One PE optional-header data-directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeDataDirectory {
    pub rva: u32,
    pub size: u32,
}

impl PeDataDirectory {
    /// MSDelta transform helpers treat either zero component as absent for
    /// directory-to-directory rift generation.
    pub fn is_empty(self) -> bool {
        self.rva == 0 || self.size == 0
    }
}

/// Named PE optional-header data-directory slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DataDirectoryKind {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Certificate = 4,
    BaseRelocation = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPointer = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    ImportAddressTable = 12,
    DelayImport = 13,
    ClrRuntimeHeader = 14,
    Reserved = 15,
}

impl DataDirectoryKind {
    pub const COUNT: usize = 16;

    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Export),
            1 => Some(Self::Import),
            2 => Some(Self::Resource),
            3 => Some(Self::Exception),
            4 => Some(Self::Certificate),
            5 => Some(Self::BaseRelocation),
            6 => Some(Self::Debug),
            7 => Some(Self::Architecture),
            8 => Some(Self::GlobalPointer),
            9 => Some(Self::Tls),
            10 => Some(Self::LoadConfig),
            11 => Some(Self::BoundImport),
            12 => Some(Self::ImportAddressTable),
            13 => Some(Self::DelayImport),
            14 => Some(Self::ClrRuntimeHeader),
            15 => Some(Self::Reserved),
            _ => None,
        }
    }

    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeOptionalHeaderKind {
    Pe32,
    Pe32Plus,
}

impl PeOptionalHeaderKind {
    pub const PE32_MAGIC: u16 = 0x010b;
    pub const PE32_PLUS_MAGIC: u16 = 0x020b;

    pub const fn from_magic(magic: u16) -> Option<Self> {
        match magic {
            Self::PE32_MAGIC => Some(Self::Pe32),
            Self::PE32_PLUS_MAGIC => Some(Self::Pe32Plus),
            _ => None,
        }
    }

    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::Pe32Plus)
    }

    pub const fn image_base_relative_offset(self) -> usize {
        match self {
            Self::Pe32 => 0x1c,
            Self::Pe32Plus => 0x18,
        }
    }

    pub const fn image_base_width(self) -> usize {
        match self {
            Self::Pe32 => 4,
            Self::Pe32Plus => 8,
        }
    }

    pub const fn size_of_image_relative_offset(self) -> usize {
        0x38
    }

    pub const fn checksum_relative_offset(self) -> usize {
        0x40
    }

    pub const fn number_of_rva_and_sizes_relative_offset(self) -> usize {
        match self {
            Self::Pe32 => 0x5c,
            Self::Pe32Plus => 0x6c,
        }
    }

    pub const fn data_directories_relative_offset(self) -> usize {
        match self {
            Self::Pe32 => 0x60,
            Self::Pe32Plus => 0x70,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeHeaderLayout {
    pub nt_headers_offset: usize,
    pub file_header_offset: usize,
    pub optional_header_offset: usize,
    pub optional_header_size: usize,
    pub optional_header_kind: PeOptionalHeaderKind,
    pub machine: PeMachine,
    pub number_of_sections: usize,
    pub number_of_rva_and_sizes: usize,
}

impl PeHeaderLayout {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DOS_E_LFANEW_OFFSET + 4 {
            return Err(Error::Malformed("PE: too small"));
        }
        let nt_headers_offset = read_u32(data, DOS_E_LFANEW_OFFSET)
            .ok_or(Error::Malformed("PE: missing e_lfanew"))?
            as usize;
        if data.get(nt_headers_offset..nt_headers_offset + PE_SIGNATURE_SIZE) != Some(PE_SIGNATURE)
        {
            return Err(Error::Malformed("PE: bad signature"));
        }

        let file_header_offset = nt_headers_offset
            .checked_add(PE_SIGNATURE_SIZE)
            .ok_or(Error::Malformed("PE: header offset overflow"))?;
        let optional_header_offset = file_header_offset
            .checked_add(COFF_HEADER_SIZE)
            .ok_or(Error::Malformed("PE: header offset overflow"))?;
        if data
            .get(file_header_offset..optional_header_offset)
            .is_none()
        {
            return Err(Error::Malformed("PE: truncated COFF header"));
        }

        let machine = read_u16(data, file_header_offset)
            .map(PeMachine::from_raw)
            .ok_or(Error::Malformed("PE: missing machine"))?;
        let number_of_sections = read_u16(data, file_header_offset + 2)
            .ok_or(Error::Malformed("PE: missing section count"))?
            as usize;
        let optional_header_size = read_u16(data, file_header_offset + 16)
            .ok_or(Error::Malformed("PE: missing optional-header size"))?
            as usize;
        let magic = read_u16(data, optional_header_offset)
            .ok_or(Error::Malformed("PE: missing optional header"))?;
        let optional_header_kind = PeOptionalHeaderKind::from_magic(magic)
            .ok_or(Error::Malformed("PE: bad optional magic"))?;
        let number_of_rva_and_sizes_offset = optional_header_offset
            .checked_add(optional_header_kind.number_of_rva_and_sizes_relative_offset())
            .ok_or(Error::Malformed("PE: header offset overflow"))?;
        let number_of_rva_and_sizes = read_u32(data, number_of_rva_and_sizes_offset)
            .ok_or(Error::Malformed("PE: missing data-directory count"))?
            as usize;

        Ok(Self {
            nt_headers_offset,
            file_header_offset,
            optional_header_offset,
            optional_header_size,
            optional_header_kind,
            machine,
            number_of_sections,
            number_of_rva_and_sizes,
        })
    }

    pub const fn is_64bit(self) -> bool {
        self.optional_header_kind.is_64bit()
    }

    pub fn timestamp_offset(self) -> Option<usize> {
        self.file_header_offset.checked_add(4)
    }

    pub fn image_base_offset(self) -> Option<usize> {
        self.optional_header_offset
            .checked_add(self.optional_header_kind.image_base_relative_offset())
    }

    pub const fn image_base_width(self) -> usize {
        self.optional_header_kind.image_base_width()
    }

    pub fn size_of_image_offset(self) -> Option<usize> {
        self.optional_header_offset
            .checked_add(self.optional_header_kind.size_of_image_relative_offset())
    }

    pub fn checksum_offset(self) -> Option<usize> {
        self.optional_header_offset
            .checked_add(self.optional_header_kind.checksum_relative_offset())
    }

    pub fn number_of_rva_and_sizes_offset(self) -> Option<usize> {
        self.optional_header_offset.checked_add(
            self.optional_header_kind
                .number_of_rva_and_sizes_relative_offset(),
        )
    }

    pub fn data_directories_offset(self) -> Option<usize> {
        self.optional_header_offset
            .checked_add(self.optional_header_kind.data_directories_relative_offset())
    }

    pub fn data_directory_offset(self, kind: DataDirectoryKind) -> Option<usize> {
        if self.number_of_rva_and_sizes <= kind.index() {
            return None;
        }
        self.data_directories_offset()?
            .checked_add(kind.index().checked_mul(8)?)
    }

    pub fn data_directory(self, data: &[u8], kind: DataDirectoryKind) -> Option<PeDataDirectory> {
        let offset = self.data_directory_offset(kind)?;
        Some(PeDataDirectory {
            rva: read_u32(data, offset)?,
            size: read_u32(data, offset + 4)?,
        })
    }

    pub fn section_table_offset(self) -> Option<usize> {
        self.optional_header_offset
            .checked_add(self.optional_header_size)
    }

    pub fn section_header_offset(self, index: usize) -> Option<usize> {
        if index >= self.number_of_sections {
            return None;
        }
        self.section_table_offset()?
            .checked_add(index.checked_mul(SECTION_HEADER_SIZE)?)
    }

    pub fn section(self, data: &[u8], index: usize) -> Option<SectionInfo> {
        let offset = self.section_header_offset(index)?;
        let end = offset.checked_add(SECTION_HEADER_SIZE)?;
        let bytes = data.get(offset..end)?;
        let name_len = bytes[..8].iter().position(|&b| b == 0).unwrap_or(8);
        Some(SectionInfo {
            name: String::from_utf8_lossy(&bytes[..name_len]).to_string(),
            virtual_size: read_u32(data, offset + 8)?,
            virtual_address: read_u32(data, offset + 12)?,
            raw_size: read_u32(data, offset + 16)?,
            raw_offset: read_u32(data, offset + 20)?,
            characteristics: read_u32(data, offset + 36)?,
        })
    }
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
        let machine = PeMachine::from_raw(header.coff_header.machine);

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
            machine,
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
        if let Some(pe) = PeView::parse(data) {
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

            return Ok(PeInfo {
                image_base: pe.image_base(),
                size_of_image: pe.size_of_image(),
                timestamp: pe.timestamp(),
                checksum: pe.check_sum(),
                is_64bit: pe.is_64bit(),
                machine: PeMachine::from_raw(pe.machine()),
                sections,
                data_directories,
            });
        }

        let layout = PeHeaderLayout::parse(data)?;
        let read32_or_zero = |offset: usize| read_u32(data, offset).unwrap_or(0);
        let read64_or_zero = |offset: usize| read_u64(data, offset).unwrap_or(0);

        let timestamp = layout.timestamp_offset().map(read32_or_zero).unwrap_or(0);
        let image_base = if layout.is_64bit() {
            layout.image_base_offset().map(read64_or_zero).unwrap_or(0)
        } else {
            layout.image_base_offset().map(read32_or_zero).unwrap_or(0) as u64
        };
        let size_of_image = layout
            .size_of_image_offset()
            .map(read32_or_zero)
            .unwrap_or(0);
        let checksum = layout.checksum_offset().map(read32_or_zero).unwrap_or(0);

        let mut data_directories = vec![(0u32, 0u32); DataDirectoryKind::COUNT];
        for (index, slot) in data_directories
            .iter_mut()
            .enumerate()
            .take(layout.number_of_rva_and_sizes.min(DataDirectoryKind::COUNT))
        {
            let Some(offset) = DataDirectoryKind::from_index(index)
                .and_then(|kind| layout.data_directory_offset(kind))
            else {
                continue;
            };
            *slot = (read32_or_zero(offset), read32_or_zero(offset + 4));
        }

        let mut sections = Vec::with_capacity(layout.number_of_sections);
        for index in 0..layout.number_of_sections {
            let Some(section) = layout.section(data, index) else {
                break;
            };
            sections.push(section);
        }

        Ok(PeInfo {
            image_base,
            size_of_image,
            timestamp,
            checksum,
            is_64bit: layout.is_64bit(),
            machine: layout.machine,
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

    pub fn data_directory(&self, kind: DataDirectoryKind) -> Option<PeDataDirectory> {
        self.data_directories
            .get(kind.index())
            .map(|&(rva, size)| PeDataDirectory { rva, size })
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
            assert_eq!(info.machine, PeMachine::Amd64);
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
            machine: PeMachine::Amd64,
            sections,
            data_directories: vec![],
        }
    }

    fn pe_with_directories(data_directories: Vec<(u32, u32)>) -> PeInfo {
        PeInfo {
            image_base: 0x140000000,
            size_of_image: 0x9000,
            timestamp: 0,
            checksum: 0,
            is_64bit: true,
            machine: PeMachine::Amd64,
            sections: vec![],
            data_directories,
        }
    }

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_header_pe(pe32_plus: bool, directory_count: u32) -> Vec<u8> {
        let mut image = vec![0u8; 0x600];
        put_u32(&mut image, DOS_E_LFANEW_OFFSET, 0x80);
        image[0x80..0x84].copy_from_slice(PE_SIGNATURE);

        let file_header = 0x84;
        let optional_header = 0x98;
        let optional_header_size = if pe32_plus { 0xf0 } else { 0xe0 };
        put_u16(
            &mut image,
            file_header,
            if pe32_plus {
                PeMachine::Amd64.raw()
            } else {
                PeMachine::I386.raw()
            },
        );
        put_u16(&mut image, file_header + 2, 1);
        put_u32(&mut image, file_header + 4, 0x1234_5678);
        put_u16(&mut image, file_header + 16, optional_header_size);

        if pe32_plus {
            put_u16(
                &mut image,
                optional_header,
                PeOptionalHeaderKind::PE32_PLUS_MAGIC,
            );
            put_u64(&mut image, optional_header + 0x18, 0x0000_0001_4000_0000);
        } else {
            put_u16(
                &mut image,
                optional_header,
                PeOptionalHeaderKind::PE32_MAGIC,
            );
            put_u32(&mut image, optional_header + 0x1c, 0x0040_0000);
        }
        put_u32(&mut image, optional_header + 0x38, 0x3000);
        put_u32(&mut image, optional_header + 0x40, 0xfeed_beef);
        let directory_count_offset = optional_header
            + if pe32_plus {
                (PeOptionalHeaderKind::Pe32Plus).number_of_rva_and_sizes_relative_offset()
            } else {
                (PeOptionalHeaderKind::Pe32).number_of_rva_and_sizes_relative_offset()
            };
        let directory_base = optional_header
            + if pe32_plus {
                (PeOptionalHeaderKind::Pe32Plus).data_directories_relative_offset()
            } else {
                (PeOptionalHeaderKind::Pe32).data_directories_relative_offset()
            };
        put_u32(&mut image, directory_count_offset, directory_count);
        if directory_count > DataDirectoryKind::Import.index() as u32 {
            put_u32(
                &mut image,
                directory_base + DataDirectoryKind::Import.index() * 8,
                0x2100,
            );
            put_u32(
                &mut image,
                directory_base + DataDirectoryKind::Import.index() * 8 + 4,
                0x28,
            );
        }
        if directory_count > DataDirectoryKind::ClrRuntimeHeader.index() as u32 {
            put_u32(
                &mut image,
                directory_base + DataDirectoryKind::ClrRuntimeHeader.index() * 8,
                0x2200,
            );
            put_u32(
                &mut image,
                directory_base + DataDirectoryKind::ClrRuntimeHeader.index() * 8 + 4,
                0x48,
            );
        }

        let section = optional_header + optional_header_size as usize;
        image[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut image, section + 8, 0x1000);
        put_u32(&mut image, section + 12, 0x2000);
        put_u32(&mut image, section + 16, 0x1000);
        put_u32(&mut image, section + 20, 0x200);
        put_u32(&mut image, section + 36, 0x6000_0020);
        image
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

    #[test]
    fn data_directory_kind_indexes_match_pe_order() {
        assert_eq!(DataDirectoryKind::Export.index(), 0);
        assert_eq!(DataDirectoryKind::Import.index(), 1);
        assert_eq!(DataDirectoryKind::Resource.index(), 2);
        assert_eq!(DataDirectoryKind::Exception.index(), 3);
        assert_eq!(DataDirectoryKind::BaseRelocation.index(), 5);
        assert_eq!(DataDirectoryKind::ClrRuntimeHeader.index(), 14);
        assert_eq!(DataDirectoryKind::Reserved.index(), 15);
        assert_eq!(DataDirectoryKind::COUNT, 16);
        assert_eq!(
            DataDirectoryKind::from_index(14),
            Some(DataDirectoryKind::ClrRuntimeHeader)
        );
        assert_eq!(DataDirectoryKind::from_index(16), None);
    }

    #[test]
    fn pe_machine_maps_known_architectures_and_file_types() {
        assert_eq!(PeMachine::from_raw(0x014c), PeMachine::I386);
        assert_eq!(PeMachine::from_raw(0x0200), PeMachine::Ia64);
        assert_eq!(PeMachine::from_raw(0x8664), PeMachine::Amd64);
        assert_eq!(PeMachine::from_raw(0x01c4), PeMachine::ArmNt);
        assert_eq!(PeMachine::from_raw(0xaa64), PeMachine::Arm64);
        assert_eq!(PeMachine::from_raw(0x1234), PeMachine::Unknown(0x1234));
        assert_eq!(PeMachine::Unknown(0x1234).raw(), 0x1234);

        assert_eq!(PeMachine::I386.classic_msdelta_file_type(), Some(0x2));
        assert_eq!(PeMachine::Ia64.classic_msdelta_file_type(), Some(0x4));
        assert_eq!(PeMachine::Amd64.classic_msdelta_file_type(), Some(0x8));
        assert_eq!(PeMachine::ArmNt.classic_msdelta_file_type(), None);

        assert_eq!(PeMachine::I386.cli4_msdelta_file_type(), Some(0x10));
        assert_eq!(PeMachine::Amd64.cli4_msdelta_file_type(), Some(0x20));
        assert_eq!(PeMachine::ArmNt.cli4_msdelta_file_type(), Some(0x40));
        assert_eq!(PeMachine::Arm64.cli4_msdelta_file_type(), Some(0x80));
        assert_eq!(PeMachine::Ia64.cli4_msdelta_file_type(), None);

        assert_eq!(PeMachine::I386.supported_create_file_type(), Some(0x2));
        assert_eq!(PeMachine::Amd64.supported_create_file_type(), Some(0x8));
        assert_eq!(PeMachine::Ia64.supported_create_file_type(), None);
        assert_eq!(PeMachine::Arm64.supported_create_file_type(), None);
    }

    #[test]
    fn pe_data_directory_lookup_uses_typed_kind() {
        let mut directories = vec![(0, 0); DataDirectoryKind::COUNT];
        directories[DataDirectoryKind::Import.index()] = (0x1200, 0x28);
        directories[DataDirectoryKind::ClrRuntimeHeader.index()] = (0x2400, 0x48);
        let pe = pe_with_directories(directories);

        assert_eq!(
            pe.data_directory(DataDirectoryKind::Import),
            Some(PeDataDirectory {
                rva: 0x1200,
                size: 0x28
            })
        );
        assert_eq!(
            pe.data_directory(DataDirectoryKind::ClrRuntimeHeader),
            Some(PeDataDirectory {
                rva: 0x2400,
                size: 0x48
            })
        );
        assert_eq!(
            pe.data_directory(DataDirectoryKind::Resource),
            Some(PeDataDirectory { rva: 0, size: 0 })
        );
        assert!(pe
            .data_directory(DataDirectoryKind::Resource)
            .unwrap()
            .is_empty());

        let truncated = pe_with_directories(vec![(0x1100, 0x10)]);
        assert_eq!(
            truncated.data_directory(DataDirectoryKind::Import),
            None,
            "missing optional-header directory slots remain absent"
        );
    }

    #[test]
    fn pe_header_layout_parses_pe32_offsets() {
        let image = synthetic_header_pe(false, DataDirectoryKind::COUNT as u32);
        let layout = PeHeaderLayout::parse(&image).unwrap();

        assert_eq!(layout.nt_headers_offset, 0x80);
        assert_eq!(layout.file_header_offset, 0x84);
        assert_eq!(layout.optional_header_offset, 0x98);
        assert_eq!(layout.optional_header_kind, PeOptionalHeaderKind::Pe32);
        assert_eq!(layout.machine, PeMachine::I386);
        assert!(!layout.is_64bit());
        assert_eq!(layout.timestamp_offset(), Some(0x88));
        assert_eq!(layout.image_base_offset(), Some(0xb4));
        assert_eq!(layout.image_base_width(), 4);
        assert_eq!(layout.size_of_image_offset(), Some(0xd0));
        assert_eq!(layout.checksum_offset(), Some(0xd8));
        assert_eq!(layout.data_directories_offset(), Some(0xf8));
        assert_eq!(
            layout.data_directory(&image, DataDirectoryKind::ClrRuntimeHeader),
            Some(PeDataDirectory {
                rva: 0x2200,
                size: 0x48
            })
        );
        assert_eq!(layout.section_table_offset(), Some(0x178));
        assert_eq!(layout.section(&image, 0).unwrap().name, ".text");
    }

    #[test]
    fn pe_header_layout_parses_pe32_plus_offsets_and_missing_slots() {
        let image = synthetic_header_pe(true, 1);
        let layout = PeHeaderLayout::parse(&image).unwrap();

        assert_eq!(layout.optional_header_kind, PeOptionalHeaderKind::Pe32Plus);
        assert_eq!(layout.machine, PeMachine::Amd64);
        assert!(layout.is_64bit());
        assert_eq!(layout.image_base_offset(), Some(0xb0));
        assert_eq!(layout.image_base_width(), 8);
        assert_eq!(layout.data_directories_offset(), Some(0x108));
        assert_eq!(
            layout.data_directory(&image, DataDirectoryKind::Import),
            None
        );
    }

    #[test]
    fn parse_lenient_uses_header_layout_contract() {
        let image = synthetic_header_pe(true, DataDirectoryKind::COUNT as u32);
        let pe = PeInfo::parse_lenient(&image).unwrap();

        assert_eq!(pe.image_base, 0x0000_0001_4000_0000);
        assert_eq!(pe.size_of_image, 0x3000);
        assert_eq!(pe.timestamp, 0x1234_5678);
        assert_eq!(pe.checksum, 0xfeed_beef);
        assert!(pe.is_64bit);
        assert_eq!(pe.machine, PeMachine::Amd64);
        assert_eq!(
            pe.data_directory(DataDirectoryKind::Import),
            Some(PeDataDirectory {
                rva: 0x2100,
                size: 0x28
            })
        );
        assert_eq!(pe.sections[0].name, ".text");
    }
}
