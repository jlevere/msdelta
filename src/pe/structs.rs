//! Zero-copy, unaligned, *mutable* views of the PE structures the transform
//! pipeline reads and rewrites in place.
//!
//! Why hand-rolled rather than a PE crate: the transforms edit the image buffer
//! in place (rewriting thunks, relocation operands, header fields, …) and must
//! accept genuine system images that strict parsers (`goblin`) reject. Read-only
//! parsers fight both needs. These structs use `zerocopy`'s little-endian
//! integer types (`U16`/`U32`/`U64`), which are alignment-1, so a view can be
//! laid over *any* file offset and its fields read/written by name -- replacing
//! the raw `buf[off + 0x10]` offset arithmetic that this layer supersedes.
//!
//! Field names and offsets follow the Win32 `IMAGE_*` definitions (winnt.h).

use zerocopy::little_endian::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// `IMAGE_DIRECTORY_ENTRY_*` indices into the optional header's data directory
/// (the full canonical set; index 15 is reserved). `ARCHITECTURE` (7) and
/// `GLOBALPTR` (8) follow winnt.h's `IMAGE_DIRECTORY_ENTRY_*` names.
pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const COM_DESCRIPTOR: usize = 14;
}

/// `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ` section characteristics.
pub const SCN_MEM_WRITE_READ: u32 = 0xC000_0000;

/// `IMAGE_SCN_MEM_EXECUTE` section characteristic (the section holds code).
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// `IMAGE_DOS_SIGNATURE` -- the "MZ" magic at file offset 0.
pub const DOS_SIGNATURE: u16 = 0x5A4D;

/// `IMAGE_FILE_MACHINE_*` values (COFF `FileHeader.Machine`).
pub mod machine {
    pub const I386: u16 = 0x014C;
    pub const AMD64: u16 = 0x8664;
    pub const ARMNT: u16 = 0x01C4;
    pub const ARM64: u16 = 0xAA64;
    pub const IA64: u16 = 0x0200;
}

/// `IMAGE_NT_OPTIONAL_HDR*_MAGIC` values (`OptionalHeader.Magic`).
pub mod magic {
    pub const PE32: u16 = 0x010B;
    pub const PE32_PLUS: u16 = 0x020B;
    pub const ROM: u16 = 0x0107;
}

/// `IMAGE_SECTION_HEADER` (40 bytes). Only the fields the transforms touch are
/// named; `characteristics` is the rewritten one (PeUnbinder marks `.idata`
/// writable). `name` is 8 bytes, null- or space-padded, not necessarily NUL-
/// terminated.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: U32,
    pub virtual_address: U32,
    pub size_of_raw_data: U32,
    pub pointer_to_raw_data: U32,
    pub pointer_to_relocations: U32,
    pub pointer_to_line_numbers: U32,
    pub number_of_relocations: U16,
    pub number_of_line_numbers: U16,
    pub characteristics: U32,
}

impl ImageSectionHeader {
    pub const SIZE: usize = 40;
    /// True when the section name equals `want` (case-insensitive, ignoring the
    /// trailing NUL/space padding), matching genuine's case-insensitive compare.
    pub fn name_eq(&self, want: &[u8]) -> bool {
        let actual: &[u8] = match self.name.iter().position(|&c| c == 0) {
            Some(n) => &self.name[..n],
            None => &self.name,
        };
        actual.eq_ignore_ascii_case(want)
    }
}

/// `IMAGE_IMPORT_DESCRIPTOR` (20 bytes). `original_first_thunk` is the ILT,
/// `first_thunk` the IAT; both are RVAs to pointer-sized thunk arrays. A
/// non-zero `time_date_stamp` marks a bound descriptor.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Default)]
#[repr(C)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: U32,
    pub time_date_stamp: U32,
    pub forwarder_chain: U32,
    pub name: U32,
    pub first_thunk: U32,
}

/// `IMAGE_EXPORT_DIRECTORY` (40 bytes). The RVA fields the transform remaps are
/// `name`, `address_of_functions`, `address_of_names`, `address_of_name_ordinals`,
/// plus the two RVA arrays sized by `number_of_functions` / `number_of_names`.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: U32,
    pub time_date_stamp: U32,
    pub major_version: U16,
    pub minor_version: U16,
    pub name: U32,
    pub base: U32,
    pub number_of_functions: U32,
    pub number_of_names: U32,
    pub address_of_functions: U32,
    pub address_of_names: U32,
    pub address_of_name_ordinals: U32,
}

/// `IMAGE_RESOURCE_DIRECTORY_ENTRY` (8 bytes). `name` and `offset_to_data` carry
/// their high bit as a string-name / subdirectory flag; the low 31 bits are an
/// offset relative to the resource directory base.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageResourceDirectoryEntry {
    pub name: U32,
    pub offset_to_data: U32,
}

/// `RUNTIME_FUNCTION` (amd64 `.pdata`, 12 bytes): all three fields are RVAs.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct RuntimeFunction {
    pub begin: U32,
    pub end: U32,
    pub unwind_data: U32,
}

/// `IMAGE_BASE_RELOCATION` block header (8 bytes).
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageBaseRelocation {
    pub page_rva: U32,
    pub size_of_block: U32,
}

/// `IMAGE_FILE_HEADER` (COFF header, 20 bytes). Immediately follows the 4-byte
/// `PE\0\0` signature. `size_of_optional_header` locates the section table;
/// `machine` distinguishes i386 / amd64 / arm64.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageFileHeader {
    pub machine: U16,
    pub number_of_sections: U16,
    pub time_date_stamp: U32,
    pub pointer_to_symbol_table: U32,
    pub number_of_symbols: U32,
    pub size_of_optional_header: U16,
    pub characteristics: U16,
}

/// `IMAGE_DATA_DIRECTORY` (8 bytes): an RVA + byte size. The optional header
/// ends with `NumberOfRvaAndSizes` of these (see `dir` for the indices).
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy, Default)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: U32,
    pub size: U32,
}

/// `IMAGE_OPTIONAL_HEADER32` (PE32) up to but not including the trailing
/// `DataDirectory[]` -- exactly 96 bytes, so the data directories begin at
/// `optional_header_offset + 96`. PE32 carries `base_of_data` and 32-bit
/// `image_base` / stack / heap fields (the point of difference from PE32+).
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageOptionalHeader32 {
    pub magic: U16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: U32,
    pub size_of_initialized_data: U32,
    pub size_of_uninitialized_data: U32,
    pub address_of_entry_point: U32,
    pub base_of_code: U32,
    pub base_of_data: U32,
    pub image_base: U32,
    pub section_alignment: U32,
    pub file_alignment: U32,
    pub major_operating_system_version: U16,
    pub minor_operating_system_version: U16,
    pub major_image_version: U16,
    pub minor_image_version: U16,
    pub major_subsystem_version: U16,
    pub minor_subsystem_version: U16,
    pub win32_version_value: U32,
    pub size_of_image: U32,
    pub size_of_headers: U32,
    pub check_sum: U32,
    pub subsystem: U16,
    pub dll_characteristics: U16,
    pub size_of_stack_reserve: U32,
    pub size_of_stack_commit: U32,
    pub size_of_heap_reserve: U32,
    pub size_of_heap_commit: U32,
    pub loader_flags: U32,
    pub number_of_rva_and_sizes: U32,
}

/// `IMAGE_OPTIONAL_HEADER64` (PE32+) up to but not including the trailing
/// `DataDirectory[]` -- exactly 112 bytes, so the data directories begin at
/// `optional_header_offset + 112`. No `base_of_data`; `image_base` and the
/// stack / heap reserve/commit fields are 64-bit.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: U16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: U32,
    pub size_of_initialized_data: U32,
    pub size_of_uninitialized_data: U32,
    pub address_of_entry_point: U32,
    pub base_of_code: U32,
    pub image_base: U64,
    pub section_alignment: U32,
    pub file_alignment: U32,
    pub major_operating_system_version: U16,
    pub minor_operating_system_version: U16,
    pub major_image_version: U16,
    pub minor_image_version: U16,
    pub major_subsystem_version: U16,
    pub minor_subsystem_version: U16,
    pub win32_version_value: U32,
    pub size_of_image: U32,
    pub size_of_headers: U32,
    pub check_sum: U32,
    pub subsystem: U16,
    pub dll_characteristics: U16,
    pub size_of_stack_reserve: U64,
    pub size_of_stack_commit: U64,
    pub size_of_heap_reserve: U64,
    pub size_of_heap_commit: U64,
    pub loader_flags: U32,
    pub number_of_rva_and_sizes: U32,
}

/// `IMAGE_DEBUG_DIRECTORY` (28 bytes): one entry in the debug data directory
/// (`dir::DEBUG`). `time_date_stamp` mirrors the COFF header's, which is why the
/// timestamp-normalization pass records its offset; `address_of_raw_data` /
/// `pointer_to_raw_data` locate the entry's payload by RVA / file offset.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageDebugDirectory {
    pub characteristics: U32,
    pub time_date_stamp: U32,
    pub major_version: U16,
    pub minor_version: U16,
    pub r#type: U32,
    pub size_of_data: U32,
    pub address_of_raw_data: U32,
    pub pointer_to_raw_data: U32,
}

/// `IMAGE_TLS_DIRECTORY32` (24 bytes; `dir::TLS`). The address fields are VAs
/// (not RVAs) and carry base relocations -- a transform target once TLS support
/// lands.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageTlsDirectory32 {
    pub start_address_of_raw_data: U32,
    pub end_address_of_raw_data: U32,
    pub address_of_index: U32,
    pub address_of_callbacks: U32,
    pub size_of_zero_fill: U32,
    pub characteristics: U32,
}

/// `IMAGE_TLS_DIRECTORY64` (40 bytes; `dir::TLS`). Like [`ImageTlsDirectory32`]
/// but the four address fields are 64-bit VAs.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageTlsDirectory64 {
    pub start_address_of_raw_data: U64,
    pub end_address_of_raw_data: U64,
    pub address_of_index: U64,
    pub address_of_callbacks: U64,
    pub size_of_zero_fill: U32,
    pub characteristics: U32,
}

/// `IMAGE_DELAYLOAD_DESCRIPTOR` (32 bytes; `dir::DELAY_IMPORT`). All `*_rva`
/// fields are RVAs into the delay-load thunk/name tables -- the analogue of
/// [`ImageImportDescriptor`] for delay-loaded imports, and a transform target
/// once delay-import support lands.
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
#[repr(C)]
pub struct ImageDelayloadDescriptor {
    pub attributes: U32,
    pub dll_name_rva: U32,
    pub module_handle_rva: U32,
    pub import_address_table_rva: U32,
    pub import_name_table_rva: U32,
    pub bound_import_address_table_rva: U32,
    pub unload_information_table_rva: U32,
    pub time_date_stamp: U32,
}

/// Compile-time guard pinning each view to the byte size winnt.h / the PE/COFF
/// specification mandates. The optional-header structs stop just before the
/// trailing `DataDirectory[]`, so their canonical sizes are 96 / 112. If a field
/// is ever added, removed, or retyped, one of these breaks the build before any
/// silent misparse can reach a fixture.
const _: () = {
    use core::mem::size_of;
    assert!(size_of::<ImageSectionHeader>() == 40);
    assert!(size_of::<ImageImportDescriptor>() == 20);
    assert!(size_of::<ImageExportDirectory>() == 40);
    assert!(size_of::<ImageResourceDirectoryEntry>() == 8);
    assert!(size_of::<RuntimeFunction>() == 12);
    assert!(size_of::<ImageBaseRelocation>() == 8);
    assert!(size_of::<ImageFileHeader>() == 20);
    assert!(size_of::<ImageDataDirectory>() == 8);
    assert!(size_of::<ImageOptionalHeader32>() == 96);
    assert!(size_of::<ImageOptionalHeader64>() == 112);
    assert!(size_of::<ImageDebugDirectory>() == 28);
    assert!(size_of::<ImageTlsDirectory32>() == 24);
    assert!(size_of::<ImageTlsDirectory64>() == 40);
    assert!(size_of::<ImageDelayloadDescriptor>() == 32);
};

/// File offset of the PE signature (`e_lfanew`), if `buf` is a PE (`MZ` magic
/// at 0, `PE\0\0` at `e_lfanew`).
#[inline]
pub fn pe_header_offset(buf: &[u8]) -> Option<usize> {
    if read_u16(buf, 0) != DOS_SIGNATURE {
        return None;
    }
    let e = read_u32(buf, 0x3c) as usize;
    (buf.get(e..e + 4) == Some(b"PE\0\0")).then_some(e)
}

/// `(file offset of the section table, NumberOfSections)`. The section table
/// follows the COFF header (NumberOfSections at +6, SizeOfOptionalHeader at +20)
/// and the optional header.
#[inline]
pub fn section_table(buf: &[u8]) -> Option<(usize, usize)> {
    let e = pe_header_offset(buf)?;
    let count = read_u16(buf, e + 6) as usize;
    let opt_size = read_u16(buf, e + 20) as usize;
    Some((e + 24 + opt_size, count))
}

/// Read a copy of a `T` view at file offset `off`, or `None` if out of bounds.
#[inline]
pub fn read<T: FromBytes + IntoBytes + KnownLayout + Immutable + Copy>(
    buf: &[u8],
    off: usize,
) -> Option<T> {
    T::ref_from_prefix(buf.get(off..)?).ok().map(|(t, _)| *t)
}

/// Borrow a mutable `T` view at file offset `off`, or `None` if out of bounds.
#[inline]
pub fn view_mut<T: FromBytes + IntoBytes + KnownLayout>(
    buf: &mut [u8],
    off: usize,
) -> Option<&mut T> {
    T::mut_from_prefix(buf.get_mut(off..)?).ok().map(|(t, _)| t)
}

/// Read a little-endian `u32` at file offset `off` (0 if out of bounds).
#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    read::<U32>(buf, off).map(|v| v.get()).unwrap_or(0)
}

/// Read a little-endian `u16` at file offset `off` (0 if out of bounds).
#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    read::<U16>(buf, off).map(|v| v.get()).unwrap_or(0)
}

/// Read a little-endian `u64` at file offset `off` (0 if out of bounds).
#[inline]
pub fn read_u64(buf: &[u8], off: usize) -> u64 {
    read::<U64>(buf, off).map(|v| v.get()).unwrap_or(0)
}

/// Write a little-endian `u32` at file offset `off` (no-op if out of bounds).
#[inline]
pub fn write_u32(buf: &mut [u8], off: usize, val: u32) {
    if let Some(v) = view_mut::<U32>(buf, off) {
        v.set(val);
    }
}

/// Write a little-endian `u64` at file offset `off` (no-op if out of bounds).
#[inline]
pub fn write_u64(buf: &mut [u8], off: usize, val: u64) {
    if let Some(v) = view_mut::<U64>(buf, off) {
        v.set(val);
    }
}

/// Write a little-endian `u16` at file offset `off` (no-op if out of bounds).
#[inline]
pub fn write_u16(buf: &mut [u8], off: usize, val: u16) {
    if let Some(v) = view_mut::<U16>(buf, off) {
        v.set(val);
    }
}

/// A lightweight, lenient *read* cursor over a PE image's headers.
///
/// This is the single entry point for header navigation: it locates the COFF
/// header, optional header (PE32 / PE32+), data directories and section table,
/// and resolves RVAs to/from file offsets -- replacing the several hand-rolled
/// header walkers that used to each re-derive these offsets. It is deliberately
/// lenient (the same reason the transforms avoid `goblin`): it validates only
/// the `MZ` / `PE\0\0` / optional-magic gates and reads everything else through
/// the bounds-checked helpers, so a truncated or unusual-but-real system image
/// yields zeroes rather than a parse failure.
#[derive(Clone, Copy)]
pub struct PeView<'a> {
    buf: &'a [u8],
    /// File offset of the `PE\0\0` signature (`e_lfanew`).
    pe_off: usize,
    /// File offset of the optional header (`pe_off + 4 + 20`).
    opt_off: usize,
    /// PE32+ (true) vs PE32 (false), from the optional-header magic.
    pe32_plus: bool,
}

impl<'a> PeView<'a> {
    /// Parse just enough to navigate: requires `MZ`, `PE\0\0`, and a recognized
    /// optional-header magic (PE32 or PE32+). Returns `None` otherwise.
    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let pe_off = pe_header_offset(buf)?;
        let opt_off = pe_off + 24;
        let pe32_plus = match read_u16(buf, opt_off) {
            magic::PE32 => false,
            magic::PE32_PLUS => true,
            _ => return None,
        };
        Some(Self {
            buf,
            pe_off,
            opt_off,
            pe32_plus,
        })
    }

    /// The underlying image bytes.
    #[inline]
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// File offset of the `PE\0\0` signature.
    #[inline]
    pub fn pe_header_offset(&self) -> usize {
        self.pe_off
    }

    /// File offset of the optional header.
    #[inline]
    pub fn optional_header_offset(&self) -> usize {
        self.opt_off
    }

    /// True for PE32+ (64-bit) images.
    #[inline]
    pub fn is_64bit(&self) -> bool {
        self.pe32_plus
    }

    /// The COFF file header (`IMAGE_FILE_HEADER`), if in bounds.
    #[inline]
    pub fn file_header(&self) -> Option<ImageFileHeader> {
        read::<ImageFileHeader>(self.buf, self.pe_off + 4)
    }

    /// `FileHeader.Machine` (e.g. [`machine::I386`], [`machine::AMD64`]).
    #[inline]
    pub fn machine(&self) -> u16 {
        read_u16(self.buf, self.pe_off + 4)
    }

    /// `FileHeader.NumberOfSections`.
    #[inline]
    pub fn number_of_sections(&self) -> usize {
        read_u16(self.buf, self.pe_off + 6) as usize
    }

    /// `FileHeader.SizeOfOptionalHeader` (locates the section table).
    #[inline]
    fn size_of_optional_header(&self) -> usize {
        read_u16(self.buf, self.pe_off + 20) as usize
    }

    /// `FileHeader.TimeDateStamp`.
    #[inline]
    pub fn timestamp(&self) -> u32 {
        read_u32(self.buf, self.pe_off + 8)
    }

    /// `OptionalHeader.ImageBase` (u32 for PE32, u64 for PE32+).
    #[inline]
    pub fn image_base(&self) -> u64 {
        if self.pe32_plus {
            read_u64(self.buf, self.opt_off + 24)
        } else {
            read_u32(self.buf, self.opt_off + 28) as u64
        }
    }

    /// `OptionalHeader.SizeOfImage` (offset 56 for both magics).
    #[inline]
    pub fn size_of_image(&self) -> u32 {
        read_u32(self.buf, self.opt_off + 56)
    }

    /// `OptionalHeader.CheckSum` (offset 64 for both magics).
    #[inline]
    pub fn check_sum(&self) -> u32 {
        read_u32(self.buf, self.opt_off + 64)
    }

    /// `OptionalHeader.NumberOfRvaAndSizes`.
    #[inline]
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        let off = self.opt_off + if self.pe32_plus { 108 } else { 92 };
        read_u32(self.buf, off)
    }

    /// File offset of the data-directory array (just past the fixed optional
    /// header: +112 for PE32+, +96 for PE32).
    #[inline]
    fn data_directory_base(&self) -> usize {
        self.opt_off + if self.pe32_plus { 112 } else { 96 }
    }

    /// Data directory `index` (see [`dir`]), or `None` if `index` is beyond
    /// `NumberOfRvaAndSizes` or out of bounds.
    #[inline]
    pub fn data_directory(&self, index: usize) -> Option<ImageDataDirectory> {
        if index >= self.number_of_rva_and_sizes() as usize {
            return None;
        }
        read::<ImageDataDirectory>(self.buf, self.data_directory_base() + index * 8)
    }

    /// File offset of the section table (just past the optional header).
    #[inline]
    pub fn section_table_offset(&self) -> usize {
        self.opt_off + self.size_of_optional_header()
    }

    /// Iterate the section headers (each a `Copy` view; stops at the first one
    /// that runs past the buffer).
    pub fn sections(&self) -> impl Iterator<Item = ImageSectionHeader> + 'a {
        let buf = self.buf;
        let base = self.section_table_offset();
        let count = self.number_of_sections();
        (0..count).map_while(move |i| {
            read::<ImageSectionHeader>(buf, base + i * ImageSectionHeader::SIZE)
        })
    }

    /// Map a relative virtual address to a file offset via the section table.
    /// Sections with no raw backing (`pointer_to_raw_data == 0`) are skipped;
    /// containment uses `virtual_size`.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in self.sections() {
            let ptr = s.pointer_to_raw_data.get();
            if ptr == 0 {
                continue;
            }
            let va = s.virtual_address.get();
            if rva >= va && rva < va.wrapping_add(s.virtual_size.get()) {
                return Some(ptr as usize + (rva - va) as usize);
            }
        }
        None
    }

    /// Map a file offset back to a relative virtual address via the section
    /// table (inverse of [`rva_to_offset`](Self::rva_to_offset)).
    pub fn offset_to_rva(&self, off: usize) -> Option<u32> {
        let off = u32::try_from(off).ok()?;
        for s in self.sections() {
            let ptr = s.pointer_to_raw_data.get();
            let raw = s.size_of_raw_data.get();
            if raw != 0 && off >= ptr && off < ptr.wrapping_add(raw) {
                return Some(s.virtual_address.get() + (off - ptr));
            }
        }
        None
    }
}
