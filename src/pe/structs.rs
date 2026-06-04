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

/// `IMAGE_DIRECTORY_ENTRY_*` indices into the optional header's data directory.
pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    pub const BASERELOC: usize = 5;
    pub const COM_DESCRIPTOR: usize = 14;
}

/// `IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ` section characteristics.
pub const SCN_MEM_WRITE_READ: u32 = 0xC000_0000;

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

/// File offset of the PE signature (`e_lfanew`), if `buf` is a PE.
#[inline]
pub fn pe_header_offset(buf: &[u8]) -> Option<usize> {
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
