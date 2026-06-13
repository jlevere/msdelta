//! Managed PE CLR metadata root parsing.

use crate::pe::cli_schema::{metadata_schema, row_size, CliSchemaFlavor, HeapIndexWidths};
use crate::pe::parse::{PeInfo, SectionInfo};
use crate::{Error, Result};

const CLR_DATA_DIRECTORY: usize = 14;
const COR20_METADATA_RVA_OFFSET: usize = 8;
const COR20_METADATA_SIZE_OFFSET: usize = 12;
const METADATA_SIGNATURE: &[u8; 4] = b"BSJB";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliStream {
    pub(crate) metadata_offset: u32,
    pub(crate) file_offset: usize,
    pub(crate) size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliStreamSet {
    pub(crate) strings: Option<CliStream>,
    pub(crate) user_strings: Option<CliStream>,
    pub(crate) blob: Option<CliStream>,
    pub(crate) guid: Option<CliStream>,
    pub(crate) tables: CliStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliMetadataModel {
    pub(crate) flavor: CliSchemaFlavor,
    pub(crate) metadata_rva: u32,
    pub(crate) metadata_file_offset: usize,
    pub(crate) metadata_size: u32,
    pub(crate) version: String,
    pub(crate) streams: CliStreamSet,
    pub(crate) heap_widths: HeapIndexWidths,
    pub(crate) valid_table_mask: u64,
    pub(crate) sorted_table_mask: u64,
    pub(crate) row_counts: [u32; 64],
    pub(crate) row_sizes: [u32; 64],
    pub(crate) table_file_offsets: [Option<usize>; 64],
}

pub(crate) fn parse_cli_metadata_from_pe(
    image: &[u8],
    flavor: CliSchemaFlavor,
) -> Result<CliMetadataModel> {
    let pe = PeInfo::parse_lenient(image)?;
    parse_cli_metadata_from_pe_info(image, &pe, flavor)
}

pub(crate) fn parse_cli_metadata_from_pe_info(
    image: &[u8],
    pe: &PeInfo,
    flavor: CliSchemaFlavor,
) -> Result<CliMetadataModel> {
    let (clr_rva, _) = pe
        .data_directories
        .get(CLR_DATA_DIRECTORY)
        .copied()
        .ok_or(Error::Malformed("PE: missing CLR data directory"))?;
    if clr_rva == 0 {
        return Err(Error::Malformed("PE: missing CLR runtime header"));
    }

    let clr_file_offset = rva_to_file_offset(&pe.sections, clr_rva)
        .ok_or(Error::Malformed("PE: CLR runtime header RVA is unmapped"))?;
    checked_slice(image, clr_file_offset, 0x48)?;
    let metadata_rva = read_u32(image, clr_file_offset + COR20_METADATA_RVA_OFFSET)?;
    let metadata_size = read_u32(image, clr_file_offset + COR20_METADATA_SIZE_OFFSET)?;
    if metadata_rva == 0 || metadata_size == 0 {
        return Err(Error::Malformed("CLI metadata: empty metadata directory"));
    }

    let metadata_file_offset = rva_to_file_offset(&pe.sections, metadata_rva)
        .ok_or(Error::Malformed("CLI metadata: metadata RVA is unmapped"))?;
    parse_cli_metadata_root(
        image,
        flavor,
        metadata_rva,
        metadata_file_offset,
        metadata_size,
    )
}

fn parse_cli_metadata_root(
    image: &[u8],
    flavor: CliSchemaFlavor,
    metadata_rva: u32,
    metadata_file_offset: usize,
    metadata_size: u32,
) -> Result<CliMetadataModel> {
    checked_slice(image, metadata_file_offset, metadata_size as usize)?;
    let root = &image[metadata_file_offset..metadata_file_offset + metadata_size as usize];
    if root.get(..4) != Some(METADATA_SIGNATURE) {
        return Err(Error::Malformed("CLI metadata: bad BSJB signature"));
    }

    let version_len = read_u32(root, 12)? as usize;
    let version_start = 16usize;
    checked_slice(root, version_start, version_len)?;
    let version_end = version_start + version_len;
    let version_bytes = &root[version_start..version_end];
    let version_nul = version_bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(version_bytes.len());
    let version = std::str::from_utf8(&version_bytes[..version_nul])
        .map_err(|_| Error::Malformed("CLI metadata: version string is not UTF-8"))?
        .to_owned();

    let stream_header_start = align_4(version_end)
        .checked_add(4)
        .ok_or(Error::Malformed("CLI metadata: stream header overflow"))?;
    checked_slice(root, stream_header_start, 0)?;
    let stream_count = read_u16(root, stream_header_start - 2)? as usize;
    if stream_count == 0 {
        return Err(Error::Malformed("CLI metadata: no streams"));
    }

    let streams = parse_stream_headers(
        root,
        metadata_file_offset,
        stream_header_start,
        stream_count,
    )?;
    let tables = streams
        .tables
        .ok_or(Error::Malformed("CLI metadata: missing #~ stream"))?;
    let tables_rel = tables.metadata_offset as usize;
    let tables_size = tables.size as usize;
    checked_slice(root, tables_rel, tables_size)?;
    let table_stream = &root[tables_rel..tables_rel + tables_size];
    let parsed_tables = parse_tables_stream(table_stream, tables.file_offset)?;

    Ok(CliMetadataModel {
        flavor,
        metadata_rva,
        metadata_file_offset,
        metadata_size,
        version,
        streams: CliStreamSet {
            strings: streams.strings,
            user_strings: streams.user_strings,
            blob: streams.blob,
            guid: streams.guid,
            tables,
        },
        heap_widths: parsed_tables.heap_widths,
        valid_table_mask: parsed_tables.valid_table_mask,
        sorted_table_mask: parsed_tables.sorted_table_mask,
        row_counts: parsed_tables.row_counts,
        row_sizes: parsed_tables.row_sizes,
        table_file_offsets: parsed_tables.table_file_offsets,
    })
}

#[derive(Default)]
struct ParsedStreamHeaders {
    strings: Option<CliStream>,
    user_strings: Option<CliStream>,
    blob: Option<CliStream>,
    guid: Option<CliStream>,
    tables: Option<CliStream>,
}

fn parse_stream_headers(
    root: &[u8],
    metadata_file_offset: usize,
    mut offset: usize,
    stream_count: usize,
) -> Result<ParsedStreamHeaders> {
    let mut parsed = ParsedStreamHeaders::default();
    let mut names = Vec::<String>::with_capacity(stream_count);

    for _ in 0..stream_count {
        let stream_offset = read_u32(root, offset)?;
        let stream_size = read_u32(root, offset + 4)?;
        let name_start = offset + 8;
        let name_end = root
            .get(name_start..)
            .and_then(|tail| tail.iter().position(|&byte| byte == 0))
            .map(|relative| name_start + relative)
            .ok_or(Error::Malformed("CLI metadata: unterminated stream name"))?;
        let name = std::str::from_utf8(&root[name_start..name_end])
            .map_err(|_| Error::Malformed("CLI metadata: stream name is not UTF-8"))?
            .to_owned();
        if names.iter().any(|existing| existing == &name) {
            return Err(Error::Malformed("CLI metadata: duplicate stream name"));
        }
        names.push(name.clone());

        checked_slice(root, stream_offset as usize, stream_size as usize)?;
        let stream = CliStream {
            metadata_offset: stream_offset,
            file_offset: metadata_file_offset
                .checked_add(stream_offset as usize)
                .ok_or(Error::Malformed(
                    "CLI metadata: stream file offset overflow",
                ))?,
            size: stream_size,
        };

        match name.as_str() {
            "#Strings" => parsed.strings = Some(stream),
            "#US" => parsed.user_strings = Some(stream),
            "#Blob" => parsed.blob = Some(stream),
            "#GUID" => parsed.guid = Some(stream),
            "#~" => parsed.tables = Some(stream),
            _ => {}
        }

        offset = align_4(
            name_end
                .checked_add(1)
                .ok_or(Error::Malformed("CLI metadata: stream header overflow"))?,
        );
        checked_slice(root, offset, 0)?;
    }

    Ok(parsed)
}

struct ParsedTablesStream {
    heap_widths: HeapIndexWidths,
    valid_table_mask: u64,
    sorted_table_mask: u64,
    row_counts: [u32; 64],
    row_sizes: [u32; 64],
    table_file_offsets: [Option<usize>; 64],
}

fn parse_tables_stream(tables: &[u8], tables_file_offset: usize) -> Result<ParsedTablesStream> {
    checked_slice(tables, 0, 24)?;
    let heap_sizes = tables[6];
    let heap_widths = HeapIndexWidths {
        strings: if heap_sizes & 0x01 != 0 { 4 } else { 2 },
        guid: if heap_sizes & 0x02 != 0 { 4 } else { 2 },
        blob: if heap_sizes & 0x04 != 0 { 4 } else { 2 },
    };
    let valid_table_mask = read_u64(tables, 8)?;
    let sorted_table_mask = read_u64(tables, 16)?;

    let mut row_counts = [0u32; 64];
    let mut cursor = 24usize;
    for (table_id, row_count) in row_counts.iter_mut().enumerate() {
        if valid_table_mask & (1u64 << table_id) != 0 {
            if metadata_schema(CliSchemaFlavor::Classic)
                .tables
                .iter()
                .all(|schema| schema.id != table_id as u8)
            {
                return Err(Error::Malformed("CLI metadata: unknown present table id"));
            }
            *row_count = read_u32(tables, cursor)?;
            cursor += 4;
        }
    }

    let mut row_sizes = [0u32; 64];
    let mut table_file_offsets = [None; 64];
    for table_id in 0..64u8 {
        let row_count = row_counts[table_id as usize];
        if row_count == 0 {
            continue;
        }
        let row_size = row_size(table_id, &row_counts, heap_widths)
            .ok_or(Error::Malformed("CLI metadata: unknown table schema"))?;
        row_sizes[table_id as usize] = row_size as u32;
        table_file_offsets[table_id as usize] = Some(
            tables_file_offset
                .checked_add(cursor)
                .ok_or(Error::Malformed("CLI metadata: table file offset overflow"))?,
        );
        let table_bytes = row_size
            .checked_mul(row_count as usize)
            .ok_or(Error::Malformed("CLI metadata: table byte size overflow"))?;
        checked_slice(tables, cursor, table_bytes)?;
        cursor += table_bytes;
    }

    Ok(ParsedTablesStream {
        heap_widths,
        valid_table_mask,
        sorted_table_mask,
        row_counts,
        row_sizes,
        table_file_offsets,
    })
}

fn rva_to_file_offset(sections: &[SectionInfo], rva: u32) -> Option<usize> {
    for section in sections {
        if section.raw_size == 0 {
            continue;
        }
        let start = section.virtual_address;
        let len = section.virtual_size.max(section.raw_size);
        let end = start.checked_add(len)?;
        if rva >= start && rva < end {
            let offset = section.raw_offset.checked_add(rva - start)?;
            return Some(offset as usize);
        }
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = checked_slice(data, offset, 2)?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = checked_slice(data, offset, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = checked_slice(data, offset, 8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn checked_slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(Error::Malformed("CLI metadata: offset overflow"))?;
    data.get(offset..end).ok_or(Error::Truncated)
}

fn align_4(value: usize) -> usize {
    (value + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn parses_minimal_cli_metadata_from_pe32() {
        let image = synthetic_managed_pe(false, StreamMutation::None);
        let model = parse_cli_metadata_from_pe(&image, CliSchemaFlavor::Classic).unwrap();

        assert_eq!(model.flavor, CliSchemaFlavor::Classic);
        assert_eq!(model.metadata_rva, 0x2100);
        assert_eq!(model.metadata_file_offset, 0x300);
        assert_eq!(model.version, "v4.0.30319");
        assert_eq!(model.heap_widths.strings, 4);
        assert_eq!(model.heap_widths.guid, 2);
        assert_eq!(model.heap_widths.blob, 4);
        assert_eq!(model.row_counts[0x00], 1);
        assert_eq!(model.row_counts[0x01], 2);
        assert_eq!(model.row_counts[0x02], 3);
        assert_eq!(model.row_counts[0x06], 4);
        assert_eq!(model.row_sizes[0x00], 12);
        assert_eq!(model.row_sizes[0x01], 10);
        assert_eq!(model.row_sizes[0x02], 18);
        assert_eq!(model.row_sizes[0x06], 18);
        assert_eq!(model.streams.strings.unwrap().size, 32);
        assert_eq!(model.streams.user_strings.unwrap().size, 4);
        assert_eq!(model.streams.blob.unwrap().size, 16);
        assert_eq!(model.streams.guid.unwrap().size, 16);
        assert!(model.table_file_offsets[0x02].is_some());
    }

    #[test]
    fn parses_minimal_cli_metadata_from_pe32_plus() {
        let image = synthetic_managed_pe(true, StreamMutation::None);
        let model = parse_cli_metadata_from_pe(&image, CliSchemaFlavor::Cli4).unwrap();

        assert_eq!(model.flavor, CliSchemaFlavor::Cli4);
        assert_eq!(model.metadata_rva, 0x2100);
        assert_eq!(model.row_counts[0x06], 4);
        assert_eq!(model.row_sizes[0x06], 18);
    }

    #[test]
    fn rejects_duplicate_streams_and_missing_tables_stream() {
        let duplicate = synthetic_managed_pe(false, StreamMutation::DuplicateStrings);
        assert!(matches!(
            parse_cli_metadata_from_pe(&duplicate, CliSchemaFlavor::Classic),
            Err(Error::Malformed("CLI metadata: duplicate stream name"))
        ));

        let missing_tables = synthetic_managed_pe(false, StreamMutation::MissingTables);
        assert!(matches!(
            parse_cli_metadata_from_pe(&missing_tables, CliSchemaFlavor::Classic),
            Err(Error::Malformed("CLI metadata: missing #~ stream"))
        ));
    }

    #[test]
    fn rejects_table_row_data_that_exceeds_stream() {
        let truncated = synthetic_managed_pe(false, StreamMutation::TruncateTables);
        assert!(matches!(
            parse_cli_metadata_from_pe(&truncated, CliSchemaFlavor::Classic),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn parses_optional_real_managed_pe_sample() {
        let Some(path) = optional_real_sample() else {
            return;
        };
        let image = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("read optional sample {}: {error}", path.display()));
        let model = parse_cli_metadata_from_pe(&image, CliSchemaFlavor::Classic)
            .unwrap_or_else(|error| panic!("parse optional sample {}: {error}", path.display()));

        assert!(model.metadata_rva > 0);
        assert!(model.metadata_size > 0);
        assert!(model.version.starts_with('v'));
        assert!(model.streams.strings.is_some());
        assert!(model.streams.blob.is_some());
        assert_ne!(model.valid_table_mask, 0);
        assert!(model.row_counts.iter().any(|&count| count > 0));
        assert!(model.row_sizes.iter().any(|&size| size > 0));
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StreamMutation {
        None,
        DuplicateStrings,
        MissingTables,
        TruncateTables,
    }

    fn synthetic_managed_pe(pe32_plus: bool, mutation: StreamMutation) -> Vec<u8> {
        let mut image = vec![0u8; 0x1000];
        image[0..2].copy_from_slice(b"MZ");
        put_u32(&mut image, 0x3c, 0x80);
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        put_u16(&mut image, 0x84, if pe32_plus { 0x8664 } else { 0x014c });
        put_u16(&mut image, 0x86, 1);
        put_u32(&mut image, 0x88, 0x1234_5678);
        put_u16(&mut image, 0x94, if pe32_plus { 0xf0 } else { 0xe0 });
        put_u16(&mut image, 0x96, 0x210e);

        let opt = 0x98usize;
        if pe32_plus {
            put_u16(&mut image, opt, 0x20b);
            put_u64(&mut image, opt + 24, 0x0000_0001_4000_0000);
            put_u32(&mut image, opt + 56, 0x3000);
            put_u32(&mut image, opt + 108, 16);
            put_u32(&mut image, opt + 112 + 14 * 8, 0x2000);
            put_u32(&mut image, opt + 112 + 14 * 8 + 4, 0x48);
        } else {
            put_u16(&mut image, opt, 0x10b);
            put_u32(&mut image, opt + 28, 0x0040_0000);
            put_u32(&mut image, opt + 56, 0x3000);
            put_u32(&mut image, opt + 92, 16);
            put_u32(&mut image, opt + 96 + 14 * 8, 0x2000);
            put_u32(&mut image, opt + 96 + 14 * 8 + 4, 0x48);
        }

        let section = opt + if pe32_plus { 0xf0 } else { 0xe0 };
        image[section..section + 5].copy_from_slice(b".text");
        put_u32(&mut image, section + 8, 0x1000);
        put_u32(&mut image, section + 12, 0x2000);
        put_u32(&mut image, section + 16, 0x1000);
        put_u32(&mut image, section + 20, 0x200);
        put_u32(&mut image, section + 36, 0x6000_0020);

        put_u32(&mut image, 0x200, 0x48);
        put_u16(&mut image, 0x204, 2);
        put_u16(&mut image, 0x206, 5);
        put_u32(&mut image, 0x208, 0x2100);
        let metadata = build_metadata_root(mutation);
        put_u32(&mut image, 0x20c, metadata.len() as u32);
        put_u32(&mut image, 0x210, 1);
        image[0x300..0x300 + metadata.len()].copy_from_slice(&metadata);
        image
    }

    fn build_metadata_root(mutation: StreamMutation) -> Vec<u8> {
        let table_stream = build_tables_stream(mutation == StreamMutation::TruncateTables);
        let stream_specs = match mutation {
            StreamMutation::DuplicateStrings => vec![
                ("#~", table_stream.clone()),
                ("#Strings", vec![0u8; 32]),
                ("#Strings", vec![0u8; 8]),
                ("#Blob", vec![0u8; 16]),
                ("#GUID", vec![0u8; 16]),
            ],
            StreamMutation::MissingTables => vec![
                ("#Strings", vec![0u8; 32]),
                ("#US", vec![0u8; 4]),
                ("#Blob", vec![0u8; 16]),
                ("#GUID", vec![0u8; 16]),
            ],
            _ => vec![
                ("#~", table_stream),
                ("#Strings", vec![0u8; 32]),
                ("#US", vec![0u8; 4]),
                ("#Blob", vec![0u8; 16]),
                ("#GUID", vec![0u8; 16]),
            ],
        };

        let mut root = Vec::new();
        root.extend_from_slice(b"BSJB");
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&1u16.to_le_bytes());
        root.extend_from_slice(&0u32.to_le_bytes());
        let version = b"v4.0.30319\0";
        root.extend_from_slice(&(version.len() as u32).to_le_bytes());
        root.extend_from_slice(version);
        while root.len() % 4 != 0 {
            root.push(0);
        }
        root.extend_from_slice(&0u16.to_le_bytes());
        root.extend_from_slice(&(stream_specs.len() as u16).to_le_bytes());

        let headers_len = stream_specs
            .iter()
            .map(|(name, _)| 8 + align_4(name.len() + 1))
            .sum::<usize>();
        let mut data_offset = align_4(root.len() + headers_len);
        let mut data_chunks = Vec::new();
        for (name, data) in stream_specs {
            root.extend_from_slice(&(data_offset as u32).to_le_bytes());
            root.extend_from_slice(&(data.len() as u32).to_le_bytes());
            root.extend_from_slice(name.as_bytes());
            root.push(0);
            while root.len() % 4 != 0 {
                root.push(0);
            }
            data_chunks.push((data_offset, data));
            data_offset = align_4(data_offset + data_chunks.last().unwrap().1.len());
        }

        while root.len()
            < data_chunks
                .first()
                .map(|(offset, _)| *offset)
                .unwrap_or(root.len())
        {
            root.push(0);
        }
        for (offset, data) in data_chunks {
            while root.len() < offset {
                root.push(0);
            }
            root.extend_from_slice(&data);
            while root.len() % 4 != 0 {
                root.push(0);
            }
        }
        root
    }

    fn build_tables_stream(truncated: bool) -> Vec<u8> {
        let mut tables = Vec::new();
        tables.extend_from_slice(&0u32.to_le_bytes());
        tables.push(2);
        tables.push(0);
        tables.push(0x05);
        tables.push(1);
        let valid = (1u64 << 0x00) | (1u64 << 0x01) | (1u64 << 0x02) | (1u64 << 0x06);
        tables.extend_from_slice(&valid.to_le_bytes());
        tables.extend_from_slice(&valid.to_le_bytes());
        for count in [1u32, 2, 3, 4] {
            tables.extend_from_slice(&count.to_le_bytes());
        }

        let full_rows_len = 12 + 2 * 10 + 3 * 18 + 4 * 18;
        let rows_len = if truncated {
            full_rows_len - 1
        } else {
            full_rows_len
        };
        tables.resize(tables.len() + rows_len, 0);
        tables
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

    fn optional_real_sample() -> Option<PathBuf> {
        let relative = "notes/genuine-samples/corpus/msil__msil_bgpcore_31bf3856ad364e35_10.0.26100.32522_none_674766aced4cedd0__BGPCore.dll/reference.bin";
        for root in [
            Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf(),
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."),
        ] {
            let candidate = root.join(relative);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
