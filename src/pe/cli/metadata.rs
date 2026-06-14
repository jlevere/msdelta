//! Managed PE CLR metadata root and preprocess-bitstream parsing.

use crate::bitstream::{BitReader, BitWriter};
use crate::pe::cli::blob::read_compressed_u32;
use crate::pe::cli::schema::{
    coded_index_schema, column_width, metadata_schema, row_size, table_schema, CliSchemaFlavor,
    CodedIndexKind, ColumnKind, HeapIndexWidths, HeapKind, TableSchema, TABLE_SENTINEL,
};
use crate::pe::cli::tokens::{
    BlobHeapOffset, GuidHeapIndex, MetadataRid, MetadataTableId, StringsHeapOffset,
    UserStringsHeapOffset,
};
use crate::pe::parse::PeInfo;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliTableRow<'a> {
    table_id: MetadataTableId,
    rid: MetadataRid,
    schema: &'static TableSchema,
    bytes: &'a [u8],
    row_counts: [u32; 64],
    heap_widths: HeapIndexWidths,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliColumnValue {
    U8(u8),
    U16(u16),
    U32(u32),
    Heap {
        kind: HeapKind,
        offset: u32,
    },
    Table {
        table: MetadataTableId,
        rid: Option<MetadataRid>,
    },
    Coded {
        kind: CodedIndexKind,
        raw: u32,
        table: Option<MetadataTableId>,
        rid: Option<MetadataRid>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliMetadataBitstreamStream {
    pub(crate) file_offset: u32,
    pub(crate) size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CliMetadataBitstreamStreams {
    pub(crate) strings: CliMetadataBitstreamStream,
    pub(crate) user_strings: CliMetadataBitstreamStream,
    pub(crate) blob: CliMetadataBitstreamStream,
    pub(crate) guid: CliMetadataBitstreamStream,
    pub(crate) tables: CliMetadataBitstreamStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CliMetadataBitstreamRecord {
    pub(crate) flavor: CliSchemaFlavor,
    pub(crate) present: bool,
    pub(crate) metadata_file_offset: u32,
    pub(crate) metadata_size: u32,
    pub(crate) metadata_rva: u32,
    pub(crate) stream_count: u32,
    pub(crate) stream_headers_end: u32,
    pub(crate) streams: CliMetadataBitstreamStreams,
    pub(crate) heap_widths: HeapIndexWidths,
    pub(crate) valid_table_mask: u64,
    pub(crate) row_counts: [u32; 64],
    pub(crate) row_sizes: [u32; 64],
    pub(crate) table_file_offsets: [Option<usize>; 64],
}

impl CliMetadataBitstreamRecord {
    pub(crate) fn empty(flavor: CliSchemaFlavor) -> Self {
        Self {
            flavor,
            present: false,
            metadata_file_offset: 0,
            metadata_size: 0,
            metadata_rva: 0,
            stream_count: 0,
            stream_headers_end: 0,
            streams: CliMetadataBitstreamStreams::empty(),
            heap_widths: HeapIndexWidths {
                strings: 2,
                guid: 2,
                blob: 2,
            },
            valid_table_mask: 0,
            row_counts: [0; 64],
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.present
    }
}

impl CliMetadataBitstreamStreams {
    const fn empty() -> Self {
        Self {
            strings: CliMetadataBitstreamStream::empty(),
            user_strings: CliMetadataBitstreamStream::empty(),
            blob: CliMetadataBitstreamStream::empty(),
            guid: CliMetadataBitstreamStream::empty(),
            tables: CliMetadataBitstreamStream::empty(),
        }
    }
}

impl CliMetadataBitstreamStream {
    const fn empty() -> Self {
        Self {
            file_offset: 0,
            size: 0,
        }
    }
}

impl CliMetadataModel {
    pub(crate) fn table_row<'a>(
        &self,
        image: &'a [u8],
        table_id: MetadataTableId,
        rid: MetadataRid,
    ) -> Result<CliTableRow<'a>> {
        let table_index = table_id.get() as usize;
        let row_count = self.row_counts[table_index];
        if rid.get() > row_count {
            return Err(Error::Malformed("CLI metadata: row RID is out of range"));
        }

        let row_size = self.row_sizes[table_index] as usize;
        let table_file_offset = self.table_file_offsets[table_index]
            .ok_or(Error::Malformed("CLI metadata: table is not present"))?;
        let row_index = (rid.get() - 1) as usize;
        let row_offset = table_file_offset
            .checked_add(
                row_size
                    .checked_mul(row_index)
                    .ok_or(Error::Malformed("CLI metadata: table row offset overflow"))?,
            )
            .ok_or(Error::Malformed("CLI metadata: table row offset overflow"))?;
        let bytes = checked_slice(image, row_offset, row_size)?;
        let schema = table_schema(table_id.get())
            .ok_or(Error::Malformed("CLI metadata: unknown table schema"))?;

        Ok(CliTableRow {
            table_id,
            rid,
            schema,
            bytes,
            row_counts: self.row_counts,
            heap_widths: self.heap_widths,
        })
    }

    pub(crate) fn table_row_by_id<'a>(
        &self,
        image: &'a [u8],
        table_id: u8,
        rid: u32,
    ) -> Result<CliTableRow<'a>> {
        self.table_row(
            image,
            MetadataTableId::new(table_id)?,
            MetadataRid::new(rid)?,
        )
    }

    pub(crate) fn strings<'a>(
        &self,
        image: &'a [u8],
        offset: StringsHeapOffset,
    ) -> Result<&'a str> {
        let Some(stream) = self.streams.strings else {
            return Err(Error::Malformed("CLI metadata: missing #Strings stream"));
        };
        let heap = cli_heap_stream(image, stream)?;
        let offset = offset.get() as usize;
        if offset == 0 {
            return Ok("");
        }
        let tail = heap.get(offset..).ok_or(Error::Malformed(
            "CLI metadata: #Strings offset is out of range",
        ))?;
        let len = tail
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(Error::Malformed(
                "CLI metadata: unterminated #Strings value",
            ))?;
        std::str::from_utf8(&tail[..len])
            .map_err(|_| Error::Malformed("CLI metadata: #Strings value is not UTF-8"))
    }

    pub(crate) fn blob<'a>(&self, image: &'a [u8], offset: BlobHeapOffset) -> Result<&'a [u8]> {
        let Some(stream) = self.streams.blob else {
            return Err(Error::Malformed("CLI metadata: missing #Blob stream"));
        };
        read_length_prefixed_heap_value(cli_heap_stream(image, stream)?, offset.get())
    }

    pub(crate) fn user_string<'a>(
        &self,
        image: &'a [u8],
        offset: UserStringsHeapOffset,
    ) -> Result<&'a [u8]> {
        let Some(stream) = self.streams.user_strings else {
            return Err(Error::Malformed("CLI metadata: missing #US stream"));
        };
        read_length_prefixed_heap_value(cli_heap_stream(image, stream)?, offset.get())
    }

    pub(crate) fn guid<'a>(
        &self,
        image: &'a [u8],
        index: GuidHeapIndex,
    ) -> Result<Option<&'a [u8]>> {
        let index = index.get();
        if index == 0 {
            return Ok(None);
        }
        let Some(stream) = self.streams.guid else {
            return Err(Error::Malformed("CLI metadata: missing #GUID stream"));
        };
        let heap = cli_heap_stream(image, stream)?;
        let offset = ((index - 1) as usize)
            .checked_mul(16)
            .ok_or(Error::Malformed("CLI metadata: #GUID index overflow"))?;
        checked_slice(heap, offset, 16).map(Some)
    }
}

impl<'a> CliTableRow<'a> {
    pub(crate) const fn table_id(&self) -> MetadataTableId {
        self.table_id
    }

    pub(crate) const fn rid(&self) -> MetadataRid {
        self.rid
    }

    pub(crate) fn column(&self, name: &str) -> Result<CliColumnValue> {
        let index = self
            .schema
            .columns
            .iter()
            .position(|column| column.name == name)
            .ok_or(Error::Malformed("CLI metadata: unknown table column"))?;
        self.column_by_index(index)
    }

    pub(crate) fn column_by_index(&self, index: usize) -> Result<CliColumnValue> {
        let column = self
            .schema
            .columns
            .get(index)
            .ok_or(Error::Malformed("CLI metadata: unknown table column"))?;
        let offset = self
            .schema
            .columns
            .iter()
            .take(index)
            .map(|column| column_width(column.kind, &self.row_counts, self.heap_widths) as usize)
            .sum::<usize>();
        let width = column_width(column.kind, &self.row_counts, self.heap_widths);
        read_column_value(column.kind, self.bytes, offset, width)
    }
}

pub(crate) fn read_cli_metadata_bitstream(
    reader: &mut BitReader<'_>,
    flavor: CliSchemaFlavor,
) -> Result<CliMetadataBitstreamRecord> {
    let present = reader.read_bits(1)? != 0;
    if !present {
        return Ok(CliMetadataBitstreamRecord::empty(flavor));
    }

    let metadata_file_offset = read_u32_bits(reader)?;
    let metadata_size = read_u32_bits(reader)?;
    let metadata_rva = read_u32_bits(reader)?;
    let stream_count = read_u32_bits(reader)?;
    let stream_headers_end = read_u32_bits(reader)?;
    let streams = CliMetadataBitstreamStreams {
        strings: CliMetadataBitstreamStream {
            file_offset: read_u32_bits(reader)?,
            size: read_u32_bits(reader)?,
        },
        user_strings: CliMetadataBitstreamStream {
            file_offset: read_u32_bits(reader)?,
            size: read_u32_bits(reader)?,
        },
        blob: CliMetadataBitstreamStream {
            file_offset: read_u32_bits(reader)?,
            size: read_u32_bits(reader)?,
        },
        guid: CliMetadataBitstreamStream {
            file_offset: read_u32_bits(reader)?,
            size: read_u32_bits(reader)?,
        },
        tables: CliMetadataBitstreamStream {
            file_offset: read_u32_bits(reader)?,
            size: read_u32_bits(reader)?,
        },
    };
    let heap_widths = HeapIndexWidths {
        strings: heap_width_from_bit(reader.read_bits(1)?),
        guid: heap_width_from_bit(reader.read_bits(1)?),
        blob: heap_width_from_bit(reader.read_bits(1)?),
    };
    let valid_table_mask = reader.read_bits(64)?;
    let mut row_counts = [0u32; 64];
    for (table_id, row_count) in row_counts.iter_mut().enumerate() {
        if valid_table_mask & (1u64 << table_id) == 0 {
            continue;
        }
        if metadata_schema(flavor)
            .tables
            .iter()
            .all(|schema| schema.id != table_id as u8)
        {
            return Err(Error::Malformed("CLI metadata: unknown present table id"));
        }
        *row_count = read_u32_bits(reader)?;
    }

    build_cli_metadata_bitstream_record(CliMetadataBitstreamRecord {
        flavor,
        present,
        metadata_file_offset,
        metadata_size,
        metadata_rva,
        stream_count,
        stream_headers_end,
        streams,
        heap_widths,
        valid_table_mask,
        row_counts,
        row_sizes: [0; 64],
        table_file_offsets: [None; 64],
    })
}

pub(crate) fn write_cli_metadata_bitstream(
    writer: &mut BitWriter,
    record: &CliMetadataBitstreamRecord,
) {
    writer.write_bits(record.present as u64, 1);
    if !record.present {
        return;
    }

    for value in [
        record.metadata_file_offset,
        record.metadata_size,
        record.metadata_rva,
        record.stream_count,
        record.stream_headers_end,
        record.streams.strings.file_offset,
        record.streams.strings.size,
        record.streams.user_strings.file_offset,
        record.streams.user_strings.size,
        record.streams.blob.file_offset,
        record.streams.blob.size,
        record.streams.guid.file_offset,
        record.streams.guid.size,
        record.streams.tables.file_offset,
        record.streams.tables.size,
    ] {
        writer.write_bits(value as u64, 32);
    }
    writer.write_bits((record.heap_widths.strings == 4) as u64, 1);
    writer.write_bits((record.heap_widths.guid == 4) as u64, 1);
    writer.write_bits((record.heap_widths.blob == 4) as u64, 1);
    writer.write_bits(record.valid_table_mask, 64);
    for (table_id, row_count) in record.row_counts.iter().enumerate() {
        if record.valid_table_mask & (1u64 << table_id) != 0 {
            writer.write_bits(*row_count as u64, 32);
        }
    }
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

    let clr_file_offset = pe
        .rva_to_file_offset(clr_rva)
        .ok_or(Error::Malformed("PE: CLR runtime header RVA is unmapped"))?;
    checked_slice(image, clr_file_offset, 0x48)?;
    let metadata_rva = read_u32(image, clr_file_offset + COR20_METADATA_RVA_OFFSET)?;
    let metadata_size = read_u32(image, clr_file_offset + COR20_METADATA_SIZE_OFFSET)?;
    if metadata_rva == 0 || metadata_size == 0 {
        return Err(Error::Malformed("CLI metadata: empty metadata directory"));
    }

    let metadata_file_offset = pe
        .rva_to_file_offset(metadata_rva)
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

fn build_cli_metadata_bitstream_record(
    mut record: CliMetadataBitstreamRecord,
) -> Result<CliMetadataBitstreamRecord> {
    if record.metadata_size == 0 {
        return Err(Error::Malformed("CLI metadata: empty metadata directory"));
    }
    if record.stream_count == 0 {
        return Err(Error::Malformed("CLI metadata: no streams"));
    }
    validate_file_range(
        record.metadata_file_offset,
        record.metadata_size,
        record.stream_headers_end,
        0,
    )?;
    validate_file_range(
        record.metadata_file_offset,
        record.metadata_size,
        record.streams.tables.file_offset,
        record.streams.tables.size,
    )?;
    for stream in [
        record.streams.strings,
        record.streams.user_strings,
        record.streams.blob,
        record.streams.guid,
    ] {
        if stream.file_offset != 0 || stream.size != 0 {
            validate_file_range(
                record.metadata_file_offset,
                record.metadata_size,
                stream.file_offset,
                stream.size,
            )?;
        }
    }

    let mut cursor = 24usize;
    for table_id in 0..64u8 {
        if record.valid_table_mask & (1u64 << table_id) != 0 {
            cursor = cursor
                .checked_add(4)
                .ok_or(Error::Malformed("CLI metadata: table byte size overflow"))?;
        }
    }
    let table_stream_size = record.streams.tables.size as usize;
    if cursor > table_stream_size {
        return Err(Error::Malformed("CLI metadata: table stream is too small"));
    }

    let tables_file_offset = record.streams.tables.file_offset as usize;
    for table_id in 0..64u8 {
        let row_count = record.row_counts[table_id as usize];
        if row_count == 0 {
            continue;
        }
        let row_size = row_size(table_id, &record.row_counts, record.heap_widths)
            .ok_or(Error::Malformed("CLI metadata: unknown table schema"))?;
        record.row_sizes[table_id as usize] = row_size as u32;
        record.table_file_offsets[table_id as usize] = Some(
            tables_file_offset
                .checked_add(cursor)
                .ok_or(Error::Malformed("CLI metadata: table file offset overflow"))?,
        );
        let table_bytes = row_size
            .checked_mul(row_count as usize)
            .ok_or(Error::Malformed("CLI metadata: table byte size overflow"))?;
        cursor = cursor
            .checked_add(table_bytes)
            .ok_or(Error::Malformed("CLI metadata: table byte size overflow"))?;
        if cursor > table_stream_size {
            return Err(Error::Malformed("CLI metadata: table stream is too small"));
        }
    }

    Ok(record)
}

fn validate_file_range(
    metadata_file_offset: u32,
    metadata_size: u32,
    file_offset: u32,
    size: u32,
) -> Result<()> {
    let metadata_end = metadata_file_offset
        .checked_add(metadata_size)
        .ok_or(Error::Malformed(
            "CLI metadata: stream file offset overflow",
        ))?;
    let stream_end = file_offset.checked_add(size).ok_or(Error::Malformed(
        "CLI metadata: stream file offset overflow",
    ))?;
    if file_offset < metadata_file_offset || stream_end > metadata_end {
        return Err(Error::Malformed("CLI metadata: stream exceeds metadata"));
    }
    Ok(())
}

fn read_u32_bits(reader: &mut BitReader<'_>) -> Result<u32> {
    Ok(reader.read_bits(32)? as u32)
}

const fn heap_width_from_bit(bit: u64) -> u8 {
    if bit == 0 {
        2
    } else {
        4
    }
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

fn read_column_value(
    kind: ColumnKind,
    row: &[u8],
    offset: usize,
    width: u8,
) -> Result<CliColumnValue> {
    let raw = read_column_unsigned(row, offset, width)?;
    match kind {
        ColumnKind::U8 => Ok(CliColumnValue::U8(raw as u8)),
        ColumnKind::U16 => Ok(CliColumnValue::U16(raw as u16)),
        ColumnKind::U32 => Ok(CliColumnValue::U32(raw)),
        ColumnKind::Heap(kind) => Ok(CliColumnValue::Heap { kind, offset: raw }),
        ColumnKind::Table(table_id) => {
            let table = MetadataTableId::new(table_id)?;
            let rid = if raw == 0 {
                None
            } else {
                Some(MetadataRid::new(raw)?)
            };
            Ok(CliColumnValue::Table { table, rid })
        }
        ColumnKind::Coded(kind) => decode_coded_index(kind, raw),
    }
}

fn decode_coded_index(kind: CodedIndexKind, raw: u32) -> Result<CliColumnValue> {
    let schema = coded_index_schema(kind);
    let tag_mask = (1u32 << schema.tag_bits) - 1;
    let tag = (raw & tag_mask) as usize;
    let rid_raw = raw >> schema.tag_bits;
    let table_raw = *schema
        .tag_to_table
        .get(tag)
        .ok_or(Error::Malformed("CLI metadata: invalid coded-index tag"))?;
    if rid_raw == 0 {
        return Ok(CliColumnValue::Coded {
            kind,
            raw,
            table: None,
            rid: None,
        });
    }
    if table_raw == TABLE_SENTINEL {
        return Err(Error::Malformed(
            "CLI metadata: coded-index tag has no target table",
        ));
    }

    Ok(CliColumnValue::Coded {
        kind,
        raw,
        table: Some(MetadataTableId::new(table_raw)?),
        rid: Some(MetadataRid::new(rid_raw)?),
    })
}

fn read_column_unsigned(row: &[u8], offset: usize, width: u8) -> Result<u32> {
    match width {
        1 => Ok(*checked_slice(row, offset, 1)?.first().unwrap() as u32),
        2 => Ok(read_u16(row, offset)? as u32),
        4 => read_u32(row, offset),
        _ => Err(Error::Malformed("CLI metadata: invalid column width")),
    }
}

fn cli_heap_stream(image: &[u8], stream: CliStream) -> Result<&[u8]> {
    checked_slice(image, stream.file_offset, stream.size as usize)
}

fn read_length_prefixed_heap_value(heap: &[u8], offset: u32) -> Result<&[u8]> {
    let offset = offset as usize;
    if offset == 0 {
        return Ok(&heap[..0]);
    }
    let tail = heap.get(offset..).ok_or(Error::Malformed(
        "CLI metadata: heap offset is out of range",
    ))?;
    let (len, header_len) = read_compressed_u32(tail)?;
    let payload_offset = offset
        .checked_add(header_len)
        .ok_or(Error::Malformed("CLI metadata: heap value offset overflow"))?;
    checked_slice(heap, payload_offset, len as usize)
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
    use serde::Deserialize;
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
        assert_eq!(model.streams.user_strings.unwrap().size, 7);
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
    fn reads_typed_table_rows_and_heap_values() {
        let image = synthetic_managed_pe(false, StreamMutation::None);
        let model = parse_cli_metadata_from_pe(&image, CliSchemaFlavor::Classic).unwrap();

        let method = model.table_row_by_id(&image, 0x06, 1).unwrap();
        assert_eq!(method.table_id().get(), 0x06);
        assert_eq!(method.rid().get(), 1);
        assert_eq!(method.column("Rva").unwrap(), CliColumnValue::U32(0x2222));
        assert_eq!(method.column("ImplFlags").unwrap(), CliColumnValue::U16(1));
        assert_eq!(method.column("Flags").unwrap(), CliColumnValue::U16(6));
        assert_eq!(
            method.column("Name").unwrap(),
            CliColumnValue::Heap {
                kind: HeapKind::Strings,
                offset: 25
            }
        );
        assert_eq!(
            method.column("Signature").unwrap(),
            CliColumnValue::Heap {
                kind: HeapKind::Blob,
                offset: 1
            }
        );
        assert_eq!(
            model.strings(&image, StringsHeapOffset::new(25)).unwrap(),
            "Method"
        );
        assert_eq!(
            model.blob(&image, BlobHeapOffset::new(1)).unwrap(),
            &[0x11, 0x22, 0x33]
        );

        let typedef = model.table_row_by_id(&image, 0x02, 1).unwrap();
        assert_eq!(
            typedef.column("Extends").unwrap(),
            CliColumnValue::Coded {
                kind: CodedIndexKind::TypeDefOrRef,
                raw: 5,
                table: Some(MetadataTableId::new(0x01).unwrap()),
                rid: Some(MetadataRid::new(1).unwrap()),
            }
        );
        assert_eq!(
            model.strings(&image, StringsHeapOffset::new(17)).unwrap(),
            "TypeDef"
        );

        let module = model.table_row_by_id(&image, 0x00, 1).unwrap();
        assert_eq!(
            module.column("Mvid").unwrap(),
            CliColumnValue::Heap {
                kind: HeapKind::Guid,
                offset: 1
            }
        );
        assert_eq!(
            model.guid(&image, GuidHeapIndex::new(1)).unwrap().unwrap(),
            &[0xab; 16]
        );
        assert_eq!(
            model
                .user_string(&image, UserStringsHeapOffset::new(1))
                .unwrap(),
            &[b'O', 0, b'K', 0, 0]
        );
    }

    #[test]
    fn rejects_typed_table_row_outside_present_range() {
        let image = synthetic_managed_pe(false, StreamMutation::None);
        let model = parse_cli_metadata_from_pe(&image, CliSchemaFlavor::Classic).unwrap();

        assert!(matches!(
            model.table_row_by_id(&image, 0x06, 5),
            Err(Error::Malformed("CLI metadata: row RID is out of range"))
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

    #[test]
    fn cli_metadata_bitstream_matches_win26100_stage_fixture_objects() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/atoms/FridaStageCapture/cli-metadata-win26100");
        let object_dir = fixture.join("objects");
        let blob_dir = fixture.join("blobs");
        if !object_dir.exists() {
            return;
        }

        let mut paths = std::fs::read_dir(&object_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(paths.len(), 50);

        let mut present = 0usize;
        let mut empty = 0usize;
        for path in paths {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let native: NativeCliMetadataRecord = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
            assert_eq!(native.record_type, "CliMetadataBitstreamRecord");
            assert_eq!(
                native.native_layout,
                "msdelta-win26100-compo-cli-metadata-v1"
            );

            let expected = native_to_bitstream_record(&native, &path);
            if expected.present {
                present += 1;
            } else {
                empty += 1;
            }

            let stem = path
                .file_stem()
                .and_then(|value| value.to_str())
                .unwrap_or_else(|| {
                    panic!("fixture object path has no UTF-8 stem: {}", path.display())
                });
            let blob_path = blob_dir.join(format!("{stem}-reader-bitstream.bin"));
            let bytes = std::fs::read(&blob_path)
                .unwrap_or_else(|error| panic!("read {}: {error}", blob_path.display()));
            let mut reader = BitReader::new(&bytes).unwrap();
            let parsed = read_cli_metadata_bitstream(&mut reader, CliSchemaFlavor::Classic)
                .unwrap_or_else(|error| {
                    panic!(
                        "parse native reader bitstream for {}: {error}",
                        blob_path.display()
                    )
                });
            assert_eq!(reader.remaining(), 0, "{} left unread bits", path.display());
            assert_eq!(parsed, expected, "{}", path.display());

            let mut writer = BitWriter::new();
            write_cli_metadata_bitstream(&mut writer, &expected);
            assert_eq!(
                writer.finish(),
                bytes,
                "writer should reproduce native reader bitstream {}",
                blob_path.display()
            );

            if parsed.present {
                assert!(
                    parsed.row_sizes.iter().any(|&size| size > 0),
                    "{} should derive row sizes",
                    path.display()
                );
                assert!(
                    parsed.table_file_offsets.iter().any(Option::is_some),
                    "{} should derive table offsets",
                    path.display()
                );
            }
        }

        assert!(present > 0, "stage fixture should include present records");
        assert!(empty > 0, "stage fixture should include empty records");
    }

    #[test]
    fn cli_metadata_bitstream_rejects_unknown_present_table() {
        let mut writer = BitWriter::new();
        writer.write_bits(1, 1);
        for value in [
            0x100u32, 0x200, 0, 1, 0x120, 0x120, 0x10, 0, 0, 0x130, 0x10, 0x140, 0x10, 0x150, 0x80,
        ] {
            writer.write_bits(value as u64, 32);
        }
        writer.write_bits(0, 1);
        writer.write_bits(0, 1);
        writer.write_bits(0, 1);
        writer.write_bits(1u64 << 63, 64);
        writer.write_bits(1, 32);

        let bytes = writer.finish();
        let mut reader = BitReader::new(&bytes).unwrap();
        assert!(matches!(
            read_cli_metadata_bitstream(&mut reader, CliSchemaFlavor::Classic),
            Err(Error::Malformed("CLI metadata: unknown present table id"))
        ));
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
                ("#Strings", strings_heap()),
                ("#Strings", vec![0u8; 8]),
                ("#Blob", blob_heap()),
                ("#GUID", guid_heap()),
            ],
            StreamMutation::MissingTables => vec![
                ("#Strings", strings_heap()),
                ("#US", user_strings_heap()),
                ("#Blob", blob_heap()),
                ("#GUID", guid_heap()),
            ],
            _ => vec![
                ("#~", table_stream),
                ("#Strings", strings_heap()),
                ("#US", user_strings_heap()),
                ("#Blob", blob_heap()),
                ("#GUID", guid_heap()),
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

    fn strings_heap() -> Vec<u8> {
        b"\0Module\0TypeName\0TypeDef\0Method\0".to_vec()
    }

    fn user_strings_heap() -> Vec<u8> {
        vec![0, 5, b'O', 0, b'K', 0, 0]
    }

    fn blob_heap() -> Vec<u8> {
        let mut heap = vec![0, 3, 0x11, 0x22, 0x33];
        heap.resize(16, 0);
        heap
    }

    fn guid_heap() -> Vec<u8> {
        vec![0xab; 16]
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
        let mut rows = vec![0u8; full_rows_len];

        put_u16(&mut rows, 0, 1);
        put_u32(&mut rows, 2, 1);
        put_u16(&mut rows, 6, 1);

        let type_ref0 = 12;
        put_u32(&mut rows, type_ref0 + 2, 8);

        let type_def0 = 12 + 2 * 10;
        put_u32(&mut rows, type_def0, 0x0012_3456);
        put_u32(&mut rows, type_def0 + 4, 17);
        put_u16(&mut rows, type_def0 + 12, (1 << 2) | 1);
        put_u16(&mut rows, type_def0 + 14, 1);
        put_u16(&mut rows, type_def0 + 16, 1);

        let method0 = 12 + 2 * 10 + 3 * 18;
        put_u32(&mut rows, method0, 0x2222);
        put_u16(&mut rows, method0 + 4, 1);
        put_u16(&mut rows, method0 + 6, 6);
        put_u32(&mut rows, method0 + 8, 25);
        put_u32(&mut rows, method0 + 12, 1);
        put_u16(&mut rows, method0 + 16, 1);

        if truncated {
            rows.pop();
        }
        tables.extend_from_slice(&rows);
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

    #[derive(Debug, Deserialize)]
    struct NativeCliMetadataRecord {
        #[serde(rename = "type")]
        record_type: String,
        native_layout: String,
        present: bool,
        metadata_file_offset: u32,
        metadata_size: u32,
        metadata_rva: u32,
        stream_count: u32,
        stream_headers_end: u32,
        streams: NativeCliStreams,
        heap_widths: NativeHeapWidths,
        valid_table_mask: String,
        row_counts: Vec<u32>,
    }

    #[derive(Debug, Deserialize)]
    struct NativeCliStreams {
        strings: NativeCliStream,
        user_strings: NativeCliStream,
        blob: NativeCliStream,
        guid: NativeCliStream,
        tables: NativeCliStream,
    }

    #[derive(Debug, Clone, Copy, Deserialize)]
    struct NativeCliStream {
        offset: u32,
        size: u32,
    }

    #[derive(Debug, Deserialize)]
    struct NativeHeapWidths {
        strings: bool,
        guid: bool,
        blob: bool,
    }

    fn native_to_bitstream_record(
        native: &NativeCliMetadataRecord,
        path: &Path,
    ) -> CliMetadataBitstreamRecord {
        assert_eq!(
            native.row_counts.len(),
            64,
            "{} should have 64 row counts",
            path.display()
        );
        let mut row_counts = [0u32; 64];
        row_counts.copy_from_slice(&native.row_counts);
        let valid_table_mask = u64::from_str_radix(
            native
                .valid_table_mask
                .strip_prefix("0x")
                .unwrap_or(&native.valid_table_mask),
            16,
        )
        .unwrap_or_else(|error| panic!("parse mask for {}: {error}", path.display()));

        if !native.present {
            return CliMetadataBitstreamRecord::empty(CliSchemaFlavor::Classic);
        }

        build_cli_metadata_bitstream_record(CliMetadataBitstreamRecord {
            flavor: CliSchemaFlavor::Classic,
            present: native.present,
            metadata_file_offset: native.metadata_file_offset,
            metadata_size: native.metadata_size,
            metadata_rva: native.metadata_rva,
            stream_count: native.stream_count,
            stream_headers_end: native.stream_headers_end,
            streams: CliMetadataBitstreamStreams {
                strings: native_stream(native.streams.strings),
                user_strings: native_stream(native.streams.user_strings),
                blob: native_stream(native.streams.blob),
                guid: native_stream(native.streams.guid),
                tables: native_stream(native.streams.tables),
            },
            heap_widths: HeapIndexWidths {
                strings: native_heap_width(native.heap_widths.strings),
                guid: native_heap_width(native.heap_widths.guid),
                blob: native_heap_width(native.heap_widths.blob),
            },
            valid_table_mask,
            row_counts,
            row_sizes: [0; 64],
            table_file_offsets: [None; 64],
        })
        .unwrap_or_else(|error| panic!("build expected record for {}: {error}", path.display()))
    }

    const fn native_stream(stream: NativeCliStream) -> CliMetadataBitstreamStream {
        CliMetadataBitstreamStream {
            file_offset: stream.offset,
            size: stream.size,
        }
    }

    const fn native_heap_width(is_wide: bool) -> u8 {
        if is_wide {
            4
        } else {
            2
        }
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
