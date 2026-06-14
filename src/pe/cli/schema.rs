//! Static ECMA-335 metadata schema used by the managed PE transform atoms.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliSchemaFlavor {
    Classic,
    Cli4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeapKind {
    Strings,
    Guid,
    Blob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeapIndexWidths {
    pub(crate) strings: u8,
    pub(crate) guid: u8,
    pub(crate) blob: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CodedIndexKind {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColumnKind {
    U8,
    U16,
    U32,
    Heap(HeapKind),
    Table(u8),
    Coded(CodedIndexKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ColumnSchema {
    pub(crate) name: &'static str,
    pub(crate) kind: ColumnKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableSchema {
    pub(crate) id: u8,
    pub(crate) name: &'static str,
    pub(crate) columns: &'static [ColumnSchema],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CodedIndexSchema {
    pub(crate) kind: CodedIndexKind,
    pub(crate) name: &'static str,
    pub(crate) tag_bits: u8,
    pub(crate) tag_to_table: &'static [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MetadataSchema {
    pub(crate) flavor: CliSchemaFlavor,
    pub(crate) metadata_kind: &'static str,
    pub(crate) tables: &'static [TableSchema],
    pub(crate) coded_indexes: &'static [CodedIndexSchema],
}

pub(crate) const TABLE_SENTINEL: u8 = 0x40;

const MODULE_COLUMNS: &[ColumnSchema] = &[
    col("Generation", ColumnKind::U16),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Mvid", ColumnKind::Heap(HeapKind::Guid)),
    col("EncId", ColumnKind::Heap(HeapKind::Guid)),
    col("EncBaseId", ColumnKind::Heap(HeapKind::Guid)),
];

const TYPEREF_COLUMNS: &[ColumnSchema] = &[
    col(
        "ResolutionScope",
        ColumnKind::Coded(CodedIndexKind::ResolutionScope),
    ),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Namespace", ColumnKind::Heap(HeapKind::Strings)),
];

const TYPEDEF_COLUMNS: &[ColumnSchema] = &[
    col("Flags", ColumnKind::U32),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Namespace", ColumnKind::Heap(HeapKind::Strings)),
    col("Extends", ColumnKind::Coded(CodedIndexKind::TypeDefOrRef)),
    col("FieldList", ColumnKind::Table(0x04)),
    col("MethodList", ColumnKind::Table(0x06)),
];

const FIELD_PTR_COLUMNS: &[ColumnSchema] = &[col("Field", ColumnKind::Table(0x04))];

const FIELD_COLUMNS: &[ColumnSchema] = &[
    col("Flags", ColumnKind::U16),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Signature", ColumnKind::Heap(HeapKind::Blob)),
];

const METHOD_PTR_COLUMNS: &[ColumnSchema] = &[col("Method", ColumnKind::Table(0x06))];

const METHOD_DEF_COLUMNS: &[ColumnSchema] = &[
    col("Rva", ColumnKind::U32),
    col("ImplFlags", ColumnKind::U16),
    col("Flags", ColumnKind::U16),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Signature", ColumnKind::Heap(HeapKind::Blob)),
    col("ParamList", ColumnKind::Table(0x08)),
];

const PARAM_PTR_COLUMNS: &[ColumnSchema] = &[col("Param", ColumnKind::Table(0x08))];

const PARAM_COLUMNS: &[ColumnSchema] = &[
    col("Flags", ColumnKind::U16),
    col("Sequence", ColumnKind::U16),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
];

const INTERFACE_IMPL_COLUMNS: &[ColumnSchema] = &[
    col("Class", ColumnKind::Table(0x02)),
    col("Interface", ColumnKind::Coded(CodedIndexKind::TypeDefOrRef)),
];

const MEMBER_REF_COLUMNS: &[ColumnSchema] = &[
    col("Class", ColumnKind::Coded(CodedIndexKind::MemberRefParent)),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Signature", ColumnKind::Heap(HeapKind::Blob)),
];

const CONSTANT_COLUMNS: &[ColumnSchema] = &[
    col("Type", ColumnKind::U8),
    col("Padding", ColumnKind::U8),
    col("Parent", ColumnKind::Coded(CodedIndexKind::HasConstant)),
    col("Value", ColumnKind::Heap(HeapKind::Blob)),
];

const CUSTOM_ATTRIBUTE_COLUMNS: &[ColumnSchema] = &[
    col(
        "Parent",
        ColumnKind::Coded(CodedIndexKind::HasCustomAttribute),
    ),
    col(
        "Type",
        ColumnKind::Coded(CodedIndexKind::CustomAttributeType),
    ),
    col("Value", ColumnKind::Heap(HeapKind::Blob)),
];

const FIELD_MARSHAL_COLUMNS: &[ColumnSchema] = &[
    col("Parent", ColumnKind::Coded(CodedIndexKind::HasFieldMarshal)),
    col("NativeType", ColumnKind::Heap(HeapKind::Blob)),
];

const DECL_SECURITY_COLUMNS: &[ColumnSchema] = &[
    col("Action", ColumnKind::U16),
    col("Parent", ColumnKind::Coded(CodedIndexKind::HasDeclSecurity)),
    col("PermissionSet", ColumnKind::Heap(HeapKind::Blob)),
];

const CLASS_LAYOUT_COLUMNS: &[ColumnSchema] = &[
    col("PackingSize", ColumnKind::U16),
    col("ClassSize", ColumnKind::U32),
    col("Parent", ColumnKind::Table(0x02)),
];

const FIELD_LAYOUT_COLUMNS: &[ColumnSchema] = &[
    col("Offset", ColumnKind::U32),
    col("Field", ColumnKind::Table(0x04)),
];

const STANDALONE_SIG_COLUMNS: &[ColumnSchema] =
    &[col("Signature", ColumnKind::Heap(HeapKind::Blob))];

const EVENT_MAP_COLUMNS: &[ColumnSchema] = &[
    col("Parent", ColumnKind::Table(0x02)),
    col("EventList", ColumnKind::Table(0x14)),
];

const EVENT_PTR_COLUMNS: &[ColumnSchema] = &[col("Event", ColumnKind::Table(0x14))];

const EVENT_COLUMNS: &[ColumnSchema] = &[
    col("EventFlags", ColumnKind::U16),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("EventType", ColumnKind::Coded(CodedIndexKind::TypeDefOrRef)),
];

const PROPERTY_MAP_COLUMNS: &[ColumnSchema] = &[
    col("Parent", ColumnKind::Table(0x02)),
    col("PropertyList", ColumnKind::Table(0x17)),
];

const PROPERTY_PTR_COLUMNS: &[ColumnSchema] = &[col("Property", ColumnKind::Table(0x17))];

const PROPERTY_COLUMNS: &[ColumnSchema] = &[
    col("Flags", ColumnKind::U16),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Type", ColumnKind::Heap(HeapKind::Blob)),
];

const METHOD_SEMANTICS_COLUMNS: &[ColumnSchema] = &[
    col("Semantics", ColumnKind::U16),
    col("Method", ColumnKind::Table(0x06)),
    col(
        "Association",
        ColumnKind::Coded(CodedIndexKind::HasSemantics),
    ),
];

const METHOD_IMPL_COLUMNS: &[ColumnSchema] = &[
    col("Class", ColumnKind::Table(0x02)),
    col(
        "MethodBody",
        ColumnKind::Coded(CodedIndexKind::MethodDefOrRef),
    ),
    col(
        "MethodDeclaration",
        ColumnKind::Coded(CodedIndexKind::MethodDefOrRef),
    ),
];

const MODULE_REF_COLUMNS: &[ColumnSchema] = &[col("Name", ColumnKind::Heap(HeapKind::Strings))];

const TYPE_SPEC_COLUMNS: &[ColumnSchema] = &[col("Signature", ColumnKind::Heap(HeapKind::Blob))];

const IMPL_MAP_COLUMNS: &[ColumnSchema] = &[
    col("MappingFlags", ColumnKind::U16),
    col(
        "MemberForwarded",
        ColumnKind::Coded(CodedIndexKind::MemberForwarded),
    ),
    col("ImportName", ColumnKind::Heap(HeapKind::Strings)),
    col("ImportScope", ColumnKind::Table(0x1a)),
];

const FIELD_RVA_COLUMNS: &[ColumnSchema] = &[
    col("Rva", ColumnKind::U32),
    col("Field", ColumnKind::Table(0x04)),
];

const ENC_LOG_COLUMNS: &[ColumnSchema] = &[
    col("Token", ColumnKind::U32),
    col("FuncCode", ColumnKind::U32),
];

const ENC_MAP_COLUMNS: &[ColumnSchema] = &[col("Token", ColumnKind::U32)];

const ASSEMBLY_COLUMNS: &[ColumnSchema] = &[
    col("HashAlgId", ColumnKind::U32),
    col("MajorVersion", ColumnKind::U16),
    col("MinorVersion", ColumnKind::U16),
    col("BuildNumber", ColumnKind::U16),
    col("RevisionNumber", ColumnKind::U16),
    col("Flags", ColumnKind::U32),
    col("PublicKey", ColumnKind::Heap(HeapKind::Blob)),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Culture", ColumnKind::Heap(HeapKind::Strings)),
];

const ASSEMBLY_PROCESSOR_COLUMNS: &[ColumnSchema] = &[col("Processor", ColumnKind::U32)];

const ASSEMBLY_OS_COLUMNS: &[ColumnSchema] = &[
    col("OSPlatformId", ColumnKind::U32),
    col("OSMajorVersion", ColumnKind::U32),
    col("OSMinorVersion", ColumnKind::U32),
];

const ASSEMBLY_REF_COLUMNS: &[ColumnSchema] = &[
    col("MajorVersion", ColumnKind::U16),
    col("MinorVersion", ColumnKind::U16),
    col("BuildNumber", ColumnKind::U16),
    col("RevisionNumber", ColumnKind::U16),
    col("Flags", ColumnKind::U32),
    col("PublicKeyOrToken", ColumnKind::Heap(HeapKind::Blob)),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("Culture", ColumnKind::Heap(HeapKind::Strings)),
    col("HashValue", ColumnKind::Heap(HeapKind::Blob)),
];

const ASSEMBLY_REF_PROCESSOR_COLUMNS: &[ColumnSchema] = &[
    col("Processor", ColumnKind::U32),
    col("AssemblyRef", ColumnKind::Table(0x23)),
];

const ASSEMBLY_REF_OS_COLUMNS: &[ColumnSchema] = &[
    col("OSPlatformId", ColumnKind::U32),
    col("OSMajorVersion", ColumnKind::U32),
    col("OSMinorVersion", ColumnKind::U32),
    col("AssemblyRef", ColumnKind::Table(0x23)),
];

const FILE_COLUMNS: &[ColumnSchema] = &[
    col("Flags", ColumnKind::U32),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col("HashValue", ColumnKind::Heap(HeapKind::Blob)),
];

const EXPORTED_TYPE_COLUMNS: &[ColumnSchema] = &[
    col("Flags", ColumnKind::U32),
    col("TypeDefId", ColumnKind::U32),
    col("TypeName", ColumnKind::Heap(HeapKind::Strings)),
    col("TypeNamespace", ColumnKind::Heap(HeapKind::Strings)),
    col(
        "Implementation",
        ColumnKind::Coded(CodedIndexKind::Implementation),
    ),
];

const MANIFEST_RESOURCE_COLUMNS: &[ColumnSchema] = &[
    col("Offset", ColumnKind::U32),
    col("Flags", ColumnKind::U32),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
    col(
        "Implementation",
        ColumnKind::Coded(CodedIndexKind::Implementation),
    ),
];

const NESTED_CLASS_COLUMNS: &[ColumnSchema] = &[
    col("NestedClass", ColumnKind::Table(0x02)),
    col("EnclosingClass", ColumnKind::Table(0x02)),
];

const GENERIC_PARAM_COLUMNS: &[ColumnSchema] = &[
    col("Number", ColumnKind::U16),
    col("Flags", ColumnKind::U16),
    col("Owner", ColumnKind::Coded(CodedIndexKind::TypeOrMethodDef)),
    col("Name", ColumnKind::Heap(HeapKind::Strings)),
];

const METHOD_SPEC_COLUMNS: &[ColumnSchema] = &[
    col("Method", ColumnKind::Coded(CodedIndexKind::MethodDefOrRef)),
    col("Instantiation", ColumnKind::Heap(HeapKind::Blob)),
];

const GENERIC_PARAM_CONSTRAINT_COLUMNS: &[ColumnSchema] = &[
    col("Owner", ColumnKind::Table(0x2a)),
    col(
        "Constraint",
        ColumnKind::Coded(CodedIndexKind::TypeDefOrRef),
    ),
];

pub(crate) const METADATA_TABLES: &[TableSchema] = &[
    table(0x00, "Module", MODULE_COLUMNS),
    table(0x01, "TypeRef", TYPEREF_COLUMNS),
    table(0x02, "TypeDef", TYPEDEF_COLUMNS),
    table(0x03, "FieldPtr", FIELD_PTR_COLUMNS),
    table(0x04, "Field", FIELD_COLUMNS),
    table(0x05, "MethodPtr", METHOD_PTR_COLUMNS),
    table(0x06, "MethodDef", METHOD_DEF_COLUMNS),
    table(0x07, "ParamPtr", PARAM_PTR_COLUMNS),
    table(0x08, "Param", PARAM_COLUMNS),
    table(0x09, "InterfaceImpl", INTERFACE_IMPL_COLUMNS),
    table(0x0a, "MemberRef", MEMBER_REF_COLUMNS),
    table(0x0b, "Constant", CONSTANT_COLUMNS),
    table(0x0c, "CustomAttribute", CUSTOM_ATTRIBUTE_COLUMNS),
    table(0x0d, "FieldMarshal", FIELD_MARSHAL_COLUMNS),
    table(0x0e, "DeclSecurity", DECL_SECURITY_COLUMNS),
    table(0x0f, "ClassLayout", CLASS_LAYOUT_COLUMNS),
    table(0x10, "FieldLayout", FIELD_LAYOUT_COLUMNS),
    table(0x11, "StandAloneSig", STANDALONE_SIG_COLUMNS),
    table(0x12, "EventMap", EVENT_MAP_COLUMNS),
    table(0x13, "EventPtr", EVENT_PTR_COLUMNS),
    table(0x14, "Event", EVENT_COLUMNS),
    table(0x15, "PropertyMap", PROPERTY_MAP_COLUMNS),
    table(0x16, "PropertyPtr", PROPERTY_PTR_COLUMNS),
    table(0x17, "Property", PROPERTY_COLUMNS),
    table(0x18, "MethodSemantics", METHOD_SEMANTICS_COLUMNS),
    table(0x19, "MethodImpl", METHOD_IMPL_COLUMNS),
    table(0x1a, "ModuleRef", MODULE_REF_COLUMNS),
    table(0x1b, "TypeSpec", TYPE_SPEC_COLUMNS),
    table(0x1c, "ImplMap", IMPL_MAP_COLUMNS),
    table(0x1d, "FieldRVA", FIELD_RVA_COLUMNS),
    table(0x1e, "ENCLog", ENC_LOG_COLUMNS),
    table(0x1f, "ENCMap", ENC_MAP_COLUMNS),
    table(0x20, "Assembly", ASSEMBLY_COLUMNS),
    table(0x21, "AssemblyProcessor", ASSEMBLY_PROCESSOR_COLUMNS),
    table(0x22, "AssemblyOS", ASSEMBLY_OS_COLUMNS),
    table(0x23, "AssemblyRef", ASSEMBLY_REF_COLUMNS),
    table(0x24, "AssemblyRefProcessor", ASSEMBLY_REF_PROCESSOR_COLUMNS),
    table(0x25, "AssemblyRefOS", ASSEMBLY_REF_OS_COLUMNS),
    table(0x26, "File", FILE_COLUMNS),
    table(0x27, "ExportedType", EXPORTED_TYPE_COLUMNS),
    table(0x28, "ManifestResource", MANIFEST_RESOURCE_COLUMNS),
    table(0x29, "NestedClass", NESTED_CLASS_COLUMNS),
    table(0x2a, "GenericParam", GENERIC_PARAM_COLUMNS),
    table(0x2b, "MethodSpec", METHOD_SPEC_COLUMNS),
    table(
        0x2c,
        "GenericParamConstraint",
        GENERIC_PARAM_CONSTRAINT_COLUMNS,
    ),
];

const TYPE_DEF_OR_REF_TAGS: &[u8] = &[0x02, 0x01, 0x1b];
const HAS_CONSTANT_TAGS: &[u8] = &[0x04, 0x08, 0x17];
const HAS_CUSTOM_ATTRIBUTE_TAGS: &[u8] = &[
    0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23,
    0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
];
const HAS_FIELD_MARSHAL_TAGS: &[u8] = &[0x04, 0x08];
const HAS_DECL_SECURITY_TAGS: &[u8] = &[0x02, 0x06, 0x20];
const MEMBER_REF_PARENT_TAGS: &[u8] = &[0x02, 0x01, 0x1a, 0x06, 0x1b];
const HAS_SEMANTICS_TAGS: &[u8] = &[0x14, 0x17];
const METHOD_DEF_OR_REF_TAGS: &[u8] = &[0x06, 0x0a];
const MEMBER_FORWARDED_TAGS: &[u8] = &[0x04, 0x06];
const IMPLEMENTATION_TAGS: &[u8] = &[0x26, 0x23, 0x27];
const CUSTOM_ATTRIBUTE_TYPE_TAGS: &[u8] =
    &[TABLE_SENTINEL, TABLE_SENTINEL, 0x06, 0x0a, TABLE_SENTINEL];
const RESOLUTION_SCOPE_TAGS: &[u8] = &[0x00, 0x1a, 0x23, 0x01];
const TYPE_OR_METHOD_DEF_TAGS: &[u8] = &[0x02, 0x06];

pub(crate) const CODED_INDEXES: &[CodedIndexSchema] = &[
    coded(
        CodedIndexKind::TypeDefOrRef,
        "TypeDefOrRef",
        2,
        TYPE_DEF_OR_REF_TAGS,
    ),
    coded(
        CodedIndexKind::HasConstant,
        "HasConstant",
        2,
        HAS_CONSTANT_TAGS,
    ),
    coded(
        CodedIndexKind::HasCustomAttribute,
        "HasCustomAttribute",
        5,
        HAS_CUSTOM_ATTRIBUTE_TAGS,
    ),
    coded(
        CodedIndexKind::HasFieldMarshal,
        "HasFieldMarshal",
        1,
        HAS_FIELD_MARSHAL_TAGS,
    ),
    coded(
        CodedIndexKind::HasDeclSecurity,
        "HasDeclSecurity",
        2,
        HAS_DECL_SECURITY_TAGS,
    ),
    coded(
        CodedIndexKind::MemberRefParent,
        "MemberRefParent",
        3,
        MEMBER_REF_PARENT_TAGS,
    ),
    coded(
        CodedIndexKind::HasSemantics,
        "HasSemantics",
        1,
        HAS_SEMANTICS_TAGS,
    ),
    coded(
        CodedIndexKind::MethodDefOrRef,
        "MethodDefOrRef",
        1,
        METHOD_DEF_OR_REF_TAGS,
    ),
    coded(
        CodedIndexKind::MemberForwarded,
        "MemberForwarded",
        1,
        MEMBER_FORWARDED_TAGS,
    ),
    coded(
        CodedIndexKind::Implementation,
        "Implementation",
        2,
        IMPLEMENTATION_TAGS,
    ),
    coded(
        CodedIndexKind::CustomAttributeType,
        "CustomAttributeType",
        3,
        CUSTOM_ATTRIBUTE_TYPE_TAGS,
    ),
    coded(
        CodedIndexKind::ResolutionScope,
        "ResolutionScope",
        2,
        RESOLUTION_SCOPE_TAGS,
    ),
    coded(
        CodedIndexKind::TypeOrMethodDef,
        "TypeOrMethodDef",
        1,
        TYPE_OR_METHOD_DEF_TAGS,
    ),
];

const CLASSIC_SCHEMA: MetadataSchema = MetadataSchema {
    flavor: CliSchemaFlavor::Classic,
    metadata_kind: "CliMetadata",
    tables: METADATA_TABLES,
    coded_indexes: CODED_INDEXES,
};

const CLI4_SCHEMA: MetadataSchema = MetadataSchema {
    flavor: CliSchemaFlavor::Cli4,
    metadata_kind: "Cli4Metadata",
    tables: METADATA_TABLES,
    coded_indexes: CODED_INDEXES,
};

pub(crate) fn metadata_schema(flavor: CliSchemaFlavor) -> &'static MetadataSchema {
    match flavor {
        CliSchemaFlavor::Classic => &CLASSIC_SCHEMA,
        CliSchemaFlavor::Cli4 => &CLI4_SCHEMA,
    }
}

pub(crate) fn table_schema(table_id: u8) -> Option<&'static TableSchema> {
    METADATA_TABLES.iter().find(|schema| schema.id == table_id)
}

pub(crate) fn coded_index_schema(kind: CodedIndexKind) -> &'static CodedIndexSchema {
    &CODED_INDEXES[kind as usize]
}

pub(crate) fn table_index_width(table_id: u8, row_counts: &[u32; 64]) -> u8 {
    if row_counts[table_id as usize] < (1 << 16) {
        2
    } else {
        4
    }
}

pub(crate) fn coded_index_width(schema: &CodedIndexSchema, row_counts: &[u32; 64]) -> u8 {
    let max_rows = schema
        .tag_to_table
        .iter()
        .copied()
        .filter(|&table_id| table_id != TABLE_SENTINEL)
        .map(|table_id| row_counts[table_id as usize])
        .max()
        .unwrap_or(0);
    if max_rows < (1u32 << (16 - schema.tag_bits)) {
        2
    } else {
        4
    }
}

pub(crate) fn row_size(
    table_id: u8,
    row_counts: &[u32; 64],
    heap_widths: HeapIndexWidths,
) -> Option<usize> {
    let table = table_schema(table_id)?;
    Some(
        table
            .columns
            .iter()
            .map(|column| column_width(column.kind, row_counts, heap_widths) as usize)
            .sum(),
    )
}

fn column_width(kind: ColumnKind, row_counts: &[u32; 64], heap_widths: HeapIndexWidths) -> u8 {
    match kind {
        ColumnKind::U8 => 1,
        ColumnKind::U16 => 2,
        ColumnKind::U32 => 4,
        ColumnKind::Heap(HeapKind::Strings) => heap_widths.strings,
        ColumnKind::Heap(HeapKind::Guid) => heap_widths.guid,
        ColumnKind::Heap(HeapKind::Blob) => heap_widths.blob,
        ColumnKind::Table(table_id) => table_index_width(table_id, row_counts),
        ColumnKind::Coded(kind) => coded_index_width(coded_index_schema(kind), row_counts),
    }
}

const fn col(name: &'static str, kind: ColumnKind) -> ColumnSchema {
    ColumnSchema { name, kind }
}

const fn table(id: u8, name: &'static str, columns: &'static [ColumnSchema]) -> TableSchema {
    TableSchema { id, name, columns }
}

const fn coded(
    kind: CodedIndexKind,
    name: &'static str,
    tag_bits: u8,
    tag_to_table: &'static [u8],
) -> CodedIndexSchema {
    CodedIndexSchema {
        kind,
        name,
        tag_bits,
        tag_to_table,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const NARROW_HEAPS: HeapIndexWidths = HeapIndexWidths {
        strings: 2,
        guid: 2,
        blob: 2,
    };

    #[test]
    fn classic_and_cli4_have_distinct_schema_handles() {
        let classic = metadata_schema(CliSchemaFlavor::Classic);
        let cli4 = metadata_schema(CliSchemaFlavor::Cli4);
        assert_eq!(classic.metadata_kind, "CliMetadata");
        assert_eq!(cli4.metadata_kind, "Cli4Metadata");
        assert_eq!(classic.tables.len(), 45);
        assert_eq!(cli4.tables.len(), 45);
        assert_eq!(classic.coded_indexes.len(), 13);
        assert_eq!(cli4.coded_indexes.len(), 13);
    }

    #[test]
    fn metadata_schema_self_checks() {
        let mut seen_ids = HashSet::new();
        let mut last = None;
        for table in METADATA_TABLES {
            assert!(table.id < 64);
            assert!(!table.name.is_empty());
            assert!(!table.columns.is_empty());
            assert!(seen_ids.insert(table.id), "duplicate table id {}", table.id);
            if let Some(previous) = last {
                assert!(previous < table.id, "metadata tables must stay sorted");
            }
            last = Some(table.id);

            for column in table.columns {
                assert!(!column.name.is_empty());
                match column.kind {
                    ColumnKind::Table(table_id) => {
                        assert!(
                            table_schema(table_id).is_some(),
                            "unknown table id {table_id:#x} referenced by {}.{}",
                            table.name,
                            column.name
                        );
                    }
                    ColumnKind::Coded(kind) => {
                        let schema = coded_index_schema(kind);
                        assert!((schema.tag_to_table.len() as u32) <= (1u32 << schema.tag_bits));
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn coded_index_schemas_match_native_descriptor_shapes() {
        assert_eq!(
            coded_index_schema(CodedIndexKind::TypeDefOrRef).tag_to_table,
            &[0x02, 0x01, 0x1b]
        );
        assert_eq!(
            coded_index_schema(CodedIndexKind::MemberRefParent).tag_to_table,
            &[0x02, 0x01, 0x1a, 0x06, 0x1b]
        );
        assert_eq!(
            coded_index_schema(CodedIndexKind::CustomAttributeType).tag_to_table,
            &[TABLE_SENTINEL, TABLE_SENTINEL, 0x06, 0x0a, TABLE_SENTINEL]
        );
        assert_eq!(
            coded_index_schema(CodedIndexKind::HasCustomAttribute).tag_bits,
            5
        );
    }

    #[test]
    fn row_sizes_use_heap_table_and_coded_index_widths() {
        let mut rows = [0u32; 64];
        rows[0x04] = 10;
        rows[0x06] = 20;
        rows[0x08] = 30;
        assert_eq!(row_size(0x02, &rows, NARROW_HEAPS), Some(14));
        assert_eq!(row_size(0x06, &rows, NARROW_HEAPS), Some(14));

        rows[0x04] = 1 << 16;
        assert_eq!(row_size(0x02, &rows, NARROW_HEAPS), Some(16));

        rows[0x02] = 1 << 14;
        assert_eq!(
            coded_index_width(coded_index_schema(CodedIndexKind::TypeDefOrRef), &rows),
            4
        );
    }
}
