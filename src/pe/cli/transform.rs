//! Classic CLI stages interleaved with the PE source transformations.

use crate::pe::atom::{AtomMeta, SourceCtx, Transform};
use crate::pe::transform::transform_flags;

pub(crate) struct TransformCliDisasm;

impl Transform for TransformCliDisasm {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "TransformCliDisasm",
            layer: "cli",
            kind: "source_transform",
            file_types: "0x2,0x4,0x8",
            flag_mask: transform_flags::CLI_DISASM,
            native_reference: "TransformCliDisasm::Run",
        }
    }

    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        if let Some(cli) = ctx.cli {
            super::disasm::transform_cli_disasm_tokens(ctx.buf, ctx.pe, cli.metadata, cli.map);
        }
    }
}

pub(crate) struct TransformCliMetadata;

impl Transform for TransformCliMetadata {
    fn meta(&self) -> AtomMeta {
        AtomMeta {
            id: "TransformCliMetadata",
            layer: "cli",
            kind: "source_transform",
            file_types: "0x2,0x4,0x8",
            flag_mask: transform_flags::CLI_METADATA,
            native_reference: "TransformCliMetadata::Run",
        }
    }

    fn apply(&self, ctx: &mut SourceCtx<'_>) {
        if let Some(cli) = ctx.cli {
            super::metadata_transform::transform_cli_metadata_with_rva_map(
                ctx.buf,
                cli.metadata,
                cli.map,
                ctx.rift,
            );
        }
    }
}
