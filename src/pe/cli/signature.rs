//! CLI signature blob token remapping.

use crate::pe::cli::blob::{read_compressed_u32, write_compressed_u32_preserving_width};
use crate::pe::cli::map::CliMapModel;
use crate::pe::cli::schema::CodedIndexKind;

const ELEMENT_TYPE_VOID: u8 = 0x01;
const ELEMENT_TYPE_TYPEDBYREF: u8 = 0x16;
const ELEMENT_TYPE_PTR: u8 = 0x0f;
const ELEMENT_TYPE_BYREF: u8 = 0x10;
const ELEMENT_TYPE_VALUETYPE: u8 = 0x11;
const ELEMENT_TYPE_CLASS: u8 = 0x12;
const ELEMENT_TYPE_VAR: u8 = 0x13;
const ELEMENT_TYPE_ARRAY: u8 = 0x14;
const ELEMENT_TYPE_GENERICINST: u8 = 0x15;
const ELEMENT_TYPE_FNPTR: u8 = 0x1b;
const ELEMENT_TYPE_SZARRAY: u8 = 0x1d;
const ELEMENT_TYPE_MVAR: u8 = 0x1e;
const ELEMENT_TYPE_CMOD_REQD: u8 = 0x1f;
const ELEMENT_TYPE_CMOD_OPT: u8 = 0x20;

const IMAGE_CEE_CS_CALLCONV_GENERIC: u8 = 0x10;

pub(crate) fn transform_method_signature_blob(blob: &mut [u8], cli_map: &CliMapModel) -> usize {
    let mut transformer = SignatureTransformer::new(blob, cli_map);
    transformer.transform_method_signature();
    transformer.rewrites
}

pub(crate) fn transform_field_signature_blob(blob: &mut [u8], cli_map: &CliMapModel) -> usize {
    let mut transformer = SignatureTransformer::new(blob, cli_map);
    if transformer.read_byte().is_some() {
        transformer.transform_type();
    }
    transformer.rewrites
}

pub(crate) fn transform_property_signature_blob(blob: &mut [u8], cli_map: &CliMapModel) -> usize {
    let mut transformer = SignatureTransformer::new(blob, cli_map);
    if transformer.read_byte().is_none() {
        return 0;
    }
    let Some(param_count) = transformer.read_compressed().map(|value| value.0) else {
        return 0;
    };
    if !transformer.transform_type() {
        return transformer.rewrites;
    }
    for _ in 0..param_count {
        if !transformer.transform_param() {
            break;
        }
    }
    transformer.rewrites
}

pub(crate) fn transform_type_spec_blob(blob: &mut [u8], cli_map: &CliMapModel) -> usize {
    let mut transformer = SignatureTransformer::new(blob, cli_map);
    transformer.transform_type();
    transformer.rewrites
}

struct SignatureTransformer<'a> {
    blob: &'a mut [u8],
    cli_map: &'a CliMapModel,
    cursor: usize,
    rewrites: usize,
}

impl<'a> SignatureTransformer<'a> {
    fn new(blob: &'a mut [u8], cli_map: &'a CliMapModel) -> Self {
        Self {
            blob,
            cli_map,
            cursor: 0,
            rewrites: 0,
        }
    }

    fn transform_method_signature(&mut self) -> bool {
        let Some(call_conv) = self.read_byte() else {
            return false;
        };
        if call_conv & IMAGE_CEE_CS_CALLCONV_GENERIC != 0 && self.read_compressed().is_none() {
            return false;
        }
        let Some(param_count) = self.read_compressed().map(|value| value.0) else {
            return false;
        };
        if !self.transform_param() {
            return false;
        }
        for _ in 0..param_count {
            if !self.transform_param() {
                return false;
            }
        }
        true
    }

    fn transform_param(&mut self) -> bool {
        if !self.transform_sentinel() {
            return false;
        }
        match self.peek_byte() {
            Some(ELEMENT_TYPE_VOID | ELEMENT_TYPE_TYPEDBYREF) => {
                self.cursor += 1;
                true
            }
            Some(ELEMENT_TYPE_BYREF) => {
                self.cursor += 1;
                self.transform_type()
            }
            Some(_) => self.transform_type(),
            None => false,
        }
    }

    fn transform_type(&mut self) -> bool {
        loop {
            let Some(element_type) = self.read_byte() else {
                return false;
            };

            match element_type {
                0x02..=0x0e | ELEMENT_TYPE_TYPEDBYREF | 0x18 | 0x19 | 0x1c => return true,
                ELEMENT_TYPE_PTR | ELEMENT_TYPE_SZARRAY => return self.transform_type(),
                ELEMENT_TYPE_VALUETYPE | ELEMENT_TYPE_CLASS => {
                    return self.transform_type_def_or_ref();
                }
                ELEMENT_TYPE_VAR | ELEMENT_TYPE_MVAR => return self.read_compressed().is_some(),
                ELEMENT_TYPE_ARRAY => {
                    return self.transform_type() && self.transform_array_shape();
                }
                ELEMENT_TYPE_GENERICINST => {
                    if !self.transform_type() {
                        return false;
                    }
                    let Some(arg_count) = self.read_compressed().map(|value| value.0) else {
                        return false;
                    };
                    for _ in 0..arg_count {
                        if !self.transform_type() {
                            return false;
                        }
                    }
                    return true;
                }
                ELEMENT_TYPE_FNPTR => return self.transform_method_signature(),
                ELEMENT_TYPE_CMOD_REQD | ELEMENT_TYPE_CMOD_OPT => {
                    if !self.transform_type_def_or_ref() {
                        return false;
                    }
                }
                _ if element_type & 0xf0 == 0x40 => {}
                _ => return false,
            }
        }
    }

    fn transform_sentinel(&mut self) -> bool {
        loop {
            let Some(byte) = self.peek_byte() else {
                return true;
            };
            if byte & 0xf0 == 0x40 {
                self.cursor += 1;
                continue;
            }
            if byte == ELEMENT_TYPE_CMOD_REQD || byte == ELEMENT_TYPE_CMOD_OPT {
                self.cursor += 1;
                if !self.transform_type_def_or_ref() {
                    return false;
                }
                continue;
            }
            return true;
        }
    }

    fn transform_array_shape(&mut self) -> bool {
        let Some(rank) = self.read_compressed().map(|value| value.0) else {
            return false;
        };
        let Some(size_count) = self.read_compressed().map(|value| value.0) else {
            return false;
        };
        for _ in 0..size_count {
            if self.read_compressed().is_none() {
                return false;
            }
        }
        let Some(lower_bound_count) = self.read_compressed().map(|value| value.0) else {
            return false;
        };
        for _ in 0..lower_bound_count {
            if self.read_compressed().is_none() {
                return false;
            }
        }
        let _ = (rank, size_count, lower_bound_count);
        true
    }

    fn transform_type_def_or_ref(&mut self) -> bool {
        let Some((raw, start, width)) = self.read_compressed() else {
            return false;
        };
        let mapped = self.map_type_def_or_ref(raw);
        if mapped != raw
            && write_compressed_u32_preserving_width(&mut self.blob[start..], width, mapped)
        {
            self.rewrites += 1;
        }
        true
    }

    fn map_type_def_or_ref(&self, raw: u32) -> u32 {
        self.cli_map
            .coded_token_map()
            .and_then(|token_map| token_map.map_coded_token(raw, CodedIndexKind::TypeDefOrRef))
            .unwrap_or(raw)
    }

    fn read_byte(&mut self) -> Option<u8> {
        let byte = *self.blob.get(self.cursor)?;
        self.cursor += 1;
        Some(byte)
    }

    fn peek_byte(&self) -> Option<u8> {
        self.blob.get(self.cursor).copied()
    }

    fn read_compressed(&mut self) -> Option<(u32, usize, usize)> {
        let start = self.cursor;
        let (value, width) = read_compressed_u32(self.blob.get(start..)?).ok()?;
        self.cursor = self.cursor.checked_add(width)?;
        Some((value, start, width))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lzx::rift::{RiftEntry, RiftTable};

    fn rift(entries: &[(i64, i64)]) -> RiftTable {
        RiftTable {
            entries: entries
                .iter()
                .map(|&(source, target)| RiftEntry { source, target })
                .collect(),
        }
    }

    #[test]
    fn remaps_type_def_or_ref_in_method_signature() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x01] = rift(&[(3, 7)]);
        let mut signature = vec![
            0x00, // default call convention
            0x01, // one parameter
            ELEMENT_TYPE_VOID,
            ELEMENT_TYPE_CLASS,
            (3 << 2) | 1, // TypeRef RID 3
        ];

        let rewrites = transform_method_signature_blob(&mut signature, &cli_map);

        assert_eq!(rewrites, 1);
        assert_eq!(signature[4], (7 << 2) | 1);
    }

    #[test]
    fn remaps_custom_modifier_before_type() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x02] = rift(&[(2, 5)]);
        let mut signature = vec![
            0x00,
            0x01,
            ELEMENT_TYPE_VOID,
            ELEMENT_TYPE_CMOD_REQD,
            2 << 2, // TypeDef RID 2
            ELEMENT_TYPE_I4,
        ];

        let rewrites = transform_method_signature_blob(&mut signature, &cli_map);

        assert_eq!(rewrites, 1);
        assert_eq!(signature[4], 5 << 2);
    }

    #[test]
    fn leaves_token_when_mapped_value_would_widen() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x01] = rift(&[(0x1f, 0x20)]);
        let mut signature = vec![
            0x00,
            0x01,
            ELEMENT_TYPE_VOID,
            ELEMENT_TYPE_CLASS,
            (0x1f << 2) | 1,
        ];

        let rewrites = transform_method_signature_blob(&mut signature, &cli_map);

        assert_eq!(rewrites, 0);
        assert_eq!(signature[4], (0x1f << 2) | 1);
    }

    #[test]
    fn remaps_generic_instance_arguments() {
        let mut cli_map = CliMapModel::default();
        cli_map.tables[0x01] = rift(&[(2, 4)]);
        cli_map.tables[0x02] = rift(&[(3, 6)]);
        let mut signature = vec![
            ELEMENT_TYPE_GENERICINST,
            ELEMENT_TYPE_CLASS,
            (2 << 2) | 1,
            0x01,
            ELEMENT_TYPE_VALUETYPE,
            3 << 2,
        ];

        let rewrites = transform_type_spec_blob(&mut signature, &cli_map);

        assert_eq!(rewrites, 2);
        assert_eq!(signature[2], (4 << 2) | 1);
        assert_eq!(signature[5], 6 << 2);
    }

    const ELEMENT_TYPE_I4: u8 = 0x08;
}
