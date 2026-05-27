//! PE preprocessing for PA30 deltas.

use crate::{Error, Result};

/// Parsed PE preprocess buffer from the delta.
///
/// From decompiled PreProcessPEForApply + PortableExecutableInfo::FromBitReader.
#[allow(dead_code)]
pub(crate) struct PePreprocess {
    pub(crate) target_image_base: u64,
    pub(crate) target_timestamp: u32,
    pub(crate) pe_rift: crate::lzx::rift::RiftTable,
    // Second rift table (from PreProcessPEForApply, separate from PE info rift)
    pub(crate) preprocess_rift: crate::lzx::rift::RiftTable,
}

pub(crate) fn parse_pe_preprocess(preprocess: &[u8]) -> Result<PePreprocess> {
    use crate::bitstream::BitReader;

    let mut reader = BitReader::new(preprocess)?;

    // PortableExecutableInfo::FromBitReader (decompiled at 18004cda0):
    //   Read64(0x40) = ImageBase
    //   Read32(0x20) = field1 (zero for typical deltas)
    //   Read32(0x20) = target TimeDateStamp
    //   RiftTable::FromBitReader = PE-level rift table
    //   CliMetadata::FromBitReader = CLI metadata
    //
    // Then PreProcessPEForApply reads more:
    //   RiftTable::FromBitReader = second rift table
    //   CliMap::FromBitReader = CLI map
    //
    let target_image_base = reader.read_bits(64)?;
    let _target_field1 = reader.read_bits(32)?;
    let target_timestamp = reader.read_bits(32)? as u32;

    let pe_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    // CliMetadata: 1-bit flag (0 = empty for native PEs)
    let cli_flag = reader.read_bits(1)?;
    if cli_flag != 0 {
        return Err(Error::Malformed("CLI metadata in preprocess not supported"));
    }

    // Second rift table from PreProcessPEForApply
    let preprocess_rift = crate::lzx::rift::RiftTable::from_reader(&mut reader)?;

    // CliMap: 1-bit flag (0 = empty for native PEs)
    if reader.remaining() > 0 {
        let climap_flag = reader.read_bits(1)?;
        if climap_flag != 0 {
            return Err(Error::Malformed("CLI map in preprocess not supported"));
        }
    }

    Ok(PePreprocess {
        target_image_base,
        target_timestamp,
        pe_rift,
        preprocess_rift,
    })
}

pub(crate) fn build_pe_preprocess(
    target_image_base: u64,
    target_timestamp: u32,
    pe_rift: &crate::lzx::rift::RiftTable,
    preprocess_rift: &crate::lzx::rift::RiftTable,
) -> Vec<u8> {
    use crate::bitstream::BitWriter;
    let mut writer = BitWriter::new();
    writer.write_bits(target_image_base, 64);
    writer.write_bits(0, 32);
    writer.write_bits(target_timestamp as u64, 32);
    pe_rift.to_writer(&mut writer);
    writer.write_bits(0, 1);
    preprocess_rift.to_writer(&mut writer);
    writer.write_bits(0, 1);
    writer.finish()
}

/// Apply PE post-processing after LZX decompression.
///
/// The encoder normalizes timestamps in the source before compression.
/// After decompression, the output has source timestamps that need
/// replacing with target timestamps at PE-structural offsets.
///
/// The preprocess buffer also contains rift tables needed for the full
/// transform pipeline (not yet wired for inferred relocations).
pub(crate) fn apply_pe_timestamp_fixup(
    reference: &[u8],
    pp: &PePreprocess,
    output: &mut [u8],
) -> Result<()> {
    let source_timestamp = pe_timestamp(reference);
    if source_timestamp == 0 || source_timestamp == pp.target_timestamp {
        return Ok(());
    }

    let new_bytes = pp.target_timestamp.to_le_bytes();

    for off in pe_timestamp_offsets(output) {
        if off + 4 <= output.len() {
            let val = u32::from_le_bytes(output[off..off + 4].try_into().unwrap());
            if val == source_timestamp {
                output[off..off + 4].copy_from_slice(&new_bytes);
            }
        }
    }

    Ok(())
}

fn pe_timestamp(data: &[u8]) -> u32 {
    crate::pe::transform::pe_timestamp(data)
}

fn pe_timestamp_offsets(data: &[u8]) -> Vec<usize> {
    crate::pe::transform::pe_timestamp_offsets(data)
}
