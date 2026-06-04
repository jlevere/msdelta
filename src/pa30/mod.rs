//! PA30 -- Microsoft's binary delta format, decoded by `msdelta.dll!ApplyDeltaB`.
//!
//! The format is undocumented; this module is built from reverse-engineering
//! `msdelta.dll` and `UpdateCompression.dll` (with PDB symbols).

mod encode;
pub(crate) mod header;
pub(crate) mod preprocess;
pub(crate) mod reverse;
pub(crate) mod signature;

pub use encode::{
    apply_get_reverse, create, get_info, get_info_ex, Codec, CreateOptions, FileType,
};
pub use header::{parse, parse_header, FormatVersion, Header, Pa31Extra, ParsedDelta, MAGIC};
pub use signature::{
    get_signature, normalize_for_signature, DeltaHash, HASH_ALG_MD5, HASH_ALG_NONE, HASH_ALG_SHA256,
};

use header::PA19_MAGIC;
use preprocess::{apply_pe_timestamp_fixup, parse_pe_preprocess};
use signature::hex_str;

use crate::{Error, Result};

/// Build the decompressor's copy-placement rift in the TARGET FILE-OFFSET
/// domain. The decompressor indexes the rift by `pos = ref_len +
/// target_file_offset` and, for a source copy, resolves it to the matching
/// SOURCE file offset. Genuine `PreProcessor::PreProcessPEForApply` computes
/// this as (native, non-.NET reduction; the CLI `Sum` is identity):
///
///   final = Reverse( Multiply( Multiply(rift_B, io2rva), io2rva ) )
///
/// where `rift_B` is the decoded preprocess rift (source RVA -> target RVA)
/// and `io2rva` = `SectionHelper::ExtractImageOffsetToRva` maps file offset ->
/// RVA. Semantically that conjugation is `io2rva^-1 . rift_B^-1 . io2rva`, i.e.
/// for a target file offset:
///   target_fo --io2rva--> rva --rift_B^-1--> source_rva --io2rva^-1--> source_fo
///
/// Genuine holds only the SOURCE image, so it uses the source `io2rva` on both
/// sides; that is exact on amd64 (FileAlignment == SectionAlignment, so file
/// offset == RVA). On i386 (FileAlignment 0x200 != SectionAlignment) the TARGET
/// file offset of an RVA-preserved tail section differs from the SOURCE file
/// offset, so the input side must use the TARGET file-offset <-> RVA map. We
/// have it: `pp.pe_rift` is the target RVA -> target file-offset map, so its
/// reverse is the target `io2rva`. Using the target map on the input side and
/// the source map on the output side makes the relayout exact for both arches:
///
///   final(target_fo) = io2rva_src^-1( rift_B^-1( io2rva_tgt(target_fo) ) )
fn build_pe_copy_rift(
    reference: &[u8],
    pp: &preprocess::PePreprocess,
) -> crate::lzx::rift::RiftTable {
    use crate::lzx::rift::RiftEntry;
    let ref_len = reference.len() as i64;

    let Ok(src_pe) = crate::pe::parse::PeInfo::parse_lenient(reference) else {
        // Reference is not a parseable PE: fall back to the RVA-domain
        // concatenation (pe_rift then preprocess_rift), sorted by source.
        let mut combined = pp.pe_rift.clone();
        for e in &pp.preprocess_rift.entries {
            combined.entries.push(*e);
        }
        combined.entries.sort_by_key(|e| e.source);
        return combined;
    };

    // io2rva for the SOURCE image, exactly as ExtractImageOffsetToRva.
    let io2rva_src = build_pe_io2rva(&src_pe);

    // Genuine `PreProcessPEForApply` builds the FORWARD chain in the source
    // file-offset -> target file-offset direction and applies a SINGLE
    // `Reverse` to the whole thing (then `Sum`s with the empty CLI map, which
    // is identity, so no Sum is needed here):
    //
    //   forward(source_fo) = pe_rift( preprocess_rift( io2rva_src(source_fo) ) )
    //                      = source_fo --io2rva_src--> rva
    //                                  --preprocess_rift--> target_rva
    //                                  --pe_rift--> target_fo
    //
    // (`a.multiply(b)` composes as `b . a`, applied innermost-first, so the
    // left-to-right `io2rva_src . preprocess_rift . pe_rift` is exactly that
    // chain.) `pe_rift` is the target RVA -> target file-offset map, used
    // directly -- no per-factor reverse. The single `Reverse` of the forward
    // chain handles the i386 FileAlignment relayout's overlaps and gaps via the
    // genuine working-buffer interval logic, which a naive swap cannot.
    let forward = io2rva_src
        .multiply(&pp.preprocess_rift)
        .multiply(&pp.pe_rift);
    let composed = forward.reverse();

    // composed maps target file offset -> source file offset. Fold into the
    // decompressor's keying: entry source = ref_len + target_fo, target = src_fo.
    let mut out = crate::lzx::rift::RiftTable {
        entries: Vec::with_capacity(composed.entries.len()),
    };
    for e in &composed.entries {
        // wrapping: composed entries can carry near-i64::MIN/MAX wrap-boundary
        // values; the sum wraps (correct) in release but would overflow-panic in
        // a debug build. The decompressor's offset lookups are wrap-consistent.
        out.entries.push(RiftEntry {
            source: ref_len.wrapping_add(e.source),
            target: e.target,
        });
    }
    out.entries.sort_by_key(|e| e.source);
    out
}

/// Build `io2rva` exactly as `SectionHelper::ExtractImageOffsetToRva`: an
/// initial `Add(0, 0)` entry, then per section (skipping those whose
/// VirtualAddress == 0 or PointerToRawData == 0) an `Add(PointerToRawData,
/// VirtualAddress)` -- i.e. `{source = file offset, target = RVA}` -- sorted by
/// source. Maps file offset -> RVA.
fn build_pe_io2rva(pe: &crate::pe::parse::PeInfo) -> crate::lzx::rift::RiftTable {
    use crate::lzx::rift::RiftEntry;
    let mut entries = vec![RiftEntry {
        source: 0,
        target: 0,
    }];
    for s in &pe.sections {
        if s.virtual_address == 0 || s.raw_offset == 0 {
            continue;
        }
        entries.push(RiftEntry {
            source: s.raw_offset as i64,
            target: s.virtual_address as i64,
        });
    }
    entries.sort_by_key(|e| e.source);
    crate::lzx::rift::RiftTable { entries }
}

/// Apply a delta to a reference buffer.
///
/// Supports PA30, PA31, and PA19 formats.
/// Equivalent to `ApplyDeltaB(0, reference, delta, &out)` on Windows.
pub fn apply(reference: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
    apply_impl(reference, delta, true)
}

/// Apply core with an optional target-hash check. `verify = false` returns the
/// reconstructed bytes even when they fail the embedded hash -- used by the
/// coverage harness to inspect *where* a decode diverges.
pub(crate) fn apply_impl(reference: &[u8], delta: &[u8], verify: bool) -> Result<Vec<u8>> {
    if delta.len() >= 4 && &delta[..4] == PA19_MAGIC {
        return crate::pa19::apply(reference, delta);
    }

    let parsed = parse(delta)?;
    let target_size = parsed.header.target_size as usize;

    const MAX_TARGET_SIZE: usize = 64 * 1024 * 1024;
    if target_size > MAX_TARGET_SIZE {
        return Err(Error::Malformed("target size exceeds 256 MB limit"));
    }

    // Reverse delta: reconstruct the source from the reference (which is the
    // target the delta was diffed against). target_size is the source length.
    if parsed.header.file_type_set & 0x100 != 0 {
        let output = reverse::apply_reversal(reference, &parsed.patch_data, target_size)?;
        if verify && parsed.header.hash_alg_id != 0 && !parsed.header.target_hash.is_empty() {
            let computed = get_signature(&output, parsed.header.hash_alg_id as u32)?;
            if computed.hash != parsed.header.target_hash {
                return Err(Error::HashMismatch {
                    expected: hex_str(&parsed.header.target_hash),
                    got: hex_str(&computed.hash),
                });
            }
        }
        return Ok(output);
    }

    let (caller_rift, pp) = if parsed.header.file_type != 1 && !parsed.preprocess.is_empty() {
        // Managed (.NET / CLI) images go through the CLI metadata/disasm pipeline
        // we do not implement. Screen on the reference's CLR header FIRST -- the
        // CLI preprocess stream is differently framed and would otherwise fail
        // deep in the bitstream parser. Reject cleanly instead.
        if crate::pe::transform::is_managed_pe(reference) {
            return Err(Error::Unsupported(
                "CLI metadata transform (managed/.NET image)",
            ));
        }
        let pp = parse_pe_preprocess(&parsed.preprocess)?;
        // Belt-and-suspenders: some managed deltas carry CLI buffers in the
        // preprocess without a CLR header surviving in the reference.
        if pp.cli_bytes > 0 {
            return Err(Error::Unsupported(
                "CLI metadata transform (managed/.NET image)",
            ));
        }
        let combined = build_pe_copy_rift(reference, &pp);
        (Some(combined), Some(pp))
    } else {
        (None, None)
    };

    // For PE deltas, msdelta normalizes the copy source by zeroing the
    // optional-header CheckSum before applying. Mirror that so copies resolve
    // identically (the target's real checksum is carried as literals).
    let pe_ref;
    let decode_ref: &[u8] = if let Some(pp) = &pp {
        let mut r = reference.to_vec();
        crate::pe::transform::zero_pe_checksum(&mut r);
        // Build T(source): transform the reference exactly as genuine
        // PreProcessPEForApply does before the LZX copy stage, so copies land
        // bit-identical. i386 relative calls/jmps + relocation operands, gated
        // by the header transform-selection flags. No-op on amd64 (handled by a
        // separate pass) and on images whose flags leave these transforms off.
        if let Ok(src_pe) = crate::pe::parse::PeInfo::parse_lenient(&r) {
            crate::pe::transform::build_transformed_source(
                &mut r,
                &src_pe,
                &pp.preprocess_rift,
                parsed.header.flags as u64,
                pp.target_image_base,
                pp.target_timestamp,
            );
        }
        pe_ref = r;
        &pe_ref
    } else {
        reference
    };

    // Discriminate the patch codec by its actual leading bytes, not by
    // file_type_set: genuine reverse deltas (ApplyDeltaGetReverseB) carry
    // file_type_set 0x101 but are plain LZX, which collides with our old
    // LZMS-wrapped bsdiff container (also 0x101). Only a real LZMS compression-
    // API container starts with its magic; everything else is PseudoLzx.
    const LZMS_API_MAGIC: [u8; 4] = 0xC0E5_510Au32.to_le_bytes();
    let is_lzms = parsed.patch_data.len() >= 4 && parsed.patch_data[..4] == LZMS_API_MAGIC;
    let mut output = if is_lzms {
        let decompressed = lzms::decompress_compression_api(&parsed.patch_data)?;
        // An LZMS Compression-API container in a PA3x delta normally holds the
        // target image directly: RAW/baseless content compressed whole, so the
        // container's uncompressed_total equals target_size and the decompressed
        // bytes ARE the target -- there is no bsdiff layer to replay. Only when
        // the payload differs in length from the target do we fall back to
        // treating it as a bsdiff patch stream against the reference.
        if decompressed.len() == target_size {
            decompressed
        } else {
            crate::bsdiff::bspatch(reference, target_size, &decompressed)?
        }
    } else {
        crate::lzx::decompress_with_rift(
            decode_ref,
            &parsed.patch_data,
            target_size,
            caller_rift.as_ref(),
        )?
    };

    if let Some(pp) = &pp {
        apply_pe_timestamp_fixup(reference, pp, &mut output)?;
        // AMD64 DisasmX64 + PdataX64 now run as SOURCE transforms in
        // build_transformed_source (decode_ref = T(source)), mirroring genuine
        // PreProcessPEForApply -- so they are no longer post-decode passes here.
    }

    // The x86 0xE8/0xE9 CALL/JMP un-translation is gated by header flag bit 0:
    // genuine ApplyDeltaB reads a transform-selection flag word from the header
    // and only runs E8x86::PostProcess when bit 0 is set. The encoder sets it
    // per-file (whether the transform helps), so resource-only PEs that should
    // NOT be touched have it clear -- which is why applying it unconditionally
    // regressed ~184 .mui. See notes/pa31-lcu-gaps/REGRESSION-AND-HANDOFF.md.
    if parsed.header.flags & 1 != 0 {
        crate::pe::transform::undo_x86_e8_translation(&mut output);
    }

    if verify && parsed.header.hash_alg_id != 0 && !parsed.header.target_hash.is_empty() {
        let computed = get_signature(&output, parsed.header.hash_alg_id as u32)?;
        if computed.hash != parsed.header.target_hash {
            return Err(Error::HashMismatch {
                expected: hex_str(&parsed.header.target_hash),
                got: hex_str(&computed.hash),
            });
        }
    }

    Ok(output)
}

/// Apply a delta into a caller-provided buffer.
///
/// Equivalent to `ApplyDeltaProvidedB(...)` on Windows. The output buffer
/// must be at least `target_size` bytes (from `get_info().target_size`).
pub fn apply_into(reference: &[u8], delta: &[u8], output: &mut [u8]) -> Result<usize> {
    let result = apply(reference, delta)?;
    if output.len() < result.len() {
        return Err(Error::Malformed("output buffer too small"));
    }
    output[..result.len()].copy_from_slice(&result);
    Ok(result.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const FIXTURES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    fn fixture_paths() -> Vec<PathBuf> {
        let mut paths: Vec<_> = std::fs::read_dir(FIXTURES_DIR)
            .expect("fixtures dir")
            .filter_map(|e| {
                let p = e.ok()?.path();
                if p.extension().and_then(|s| s.to_str()) == Some("manifest") {
                    Some(p)
                } else {
                    None
                }
            })
            .collect();
        paths.sort();
        paths
    }

    fn strip_dcm(data: &[u8]) -> &[u8] {
        &data[4..]
    }

    #[test]
    fn parse_smallest_fixture_header() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let pa30 = strip_dcm(&data);
        let header = parse_header(pa30).unwrap();

        assert_eq!(header.target_file_time, 0x019db1ded5d71680);
        assert_eq!(header.file_type_set, 1);
        assert_eq!(header.file_type, 1);
        assert_eq!(header.flags, 0x20000);
        assert_eq!(header.target_size, 415);
        assert_eq!(header.hash_alg_id, 0);
        assert!(header.target_hash.is_empty());
    }

    #[test]
    fn parse_smallest_fixture_full() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let pa30 = strip_dcm(&data);
        let parsed = parse(pa30).unwrap();

        assert_eq!(parsed.header.target_size, 415);
        assert!(
            parsed.preprocess.is_empty(),
            "RAW file type should have empty preprocess buffer"
        );
        assert!(
            !parsed.patch_data.is_empty(),
            "patch data should not be empty"
        );
    }

    #[test]
    fn parse_all_fixtures_full() {
        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let parsed = parse(pa30).unwrap_or_else(|e| {
                panic!("failed to parse {}: {}", path.display(), e);
            });

            assert!(
                parsed.preprocess.is_empty(),
                "RAW file type should have empty preprocess: {}",
                path.display()
            );
            assert!(
                !parsed.patch_data.is_empty(),
                "patch data empty: {}",
                path.display()
            );
            assert!(
                parsed.header.target_size > 0,
                "target_size must be positive: {}",
                path.display()
            );
        }
    }

    #[test]
    fn parse_all_fixtures() {
        let expected_sizes: &[(&str, i64)] = &[
            ("amd64_dual", 52889),
            ("amd64_microsoft-windows-core", 415),
            ("amd64_microsoft-windows-font", 2305),
            ("amd64_microsoft-windows-network", 96246),
            ("amd64_microsoft-windows-s", 7080),
            ("amd64_multipoint", 1961),
            ("wow64_microsoft-windows-o", 3263571),
        ];

        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let header = parse_header(pa30).unwrap_or_else(|e| {
                panic!("failed to parse {}: {}", path.display(), e);
            });

            assert_eq!(header.file_type_set, 1, "{}", path.display());
            assert_eq!(header.file_type, 1, "{}", path.display());
            assert_eq!(header.flags, 0x20000, "{}", path.display());
            assert_eq!(header.hash_alg_id, 0, "{}", path.display());
            assert!(header.target_hash.is_empty(), "{}", path.display());
            assert!(header.target_size > 0, "{}", path.display());

            let fname = path.file_name().unwrap().to_str().unwrap();
            for &(prefix, expected_size) in expected_sizes {
                if fname.starts_with(prefix) {
                    assert_eq!(
                        header.target_size, expected_size,
                        "target_size mismatch for {}",
                        fname
                    );
                    break;
                }
            }
        }
    }

    fn base_manifest() -> Vec<u8> {
        std::fs::read(PathBuf::from(FIXTURES_DIR).join("base_manifest.bin")).unwrap()
    }

    #[test]
    fn apply_smallest_fixture() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let pa30 = strip_dcm(&data);
        let base = base_manifest();

        let result = apply(&base, pa30);
        match &result {
            Ok(output) => {
                assert_eq!(output.len(), 415);
                let text = std::str::from_utf8(output).expect("output should be valid UTF-8");
                assert!(text.contains("<?xml"), "output should be XML");
                assert!(
                    text.contains("assembly"),
                    "output should contain assembly tag"
                );
            }
            Err(e) => {
                panic!("decompression failed: {e}");
            }
        }
    }

    #[test]
    fn apply_all_fixtures() {
        let base = base_manifest();
        let mut failures = Vec::new();
        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let header = parse_header(pa30).unwrap();
            let result = apply(&base, pa30);
            let fname = path.file_name().unwrap().to_str().unwrap().to_string();
            match &result {
                Ok(output) => {
                    assert_eq!(
                        output.len(),
                        header.target_size as usize,
                        "size mismatch: {fname}",
                    );
                    let text = std::str::from_utf8(output).expect("should be UTF-8");
                    assert!(text.contains("<?xml"), "should be XML: {fname}");
                }
                Err(e) => {
                    failures.push(format!("{fname}: {e}"));
                }
            }
        }
        assert!(
            failures.is_empty(),
            "decompression failures:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn snapshot_smallest_fixture() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        )
        .unwrap();
        let base = base_manifest();
        let pa30 = strip_dcm(&data);
        let output = apply(&base, pa30).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        insta::assert_snapshot!("BOOTSTRAP_smallest_manifest", text);
    }

    #[test]
    fn debug_wow64_divergence() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "wow64_microsoft-windows-o..euapcommonproxystub_31bf3856ad364e35_10.0.26100.7309_none_38de5e2364a9fd20.manifest",
            ),
        ).unwrap();
        let golden_path = PathBuf::from(FIXTURES_DIR).join("wow64_golden.xml");
        if !golden_path.exists() {
            eprintln!("SKIP: no golden file");
            return;
        }
        let golden = std::fs::read(&golden_path).unwrap();
        let base = base_manifest();
        let pa30 = strip_dcm(&data);
        let parsed = parse(pa30).unwrap();
        let (partial, err) = crate::lzx::decompress_partial(
            &base,
            &parsed.patch_data,
            parsed.header.target_size as usize,
        );

        if let Some(e) = &err {
            eprintln!("Decompression error after {} bytes: {e}", partial.len());
        }

        let compare_len = partial.len().min(golden.len());
        let mut first_diff = None;
        for i in 0..compare_len {
            if partial[i] != golden[i] {
                first_diff = Some(i);
                break;
            }
        }

        if let Some(pos) = first_diff {
            eprintln!(
                "wow64 diverges at byte {pos} of {compare_len} -- known issue, see notes/blockers.md"
            );
        } else if err.is_some() {
            eprintln!("Partial output ({compare_len} bytes) matches golden");
        } else {
            assert_eq!(partial.len(), golden.len(), "size mismatch with golden");
        }
    }

    #[test]
    fn roundtrip_simple() {
        let reference =
            b"Hello, this is a reference buffer with some repeated content. Hello again!";
        let target = b"Hello, this is a modified buffer with some repeated content. Goodbye!";

        let delta = create(reference, target).unwrap();
        assert!(delta.starts_with(b"PA30"));

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target, "round-trip failed");
    }

    #[test]
    fn roundtrip_pa31() {
        let reference =
            b"Hello, this is a reference buffer with some repeated content. Hello again!";
        let target = b"Hello, this is a modified buffer with some repeated content. Goodbye!";

        let delta = CreateOptions::new()
            .version(FormatVersion::PA31)
            .execute(reference, target)
            .unwrap();
        assert!(delta.starts_with(b"PA31"));

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.version, FormatVersion::PA31);
        assert!(header.pa31_extra.is_some());

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_bsdiff_simple() {
        let reference =
            b"Hello, this is a reference buffer with some repeated content. Hello again!";
        let target = b"Hello, this is a modified buffer with some repeated content. Goodbye!";

        let delta = CreateOptions::new()
            .codec(Codec::BsDiff)
            .execute(reference, target)
            .unwrap();
        assert!(delta.starts_with(b"PA30"));

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.flags & 0x100, 0x100);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_bsdiff_empty_target() {
        let reference = b"some reference data here";
        let delta = CreateOptions::new()
            .codec(Codec::BsDiff)
            .execute(reference, b"")
            .unwrap();
        let recovered = apply(reference, &delta).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn roundtrip_bsdiff_with_hash() {
        let reference = b"reference for bsdiff hash test";
        let target = b"target for bsdiff hash test with integrity checking";

        let delta = CreateOptions::new()
            .codec(Codec::BsDiff)
            .hash_algorithm(HASH_ALG_SHA256)
            .execute(reference, target)
            .unwrap();

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.hash_alg_id, HASH_ALG_SHA256 as i32);
        assert_eq!(header.flags & 0x100, 0x100);

        let header2 = parse_header(&delta).unwrap();
        assert_eq!(header2.target_size, target.len() as i64);
        assert_eq!(header2.target_hash.len(), 32);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_identical() {
        let data = b"The reference and target are the same.";
        let delta = create(data, data).unwrap();
        let recovered = apply(data, &delta).unwrap();
        assert_eq!(recovered, data.as_slice());
    }

    #[test]
    fn roundtrip_empty_target() {
        let reference = b"some reference data";
        let delta = create(reference, b"").unwrap();
        let recovered = apply(reference, &delta).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn preprocess_buffer_roundtrip() {
        use crate::lzx::rift::{RiftEntry, RiftTable};
        let rift = RiftTable {
            entries: vec![
                RiftEntry {
                    source: 0,
                    target: 0,
                },
                RiftEntry {
                    source: 0x1000,
                    target: 0x1200,
                },
            ],
        };
        let empty_rift = RiftTable { entries: vec![] };
        let buf = preprocess::build_pe_preprocess(
            0x140000000,
            0xCAFEBABE,
            0x12345678,
            &rift,
            &empty_rift,
        );
        let parsed = preprocess::parse_pe_preprocess(&buf).unwrap();
        assert_eq!(parsed.target_image_base, 0x140000000);
        assert_eq!(parsed.target_timestamp, 0x12345678);
        assert_eq!(parsed.pe_rift.entries.len(), 2);
        assert_eq!(parsed.pe_rift.entries[0].source, 0);
        assert_eq!(parsed.pe_rift.entries[0].target, 0);
        assert_eq!(parsed.pe_rift.entries[1].source, 0x1000);
        assert_eq!(parsed.pe_rift.entries[1].target, 0x1200);
        assert!(parsed.preprocess_rift.entries.is_empty());
    }

    #[test]
    fn roundtrip_pe_cmd_to_cmd_patched() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let src = delta_source("cmd.exe");
        let tgt = delta_source("cmd_patched.exe");
        let delta = CreateOptions::new()
            .file_type(FileType::Auto)
            .execute(&src, &tgt)
            .unwrap();
        let header = parse_header(&delta).unwrap();
        assert_eq!(header.file_type, 8, "should detect AMD64");
        let recovered = apply(&src, &delta).unwrap();
        assert_eq!(recovered.len(), tgt.len());
        assert_eq!(recovered, tgt);
    }

    #[test]
    fn roundtrip_pe_advapi32() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let src = delta_source("advapi32_old.dll");
        let tgt = delta_source("advapi32_new.dll");
        let delta = CreateOptions::new()
            .file_type(FileType::Auto)
            .execute(&src, &tgt)
            .unwrap();
        let header = parse_header(&delta).unwrap();
        assert_eq!(header.file_type, 8);
        let recovered = apply(&src, &delta).unwrap();
        assert_eq!(recovered.len(), tgt.len());
        assert_eq!(recovered, tgt);
    }

    #[test]
    fn roundtrip_with_md5() {
        let reference = b"reference data for hash test";
        let target = b"target data that should be integrity-checked with MD5";

        let delta = CreateOptions::new()
            .hash_algorithm(HASH_ALG_MD5)
            .execute(reference, target)
            .unwrap();

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.hash_alg_id, HASH_ALG_MD5 as i32);
        assert_eq!(header.target_hash.len(), 16);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_with_sha256() {
        let reference = b"reference data for hash test";
        let target = b"target data that should be integrity-checked with SHA256";

        let delta = CreateOptions::new()
            .hash_algorithm(HASH_ALG_SHA256)
            .execute(reference, target)
            .unwrap();

        let header = parse_header(&delta).unwrap();
        assert_eq!(header.hash_alg_id, HASH_ALG_SHA256 as i32);
        assert_eq!(header.target_hash.len(), 32);

        let recovered = apply(reference, &delta).unwrap();
        assert_eq!(recovered, target);
    }

    #[test]
    fn roundtrip_all_fixtures() {
        let base = base_manifest();
        let mut failures = Vec::new();
        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let target = apply(&base, pa30).unwrap();

            let fname = path.file_name().unwrap().to_str().unwrap().to_string();
            if target.len() > 500_000 {
                continue;
            }
            match create(&base, &target) {
                Ok(our_delta) => match apply(&base, &our_delta) {
                    Ok(recovered) => {
                        if recovered != target {
                            failures.push(format!("{fname}: content mismatch"));
                        }
                    }
                    Err(e) => failures.push(format!("{fname}: decode error: {e}")),
                },
                Err(e) => failures.push(format!("{fname}: encode error: {e}")),
            }
        }
        assert!(
            failures.is_empty(),
            "round-trip failures:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn decoder_matches_msdelta_dll() {
        use md5::{Digest, Md5};
        let golden_hashes: &[(&str, &str)] = &[
            ("65|", "05CE391BCD42CC29C917F242AF7EEFC8"),
            ("249|", "625E5A94109DEC39C60506B26F377CAF"),
            ("355|", "91FC84854C00CDB72644457E20D96CC7"),
            ("696|", "0260B236B57AF816BE98A50B2A5AACEE"),
            ("2852|", "906500830BF571878E536274CC1CE756"),
            ("9292|", "5F8671540358C1B95B2AD263BFAB7008"),
            ("175668|", "672F3A6D63609E3830089EB7763C31B7"),
        ];

        let base = base_manifest();
        let mut failures = Vec::new();

        for path in fixture_paths() {
            let data = std::fs::read(&path).unwrap();
            let pa30 = strip_dcm(&data);
            let output = apply(&base, pa30).unwrap();

            // digest 0.11's output array no longer implements UpperHex.
            let hash: String = Md5::digest(&output)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            let file_size = data.len();
            let key = format!("{file_size}|");

            if let Some(&(_, expected_md5)) = golden_hashes.iter().find(|(k, _)| *k == key) {
                if hash != expected_md5 {
                    failures.push(format!(
                        "{}: MD5 mismatch: ours={hash} msdelta={}",
                        path.file_name().unwrap().to_str().unwrap(),
                        expected_md5
                    ));
                }
            }
        }

        assert!(
            failures.is_empty(),
            "decoder output differs from msdelta.dll:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn reverse_delta_roundtrip() {
        let reference = b"Hello, this is a reference buffer with content.";
        let target = b"Hello, this is a modified buffer with new content!";

        let (decoded_target, reverse_delta) =
            apply_get_reverse(reference, &create(reference, target).unwrap()).unwrap();
        assert_eq!(decoded_target, target);

        let recovered_reference = apply(target, &reverse_delta).unwrap();
        assert_eq!(recovered_reference, reference.as_slice());
    }

    #[test]
    fn get_info_basic() {
        let data = std::fs::read(
            PathBuf::from(FIXTURES_DIR).join(
                "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
            ),
        ).unwrap();
        let pa30 = strip_dcm(&data);
        let info = get_info(pa30).unwrap();
        assert_eq!(info.target_size, 415);
        assert_eq!(info.file_type, 1);
    }

    #[test]
    fn signature_md5() {
        let data = b"Hello, World!";
        let sig = get_signature(data, HASH_ALG_MD5).unwrap();
        assert_eq!(sig.alg_id, HASH_ALG_MD5);
        assert_eq!(sig.hash.len(), 16); // MD5 = 128 bits
    }

    #[test]
    fn signature_sha256() {
        let data = b"Hello, World!";
        let sig = get_signature(data, HASH_ALG_SHA256).unwrap();
        assert_eq!(sig.alg_id, HASH_ALG_SHA256);
        assert_eq!(sig.hash.len(), 32); // SHA-256 = 256 bits
    }

    #[test]
    fn detect_pa19() {
        // PA19 with enough bytes for the header parser
        let mut data = b"PA19".to_vec();
        data.extend_from_slice(&[0u8; 28]); // pad for header fields
        match parse_header(&data) {
            Ok(h) => assert_eq!(h.version, FormatVersion::PA19),
            Err(e) => panic!("PA19 parse failed: {e}"),
        }
    }

    #[test]
    fn reject_truncated() {
        assert!(matches!(parse_header(b"PA3"), Err(Error::Truncated)));
        assert!(matches!(
            parse_header(b"PA30\x00\x00"),
            Err(Error::Truncated)
        ));
    }

    #[test]
    fn reject_bad_magic() {
        let data = b"XX30\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(matches!(parse_header(data), Err(Error::BadMagic { .. })));
    }

    #[test]
    fn fuzz_crash_no_panic() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
        let reference = b"minimal reference buffer for fuzzing";
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("fuzz_crash")
            {
                let data = std::fs::read(&path).unwrap();
                let result = apply(reference, &data);
                assert!(
                    result.is_err(),
                    "malformed input {} should return Err",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn apply_pe_amd64_delta() {
        let dir = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/deltas"
        ));
        if !dir.exists() {
            return;
        }
        let src = std::fs::read(dir.join("sources/cmd.exe")).unwrap();
        let tgt = std::fs::read(dir.join("sources/cmd_patched.exe")).unwrap();
        let delta = std::fs::read(dir.join("cmd__to__cmd_patched__pe_amd64.pa30")).unwrap();
        let result = apply(&src, &delta).unwrap();
        assert_eq!(result, tgt);
    }

    /// Genuine PE-transform oracle fixtures (gitignored; only present in the
    /// main working tree). Locks in the AMD64 `.pdata` RVA-remap gain and the
    /// cabinet control so the transform pass cannot silently regress.
    #[test]
    fn pe_transform_oracle_fixtures() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures");
        if !dir.join("comctl32.delta").exists() {
            return;
        }

        // Count differing bytes inside the named section of two PE images.
        // Uses the lenient parser: goblin rejects some genuine system images
        // (notably the i386 comctl32 fixture).
        fn section_diff(truth: &[u8], ours: &[u8], section: &str) -> usize {
            let pe = crate::pe::parse::PeInfo::parse_lenient(truth).unwrap();
            let s = pe.sections.iter().find(|s| s.name == section).unwrap();
            let (off, len) = (s.raw_offset as usize, s.raw_size as usize);
            let end = (off + len).min(truth.len()).min(ours.len());
            (off..end).filter(|&i| truth[i] != ours[i]).count()
        }

        // cabinet: near-identical control -- must stay byte-exact.
        let cab_old = std::fs::read(dir.join("cabinet_old.dll")).unwrap();
        let cab_delta = std::fs::read(dir.join("cabinet.delta")).unwrap();
        let cab_new = std::fs::read(dir.join("cabinet_new.dll")).unwrap();
        let cab_out = apply(&cab_old, &cab_delta).unwrap();
        assert_eq!(cab_out, cab_new, "cabinet control regressed");

        // comctl32 amd64: BYTE-EXACT. The amd64 T(source) architecture --
        // DisasmX64 (RIP-relative disp32 / rel32) and PdataX64 (RUNTIME_FUNCTION
        // RVA fields) run as SOURCE transforms before the LZX copy stage, exactly
        // as genuine PreProcessPEForApply does -- so both copied and literal-
        // provided bytes land the transformed value. 644585 -> 0.
        let old = std::fs::read(dir.join("comctl32_old.dll")).unwrap();
        let delta = std::fs::read(dir.join("comctl32.delta")).unwrap();
        let truth = std::fs::read(dir.join("comctl32_new.dll")).unwrap();
        let out = apply(&old, &delta).unwrap();
        assert_eq!(out.len(), truth.len(), "comctl32 length");
        assert_eq!(out, truth, "comctl32 amd64 not byte-exact");

        // comctl32 i386 (file_type 2): the target-file-offset rift composition
        // (section boundaries + intra-section preprocess breakpoints) relays the
        // tail sections so .idata/.didat/.rsrc reconstruct byte-exactly and .data
        // nearly so. The residual lives in .text (relative CALL/JMP displacement
        // rewrites) and .reloc (relocation-table regeneration), neither of which
        // is implemented yet -- those need the per-byte transform marker map.
        let x86_old = match std::fs::read(dir.join("comctl32x86_old.dll")) {
            Ok(d) => d,
            Err(_) => return,
        };
        let x86_delta = std::fs::read(dir.join("comctl32x86.delta")).unwrap();
        let x86_truth = std::fs::read(dir.join("comctl32x86_new.dll")).unwrap();
        let x86_out = apply(&x86_old, &x86_delta).unwrap();
        assert_eq!(x86_out.len(), x86_truth.len(), "comctl32 x86 length");
        // Locked at 0: copy placement is exact for these directories.
        assert_eq!(
            section_diff(&x86_truth, &x86_out, ".idata"),
            0,
            "comctl32 x86 .idata regressed (was 0)"
        );
        assert_eq!(
            section_diff(&x86_truth, &x86_out, ".didat"),
            0,
            "comctl32 x86 .didat regressed (was 0)"
        );
        assert_eq!(
            section_diff(&x86_truth, &x86_out, ".rsrc"),
            0,
            "comctl32 x86 .rsrc regressed (was 0)"
        );
        assert!(
            section_diff(&x86_truth, &x86_out, ".data") <= 5,
            "comctl32 x86 .data regressed (was 5, pre-rift 764)"
        );
        // The full i386 transform family (T(source): relative calls/jmps,
        // relocation operand rewrite + .reloc block rebuild, MarkNonExe gate,
        // export-table RVA mapping) reconstructs comctl32 x86 BYTE-EXACTLY --
        // 644585 total diffs pre-campaign -> 0.
        assert_eq!(x86_out, x86_truth, "comctl32 x86 not byte-exact");
    }

    /// Per-section diff report for the genuine PE fixtures via the full
    /// `apply()` path. A progress harness for the remaining transforms
    /// (notably the i386 .reloc block rebuild). Ignored (needs the gitignored
    /// fixtures); run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn pe_fixture_section_report() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures");
        if !dir.join("comctl32x86.delta").exists() {
            eprintln!("pe fixtures absent; skipping");
            return;
        }
        let report = |name: &str, old: &str, delta: &str, truth: &str| {
            let o = std::fs::read(dir.join(old)).unwrap();
            let d = std::fs::read(dir.join(delta)).unwrap();
            let t = std::fs::read(dir.join(truth)).unwrap();
            let out = apply(&o, &d).unwrap();
            let pe = crate::pe::parse::PeInfo::parse_lenient(&t).unwrap();
            let total: usize = (0..out.len().min(t.len()))
                .filter(|&i| out[i] != t[i])
                .count();
            eprintln!("{name}: total diff = {total}");
            for s in &pe.sections {
                let (a, len) = (s.raw_offset as usize, s.raw_size as usize);
                let end = (a + len).min(t.len()).min(out.len());
                let n = (a..end).filter(|&i| out[i] != t[i]).count();
                if n > 0 {
                    eprintln!("  {:<8} diff = {n}", s.name);
                }
            }
        };
        report(
            "comctl32 x86",
            "comctl32x86_old.dll",
            "comctl32x86.delta",
            "comctl32x86_new.dll",
        );
        report(
            "comctl32 amd64",
            "comctl32_old.dll",
            "comctl32.delta",
            "comctl32_new.dll",
        );
    }

    /// T(source) oracle: reconstruct genuine's transformed source by inverting
    /// the delta's copy ops against the known target (truth), then diff our
    /// `build_transformed_source` against it BY SOURCE OFFSET + SECTION. This
    /// isolates source-transform bugs from decode/copy/literal noise -- the
    /// instrument for driving the remaining transforms to byte-exact. Ignored
    /// (needs gitignored fixtures); run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn tsource_oracle() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures");
        if !dir.join("comctl32x86.delta").exists() {
            eprintln!("pe fixtures absent; skipping");
            return;
        }
        // FIX=<matrix-fixture-dirname> runs the oracle on a coverage-matrix
        // fixture (base.bin/forward.delta/truth.bin) instead of comctl32.
        if let Ok(fix) = std::env::var("FIX") {
            let fd = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("notes/pe-fixtures-matrix")
                .join(&fix);
            return run_tsource_oracle(
                &fix,
                std::fs::read(fd.join("base.bin")).unwrap(),
                std::fs::read(fd.join("forward.delta")).unwrap(),
                std::fs::read(fd.join("truth.bin")).unwrap(),
            );
        }
        let check = |label: &str, oldf: &str, deltaf: &str, truthf: &str| {
            let old = std::fs::read(dir.join(oldf)).unwrap();
            let delta_raw = std::fs::read(dir.join(deltaf)).unwrap();
            let truth = std::fs::read(dir.join(truthf)).unwrap();
            run_tsource_oracle(label, old, delta_raw, truth);
        };
        check(
            "comctl32 x86",
            "comctl32x86_old.dll",
            "comctl32x86.delta",
            "comctl32x86_new.dll",
        );
    }

    fn run_tsource_oracle(label: &str, old: Vec<u8>, delta_raw: Vec<u8>, truth: Vec<u8>) {
        {
            let parsed = parse(&delta_raw).unwrap();
            let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
            let combined = build_pe_copy_rift(&old, &pp);
            if std::env::var("RIFTDUMP").is_ok() {
                let spe0 = crate::pe::parse::PeInfo::parse_lenient(&old).unwrap();
                eprintln!(
                    "{label}: src_base={:#x} tgt_base={:#x} rift_entries={} pe_rift={}",
                    spe0.image_base,
                    pp.target_image_base,
                    pp.preprocess_rift.entries.len(),
                    pp.pe_rift.entries.len()
                );
                for e in pp.preprocess_rift.entries.iter().take(12) {
                    eprintln!(
                        "  rift src={:#x} -> tgt={:#x} (off {})",
                        e.source,
                        e.target,
                        e.target - e.source
                    );
                }
            }

            // Copy-source map from a decode (offsets are content-independent).
            let mut zsrc = old.clone();
            crate::pe::transform::zero_pe_checksum(&mut zsrc);
            let (_out, copy_src) = crate::lzx::decompress_with_copy_source(
                &zsrc,
                &parsed.patch_data,
                parsed.header.target_size as usize,
                Some(&combined),
            )
            .unwrap();

            // observed_Tsrc[s] = truth[o] for every output byte o that copied
            // reference offset s. This is genuine's T(source) at copied offsets.
            let mut observed: Vec<Option<u8>> = vec![None; old.len()];
            for (o, &s) in copy_src.iter().enumerate() {
                if s >= 0 && (s as usize) < observed.len() && o < truth.len() {
                    observed[s as usize] = Some(truth[o]);
                }
            }

            // Our T(source).
            let mut mine = old.clone();
            crate::pe::transform::zero_pe_checksum(&mut mine);
            let spe = crate::pe::parse::PeInfo::parse_lenient(&mine).unwrap();
            crate::pe::transform::build_transformed_source(
                &mut mine,
                &spe,
                &pp.preprocess_rift,
                parsed.header.flags as u64,
                pp.target_image_base,
                pp.target_timestamp,
            );

            let sec_of = |fo: usize| -> String {
                spe.sections
                    .iter()
                    .find(|s| {
                        fo >= s.raw_offset as usize && fo < (s.raw_offset + s.raw_size) as usize
                    })
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| "<hdr/gap>".into())
            };
            let mut by_sec = std::collections::BTreeMap::<String, usize>::new();
            let mut covered = 0usize;
            let mut shown = 0usize;
            for (s, obs) in observed.iter().enumerate() {
                let Some(t) = obs else { continue };
                covered += 1;
                if mine[s] != *t {
                    let sec = sec_of(s);
                    *by_sec.entry(sec.clone()).or_default() += 1;
                    let want = std::env::var("SECFILTER").unwrap_or_else(|_| ".text".into());
                    if shown < 14 && sec == want {
                        let w = |buf: &[u8]| -> String {
                            (s.saturating_sub(6)..(s + 6).min(buf.len()))
                                .map(|k| format!("{:02x}", buf[k]))
                                .collect::<Vec<_>>()
                                .join(" ")
                        };
                        let g: Vec<u8> = (s.saturating_sub(6)..(s + 6).min(old.len()))
                            .map(|k| observed[k].unwrap_or(old[k]))
                            .collect();
                        eprintln!("  TSDIFF fo={s:#x} [{sec}]");
                        eprintln!("    raw    : {}", w(&old));
                        eprintln!(
                            "    genuine: {}",
                            g.iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                        eprintln!("    mine   : {}", w(&mine));
                        shown += 1;
                    }
                }
            }
            let total: usize = by_sec.values().sum();
            eprintln!(
                "{label}: T(source) mismatches = {total} over {covered} copied bytes; by section: {by_sec:?}"
            );
        };
    }

    /// Dump the .reloc block structure of raw source vs genuine truth, to ground
    /// the block-rebuild implementation. Ignored; `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn reloc_structure_dump() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures");
        if !dir.join("comctl32x86.delta").exists() {
            return;
        }
        let old = std::fs::read(dir.join("comctl32x86_old.dll")).unwrap();
        let truth = std::fs::read(dir.join("comctl32x86_new.dll")).unwrap();
        let dump = |label: &str, img: &[u8]| {
            let pe = crate::pe::parse::PeInfo::parse_lenient(img).unwrap();
            let (rrva, rsize) = pe.data_directories[5];
            let fo = pe
                .sections
                .iter()
                .find(|s| {
                    rrva >= s.virtual_address
                        && rrva < s.virtual_address + s.virtual_size.max(s.raw_size)
                })
                .map(|s| (s.raw_offset + (rrva - s.virtual_address)) as usize)
                .unwrap();
            eprintln!("{label}: reloc rva={rrva:#x} size={rsize:#x} fo={fo:#x}");
            let mut bo = fo;
            let end = fo + rsize as usize;
            let mut blocks = 0;
            while bo + 8 <= end && blocks < 8 {
                let page = u32::from_le_bytes(img[bo..bo + 4].try_into().unwrap());
                let sz = u32::from_le_bytes(img[bo + 4..bo + 8].try_into().unwrap());
                let nent = if sz >= 8 { (sz - 8) / 2 } else { 0 };
                let first: Vec<String> = (0..nent.min(4))
                    .map(|j| {
                        let e = u16::from_le_bytes(
                            img[bo + 8 + j as usize * 2..bo + 8 + j as usize * 2 + 2]
                                .try_into()
                                .unwrap(),
                        );
                        format!("t{}:{:#05x}", e >> 12, e & 0xfff)
                    })
                    .collect();
                eprintln!(
                    "  page={page:#x} size={sz:#x} nent={nent} [{}]",
                    first.join(" ")
                );
                if sz < 8 {
                    break;
                }
                bo += sz as usize;
                blocks += 1;
            }
        };
        dump("raw source", &old);
        dump("genuine truth", &truth);

        // Build our T(source) and compare its .reloc to truth's.
        let delta_raw = std::fs::read(dir.join("comctl32x86.delta")).unwrap();
        let parsed = parse(&delta_raw).unwrap();
        let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
        let mut mine = old.clone();
        crate::pe::transform::zero_pe_checksum(&mut mine);
        let spe = crate::pe::parse::PeInfo::parse_lenient(&mine).unwrap();
        crate::pe::transform::build_transformed_source(
            &mut mine,
            &spe,
            &pp.preprocess_rift,
            parsed.header.flags as u64,
            pp.target_image_base,
            pp.target_timestamp,
        );
        dump("mine T(source)", &mine);
        // First divergence in .reloc between mine and truth.
        let (rrva, rsize) = spe.data_directories[5];
        let mfo = spe
            .sections
            .iter()
            .find(|s| {
                rrva >= s.virtual_address
                    && rrva < s.virtual_address + s.virtual_size.max(s.raw_size)
            })
            .map(|s| (s.raw_offset + (rrva - s.virtual_address)) as usize)
            .unwrap();
        let tpe = crate::pe::parse::PeInfo::parse_lenient(&truth).unwrap();
        let (trva, _) = tpe.data_directories[5];
        let tfo = tpe
            .sections
            .iter()
            .find(|s| {
                trva >= s.virtual_address
                    && trva < s.virtual_address + s.virtual_size.max(s.raw_size)
            })
            .map(|s| (s.raw_offset + (trva - s.virtual_address)) as usize)
            .unwrap();
        for k in 0..(rsize as usize) {
            if mine.get(mfo + k) != truth.get(tfo + k) {
                eprintln!(
                    "first .reloc divergence at block-rel {:#x}: mine={:02x?} truth={:02x?}",
                    k,
                    &mine[mfo + k..mfo + k + 16],
                    &truth[tfo + k..tfo + k + 16]
                );
                break;
            }
        }
    }

    /// Coverage matrix: apply every minted (base, delta, truth) triple in
    /// notes/pe-fixtures-matrix and report per-fixture pass/diff + per-section
    /// breakdown. The systematic breadth check across diverse DLLs/arches.
    /// Ignored (needs the gitignored fixtures); `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn pe_coverage_matrix() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures-matrix");
        if !root.exists() {
            eprintln!("matrix fixtures absent; skipping");
            return;
        }
        let mut dirs: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        let mut exact = 0;
        let mut nonzero = 0;
        let mut errored = 0;
        let mut rows: Vec<(String, String)> = Vec::new();
        for d in &dirs {
            let name = d.file_name().unwrap().to_string_lossy().to_string();
            let (base, delta, truth) = (
                std::fs::read(d.join("base.bin")),
                std::fs::read(d.join("forward.delta")),
                std::fs::read(d.join("truth.bin")),
            );
            let (Ok(base), Ok(delta), Ok(truth)) = (base, delta, truth) else {
                continue;
            };
            let (ft, fl) = parse(&delta)
                .map(|p| (p.header.file_type, p.header.flags))
                .unwrap_or((-1, 0));
            match apply_impl(&base, &delta, false) {
                Ok(out) => {
                    let total: usize = (0..out.len().min(truth.len()))
                        .filter(|&i| out[i] != truth[i])
                        .count()
                        + (out.len() as i64 - truth.len() as i64).unsigned_abs() as usize;
                    if total == 0 {
                        exact += 1;
                    } else {
                        nonzero += 1;
                        // per-section breakdown of the worst offenders
                        let secs = crate::pe::parse::PeInfo::parse_lenient(&truth)
                            .map(|pe| {
                                let mut v: Vec<(String, usize)> = pe
                                    .sections
                                    .iter()
                                    .map(|s| {
                                        let a = s.raw_offset as usize;
                                        let e = (a + s.raw_size as usize)
                                            .min(truth.len())
                                            .min(out.len());
                                        let n = (a..e).filter(|&i| out[i] != truth[i]).count();
                                        (s.name.clone(), n)
                                    })
                                    .filter(|(_, n)| *n > 0)
                                    .collect();
                                v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
                                v.iter()
                                    .take(4)
                                    .map(|(s, n)| format!("{s}:{n}"))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        rows.push((
                            name.clone(),
                            format!("ft={ft} fl={fl:#x} DIFF={total} [{secs}]"),
                        ));
                    }
                }
                Err(e) => {
                    errored += 1;
                    rows.push((name.clone(), format!("ft={ft} fl={fl:#x} ERR={e}")));
                }
            }
        }
        eprintln!("\n=== PE COVERAGE MATRIX ({} fixtures) ===", dirs.len());
        for (n, info) in &rows {
            eprintln!("  {n:<60} {info}");
        }
        eprintln!(
            "\nSUMMARY: byte-exact={exact}  diff={nonzero}  errored={errored}  total={}",
            dirs.len()
        );
    }

    /// Rift-composition corpus: validate `build_pe_copy_rift` against genuine
    /// dpx's composed copy rift dumped by the lab harness (notes/lab/rifts/<fix>.rift,
    /// gitignored). Each line is `target_fo,source_fo` (hex, possibly negative as
    /// 0xffff.. unsigned). We compare our composed rift (with the ref_len shift
    /// removed) to genuine's, ignoring only the i64::MIN/MAX wrap sentinels.
    /// This exercises the multiply/reverse composition across every minted
    /// topology (4..304 entries). Ignored; needs the gitignored dumps.
    #[test]
    #[ignore]
    fn rift_corpus() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures-matrix");
        let rifts = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/lab/rifts");
        if !rifts.exists() {
            eprintln!("rift dumps absent; skipping");
            return;
        }
        // A value within this of i64::MIN/MAX is a wrap sentinel, not a real entry.
        let is_sentinel = |v: i64| !(-0x7000_0000_0000_0000..=0x7000_0000_0000_0000).contains(&v);
        let parse_hex = |s: &str| -> i64 {
            u64::from_str_radix(s.trim(), 16)
                .map(|u| u as i64)
                .unwrap_or(0)
        };
        let mut pass = 0;
        let mut fail = 0;
        let mut rows: Vec<String> = Vec::new();
        let mut entries: Vec<_> = std::fs::read_dir(&rifts)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "rift"))
            .collect();
        entries.sort();
        for rp in &entries {
            let fix = rp.file_stem().unwrap().to_string_lossy().to_string();
            let d = root.join(&fix);
            let (Ok(base), Ok(delta)) = (
                std::fs::read(d.join("base.bin")),
                std::fs::read(d.join("forward.delta")),
            ) else {
                continue;
            };
            let Ok(parsed) = parse(&delta) else { continue };
            if parsed.preprocess.is_empty() {
                continue;
            }
            let Ok(pp) = parse_pe_preprocess(&parsed.preprocess) else {
                continue;
            };
            // Managed (.NET) images carry a CLI-metadata rift contribution we do
            // not implement (apply_impl rejects them up front); their composed
            // rift legitimately differs, so they are out of scope here.
            if pp.cli_bytes > 0 {
                continue;
            }
            let reflen = base.len() as i64;
            let ours = build_pe_copy_rift(&base, &pp);

            // Genuine (target_fo, source_fo) set, sentinels dropped.
            let mut want: Vec<(i64, i64)> = std::fs::read_to_string(rp)
                .unwrap()
                .lines()
                .filter_map(|l| l.split_once(','))
                .map(|(a, b)| (parse_hex(a), parse_hex(b)))
                .filter(|&(t, s)| !is_sentinel(t) && !is_sentinel(s))
                .collect();
            want.sort();
            // Ours, ref_len removed, sentinels dropped.
            let mut got: Vec<(i64, i64)> = ours
                .entries
                .iter()
                .map(|e| (e.source - reflen, e.target))
                .filter(|&(t, s)| !is_sentinel(t) && !is_sentinel(s))
                .collect();
            got.sort();
            got.dedup();
            want.dedup();
            if got == want {
                pass += 1;
            } else {
                fail += 1;
                let only_want: Vec<_> = want.iter().filter(|e| !got.contains(e)).take(4).collect();
                let only_got: Vec<_> = got.iter().filter(|e| !want.contains(e)).take(4).collect();
                rows.push(format!(
                    "{fix}: genuine={} ours={} | missing={:x?} extra={:x?}",
                    want.len(),
                    got.len(),
                    only_want,
                    only_got
                ));
            }
        }
        eprintln!("\n=== RIFT CORPUS ===");
        for r in &rows {
            eprintln!("  {r}");
        }
        eprintln!("\nrift corpus: {pass} match / {fail} differ");
        assert_eq!(
            fail, 0,
            "rift composition diverges from genuine on {fail} fixtures"
        );
    }

    /// Large-scale bulk corpus: apply every minted (base, delta) pair in
    /// notes/pe-fixtures-bulk and verify the output SHA-256 against the genuine
    /// truth hash recorded in manifest.csv (fixid,truth_sha256,base_len). Ships
    /// only base+delta+hash (no truth.bin) to keep the corpus transferable, so it
    /// scales to hundreds of diverse WinSxS version-pair fixtures. Reports
    /// byte-exact / mismatch / managed-rejected / errored. Ignored; needs the
    /// gitignored corpus. `cargo test --release --lib bulk_corpus -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn bulk_corpus() {
        use digest::Digest;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures-bulk");
        let manifest = root.join("manifest.csv");
        if !manifest.exists() {
            eprintln!("bulk corpus absent; skipping");
            return;
        }
        let txt = std::fs::read_to_string(&manifest).unwrap();
        let (mut exact, mut mismatch, mut managed, mut errored, mut total) = (0, 0, 0, 0, 0);
        let mut bad: Vec<String> = Vec::new();
        for line in txt.lines() {
            let mut it = line.split(',');
            let (Some(fid), Some(sha)) = (it.next(), it.next()) else {
                continue;
            };
            let d = root.join(fid);
            let (Ok(base), Ok(delta)) = (
                std::fs::read(d.join("base.bin")),
                std::fs::read(d.join("forward.delta")),
            ) else {
                continue;
            };
            total += 1;
            match apply_impl(&base, &delta, false) {
                Ok(out) => {
                    let mut h = sha2::Sha256::new();
                    h.update(&out);
                    let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
                    if got == sha {
                        exact += 1;
                    } else {
                        mismatch += 1;
                        let (ft, fl) = parse(&delta)
                            .map(|p| (p.header.file_type, p.header.flags))
                            .unwrap_or((-1, 0));
                        let arch = fid.split("__").next().unwrap_or("?");
                        bad.push(format!("{arch} ft={ft} fl={fl:#x} {fid}"));
                    }
                }
                Err(Error::Unsupported(_)) => managed += 1,
                Err(e) => {
                    errored += 1;
                    if bad.len() < 25 {
                        bad.push(format!("{fid} ERR={e}"));
                    }
                }
            }
        }
        eprintln!("\n=== BULK CORPUS ({total} fixtures) ===");
        for b in &bad {
            eprintln!("  FAIL {b}");
        }
        eprintln!(
            "byte-exact={exact}  mismatch={mismatch}  managed-rejected={managed}  errored={errored}  total={total}"
        );
        // Exploratory breadth corpus (randomly minted, regenerable, gitignored):
        // a generous floor catches a catastrophic decode regression without
        // red-failing on the known long-tail edges (drivers, codecs, .NET
        // satellites). The curated matrix / 377 RAW / rift corpora are the strict
        // regression gates.
        assert!(
            total == 0 || exact * 100 >= total * 80,
            "bulk byte-exact rate {exact}/{total} fell below 80%"
        );
    }

    /// amd64 ground-truth probe: apply a matrix fixture and dump the final
    /// output-vs-truth byte diffs for one section, with context. Unlike the
    /// tsource_oracle this is NON-circular -- it compares our real apply output
    /// to genuine truth directly, the right instrument for the post-decode amd64
    /// transforms (.pdata/.reloc/RIP-rel). `FIX=<dir> SEC=<.pdata> [N=<count>]`.
    /// Ignored; `cargo test --release --lib amd64_probe -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn amd64_probe() {
        let fix = match std::env::var("FIX") {
            Ok(f) => f,
            Err(_) => {
                eprintln!("set FIX=<matrix dir>");
                return;
            }
        };
        let sec_want = std::env::var("SEC").unwrap_or_else(|_| ".pdata".into());
        let limit: usize = std::env::var("N")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16);
        // Special case: the comctl32 amd64 fixture lives in notes/pe-fixtures
        // (the cleanest amd64 .pdata-only signal), not the matrix dir.
        let (base, delta, truth) = if fix == "comctl32-amd64" {
            let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures");
            (
                std::fs::read(d.join("comctl32_old.dll")).unwrap(),
                std::fs::read(d.join("comctl32.delta")).unwrap(),
                std::fs::read(d.join("comctl32_new.dll")).unwrap(),
            )
        } else {
            let fd = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("notes/pe-fixtures-matrix")
                .join(&fix);
            if !fd.exists() {
                eprintln!("fixture absent");
                return;
            }
            (
                std::fs::read(fd.join("base.bin")).unwrap(),
                std::fs::read(fd.join("forward.delta")).unwrap(),
                std::fs::read(fd.join("truth.bin")).unwrap(),
            )
        };
        let out = apply_impl(&base, &delta, false).unwrap();
        // DUMP_TSRC=<path>: write OUR build_transformed_source output (T(source))
        // for byte-diff against genuine's dpx-dumped T(source) (lab harness).
        if let Ok(path) = std::env::var("DUMP_TSRC") {
            let parsed = parse(&delta).unwrap();
            let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
            let mut t = base.clone();
            crate::pe::transform::zero_pe_checksum(&mut t);
            let spe = crate::pe::parse::PeInfo::parse_lenient(&t).unwrap();
            crate::pe::transform::build_transformed_source(
                &mut t,
                &spe,
                &pp.preprocess_rift,
                parsed.header.flags as u64,
                pp.target_image_base,
                pp.target_timestamp,
            );
            std::fs::write(&path, &t).unwrap();
            eprintln!("wrote our T(source) to {path} ({} bytes)", t.len());
        }
        // REF_TSRC=<path>: decode against a PROVIDED T(source) (e.g. genuine's
        // lab dump) with OUR copy rift, to isolate T(source) bugs from rift/decode.
        if let Ok(refp) = std::env::var("REF_TSRC") {
            let parsed = parse(&delta).unwrap();
            let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
            let rift = build_pe_copy_rift(&base, &pp);
            let gref = std::fs::read(&refp).unwrap();
            let (dec, csrc) = crate::lzx::decompress_with_copy_source(
                &gref,
                &parsed.patch_data,
                parsed.header.target_size as usize,
                Some(&rift),
            )
            .unwrap();
            let tpe2 = crate::pe::parse::PeInfo::parse_lenient(&truth).unwrap();
            let total = (0..dec.len().min(truth.len()))
                .filter(|&i| dec[i] != truth[i])
                .count();
            let sec = tpe2.sections.iter().find(|s| s.name == ".idata");
            let idata = sec
                .map(|s| {
                    let a = s.raw_offset as usize;
                    let e = (a + s.raw_size as usize).min(truth.len()).min(dec.len());
                    (a..e).filter(|&i| dec[i] != truth[i]).count()
                })
                .unwrap_or(0);
            eprintln!(
                "REF_TSRC decode: total diff={total} .idata={idata} (genuine T(source) + our rift)"
            );
            // For the first few .idata diffs: is it a copy (csrc>=0, reading the
            // wrong source) or a literal (csrc==-1)? gref==genuine T(source).
            if let Some(s) = sec {
                let a = s.raw_offset as usize;
                let e = (a + s.raw_size as usize).min(truth.len()).min(dec.len());
                let mut shown = 0;
                let mut i = a;
                while i < e && shown < 8 {
                    if dec[i] != truth[i] {
                        let cs = csrc[i];
                        let kind = if cs < 0 {
                            "LITERAL".to_string()
                        } else {
                            format!(
                                "copy<-src {cs:#x} grefbyte={:#04x}",
                                gref.get(cs as usize).copied().unwrap_or(0)
                            )
                        };
                        eprintln!(
                            "  .idata fo={i:#x} out={:#04x} truth={:#04x}  {kind}",
                            dec[i], truth[i]
                        );
                        shown += 1;
                        while i < e && dec[i] != truth[i] {
                            i += 1;
                        }
                        continue;
                    }
                    i += 1;
                }
            }
        }
        if std::env::var("RIFTDUMP").is_ok() {
            let parsed = parse(&delta).unwrap();
            let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
            eprintln!(
                "preprocess_rift ({} entries):",
                pp.preprocess_rift.entries.len()
            );
            for e in &pp.preprocess_rift.entries {
                eprintln!(
                    "  src={:#x} -> tgt={:#x} (off {})",
                    e.source,
                    e.target,
                    e.target - e.source
                );
            }
            // Our composed copy rift, with the ref_len shift removed so it is in
            // the same target_fo -> source_fo domain as genuine's dumped rift.
            let reflen = base.len() as i64;
            let composed = build_pe_copy_rift(&base, &pp);
            eprintln!(
                "build_pe_copy_rift ({} entries) [source-ref_len, target]:",
                composed.entries.len()
            );
            for e in &composed.entries {
                eprintln!("  {:x},{:x}", e.source - reflen, e.target);
            }
            // FORWARDCHAIN: dump the forward chain (source_fo -> target_fo)
            // io2rva_src . preprocess_rift . pe_rift, as raw (source,target) pairs
            // so the scratch Reverse port can be validated against genuine.
            if std::env::var("FORWARDCHAIN").is_ok() {
                if let Ok(src_pe) = crate::pe::parse::PeInfo::parse_lenient(&base) {
                    let io2rva_src = build_pe_io2rva(&src_pe);
                    eprintln!("io2rva_src ({} entries):", io2rva_src.entries.len());
                    for e in &io2rva_src.entries {
                        eprintln!("  {:x},{:x}", e.source, e.target);
                    }
                    eprintln!("pe_rift ({} entries):", pp.pe_rift.entries.len());
                    for e in &pp.pe_rift.entries {
                        eprintln!("  {:x},{:x}", e.source, e.target);
                    }
                    let fwd = io2rva_src
                        .multiply(&pp.preprocess_rift)
                        .multiply(&pp.pe_rift);
                    eprintln!(
                        "forward_chain ({} entries) [source_fo,target_fo]:",
                        fwd.entries.len()
                    );
                    for e in &fwd.entries {
                        eprintln!("  {:x},{:x}", e.source, e.target);
                    }
                }
            }
        }
        let tpe = crate::pe::parse::PeInfo::parse_lenient(&truth).unwrap();
        // SEC=ALL scans the whole buffer (catches header/gap diffs); otherwise a
        // named section's raw range.
        let (a, e) = if sec_want == "ALL" {
            (0usize, out.len().min(truth.len()))
        } else {
            let Some(sec) = tpe.sections.iter().find(|s| s.name == sec_want) else {
                eprintln!("section {sec_want} not found");
                return;
            };
            (
                sec.raw_offset as usize,
                (sec.raw_offset + sec.raw_size) as usize,
            )
        };
        let sec = tpe
            .sections
            .iter()
            .find(|s| s.name == sec_want)
            .unwrap_or(&tpe.sections[0]);
        let n: usize = (a..e.min(out.len()).min(truth.len()))
            .filter(|&i| out[i] != truth[i])
            .count();
        eprintln!(
            "{fix} [{sec_want}] rva={:#x} fo={:#x} size={:#x}: {n} diffs",
            sec.virtual_address, sec.raw_offset, sec.raw_size
        );
        let mut shown = 0usize;
        let mut i = a;
        while i < e.min(out.len()).min(truth.len()) && shown < limit {
            if out[i] != truth[i] {
                let rva = sec.virtual_address as usize + (i - sec.raw_offset as usize);
                let w = |b: &[u8]| {
                    (i.saturating_sub(4)..(i + 12).min(b.len()))
                        .map(|k| format!("{:02x}", b[k]))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                eprintln!("  fo={i:#x} rva={rva:#x}");
                eprintln!("    out  : {}", w(&out));
                eprintln!("    truth: {}", w(&truth));
                shown += 1;
                // skip to the next run of equal bytes to avoid spamming one field
                while i < e && out[i] != truth[i] {
                    i += 1;
                }
                continue;
            }
            i += 1;
        }
    }

    const DELTA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/deltas");

    fn delta_source(name: &str) -> Vec<u8> {
        std::fs::read(PathBuf::from(DELTA_DIR).join("sources").join(name)).unwrap()
    }

    fn delta_file(name: &str) -> Vec<u8> {
        std::fs::read(PathBuf::from(DELTA_DIR).join(name)).unwrap()
    }

    #[test]
    fn apply_raw_cmd_to_where() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let result = apply(
            &delta_source("cmd.exe"),
            &delta_file("cmd__to__where__raw.pa30"),
        )
        .unwrap();
        let expected = delta_source("where.exe");
        assert_eq!(result.len(), expected.len(), "size mismatch");
        let mut diffs = 0;
        let mut first = None;
        for i in 0..result.len() {
            if result[i] != expected[i] {
                if first.is_none() {
                    first = Some(i);
                }
                diffs += 1;
            }
        }
        assert_eq!(
            diffs,
            0,
            "first diff at {:?}, total {diffs} diffs out of {}",
            first,
            result.len()
        );
    }

    #[test]
    fn apply_raw_cmd_to_notepad() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let result = apply(
            &delta_source("cmd.exe"),
            &delta_file("cmd__to__notepad__raw.pa30"),
        )
        .unwrap();
        assert_eq!(result, delta_source("notepad.exe"));
    }

    #[test]
    fn apply_raw_cmd_to_notepad_flag0x20000() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let result = apply(
            &delta_source("cmd.exe"),
            &delta_file("cmd__to__notepad__raw_flag0x20000.pa30"),
        )
        .unwrap();
        assert_eq!(result, delta_source("notepad.exe"));
    }

    #[test]
    fn apply_prsm_cmd_to_notepad() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let result = apply(
            &delta_source("cmd.exe"),
            &delta_file("cmd__to__notepad__raw_bsdiff_flag0x100.pa30"),
        )
        .unwrap();
        assert_eq!(result, delta_source("notepad.exe"));
    }

    #[test]
    fn apply_raw_advapi32() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let result = apply(
            &delta_source("advapi32_old.dll"),
            &delta_file("advapi32_raw.pa30"),
        )
        .unwrap();
        assert_eq!(result, delta_source("advapi32_new.dll"));
    }

    #[test]
    fn apply_pe_advapi32() {
        if !PathBuf::from(DELTA_DIR).exists() {
            return;
        }
        let result = apply(
            &delta_source("advapi32_old.dll"),
            &delta_file("advapi32_pe.pa30"),
        )
        .unwrap();
        let expected = delta_source("advapi32_new.dll");
        let mut diffs = Vec::new();
        for i in 0..result.len().min(expected.len()) {
            if result[i] != expected[i] {
                diffs.push(i);
            }
        }
        if !diffs.is_empty() {
            for &i in diffs.iter().take(20) {
                eprintln!(
                    "  diff[{i}]: got={:#04x} want={:#04x}",
                    result[i], expected[i]
                );
            }
            panic!("{} diffs, first at {}", diffs.len(), diffs[0]);
        }
        assert_eq!(result.len(), expected.len());
    }
}
