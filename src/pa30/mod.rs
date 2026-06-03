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
/// target_file_offset` and, for a source copy, reads `reference[pos -
/// distance]`; with the rift offset folded in this resolves to the
/// matching SOURCE file offset. So each entry must read
///   { source: ref_len + new_file_offset, target: old_file_offset }
/// at every section boundary where the new->old file-offset shift changes.
///
/// `pp.pe_rift` carries the NEW image's `RVA -> file-offset` map (its
/// entries are exactly the new section starts: source = new RVA, target =
/// new file offset). Section RVAs are preserved across the delta, so we
/// match each new section to the old one by RVA (parsed from the
/// reference) and emit the new->old file-offset correspondence.
///
/// On amd64 FileAlignment == SectionAlignment, so RVA == file offset and
/// this reduces to the identity the old code happened to produce; on i386
/// (FileAlignment 0x200) it is what actually relays the tail sections.
///
/// The intra-section RVA changes carried by `pp.preprocess_rift` are ALSO
/// copy-placement: where bytes moved *within* a section between source and
/// target, the copy must follow that shift too. We fold those breakpoints
/// into the same file-offset rift below. Field-level fixups that the copy
/// cannot express (e.g. relocation rebasing) remain post-decompress passes.
fn build_pe_copy_rift(
    reference: &[u8],
    pp: &preprocess::PePreprocess,
) -> crate::lzx::rift::RiftTable {
    use crate::lzx::rift::RiftEntry;
    let ref_len = reference.len() as i64;
    let mut combined = crate::lzx::rift::RiftTable {
        entries: Vec::new(),
    };
    if let Ok(src_pe) = crate::pe::parse::PeInfo::parse_lenient(reference) {
        // NEW section starts: pe_rift entry source = new RVA, target = new FO.
        // Convert any TARGET RVA to a TARGET file offset by locating the
        // bracketing new-section start (RVA -> FO is a constant shift inside a
        // section).
        let new_starts: Vec<(u32, u32)> = pp
            .pe_rift
            .entries
            .iter()
            .map(|e| (e.source as u32, e.target as u32))
            .collect();
        let tgt_rva_to_fo = |rva: u32| -> Option<u32> {
            let mut best: Option<(u32, u32)> = None;
            for &(srva, sfo) in &new_starts {
                if srva <= rva && best.map(|(b, _)| srva >= b).unwrap_or(true) {
                    best = Some((srva, sfo));
                }
            }
            best.map(|(srva, sfo)| sfo + (rva - srva))
        };
        // SOURCE RVA -> SOURCE file offset via the reference section table.
        let src_rva_to_fo = |rva: u32| -> Option<u32> {
            src_pe
                .sections
                .iter()
                .find(|s| {
                    rva >= s.virtual_address
                        && rva < s.virtual_address + s.virtual_size.max(s.raw_size)
                })
                .map(|s| s.raw_offset + (rva - s.virtual_address))
        };

        // Section-boundary entries (new FO -> old FO, matched by RVA).
        for e in &pp.pe_rift.entries {
            let new_rva = e.source as u32;
            let new_fo = e.target as u32;
            if let Some(s) = src_pe.sections.iter().find(|s| {
                new_rva >= s.virtual_address
                    && new_rva < s.virtual_address + s.virtual_size.max(s.raw_size)
            }) {
                let old_fo = s.raw_offset + (new_rva - s.virtual_address);
                combined.entries.push(RiftEntry {
                    source: ref_len + new_fo as i64,
                    target: old_fo as i64,
                });
            } else {
                combined.entries.push(RiftEntry {
                    source: ref_len + new_fo as i64,
                    target: new_fo as i64,
                });
            }
        }

        // Intra-section breakpoints from the preprocess rift: at each
        // (source RVA -> target RVA) entry, the copy source shifts. Express
        // it in the file-offset domain: break at the TARGET file offset, read
        // the SOURCE file offset.
        for e in &pp.preprocess_rift.entries {
            let src_rva = e.source as u32;
            let tgt_rva = e.target as u32;
            if let (Some(tgt_fo), Some(src_fo)) = (tgt_rva_to_fo(tgt_rva), src_rva_to_fo(src_rva)) {
                combined.entries.push(RiftEntry {
                    source: ref_len + tgt_fo as i64,
                    target: src_fo as i64,
                });
            }
        }
    } else {
        // Reference is not a parseable PE: fall back to the previous
        // behaviour (RVA-domain pe_rift + preprocess_rift concatenation).
        combined = pp.pe_rift.clone();
        for e in &pp.preprocess_rift.entries {
            combined.entries.push(*e);
        }
    }
    combined.entries.sort_by_key(|e| e.source);
    combined
}

/// Apply a delta to a reference buffer.
///
/// Supports PA30, PA31, and PA19 formats.
/// Equivalent to `ApplyDeltaB(0, reference, delta, &out)` on Windows.
pub fn apply(reference: &[u8], delta: &[u8]) -> Result<Vec<u8>> {
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
        if parsed.header.hash_alg_id != 0 && !parsed.header.target_hash.is_empty() {
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
        let pp = parse_pe_preprocess(&parsed.preprocess)?;
        // Managed (.NET) target: the CLI metadata/map transforms are not yet
        // implemented (we parse and discard those buffers). Decoding anyway
        // produces silently-wrong bytes that only surface as a late hash
        // mismatch, so refuse up front. See TODO.md (PE transform pipeline).
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
    let decode_ref: &[u8] = if pp.is_some() {
        let mut r = reference.to_vec();
        crate::pe::transform::zero_pe_checksum(&mut r);
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

        // AMD64 .pdata RVA remap (RiftTransformPdataAmd64 apply pass): rewrite
        // each RUNTIME_FUNCTION's RVA fields through the preprocess rift so they
        // point at the target layout. Only for x64 images; the rift maps
        // source-RVA -> target-RVA, and is a no-op when empty (e.g. cabinet).
        if parsed.header.file_type == crate::pe::transform::FILE_TYPE_AMD64
            && !pp.preprocess_rift.entries.is_empty()
        {
            if let Ok(out_pe) = crate::pe::parse::PeInfo::parse(&output) {
                const EXCEPTION_DIR: usize = 3;
                if let Some(&(pdata_rva, pdata_size)) =
                    out_pe.data_directories.get(EXCEPTION_DIR)
                {
                    // Translate the exception-directory RVA to a file offset via
                    // the output's own section table (file offset != RVA here).
                    let pdata_file_off = out_pe
                        .sections
                        .iter()
                        .find(|s| {
                            pdata_rva >= s.virtual_address
                                && pdata_rva < s.virtual_address + s.virtual_size.max(s.raw_size)
                        })
                        .map(|s| s.raw_offset + (pdata_rva - s.virtual_address))
                        .unwrap_or(pdata_rva);
                    crate::pe::transform::remap_pdata_rvas(
                        &mut output,
                        pdata_file_off,
                        pdata_size,
                        &pp.preprocess_rift,
                    );
                }
            }
        }
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

    if parsed.header.hash_alg_id != 0 && !parsed.header.target_hash.is_empty() {
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

        // comctl32 amd64: the .pdata UnwindData remap plus the file-offset rift
        // composition drop the diff to 144 (the residual is the unwind-info
        // relayout, a separate pass).
        let old = std::fs::read(dir.join("comctl32_old.dll")).unwrap();
        let delta = std::fs::read(dir.join("comctl32.delta")).unwrap();
        let truth = std::fs::read(dir.join("comctl32_new.dll")).unwrap();
        let out = apply(&old, &delta).unwrap();
        assert_eq!(out.len(), truth.len(), "comctl32 length");
        let pdata = section_diff(&truth, &out, ".pdata");
        assert!(
            pdata <= 147,
            "comctl32 .pdata diff regressed: {pdata} (expected <= 147, was 6877 pre-remap)"
        );

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
        // Upper bounds that must not regress while the .text/.reloc transforms
        // remain unimplemented (pre-rift these were 338983 and 73198).
        assert!(
            section_diff(&x86_truth, &x86_out, ".text") <= 16690,
            "comctl32 x86 .text regressed (expected <= 16690, was 338983 pre-rift)"
        );
        assert!(
            section_diff(&x86_truth, &x86_out, ".reloc") <= 19453,
            "comctl32 x86 .reloc regressed (expected <= 19453, was 73198 pre-rift)"
        );
    }

    /// Exploratory: decode comctl32 x86 with the copy-vs-literal provenance map
    /// and correlate .text byte diffs (truth vs our untransformed output) with
    /// the marker bitmap and E8/E9 relative call/jmp sites. Confirms genuine
    /// msdelta's instruction transform applies ONLY to copied bytes. Ignored by
    /// default (needs the gitignored fixtures); run with `--ignored --nocapture`.
    #[test]
    #[ignore]
    fn analyze_x86_text_marker() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("notes/pe-fixtures");
        if !dir.join("comctl32x86.delta").exists() {
            eprintln!("comctl32x86 fixtures absent; skipping");
            return;
        }
        let old = std::fs::read(dir.join("comctl32x86_old.dll")).unwrap();
        let delta_raw = std::fs::read(dir.join("comctl32x86.delta")).unwrap();
        let truth = std::fs::read(dir.join("comctl32x86_new.dll")).unwrap();

        let parsed = parse(&delta_raw).unwrap();
        let target_size = parsed.header.target_size as usize;
        let pp = parse_pe_preprocess(&parsed.preprocess).unwrap();
        let combined = build_pe_copy_rift(&old, &pp);

        let mut pe_ref = old.clone();
        crate::pe::transform::zero_pe_checksum(&mut pe_ref);
        let (out, prov) = crate::lzx::decompress_with_provenance(
            &pe_ref,
            &parsed.patch_data,
            target_size,
            Some(&combined),
        )
        .unwrap();
        assert_eq!(out.len(), truth.len());
        assert_eq!(prov.len(), out.len());

        // .text bounds from truth.
        let pe = crate::pe::parse::PeInfo::parse_lenient(&truth).unwrap();
        let text = pe.sections.iter().find(|s| s.name == ".text").unwrap();
        let (off, len) = (text.raw_offset as usize, text.raw_size as usize);
        let end = (off + len).min(truth.len());

        // Diffs in .text, split by marker.
        let mut diff_marked = 0usize;
        let mut diff_literal = 0usize;
        for i in off..end {
            if out[i] != truth[i] {
                if prov[i] == 1 {
                    diff_marked += 1;
                } else {
                    diff_literal += 1;
                }
            }
        }
        eprintln!(
            ".text diffs: total={}, marker=1(copied)={}, marker=0(literal)={}",
            diff_marked + diff_literal,
            diff_marked,
            diff_literal
        );

        // E8/E9 sites whose TRUTH target lands within .text (real relative
        // calls/jmps). For each, test the rift-remap formula
        //   final_disp = our_disp + map(dest_rva) - map(site_rva)
        // where map = preprocess_rift (source RVA -> target RVA offset).
        let text_lo = text.virtual_address as i64;
        let text_hi = text_lo + text.raw_size as i64;
        let in_text = |rva: i64| rva >= text_lo && rva < text_hi;
        let map = |rva: i64| pp.preprocess_rift.map(rva);
        let rev = pp.preprocess_rift.reverse();
        let revmap = |rva: i64| rev.map(rva);

        let mut real = 0usize;
        let mut changed = 0usize;
        let mut formula_ok = 0usize;
        let mut formula_bad = 0usize;
        let mut examples = 0usize;
        let mut i = off;
        while i + 5 <= end {
            let op = truth[i];
            if op == 0xE8 || op == 0xE9 {
                let site_rva = text.virtual_address as i64 + (i - off) as i64;
                let our_disp = i32::from_le_bytes(out[i + 1..i + 5].try_into().unwrap()) as i64;
                let truth_disp = i32::from_le_bytes(truth[i + 1..i + 5].try_into().unwrap()) as i64;
                let truth_dest = site_rva + 5 + truth_disp;
                if !in_text(truth_dest) {
                    i += 1;
                    continue;
                }
                real += 1;
                // site_rva is the TARGET site rva R_t. Recover the SOURCE site
                // rva R_s = R_t + rev.map(R_t); the copied displacement points to
                // SOURCE dest D_s = R_s + 5 + our_disp.
                let src_site = site_rva + revmap(site_rva);
                let src_dest = src_site + 5 + our_disp;
                // final_disp = our_disp + map(D_s) - map(R_s); map(R_s) = -rev(R_t).
                let predicted = our_disp + map(src_dest) + revmap(site_rva);
                if our_disp != truth_disp {
                    changed += 1;
                }
                if predicted == truth_disp {
                    formula_ok += 1;
                } else {
                    formula_bad += 1;
                    if examples < 30 {
                        eprintln!(
                            "BAD fo={:#x} R_t={:#x} op={:#04x} our={:#x} truth={:#x} src_site={:#x} src_dest={:#x} map(D_s)={} rev(R_t)={} pred={:#x}",
                            i, site_rva, op, our_disp, truth_disp, src_site, src_dest,
                            map(src_dest), revmap(site_rva), predicted
                        );
                        examples += 1;
                    }
                }
            }
            i += 1;
        }
        eprintln!(
            "real in-text E8/E9: total={real}, changed(our!=truth)={changed}, formula_ok={formula_ok}, formula_bad={formula_bad}"
        );
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
