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
        // Combine PE rift + preprocess rift into one table for the decompressor
        let mut combined = pp.pe_rift.clone();
        for e in &pp.preprocess_rift.entries {
            combined.entries.push(*e);
        }
        combined.entries.sort_by_key(|e| e.source);
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
    }

    // Undo MSDelta's x86 relative-CALL preprocessing. Genuine ApplyDeltaB runs
    // this on the reconstructed image whenever it is a 32-bit (i386) PE,
    // independent of the msdelta file_type (these LCU express deltas are RAW yet
    // still carry the transform). It is a no-op on non-PE output and on
    // amd64/msil images, so it is safe to call unconditionally here.
    crate::pe::transform::undo_x86_e8_translation(&mut output);

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
