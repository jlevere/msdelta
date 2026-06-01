//! Decode genuine Microsoft solid LZMS WIM resources, proving interop against
//! real `wimgapi.dll` output (not a third-party encoder).
//!
//! Provenance: produced on jackson-dev (Windows Server 2025, wimgapi
//! 10.0.26100.1, DISM 10.0.26100.5074) via
//! `dism /Export-Image ... /Compress:recovery`, which packs the image into a
//! solid LZMS resource. The resource bytes were extracted verbatim from the
//! ESD at their blob-table offset. Two fixtures:
//!
//! - `wim_solid_lzms_ms.resource` (78 B): single 64 MiB-chunk-window resource
//!   holding 180000 bytes of repeated "The quick brown fox..." text.
//! - `wim_solid_lzms_ms_3chunk.resource` (64 B): 140 MiB of zeros across three
//!   64 MiB solid chunks — exercises the multi-entry chunk-size table.

#[test]
fn decodes_genuine_ms_single_chunk_text() {
    let resource = include_bytes!("fixtures/lzms/wim_solid_lzms_ms.resource");
    let decoded = lzms::decompress_wim_solid(resource).expect("decode genuine MS solid resource");

    let unit = b"The quick brown fox jumps over the lazy dog. ";
    let mut expected = Vec::new();
    while expected.len() < 180_000 {
        expected.extend_from_slice(unit);
    }
    expected.truncate(180_000);

    assert_eq!(decoded.len(), 180_000);
    assert_eq!(decoded, expected);
}

#[test]
fn decodes_genuine_ms_multichunk_zeros() {
    let resource = include_bytes!("fixtures/lzms/wim_solid_lzms_ms_3chunk.resource");
    let decoded = lzms::decompress_wim_solid(resource).expect("decode genuine MS solid resource");
    assert_eq!(decoded.len(), 146_800_640); // 140 MiB across 3 solid chunks
    assert!(decoded.iter().all(|&b| b == 0), "expected all zeros");
}

/// Regression for the adaptive-Huffman rebuild order. This genuine MS solid
/// holds diverse content (a `.cat` catalog + component manifests from a real
/// Windows UUP `.esd`), so it decodes enough distinct symbols to cross the
/// 1024-symbol rebuild threshold -- unlike the highly-repetitive fixtures
/// above, which stay under it. Before the fix the decoder halved frequencies
/// *before* rebuilding the code (MS rebuilds first, then halves), so it
/// desynced right after the first rebuild ("LZ offset past start"). Decoding to
/// the full plaintext proves the rebuild now matches Microsoft's.
#[test]
fn decodes_genuine_ms_with_huffman_rebuild() {
    let resource = include_bytes!("fixtures/lzms/wim_solid_lzms_ms_rebuild.resource");
    let decoded = lzms::decompress_wim_solid(resource).expect("decode genuine MS solid resource");
    assert_eq!(decoded.len(), 27972);
    // The first packed blob is a `.cat` (PKCS#7 SignedData): SEQUENCE then the
    // signedData OID 1.2.840.113549.1.7.2.
    assert_eq!(&decoded[0..2], &[0x30, 0x82]);
    assert_eq!(
        &decoded[4..15],
        &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]
    );
}

/// Re-encoding the genuine plaintext through our own solid encoder must
/// round-trip (uses a small chunk size to stay multi-chunk without 64 MiB).
#[test]
fn solid_reencode_roundtrips() {
    let unit = b"The quick brown fox jumps over the lazy dog. ";
    let mut data = Vec::new();
    while data.len() < 180_000 {
        data.extend_from_slice(unit);
    }
    data.truncate(180_000);

    let resource = lzms::compress_wim_solid(&data, 65_536).unwrap();
    assert_eq!(lzms::decompress_wim_solid(&resource).unwrap(), data);
}
