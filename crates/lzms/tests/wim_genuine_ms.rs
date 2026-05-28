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
