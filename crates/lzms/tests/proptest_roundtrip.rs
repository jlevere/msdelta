//! Property-based round-trip and robustness tests for the public LZMS API.
//!
//! The strongest correctness signal for this crate: anything we encode must
//! decode back bit-for-bit, and the decoder must never panic on arbitrary
//! input (only ever return `Ok`/`Err`).

use proptest::prelude::*;

/// Generate byte buffers with structure that exercises every codec path:
/// literals, repeats, runs, and delta-friendly arithmetic sequences.
fn structured_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // Arbitrary noise (literals / incompressible).
        proptest::collection::vec(any::<u8>(), 0..4096),
        // Long runs and repeated blocks (LZ + rep matches, long matches).
        proptest::collection::vec(any::<u8>(), 0..64).prop_map(|seed| seed
            .iter()
            .cycle()
            .take(8000)
            .copied()
            .collect()),
        // Arithmetic / strided sequences (delta matches across powers).
        (1u32..=255, 0u32..=255)
            .prop_map(|(step, start)| (0..6000u32).map(|i| (start + i * step) as u8).collect()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Raw bitstream round-trip.
    #[test]
    fn raw_roundtrip(data in structured_bytes()) {
        let compressed = lzms::compress(&data).unwrap();
        let restored = lzms::decompress(&compressed, data.len()).unwrap();
        prop_assert_eq!(restored, data);
    }

    /// Compression API container round-trip.
    #[test]
    fn container_roundtrip(data in structured_bytes()) {
        let wrapped = lzms::compress_compression_api(&data).unwrap();
        let restored = lzms::decompress_compression_api(&wrapped).unwrap();
        prop_assert_eq!(restored, data);
    }

    /// The container decoder must not panic on arbitrary bytes.
    #[test]
    fn container_decode_never_panics(data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let _ = lzms::decompress_compression_api(&data);
    }

    /// The raw decoder must not panic on arbitrary bytes / declared sizes.
    #[test]
    fn raw_decode_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..8192),
        size in 0usize..16384,
    ) {
        let _ = lzms::decompress(&data, size);
    }

    /// Mutating a single byte of a valid container must never panic the decoder
    /// (it may decode to something else, error, but not crash).
    #[test]
    fn container_bitflip_never_panics(
        data in proptest::collection::vec(any::<u8>(), 1..2048),
        idx in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let mut wrapped = lzms::compress_compression_api(&data).unwrap();
        let i = idx.index(wrapped.len());
        wrapped[i] ^= xor;
        let _ = lzms::decompress_compression_api(&wrapped);
    }
}
