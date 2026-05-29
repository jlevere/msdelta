#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta_fuzz::Plaintext;

// Encoder -> decoder round-trip must be lossless for any input, through both the
// raw bitstream and the Compression API container. Structured plaintext (runs,
// repeats, arithmetic sequences) exercises the match/rep/delta paths that random
// bytes rarely reach.
fuzz_target!(|p: Plaintext| {
    let data = p.bytes();

    let compressed = lzms::compress(&data).expect("compress");
    let restored = lzms::decompress(&compressed, data.len()).expect("decompress");
    assert_eq!(restored, data, "raw round-trip mismatch");

    let wrapped = lzms::compress_compression_api(&data).expect("compress_compression_api");
    let restored = lzms::decompress_compression_api(&wrapped).expect("decompress_compression_api");
    assert_eq!(restored, data, "container round-trip mismatch");
});
