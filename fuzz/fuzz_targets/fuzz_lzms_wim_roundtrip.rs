#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta_fuzz::Plaintext;

// WIM framings must round-trip losslessly for any input, in both the solid and
// the non-solid layouts, for a derived chunk size. Structured plaintext drives
// multi-chunk paths through real match/run handling.
fuzz_target!(|p: Plaintext| {
    let data = p.bytes();

    // Pick a small chunk size from the data so multi-chunk paths get exercised
    // without blowing up; keep it >= 1.
    let chunk_size = (data.len() / 4).max(1);

    let solid = lzms::compress_wim_solid(&data, chunk_size).expect("compress_wim_solid");
    let restored = lzms::decompress_wim_solid(&solid).expect("decompress_wim_solid");
    assert_eq!(restored, data, "solid WIM round-trip mismatch");

    let nonsolid = lzms::compress_wim(&data, chunk_size).expect("compress_wim");
    let restored =
        lzms::decompress_wim(&nonsolid, chunk_size, data.len()).expect("decompress_wim");
    assert_eq!(restored, data, "non-solid WIM round-trip mismatch");
});
