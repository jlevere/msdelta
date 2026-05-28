#![no_main]

use libfuzzer_sys::fuzz_target;

// The Compression API container decoder must never panic on arbitrary input,
// including malformed headers, bad CRCs, and truncated chunk records.
fuzz_target!(|data: &[u8]| {
    let _ = lzms::decompress_compression_api(data);
});
