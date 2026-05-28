#![no_main]

use libfuzzer_sys::fuzz_target;

// Decoder robustness on *near-valid* streams. Feeding the decoder raw random
// bytes (as fuzz_lzms_container does) mostly exercises the early structural
// checks, because random bytes almost never form a valid range-coder +
// backward-bitstream + Huffman stream. Here we compress fuzzer-controlled
// plaintext into a real container, then apply two fuzzer-controlled single-byte
// mutations before decoding, so the decode loop itself (matches, deltas, LRU
// queues, length/offset slots) is reached and stressed. It must never panic.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (ctrl, plain) = data.split_at(4);
    let Ok(mut wrapped) = lzms::compress_compression_api(plain) else {
        return;
    };
    if !wrapped.is_empty() {
        let p0 = u16::from_le_bytes([ctrl[0], ctrl[1]]) as usize % wrapped.len();
        wrapped[p0] ^= 0xFF;
        let p1 = u16::from_le_bytes([ctrl[2], ctrl[3]]) as usize % wrapped.len();
        wrapped[p1] = wrapped[p1].wrapping_add(ctrl[0]).wrapping_add(1);
    }
    // The mutation may corrupt the stream arbitrarily; any Ok/Err is fine, a
    // panic/abort/OOM is not.
    let _ = lzms::decompress_compression_api(&wrapped);
});
