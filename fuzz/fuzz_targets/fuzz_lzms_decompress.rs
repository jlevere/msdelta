#![no_main]

use libfuzzer_sys::fuzz_target;

// Raw LZMS bitstream decoder must never panic on arbitrary input. The first
// few bytes pick a declared output size; the rest is the bitstream.
fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize % (1 << 20);
    let _ = lzms::decompress(&data[4..], size);
});
