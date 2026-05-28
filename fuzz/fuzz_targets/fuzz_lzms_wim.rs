#![no_main]

use libfuzzer_sys::fuzz_target;

// Both untrusted-input WIM decode paths must never panic, abort, or OOM on
// arbitrary bytes. They may return Err, but nothing more.
fuzz_target!(|data: &[u8]| {
    // The solid resource is self-describing: feed it the raw input directly.
    let _ = lzms::decompress_wim_solid(data);

    // The non-solid resource takes its chunk size and total uncompressed size
    // out of band; derive both from the first bytes, bounded to sane ranges.
    if data.len() >= 8 {
        let chunk_size =
            (u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize % (1 << 20)) + 1;
        let uncompressed_size =
            u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize % (1 << 22);
        let _ = lzms::decompress_wim(&data[8..], chunk_size, uncompressed_size);
    }
});
