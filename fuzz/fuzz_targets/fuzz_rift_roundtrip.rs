#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta::pa30::parse_header;

fuzz_target!(|data: &[u8]| {
    // Fuzz the full PA30 parse path (header + preprocess + patch_data buffers)
    if data.len() < 12 {
        return;
    }
    let _ = parse_header(data);
    // Also try full parse + apply with empty reference
    let _ = msdelta::pa30::apply(&[], data);
});
