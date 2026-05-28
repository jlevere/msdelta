#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 || data.len() > 8192 {
        return;
    }
    if let Ok(header) = msdelta::pa30::parse_header(data) {
        if header.target_size > 65536 {
            return;
        }
    }
    let reference = b"minimal reference buffer for fuzzing";
    let _ = msdelta::pa30::apply(reference, data);
});
