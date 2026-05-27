#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta::pa30::parse_header;

fuzz_target!(|data: &[u8]| {
    // Fuzz the PA30 header parser (exercises bitstream reader)
    let _ = parse_header(data);
});
