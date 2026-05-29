#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta::pa30::parse_header;

// The PA30/PA31 header parser and its bitstream reader must never panic on
// arbitrary input. Pair with fuzz/pa30.dict so the mutator gets past the magic.
fuzz_target!(|data: &[u8]| {
    let _ = parse_header(data);
});
