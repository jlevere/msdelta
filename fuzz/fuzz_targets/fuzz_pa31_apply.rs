#![no_main]

use libfuzzer_sys::fuzz_target;

// PA31-guided apply fuzzing. The seed corpus is the genuine Win11 LCU express
// PA31 deltas (notes/pa31-lcu-gaps/delta_*.bin), which are baseless -- they
// reconstruct the target from an empty reference. Mutating valid PA31 deltas
// keeps the input structurally close enough to exercise the deep paths the
// PA30-seeded fuzz_apply target never reaches: the PA31 sub-buffer header, the
// LZMS Compression-API container decode, the LZMS-vs-raw dispatch, and the x86
// 0xE8 transform on reconstructed i386 PE output. apply() caps allocation
// internally, so no size guard is needed here.
fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let _ = msdelta::pa30::apply(&[], data);
});
