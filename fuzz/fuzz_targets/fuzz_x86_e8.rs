#![no_main]

use libfuzzer_sys::fuzz_target;

// Directly fuzz the x86 0xE8 CALL un-translation (undo_x86_e8_translation),
// which msdelta applies to reconstructed i386 PE targets. It parses PE headers
// by hand (machine / PE32 magic / CLR-ILONLY) and walks the buffer rewriting
// 4-byte operands, so it must never panic or read out of bounds on arbitrary
// (PE-shaped or not) input. Seed corpus: the genuine PA31 LCU target images.
fuzz_target!(|data: &[u8]| {
    let mut buf = data.to_vec();
    let _ = msdelta::fuzzing::undo_x86_e8_translation(&mut buf);
});
