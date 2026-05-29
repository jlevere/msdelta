#![no_main]

use libfuzzer_sys::fuzz_target;

// A real reference buffer, so the decode loop's COPY/RUN machinery is actually
// reached. With a tiny placeholder reference almost every copy op fails its
// bounds check on the first byte and the fuzzer never gets past the structural
// front door of the decoder, which is why this target only ever turned up
// shallow header/parse crashes. cmd.exe is the source side of the seed deltas
// in tests/fixtures/deltas (cmd -> notepad, cmd -> where, ...), so a corpus
// built from those, and mutations of it, land their copies inside this buffer
// and exercise the real machinery.
//
// No size guard: apply() already caps allocation at MAX_TARGET_SIZE (64 MiB)
// internally, so a hostile header cannot drive an unbounded allocation here.
// The previous `target_size > 65536` / `len > 8192` guards added no protection
// the library does not already provide and only served to reject every
// realistic delta (cmd -> notepad alone targets 360 KiB).
static REFERENCE: &[u8] = include_bytes!("../../tests/fixtures/deltas/sources/cmd.exe");

fuzz_target!(|data: &[u8]| {
    // Below the minimum PA30 header there is nothing to exercise.
    if data.len() < 12 {
        return;
    }
    let _ = msdelta::pa30::apply(REFERENCE, data);
});
