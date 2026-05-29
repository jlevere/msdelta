#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta_fuzz::RoundTrip;

// Structure-aware encode -> decode round-trip across the PA30 codec/version
// combinations. The target is derived from the reference (see RoundTrip), so the
// encoder's match finder actually fires. A delta our encoder produces must
// decode back to exactly the target; anything else is a bug in one side.
fuzz_target!(|rt: RoundTrip| {
    let target = rt.target();

    let delta = match rt.create_options().execute(&rt.reference, &target) {
        Ok(d) => d,
        // The encoder may legitimately reject some inputs (e.g. empty buffers
        // for some codecs); only a successful encode is held to round-trip.
        Err(_) => return,
    };

    let recovered = msdelta::pa30::apply(&rt.reference, &delta)
        .expect("encoder produced a delta that fails to decode");
    assert_eq!(recovered, target, "round-trip mismatch");
});
