#![no_main]

use libfuzzer_sys::fuzz_target;
use msdelta::pa30::{Codec, CreateOptions};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let reference = &data[1..1 + split.min(data.len() - 1)];
    let target = &data[1 + split.min(data.len() - 1)..];

    let delta = match CreateOptions::new()
        .codec(Codec::BsDiff)
        .execute(reference, target)
    {
        Ok(d) => d,
        Err(_) => return,
    };
    let recovered = msdelta::pa30::apply(reference, &delta).unwrap();
    assert_eq!(recovered, target);
});
