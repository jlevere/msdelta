#![no_main]

use libfuzzer_sys::fuzz_target;

// Direct fuzzing of the PseudoLzx decoder -- the most complex byte-parser in the
// crate (embedded rift table, composite/segment format, pretree + Huffman, the
// offset/length slot decode, and the reference/output copy machinery). Until now
// it was only reached *through* `pa30::apply`, behind the PA3x header and the
// LZMS/dispatch logic, so the fuzzer spent most of its budget on framing rather
// than the LZX core.
//
// Seeds are the genuine PA31 LCU deltas; if the input parses as a PA3x delta we
// decode its (real, in-bitstream) LZX patch payload directly, otherwise we treat
// the tail as a raw bitstream with a size taken from the 4-byte prefix. Each
// payload is decoded both baseless (literal/back-ref path) and against a real
// reference (the rift-driven COPY path), which must never panic or read OOB.
static REFERENCE: &[u8] = include_bytes!("../../tests/fixtures/deltas/sources/cmd.exe");

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let (patch, size) = match msdelta::pa30::parse(data) {
        Ok(p) if !p.patch_data.is_empty() => {
            (p.patch_data, p.header.target_size.max(0) as usize)
        }
        _ => (
            data[4..].to_vec(),
            u32::from_le_bytes(data[..4].try_into().unwrap()) as usize,
        ),
    };
    let size = size % (32 << 20); // cap at 32 MiB
    let _ = msdelta::fuzzing::lzx_decompress_partial(&[], &patch, size);
    let _ = msdelta::fuzzing::lzx_decompress_partial(REFERENCE, &patch, size);
});
