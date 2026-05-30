#![no_main]
//! Fuzz the XPRESS_HUFF (LZ77+Huffman) Compression-API container decoder -- the
//! bit-level code that decompresses type-1 ("deletes") payloads in reverse
//! deltas. Raw bytes are the right input here: the decoder parses them directly.
//! Seed the corpus from a genuine container (fuzz/seed_corpus.sh) so the mutator
//! starts past the 0xC0E5510A header and the 256-byte Huffman table.
//!
//! No size guard needed: decompress_container caps its output reserve and reads
//! are bounds-checked, so a hostile header cannot drive an unbounded allocation.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = msdelta::fuzzing::xpress_decompress_container(data);
});
