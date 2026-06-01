//! Dump the structure of a PA30/PA31 delta using this crate's own parser, to
//! diff our encoder output against genuine `msdelta.dll` deltas.
//!
//! Usage: cargo run --example analyze_delta -- <ref-file> <delta-file> [<delta-file> ...]

use std::fs;

use msdelta::pa30::{apply, parse};

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let reference = fs::read(&args[0]).unwrap();
    println!("reference: {} bytes\n", reference.len());

    for path in &args[1..] {
        let delta = fs::read(path).unwrap();
        println!("=== {} ({} bytes) ===", path, delta.len());
        println!("  raw head: {}", hex(&delta[..delta.len().min(16)]));
        match parse(&delta) {
            Ok(p) => {
                let h = &p.header;
                println!(
                    "  version={:?} filetime={:#018x} ftset={:#x} ftype={:#x} flags={:#x} tsize={} hashalg={:#x} hashlen={}",
                    h.version, h.target_file_time, h.file_type_set, h.file_type, h.flags,
                    h.target_size, h.hash_alg_id, h.target_hash.len()
                );
                println!(
                    "  preprocess: {} bytes  full: {}",
                    p.preprocess.len(),
                    hex(&p.preprocess)
                );
                println!(
                    "  patch_data: {} bytes  head: {}",
                    p.patch_data.len(),
                    hex(&p.patch_data[..p.patch_data.len().min(24)])
                );
            }
            Err(e) => println!("  parse() FAILED: {e}"),
        }
        match apply(&reference, &delta) {
            Ok(out) => println!("  our apply(): OK, {} bytes", out.len()),
            Err(e) => println!("  our apply(): ERR {e}"),
        }
        println!();
    }
}
