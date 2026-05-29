//! Generate a round-trip corpus for cross-checking our encoder against the
//! real `msdelta.dll` (`ApplyDeltaB`) on a Windows host.
//!
//! For each case we write `<name>.ref` (reference buffer) and `<name>.delta`
//! (delta produced by this crate's encoder), self-verify with our own
//! decoder, and append a line to `manifest.tsv`:
//!
//!     <name>\t<expected-target-sha256>\t<target-len>
//!
//! The Windows harness applies each delta to its reference via `ApplyDeltaB`,
//! hashes the output, and compares against the manifest.
//!
//! Usage: cargo run --release --example gen_roundtrip_corpus -- <out-dir>

use std::fs;
use std::path::{Path, PathBuf};

use msdelta::pa30::{
    apply, CreateOptions, Codec, FileType, FormatVersion, HASH_ALG_MD5, HASH_ALG_SHA256,
};
use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

struct Case {
    name: &'static str,
    reference: Vec<u8>,
    target: Vec<u8>,
    opts: CreateOptions,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deltas/sources")
}

fn read_fixture(name: &str) -> Vec<u8> {
    fs::read(fixtures_dir().join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("usage: gen_roundtrip_corpus <out-dir>"));
    fs::create_dir_all(&out).unwrap();

    let ref_text =
        b"Hello, this is a reference buffer with some repeated content. Hello again! \
          The quick brown fox jumps over the lazy dog. Repeated content repeated content."
            .to_vec();
    let tgt_text =
        b"Hello, this is a MODIFIED buffer with some repeated content. Goodbye now! \
          The quick brown fox jumps over the lazy cat. Repeated content repeated content."
            .to_vec();

    // A larger, compressible body to exercise multi-segment LZX.
    let big_ref: Vec<u8> = (0..400_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    let mut big_tgt = big_ref.clone();
    for chunk in big_tgt.chunks_mut(4096) {
        if let Some(b) = chunk.get_mut(17) {
            *b ^= 0xAA;
        }
    }
    big_tgt.extend_from_slice(b"appended tail region that did not exist in the reference buffer");

    let cmd = read_fixture("cmd.exe");
    let cmd_patched = read_fixture("cmd_patched.exe");
    let advapi_old = read_fixture("advapi32_old.dll");
    let advapi_new = read_fixture("advapi32_new.dll");

    let cases = vec![
        Case {
            name: "text_pa30_lzx",
            reference: ref_text.clone(),
            target: tgt_text.clone(),
            opts: CreateOptions::new(),
        },
        Case {
            name: "text_pa31_lzx",
            reference: ref_text.clone(),
            target: tgt_text.clone(),
            opts: CreateOptions::new().version(FormatVersion::PA31),
        },
        Case {
            name: "text_bsdiff",
            reference: ref_text.clone(),
            target: tgt_text.clone(),
            opts: CreateOptions::new().codec(Codec::BsDiff),
        },
        Case {
            name: "text_md5",
            reference: ref_text.clone(),
            target: tgt_text.clone(),
            opts: CreateOptions::new().hash_algorithm(HASH_ALG_MD5),
        },
        Case {
            name: "text_sha256",
            reference: ref_text.clone(),
            target: tgt_text.clone(),
            opts: CreateOptions::new().hash_algorithm(HASH_ALG_SHA256),
        },
        Case {
            name: "bigtext_lzx_multiseg",
            reference: big_ref.clone(),
            target: big_tgt.clone(),
            opts: CreateOptions::new(),
        },
        Case {
            name: "bigtext_bsdiff",
            reference: big_ref,
            target: big_tgt,
            opts: CreateOptions::new().codec(Codec::BsDiff),
        },
        Case {
            name: "pe_cmd_amd64_auto",
            reference: cmd.clone(),
            target: cmd_patched.clone(),
            opts: CreateOptions::new().file_type(FileType::Auto),
        },
        Case {
            name: "pe_cmd_amd64_pa31",
            reference: cmd.clone(),
            target: cmd_patched,
            opts: CreateOptions::new().file_type(FileType::Auto).version(FormatVersion::PA31),
        },
        Case {
            name: "pe_advapi32_auto",
            reference: advapi_old,
            target: advapi_new,
            opts: CreateOptions::new().file_type(FileType::Auto),
        },
        Case {
            name: "identical",
            reference: ref_text.clone(),
            target: ref_text.clone(),
            opts: CreateOptions::new(),
        },
        Case {
            name: "empty_target",
            reference: ref_text,
            target: Vec::new(),
            opts: CreateOptions::new(),
        },
    ];

    let mut manifest = String::new();
    let mut self_fail = 0usize;
    for c in &cases {
        let delta = c
            .opts
            .execute(&c.reference, &c.target)
            .unwrap_or_else(|e| panic!("encode {} failed: {e}", c.name));

        // Self-check with our own decoder before shipping.
        match apply(&c.reference, &delta) {
            Ok(out) if out == c.target => {}
            Ok(out) => {
                eprintln!(
                    "SELF-FAIL {}: our decoder produced {} bytes, expected {}",
                    c.name,
                    out.len(),
                    c.target.len()
                );
                self_fail += 1;
            }
            Err(e) => {
                eprintln!("SELF-FAIL {}: our decoder errored: {e}", c.name);
                self_fail += 1;
            }
        }

        write_file(&out, &format!("{}.ref", c.name), &c.reference);
        write_file(&out, &format!("{}.target", c.name), &c.target);
        write_file(&out, &format!("{}.delta", c.name), &delta);
        manifest.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            c.name,
            sha256_hex(&c.target),
            c.target.len(),
            delta.len(),
        ));
        println!(
            "{:<24} ref={:>8} target={:>8} delta={:>8}",
            c.name,
            c.reference.len(),
            c.target.len(),
            delta.len()
        );
    }

    fs::write(out.join("manifest.tsv"), manifest).unwrap();
    if self_fail > 0 {
        panic!("{self_fail} case(s) failed our own decoder; aborting before Windows cross-check");
    }
    println!("\nwrote {} cases to {}", cases.len(), out.display());
}

fn write_file(dir: &Path, name: &str, data: &[u8]) {
    fs::write(dir.join(name), data).unwrap();
}
