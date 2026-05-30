// Decode a sweep of genuine reverse diffs and compare each to the genuine base
// SHA-256 recorded by the VM-side ApplyDeltaB. Usage: sweep_check [dir]
use std::collections::BTreeMap;
use std::fs;

fn sha(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "notes/genuine-samples/sweep".into());
    let manifest = fs::read_to_string(format!("{dir}/manifest.csv")).expect("manifest");
    let (mut pass, mut fail) = (0u32, 0u32);
    let mut buckets: BTreeMap<String, u32> = BTreeMap::new();
    let mut examples: BTreeMap<String, String> = BTreeMap::new();

    for line in manifest.lines() {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 6 { continue; }
        let (id, base_sha) = (f[0], f[4]);
        let reference = fs::read(format!("{dir}/{id}/reference.bin")).unwrap();
        let delta = fs::read(format!("{dir}/{id}/reverse.pa31")).unwrap();
        match msdelta::pa30::apply(&reference, &delta) {
            Ok(out) if sha(&out) == base_sha => pass += 1,
            Ok(out) => {
                fail += 1;
                println!("FAIL hash-mismatch id={id} base_len={} got_len={} delta_len={}", f[3], out.len(), delta.len());
                let k = "hash-mismatch".to_string();
                *buckets.entry(k.clone()).or_default() += 1;
                examples.entry(k).or_insert_with(|| id.to_string());
            }
            Err(e) => {
                fail += 1;
                println!("FAIL err id={id} base_len={} delta_len={}: {e}", f[3], delta.len());
                let k = format!("ERR {e}");
                *buckets.entry(k.clone()).or_default() += 1;
                examples.entry(k).or_insert_with(|| id.to_string());
            }
        }
    }
    println!("\n=== sweep: {pass} pass, {fail} fail (of {}) ===", pass + fail);
    for (k, n) in &buckets {
        println!("  [{n}x] {k}\n        e.g. {}", examples[k]);
    }
}
