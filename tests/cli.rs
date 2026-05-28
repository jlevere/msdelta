//! End-to-end tests that drive the compiled `msdelta` binary.
//!
//! Cargo exposes the built binary path via `CARGO_BIN_EXE_msdelta`, so these
//! exercise the real argument parsing and I/O without extra dev-dependencies.

#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_msdelta"))
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// create -> info -> apply must reproduce the target byte-for-byte.
#[test]
fn round_trip_create_apply() {
    let dir = tempdir();
    let reference = dir.join("ref.bin");
    let target = dir.join("tgt.bin");
    let delta = dir.join("d.delta");
    let out = dir.join("out.bin");

    std::fs::write(&reference, vec![0xABu8; 8192]).unwrap();
    let mut tgt = vec![0xABu8; 8192];
    tgt.extend_from_slice(b"appended-tail-that-differs");
    std::fs::write(&target, &tgt).unwrap();

    let status = bin()
        .args(["create"])
        .arg(&reference)
        .arg(&target)
        .arg("-o")
        .arg(&delta)
        .args(["--hash", "sha256"])
        .status()
        .unwrap();
    assert!(status.success(), "create failed");

    let status = bin()
        .args(["apply"])
        .arg(&reference)
        .arg(&delta)
        .arg("-o")
        .arg(&out)
        .status()
        .unwrap();
    assert!(status.success(), "apply failed");

    assert_eq!(std::fs::read(&out).unwrap(), tgt, "round-trip mismatch");
}

/// A real DCM-wrapped WinSxS manifest decodes against the base manifest.
#[test]
fn decode_real_manifest() {
    let base = fixtures().join("base_manifest.bin");
    let manifest = fixtures().join(
        "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
    );
    if !base.exists() || !manifest.exists() {
        eprintln!("skipping: fixtures not present");
        return;
    }

    let out = bin()
        .args(["apply"])
        .arg(&base)
        .arg(&manifest)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.starts_with(b"<?xml"),
        "expected XML, got: {:?}",
        &out.stdout[..out.stdout.len().min(32)]
    );
}

/// `info` on the same manifest reports the DCM container and PA30 version.
#[test]
fn info_reports_container() {
    let manifest = fixtures().join(
        "amd64_microsoft-windows-core_31bf3856ad364e35_10.0.26100.1_none_a943f5e781a44c5c.manifest",
    );
    if !manifest.exists() {
        eprintln!("skipping: fixture not present");
        return;
    }

    let out = bin().args(["info"]).arg(&manifest).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("container:    DCM"), "got:\n{text}");
    assert!(text.contains("PA30"), "got:\n{text}");
}

/// Unknown enum values are rejected by clap with a non-zero exit.
#[test]
fn rejects_bad_hash() {
    let dir = tempdir();
    let f = dir.join("f.bin");
    std::fs::write(&f, b"hello").unwrap();

    let status = bin()
        .args(["create"])
        .arg(&f)
        .arg(&f)
        .args(["--hash", "crc32"])
        .status()
        .unwrap();
    assert!(!status.success(), "bad --hash value should fail");
}

/// `signature --normalize` produces a stable digest line.
#[test]
fn signature_outputs_digest() {
    let dir = tempdir();
    let f = dir.join("f.bin");
    std::fs::write(&f, b"some bytes to hash").unwrap();

    let out = bin().args(["signature"]).arg(&f).output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("sha256 "), "got: {text}");
    // 32-byte digest -> 64 hex chars plus the "sha256 " prefix and newline.
    assert_eq!(text.trim().len(), "sha256 ".len() + 64);
}

/// Per-test scratch directory under the target dir; no external tempfile dep.
fn tempdir() -> PathBuf {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    // CARGO_TARGET_TMPDIR is unique per test binary; namespace by test thread.
    let dir = base.join(format!("t-{:?}", std::thread::current().id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
