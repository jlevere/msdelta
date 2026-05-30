//! End-to-end test of the job wire contract: generate in-memory cases, lower
//! them through the msdelta domain into a job directory, then read the job
//! back and confirm it survives the round trip with all files present.

use std::fs;

use oracle::kernel::{Direction, Domain, Job};
use oracle::msdelta::{CreateSpec, MsDeltaCase, MsDeltaDomain, FILE_TYPE_RAW, HASH_ALG_MD5};

fn sample_cases() -> Vec<MsDeltaCase> {
    let reference = b"the quick brown fox jumps over the lazy dog, repeatedly and often".to_vec();
    let target = b"the quick brown cat jumps over the lazy dog, repeatedly and rarely".to_vec();
    vec![
        MsDeltaCase::raw("text.0001", "text", reference.clone(), target.clone()),
        // Same inputs but with an MD5 integrity hash on the native side.
        {
            let mut c = MsDeltaCase::raw("text.0002", "text", reference, target);
            c.native = CreateSpec::raw().with_hash(HASH_ALG_MD5);
            c.directions = vec![Direction::OursToNative, Direction::OursToOurs];
            c
        },
    ]
}

#[test]
fn job_round_trips_through_disk() {
    let dir = tempfile::tempdir().unwrap();
    let domain = MsDeltaDomain;
    let cases = sample_cases();

    let written = domain.build_job(0xC0FFEE, &cases, dir.path()).unwrap();
    assert_eq!(written.domain, "msdelta");
    assert_eq!(written.seed, 0xC0FFEE);
    assert_eq!(written.cases.len(), 2);

    // Read it back through the kernel and confirm structural identity.
    let read: Job<CreateSpec> = Job::read(dir.path()).unwrap();
    assert_eq!(read, written);
    assert_eq!(read.schema_version, 1);

    // Every referenced file exists and the recorded length matches.
    for case in &read.cases {
        for name in [&case.reference, &case.target, &case.ours_delta] {
            assert!(dir.path().join(name).exists(), "missing {name}");
        }
        let target = fs::read(dir.path().join(&case.target)).unwrap();
        assert_eq!(target.len() as u64, case.target_len);
    }
}

#[test]
fn create_spec_carries_exact_native_args() {
    let dir = tempfile::tempdir().unwrap();
    let domain = MsDeltaDomain;
    let job = domain.build_job(1, &sample_cases(), dir.path()).unwrap();

    // Case 1: plain raw, no hash.
    assert_eq!(job.cases[0].native.file_type_set, FILE_TYPE_RAW);
    assert_eq!(job.cases[0].native.hash_alg, 0);
    // Case 2: raw + MD5 hash, restricted direction set.
    assert_eq!(job.cases[1].native.hash_alg, HASH_ALG_MD5);
    assert_eq!(
        job.cases[1].directions,
        vec![Direction::OursToNative, Direction::OursToOurs]
    );
}

#[test]
fn direction_serializes_to_snake_case() {
    let json = serde_json::to_string(&Direction::OursToNative).unwrap();
    assert_eq!(json, "\"ours_to_native\"");
    let back: Direction = serde_json::from_str("\"native_to_ours\"").unwrap();
    assert_eq!(back, Direction::NativeToOurs);
}
