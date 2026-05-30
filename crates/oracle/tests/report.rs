//! Offline tests for result parsing, scoring, and bucketing. The full
//! build_report path is validated against real lab output; these cover the
//! pure pieces without a lab.

use oracle::kernel::report::{bucketize, normalize_error, DllResult, RawVerdict, Verdict};

#[test]
fn dll_result_tolerates_utf8_bom() {
    let json = r#"{"dll":"msdelta.dll","domain":"msdelta","seed":1,"results":[
        {"id":"a","ours_to_native":{"status":"PASS","got_sha":"ab","got_len":3}}]}"#;
    let with_bom = {
        let mut v = vec![0xEF, 0xBB, 0xBF];
        v.extend_from_slice(json.as_bytes());
        v
    };
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("result.msdelta.json");
    std::fs::write(&p, with_bom).unwrap();
    let r = DllResult::read(&p).unwrap();
    assert_eq!(r.dll, "msdelta.dll");
    assert_eq!(r.results.len(), 1);
}

#[test]
fn normalize_error_extracts_stable_keys() {
    assert_eq!(
        normalize_error("Exception calling \"Apply\": \"ApplyDeltaB GetLastError=13\""),
        "GetLastError=13"
    );
    assert_eq!(
        normalize_error("Object reference not set to an instance of an object."),
        "null-output (empty target)"
    );
}

#[test]
fn classify_maps_statuses() {
    let pass = RawVerdict { status: "PASS".into(), ..Default::default() };
    let ok = RawVerdict { status: "OK".into(), ..Default::default() };
    let fail = RawVerdict { status: "FAIL".into(), got_sha: "deadbeef".into(), got_len: 9, ..Default::default() };
    let err = RawVerdict { status: "ERROR".into(), message: "x GetLastError=13".into(), ..Default::default() };
    assert!(Verdict::classify(Some(&pass)).is_pass());
    assert!(Verdict::classify(Some(&ok)).is_pass());
    assert!(matches!(Verdict::classify(Some(&fail)), Verdict::Fail { .. }));
    assert!(matches!(Verdict::classify(Some(&err)), Verdict::Error { .. }));
    assert!(matches!(Verdict::classify(None), Verdict::Skipped));
}

#[test]
fn bucketize_groups_by_signature_and_skips_passes() {
    let pass = Verdict::Pass;
    let err13a = Verdict::Error { detail: "GetLastError=13".into() };
    let err13b = Verdict::Error { detail: "GetLastError=13".into() };
    let rows = vec![
        ("ours_to_native", "msdelta.dll", "manifest_pair", "m.0", &err13a),
        ("ours_to_native", "msdelta.dll", "manifest_pair", "m.1", &err13b),
        ("ours_to_native", "msdelta.dll", "text", "t.0", &pass), // skipped
    ];
    let buckets = bucketize(rows.into_iter());
    assert_eq!(buckets.len(), 1, "two same-signature errors -> one bucket");
    assert_eq!(buckets[0].count, 2);
    assert!(buckets[0].signature.contains("manifest_pair"));
}
