//! Building a scored, bucketed report for the msdelta domain.
//!
//! Merges every `result.<dll>.json` in a job directory with the locally-run
//! decode oracle (apply each genuine gold with our decoder) into one
//! [`Report`]. The decode half is the "read anything MS emits" surface, tested
//! for free on the golds the lab produced.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::kernel::report::{bucketize, Bucket, DllResult, Verdict};
use crate::kernel::Job;

use super::{sha256_hex, CreateSpec};

/// Per-DLL scored verdicts for one case.
#[derive(Serialize, Clone, Debug)]
pub struct DllCaseReport {
    /// Our delta applied by the genuine DLL (encode interop).
    pub ours_to_native: Verdict,
    /// Genuine `CreateDeltaB` produced a delta (native produce half).
    pub native_create: Verdict,
    /// Our decoder applied the genuine gold == target (decode interop, local).
    pub native_decode: Verdict,
    /// Genuine create->apply round-trip (control).
    pub native_to_native: Verdict,
}

/// One case across all DLLs.
#[derive(Serialize, Clone, Debug)]
pub struct CaseReport {
    pub id: String,
    pub category: String,
    pub dlls: BTreeMap<String, DllCaseReport>,
}

/// The merged report.
#[derive(Serialize, Clone, Debug)]
pub struct Report {
    pub domain: String,
    pub seed: u64,
    /// `"dll/direction" -> [pass, total]` (skipped cases excluded from total).
    pub summary: BTreeMap<String, [usize; 2]>,
    pub buckets: Vec<Bucket>,
    pub cases: Vec<CaseReport>,
}

/// Locally decode one genuine gold and compare to the expected target.
fn decode_gold(
    dir: &Path,
    reference: &str,
    gold: &str,
    expected_sha: &str,
) -> Verdict {
    let refb = match fs::read(dir.join(reference)) {
        Ok(b) => b,
        Err(e) => return Verdict::Error { detail: format!("read ref: {e}") },
    };
    let goldb = match fs::read(dir.join(gold)) {
        Ok(b) => b,
        Err(e) => return Verdict::Error { detail: format!("read gold: {e}") },
    };
    match msdelta::pa30::apply(&refb, &goldb) {
        Ok(out) if sha256_hex(&out) == expected_sha => Verdict::Pass,
        Ok(out) => Verdict::Fail {
            detail: format!("decoded {} bytes, sha mismatch", out.len()),
        },
        Err(e) => Verdict::Error { detail: format!("our decode: {e}") },
    }
}

/// Build the merged report from a job directory containing `job.json`, the
/// inputs, and one or more `result.<dll>.json` (+ golds) pulled from the lab.
pub fn build_report(dir: &Path) -> io::Result<Report> {
    let job: Job<CreateSpec> = Job::read(dir)?;

    // Index job cases for category + reference/target lookup.
    struct CaseMeta {
        category: String,
        reference: String,
        target_sha256: String,
    }
    let meta: BTreeMap<String, CaseMeta> = job
        .cases
        .iter()
        .map(|c| {
            (
                c.id.clone(),
                CaseMeta {
                    category: c.category.clone(),
                    reference: c.reference.clone(),
                    target_sha256: c.target_sha256.clone(),
                },
            )
        })
        .collect();

    // Load every result.<dll>.json in the dir.
    let mut dll_results: Vec<DllResult> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("result.") && name.ends_with(".json") {
            dll_results.push(DllResult::read(&path)?);
        }
    }
    dll_results.sort_by(|a, b| a.dll.cmp(&b.dll));

    // Assemble per-case, per-dll verdicts.
    let mut cases: BTreeMap<String, CaseReport> = BTreeMap::new();
    let mut summary: BTreeMap<String, [usize; 2]> = BTreeMap::new();

    let tally = |key: String, v: &Verdict, summary: &mut BTreeMap<String, [usize; 2]>| {
        if matches!(v, Verdict::Skipped) {
            return;
        }
        let e = summary.entry(key).or_default();
        e[1] += 1;
        if v.is_pass() {
            e[0] += 1;
        }
    };

    for dr in &dll_results {
        for rc in &dr.results {
            let Some(m) = meta.get(&rc.id) else { continue };
            let ours = Verdict::classify(rc.ours_to_native.as_ref());
            let create = Verdict::classify(rc.native_to_ours.as_ref());
            let control = Verdict::classify(rc.native_to_native.as_ref());

            // Local decode: only meaningful if create produced a gold.
            let decode = match rc.native_to_ours.as_ref() {
                Some(v) if v.status == "OK" && !v.gold.is_empty() => {
                    decode_gold(dir, &m.reference, &v.gold, &m.target_sha256)
                }
                _ => Verdict::Skipped,
            };

            tally(format!("{}/ours_to_native", dr.dll), &ours, &mut summary);
            tally(format!("{}/native_create", dr.dll), &create, &mut summary);
            tally(format!("{}/native_decode", dr.dll), &decode, &mut summary);
            tally(format!("{}/native_to_native", dr.dll), &control, &mut summary);

            cases
                .entry(rc.id.clone())
                .or_insert_with(|| CaseReport {
                    id: rc.id.clone(),
                    category: m.category.clone(),
                    dlls: BTreeMap::new(),
                })
                .dlls
                .insert(
                    dr.dll.clone(),
                    DllCaseReport {
                        ours_to_native: ours,
                        native_create: create,
                        native_decode: decode,
                        native_to_native: control,
                    },
                );
        }
    }

    let cases: Vec<CaseReport> = cases.into_values().collect();

    // Bucket failures across every (direction, dll, category, id).
    let mut rows: Vec<(&str, &str, &str, &str, &Verdict)> = Vec::new();
    for c in &cases {
        for (dll, r) in &c.dlls {
            rows.push(("ours_to_native", dll, &c.category, &c.id, &r.ours_to_native));
            rows.push(("native_create", dll, &c.category, &c.id, &r.native_create));
            rows.push(("native_decode", dll, &c.category, &c.id, &r.native_decode));
            rows.push(("native_to_native", dll, &c.category, &c.id, &r.native_to_native));
        }
    }
    let buckets = bucketize(rows.into_iter());

    Ok(Report {
        domain: job.domain,
        seed: job.seed,
        summary,
        buckets,
        cases,
    })
}
