//! Reading native-executor results and scoring them into a report.
//!
//! The lab harness writes one `result.<dll>.json` per reference DLL. This
//! module deserializes those (tolerating the UTF-8 BOM that PowerShell's
//! `Set-Content -Encoding utf8` prepends), classifies each cell of the interop
//! matrix into a [`Verdict`], and buckets failures by signature so a run
//! reports "N/M pass, K buckets" instead of a wall of cases.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One direction's raw result as emitted by the harness. Fields are optional
/// because their presence depends on the direction (apply vs create).
#[derive(Deserialize, Clone, Debug, Default)]
pub struct RawVerdict {
    pub status: String,
    #[serde(default)]
    pub got_sha: String,
    #[serde(default)]
    pub got_len: i64,
    #[serde(default)]
    pub gold: String,
    #[serde(default)]
    pub gold_len: i64,
    #[serde(default)]
    pub message: String,
}

/// One case's raw results across the directions the harness ran.
#[derive(Deserialize, Clone, Debug)]
pub struct RawCase {
    pub id: String,
    pub ours_to_native: Option<RawVerdict>,
    pub native_to_ours: Option<RawVerdict>,
    pub native_to_native: Option<RawVerdict>,
}

/// A full `result.<dll>.json`.
#[derive(Deserialize, Clone, Debug)]
pub struct DllResult {
    pub dll: String,
    pub domain: String,
    pub seed: u64,
    pub results: Vec<RawCase>,
}

impl DllResult {
    /// Read a `result.<dll>.json`, stripping a leading UTF-8 BOM if present.
    pub fn read(path: &Path) -> io::Result<Self> {
        let bytes = fs::read(path)?;
        let slice = bytes
            .strip_prefix(&[0xEF, 0xBB, 0xBF])
            .unwrap_or(bytes.as_slice());
        serde_json::from_slice(slice).map_err(io::Error::other)
    }
}

/// Scored outcome for one cell of the interop matrix.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Produced the exact target (apply) or created a delta (create).
    Pass,
    /// Ran but produced the wrong bytes.
    Fail { detail: String },
    /// The native call or our decode errored.
    Error { detail: String },
    /// Not run for this case/direction.
    Skipped,
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }

    /// Map a harness status string + verdict body into a [`Verdict`].
    /// `apply_like` directions compare a produced hash; create-only records
    /// treat "OK" as pass.
    pub fn classify(raw: Option<&RawVerdict>) -> Verdict {
        match raw {
            None => Verdict::Skipped,
            Some(v) => match v.status.as_str() {
                "PASS" | "OK" => Verdict::Pass,
                "FAIL" => Verdict::Fail {
                    detail: format!("got {} ({}B)", short_sha(&v.got_sha), v.got_len),
                },
                _ => Verdict::Error {
                    detail: normalize_error(&v.message),
                },
            },
        }
    }
}

fn short_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

/// Collapse a native error message to a stable bucket key (e.g. drop the
/// "Exception calling ..." wrapper, keep "ApplyDeltaB GetLastError=13").
pub fn normalize_error(msg: &str) -> String {
    if let Some(idx) = msg.find("GetLastError=") {
        let tail = &msg[idx..];
        let code: String = tail
            .chars()
            .take_while(|c| *c != '"' && *c != '\\')
            .collect();
        return code;
    }
    if msg.contains("Object reference not set") {
        return "null-output (empty target)".to_string();
    }
    msg.chars().take(60).collect()
}

/// A bucket of failures sharing a signature.
#[derive(Serialize, Clone, Debug)]
pub struct Bucket {
    pub signature: String,
    pub count: usize,
    pub examples: Vec<String>,
}

/// Group failing `(direction-label, dll, category, id, verdict)` rows into
/// buckets by `direction|dll|category|detail`.
pub fn bucketize<'a>(
    rows: impl Iterator<Item = (&'a str, &'a str, &'a str, &'a str, &'a Verdict)>,
) -> Vec<Bucket> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (dir, dll, category, id, verdict) in rows {
        let detail = match verdict {
            Verdict::Pass | Verdict::Skipped => continue,
            Verdict::Fail { detail } => format!("FAIL {detail}"),
            Verdict::Error { detail } => format!("ERROR {detail}"),
        };
        let sig = format!("{dir}|{dll}|{category}|{detail}");
        map.entry(sig).or_default().push(id.to_string());
    }
    map.into_iter()
        .map(|(signature, mut examples)| {
            let count = examples.len();
            examples.truncate(5);
            Bucket {
                signature,
                count,
                examples,
            }
        })
        .collect()
}
