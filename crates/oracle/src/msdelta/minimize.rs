//! Failure minimization: shrink a failing case to a small repro.
//!
//! The lab oracle round-trip is the expensive step, so each round produces a
//! batch of shrink candidates evaluated together in ONE lab job (the harness
//! already runs N cases per invocation). The smallest candidate that still
//! reproduces the failure becomes the next round's input.
//!
//! Prefix-bisection alone is unsound here: msdelta's acceptance is
//! non-monotonic in target length (a 12000-byte prefix can fail where 16000
//! passes). So each round probes several cut points and orientations (head
//! prefixes, tail suffixes, middle excisions) and keeps the smallest survivor,
//! converging on a small -- not provably minimal -- repro. That mirrors how the
//! 938-byte manifest repro was found by hand.

use msdelta::pa30::{Codec, CreateOptions, FileType};

use super::spec::FILE_TYPE_RAW;
use super::CreateSpec;

/// Best-effort reconstruction of our encoder options from the genuine
/// `CreateSpec`, so shrunk candidates are encoded the same way the original
/// failing case was. (job.json carries the native spec, not our CreateOptions.)
pub fn ours_from_spec(spec: &CreateSpec) -> CreateOptions {
    let mut o = CreateOptions::new();
    o = if spec.file_type_set == FILE_TYPE_RAW {
        o.file_type(FileType::Raw)
    } else {
        o.file_type(FileType::Auto)
    };
    if spec.set_flags & 0x100 != 0 {
        o = o.codec(Codec::BsDiff);
    }
    if spec.hash_alg != 0 {
        o = o.hash_algorithm(spec.hash_alg);
    }
    o
}

/// A labeled shrink candidate: how it was derived plus the shrunk target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub label: String,
    pub target: Vec<u8>,
}

/// Smallest candidate length we bother probing.
const MIN_LEN: usize = 8;

/// Produce shrink candidates for `target`. Deterministic; mixes head-prefixes,
/// tail-suffixes, and middle excisions at several granularities so a
/// non-monotonic acceptance boundary is still crossed.
pub fn shrink_candidates(target: &[u8]) -> Vec<Candidate> {
    let n = target.len();
    if n <= MIN_LEN {
        return Vec::new();
    }
    let mut out: Vec<Candidate> = Vec::new();
    let mut push = |label: String, bytes: Vec<u8>| {
        if bytes.len() >= MIN_LEN && bytes.len() < n {
            out.push(Candidate {
                label,
                target: bytes,
            });
        }
    };

    // Head prefixes (keep the start).
    for (num, den) in [(7, 8), (3, 4), (1, 2), (1, 4), (1, 8)] {
        let len = n * num / den;
        push(format!("prefix_{num}_{den}"), target[..len].to_vec());
    }
    // Tail suffixes (drop the start).
    for (num, den) in [(3, 4), (1, 2)] {
        let start = n - n * num / den;
        push(format!("suffix_{num}_{den}"), target[start..].to_vec());
    }
    // Middle excisions (remove a central span, splice head+tail).
    for (num, den) in [(1, 2), (1, 4)] {
        let cut = n * num / den;
        let lo = (n - cut) / 2;
        let hi = lo + cut;
        let mut spliced = target[..lo].to_vec();
        spliced.extend_from_slice(&target[hi..]);
        push(format!("excise_mid_{num}_{den}"), spliced);
    }

    // Dedup by length (cheap) keeping distinct sizes; many fractions collide
    // on tiny inputs.
    out.sort_by_key(|c| c.target.len());
    out.dedup_by_key(|c| c.target.len());
    out
}
