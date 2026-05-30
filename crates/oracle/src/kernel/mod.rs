//! Domain-agnostic differential-testing kernel.
//!
//! Owns the job wire format ([`job`]), the interop matrix ([`Direction`]), and
//! the [`Domain`] seam that domains plug into. Knows nothing about deltas,
//! WIM, or any specific format. Later phases add transport, scoring,
//! bucketing, and minimization here.

mod direction;
pub mod job;
pub mod report;
pub mod rng;

use std::io;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;

pub use direction::Direction;
pub use job::{Job, JobCase};

/// A seeded, deterministic source of cases for one category.
///
/// Generic over the case type `C` (the domain supplies it), so the kernel
/// stays domain-agnostic. `generate` must be a pure function of `(seed,
/// count)`: the same arguments always yield identical cases, which is what
/// makes a failing run reproducible off-lab.
pub trait Generator<C> {
    /// Stable category name, recorded on every case this produces.
    fn category(&self) -> &str;

    /// Produce up to `count` cases from `seed`. May return fewer (e.g. a
    /// fixture-backed generator with fewer than `count` fixtures available).
    fn generate(&self, seed: u64, count: usize) -> Vec<C>;
}

/// A pluggable problem domain (e.g. PA30 deltas, or WIM resources).
///
/// The kernel drives the harness generically over this trait. A domain
/// supplies its in-memory case type, the serializable native-side payload that
/// crosses the wire, and the *lowering* from one to the other: writing the
/// case's input/artifact files into a job directory and producing the matching
/// [`JobCase`] record.
///
/// Generators ([phase 0b]) and the local-consume oracle ([phase 0d]) attach to
/// this same trait as they land; it is intentionally small now and grows as
/// the kernel does.
///
/// [phase 0b]: crate::msdelta
/// [phase 0d]: crate::msdelta
pub trait Domain {
    /// In-memory case content produced by the domain's generators.
    type Case;

    /// Per-case parameters the native reference needs, serialized into
    /// `job.json` verbatim. Opaque to the kernel.
    type NativeParams: Serialize + DeserializeOwned + Clone;

    /// Stable domain name, stored in the job and used in paths/reports.
    fn name(&self) -> &str;

    /// Lower an in-memory case into wire form: write its `reference`, `target`,
    /// and our-encoder `ours_delta` files under `dir`, and return the
    /// [`JobCase`] describing them. Errors propagate (e.g. our encoder failing
    /// on a case is itself a finding worth surfacing).
    fn lower(
        &self,
        case: &Self::Case,
        dir: &Path,
    ) -> io::Result<JobCase<Self::NativeParams>>;

    /// Build a [`Job`] by lowering every case into `dir` and writing the
    /// manifest. Default impl is the common path; domains rarely override it.
    fn build_job(
        &self,
        seed: u64,
        cases: &[Self::Case],
        dir: &Path,
    ) -> io::Result<Job<Self::NativeParams>> {
        std::fs::create_dir_all(dir)?; // lowering writes input files into dir
        let mut job = Job::new(self.name().to_string(), seed);
        for case in cases {
            job.cases.push(self.lower(case, dir)?);
        }
        job.write(dir)?;
        Ok(job)
    }
}
