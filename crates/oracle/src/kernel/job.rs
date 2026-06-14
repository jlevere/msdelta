//! The job wire format: the versioned contract between the local Rust side and
//! the native reference executor on the lab host.
//!
//! A *job* is a directory containing input/artifact files plus a `job.json`
//! that describes every case. The Rust side writes it; the lab executor reads
//! it and runs the requested [`Direction`]s. Everything domain-specific is
//! confined to the opaque-to-the-kernel `native` payload (`P`), so the kernel
//! neither knows nor cares that the payload describes delta creation.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::Direction;

/// Current `job.json` schema version. Bump on any breaking layout change so an
/// old executor refuses a new job rather than misreading it.
pub const SCHEMA_VERSION: u32 = 1;

/// Filename of the manifest within a job directory.
pub const JOB_FILE: &str = "job.json";

/// A full job: a set of cases sharing a generation seed and domain.
///
/// Generic over `P`, the domain's per-case native payload (for the msdelta
/// domain that is [`crate::msdelta::CreateSpec`]).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Job<P> {
    /// Wire schema version; see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Domain name (e.g. `"msdelta"`). Lets one executor host multiple domains.
    pub domain: String,
    /// Seed the cases were generated from; makes a run reproducible.
    pub seed: u64,
    /// The cases to run.
    pub cases: Vec<JobCase<P>>,
}

/// One case in a job. File fields are names relative to the job directory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct JobCase<P> {
    /// Stable, reproducible identifier (e.g. `"manifest_pair.0007"`).
    pub id: String,
    /// Generator category this case came from.
    pub category: String,
    /// Reference (source) buffer filename.
    pub reference: String,
    /// Expected target buffer filename.
    pub target: String,
    /// Our encoder's delta filename (pre-produced locally for `ours_to_native`).
    pub ours_delta: String,
    /// Hex SHA-256 of the expected target.
    pub target_sha256: String,
    /// Length of the expected target in bytes.
    pub target_len: u64,
    /// Hex SHA-256 of the reference (source). Lets the executor verify a reverse
    /// delta reconstructs the source.
    #[serde(default)]
    pub reference_sha256: String,
    /// Our reverse-delta filename (target -> reference), produced when the case
    /// runs the `reverse_round_trip` direction. None otherwise.
    #[serde(default)]
    pub reverse_delta: Option<String>,
    /// Domain-specific native-side parameters (opaque to the kernel).
    pub native: P,
    /// Which interop-matrix cells to run for this case.
    pub directions: Vec<Direction>,
}

impl<P> Job<P>
where
    P: Serialize + DeserializeOwned,
{
    /// Build an empty job for a domain + seed.
    pub fn new(domain: impl Into<String>, seed: u64) -> Self {
        Job {
            schema_version: SCHEMA_VERSION,
            domain: domain.into(),
            seed,
            cases: Vec::new(),
        }
    }

    /// Serialize `job.json` into `dir`. Input/artifact files referenced by the
    /// cases are written separately (by the domain's lowering); this writes
    /// only the manifest. Creates `dir` if needed.
    pub fn write(&self, dir: &Path) -> io::Result<PathBuf> {
        fs::create_dir_all(dir)?;
        let path = dir.join(JOB_FILE);
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Read and validate `job.json` from `dir`.
    pub fn read(dir: &Path) -> io::Result<Self> {
        let bytes = fs::read(dir.join(JOB_FILE))?;
        let slice = bytes
            .strip_prefix(&[0xEF, 0xBB, 0xBF])
            .unwrap_or(bytes.as_slice());
        let job: Job<P> = serde_json::from_slice(slice).map_err(io::Error::other)?;
        if job.schema_version != SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "job.json schema_version {} != supported {}",
                    job.schema_version, SCHEMA_VERSION
                ),
            ));
        }
        Ok(job)
    }
}
