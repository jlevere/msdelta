//! The msdelta in-memory case and its lowering into a job.

use std::fs;
use std::io;
use std::path::Path;

use msdelta::pa30::CreateOptions;
use sha2::{Digest, Sha256};

use crate::kernel::{Direction, JobCase};

use super::CreateSpec;

/// One differential-test case in the PA30-delta domain.
///
/// Held in memory by generators. It pairs *how we encode* (`ours`, our
/// [`CreateOptions`]) with *how the native reference creates* (`native`, the
/// genuine [`CreateSpec`]). The two should describe the same intent (both raw,
/// or both executable); the [`raw`](MsDeltaCase::raw) and
/// [`executables`](MsDeltaCase::executables) constructors keep them in sync.
#[derive(Clone, Debug)]
pub struct MsDeltaCase {
    /// Stable identifier (e.g. `"text.0001"`).
    pub id: String,
    /// Generator category.
    pub category: String,
    /// Reference (source) buffer.
    pub reference: Vec<u8>,
    /// Expected target buffer.
    pub target: Vec<u8>,
    /// How our encoder produces this case's delta.
    pub ours: CreateOptions,
    /// The genuine `CreateDeltaB` parameters for this case.
    pub native: CreateSpec,
    /// Which interop-matrix cells to run.
    pub directions: Vec<Direction>,
}

/// Every direction; the default coverage for a fully exercised case.
pub fn all_directions() -> Vec<Direction> {
    vec![
        Direction::OursToNative,
        Direction::NativeToOurs,
        Direction::NativeToNative,
        Direction::OursToOurs,
    ]
}

impl MsDeltaCase {
    /// Fully explicit constructor: pair an arbitrary [`CreateOptions`] with an
    /// arbitrary [`CreateSpec`]. Used by generators that exercise non-default
    /// codecs/hashes/versions (e.g. bsdiff, MD5, PA31). Defaults to all
    /// directions; narrow with [`with_directions`](MsDeltaCase::with_directions).
    pub fn new(
        id: impl Into<String>,
        category: impl Into<String>,
        reference: Vec<u8>,
        target: Vec<u8>,
        ours: CreateOptions,
        native: CreateSpec,
    ) -> Self {
        MsDeltaCase {
            id: id.into(),
            category: category.into(),
            reference,
            target,
            ours,
            native,
            directions: all_directions(),
        }
    }

    /// A raw (non-executable) case: our `CreateOptions::new()` against
    /// [`CreateSpec::raw`], all directions.
    pub fn raw(
        id: impl Into<String>,
        category: impl Into<String>,
        reference: Vec<u8>,
        target: Vec<u8>,
    ) -> Self {
        MsDeltaCase {
            id: id.into(),
            category: category.into(),
            reference,
            target,
            ours: CreateOptions::new(),
            native: CreateSpec::raw(),
            directions: all_directions(),
        }
    }

    /// An executable (PE) case: our auto file-type detection against
    /// [`CreateSpec::executables`], all directions.
    pub fn executables(
        id: impl Into<String>,
        category: impl Into<String>,
        reference: Vec<u8>,
        target: Vec<u8>,
    ) -> Self {
        use msdelta::pa30::FileType;
        MsDeltaCase {
            id: id.into(),
            category: category.into(),
            reference,
            target,
            ours: CreateOptions::new().file_type(FileType::Auto),
            native: CreateSpec::executables(),
            directions: all_directions(),
        }
    }

    /// Restrict this case to a subset of directions (builder style).
    pub fn with_directions(mut self, directions: Vec<Direction>) -> Self {
        self.directions = directions;
        self
    }

    /// Lower into wire form: write `<id>.ref`, `<id>.target`, and
    /// `<id>.ours.delta` under `dir`, then return the [`JobCase`] record.
    /// Decode-only cases get an empty delta placeholder because the harness only
    /// reads it for directions that consume our output.
    pub fn lower(&self, dir: &Path) -> io::Result<JobCase<CreateSpec>> {
        let ref_name = format!("{}.ref", self.id);
        let tgt_name = format!("{}.target", self.id);
        let delta_name = format!("{}.ours.delta", self.id);

        fs::write(dir.join(&ref_name), &self.reference)?;
        fs::write(dir.join(&tgt_name), &self.target)?;

        let needs_ours_delta = needs_ours_forward_delta(&self.directions);
        let delta = if needs_ours_delta {
            // Our encoder running on this case is itself part of the test surface:
            // a failure here is a finding, so surface it rather than skipping.
            let delta = self
                .ours
                .execute(&self.reference, &self.target)
                .map_err(|e| {
                    io::Error::other(format!("our encoder failed on case {}: {e}", self.id))
                })?;
            fs::write(dir.join(&delta_name), &delta)?;
            Some(delta)
        } else {
            fs::write(dir.join(&delta_name), [])?;
            None
        };

        // For reverse-delta cases, also produce our reverse delta (target ->
        // reference) so the executor can check the genuine DLL accepts it.
        let reverse_delta = if self.directions.contains(&Direction::ReverseRoundTrip) {
            let delta = delta
                .as_deref()
                .expect("reverse round-trip cases should produce an ours delta");
            let (_target, rev) =
                msdelta::pa30::apply_get_reverse(&self.reference, delta).map_err(|e| {
                    io::Error::other(format!("our apply_get_reverse failed on {}: {e}", self.id))
                })?;
            let name = format!("{}.ours.reverse.delta", self.id);
            fs::write(dir.join(&name), &rev)?;
            Some(name)
        } else {
            None
        };

        Ok(JobCase {
            id: self.id.clone(),
            category: self.category.clone(),
            reference: ref_name,
            target: tgt_name,
            ours_delta: delta_name,
            target_sha256: sha256_hex(&self.target),
            target_len: self.target.len() as u64,
            reference_sha256: sha256_hex(&self.reference),
            reverse_delta,
            native: self.native.clone(),
            directions: self.directions.clone(),
        })
    }
}

fn needs_ours_forward_delta(directions: &[Direction]) -> bool {
    directions.iter().any(|direction| {
        matches!(
            direction,
            Direction::OursToNative | Direction::OursToOurs | Direction::ReverseRoundTrip
        )
    })
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
