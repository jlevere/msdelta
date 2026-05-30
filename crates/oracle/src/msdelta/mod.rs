//! The PA30-delta domain: the [`Domain`] plugin for `msdelta`.
//!
//! Supplies what a case is ([`MsDeltaCase`]), the genuine `CreateDeltaB`
//! parameters that cross the wire ([`CreateSpec`]), and the lowering from one
//! to the other. Generators (phase 0b) and the local-consume decode oracle
//! (phase 0d) attach here.

mod case;
pub mod generators;
pub mod minimize;
pub mod report;
mod spec;

use std::io;
use std::path::Path;

use crate::kernel::{Domain, JobCase};

pub use case::{all_directions, sha256_hex, MsDeltaCase};
pub use generators::default_suite;
pub use spec::{
    CreateSpec, FILE_TYPE_RAW, FILE_TYPE_SET_EXECUTABLES, HASH_ALG_MD5, HASH_ALG_NONE,
    HASH_ALG_SHA256,
};

/// The PA30-delta domain. Zero-sized; state-free.
#[derive(Clone, Copy, Debug, Default)]
pub struct MsDeltaDomain;

/// The domain name stored in `job.json`.
pub const DOMAIN_NAME: &str = "msdelta";

impl Domain for MsDeltaDomain {
    type Case = MsDeltaCase;
    type NativeParams = CreateSpec;

    fn name(&self) -> &str {
        DOMAIN_NAME
    }

    fn lower(&self, case: &MsDeltaCase, dir: &Path) -> io::Result<JobCase<CreateSpec>> {
        case.lower(dir)
    }
}
