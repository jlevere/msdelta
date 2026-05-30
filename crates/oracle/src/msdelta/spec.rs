//! The genuine `CreateDeltaB` parameters for a case.
//!
//! These are the exact arguments the native executor passes to
//! `CreateDeltaB(FileTypeSet, SetFlags, ResetFlags, ..., HashAlgId, ...)`.
//! Carrying them explicitly in `job.json` is what lets the lab harness be a
//! dumb executor: it never has to infer the file-type set from the case name
//! (the fragile `name -like "pe_*"` heuristic the old `gen_golden.ps1` used).

use serde::{Deserialize, Serialize};

/// `DELTA_FILE_TYPE_RAW`: treat inputs as opaque bytes, no executable transform.
pub const FILE_TYPE_RAW: u64 = 0x0000_0001;

/// `DELTA_FILE_TYPE_SET_EXECUTABLES` = RAW | I386 | IA64 | AMD64 = 0x0F. Lets
/// `CreateDeltaB` pick the right per-architecture executable transform. (NOT
/// 0xFFFFFFFE -- that sets undefined high bits and clears RAW, and genuine
/// CreateDeltaB rejects it with ERROR_INVALID_DATA; the oracle's control
/// direction caught that.)
pub const FILE_TYPE_SET_EXECUTABLES: u64 = 0x0000_000F;

/// No target-integrity hash.
pub const HASH_ALG_NONE: u32 = 0x0000_0000;
/// `CALG_MD5`.
pub const HASH_ALG_MD5: u32 = 0x0000_8003;
/// `CALG_SHA_256`. Only honored by `UpdateCompression.dll`, not `msdelta.dll`.
pub const HASH_ALG_SHA256: u32 = 0x0000_800C;

/// Parameters for one genuine `CreateDeltaB` call.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CreateSpec {
    /// `FileTypeSet` argument.
    pub file_type_set: u64,
    /// `SetFlags` argument (e.g. `0x100` selects the documented "bsdiff" mode).
    pub set_flags: u64,
    /// `ResetFlags` argument.
    pub reset_flags: u64,
    /// `HashAlgId` argument; one of the `HASH_ALG_*` constants.
    pub hash_alg: u32,
}

impl CreateSpec {
    /// A raw (non-executable) delta with no hash.
    pub fn raw() -> Self {
        CreateSpec {
            file_type_set: FILE_TYPE_RAW,
            set_flags: 0,
            reset_flags: 0,
            hash_alg: HASH_ALG_NONE,
        }
    }

    /// An executable (PE) delta with no hash, letting `CreateDeltaB` auto-pick
    /// the architecture transform.
    pub fn executables() -> Self {
        CreateSpec {
            file_type_set: FILE_TYPE_SET_EXECUTABLES,
            set_flags: 0,
            reset_flags: 0,
            hash_alg: HASH_ALG_NONE,
        }
    }

    /// Set the target-integrity hash algorithm (builder style).
    pub fn with_hash(mut self, alg: u32) -> Self {
        self.hash_alg = alg;
        self
    }

    /// Set `SetFlags` (builder style).
    pub fn with_set_flags(mut self, flags: u64) -> Self {
        self.set_flags = flags;
        self
    }
}
