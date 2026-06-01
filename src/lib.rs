//! Pure-Rust encoder and decoder for Microsoft's MSDelta binary patch format.
//!
//! Supports PA30, PA31, and PA19 delta formats, the DCM wrapper used for
//! Windows component manifests, and all associated compression codecs
//! (PseudoLzx, BsDiff, LZX, LZMS).
//!
//! # Quick start
//!
//! ```no_run
//! # let base_manifest = vec![0u8; 100];
//! # let (old_file, new_file) = (vec![0u8; 10], vec![0u8; 10]);
//! // Decode a DCM-wrapped manifest
//! let compressed = std::fs::read("manifest.dcm").unwrap();
//! let pa30_data = msdelta::dcm::strip(&compressed).unwrap();
//! let xml = msdelta::pa30::apply(&base_manifest, pa30_data).unwrap();
//!
//! // Create a delta
//! let delta = msdelta::pa30::create(&old_file, &new_file).unwrap();
//!
//! // Create a delta with integrity hash
//! use msdelta::pa30::{CreateOptions, HASH_ALG_SHA256};
//! let delta = CreateOptions::new()
//!     .hash_algorithm(HASH_ALG_SHA256)
//!     .execute(&old_file, &new_file)
//!     .unwrap();
//! ```

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("input too short")]
    Truncated,
    #[error("bad magic (expected {expected:?}, got {got:?})")]
    BadMagic {
        expected: &'static [u8],
        got: Vec<u8>,
    },
    #[error("bitstream exhausted: needed {needed} bits, {available} available")]
    BitstreamExhausted { needed: u32, available: u32 },
    #[error("invalid variable-length integer encoding")]
    InvalidVarInt,
    #[error("target hash too large ({size} bytes, max {max})")]
    HashTooLarge { size: usize, max: usize },
    #[error("malformed stream: {0}")]
    Malformed(&'static str),
    #[error("target hash mismatch (expected {expected}, got {got})")]
    HashMismatch { expected: String, got: String },
    #[error("PA19: {0}")]
    Pa19(String),
    #[error("base manifest extraction: {0}")]
    BaseManifest(&'static str),
    #[error(transparent)]
    Lzms(#[from] lzms::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
pub(crate) mod bitstream;
#[allow(dead_code)]
pub(crate) mod bsdiff;
pub mod dcm;
#[allow(dead_code)]
pub(crate) mod huffman;
#[allow(dead_code)]
pub(crate) mod lzx;
pub mod pa19;
pub mod pa30;
#[allow(dead_code)]
pub(crate) mod pe;
#[cfg(feature = "winsxs")]
pub mod winsxs;
#[allow(dead_code)]
pub(crate) mod xpress;

/// Decoder entry points exposed only under the `fuzzing` feature so the fuzz
/// harnesses can target the bit-level codecs directly (these are internal
/// `pub(crate)` items in normal builds).
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use crate::Result;

    /// Fuzz the XPRESS_HUFF Compression-API container decoder.
    pub fn xpress_decompress_container(data: &[u8]) -> Result<Vec<u8>> {
        crate::xpress::decompress_container(data)
    }

    /// Fuzz the reverse-delta (`ReversePatchFormat`) apply against a reference.
    pub fn apply_reversal(
        target: &[u8],
        reversal_data: &[u8],
        source_size: usize,
    ) -> Result<Vec<u8>> {
        crate::pa30::reverse::apply_reversal(target, reversal_data, source_size)
    }
}
