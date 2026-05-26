//! Pure-Rust encoder and decoder for Microsoft's MSDelta binary patch format.
//!
//! Supports PA30, PA31, and PA19 delta formats, the DCM wrapper used for
//! Windows component manifests, and all associated compression codecs
//! (PseudoLzx, BsDiff, LZX, LZMS).
//!
//! # Quick start
//!
//! ```no_run
//! // Decode a DCM-wrapped manifest
//! let compressed = std::fs::read("manifest.dcm").unwrap();
//! let pa30_data = msdelta::dcm::strip(&compressed).unwrap();
//! let xml = msdelta::pa30::apply(&base_manifest, pa30_data).unwrap();
//!
//! // Create a delta
//! let delta = msdelta::pa30::create(&old_file, &new_file).unwrap();
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
    #[error("PA19: {0}")]
    Pa19(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod bitstream;
pub mod bsdiff;
pub mod dcm;
pub mod huffman;
pub mod lzx;
pub mod lzms;
pub mod pa19;
pub mod pa30;
pub mod pe;
