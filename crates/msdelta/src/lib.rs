//! Pure-Rust encoder and decoder for Microsoft's MSDelta binary patch format ("PA30"),
//! and the DCM wrapper used for Windows component manifests in `WinSxS`.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("input too short")]
    Truncated,
    #[error("bad magic (expected {expected:?}, got {got:?})")]
    BadMagic { expected: &'static [u8], got: Vec<u8> },
    #[error(transparent)]
    Bitstream(#[from] msdelta_bitstream::Error),
    #[error(transparent)]
    Lzx(#[from] msdelta_lzx::Error),
    #[error(transparent)]
    Pa19(#[from] msdelta_pa19::Error),
    #[error("target hash too large ({size} bytes, max {max})")]
    HashTooLarge { size: usize, max: usize },
    #[error("malformed delta stream: {0}")]
    Malformed(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod dcm;
pub mod pa30;

pub use msdelta_bitstream as bitstream_crate;
pub use msdelta_lzx as lzx_crate;
