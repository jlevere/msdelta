//! PseudoLzx compression codec for MSDelta PA30 patches.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Bitstream(#[from] msdelta_bitstream::Error),
    #[error("malformed delta stream: {0}")]
    Malformed(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod lzx;
pub mod rift;
