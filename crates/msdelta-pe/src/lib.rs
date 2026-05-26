//! PE binary transforms and rift table generation for MSDelta.
//!
//! Handles the file-type-specific preprocessing that msdelta.dll applies
//! when FileType is I386, AMD64, or CLI4 (not RAW).

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid PE: {0}")]
    InvalidPe(String),
    #[error("transform error: {0}")]
    Transform(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod pe;
pub mod transform;
