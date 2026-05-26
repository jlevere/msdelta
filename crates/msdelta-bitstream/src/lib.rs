//! LSB-first bitstream reader/writer and Huffman codec.
//!
//! Foundational types for MSDelta format processing. No domain-specific
//! knowledge — just bit-level I/O and canonical Huffman coding.

#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("input too short")]
    Truncated,
    #[error("bitstream exhausted: needed {needed} bits, {available} available")]
    BitstreamExhausted { needed: u32, available: u32 },
    #[error("invalid variable-length integer encoding")]
    InvalidVarInt,
    #[error("malformed stream: {0}")]
    Malformed(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

pub mod bitstream;
pub mod huffman;
