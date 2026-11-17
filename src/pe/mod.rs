//! PE binary transforms and rift table generation for MSDelta.

pub(crate) mod addr;
pub(crate) mod atom;
pub(crate) mod cli;
mod inferred_relocations;
mod lock_prefixes;
mod markers;
pub mod parse;
mod relocations;
pub mod rift_gen;
pub mod structs;
pub mod transform;
pub(crate) mod x64;
