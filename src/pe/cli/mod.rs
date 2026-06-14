//! Typed CLR metadata support used by managed MSDelta atoms.
//!
//! This module keeps CLR metadata concerns separate from the surrounding PE
//! parser. Semantic metadata models, ECMA-335 wire parsing, MSDelta preprocess
//! bitstreams, token remapping, and future transform logic should extend this
//! namespace instead of adding more PE-level byte-offset code.

pub(crate) mod blob;
pub(crate) mod context;
pub(crate) mod map;
pub(crate) mod metadata;
pub(crate) mod schema;
pub(crate) mod tokens;
