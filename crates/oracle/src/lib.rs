//! Differential-testing oracle for `msdelta`.
//!
//! Drives generated inputs through both this crate and a genuine native
//! reference (`msdelta.dll` / `UpdateCompression.dll`) and compares the
//! results, so "100% interop" becomes a measured number rather than a curated
//! corpus.
//!
//! # Architecture: internal seam, extract later
//!
//! The crate is split into two layers with a hard boundary between them:
//!
//! - [`kernel`] is domain-agnostic. It owns the job wire format, the
//!   producer x consumer interop matrix ([`kernel::Direction`]), and (later)
//!   transport, scoring, bucketing, and minimization. It knows nothing about
//!   deltas; it is generic over a [`kernel::Domain`].
//! - [`msdelta`] is the plugin. It implements [`kernel::Domain`] for the PA30
//!   delta format: what a case contains, how we encode/decode locally, and the
//!   genuine `CreateDeltaB` parameters that cross the wire.
//!
//! The same kernel is intended to drive other native-reference interop work
//! (e.g. `wim-rs` against `wimgapi`). When that second consumer arrives, the
//! kernel lifts out into a standalone crate mechanically. Until then it stays
//! here so both layers can iterate in one place.

pub mod kernel;
pub mod msdelta;
