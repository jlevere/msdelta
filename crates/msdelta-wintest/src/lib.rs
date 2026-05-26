//! Integration tests for msdelta against the real Windows msdelta.dll.
//!
//! These tests only run on Windows where msdelta.dll is available.
//! They validate that:
//! 1. Our decoder produces identical output to msdelta.dll for the same delta
//! 2. Deltas we encode are accepted by msdelta.dll's ApplyDeltaB
//! 3. msdelta.dll's ApplyDeltaB output matches our decoder's output
//!
//! To run: `cargo test -p msdelta-wintest` on a Windows machine.
//! In CI: add a Windows runner that clones the repo and runs these tests.

#[cfg(windows)]
pub mod native;

#[cfg(windows)]
pub use native::NativeMsDelta;

/// Marker for tests that require Windows.
#[cfg(not(windows))]
pub fn is_windows() -> bool {
    false
}

#[cfg(windows)]
pub fn is_windows() -> bool {
    true
}
