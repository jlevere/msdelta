//! The producer x consumer interop matrix.
//!
//! Every interop test is one cell of a 2x2 grid: an artifact is *produced* by
//! either our Rust implementation or the native reference, then *consumed* by
//! one of the two. The four cells are domain-agnostic; only what "produce" and
//! "consume" mean is domain-specific.
//!
//! For the msdelta domain the mapping is:
//!
//! | direction        | produce         | consume          | runs on |
//! |------------------|-----------------|------------------|---------|
//! | [`OursToNative`] | our encoder     | native ApplyDeltaB | lab    |
//! | [`NativeToOurs`] | native CreateDeltaB | our decoder  | lab + local |
//! | [`NativeToNative`] | native CreateDeltaB | native ApplyDeltaB | lab |
//! | [`OursToOurs`]   | our encoder     | our decoder      | local   |
//!
//! [`OursToNative`]: Direction::OursToNative
//! [`NativeToOurs`]: Direction::NativeToOurs
//! [`NativeToNative`]: Direction::NativeToNative
//! [`OursToOurs`]: Direction::OursToOurs

use serde::{Deserialize, Serialize};

/// One cell of the producer x consumer interop matrix.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// We produce the artifact; the native reference consumes it. This is the
    /// headline encode-interop test ("does the genuine DLL accept what we
    /// emit and apply it to the exact target?").
    OursToNative,
    /// The native reference produces the artifact; we consume it. This is the
    /// decode-completeness test ("can we read anything the DLL emits?"). The
    /// produce half runs on the lab; the consume half runs locally on the
    /// returned golden artifact.
    NativeToOurs,
    /// The native reference produces and consumes. A control that proves the
    /// harness marshalling and the input pair themselves are sound.
    NativeToNative,
    /// We produce and consume. A purely local self round-trip; needs no lab.
    OursToOurs,
    /// Reverse-delta round trip via the native `ApplyDeltaGetReverseB`: apply a
    /// forward delta to get the target AND a reverse delta, then check the
    /// reverse reconstructs the source. Exercises the forward/reverse
    /// differential servicing API. The native side also emits the genuine
    /// reverse delta as a gold for our decoder to read.
    ReverseRoundTrip,
}

impl Direction {
    /// Whether running this direction requires the native reference on the lab
    /// host. [`OursToOurs`](Direction::OursToOurs) is the only fully-local one.
    pub fn needs_native(self) -> bool {
        !matches!(self, Direction::OursToOurs)
    }
}
