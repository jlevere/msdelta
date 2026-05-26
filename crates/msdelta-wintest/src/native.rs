//! FFI bindings to the real msdelta.dll on Windows.
//!
//! Provides a safe Rust wrapper around ApplyDeltaB, CreateDeltaB,
//! GetDeltaInfoB, and GetDeltaSignatureB for cross-validation testing.

#![cfg(windows)]

use std::ffi::c_void;
use std::ptr;

#[repr(C)]
struct DeltaInput {
    lp_start: *const u8,
    u_size: usize,
    editable: i32,
}

#[repr(C)]
struct DeltaOutput {
    lp_start: *mut u8,
    u_size: usize,
}

extern "system" {
    fn ApplyDeltaB(
        apply_flags: i64,
        source: DeltaInput,
        delta: DeltaInput,
        lp_target: *mut DeltaOutput,
    ) -> i32;

    fn CreateDeltaB(
        file_type_set: i64,
        set_flags: i64,
        reset_flags: i64,
        source: DeltaInput,
        target: DeltaInput,
        source_options: DeltaInput,
        target_options: DeltaInput,
        global_options: DeltaInput,
        lp_target_file_time: *const c_void,
        hash_alg_id: u32,
        lp_delta: *mut DeltaOutput,
    ) -> i32;

    fn DeltaFree(lp_memory: *mut u8) -> i32;
}

/// Safe wrapper around the native msdelta.dll API.
pub struct NativeMsDelta;

impl NativeMsDelta {
    /// Apply a delta using the real msdelta.dll.
    pub fn apply(reference: &[u8], delta: &[u8]) -> Result<Vec<u8>, String> {
        let source = DeltaInput {
            lp_start: reference.as_ptr(),
            u_size: reference.len(),
            editable: 0,
        };
        let delta_input = DeltaInput {
            lp_start: delta.as_ptr(),
            u_size: delta.len(),
            editable: 0,
        };
        let mut output = DeltaOutput {
            lp_start: ptr::null_mut(),
            u_size: 0,
        };

        let ok = unsafe { ApplyDeltaB(0, source, delta_input, &mut output) };
        if ok == 0 {
            return Err("ApplyDeltaB failed".into());
        }

        let result =
            unsafe { std::slice::from_raw_parts(output.lp_start, output.u_size) }.to_vec();
        unsafe {
            DeltaFree(output.lp_start);
        }
        Ok(result)
    }

    /// Create a delta using the real msdelta.dll.
    pub fn create(
        reference: &[u8],
        target: &[u8],
        file_type_set: i64,
    ) -> Result<Vec<u8>, String> {
        let source = DeltaInput {
            lp_start: reference.as_ptr(),
            u_size: reference.len(),
            editable: 0,
        };
        let target_input = DeltaInput {
            lp_start: target.as_ptr(),
            u_size: target.len(),
            editable: 0,
        };
        let empty = DeltaInput {
            lp_start: ptr::null(),
            u_size: 0,
            editable: 0,
        };
        let mut output = DeltaOutput {
            lp_start: ptr::null_mut(),
            u_size: 0,
        };

        let ok = unsafe {
            CreateDeltaB(
                file_type_set,
                0,
                0,
                source,
                target_input,
                empty,
                empty,
                empty,
                ptr::null(),
                0,
                &mut output,
            )
        };
        if ok == 0 {
            return Err("CreateDeltaB failed".into());
        }

        let result =
            unsafe { std::slice::from_raw_parts(output.lp_start, output.u_size) }.to_vec();
        unsafe {
            DeltaFree(output.lp_start);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_apply_our_delta() {
        // Create a delta with our encoder, apply with msdelta.dll
        let reference = b"Hello, this is a reference buffer.";
        let target = b"Hello, this is a modified buffer!";

        let our_delta = msdelta::pa30::create(reference, target)
            .expect("our encoder failed");

        let native_result = NativeMsDelta::apply(reference, &our_delta)
            .expect("msdelta.dll failed on our delta");

        assert_eq!(native_result, target, "msdelta.dll disagrees with our encoder");
    }

    #[test]
    fn native_create_our_decode() {
        // Create a delta with msdelta.dll, decode with our decoder
        let reference = b"Hello, this is a reference buffer.";
        let target = b"Hello, this is a modified buffer!";

        let native_delta = NativeMsDelta::create(reference, target, 1)
            .expect("msdelta.dll CreateDeltaB failed");

        let our_result = msdelta::pa30::apply(reference, &native_delta)
            .expect("our decoder failed on msdelta.dll delta");

        assert_eq!(our_result, target, "our decoder disagrees with msdelta.dll encoder");
    }

    #[test]
    fn roundtrip_cross_validation() {
        // Full cross-validation: both directions
        let reference = b"The quick brown fox jumps over the lazy dog. The quick brown fox.";
        let target = b"The slow brown fox walks over the lazy cat. The slow brown fox.";

        // Our encode → native decode
        let our_delta = msdelta::pa30::create(reference, target).unwrap();
        let native_decoded = NativeMsDelta::apply(reference, &our_delta).unwrap();
        assert_eq!(native_decoded, target, "native decode of our delta failed");

        // Native encode → our decode
        let native_delta = NativeMsDelta::create(reference, target, 1).unwrap();
        let our_decoded = msdelta::pa30::apply(reference, &native_delta).unwrap();
        assert_eq!(our_decoded, target, "our decode of native delta failed");

        // Both decoders agree on native delta
        let native_decoded2 = NativeMsDelta::apply(reference, &native_delta).unwrap();
        assert_eq!(native_decoded2, our_decoded, "decoders disagree on native delta");
    }
}
