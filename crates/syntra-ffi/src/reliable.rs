//! Reliable-session validation parity for the production C ABI.
//!
//! OPTIONAL `syntra.reliable-session/1`. Wrappers around
//! `syntra-core::reliable` validation so C embeddings get the same
//! shape checks as Rust and Go without new wire variants. No network, no
//! payload interpretation, no custom crypto, no exactly-once claims.
//!
//! Status codes reuse the production ABI (`SYNTRA_FFI_OK`/`INVALID`); per-RPC
//! failures never travel as status codes. All functions are pure validation
//! (no handles; inputs are copied into a bounded temporary buffer of at
//! most 256 B before validation) and are additive: existing
//! ABI signatures are untouched.

use std::slice;

use super::{SYNTRA_FFI_INVALID, SYNTRA_FFI_OK};

fn borrow_bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, i32> {
    if len == 0 {
        return Ok(Vec::new());
    }
    // Bound the copy BEFORE from_raw_parts/to_vec: a hostile caller must
    // not be able to force an arbitrarily large allocation. 256 B is the
    // largest bound any reliable-session validator accepts
    // (MAX_RESUME_CREDENTIAL_LEN); session/delivery ids (16 B) are covered.
    if len > syntra_core::reliable::MAX_RESUME_CREDENTIAL_LEN {
        return Err(SYNTRA_FFI_INVALID);
    }
    if ptr.is_null() {
        return Err(SYNTRA_FFI_INVALID);
    }
    unsafe { Ok(slice::from_raw_parts(ptr, len).to_vec()) }
}

/// Validate a 16-byte session identifier (non-zero, opaque, distinct from
/// `connection_id`). Returns `OK` when valid, `INVALID` otherwise.
#[no_mangle]
pub extern "C" fn syntra_ffi_reliable_session_id_valid(id: *const u8, len: usize) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = match borrow_bytes(id, len) {
            Ok(v) => v,
            Err(c) => return c,
        };
        match syntra_core::reliable::validate_session_id(&bytes) {
            Ok(_) => SYNTRA_FFI_OK,
            Err(_) => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(super::SYNTRA_FFI_INTERNAL)
}

/// Validate a 16-byte stable delivery identifier (non-zero, distinct from
/// `request_id`). Returns `OK` when valid, `INVALID` otherwise.
#[no_mangle]
pub extern "C" fn syntra_ffi_reliable_delivery_id_valid(id: *const u8, len: usize) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = match borrow_bytes(id, len) {
            Ok(v) => v,
            Err(c) => return c,
        };
        match syntra_core::reliable::validate_delivery_id(&bytes) {
            Ok(_) => SYNTRA_FFI_OK,
            Err(_) => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(super::SYNTRA_FFI_INTERNAL)
}

/// Validate an opaque resume handle (16..256 bytes, non-zero).
#[no_mangle]
pub extern "C" fn syntra_ffi_reliable_resume_credential_valid(cred: *const u8, len: usize) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bytes = match borrow_bytes(cred, len) {
            Ok(v) => v,
            Err(c) => return c,
        };
        match syntra_core::reliable::validate_resume_credential(&bytes) {
            Ok(_) => SYNTRA_FFI_OK,
            Err(_) => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(super::SYNTRA_FFI_INTERNAL)
}

/// Validate monotonic epoch advance (`proposed > current`, both nonzero).
#[no_mangle]
pub extern "C" fn syntra_ffi_reliable_epoch_advance_valid(current: u64, proposed: u64) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match syntra_core::reliable::check_epoch_advance(current, proposed) {
            Ok(_) => SYNTRA_FFI_OK,
            Err(_) => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(super::SYNTRA_FFI_INTERNAL)
}

/// Negotiate a keepalive lease (zero selects host defaults; clamps headroom).
/// On success writes confirmed `idle_ms`/`keepalive_ms` and returns `OK`;
/// on out-of-range returns `INVALID` without writing.
#[no_mangle]
pub extern "C" fn syntra_ffi_reliable_negotiate_lease(
    idle_ms: u32,
    keepalive_ms: u32,
    idle_out: *mut u32,
    keepalive_out: *mut u32,
) -> i32 {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if idle_out.is_null() || keepalive_out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let proposal = syntra_core::reliable::LeaseProposal {
            idle_timeout_ms: idle_ms,
            keepalive_interval_ms: keepalive_ms,
        };
        match syntra_core::reliable::negotiate_lease(proposal) {
            Ok(confirmed) => {
                unsafe {
                    *idle_out = confirmed.idle_timeout_ms;
                    *keepalive_out = confirmed.keepalive_interval_ms;
                }
                SYNTRA_FFI_OK
            }
            Err(_) => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(super::SYNTRA_FFI_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_and_delivery_validation_parity() {
        assert_eq!(
            syntra_ffi_reliable_session_id_valid([7u8; 16].as_ptr(), 16),
            SYNTRA_FFI_OK
        );
        assert_eq!(
            syntra_ffi_reliable_session_id_valid([0u8; 16].as_ptr(), 16),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(
            syntra_ffi_reliable_delivery_id_valid([9u8; 16].as_ptr(), 16),
            SYNTRA_FFI_OK
        );
        assert_eq!(
            syntra_ffi_reliable_delivery_id_valid([0u8; 16].as_ptr(), 16),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(
            syntra_ffi_reliable_resume_credential_valid([7u8; 32].as_ptr(), 32),
            SYNTRA_FFI_OK
        );
        assert_eq!(syntra_ffi_reliable_epoch_advance_valid(3, 4), SYNTRA_FFI_OK);
        assert_eq!(
            syntra_ffi_reliable_epoch_advance_valid(3, 3),
            SYNTRA_FFI_INVALID
        );
        let mut idle = 0u32;
        let mut keepalive = 0u32;
        assert_eq!(
            syntra_ffi_reliable_negotiate_lease(0, 0, &mut idle, &mut keepalive),
            SYNTRA_FFI_OK
        );
        assert!(keepalive < idle);
    }
}
