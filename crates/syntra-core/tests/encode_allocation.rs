//! Observe allocation at the codec boundary, not just its eventual error.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[path = "fixtures/bebop.rs"]
mod bebop;

use syntra_core::wire::{call_result::Outcome, frame::Body, CallResult, Frame, Notification};
use syntra_core::{
    decode_frame, encode_frame, missing_result_outcome_id, validate_wire_structure,
    ConnectionState, ErrorCode, ValidationContext, MAX_CONNECTION_ID_BYTES, MAX_CREDENTIAL_BYTES,
    MAX_DIAGNOSTIC_BYTES, MAX_FRAME_BYTES,
};

struct ObservedAllocator;
static OBSERVE: AtomicBool = AtomicBool::new(false);
static LARGE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static MIN_OBSERVED_SIZE: AtomicUsize = AtomicUsize::new(MAX_FRAME_BYTES);

fn observe(size: usize) {
    if OBSERVE.load(Ordering::Relaxed) && size >= MIN_OBSERVED_SIZE.load(Ordering::Relaxed) {
        LARGE_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: All allocation operations delegate unchanged to System. Observation
// uses only atomics and never allocates or changes the allocator contract.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn observed<T>(minimum_size: usize, operation: impl FnOnce() -> T) -> (T, usize) {
    LARGE_ALLOCATIONS.store(0, Ordering::Relaxed);
    MIN_OBSERVED_SIZE.store(minimum_size, Ordering::Relaxed);
    OBSERVE.store(true, Ordering::Relaxed);
    let result = operation();
    OBSERVE.store(false, Ordering::Relaxed);
    (result, LARGE_ALLOCATIONS.load(Ordering::Relaxed))
}

#[test]
fn codec_bounds_are_enforced_before_allocation() {
    // This binary deliberately has one test so observation cannot count a
    // concurrent test's large input allocation.
    for body in [
        Body::Result(CallResult {
            outcome: Some(Outcome::Payload(vec![0; MAX_FRAME_BYTES])),
        }),
        Body::Notification(Notification {
            payload: vec![0; MAX_FRAME_BYTES],
        }),
    ] {
        let frame = Frame {
            version: 1,
            request_id: if matches!(body, Body::Notification(_)) {
                0
            } else {
                1
            },
            body: Some(body),
        };
        let (result, allocations) = observed(MAX_FRAME_BYTES, || {
            encode_frame(&frame, ValidationContext::active(1))
        });
        assert_eq!(result.unwrap_err().code(), ErrorCode::ResourceExhausted);
        assert_eq!(allocations, 0);
    }

    for (body, limit, context, code) in [
        (
            10,
            MAX_CREDENTIAL_BYTES,
            ValidationContext::pre_handshake(ConnectionState::Connected),
            ErrorCode::ResourceExhausted,
        ),
        (
            11,
            MAX_CONNECTION_ID_BYTES,
            ValidationContext::pre_handshake(ConnectionState::Negotiating),
            ErrorCode::InvalidArgument,
        ),
        (
            13,
            MAX_DIAGNOSTIC_BYTES,
            ValidationContext::active(1),
            ErrorCode::InvalidArgument,
        ),
    ] {
        // A positive control observes the owned field copy at its exact limit.
        let good = bebop::field_frame(body, &vec![b'x'; limit]);
        let (result, allocations) = observed(limit, || decode_frame(&good, context));
        result.unwrap();
        assert!(allocations > 0, "body={body}: did not see the field copy");

        let bad = bebop::field_frame(body, &vec![b'x'; limit + 1]);
        let (result, allocations) = observed(limit + 1, || decode_frame(&bad, context));
        assert_eq!(result.unwrap_err().code(), code);
        assert_eq!(allocations, 0, "body={body}: copied over-limit field");
        let (result, allocations) = observed(limit + 1, || validate_wire_structure(&bad));
        assert_eq!(result.unwrap_err().code(), code);
        assert_eq!(allocations, 0);
        let (id, allocations) = observed(limit + 1, || missing_result_outcome_id(&bad, context));
        assert_eq!(id, None);
        assert_eq!(allocations, 0);
    }

    // A valid first field doesn't justify copying its payload before checking
    // the enclosing message's terminator and the rest of the frame.
    let mut message = vec![1];
    message.extend(bebop::sized(&vec![0xff; 64 * 1024]));
    let raw = bebop::frame(1, 0, 15, &bebop::sized(&message));
    let (result, allocations) = observed(64 * 1024, || {
        decode_frame(&raw, ValidationContext::active(1))
    });
    assert_eq!(result.unwrap_err().code(), ErrorCode::InvalidArgument);
    assert_eq!(allocations, 0);
}
