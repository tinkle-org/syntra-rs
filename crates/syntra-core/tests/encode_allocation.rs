//! Observe allocation at the codec boundary, not just its eventual error.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use syntra_core::proto::{frame::Body, rpc_result::Outcome, Frame, Notification, RpcResult};
use syntra_core::{encode_frame, ErrorCode, ValidationContext, MAX_FRAME_BYTES};

struct ObservedAllocator;
static OBSERVE: AtomicBool = AtomicBool::new(false);
static LARGE_ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

fn observe(size: usize) {
    if OBSERVE.load(Ordering::Relaxed) && size >= MAX_FRAME_BYTES {
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

#[test]
fn oversized_encode_never_allocates_an_output_envelope() {
    // This binary deliberately has one test so observation cannot count a
    // concurrent test's large input allocation.
    for body in [
        Body::Result(RpcResult {
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
        LARGE_ALLOCATIONS.store(0, Ordering::Relaxed);
        OBSERVE.store(true, Ordering::Relaxed);
        let result = encode_frame(&frame, ValidationContext::active(1));
        OBSERVE.store(false, Ordering::Relaxed);
        assert_eq!(result.unwrap_err().code(), ErrorCode::ResourceExhausted);
        assert_eq!(LARGE_ALLOCATIONS.load(Ordering::Relaxed), 0);
    }
}
