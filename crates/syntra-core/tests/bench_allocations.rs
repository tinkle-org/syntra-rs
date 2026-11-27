//! Separate process: the timing harnesses never install this allocator.
#![cfg(not(target_arch = "wasm32"))]

#[path = "../benches/fixtures/frame.rs"]
mod frame;
#[path = "../benches/fixtures/record.rs"]
mod record;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use syntra_core::ValidationContext;

thread_local! { static CALLS: Cell<usize> = const { Cell::new(0) }; }

struct Counter;
#[global_allocator]
static ALLOCATOR: Counter = Counter;

// SAFETY: the non-allocating thread-local counter does not change System's arguments or results.
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        CALLS.set(CALLS.get() + 1);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        CALLS.set(CALLS.get() + 1);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        CALLS.set(CALLS.get() + 1);
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

fn measure_request(payload_len: usize) -> (usize, usize) {
    let ctx = ValidationContext::active(1);
    let bytes = syntra_core::encode_frame(&frame::request_frame(payload_len), ctx).unwrap();
    let before = CALLS.get();
    let result = frame::roundtrip(&bytes, ctx);
    let calls = CALLS.get() - before;
    assert_eq!(result, bytes);
    (bytes.len(), calls)
}

#[test]
fn request_roundtrip_keeps_the_protobuf_size_and_allocation_budget() {
    for (payload_len, wire_len, max_calls) in [(0, 29, 2), (1_048_320, 1_048_355, 4)] {
        let (len, calls) = measure_request(payload_len);
        assert_eq!(len, wire_len);
        assert!(
            calls <= max_calls,
            "{payload_len}-byte payload: {calls} allocation calls"
        );
    }
}

#[test]
#[ignore = "allocation measurement runs with post-merge benchmarks"]
fn allocations_per_operation() {
    for size in frame::ROUNDTRIP_SIZES {
        let (_, calls) = measure_request(size);
        println!("frame/roundtrip_request/{size} {calls}");
    }
    for size in record::RECORD_SIZES {
        let mut operation = record::warm_record(size);
        let before = CALLS.get();
        operation();
        let calls = CALLS.get() - before;
        println!("connection/record_warm/{size} {calls}");
    }
}
