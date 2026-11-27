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

#[test]
#[ignore = "allocation measurement runs with post-merge benchmarks"]
fn allocations_per_operation() {
    for size in frame::ROUNDTRIP_SIZES {
        let bytes =
            syntra_core::encode_frame(&frame::request_frame(size), ValidationContext::active(1))
                .unwrap();
        let before = CALLS.get();
        let result = frame::roundtrip(&bytes, ValidationContext::active(1));
        let calls = CALLS.get() - before;
        assert_eq!(result, bytes);
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
