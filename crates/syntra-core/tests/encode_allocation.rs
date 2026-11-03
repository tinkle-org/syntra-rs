//! Observe allocation at the codec boundary, not just its eventual error.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use prost::Message;
use syntra_core::proto::{frame::Body, rpc_result::Outcome, Frame, Notification, RpcResult};
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

fn varint(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 128 {
        bytes.push(value as u8 | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

fn len(field: usize, value: &[u8]) -> Vec<u8> {
    [varint(field << 3 | 2), varint(value.len()), value.to_vec()].concat()
}

#[test]
fn codec_bounds_are_enforced_before_allocation() {
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
        let (result, allocations) = observed(MAX_FRAME_BYTES, || {
            encode_frame(&frame, ValidationContext::active(1))
        });
        assert_eq!(result.unwrap_err().code(), ErrorCode::ResourceExhausted);
        assert_eq!(allocations, 0);
    }

    for (body, field, limit, context, code) in [
        (
            10,
            3,
            MAX_CREDENTIAL_BYTES,
            ValidationContext::pre_handshake(ConnectionState::Connected),
            ErrorCode::ResourceExhausted,
        ),
        (
            11,
            1,
            MAX_CONNECTION_ID_BYTES,
            ValidationContext::pre_handshake(ConnectionState::Negotiating),
            ErrorCode::InvalidArgument,
        ),
        (
            13,
            2,
            MAX_DIAGNOSTIC_BYTES,
            ValidationContext::active(1),
            ErrorCode::InvalidArgument,
        ),
    ] {
        // Build every raw input before arming. Include an oversized earlier
        // value that prost would otherwise allocate and then overwrite.
        let oversized = len(field, &vec![b'x'; limit + 1]);
        let bounded = len(field, b"ok");
        let values = [
            oversized.clone(),
            [oversized.clone(), bounded.clone()].concat(),
            [bounded, oversized].concat(),
            len(field, &vec![b'x'; limit]),
        ];
        for (index, value) in values.into_iter().enumerate() {
            let inner = match body {
                10 => [vec![8, 1, 16, 1], value].concat(),
                13 => len(2, &[vec![8, 13], value].concat()),
                _ => value,
            };
            let header = if body == 13 {
                vec![8, 1, 16, 7]
            } else {
                vec![8, 1]
            };
            let raw = [header, len(body, &inner)].concat();
            let (result, allocations) = observed(limit + 1, || decode_frame(&raw, context));
            assert_eq!(allocations, 0, "body={body}, duplicate case={index}");
            if index == 3 {
                // Exact boundary is admitted. This positive control proves the
                // observer sees generated field allocation when it is armed.
                assert!(result.is_ok());
                let (result, allocations) = observed(limit, || decode_frame(&raw, context));
                assert!(result.is_ok());
                assert!(
                    allocations > 0,
                    "body={body}: observer must see exact-limit allocation"
                );
            } else {
                assert_eq!(result.unwrap_err().code(), code);
                let (result, allocations) = observed(limit + 1, || validate_wire_structure(&raw));
                assert_eq!(result.unwrap_err().code(), code);
                assert_eq!(allocations, 0);
            }
            let (id, allocations) =
                observed(limit + 1, || missing_result_outcome_id(&raw, context));
            assert_eq!(id, None);
            assert_eq!(allocations, 0);
        }
    }

    // The reviewer's exact 8,193-byte credential reproduction, not a generated
    // approximation. Construction is outside the allocation observation window.
    let mut raw = vec![
        0x08, 0x01, 0x52, 0x88, 0x40, 0x08, 0x01, 0x10, 0x01, 0x1a, 0x81, 0x40,
    ];
    raw.extend(vec![0; 8_193]);
    let (result, allocations) = observed(8_193, || {
        decode_frame(
            &raw,
            ValidationContext::pre_handshake(ConnectionState::Connected),
        )
    });
    assert_eq!(result.unwrap_err().code(), ErrorCode::ResourceExhausted);
    assert_eq!(allocations, 0);

    // Independently check the raw reproduction's decoded shape, with observation
    // off: generated decoding alone accepts and allocates the oversized field.
    let decoded = Frame::decode(raw.as_slice()).unwrap();
    match decoded.body.unwrap() {
        Body::Hello(hello) => assert_eq!(hello.credential.len(), 8_193),
        other => panic!("unexpected reproduction body {other:?}"),
    }
}
