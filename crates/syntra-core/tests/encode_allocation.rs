//! Observe allocation at the codec boundary, not just its eventual error.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use syntra_core::proto::{frame::Body, rpc_result::Outcome, Frame, Notification, RpcResult};
use syntra_core::{
    decode_frame, encode_frame, missing_result_outcome_id, validate_frame, validate_wire_structure,
    ConnectionState, ErrorCode, RpcRequest, ValidationContext, MAX_CONNECTION_ID_BYTES,
    MAX_CREDENTIAL_BYTES, MAX_DIAGNOSTIC_BYTES, MAX_FRAME_BYTES,
};

struct ObservedAllocator;
thread_local! {
    static OBSERVATION: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
}

fn observe(size: usize) {
    if let Some((minimum, count)) = OBSERVATION.get() {
        if size >= minimum {
            OBSERVATION.set(Some((minimum, count + 1)));
        }
    }
}

// SAFETY: All allocation operations delegate unchanged to System. Observation
// uses a nonallocating thread-local counter and does not change the allocator contract.
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
    OBSERVATION.set(Some((minimum_size, 0)));
    let result = operation();
    (result, OBSERVATION.take().unwrap().1)
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
fn valid_request_allocates_only_the_encoded_output() {
    let ctx = ValidationContext::active(1);
    for size in [0, MAX_FRAME_BYTES - 256] {
        let frame = Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![0; size],
                timeout_ms: 500,
            })),
        };
        let (_, allocations) = observed(1, || validate_frame(&frame, ctx).unwrap());
        assert_eq!(allocations, 0, "validating a request");
        let (bytes, allocations) = observed(1, || encode_frame(&frame, ctx).unwrap());
        assert_eq!(allocations, 1, "encoding a request");
        assert_eq!(bytes.capacity(), bytes.len());
        let (_, allocations) = observed(1, || validate_wire_structure(&bytes).unwrap());
        assert_eq!(allocations, 0, "scanning a request");
    }
}

#[test]
fn codec_bounds_are_enforced_before_allocation() {
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

    // A complete payload is not copied until the entire envelope is admitted.
    let mut raw = [vec![8, 1], len(15, &len(1, &vec![0; 64 * 1024]))].concat();
    raw.push(0); // Invalid field after the notification.
    let (result, allocations) = observed(64 * 1024, || {
        decode_frame(&raw, ValidationContext::active(1))
    });
    assert_eq!(result.unwrap_err().code(), ErrorCode::InvalidArgument);
    assert_eq!(allocations, 0);
}
