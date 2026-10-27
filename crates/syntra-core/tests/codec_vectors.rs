//! Codec + validation vectors (SNTR-WIRE-900, SNTR-SER-900).
//!
//! Drives `conformance/test-vectors` byte expectations through the core
//! codec: one valid frame per variant, empty-body rejection, the
//! request_id misuse matrix, unknown-variant rejection, reserved-number
//! rejection, duplicate-oneof rejection, depth/allocation bounds, and
//! empty-payload round-trips.

use prost::Message;
use syntra_core::proto::frame::Body;
use syntra_core::proto::{
    Cancel, ClientHello, Frame, Notification, RpcError, RpcRequest, RpcResult, ServerReady,
};
use syntra_core::{
    decode_frame, encode_frame, validate_frame, ConnectionState, ErrorCode, ValidationContext,
    MAX_FRAME_BYTES,
};

fn active() -> ValidationContext {
    ValidationContext::active(1)
}

fn connected() -> ValidationContext {
    ValidationContext::pre_handshake(ConnectionState::Connected)
}

#[test]
fn one_valid_frame_per_variant() {
    let frames = vec![
        Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        },
        Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Ready(ServerReady {
                connection_id: "conn-1".into(),
            })),
        },
        Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: b"hi".to_vec().into(),
                timeout_ms: 500,
            })),
        },
        Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Result(RpcResult {
                outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(
                    b"hi".to_vec().into(),
                )),
            })),
        },
        Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Cancel(Cancel {})),
        },
        Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Notification(Notification {
                payload: b"tick".to_vec().into(),
            })),
        },
    ];
    for f in &frames {
        let ctx = match f.body {
            // hello is the CONNECTED first unit; ready arrives in
            // NEGOTIATING/AUTHENTICATING; application units in ACTIVE.
            Some(Body::Hello(_)) => connected(),
            Some(Body::Ready(_)) => ValidationContext::pre_handshake(ConnectionState::Negotiating),
            _ => active(),
        };
        let bytes = encode_frame(f, ctx).expect("valid frame encodes");
        let back = decode_frame(&bytes, ctx).expect("valid frame decodes");
        assert_eq!(&back, f);
    }
}

#[test]
fn empty_body_rejected() {
    let f = Frame {
        version: 1,
        request_id: 0,
        body: None,
    };
    let bytes = f.encode_to_vec();
    let err = decode_frame(&bytes, connected()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn request_id_misuse_matrix() {
    // hello/ready/notification MUST use 0; request/result/cancel MUST NOT.
    let cases: Vec<(Frame, bool)> = vec![
        (
            Frame {
                version: 1,
                request_id: 3,
                body: Some(Body::Hello(ClientHello {
                    min_version: 1,
                    max_version: 1,
                    credential: vec![],
                })),
            },
            false,
        ),
        (
            Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Request(RpcRequest {
                    method: "/example.Echo/Echo".into(),
                    payload: vec![].into(),
                    timeout_ms: 0,
                })),
            },
            false,
        ),
        (
            Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Result(RpcResult { outcome: None })),
            },
            false,
        ),
        (
            Frame {
                version: 1,
                request_id: 5,
                body: Some(Body::Notification(Notification {
                    payload: vec![].into(),
                })),
            },
            false,
        ),
    ];
    for (f, ok) in cases {
        assert_eq!(validate_frame(&f, active()).is_ok(), ok);
    }
}

#[test]
fn reserved_numbers_rejected() {
    // Field 16, length-delimited, one zero byte of content.
    let bytes = vec![0x08, 0x01, 0x82, 0x01, 0x01, 0x00];
    let err = decode_frame(&bytes, connected()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn duplicate_oneof_rejected() {
    // A hello body (field 10) followed by a ready body (field 11):
    // prost would collapse these, so the raw scan must reject first.
    let mut bytes = Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![],
        })),
    }
    .encode_to_vec();
    let ready = ServerReady {
        connection_id: "x".into(),
    }
    .encode_to_vec();
    bytes.push(0x5A); // field 11, wire type 2
    bytes.push(ready.len() as u8);
    bytes.extend_from_slice(&ready);
    let err = decode_frame(&bytes, connected()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
}

#[test]
fn unknown_body_only_is_unimplemented() {
    // Version only + unknown field 90 (length-delimited "x"): no known
    // body, but unknown content -> UNIMPLEMENTED (not empty-body).
    let bytes = vec![0x08, 0x01, 0xD2, 0x05, 0x01, b'x'];
    let err = decode_frame(&bytes, connected()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unimplemented);
}

#[test]
fn unknown_fields_tolerated() {
    // Same hello as the no-length-prefix proof plus an unknown field:
    // accepted as the same logical Frame (SNTR-SER-003).
    let mut bytes = Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![],
        })),
    }
    .encode_to_vec();
    bytes.extend_from_slice(&[0xD2, 0x05, 0x01, b'x']);
    let back = decode_frame(&bytes, connected()).expect("unknown fields tolerated");
    assert!(matches!(back.body, Some(Body::Hello(_))));
}

#[test]
fn oversize_rejected_at_max_plus_one() {
    let bytes = vec![0x55u8; MAX_FRAME_BYTES + 1];
    let err = decode_frame(&bytes, active()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
}

#[test]
fn huge_length_prefix_rejected_before_alloc() {
    // Tag for field 12 (request, LEN) with a 64 MiB length prefix but no
    // content: allocation bound fires before prost allocates.
    let bytes = vec![0x08, 0x01, 0x62, 0x80, 0x80, 0x80, 0x02];
    let err = decode_frame(&bytes, active()).unwrap_err();
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
}

#[test]
fn empty_payload_round_trips() {
    // Empty success payload is success (not missing outcome).
    let f = Frame {
        version: 1,
        request_id: 8,
        body: Some(Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(
                vec![].into(),
            )),
        })),
    };
    let bytes = encode_frame(&f, active()).unwrap();
    let back = decode_frame(&bytes, active()).unwrap();
    assert_eq!(back, f);
}

#[test]
fn missing_outcome_and_zero_code_rejected() {
    let f = Frame {
        version: 1,
        request_id: 9,
        body: Some(Body::Result(RpcResult { outcome: None })),
    };
    assert!(validate_frame(&f, active()).is_err());
    let f = Frame {
        version: 1,
        request_id: 9,
        body: Some(Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(RpcError {
                code: 0,
                message: "bad".into(),
            })),
        })),
    };
    assert!(validate_frame(&f, active()).is_err());
}

#[test]
fn version_discipline() {
    // Pre-handshake zero version rejected.
    let f = Frame {
        version: 0,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![],
        })),
    };
    assert!(decode_frame(&f.encode_to_vec(), connected()).is_err());
    // ACTIVE mismatch rejected.
    let f = Frame {
        version: 2,
        request_id: 3,
        body: Some(Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![].into(),
            timeout_ms: 1,
        })),
    };
    assert!(validate_frame(&f, active()).is_err());
}

#[test]
fn malformed_bytes_rejected_deterministically() {
    // Truncated varint tag.
    assert!(decode_frame(&[0x80], active()).is_err());
    // Illegal wire type (6).
    assert!(decode_frame(&[0x08, 0x01, 0x36], active()).is_err());
    // Empty input.
    assert!(decode_frame(&[], active()).is_err());
}

#[test]
fn every_variable_size_body_obeys_the_envelope_bound_first() {
    let bodies = [
        Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![0; MAX_FRAME_BYTES],
        }),
        Body::Ready(ServerReady {
            connection_id: "x".repeat(MAX_FRAME_BYTES),
        }),
        Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![0; MAX_FRAME_BYTES],
            timeout_ms: 1,
        }),
        Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(vec![
                0; MAX_FRAME_BYTES
            ])),
        }),
        Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(RpcError {
                code: ErrorCode::Internal.as_i32(),
                message: "x".repeat(MAX_FRAME_BYTES),
            })),
        }),
        Body::Notification(Notification {
            payload: vec![0; MAX_FRAME_BYTES],
        }),
    ];
    for body in bodies {
        // Deliberately invalid version and ID: size is validation step 1,
        // independent of variant, state, and later semantic limits.
        let frame = Frame {
            version: 0,
            request_id: 0,
            body: Some(body),
        };
        assert!(frame.encoded_len() > MAX_FRAME_BYTES);
        for state in [
            ConnectionState::Connected,
            ConnectionState::Negotiating,
            ConnectionState::Authenticating,
            ConnectionState::Active,
            ConnectionState::Closing,
            ConnectionState::Closed,
        ] {
            let ctx = ValidationContext {
                state,
                negotiated_version: Some(1),
            };
            assert_eq!(
                validate_frame(&frame, ctx).unwrap_err().code(),
                ErrorCode::ResourceExhausted
            );
            assert_eq!(
                encode_frame(&frame, ctx).unwrap_err().code(),
                ErrorCode::ResourceExhausted
            );
        }
    }
}

#[test]
fn exact_envelope_boundary_round_trips_for_application_bodies() {
    let bodies = [
        Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![0; MAX_FRAME_BYTES],
            timeout_ms: 1,
        }),
        Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(vec![
                0; MAX_FRAME_BYTES
            ])),
        }),
        Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(RpcError {
                code: ErrorCode::Internal.as_i32(),
                message: "x".repeat(MAX_FRAME_BYTES),
            })),
        }),
        Body::Notification(Notification {
            payload: vec![0; MAX_FRAME_BYTES],
        }),
    ];
    for body in bodies {
        let mut frame = Frame {
            version: 1,
            request_id: if matches!(body, Body::Notification(_)) {
                0
            } else {
                1
            },
            body: Some(body),
        };
        let overhead = frame.encoded_len() - MAX_FRAME_BYTES;
        match frame.body.as_mut().unwrap() {
            Body::Request(r) => r.payload.truncate(MAX_FRAME_BYTES - overhead),
            Body::Notification(n) => n.payload.truncate(MAX_FRAME_BYTES - overhead),
            Body::Result(r) => match r.outcome.as_mut().unwrap() {
                syntra_core::proto::rpc_result::Outcome::Payload(p) => {
                    p.truncate(MAX_FRAME_BYTES - overhead)
                }
                syntra_core::proto::rpc_result::Outcome::Error(e) => {
                    e.message.truncate(MAX_FRAME_BYTES - overhead)
                }
            },
            _ => unreachable!(),
        }
        assert_eq!(frame.encoded_len(), MAX_FRAME_BYTES);
        assert!(validate_frame(&frame, active()).is_ok());
        let bytes = encode_frame(&frame, active()).unwrap();
        assert_eq!(bytes.len(), MAX_FRAME_BYTES);
        assert_eq!(decode_frame(&bytes, active()).unwrap(), frame);
        match frame.body.as_mut().unwrap() {
            Body::Request(r) => r.payload.push(0),
            Body::Notification(n) => n.payload.push(0),
            Body::Result(r) => match r.outcome.as_mut().unwrap() {
                syntra_core::proto::rpc_result::Outcome::Payload(p) => p.push(0),
                syntra_core::proto::rpc_result::Outcome::Error(e) => e.message.push('x'),
            },
            _ => unreachable!(),
        }
        assert_eq!(frame.encoded_len(), MAX_FRAME_BYTES + 1);
        assert_eq!(
            validate_frame(&frame, active()).unwrap_err().code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            encode_frame(&frame, active()).unwrap_err().code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            decode_frame(&frame.encode_to_vec(), active())
                .unwrap_err()
                .code(),
            ErrorCode::ResourceExhausted
        );
    }
}

#[test]
fn duplicate_scalars_follow_protobuf_last_wins() {
    // Duplicate version/request_id occurrences are type-checked but not
    // rejected; prost merge takes the last value (SNTR-SER-002, RFC 0001
    // B4). Matches the Go binding's scanFrameTags behavior.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    // version 2 then 1, last wins 1 -> decodes in ACTIVE(1).
    let back = decode_frame(
        &hex("080208011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403"),
        active(),
    )
    .expect("duplicate version last-wins");
    assert_eq!(back.version, 1);
    assert_eq!(back.request_id, 7);
    // request_id 7 then 8, last wins 8.
    let back = decode_frame(
        &hex("080110071008621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403"),
        active(),
    )
    .expect("duplicate request_id last-wins");
    assert_eq!(back.request_id, 8);
    // Duplicate bodies remain rejected (SNTR-WIRE-002).
    let mut bytes = Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![],
        })),
    }
    .encode_to_vec();
    let ready = ServerReady {
        connection_id: "x".into(),
    }
    .encode_to_vec();
    bytes.push(0x5A);
    bytes.push(ready.len() as u8);
    bytes.extend_from_slice(&ready);
    assert_eq!(
        decode_frame(&bytes, connected()).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn nonempty_cancel_tolerated_as_unknown_fields() {
    // Cancel carries no defined fields; inner unknown bytes are tolerated
    // per SNTR-SER-003, matching the Go binding. Malformed inner wire
    // still fails via prost decode.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    for raw in [hex("0801100c7200"), hex("0801100c72020801")] {
        let back = decode_frame(&raw, active()).expect("cancel decodes");
        assert!(matches!(back.body, Some(Body::Cancel(_))));
        assert_eq!(back.request_id, 12);
    }
}

#[test]
fn nested_unassigned_numbers_tolerated() {
    // Numbers 16/17 are reserved only at the top-level Frame. Inside
    // nested messages they are unassigned unknown fields tolerated per
    // SNTR-SER-003, matching the Go binding. Top-level 16/17 stay rejected.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    for raw in [
        hex("080110076a0a0a0568656c6c6f800100"),
        hex("080110076a0a0a0568656c6c6f880100"),
    ] {
        let back = decode_frame(&raw, active()).expect("nested 16/17 tolerated");
        match back.body {
            Some(Body::Result(r)) => match r.outcome {
                Some(syntra_core::proto::rpc_result::Outcome::Payload(p)) => {
                    assert_eq!(&p[..], b"hello")
                }
                other => panic!("unexpected outcome {other:?}"),
            },
            other => panic!("unexpected body {other:?}"),
        }
    }
    for raw in [hex("0801800100"), hex("08018a0100")] {
        assert_eq!(
            decode_frame(&raw, active()).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}

#[test]
fn closing_only_allows_result_and_cancel_and_closed_allows_nothing() {
    let bodies = [
        Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![],
        }),
        Body::Ready(ServerReady {
            connection_id: "conn-1".into(),
        }),
        Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![],
            timeout_ms: 1,
        }),
        Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(vec![])),
        }),
        Body::Cancel(Cancel {}),
        Body::Notification(Notification { payload: vec![] }),
    ];
    for body in bodies {
        let draining = matches!(body, Body::Result(_) | Body::Cancel(_));
        let frame = Frame {
            version: 1,
            request_id: if matches!(body, Body::Request(_) | Body::Result(_) | Body::Cancel(_)) {
                1
            } else {
                0
            },
            body: Some(body),
        };
        for state in [ConnectionState::Closing, ConnectionState::Closed] {
            let ctx = ValidationContext {
                state,
                negotiated_version: Some(1),
            };
            let allowed = draining && state == ConnectionState::Closing;
            let validated = validate_frame(&frame, ctx);
            assert_eq!(validated.is_ok(), allowed, "{state:?}: {:?}", frame.body);
            if let Err(e) = validated {
                assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            }
            assert_eq!(encode_frame(&frame, ctx).is_ok(), allowed);
            assert_eq!(decode_frame(&frame.encode_to_vec(), ctx).is_ok(), allowed);
        }
    }
}
