//! Local byte-exact envelope examples and connection semantics.

#[path = "fixtures/bebop.rs"]
mod bebop;
#[allow(dead_code)]
#[path = "../../../tests/interoperability/vectors.rs"]
mod vectors;

use syntra_core::wire::{call_result::Outcome, frame::Body, RpcError};
use syntra_core::{
    decode_frame, decode_frame_structure, encode_frame, validate_frame, validate_wire_structure,
    Call, CallResult, Cancel, ClientHello, ConnectionState, ErrorCode, Frame, Notification,
    ServerReady, ValidationContext, MAX_FRAME_BYTES,
};

fn examples() -> Vec<(&'static str, Frame, ValidationContext)> {
    use vectors::bebop::*;
    let id = 0x0102_0304_0506_0708;
    [
        (
            HELLO,
            0,
            Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![0xff, 0],
            }),
        ),
        (
            READY,
            0,
            Body::Ready(ServerReady {
                connection_id: "é".into(),
            }),
        ),
        (
            CALL,
            id,
            Body::Call(Call {
                method: "/a/B".into(),
                payload: vec![0xff, 0],
                timeout_ms: 0x11223344,
            }),
        ),
        (
            SUCCESS,
            id,
            Body::Result(CallResult {
                outcome: Some(Outcome::Payload(vec![0xff, 0])),
            }),
        ),
        (
            EMPTY_SUCCESS,
            id,
            Body::Result(CallResult {
                outcome: Some(Outcome::Payload(vec![])),
            }),
        ),
        (
            ERROR,
            id,
            Body::Result(CallResult {
                outcome: Some(Outcome::Error(RpcError {
                    code: 13,
                    message: "é".into(),
                })),
            }),
        ),
        (CANCEL, id, Body::Cancel(Cancel {})),
        (
            NOTIFICATION,
            0,
            Body::Notification(Notification {
                payload: vec![0xff, 0],
            }),
        ),
    ]
    .into_iter()
    .map(|(hex, request_id, body)| {
        let ctx = match body {
            Body::Hello(_) => ValidationContext::pre_handshake(ConnectionState::Connected),
            Body::Ready(_) => ValidationContext::pre_handshake(ConnectionState::Negotiating),
            _ => ValidationContext::active(1),
        };
        (
            hex,
            Frame {
                version: 1,
                request_id,
                body: Some(body),
            },
            ctx,
        )
    })
    .collect()
}

#[test]
fn bebop_envelope_vectors_match_in_both_directions() {
    for (hex, frame, ctx) in examples() {
        let raw = vectors::hex_to_bytes(hex);
        assert_eq!(frame.encoded_len(), raw.len());
        assert_eq!(encode_frame(&frame, ctx).unwrap(), raw);
        validate_wire_structure(&raw).unwrap();
        assert_eq!(decode_frame_structure(&raw).unwrap(), frame);
        assert_eq!(decode_frame(&raw, ctx).unwrap(), frame);
    }
}

#[test]
fn exactly_one_complete_envelope_is_required() {
    for (hex, _, ctx) in examples() {
        let raw = vectors::hex_to_bytes(hex);
        for n in 0..raw.len() {
            assert_eq!(
                decode_frame(&raw[..n], ctx).unwrap_err().code(),
                ErrorCode::InvalidArgument,
                "{hex} cut at {n}"
            );
        }
        for extra in [&[0][..], raw.as_slice()] {
            let bad = [raw.as_slice(), extra].concat();
            assert_eq!(
                validate_wire_structure(&bad).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
            assert_eq!(
                decode_frame(&bad, ctx).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        }
    }
    let legacy = vectors::no_length_prefix_rejected();
    let ctx = ValidationContext::pre_handshake(ConnectionState::Connected);
    assert_eq!(
        decode_frame(&legacy, ctx).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn unregistered_rpc_error_codes_keep_the_wire_integer() {
    let ctx = ValidationContext::active(1);
    for raw in [i32::MIN, -1, i32::MAX] {
        let frame = Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Result(CallResult {
                outcome: Some(Outcome::Error(RpcError {
                    code: raw,
                    message: String::new(),
                })),
            })),
        };
        let bytes = encode_frame(&frame, ctx).unwrap();
        assert_eq!(decode_frame(&bytes, ctx).unwrap(), frame);
        assert_eq!(
            ErrorCode::from_i32_lossy(raw),
            (ErrorCode::Unknown, Some(raw))
        );
    }
}

#[test]
fn body_kind_controls_id_and_state() {
    use ConnectionState::*;
    for (hex, mut frame, ctx) in examples() {
        let mut raw = vectors::hex_to_bytes(hex);
        for state in [
            Connected,
            Negotiating,
            Authenticating,
            Active,
            Closing,
            Closed,
        ] {
            let ctx = ValidationContext {
                state,
                negotiated_version: Some(1),
            };
            let allowed = match frame.body.as_ref().unwrap() {
                Body::Hello(_) => matches!(state, Connected | Negotiating | Authenticating),
                Body::Ready(_) => matches!(state, Negotiating | Authenticating),
                Body::Call(_) => state == Active,
                Body::Result(_) | Body::Notification(_) | Body::Cancel(_) => {
                    matches!(state, Active | Closing)
                }
            };
            assert_eq!(
                decode_frame(&raw, ctx).map(|_| ()).map_err(|e| e.code()),
                if allowed {
                    Ok(())
                } else {
                    Err(ErrorCode::FailedPrecondition)
                }
            );
            assert_eq!(encode_frame(&frame, ctx).is_ok(), allowed);
        }
        frame.request_id = u64::from(frame.request_id == 0);
        raw[4..12].copy_from_slice(&frame.request_id.to_le_bytes());
        assert_eq!(
            decode_frame(&raw, ctx).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            validate_frame(&frame, ctx).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}

#[test]
fn every_variable_size_body_obeys_envelope_bound_before_semantics() {
    for (_, mut frame, _) in examples() {
        match frame.body.as_mut().unwrap() {
            Body::Hello(h) => h.credential.resize(MAX_FRAME_BYTES, 0),
            Body::Ready(r) => r.connection_id = "x".repeat(MAX_FRAME_BYTES),
            Body::Call(c) => c.payload.resize(MAX_FRAME_BYTES, 0),
            Body::Result(r) => match r.outcome.as_mut().unwrap() {
                Outcome::Error(e) => e.message = "x".repeat(MAX_FRAME_BYTES),
                Outcome::Payload(p) => p.resize(MAX_FRAME_BYTES, 0),
            },
            Body::Notification(n) => n.payload.resize(MAX_FRAME_BYTES, 0),
            Body::Cancel(_) => continue,
        }
        frame.version = 0;
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
fn exact_envelope_boundary_for_application_payloads() {
    use bebop::{field_frame, frame, sized, union};

    let ctx = ValidationContext::active(1);
    for tag in [12, 13, 15] {
        let wire = |payload: &[u8]| match tag {
            12 => {
                let fields = [&[1][..], &sized(b"/a/B"), &[2], &sized(payload), &[0]].concat();
                frame(1, 7, tag, &sized(&fields))
            }
            13 => frame(1, 7, tag, &union(1, &sized(payload))),
            15 => field_frame(tag, payload),
            _ => unreachable!(),
        };
        let payload = vec![0xff; MAX_FRAME_BYTES - wire(&[]).len()];
        let bytes = wire(&payload);
        assert_eq!(bytes.len(), MAX_FRAME_BYTES);
        let mut frame = decode_frame(&bytes, ctx).unwrap();
        assert_eq!(encode_frame(&frame, ctx).unwrap(), bytes);

        let mut trailing = wire(&payload[..payload.len() - 1]);
        trailing.push(0);
        assert_eq!(trailing.len(), MAX_FRAME_BYTES);
        assert_eq!(
            decode_frame(&trailing, ctx).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );

        let p = match frame.body.as_mut().unwrap() {
            Body::Call(c) => &mut c.payload,
            Body::Result(CallResult {
                outcome: Some(Outcome::Payload(p)),
            }) => p,
            Body::Notification(n) => &mut n.payload,
            _ => unreachable!(),
        };
        p.push(0);
        let bytes = wire(p);
        assert_eq!(bytes.len(), MAX_FRAME_BYTES + 1);
        assert_eq!(frame.encoded_len(), bytes.len());
        assert_eq!(
            validate_frame(&frame, ctx).unwrap_err().code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            encode_frame(&frame, ctx).unwrap_err().code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            validate_wire_structure(&bytes).unwrap_err().code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            decode_frame(&bytes, ctx).unwrap_err().code(),
            ErrorCode::ResourceExhausted
        );
    }
}
