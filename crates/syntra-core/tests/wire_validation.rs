//! Field admission, semantic error ordering, and narrow correlation regressions.

#[path = "fixtures/bebop.rs"]
mod bebop;
use bebop::{field_frame, frame, sized, union};
use syntra_core::wire::{call_result::Outcome, frame::Body, RpcError};
use syntra_core::{
    bounded_diagnostic, build_hello, decode_frame, encode_frame, missing_result_outcome_id,
    validate_connection_id, validate_frame, validate_wire_structure, Call, CallResult, Cancel,
    ConnectionState, ErrorCode, Frame, RequestIdAllocator, ValidationContext,
    MAX_CONNECTION_ID_BYTES, MAX_CREDENTIAL_BYTES, MAX_DIAGNOSTIC_BYTES,
};

fn active() -> ValidationContext {
    ValidationContext::active(1)
}

fn rejected(raw: &[u8], ctx: ValidationContext, code: ErrorCode) {
    assert_eq!(validate_wire_structure(raw).unwrap_err().code(), code);
    assert_eq!(decode_frame(raw, ctx).unwrap_err().code(), code, "{ctx:?}");
    assert_eq!(missing_result_outcome_id(raw, ctx), None);
}

#[test]
fn versions_precede_id_and_state_but_not_malformed_structure() {
    for version in [0, 2, u32::MAX] {
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
            let expected = if version != 0 && state == ConnectionState::Active {
                ErrorCode::FailedPrecondition
            } else {
                ErrorCode::InvalidArgument
            };
            // Cancel also has an invalid ID, which must not mask the version mismatch.
            let raw = frame(version, 0, 14, &sized(&[0]));
            let typed = Frame {
                version,
                request_id: 0,
                body: Some(Body::Cancel(Cancel {})),
            };
            validate_wire_structure(&raw).unwrap();
            assert_eq!(decode_frame(&raw, ctx).unwrap_err().code(), expected);
            assert_eq!(validate_frame(&typed, ctx).unwrap_err().code(), expected);
            assert_eq!(encode_frame(&typed, ctx).unwrap_err().code(), expected);
            rejected(&raw[..raw.len() - 1], ctx, ErrorCode::InvalidArgument);
        }
    }
}

#[test]
fn unknown_union_is_not_a_missing_choice_or_reserved_body() {
    for tag in [0, 16, 17, 18, 31, 255] {
        let raw = frame(1, 7, tag, &[0xff]);
        rejected(
            &raw,
            active(),
            if matches!(tag, 0 | 16 | 17) {
                ErrorCode::InvalidArgument
            } else {
                ErrorCode::Unimplemented
            },
        );
        rejected(&raw[..raw.len() - 1], active(), ErrorCode::InvalidArgument);
    }
    for tag in [0, 3, 15, 255] {
        rejected(
            &frame(1, 7, 13, &union(tag, &[0xff])),
            active(),
            if tag == 0 {
                ErrorCode::InvalidArgument
            } else {
                ErrorCode::Unimplemented
            },
        );
    }
}

#[test]
fn unknown_message_tail_is_opaque_only_inside_its_declared_extent() {
    // Future fields have no independent size. Bytes after their first tag
    // cannot be treated as parent fields, nor as another result/notification.
    let fields = [1, 1, 0, 0, 0, 0xff, 90, 2, 0xff, 0xff, 0xff, 0xff, 0];
    let raw = frame(1, 0, 15, &sized(&fields));
    let value = decode_frame(&raw, active()).unwrap();
    assert_eq!(
        value.body,
        Some(Body::Notification(syntra_core::Notification {
            payload: vec![0xff]
        }))
    );
    rejected(
        &frame(1, 0, 15, &sized(&fields[..fields.len() - 1])),
        active(),
        ErrorCode::InvalidArgument,
    );
    rejected(
        &frame(1, 0, 15, &[sized(&fields), vec![0]].concat()),
        active(),
        ErrorCode::InvalidArgument,
    );
    let result = frame(1, 7, 13, &union(2, &sized(&[1, 13, 0, 0, 0, 99, 0xff, 0])));
    let value = decode_frame(&result, active()).unwrap();
    assert_eq!(
        value.body,
        Some(Body::Result(CallResult {
            outcome: Some(Outcome::Error(RpcError {
                code: 13,
                message: String::new()
            }))
        }))
    );
}

#[test]
fn known_field_order_terminators_and_nested_lengths_are_checked() {
    for fields in [
        &[][..],
        &[0, 0],
        &[1, 1, 0, 0, 0],
        &[1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        &[2, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        &[3, 0xff, 0xff, 0xff, 0xff, 0],
    ] {
        rejected(
            &frame(1, 0, 10, &sized(fields)),
            ValidationContext::pre_handshake(ConnectionState::Connected),
            ErrorCode::InvalidArgument,
        );
    }
    for raw in [
        frame(1, 7, 14, &[0xff; 4]),
        frame(1, 7, 13, &[0xff; 5]),
        frame(1, 7, 13, &union(1, &[0xff; 4])),
        frame(1, 7, 13, &union(1, &[0, 0, 0, 0, 0])),
        frame(
            1,
            7,
            13,
            &[union(1, &sized(b"ok")), union(1, &sized(b""))].concat(),
        ),
    ] {
        rejected(&raw, active(), ErrorCode::InvalidArgument);
    }
}

#[test]
fn strings_must_be_utf8_and_semantics_are_not_structure() {
    for tag in [11, 12, 13] {
        rejected(
            &field_frame(tag, &[0xff]),
            active(),
            ErrorCode::InvalidArgument,
        );
    }
    let connected = ValidationContext::pre_handshake(ConnectionState::Connected);
    let negotiating = ValidationContext::pre_handshake(ConnectionState::Negotiating);
    for (raw, ctx) in [
        (
            frame(1, 0, 10, &sized(&[1, 2, 0, 0, 0, 2, 1, 0, 0, 0, 0])),
            connected,
        ),
        (field_frame(11, b""), negotiating),
        (field_frame(12, b"/a/b/c"), active()),
        (
            frame(1, 7, 13, &union(2, &sized(&[1, 0, 0, 0, 0, 0]))),
            active(),
        ),
    ] {
        validate_wire_structure(&raw).unwrap();
        assert_eq!(
            decode_frame(&raw, ctx).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
    for (size, expected) in [(512, Ok(())), (513, Err(ErrorCode::InvalidArgument))] {
        let method = format!("/a/{}", "b".repeat(size - 3));
        assert_eq!(
            decode_frame(&field_frame(12, method.as_bytes()), active())
                .map(|_| ())
                .map_err(|e| e.code()),
            expected
        );
    }
}

#[test]
fn missing_outcome_correlates_only_an_exact_otherwise_legal_result() {
    for id in [1, u64::MAX] {
        let raw = frame(1, id, 13, &[]);
        assert_eq!(
            validate_wire_structure(&raw).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
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
            let allowed = matches!(state, ConnectionState::Active | ConnectionState::Closing);
            assert_eq!(
                decode_frame(&raw, ctx).unwrap_err().code(),
                ErrorCode::InvalidArgument,
                "{ctx:?}"
            );
            assert_eq!(missing_result_outcome_id(&raw, ctx), allowed.then_some(id));
        }
        for n in 0..raw.len() {
            assert_eq!(missing_result_outcome_id(&raw[..n], active()), None);
        }
        for invalid in [
            frame(1, 0, 13, &[]),
            frame(2, id, 13, &[]),
            frame(0, id, 13, &[]),
            frame(1, id, 14, &[]),
            frame(1, id, 13, &[0]),
            frame(1, id, 13, &union(1, &sized(&[]))),
            [raw.clone(), vec![0]].concat(),
        ] {
            assert_eq!(missing_result_outcome_id(&invalid, active()), None);
        }
        assert_eq!(
            missing_result_outcome_id(
                &raw,
                ValidationContext::pre_handshake(ConnectionState::Active)
            ),
            None
        );
    }
}

#[test]
fn local_field_limits_count_bytes_not_characters() {
    assert_eq!(MAX_CREDENTIAL_BYTES, 8192);
    build_hello(1, 1, vec![]).unwrap();
    build_hello(1, 1, vec![0xff; MAX_CREDENTIAL_BYTES]).unwrap();
    assert_eq!(
        build_hello(1, 1, vec![0xff; MAX_CREDENTIAL_BYTES + 1])
            .unwrap_err()
            .code(),
        ErrorCode::ResourceExhausted
    );
    assert_eq!(MAX_CONNECTION_ID_BYTES, 128);
    let id = "é".repeat(MAX_CONNECTION_ID_BYTES / 2);
    validate_connection_id(&id).unwrap();
    for invalid in ["", &format!("{id}x")] {
        assert_eq!(
            validate_connection_id(invalid).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
    assert_eq!(MAX_DIAGNOSTIC_BYTES, 4096);
    for (text, expected) in [
        ("".to_owned(), 0),
        ("é".repeat(2048), 4096),
        (format!("{}é", "x".repeat(4095)), 4095),
        ("x".repeat(4097), 4096),
    ] {
        let bounded = bounded_diagnostic(text.clone());
        assert_eq!(bounded.len(), expected);
        assert!(text.starts_with(&bounded));
        assert_eq!(
            syntra_core::RpcError::new(ErrorCode::Internal, text).message,
            bounded
        );
    }
}

#[test]
fn direct_admission_and_encoder_reject_invalid_call_and_result_values() {
    for body in [
        None,
        Some(Body::Call(Call {
            method: "/bad path/B".into(),
            ..Call::default()
        })),
        Some(Body::Result(CallResult { outcome: None })),
        Some(Body::Result(CallResult {
            outcome: Some(Outcome::Error(RpcError {
                code: 0,
                message: "not success".into(),
            })),
        })),
        Some(Body::Result(CallResult {
            outcome: Some(Outcome::Error(RpcError {
                code: 13,
                message: "x".repeat(4097),
            })),
        })),
    ] {
        let frame = Frame {
            version: 1,
            request_id: 7,
            body,
        };
        assert_eq!(
            validate_frame(&frame, active()).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            encode_frame(&frame, active()).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}

#[test]
fn allocator_is_unique_across_threads_and_never_recycles_abandoned_ids() {
    let allocator = std::sync::Arc::new(RequestIdAllocator::default());
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let allocator = allocator.clone();
            std::thread::spawn(move || {
                (0..100)
                    .map(|_| allocator.next_candidate().unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut ids: Vec<_> = workers
        .into_iter()
        .flat_map(|w| w.join().unwrap())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (1..=400).collect::<Vec<_>>());
    assert_eq!(allocator.next_candidate().unwrap(), 401);
}
