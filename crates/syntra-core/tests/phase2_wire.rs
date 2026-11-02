//! Accepted-pin RFC 0004 D1 / RFC 0005 D2 / RFC 0008 D1 raw-wire regressions.
//! These local vectors do not modify managed conformance snapshots.

use prost::Message;
use syntra_core::proto::{frame::Body, rpc_result::Outcome};
use syntra_core::{
    bounded_diagnostic, build_hello, decode_frame, encode_frame, missing_result_outcome_id,
    validate_connection_id, validate_frame, validate_wire_structure, ConnectionState, ErrorCode,
    Frame, RequestIdAllocator, RpcError, RpcResult, SyntraError, ValidationContext,
    MAX_CONNECTION_ID_BYTES, MAX_CREDENTIAL_BYTES, MAX_DECODE_DEPTH, MAX_DIAGNOSTIC_BYTES,
    MAX_FRAME_BYTES,
};

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value >= 128 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn field(number: u32, wire: u8, value: &[u8]) -> Vec<u8> {
    let mut out = varint((u64::from(number) << 3) | u64::from(wire));
    if wire == 2 {
        out.extend(varint(value.len() as u64));
    }
    out.extend(value);
    out
}

fn len(number: u32, value: &[u8]) -> Vec<u8> {
    field(number, 2, value)
}

fn frame(body: u32, value: &[u8]) -> Vec<u8> {
    let mut out = vec![8, 1, 16, 7];
    out.extend(len(body, value));
    out
}

fn active() -> ValidationContext {
    ValidationContext::active(1)
}

fn rejected(raw: &[u8], code: ErrorCode) -> String {
    let structure = validate_wire_structure(raw).unwrap_err();
    let decoded = decode_frame(raw, active()).unwrap_err();
    assert_eq!(structure.code(), code, "{structure}");
    assert_eq!(decoded.code(), code, "{decoded}");
    assert_eq!(structure.to_string(), decoded.to_string());
    match structure {
        SyntraError::Protocol { message, .. } => message,
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn body_partition_and_metadata_are_exact() {
    for number in 18..=31 {
        assert_eq!(
            rejected(&frame(number, &[0xff]), ErrorCode::Unimplemented),
            "unknown frame body variant"
        );
        for wire in [0, 1, 3, 4, 5] {
            rejected(&field(number, wire, &[0; 8]), ErrorCode::InvalidArgument);
        }
    }
    for number in (3..=9).chain([32, 90, 0x1fff_ffff]) {
        let metadata = len(number, &[0xff]); // Unknown LEN content stays opaque.
        rejected(&metadata, ErrorCode::InvalidArgument);
        for before in [true, false] {
            let known = frame(14, &[]);
            let raw = if before {
                [metadata.clone(), known].concat()
            } else {
                [known, metadata.clone()].concat()
            };
            let back = decode_frame(&raw, active()).unwrap();
            assert_eq!(back.version, 1);
            assert_eq!(back.request_id, 7);
            assert!(matches!(back.body, Some(Body::Cancel(_))));
            validate_wire_structure(&raw).unwrap();
        }
    }
    for number in [16, 17] {
        assert_eq!(
            rejected(&frame(number, &[]), ErrorCode::InvalidArgument),
            "frame uses reserved field number"
        );
    }
}

#[test]
fn raw_body_and_outcome_multiplicity_never_merge() {
    for first in [14, 18, 31] {
        for second in [14, 18, 31] {
            let raw = [frame(first, &[]), len(second, &[])].concat();
            assert_eq!(
                rejected(&raw, ErrorCode::InvalidArgument),
                "frame body must have exactly one occurrence"
            );
        }
    }
    for first in [1, 2, 3, 15] {
        for second in [1, 2, 3, 15] {
            let outcomes = [len(first, &[]), len(second, &[])].concat();
            assert_eq!(
                rejected(&frame(13, &outcomes), ErrorCode::InvalidArgument),
                "result outcome must have exactly one occurrence"
            );
        }
    }
    for future in 3..=15 {
        rejected(&frame(13, &len(future, &[0xff])), ErrorCode::Unimplemented);
        for wire in [0, 1, 3, 4, 5] {
            rejected(
                &frame(13, &field(future, wire, &[0; 8])),
                ErrorCode::InvalidArgument,
            );
        }
    }
    for metadata in [16, 17, 32, 0x1fff_ffff] {
        rejected(&frame(13, &len(metadata, &[])), ErrorCode::InvalidArgument);
        for before in [true, false] {
            let outcome = len(1, &[]);
            let metadata = len(metadata, &[0xff]);
            let raw = frame(
                13,
                &if before {
                    [metadata, outcome].concat()
                } else {
                    [outcome, metadata].concat()
                },
            );
            assert_eq!(
                decode_frame(&raw, active()).unwrap().body,
                Some(Body::Result(RpcResult {
                    outcome: Some(Outcome::Payload(vec![]))
                }))
            );
        }
    }
}

#[test]
fn complete_structure_precedes_all_raw_classifications_in_both_orders() {
    let mut huge = varint(90 << 3 | 2);
    huge.extend(varint(MAX_FRAME_BYTES as u64 + 1));
    // A known request with a truncated nested timeout, not opaque payload.
    let malformed = len(12, &[0x18, 0x80]);
    for semantic in [
        len(16, &[]),
        [len(14, &[]), len(14, &[])].concat(),
        len(18, &[]),
        len(13, &len(3, &[])),
        len(13, &[]),
        len(13, &[0x0a, 0, 0x0a, 0]),
    ] {
        for before in [true, false] {
            for (structural, code, expected) in [
                (&huge, ErrorCode::ResourceExhausted, "allocation bound"),
                (&malformed, ErrorCode::InvalidArgument, "truncated varint"),
            ] {
                let raw = if before {
                    [semantic.clone(), structural.clone()].concat()
                } else {
                    [structural.clone(), semantic.clone()].concat()
                };
                assert!(rejected(&raw, code).contains(expected));
            }
        }
    }
    // Complete each RpcResult before classifying its outcome, too.
    for outcome in [vec![], len(3, &[]), vec![0x0a, 0, 0x0a, 0]] {
        for before in [true, false] {
            let bad = vec![0]; // Cannot be repaired by the following field.
            let raw = frame(
                13,
                &if before {
                    [outcome.clone(), bad].concat()
                } else {
                    [bad, outcome.clone()].concat()
                },
            );
            assert_eq!(
                rejected(&raw, ErrorCode::InvalidArgument),
                "invalid protobuf field number"
            );
        }
    }
    // Frame classification precedes nested outcome classification.
    for other in [16, 17, 18, 14] {
        for before in [true, false] {
            let result = len(13, &len(3, &[]));
            let other_field = len(other, &[]);
            let raw = if before {
                [other_field, result].concat()
            } else {
                [result, other_field].concat()
            };
            let message = rejected(&raw, ErrorCode::InvalidArgument);
            assert!(message.starts_with("frame "), "{message}");
        }
    }
}

// Wrap a core field in its known message boundaries. None denotes Frame itself.
fn wrap(body: Option<u32>, error: bool, value: &[u8]) -> Vec<u8> {
    match (body, error) {
        (Some(body), true) => frame(body, &len(2, value)),
        (Some(body), false) => frame(body, value),
        (None, _) => [value.to_vec(), frame(14, &[])].concat(),
    }
}

#[test]
fn every_known_core_field_occurrence_is_type_checked() {
    let fields = [
        (None, false, 1, 0),
        (None, false, 2, 0),
        (Some(10), false, 1, 0),
        (Some(10), false, 2, 0),
        (Some(10), false, 3, 2),
        (Some(11), false, 1, 2),
        (Some(12), false, 1, 2),
        (Some(12), false, 2, 2),
        (Some(12), false, 3, 0),
        (Some(13), false, 1, 2),
        (Some(13), false, 2, 2),
        (Some(13), true, 1, 0),
        (Some(13), true, 2, 2),
        (Some(15), false, 1, 2),
    ];
    for (body, error, number, expected_wire) in fields {
        for wrong_wire in [0, 1, 2, 3, 4, 5] {
            if wrong_wire == expected_wire {
                continue;
            }
            let wrong = field(number, wrong_wire, &[0; 8]);
            let valid = field(
                number,
                expected_wire,
                if expected_wire == 2 { &[] } else { &[1] },
            );
            for before in [true, false] {
                let value = if before {
                    [wrong.clone(), valid.clone()].concat()
                } else {
                    [valid.clone(), wrong.clone()].concat()
                };
                assert_eq!(
                    rejected(&wrap(body, error, &value), ErrorCode::InvalidArgument),
                    "wrong wire type for core field",
                    "body={body:?} error={error} field={number} wire={wrong_wire}"
                );
                assert_eq!(
                    missing_result_outcome_id(&wrap(body, error, &value), active()),
                    None
                );
            }
        }
    }
    for body in 10..=15 {
        rejected(&field(body, 0, &[0]), ErrorCode::InvalidArgument);
    }
}

#[test]
fn every_known_string_occurrence_requires_utf8_but_bytes_stay_opaque() {
    for (body, error, number) in [(11, false, 1), (12, false, 1), (13, true, 2)] {
        for before in [true, false] {
            let bad = len(number, &[0xff]);
            let good = len(number, b"valid");
            let raw = if before {
                [bad, good].concat()
            } else {
                [good, bad].concat()
            };
            assert_eq!(
                rejected(&wrap(Some(body), error, &raw), ErrorCode::InvalidArgument),
                "invalid UTF-8 in core string"
            );
            assert_eq!(
                missing_result_outcome_id(&wrap(Some(body), error, &raw), active()),
                None
            );
        }
    }
    for (body, number) in [(10, 3), (12, 2), (13, 1), (15, 1)] {
        validate_wire_structure(&frame(body, &len(number, &[0xff, 0, 0x80]))).unwrap();
    }
}

fn group(number: u32, inner: &[u8]) -> Vec<u8> {
    [field(number, 3, inner), field(number, 4, &[])].concat()
}

#[test]
fn lawful_unknown_groups_are_bounded_and_do_not_inherit_parent_schema() {
    // Inside unknown groups, even Frame-reserved and core-known numbers are
    // ordinary unknown fields. Group contents must still be well formed.
    let contents = [field(1, 0, &[1]), field(16, 0, &[0])].concat();
    for (body, number) in [(14, 1), (13, 16)] {
        let mut nested = group(number, &contents);
        if body == 13 {
            nested.extend(len(1, &[]));
        }
        decode_frame(&frame(body, &nested), active()).unwrap();
    }
    let mut nested = vec![];
    for _ in 0..MAX_DECODE_DEPTH {
        nested = group(90, &nested);
    }
    let raw = [frame(14, &[]), nested.clone()].concat();
    decode_frame(&raw, active()).unwrap();
    for before in [true, false] {
        let too_deep = group(90, &nested);
        let reserved = len(16, &[]);
        let raw = if before {
            [too_deep, reserved].concat()
        } else {
            [reserved, too_deep].concat()
        };
        rejected(&raw, ErrorCode::ResourceExhausted);
    }
    // Embedded message depth also consumes the budget.
    rejected(&frame(14, &nested), ErrorCode::ResourceExhausted);
    for malformed in [
        field(90, 3, &[]),
        field(90, 4, &[]),
        [field(90, 3, &[]), field(91, 4, &[])].concat(),
        group(90, &[0]),
    ] {
        rejected(&malformed, ErrorCode::InvalidArgument);
    }
}

#[test]
fn tags_varints_lengths_and_fixed_fields_are_bounded() {
    let overflow = [vec![0x80; 9], vec![2]].concat();
    let overlong = [vec![0x80; 10], vec![0]].concat();
    for bad in [overflow, overlong, vec![0x80]] {
        rejected(&bad, ErrorCode::InvalidArgument); // tag
        rejected(&field(90, 0, &bad), ErrorCode::InvalidArgument);
        let raw = [varint(90 << 3 | 2), bad].concat();
        rejected(&raw, ErrorCode::InvalidArgument); // length
    }
    for bad in [
        vec![0],
        varint(0x2000_0000 << 3),
        varint(u64::MAX),
        field(90, 6, &[]),
        field(90, 7, &[]),
        field(90, 1, &[0; 7]),
        field(90, 5, &[0; 3]),
        [varint(90 << 3 | 2), vec![2, 0]].concat(),
    ] {
        rejected(&bad, ErrorCode::InvalidArgument);
    }
    // Maximum uint64 metadata value and maximum field number are lawful.
    let raw = [frame(14, &[]), field(0x1fff_ffff, 0, &varint(u64::MAX))].concat();
    decode_frame(&raw, active()).unwrap();
}

#[test]
fn nonminimal_encodings_and_ordinary_scalar_merge_are_preserved() {
    // Non-minimal tag, scalar and length; duplicate version/id last wins.
    let mut raw = vec![0x88, 0, 0x82, 0, 8, 1, 16, 9, 16, 7, 0xf2, 0, 0x80, 0];
    let back = decode_frame(&raw, active()).unwrap();
    assert_eq!(back.version, 1);
    assert_eq!(back.request_id, 7);
    assert!(matches!(back.body, Some(Body::Cancel(_))));
    // A ten-byte non-minimal zero is still a valid bounded unknown scalar.
    raw.extend(field(
        90,
        0,
        &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0],
    ));
    decode_frame(&raw, active()).unwrap();
    let request = [len(1, b"/a/B"), field(3, 0, &[9, 0x18, 7])].concat();
    let back = decode_frame(&frame(12, &request), active()).unwrap();
    match back.body.unwrap() {
        Body::Request(r) => {
            assert_eq!(r.method, "/a/B");
            assert_eq!(r.timeout_ms, 7);
        }
        other => panic!("unexpected body {other:?}"),
    }
}

#[test]
fn credentials_and_connection_ids_have_exact_byte_boundaries() {
    assert_eq!(MAX_CREDENTIAL_BYTES, 8192);
    assert_eq!(MAX_CONNECTION_ID_BYTES, 128);
    for size in [0, 8192, 8193] {
        let built = build_hello(1, 1, vec![0xff; size]);
        assert_eq!(built.is_ok(), size <= 8192);
        let f = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![0xff; size],
            })),
        };
        let ctx = ValidationContext::pre_handshake(ConnectionState::Connected);
        assert_eq!(encode_frame(&f, ctx).is_ok(), size <= 8192);
        assert_eq!(decode_frame(&f.encode_to_vec(), ctx).is_ok(), size <= 8192);
        if size > 8192 {
            assert_eq!(built.unwrap_err().code(), ErrorCode::ResourceExhausted);
            assert_eq!(
                decode_frame(&f.encode_to_vec(), ctx).unwrap_err().code(),
                ErrorCode::ResourceExhausted
            );
        } else {
            assert_eq!(decode_frame(&f.encode_to_vec(), ctx).unwrap(), f);
        }
    }
    for id in [
        "".into(),
        "x".repeat(128),
        "x".repeat(129),
        "é".repeat(64),
        format!("{}x", "é".repeat(64)),
    ] {
        let valid = !id.is_empty() && id.len() <= 128;
        assert_eq!(validate_connection_id(&id).is_ok(), valid);
        let f = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Ready(syntra_core::ServerReady { connection_id: id })),
        };
        let ctx = ValidationContext::pre_handshake(ConnectionState::Negotiating);
        assert_eq!(encode_frame(&f, ctx).is_ok(), valid);
        assert_eq!(decode_frame(&f.encode_to_vec(), ctx).is_ok(), valid);
        if !valid {
            assert_eq!(
                decode_frame(&f.encode_to_vec(), ctx).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        } else {
            assert_eq!(decode_frame(&f.encode_to_vec(), ctx).unwrap(), f);
        }
    }
}

#[test]
fn diagnostics_bound_local_producers_but_reject_oversized_peer_text() {
    assert_eq!(MAX_DIAGNOSTIC_BYTES, 4096);
    for text in [
        "".into(),
        "x".repeat(4096),
        "x".repeat(4097),
        "é".repeat(2048),
        format!("{}é", "x".repeat(4095)),
    ] {
        let bounded = bounded_diagnostic(text.clone());
        assert!(bounded.len() <= 4096);
        assert!(text.starts_with(&bounded));
        assert_eq!(
            RpcError::new(ErrorCode::Internal, text.clone()).message,
            bounded
        );
        if text.len() <= 4096 {
            assert_eq!(bounded, text);
        }
        let f = Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Error(syntra_core::proto::RpcError {
                    code: 13,
                    message: text.clone(), // Direct public String construction.
                })),
            })),
        };
        let valid = text.len() <= 4096;
        assert_eq!(validate_frame(&f, active()).is_ok(), valid);
        assert_eq!(encode_frame(&f, active()).is_ok(), valid);
        let decoded = decode_frame(&f.encode_to_vec(), active());
        if valid {
            assert_eq!(decoded.unwrap(), f);
        } else {
            assert_eq!(decoded.unwrap_err().code(), ErrorCode::InvalidArgument);
        }
    }
    assert_eq!(
        bounded_diagnostic(format!("{}é", "x".repeat(4095))).len(),
        4095
    );
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

#[test]
fn missing_outcome_correlates_only_after_full_validation_without_accepting_frame() {
    // CONF-RPC-010: this is still rejected by both normal wire entry points.
    let raw = [8, 1, 16, 14, 0x6a, 0];
    let ctx = active();
    assert_eq!(missing_result_outcome_id(&raw, ctx), Some(14));
    rejected(&raw, ErrorCode::InvalidArgument);
    assert_eq!(ctx.state, ConnectionState::Active);
    // Metadata, including opaque content and lawful groups, is not an outcome.
    let metadata = [len(16, &[0xff]), group(17, &len(1, &[0xff]))].concat();
    for before in [true, false] {
        let nested = frame(13, &metadata);
        let outer = group(90, &len(13, &len(1, &[])));
        let raw = if before {
            [outer, nested].concat()
        } else {
            [nested, outer].concat()
        };
        assert_eq!(missing_result_outcome_id(&raw, ctx), Some(7));
        rejected(&raw, ErrorCode::InvalidArgument);
    }
    // Non-minimal encodings and ordinary header last-value semantics survive.
    let raw = [0x88, 0, 2, 8, 1, 16, 0, 16, 14, 0xea, 0, 0x80, 0];
    assert_eq!(missing_result_outcome_id(&raw, ctx), Some(14));
    let raw = [raw.to_vec(), field(2, 0, &varint(u64::MAX))].concat();
    assert_eq!(missing_result_outcome_id(&raw, ctx), Some(u64::MAX));
}

#[test]
fn missing_outcome_never_correlates_other_bodies_or_raw_multiplicity() {
    let missing = frame(13, &[]);
    assert_eq!(missing_result_outcome_id(&[], active()), None);
    assert_eq!(missing_result_outcome_id(&[8, 1, 16, 7], active()), None);
    for number in 10..=31 {
        let other = len(number, &[]);
        if number != 13 {
            assert_eq!(
                missing_result_outcome_id(&frame(number, &[]), active()),
                None
            );
        }
        // Includes repeated results, control frames, reserved and future bodies.
        for before in [true, false] {
            let raw = if before {
                [other.clone(), missing.clone()].concat()
            } else {
                [missing.clone(), other.clone()].concat()
            };
            assert_eq!(missing_result_outcome_id(&raw, active()), None);
            rejected(&raw, ErrorCode::InvalidArgument);
        }
    }
    for number in (3..=9).chain([32, 90]) {
        let metadata_only = [vec![8, 1, 16, 7], len(number, &[])].concat();
        assert_eq!(missing_result_outcome_id(&metadata_only, active()), None);
    }
}

#[test]
fn missing_outcome_never_correlates_any_present_outcome_or_oversized_diagnostic() {
    for first in 1..=15 {
        let outcome = if first == 2 {
            len(2, &[8, 13]) // Lawful error outcome, not a missing outcome.
        } else {
            len(first, &[])
        };
        let raw = frame(13, &outcome);
        assert_eq!(missing_result_outcome_id(&raw, active()), None);
        for second in 1..=15 {
            let raw = frame(13, &[outcome.clone(), len(second, &[])].concat());
            assert_eq!(missing_result_outcome_id(&raw, active()), None);
            rejected(&raw, ErrorCode::InvalidArgument);
        }
    }
    let error = [vec![8, 13], len(2, &vec![b'x'; MAX_DIAGNOSTIC_BYTES + 1])].concat();
    let raw = frame(13, &len(2, &error));
    assert_eq!(missing_result_outcome_id(&raw, active()), None);
    assert_eq!(
        decode_frame(&raw, active()).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

#[test]
fn missing_outcome_never_correlates_malformed_or_wrong_type_occurrences() {
    let missing = frame(13, &[]);
    let overflow = [vec![0x80; 9], vec![2]].concat();
    let root_faults = [
        vec![0],
        vec![0x80],
        varint(0x2000_0000 << 3),
        field(90, 0, &overflow),
        [varint(90 << 3 | 2), overflow].concat(),
        field(90, 1, &[0; 7]),
        field(90, 5, &[0; 3]),
        field(90, 6, &[]),
        field(90, 7, &[]),
        field(90, 3, &[]),
        field(90, 4, &[]),
        [field(90, 3, &[]), field(91, 4, &[])].concat(),
        len(1, &[]), // Wrong version type, even alongside valid version.
        len(2, &[]), // Wrong request_id type, even alongside valid ID.
        field(13, 0, &[0]),
        len(11, &len(1, &[0xff])), // Invalid UTF-8 in another body occurrence.
        len(12, &[0x1a, 0]),       // Wrong nested timeout type in another occurrence.
    ];
    for fault in root_faults {
        for before in [true, false] {
            let raw = if before {
                [fault.clone(), missing.clone()].concat()
            } else {
                [missing.clone(), fault.clone()].concat()
            };
            assert_eq!(missing_result_outcome_id(&raw, active()), None);
        }
    }
    // Unknown result metadata must be fully validated, not just skipped by tag.
    for nested in [
        vec![0],
        vec![0x80],
        field(16, 0, &[0x80]),
        [varint(16 << 3 | 2), vec![2, 0]].concat(),
        field(16, 3, &[]),
        field(1, 0, &[0]),
        field(2, 0, &[0]),
        field(3, 0, &[0]),
    ] {
        assert_eq!(
            missing_result_outcome_id(&frame(13, &nested), active()),
            None
        );
    }
}

#[test]
fn missing_outcome_checks_merged_version_id_and_state() {
    let raw = frame(13, &[]);
    for suffix in [vec![8, 0], vec![8, 2], vec![16, 0]] {
        let invalid = [raw.clone(), suffix].concat();
        assert_eq!(missing_result_outcome_id(&invalid, active()), None);
    }
    assert_eq!(missing_result_outcome_id(&[8, 1, 0x6a, 0], active()), None);
    assert_eq!(missing_result_outcome_id(&[16, 7, 0x6a, 0], active()), None);
    for state in [
        ConnectionState::Connected,
        ConnectionState::Negotiating,
        ConnectionState::Authenticating,
        ConnectionState::Closed,
    ] {
        for negotiated_version in [None, Some(1)] {
            let ctx = ValidationContext {
                state,
                negotiated_version,
            };
            assert_eq!(missing_result_outcome_id(&raw, ctx), None);
        }
    }
    let ctx = ValidationContext {
        state: ConnectionState::Active,
        negotiated_version: None,
    };
    assert_eq!(missing_result_outcome_id(&raw, ctx), None);
    // Existing results remain legal while draining, with the negotiated version.
    let ctx = ValidationContext {
        state: ConnectionState::Closing,
        negotiated_version: Some(1),
    };
    assert_eq!(missing_result_outcome_id(&raw, ctx), Some(7));
    let ctx = ValidationContext {
        negotiated_version: Some(2),
        ..ctx
    };
    assert_eq!(missing_result_outcome_id(&raw, ctx), None);
}

#[test]
fn missing_outcome_obeys_exact_envelope_and_depth_limits() {
    let missing = frame(13, &[]);
    // Metadata is discarded by prost, but still counts against the raw bound.
    let mut raw = [missing.clone(), len(90, &vec![0xff; MAX_FRAME_BYTES - 11])].concat();
    assert_eq!(raw.len(), MAX_FRAME_BYTES);
    assert_eq!(missing_result_outcome_id(&raw, active()), Some(7));
    raw.push(0);
    assert_eq!(missing_result_outcome_id(&raw, active()), None);
    let huge = [varint(90 << 3 | 2), varint(MAX_FRAME_BYTES as u64 + 1)].concat();
    let raw = [missing.clone(), huge].concat();
    assert_eq!(missing_result_outcome_id(&raw, active()), None);
    let mut nested = vec![];
    for _ in 0..MAX_DECODE_DEPTH {
        nested = group(90, &nested);
    }
    let raw = [missing.clone(), nested.clone()].concat();
    assert_eq!(missing_result_outcome_id(&raw, active()), Some(7));
    let raw = [missing, group(90, &nested)].concat();
    assert_eq!(missing_result_outcome_id(&raw, active()), None);
    // Result's own message boundary also consumes the depth budget.
    assert_eq!(
        missing_result_outcome_id(&frame(13, &nested), active()),
        None
    );
}

fn field_bound_frame(body: u32, fields: &[u8]) -> Vec<u8> {
    let inner = match body {
        10 => [vec![8, 1, 16, 1], fields.to_vec()].concat(),
        13 => len(2, &[vec![8, 13], fields.to_vec()].concat()),
        _ => fields.to_vec(),
    };
    let header = if body == 13 {
        vec![8, 1, 16, 7]
    } else {
        vec![8, 1]
    };
    [header, len(body, &inner)].concat()
}

#[test]
fn field_admission_caps_every_occurrence_but_preserves_bounded_last_value_semantics() {
    for (body, number, limit, code, ctx) in [
        (
            10,
            3,
            MAX_CREDENTIAL_BYTES,
            ErrorCode::ResourceExhausted,
            ValidationContext::pre_handshake(ConnectionState::Connected),
        ),
        (
            11,
            1,
            MAX_CONNECTION_ID_BYTES,
            ErrorCode::InvalidArgument,
            ValidationContext::pre_handshake(ConnectionState::Negotiating),
        ),
        (
            13,
            2,
            MAX_DIAGNOSTIC_BYTES,
            ErrorCode::InvalidArgument,
            active(),
        ),
    ] {
        let oversized = len(number, &vec![b'x'; limit + 1]);
        let at_limit = len(number, &vec![b'x'; limit]);
        let small = len(number, b"ok");
        // An oversized early value cannot be admitted merely because a later
        // value replaces it: prost would allocate each consumed occurrence.
        for fields in [
            oversized.clone(),
            [oversized.clone(), small.clone()].concat(),
            [small.clone(), oversized].concat(),
        ] {
            let raw = field_bound_frame(body, &fields);
            let message = rejected(&raw, code);
            assert!(message.contains("bound") || message == "invalid connection_id length");
            assert_eq!(missing_result_outcome_id(&raw, ctx), None);
        }
        for (fields, expected) in [
            ([at_limit.clone(), small.clone()].concat(), b"ok".to_vec()),
            ([small, at_limit].concat(), vec![b'x'; limit]),
        ] {
            let raw = field_bound_frame(body, &fields);
            validate_wire_structure(&raw).unwrap();
            let frame = decode_frame(&raw, ctx).unwrap();
            match frame.body.unwrap() {
                Body::Hello(hello) => assert_eq!(hello.credential, expected),
                Body::Ready(ready) => assert_eq!(ready.connection_id.as_bytes(), expected),
                Body::Result(result) => match result.outcome.unwrap() {
                    Outcome::Error(error) => {
                        assert_eq!(error.code, 13);
                        assert_eq!(error.message.as_bytes(), expected);
                    }
                    other => panic!("unexpected outcome {other:?}"),
                },
                other => panic!("unexpected body {other:?}"),
            }
        }
    }
}

#[test]
fn field_bounds_are_deferred_until_complete_structure_and_raw_choices_pass() {
    for (body, number, limit) in [
        (10, 3, MAX_CREDENTIAL_BYTES),
        (11, 1, MAX_CONNECTION_ID_BYTES),
        (13, 2, MAX_DIAGNOSTIC_BYTES),
    ] {
        let oversized = len(number, &vec![b'x'; limit + 1]);
        let raw = field_bound_frame(body, &oversized);
        for (fault, message) in [
            (vec![0], "invalid protobuf field number"),
            (len(1, &[]), "wrong wire type for core field"),
            (len(12, &[0x1a, 0]), "wrong wire type for core field"),
            (len(11, &len(1, &[0xff])), "invalid UTF-8 in core string"),
            (len(16, &[]), "frame uses reserved field number"),
            (len(17, &[]), "frame uses reserved field number"),
            (len(14, &[]), "frame body must have exactly one occurrence"),
            (len(18, &[]), "frame body must have exactly one occurrence"),
        ] {
            for before in [true, false] {
                let input = if before {
                    [fault.clone(), raw.clone()].concat()
                } else {
                    [raw.clone(), fault.clone()].concat()
                };
                assert_eq!(rejected(&input, ErrorCode::InvalidArgument), message);
                assert_eq!(missing_result_outcome_id(&input, active()), None);
            }
        }
        // Invalid UTF-8 in a known string occurrence is structural, even when
        // preceded by an oversized value that would otherwise be overwritten.
        if body != 10 {
            let mut invalid_oversized = vec![b'x'; limit + 1];
            invalid_oversized[limit] = 0xff;
            assert_eq!(
                rejected(
                    &field_bound_frame(body, &len(number, &invalid_oversized)),
                    ErrorCode::InvalidArgument
                ),
                "invalid UTF-8 in core string"
            );
            for before in [true, false] {
                let invalid_utf8 = len(number, &[0xff]);
                let fields = if before {
                    [invalid_utf8, oversized.clone()].concat()
                } else {
                    [oversized.clone(), invalid_utf8].concat()
                };
                assert_eq!(
                    rejected(
                        &field_bound_frame(body, &fields),
                        ErrorCode::InvalidArgument
                    ),
                    "invalid UTF-8 in core string"
                );
            }
        }
        if body == 13 {
            let error = len(2, &[vec![8, 13], oversized].concat());
            for outcome in 1..=15 {
                for before in [true, false] {
                    let other = len(outcome, &[]);
                    let outcomes = if before {
                        [other, error.clone()].concat()
                    } else {
                        [error.clone(), other].concat()
                    };
                    assert_eq!(
                        rejected(&frame(13, &outcomes), ErrorCode::InvalidArgument),
                        "result outcome must have exactly one occurrence"
                    );
                }
            }
        }
    }
}

#[test]
fn field_caps_are_schema_scoped_not_applied_inside_opaque_content() {
    // These byte strings deliberately look like oversized bounded core fields.
    // They are still opaque in metadata, credentials, and application payloads.
    let looks_like_diagnostic = len(2, &vec![b'x'; MAX_DIAGNOSTIC_BYTES + 1]);
    let hello = field_bound_frame(10, &len(3, &looks_like_diagnostic));
    decode_frame(
        &hello,
        ValidationContext::pre_handshake(ConnectionState::Connected),
    )
    .unwrap();
    for raw in [
        frame(13, &len(1, &looks_like_diagnostic)),
        frame(
            12,
            &[len(1, b"/a/B"), len(2, &looks_like_diagnostic)].concat(),
        ),
        [frame(14, &[]), len(90, &looks_like_diagnostic)].concat(),
        frame(14, &group(90, &looks_like_diagnostic)),
    ] {
        decode_frame(&raw, active()).unwrap();
    }
}
