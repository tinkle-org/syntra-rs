#![no_main]

use libfuzzer_sys::{arbitrary::Unstructured, fuzz_target};
use prost::encoding::{encode_key, encode_varint, string, uint32, uint64, WireType};
use prost::Message;
use syntra_core::proto::frame::Body;
use syntra_core::{
    decode_frame, decode_frame_structure, encode_frame, missing_result_outcome_id,
    validate_wire_structure, ConnectionState, Frame, ValidationContext, MAX_FRAME_BYTES,
};

fn check_raw_request(data: &[u8]) {
    if let Ok(frame) = decode_frame_structure(data) {
        assert!(data.len() <= MAX_FRAME_BYTES);
        if matches!(frame.body, Some(Body::Request(_))) {
            assert!(frame == Frame::decode(data).expect("Prost rejected an admitted request"));
        }
    }
}

fn len_field(tag: u32, value: &[u8], out: &mut Vec<u8>) {
    encode_key(tag, WireType::LengthDelimited, out);
    encode_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn legal_request(data: &[u8]) -> Vec<u8> {
    // Unstructured zero-pads short integer draws; even empty input gets a case.
    let mut input = Unstructured::new(data);
    let flags = input.arbitrary::<u8>().unwrap();
    let name_len = usize::from(input.arbitrary::<u8>().unwrap());
    let id = input.arbitrary::<u64>().unwrap().max(1);
    let timeout = input.arbitrary::<u32>().unwrap();
    let rest = input.take_rest();
    let (name, payload) = rest.split_at(name_len.min(rest.len()));
    let mut method = String::from("/svc/M");
    method.extend(name.iter().map(|b| char::from(b'a' + b % 26)));
    // Leave room for the method (<=261 bytes), scalar duplicates and wire headers.
    let payload = &payload[..payload.len().min(MAX_FRAME_BYTES - 512)];

    let with_payload = flags & 2 != 0;
    let payload_len = if with_payload { payload.len() } else { 0 };
    let mut request = Vec::with_capacity(method.len() + payload_len + 32);
    let merge = flags & 1 != 0;
    if merge {
        len_field(1, b"/old/M", &mut request);
        len_field(2, b"old", &mut request);
        uint32::encode(3, &1, &mut request);
    }
    const ORDERS: [[u32; 3]; 6] = [
        [1, 2, 3],
        [1, 3, 2],
        [2, 1, 3],
        [2, 3, 1],
        [3, 1, 2],
        [3, 2, 1],
    ];
    for tag in ORDERS[usize::from(flags >> 4) % ORDERS.len()] {
        match tag {
            1 => string::encode(tag, &method, &mut request),
            2 if with_payload => len_field(tag, payload, &mut request),
            3 if flags & 4 != 0 => uint32::encode(tag, &timeout, &mut request),
            _ => {} // Omitted scalars/bytes retain their prior or default value.
        }
    }
    let mut frame = Vec::with_capacity(request.len() + 32);
    if merge {
        uint32::encode(1, &2, &mut frame);
        uint64::encode(2, &0, &mut frame);
    }
    let body_first = flags & 8 != 0;
    if body_first {
        len_field(12, &request, &mut frame);
    }
    uint32::encode(1, &1, &mut frame);
    uint64::encode(2, &id, &mut frame);
    if !body_first {
        len_field(12, &request, &mut frame);
    }
    assert!(frame.len() <= MAX_FRAME_BYTES);
    frame
}

fn check_legal_request(data: &[u8]) {
    let wire = legal_request(data);
    let expected = Frame::decode(wire.as_slice()).expect("generated invalid protobuf");
    assert!(matches!(expected.body, Some(Body::Request(_))));
    let actual = decode_frame(&wire, ValidationContext::active(1)).expect("rejected legal request");
    assert!(actual == expected);
}

fn check_contexts(data: &[u8]) {
    for ctx in [
        ValidationContext::pre_handshake(ConnectionState::Connected),
        ValidationContext::pre_handshake(ConnectionState::Negotiating),
        ValidationContext::active(1),
    ] {
        let decoded = decode_frame(data, ctx);
        if let Some(id) = missing_result_outcome_id(data, ctx) {
            assert_ne!(id, 0);
            assert!(decoded.is_err());
        }
        if let Ok(frame) = decoded {
            assert!(validate_wire_structure(data).is_ok());
            let encoded = encode_frame(&frame, ctx).unwrap();
            assert_eq!(decode_frame(&encoded, ctx).unwrap(), frame);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_FRAME_BYTES + 1 {
        check_raw_request(data);
        check_legal_request(data);
        // Avoid three additional context scans/round trips on near-limit frames.
        if data.len() <= 4096 {
            check_contexts(data);
        }
    }
});
