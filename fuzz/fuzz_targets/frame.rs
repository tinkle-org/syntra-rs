#![no_main]

use libfuzzer_sys::fuzz_target;
use syntra_core::{
    decode_frame, encode_frame, missing_result_outcome_id, validate_wire_structure,
    ConnectionState, ValidationContext,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
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
});
