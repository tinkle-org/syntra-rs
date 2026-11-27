#![no_main]

use libfuzzer_sys::fuzz_target;
use syntra_core::frame::{decode_frame, encode_frame, ValidationContext};
use syntra_core::state::ConnectionState;

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    for ctx in [
        ValidationContext::pre_handshake(ConnectionState::Negotiating),
        ValidationContext::active(1),
    ] {
        if let Ok(frame) = decode_frame(data, ctx) {
            // Unknown fields need not survive re-encoding; the decoded value must.
            assert!(decode_frame(&encode_frame(&frame), ctx).unwrap() == frame);
        }
    }
});
