use syntra_core::proto::{frame::Body, Frame, RpcRequest};
use syntra_core::{decode_frame, encode_frame, ValidationContext};

pub const ROUNDTRIP_SIZES: [usize; 2] = [0, 1_048_320];

pub fn request_frame(payload_len: usize) -> Frame {
    Frame {
        version: 1,
        request_id: 7,
        body: Some(Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![0xAB; payload_len],
            timeout_ms: 5000,
        })),
    }
}

pub fn roundtrip(bytes: &[u8], ctx: ValidationContext) -> Vec<u8> {
    encode_frame(&decode_frame(bytes, ctx).unwrap(), ctx).unwrap()
}
