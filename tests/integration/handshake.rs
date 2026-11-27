//! Neutral handshake fixtures (byte-level vectors + version cases).
//!
//! Drives handshake.md conformance: success, version mismatch
//! (low/high/disjoint), malformed ranges, unexpected pre-ACTIVE frames,
//! second `hello`, and `connection_id`-as-credential rejection. Expected
//! outcomes are codes + transitions, never message text.

use syntra_core::{
    encode_frame, wire::frame::Body, ClientHello, ConnectionState, Frame, ServerReady,
    ValidationContext,
};

/// Encode a `hello` envelope (first Syntra unit on the transport).
pub fn hello_bytes(min_version: u32, max_version: u32, credential: Vec<u8>) -> Vec<u8> {
    if syntra_core::validate_hello_range(min_version, max_version).is_err() {
        // Start with a real envelope so only the peer's advertised range is bad.
        let mut bytes = hello_bytes(1, 1, credential);
        // Fixed header, Hello union, then message fields 1 and 2 (both LE u32).
        assert_eq!((bytes[16], bytes[21], bytes[26]), (10, 1, 2));
        bytes[..4].copy_from_slice(&max_version.to_le_bytes());
        bytes[22..26].copy_from_slice(&min_version.to_le_bytes());
        bytes[27..31].copy_from_slice(&max_version.to_le_bytes());
        return bytes;
    }
    encode_frame(
        &Frame {
            version: max_version,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version,
                max_version,
                credential,
            })),
        },
        ValidationContext::pre_handshake(ConnectionState::Connected),
    )
    .unwrap()
}

/// Encode a `ready` envelope as a host would send it.
pub fn ready_bytes(version: u32, connection_id: &str) -> Vec<u8> {
    encode_frame(
        &Frame {
            version,
            request_id: 0,
            body: Some(Body::Ready(ServerReady {
                connection_id: connection_id.to_string(),
            })),
        },
        ValidationContext::pre_handshake(ConnectionState::Negotiating),
    )
    .unwrap()
}

/// Version-range cases: (min, max) with no overlap against host [1, 1].
pub fn disjoint_ranges() -> Vec<(u32, u32)> {
    vec![(2, 3), (5, 5)]
}

/// Malformed ranges (shape failures, before any negotiation).
pub fn malformed_ranges() -> Vec<(u32, u32)> {
    vec![(0, 1), (1, 0), (2, 1)]
}
