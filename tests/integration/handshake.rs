//! Neutral handshake fixtures (byte-level vectors + version cases).
//!
//! Drives handshake.md conformance: success, version mismatch
//! (low/high/disjoint), malformed ranges, unexpected pre-ACTIVE frames,
//! second `hello`, and `connection_id`-as-credential rejection. Expected
//! outcomes are codes + transitions, never message text.

use syntra_core::proto::{frame::Body, ClientHello, Frame, ServerReady};

/// Encode a `hello` envelope (first Syntra unit on the transport).
pub fn hello_bytes(min_version: u32, max_version: u32, credential: Vec<u8>) -> Vec<u8> {
    use prost::Message;
    Frame {
        version: max_version,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version,
            max_version,
            credential: credential.into(),
        })),
    }
    .encode_to_vec()
}

/// Encode a `ready` envelope as a host would send it.
pub fn ready_bytes(version: u32, connection_id: &str) -> Vec<u8> {
    use prost::Message;
    Frame {
        version,
        request_id: 0,
        body: Some(Body::Ready(ServerReady {
            connection_id: connection_id.to_string(),
        })),
    }
    .encode_to_vec()
}

/// Version-range cases: (min, max) with no overlap against host [1, 1].
pub fn disjoint_ranges() -> Vec<(u32, u32)> {
    vec![(2, 3), (5, 5)]
}

/// Malformed ranges (shape failures, before any negotiation).
pub fn malformed_ranges() -> Vec<(u32, u32)> {
    vec![(0, 1), (1, 0), (2, 1)]
}
