//! Neutral handshake fixtures (byte-level vectors + version cases).
//!
//! Drives handshake.md conformance: success, version mismatch
//! (low/high/disjoint), malformed ranges, unexpected pre-ACTIVE frames,
//! second `hello`, and `connection_id`-as-credential rejection. Expected
//! outcomes are codes + transitions, never message text.

use bebop::{Record, SliceWrapper};
use syntra_core::generated::{Frame, FrameBody};

// Test input is serialized without semantic checks; the receiving peer validates it.
fn handshake_frame(version: u32, body: FrameBody<'_>) -> Vec<u8> {
    let mut bytes = Vec::new();
    Frame {
        version,
        request_id: 0,
        body,
    }
    .serialize(&mut bytes)
    .unwrap();
    bytes
}

/// Encode a `hello` envelope (first Syntra unit on the transport).
pub fn hello_bytes(min_version: u32, max_version: u32, credential: Vec<u8>) -> Vec<u8> {
    handshake_frame(
        max_version.max(1), // Even a malformed offer is tested inside a nonzero-version frame.
        FrameBody::ClientHello {
            min_version: Some(min_version),
            max_version: Some(max_version),
            credential: (!credential.is_empty()).then(|| SliceWrapper::from_cooked(&credential)),
        },
    )
}

/// Encode a `ready` envelope as a host would send it.
pub fn ready_bytes(version: u32, connection_id: &str) -> Vec<u8> {
    handshake_frame(
        version,
        FrameBody::ServerReady {
            connection_id: Some(connection_id),
        },
    )
}

/// Version-range cases: (min, max) with no overlap against host [1, 1].
pub fn disjoint_ranges() -> Vec<(u32, u32)> {
    vec![(2, 3), (5, 5)]
}

/// Malformed ranges (shape failures, before any negotiation).
pub fn malformed_ranges() -> Vec<(u32, u32)> {
    vec![(0, 1), (1, 0), (2, 1)]
}
