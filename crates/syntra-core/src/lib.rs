//! `syntra-core`: transport-independent Syntra v1 protocol mechanics.
//!
//! This crate owns envelope codec, validation (`SNTR-WIRE-*`,
//! `SNTR-SER-*`), version negotiation, the six-state connection machine
//! (`SNTR-HS-001`), request-id allocation, the bounded pending-RPC table,
//! method-shape validation, typed errors, and the integral Syntra 1.0 encryption
//! kernel in [`secure_channel`]. The kernel owns authenticated context, Noise
//! establishment, ordered record protection and bounded frame-stream assembly.
//! This crate never touches the network or interprets application payloads;
//! scheduling, host policy and carrier I/O belong to its callers.
//!
//! [`proto`] contains the generated messages from `proto/syntra/v1/*.proto`.
//! Use [`encode_frame`] and [`decode_frame`] at the envelope boundary: generated
//! messages alone do not enforce wire or connection rules. See the [contributor
//! guide] for generation and the [connection guide] for encryption and embedding.
//!
//! Pre-`ACTIVE` failures expose local typed errors and close the connection
//! without an error envelope; application frames, including notifications,
//! are forbidden before `ACTIVE`. Request IDs are never reused within a
//! connection; byte bounds and raw-wire validation apply on decode and emission.
//! The enforced rules are documented on each item.
//!
//! [contributor guide]: https://github.com/tinkle-org/syntra-rs/blob/main/CONTRIBUTING.md#schema-and-generated-code
//! [connection guide]: https://github.com/tinkle-org/syntra-rs/blob/main/CONNECTION.md

/// Committed prost bindings; regenerate via `scripts/check-generated.py --write`
/// so that `ClientHello` uses its credential-safe `Debug` implementation.
pub mod proto {
    include!("generated/syntra.v1.rs");
}

pub mod codec;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod reliable;
pub mod rpc;
pub mod secure_channel;
pub mod state;

pub use codec::{decode_frame, decode_frame_structure, encode_frame, MAX_FRAME_BYTES};
pub use error::{bounded_diagnostic, ErrorCode, RpcError, SyntraError, MAX_DIAGNOSTIC_BYTES};
pub use frame::{
    missing_result_outcome_id, validate_frame, validate_wire_structure, FrameKind,
    ValidationContext, MAX_DECODE_DEPTH,
};
pub use handshake::{
    build_hello, negotiate_version, validate_connection_id, validate_hello_range,
    HANDSHAKE_TIMEOUT_DEFAULT, MAX_CONNECTION_ID_BYTES, MAX_CREDENTIAL_BYTES, MAX_VERSION,
    MIN_VERSION,
};
pub use proto::{Cancel, ClientHello, Frame, Notification, RpcRequest, RpcResult, ServerReady};
pub use rpc::{validate_method, PendingOutcome, PendingTable, RequestIdAllocator};
pub use state::{ConnectionState, StateEvent};
