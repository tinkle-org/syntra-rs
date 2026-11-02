//! `syntra-core`: transport-independent Syntra v1 protocol mechanics.
//!
//! This crate owns envelope codec, validation (`SNTR-WIRE-*`,
//! `SNTR-SER-*`), version negotiation, the six-state connection machine
//! (`SNTR-HS-001`), request-id allocation, the bounded pending-RPC table,
//! method-shape validation, and typed errors. It never touches the
//! network and never interprets application payloads.
//!
//! Wire sources: committed prost output of `proto/syntra/v1/*.proto`
//! (see `buf.gen.yaml`; pins in upstream [schema generation]).
//! Generated types are data structures only; all behavior here is
//! implemented against the upstream [specifications].
//!
//! Open questions this crate does NOT invent bindings for (see
//! [session open questions] and [auth/session lifecycle RFC]):
//! typed pre-`ACTIVE` error carrier (B1), pre-`ACTIVE` notification conflict
//! (B2). Accepted RFC 0004 D1 forbids connection-local request-ID reuse;
//! RFC 0005 D2/D3 fixes byte bounds; RFC 0008 D1 fixes raw-wire validation.
//! Where a conflict exists the enforced rule is documented on the item.
//!
//! [schema generation]: https://github.com/tinkle-org/syntra/blob/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/specifications/schema/generation.md
//! [specifications]: https://github.com/tinkle-org/syntra/tree/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/specifications
//! [session open questions]: https://github.com/tinkle-org/syntra/blob/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/SESSION-OPEN-QUESTIONS.md
//! [auth/session lifecycle RFC]: https://github.com/tinkle-org/syntra/blob/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/rfcs/0002-auth-session-lifecycle.md

/// Committed prost output (see `buf.gen.yaml`). Do not hand-edit; this
/// file is byte-pinned to a pinned `buf generate` run (drift-checked).
/// It is pulled in via `include!` (rather than `#[path] mod`) so stable
/// `rustfmt` leaves the pinned bytes untouched.
pub mod proto {
    include!("generated/syntra.v1.rs");
}

pub mod codec;
pub mod error;
pub mod frame;
pub mod handshake;
pub mod reliable;
pub mod rpc;
pub mod state;

pub use codec::{decode_frame, encode_frame, MAX_FRAME_BYTES};
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
