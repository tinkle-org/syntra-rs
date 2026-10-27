//! `syntra-ws`: WSS/WS transport adapters for Syntra v1.
//!
//! Profiles: `SNTR-WS-V1` (plaintext, restricted-development only:
//! loopback or isolated test networks, never public traffic) and
//! `SNTR-WSS-H1-V1` (TLS 1.3 over HTTP/1.1 Upgrade, production-capable).
//!
//! Mapping (normative): exactly one complete binary WebSocket message
//! (opcode 0x2, reassembled across fragments) contains exactly one
//! serialized Syntra `Frame`. No TCP length prefix inside WS messages.
//! Binary only; text (0x1) is rejected (close 1003). Empty binary is
//! rejected (`INVALID_ARGUMENT`). Assembled messages exceeding
//! 1 MiB are rejected during assembly (close 1009) on native. Browsers
//! reject only after browser-managed assembly and cannot send 1009 from
//! application code; see the `wasm` module for the conformance limitations.
//! Control frames
//! (Ping/Pong/Close) never reach the Syntra core.
//!
//! Credentials travel only in `ClientHello.credential`, never in URLs,
//! headers, or query strings. No `Authorization` header is ever set
//! (browsers forbid it; native code has no need for it).

pub mod config;
pub mod error;

#[cfg(not(target_arch = "wasm32"))]
pub mod native;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use config::{Endpoint, WsConfig};
pub use error::TransportError;

#[cfg(not(target_arch = "wasm32"))]
pub use native::{connect, WsHandle};

#[cfg(target_arch = "wasm32")]
pub use wasm::{connect, WsHandle};

/// WebSocket subprotocol token (WS section 1C, WSS section 1C).
pub const SUBPROTOCOL: &str = "syntra.v1";
/// Canonical endpoint path (WS section 1B).
pub const ENDPOINT_PATH: &str = "/syntra/v1/ws";
