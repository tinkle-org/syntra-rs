//! Native C ABI surface: test fixture plus production frame-pump.
//!
//! Default builds export no Syntra C ABI symbols.
//! - `test-fixture`: legacy blocking loopback ABI for native tests only.
//!   `syntra_open` always creates an in-process echo/get-put fixture.
//! - `production`: transport-agnostic initiator/responder cores. The
//!   embedding application owns transport bytes, authentication policy,
//!   authorization policy, method dispatch, persistence, and recovery.
//!
//! All WASM targets are rejected at compile time. The production ABI is
//! native-only; no browser ABI is defined here.
//!
//! Native test commands:
//! `cargo test -p syntra-ffi --features test-fixture`.
//! `cargo test -p syntra-ffi --features production`.
//! Headers: `include/syntra.h` (fixture), `include/syntra_production.h`
//! (production). Checks:
//! `python3 crates/syntra-ffi/tests/build_contract.py`.
//!
//! Authentication, authorization, method schemas, domain behavior, replay
//! storage, presence, and durable data remain host-owned. Externally
//! reachable production traffic requires TLS.
//!
//! # Caller obligations (fixture only)
//! All non-null pointers must be valid, aligned, and live for the call; input
//! strings must be NUL-terminated; byte buffers must cover their stated
//! lengths. Outputs must be writable and must not overlap one another or any
//! input. Owned return buffers must be freed exactly once with the matching
//! free function and their original length. Unwinding-panic containment does
//! not make invalid pointers, allocation failure, or panic=abort safe.
//! Blocking functions must not be called from a Tokio asynchronous execution
//! context.

#[cfg(target_family = "wasm")]
compile_error!("syntra-ffi does not support WASM: native ABIs only; no browser ABI is available");

#[cfg(all(feature = "test-fixture", not(target_family = "wasm")))]
mod fixture;

#[cfg(all(feature = "test-fixture", not(target_family = "wasm")))]
pub use fixture::*;

#[cfg(all(feature = "production", not(target_family = "wasm")))]
mod production;

#[cfg(all(feature = "production", not(target_family = "wasm")))]
mod reliable;

#[cfg(all(feature = "production", not(target_family = "wasm")))]
pub use production::*;

#[cfg(all(feature = "production", not(target_family = "wasm")))]
pub use reliable::*;
