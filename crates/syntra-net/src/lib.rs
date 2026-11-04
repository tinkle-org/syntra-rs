//! Native Syntra networking, protected connections and managed client/server lifecycle.
//!
//! All supplied carriers use Syntra's integral encryption layer from
//! `syntra_core::secure_channel`. Carrier features select I/O implementations, not
//! whether the Syntra connection is encrypted.
//! The opt-in `http` module implements the RFC0013 HTTP/HTTPS candidate with
//! protected connections. It does not activate the upstream carrier registry.
//!
//! # Target and scheduler contract
//!
//! The `managed` feature provides a library-owned Tokio worker pool. Lower-level
//! record, carrier and reconnect APIs require a running native Tokio runtime.
//! Carrier features select networking dependencies independently of scheduling.
//!
//! On wasm32 this crate compiles with its default features but exposes no driver
//! modules or types. Portable WASM embedders compose `syntra_core::secure_channel`
//! and `syntra-runtime` with platform I/O. All explicit features are native-only.
#![forbid(unsafe_code)]

#[cfg(all(
    target_arch = "wasm32",
    any(
        feature = "tcp",
        feature = "cross-carrier-candidate",
        feature = "http",
        feature = "websocket",
        feature = "tls-rustls",
        feature = "reconnect",
        feature = "managed",
        feature = "proxy",
        feature = "native-enrollment"
    )
))]
compile_error!(
    "syntra-net features tcp, cross-carrier-candidate, http, websocket, tls-rustls, reconnect, managed, proxy, and native-enrollment require a non-wasm32 target; disable these features for wasm32 and compose syntra-core and syntra-runtime with platform I/O"
);

#[cfg(all(feature = "reconnect", not(target_arch = "wasm32")))]
pub mod client;
#[cfg(all(feature = "native-enrollment", not(target_arch = "wasm32")))]
pub mod enrollment;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub mod http;
#[cfg(all(feature = "managed", not(target_arch = "wasm32")))]
pub mod network;
#[cfg(all(feature = "proxy", not(target_arch = "wasm32")))]
pub mod proxy;
#[cfg(not(target_arch = "wasm32"))]
pub mod pump;
#[cfg(all(feature = "tcp", not(target_arch = "wasm32")))]
pub mod routes;
#[cfg(all(
    any(feature = "websocket", feature = "http"),
    not(target_arch = "wasm32")
))]
pub mod tls;
#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
pub mod websocket;

#[cfg(all(feature = "tcp", not(target_arch = "wasm32")))]
pub mod tcp;

#[cfg(all(
    any(feature = "tcp", feature = "websocket", feature = "http"),
    not(target_arch = "wasm32")
))]
mod stream;

#[cfg(all(feature = "reconnect", not(target_arch = "wasm32")))]
pub use client::{
    CallError, CoreReady, Failure, GenerationValue, LifecycleStatus, Notification, ReconnectConfig,
    ReconnectingClient,
};
#[cfg(not(target_arch = "wasm32"))]
pub use pump::{
    AuthenticatorFactory, ClientHandle, ConnectionAuthorization, Error, EstablishmentBudget,
    HostHandle, Limits, PolicyJobs, RecordReader, RecordWriter, RecoveryAuthenticatorFactory,
    TransportShutdown,
};
