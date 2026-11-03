//! Secure Syntra 1.0 record I/O for embedders, with explicit optional carriers.
//!
//! All supplied carriers use Syntra's integral encryption layer from
//! `syntra_core::secure_channel`. Carrier features select I/O implementations, not
//! whether the Syntra connection is encrypted.
//!
//! # Target and scheduler contract
//!
//! The record driver, policy workers, carriers, and reconnect helper require a
//! native (non-wasm32) target and a running Tokio runtime. Disabling carrier
//! features removes socket dependencies; it does not change the driver's native
//! scheduling and task-ownership contract.
//!
//! On wasm32 this crate compiles with its default features but exposes no driver
//! modules or types. This is not a WebAssembly transport implementation. Browser
//! applications use `syntra-web`'s local driver with `syntra_core::secure_channel` and
//! `syntra-runtime`. The `tcp`, `websocket`, `reconnect`, and `native-enrollment`
//! features are native-only and must be disabled for wasm32 builds.
#![forbid(unsafe_code)]

#[cfg(all(
    target_arch = "wasm32",
    any(
        feature = "tcp",
        feature = "websocket",
        feature = "reconnect",
        feature = "native-enrollment"
    )
))]
compile_error!(
    "syntra-transport features tcp, websocket, reconnect, and native-enrollment require a non-wasm32 target; disable these features for wasm32 and use syntra-web's browser-local driver"
);

#[cfg(all(feature = "reconnect", not(target_arch = "wasm32")))]
pub mod client;
#[cfg(all(feature = "native-enrollment", not(target_arch = "wasm32")))]
pub mod enrollment;
#[cfg(not(target_arch = "wasm32"))]
pub mod pump;
#[cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
pub mod websocket;

#[cfg(all(feature = "tcp", not(target_arch = "wasm32")))]
pub mod tcp;

#[cfg(all(
    any(feature = "tcp", feature = "websocket"),
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
