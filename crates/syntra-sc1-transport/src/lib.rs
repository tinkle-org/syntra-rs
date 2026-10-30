//! Experimental SC1/WSS implementation of the accepted upstream profile `SNTR-SC1-WSS-V1`
//! (RFC 0007 §11; accepted 2026-10-29). Experimental and unpublished: registration is
//! not execution, and no `CONF` verdict is claimed here.
//! Baseline `syntra-ws` retains its separate Frame-per-message wire contract.
#![forbid(unsafe_code)]

pub mod client;
pub mod pump;
pub mod websocket;

#[cfg(feature = "development-carriers")]
pub mod tcp;

pub use client::{
    CallError, CoreReady, Failure, GenerationValue, LifecycleStatus, Notification, ReconnectConfig,
    ReconnectingClient,
};
pub use pump::{AuthenticatorFactory, ClientHandle, Error, HostHandle, Limits};
