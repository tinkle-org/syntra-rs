//! Experimental SC1/WSS implementation of the pinned RFC 0007 §11 proposal.
//! No accepted upstream profile, production authorization or independent audit.
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
