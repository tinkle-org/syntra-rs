//! Owned envelope and recovery data for runtime, ABI and application callers.
//!
//! ```
//! use syntra_core::{decode_frame, encode_frame, Call, Frame, ValidationContext};
//! use syntra_core::wire::frame::Body;
//!
//! let ctx = ValidationContext::active(1);
//! let frame = Frame {
//!     version: 1,
//!     request_id: 7,
//!     body: Some(Body::Call(Call {
//!         method: "/example.Echo/Echo".into(),
//!         payload: vec![0xff, 0],
//!         timeout_ms: 250,
//!     })),
//! };
//! let bytes = encode_frame(&frame, ctx)?;
//! assert_eq!(decode_frame(&bytes, ctx)?, frame);
//! # Ok::<(), syntra_core::SyntraError>(())
//! ```
//!
//! `Body::Result(CallResult { outcome: Some(call_result::Outcome::Payload(vec![])) })`
//! represents a successful empty result; an absent outcome is invalid.
//! [`RpcError`] holds the raw i32 code; [`crate::RpcError`] holds the classified
//! application error and retains an unrecognized numeric code for diagnostics.
//!
//! `encode_frame(&frame, ctx)` / `decode_frame(bytes, ctx)` check structure and
//! connection semantics. `decode_frame_structure(bytes)` is for inspecting a
//! structurally valid envelope after semantic rejection, not for dispatch.
//! `Frame::encoded_len()` supports queue accounting without encoding.
//! Recovery's profile codec and policy live in the runtime; the raw generated
//! records are available under `syntra_core::generated` for its adapter.

mod recovery;
pub use crate::ErrorCode;
pub use recovery::*;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    pub version: u32,
    pub request_id: u64,
    pub body: Option<frame::Body>,
}

pub mod frame {
    use super::*;
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Body {
        Hello(ClientHello),
        Ready(ServerReady),
        Call(Call),
        Result(CallResult),
        Cancel(Cancel),
        Notification(Notification),
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub min_version: u32,
    pub max_version: u32,
    pub credential: Vec<u8>,
}

impl std::fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHello")
            .field("min_version", &self.min_version)
            .field("max_version", &self.max_version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerReady {
    pub connection_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Call {
    pub method: String,
    pub payload: Vec<u8>,
    pub timeout_ms: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallResult {
    pub outcome: Option<call_result::Outcome>,
}

pub mod call_result {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Outcome {
        Payload(Vec<u8>),
        Error(super::RpcError),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cancel {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Notification {
    pub payload: Vec<u8>,
}
