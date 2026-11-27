//! Envelope semantics, shared by inbound decoding, direct runtime admission and emission.

use crate::error::{ErrorCode, SyntraError};
use crate::state::ConnectionState;
use crate::wire::{call_result::Outcome, frame::Body, Frame};

pub use crate::codec::{decode_frame, missing_result_outcome_id, validate_wire_structure};

/// Maximum serialized envelope, independent of transport record size.
pub const MAX_FRAME_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Hello,
    Ready,
    Call,
    Result,
    Cancel,
    Notification,
}

#[derive(Debug, Clone, Copy)]
pub struct ValidationContext {
    pub state: ConnectionState,
    pub negotiated_version: Option<u32>,
}

impl ValidationContext {
    pub fn pre_handshake(state: ConnectionState) -> Self {
        Self {
            state,
            negotiated_version: None,
        }
    }
    pub fn active(version: u32) -> Self {
        Self {
            state: ConnectionState::Active,
            negotiated_version: Some(version),
        }
    }
}

pub(crate) fn violation(code: ErrorCode, message: &'static str) -> SyntraError {
    SyntraError::Protocol {
        code,
        message: message.into(),
    }
}

/// Checks size/choice, version, ID, state and finally per-body semantics in order.
pub fn validate_frame(frame: &Frame, ctx: ValidationContext) -> Result<FrameKind, SyntraError> {
    use ErrorCode::{FailedPrecondition, InvalidArgument, ResourceExhausted};
    if frame.encoded_len() > MAX_FRAME_BYTES {
        return Err(violation(
            ResourceExhausted,
            "frame exceeds maximum envelope size",
        ));
    }
    let body = frame
        .body
        .as_ref()
        .ok_or_else(|| violation(InvalidArgument, "frame body must be set"))?;
    let kind = match body {
        Body::Hello(_) => FrameKind::Hello,
        Body::Ready(_) => FrameKind::Ready,
        Body::Call(_) => FrameKind::Call,
        Body::Result(_) => FrameKind::Result,
        Body::Cancel(_) => FrameKind::Cancel,
        Body::Notification(_) => FrameKind::Notification,
    };

    if ctx.state == ConnectionState::Active && ctx.negotiated_version.is_none() {
        return Err(violation(
            FailedPrecondition,
            "no negotiated version in ACTIVE",
        ));
    }
    if frame.version == 0 {
        return Err(violation(InvalidArgument, "frame version must be nonzero"));
    }
    if ctx.negotiated_version.is_some_and(|v| frame.version != v) {
        let code = if ctx.state == ConnectionState::Active {
            FailedPrecondition
        } else {
            InvalidArgument
        };
        return Err(violation(code, "frame version mismatch"));
    }
    let correlated = matches!(
        kind,
        FrameKind::Call | FrameKind::Result | FrameKind::Cancel
    );
    if correlated && frame.request_id == 0 {
        return Err(violation(
            InvalidArgument,
            "call/result/cancel must use nonzero request_id",
        ));
    }
    if !correlated && frame.request_id != 0 {
        return Err(violation(
            InvalidArgument,
            "hello/ready/notification must use request_id 0",
        ));
    }
    let handshake = matches!(kind, FrameKind::Hello | FrameKind::Ready);
    let state_error = match ctx.state {
        ConnectionState::Connected if kind != FrameKind::Hello => {
            Some("only hello is legal in CONNECTED")
        }
        ConnectionState::Negotiating | ConnectionState::Authenticating if !handshake => {
            Some("application frames forbidden before ACTIVE")
        }
        ConnectionState::Active if handshake => Some("hello/ready forbidden in ACTIVE"),
        ConnectionState::Closing
            if !matches!(
                kind,
                FrameKind::Result | FrameKind::Cancel | FrameKind::Notification
            ) =>
        {
            Some("only result/cancel/notification legal in CLOSING")
        }
        ConnectionState::Closed => Some("no frames legal in CLOSED"),
        _ => None,
    };
    if let Some(message) = state_error {
        return Err(violation(FailedPrecondition, message));
    }
    match body {
        Body::Hello(h) => {
            crate::handshake::validate_hello_range(h.min_version, h.max_version)?;
            if h.credential.len() > crate::MAX_CREDENTIAL_BYTES {
                return Err(violation(
                    ResourceExhausted,
                    "hello credential exceeds bound",
                ));
            }
        }
        Body::Ready(r) => crate::validate_connection_id(&r.connection_id)?,
        Body::Call(c) => crate::validate_method(&c.method)?,
        Body::Result(r) => match &r.outcome {
            None => return Err(violation(InvalidArgument, "result outcome must be set")),
            Some(Outcome::Error(e)) if e.code == 0 => {
                return Err(violation(InvalidArgument, "error code must be nonzero"))
            }
            Some(Outcome::Error(e)) if e.message.len() > crate::MAX_DIAGNOSTIC_BYTES => {
                return Err(violation(
                    InvalidArgument,
                    "error message exceeds diagnostic bound",
                ))
            }
            _ => {}
        },
        Body::Cancel(_) | Body::Notification(_) => {}
    }
    Ok(kind)
}
