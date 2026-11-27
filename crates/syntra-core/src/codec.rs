//! Bounded Bebop v3 frame codec. The generated reader borrows the input;
//! only admitted fields are copied into caller-owned domain values.

use crate::frame::{violation, ValidationContext};
use crate::generated::{self as g, CallOutcome, FrameBody};
use crate::wire::{call_result::Outcome, frame::Body, *};
use crate::{validate_frame, ErrorCode, SyntraError};
use bebop::{Record, SliceWrapper, SubRecord};

pub use crate::frame::MAX_FRAME_BYTES;

mod preflight;
pub use preflight::{missing_result_outcome_id, validate_wire_structure};

impl Frame {
    fn borrowed(&self) -> g::Frame<'_> {
        fn bytes(v: &[u8]) -> Option<SliceWrapper<'_, u8>> {
            (!v.is_empty()).then(|| SliceWrapper::from_cooked(v))
        }
        let body = match &self.body {
            Some(Body::Hello(h)) => FrameBody::ClientHello {
                min_version: Some(h.min_version),
                max_version: Some(h.max_version),
                credential: bytes(&h.credential),
            },
            Some(Body::Ready(r)) => FrameBody::ServerReady {
                connection_id: Some(&r.connection_id),
            },
            Some(Body::Call(c)) => FrameBody::Call {
                method: Some(&c.method),
                payload: bytes(&c.payload),
                timeout_ms: (c.timeout_ms != 0).then_some(c.timeout_ms),
            },
            Some(Body::Result(r)) => FrameBody::CallResult {
                outcome: match &r.outcome {
                    Some(Outcome::Payload(p)) => CallOutcome::Success {
                        payload: SliceWrapper::from_cooked(p),
                    },
                    Some(Outcome::Error(e)) => CallOutcome::RpcError {
                        code: Some(e.code),
                        diagnostic: (!e.message.is_empty()).then_some(&e.message),
                    },
                    None => CallOutcome::Unknown,
                },
            },
            Some(Body::Cancel(_)) => FrameBody::Cancel {},
            Some(Body::Notification(n)) => FrameBody::Notification {
                payload: bytes(&n.payload),
            },
            None => FrameBody::Unknown,
        };
        g::Frame {
            version: self.version,
            request_id: self.request_id,
            body,
        }
    }

    /// Wire size without serialization, copying payloads or allocating output.
    /// For unset choices the size includes the union header; emission rejects them.
    pub fn encoded_len(&self) -> usize {
        self.borrowed().serialized_size()
    }
}

/// Encode one validated envelope into a newly owned buffer. The size check in
/// `validate_frame` runs before any output allocation or narrowing to a wire u32.
pub fn encode_frame(frame: &Frame, ctx: ValidationContext) -> Result<Vec<u8>, SyntraError> {
    validate_frame(frame, ctx)?;
    let record = frame.borrowed();
    let mut output = vec![0; record.serialized_size()];
    let mut writer = output.as_mut_slice();
    record
        .serialize(&mut writer)
        .map_err(|_| violation(ErrorCode::Internal, "frame encode failed"))?;
    if !writer.is_empty() {
        return Err(violation(ErrorCode::Internal, "frame size mismatch"));
    }
    Ok(output)
}

/// Decode the complete bounded structure, *without* trusting version, method,
/// request ID or connection state. Used for runtime error classification only.
pub fn decode_frame_structure(bytes: &[u8]) -> Result<Frame, SyntraError> {
    validate_wire_structure(bytes)?;
    // Record::deserialize discards the consumed length. Keep the schema reader
    // and the structural admission check in agreement even as the schema evolves.
    let (used, raw) = g::Frame::_deserialize_chained(bytes)
        .map_err(|_| violation(ErrorCode::InvalidArgument, "malformed Bebop frame"))?;
    if used != bytes.len() {
        return Err(violation(ErrorCode::InvalidArgument, "frame size mismatch"));
    }
    let body = match raw.body {
        FrameBody::ClientHello {
            min_version,
            max_version,
            credential,
        } => Body::Hello(ClientHello {
            min_version: min_version.unwrap_or_default(),
            max_version: max_version.unwrap_or_default(),
            credential: credential.map(|b| b.to_vec()).unwrap_or_default(),
        }),
        FrameBody::ServerReady { connection_id } => Body::Ready(ServerReady {
            connection_id: connection_id.unwrap_or_default().into(),
        }),
        FrameBody::Call {
            method,
            payload,
            timeout_ms,
        } => Body::Call(Call {
            method: method.unwrap_or_default().into(),
            payload: payload.map(|b| b.to_vec()).unwrap_or_default(),
            timeout_ms: timeout_ms.unwrap_or_default(),
        }),
        FrameBody::CallResult { outcome } => Body::Result(CallResult {
            outcome: Some(match outcome {
                CallOutcome::Success { payload } => Outcome::Payload(payload.to_vec()),
                CallOutcome::RpcError { code, diagnostic } => Outcome::Error(RpcError {
                    code: code.unwrap_or_default(),
                    message: diagnostic.unwrap_or_default().into(),
                }),
                CallOutcome::Unknown => {
                    return Err(violation(
                        ErrorCode::Unimplemented,
                        "unknown result outcome",
                    ))
                }
            }),
        }),
        FrameBody::Notification { payload } => Body::Notification(Notification {
            payload: payload.map(|b| b.to_vec()).unwrap_or_default(),
        }),
        FrameBody::Cancel {} => Body::Cancel(Cancel {}),
        FrameBody::Unknown => {
            return Err(violation(ErrorCode::Unimplemented, "unknown frame body"))
        }
    };
    Ok(Frame {
        version: raw.version,
        request_id: raw.request_id,
        body: Some(body),
    })
}

/// Decode one complete envelope and validate it before dispatch.
pub fn decode_frame(bytes: &[u8], ctx: ValidationContext) -> Result<Frame, SyntraError> {
    let frame = decode_frame_structure(bytes)?;
    validate_frame(&frame, ctx)?;
    Ok(frame)
}
