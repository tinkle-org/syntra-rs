//! Frame codec + envelope validation (`SNTR-WIRE-*`, `SNTR-SER-*`).
//!
//! Every Syntra unit on every transport is exactly one serialized
//! `Frame`. Producers set exactly one `body` variant; validators enforce
//! `request_id` discipline, version checks, size bounds, and
//! variant-state legality before any dispatch. First failure determines
//! the error.
//!
//! Hardening (SNTR-SER-006/007/008, SNTR-WIRE-002/004):
//! - unknown wire fields are tolerated per SNTR-SER-003, EXCEPT reserved
//!   top-level numbers 16/17, which are rejected. Numbers 16/17 inside
//!   nested messages are unassigned and tolerated;
//! - body space is 10..31: known 10..15, reserved 16/17, future 18..31;
//!   metadata never supplies a missing body;
//! - duplicate `body` alternatives on the wire (two `oneof` members, or
//!   the same member twice — prost would collapse them) are rejected;
//!   duplicate `version`/`request_id` scalars follow protobuf merge
//!   semantics (last wins) and are not rejected;
//! - the complete structural walk precedes reserved/multiplicity/future
//!   classification, including every known field occurrence and unknown groups;
//! - nesting depth is bounded (known messages and unknown groups) with a
//!   hard cap of 32, and no single length prefix may exceed the envelope
//!   bound, before prost decodes anything;
//! - credential/connection-ID/diagnostic byte caps are admission bounds on
//!   every raw occurrence, checked after structural and raw-choice validation
//!   but before generated decoding. Even a subsequently overwritten value is
//!   consumed by prost and must fit its field's allocation budget. In-bound
//!   ordinary singular duplicates still retain protobuf last-value semantics.

use prost::Message;

use crate::error::{ErrorCode, SyntraError};
use crate::proto::frame::Body;
use crate::proto::Frame;
use crate::state::ConnectionState;

/// Default maximum serialized `Frame` bytes (SNTR-WIRE-006).
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// Hard cap on nesting below the root (SNTR-SER-006), including unknown
/// protobuf groups. Known v1 messages nest as `Frame` -> `RpcResult` -> `RpcError`.
pub const MAX_DECODE_DEPTH: u32 = 32;

/// What a validated frame contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Hello,
    Ready,
    Request,
    Result,
    Cancel,
    Notification,
}

/// Context for validation: current state + negotiated version.
#[derive(Debug, Clone, Copy)]
pub struct ValidationContext {
    /// Current connection state.
    pub state: ConnectionState,
    /// Selected version once handshake completed; None before ACTIVE.
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

/// Encode a `Frame` to protobuf bytes.
pub fn encode_frame(frame: &Frame) -> Vec<u8> {
    frame.encode_to_vec()
}

/// Shared bounded structural walk, before any raw-choice classification or
/// generated decoding. Also used by the narrow missing-outcome correlator.
fn structural_scan(bytes: &[u8]) -> Result<ScanStats, SyntraError> {
    if bytes.is_empty() {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "empty frame bytes".to_string(),
        });
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(SyntraError::Protocol {
            code: ErrorCode::ResourceExhausted,
            message: "frame exceeds maximum envelope size".to_string(),
        });
    }
    let mut scan = ScanStats::default();
    walk(bytes, &mut 0, Schema::Frame, 0, None, &mut scan)?;
    Ok(scan)
}

/// Shared strict prelude for decoding and raw-wire validation.
fn pre_scan(bytes: &[u8]) -> Result<(), SyntraError> {
    let scan = structural_scan(bytes)?;
    // No semantic classification may short-circuit the complete structural walk.
    scan.validate_body()?;
    if let Some(outcome) = &scan.outcome {
        outcome.validate("result outcome")?;
    }
    scan.validate_field_bounds()
}

/// Decode + validate a received `Frame`.
///
/// Steps in order (SNTR-WIRE-005): (1) well-formedness + size/depth,
/// (2) version, (3) `request_id` discipline, (4) variant-state legality,
/// (5) per-variant semantics. First failure determines the error;
/// validation completes before dispatch.
pub fn decode_frame(bytes: &[u8], ctx: ValidationContext) -> Result<Frame, SyntraError> {
    pre_scan(bytes)?;
    let frame = Frame::decode(bytes).map_err(|_| SyntraError::Protocol {
        code: ErrorCode::InvalidArgument,
        message: "malformed protobuf frame".to_string(),
    })?;
    validate_frame(&frame, ctx)?;
    Ok(frame)
}

/// Validate an already-decoded `Frame` (also used before sending).
pub fn validate_frame(frame: &Frame, ctx: ValidationContext) -> Result<FrameKind, SyntraError> {
    // Size is validation step 1 for every body and every entry point,
    // including already-decoded frames passed directly to the runtime.
    if frame.encoded_len() > MAX_FRAME_BYTES {
        return Err(SyntraError::Protocol {
            code: ErrorCode::ResourceExhausted,
            message: "frame exceeds maximum envelope size".to_string(),
        });
    }
    let body = frame.body.as_ref().ok_or(SyntraError::Protocol {
        code: ErrorCode::InvalidArgument,
        message: "frame body must be set".to_string(),
    })?;

    let kind = match body {
        Body::Hello(_) => FrameKind::Hello,
        Body::Ready(_) => FrameKind::Ready,
        Body::Request(_) => FrameKind::Request,
        Body::Result(_) => FrameKind::Result,
        Body::Cancel(_) => FrameKind::Cancel,
        Body::Notification(_) => FrameKind::Notification,
    };

    // Version check (SNTR-WIRE-005 step 2).
    match ctx.state {
        ConnectionState::Active => {
            let v = ctx.negotiated_version.ok_or(SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: "no negotiated version in ACTIVE".to_string(),
            })?;
            if frame.version != v {
                return Err(SyntraError::Protocol {
                    // Zero is malformed; changing an established version
                    // violates the negotiated connection contract.
                    code: if frame.version == 0 {
                        ErrorCode::InvalidArgument
                    } else {
                        ErrorCode::FailedPrecondition
                    },
                    message: "frame version mismatch".to_string(),
                });
            }
        }
        _ => {
            // Pre-handshake: hello carries proposed max; ready carries
            // selected. Zero is never a negotiated version. In Closing the
            // negotiated version persists, so require an exact match when it
            // is known; otherwise require nonzero.
            if let Some(v) = ctx.negotiated_version {
                if frame.version != v {
                    return Err(SyntraError::Protocol {
                        code: ErrorCode::InvalidArgument,
                        message: "frame version mismatch".to_string(),
                    });
                }
            } else if frame.version == 0 {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "frame version must be nonzero".to_string(),
                });
            }
        }
    }

    // request_id discipline (SNTR-WIRE-003).
    match kind {
        FrameKind::Hello | FrameKind::Ready | FrameKind::Notification => {
            if frame.request_id != 0 {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "hello/ready/notification must use request_id 0".to_string(),
                });
            }
        }
        FrameKind::Request | FrameKind::Result | FrameKind::Cancel => {
            if frame.request_id == 0 {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "request/result/cancel must use nonzero request_id".to_string(),
                });
            }
        }
    }

    // Variant-state legality (SNTR-WIRE-003, SNTR-HS-012).
    match ctx.state {
        ConnectionState::Connected => {
            if kind != FrameKind::Hello {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "only hello is legal in CONNECTED".to_string(),
                });
            }
        }
        ConnectionState::Negotiating | ConnectionState::Authenticating => {
            // Initiator must not send application frames before ACTIVE;
            // second hello / ready-to-host etc. are handshake failures.
            match kind {
                FrameKind::Request
                | FrameKind::Result
                | FrameKind::Cancel
                | FrameKind::Notification => {
                    return Err(SyntraError::Protocol {
                        code: ErrorCode::FailedPrecondition,
                        message: "application frames forbidden before ACTIVE".to_string(),
                    })
                }
                _ => {}
            }
        }
        ConnectionState::Active => match kind {
            FrameKind::Hello | FrameKind::Ready => {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "hello/ready forbidden in ACTIVE".to_string(),
                })
            }
            _ => {}
        },
        ConnectionState::Closing => {
            // Drain existing RPCs while tolerating already-queued events.
            // Notifications never complete an RPC and never require admission;
            // rejecting them here would turn a clean drain into misbehavior.
            if !matches!(
                kind,
                FrameKind::Result | FrameKind::Cancel | FrameKind::Notification
            ) {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "only result/cancel/notification legal in CLOSING".to_string(),
                });
            }
        }
        ConnectionState::Closed => {
            return Err(SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: "no frames legal in CLOSED".to_string(),
            });
        }
    }

    // Per-variant semantics (SNTR-WIRE-005 step 5).
    match body {
        Body::Hello(h) => {
            crate::handshake::validate_hello_range(h.min_version, h.max_version)?;
            if h.credential.len() > crate::handshake::MAX_CREDENTIAL_BYTES {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::ResourceExhausted,
                    message: "hello credential exceeds bound".to_string(),
                });
            }
        }
        Body::Ready(r) => {
            crate::handshake::validate_connection_id(&r.connection_id)?;
        }
        Body::Request(req) => {
            crate::rpc::validate_method(&req.method)?;
        }
        Body::Result(res) => {
            // outcome must be set, including for empty success (SNTR-RPC-006).
            if res.outcome.is_none() {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "result outcome must be set".to_string(),
                });
            }
            if let Some(crate::proto::rpc_result::Outcome::Error(e)) = &res.outcome {
                if e.code == 0 {
                    return Err(SyntraError::Protocol {
                        code: ErrorCode::InvalidArgument,
                        message: "error code must be nonzero".to_string(),
                    });
                }
                if e.message.len() > crate::error::MAX_DIAGNOSTIC_BYTES {
                    return Err(invalid("error message exceeds diagnostic bound"));
                }
            }
        }
        Body::Cancel(_) => {}
        Body::Notification(_) => {
            // Empty payload is valid (SNTR-WIRE-007); no further checks.
        }
    }

    Ok(kind)
}

/// Raw-wire validation, including body/outcome classification and per-occurrence
/// allocation bounds, without version, state or other field-value semantics.
/// No generated decoder allocation is needed.
pub fn validate_wire_structure(bytes: &[u8]) -> Result<(), SyntraError> {
    pre_scan(bytes)
}

/// Recover correlation only for an otherwise legal result with zero raw outcomes.
///
/// This supports local `INVALID_ARGUMENT` completion of an affected pending RPC
/// (CONF-RPC-010), not accepting the frame or emitting an error response. The
/// caller still owns pending-ID lookup and terminal selection. `None` means this
/// specific failure cannot be safely correlated; retain normal decode-error
/// handling. Malformed structure, reserved/duplicate/future bodies, any outcome
/// occurrence, and invalid version/ID/state never yield an ID.
///
/// Uses the same complete bounded walk as [`decode_frame`] before generated
/// decoding. Normal decoding and [`validate_wire_structure`] remain strict.
pub fn missing_result_outcome_id(bytes: &[u8], ctx: ValidationContext) -> Option<u64> {
    let scan = structural_scan(bytes).ok()?;
    scan.validate_body().ok()?;
    if scan.outcome.as_ref()?.count != 0 {
        return None;
    }
    scan.validate_field_bounds().ok()?;
    let mut frame = Frame::decode(bytes).ok()?;
    let Some(Body::Result(result)) = frame.body.as_mut() else {
        return None;
    };
    if result.outcome.is_some() {
        return None;
    }
    // Supply an empty success only to reuse all other envelope validation. This
    // temporary value never escapes; the received frame remains invalid.
    result.outcome = Some(crate::proto::rpc_result::Outcome::Payload(Vec::new()));
    validate_frame(&frame, ctx).ok()?;
    Some(frame.request_id)
}

#[derive(Default)]
struct RawChoice {
    count: u32,
    future: bool,
}

impl RawChoice {
    fn record(&mut self, future: bool) {
        self.count += 1; // At most MAX_FRAME_BYTES field occurrences.
        self.future |= future;
    }

    fn validate(&self, name: &str) -> Result<(), SyntraError> {
        if self.count != 1 {
            return Err(invalid(&format!("{name} must have exactly one occurrence")));
        }
        if self.future {
            return Err(SyntraError::Protocol {
                code: ErrorCode::Unimplemented,
                message: format!("unknown {name} variant"),
            });
        }
        Ok(())
    }
}

#[derive(Default)]
struct ScanStats {
    reserved: bool,
    body: RawChoice,
    // Only relevant after exactly one known Frame body has been established.
    // Multiple result bodies are rejected before this last observation is used.
    outcome: Option<RawChoice>,
    // Deferred so malformed structure and raw-choice failures always win.
    field_bound_violation: Option<FieldBoundViolation>,
}

enum FieldBoundViolation {
    Credential,
    ConnectionId,
    Diagnostic,
}

impl ScanStats {
    fn validate_body(&self) -> Result<(), SyntraError> {
        if self.reserved {
            return Err(invalid("frame uses reserved field number"));
        }
        self.body.validate("frame body")
    }

    fn validate_field_bounds(&self) -> Result<(), SyntraError> {
        match self.field_bound_violation {
            Some(FieldBoundViolation::Credential) => {
                Err(resource("hello credential exceeds bound"))
            }
            Some(FieldBoundViolation::ConnectionId) => Err(invalid("invalid connection_id length")),
            Some(FieldBoundViolation::Diagnostic) => {
                Err(invalid("error message exceeds diagnostic bound"))
            }
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
enum Schema {
    Frame,
    Hello,
    Ready,
    Request,
    RpcResult,
    RpcError,
    Cancel,
    Notification,
    UnknownGroup,
}

#[derive(Clone, Copy)]
enum FieldType {
    Scalar,
    Bytes,
    String,
    Message(Schema),
}

impl Schema {
    fn field_type(self, field: u32) -> Option<FieldType> {
        use FieldType::{Bytes, Message, Scalar, String};
        match (self, field) {
            (Self::Frame, 1 | 2) | (Self::Hello, 1 | 2) => Some(Scalar),
            (Self::Frame, 10) => Some(Message(Self::Hello)),
            (Self::Frame, 11) => Some(Message(Self::Ready)),
            (Self::Frame, 12) => Some(Message(Self::Request)),
            (Self::Frame, 13) => Some(Message(Self::RpcResult)),
            (Self::Frame, 14) => Some(Message(Self::Cancel)),
            (Self::Frame, 15) => Some(Message(Self::Notification)),
            (Self::Frame, 18..=31) | (Self::RpcResult, 3..=15) => Some(Bytes),
            (Self::Hello, 3)
            | (Self::Request, 2)
            | (Self::RpcResult, 1)
            | (Self::Notification, 1) => Some(Bytes),
            (Self::Ready, 1) | (Self::Request, 1) | (Self::RpcError, 2) => Some(String),
            (Self::Request, 3) | (Self::RpcError, 1) => Some(Scalar),
            (Self::RpcResult, 2) => Some(Message(Self::RpcError)),
            _ => None,
        }
    }
}

/// Allocation-free structural walk. Unknown LEN values and opaque bytes are
/// skipped, not interpreted; lawful unknown groups have matching end tags and
/// consume the same depth budget as embedded known messages. Root depth is zero.
fn walk(
    bytes: &[u8],
    i: &mut usize,
    schema: Schema,
    depth: u32,
    end_group: Option<u32>,
    scan: &mut ScanStats,
) -> Result<(), SyntraError> {
    if depth > MAX_DECODE_DEPTH {
        return Err(resource("frame nesting exceeds depth bound"));
    }
    let mut outcome = RawChoice::default();
    while *i < bytes.len() {
        let tag = read_varint(bytes, i)?;
        let number = tag >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return Err(invalid("invalid protobuf field number"));
        }
        let field = number as u32;
        let wire = (tag & 7) as u8;
        let field_type = schema.field_type(field);
        if let Some(ty) = field_type {
            let expected = if matches!(ty, FieldType::Scalar) {
                0
            } else {
                2
            };
            if wire != expected {
                return Err(invalid("wrong wire type for core field"));
            }
        }
        if wire == 4 {
            return if end_group == Some(field) {
                Ok(())
            } else {
                Err(invalid("unexpected protobuf end group"))
            };
        }
        match schema {
            Schema::Frame => {
                if matches!(field, 16 | 17) {
                    scan.reserved = true;
                }
                if (10..=31).contains(&field) {
                    scan.body.record(field >= 18);
                }
            }
            Schema::RpcResult if field <= 15 => outcome.record(field >= 3),
            _ => {}
        }
        match wire {
            0 => {
                read_varint(bytes, i)?;
            }
            1 => advance(bytes, i, 8)?,
            2 => {
                let len = read_varint(bytes, i)?;
                if len > MAX_FRAME_BYTES as u64 {
                    return Err(resource("frame field exceeds allocation bound"));
                }
                let start = *i;
                advance(bytes, i, len as usize)?;
                let value = &bytes[start..*i];
                match field_type {
                    Some(FieldType::Message(nested)) => {
                        walk(value, &mut 0, nested, depth + 1, None, scan)?;
                    }
                    Some(FieldType::String) => {
                        std::str::from_utf8(value)
                            .map_err(|_| invalid("invalid UTF-8 in core string"))?;
                    }
                    _ => {}
                }
                // Do not reject early: later structural failures (including
                // invalid UTF-8 in any occurrence) precede field admission.
                // Unknown/opaque content is never interpreted as a submessage.
                let violation = match (schema, field) {
                    (Schema::Hello, 3) if len > crate::handshake::MAX_CREDENTIAL_BYTES as u64 => {
                        Some(FieldBoundViolation::Credential)
                    }
                    (Schema::Ready, 1)
                        if len > crate::handshake::MAX_CONNECTION_ID_BYTES as u64 =>
                    {
                        Some(FieldBoundViolation::ConnectionId)
                    }
                    (Schema::RpcError, 2) if len > crate::error::MAX_DIAGNOSTIC_BYTES as u64 => {
                        Some(FieldBoundViolation::Diagnostic)
                    }
                    _ => None,
                };
                if scan.field_bound_violation.is_none() {
                    scan.field_bound_violation = violation;
                }
            }
            3 => walk(bytes, i, Schema::UnknownGroup, depth + 1, Some(field), scan)?,
            5 => advance(bytes, i, 4)?,
            _ => return Err(invalid("illegal protobuf wire type")),
        }
    }
    if end_group.is_some() {
        return Err(invalid("unterminated protobuf group"));
    }
    if matches!(schema, Schema::RpcResult) {
        scan.outcome = Some(outcome);
    }
    Ok(())
}

fn advance(bytes: &[u8], i: &mut usize, width: usize) -> Result<(), SyntraError> {
    if width > bytes.len() - *i {
        return Err(invalid("truncated protobuf field"));
    }
    *i += width;
    Ok(())
}

fn read_varint(bytes: &[u8], i: &mut usize) -> Result<u64, SyntraError> {
    let mut value = 0u64;
    for n in 0..10 {
        let b = *bytes.get(*i).ok_or_else(|| invalid("truncated varint"))?;
        *i += 1;
        // At most one payload bit in byte ten. This also rejects continuation
        // there, but permits valid non-minimal encodings within ten bytes.
        if n == 9 && b > 1 {
            return Err(invalid("overflowing protobuf varint"));
        }
        value |= u64::from(b & 0x7f) << (7 * n);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("overlong protobuf varint"))
}

fn invalid(message: &str) -> SyntraError {
    SyntraError::Protocol {
        code: ErrorCode::InvalidArgument,
        message: message.into(),
    }
}

fn resource(message: &str) -> SyntraError {
    SyntraError::Protocol {
        code: ErrorCode::ResourceExhausted,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::*;

    fn ctx_active() -> ValidationContext {
        ValidationContext::active(1)
    }

    #[test]
    fn rejects_empty_body() {
        let f = Frame {
            version: 1,
            request_id: 4,
            body: None,
        };
        assert!(validate_frame(&f, ctx_active()).is_err());
    }

    #[test]
    fn wire_structure_rejects_bodyless_input_like_decode() {
        // version=1 with no body: structurally incomplete.
        let raw = [0x08u8, 0x01];
        assert!(validate_wire_structure(&raw).is_err());
        assert!(decode_frame(&raw, ctx_active()).is_err());
    }

    #[test]
    fn wire_structure_rejects_malformed_nested_body_like_decode() {
        // version=1 plus a request body (field 12) whose nested bytes are
        // protobuf garbage: the bounded structural walk rejects it.
        let mut raw = vec![0x08u8, 0x01, 0x62, 0x0A];
        raw.extend([0xFFu8; 10]);
        assert!(validate_wire_structure(&raw).is_err());
        assert!(decode_frame(&raw, ctx_active()).is_err());
    }

    #[test]
    fn wire_structure_matches_decode_on_metadata_only_envelope() {
        // Field 90 is metadata, not a future body: body remains absent.
        let raw = [0x08u8, 0x01, 0xD0, 0x05, 0x01];
        let wire_err = validate_wire_structure(&raw).expect_err("unknown-only must fail");
        assert!(matches!(
            wire_err,
            SyntraError::Protocol {
                code: crate::error::ErrorCode::InvalidArgument,
                ..
            }
        ));
        let decode_err = decode_frame(&raw, ctx_active()).expect_err("unknown-only must fail");
        assert!(matches!(
            decode_err,
            SyntraError::Protocol {
                code: crate::error::ErrorCode::InvalidArgument,
                ..
            }
        ));
    }

    #[test]
    fn request_id_discipline() {
        // hello with nonzero id
        let f = Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        };
        assert!(validate_frame(
            &f,
            ValidationContext::pre_handshake(ConnectionState::Connected)
        )
        .is_err());
        // request with zero id
        let f = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![],
                timeout_ms: 500,
            })),
        };
        assert!(validate_frame(&f, ctx_active()).is_err());
    }

    #[test]
    fn result_requires_outcome() {
        let f = Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Result(RpcResult { outcome: None })),
        };
        assert!(validate_frame(&f, ctx_active()).is_err());
    }

    #[test]
    fn empty_payload_round_trip_is_success() {
        let f = Frame {
            version: 1,
            request_id: 8,
            body: Some(Body::Result(RpcResult {
                outcome: Some(crate::proto::rpc_result::Outcome::Payload(vec![])),
            })),
        };
        assert!(validate_frame(&f, ctx_active()).is_ok());
    }
}
