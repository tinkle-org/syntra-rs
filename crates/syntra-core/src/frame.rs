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
//! - an unset `body` with unknown top-level content is an unknown variant
//!   (`UNIMPLEMENTED`), while an unset `body` with no unknown content is
//!   an empty body (`INVALID_ARGUMENT`);
//! - duplicate `body` alternatives on the wire (two `oneof` members, or
//!   the same member twice — prost would collapse them) are rejected;
//!   duplicate `version`/`request_id` scalars follow protobuf merge
//!   semantics (last wins) and are not rejected;
//! - nesting depth is schema-bounded (known message fields only) with a
//!   hard cap of 32, and no single length prefix may exceed the envelope
//!   bound, before prost decodes anything.

use prost::Message;

use crate::error::{ErrorCode, SyntraError};
use crate::proto::frame::Body;
use crate::proto::Frame;
use crate::state::ConnectionState;

/// Default maximum serialized `Frame` bytes (SNTR-WIRE-006).
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// Hard cap on message nesting depth (SNTR-SER-006). The v1 schema nests
/// at most 3 deep (`Frame` -> `RpcResult` -> `RpcError`); anything deeper
/// can only come from corrupt or hostile input.
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

/// Shared raw-wire prelude: emptiness, envelope size, then the bounded
/// top-level pre-scan. Used by both [`decode_frame`] and
/// [`validate_wire_structure`] so the two entry points cannot drift.
fn pre_scan(bytes: &[u8]) -> Result<ScanStats, SyntraError> {
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
    scan_top_level(bytes)
}

/// Decode + validate a received `Frame`.
///
/// Steps in order (SNTR-WIRE-005): (1) well-formedness + size/depth,
/// (2) version, (3) `request_id` discipline, (4) variant-state legality,
/// (5) per-variant semantics. First failure determines the error;
/// validation completes before dispatch.
pub fn decode_frame(bytes: &[u8], ctx: ValidationContext) -> Result<Frame, SyntraError> {
    // Raw pre-scan (SNTR-SER-006/008, SNTR-WIRE-002/004): reserved
    // numbers, duplicate bodies, unknown-only bodies, and depth/alloc
    // limits are decided here, before prost allocates anything.
    let scan = pre_scan(bytes)?;
    let frame = Frame::decode(bytes).map_err(|_| SyntraError::Protocol {
        code: ErrorCode::InvalidArgument,
        message: "malformed protobuf frame".to_string(),
    })?;
    if frame.body.is_none() {
        if scan.unknown_present {
            // Decoded to no known variant but carried unknown top-level
            // content: a future `oneof` member or unknown masquerading as
            // body (SNTR-WIRE-004). Never silently dropped, never success.
            return Err(SyntraError::Protocol {
                code: ErrorCode::Unimplemented,
                message: "unknown frame variant".to_string(),
            });
        }
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "frame body must be set".to_string(),
        });
    }
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
                    code: ErrorCode::InvalidArgument,
                    message: "frame version mismatch".to_string(),
                });
            }
        }
        _ => {
            // Pre-handshake: hello carries proposed max; ready carries
            // selected. Zero is never a negotiated version.
            if frame.version == 0 {
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
                FrameKind::Request | FrameKind::Cancel | FrameKind::Notification => {
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
            // Only drain existing RPCs. No re-handshake or event delivery.
            if !matches!(kind, FrameKind::Result | FrameKind::Cancel) {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "only result/cancel legal in CLOSING".to_string(),
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
            }
        }
        Body::Cancel(_) => {}
        Body::Notification(_) => {
            // Empty payload is valid (SNTR-WIRE-007); no further checks.
        }
    }

    Ok(kind)
}

/// Outcome of the raw wire pre-scan.
struct ScanStats {
    unknown_present: bool,
    body_present: bool,
}

/// Raw-wire structural validation without semantic checks.
///
/// Runs the same bounded pre-scan as [`decode_frame`] (reserved
/// top-level fields, duplicate body alternatives, truncation,
/// allocation and depth bounds) followed by a full prost decode, but
/// classifies no method, version, or state semantics. The decode matters:
/// the pre-scan skips most body contents (only `RpcResult` -> `RpcError`
/// is descended into), so malformed nested protobuf would otherwise read
/// as structurally sound. Used by embedding boundaries that map some
/// decode failures to per-RPC errors: structural violations stay fatal
/// even when the envelope also carries a malformed method.
pub fn validate_wire_structure(bytes: &[u8]) -> Result<(), SyntraError> {
    let scan = pre_scan(bytes)?;
    Frame::decode(bytes).map_err(|_| SyntraError::Protocol {
        code: ErrorCode::InvalidArgument,
        message: "malformed protobuf frame".to_string(),
    })?;
    if !scan.body_present {
        if scan.unknown_present {
            // Unknown-only envelope: same SNTR-WIRE-004 classification as
            // `decode_frame`, never silently dropped, never success.
            return Err(SyntraError::Protocol {
                code: ErrorCode::Unimplemented,
                message: "unknown frame variant".to_string(),
            });
        }
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "frame body must be set".to_string(),
        });
    }
    Ok(())
}

/// Scan top-level protobuf wire bytes before prost decodes.
///
/// Enforces, in one bounded pass:
/// - reserved top-level numbers 16/17 rejected (SNTR-SER-008; prost drops
///   unknown fields, so detection must happen on raw bytes). Numbers 16/17
///   inside nested messages are unassigned, not reserved, and are tolerated
///   per SNTR-SER-003 (see `check_nested`);
/// - duplicate `body` alternatives rejected (SNTR-WIRE-002; prost would
///   collapse two `oneof` members into one, hiding the violation);
///   duplicate `version`/`request_id` scalars follow protobuf merge
///   semantics (last wins) and are not rejected here, matching the Go
///   binding and SNTR-SER-002 non-canonical tolerance;
/// - unknown-top-level-content flag for unknown-variant handling
///   (SNTR-WIRE-004);
/// - allocation bound: no length prefix may exceed `MAX_FRAME_BYTES`
///   (SNTR-SER-006);
/// - depth bound: recursion into known message fields only
///   (`RpcResult` -> `RpcError`), capped at `MAX_DECODE_DEPTH`
///   (SNTR-SER-006). Unknown and opaque fields (payloads, credentials,
///   strings) are skipped by length, never descended into, so arbitrary
///   application bytes can neither false-positive nor blow up the walk.
fn scan_top_level(bytes: &[u8]) -> Result<ScanStats, SyntraError> {
    let mut body_count: u32 = 0;
    let mut unknown_present = false;
    let mut i = 0;
    while i < bytes.len() {
        let (tag, next) = read_varint(bytes, i).ok_or(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "malformed protobuf tag".to_string(),
        })?;
        i = next;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x07) as u8;
        reject_reserved(field)?;
        if (10..=15).contains(&field) {
            if wire != 2 {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "malformed frame body encoding".to_string(),
                });
            }
            body_count += 1;
            if body_count > 1 {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "frame must contain exactly one body".to_string(),
                });
            }
        } else if !matches!(field, 1 | 2) {
            unknown_present = true;
        }
        i = skip_top_value(bytes, i, wire, field)?;
    }
    Ok(ScanStats { unknown_present, body_present: body_count == 1 })
}

fn reject_reserved(field: u32) -> Result<(), SyntraError> {
    if field == 16 || field == 17 {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "frame uses reserved field number".to_string(),
        });
    }
    Ok(())
}

/// Skip one top-level wire value. `RpcResult` bodies (field 13) are
/// descended into with schema awareness so `RpcError` nesting is still
/// bounded; every other length-delimited field is skipped whole.
fn skip_top_value(bytes: &[u8], i: usize, wire: u8, field: u32) -> Result<usize, SyntraError> {
    match wire {
        0 => skip_varint(bytes, i),
        1 => skip_fixed(bytes, i, 8, "truncated fixed64"),
        2 => {
            let (len, next) = read_varint(bytes, i).ok_or(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "truncated length prefix".to_string(),
            })?;
            check_alloc(len)?;
            let len = len as usize;
            if next + len > bytes.len() {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "truncated length-delimited field".to_string(),
                });
            }
            if field == 13 {
                // RpcResult: validate the nested message with depth
                // tracking (depth 1); its RpcError (field 2) descends to
                // depth 2. All other nested content is opaque.
                check_nested(&bytes[next..next + len], Schema::RpcResult, 1)?;
            }
            Ok(next + len)
        }
        5 => skip_fixed(bytes, i, 4, "truncated fixed32"),
        _ => Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "illegal wire type".to_string(),
        }),
    }
}

/// Which message schema a nested region must satisfy.
#[derive(Clone, Copy)]
enum Schema {
    RpcResult,
    RpcError,
}

/// Schema-aware nested check. Only known message-typed fields are
/// descended into; opaque `bytes`/`string` fields are skipped whole.
/// Field numbers 16/17 are reserved only at the top-level `Frame`
/// (SNTR-SER-008); inside nested messages they are unassigned unknown
/// fields tolerated per SNTR-SER-003, matching the Go binding. Only the
/// top-level scan rejects them.
fn check_nested(bytes: &[u8], schema: Schema, depth: u32) -> Result<(), SyntraError> {
    if depth > MAX_DECODE_DEPTH {
        return Err(SyntraError::Protocol {
            code: ErrorCode::ResourceExhausted,
            message: "frame nesting exceeds depth bound".to_string(),
        });
    }
    let mut i = 0;
    while i < bytes.len() {
        let (tag, next) = read_varint(bytes, i).ok_or(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "malformed nested tag".to_string(),
        })?;
        i = next;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x07) as u8;
        match wire {
            0 => i = skip_varint(bytes, i)?,
            1 => i = skip_fixed(bytes, i, 8, "truncated nested fixed64")?,
            2 => {
                let (len, after) = read_varint(bytes, i).ok_or(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "truncated nested length prefix".to_string(),
                })?;
                check_alloc(len)?;
                let len = len as usize;
                if after + len > bytes.len() {
                    return Err(SyntraError::Protocol {
                        code: ErrorCode::InvalidArgument,
                        message: "truncated nested field".to_string(),
                    });
                }
                // Descend only into RpcError (field 2 of RpcResult).
                // RpcError itself has no message-typed fields, so this
                // terminates after one more level by construction.
                if matches!(schema, Schema::RpcResult) && field == 2 {
                    check_nested(&bytes[after..after + len], Schema::RpcError, depth + 1)?;
                }
                i = after + len;
            }
            5 => i = skip_fixed(bytes, i, 4, "truncated nested fixed32")?,
            _ => {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "illegal nested wire type".to_string(),
                })
            }
        }
    }
    Ok(())
}

fn check_alloc(len: u64) -> Result<(), SyntraError> {
    if len > MAX_FRAME_BYTES as u64 {
        return Err(SyntraError::Protocol {
            code: ErrorCode::ResourceExhausted,
            message: "frame field exceeds allocation bound".to_string(),
        });
    }
    Ok(())
}

fn skip_varint(bytes: &[u8], i: usize) -> Result<usize, SyntraError> {
    let mut j = i;
    loop {
        let b = *bytes.get(j).ok_or(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "truncated varint".to_string(),
        })?;
        j += 1;
        if b & 0x80 == 0 {
            return Ok(j);
        }
        if j - i > 10 {
            return Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "overlong varint".to_string(),
            });
        }
    }
}

fn skip_fixed(
    bytes: &[u8],
    i: usize,
    width: usize,
    what: &'static str,
) -> Result<usize, SyntraError> {
    if i + width > bytes.len() {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: what.to_string(),
        });
    }
    Ok(i + width)
}

fn read_varint(bytes: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        let b = *bytes.get(i)?;
        i += 1;
        value |= ((b & 0x7F) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        if shift > 64 {
            return None;
        }
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
        // protobuf garbage: the pre-scan skips body contents by length, so
        // only the full decode rejects it.
        let mut raw = vec![0x08u8, 0x01, 0x62, 0x0A];
        raw.extend([0xFFu8; 10]);
        assert!(validate_wire_structure(&raw).is_err());
        assert!(decode_frame(&raw, ctx_active()).is_err());
    }

    #[test]
    fn wire_structure_matches_decode_on_unknown_only_envelope() {
        // version=1 plus unknown top-level field 90: SNTR-WIRE-004
        // classifies this UNIMPLEMENTED, never INVALID_ARGUMENT.
        let raw = [0x08u8, 0x01, 0xD0, 0x05, 0x01];
        let wire_err = validate_wire_structure(&raw).expect_err("unknown-only must fail");
        assert!(matches!(
            wire_err,
            SyntraError::Protocol { code: crate::error::ErrorCode::Unimplemented, .. }
        ));
        let decode_err = decode_frame(&raw, ctx_active()).expect_err("unknown-only must fail");
        assert!(matches!(
            decode_err,
            SyntraError::Protocol { code: crate::error::ErrorCode::Unimplemented, .. }
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
