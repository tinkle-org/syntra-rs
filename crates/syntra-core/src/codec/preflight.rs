//! Exact slice extents before generated code performs offset arithmetic. There
//! are at most two unions and one message on any path; no recursive wire walk.

use super::*;
use crate::{MAX_CONNECTION_ID_BYTES, MAX_CREDENTIAL_BYTES, MAX_DIAGNOSTIC_BYTES};

fn malformed() -> SyntraError {
    violation(ErrorCode::InvalidArgument, "malformed Bebop frame")
}

fn take<'a>(input: &mut &'a [u8], len: usize) -> Result<&'a [u8], SyntraError> {
    let (value, rest) = input.split_at_checked(len).ok_or_else(malformed)?;
    *input = rest;
    Ok(value)
}

fn length(input: &mut &[u8]) -> Result<usize, SyntraError> {
    Ok(u32::from_le_bytes(take(input, 4)?.try_into().unwrap()) as usize)
}

fn blob<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], SyntraError> {
    let len = length(input)?;
    take(input, len)
}

fn union(mut input: &[u8]) -> Result<(u8, &[u8]), SyntraError> {
    let len = length(&mut input)?;
    let tag = take(&mut input, 1)?[0];
    if input.len() != len {
        return Err(malformed());
    }
    Ok((tag, input))
}

fn message(kind: u8, mut content: &[u8]) -> Result<(), SyntraError> {
    let mut fields = blob(&mut content)?;
    if !content.is_empty() || fields.last() != Some(&0) {
        return Err(malformed());
    }
    let mut last = 0;
    let mut bound_error = None;
    loop {
        let field = take(&mut fields, 1)?[0];
        if field == 0 {
            if !fields.is_empty() {
                return Err(malformed());
            }
            break;
        }
        if field <= last {
            return Err(malformed());
        }
        last = field;
        match (kind, field) {
            (10, 1 | 2) | (12, 3) | (2, 1) => {
                take(&mut fields, 4)?;
            }
            (10, 3) | (11, 1) | (12, 1 | 2) | (2, 2) | (15, 1) => {
                let value = blob(&mut fields)?;
                if matches!((kind, field), (11 | 12, 1) | (2, 2)) {
                    std::str::from_utf8(value).map_err(|_| malformed())?;
                }
                bound_error = bound_error.or(match (kind, field) {
                    (10, 3) if value.len() > MAX_CREDENTIAL_BYTES => Some((
                        ErrorCode::ResourceExhausted,
                        "hello credential exceeds bound",
                    )),
                    (11, 1) if value.len() > MAX_CONNECTION_ID_BYTES => {
                        Some((ErrorCode::InvalidArgument, "invalid connection_id length"))
                    }
                    (2, 2) if value.len() > MAX_DIAGNOSTIC_BYTES => Some((
                        ErrorCode::InvalidArgument,
                        "error message exceeds diagnostic bound",
                    )),
                    _ => None,
                });
            }
            // Unlike a tagged-length field format, Bebop cannot skip one
            // unknown field. The *rest* of this bounded message is opaque.
            _ => break,
        }
    }
    match bound_error {
        Some((code, reason)) => Err(violation(code, reason)),
        None => Ok(()),
    }
}

/// Check the entire envelope and each known field without allocating decoded
/// values. Unknown message tails are skipped within the declared extent;
/// unknown union arms cannot be dispatched. Version/ID/state checks are separate.
pub fn validate_wire_structure(bytes: &[u8]) -> Result<(), SyntraError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(violation(
            ErrorCode::ResourceExhausted,
            "frame exceeds maximum envelope size",
        ));
    }
    let (body, content) = union(bytes.get(12..).ok_or_else(malformed)?)?;
    match body {
        10..=12 | 14..=15 => message(body, content),
        13 => match union(content)? {
            (1, mut data) => {
                blob(&mut data)?;
                if data.is_empty() {
                    Ok(())
                } else {
                    Err(malformed())
                }
            }
            (2, data) => message(2, data),
            (0, _) => Err(malformed()),
            _ => Err(violation(
                ErrorCode::Unimplemented,
                "unknown result outcome",
            )),
        },
        0 | 16 | 17 => Err(malformed()),
        _ => Err(violation(ErrorCode::Unimplemented, "unknown frame body")),
    }
}

/// Local correlation only: an exact, complete result envelope declaring zero
/// bytes for its required outcome. Never infer an ID from a truncated union,
/// an unknown discriminator or any other malformed structure.
pub fn missing_result_outcome_id(bytes: &[u8], ctx: ValidationContext) -> Option<u64> {
    let (header, body) = bytes.split_at_checked(12)?;
    if body != [0, 0, 0, 0, 13] {
        return None;
    }
    let frame = Frame {
        version: u32::from_le_bytes(header[..4].try_into().ok()?),
        request_id: u64::from_le_bytes(header[4..].try_into().ok()?),
        body: Some(Body::Result(CallResult {
            outcome: Some(Outcome::Payload(Vec::new())),
        })),
    };
    validate_frame(&frame, ctx).ok()?;
    Some(frame.request_id)
}
