//! Codec entry points: length bounds + validated encode/decode.

use prost::Message;

use crate::error::SyntraError;
use crate::frame::{validate_frame, ValidationContext};
use crate::proto::Frame;

pub use crate::frame::{
    decode_frame, decode_frame_structure, missing_result_outcome_id, validate_wire_structure,
    MAX_FRAME_BYTES,
};

/// Encode a validated `Frame`. Validates before encoding so malformed
/// envelopes are never emitted (SNTR-SER-010).
pub fn encode_frame(frame: &Frame, ctx: ValidationContext) -> Result<Vec<u8>, SyntraError> {
    validate_frame(frame, ctx)?;
    Ok(frame.encode_to_vec())
}
