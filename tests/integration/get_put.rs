//! Neutral get-put fixtures (no storage model, no chat semantics).
//!
//! Methods `/example.KV/Get` and `/example.KV/Put` exercise the terminal
//! `result` shapes: `Put` succeeds with empty output, `Get` for an
//! unknown key fails with `NOT_FOUND`. The key encoding below is a test
//! convenience (length-prefixed key bytes + value bytes); the core
//! treats every payload as opaque.

/// Neutral lookup method.
pub const KV_GET_METHOD: &str = "/example.KV/Get";
/// Neutral store method.
pub const KV_PUT_METHOD: &str = "/example.KV/Put";

/// Encode a put payload: `[key_len u32 BE][key][value]`.
pub fn put_payload(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.len() + value.len());
    out.extend_from_slice(&(key.len() as u32).to_be_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(value);
    out
}

/// Encode a get payload: the raw key bytes.
pub fn get_payload(key: &[u8]) -> Vec<u8> {
    key.to_vec()
}

/// Representative keys (byte-exact, case-sensitive; no normalization).
pub fn sample_keys() -> Vec<Vec<u8>> {
    vec![b"alpha".to_vec(), b"beta".to_vec(), Vec::new()]
}
