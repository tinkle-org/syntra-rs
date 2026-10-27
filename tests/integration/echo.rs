//! Neutral echo fixtures (SNTR-RPC-900; no application semantics).
//!
//! The only method used here is `/example.Echo/Echo`, which returns its
//! input payload byte-for-byte. Payloads cover empty, small, opaque
//! binary (including non-UTF-8), and kilobyte-scale inputs.

/// Neutral echo method (rpc.md section 1C wire-syntax example).
pub const ECHO_METHOD: &str = "/example.Echo/Echo";

/// Representative opaque payloads. Presence (not length) carries meaning:
///
/// - empty input invokes the method with empty input;
/// - empty success output means success with empty output;
/// - arbitrary bytes (including non-UTF-8) round-trip untouched.
pub fn echo_payloads() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"hello syntra".to_vec(),
        vec![0x55; 1024],
        vec![0x00, 0xff, 0xfe, 0x01, 0x80],
        "full-width echo — e2e".as_bytes().to_vec(),
    ]
}

/// Assert an echo round-trip preserved bytes exactly.
pub fn assert_echo(got: &[u8], want: &[u8]) {
    assert_eq!(got, want, "echo must be byte-exact");
}
