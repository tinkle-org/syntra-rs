//! WebSocket control bytes and frame bounds are checked against `fixtures/transport.yaml`.
//! The Protobuf examples below are serialized envelopes, not protected records.

/// Valid CONNECTED-state anonymous hello, without a stream length prefix (VEC-WS-009).
pub const NO_LENGTH_PREFIX_GOOD_HEX: &str = "0801520408011001";

/// Appending this length-delimited field 90 leaves the logical frame unchanged.
pub const UNKNOWN_FIELD_SUFFIX_HEX: &str = "d2050178";

/// Historical length-prefixed and suffixed variants are not valid envelopes.
pub const VARINT_PREFIXED_HEX: &str = "080801520408011001";
pub const U32_PREFIXED_HEX: &str = "000000080801520408011001";
pub const SUFFIXED_HEX: &str = "080152040801100100";

/// Ping wire bytes, host -> client (VEC-WS-005, FIN=1, opcode 0x9).
pub const PING_WIRE_HEX: &str = "890670696e672d31";

/// Pong wire bytes, client -> host (MASK=1, key 37fa213d).
pub const PONG_WIRE_HEX: &str = "8a8637fa213d47934f5a1acb";

/// Close handshake, client -> host (Close 1000, masked).
pub const CLOSE_CLIENT_WIRE_HEX: &str = "888237fa213d3412";

/// Close handshake, host -> client (Close 1000).
pub const CLOSE_HOST_WIRE_HEX: &str = "880203e8";

/// Spec close-code table (WS section 1J, fixtures VEC-WS-007):
/// (wire code, condition label).
pub const CLOSE_CODE_TABLE: &[(u16, &str)] = &[
    (1000, "normal closure"),
    (1001, "going away"),
    (1002, "protocol error"),
    (1003, "unsupported data"),
    (1007, "invalid frame payload data"),
    (1008, "policy violation"),
    (1009, "message too big"),
    (1011, "internal error"),
];

/// Codes that MUST NEVER appear on the wire (local-only statuses).
pub const RESERVED_CLOSE_CODES: &[u16] = &[1005, 1006, 1015];

/// Default maximum envelope size (SNTR-WIRE-006).
pub const MAX_FRAME_BYTES: usize = 1_048_576;

/// Decode lowercase hex (no prefixes, no whitespace).
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "hex length must be even");
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_val(pair[0]);
        let lo = hex_val(pair[1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex char"),
    }
}
