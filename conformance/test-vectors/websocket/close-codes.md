# Close-Code Mapping Table — WS / WSS (Normative)

RFC 6455 §7.4 status codes as used by the Syntra WS and WSS profiles.
"Send" is the code the detecting peer puts in the first Close frame;
"Local Syntra signal" is the error context where an RPC or handshake context
exists (handshake-phase failures additionally close per SNTR-HS-040).
Codes 1005, 1006, and 1015 MUST NOT be sent on the wire; they appear below
only to forbid them. Application-private codes 4000–4999 MUST NOT be used to
signal any condition in this table.

| Wire code | Name (RFC 6455) | Sent when (Syntra condition) | Local Syntra signal | Connection after |
|---|---|---|---|---|
| 1000 | Normal closure | Normal shutdown; handshake-complete session ending cleanly | None (in-flight RPCs get `UNAVAILABLE`/`CANCELLED` per SNTR-HS-006) | CLOSED via graceful path |
| 1001 | Going away | Host shutdown, client navigation away, idle/liveness timeout, write-grace expiry on a slow receiver | `UNAVAILABLE` to in-flight RPCs | CLOSED |
| 1002 | Protocol error | Envelope validation failure: version-range mismatch, wrong-state frame, second `hello`, pre-ACTIVE `request`/`cancel`/`notification`, `request_id` misuse, unknown `Frame.body` variant; client abort on wrong/missing subprotocol in 101 | `UNIMPLEMENTED` (version/variant) or `FAILED_PRECONDITION` (state) | CLOSING→CLOSED (SNTR-HS-040) |
| 1003 | Unsupported data | Text message (opcode 0x1) received | `UNIMPLEMENTED`; no `result` synthesized | CLOSING→CLOSED |
| 1007 | Invalid frame payload data | Assembled binary message fails protobuf decode: truncated varint, illegal wire type, overlong length, invalid UTF-8 in `string` fields, reserved numbers 16/17, trailing garbage / embedded length prefix | `INVALID_ARGUMENT` (affected unit; handshake-phase closes) | Affected unit fails; handshake-phase CLOSED |
| 1008 | Policy violation | Authentication failure at handshake (invalid/expired/revoked credential) or authorization refusal requiring close; post-101 admission denial | `UNAUTHENTICATED` / `PERMISSION_DENIED` (generic message, SNTR-ASEC-011) | CLOSING→CLOSED |
| 1009 | Message too big | Assembled binary length (or decompressed length where compression was explicitly enabled) exceeds the effective maximum envelope size | `RESOURCE_EXHAUSTED` | CLOSING→CLOSED for the message |
| 1011 | Internal error | Host internal failure preventing continuation of the connection | `INTERNAL` (generic message) | Per policy (usually CLOSED) |
| — (never send 1005) | No status received (local only) | MUST NOT be sent; a locally detected absence of status is reported as abnormal loss | `UNAVAILABLE` (outcome unknown) | CLOSED via loss |
| — (never send 1006) | Abnormal closure (local only) | MUST NOT be sent; abrupt TCP loss without a Close handshake | `UNAVAILABLE` (outcome unknown, SNTR-REL-009) | CLOSED via loss |
| — (never send 1015) | TLS handshake failure (local only) | MUST NOT be sent (WSS); TLS failures fail below WS with an alert, no Syntra `hello` sent | Terminal handshake failure (SNTR-TSEC) | No Syntra connection |

Reason strings: the first Close MAY carry a short UTF-8 reason after the
2-byte code (e.g., `1000 "done"`). Reasons MUST NOT contain credentials,
tokens, raw untrusted bytes, or private diagnostics. The peer MUST echo the
Close and then close TCP (TLS `close_notify` first, for WSS). A Close received
while fragmented input is pending discards the partial message.
