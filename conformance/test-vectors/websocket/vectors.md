# Test Vectors — WebSocket Binary Framing (`VEC-WS-001…009`)

Conventions: `C` = initiator (masks frames), `H` = host (never masks).
`Frame{...}` denotes the protobuf-serialized Syntra envelope bytes per
`proto/syntra/v1/envelope.proto`; `LEN` = its length in bytes. Vectors assert
transport shape; they do not freeze protobuf field encoding. Bounds assume the
default MAX of 1,048,576 bytes unless the deployment documents otherwise.

## VEC-WS-001 valid Upgrade request (client → host)

```http
GET /syntra/v1/ws HTTP/1.1
Host: syntra.example:80
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: syntra.v1
Origin: (absent for native clients; e.g. https://app.example for browsers)
```

Notes: path is exactly `/syntra/v1/ws` (no trailing slash). No credential in
target, query, or headers. `Sec-WebSocket-Protocol` lists `syntra.v1` first.
`Origin`, when present, is a browser signal only, never authentication.

## VEC-WS-002 valid Upgrade response (host → client)

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
Sec-WebSocket-Protocol: syntra.v1
```

Notes: `Sec-WebSocket-Accept` is derived from the request key per RFC 6455 §4.2.2
(the value above pairs with the key in VEC-WS-001). Absence of the
`Sec-WebSocket-Protocol` line, or any value other than `syntra.v1`, means the
connection is not Syntra: the client MUST abort without sending envelopes.

## VEC-WS-003 single binary message carrying one Frame (either direction)

RFC 6455 wire shape (server → client shown unmasked; client → server sets
the MASK bit, inserts a 4-byte masking key after the length field, and XORs
every payload byte with `key[i mod 4]`):

```text
byte 0: 0x82            ; FIN=1, opcode=0x2 (binary)
byte 1: LEN marker      ; 0..125 directly, 0x7E + 16-bit LEN, or 0x7F + 64-bit LEN
bytes:  Frame{...}      ; exactly LEN bytes of protobuf, no transport prefix/suffix
```

Example instance (ACTIVE, echo): `Frame{version=1, request_id=7,
request{method="/example.Echo/Echo", payload=<opaque>, timeout_ms=500}}`
sent as one message with FIN=1, opcode 0x2. The peer decodes the LEN bytes
directly as one `Frame` and returns one `Frame{id=7, result{...}}` message.

## VEC-WS-004 fragmented binary message with interleaved Ping

One `Frame{id=8, request{/example.KV/Get}}` of total assembled length LEN,
sent as three fragments with a Ping between fragments 1 and 2:

```text
C→H: 0x02 ... first chunk  ; FIN=0, opcode=0x2 (masked)
H→C: Ping{ping-1}           ; 0x89, control frame, MAY interleave
C→H: Pong{ping-1}           ; 0x8A, masked echo as in VEC-WS-005
C→H: 0x00 ... middle chunk ; FIN=0, opcode=0x0 (continuation, masked)
C→H: 0x80 ... final chunk  ; FIN=1, opcode=0x0 (continuation, masked)
```

The recipient MUST reassemble all three chunks (in order, total LEN) before
decoding, MUST handle the Ping/Pong at the WS layer without disturbing
reassembly, and MUST process the result as exactly one `Frame`.

## VEC-WS-005 Ping / Pong

```text
H→C: 0x89 0x06 0x70 0x69 0x6E 0x67 0x2D 0x31
C→H: 0x8A 0x86 0x37 0xFA 0x21 0x3D 0x47 0x93 0x4F 0x5A 0x1A 0xCB
```

The Ping payload is `ping-1` (6 bytes, within the 125-byte control limit).
The Pong sets MASK (`0x86`), includes key `37 fa 21 3d`, and carries the
XOR-masked payload `47 93 4f 5a 1a cb`, which unmasks to the identical `ping-1`.
The fixed key is a deterministic test fixture only: real clients MUST use
fresh unpredictable masking keys for every frame per RFC 6455, including
Pong and Close. Servers never mask.

Unsolicited Pong (`0x8A` with no outstanding Ping) MUST be accepted and
ignored: no Syntra envelope, no event, no state change.

## VEC-WS-006 normal close handshake

```text
C→H: 0x88 0x82 0x37 0xFA 0x21 0x3D 0x34 0x12
H→C: 0x88 0x02 0x03 0xE8   ; Close{1000} echo
--- TCP close (TLS close_notify first, for WSS) ---
```

The client Close sets MASK (`0x82`) and includes the fixture key
`37 fa 21 3d`; XOR-masked `34 12` decodes to `03 e8` (1000, no reason).
With a reason string: the unmasked payload is the 2-byte code followed by
UTF-8 text (e.g., `0x03 0xE8 "done"`). Client masking covers the code and the
entire reason; the length counts those payload bytes, not the key. Reason
text MUST NOT contain credentials or raw bytes.

## VEC-WS-007 protocol-error and data-type closes

```text
text message received : Close{1003}  ; 0x03EB, UNSUPPORTED DATA
second hello / pre-ACTIVE RPC / request_id misuse / unknown variant : Close{1002}  ; 0x03EA, PROTOCOL ERROR
malformed protobuf / reserved numbers 16,17 : Close{1007}  ; 0x03EF, INVALID PAYLOAD
auth denial post-101 : Close{1008}  ; 0x03F0, POLICY VIOLATION
assembled (or decompressed) length > MAX : Close{1009}  ; 0x03F1, MESSAGE TOO BIG
host internal failure : Close{1011}  ; 0x03F3, INTERNAL ERROR
going away / idle / shutdown : Close{1001}  ; 0x03E9
```

Codes 1005, 1006, and 1015 MUST NEVER appear on the wire; they are local-only
statuses. See `close-codes.md` for the full normative table.

## VEC-WS-008 oversize boundary

With default MAX = 1,048,576: a message whose assembled length is exactly
1,048,576 MUST be accepted (subject to valid decode); a message of exactly
1,048,577 (MAX+1) — sent whole or fragmented — MUST trigger the oversize path:
stop accumulating past the bound, discard, Close{1009}, `RESOURCE_EXHAUSTED`
context. The harness MUST test both sides of the serialized envelope boundary.
For exactly-MAX acceptance, construct a valid `Frame` in a legal state and
within all field limits, adjusting the opaque payload length so tags, length
varints, and enclosing fields bring the serialized total to MAX. `0x55`
filler belongs only inside that payload; an all-`0x55` message is not a valid
acceptance fixture. The size bound does not waive decode or semantic validation.

## VEC-WS-009 no-length-prefix negative proof

A conformant sender produces `message = protobuf(Frame)` (VEC-WS-003).
Use the concrete protobuf payload `0801520408011001` (8 bytes), the same
hello as `tcp/V1`: `Frame{version:1, hello{min_version:1, max_version:1}}`.
Send client → host in CONNECTED with anonymous acceptance enabled. The following payloads
test direct decoding without TCP-style prefix stripping:

```text
GOOD: 0801520408011001                  ; accepted
GOOD: 0801520408011001d2050178          ; accepted, appended unknown field 90 = "x"
BAD:  08 + 0801520408011001            ; prepended varint length 8, malformed
BAD:  00000008 + 0801520408011001      ; prepended u32 length 8, illegal field-zero tag
BAD:  0801520408011001 + 00            ; malformed suffix, illegal field-zero tag
```

Each payload is one complete binary message with its actual length in the WS
header. These client hello fixtures set MASK, include a 4-byte key, and XOR
the payload as in VEC-WS-003. For a host-legal `Frame`, the server-to-client
shape is `[0x82][LEN][protobuf(Frame)]` (unmasked); hello is not host-originated.
The BAD cases MUST fail as `INVALID_ARGUMENT` context and close
per the malformed-protobuf path (1007).

Receivers MUST decode the entire message payload directly as one `Frame` with
no prefix stripping. Protobuf has no intrinsic message-end marker: valid
appended unknown fields are part of that same message and MUST be tolerated
per SNTR-SER-003, subject to bounds, reserved-tag rejection, and envelope
validation. Only a malformed suffix is rejected as trailing garbage; its
position after known fields is not itself an error. These concrete prefixed
negative inputs do not imply that every arbitrary prefix is undecodable.

## WSS notes (no separate binary vectors)

All vectors above run unchanged over WSS with the bytes carried inside the
TLS 1.3 channel: TCP → TLS 1.3 handshake (SNI, ALPN `http/1.1` where
negotiated, chain + hostname + expiry validation) → Upgrade bytes (same path,
`wss` scheme in the logical URI) → binary messages (same opcodes) → Close
handshake → `close_notify` → TCP close. No Syntra byte precedes successful
validation. TLS fixtures (valid/invalid/wrong-host/expired/revoked/<1.3/
proxy-mismatch/rotation) are harness-named references owned by
`specifications/security/*`, not embedded bytes here.
