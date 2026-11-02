# Conformance — WebSocket Transport (`CONF-WS-001…017`)

Related normative requirements are cited per case; test IDs are not normative. All cases Mandatory. Neutral fixtures only (`/example.Echo/Echo`, `/example.KV/Get`). All cases run with compression off unless the case states otherwise. Byte order on the wire follows RFC 6455; client frames are masked, server frames are not.

## CONF-WS-001 valid WS Upgrade

- Related normative requirement: SNTR-WS-001, SNTR-WS-010/011/020, SNTR-WS-040/041.
- Preconditions: plaintext WS host serves `/syntra/v1/ws`; no TLS.
- Input: `GET /syntra/v1/ws HTTP/1.1` with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key: <base64>`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Protocol: syntra.v1`.
- Expected output: `101 Switching Protocols` with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Accept: <derived>`, `Sec-WebSocket-Protocol: syntra.v1`. No Syntra envelope sent before 101.
- Expected connection state: WS established (Syntra CONNECTED, handshake timer running).
- Expected session state: none (no principal bound).
- Mandatory/optional: Mandatory.

## CONF-WS-002 subprotocol negotiation

- Related normative requirement: SNTR-WS-020/023/024.
- Preconditions: as in CONF-WS-001; client offers `syntra.v1` first plus (optionally) an unknown future token second.
- Input: Upgrade with `Sec-WebSocket-Protocol: syntra.v1, x-future-proto`.
- Expected output: 101 selects exactly `syntra.v1`. Connection proceeds to Syntra handshake; core version still negotiates via `hello`/`ready` independently.
- Expected connection state: CONNECTED → NEGOTIATING on first binary `hello`.
- Expected session state: none until `ready`.
- Mandatory/optional: Mandatory.

## CONF-WS-003 missing subprotocol

- Related normative requirement: SNTR-WS-021.
- Preconditions: conformant host; client omits `Sec-WebSocket-Protocol`.
- Input: Upgrade without the header.
- Expected output: Upgrade fails (HTTP 400/426, no 101). If a 101 without the header is ever received, the client aborts without sending Syntra bytes and reports `FAILED_PRECONDITION` locally.
- Expected connection state: no WS connection; no Syntra state.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WS-004 unsupported subprotocol

- Related normative requirement: SNTR-WS-022.
- Preconditions: host implements only `syntra.v1`; client offers only `other.proto`.
- Input: Upgrade with `Sec-WebSocket-Protocol: other.proto`.
- Expected output: Upgrade fails (no 101). Client receiving a 101 selecting anything other than `syntra.v1` aborts without Syntra bytes and reports `UNIMPLEMENTED`.
- Expected connection state: no WS connection.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WS-005 binary envelope round-trip

- Related normative requirement: SNTR-WS-030/031/035/036, SNTR-WIRE-001/002.
- Preconditions: ACTIVE session over WS (completed `hello`→`ready`).
- Input: `Frame{id=7, request{method=/example.Echo/Echo, payload=opaque, timeout_ms=500}}` serialized to protobuf, sent as one binary message (opcode 0x2); repeat with empty, small, and arbitrary non-UTF-8 payloads.
- Expected output: exactly one `Frame{id=7, result{payload}}` as one binary message with bit-identical payload; no length prefix inside the message (a `[length][protobuf]` message fails decode — see VEC-WS-009).
- Expected connection state: ACTIVE, usable.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-WS-006 text message rejection

- Related normative requirement: SNTR-WS-031, SNTR-WS-081/082.
- Preconditions: ACTIVE session.
- Input: peer sends a text message (opcode 0x1, valid UTF-8, e.g., `hello`).
- Expected output: recipient closes with code 1003 (unsupported data); `UNIMPLEMENTED` context locally; no Syntra `result` synthesized; no handler dispatch.
- Expected connection state: CLOSING→CLOSED.
- Expected session state: terminated (default connection-bound).
- Mandatory/optional: Mandatory.

## CONF-WS-007 fragmented binary message

- Related normative requirement: SNTR-WS-033/034.
- Preconditions: ACTIVE session.
- Input: one `Frame{id=8, request{/example.KV/Get}}` binary message split across 3 fragments (binary + 2 continuations, FIN on last), with a Ping interleaved between fragments.
- Expected output: recipient answers Pong, reassembles all fragments, then decodes exactly one `Frame` and processes it normally (one terminal `result{id=8}`). Fragment boundaries have no semantic effect.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-WS-008 oversized assembled message

- Related normative requirement: SNTR-WS-035, SNTR-WIRE-006.
- Preconditions: ACTIVE session; default bound 1 MiB unless documented otherwise.
- Input: assembled binary message of exactly MAX+1 bytes (1,048,577 for the default bound), sent whole or fragmented.
- Expected output: recipient stops accumulating past the bound, discards the message, closes with code 1009; `RESOURCE_EXHAUSTED` context; no panic, no unbounded allocation.
- Expected connection state: CLOSING→CLOSED (connection-level exhaustion).
- Expected session state: terminated.
- Mandatory/optional: Mandatory.

## CONF-WS-009 Ping/Pong liveness

- Related normative requirement: SNTR-WS-070…073.
- Preconditions: ACTIVE session, idle (no RPC in flight).
- Input: host sends Ping (payload `ping-1`); initiator replies; then initiator sends Ping and host replies; then an unsolicited Pong is injected.
- Expected output: each Ping receives a Pong with the identical payload promptly; unsolicited Pong is accepted and ignored (no state change, no event delivered to the core). No Syntra envelope is emitted for any control frame.
- Expected connection state: ACTIVE throughout.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-WS-010 normal close

- Related normative requirement: SNTR-WS-080/081.
- Preconditions: ACTIVE session, no in-flight RPCs.
- Input: either peer sends Close{1000, reason}; peer echoes Close{1000}; TCP closes.
- Expected output: clean Close handshake per RFC 6455 §7; state discarded except diagnostics; no error reported for completed RPCs.
- Expected connection state: CLOSED via graceful path.
- Expected session state: terminated normally.
- Mandatory/optional: Mandatory.

## CONF-WS-011 protocol-error close

- Related normative requirement: SNTR-WS-081/082, SNTR-HS-012, SNTR-WIRE-003.
- Preconditions: ACTIVE session.
- Input (three runs): (a) second `hello` on the same connection; (b) `request` with `request_id == 0`; (c) empty binary message.
- Expected output: (a)/(b) Close 1002 with `FAILED_PRECONDITION` context; (c) Close 1007 (or 1002) with `INVALID_ARGUMENT` context. Handshake-phase variants close the connection; no second handshake on the same transport.
- Expected connection state: CLOSING→CLOSED in every run.
- Expected session state: terminated.
- Mandatory/optional: Mandatory.

## CONF-WS-012 abrupt disconnect

- Related normative requirement: SNTR-HS-014, SNTR-REL-009.
- Preconditions: ACTIVE session with at least one in-flight RPC (`id=12`).
- Input: abrupt TCP loss with no Close handshake.
- Expected output: `UNAVAILABLE` to every in-flight RPC; outcome reported as unknown; MUST NOT be reported as success or as proof of non-execution.
- Expected connection state: CLOSED via loss.
- Expected session state: terminated abnormally.
- Mandatory/optional: Mandatory.

## CONF-WS-013 reconnect starts a new session

- Related normative requirement: SNTR-WS-120, SNTR-SESS-003/008/010/011.
- Preconditions: session over WS connection A ended (close or loss).
- Input: new WS connection B + fresh `hello` with fresh credential; attempt to reuse connection A's `connection_id` as a credential.
- Expected output: connection B handshakes as a new session (fresh `connection_id`); the `connection_id`-as-credential attempt is rejected (`FAILED_PRECONDITION` or `UNAUTHENTICATED`) + close; in-flight RPCs from A are not continued on B; subscriptions from A do not survive.
- Expected connection state: A CLOSED; B ACTIVE after fresh handshake.
- Expected session state: A's session ended; B's session independent.
- Mandatory/optional: Mandatory.

## CONF-WS-014 session resume without capability rejected

- Related normative requirement: SNTR-WS-120, SNTR-SESS-006/020.
- Preconditions: default v1 (no resumption capability negotiated).
- Input: any resumption attempt (stale token, `connection_id` presentation, cross-transport presentation).
- Expected output: rejection with `UNAUTHENTICATED` or `FAILED_PRECONDITION` + close. Host documents "no resumption — sessions are connection-bound".
- Expected connection state: CLOSING→CLOSED for the attempt.
- Expected session state: no session restored.
- Mandatory/optional: Mandatory.

## CONF-WS-015 concurrent RPCs over one WS connection

- Related normative requirement: SNTR-RPC-002/008, SNTR-REL-007 (via SNTR-WS-100).
- Preconditions: ACTIVE; host supports ≥2 concurrent RPCs (minimum 16).
- Input: `Frame{id=7, request{Echo, A}}` and `Frame{id=8, request{KV/Get, B}}` outstanding simultaneously; host completes second first.
- Expected output: two terminal results `id=7` and `id=8`, each correlated exactly once; order `8`-before-`7` accepted; no cross-delivery; correlation by ID only.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-WS-016 server event over WS

- Related normative requirement: SNTR-HS-005, SNTR-EVENT-005 (via core), SNTR-WS-040.
- Preconditions: ACTIVE with a negotiated subscription (application-defined via generic RPC).
- Input: host emits `Frame{request_id=0, notification{payload}}` as a binary message; one run with an event arriving between `request{id=9}` and its `result{id=9}`.
- Expected output: initiator delivers the notification as an event without completing `id=9`; the later `result{id=9}` still completes exactly once. Pre-ACTIVE `notification` is a handshake failure per core table (not asserted as delivery).
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory (only where the implementation claims events; otherwise the pre-ACTIVE rejection half still applies).

## CONF-WS-017 slow consumer backpressure

- Related normative requirement: SNTR-WS-100/101/102, SNTR-REL-007/008, SNTR-ASEC-020.
- Preconditions: ACTIVE with documented inbound/outbound/queue bounds.
- Input: flood exceeding the bound (message burst, or 17th concurrent RPC where max is 16, or a peer that stops reading past the write grace period).
- Expected output: excess RPC rejected with `RESOURCE_EXHAUSTED` (connection stays usable, conformant traffic unaffected); connection-level exhaustion closes (1009/1011) with `UNAVAILABLE` to affected in-flight RPCs; initiator backs off with jitter (no tight loop); host recovers without restart.
- Expected connection state: ACTIVE for per-RPC shedding; CLOSING for connection-level exhaustion.
- Expected session state: unchanged except where the connection closed.
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-WS-001 | WS-001/010/011/020/040 (Upgrade, endpoint) |
| CONF-WS-002 | WS-020/023/024 (negotiation, version independence) |
| CONF-WS-003 | WS-021 (missing subprotocol) |
| CONF-WS-004 | WS-022 (unsupported subprotocol) |
| CONF-WS-005 | WS-030/031/035/036 (binary mapping, no prefix) |
| CONF-WS-006 | WS-031/081 (text rejection 1003) |
| CONF-WS-007 | WS-033/034 (fragmentation, control interleave) |
| CONF-WS-008 | WS-035 (oversize 1009) |
| CONF-WS-009 | WS-070…073 (Ping/Pong) |
| CONF-WS-010 | WS-080/081 (normal close 1000) |
| CONF-WS-011 | WS-081/082 (protocol-error closes) |
| CONF-WS-012 | HS-014, REL-009 (loss → UNAVAILABLE) |
| CONF-WS-013 | WS-120, SESS-003/008/010 (reconnect = new session) |
| CONF-WS-014 | WS-120, SESS-006/020 (no-capability resume rejected) |
| CONF-WS-015 | RPC-002/008 over WS (concurrency, order) |
| CONF-WS-016 | HS-005, EVENT-005 over WS (events) |
| CONF-WS-017 | WS-100/101/102 (backpressure, exhaustion) |
