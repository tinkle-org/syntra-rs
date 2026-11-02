# Conformance — RPC correlation, deadlines, cancellation, idempotency (`CONF-RPC-001…013`)

Related normative requirements are cited per case; test IDs are not normative. All cases Mandatory. Neutral fixtures only (`/example.Echo/Echo`, `/example.KV/Get`).

## CONF-RPC-001 basic request/response

- Related normative requirement: SNTR-RPC-001, SNTR-RPC-002, SNTR-RPC-003, SNTR-RPC-006, SNTR-WIRE-001/002.
- Preconditions: session ACTIVE; method `/example.Echo/Echo` exists.
- Input: `Frame{id=7, request{method=/example.Echo/Echo, payload=opaque, timeout_ms=500}}` (repeat with empty, small, arbitrary non-UTF-8 payloads).
- Expected output: exactly one `Frame{id=7, result{payload}}` with bit-identical payload; correlation IDs match exactly.
- Expected connection state: ACTIVE, usable.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-RPC-002 two concurrent requests

- Related normative requirement: SNTR-RPC-002, SNTR-RPC-008, SNTR-REL-007.
- Preconditions: ACTIVE; host supports ≥2 concurrent RPCs (minimum is 16).
- Input: `Frame{id=7, request{Echo, A}}` and `Frame{id=8, request{KV/Get, B}}` outstanding simultaneously.
- Expected output: two terminal results, `id=7` and `id=8`, each correlated exactly once; no cross-delivery.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.
- Scope: persistent-carrier concurrency (SNTR-RPC-008) — this case runs on persistent Syntra connections (TCP/TLS, WS/WSS, SC1), machine-readable via its manifest `applicable_transports: [tcp_tls, ws_wss]` (SC1 multiplexes within the `ws_wss` family; an HTTP/HTTPS-only claim reports `SKIP` citing the key). HTTP/HTTPS exchanges are independent logical connections each carrying one RPC (SNTR-HTTP-070); their minimum concurrency is transport-owned (SNTR-HTTP-072 per CONF-HTTP-013, SNTR-HTTPS-041 per CONF-HTTPS-003).

## CONF-RPC-003 reversed response order

- Related normative requirement: SNTR-RPC-002 (correlation, not FIFO).
- Preconditions: ACTIVE with two outstanding RPCs as in CONF-RPC-002.
- Input: host completes the second request first (e.g., slow handler A, fast handler B).
- Expected output: `Frame{id=8, result}` arrives before `Frame{id=7, result}`; initiator correlates by ID and MUST NOT treat order as significant.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.
- Scope: persistent-carrier correlation case (TCP/TLS, WS/WSS, SC1), machine-readable via its manifest `applicable_transports: [tcp_tls, ws_wss]`; an HTTP/HTTPS-only claim reports `SKIP` for this case citing the key (conformance README §6). On HTTP/HTTPS the ordering-none and reverse-completion coverage is transport-owned: `CONF-HTTP-013` (SNTR-HTTP-072) and `CONF-HTTPS-003` (SNTR-HTTPS-042/041) run it at scale across independent exchanges/streams (RFC 0004 D3).

## CONF-RPC-004 duplicate request ID

- Related normative requirement: SNTR-RPC-002, SNTR-RPL-012 (accepted RFC 0004 D2).
- Preconditions: ACTIVE; `id=7` outstanding (no terminal result yet). Applicable persistent Syntra carriers (TCP/TLS, WS/WSS, SC1); RFC 0004 D3 exempts independent HTTP/HTTPS exchanges — including every HTTP/2 stream, which is a per-exchange carrier (SNTR-HTTPS-041) — so per-exchange transport profiles skip this case.
- Input: the harness admits the first `Frame{id=7, request{...}}` and starts its Echo handler with the terminal-result commitment held behind a test-controlled barrier, then injects a second `Frame{id=7, request{...}}` while the first is outstanding. The invalid duplicate stimulus is harness-injected; a conforming client never generates a duplicate ID, and the initiator-side discipline (RFC 0004 D1) stays a separate client obligation.
- Deterministic coordination (manifest `duplicate_while_pending: {barrier: first_terminal_result, release_after: violation_and_closure}`): the barrier is released only after the host detects the duplicate through the high-water rule, records the local violation, and termination of the connection is processed. No timing sleeps and no prose-only assumptions; without the barrier the first Echo could commit before detection, making "no result under ID 7" a scheduling prediction instead of a testable assertion.
- Expected output: the duplicate is detected and rejected at admission (`N <= high-water H`) — never dispatched, never admitted — so nothing executes for it and no result is sent under the offending ID (no duplicate attempt and no zero-ID error). The manifest asserts `error.carriage: local_only` and `expected.frames: []`: the host records `FAILED_PRECONDITION` locally, with no Syntra response Frame emitted in this controlled scenario. The original RPC's peer-visible outcome becomes unknown (connection-loss mapping, e.g. `UNAVAILABLE`; MUST NOT be reported as success); already committed outcomes stay committed — the barrier guarantees none was, and closure is not rollback, so it retracts nothing. This fixture deliberately controls the race; it does not strengthen RFC 0004 D2 for implementations outside the fixture.
- Expected connection state: CLOSED (via violation).
- Expected session state: terminated abnormally.
- Mandatory/optional: Mandatory.

## CONF-RPC-005 unknown response ID

- Related normative requirement: SNTR-RPC-§4 (result for unknown ID).
- Preconditions: ACTIVE; no outstanding RPC with `id=99`.
- Input: peer sends `Frame{id=99, result{payload}}` (simulate via test harness acting as host).
- Expected output: locally ignored with a diagnostic; no error storm, no state change, no completion signaled to any caller.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-RPC-006 unknown method

- Related normative requirement: SNTR-RPC-001, SNTR-RPC-030, SNTR-ERR-002 (`UNIMPLEMENTED`), SNTR-ERR-020.
- Preconditions: ACTIVE.
- Input: `Frame{id=11, request{method=/example.Unknown/Call, payload, timeout}}`.
- Expected output: `Frame{id=11, result{error{UNIMPLEMENTED, generic message}}}`; no handler dispatch.
- Expected connection state: ACTIVE, usable.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-RPC-007 invalid method shape and oversize envelope

- Related normative requirement: SNTR-RPC-001, SNTR-WIRE-005/006, SNTR-SER-007, SNTR-ERR-002.
- Preconditions: ACTIVE.
- Input: (a) malformed paths (`example.Echo`, `/example`, `/a/b/c`, empty, with spaces/control chars); (b) a serialized `Frame` of exactly MAX+1 bytes (1,048,577).
- Expected output: (a) `INVALID_ARGUMENT` without dispatch; (b) `RESOURCE_EXHAUSTED` (or connection closure where unbounded pre-handshake); no panic, no unbounded allocation.
- Expected connection state: ACTIVE for (a); per policy for (b).
- Expected session state: unchanged for (a).
- Mandatory/optional: Mandatory.

## CONF-RPC-008 deadline expiry

- Related normative requirement: SNTR-RPC-004, SNTR-REL-006, SNTR-ERR-002 (`DEADLINE_EXCEEDED`).
- Preconditions: ACTIVE; handler deliberately slower than the budget (or injected clock).
- Input: `Frame{id=9, request{Echo, timeout_ms=100}}` with handler exceeding 100 ms.
- Expected output: `Frame{id=9, result{error{DEADLINE_EXCEEDED}}}`; handler effects unknown; initiator surfaces expiry distinctly from application errors.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-RPC-009 cancellation race

- Related normative requirement: SNTR-RPC-005, SNTR-RPC-021/031, SNTR-ERR-002 (`CANCELLED`).
- Preconditions: ACTIVE with an outstanding slow RPC `id=12`.
- Input: (a) `Frame{id=12, cancel}` before completion; (b — separate run) `cancel` arriving after the result was already determined; (c) `cancel` for unknown/completed `id=77`.
- Expected output: (a) `Frame{id=12, result{error{CANCELLED}}}`; (b) the success result wins (completion wins); (c) ignored with no error. Exactly one terminal result in every run; never a rollback claim.
- Expected connection state: ACTIVE throughout.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory. (The cancel-vs-deadline simultaneous race is the open tie-break B10 and is NOT asserted here.)

## CONF-RPC-010 malformed result without outcome

- Related normative requirement: SNTR-RPC-002, SNTR-ERR-004.
- Preconditions: ACTIVE with outstanding RPC `id=14`.
- Input: responder emits `Frame{id=14, result}` with neither payload nor error selected (client-side protocol violation).
- Expected output: client reports local `INVALID_ARGUMENT` for that RPC, never success; no error response on the wire is required.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory (client role only).

## CONF-RPC-011 idempotent retry with fresh request ID

- Related normative requirement: SNTR-RPC-007, SNTR-RPC-010, SNTR-REL-003/004.
- Preconditions: ACTIVE, then abrupt transport loss before any `result`; a new connection is established (connection_lost precondition).
- Input: original `Frame{id=100, request{Echo, op-key "op-ABC"}}` whose outcome was never observed; retried on the new connection as `Frame{id=201, request{Echo, same op-key bytes}}`.
- Expected output: fresh `request_id` on the new connection (201 ≠ 100 — the ID space dies with the connection, SNTR-RPC-010), operation-key bytes preserved bit-exact inside the opaque payload, server behavior matches its documented dedup policy; the core never deduplicates by `request_id` and `request_id` is never an idempotency key across connections. Outcome-unknown loss is retried only for idempotent/with-key operations (SNTR-REL-003/004).
- Expected connection state: ACTIVE.
- Expected session state: active.
- Mandatory/optional: Mandatory.

## CONF-RPC-012 connection loss before response

- Related normative requirement: SNTR-HS-014, SNTR-REL-009, SNTR-CORE-005, SNTR-ERR-002 (`UNAVAILABLE`).
- Preconditions: ACTIVE with at least one in-flight RPC.
- Input: abrupt transport loss before any `result`.
- Expected output: `UNAVAILABLE` to every in-flight RPC; outcome reported as unknown; MUST NOT be reported as success or as proof of non-execution.
- Expected connection state: CLOSED (via loss).
- Expected session state: terminated abnormally; reconnect assumes no continuity.
- Mandatory/optional: Mandatory.

## CONF-RPC-013 concurrency floor with out-of-order completion

- Related normative requirement: SNTR-RPC-002, SNTR-RPC-008, SNTR-REL-007.
- Preconditions: ACTIVE; host supports the ≥16 floor (SNTR-RPC-008; no negotiated mode below 16 — RFC 0005 D2).
- Input: 16 simultaneously outstanding `Echo` requests with ids 21–36, each carrying a distinct opaque payload (rpc-p21 … rpc-p36); the initiator sends all of them without waiting. Harness barrier semantics (`reverse_completion_order: {barrier: all_admitted}`): the host releases no result until every request is admitted (all 16 outstanding simultaneously), then completes them in strictly descending id order.
- Expected output: exactly 16 terminal results observed out of request order (ids 36–21); each result echoes its requester's exact payload bytes (identical-echo assertion), so a result delivered under the wrong request_id fails the fixture even before payload-content checks; each correlated exactly once with the echoed payload; initiator correlates solely by request_id and MUST NOT assume FIFO. Excess above the documented maximum is rejected with `RESOURCE_EXHAUSTED` while conformant traffic continues (SNTR-RPC-008).
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.
- Scope: this case executes persistent connection multiplexing (TCP/TLS, WS/WSS, SC1), machine-readable via its manifest `applicable_transports: [tcp_tls, ws_wss]` (SC1 multiplexes within the `ws_wss` family). It MUST NOT be interpreted as requiring any HTTP exchange to carry 16 concurrent RPCs: each HTTP/HTTPS exchange is one logical connection with one RPC (SNTR-HTTP-070; RFC 0004 D3), the HTTP minimums are transport-owned (SNTR-HTTP-072 listener endpoint groups; SNTR-HTTPS-041 HTTP/2 streams), and an HTTP/HTTPS-only claim reports `SKIP` for this case citing the `applicable_transports` key (conformance README §6).

## Traceability

| Test | Requirement family |
|---|---|
| CONF-RPC-001 | RPC-001/002/003/006, WIRE-001/002 (model, correlation) |
| CONF-RPC-002 | RPC-002/008, REL-007 (concurrency) |
| CONF-RPC-003 | RPC-002 (ordering by ID) |
| CONF-RPC-004 | RPC-002, RPL-012 (duplicate ID connection violation) |
| CONF-RPC-005 | RPC-§4 (unknown result ID) |
| CONF-RPC-006 | RPC-001/030, ERR-002 (unknown method) |
| CONF-RPC-007 | RPC-001/030, WIRE-005/006, SER-007 (validation, bounds) |
| CONF-RPC-008 | RPC-004, REL-006 (deadlines) |
| CONF-RPC-009 | RPC-005/021/031 (cancellation) |
| CONF-RPC-010 | RPC-002, ERR-004 (malformed result without outcome) |
| CONF-RPC-011 | RPC-007/010, REL-003/004 (idempotent retry, fresh request ID) |
| CONF-RPC-012 | HS-014, REL-009 (loss) |
| CONF-RPC-013 | RPC-002/008 (16 floor, out-of-order) |
