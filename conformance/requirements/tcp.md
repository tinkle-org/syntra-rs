# Conformance — TCP framing (`CONF-TCP-001…008`)

Test-case IDs use the `CONF-TCP-*` prefix. They are **test identifiers, not normative requirement IDs**: normative force stays with the cited `SNTR-TCP-*` (and core/security) requirements. Location `conformance/requirements/` holds the transport conformance cases; shared byte vectors live in `conformance/test-vectors/tcp/`.

All cases use neutral envelopes (verified `hello` vectors; echo RPC where ACTIVE is required). “Pass” MUST NOT be reported unless executed with logs.

## CONF-TCP-001 connection establishment

- Related normative requirement: SNTR-TCP-002, SNTR-HS-002, SNTR-TCP-007.
- Preconditions: server listening on the profile port; client initiates TCP.
- Input: TCP active open; start the handshake timer; send exactly one length-prefixed `Frame{hello}` (vector V1) as the first bytes (no magic).
- Expected output: connection reaches NEGOTIATING; host validates version then credential; no data required before the first prefix.
- Expected connection state: CONNECTED → NEGOTIATING.
- Expected session state: none yet.
- Mandatory/optional: Mandatory.

## CONF-TCP-002 frame parsing

- Related normative requirement: SNTR-TCP-004, SNTR-TCP-006, SNTR-SER-002.
- Preconditions: vector V1 (canonical) and V2 (reordered) from `conformance/test-vectors/tcp/vectors.json`.
- Input: send V1; separately send V2.
- Expected output: both decode to the identical logical `Frame{version:1, hello{min_version:1, max_version:1}}`; V2 MUST be accepted (order tolerance); handshake proceeds identically.
- Expected connection state: NEGOTIATING (then per policy).
- Expected session state: none yet.
- Mandatory/optional: Mandatory.

## CONF-TCP-003 partial reads

- Related normative requirement: SNTR-TCP-006.
- Preconditions: ACTIVE or pre-handshake reader loop (either; no read-size assumption).
- Input: deliver V1 one byte at a time (including splitting inside the 4-byte prefix).
- Expected output: the unit is accepted once complete; no timeout, no error, no resync behavior.
- Expected connection state: unchanged by the delivery pattern.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-TCP-004 multiple frames

- Related normative requirement: SNTR-TCP-006, SNTR-RPC-002.
- Preconditions: ACTIVE with echo available.
- Input: send two complete request units back-to-back in one write (V3 pattern applied to RPC requests `id=7`, `id=8`).
- Expected output: two terminal results, each correlated exactly once, in any order.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-TCP-005 invalid length

- Related normative requirement: SNTR-TCP-005, SNTR-TCP-006 (§5/§7), SNTR-WIRE-002.
- Preconditions: any state.
- Input: (a) zero-length prefix V5; (b) short length V9 (prefix smaller than the sender's intended bytes).
- Expected output: (a) reject as malformed; close in all states. (b) strict framing: first unit parsed as its counted bytes (invalid envelope → core-table handling), remainder framed as the next unit; MUST NOT rescan for plausibility.
- Expected connection state: (a) CLOSED; (b) per the parsed units' validation outcome.
- Expected session state: (a) none/ended; (b) per outcome.
- Mandatory/optional: Mandatory.

## CONF-TCP-006 oversized frame

- Related normative requirement: SNTR-TCP-005, SNTR-WIRE-006, SNTR-SER-006.
- Preconditions: any state; instrumentation (or allocator accounting) proving no payload-sized allocation.
- Input: oversized prefix V6 (`00 10 00 01`, max+1) with no payload bytes following.
- Expected output: rejection on the prefix alone, before allocating the declared payload; immediate connection termination in all states.
- Expected connection state: CLOSED.
- Expected session state: none/ended.
- Mandatory/optional: Mandatory.

## CONF-TCP-007 invalid envelope

- Related normative requirement: SNTR-TCP-§7 table, SNTR-WIRE-003, SNTR-SER-007/008.
- Preconditions: ACTIVE (for per-RPC rows) and pre-`ACTIVE` (for close rows); fixtures: bodyless unit, `request_id` misuse, unknown variant, reserved tag 16/17, malformed method.
- Input: each fixture as one framed unit.
- Expected output: `INVALID_ARGUMENT` / `FAILED_PRECONDITION` / `UNIMPLEMENTED` / reserved-malformed handling per the core tables; handshake-phase rows close; `ACTIVE` per-RPC rows keep the connection usable.
- Expected connection state: per row (CLOSED pre-`ACTIVE`; ACTIVE for per-RPC rows).
- Expected session state: per row.
- Mandatory/optional: Mandatory.

## CONF-TCP-008 connection close

- Related normative requirement: SNTR-TCP-009, SNTR-TCP-010, SNTR-HS-006/013/014, SNTR-SESS-004, SNTR-REL-009.
- Preconditions: ACTIVE with one in-flight RPC and (where claimed) one subscription.
- Input: (a) graceful FIN sequence after stopping new RPCs; (b) abrupt RST/loss; (c) half-close (`shutdown(SHUT_WR)`) from the peer.
- Expected output: (a) in-flight RPCs get `UNAVAILABLE` or `CANCELLED`, no new RPCs, teardown to CLOSED; (b) `UNAVAILABLE` with unknown outcome; subscriptions end; (c) treated as end-of-stream with no special semantics — process buffered units, then close fully; half-open retention is bounded by the close grace timer.
- Expected connection state: CLOSED in all rows.
- Expected session state: ended in all rows; reconnect requires a fresh handshake.
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-TCP-001 | TCP-002/007, HS-002 (establishment, first unit) |
| CONF-TCP-002 | TCP-004/006, SER-002 (parsing, order tolerance) |
| CONF-TCP-003 | TCP-006 (partial reads) |
| CONF-TCP-004 | TCP-006, RPC-002 (concatenated units) |
| CONF-TCP-005 | TCP-005/006 (length edge cases) |
| CONF-TCP-006 | TCP-005, WIRE-006 (oversize fail-closed) |
| CONF-TCP-007 | TCP-§7, WIRE-003, SER-007/008 (invalid envelope) |
| CONF-TCP-008 | TCP-009/010, HS-006/013/014 (close paths) |
