# Conformance — session lifecycle (`CONF-SESS-001…010`, Optional `CONF-SESS-R01`)

Related normative requirements are cited per case; test IDs are not normative. Cases 001…010 are Mandatory. Neutral fixtures only. Resumption-success is not claimed in default v1: these resume cases assert rejection. The manifest also defines Optional `CONF-SESS-R01`, gated on `resume-v1`; it is skipped while that capability is unclaimed.

## CONF-SESS-001 successful session creation

- Related normative requirement: SNTR-SESS-001, SNTR-HS-004, SNTR-AUTH-005, SNTR-AUTH-007.
- Preconditions: secure transport established and verified (or loopback-restricted development); host supports wire version 1; credential valid per application policy.
- Input: `Frame{version=max, request_id=0, hello{min_version=1, max_version=1, credential=opaque-valid}}`.
- Expected output: exactly one `Frame{version=1, request_id=0, ready{connection_id}}` with fresh opaque `connection_id`; no application effect beyond binding.
- Expected connection state: ACTIVE.
- Expected session state: active; session equals the connection (SNTR-SESS-003); principal bound (SNTR-AUTH-007).
- Mandatory/optional: Mandatory.

## CONF-SESS-002 authentication rejection

- Related normative requirement: SNTR-AUTH-006, SNTR-AUTH-009, SNTR-HS-004.
- Preconditions: version overlap exists; credential invalid (and separately: expired, revoked, valid-but-unauthorized).
- Input: `Frame{hello{credential=opaque-invalid}}` (each sub-case separately).
- Expected output: handshake failure carrying `UNAUTHENTICATED` (invalid/expired/revoked) or `PERMISSION_DENIED` (valid but unauthorized); generic message; no credential echo; no principal oracle beyond the documented code distinction.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: none; nothing resumable.
- Mandatory/optional: Mandatory (all four sub-cases).

## CONF-SESS-003 request before ACTIVE

- Related normative requirement: SNTR-HS-012, SNTR-WIRE-003, SNTR-CORE-011.
- Preconditions: handshake started; connection in CONNECTED, NEGOTIATING, or AUTHENTICATING (no `ready` received).
- Input: `Frame{request_id=7, request{/example.Echo/Echo, payload, timeout_ms}}` before ACTIVE (variants: `cancel`, `notification`).
- Expected output: handshake failure carrying `FAILED_PRECONDITION` (local reporting + closure; exact pre-ACTIVE carrier is blocker B1 — MUST close, MUST NOT dispatch, MUST NOT emit zero-`request_id` `result`); authorization hooks MUST NOT be bypassed.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-SESS-004 expired session

- Related normative requirement: SNTR-SESS-005, SNTR-AUTH-008.
- Preconditions: session ACTIVE with a credential/principal subject to a documented max lifetime; lifetime elapses (injected clock or short-lived fixture credential).
- Input: expiry elapses; then `Frame{request_id=9, request{/example.Echo/Echo}}`.
- Expected output: expiry signaled as `UNAUTHENTICATED` (binding withdrawn) or `UNAVAILABLE` (host shutdown); never silent; affected RPCs fail; connection closes by default.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: withdrawn; not resumable without a negotiated resumption capability (none in default v1).
- Mandatory/optional: Mandatory.

## CONF-SESS-005 invalid session credential

- Related normative requirement: SNTR-SESS-006, SNTR-SESS-020.
- Preconditions: new transport connected; no resumption capability negotiated.
- Input: `Frame{request_id=0, hello{min_version=1, max_version=1, credential=prior_connection_id}}`; repeat with stale/unknown resume bytes presented as a credential/token.
- Expected output: `UNAUTHENTICATED` + close; connection identity MUST NOT authenticate a principal; no session established.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-SESS-006 graceful close

- Related normative requirement: SNTR-HS-006, SNTR-HS-013, SNTR-SESS-004.
- Preconditions: session ACTIVE; optionally one in-flight RPC.
- Input: either peer initiates graceful close; no new RPCs; observe transport-profile grace period; teardown.
- Expected output: in-flight RPCs receive `UNAVAILABLE` or `CANCELLED`; no new RPCs accepted; no `CloseSession` message exists or is required.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: terminated normally; per-connection state discarded except diagnostics.
- Mandatory/optional: Mandatory.

## CONF-SESS-007 abrupt transport loss

- Related normative requirement: SNTR-HS-014, SNTR-SESS-004, SNTR-REL-009.
- Preconditions: session ACTIVE with at least one in-flight RPC.
- Input: abrupt transport loss (no close handshake).
- Expected output: `UNAVAILABLE` to all in-flight RPCs; outcome reported as unknown; MUST NOT be reported as application success.
- Expected connection state: CLOSED (via loss, not via CLOSING handshake).
- Expected session state: terminated abnormally; no continuity assumed on reconnect (SNTR-SESS-008).
- Mandatory/optional: Mandatory.

## CONF-SESS-008 resume rejected without capability

- Related normative requirement: SNTR-SESS-006, SNTR-SESS-020, SNTR-RPL-011.
- Preconditions: default v1 (no resumption capability negotiated).
- Input: on a new connection, present stale resume bytes (unknown, expired, or wrong-audience) in `hello.credential`.
- Expected output: rejection with `UNAUTHENTICATED` + close; no session established. Note: `FAILED_PRECONDITION` is acceptable only as an optional alternative for non-fixture presentations and is not required to pass the manifest fixture.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: none; client MUST start a fresh handshake with a fresh credential.
- Mandatory/optional: Mandatory.

## CONF-SESS-009 replayed resume credential

- Related normative requirement: SNTR-RPL-011, SNTR-ASEC-008, SNTR-SESS-006.
- Preconditions: default v1 (no resumption RFC exists, so no valid token can exist); attacker replays any previously observed resume-shaped bytes on a new connection.
- Input: present `fixture:replayed-resume-bytes` in `hello.credential`; repeat the presentation twice.
- Expected output: `UNAUTHENTICATED` + close; reuse MUST NOT yield a session; event rate-limited as suspected replay where repeated.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: none.
- Mandatory/optional: Mandatory (as a rejection test; resumption-success testing is Optional and requires an approved resumption RFC + capability ID, which does not exist).

## CONF-SESS-010 unsupported protocol version

- Related normative requirement: SNTR-HS-003, SNTR-HS-010, SNTR-VER-002.
- Preconditions: transport connected; host supports v1 only; initiator range disjoint from host support.
- Input: `Frame{request_id=0, hello{min_version=2, max_version=2}}`; repeat with other disjoint ranges per the manifest notes.
- Expected output: handshake failure carrying `UNIMPLEMENTED` + close; no credential evaluation; no downgrade retry by the implementation.
- Expected connection state: CLOSING then CLOSED.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-SESS-R01 resume accepted (Optional)

- Related normative requirement: SNTR-SESS-006.
- Preconditions: new transport connected; approved `resume-v1` capability claimed.
- Input: `Frame{request_id=0, hello{min_version=1, max_version=1, credential=rfc_resume_token}}`.
- Expected output: resume accepted with principal re-binding and fresh request-ID space; no implicit restoration of RPCs, subscriptions, or cursors.
- Expected connection state: ACTIVE.
- Expected session state: active.
- Mandatory/optional: Optional, gated on `resume-v1`; SKIP in default v1 because no resumption RFC exists.

## Traceability

| Test | Requirement family | Wire fixture |
|---|---|---|
| CONF-SESS-001 | SESS-001, HS-004, AUTH-005/007 | hello→ready, fresh connection_id |
| CONF-SESS-002 | AUTH-006/009, HS-004 | invalid/expired/revoked/unauthorized credentials |
| CONF-SESS-003 | HS-012, WIRE-003, CORE-011 | pre-ACTIVE request/cancel/notification |
| CONF-SESS-004 | SESS-005, AUTH-008 | lifetime expiry then RPC |
| CONF-SESS-005 | SESS-006/020 | connection_id-as-credential, stale/unknown tokens |
| CONF-SESS-006 | HS-006/013, SESS-004 | graceful close with in-flight RPC |
| CONF-SESS-007 | HS-014, SESS-004, REL-009 | abrupt loss with in-flight RPC |
| CONF-SESS-008 | SESS-006/020, RPL-011 | stale/unknown/expired/wrong-audience resume bytes |
| CONF-SESS-009 | RPL-011, ASEC-008, SESS-006 | replayed resume bytes |
| CONF-SESS-010 | HS-003/010, VER-002 | disjoint version ranges |
| CONF-SESS-R01 | SESS-006 | RFC-defined resume token (Optional; SKIP in default v1) |
