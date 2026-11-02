# Conformance — error taxonomy, distinction, retry, unknown codes (`CONF-ERR-001…004`)

Related normative requirements are cited per case; test IDs are not normative. All cases Mandatory. Neutral fixtures only.

## CONF-ERR-001 RpcError taxonomy and message hygiene

- Related normative requirement: SNTR-ERR-001, SNTR-ERR-002, SNTR-ERR-003, SNTR-ERR-010/011/020/021, SNTR-ASEC-011/024.
- Preconditions: ACTIVE; fixtures capable of producing each of the 16 nonzero codes at least once via neutral operations (echo, generic key/value, validation, authz, overload, deadline, loss simulation).
- Input: drive each code at least once; capture every `RpcError{message}` and all logs/traces/wire dumps.
- Expected output: only defined nonzero codes emitted; `message` human-readable, generic, with no credentials, tokens, stack traces, paths, SQL text, secret identifiers, private diagnostics, or raw untrusted bytes (negative grep); client branches on `code`, never on `message` text.
- Expected connection state: per the code (usable except binding withdrawal/loss).
- Expected session state: unchanged except where the code withdraws the binding (`UNAUTHENTICATED`).
- Mandatory/optional: Mandatory.

## CONF-ERR-002 protocol error versus RPC error distinction

- Related normative requirement: SNTR-ERR-004, SNTR-WIRE-003/004/011, SNTR-HS-012, SNTR-RPC-001/030.
- Preconditions: one connection in handshake phase, one session ACTIVE.
- Input: (a) malformed envelope on the handshake connection (empty body, zero-`request_id` `request`, second `hello`); (b) valid `Frame{id=11, request{/example.Unknown/Call}}` on the ACTIVE connection; (c) valid `Frame{id=12, request{/example.KV/Get, missing key}}` where NOT_FOUND is the documented mapping.
- Expected output: (a) protocol error — handshake failure + close, no dispatch, no `result`; (b) RPC error `Frame{id=11, result{error{UNIMPLEMENTED}}}` with the connection usable; (c) RPC error `Frame{id=12, result{error{NOT_FOUND}}}` with the connection usable.
- Expected connection state: (a) CLOSING→CLOSED; (b)(c) ACTIVE.
- Expected session state: (a) none; (b)(c) unchanged.
- Mandatory/optional: Mandatory.

## CONF-ERR-003 retry classification evidence

- Related normative requirement: SNTR-ERR-006, SNTR-REL-003, `rpc.md` §1I.
- Preconditions: ACTIVE; fixtures for loss, deadline, overload, auth failure, terminal application error.
- Input: for each failure class, record the code and the implementation's retry decision.
- Expected output: `UNAVAILABLE`/`DEADLINE_EXCEEDED` retried only when idempotent or operation-keyed; `RESOURCE_EXHAUSTED` retried only with backoff; terminal results (`INVALID_ARGUMENT`, `NOT_FOUND`, `PERMISSION_DENIED`, `UNIMPLEMENTED`, `CANCELLED` without re-evaluation, `INTERNAL`/`UNKNOWN` as unknown-outcome) never blindly auto-retried; no mutation classified safe-to-retry without an idempotency basis.
- Expected connection state: per the underlying failure.
- Expected session state: per the underlying failure.
- Mandatory/optional: Mandatory.

## CONF-ERR-004 unknown enum and zero-code handling

- Related normative requirement: SNTR-ERR-001, SNTR-ERR-005, SNTR-ERR-010.
- Preconditions: codec-level fixtures (synthetic bytes), no live peer required.
- Input: (a) `RpcResult{error{code=0 (UNSPECIFIED), message}}`; (b) `RpcError` with a future numeric code (e.g., 99) on the wire.
- Expected output: (a) rejected as a failure-code violation (never treated as success); (b) mapped to `UNKNOWN` for application reporting with the numeric value preserved diagnostically where possible; neither input crashes the implementation nor is treated as success.
- Expected connection state: unchanged (codec-level assertions).
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-ERR-001 | ERR-001/002/003/010/011/020/021 (taxonomy, hygiene) |
| CONF-ERR-002 | ERR-004, WIRE-003/004/011, HS-012 (protocol vs RPC) |
| CONF-ERR-003 | ERR-006, REL-003, rpc §1I (retry classification) |
| CONF-ERR-004 | ERR-001/005/010 (unknown/zero codes) |
