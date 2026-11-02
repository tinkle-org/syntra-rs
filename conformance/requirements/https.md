# Conformance — HTTPS/H1 and HTTPS/H2 (`CONF-HTTPS-001…014`)

Related normative requirements are cited per case; test IDs are not normative. All cases Mandatory. Neutral fixtures only. Every envelope assertion reuses the `conformance/test-vectors/http/` vectors: the logical `Frame`s MUST be byte-identical across HTTPS/H1 and HTTPS/H2 (only framing differs). TLS fixtures use throwaway test PKI, never production roots or credentials.

## CONF-HTTPS-001 HTTPS/H1 success

- Related normative requirement: SNTR-HTTPS-001/010/030, SNTR-HTTP-001/020.
- Preconditions: valid test chain for the endpoint name; TLS 1.3 negotiated.
- Input: the CONF-HTTP-001 exchange over HTTPS/H1.
- Expected output: `200` with the `FRAME_RES_OK` logical result, `Syntra-Version: 1`, `Cache-Control: no-store`; chain + hostname verified before the credential was sent (harness asserts no credential bytes preceded verification).
- Mandatory/optional: Mandatory.

## CONF-HTTPS-002 HTTPS/H2 success

- Related normative requirement: SNTR-HTTPS-001/020/040, SNTR-HTTP-020.
- Preconditions: ALPN negotiates `h2`.
- Input: one RPC on stream 1 (`FRAME_REQ` equivalent), `:method POST`, `:path /syntra/v1/rpc`, full headers.
- Expected output: `:status 200` with the identical logical result as CONF-HTTPS-001; stream ends after the single response (no half-close tricks, no trailers carrying Syntra semantics).
- Mandatory/optional: Mandatory.

## CONF-HTTPS-003 concurrent H2 streams, out-of-order completion

- Related normative requirement: SNTR-HTTPS-041/042/043.
- Input: SIXTEEN concurrent streams on one transport connection (odd client stream IDs 1..31), each with a distinct `request_id` (21–36) and a distinct opaque payload; the harness admits all sixteen streams before releasing any terminal outcome, then the host completes them in strictly descending `request_id` order.
- Expected output: initiator correlates by echoed `request_id` only; no FIFO, stream-ID, or priority-order assumption; each `200` envelope echoes its own stream's payload bit-exactly under the same echoed `request_id`; stream IDs never appear in any Syntra field (negative check on wire traces); excess beyond the host's documented maximum rejects pre-dispatch with `429`/`503` or post-acceptance with `200` + `RESOURCE_EXHAUSTED`.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-004 invalid chain rejected before any credential

- Related normative requirement: SNTR-HTTPS-010/011, SNTR-TSEC-003.
- Input: (a) self-signed-untrusted chain; (b) wrong-chain; (c) malformed certificate on a secure profile.
- Expected output: TLS handshake fails; no HTTP request and no credential bytes are sent (harness packet capture); local report `UNAVAILABLE` to waiters; no plaintext fallback attempted.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-005 wrong hostname and expired certificate

- Related normative requirement: SNTR-HTTPS-012, SNTR-TSEC-004.
- Input: (a) chain-valid certificate for a different name (SAN mismatch); (b) expired certificate.
- Expected output: rejection before credential presentation in both; chain-validity alone never suffices; no credential disclosure.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-006 TLS below 1.3 refused; no plaintext fallback

- Related normative requirement: SNTR-HTTPS-010/013, SNTR-TSEC-002/007.
- Input: (a) server offers only TLS 1.2 (harness); (b) TLS failure followed by an implementation-level retry attempt.
- Expected output: (a) negotiation fails; (b) no automatic retry over plaintext and no weaker-version retry by the implementation — fail closed, credentials undisclosed.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-007 ALPN mismatch fails closed

- Related normative requirement: SNTR-HTTPS-020/021.
- Input: client offers only `http/1.1` against an H2-only endpoint (and separately only `h2` against an H1-only endpoint); plus non-TLS bytes on the TLS port.
- Expected output: connection fails (no protocol confusion, no fallback to an unintended binding); ALPN plays no auth role (no principal accepted on ALPN grounds).
- Mandatory/optional: Mandatory.

## CONF-HTTPS-008 rotation accepted; pinning absent

- Related normative requirement: SNTR-HTTPS-014, SNTR-TSEC-006.
- Input: server rotates to a new chain-valid certificate mid-test-window (overlap), initiator connects during overlap and after.
- Expected output: both connect (no hard-coded leaf pinning); rotation required no protocol version change.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-009 REFUSED_STREAM is safe; other resets are unknown

- Related normative requirement: SNTR-HTTPS-051, SNTR-HTTP-080/082.
- Input: (a) host answers `REFUSED_STREAM` for a fresh stream; (b) host resets a stream mid-response with `CANCEL`/`INTERNAL_ERROR`-class code after dispatch.
- Expected output: (a) initiator MAY report definitely-not-executed and retry with fresh `request_id` + same op key; (b) initiator reports `UNAVAILABLE` (outcome unknown) and retries only if idempotent/with-key. The two MUST NOT be conflated (negative check: (b) never treated as proof of non-execution).
- Mandatory/optional: Mandatory.

## CONF-HTTPS-010 GOAWAY drains; no new streams

- Related normative requirement: SNTR-HTTPS-051.
- Input: server sends `GOAWAY` with two streams in flight, then tears down.
- Expected output: in-flight streams report `UNAVAILABLE` (unknown outcome); initiator opens no new streams on the draining connection; reconnect uses fresh streams, fresh `request_id`s, repeated op keys.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-011 proxy mismatch rejected

- Related normative requirement: SNTR-HTTPS-060, SNTR-TSEC-008.
- Input: (a) TLS-terminating proxy with an insecure/plaintext backend leg presented as secure; (b) mismatched SNI/`:authority` between front and backend; (c) `X-Forwarded-*` headers claiming a different principal.
- Expected output: binding failure (handshake/binding error, close) in (a) and (b); in (c) forwarded headers are ignored for auth (per-request `Authorization` alone decides; cross-principal use denied).
- Mandatory/optional: Mandatory.

## CONF-HTTPS-012 push refused; cross-profile non-resumption

- Related normative requirement: SNTR-HTTPS-045/070, SNTR-HTTP-130.
- Input: (a) host sends `PUSH_PROMISE` for a Syntra resource; (b) present an H1-established credential/session context on an H2 connection (and vice versa) as continuity.
- Expected output: (a) initiator refuses (`RST_STREAM`), parses nothing as `Frame`/event; (b) rejected as unnegotiated resumption (`401`/`FAILED_PRECONDITION`-class binding failure + close per profile); sessions never span profiles in default v1.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-013 response-authenticated layering holds on H2

- Related normative requirement: SNTR-HTTPS-052, SNTR-HTTP-040/041/042.
- Input: over H2, (a) unknown-method RPC; (b) `404`-equivalent bad `:path`; (c) bit-flipped `200` body injected by the harness.
- Expected output: (a) `:status 200` + `result{error{UNIMPLEMENTED}}`; (b) `:status 404` with no envelope; (c) discarded as `UNAVAILABLE`, never success. Status-vs-envelope discipline is identical to H1.
- Mandatory/optional: Mandatory.

## CONF-HTTPS-014 per-stream auth isolation on shared connections

- Related normative requirement: SNTR-HTTPS-031/043, SNTR-HTTP-064/065/071.
- Input: streams 1 and 3 on one H2 connection (and two exchanges on one H1 keep-alive connection) with different credentials — principal P, then principal Q, then no credential.
- Expected output: each stream/exchange evaluated independently (P's work, Q's work, anonymous-per-policy); Q's credential never authorizes P's stream and vice versa; connection/TLS-session reuse implies no principal and no session.
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-HTTPS-001/002/003 | HTTPS-001/020/030/040–043 (profiles, streams, ordering) |
| CONF-HTTPS-004/005/006 | HTTPS-010–013 (TLS validation, downgrade refusal) |
| CONF-HTTPS-007 | HTTPS-020/021 (ALPN) |
| CONF-HTTPS-008 | HTTPS-014 (rotation) |
| CONF-HTTPS-009/010 | HTTPS-050/051 (stream/connection failures) |
| CONF-HTTPS-011 | HTTPS-060/061 (proxies, posture) |
| CONF-HTTPS-012 | HTTPS-045/070 (exclusions, cross-profile) |
| CONF-HTTPS-013 | HTTPS-052 + HTTP-040–042 (H2 layering) |
| CONF-HTTPS-014 | HTTPS-031/043 + HTTP-064/065/071 (isolation) |
