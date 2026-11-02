# Conformance — HTTP/1.1 RPC mapping (`CONF-HTTP-001…018`)

Related normative requirements are cited per case; test IDs are not normative. All cases Mandatory. Neutral fixtures only (`/example.Echo/Echo`, `/example.KV/Get`). Unless a case states otherwise, run over the loopback plaintext profile (development-only) AND over HTTPS/H1; every `200`-envelope assertion MUST hold byte-identically (same logical `Frame`s) on both, per SNTR-WIRE-901/SNTR-HTTP-901. Credential fixtures use throwaway opaque bytes, never production credentials.

## CONF-HTTP-001 canonical success

- Related normative requirement: SNTR-HTTP-001/010/011/020/021/030/031.
- Preconditions: endpoint serves `POST /syntra/v1/rpc`; method `/example.Echo/Echo` exists; credential valid per policy.
- Input: `POST /syntra/v1/rpc` with `Content-Type: application/vnd.syntra.v1+protobuf`, `Syntra-Min-Version: 1`, `Syntra-Max-Version: 1`, `Authorization: Syntra <base64-valid>`, `Cache-Control: no-store`, body = `FRAME_REQ` vector (request `id=7`, `/example.Echo/Echo`, payload `hello`, `timeout_ms=500`).
- Expected output: `200` with `Content-Type: application/vnd.syntra.v1+protobuf`, `Syntra-Version: 1`, `Cache-Control: no-store`, body = one `Frame{v=1, id=7, result{payload=hello}}` (byte-equal to `FRAME_RES_OK` up to non-canonical encoding equivalence; logical equality REQUIRED).
- Expected connection state: exchange complete; no Syntra state retained.
- Expected session state: none retained (per-request independence).
- Mandatory/optional: Mandatory.

## CONF-HTTP-002 wrong method

- Related normative requirement: SNTR-HTTP-002.
- Input: `GET` (and separately `PUT`, `OPTIONS` without CORS deployment) on the exact path with otherwise valid headers/body.
- Expected output: `405` with `Allow: POST`; body empty-or-ignored; no envelope dispatched.
- Mandatory/optional: Mandatory.

## CONF-HTTP-003 wrong path and trailing slash

- Related normative requirement: SNTR-HTTP-002.
- Input: (a) `POST /syntra/v1/rpc2`; (b) `POST /syntra/v1/RPC` (case); (c) `POST /syntra/v1/rpc/` (trailing slash).
- Expected output: `404` in all three; no normalization of (c) to the canonical path; no dispatch.
- Mandatory/optional: Mandatory.

## CONF-HTTP-004 query rejection

- Related normative requirement: SNTR-HTTP-003/005.
- Input: `POST /syntra/v1/rpc?next=/x` (and separately with a credential-shaped query `?credential=AAAA`).
- Expected output: `400`; no dispatch; query material never logged as credential; negative grep of logs for the query value.
- Mandatory/optional: Mandatory.

## CONF-HTTP-005 wrong content type

- Related normative requirement: SNTR-HTTP-011.
- Input: valid envelope body with (a) missing `Content-Type`; (b) `application/octet-stream`; (c) the canonical type plus `; charset=utf-8`.
- Expected output: `415` in all three, before body parsing.
- Mandatory/optional: Mandatory.

## CONF-HTTP-006 malformed body and trailing bytes

- Related normative requirement: SNTR-HTTP-020/021, SNTR-SER-007.
- Input: (a) truncated varint body; (b) decodable Protobuf that is not a `request` envelope (`ready` variant bytes); (c) valid `FRAME_REQ` followed by 4 extra bytes.
- Expected output: `400` in all three; no dispatch; no panic; no unbounded allocation.
- Mandatory/optional: Mandatory.

## CONF-HTTP-007 oversized body

- Related normative requirement: SNTR-HTTP-110/111/112/114.
- Input: (a) `Content-Length: 1048577` (MAX+1) with valid headers; (b) chunked body streaming past MAX+1 bytes.
- Expected output: `413` in both; for (a) the server MUST NOT read the body; for (b) the server aborts the read at the bound. Exactly-MAX body (1048576) is accepted for dispatch (boundary fixture).
- Mandatory/optional: Mandatory.

## CONF-HTTP-008 version mismatch and bad version headers

- Related normative requirement: SNTR-HTTP-030/031.
- Input: (a) `Syntra-Min-Version: 2, Syntra-Max-Version: 3` against a v1-only host; (b) `min=3, max=2` (inverted); (c) missing version headers; (d) request `Frame.version=2` disagreeing with `Max-Version: 1`.
- Expected output: `400` in all four, without credential evaluation or dispatch.
- Mandatory/optional: Mandatory.

## CONF-HTTP-009 missing credential per policy

- Related normative requirement: SNTR-HTTP-060/061/064.
- Input: no `Authorization` header (anonymous attempt) against (a) a host that accepts anonymous, (b) a host that denies anonymous.
- Expected output: (a) `200` with bound anonymous principal for that exchange only; (b) `401` with `WWW-Authenticate: Syntra realm="..."`. No principal oracle beyond the documented policy distinction.
- Mandatory/optional: Mandatory (both sub-cases).

## CONF-HTTP-010 invalid, malformed, and expired credential

- Related normative requirement: SNTR-HTTP-060/061/062/063.
- Input: (a) unknown opaque credential; (b) `Authorization: Bearer <x>` (foreign scheme); (c) `Authorization: Syntra !!!not-base64!!!`; (d) expired credential; (e) revoked credential.
- Expected output: `401` with `WWW-Authenticate` in all five; generic message; credential bytes absent from body, headers (other than the echoed scheme), logs, and diagnostics (negative grep).
- Mandatory/optional: Mandatory.

## CONF-HTTP-011 normal RpcError over 200 (layering)

- Related normative requirement: SNTR-HTTP-040/041, SNTR-ERR-§1D.
- Input: valid exchange invoking (a) unknown method `/example.Unknown/Call`; (b) unauthorized method for the bound principal; (c) handler that exceeds `timeout_ms=100`.
- Expected output: `200` in all three with bodies (a) `result{error{UNIMPLEMENTED}}`, (b) `result{error{PERMISSION_DENIED}}`, (c) `result{error{DEADLINE_EXCEEDED}}` (byte-check shape per `FRAME_RES_ERR` pattern). No `4xx`/`5xx` used for any handler verdict; `500` never appears.
- Mandatory/optional: Mandatory.

## CONF-HTTP-012 binding-status layering (no synthesized results)

- Related normative requirement: SNTR-HTTP-040/041/042/043.
- Input: force each of `400`, `401`, `404`, `405`, `413`, `415`, `429`, `503` (via the corresponding malformed/overload fixture), plus a `200` with a corrupted body (bit-flipped vector) injected between host and initiator.
- Expected output: initiator reports a transport failure for every case, synthesizes NO `RpcResult`, and surfaces the documented local code (`INVALID_ARGUMENT`/`UNAUTHENTICATED`/`UNIMPLEMENTED`/`RESOURCE_EXHAUSTED`/`UNAVAILABLE` per table); the corrupted-`200` case reports `UNAVAILABLE` (unknown outcome), never success.
- Mandatory/optional: Mandatory.

## CONF-HTTP-013 concurrent exchanges independent and unordered

- Related normative requirement: SNTR-HTTP-070/071/072/073.
- Input: SIXTEEN concurrent exchanges against one listener endpoint group, each carried on its own separate pooled HTTP/1.1 connection, each with a distinct `request_id` (21–36), a distinct opaque payload (rpc-p21..rpc-p36; the reuse exchange adds rpc-p37), and its own throwaway credential fixture (A/B across the batch, C on the reused-ID exchange, A/B across the pipelined rows — per-exchange declarations on the input side, no case-level default); the harness admits all sixteen before releasing any terminal outcome, and the host completes them in strictly descending `request_id` order. The exchanges MUST NOT be pipelined on one connection: HTTP/1.1 returns pipelined responses in request order, so a shared pipelined connection would make per-exchange descending completion unverifiable (the order would merely mirror request order). A final sequential exchange reuses `id=21` with a fresh payload. Pipelining is tested by a separate sub-case WITHOUT requiring reversed response order: several exchanges pipelined on one keep-alive connection must still correlate each response by its echoed `request_id` and MUST NOT merge state across exchanges (SNTR-HTTP-071); pipelined responses returning in request order is HTTP/1.1-correct and not a violation of SNTR-HTTP-072.
- Expected output: results correlate by echoed ID only (reverse order accepted); each `200` envelope echoes its own exchange's payload bit-exactly under the same echoed `request_id`; the reused ID is a new unrelated correlation (no duplicate rejection across exchanges, no cross-exchange request-ID memory). Expected result rows carry only the emitted `result` Frame's own keys (`request_id`, `body`, `payload_b64`): `syntra.v1.Frame` has no credentials field, and the harness associates each result with its originating exchange by the echoed `request_id`. The assertion that a distinct payload is echoed identically proves response-to-exchange association and state isolation; it does not by itself prove which credential subject each handler bound — that would need a principal-sensitive authorization assertion (exchange-level credential evaluation stays with CONF-HTTP-009/CONF-HTTP-010).
- Mandatory/optional: Mandatory.

## CONF-HTTP-014 retry and idempotency discipline

- Related normative requirement: SNTR-HTTP-080/081/082.
- Input: (a) connection loss before any response for an operation carrying op-key bytes `ABC` in the payload, then a retry exchange with fresh `request_id` and bit-identical key bytes; (b) `503` on first attempt of an idempotent read, then retry; (c) `400` on a malformed attempt, then corrected re-issue as a new decision (not a blind retry).
- Expected output: (a) key bytes preserved bit-exact; server behavior matches its documented dedup policy; (b) retry succeeds; (c) no automatic retry loop; `401`-after-identical-retry fixture shows bounded backoff, never a tight loop.
- Mandatory/optional: Mandatory.

## CONF-HTTP-015 redirect non-following and cache headers

- Related normative requirement: SNTR-HTTP-100/101, SNTR-HTTP-090/091.
- Input: (a) endpoint answers `307` to a new origin (test harness); (b) inspect request/response headers of a success exchange.
- Expected output: (a) initiator terminates with transport outcome `UNAVAILABLE` without re-sending the request or credential (no second request observed by the harness); (b) request and response both carry `Cache-Control: no-store`; response carries no `ETag`/`Last-Modified`; no `304` is ever sent for the endpoint.
- Mandatory/optional: Mandatory.

## CONF-HTTP-016 compression rejected by default

- Related normative requirement: SNTR-HTTP-120/121.
- Input: (a) request with `Content-Encoding: gzip` (opaque gzip bytes body); (b) request with `Accept-Encoding: gzip` against default deployment.
- Expected output: (a) `415`; (b) response carries no `Content-Encoding` (identity). Where a deployment documents compression, the capped-bomb fixture (decompressed bytes past bound → `413`) MUST pass instead.
- Mandatory/optional: Mandatory.

## CONF-HTTP-017 no event push; upgrade refused

- Related normative requirement: SNTR-HTTP-130/131.
- Input: (a) `Upgrade: websocket` on the endpoint; (b) hold a valid exchange open and observe whether any unsolicited bytes arrive outside the single response.
- Expected output: (a) `400`; (b) exactly one response per request; no `Notification` frames, no SSE framing, no second response. Polling-via-RPC (application-defined read) works as an ordinary second exchange.
- Mandatory/optional: Mandatory.

## CONF-HTTP-018 CORS is policy, never authorization

- Related normative requirement: SNTR-HTTP-140/141.
- Input: (a) browser-shaped request with `Origin: https://evil.example` against a CORS-enabled deployment; (b) `OPTIONS` preflight on the endpoint; (c) omit `Authorization` but supply an `Origin` allow-listed value.
- Expected output: (a) no `Access-Control-Allow-Origin: *` with credentials, no reflected origin outside the allow-list; (b) preflight handled only where the deployment documents it, otherwise `405`; (c) still `401`/anonymous-per-policy — CORS headers alone authorize nothing.
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-HTTP-001 | HTTP-001/010/011/020/021/030/031 (canonical exchange) |
| CONF-HTTP-002/003/004 | HTTP-002/003/005 (target discipline) |
| CONF-HTTP-005/006/007 | HTTP-011/020/021/110–114 (type, shape, bounds) |
| CONF-HTTP-008 | HTTP-030/031 (version synthesis) |
| CONF-HTTP-009/010 | HTTP-060–064 (auth carriage) |
| CONF-HTTP-011/012 | HTTP-040–043 (status layering) |
| CONF-HTTP-013 | HTTP-070–073 (session independence) |
| CONF-HTTP-014 | HTTP-080–082 (retry/idempotency) |
| CONF-HTTP-015 | HTTP-090/091/100/101 (cache, redirects) |
| CONF-HTTP-016 | HTTP-120/121 (compression) |
| CONF-HTTP-017 | HTTP-130/131 (no push) |
| CONF-HTTP-018 | HTTP-140/141 (CORS) |
