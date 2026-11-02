# Test vectors — status mapping matrix

Harness automation of `specifications/transports/http.md` §1E. Each row: stimulus → expected status, expected body rule, initiator local report. "No envelope" means the harness MUST fail if any bytes parse as a `Frame`. Local codes are adapter reports, never host verdicts. The `200`-envelope rows use the vectors in `request-response-examples.md`.

| # | Stimulus | Status | Body | Local report |
|---|---|---|---|---|
| S-01 | Valid `FRAME_REQ`-class exchange, handler succeeds | `200` | One `result{payload}` envelope | Envelope outcome |
| S-02 | Unknown method `/example.Unknown/Call` | `200` | One `result{error{UNIMPLEMENTED}}` envelope | Envelope outcome |
| S-03 | Method forbidden for the bound principal | `200` | One `result{error{PERMISSION_DENIED}}` envelope | Envelope outcome |
| S-04 | Handler exceeds `timeout_ms` | `200` | One `result{error{DEADLINE_EXCEEDED}}` envelope | Envelope outcome |
| S-05 | `GET` (also `PUT`, `DELETE`) on exact path | `405` + `Allow: POST` | No envelope | `UNIMPLEMENTED` |
| S-06 | `POST` to `/syntra/v1/rpc/`, `/syntra/v1/RPC`, `/syntra/v1/rpc2` | `404` | No envelope | `UNIMPLEMENTED` |
| S-07 | Any query string, incl. `?credential=...` | `400` | No envelope | `INVALID_ARGUMENT` |
| S-08 | Missing/wrong/parameterized `Content-Type` | `415` | No envelope | `INVALID_ARGUMENT` |
| S-09 | Truncated body; non-`request` variant body; trailing bytes after the `Frame` | `400` | No envelope | `INVALID_ARGUMENT` |
| S-10 | `Content-Length: 1048577`; chunked stream past bound | `413` | No envelope; body unread (declared case) | `RESOURCE_EXHAUSTED` |
| S-11 | `Syntra-Min/Max-Version` missing, malformed, inverted, or with no overlap; `Frame.version` ≠ `Max` | `400` | No envelope | `INVALID_ARGUMENT` |
| S-12 | Missing credential vs denying host; unknown/expired/revoked/malformed credential; foreign auth scheme | `401` + `WWW-Authenticate` | No envelope | `UNAUTHENTICATED` |
| S-13 | Valid credential, principal denied all access | `403` | No envelope | `PERMISSION_DENIED` |
| S-14 | Slow headers/body past window | `408` + close | No envelope | `UNAVAILABLE` (unknown) |
| S-15 | Pre-dispatch rate/concurrency/queue exhaustion | `429` | No envelope | `RESOURCE_EXHAUSTED` |
| S-16 | Oversize headers (incl. oversize `Authorization`) | `431` | No envelope | `RESOURCE_EXHAUSTED` |
| S-17 | `Content-Encoding: gzip` (default deployment) | `415` | No envelope | `INVALID_ARGUMENT` |
| S-18 | `Upgrade: websocket` on the endpoint | `400` | No envelope | `INVALID_ARGUMENT` |
| S-19 | Adapter/host crash before dispatch or during encoding | `500` | No envelope | `UNAVAILABLE` (unknown) |
| S-20 | Proxy/backend inconsistency; pre-dispatch overload/shutdown; gateway timeout | `502` / `503` / `504` | Ignored | `UNAVAILABLE` (unknown) |
| S-21 | `3xx` received on the endpoint | (as sent) | Ignored, never followed | `UNAVAILABLE` (unknown) |
| S-22 | `200` with undecodable body, trailing bytes, wrong `request_id`, version mismatch, or unset `outcome` | `200` (malformed) | Discarded | `UNAVAILABLE` (unknown), never success |
| S-23 | Connection loss mid-exchange, no status | — | — | `UNAVAILABLE` (unknown) |
| S-24 | H2 `REFUSED_STREAM` on a fresh stream (HTTPS/H2 only) | (stream error) | — | Definitely-not-executed; safe retry |
| S-25 | Any other H2 stream reset after dispatch began; `GOAWAY` with in-flight streams | (stream/conn error) | — | `UNAVAILABLE` (unknown) |

Negative invariants the harness MUST assert on every row: no `RpcResult` is ever synthesized from a non-`200`; no `500` ever carries a handler verdict; no credential-shaped material appears outside `Authorization`; error text contains no credential, token, or backend diagnostic.
