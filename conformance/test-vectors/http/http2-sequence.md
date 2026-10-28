# Test vectors — HTTPS/H2 concurrent-stream sequence

Normative binding: `specifications/transports/https.md` §1E–§1F. Logical envelopes reuse `request-response-examples.md` (V-HTTP-REQ-01 shape with `request_id` 7 and 8). Stream IDs below are H2 transport artifacts: the harness MUST assert they never appear in any Syntra field. `:status` delivery follows the status-mapping matrix over H2 response headers.

```mermaid
sequenceDiagram
  participant C as Initiator
  participant H as Host
  Note over C,H: TLS 1.3 established; ALPN=h2; chain + hostname verified;<br/>no Syntra bytes sent before verification
  C->>H: HEADERS stream=1: POST https://syntra.example/syntra/v1/rpc<br/>(Syntra-Min/Max-Version: 1, Authorization, Content-Type)
  C->>H: DATA stream=1: Frame{v=1, id=7, request{/example.Echo/Echo, A, 500ms}}
  C->>H: HEADERS stream=3: POST https://syntra.example/syntra/v1/rpc<br/>(same headers, independent credential evaluation)
  C->>H: DATA stream=3: Frame{v=1, id=8, request{/example.KV/Get, B, 500ms}}
  Note over H: Handler for id=8 finishes first
  H-->>C: HEADERS stream=3: :status=200 (Content-Type, Syntra-Version: 1, no-store)
  H-->>C: DATA stream=3: Frame{v=1, id=8, result{B-result}}
  H-->>C: HEADERS stream=1: :status=200
  H-->>C: DATA stream=1: Frame{v=1, id=7, result{A-result}}
  Note over C: Completion order 8-before-7 is legal;<br/>correlate by echoed id only; streams 1,3 hold no session
```

## Failure overlays (same streams, alternate endings)

- **REFUSED_STREAM on stream 5 (fresh request):** initiator reports definitely-not-executed; retry with fresh `request_id` + identical operation-key bytes is conformant (vectors S-24).
- **`RST_STREAM` on stream 1 mid-response:** initiator discards stream 1, reports `UNAVAILABLE` (unknown outcome), retries only if idempotent/with-key (vectors S-25).
- **`GOAWAY` with streams 1 and 3 in flight:** both report `UNAVAILABLE`; no new streams on the draining connection; reconnect repeats both operations with fresh streams, fresh `request_id`s, repeated op keys (CONF-HTTPS-010).
- **`PUSH_PROMISE` from the host:** initiator sends `RST_STREAM`, parses nothing, reports a transport diagnostic — push is never a Syntra event (CONF-HTTPS-012).
- **Cross-profile replay:** presenting stream-1's credential context on an H1 connection (or vice versa) as continuity is rejected as unnegotiated resumption — each stream/exchange re-authenticates independently (CONF-HTTPS-012/014).
