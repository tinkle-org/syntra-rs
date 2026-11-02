# Test Vectors — WebSocket / Secure WebSocket

Vectors in this directory are deterministic structural fixtures for `CONF-WS-*` and `CONF-WSS-*`.
Actual `Frame` protobuf bytes depend on the negotiated schema in `proto/syntra/v1/*.proto`;
the hex below shows the WS-layer bytes (Upgrade text and RFC 6455 framing) with the
`Frame` payload described by field layout rather than frozen bytes, so that a
serialization change does not silently invalidate the transport assertions.
What IS frozen: paths, schemes, headers, opcodes, masking direction, close codes,
fragmentation shape, the oversize boundary (MAX+1), and the no-length-prefix rule.

Files:

- `vectors.md` — Upgrade bytes, binary-message framing, fragmentation, Ping/Pong,
  close handshake, oversize boundary, and the no-length-prefix negative proof.
- `close-codes.md` — normative close-code mapping table with wire values.
- WSS-only TLS fixtures (certificates, chains, revocation) are referenced by
  harness name from `specifications/security/*` and are never embedded here;
  no private key material appears in this repository.

All payloads use neutral methods (`/example.Echo/Echo`, `/example.KV/Get`) and
opaque byte payloads. No credential-pattern strings appear in any Upgrade target,
query, or header in these vectors (negative-grep clean).
