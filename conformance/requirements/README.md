# Human-readable transport conformance cases — index

Test-case IDs use transport prefixes (`CONF-TCP-*`, `CONF-TLS-*`,
`CONF-HTTP-*`, `CONF-HTTPS-*`, `CONF-WS-*`, `CONF-WSS-*`). They are **test
identifiers, not normative requirement IDs**: normative force stays with the
cited `SNTR-*` requirements. The machine-readable equivalents in
`conformance/manifest/transport-*.yaml` share these IDs one-to-one and are
authoritative for runners.

| File | Cases | Profile |
|---|---|---|
| `tcp.md` | CONF-TCP-001…008 | SNTR-TCP-V1 (restricted development only) |
| `tls-tcp.md` | CONF-TLS-001…004 | SNTR-TLS-TCP-V1 |
| `http.md` | CONF-HTTP-001…018 | SNTR-HTTP-V1 (restricted development only) |
| `https.md` | CONF-HTTPS-001…014 | SNTR-HTTPS-H1-V1 + SNTR-HTTPS-H2-V1 |
| `websocket.md` | CONF-WS-001…017 | SNTR-WS-V1 (restricted development only) |
| `secure-websocket.md` | CONF-WSS-001…010 (+ the WS suite run over `wss://`) | SNTR-WSS-H1-V1 |

Core/session/RPC/event prose companions live in `conformance/rpc/`,
`conformance/auth-session/`, `conformance/errors/`, and
`conformance/events/`; their machine-readable forms are
`conformance/manifest/{core,session,rpc,events}.yaml`. Negative security
cases (`CONF-SEC-001…011`) live only as manifests in
`conformance/manifest/security.yaml`, traced from
`specifications/security/test-plan.md`.
