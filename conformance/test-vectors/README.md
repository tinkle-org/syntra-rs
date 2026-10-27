# Conformance test vectors — index and conventions

Deterministic, implementation-neutral fixtures. All payloads use neutral
methods (`/example.Echo/Echo`, `/example.KV/Get`, `/example.Events/Subscribe`)
and opaque byte payloads. Hosts are `syntra.example` / `example.com`;
credentials are throwaway (`opaque-test-credential-A`). No production name,
credential, or key material appears anywhere in this directory.

| Directory | Section | Contents |
|---|---|---|
| `protobuf/` | §J | Golden logical encodings (human + hex + semantic fields), protoc-verified |
| `tcp/` | §K | Exact `[length][protobuf]` wire bytes (`vectors.json`, `byte-vectors.yaml`) |
| `http/` | §L | Request/response fixtures, status matrix, H2 sequence |
| `websocket/` | §M | Upgrade, binary framing, fragmentation, Ping/Pong, close codes |

Conventions:

- Base64 is RFC 4648 §4 standard alphabet.
- Protobuf assertions are **logical equality** (decoded fields), never byte
  equality across encoders — except a TCP prefix plus its chosen fixture bytes,
  which are byte-exact for that fixture.
- No raw TLS byte vectors are defined (TLS is negotiated, not frozen).
  Certificate fixtures are harness-named references (`test-pki:*`) owned by
  `specifications/security/*`; no PEM or key bytes are embedded here.
- Vector IDs are stable: `protobuf/GOLD-PROT-*`, `tcp/V1…V12`, `http/V-HTTP-*`
  and `http/X-HTTP-*`, `websocket/VEC-WS-*`. Manifests cite them in
  `vector_refs`; runners resolve them by ID, never by copying bytes by hand.
