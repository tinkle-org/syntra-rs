# Carrier and context fixtures

These fixtures are maintained here. `transport.yaml` retains the TCP inner frame bound
and the RFC 6455 control bytes and close codes from `tcp/byte-vectors.yaml` and
`websocket/fixtures.yaml` at `tinkle-org/syntra` commit `8ede3810b29fbba4d0e6ae6751a0025ceedda140`.
`ws-no-length-prefix.hex` is the `frame_hex` input from `websocket/VEC-WS-009` in
that same revision. It is a valid, unprefixed Protobuf `ClientHello` envelope. Its entry in
`transport.yaml` pins the digest of the decoded bytes, independent of line endings.

`context-cases.json` keeps the carrier-specific recipe lists from `conformance/manifest/connection.yaml`
at `3f7e8ea037fefcc5c86101d23e7722c83e28a0d3`; `syntra-1.0-context.json` contains their public
context and prologue bytes and mutations. The context check exercises the local Rust parser,
not all preconditions and outcomes of those manifest cases. No external checkout is needed.

`wss-scenarios.yaml` contains the local exchanges and their expected observations.
The execution adapter encodes their hello and request frames as Protobuf, then checks the
Rust host's observations. The recovery control payloads are `RecoveryNegotiateRequest`
and `RecoverySubscribeRequest` from `proto/syntra/v1/recovery_profile.proto`.
