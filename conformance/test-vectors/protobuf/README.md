# Golden Protobuf vectors (Section J)

Known valid encodings for every v1 core message, verified with
`protoc --decode=syntra.v1.Frame` against `proto/syntra/v1/*.proto`.

- [`vectors.yaml`](vectors.yaml) — machine-readable: human representation,
  serialized hex, and expected semantic fields per vector.
- Task-name mapping (`ServerHello`, `Authentication`, `RpcResponse`, `Event`,
  `ProtocolError`) is documented at the top of `vectors.yaml`, because those
  names do not exist as wire types in v1 (`ServerReady`, `RpcResult`,
  `Notification`, typed errors instead).

Critical rule (SNTR-SER-002/901): these vectors assert **logical equality**
(decoded fields), never byte-identical re-emission. A conforming implementation
MUST accept field-reordered and unknown-field-bearing equivalents
(`GOLD-PROT-UNKNOWN-FIELD-01` proves tolerance). Only the TCP framing prefix
(`test-vectors/tcp/`) plus a chosen fixture payload is byte-exact — and only
for that fixture.
