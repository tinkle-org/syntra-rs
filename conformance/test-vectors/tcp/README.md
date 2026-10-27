# TCP framing test vectors

Exact byte vectors for the `SNTR-TCP-V1` stream framing (`specifications/transports/tcp.md` §13). The complete table with expected handling lives in the spec; this directory provides the machine-readable copy.

- [`vectors.json`](vectors.json) — V1–V9 with `wire_hex` (length prefix + payload as transmitted), expected decodings, and handling. V1, V2, and empty-payload decodings were verified with `buf convert` against `compatibility/v1-initial/image.json`.
- Canonical encodings assume field-ordered Protobuf output; parsers MUST also accept field-reordered equivalents (V2 proves this for the `hello` unit) and MUST NOT assume byte-identical output across encoders.
- V4 is a construction recipe (1,048,576-byte valid `Frame`); V6–V8 require no following payload bytes — rejection happens on the prefix or at EOF.
