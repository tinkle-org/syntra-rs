# Test vectors — HTTP transport (`conformance/test-vectors/http/`)

Byte-level fixtures for the HTTP/HTTPS transport bindings. All vectors use neutral methods (`/example.Echo/Echo`, `/example.KV/Get`) and throwaway credentials. Base64 is RFC 4648 §4 standard alphabet. Serialized `Frame`s below are canonical encodings; decoders MUST accept any valid non-canonical encoding of the same logical message (SNTR-SER-002/901) — vectors assert logical equality, never byte equality, on receipt.

- [Request/response examples](request-response-examples.md) — raw HTTP/1.1 messages with real `Frame` bodies, success and error envelopes, binding-error responses.
- [Status mapping matrix](status-mapping.md) — stimulus → status/body/local-code rows for harness automation.
- [HTTP/2 sequence](http2-sequence.md) — concurrent-stream exchange with out-of-order completion.
