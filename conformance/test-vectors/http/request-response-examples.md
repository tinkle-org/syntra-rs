# Test vectors — HTTP request/response examples

Conventions: `Frame` field numbers are `version=1, request_id=2, request=12, result=13`; `RpcRequest` fields `method=1, payload=2, timeout_ms=3`; `RpcResult` outcome `payload=1, error=2`; `RpcError` fields `code=1, message=2`. `ErrorCode UNIMPLEMENTED = 12`. The sample credential is the ASCII bytes `opaque-test-credential-A` (24 bytes), base64 `b3BhcXVlLXRlc3QtY3JlZGVudGlhbC1B`. It is a throwaway fixture, never a production secret.

## Vector V-HTTP-REQ-01 — request envelope

Logical value: `Frame{version=1, request_id=7, request{method="/example.Echo/Echo", payload="hello", timeout_ms=500}}`.

- Hex: `08011007621e0a122f6578616d706c652e4563686f2f4563686f120568656c6c6f18f403`
- Base64 (36 bytes): `CAEQB2IeChIvZXhhbXBsZS5FY2hvL0VjaG8SBWhlbGxvGPQD`

## Vector V-HTTP-RES-OK-01 — success envelope

Logical value: `Frame{version=1, request_id=7, result{payload="hello"}}`.

- Hex: `080110076a070a0568656c6c6f`
- Base64 (13 bytes): `CAEQB2oHCgVoZWxsbw==`

## Vector V-HTTP-RES-ERR-01 — error envelope

Logical value: `Frame{version=1, request_id=7, result{error{code=12, message="unknown method"}}}`.

- Hex: `080110076a141212080c120e756e6b6e6f776e206d6574686f64`
- Base64 (26 bytes): `CAEQB2oUEhIIDBIOdW5rbm93biBtZXRob2Q=`

## Exchange X-HTTP-01 — canonical success (HTTP/1.1)

Request (body is the 36 raw bytes of V-HTTP-REQ-01, shown as base64 for readability):

```http
POST /syntra/v1/rpc HTTP/1.1
Host: syntra.example
Content-Type: application/vnd.syntra.v1+protobuf
Content-Length: 36
Syntra-Min-Version: 1
Syntra-Max-Version: 1
Authorization: Syntra b3BhcXVlLXRlc3QtY3JlZGVudGlhbC1B
Cache-Control: no-store

CAEQB2IeChIvZXhhbXBsZS5FY2hvL0VjaG8SBWhlbGxvGPQD
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: application/vnd.syntra.v1+protobuf
Content-Length: 13
Syntra-Version: 1
Cache-Control: no-store

CAEQB2oHCgVoZWxsbw==
```

Initiator checks: status `200`, response `Content-Type` exact, `Syntra-Version: 1` equals envelope `version`, echoed `request_id == 7`, `outcome` set → success payload `hello`.

## Exchange X-HTTP-02 — application error stays 200

Same request shape, method `/example.Unknown/Call`. Response:

```http
HTTP/1.1 200 OK
Content-Type: application/vnd.syntra.v1+protobuf
Content-Length: 26
Syntra-Version: 1
Cache-Control: no-store

CAEQB2oUEhIIDBIOdW5rbm93biBtZXRob2Q=
```

The `UNIMPLEMENTED` verdict is inside the envelope. A harness MUST fail if this exchange ever surfaces as `404`/`500`.

## Exchange X-HTTP-03 — bad credential is 401 with no envelope

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Syntra realm="syntra"
Content-Length: 0
Cache-Control: no-store
```

Empty body. The initiator MUST NOT parse a body here and MUST report local `UNAUTHENTICATED` without synthesizing a `RpcResult`.

## Exchange X-HTTP-04 — oversize body is 413 without reading

Request declares `Content-Length: 1048577` (MAX+1). Response (body never read):

```http
HTTP/1.1 413 Content Too Large
Content-Length: 0
Cache-Control: no-store
```

## Exchange X-HTTP-05 — wrong media type is 415

Request with `Content-Type: application/octet-stream`. Response:

```http
HTTP/1.1 415 Unsupported Media Type
Content-Length: 0
Cache-Control: no-store
```

## Exchange X-HTTP-06 — anonymous attempt

Request identical to X-HTTP-01 minus the `Authorization` header. Against an anonymous-accepting host the response is a `200` envelope bound to a least-privilege anonymous principal for that exchange only; against a denying host it is X-HTTP-03. Either way, no state carries to the next exchange.
