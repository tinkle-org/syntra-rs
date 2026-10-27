# Real browser fixture

`client.rs` is native-only. It uses in-memory runtime fixtures and does not
prove browser WebSocket behavior. `browser.html` runs actual generated
`syntra-web` exports in a browser, including JS rejection paths.

Prerequisites: build `syntra-web` with `wasm-pack build --target web` (or the
equivalent matching wasm-bindgen CLI), serve the generated module/WASM and
this HTML from a trusted local HTTP(S) origin, and provide three trusted WSS
endpoints. No browser runner or generated WASM assets are bundled here.

Run the opt-in native fixture with:

```sh
cargo test --locked -p syntra-ws --test browser_fixture -- --ignored --nocapture
```

It listens only on loopback ports 19781 (normal echo), 19782 (MAX+1 binary
after ready), and 19783 (stalled Upgrade). Put a locally trusted TLS reverse
proxy in front of those three ports; configure its Origin policy to permit
the page and its Upgrade timeout above 12 seconds for the stalled fixture.
The plaintext legs are loopback-only test traffic, not production endpoints.
The fixture accepts one connection per port and exits after they finish;
restart it for each browser run. Its total lifetime is bounded to 60 seconds.

Open the HTML with these explicit query parameters (URL-encode each value):

- `module`: URL of the generated `syntra_web.js` module (CORS must permit it).
- `normal`: trusted WSS URL proxying port 19781 at `/syntra/v1/ws`.
- `oversize`: trusted WSS URL proxying port 19782 at `/syntra/v1/ws`.
- `stall`: trusted WSS URL proxying port 19783 at `/syntra/v1/ws`.

The page displays PASS/FAIL and sets `document.documentElement.dataset.result`
for an external browser runner. An omitted endpoint is a failure, not a skip.
The fixture supplies empty Syntra credentials (empty `ClientHello.credential`)
and appends no query strings to the endpoint URLs; it cannot prevent
browser-managed cookies/credentials the browser attaches for the endpoint
origin during the WebSocket handshake — use an isolated endpoint origin if a
credential-free handshake is required. It checks
that oversized input is rejected locally and closes the transport, not that
the browser emits 1009: browser JS cannot choose 1009 and cannot cap assembly
or the ws_stream_wasm internal receive queue. Browser TLS version/certificate
policy is browser-controlled. This fixture is not full WSS conformance.
