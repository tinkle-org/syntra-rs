# Protected browser connection procedures

`syntra-web` provides a protected Syntra 1.0 WSS connection through the default
`browser-connection` feature. `connect(url, credential, options)` requires
`ConnectionOptions` containing an independently provisioned Noise public-key
pin, key id and scope. Bootstrap uses NK; returning mode adds the authorization
key, handle and epoch for NKpsk0. Credentials travel in encrypted ClientHello.
The exact endpoint is `/syntra/1.0/ws` and subprotocol is `syntra.1.0`; there is
no plaintext connect API or fallback. See [CONNECTION.md](../../../CONNECTION.md)
for current encryption and connection guidance.

`client.rs` is native-only runtime fixture coverage. Native tests and WASM
compilation do not establish browser execution. The procedures below distinguish
kernel browser tests, synthetic carrier faults and real browser WSS. Record actual
results and skipped cases for each boundary exercised.
The [unified implementation-evidence runner](../../../CONTRIBUTING.md#implementation-evidence)
does not execute these browser procedures; its browser gate stays `NOT_EXECUTED`.
Record browser observations separately with their implementation revision and
candidate provenance.

## Build the browser artifacts

Run from the workspace root with Rust 1.88.0 and its `wasm32-unknown-unknown`
target installed. Install `wasm-bindgen-cli` at the **exact `wasm-bindgen` version
in `Cargo.lock`**; it supplies both `wasm-bindgen` and
`wasm-bindgen-test-runner`. Node.js and Python 3 are also required.

```sh
export RUSTUP_TOOLCHAIN=1.88.0
sh crates/syntra-web/tests/build-browser.sh
```

The script builds release WASM twice and generates web modules:

- `target/syntra-browser-production/syntra_web.js`: built with
  `--no-default-features --features browser-connection`.
- `target/syntra-browser-fixture/syntra_web.js`: built with
  `--features browser-test-fixture`; used only for the synthetic peer.

`WASM_BINDGEN` can select the CLI executable. The script runs
`check-wasm-imports.mjs` on both artifacts, rejecting unresolved `env` imports,
missing connection exports and test-peer exports in the production artifact.
Do not substitute dummy imports to get a module to load. Keep fixture features
out of production artifacts.

Serve the workspace in a separate terminal:

```sh
python3 -m http.server 8765 --bind 127.0.0.1
```

Use a browser context with the fixture page visible throughout execution.
The driver retires connections on hidden/pagehide events and unknown elapsed
continuity. The pages require a window/document and browser randomness.

## Record-protection kernel in a browser

```sh
sh crates/syntra-web/tests/run-kernel-browser.sh
```

This script selects `wasm-bindgen-test-runner` and sets
`WASM_BINDGEN_USE_BROWSER=1` for `syntra-core` library tests on WASM, including
`syntra_core::secure_channel`.
Provide the browser/WebDriver setup required by that runner, or set
`NO_HEADLESS=1` and visit its printed test URL in a normal browser. Override
the executable with `WASM_BINDGEN_TEST_RUNNER` if needed; arguments passed to
the script are forwarded to `cargo test`. Record the actual test verdict.
These tests do not open a real WSS connection.

## Synthetic carrier and browser lifecycle faults

After building and serving the workspace, open:

```text
http://127.0.0.1:8765/crates/syntra-web/tests/connection-browser.html?module=/target/syntra-browser-production/syntra_web.js&fixtureModule=/target/syntra-browser-fixture/syntra_web.js
```

`connection-browser.js` loads the production-feature client and a separate
same-library peer. It temporarily replaces `WebSocket` with a synthetic carrier.
Cases include bootstrap/returning segmented echo, wrong pin/PSK, endpoint and
subprotocol rejection, invalid records, bounded queues, stalled establishment
and writes, partial-frame deadlines, clock discontinuity, pagehide and cleanup.
Some cases deliberately wait 15–31 seconds; allow the whole sequence to finish
before collecting results.

Inspect the displayed JSON and `window.syntraEvidence`: `passed`, `skipped` and
`failed` are separate lists. `document.documentElement.dataset.result` is
`pass` when there are no failures **even if cases were skipped**. This harness
always lists missing durable-store and real-device evidence. Without optional
`wss` configuration it also skips real WSS. Synthetic successes do not establish
TLS or independent cryptographic interoperability.

The optional `wss` URL, 64-hex-character public `pin`, `keyId` (default 0) and
`scope` (default `browser-fixture`) query parameters enable one real bootstrap
echo after the synthetic sequence. Use the dedicated page below to exercise
both real WSS modes. Never place application credentials or authorization keys
in URLs.

## Real browser WSS: bootstrap and returning

Provide a PEM certificate chain and private key **already trusted by the test
browser**, valid for the loopback host used in the URL. The fixture does not
install trust anchors or bypass certificate validation. Start these commands
in two separate terminals, replacing the PEM paths:

```sh
cargo run --locked -p syntra-web --features wss-test-fixture --example browser_wss_fixture -- /path/to/trusted-cert.pem /path/to/trusted-key.pem 127.0.0.1:9443 bootstrap
```

```sh
cargo run --locked -p syntra-web --features wss-test-fixture --example browser_wss_fixture -- /path/to/trusted-cert.pem /path/to/trusted-key.pem 127.0.0.1:9444 returning
```

The example accepts loopback listeners only and terminates TLS directly with
`TlsServerSettings`. Each process generates and prints a fresh public Noise
pin. Copy each pin into its corresponding page parameter; do not learn a
production pin from a connecting peer. The harness uses key id 0, scope
`browser-fixture`, and public, fixed returning-mode test inputs defined in
`connection-wss.js` and the example. Use only fixture data with these servers.

With the workspace HTTP server still running, open the following URL after
replacing both pin placeholders with the printed 64-character hexadecimal pins:

```text
http://127.0.0.1:8765/crates/syntra-web/tests/connection-wss.html?expect=verified&bootstrapUrl=wss://127.0.0.1:9443/syntra/1.0/ws&bootstrapPin=BOOTSTRAP_PIN&returningUrl=wss://127.0.0.1:9444/syntra/1.0/ws&returningPin=RETURNING_PIN
```

If the certificate names `localhost` instead, use that host in the WSS URLs.
URL-encode parameter values when necessary. `browser.html` loads the same
`connection-wss.js` harness and accepts the same parameters.

The page loads the production module by default (`module` may override its
URL), performs encrypted establishment and a 180,000-byte segmented echo in
each mode, then closes the owner and checks the client registry. Inspect the
JSON and `window.syntraWssEvidence`. A missing endpoint or pin is recorded as
`skipped`; require **both modes** in `passed` and no failures for a complete
positive run. The dataset result can be `pass` with one mode skipped, or `skip`
when neither mode ran. Stop the example processes with Ctrl-C after collection.

### Untrusted certificate rejection

OpenSSL is required. After the build script has created the fixture directory,
generate the negative fixture and start its listener:

```sh
sh crates/syntra-web/tests/make-untrusted-cert.sh
sh crates/syntra-web/tests/run-untrusted-listener.sh
```

The generator refuses to overwrite existing PEM files. Both scripts accept an
optional output-directory argument; the directory must already exist. The
listener binds `127.0.0.1:9443`, so stop the positive bootstrap server first.
Do not install this self-signed certificate into a root store. This listener is
an OpenSSL TLS 1.3 HTTP responder, not a successful Upgrade or Syntra peer.

Open `connection-wss.html` with `expect=untrusted`, a `bootstrapUrl` of
`wss://127.0.0.1:9443/syntra/1.0/ws` and a syntactically valid, nonzero 32-byte
public `bootstrapPin` in hex. To exercise both mode branches, also set
`returningUrl` to that same listener and supply a valid public `returningPin`.
The pins are validation inputs only; no Noise handshake should be reached.
Require the corresponding rejection results in `window.syntraWssEvidence`.
The page asserts one dial per attempt and zero `WebSocket.send` calls before
rejection, including no M1/ClientHello and no fallback. Record browser certificate
diagnostics alongside the result: an unreachable listener alone is not evidence
that certificate validation rejected a live TLS server.

## Limits and evidence boundaries

`connection::Limits::default()` sets a 15-second total attempt budget, a shared
5-second Noise/hello establishment budget, 30-second next-record and partial-frame
budgets, a 10-second frame-write budget, a 1-second owner-close budget and a
24-hour lifetime. Receive queues are bounded to 32 messages and 256KiB after
browser message assembly; the output `bufferedAmount` threshold is 128KiB.
These are application-owned bounds, not caps on browser/network allocations
before delivery of a message event.

The driver also retires a connection when the gap between observations exceeds
two seconds, before allowing buffered work to proceed. This can happen during a
long main-thread task even on a visible page. It is separate from the kernel's
dual-clock disagreement tolerance and the record/frame timeout budgets above.

TLS version/certificate policy, implicit cookies, Upgrade inspection and control
frames are browser-controlled. The client rejects negotiated extensions, but
cannot disable the browser's compression offer. Deployment must enforce direct
host TLS termination, TLS 1.3+, cookie rejection, disabled compression and an
Origin policy. The example's echo success does not validate that complete
deployment policy. `connection_support()` exposes the implementation's current
support disclosure, including browser durable-store and secret-erasure limits.
Record the source revision/worktree, tool versions, browser, fixture mode and
actual failures/skips. These procedures alone do not establish full conformance,
OS suspend behavior, soak/energy budgets or independent security review.
