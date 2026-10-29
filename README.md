# Syntra Rust

Rust implementation of Syntra v1 with generated Protobuf types, bounded
codecs, client/host runtimes, reliable-session and recovery helpers, and
experimental SC1 channels over native WSS, with opt-in development carriers.

Extracted from [`tinkle-org/syntra`](https://github.com/tinkle-org/syntra) at
[`2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`](https://github.com/tinkle-org/syntra/commit/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c).
See [MIGRATION.md](MIGRATION.md) for provenance and the path mapping.

**SC1 is an experimental implementation of the RFC 0007 section 11 canonical
context proposal, not an activated upstream profile or an independently audited
secure channel.** Its review pin is
`94404d7378136d8b6c88ece28bf945c88d1653ba`, distinct from the extraction pin
above. Read [SC1.md](SC1.md) for the wire format and source-backed API sketch,
and [AUDIT.md](AUDIT.md) for recorded results and historical evidence.
The core `Frame` schema and baseline `syntra-ws` framing/endpoints remain
unchanged; custom runtime writers must adopt the emission-gate contract below.
Schema and fixture provenance is in [MIGRATION.md](MIGRATION.md).

Use **Rust 1.88.0** for production builds and current verification. The
crate MSRV floor is **1.88**; it is a build compatibility constraint, not a
security recommendation. Production binaries must be built with a
security-patched toolchain. Current dependency pins are:

| Dependency | Version |
| --- | --- |
| `prost` | =0.13.5 |
| `snow` | =0.10.0 |
| `getrandom` | 0.3 |
| `tokio` | 1 |
| `tungstenite` / `tokio-tungstenite` | 0.26 |
| `rustls` | 0.23 |

There are no releases yet; future releases use repository-root `vX.Y.Z` tags.

## Default: native async workspace

The default build needs no CGO or native library beyond the Rust toolchain.
`cargo build` fetches crates sources only; this repository never downloads
native binaries.

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo build --locked
cargo test --locked
```

Root `default-members` excludes `syntra-integration`. Explicit `--workspace`
includes it and intentionally enables the transport's development carriers
through that crate's dependency. CI separately tests isolated WSS-only defaults
and explicit development features; a workspace run alone does not prove default
feature isolation.

## Workspace and scope

| Crate | APIs / source |
|---|---|
| `syntra-core` | Envelope codec, validation, handshake and protocol state |
| `syntra-runtime` | Transport-independent `Initiator`/`Host`, sessions, RPC correlation, notifications, recovery drivers |
| `syntra-secure-channel` | Socket-free SC1: `Context`, `ClientHandshake`, `respond`, `Channel`, `Secret32`, `KeyStore` |
| `syntra-ws` | Native WS/WSS adapters (binary-only, one message per `Frame`) |
| `syntra-sc1-transport` | Experimental, unpublished native SC1: WSS `websocket`, opt-in `ReconnectingClient`, carrier-neutral `pump`, development `tcp` and loopback WS |
| `syntra-web` | Browser-facing WASM client; native fixtures for tests |
| `syntra-ffi` | Native C ABI with explicit production and test-fixture modes |
| `syntra-integration` | Migrated Docker SC1 carrier fixtures (not published; container execution outstanding) |

`Transport` adapters exchange exactly one serialized `Frame` per pump step in
each direction. The supplied SC1 adapters add encrypted record framing and
bounded socket I/O. Upstream's production TLS baseline remains in effect;
this experimental draft does not supersede it.

`syntra-sc1-transport` replaces the prerelease `syntra-tcp` and
`syntra-ws-sc1` crates. Its default feature set is empty (`default = []`);
the default carrier API exposes WSS only. `development-carriers` adds the
restricted-development `tcp` module and plaintext loopback WS. The public
`syntra_sc1_transport::pump` has no dependency on that TCP module. This is an
intentional prerelease source/API/wire break; legacy aliases and fallback are
not supported. Baseline `syntra-ws` remains a separate Frame-per-message adapter.

Credential verification is host-owned. `Authenticator` verifies opaque hello
bytes and returns a `Principal`; `AllowAnonymous` and static-token helpers
are test/example conveniences, not credential verifiers. For SC1,
`AuthenticatorFactory::create(&VerifiedIdentity)` receives freshly confirmed
channel context and constructs the application's `Authenticator`, which still
verifies the explicit hello credential. Same-principal binding, current validity
and periodic revocation checks are host contracts, not a supplied identity system.
An empty credential never implicitly means "use the channel principal."

`Handler::authorize` runs before every method's handler effects. **The
default denies every RPC.** Use a principal-aware policy, or `AllowAll` for
an explicit allow-all deployment. A permission denial leaves the connection
usable; an expired/revoked binding reported as `UNAUTHENTICATED` withdraws
the principal, settles other calls and closes the connection.

### Dial and call

Use `syntra_sc1_transport::websocket::connect` for native WSS. Supply a
`ClientConfig` whose context binds `Carrier::SecureWebSocket`, an authenticated
Noise server pin and exact provisioned scope. The client is ready to call when
the connection succeeds:

```rust,ignore
let client = syntra_sc1_transport::websocket::connect(
    "wss://example.service/syntra/v1/sc1/ws", security, credential, runtime, limits,
).await?;
let result = client.conn.call("/example.Service/Method", b"hello".to_vec(), 1000).await?;
client.close().await;
```

The [SC1 API sketch](SC1.md#api-sketch) documents `connect_with_roots`,
`TlsServerSettings::new` and `accept_tls_stream`. The canonical endpoint is
`/syntra/v1/sc1/ws`, with exactly the `syntra.sc1.v1` subprotocol. WSS requires
verified TLS 1.3 as well as the Noise pin; TCP/WS are never automatic fallback.
The opt-in `ReconnectingClient` owns a bounded reconnect loop with explicit
`ReconnectConfig` and pause/network/wake controls. Its status receiver returns
owned current-state snapshots, and calls/results are fenced by connection
generation. `CoreReady` is not recovery readiness, and mutations are never
automatically replayed. See [the client usage contract](SC1.md#reconnecting-client)
for fresh connector inputs, retry budgets, failure classification and shutdown.

Dialing has a **15-second total connection attempt budget**, including
socket/TLS/upgrade, SC1 and core readiness. On the responder, SC1 establishment
and the client's encrypted-hello confirmation share a five-second channel limit.
The returned client's lifetime is independent of the dial future: always close it.
These low-level connect functions do not reconnect. Reconnect is opt-in through
the client wrapper; neither path automatically replays RPCs or weakens the carrier.

The development `tcp::Listener::bind(address, maximum_connections)` acquires
admission before accepting; new accept calls backpressure when the limit is
reached. Close is abortive by default and bounded; `close_gracefully` shares one
absolute grace deadline across runtime drain and carrier flush. See
[SC1.md](SC1.md#limits-cancellation-and-ownership) for ownership, budgets
and the adapter-owned graceful protocol.

After hello/ready, each host connection uses an asynchronous FIFO writer.
Queued plus active writes are bounded by the runtime writer capacity;
saturation terminates the connection with `RESOURCE_EXHAUSTED`. Each write
defaults to a ten-second timeout for one frame's complete record sequence.
Shutdown poisons cipher state, joins I/O and runs transport-loss teardown so
pending calls settle as unknown outcomes.

Custom initiator writers must pass each **original `Vec<u8>`** dequeued from
the byte-pump receiver, without cloning or reallocating, to
`Initiator::prepare_outbound` exactly once immediately before synchronous
carrier handoff/encryption. `None` skips a stale item; `Some(bytes)` carries
the live request with floored positive remaining milliseconds. Finish that
unit in order or abort the carrier. Never re-gate fragments or ciphertext.
The receiver still yields one serialized `Frame` per `Vec`; see
[SC1.md](SC1.md#runtime-emission-gate) for the handoff contract.

Application payload schemas, identity systems, messenger subscriptions,
presence, JSON gateways, service discovery and gRPC clients are outside the
workspace's scope. There is no HTTP/HTTPS request-response transport
planned; HTTP is used for the WebSocket upgrade. UDP is deferred.
Reliable-session helpers do not claim exactly-once effects or make arbitrary
RPC retries safe. Recovery cursors and payloads stay opaque; the helpers are
not a complete subscription/recovery service.

### Resource and compatibility behavior

- A serialized frame is limited to 1 MiB, including envelope overhead. A
  payload at a separate application limit can therefore fail encoding.
  Failed request encoding does not reserve a call slot or start its timer.
- The runtime host admits a notification only while its bounded queue has
  capacity. Saturation drops the newest notification and counts it; terminal
  RPC results remain admissible. Only successful enqueues wake notification
  waiters. No matching subscription work is claimed beyond carriage.
- SC1 limits ciphertext records to 65,535 bytes and plaintext to 65,519
  bytes; the encrypted frame stream may span records. Lifetime is at most 24
  hours or 2^32 records per direction. Pending transport operations are
  bounded by writer/notification capacities, each `1..1024`. See
  [SC1.md](SC1.md) for exact clocks, cancellation requirements and
  revocation checks.
- Unknown fields alongside a known body are tolerated. Unknown top-level
  content without a known body yields `UNIMPLEMENTED`; a genuinely empty body
  yields `INVALID_ARGUMENT`. Body tags are 10–15; 16–17 remain reserved.
  Reserved tags, duplicate oneof alternatives, malformed unknown wire data
  and nesting beyond depth 32 are rejected by the bounded codec on decode
  and emission; opaque payload bytes are not parsed.

## Native FFI

Default `syntra-ffi` builds export no Syntra C ABI. Select the production
frame-pump ABI explicitly; its header is
[`syntra_production.h`](crates/syntra-ffi/include/syntra_production.h).
Production FFI keeps its own protocol state machine behind the C ABI and is
not the async runtime behind a different entry point; runtime fixes do not
automatically reach it. The test-fixture loopback ABI is a separate build
for tests only.

This production ABI is not automatically an SC1 SDK; the consolidated native
transport does not add SC1 to the FFI state machine.

```sh
cargo build --locked -p syntra-ffi --no-default-features
cargo build --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
python3 crates/syntra-ffi/tests/build_contract.py
```

`test-fixture` exports the separate blocking loopback ABI for tests only;
do not ship it or enable it through `--all-features`. The build-contract
check needs Python 3, `nm`, a C compiler and the WASM target. It builds
isolated artifacts, checks exports, runs C smoke tests and verifies the
expected FFI WASM rejection in all three modes.

### WASM

```sh
rustup target add --toolchain 1.88.0 wasm32-unknown-unknown
cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown
```

`syntra-ffi` is native-only. Compilation checks do not run a browser;
the opt-in [real-browser fixture](crates/syntra-web/tests/browser.md)
documents the separate browser procedure. Browser SC1 is not implemented.

### Go native sibling

For sibling checkouts `syntra-rs/` and
[`syntra-go/`](https://github.com/tinkle-org/syntra-go), first build the
production library above. From the **syntra-go root**, use an absolute
library path (adjust it if `CARGO_TARGET_DIR` is set):

```sh
LIBDIR="$(realpath ../syntra-rs/target/debug)"
# Linux
CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR -lsyntra_ffi" LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" go test -tags syntranative -count=1 ./...
# macOS (use this command instead on macOS)
CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR -lsyntra_ffi" DYLD_LIBRARY_PATH="$LIBDIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" go test -tags syntranative -count=1 ./...
```

This requires a Go toolchain and C compiler for the same architecture as
the Rust library. Pure-Go builds need no Rust library. Cross-repository
integration is checked separately from this repository's Rust CI.

## Benchmarks, containers and generated code

Criterion microbenchmarks isolate framing and channel work from real
networks; see [BENCHMARKS.md](BENCHMARKS.md) for timing boundaries and
commands. Container tooling is documented in
[crates/syntra-integration/README.md](crates/syntra-integration/README.md)
and is not run by root `cargo test --workspace`.

Generated files are committed under
`crates/syntra-core/src/generated/`. Use Buf CLI **1.59.0**, the remote
Rust plugin **`neoeinstein-prost:v0.4.0` revision 1**, as pinned in
`buf.gen.yaml`. The eight logical schema paths have explicit mappings to
this module. The `.proto` snapshots intentionally retain their original
options; do not rewrite them by hand.

```sh
buf generate --template buf.gen.yaml
python3 scripts/check-generated.py
python3 scripts/check-upstream-pin.py
```

The drift script uses Python's standard library and generates into a
temporary directory, then compares filenames and bytes. It requires Buf and
access to its remote plugin service, but no local `protoc`.

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- --no-deps
cargo audit --deny warnings
cargo deny --locked check advisories licenses sources
```

CI uses Rust **1.88.0**. Root tests and benchmarks require no Docker. PR CI
runs formatting, clippy, locked tests, FFI contract, WASM compile,
generation drift and security jobs; the scheduled lane adds native compat
and coverage. See [CONTRIBUTING.md](CONTRIBUTING.md),
[crates/syntra-integration/README.md](crates/syntra-integration/README.md)
and [BENCHMARKS.md](BENCHMARKS.md).

The latest local run records 372 workspace tests passed, 0 failed and
2 ignored (Docker/browser), separate WSS-only and development-carrier runs,
FFI/WASM checks, tooling/security checks and all three Criterion smoke targets.
See [AUDIT.md](AUDIT.md#current-recorded-verification) for exact results and
[implementation status](docs/implementation-status.md) for the Rust backlog.
Docker was not executed because the daemon was unavailable; browser execution
also remains unverified. Post-documentation checks passed. Release
gates remain upstream activation, independent pure-Go/Rust interoperability in
both roles and modes, recovery and mobile validation, and independent human review.
