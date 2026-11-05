# Syntra Rust

Embeddable Rust implementation of Syntra 1.0 with an integral Noise-based
encryption layer, bounded Protobuf codecs, client/host runtimes, negotiated
update/recovery and full-state persistence adapters. Native drivers compose the
portable encryption kernel and message runtime with platform I/O.

The `syntra_core::secure_channel` module owns cryptographic state, separate from
runtime scheduling and socket policy. Encryption is integral to the protocol. See
[CONNECTION.md](CONNECTION.md) for current architecture and embedding boundaries.

The implementation is experimental and unpublished. No formal conformance,
independent interoperability or independent
security-review verdict is claimed. The current candidate is recorded in
[`protocol-contract.json`](protocol-contract.json); it pins `committed-candidate`
inputs, not a release or specification freeze. See
[input provenance](CONTRIBUTING.md#input-provenance-and-authority) for the separate
11-input upstream lock, source credit and exact Git/offline checks.

Use **Rust 1.88.0** for production builds and current verification. The
crate MSRV floor is **1.88**; it is a build compatibility constraint, not a
security recommendation. Production binaries must be built with a
security-patched toolchain. Current dependency pins are:

| Dependency | Version |
| --- | --- |
| `prost` | =0.14.4 |
| `snow` | =0.10.0 |
| `getrandom` | 0.3 |
| `tokio` | 1 |
| `tungstenite` / `tokio-tungstenite` | 0.30 |
| `rustls` | 0.23 |

Cargo package release configuration is in [release-plz.toml](release-plz.toml).
Protocol specification releases and package releases are separate.

## Default: native async workspace

The default build needs no CGO or native library beyond the Rust toolchain.
`cargo build` fetches crates sources only; this repository never downloads
native binaries.

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo build --locked
cargo test --locked
```

The workspace has five members. The four root `default-members` are `syntra-core`,
`syntra-runtime`, `syntra-net` and `syntra-ffi`. The extra `syntra-integration`
member is selected by `--workspace` and enables `syntra-net`'s `tcp` and
`websocket` features through its dependency.
CI separately checks socket-free defaults and explicit carrier features;
a workspace run alone does not prove default feature isolation.

## Workspace and scope

| Crate | APIs / source |
|---|---|
| `syntra-core` | Envelope codec, validation, handshake and protocol state; integral encryption in `syntra_core::secure_channel`: `Context`, `ClientHandshake`, `respond`, `Channel`, `Secret32`, `KeyStore`; no sockets or message-runtime dependency |
| `syntra-runtime` | Transport-independent `Initiator`/`Host`, sessions, RPC correlation, notifications, recovery drivers |
| `syntra-net` | Native record driver, TCP/WebSocket I/O, trusted application TLS composition, optional rustls WSS, managed networking, explicit routes/proxies, candidate HTTP/HTTPS connections and enrollment reference |
| `syntra-ffi` | Native C ABI with explicit production and test-fixture modes |
| `syntra-integration` | Unpublished fixture peer and Docker carrier integration tests |

Runtime byte channels exchange serialized `Frame` values inside the embedder.
Supplied connection drivers compose them with encrypted record framing and
bounded I/O. The plaintext frame boundary is not an unencrypted Syntra mode.
WSS additionally requires a verified TLS connection; it does not replace Syntra encryption.

`syntra-net` has empty default features (`default = []`), exposing the native
carrier-neutral `pump` without socket dependencies. Select capabilities explicitly:

| Feature | Capability |
| --- | --- |
| `tcp` | Encrypted TCP dial, connected-stream composition, admission-bounded listener and `routes` module |
| `cross-carrier-candidate` | Explicit opt-in sequential cross-carrier route policy; enables only `tcp`, with no implicit HTTP, TLS, managed runtime or reconnect support |
| `http` | Draft RFC0013 candidate HTTP/HTTPS Noise/RPC connections, listeners and raw codec/pair APIs; enables `syntra-core/http-candidate`, `getrandom` and the application `tls` boundary, without implying WebSocket or a TLS implementation |
| `websocket` | WebSocket framing/HTTP upgrade and loopback WS; application `tls` boundary, with no production TLS implementation dependency |
| `tls-rustls` | Enables `websocket` plus optional rustls, native trust roots and Tokio TLS convenience APIs for WSS |
| `reconnect` | Bounded reconnect helper with generation-fenced calls and explicit lifecycle controls |
| `managed` | Enables `tcp` and `reconnect`; owns runtime/clients/TCP listeners; add `websocket` for WS/WSS listeners or `http` for candidate HTTP/HTTPS listeners |
| `proxy` | Enables `tcp`; SOCKS5 and HTTP CONNECT tunnels, plus real HTTP forwarding through `routes` when combined with `http` |
| `native-enrollment` | Native SQLite enrollment reference |

Low-level drivers require a caller's native Tokio runtime; `Network` owns its
runtime and can be used from ordinary threads. Portable WASM embedders use core
and runtime with platform-owned I/O. TCP/WS/WSS connections always use Syntra encryption.
Native encrypted TCP is a supported production carrier; WS is restricted to
loopback development use. Ordinary route selection remains same-carrier;
cross-carrier failover requires the explicit candidate API and policy below.

`routes::client_routes` takes a `RouteConfig` with explicit, preprovisioned socket
addresses and a separate endpoint/URL allowlist. Each attempt selects one route
round-robin and obtains fresh security/credential inputs. Routes retain one
carrier: direct TCP, WS or WSS, or proxied TCP/WSS with `proxy`. WSS routes use a
trusted application TLS provider. With `http`, routes also support candidate
HTTP/HTTPS directly or through SOCKS5/CONNECT, plus real HTTP forward-proxy
requests via `Route::HttpForward`. HTTPS always uses application TLS on both
streams; forward-proxy mode is explicit plain outer HTTP with integral Noise.
Reconnect policy belongs to the owning client;
routes add no discovery or automatic replay.

### Candidate cross-carrier failover

The new `cross-carrier-candidate = ["tcp"]` feature adds
`routes::CrossCarrierPolicy { permitted_carriers: Vec<Carrier> }` and
`routes::client_routes_cross_carrier(RouteConfig, policy, inputs)`. Its callback
has shape `Fn(&Endpoint) -> Result<(ClientConfig, Vec<u8>), Error>` and supplies
fresh, independently provisioned security settings and credentials for the selected
endpoint. The returned connector has shape `Fn(EstablishmentBudget) -> DialFuture`.
Compose it with `Network::client_with_budget` (`managed`) or
`ReconnectingClient::new_with_budget` (`reconnect`); use
`new_with_recovery_and_budget` for fresh recovery negotiation per generation.
The budget-aware APIs carry the owner's cutoff through carrier I/O and any
required recovery negotiation.

A polled future attempts at most one route, selected round-robin; one supervisor
owns sequential retry counts, outage limits, backoff and control/generation fencing. The entire
route set, allowlist and bounded nonempty carrier policy are validated before
inputs or dialing. WS is excluded. `client_routes` remains same-carrier even
when Cargo features are unified. Permitting TCP explicitly allows absence of
outer TLS; Noise remains mandatory. TLS-mandatory deployments permit only WSS
and HTTPS. No unlisted direct route, RPC replay or live connection migration is
introduced. Current upstream rules forbid automatic carrier fallback; this is
an opt-in candidate policy, without formal adoption or security approval. See
[CROSS-CARRIER.md](CROSS-CARRIER.md) for the proposed normative delta, failure
boundaries, enrollment constraints and validation commands.

Credential verification is host-owned. `Authenticator` verifies opaque hello
bytes and returns a `Principal`; `AllowAnonymous` and static-token helpers
are test/example conveniences, not credential verifiers. After encrypted
establishment, `AuthenticatorFactory::create(&VerifiedIdentity)` receives freshly confirmed
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

The native examples run a local client and server using the library-owned worker
pool, bounded readiness waits and explicit shutdown reports:

```sh
cargo run --locked -p syntra-net --no-default-features --features managed --example managed_tcp
cargo run --locked -p syntra-net --no-default-features --features managed,websocket --example managed_wss
cargo run --locked -p syntra-net --no-default-features --features managed,websocket,cross-carrier-candidate --example managed_wss -- --failover
cargo run --locked -p syntra-net --no-default-features --features managed,http --example managed_http
cargo run --locked -p syntra-net --no-default-features --features managed,http --example managed_http -- --https
```

The WSS example supplies an application TLS provider and an explicitly trusted
local certificate. Its TLS dependencies are example-only; the `websocket`
production dependency graph does not select a TLS implementation.
With the candidate feature, `--failover` first attempts a deliberately unresponsive
local TCP endpoint, then establishes provider-verified WSS under the same reconnect
policy. It checks route order, encrypted echo and complete owned shutdown.
The HTTP example exercises the explicit RFC0013 candidate; `--https` supplies
application TLS for both persistent streams without enabling WebSocket.

Enable `syntra-net`'s `tls-rustls` feature and use
`syntra_net::websocket::connect` for native WSS. Supply a
`syntra_core::secure_channel::ClientConfig` whose context binds
`Carrier::SecureWebSocket`, an authenticated Noise server pin and exact provisioned
scope. The client is ready to call when
the connection succeeds:

```rust,ignore
let client = syntra_net::websocket::connect(
    "wss://example.service/syntra/1.0/ws", security, credential, runtime, limits,
).await?;
let result = client.conn.call("/example.Service/Method", b"hello".to_vec(), 1000).await?;
client.close().await;
```

The [connection guide](CONNECTION.md#records-and-carriers) describes
`connect_with_roots`, `TlsServerSettings::new`, `accept_tls_stream` and
application-provided TLS composition. With `websocket` alone, a trusted
`tls::TlsProvider` must perform real TLS and certificate validation; its metadata
is not a self-asserted substitute for those checks. The engine checks the completed
connection's authority, role, TLS 1.3, HTTP/1.1 ALPN and disabled early data under
the original attempt budget. Provider selection and review belong to the application.
The canonical endpoint is
`/syntra/1.0/ws`, with exactly the `syntra.1.0` subprotocol. WSS requires
a verified TLS 1.3 connection as well as the Noise pin. Ordinary APIs do not
automatically fall back to TCP; only the separately permitted candidate can
select it on a later retryable attempt. WS is excluded from that candidate.
The opt-in `reconnect` feature's `ReconnectingClient` owns a bounded reconnect
loop with explicit `ReconnectConfig` and pause/network/wake controls. Its status
receiver returns owned current-state snapshots, and calls/results are fenced by connection
generation. `CoreReady` is not recovery readiness, and mutations are never
automatically replayed. See [the client source contract](crates/syntra-net/src/client.rs)
for fresh connector inputs, retry budgets, failure classification and shutdown.

Dialing has a **15-second total connection attempt budget**, including
socket/TLS/upgrade, Noise and message readiness. On the responder, Noise
establishment and the client's encrypted-hello confirmation share a five-second
channel limit.
The returned client's lifetime is independent of the dial future: always close it.
These low-level connect functions do not reconnect. Reconnect is opt-in through
the client wrapper; each selected carrier retains its security requirements and
neither path automatically replays RPCs.

The `tcp` feature's `tcp::Listener::bind(address, maximum_connections)` acquires
admission before accepting; new accept calls backpressure when the limit is
reached. Close is abortive by default and bounded; `close_gracefully` shares one
absolute grace deadline across runtime drain and carrier flush. See
[CONNECTION.md](CONNECTION.md#budgets-emission-and-lifecycle) for ownership, budgets
and the adapter-owned graceful protocol.

After hello/ready, each host connection uses an asynchronous FIFO writer.
Queued plus active writes are bounded by the runtime writer capacity;
saturation terminates the connection with `RESOURCE_EXHAUSTED`. Each write
defaults to a ten-second timeout for one frame's complete record sequence.
Shutdown retires cipher state and runs transport-loss teardown so pending calls
settle as unknown outcomes. Use `shutdown_transport` and the runtime shutdown
report to distinguish joined completion from retained incomplete work; see
[connection ownership](CONNECTION.md#budgets-emission-and-lifecycle).

Custom initiator writers must pass each **original `Vec<u8>`** dequeued from
the byte-pump receiver, without cloning or reallocating, to
`Initiator::prepare_outbound` exactly once immediately before synchronous
carrier handoff/encryption. `None` skips a retired item; `Some(bytes)` carries
the live request with floored positive remaining milliseconds. Finish that
unit in order or abort the carrier. Never re-gate fragments or ciphertext.
The receiver still yields one serialized `Frame` per `Vec`; see
[CONNECTION.md](CONNECTION.md#budgets-emission-and-lifecycle) for the handoff contract.

Application payload schemas, identity systems, messenger subscriptions,
presence, JSON gateways, service discovery and gRPC clients are outside the
workspace's scope. HTTP upgrade and CONNECT tunneling also serve the
WebSocket/proxy paths. `proxy::HttpForwardTarget` is metadata only;
`routes::Route::HttpForward` performs the candidate HTTP forward requests.
UDP is deferred.
Reliable-session helpers do not claim exactly-once effects or make arbitrary
RPC retries safe. Recovery cursors and payloads stay opaque. The accepted
update/recovery binding is explicitly configured and negotiated as described below;
local helpers do not themselves supply wire behavior or durable effects.

### Candidate HTTP/HTTPS connections

The explicit `http` opt-in composes paired HTTP streams with actual Noise,
encrypted hello/ready and RPC through the shared kernel/runtime/pump.
`Carrier::Http` and `Carrier::Https` use candidate codes 4/5; default core builds
reject them. HTTPS requires a trusted application TLS provider on both streams.

```rust,ignore
use syntra_net::{http, EstablishmentBudget};

let budget = EstablishmentBudget::new(clock, limits.attempt_timeout)?;
let client = http::connect_with_budget(
    destination, authority, provider, security, credential, (runtime, limits), budget,
).await?;
let reply = client.conn.call("/example.Service/Method", b"hello".to_vec(), 1000).await?;
client.close().await;
```

Here `provider: None` requires `Carrier::Http`; `Some(provider)` requires
`Carrier::Https`. The pin, scope, destination and authority are provisioned
independently. Connected-stream APIs and `http::bind(ServerConfig)` expose the
same candidate connection path; the listener returns a control handle and a
`ServerRun` owner to drive and retain through shutdown. With `managed,http`,
`Network::listen_http`/`listen_https` own that run and return `ManagedHttpServer`.
The raw `codec`, `client_pair` and `server_pair` APIs remain separate lower-level
building blocks; raw record admission alone proves neither Noise nor RPC readiness.

RFC0013 remains Draft upstream. This is full-RPC implementation-candidate
capability, not registered, approved or shippable accepted-spec support.
Local regression execution does not replace human security review. It makes no conformance claim and
does not change the active three-carrier contract or its pins. See
[the candidate connection guide](CONNECTION.md#candidate-httphttps-connections).

### Negotiated update/recovery

Configure `Host::configure_recovery(service)` while CONNECTED, before hello.
For the native protected record driver, wrap the existing factory with
`RecoveryAuthenticatorFactory::new(base, service)`; the accept path configures
the service before consuming the encrypted hello. The service binds the actual
Core principal and invokes the application's bounded `RecoverySource` policy.
With no configured service, recovery calls return `UNIMPLEMENTED` and Core
interoperability remains available.

`recovery::wire_client::RecoveryClient::new` attaches one immutable inbox to its
Initiator. Explicit ACTIVE negotiation enables recovery routing before the generic
lossy notification queue. Typed APIs implement all nine methods, fixed-boundary
rounds, replay and snapshot fencing, bounded retries and subscriber-local overflow.
Snapshot installation preserves the provider generation; only declared scoped
provider loss or a shared rebase changes it. Mixed notification protocols require
explicit demultiplexing, not a failed-decode fallback.

Applications supply recoverable source-side issued checkpoint/snapshot bindings
and full-state persistence under `(principal, stable stream, generation, checkpoint)`.
`recovery::persistence::FileRecoveryStore`, available on native targets with
`syntra-runtime/file-store`, is a single-writer full-record reference with atomic
replacement and uncertainty reporting, not encrypted credential
storage or a production source/history database. A digest or memory store is not
durable-effect evidence. See [the persistence source contract](crates/syntra-runtime/src/recovery/persistence.rs)
for ownership and storage assumptions. WASM embedders supply their own durable
store; the native ABI has a separate
[typed recovery-client contract](crates/syntra-ffi/include/syntra_recovery.h).
These APIs do not make automatic mutation replay safe or establish formal conformance.
The recovery service's `profile_version` fields version this negotiated extension;
they do not select a different encryption protocol.

### Resource bounds and validation

- `ConnectionConfig::default().max_outstanding` is 32. Validated runtime
  constructors require 16..=1024, with writer/notification capacities 1..=1024
  (both default 256). Use `try_new*` for fallible construction; `new*`
  constructors panic on invalid configuration. Stricter execution/principal
  admission quotas are separate from the supported Core concurrency floor.
- A serialized frame is limited to 1 MiB, including envelope overhead. A
  payload at a separate application limit can therefore fail encoding.
  Failed request encoding retires any reserved ID and cleans its registration.
  The absolute call budget starts before readiness/writer queue waiting.
- The initiator's bounded notification queue drops the newest notification and
  counts losses when saturated. Host output has bounded writer backpressure
  and separately charged terminal-output slots. Negotiated recovery has
  per-H data/control routing before this generic queue. Platform lifecycle and
  shutdown need separate verification at each embedding boundary.
- Syntra encryption limits ciphertext records to 65,535 bytes and plaintext to 65,519
  bytes; the encrypted frame stream may span records. Lifetime is at most 24
  hours or 2^32 records per direction. Transport `Limits::validate` also validates the
  shared runtime configuration. Default factories share a process-wide budget
  of 1024 live executions across connections/replacements; custom factories
  can return a retained host/principal budget. External work must retain its
  execution lease until it stops. See
  [CONNECTION.md](CONNECTION.md) and the source contracts for clocks, cancellation requirements and
  revocation checks.
- Unknown metadata alongside a known body is tolerated. Metadata alone, with
  no body, yields `INVALID_ARGUMENT`. Body tags are 10–15, 16–17 remain
  forbidden, and a sole valid future 18–31 body yields `UNIMPLEMENTED`.
  Reserved tags, duplicate oneof alternatives, malformed unknown wire data
  and nesting beyond depth 32 are rejected by the bounded codec on decode
  and emission; opaque payload bytes are not parsed.
- Request IDs are permanently non-reused and ordered at FIFO enqueue/emission;
  host high-water violations close without an offending-ID result. Pending
  terminal gates check the deadline first; previously selected outcomes stay
  terminal. See the [core](crates/syntra-core/src/lib.rs) and
  [runtime](crates/syntra-runtime/src/lib.rs) source contracts.

## Native FFI

Default `syntra-ffi` builds export no Syntra C ABI. Select the production
frame-pump ABI explicitly; its header is
[`syntra_production.h`](crates/syntra-ffi/include/syntra_production.h).
Production FFI uses the shared Initiator/Host runtime and typed recovery client.
It exposes a low-level plaintext frame boundary, not a complete protected Syntra
connection. The embedding driver must supply Syntra encrypted establishment,
record protection and the selected carrier's security and ordered I/O.
`SYNTRA_CAP_RECORD_PROTECTION` remains unset. TLS alone does not complete this
interface's Syntra implementation. The test-fixture loopback ABI is a separate
build for tests only.

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
cargo check --locked -p syntra-core -p syntra-runtime --target wasm32-unknown-unknown
python3 crates/syntra-net/tests/target_contract.py
sh crates/syntra-core/tests/run-kernel-browser.sh
```

Core and runtime support portable WASM embedding. `syntra-net` exposes native
drivers; its default WASM build has no driver exports and rejects native features.
`syntra-ffi` is native-only. The kernel browser runner requires a matching
`wasm-bindgen-test-runner` and a browser/WebDriver; compilation alone does not
execute those tests or verify a browser carrier.

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
options; do not rewrite them by hand. Check local schema/test-asset digests with
`python3 scripts/check-upstream-pin.py --offline`. For provenance verification,
use `--upstream ../syntra` or set `SYNTRA_SDD_ROOT`; the local Git object database
must contain the exact pinned upstream commit. No network fetch is performed.
See [CONTRIBUTING.md](CONTRIBUTING.md#input-provenance-and-authority) for the
scoped implementation inputs, candidate transformations and review requirements.

```sh
buf generate --template buf.gen.yaml
python3 scripts/check-generated.py
python3 scripts/check-upstream-pin.py --offline
```

The drift script uses Python's standard library and generates into a
temporary directory, then compares filenames and bytes. It requires Buf and
access to its remote plugin service, but no local `protoc`.

Unified implementation evidence is produced by
`scripts/conformance_evidence.py`, optionally with `--candidate-agreement offline`
or `--candidate-agreement release` and supplemental `--run-local` lanes. The
release mode verifies committed candidate inputs, not publication authorization. See
[implementation evidence](CONTRIBUTING.md#implementation-evidence) for commands,
the exact Git-input requirement and result interpretation. Candidate agreement,
fixture transcription checks and local test execution have distinct scopes;
formal conformance remains `NOT_EXECUTED` in this report.

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
