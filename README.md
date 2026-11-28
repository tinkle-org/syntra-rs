# Syntra Rust

Embeddable Rust implementation of Syntra 1.0 with an integral Noise-based
encryption layer, bounded message codecs, client/host runtimes, negotiated
update/recovery and full-state persistence adapters. Native drivers compose the
portable encryption kernel and message runtime with platform I/O.

The `syntra_core::secure_channel` module owns cryptographic state, separate from
runtime scheduling and socket policy. Encryption is integral to the protocol. See
[CONNECTION.md](CONNECTION.md) for current architecture and embedding boundaries.

The implementation is experimental and distributed as release-candidate crates.
No formal conformance or independent security-review verdict is claimed.
`syntra-rs` owns its wire contract. The historical Protobuf schema from this
repository's `b99f56b` revision is in [`proto/syntra/v1`](proto/syntra/v1).
`syntra_core::proto` exposes its prost types, including `Frame`, `RpcRequest`,
and `RpcResult`. The Rust implementation defines validation, session behavior,
record protection, and carrier bindings.

**Upgrading from [#54](https://github.com/tinkle-org/syntra-rs/pull/54):** the
Bebop and Protobuf encodings are incompatible, but both use wire version **1**.
Coordinate the switch on clients, hosts, and any application-owned frame pumps.
There is no format negotiation, dual decoder, or fallback for a mixed deployment.

Use **Rust 1.89.0** for production builds and current verification. The
crate MSRV floor is **1.89**; it is a build compatibility constraint, not a
security recommendation. Production binaries must be built with a
security-patched toolchain. Current dependency pins are:

| Dependency | Version |
| --- | --- |
| `prost` | =0.14.6 |
| `snow` | =0.10.0 |
| `getrandom` | 0.3 |
| `tokio` | 1 |
| `tungstenite` / `tokio-tungstenite` | 0.30 |
| `rustls` | 0.23 |

Cargo package release configuration is in [release-plz.toml](release-plz.toml).
The public package set is `syntra-core`, `syntra-runtime`, `syntra-net` and
`syntra-ffi`; `syntra-integration` remains unpublished test infrastructure.
Each package is released separately on crates.io, not as a workspace bundle.

## Default: native async workspace

The default build needs no CGO or native library beyond the Rust toolchain.
`cargo build` uses the committed bindings; it does not download a schema compiler.

```sh
export RUSTUP_TOOLCHAIN=1.89.0
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

For downstream native TCP use, depend on `syntra-net` with `default-features = false`
and `features = ["tcp"]` when the application owns a Tokio runtime, or select
`features = ["managed"]` for the library-owned runtime/reconnect lifecycle.
See the [package README](crates/syntra-net/README.md) for the dependency declaration,
security inputs, and native/WASM boundaries. Pin compatible
RC versions together when also using core/runtime types directly.
For `syntra-ws` callers, [Dial and call](#dial-and-call) shows the `syntra-net`
connection inputs and explicit shutdown; changing the dependency name alone is not enough.

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
| `http` | Candidate HTTP/HTTPS Noise/RPC connections, listeners and raw codec/pair APIs; enables `syntra-core/http-candidate`, `getrandom` and the application `tls` boundary, without implying WebSocket or a TLS implementation |
| `websocket` | WebSocket framing/HTTP upgrade and loopback WS; application `tls` boundary, with no production TLS implementation dependency |
| `tls-rustls` | Enables `websocket` plus optional rustls, native trust roots and Tokio TLS convenience APIs for WSS |
| `reconnect` | Bounded reconnect helper with generation-fenced calls and explicit lifecycle controls |
| `managed` | Enables `tcp` and `reconnect`; owns runtime/clients/TCP listeners; add `websocket` for WS/WSS listeners or `http` for candidate HTTP/HTTPS listeners |
| `media` | Enables `managed`, bundled SQLite, and SHA-256; adds returning-mode TCP lanes with slot and byte limits, optional interactive update restore, and immutable versioned transfers. See [MEDIA.md](MEDIA.md). |
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
and HTTPS. Retries never create an unlisted direct route, replay an RPC, or
transfer a live connection. See [CROSS-CARRIER.md](CROSS-CARRIER.md) for policy, failure
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
The HTTP example exercises the candidate carrier; `--https` supplies
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
RPC retries safe. Recovery cursors and payloads stay opaque. The
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

HTTP/HTTPS support is experimental and disabled by default. See
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
- Decode peer input with `syntra_core::decode_frame(bytes, ctx)`, not raw
  `prost::Message::decode`. Core checks the encoded size, nesting, and raw
  `oneof` occurrences before prost can collapse duplicate alternatives. It
  validates the frame against connection state before dispatch. Application
  payloads remain opaque to the envelope codec.
- Request IDs are permanently non-reused and ordered at FIFO enqueue/emission;
  host high-water violations close without an offending-ID result. Pending
  terminal gates check the deadline first; previously selected outcomes stay
  terminal. See the [core](crates/syntra-core/src/lib.rs) and
  [runtime](crates/syntra-runtime/src/lib.rs) source contracts.

## Host-local request budgets

`Handler::request_budget(&Principal, &str, &[u8]) -> Option<Duration>` optionally
shortens an application RPC's deadline. The selector runs after
bounded envelope/method validation and ordered request-ID consumption, before
initial authorization. Its payload is opaque, bounded, untrusted data. The callback
must be prompt, nonblocking and side-effect-free; FIFO admission remains held,
but protocol mutexes, raw-I/O gates and lifecycle guards are released around it.
Lifecycle state is reacquired and rechecked before authorization, then retained
through authorization and request registration to serialize terminal reservation.
Built-in update/recovery RPCs retain their separate routing and source policy.

The effective deadline is original complete-frame receipt plus the minimum of
the effective wire/default timeout, deployment maximum and optional host cap.
Queueing, selector execution and authorization all consume that same budget.
`None` preserves existing limits; `Some(Duration::ZERO)` expires immediately,
and a longer cap, including `Duration::MAX`, cannot extend or overflow them.
Expiration is rechecked before handler construction and terminal selection;
an already selected result remains immutable.

The additive hooks use `syntra_runtime::elapsed::ElapsedDeadline`, which carries
the host's clock and offers `check`, `remaining`, `expired` and `run`:

| API | Budget and compatibility |
| --- | --- |
| `Handler::authorize_with_budget(principal, method, budget)` | Same request-wide deadline; synchronous/nonblocking, defaults to existing `authorize` (fail-closed) |
| `RequestContext::budget()` | Readonly clone of that deadline for cooperative application/storage work, including ordinary RPCs |
| `Authority::observe_with_budget(transition, budget)` | Existing read timeout restricted by prior freshness and terminal cutoff; defaults to `observe` |
| `Authority::commit_with_budget(transition, lease, budget)` | Terminal cutoff with teardown tail excluded; defaults to `commit` |

Existing handlers, closure/FFI adapters and authority implementations keep their
default behavior. `AllowAll` forwards the selector and context/execution hooks;
its authorization, including the default budget-aware delegation, still explicitly
bypasses the inner policy. Custom forwarding adapters must preserve these hooks.
These are SDK-local APIs with no wire, schema or peer-option change. Cooperative
callers must bound their own I/O and retain execution leases through actual work.
Timeout does not establish rollback, prevent a late durable commit, or guarantee
receipt delivery. See [terminal deadlines](TERMINAL_RECEIPT_DESIGN.md#deadline-and-retained-cleanup).

## Optional terminal receipt

Native TCP supports a default-disabled terminal result for an authorized
self-withdrawing operation. Use `AuthenticatorFactory::terminal_receipt` for a
fixed payload, or `terminal_methods` to configure fixed and outcome methods on
the same verified binding. An outcome method allows 1–8 non-sensitive payloads.
The handler calls `context.retire(expected_revision).await`; the authority adapter
owns the mutation. An owned withdrawal with a pending application result cannot
authorize output. After `commit` returns, `retire` requires fresh final evidence:
for an outcome method, the durable result for that same operation selects the
payload. The handler returns that `HandlerOutcome` without waiting for delivery.
A selected outcome, complete local writing, peer observation,
and joined cleanup are different facts. Loss is unknown and never automatically
retried or replayed.

The typed policy replaces the ordinary connection guard; combining it with an
independent generic guard is refused. The runtime fences ordinary traffic and
retires actual recovery attachments before transition. Raw/custom record, WASM,
FFI, WS/WSS, and HTTP/HTTPS paths do not support terminal effects. Existing clients
using the Protobuf wire format parse the ordinary `RpcResult`, with no new
wire message or peer option. See
[API, support, tests, and evidence limits](TERMINAL_RECEIPT_DESIGN.md).

## Native FFI

Default `syntra-ffi` builds export no Syntra C ABI. Select the production
frame-pump ABI explicitly; its header is
[`syntra_production.h`](crates/syntra-ffi/include/syntra_production.h).
The `production` frame pump uses the shared Initiator/Host runtime and typed recovery client.
It exposes a low-level plaintext frame boundary, not a complete protected Syntra
connection. The embedding driver must supply Syntra encrypted establishment,
record protection and the selected carrier's security and ordered I/O.
`SYNTRA_CAP_RECORD_PROTECTION` remains unset. TLS alone does not complete this
interface's Syntra implementation. The test-fixture loopback ABI is a separate
build for tests only.

For a client that should **not** implement a frame pump, `managed-media` adds a
separate protected TCP client to the production artifact. It does not change
`syntra_t` or its capability mask. See [managed C usage, transfer resume, and
build commands](MEDIA.md#use-the-managed-c-client).

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
expected FFI WASM rejection for default, fixture, production, and managed-media builds.

### WASM

```sh
rustup target add --toolchain 1.89.0 wasm32-unknown-unknown
cargo check --locked -p syntra-core -p syntra-runtime --target wasm32-unknown-unknown
python3 crates/syntra-net/tests/target_contract.py
sh crates/syntra-core/tests/run-kernel-browser.sh
```

Core and runtime support portable WASM embedding. `syntra-net` exposes native
drivers; its default WASM build has no driver exports and rejects native features.
`syntra-ffi` is native-only. The kernel browser runner requires a matching
`wasm-bindgen-test-runner` and a browser/WebDriver; compilation alone does not
execute those tests or verify a browser carrier.

## Benchmarks, containers and generated code

Criterion microbenchmarks isolate framing and channel work from real
networks; see [BENCHMARKS.md](BENCHMARKS.md) for timing boundaries and
commands. Container tooling is documented in
[crates/syntra-integration/README.md](crates/syntra-integration/README.md)
and is not run by root `cargo test --workspace`.

Normal builds use committed Rust bindings; they do not run Buf. For schema
changes, see [schema and generated code](CONTRIBUTING.md#schema-and-generated-code)
for the pinned Buf CLI and plugin, regeneration command, and drift check.

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- --no-deps
cargo audit --deny warnings
cargo deny --locked check advisories licenses sources
```

CI uses Rust **1.89.0**. Root tests and benchmarks require no Docker. PR/main CI
runs formatting, clippy, locked tests, FFI contract, WASM compile,
generation drift and security jobs, with required macOS native validation.
Scheduled validation periodically rechecks Linux, macOS and Windows and adds
coverage and vulnerability scans. See [CONTRIBUTING.md](CONTRIBUTING.md),
[crates/syntra-integration/README.md](crates/syntra-integration/README.md)
and [BENCHMARKS.md](BENCHMARKS.md).
