# Syntra encryption and connections

Syntra 1.0 includes encrypted connection establishment and protected records as
part of the protocol. The `syntra_core::secure_channel` module owns cryptographic
state within core, separate from runtime scheduling and socket policy.
Encryption is integral to every connection.

This guide describes the current worktree. The v2 candidate contract in
[`protocol-contract.json`](protocol-contract.json) records source provenance,
domain, carrier bindings and context layout, with raw source hashes separate from
derived artifact hashes. Its `CARRIER` bindings describe one protocol. The record
pins the exact candidate inputs at upstream commit
`3f7e8ea037fefcc5c86101d23e7722c83e28a0d3`. See
[CONTRIBUTING.md](CONTRIBUTING.md#input-provenance-and-authority) for the separate
pinned upstream inputs. No formal conformance or independent security-review
verdict is claimed here. The terminal receipt fixture report at
`syntra-go/TERMINAL_RECEIPT_INTEROP.md` requires a sibling checkout and records a
bounded bidirectional TCP matrix, not general interoperability. That uncommitted
report is absent from the run-2 Go commit; no pinned hosted copy is claimed.

## Layer and crate ownership

| Layer | Implementation | Responsibility |
| --- | --- | --- |
| Message mechanics | `syntra-core` | Protobuf envelope codec, validation, message handshake, connection state and RPC rules |
| Message runtime | `syntra-runtime` | Initiator/Host execution, queues, authentication/authorization hooks, recovery and lifecycle |
| Encryption | `syntra_core::secure_channel` | Authenticated context, Noise handshake, ordered cipher state, protected record bounds and frame-stream assembly |
| Native I/O | `syntra-net` | Record driver, TCP/WebSocket I/O, TLS provider composition, optional rustls WSS, managed runtime/listeners and proxy helpers |
| Native ABI | `syntra-ffi` | Shared-runtime plaintext frame boundary; embedding driver supplies encryption and carrier I/O |
| Verification | `syntra-integration` | Unpublished fixture peer and Docker carrier tests |

The five-member workspace keeps core, runtime, net and FFI in the root defaults;
integration is the extra fixture member. Core and runtime are portable to WASM.
WASM embedders compose the kernel and message runtime with platform-owned I/O.

Serialized `Frame` interfaces and in-memory loopback helpers are useful inside an
embedder or test harness. They are not complete Syntra connections and must not
be exposed as an alternative plaintext network protocol. The production FFI
currently leaves `SYNTRA_CAP_RECORD_PROTECTION` unset; selecting its `production`
feature does not supply a protected connection driver.

## Establishment and trust

Both authentication modes use X25519, ChaCha20-Poly1305 and SHA-256:

| Mode | Noise pattern | Provisioned client inputs |
| --- | --- | --- |
| Bootstrap | `Noise_NK_25519_ChaChaPoly_SHA256` | Authenticated server public-key pin and exact intended scope |
| Returning | `Noise_NKpsk0_25519_ChaChaPoly_SHA256` | Same pin/scope plus a nonzero 32-byte authorization key, nonzero lookup handle and epoch |

The server pin and scope come from trusted provisioning, not the endpoint being
contacted. Context binds the mode, carrier, server-key ID, epoch, handle and scope.
Scope is UTF-8 of 1–255 bytes, preserved without normalization. The exact domain
is `syntra.1.0`. The complete encoded context is the entire Noise prologue;
transport records use empty associated data. There is no additional application
AD or context negotiation. Use the
[kernel's `Context` encoding and handshake implementation](crates/syntra-core/src/secure_channel/mod.rs)
for field order and validation rather than duplicating byte offsets.

Bootstrap authenticates the pinned server, not an enrolled client principal.
Returning mode proves possession of an authorization key. A parsed context, lookup
handle or first handshake message alone is not a confirmed client identity.
The responder kernel issues `VerifiedIdentity` only after successfully decrypting
a client transport record and refuses responder encryption before that
confirmation. The native host driver additionally waits for authenticated client
data reconstructing a valid `ClientHello` before creating its `Authenticator`.
Confirmation proves fresh channel participation; it does not by itself grant an
application identity or enrollment authority.

`ClientHello` credentials travel inside the encrypted record stream. The
application's `Authenticator` still verifies those explicit credentials and binds
a principal. `Handler::authorize` checks that principal before each method's
effects. Key-store validity, enrollment/revocation policy and application-side
effect fencing remain host responsibilities. Neither encryption nor TLS supplies
an application identity system or permission policy.

**Opt-in native TCP terminal receipt:** `AuthenticatorFactory::terminal_receipt`
supplies a fixed method/payload policy and a typed application authority adapter.
`Handler::handle_with_context` receives a private `RequestContext`; its
`retire(expected_revision)` fences ordinary traffic, waits for full-frame writer
quiescence, and attempts the conditional transition before returning the fixed
handler outcome. Return that outcome promptly; do not await its own output.
Only exact, fresh owned-commit evidence permits that result. The typed per-binding
authority replaces the ordinary connection guard; combining it with an independent
generic guard is refused. Actual Host recovery attachments are fenced and retired
before transition. The default is disabled. Raw/custom record, WASM, FFI, WS/WSS,
and HTTP/HTTPS drivers do not support this path; they refuse before the terminal
mutation.
No client method, wire field or advertised capability is added. Ordinary
withdrawal/graceful close keep their existing defaults. See
[API, authority contract, support, and evidence](TERMINAL_RECEIPT_DESIGN.md).
Local writing, client observation, and joined cleanup remain separate facts;
loss never permits an automatic mutation retry.

Each connection requires fresh cryptographic randomness for ephemeral handshake
keys. Entropy failure aborts establishment. Authorization keys and lookup handles
must be independently sampled, with collisions, nonzero values, epoch allocation,
scope, expiry and revocation enforced by the enrollment owner. `Enrollment::generate`
is a sampling helper, not a store or complete enrollment policy.

Reconnect creates fresh handshake and cipher state. Never persist, clone, restore
or reset live traffic keys/nonces, or reuse them after cancellation, process
restart or suspension. Returning mode must not silently fall back to bootstrap;
ordinary APIs do not change carriers after failure. The separately opted-in
[cross-carrier candidate](#candidate-cross-carrier-failover) permits only explicitly
provisioned carriers after retryable availability loss; detected trust or protocol
failure blocks automatic continuation. See the
[kernel](crates/syntra-core/src/secure_channel/mod.rs) and
[randomness/crypto resolver](crates/syntra-core/src/secure_channel/resolver.rs).

## Records and carriers

The encryption kernel accepts at most 65,519 plaintext bytes per record, producing
at most 65,535 ciphertext bytes including the 16-byte authentication tag. Empty
records are rejected. Each serialized message frame is at most 1 MiB and has an
encrypted u32 big-endian length prefix; this inner frame stream may span records.
Channels retire after at most 24 hours or 2^32 records per direction. Frame,
record and channel limits apply independently.

Authentication failures, invalid record lengths, malformed inner framing and
truncated/failed I/O are terminal for the connection. Record errors permanently
poison `Channel`, and a failed `FrameDecoder` cannot be reused. Drivers abort
rather than scanning for a new prefix, skipping records, resetting nonces or
attempting stream resynchronization.

Native `syntra-net` defaults to no carrier features. Its record driver is
available without socket dependencies but requires a native Tokio runtime.
Explicit `tcp` and `websocket` features add I/O implementations. `websocket` owns
framing and HTTP upgrade, with no production TLS implementation dependency;
`tls-rustls` adds the optional rustls/native-root WSS convenience path.
`reconnect` adds the opt-in connection manager. `managed` enables TCP, reconnect
and a library-owned multithreaded runtime through `network`. `proxy` enables TCP
and explicit tunnel helpers. `tcp` also exposes explicit client `routes`.
`http` independently enables the Draft RFC0013 candidate HTTP/HTTPS connection
path, `syntra-core/http-candidate`, `getrandom` and application `tls` composition,
without implying `websocket` or a TLS implementation. `native-enrollment` adds
a native host reference. All high-level connection drivers use Syntra encryption.
The separate `cross-carrier-candidate = ["tcp"]` feature adds an explicit route
policy API. It does not implicitly enable `http`, `websocket`, `tls-rustls`,
`managed` or `reconnect`; those capabilities require independent feature selection.

| Carrier | Record binding | Additional boundary |
| --- | --- | --- |
| TCP | u16 big-endian message length followed by M1, M2 or ciphertext bytes | Production carrier with integral Syntra encryption; packet boundaries have no protocol meaning |
| WebSocket | One binary WebSocket message per M1, M2 or ciphertext record; no outer u16 prefix | Native WS dials are restricted to loopback development fixtures |
| WSS | Same binary-message binding, with `Carrier::SecureWebSocket` | Verified TLS 1.3 in addition to the provisioned Noise pin |

The WebSocket endpoint is `/syntra/1.0/ws`, with exact subprotocol `syntra.1.0`.
TLS protects the WSS carrier; it does not replace Syntra's handshake or encrypted
records. HTTP/HTTPS are not registered carriers. HTTP upgrade and CONNECT
tunneling are bounded setup steps; forward-request metadata alone does not
implement an HTTP proxy carrier. RFC0013 is Draft upstream. Adoption remains
unresolved separately; these APIs make no conformance claim.

Native clients select the exact endpoint and subprotocol, reject URL credentials,
queries and fragments, and send no HTTP credentials or cookies. The client checks
an HTTP/1.1 `101` response with CRLF framing, bounded headers, a `Connection`
token list containing `upgrade`, a single case-insensitive `Upgrade: websocket`
value, and single exact `Sec-WebSocket-Accept` and `Sec-WebSocket-Protocol` values. Any
`Sec-WebSocket-Extensions` response is rejected; redirects are not followed.
The native server requires the endpoint without a query and exactly one
subprotocol header with value `syntra.1.0`, rejects `Authorization` and `Cookie`,
and does not negotiate compression. Fragment reassembly and Ping/Pong handling
are below the record layer and remain within the absolute read deadline. The
native server rejects any present `Origin` header. Native clients omit it;
forwarded origin headers are not used to establish trust.

For the rustls WSS convenience path, enable `syntra-net`'s `tls-rustls` feature and call
`syntra_net::websocket::connect` with a provisioned
`syntra_core::secure_channel::ClientConfig`, explicit credentials, runtime
configuration and transport limits. The returned client is ready after protected establishment
and the message handshake. `connect_with_roots` accepts explicit trust roots;
`TlsServerSettings::new` and `accept_tls_stream` provide the native server path.
See the [native module](crates/syntra-net/src/websocket.rs) and
[record driver](crates/syntra-net/src/pump.rs) for exact signatures and
ownership contracts. This path owns TLS termination directly, checks TLS 1.3 and
disables early data. Callers must retain and close returned handles.

With `websocket` alone, the application may supply a trusted `tls::TlsProvider`.
Start one `EstablishmentBudget` before dialing/accepting and pass the connected
stream to `tls::connect_stream_with_budget` or `tls::accept_stream_with_budget`.
The resulting single-owner `VerifiedTlsStream` carries that same budget into
`websocket::connect_tls_stream_with_budget` or `accept_verified_tls_stream`.
TLS, upgrade, Noise and message readiness share the deadline and per-poll I/O gate.

Providers are trusted application code and must complete real TLS 1.3 on the
supplied connection, disable early data/0-RTT, negotiate `http/1.1`, and use
current trust policy. Clients must verify the certificate chain, authority
hostname, time validity and application revocation policy, including resumed
sessions; servers use current credentials for their provisioned local authority.
The engine checks connection-scoped authority, role, version, ALPN and early-data
metadata, but those checks cannot prove that arbitrary provider code did TLS or
certificate verification. Metadata is not a security self-assertion. Plaintext,
forwarded headers and external proxy claims cannot establish WSS trust. TLS never
substitutes for the provisioned Noise pin or application authentication.

### Managed networking and proxies

`network::Network`, gated by `managed`, owns its runtime, managed clients and
admission-bounded TCP listeners. With `managed,websocket`, `listen_ws` and
`listen_wss` use `WebSocketServerConfig` and the same server supervision as TCP.
`WebSocketTls::Loopback` confines WS to loopback;
`WebSocketTls::Provider { provider, authority }` supplies trusted application TLS for WSS. The WSS listener
uses that provider regardless of whether optional `tls-rustls` is enabled.
Admission ownership spans establishment, the whole host handle and teardown.
The network delegates reconnect policy and generation fencing to
`ReconnectingClient`. Operations can be awaited on another executor
or waited from ordinary threads; blocking waits refuse a Tokio context. Pause,
network availability and shutdown controls retain task ownership. Inspect the
shutdown report: an expired wait retains unfinished runtime/work ownership,
and drop transfers it to an observable process registry. No operation is replayed.

The `proxy` module supplies explicit SOCKS5 and HTTP CONNECT tunnels under the
original establishment budget. Proxy authentication and destination authority
are separate from Syntra credentials and Noise identity. A tunnel does not prove
TLS or change the selected carrier. `HttpForwardTarget` supplies validated
absolute-URI/Host metadata only. With `http,proxy`, `routes::Route::HttpForward`
uses explicit absolute-form requests for the candidate HTTP binding; it does not
send CONNECT or fall back to a direct route.

`routes::client_routes`, available with `tcp`, builds a connector from `RouteConfig`.
Provision socket addresses and a separate endpoint/URL allowlist explicitly;
proxy allowlisting covers both the proxy socket and destination. Each attempt
selects one route round-robin and obtains fresh security/credential inputs.
The route set must retain one carrier. Direct TCP, loopback WS and
application-provider WSS are supported, plus proxied TCP/WSS with `proxy`.
With `http`, the route set may instead select candidate `Http` or `Https`.
`HttpProxy`/`HttpsProxy` establish both streams through SOCKS5 or HTTP CONNECT;
`HttpForward` performs real plain-HTTP forward requests. Only that forward
route sends proxy-hop credentials in HTTP requests; origin credentials remain
inside Syntra encryption. HTTPS verifies both streams with application TLS.
The connector carries one budget through socket/proxy, TLS, upgrade, Noise and
readiness. It adds no DNS discovery, redirects or retry loop; the owning
`ReconnectingClient` or `Network` decides whether another attempt is permitted.

### Candidate cross-carrier failover

The new opt-in API is
`routes::client_routes_cross_carrier(RouteConfig, CrossCarrierPolicy, inputs)`,
where `CrossCarrierPolicy { permitted_carriers: Vec<Carrier> }` has no default
permissions and `inputs` has shape
`Fn(&Endpoint) -> Result<(ClientConfig, Vec<u8>), Error>`. It returns a
budget-aware connector, `Fn(EstablishmentBudget) -> routes::DialFuture`.
The candidate contract is documented in [CROSS-CARRIER.md](CROSS-CARRIER.md).

Validate runtime/transport limits, every route and every allowlist entry,
including unused entries, and the bounded nonempty, duplicate-free carrier policy
before invoking inputs, TLS providers or dialing. Routes and allowlists each
contain `1..=routes::MAX_ROUTES` entries (currently 256). Every endpoint must be
valid and permitted, and every route must match the separately provisioned
allowlist; proxy identities cover both proxy socket and destination. WS is
excluded even on loopback. Existing `client_routes` retains its homogeneous
carrier requirement, including when the candidate feature is enabled by another
dependency through Cargo feature unification; homogeneous loopback WS remains
available there.

A polled future attempts at most one route, selected round-robin, and calls inputs
for that endpoint when its budget admits the attempt. Constructing and dropping
an unpolled future neither advances selection nor obtains inputs or dials.
The callback must be nonblocking and return
fresh security settings and explicit credentials; a context-carrier mismatch is
rejected before dialing, without rewriting the context. Selection has no priority
failback, health cache or racing. Use one connector under one supervisor for
sequential attempts, without an application-side carrier retry loop.

Compose with `Network::client_with_budget` under `managed`, or
`ReconnectingClient::new_with_budget` under `reconnect`. The reconnect owner alone
owns attempt counts, total outage time (including paused/offline time), bounded
backoff, controls and generation fencing. Pass its same `EstablishmentBudget`
through socket/proxy setup, TLS, upgrade or both HTTP streams, Noise and ready,
down to raw I/O polls. A stricter route limit may shorten this budget but must
retain its owner/clock identity and never extend its deadline. Route rotation
must not reset outage accounting or create a new independent setup budget.
Use `ReconnectingClient::new_with_recovery_and_budget` when recovery must
negotiate afresh on each generation under the owner's remaining budget;
`CoreReady` alone does not establish recovery readiness. The raw I/O gate stays
active through required negotiation on both HTTP streams as well as other
carriers, and releases only when that negotiation is accepted. Ordinary
connections release the establishment gate at CoreReady; their active lifetime
is not limited to the setup timeout.

Detected trust, protocol, local AEAD/record authentication, framing and proxy
authorization failures (including HTTP 403/407 and SOCKS ruleset denial) block
automatic continuation. `Io`, `Timeout` and `Closed` are retryable loss categories
only within the owner's remaining policy budget. An arbitrary provider's
post-handshake opaque I/O error cannot reveal a missing typed trust/protocol
failure; diagnostics cannot claim to have detected or fixed that security status.

Carrier permission is independent of route permission: permitting TCP expressly
allows no outer TLS, with Noise still mandatory. Plain candidate HTTP also lacks
outer TLS. TLS-mandatory deployments permit only WSS/HTTPS and list only those
routes. A failed proxy route never creates a direct fallback; a direct path must
be separately listed, allowlisted and permitted. Scope, pin, authentication mode
and credentials are independently provisioned per endpoint, never modified or
inferred from failure. The native enrollment backend retains immutable TCP/WSS
permissions; HTTP/HTTPS host authentication is application-provided, with no
automatic enrollment permission expansion. Every successor has fresh Noise,
cipher state, authentication and explicitly negotiated recovery. RPCs and live
connections do not migrate; loss leaves unfinished RPC outcomes unknown.

Upstream `SNTR-TSEC-007`, `SNTR-WS-202` and `SNTR-WSS-201` currently forbid
automatic carrier fallback, and Draft RFC0013 `R13-26` retains same-carrier
failover. This candidate proposes a narrow explicit-policy exception; it does
not edit active contract pins, source hashes or the protocol registry and records
no formal adoption or security approval. See the
[proposed normative delta](CROSS-CARRIER.md#proposed-normative-delta) and
[validation commands](CROSS-CARRIER.md#validation).

### Candidate HTTP/HTTPS connections

The `http` opt-in supplies full candidate connections over two persistent streams:
Noise, encrypted hello/ready, `ClientHandle`/`HostHandle` and RPC use the shared
kernel/runtime/pump. Candidate `Carrier::Http`/`Https` use codes 4/5 through
`syntra-core/http-candidate`; default core parsing rejects both. The active
contract still has three carriers. RFC0013 remains Draft, with adoption and
registration unresolved. These connections provide local implementation evidence,
not human security approval, shippable accepted-spec support or conformance.

| API | Candidate capability |
| --- | --- |
| `http::connect_streams_with_budget` | Compose distinct connected streams with explicit `Carrier::Http`, provisioned Noise pin/scope and authority |
| `http::verify_tls_streams_with_budget` / `connect_tls_pair_with_budget` | Verify both streams through trusted application TLS, then establish `Carrier::Https` |
| `http::connect_with_budget` | Dial one preprovisioned destination for both streams under the original budget; HTTP requires no provider, HTTPS requires one |
| `http::bind(ServerConfig)` | Bind a candidate listener with an association registry and configurable resource limits; return `ServerHandle` plus inline `ServerRun` |
| `Network::listen_http` / `listen_https` | With `managed,http`, supervise that listener/registry on the owned runtime and return `ManagedHttpServer` |

TLS, HTTP setup, Noise and readiness share the original attempt budget. HTTPS
requires the same authority, client role and original budget for both TLS
streams, with actual certificate/current-policy checks by trusted provider code.
Metadata or matching deadlines alone are not trust or budget identity. Neither
HTTP association selectors nor proxy headers authenticate an application principal.

Drive `ServerRun` through completion and retain its control handle. Dropping the
run signals stop and transfers its remaining owner to the observable
`retired_servers` registry; the owning Tokio runtime must remain alive. Managed
listeners keep that owner under `Network`, including incomplete cleanup. Binding
does not mean an association is ready; inspect readiness and shutdown/status
reports separately. Resource accounting and cleanup remain under active review.

The raw `http::codec`, `client_pair` and `server_pair` APIs are also available.
They expose bounded request/response encoding and `RecordReader`/`RecordWriter`
adapters without independently performing Noise or hello/ready. Drive the raw
server driver inline with its consumer/producer. Raw input admission or an
`OpenEnvelope` prefix check proves neither authenticated context, execution nor
delivery. Complete candidate connections must select codes 4/5 explicitly,
never relabel HTTP records as TCP or WebSocket.

## Budgets, emission and lifecycle

Native drivers bound the full attempt through message readiness to
15 seconds, Noise plus encrypted-hello confirmation to 5 seconds, and one frame's
output across all records to 10 seconds. Current defaults bound next-record waits
and partial-frame assembly to 30 seconds and carrier teardown to 1 second; consult
[`pump::Limits`](crates/syntra-net/src/pump.rs) for validation.
The next-record deadline includes idle time, partial carrier prefixes, fragment
reassembly and control traffic. A partial inner frame gets one absolute assembly
deadline from its first incomplete authenticated plaintext; trickled records do
not renew it. The deadline survives readiness/task handoff and backpressured
delivery. Completing that frame may start a new assembly budget for the next one.
Switching layers does not grant a fresh setup budget or cryptographic lifetime.
Expiry, clock regression or unknown elapsed continuity retire the connection.

Custom initiator writers must pass the original `Vec<u8>` dequeued from the runtime
receiver, without cloning or reallocating, to `Initiator::prepare_outbound` once
immediately before synchronous handoff/encryption. `None` discards retired output;
after `Some(bytes)`, finish that unit in order or abort. Do not re-gate fragments
or ciphertext. The native pump additionally rechecks connection authorization
and lifecycle gates before encrypting output and before carrier I/O. Custom
drivers must preserve these checks for both initiator and host output.

`Channel::encrypt` consumes the next send nonce. Retain the resulting immutable
ciphertext and its write future across partial writes/backpressure; finish it in
order or abort. Never re-encrypt a replacement or relabel ciphertext after a
timeout, cancellation, revocation or lifecycle change. Recheck delivery and
authorization gates before repolling carrier I/O.

Runtime writer and notification capacities count items, not bytes. With frames
up to 1 MiB, a queue capacity must not be described as a byte-memory cap. Host
writer accounting includes queued and active work, with separate terminal-output
slots and execution leases. Generic initiator notification overflow drops the
newest item and counts losses; recovery routing has its own bounded inbox.
Native carrier buffers and process-wide execution/policy budgets are additional
bounds. See the
[runtime configuration](crates/syntra-runtime/src/connection.rs),
[host writer](crates/syntra-runtime/src/host.rs) and driver sources.

Retain the whole `ClientHandle` or `HostHandle`, not just `conn` or `host` captured
by an async task: the handle owns the pump. The
[TCP listener](crates/syntra-net/src/tcp.rs) acquires admission before socket
accept and keeps its permit with the stream through establishment and the live
connection. Keep accepting while driving handshakes concurrently so one slow
handshake cannot serialize all accepts. WebSocket/WSS accept callers supply their
own aggregate admission bound, retaining each permit with the whole connection
owner through teardown.

`close` is a bounded abortive stop/wait, not a full shutdown attestation.
`close_gracefully` stops runtime admission and drains admitted output, including a
frame already dequeued by the pump, under one absolute grace deadline shared with
carrier flush and join. Failure or expiry aborts unfinished output. For explicit
ownership reporting, `shutdown_transport(&mut self, grace)` stops admission and
joins within the runtime's first shutdown budget; `ShutdownIncomplete` retains the
owner for later observation/retry, without extending that budget. Consuming close
or drop signals stop while the runtime retains unfinished task ownership. Inspect
`conn.shutdown_report` or `host.shutdown_report` as well: transport completion
does not attest that external business effects or execution leases have stopped.
Timed-out synchronous policy/DNS/root-loading jobs remain accounted for until
they actually exit; shared worker pools have their own shutdown APIs. See
[pump ownership](crates/syntra-net/src/pump.rs) and
[runtime shutdown](crates/syntra-runtime/src/shutdown.rs).

Connection loss, suspension and incomplete shutdown do not prove a remote method
did not execute. Keep terminal outcomes, external execution leases, durable
recovery state and carrier task ownership distinct. Recovery is explicitly
configured and negotiated; enabling a carrier or reconnect helper does not make
arbitrary retries safe or provide exactly-once business effects.
The recovery wire service and its `profile_version` fields describe a negotiated
update/recovery extension. They do not make encryption a separately selectable
protocol. Keep the service schemas and method contracts at their existing source
boundaries.

The opt-in [reconnecting client](crates/syntra-net/src/client.rs) owns one
dial loop, fresh connector inputs and generation-fenced calls/results. Requests,
notifications, keys, cipher state and resume state are never replayed into a
successor. Outage budgets include paused/offline time. `CoreReady` is not recovery
readiness: each generation negotiates recovery anew, and applications explicitly
restore subscriptions and reconcile durable progress.

## Enrollment and secret ownership

The opt-in [`native-enrollment` module](crates/syntra-net/src/enrollment.rs)
provides a bounded SQLite reference store with protected authorization keys,
rotation/recovery state, tombstones and anchored updates. It requires deployment
implementations of authenticated time, key protection/cryptographic erasure, an
external linearizable rollback authority, independent enrollment/recovery
authorization and durable-device-ack verification. A second local file is not an
independent rollback authority. Uncertain commits/anchor settlement remain
fail-closed until reconciled; do not replay an uncertain transition as a fresh one.

Provision private database/lock directories and protect path replacement,
symlinks, journal, temporary, backup and restore paths. Run synchronous store and
protection operations on a bounded blocking executor. Explicit policy permits
TCP and/or WSS enrollment bindings; WS is not an enrollment binding. Sampling
helpers alone do not provide collision checks or secure persistence. Independently
distribute server pins; the
[pin-update authority](crates/syntra-net/src/enrollment/pins.rs) must not
learn trust from the connecting peer.

The [enrollment authenticator factory](crates/syntra-net/src/enrollment/authorization.rs)
requires the same store for Noise admission and current-validity policy, verifies
the explicit hello credential through `ApplicationIdentity`, and enforces the
same principal as the enrollment binding. Credential-less returning devices need
explicit application policy. The pump rechecks validity before hello/ready,
inbound dispatch and outbound delivery, and while idle. Deployment-owned handler
effect-commit fencing is still required; transport revocation cannot roll back
business effects. There is no supplied enrollment RPC or deployment credential.

`Secret32` is non-cloneable, redacted and zeroized on drop; transient plaintext
buffers use zeroizing wrappers where owned by the kernel/driver. The
[crypto resolver](crates/syntra-core/src/secure_channel/resolver.rs) overwrites retained
DH/cipher keys on destruction, but Snow's internal handshake/KDF scratch copies
have no erasure API. Runtime messages, application copies, allocator/runtime
storage and JS/engine copies do not have a complete erasure guarantee. SQLite
unlink/secure-delete does not erase media or backups: deployment key protection
must make retired wrapped keys irrecoverable across the entire backup boundary.

## WASM and ABI boundaries

Core and runtime expose portable Rust APIs for WASM. The encryption kernel keeps
its browser entropy and elapsed-clock support. Embedders own carrier I/O,
scheduling and lifecycle integration. `syntra-net` has no driver exports on
wasm32 and rejects its native-only features; the
[target contract](crates/syntra-net/tests/target_contract.py) checks that boundary.

`syntra-ffi` is native-only. Its `production` feature uses shared Initiator/Host
and recovery code but exposes plaintext frames to an application-owned driver.
That driver must implement Syntra encrypted establishment and record protection,
plus the selected carrier's security and ordered I/O. A raw TLS socket alone does
not complete this ABI's Syntra implementation. The separate `test-fixture` ABI is
loopback-only and must not ship.

## Verification scope

Run the isolated native, WASM, FFI and carrier checks in
[CONTRIBUTING.md](CONTRIBUTING.md). Kernel browser execution and Docker integration
are separate from compilation. Public context fixtures establish encoding
agreement, not independent cryptographic vectors.
Same-library round trips and candidate contract checks are not formal conformance
or independent cross-language interoperability evidence. Preserve the revision
and scope of each recorded result. The
[unified implementation-evidence runner](CONTRIBUTING.md#implementation-evidence)
checks declared inputs and optional candidate agreement separately from its local
execution lanes. Its formal-conformance gate remains `NOT_EXECUTED`.
