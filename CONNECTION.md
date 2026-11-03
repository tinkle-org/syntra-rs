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
`3f7e8ea037fefcc5c86101d23e7722c83e28a0d3` and preserves the earlier dirty-worktree
observation separately; the baseline HEAD is not the candidate commit. See
[CONTRIBUTING.md](CONTRIBUTING.md#input-provenance-and-authority) for the separate
pinned upstream inputs. No formal conformance, independent
interoperability or independent security-review verdict is claimed here.

## Layer and crate ownership

| Layer | Implementation | Responsibility |
| --- | --- | --- |
| Message mechanics | `syntra-core` | Protobuf envelope codec, validation, message handshake, connection state and RPC rules |
| Message runtime | `syntra-runtime` | Initiator/Host execution, queues, authentication/authorization hooks, recovery and lifecycle |
| Encryption | `syntra_core::secure_channel` | Authenticated context, Noise handshake, ordered cipher state, protected record bounds and frame-stream assembly |
| Native I/O | `syntra-transport` | Carrier-neutral record driver, optional TCP/WebSocket carriers and reconnect helper |
| Browser binding | `syntra-web` | JavaScript API, browser-local WSS driver, callbacks, queues and page lifecycle |
| Native ABI | `syntra-ffi` | Shared-runtime plaintext frame boundary; embedding driver supplies encryption and carrier I/O |
| Verification | `syntra-integration` | Unpublished fixture peer and Docker carrier tests |

The native and browser connection drivers compose the same encryption kernel
with the same message runtime. Their scheduling and platform capabilities differ;
their crate boundaries do not define different security protocols.

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

Each connection requires fresh cryptographic randomness for ephemeral handshake
keys. Entropy failure aborts establishment. Authorization keys and lookup handles
must be independently sampled, with collisions, nonzero values, epoch allocation,
scope, expiry and revocation enforced by the enrollment owner. `Enrollment::generate`
is a sampling helper, not a store or complete enrollment policy.

Reconnect creates fresh handshake and cipher state. Never persist, clone, restore
or reset live traffic keys/nonces, or reuse them after cancellation, process
restart or suspension. Returning mode must not silently fall back to bootstrap;
carrier failures must not trigger a weaker carrier. See the
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

Native `syntra-transport` defaults to no carrier features. Its record driver is
available without socket dependencies but requires a native Tokio runtime.
Explicit `tcp` and `websocket` features add I/O implementations; `reconnect` adds
the opt-in connection manager, and `native-enrollment` adds a native host
reference. These switches do not switch encryption on or off.

| Carrier | Record binding | Additional boundary |
| --- | --- | --- |
| TCP | u16 big-endian message length followed by M1, M2 or ciphertext bytes | Production carrier with integral Syntra encryption; packet boundaries have no protocol meaning |
| WebSocket | One binary WebSocket message per M1, M2 or ciphertext record; no outer u16 prefix | Native WS dials are restricted to loopback development fixtures |
| WSS | Same binary-message binding, with `Carrier::SecureWebSocket` | Verified TLS 1.3 in addition to the provisioned Noise pin |

The WebSocket endpoint is `/syntra/1.0/ws`, with exact subprotocol `syntra.1.0`.
TLS protects the WSS carrier; it does not replace Syntra's handshake or encrypted
records. HTTP is used for the WebSocket upgrade, not a request-response transport.

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
server's deployment must additionally enforce its Origin policy.

For native WSS, enable `syntra-transport`'s `websocket` feature and call
`syntra_transport::websocket::connect` with a provisioned
`syntra_core::secure_channel::ClientConfig`, explicit credentials, runtime
configuration and transport limits. The returned client is ready after protected establishment
and the message handshake. `connect_with_roots` accepts explicit trust roots;
`TlsServerSettings::new` and `accept_tls_stream` provide the native server path.
See the [native module](crates/syntra-transport/src/websocket.rs) and
[record driver](crates/syntra-transport/src/pump.rs) for exact signatures and
ownership contracts. Native WSS owns TLS termination directly, checks TLS 1.3 and
disables early data; forwarded headers or caller-terminated TLS cannot upgrade a
WS binding into WSS. Callers must retain and close returned handles.

## Budgets, emission and lifecycle

Native and browser drivers bound the full attempt through message readiness to
15 seconds, Noise plus encrypted-hello confirmation to 5 seconds, and one frame's
output across all records to 10 seconds. Current defaults bound next-record waits
and partial-frame assembly to 30 seconds and carrier teardown to 1 second; consult
[`pump::Limits`](crates/syntra-transport/src/pump.rs) and
[`connection::Limits`](crates/syntra-web/src/connection.rs) for validation.
The next-record deadline includes idle time, partial carrier prefixes, fragment
reassembly and control traffic. A partial inner frame gets one absolute assembly
deadline from its first incomplete authenticated plaintext; trickled records do
not renew it. The deadline survives readiness/task handoff and backpressured
delivery. Completing that frame may start a new assembly budget for the next one.
Switching layers does not grant a fresh setup budget or cryptographic lifetime.
Expiry, clock regression or unknown elapsed continuity retire the connection.

Custom initiator writers must pass the original `Vec<u8>` dequeued from the runtime
receiver, without cloning or reallocating, to `Initiator::prepare_outbound` once
immediately before synchronous handoff/encryption. `None` discards stale output;
after `Some(bytes)`, finish that unit in order or abort. Do not re-gate fragments
or ciphertext. The native pump additionally rechecks connection authorization
and lifecycle gates before encrypting output and before carrier I/O. Custom
drivers must preserve these checks for both initiator and host output.

`Channel::encrypt` consumes the next send nonce. Retain the resulting immutable
ciphertext and its write future across partial writes/backpressure; finish it in
order or abort. Never re-encrypt a replacement or relabel ciphertext after a
timeout, cancellation, revocation or lifecycle change. Recheck delivery and
authorization gates before repolling carrier I/O. Browser `send` failure is also
terminal; `bufferedAmount` measures local buffering, not peer receipt.

Runtime writer and notification capacities count items, not bytes. With frames
up to 1 MiB, a queue capacity must not be described as a byte-memory cap. Host
writer accounting includes queued and active work, with separate terminal-output
slots and execution leases. Generic initiator notification overflow drops the
newest item and counts losses; recovery routing has its own bounded inbox. Browser
receive queues have separate message/byte bounds **after** browser assembly and a
separate output buffering threshold. Native carrier buffers and process-wide
execution/policy budgets are additional bounds. See the
[runtime configuration](crates/syntra-runtime/src/connection.rs),
[host writer](crates/syntra-runtime/src/host.rs) and driver sources.

Retain the whole `ClientHandle` or `HostHandle`, not just `conn` or `host` captured
by an async task: the handle owns the pump. The
[TCP listener](crates/syntra-transport/src/tcp.rs) acquires admission before socket
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
[pump ownership](crates/syntra-transport/src/pump.rs) and
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

The opt-in [reconnecting client](crates/syntra-transport/src/client.rs) owns one
dial loop, fresh connector inputs and generation-fenced calls/results. Requests,
notifications, keys, cipher state and resume state are never replayed into a
successor. Outage budgets include paused/offline time. `CoreReady` is not recovery
readiness: each generation negotiates recovery anew, and applications explicitly
restore subscriptions and reconcile durable progress.

## Enrollment and secret ownership

The opt-in [`native-enrollment` module](crates/syntra-transport/src/enrollment.rs)
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
[pin-update authority](crates/syntra-transport/src/enrollment/pins.rs) must not
learn trust from the connecting peer.

The [enrollment authenticator factory](crates/syntra-transport/src/enrollment/authorization.rs)
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

## Browser and ABI boundaries

`syntra-web`'s default `browser-connection` feature exposes protected WSS through
`ConnectionOptions`, `connect`, `call`, `poll_notify` and `close`. It uses the same
encryption kernel, but browser APIs do not expose all native TLS, upgrade-header,
pre-reassembly buffering or secret-erasure controls. The client validates the
exact WSS URL before constructing a WebSocket, then requires `syntra.1.0` as the
selected subprotocol and rejects negotiated extensions. JavaScript cannot inspect
the raw Upgrade headers, disable implicit cookies or compression offers, select
TLS versions/custom roots, or control Ping/Pong. Deployment must enforce direct
host TLS termination, TLS 1.3+, cookie rejection, disabled compression and an
Origin policy. Browser TLS validation alone does not establish that policy.

Hidden/pagehide lifecycle events retire connections; an observation gap exceeding
two seconds also retires
the connection before buffered work proceeds, even on a visible page. This is
separate from the kernel's dual-clock disagreement tolerance. Background operation
is unsupported. Browser close is abortive and bounded; it does not attest delivery
of an authenticated close or remote completion. See the explicit
[`connection::SUPPORT`](crates/syntra-web/src/connection.rs) disclosure and
[browser procedures](crates/syntra-web/tests/browser.md). This is not a claim of
native-equivalent WSS or full protocol conformance.

`syntra-ffi` is native-only. Its `production` feature uses shared Initiator/Host
and recovery code but exposes plaintext frames to an application-owned driver.
That driver must implement Syntra encrypted establishment and record protection,
plus the selected carrier's security and ordered I/O. A raw TLS socket alone does
not complete this ABI's Syntra implementation. The separate `test-fixture` ABI is
loopback-only and must not ship.

## Verification scope

Run the isolated native, WASM, FFI and carrier checks in
[CONTRIBUTING.md](CONTRIBUTING.md). Browser execution and Docker integration have
their own procedures; compilation alone does not run either. Public context
fixtures establish encoding agreement, not independent cryptographic vectors.
Same-library round trips and candidate contract checks are not formal conformance
or independent cross-language interoperability evidence. Preserve the revision
and scope of each recorded result. The
[unified implementation-evidence runner](CONTRIBUTING.md#implementation-evidence)
checks declared inputs and optional candidate agreement separately from its local
execution lanes. Its formal-conformance gate remains `NOT_EXECUTED`.
