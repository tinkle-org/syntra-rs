# SC1 implementation and verification

This document describes `crates/syntra-secure-channel/` and the unpublished
native adapter `crates/syntra-sc1-transport/`. They target the accepted upstream
profile `SNTR-SC1-WSS-V1`. The implementation remains experimental; host-policy
and verification gaps are documented below. No formal conformance verdict or
independent security audit is claimed.

The contract is [RFC 0007 §11.4](https://github.com/tinkle-org/syntra/blob/0e8b0f8a4a789cb3d6d00b993e281867d2325e06/rfcs/0007-secure-channel-device-authorization.md)
and its companion specifications at upstream commit
`0e8b0f8a4a789cb3d6d00b993e281867d2325e06` (PR #18, accepted 2026-10-29).
The [SC1/WSS manifest](https://github.com/tinkle-org/syntra/blob/0e8b0f8a4a789cb3d6d00b993e281867d2325e06/conformance/manifest/sc1-wss.yaml)
registers `CONF-SCW-001` through `CONF-SCW-024`. Registration does not establish
an executed result. See [MIGRATION.md](MIGRATION.md) for the separate extraction,
proposal-review and accepted-contract provenance. Current local results and
earlier verification records are in [AUDIT.md](AUDIT.md#current-recorded-verification).

The prerelease source/API/wire break replaces `syntra-tcp` and `syntra-ws-sc1`
with `syntra-sc1-transport`. `default = []` exposes WSS as the default carrier;
`development-carriers` adds the restricted `tcp` module and plaintext loopback
WS. The public `pump` module is carrier-neutral and does not depend on `tcp`.
Baseline `syntra-ws` keeps its Frame-per-message framing and endpoints. Custom
runtime writers must also honor the emission gate described below. Browser SC1
is not added. The production FFI remains a separate state machine and is not
automatically an SC1 SDK.

Use **Rust 1.88.0** for current verification and production builds, for example
`export RUSTUP_TOOLCHAIN=1.88.0` before running the commands below. The crate
MSRV floor is also **1.88**. Production binaries must be built with a
security-patched toolchain. Current dependency pins are:

| Dependency | Version |
| --- | --- |
| `snow` | =0.10.0 |
| `getrandom` | 0.3 |
| `zeroize` | 1 |
| `tokio` | 1 |
| `tungstenite` / `tokio-tungstenite` | 0.26 |
| `rustls` | 0.23 |

There are no releases yet; future releases use repository-root `vX.Y.Z` tags.

## Construction and trust

| Mode byte | API constant | Noise name | Client material |
| --- | --- | --- | --- |
| 1 | `Mode::Bootstrap` | `Noise_NK_25519_ChaChaPoly_SHA256` | Authenticated, pinned server public key; no authorization key |
| 2 | `Mode::Returning` | `Noise_NKpsk0_25519_ChaChaPoly_SHA256` | Same server pin plus a provisioned, nonzero 32-byte authorization key |

Both modes use X25519, ChaCha20-Poly1305 and SHA-256 through `snow 0.10.0`
with its standard providers. `Enrollment::generate` and the Noise handshake
use fallible OS randomness; each handshake uses fresh Noise ephemeral
randomness. There is no deterministic RNG option, cipher-state serialization,
nonce restoration, in-place rekey, suite negotiation or automatic
downgrade/fallback. Reconnect always performs a fresh handshake and starts
new ordered cipher states.

Bootstrap authenticates the pinned server, **not an enrolled client
principal**. Returning mode proves possession of a high-entropy authorization
key. Neither a public handle nor successful M1 processing alone establishes a
freshly confirmed client session. A replayed M1 may elicit M2, but cannot
confirm the responder's new channel without an authenticated client record
under the new keys. The encrypted `ClientHello` normally supplies that first
record. No application data is carried in either Noise handshake payload.

The server pin and endpoint scope must come from an authenticated provisioning
source. Scope is valid UTF-8, compared as exact bytes rather than a URL-derived
identity; there is no text normalization. Context bytes, handles, lengths,
timing and carrier metadata are public. Protecting payloads does not hide them.

## Canonical context

The canonical public context `P` is this concatenation. All offsets are
zero-based, and ranges are half-open. Let `S = len(scope)`.

| Offset | Bytes | Field |
| --- | ---: | --- |
| `[0,13)` | 13 | Exact ASCII `syntra.sc1.v1`, with no terminator |
| `[13,14)` | 1 | Mode: bootstrap `1`, returning `2` |
| `[14,15)` | 1 | Carrier: TCP `1`, WS `2`, WSS `3` |
| `[15,19)` | 4 | `server_key_id`, unsigned big-endian u32 |
| `[19,27)` | 8 | Enrollment epoch, unsigned big-endian u64 |
| `[27,35)` | 8 | Enrollment lookup handle, opaque bytes |
| `[35,37)` | 2 | Scope byte length `S`, unsigned big-endian u16 |
| `[37,37+S)` | S | Valid UTF-8 intended endpoint/server scope, `1..255` bytes |

The total is **`37 + S` bytes**, or 38–292 bytes. There is no padding,
optional field or trailing content. Bootstrap requires an all-zero handle and
epoch zero; returning mode requires a nonzero independent handle and nonzero
current epoch. Length counts UTF-8 bytes, not characters. `server_key_id` has
no nonzero constraint. Carrier, scope and server-key ID must match the
responder's configuration.

These canonical bytes are the public prefix of M1 and the **entire Noise
prologue: `prologue = P`**. There is no additional domain prefix, terminator or
revision field. Altering any field changes the authenticated handshake context.
The old Rust `SNTRSC1L`/local-revision-1 format and the old Go draft domain are
historical formats, rejected rather than accepted as aliases. Old local endpoint
and subprotocol tokens are also rejected; there is no fallback.

Exact fixtures in
`crates/syntra-secure-channel/tests/fixtures/sc1_context_v1.rs` transcribe the
four public context/prologue examples from `conformance/plans/sc1-context-v1.json`
at proposal-review commit `94404d7378136d8b6c88ece28bf945c88d1653ba`.
Their bytes also match the [registered context vectors](https://github.com/tinkle-org/syntra/blob/0e8b0f8a4a789cb3d6d00b993e281867d2325e06/conformance/test-vectors/sc1/context-vectors.yaml)
at the accepted-contract pin; the original plans JSON remains upstream.
**These are public encoding fixtures only, not
independent cryptographic vectors.** Parser fixtures use a dummy 48-byte suffix;
they do not specify Noise ciphertext, fixed ephemeral keys, or independent
Go/Rust interoperability. The recorded local tests do not establish independent
cryptographic or interoperability evidence.

## Handshake and record wire format

- **M1:** canonical context followed by exactly 48 Noise bytes (32-byte
  ephemeral public key and the 16-byte tag for an empty handshake payload).
  Its total size is `37 + S + 48`, or **86–340 bytes**.
- **M2:** exactly 48 Noise bytes, with an empty handshake payload.
- **Transport record:** 1–65,519 plaintext bytes plus a 16-byte AEAD tag:
  17–65,535 ciphertext bytes. Empty plaintext records are rejected.

The client authenticates the complete context through the prologue and its
provisioned server public key. X25519 all-zero shared results are rejected.
Unexpected lengths, versions, modes, context, payloads and extra bytes are
terminal. After `Split`, both directions use standard ordered Noise transport
messages with empty associated data. Send and receive nonce state is
independent and never copied or reset.

### Restricted-development TCP

Every message, **including M1 and M2**, is encoded as:

```text
u16BE(message byte length) || message bytes
```

The length excludes its own two bytes. TCP packet boundaries have no meaning.
Partial reads/writes and coalesced packets are handled by the adapter. Zero
lengths, over-capacity handshake messages and incomplete messages fail.
During establishment the first wrapper is bounded to 340 bytes and M2 to 48.

The binding identifier is `syntra.sc1.v1`, with `Carrier::Tcp` in the context.
This module requires `development-carriers`; there is no default TCP port.
Generic stream helpers remain development fixtures. Wrapping one in TLS does
not turn it into the WSS carrier or permit `Carrier::SecureWebSocket`.

### WebSocket and secure WebSocket

Each binary WebSocket **message** contains exactly one M1, M2 or ciphertext
record. There is **no SC1 u16 prefix** inside it. WebSocket fragmentation is
reassembled by the underlying library; WebSocket frames are not SC1 records.
The exact subprotocol is `syntra.sc1.v1` and the endpoint path is
`/syntra/v1/sc1/ws`. Text, oversized, truncated and unauthenticatable
messages fail. Ping/Pong/Close are carrier control messages, never channel
confirmation, application completion or RPC results. Control frames cannot
extend an absolute receive/establishment deadline.

`syntra_sc1_transport::websocket::connect` accepts `wss://` with
`Carrier::SecureWebSocket`. With `development-carriers`, `ws://` requires
`Carrier::WebSocket`, a parsed loopback IP or `localhost`, and a resolved
loopback peer. It requires exactly the endpoint path above, with no userinfo,
query or fragment. The host requires exactly the subprotocol token and rejects
`Authorization` and `Cookie` headers; it does not treat `Origin` as
authentication. The client sends no credential in the Upgrade. WSS uses TLS
1.3, native trust roots and hostname validation in addition to the provisioned
Noise server pin; `connect_with_roots` instead trusts only the supplied roots.
Both build the TLS connector internally with early data disabled. The WSS
server API owns TLS establishment from a raw stream via `accept_tls_stream`
and `TlsServerSettings`. Caller-terminated TLS or proxy headers cannot assert
WSS through the development `accept_stream` API. The development `accept`
helper rejects non-loopback peers; raw-stream fixtures require caller-enforced
development confinement and admission bounds. Browser SC1 is not implemented.

There is no HTTP/HTTPS request-response transport or plan for one in this
implementation. HTTP is used only for the WebSocket upgrade. UDP is deferred.

### Authenticated frame stream

The authenticated plaintext in each direction is:

```text
u32BE(serialized Frame byte length) || serialized Frame || next prefix || ...
```

Serialized frames are 1–1,048,576 bytes (1 MiB). The four-byte frame length
is encrypted with the frame stream and may itself span records. Frames may
span records; a receiver also accepts multiple frame envelopes in one record.
`Send` serializes a whole envelope against other sends, and the pump delivers
one owned frame at a time. Receivers validate lengths before frame allocation.

The core Protobuf `Frame` schema is unchanged. Application payloads remain
opaque. AEAD associated data for transport records is **empty**: neither the
TCP length header nor WebSocket framing is passed as ciphertext header AD.
Those outer boundaries delimit records; authenticated stream ordering and the
encrypted u32 frame length protect reconstruction. Tampering is terminal,
not a resynchronization opportunity.

A 1 MiB serialized frame uses 17 records. Its TCP overhead is
`4 + 18*17 = 310` bytes; this excludes handshake, Syntra readiness,
carrier/IP overhead and application payload encoding.

## Limits, cancellation and ownership

`syntra_sc1_transport::Limits::default()` applies through the shared pump:

| Option | Default | Accepted nonzero range |
| --- | --- | --- |
| `attempt_timeout` | 15s | Positive, at most 24h; covers dialing/TLS/upgrade, SC1 and core readiness |
| `channel_timeout` | 5s | Positive, at most 24h; SC1 establishment and responder's encrypted hello confirmation |
| `record_timeout` | 30s | Positive, at most 24h; next complete record including idle wait |
| `frame_timeout` | 30s | Positive, at most 24h; from first incomplete plaintext, never refreshed by trickle records |
| `write_timeout` | 10s | Positive, at most 24h; one entire frame's encrypted output |
| `close_timeout` | 1s | Positive, at most 24h; owner-task join after close, then abort |
| `lifetime` | 24h | Positive, at most 24h, configurable downward |

SC1 `Limits::validate` requires `writer_capacity`, `notification_capacity` and
`max_outstanding` to be in `1..=1024`. This validation applies at the SC1
adapter boundary, not to every runtime constructor. The shared runtime default
`ConnectionConfig::default().max_outstanding` is 32, matching the pending-RPC
default in `SNTR-SCW-012`. It affects all transports using the runtime defaults;
callers can set an explicit value. The initiator bounds pending outbound RPCs
and the host bounds active inbound RPCs using this setting. The new
`default_max_outstanding_is_32_per_sntr_scw_012` test in
`crates/syntra-runtime/src/connection.rs` checks the default value only; it does
not test admission of a 32nd call or refusal of a 33rd.

Writer and notification queue defaults remain 256 each. The writer queue holds at most 256
frame items; with a 1 MiB frame ceiling this permits up to 256 MiB of
serialized queued frame bytes per direction. Deployments should use a smaller
queue appropriate to their memory budget. There is one incomplete receive
frame, one pending authenticated record, one outgoing frame/record sequence,
and a bounded batch of complete frames per received record. No adapter creates
a task per frame or per policy lookup.

The record deadline includes idle wait and partial carrier input. The frame
assembly deadline begins when authenticated decoding leaves an incomplete
frame, before backpressured delivery, and is not refreshed by later trickle
records for that frame. Caller deadlines can shorten operations. A successful
handshake does not bind the transport lifetime to the dial future's lifetime.

The pump enforces an absolute transport lifetime after channel establishment,
including while the socket is idle; establishment has separate bounded attempt
and channel budgets. The channel also refuses use at 24h of age or after
**2^32 records per direction**. Enrollment expiry and revocation remain host-owned
policy checks; the channel does not implement periodic enrollment revalidation.
The low-level transport does not reconnect or rotate keys automatically.
The opt-in reconnecting client performs a fresh handshake for every connection.

Each connection has one reader and one writer, supervised by one owner task.
The writer retains the exact ciphertext across `write_all` partial writes and
does not select another frame mid-write. RPC-call cancellation does not cancel
this owned output. Write error/timeout/connection cancellation aborts the
channel; it never encrypts a replacement under a consumed nonce. A locally
rejected plaintext length in the socket-free `Channel::encrypt` does not
consume a nonce, but it still permanently poisons the channel. Authentication
failure, framing error and every channel record error also poison channel
state. Direct users of
`Channel::encrypt` must retain its returned ciphertext until successful
ordered emission, or call `Channel::close` on output error/cancellation.
There is no resynchronization scan. Incomplete record/frame bytes are
discarded at EOF, never dispatched. Complete-boundary EOF is transport loss
rather than authenticated proof of orderly application completion.

Until core readiness, establishment I/O stays inline in the connect future;
there is no background pump to orphan. Cancelling a partial dial drops its
carrier halves before a replacement dial can begin. A ready-containing decoded
batch is ingested completely before handing I/O to the background pump; readiness
cannot cancel ingestion midway through that batch. Any partial frame decoder
state and its existing absolute frame deadline are carried into the pump without
granting a new assembly budget. Accepted connections likewise flush `ready`
inline before transferring ownership to background tasks.

After readiness, dropping a low-level handle signals its owner. The owner
poisons cipher state, aborts/joins both I/O children, drops the stream, and calls
runtime transport-loss teardown so cloned initiators and pending calls settle.
`ClientHandle::close(self).await` waits for this bounded teardown. Close may abort
unfinished ciphertext; the channel is then discarded, never reused. Fixtures must retain
whole handles for as long as the connection is live: spawning a detached
waiter that only touches a sub-path such as `h.host` moves just that field
into the waiter future under disjoint async-block capture and drops the rest
of the handle including its pump at the end of the enclosing scope,
which tears the connection down.

`ClientHandle::close_gracefully(grace)` and `HostHandle::close_gracefully(grace)`
share one absolute grace deadline across runtime drain, carrier flushing,
shutdown and completion acknowledgement, capped by channel lifetime. Grace
expiry returns `Error::Timeout` and aborts unfinished output. Cancelling the
graceful future also aborts its owned pump. Channel authentication/framing
failures, I/O failures and runtime security-close reasons abort immediately
even while graceful drain is requested. Calling the bare runtime
`close_gracefully` directly cannot account for the adapter's already-dequeued
ciphertext and does not guarantee carrier drain.

The development `syntra_sc1_transport::tcp::Listener` acquires admission
before accepting. Its permit stays with the accepted byte stream through SC1
handshake, handle lifetime and pump teardown. New accept calls backpressure
when the limit is reached. Generic accepted streams and WS callers must
enforce their own aggregate connection/handshake/crypto budget, such as an
owned semaphore permit retained alongside or inside each stream.

Closing notifications are tolerated for drain. In `CLOSING`, structurally
valid, correctly versioned notifications neither complete an RPC nor count as
misbehavior; they are queued when possible and dropped with loss accounting
when full. Principal withdrawal is resumable: terminal `UNAUTHENTICATED` work
persists across cancellation, and a retry continues queueing and closing
rather than leaving a half-closed connection. Graceful close waits for both
inflight RPCs and pending withdrawal terminals before closing.

SC1 establishment, framing, authentication and connection-fatal policy failures
terminate the carrier without a diagnostic payload or promised WS close code.
An ordinary post-ready method denial returns `PERMISSION_DENIED` and leaves
the connection usable. Normal writer exhaustion
attempts TCP shutdown or WS Close within the close budget. No carrier close
is an authenticated SC1 close or delivery ack. Unknown RPC outcomes require
application-level handling; there is no automatic RPC replay, session
resumption, subscription restoration or durable event recovery.

## Credential records and session policy

`KeyStore::lookup(&Context)` is a host-owned, read-only lookup into a
protected store. Records are scoped by the full provisioned routing tuple
(server-key ID, carrier, exact scope, handle and epoch). Lookup occurs before
possession is established. It must be nonblocking, bounded and free of
principal-granting or enrollment side effects. A matching handle/epoch is
only a routing result.

Returning-mode handshake entry points reject an all-zero AK. The client
returns `Error::Invalid` before constructing Noise state or consuming handshake
randomness. The responder returns `Error::Authentication` after lookup returns
the zero key and before Noise construction. These errors contain no key
material. `Secret32::new` remains an unrestricted 32-byte container; the
handshake checks do not establish that a provisioned nonzero key was generated
securely or that its enrollment is still authorized.

After M2 the responder still has **no verified client identity** and cannot
encrypt application records. A first successfully authenticated client
transport record enables a private-constructed `VerifiedIdentity`. It carries
public context and the 32-byte Noise handshake hash, never keys. Bootstrap
identity confirms fresh participation in the pinned-server channel; it does
not prove a device enrollment. Returning identity confirms possession under
fresh keys.

The adapters additionally require a complete, valid Syntra `hello` as the
first encrypted envelope, with no coalesced extra envelope or partial trailing
envelope. Only then do they invoke `AuthenticatorFactory::create(&VerifiedIdentity)`
and construct a runtime `Host`. The factory should re-read current enrollment
policy and return an `Authenticator` that captures this channel's identity.
Runtime `Authenticator::authenticate(hello.credential)` binds the principal
before `ready`. Bootstrap requires application credentials or an explicitly
authorized provisioning policy; returning AK possession still needs current
principal/scope policy and per-method authorization.

Replaying M1 may allocate a bounded transient handshake and produce a fresh
M2. It never invokes the factory, binds a principal, dispatches RPCs or
releases sensitive output. An encrypted hello from another channel fails under
the fresh keys. The client awaits runtime `ready` before issuing protected
RPCs.

An empty credential never implicitly means "use the channel principal." The
host verifies its application identity separately and checks current
enrollment before `ready`. Every method still needs authorization; the
runtime `Handler::authorize` default denies. A permission denial leaves the
connection usable; an expired/revoked binding reported as `UNAUTHENTICATED`
withdraws the principal, settles other calls and closes the connection.

The same-principal binding, current validity and continuing revocation checks
above are obligations of the host's implementations. The workspace does not
supply a complete identity/authorization store or periodic host revalidation;
those remain implementation work, not completed features of the factory hook.

### Provisioning boundary and audited TODO

**Only explicit authenticated out-of-band provisioning is supported.**
`Enrollment::generate(epoch)` samples the 32-byte authorization key and an
independent random eight-byte handle. The host must allocate a nonzero returning
epoch, reject/resample an all-zero AK or handle, and check handle collisions in its
scoped store before provisioning. A handle must not be a key prefix, hash of a
key, principal-derived value or counter.

Store transactionality, secure delivery, client acknowledgement, retry and
recovery after lost delivery, protected client storage, revocation
dissemination and rotation workflow are host responsibilities. This module
implements **no enrollment RPC or end-to-end issuance/rotation workflow**.
Bootstrap does not implement one implicitly. These are open integration and
audit TODOs, not completed security features.

## Connection orchestration

`syntra_sc1_transport::websocket::connect` dials, completes TLS/Upgrade and SC1,
runs the Syntra hello/ready exchange and checks readiness within one
**15-second total attempt budget**, shortened by the caller where applicable.
The returned client's lifetime is
independent of the dial future: always close it explicitly. This low-level API
does not reconnect. Opt-in reconnect is described below; neither layer replays
RPCs automatically or falls back to a weaker carrier.

The application owns its accept loop and retains each `HostHandle` for as long
as that connection is served; dropping a handle aborts its pump. WSS callers
bound aggregate admission across TLS, Upgrade, SC1 and the live connection.
In the development `tcp` module, `Listener::accept_socket` acquires a permit
before accepting, and the permit stays with the stream through its handle
lifetime. Drive each admitted stream's `tcp::accept_stream` concurrently so
one stalled handshake cannot block later accepts. `tcp::connect_stream` and
`tcp::accept_stream` are development helpers for caller-owned ordered streams.

The opt-in `client` module wraps this transport with explicit bounded reconnect
policy. Root builds exclude the integration crate through `default-members`;
`--workspace` includes it and intentionally enables development carriers. CI's
separate `--no-default-features` run checks isolated WSS-only defaults.

### API sketch

These are signatures from `crates/syntra-sc1-transport/src/websocket.rs`, not
a complete provisioning or client-lifecycle example. Types `ClientConfig` and
`ServerConfig` come from `syntra-secure-channel`, `ConnectionConfig` and
`Handler` from `syntra-runtime`, and handles, `AuthenticatorFactory`, `Limits`
and `Error` from `syntra-sc1-transport`. `Arc` is `std::sync::Arc`.

```text
websocket::connect(
    url: &str,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> impl Future<Output = Result<ClientHandle, Error>>

websocket::connect_with_roots(
    url: &str,
    roots: rustls::RootCertStore,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> impl Future<Output = Result<ClientHandle, Error>>

websocket::TlsServerSettings::new(
    certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<websocket::TlsServerSettings, Error>

websocket::accept_tls_stream<S>(
    stream: S,
    tls: &websocket::TlsServerSettings,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> impl Future<Output = Result<HostHandle, Error>>
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static
```

For example, given authenticated provisioning, credential, runtime and limits:

```rust,ignore
use syntra_sc1_transport::websocket;

let client = websocket::connect(
    "wss://example.service/syntra/v1/sc1/ws",
    security, credential, runtime, limits,
).await?;
let reply = client.conn.call("/example.Service/Method", b"hello".to_vec(), 1000).await?;
client.close().await;
```

The security context must use `Carrier::SecureWebSocket`; TLS hostname trust
does not replace the authenticated Noise pin and scope. `TlsServerSettings::new`
takes a DER certificate chain and matching private key and constructs immutable
TLS 1.3-only settings; `accept_tls_stream` takes a raw accepted stream, not an
already terminated TLS stream. Retain whole returned handles while serving a
connection, including alongside any admission permit.

### Reconnecting client

`syntra_sc1_transport::client::ReconnectingClient` is a non-clone owner of one
dial loop and at most one active `ClientHandle`. Its constructor is:

```text
ReconnectingClient::new<F, Fut>(config: ReconnectConfig, connector: F)
    -> Result<ReconnectingClient, Error>
where F: Fn() -> Fut + Send + Sync + 'static,
      Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static
```

Supply a cancellation-safe, cooperatively asynchronous connector that obtains
fresh owned security configuration and credentials for **every invocation**, then
calls `websocket::connect` or `connect_with_roots`. Do not clone secret/key state,
reuse cipher state, block inside the factory/future, or spawn detached partial
dials. Construction requires a live Tokio runtime. The existing SC1/WSS connector
keeps I/O inline until ready and satisfies partial-dial cancellation ownership.
The owner retires the old handle before publishing a replacement, and control
updates coalesce rather than queueing parallel dials.

There is no default retry policy. Every duration in `ReconnectConfig`
(`attempt_timeout`, `reconnect_budget`, `base_backoff`, `max_backoff`,
`close_timeout`) must be nonzero and at most **86,400 seconds (one day)**.
`max_attempts` must be nonzero and `base_backoff <= max_backoff`. The caller
selects `start_paused` and `initial_network_available` explicitly. For example,
given an application-supplied connector with the signature above:

```rust,ignore
use std::time::Duration;
use syntra_sc1_transport::{LifecycleStatus, ReconnectConfig, ReconnectingClient};

let mut client = ReconnectingClient::new(
    ReconnectConfig {
        attempt_timeout: Duration::from_secs(15),
        reconnect_budget: Duration::from_secs(120),
        max_attempts: 5,
        base_backoff: Duration::from_millis(250),
        max_backoff: Duration::from_secs(10),
        close_timeout: Duration::from_secs(2),
        start_paused: false,
        initial_network_available: true,
    },
    connector,
)?;
let mut status = client.subscribe_status();
let current: LifecycleStatus = status.snapshot();
// Inspect current; status.changed().await? yields the next unseen owned snapshot.
// The application decides how to handle readiness, blocking and exhaustion.
```

#### Status and generation contracts

`client.status()` returns an owned `LifecycleStatus`.
`subscribe_status()` returns `client::StatusReceiver`; both
`snapshot(&mut self) -> LifecycleStatus` and
`changed(&mut self).await -> Result<LifecycleStatus, RecvError>` return **owned**
states, never public watch borrow guards. `snapshot` marks the current state
seen; `changed` waits for an unseen state and is cancellation-safe. Retaining a
snapshot across an await or a client control call cannot block status publication.
This is a watch of current state, not an event log: slow consumers can miss
intermediate `Connecting`, `Backoff`, `CoreReady` or other states.

`LifecycleStatus::CoreReady(CoreReady { generation, connection_id, version })`
means SC1 and the core hello/ready exchange completed. **CoreReady is not recovery
ready.** Negotiate application recovery separately for every generation before
application operations that depend on restored state. A status snapshot does not
reserve that generation or guarantee it remains live.

- `call(&self, method: &str, payload: Vec<u8>, timeout_ms: u32)` returns a future
  yielding `Result<GenerationValue<Vec<u8>>, CallError>`.
- `next_notification(&self)` yields `Result<GenerationValue<Notification>, CallError>`.
  `Notification` includes `payload: Option<Vec<u8>>`, `dropped_count` and
  `dropped_bytes`; loss totals are local to the tagged generation, not durable
  recovery progress. Concurrent consumers share the runtime's bounded queue.
- Each operation snapshots its active generation **at invocation**, even before
  its future is polled. It neither waits for readiness nor migrates into a
  successor generation. Success includes `generation` and `value`;
  `CallError::Rpc { generation, source }` tags the runtime error.
  `CallError::Unavailable { generation: None }` means no active generation was
  available; `Some(generation)` means the operation may have reached that peer
  and its outcome can be unknown.

No request, mutation, notification, cipher state or application recovery state is
replayed automatically. Resolve unknown outcomes through application semantics;
reconnection does not make a mutation safe to retry.

#### Controls, budgets and failures

| Control | Contract |
| --- | --- |
| `pause()` | Fence the current dial/connection and suppress attempts while paused. |
| `resume()` | Unpause and permit one immediate attempt even with an offline network hint; do not clear blocked errors or exhausted budgets. |
| `network_available(bool)` | Update the network hint and invalidate the old dial/connection even when the boolean is unchanged (for example, network switching); offline suppresses automatic retries. |
| `retry()` | Explicitly clear blocking/exhaustion and start a fresh attempt-count and elapsed-outage budget; unpause and permit one offline attempt. |
| `platform_wake()` | Explicitly retire existing transport/security state after platform wake; preserve pause/network settings and existing retry budgets. |
| `stop()` | Signal terminal shutdown and fence calls; this owner cannot be restarted by retry/resume. |

An outage budget starts at the first attempt or retirement/loss of an active
connection. Its elapsed time includes backoff, cleanup and subsequent pauses or
offline periods; pause/resume/network/wake controls do not replenish it or consumed
attempts. A client initially paused/offline before its first attempt has not yet
started that outage clock. Each dial is bounded by the smaller of
`attempt_timeout` and the remaining outage budget, in addition to the connector's
own limits. Exhaustion stops automatic attempts until explicit `retry()`; a
paused/offline status can remain visible until controls permit another attempt.

Backoff uses OS-random equal jitter over the positive interval from half the
exponential cap (rounded up to nanoseconds) through the cap. The cap is
`min(base_backoff * 2^min(failures - 1, 31), max_backoff)`, with saturating
arithmetic. The failure exponent resets **only after actual core readiness**;
manual retry starts new attempt/time budgets but preserves that exponent.
Controls may expedite an attempt without resetting failure history. An entropy
failure blocks rather than substituting deterministic jitter.

Locally classified configuration/authentication, channel, runtime and framing
failures enter `Blocked(Failure)` until explicit `retry()`; resume or a positive
network hint does not clear that block. I/O, timeout and generic `Closed` failures
use the bounded retry policy. Remote termination after readiness is exposed by
the current pump only as generic `Closed`: the wrapper cannot distinguish a
remote authentication/protocol failure from transient loss and therefore gives
those closes bounded retry, not an inferred auth diagnosis. Generation/control
revision exhaustion retires the owner without counter wrap.

#### Shutdown ownership

`ReconnectingClient::close(&mut self).await -> Result<(), Error>` signals stop and
joins the sole owner within `close_timeout`. **Timeout is incomplete shutdown**:
the join handle stays owned, `ShutdownIncomplete` is observable, and a later
`close().await` can finish joining. Cancelling the close future also retains
ownership. If retiring a connection exceeds its cleanup budget, replacement is
prohibited and cleanup continues to completion under the same owner.

`Drop` signals that owner to finish asynchronous cleanup; it does not synchronously
join it. Keep the Tokio runtime alive for teardown, including after Drop. The
wrapper's mutable close contract is distinct from the consuming low-level
`ClientHandle::close(self)` API. Monotonic timers do not establish suspend
continuity: explicitly call `platform_wake()` when the platform resumes.

### Runtime emission gate

The runtime byte-pump receiver still yields one serialized `Frame` per
`Vec<u8>`. Every custom initiator writer must pass the **original allocation**
from that receiver to `Initiator::prepare_outbound(bytes)` exactly once,
immediately before synchronous carrier handoff/encryption. Do not clone or
reallocate the item: allocation identity distinguishes it from reused wire IDs.

- `None` discards an expired, cancelled, dropped, completed or already handed-off
  RPC item.
- `Some(bytes)` contains a live request reserialized with positive, floored
  remaining milliseconds; its local absolute deadline is unchanged.
  Handshake/control frames pass through unchanged.
- After `Some`, finish the unit in order or abort the carrier. Do not retry,
  rewrite or re-gate it, and never apply the gate to fragments or ciphertext.

The gate linearizes queued-to-emitting handoff with runtime terminal selection;
it does not promise the first OS write occurs before arbitrary awaits inside a
carrier sink. The elapsed RPC clock's continuity across platform suspend remains
the embedding application's responsibility. See the source doc comment on
`Initiator::prepare_outbound` for the authoritative writer contract.

## Secret lifetime and assurance limits

`Secret32` diagnostic formatting is redacted; generated hello messages, raw
buffers and arbitrary application logging are not automatically redacted. Do
not log credentials, whole hellos, authorization keys or private keys.

The code clears accessible ephemeral private buffers and reusable record
scratch, drops handshake/cipher references, and releases runtime-owned
protobuf credential references after emission or close where the API permits.
**Complete memory erasure is not guaranteed:** Snow 0.10.0 exposes no erasure
interface for its internal chaining key, handshake/KDF temporaries or PSK
construction copies. Rust moves, allocator copies, runtime-owned protobuf
credentials, application stores and caller copies are also outside a complete
erasure guarantee. This is a composition-review limitation, not a claim that
`zeroize` can erase inaccessible upstream memory.

The implementation makes no post-quantum, application E2EE, metadata
anonymity, compromised-endpoint protection, measured speed/energy
superiority or independent interoperability claim. Any forward-secrecy
assessment assumes fresh, secret ephemerals and appropriate disposal
throughout the complete composition.

## Local verification status

The recorded acceptance-alignment run passed 377 workspace tests with no
failures and two ignored tests (Docker and browser). Separate SC1 transport
runs passed 52 tests with `--no-default-features` and 60 tests with
`--features development-carriers`. Formatting and pin validation passed;
workspace Clippy exited successfully with 43 unique warnings. These are
working-tree results, not revision-pinned release evidence.

The earlier emission-gate run also checked the explicit FFI variants, C build
contract, WASM compilation, generation drift, workflows, security tools and
Criterion smoke targets. Those checks were not rerun for acceptance alignment.
See [AUDIT.md](AUDIT.md#current-recorded-verification) for commands, feature
configurations and separate run records. Docker and browser execution remain
unverified. [BENCHMARKS.md](BENCHMARKS.md) preserves historical timing captures
without a new performance claim.

Outstanding release evidence includes formal conformance execution,
independent pure-Go/Rust interoperability for both initiator/responder roles
and bootstrap/returning modes, recovery and mobile validation, and independent
security review. Upstream profile acceptance is complete.
Public encoding fixtures alone close none of these gates. No MTProto
implementation code was copied; the repository implementation remains licensed
under Apache-2.0, as recorded in the root manifest and `LICENSE`.
The remaining host-policy, activated protocol/execution-accounting, durable wire
recovery, FFI/mobile and independent-evidence work is tracked in
[implementation status](docs/implementation-status.md).

### Conformance case cross-reference

The case IDs and requirement references below follow the pinned upstream
[SC1/WSS manifest](https://github.com/tinkle-org/syntra/blob/0e8b0f8a4a789cb3d6d00b993e281867d2325e06/conformance/manifest/sc1-wss.yaml).
This table maps local tests and implementation checks to the registered cases;
it does not report formal case verdicts. `Local probe` identifies a direct test
for the described behavior, `Partial` identifies narrower or adjacent evidence,
and `Not demonstrated` means the distinguishing probe is absent. None of these
labels is an upstream `PASS`, `FAIL` or other execution verdict.

Source keys keep the test references readable:

| Key | Source |
| --- | --- |
| C | [Secure-channel integration tests](crates/syntra-secure-channel/tests/channel.rs) |
| X | [Context fixture and negative-recipe tests](crates/syntra-secure-channel/src/context_tests.rs) |
| L | [Channel implementation and unit tests](crates/syntra-secure-channel/src/lib.rs) |
| W | [WSS transport tests](crates/syntra-sc1-transport/tests/wss.rs) |
| P | [Carrier-neutral pump tests](crates/syntra-sc1-transport/src/pump/tests.rs) |
| R | [Reconnecting-client tests](crates/syntra-sc1-transport/src/client.rs) |
| D | [Development TCP tests](crates/syntra-sc1-transport/tests/connectivity.rs) |
| V | [Development WS tests](crates/syntra-sc1-transport/tests/websocket.rs) |
| H | [Runtime host tests](crates/syntra-runtime/src/host.rs) |

| Case and behavior | Upstream requirements | Local evidence | Coverage limits |
| --- | --- | --- | --- |
| CONF-SCW-001: endpoint, subprotocol and Upgrade selection | `SNTR-SCW-001`, `SNTR-SC-013` | W: `verified_wss_real_socket_rpc_both_modes`, `legacy_endpoint_subprotocol_and_header_credentials_are_rejected_over_tls`, `invalid_upgrade_subprotocol_never_sends_sc1` | Partial. Positive WSS and legacy path/token rejection are tested; there is no explicit `syntra.sc1.draft1` Upgrade-token probe. Context-domain rejection belongs to 013. |
| CONF-SCW-002: exact WSS context and prologue | `SNTR-SCW-002`, `SNTR-SC-003` | X: `four_pinned_upstream_context_and_prologue_fixtures`; [fixtures 02 and 04](crates/syntra-secure-channel/tests/fixtures/sc1_context_v1.rs) | Partial. Exact encoding, prologue and real M1 prefix are checked, including UTF-8 scope. These exact fixtures are not exercised through responder acceptance and readiness. |
| CONF-SCW-003: Noise modes, empty payloads, sizes and fresh ephemerals | `SNTR-SCW-003`, `SNTR-SC-001`, `SNTR-SC-004`, `SNTR-SC-005` | C: `both_modes_bidirectional_and_fresh_confirmation`, `wrong_keys_and_prologue_fail_without_fallback`, `tampered_second_flight_and_early_payload_lengths_are_rejected`, `wrapper_is_canonical_and_bounded`; X: `scope_byte_bounds_utf8_and_no_normalization`; L: `snow_entropy_error_is_returned_without_first_flight` | Partial. Boundary parser fixtures use dummy Noise suffixes; full boundary handshakes, wrong-suite peers and valid nonempty-payload peers are not demonstrated. |
| CONF-SCW-004: independent TLS-identity and Noise-pin failures | `SNTR-SCW-004`, `SNTR-TSEC-003`, `SNTR-TSEC-004` | W: `untrusted_certificate_and_wrong_hostname_fail_before_sc1`, `wrong_noise_pin_is_rejected_before_authentication` | Local probe. Trust/hostname and Noise-pin failures independently reject before the factory runs. This is not the full manifest error-code and hygiene matrix. |
| CONF-SCW-005: active-session binary and fragmented records | `SNTR-SCW-005`, `SNTR-SC-007` | W: `verified_wss_real_socket_rpc_both_modes` | Partial. Protected binary RPCs are tested; deliberately fragmented active-session records and control-frame noncompletion are not. Handshake fragmentation is tested separately under 021. |
| CONF-SCW-006: reject Upgrade credentials with HTTP 400 | `SNTR-SCW-006`, `SNTR-SC-013` | W: `legacy_endpoint_subprotocol_and_header_credentials_are_rejected_over_tls`; [Upgrade callback](crates/syntra-sc1-transport/src/websocket.rs) | Partial. Authorization and Cookie rejection is tested, but the test does not assert HTTP 400 or rejection-response hygiene. The callback supplies the 400 status. |
| CONF-SCW-007: direct TLS and refusal of proxy carrier claims | `SNTR-SCW-007`, `SNTR-TSEC-008` | W: `secure_server_rejects_plaintext_and_proxy_tls_claims`; V: `development_ws_rejects_non_loopback_and_secure_carrier` | Local probe for plaintext forwarding-header claims and development-API restrictions. No deployed proxy-topology test is established. |
| CONF-SCW-008: development carriers disabled by default | `SNTR-SCW-008`, `SNTR-SC-013` | W: `default_build_rejects_even_loopback_plaintext_ws`; V: `development_ws_rejects_non_loopback_and_secure_carrier`; [feature declarations](crates/syntra-sc1-transport/Cargo.toml) | Partial. WS default rejection is directly tested in the isolated lane. TCP default absence is a feature-gating check, not a compile-fail probe. |
| CONF-SCW-009: boundary record sizes with empty AD | `SNTR-SCW-009`, `SNTR-SC-007` | C: `record_and_frame_limits_and_segmentation`; L: `Channel::encrypt` and `Channel::decrypt` | Partial. Maximum plaintext chunks round-trip, but the exact minimum and maximum ciphertext sizes are not asserted as a both-role/mode boundary matrix. Empty AD is structural. |
| CONF-SCW-010: inner framing, splits, coalescing and frame bounds | `SNTR-SCW-010`, `SNTR-SC-008` | C: `every_inner_split_point_and_coalescing`, `record_and_frame_limits_and_segmentation`; P: `partial_frame_deadline_includes_every_backpressured_delivery_in_the_batch` | Partial. Parser and channel tests cover small-frame splits, a segmented 1 MiB frame and invalid lengths. They do not establish the complete WSS dispatch matrix. |
| CONF-SCW-011: first hello may span records, with no trailing envelope | `SNTR-SCW-011`, `SNTR-SC-006`, `SNTR-DAUTH-010` | W: `verified_wss_real_socket_rpc_both_modes`; [pump implementation](crates/syntra-sc1-transport/src/pump.rs), `accept_records` | Partial. Ordinary hello/ready is tested. Record-spanning hello and extra complete/partial envelope rejection are implemented but lack dedicated probes. |
| CONF-SCW-012: lifetime, counters, stalled output and fresh reconnect | `SNTR-SCW-012`, `SNTR-SC-009`, `SNTR-SC-011`, `SNTR-SC-012`, `SNTR-SC-014`, `SNTR-DAUTH-009` | L: `record_budget_is_terminal_in_each_direction`, `age_ceiling_is_terminal_without_adapter_timers`; P: `confirmation_cannot_outlive_noise_lifetime_in_either_mode`, `graceful_close_deadline_aborts_a_stalled_carrier`; D: `nonce_consumed_output_error_closes_runtime_and_does_not_dispatch`; R: `replacement_fences_pending_calls_and_never_replays_mutations`; W: `reconnecting_client_replaces_real_wss_with_fresh_generation_both_modes` | Partial. Counter/age tests inject limits; stall and no-replay evidence includes generic/development carriers. WSS reconnect checks connection generations and effects, not distinct traffic keys. The runtime default-value test is supplementary. |
| CONF-SCW-013: malformed contexts rejected before Noise and lookup | `SNTR-SCW-002`, `SNTR-SC-003`, `SNTR-SC-010` | X: `upstream_negative_recipes_reject_before_lookup_and_noise`, `malformed_fields_and_every_truncation_reject_without_lookup`, `invalid_contexts_reject_before_initiator_noise_rng` | Local probe for all 12 negative recipes and lookup avoidance, with a positive lookup control. Full WSS teardown and hygiene assertions remain separate. |
| CONF-SCW-014: replayed M1, missing/corrupt M2 and pre-ready requests | `SNTR-SC-004`, `SNTR-SC-006`, `SNTR-SC-010`, `SNTR-DAUTH-008` | C: `replay_m1_does_not_confirm_and_old_transport_record_fails`; D: `replayed_first_flight_never_calls_factory`; W: `unconfirmed_m2_never_releases_hello_or_credential`; H: `pre_active_request_fails` | Partial. The WSS M2 probe is returning-mode only; replay/factory evidence is development TCP. No complete WSS matrix covers every input and protected effect. |
| CONF-SCW-015: AK, handle, epoch and collision validation | `SNTR-DAUTH-001`, `SNTR-DAUTH-003` | L: `returning_zero_ak_client_rejects_before_noise_rng`, `returning_zero_ak_store_rejects_before_noise`; C: `mode_requires_exact_authorization_key_presence`, `secrets_are_redacted_and_enrollments_are_independent`; X: `malformed_fields_and_every_truncation_reject_without_lookup` | Partial. Zero AK, zero returning handle/epoch and key presence are checked. Store collision handling is not supplied. The responder test checks the error; pre-Noise ordering is also verified in source. |
| CONF-SCW-016: enrollment/application principal mismatch before ready | `SNTR-DAUTH-005`, `SNTR-DAUTH-010` | Adjacent evidence: W, `sc1_authorization_rejection_is_distinct_from_tls_validation` | Not demonstrated. Generic factory denial does not compare trusted enrollment principal A with independently verified application principal B. This remains host implementation work. |
| CONF-SCW-017: carrier-2 context rejected under WSS before lookup | `SNTR-SCW-002`, `SNTR-SC-003`, `SNTR-SC-010` | C: `carrier_context_cannot_be_reinterpreted`; L: `respond`, carrier comparison before lookup | Partial. Carrier mismatch is tested, but there is no exact `SC1-CONTEXT-03` to carrier-3 responder probe with lookup counting. Client URL/config rejection does not establish this case. |
| CONF-SCW-018: post-ready method denial without effects or connection loss | `SNTR-DAUTH-005`, `SNTR-DAUTH-010` | H: `handlers_without_authorization_fail_closed`, `allow_all_wrapper_restores_explicit_permissive_behavior`, `authorization_uses_bound_principal_and_method_on_every_call` | Partial. Runtime tests check denial, no handler effects and an active host. A dedicated SC1/WSS probe for one terminal result followed by a successful permitted call is absent. |
| CONF-SCW-019: active-session text, compressed, empty and truncated messages | `SNTR-SCW-005`, `SNTR-SC-007`, `SNTR-SC-010` | Adjacent evidence: V, `separate_endpoint_and_subprotocol_are_required`; W, `invalid_raw_upgrade_responses_never_receive_m1`; [WS record reader](crates/syntra-sc1-transport/src/websocket.rs) | Not demonstrated for the active-session WSS matrix. Existing text and extension probes run during establishment; they do not establish these post-ready rejection cases. |
| CONF-SCW-020: oversize plaintext/ciphertext rejection | `SNTR-SCW-009`, `SNTR-SC-007`, `SNTR-SC-010` | C: `record_and_frame_limits_and_segmentation` | Partial. `MAX_PLAINTEXT + 1` encryption fails and poisons the channel. No otherwise-valid 65,536-byte ciphertext receive probe is present. |
| CONF-SCW-021: fragmented M1/M2 reassembled before Noise | `SNTR-SCW-003`, `SNTR-SCW-005`, `SNTR-SC-002` | W: `fragmented_m1_reassembles_before_noise_server_role_both_modes`, `fragmented_m2_reassembles_before_noise_client_role_both_modes` | Local probe in both modes and receiving roles. Both reach readiness; the M1 test asserts Active and the M2 test completes an echo RPC. Each message uses one midpoint split. |
| CONF-SCW-022: isolated truncated-tag rejection | `SNTR-SCW-009`, `SNTR-SC-007`, `SNTR-SC-010` | Adjacent evidence: C, `tamper_and_reorder_poison_state`; D, `every_outer_split_point_and_truncated_record` | Not demonstrated. Ciphertext corruption/reordering and truncated record framing do not isolate an otherwise-valid record with a truncated AEAD tag. |
| CONF-SCW-023: reject a record produced with nonempty AD | `SNTR-SCW-009`, `SNTR-SC-007`, `SNTR-SC-010` | L: `Channel::encrypt` and `Channel::decrypt` use standard transport operations with no AD argument | Not demonstrated. Structural empty-AD use is not an executable foreign nonempty-AD ciphertext rejection probe. |
| CONF-SCW-024: invalid Upgrade response sends no M1 | `SNTR-SCW-006` | W: `invalid_raw_upgrade_responses_never_receive_m1` | Local probe for wrong, missing and duplicate Accept values, plus other malformed responses; it observes connection closure with no subsequent M1 bytes. |

The raw-frame helpers for 021 are test peers, not production WebSocket
validators. They use fixture masking keys and a 1 MiB allocation cap; that cap
does not change the production adapter's 65,535-byte ciphertext-message limit.
The probes split each handshake message into two fragments and do not insert
Ping between them. Subsequent hello/ready/RPC messages are whole, so these
tests do not supply the active-record fragmentation evidence missing from 005.
