# SC1 local revision 1

This document describes the implementation in `syntra-secure-channel/` and
the ordered adapters in `syntra-tcp/` and `syntra-ws/src/sc1.rs`.
**SC1 local revision 1 is an implementation-specific draft. It has not been
accepted upstream or independently security-audited.** The domain,
subprotocol and context encoding below identify this draft only.

The upstream design reference is [RFC 0007 at specification commit
`e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02).
That proposal leaves wire and lifecycle decisions for review; this document
records the concrete local choices without asserting upstream conformance.
See [AUDIT.md](AUDIT.md) for evidence and outstanding work.

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
| 0 | `Mode::Bootstrap` | `Noise_NK_25519_ChaChaPoly_SHA256` | Authenticated, pinned server public key; no authorization key |
| 1 | `Mode::Returning` | `Noise_NKpsk0_25519_ChaChaPoly_SHA256` | Same server pin plus a provisioned 32-byte authorization key |

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
source. Scope is exact bytes, not a URL-derived identity; there is no text
normalization. Context bytes, handles, lengths, timing and carrier metadata
are public. Protecting payloads does not hide them.

## Canonical context

The canonical public context `P` is this concatenation. All offsets are
zero-based, and ranges are half-open. Let `S = len(scope)`.

| Offset | Bytes | Field |
| --- | ---: | --- |
| `[0,8)` | 8 | Exact ASCII magic `SNTRSC1L`, with no terminator |
| `[8,10)` | 2 | Revision `1`, unsigned big-endian u16 |
| `[10,11)` | 1 | Mode: bootstrap `0`, returning `1` |
| `[11,12)` | 1 | Carrier: TCP `1`, WebSocket `2` |
| `[12,16)` | 4 | `server_key_id`, unsigned big-endian u32 |
| `[16,18)` | 2 | Scope byte length `S`, unsigned big-endian u16 |
| `[18,18+S)` | S | Intended endpoint/server scope bytes, `1..255` bytes |
| `[18+S,26+S)` | 8 | Enrollment lookup handle, opaque bytes |
| `[26+S,34+S)` | 8 | Enrollment epoch, unsigned big-endian u64 |

The total is **`34 + S` bytes**, or 35–289 bytes. There is no padding,
optional field or trailing content. Bootstrap requires an all-zero handle and
epoch zero; returning mode uses its enrollment's independent handle and
current epoch. `server_key_id` has no nonzero constraint. Carrier, scope and
server-key ID must match the responder's configuration.

These canonical bytes are the public prefix of M1 and part of the complete
Noise prologue. The prologue is `domain || P`, where the domain is the exact
ASCII bytes `syntra-rs/sc1/local/1` followed by one `00` byte. Altering any
field changes the authenticated handshake context.

## Handshake and record wire format

- **M1:** canonical context followed by exactly 48 Noise bytes (32-byte
  ephemeral public key and the 16-byte tag for an empty handshake payload).
  Its total size is `34 + S + 48`, or 83–337 bytes.
- **M2:** exactly 48 Noise bytes, with an empty handshake payload.
- **Transport record:** 1–65,519 plaintext bytes plus a 16-byte AEAD tag:
  17–65,535 ciphertext bytes. Empty plaintext records are rejected.

The client authenticates the complete context through the prologue and its
provisioned server public key. X25519 all-zero shared results are rejected.
Unexpected lengths, versions, modes, context, payloads and extra bytes are
terminal. After `Split`, both directions use standard ordered Noise transport
messages with empty associated data. Send and receive nonce state is
independent and never copied or reset.

### TCP

Every message, **including M1 and M2**, is encoded as:

```text
u16BE(message byte length) || message bytes
```

The length excludes its own two bytes. TCP packet boundaries have no meaning.
Partial reads/writes and coalesced packets are handled by the adapter. Zero
lengths, over-capacity handshake messages and incomplete messages fail.
During establishment the first wrapper is bounded to 337 bytes and M2 to 48.

The local TCP binding identifier is `syntra.sc1.local1.tcp`. There is no
default TCP port; the caller supplies an address. Native hosts accept an
ordinary TCP stream or a caller-terminated TLS stream.

### WebSocket and secure WebSocket

Each binary WebSocket **message** contains exactly one M1, M2 or ciphertext
record. There is **no SC1 u16 prefix** inside it. WebSocket fragmentation is
reassembled by the underlying library; WebSocket frames are not SC1 records.
The local subprotocol is `syntra.sc1.local1.ws` and the endpoint path is
`/syntra/local/sc1/1/ws`. Text, oversized, truncated and unauthenticatable
messages fail. Ping/Pong/Close are carrier control messages, never channel
confirmation, application completion or RPC results. Control frames cannot
extend an absolute receive/establishment deadline.

`syntra_ws::sc1::connect` accepts explicit `ws://` or `wss://` URLs and
requires exactly the endpoint path above, with no userinfo, query or
fragment. The host requires exactly the subprotocol token and rejects
`Authorization` and `Cookie` headers; it does not treat `Origin` as
authentication. The client sends no credential in the Upgrade. WSS uses TLS
1.3, system roots and hostname validation in addition to the provisioned
Noise server pin. Browser SC1 is not implemented.

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

`Limits::default()` applies to TCP directly and to WebSocket through the same
shared pump:

| Option | Default | Accepted nonzero range |
| --- | --- | --- |
| `attempt_timeout` | 15s | Positive, at most 24h; covers dialing/upgrade, SC1 and core readiness |
| `channel_timeout` | 5s | Positive, at most 24h; establishment plus encrypted hello confirmation |
| `record_timeout` | 30s | Positive, at most 24h; next complete record including idle wait |
| `frame_timeout` | 30s | Positive, at most 24h; from first incomplete plaintext, never refreshed by trickle records |
| `write_timeout` | 10s | Positive, at most 24h; one entire frame's encrypted output |
| `close_timeout` | 1s | Positive, at most 24h; owner-task join after close, then abort |
| `lifetime` | 24h | Positive, at most 24h, configurable downward |

`writer_capacity`, `notification_capacity` and the runtime outstanding RPC
count must be `1..1024`. The default runtime writer queue holds at most 256
frame items; with a 1 MiB frame ceiling this permits up to 256 MiB of
serialized queued frame bytes per direction. Deployments should use a smaller
queue appropriate to their memory budget. There is one incomplete receive
frame, one pending authenticated record, one outgoing frame/record sequence,
and a bounded batch of complete frames per received record. No adapter creates
a task per frame or per policy lookup.

An idle record read has no assembly timeout until its first wire byte; then
the record clock includes partial headers and all fragments. The frame clock
begins at the first authenticated frame-prefix byte and is never refreshed by
later records. Caller deadlines can shorten all operations. A successful
handshake does not bind the transport lifetime to that handshake context.

The adapter enforces an absolute lifetime, including handshake time, even on
an idle socket. The channel also refuses use at 24h of age or after
**2^32 records per direction**, and observes the initial enrollment expiry.
There is no automatic reconnect or key rotation. Reconnect requires a fresh
handshake.

Each connection has one reader and one writer, supervised by one owner task.
The writer retains the exact ciphertext across `write_all` partial writes and
does not select another frame mid-write. RPC-call cancellation does not cancel
this owned output. Write error/timeout/connection cancellation aborts the
channel; it never encrypts a replacement under a consumed nonce. A locally
rejected plaintext length in the socket-free `Channel::encrypt` does not
consume a nonce. Authentication failure, framing error and every channel
record error permanently poison channel state. Direct users of
`Channel::encrypt` must retain its returned ciphertext until successful
ordered emission, or call `Channel::close` on output error/cancellation.
There is no resynchronization scan. Incomplete record/frame bytes are
discarded at EOF, never dispatched. Complete-boundary EOF is transport loss
rather than authenticated proof of orderly application completion.

Dropping a handle or cancelling a connect future signals its owner. The owner
poisons cipher state, aborts/joins both I/O children, drops the stream, and
calls runtime transport-loss teardown so cloned initiators and pending calls
settle. `close().await` waits for this bounded teardown. Close may abort
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

`syntra_tcp::Listener::bind(address, maximum_connections)` acquires admission
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

SC1 framing, authentication and policy failures terminate the carrier without
a diagnostic payload or promised WS close code. Normal writer exhaustion
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

### Provisioning boundary and audited TODO

**Only explicit authenticated out-of-band provisioning is supported.** The
host generates the 32-byte authorization key with `Enrollment::generate`
and independently samples a random eight-byte handle, rejecting zero and
check
...[truncated 6154 chars]ing collision-checked handles in its store. A handle must not be a key
prefix, hash of a key, principal-derived value or counter.

Store transactionality, secure delivery, client acknowledgement, retry and
recovery after lost delivery, protected client storage, revocation
dissemination and rotation workflow are host responsibilities. This module
implements **no enrollment RPC or end-to-end issuance/rotation workflow**.
Bootstrap does not implement one implicitly. These are open integration and
audit TODOs, not completed security features.

## Connection orchestration

`syntra_tcp::connect` dials, completes SC1, runs the Syntra hello/ready
exchange and checks readiness within one **15-second total attempt budget**,
shortened by the caller where applicable. The returned client's lifetime is
independent of the dial future: always close it explicitly. There is no
automatic reconnect, RPC replay or fallback.

`Listener::bind(address, maximum_connections)` owns the socket; each
`accept` acquires one admission permit that stays with the accepted stream
through its handle lifetime. The application owns its accept loop and
retains each `HostHandle` for as long as that connection is served; dropping
a handle aborts its pump. For caller-owned streams, `connect_stream` and
`accept_stream` take any `AsyncRead + AsyncWrite + Unpin + Send` endpoint
and run the same pump. `syntra_ws::sc1::{connect, accept, accept_stream}`
wrap the same pump around WebSocket binary messages.

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

Local tests cover exact context encoding, both patterns, wrong server
keys/AKs, context tampering, canonical wrapper bounds, first-flight replay
with fresh M2, withheld confirmation, tag failure, reordering, terminal
record limits, 1 MiB segmentation, all short inner split points and
coalescing, entropy failure and secret redaction. Native TCP and WS tests
use real loopback sockets in both modes, principal deny, and multi-record
RPC round trips without Docker. The Docker suite in
`crates/syntra-integration` repeats the handshake, echo, concurrency,
denial and wrong-key coverage for TCP and WS over real container networking.
These are local tests, not upstream registered conformance vectors or
evidence of an independent implementation's interop. Benchmarks and separate
tooling are documented in [BENCHMARKS.md](BENCHMARKS.md).
