# Phase 3 — Update/recovery implementation contract

Target: `syntra@8ede3810b29fbba4d0e6ae6751a0025ceedda140`, RFC 0006 §11;
the working tree adds explicitly negotiated `syntra.update-recovery/1`. Local verification
intent is not a formal `CONF-*` verdict/release claim; executed results belong in `AUDIT.md`.

## Runtime attachment and authority

`Host::configure_recovery(Arc<RecoveryService>)` registers one immutable service while
CONNECTED, before hello ingestion; repeat/late configuration fails with `FailedPrecondition`.
Default: no service; the entire UpdateRecovery prefix returns `Unimplemented` without app dispatch.
A configured session is created lazily from the actual authenticated Core `Principal`.
No selector, client hint, carrier header or storage scope selects P.
Profile operations use `RecoverySource` policy, independently of the application's
fail-closed `Handler::authorize`; configuring recovery grants no application RPC access.

SC1's `AuthenticatorFactory::recovery_service()` defaults to `None` and must return promptly
before the accepted Host ingests hello. `RecoveryAuthenticatorFactory::new(base, service)`
supplies `Some(service.clone())`, delegating authentication/`execution_budget()` to base.
It is re-exported at the `syntra-sc1-transport` root; WSS accepts `Arc<dyn AuthenticatorFactory>`,
handler, `ConnectionConfig` and `Limits`. `websocket::accept_tls_stream` takes
`TlsServerSettings` and SC1 `ServerConfig` with `Carrier::SecureWebSocket`; client
`connect`/`connect_with_roots` retain explicit credential/configuration arguments.
Recovery adds no WSS auto-enable option or new carrier negotiation.

`RecoverySource` resolves selector aliases to stable S within P and supplies G.
Every admitted stream operation, exact retry and protected emission rechecks its
`AuthorizationHook` and current G; Negotiate only selects profile/bounds. `Emit` covers
publication/notification production. Terminal loss/termination controls are namespace-fenced.
`PermissionDenied` terminates the affected stream without withdrawing unrelated authority.
`Unauthenticated` is sticky and triggers Core root-principal withdrawal. Service-wide
publication/provider-loss paths fence every existing session for P, including idle,
unnegotiated and busy sessions; awakened Host workers withdraw Core bindings.
Future connections still require current source policy.

Publication retains even late `validate_issued` authentication failures and wakes an idle notifier.
`host_recovery::Call::handle` records withdrawal before RPC terminal selection; the notifier
inspects it before protected output. Core deadlines win pending RPC selection at expiry.
Withdrawal stops admission, unbinds P and settles unfinished calls generically;
already-selected RPC success remains selected.
Neither withdrawal nor timeout rolls back effects or rewrites an already emitting unit.
Source callbacks are fast, bounded and synchronous: no blocking/reentry. Deadlines are
checked around synchronous work/result exposure; callbacks cannot be forcibly interrupted.

## Nine ordinary RPCs and notification routing

Methods have prefix `/syntra.v1.UpdateRecovery/`; bare protobuf payloads use existing Core envelopes.

| Method suffix | Request | Successful correlated result |
| --- | --- | --- |
| `Negotiate` | `RecoveryNegotiateRequest` | `RecoveryNegotiateResponse` |
| `Subscribe` | `RecoverySubscribeRequest` | `RecoverySubscribeResponse` |
| `Replay` | `RecoveryReplayRequest` | `RecoveryReplayPage` |
| `CatchUp` | `RecoveryCatchUpRequest` | `RecoveryCatchUpAccepted` |
| `Confirm` | `RecoveryConfirmRequest` | `RecoveryConfirmResponse` |
| `SnapshotConfirm` | `RecoverySnapshotConfirmRequest` | `RecoverySnapshotInstalled` |
| `SnapshotOffer` | `RecoverySnapshotOfferRequest` | `RecoverySnapshotDescriptor` |
| `SnapshotFetch` | `RecoverySnapshotFetchRequest` | `RecoverySnapshotChunk` |
| `Unsubscribe` | `RecoveryUnsubscribeRequest` | `RecoveryUnsubscribeResponse` |

All calls retain [Phase 2](phase2-core-rpc.md) received-order high-water admission,
fresh nonzero RPC IDs, lifecycle/version/authentication gates, execution/output
accounting and deadline-first terminal selection. With no explicit timeout the
profile default is five seconds, configurable downward and capped by Host policy;
the adapter also caps supplied remaining time at its profile deadline.
Known non-Negotiate operations on an unconfirmed connection return `Unimplemented`.
`RecoveryClient::new(initiator, principal_scope, store, limits)` auto-attaches its immutable
`RecoveryInbox` to that connection. Second attachment is rejected even after dropping the client.
Only validated ACTIVE negotiation of the exact capability/version offer 1..1 enables ingress.
`Negotiation::RecoveryUnavailable` is an explicit mandatory-only outcome.

Once enabled, the inbox owns the stream before the generic lossy `notif_tx` queue.
It validates `RecoveryNotification` (Batch/ReplayComplete/Trailer), with no failed-decode fallback.
Mixed application notifications require an explicit demultiplexer. Closing or
dropping the client closes its inbox; late opaque notifications are discarded,
not redirected into generic application delivery. Connection teardown also closes it.

## Round, replay and snapshot gates

P/S/G/C are principal scope, stable stream, provider continuity generation and opaque
checkpoint. H is a fresh connection-local subscription handle; B is the nonempty
boundary captured once by Subscribe. A gap retires H, clears held data, offers,
cursors and markers, then requires fresh Subscribe/H/B. Equal boundary bytes do not
revive an old round. No checkpoint arithmetic establishes scope.
`InitialLiveOnly` uses an explicit empty start, skips Replay and cannot overwrite a durable
record or claim historical restoration. `ResumeDurable` loads full P/S state without relabeling G.

Replay and CatchUp are exclusive per H. Each Replay returns exactly one bare page
in its correlated result; completion travels only as wrapped ReplayComplete in
`RecoveryNotification`. A page is never also delivered as a Notification.
Markers echo verbatim; replay and live entries share validation/persistence, checking
version/H/scope/G before duplicate suppression. An empty final page from C == B is policy,
not an additional upstream MUST. CatchUpAccepted accepts a trigger, not completion;
its batches stream as notifications and its completion is a catchup-complete Trailer.
Live offers wait for matching connection/H/G/version/B completion and durable
progress through B, with pending offers drained. Idle alone never opens the gate.

Lost completion uses an exact preceding Replay or the same CatchUp payload with
fresh Core IDs. Retained replies preserve pagination and re-emit completion;
canonical response equality rejects changed retries. Client retryable RPC errors
are DeadlineExceeded, Unavailable and ResourceExhausted. Finite attempts, absolute
TTL and bounded exponential backoff/skew apply; exhaustion retires work and returns
recovery/reconnect state. Subscribe allocation and application mutations are never
automatically replayed. Reconnection/authentication/renegotiation/resubscription remain
explicit application work; remote teardown is bounded best effort.

Retention miss preserves G and issued binding: failed Replay plus SnapshotRequired
authorizes the snapshot path, not silent restart. `SnapshotCurrentGeneration` is
an explicit replacement intent independent of an old durable checkpoint.
The descriptor binds X to P/S/H/current G and provider-proven S0 independently of B.
The source contract requires recoverable S0/content binding before constructing
`ProviderSnapshot`; the adapter never invents a surrogate token.
Fetch returns one immutable, nonempty page per result; complete index coverage and bounded
byte accounting derive completion locally. `RecoverySnapshotComplete` has no wire carrier.
It has no method, result slot or RecoveryNotification arm.

The application validates/transforms complete snapshot bytes, atomically persists
full state with current G/S0, then sends SnapshotConfirm. Only matching
`RecoverySnapshotInstalled` opens the independent S0 live gate, even if S0 != B;
old ReplayComplete/catchup-complete signals cannot open it. G remains unchanged;
installation neither rebases the provider nor issues a replacement checkpoint.
The host validates the held chain before discarding a snapshot-covered prefix.
Supersede, gap, loss or invalid stage retires H/X and requires fresh H even at equal
B/S0/G. SnapshotRequired during staging/install commit invalidates the pending snapshot.
An already-durable write remains resume evidence, but cannot authorize old-X/round Confirm.

## Bounded provider and queue responsibilities

`RecoverySource` owns recoverable issued P/S/G/C bindings for every batch result and S0
independently of Confirm, including across host restart. Global checkpoint membership
or selector equality is insufficient. Ordinary pruning returns `ProviderRetentionMiss`
from replay, not from `validate_issued`.
The runtime supplies no durable source ledger or production history/snapshot store.
Applications serialize capture/publication or recoverably retry identical issued batches
under a bounded budget; publication errors must be observed.
Source history, binding indexes and immutable snapshots need count/byte/lifetime bounds.

`RecoveryLimits` in `recovery/wire.rs` validates these deployment defaults/caps:

| Resource | Default; accepted configuration ceiling |
| --- | --- |
| Subscriptions | 64/connection, 256/principal; may narrow |
| Pending profile RPCs | 16/connection; configurable 1..=16, separate from Core's capacity floor |
| Queued data bytes | 256 KiB/stream, 1 MiB/connection; may narrow |
| Queued messages | 256/stream; up to 4,096 |
| Replay page | 64 entries, 256 KiB serialized entries total, 256 KiB/entry; may narrow |
| Snapshot | 256 pages, 256 KiB/page; may narrow |
| Connections | 1,024/service, 16/principal; ceilings 65,536 and 1,024 |
| Handle allocation slots | 1,024/connection; ceiling 65,536, at least subscription quota |
| Retained replies | 256 and 1 MiB/connection; ceilings 4,096 and 16 MiB |
| Reply TTL / retry count | 30 s / 8; ceilings 3,600 s / 1,024 |
| Default deadline | 5 s; positive, configurable downward |

Client count 8 includes first submission; host replies allow eight duplicate retries.
Client backoff is `(10 ms << min(attempts, 5)) + 0..16 ms` skew. Absolute TTL is no server
retention guarantee; expired replies cannot authorize same-H restart/reinstallation.
Selectors/stable identities/principal subjects: 1,024 bytes; handles/source snapshot
keys/reasons: 256; checkpoints/boundaries/markers: 4,096. Payload preflight reserves
128 bytes below Core's maximum Frame, bounds known occurrences before allocation,
and ignores well-formed unknown fields.
Reply ledgers, offered checkpoints, retired handles and speculative Subscribe candidates
are count/byte bounded; counters fail closed rather than wrap. Client aggregate staging
is capped at one configured maximum snapshot (default 64 MiB), with one pending offer/H.

Host production is round-robin, one bounded step/page at a time. Data and held-live
queues share quotas; offered-checkpoint accounting is separately bounded. Inbox
live/replay queues and leased offers share data budgets. Each admitted slot has
separate bounded completion/terminal control storage, so data saturation cannot
hide termination. Overflow clears only the affected H with unchanged G,
`terminated=true`, ASCII `local-queue-exhausted`, and no next_generation; local
inbox termination is reported locally. Healthy streams and Core RPCs can progress.
Only true provider loss/shared rebase supplies old G/next G for affected P/S.

The Host owns one notifier, holding at most one popped frame across writer
backpressure. After the last await it rechecks source authority/G/phase and Core
lifecycle immediately before enqueue. Stale protected output is discarded;
ownership contention retries within the same absolute deadline. No provider/state
mutex spans writer waits, application callbacks or persistence. A stalled writer
or nonretryable production failure closes Core rather than leaving a silent worker.

## Full-state local persistence

`recovery::persistence::RecoveryPersistence` loads/commits full opaque `application_state`,
G and C in `DurableRecord` under `PersistenceScope(P, S)`; an effects digest is insufficient.
CAS expects absence or exact previous G/C. Exact full-record duplicates are idempotent
even with stale expected position; other stale writes conflict. Ordering and authorized
epoch changes remain caller-owned.
`RecoveryProgress` separates locally_durable, confirm_sent and peer_acknowledged.
`confirm_sent` means submission to `Initiator::call`, not carrier write/receipt. Resume uses
durable known-safe evidence, possibly newer than peer acknowledgment; Confirm failure never rolls it back.

Native `FileRecoveryStore` uses pinned `fs2 = "=0.4.3"` for a lifetime exclusive kernel
advisory process lock and bounded local records with embedded scope, SHA-256 checksum,
private temp-file sync, same-directory rename and directory sync. Crash releases the
lock; its file remains. Rename-attempt/directory-sync uncertainty fences writes with
`CommitUnknown`: reopen/reconcile full records, never guess rollback or blindly Confirm.
Native client storage uses `spawn_blocking`; writes may outlive caller cancellation,
which fences the wrapper and cannot emit a late Confirm. Filesystem assumptions:
dedicated private local storage, trusted ancestors/cooperating writers, atomic replacement
and honored flushes. Unix private modes, link/special-file checks and equivalent
caller-provisioned ACLs apply; no sandbox against hostile concurrent path replacement.
Checksums detect corruption, not authentication; scope hashes are filenames, data is plaintext.
Scopes are sensitive binding labels, never credentials; credentials/handles are not stored.
Defaults: 256 records, 64 MiB state/record, 256 MiB total encoding, plus one bounded temp record headroom.

WASM supports a nonblocking persistence adapter, not synchronous filesystem/database work
or a browser durability claim. Legacy `ProfileEngine`, drivers and `DurableStore` align
same-G semantics; wired wrappers add per-connection/per-H fencing beyond selector-only helpers.
`MemoryStore`/`MemoryRecoveryStore` are not durable; reference providers are not production
stores. File encoding is local, not a new wire allocation/schema. Applications own source bindings.

## Local verification intent and remaining gates

Owners: runtime `recovery/wire*.rs`, `host_recovery.rs`, persistence, SC1 `pump.rs`/`websocket.rs`.

| Intent / local regression locations | Requirement and registered case trace |
| --- | --- |
| Negotiation, actual principal, immutable routing: `host_recovery_tests`, `tests/recovery_wire`, `wire_client_tests` | SYN-URP-001/010/020/021; CONF-URP-001/007 |
| Shared replay/live pipeline, fresh H/B and exact retries: wire/client tests | SYN-URP-003/004/014/022/023/024; CONF-URP-002/003/004/011/012 |
| Scoped loss, retention and isolated quotas: wire/host/client tests | SYN-URP-007/012/013/015/017/018/026; CONF-URP-005/008/009/010 |
| S0 install, supersede and commit races: wire/client tests | SYN-URP-016/021/025; CONF-URP-006/013/014/016/017 |
| Full-state crash/reopen/CAS: `tests/recovery_persistence`, persistence-file unit tests | SYN-URP-005/006/013; CONF-URP-015/016 |
| Publication revocation, post-writer revalidation: `host_recovery_tests`; actual WSS: SC1 `tests/recovery_wss` | SNTR-AUTH-008, SNTR-REL-005/007; RFC 0006 §11, RFC 0004 terminal ownership |

Pinned `conformance/manifest/recovery.yaml` cases 011/012 encode bare inner ReplayComplete
where RecoveryNotification is required. Preserve that upstream fixture discrepancy;
it cannot justify weakening the codec. Mixed-notification integration, automatic recovered-service
reconnect, browser/WASM and FFI v2 integration remain Phase 5/6 work. Independent Go/device
execution, human review, formal role/profile-selected CONF runs and release/freeze decisions
remain Phase 7 gates. This document records no test totals or execution verdicts.
