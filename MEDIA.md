# Native lanes and resumable media

Use `syntra-net/media` when interactive calls and updates should use a different TCP connection from bulk RPCs. Use `syntra-ffi/managed-media` when a native C client should let Rust own both connections. A lane selects **where to send**; the host still decides **who may do what**. Neither API replays an application RPC after loss.

## Choose the interface

| Build | What you get | What stays outside it |
| --- | --- | --- |
| `syntra-net`, defaults | Native carrier-neutral record pump, no socket features | No managed lanes. Existing `tcp` and `managed` callers can keep their single-connection APIs. |
| `syntra-net`, `media` | `lanes` and `media`; enables `managed` (TCP, reconnect, multithreaded Tokio), bundled SQLite via `rusqlite`, and `sha2` | No implicit WS/WSS, HTTP/HTTPS, proxy, cross-carrier routing, enrollment, or recovery file store. No driver on wasm32. |
| `syntra-ffi`, defaults | No `syntra_*` C ABI | `test-fixture` is a separate blocking loopback ABI. Never ship it or combine it with production via `--all-features`. |
| `syntra-ffi`, `production` | ABI 1 `syntra_t`: shared Core client/host, plaintext frame pump, lifecycle, and typed recovery **client** with foreign persistence | Embedder supplies verified establishment, Noise records, carrier I/O, ordering, and close. No managed dial, reconnect, recovery host, or built-in file transfer. TLS alone does not complete this path. |
| `syntra-ffi`, `managed-media` | All production exports **plus** `syntra_managed_*`: a protected returning-mode TCP **client**, file transfers, and opt-in interactive update restore with foreign storage | No managed C listener, recovery provider, or built-in credential rotation. Never cast `syntra_managed_t` to `syntra_t`. All FFI builds reject WASM. |

In **both** production artifacts, `syntra_abi_version() == 1` and `syntra_capabilities() == 13` (`CORE | RECOVERY_CLIENT | LIFECYCLE`). `SYNTRA_CAP_RECORD_PROTECTION` (2) stays unset for the frame pump. The mask neither detects managed symbols nor describes the peer or a live session. Link the intended artifact and matching [managed](crates/syntra-ffi/include/syntra_managed.h) or [frame-pump](crates/syntra-ffi/include/syntra_production.h) header. See the [net](crates/syntra-net/Cargo.toml) and [FFI](crates/syntra-ffi/Cargo.toml) manifests for feature composition.

## Use the Rust lanes

In the [local dependency declaration](crates/syntra-net/README.md#using-tcp), select `features = ["media"]` instead of `features = ["tcp"]`.

1. From an ordinary thread, open `LaneClient::tcp(address, LaneConfig::default(), inputs)` and retain the owner (usually in an `Arc`). `address` is one provisioned `SocketAddr`. `inputs` must promptly return fresh `(ClientConfig, Vec<u8>)` for **every** attempt: `Mode::Returning`, `Carrier::Tcp`, trusted pin and scope, key ID, handle, epoch, authorization key, and explicit hello credential. Both connections perform their own Noise and hello/ready handshakes. There is no wire purpose flag, discovery, or bootstrap fallback.
2. Construction means local registration, not readiness. Observe `status` or `subscribe_status` for **each** `Lane`. `call_interactive` submits an RPC; `next_notification` creates a pull for the current interactive generation. A pending poll dequeues nothing. Dropping the observer (including a timed-out `wait`) releases its credit without leaving a background reader; `try_take`, `wait`, or `.await` must actually return the notification to consume it. Check the optional payload and loss counters.
3. For bulk RPCs, call `try_reserve_media(request_bytes, max_response_bytes)` **before** reading or allocating the payload. Cold demand wakes one parked supervisor and normally returns `LaneError::NotReady`; `Busy` means contention or capacity. Wait for readiness or released credit under your own deadline, then retry **admission only**. An unused reservation drops its charge. Do not silently reroute bulk work to the interactive lane.

For example, reserve for both directions **before** constructing a generic bulk request. The transfer helper below does this for each chunk.

```rust
use syntra_net::lanes::{LaneClient, LaneError, MediaOperation};

fn submit(lanes: &LaneClient, size: usize, make_chunk: impl FnOnce() -> Vec<u8>)
    -> Result<MediaOperation, LaneError>
{
    let permit = lanes.try_reserve_media(size, 8)?; // At most an 8-byte reply.
    permit.call("/example.Objects/Write", make_chunk(), 5_000)
}
```

Await the operation, use `try_take`, or `wait(timeout)` outside Tokio. Handle both the wait error and the RPC result. A timed-out waiter or a dropped operation does not undo submitted work. Calls and reservations are fenced to a **lane-local** generation; equal generation numbers on different lanes mean nothing. A queued result can outlive its connection. Keep the `MediaResponse` while queueing it downstream; `into_bytes()` transfers the bytes **out** of managed accounting.

| Bound | What it measures |
| --- | --- |
| Interactive defaults: 32 `interactive_operations`, 32 MiB `interactive_bytes` per owner | Calls and notification observers share both limits. Each reserves one slot and 1 MiB; a call also reserves the method and request payload lengths. Thus even tiny calls can exhaust bytes before slots. Credit covers a running RPC even if its waiter leaves, and a completed result until consumed or discarded. At capacity, `call_interactive` returns `Error::Configuration`; `next_notification` returns `LaneError::Busy`. |
| Ordinary interactive push inbox, per generation | Separate from the above credit. Capacity in entries is `min(runtime.notification_capacity, interactive_operations, interactive_bytes / MAX_FRAME_BYTES)` (integer division). No second lane queue drains it. On overflow, Core drops the newest notification and counts the loss. |
| `LaneConfig` defaults: 8 media operations, 8 MiB `media_bytes` | Each reservation charges one slot plus **request bound + maximum response payload**, including unread completions. Each side is at most 1 MiB; the encoded Core frame must also fit 1 MiB including overhead. An oversized reply is rejected after receipt; that error does not mean the method did not run. |
| One `NetworkConfig` **per lane** | Each pool gets its own configured workers and operation limit. `media_operations` must leave two pool slots for the supervisor and idle task. Logical payload credit excludes runtime queues, encryption, socket buffers, storage, and caller copies. It is not a process memory or latency bound. |
| Media idle default: 15 s | A healthy, unused media generation parks when no reservation or RPC is active. An unread completion retains credit but need not keep a socket alive. Later demand establishes a fresh generation. |

`pause`, `resume`, `network_available`, and `platform_wake` control the lane owners; signal a platform wake rather than continuing old cipher state. Each supervisor retries availability loss within its own budget (defaults: 5 attempts, 15 s per attempt, 60 s outage). Detected authentication, protocol, or framing failure blocks automatic retry; a remote EOF may carry no such diagnosis. Investigate `Blocked`/`Exhausted` before explicit `retry()`: it retries **connections**, including the interactive one, never an RPC. `shutdown(timeout)` spends one wait across both pools. Check `complete`, `pending_operations`, and `failed_supervisors`; retain incomplete owners for later observation. See [lanes](crates/syntra-net/src/lanes.rs) and [reconnect failure classification](crates/syntra-net/src/client.rs).

## Restore interactive updates (Rust)

Use `LaneClient::tcp_with_updates(address, config, inputs, stream, app)` instead of `tcp` for **one** provisioned stream on the interactive lane. Configure a host `RecoveryService` before hello (see [negotiated recovery](README.md#negotiated-updaterecovery)). Supply `UpdateStream` with `principal_scope`, `stable_stream`, `selector`, validated `RecoveryLimits`, and a shared `RecoveryPersistence` store. Provision a valid full record and a source-issued checkpoint first: this driver uses `ResumeDurable`, not an initial live-only subscription.

| Observation | What the application may infer |
| --- | --- |
| `CoreReady` | The Core connection is ready, not the stream. |
| `RecoveryNegotiated` | This generation negotiated the profile. A subscription and its application state still need restoring. |
| `update_status() == Restored(g)` (variant of `UpdateStatus`) | For current connection generation `g`, `restore` loaded the persisted record and the driver observed `CaughtUp` for the new subscription. This is a snapshot, not a promise about future updates. |

`UpdateApplication::apply` computes **full replacement state** for each offered batch. `persist_and_confirm` conditionally commits it with the provider generation and checkpoint before confirming. The driver runs callbacks serially; make them nonblocking and cancellation-safe, without irreversible side effects outside that commit. After loss the next generation negotiates, subscribes, and reloads the authoritative record; it does not reuse a subscription handle. Connection generation and provider stream generation are distinct.

Treat `Waiting`, `Restoring`, or `Failed(g, error)` as not restored. Missing history, incompatible generation, an unexpected event, or persistence uncertainty is not permission to reset a checkpoint, confirm, or silently switch to live-only. Reconcile or explicitly bootstrap outside this driver. Once negotiated, the [recovery inbox](crates/syntra-runtime/src/recovery/wire_inbox.rs) expects recovery notifications; do not mix arbitrary notifications into it or fall back to ordinary delivery on a decode error.

A memory store tests the [persistence contract](crates/syntra-runtime/src/recovery/persistence.rs), not crash durability; native `syntra-runtime/file-store` is a separate opt-in. For the managed C equivalent see [durable updates in C](#durable-updates-in-c).

## Transfer an immutable version

Install `SqliteMediaHost::open(path, authority_scope, policy)` on the Rust host and obtain a **fresh** `host.handler()` for each accepted connection. Route the seven exact paths below, forwarding both `Handler::authorize` and `handle_with_context` (including the execution lease and budget). Do not wrap the media handler in `AllowAll`. The [linked C consumer's Rust host](crates/syntra-ffi/tests/managed_host.rs) shows the routing, using **fixture-only** credentials and policy.

On the client, persist the manifest and authority/account **before** the first upload. Choose a fresh stable transfer ID and pin the length and SHA-256 of an immutable regular source file. With `lanes: Arc<LaneClient>`, `MediaClient::new(lanes.clone())` pins the generation of the initial Query or Describe reservation through the remaining RPCs. A different generation requires an explicit new attempt; the engine never submits the next chunk to a replacement. Both lanes and all reconnects on a production owner must use the same provisioned pin, context, authorization key and hello credential. Recreate the owner on rotation, and never reassign an unchanged credential to a different account. Drive `upload` and `download` on Tokio (file work uses blocking workers). For example, given a ready lane, a pinned manifest, and a private destination:

```rust
use std::{path::Path, sync::Arc};
use syntra_net::{lanes::LaneClient, media::{self, DownloadStore, Manifest, MediaClient}};

async fn transfer(lanes: Arc<LaneClient>, spec: Manifest, source: &Path, dest: &DownloadStore)
    -> media::Result<()>
{
    let client = MediaClient::new(lanes);
    client.upload(spec, source).await?;
    client.download(spec, dest).await
}
```

### V1 RPC contract

These are ordinary Core RPC payloads under **`/syntra.media.v1.Media/`**, not new Protobuf fields, a carrier, or a negotiated Core version. All fields are required, concatenated in the order shown; integers are unsigned, big-endian. No optional fields or trailing bytes. Do **not** serialize a native Rust or C struct as the request.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `key` | `object[16]`, `version:u64` | All requests, directly or in the manifest | Opaque object ID and nonzero immutable version, scoped to one host authority. |
| `manifest` | `key`, `transfer_id[16]`, `length:u64`, `sha256[32]` | All requests except Describe; Describe reply | Exactly 80 bytes. Whole-object length 0..=1 GiB. IDs and digests are not credentials. |
| `block` | `offset:u64`, `sha256[32]`, remaining data | Put request / Read reply | Data chunks start at aligned offsets and are exactly 256 KiB except a short final chunk. An empty object has no data chunks. The EOF **Read reply only** is 40 bytes, with no data (see `Read` below). |
| `state` | `tag:u8`, then `next:u64` **only** for tag 1 | State replies | `0` absent, `1` uploading (next byte offset, aligned or end), `2` committed, `3` aborted. |

| Method suffix | Request → success reply | Behavior and notable refusals |
| --- | --- | --- |
| `Query` | manifest → state | Look up transfer ID for this authenticated owner and exact manifest. Wrong owner: `PERMISSION_DENIED`; different manifest: `ALREADY_EXISTS`. |
| `Begin` | manifest → state | Bind absent ID to owner and reserve object/version; identical binding returns current state. Another live transfer or committed version for the key conflicts. |
| `Put` | manifest + block → state | Atomically store the next chunk and advance the offset. An identical stored block returns current state; changed duplicate conflicts. Gap, absent, or aborted: `FAILED_PRECONDITION`; bad digest: `DATA_LOSS`. |
| `Finalize` | manifest → state | For a complete upload, authorize and verify chunks and whole SHA-256 in a read-only WAL snapshot. A separate writer transaction reauthorizes and checks owner, manifest, content revision, complete position, cancellation, and deadline before commit. Revocation or a changed revision prevents publication; repeating Finalize on an already committed version rechecks authorization but does not rehash the object. |
| `Abort` | manifest → state | Discard in-progress chunks and free the key, retaining an aborted ID tombstone. Repeat abort returns aborted; absent or committed fails precondition. Cannot retract a published version. |
| `Describe` | key → manifest | Return only a committed version under current object policy; otherwise `NOT_FOUND` if authorized but not published. |
| `Read` | manifest + offset:u64 → block | Require Read permission and the exact committed manifest. Data offsets require valid geometry, digest and sufficient response credit. At `offset == length`, return an EOF block: that offset, SHA-256 of empty bytes, and no data. EOF is valid for empty objects and checks content access independently of Describe. |

Malformed fields or geometry map to `INVALID_ARGUMENT`; conflicts to `ALREADY_EXISTS`; corrupt content to `DATA_LOSS`. All methods can be denied by policy, cancelled, or time out; storage/worker failures can surface as `INTERNAL`. See the [codec](crates/syntra-net/src/media.rs), [host dispatch](crates/syntra-net/src/media/host.rs), and [transactions](crates/syntra-net/src/media/store.rs).

**Lost Put or Finalize reply?** Do not allocate a new transfer ID or blindly replay the last call. Explicitly re-enter `upload` with the same manifest and account: it queries first, begins only if absent, continues from the host's offset, or returns on committed without reopening the file. Aborted is terminal for that ID. Dropping the future stops new calls; an admitted RPC or local transaction may still finish.

**Interrupted download?** Reopen `DownloadStore::open(path, scope)` using the same private SQLite file and stable authority **and** account scope. `download` verifies the local prefix and stores each verified chunk with its checkpoint transactionally. Completion checks the whole-object digest and requires a same-generation `Read` at EOF, including on cache hits and empty downloads. Describe permission alone is insufficient. `copy_verified` checks the committed object before writing from the same WAL snapshot; it is a blocking local export, **not** a fresh remote authorization. Writers can commit during export. A slow sink can delay WAL reclamation, and a failing sink may have partial output; stage it privately before publishing. `discard(spec)` explicitly removes only that local copy. See the [transfer client](crates/syntra-net/src/media/client.rs).

## Enforce bounds and authority on the host

Both sockets must bind the explicit encrypted hello credential to the intended authenticated principal. A handle, lane, request ID, manifest, or claimed payload identity cannot establish that binding. Layer three decisions:

1. **Classify and admit.** Before shared execution starts, call `ExecutionBudget::configure_operations(limits, authority)` once; return clones of that budget from `AuthenticatorFactory::execution_budget` for both sockets **and replacements**. This runtime policy is opt-in, independent of compiling `media`. Without it the old execution limits remain; there is no automatic interactive reserve or per-principal byte quota. `OperationAuthority::try_admit` assigns `OperationClass` from the bound principal and method, never from the lane or a payload label. Use nonblocking decisions, including grants for any recovery methods you intend to serve.
2. **Account for real work.** Charge request payload plus `OperationGrant::response_frame_bytes` (encoded result, 1024..=1 MiB). `Method::response_frame_bytes()` supplies conservative media-method sizes. `OperationLimits` reserves interactive slots within local and shared execution caps and interactive bytes within the shared byte ceiling; interactive work still obeys the totals. Retain `ExecutionLease` in external work until it actually stops.
3. **Authorize the object and fence effects.** `ObjectPolicy` checks `(transaction, principal, method, object/version)` before lookup, read, or mutation. Bind upload operations to their owner; independently authorize readers. To serialize revocation with SQLite effects, read the ACL in that transaction and commit revocations in the **same database**. A cached decision or independent ACL service does not provide that fence. Configure `ConnectionAuthorization` to check idle/live connections as needed; admission on one socket does not withdraw its sibling or roll back a commit.

The [managed output owner](crates/syntra-runtime/src/host_execution.rs) retains the logical byte charge and ticket through the complete frame write or abort. With a raw `Receiver<Vec<u8>>`, ordinary output accounting ends at writer-channel handoff. Neither boundary is proof of peer receipt. `QuotaOwnership::ExclusiveProcess` requires actual exclusive placement through failover; otherwise supply non-overlapping `External` tickets. Return `Unavailable` for missing or stale ownership, `Exhausted` for exhausted quota, and `Revoked` for a withdrawn binding; do not fall back to local counters.

Provision private directories, separate host authority and download account databases, stable inputs, disk quotas across objects, tombstone retention, backups, and at-rest protection. SQLite transactions and hash checks do not prove that a particular filesystem survives power loss, that a backup is current, or that a previously exported copy can be revoked.

## Use the managed C client

Use the declarations in [`syntra_managed.h`](crates/syntra-ffi/include/syntra_managed.h); [`managed_smoke.c`](crates/syntra-ffi/tests/managed_smoke.c) is a linked C11 example. The sequence is:

1. `syntra_managed_open(SYNTRA_ABI_VERSION, &config, &owner, &id)` copies counted slices (not C strings). Supply numeric `IP:port` (bracket IPv6), exact UTF-8 scope (1–255 bytes), nonzero 32-byte pin, key ID, returning mode, nonzero 8-byte handle, nonzero epoch and 32-byte authorization key, and explicit credential (0–8192 bytes). Rust builds fresh connections from those copied inputs; recreate the owner on rotation. `SYNTRA_OK` means registered for startup, not ready. Use bounded, paced `syntra_managed_status` checks; bulk starts on demand.
2. Submit `syntra_managed_call` on `SYNTRA_MANAGED_INTERACTIVE` or `SYNTRA_MANAGED_BULK`, or `syntra_managed_next_notification` on interactive only. `SYNTRA_PENDING` **on submission** means no token; `SYNTRA_BUSY` means no capacity. Check status, drain completions, and retry admission within a local budget. `SYNTRA_OK` + token means **poll that token**, do not submit again. An interactive call made before readiness can have a token and later return unavailable.
3. `syntra_managed_poll(owner, id, token, &result)` returning `SYNTRA_PENDING` means work is outstanding. On `SYNTRA_OK`, the token is consumed: check `result.grpc_code` (zero is success). Check `generation` for lane calls/notifications and `has_data`, `dropped_count`, and `dropped_bytes` for notification loss/end. Release owned bytes exactly once with `syntra_free(result.data.data, result.data.len)` before reusing the output. Owner IDs and job tokens are local, not wire IDs. A stale ID check does not make a freed pointer safe.
4. For files use `syntra_managed_upload` or `syntra_managed_download` with a pinned `syntra_manifest_t`. Supply trusted UTF-8 paths (1–4096 bytes, no NUL); download takes a scope (1–1024 bytes) and optional `syntra_sink_t`. A null `chunk` callback keeps the verified DB without exporting. Otherwise consume/copy the borrowed chunk before returning zero; do not block, unwind, or reenter. Keep the callback and context live until terminal poll consumes the job or shutdown polling observes completion.
5. `syntra_managed_progress` counts successful RPCs and request/response **payload** bytes for this job; `object_bytes` is the manifest length, **not** bytes transferred. `syntra_managed_cancel` requests a local transfer stop; it is neither remote `Abort` nor a callback-lifetime fence. On a raw interactive or bulk call, cancel discards interest in the unread result: the token stays charged until the underlying call settles and polling consumes it as `CANCELLED` without data. It does not cancel a notification receive or prove rollback.
6. Signal lifecycle changes with `syntra_managed_control`. To close, call `syntra_managed_shutdown`, then `syntra_managed_shutdown_poll`. While `SYNTRA_SHUTDOWN_INCOMPLETE`, retain owner and callback contexts, even after a UI wait expires. Terminal `SYNTRA_OK` (or observed failure `SYNTRA_INTERNAL`) precedes exclusive `syntra_managed_destroy`; consume any wanted results first. Never use the pointer after successful destroy.

Per C owner: **32 outstanding jobs**, including unread results. Raw bulk calls and transfers together get at most **6** slots, at most **2** of them transfers; only **1** notification receive may be outstanding. Generic methods are at most 512 bytes, payload/result at most 1 MiB subject to frame overhead. A generic bulk call reserves the request length plus a full 1 MiB reply; transfer jobs reserve by chunk/method instead. These bounds exclude C-owned buffers after poll, callback allocations, and other owners. See the [owner](crates/syntra-ffi/src/managed.rs) and [transfer worker](crates/syntra-ffi/src/managed_transfer.rs).

### Durable updates in C

`syntra_managed_open` alone does not restore updates. For one durable interactive stream, use `syntra_managed_open_updates` with `syntra_updates_t`: counted `principal_scope`, `stable_stream`, and `selector` (1–1024 bytes each), a context, and both callbacks. Seed the application store with a real full record first. `restore` receives that record; `apply` receives the connection generation, provider generation, predecessor, result checkpoint, and batch payload. It writes the **entire** replacement state to the supplied buffer (at most 1 MiB), sets `used`, and returns zero on success. Do not retain borrowed pointers, block, reenter, or unwind. Keep functions/context live until terminal shutdown.

Service one storage request at a time with `syntra_managed_storage_take` and `syntra_managed_storage_complete` on **this** owner, using the request's receipt token. `LOAD` reads the exact principal/stream; `CAS_COMMIT` atomically compares the expected position and commits the full state, provider generation, and checkpoint. Return `SYNTRA_STORAGE_DURABLE` only after actual durable commit, `SYNTRA_STORAGE_COMMIT_UNKNOWN` if uncertain. Free each taken request with `syntra_storage_request_free`; freeing it does **not** acknowledge the work. The [receipt contract](crates/syntra-ffi/include/syntra_recovery.h) specifies duplicate/conflict handling and the five-second elapsed deadline. Even a late request needs completion after foreign work stops; shutdown cannot finish with an unacknowledged delivery. Reopen and reconcile an expired bridge rather than confirming a late write.

Poll `syntra_managed_update_status` as well as lane status. `SYNTRA_UPDATES_RESTORED` refers to `CaughtUp` on the reported interactive generation. `READY` alone is insufficient; `FAILED` carries a `grpc_code`. For the actual receipt and callback sequence, see the [C resume fixture](crates/syntra-ffi/tests/managed_fixture/resume.h) and [managed adapter](crates/syntra-ffi/src/managed_updates.rs). Do not use `syntra_recovery_attach` or frame-pump storage functions on this owner.

## Verify from the workspace root

```sh
export RUSTUP_TOOLCHAIN=1.89.0
cargo test --locked -p syntra-net --no-default-features
cargo test --locked -p syntra-net --no-default-features --features media --lib lanes::tests::
cargo test --locked -p syntra-net --no-default-features --features media --lib media::tests::
cargo test --locked -p syntra-net --no-default-features --lib pump::tests::operation_output::
cargo test --locked -p syntra-integration --test connection_purpose --test operation_admission
cargo test --locked -p syntra-integration --features managed-media --test managed_media_fault
cargo run --release --locked -p syntra-integration --features managed-media --bin mixed_traffic -- --production-lanes --smoke
cargo build --locked -p syntra-ffi --release --no-default-features --features managed-media

# Linux/macOS: Python 3, Cargo, nm, and cc. Links the C consumer and drives its Rust host.
python3 crates/syntra-ffi/tests/build_contract.py BuildContract.test_managed_additive_exports_and_protected_consumer

# Full artifact/target checks, including expected rejections:
rustup target add --toolchain 1.89.0 wasm32-unknown-unknown
python3 crates/syntra-ffi/tests/build_contract.py
python3 crates/syntra-net/tests/target_contract.py
```

| Check | Fault or boundary exercised |
| --- | --- |
| [Lane tests](crates/syntra-net/src/lanes.rs) | Exercise slot and byte exhaustion independently, inbox overflow, abandoned notification pulls, and RPC credit after waiter timeout. Also cover cold/idle generations and negotiated restore with an in-memory recovery store. |
| [Transfer tests](crates/syntra-net/src/media/tests.rs) | Deny EOF Read for cached and empty downloads; revoke the ACL or change content between verification and publish. Also inject lost Put/Finalize replies and reopen SQLite. These are RPC/store faults, not packet loss or power cuts. |
| [Host restart test](crates/syntra-net/src/media/tests/process_restart.rs) | Exit one process after a part commits and another after finalization, both before the client gets a success reply. A third process recovers the published version by query and verifies the ordered bytes. |
| [Admission tests](crates/syntra-integration/tests/operation_admission.rs) | Shared tickets, external work after cancellation, writer backpressure, and revocation. Multiple pools model multiple owners; there is no distributed quota service in the test. |
| [Writer tests](crates/syntra-net/src/pump/operation_output_tests.rs) | Stall the final record with another result queued. Check byte credit on a sibling connection before and after write completion, injected write failure, or abortive shutdown. |
| [TCP interruption tests](crates/syntra-integration/tests/managed_media_fault.rs) | Deliver only part of a protected media reply, complete an interactive call and notification, then cut the media socket. The old call fails without replay, and a fresh generation accepts a new call. Waking a client with no media demand redials only interactive. |
| [Linked C consumer](crates/syntra-ffi/tests/build_contract.py) | The smoke test holds 31 tiny interactive calls unread; the 32nd returns `SYNTRA_BUSY` with no token because of byte credit. The resume fixture holds a reply after Put commits, then starts a fresh C process with the same manifest and a replacement hello credential. The host stays running. Plain `cargo test` does not run this fixture. |
| [Mixed-traffic smoke](crates/syntra-integration/src/production_lanes.rs) | Compares local single, manual-two, and `LaneClient` paths with synthetic RPCs. It does not measure SQLite file transfer, recovery, or the C ABI. See [benchmark methodology](BENCHMARKS.md) for interpreting measurements. |

These checks do not establish independent interoperability, exactly-once effects, physical crash durability, or an interactive latency SLA.

## Migration and review checklist

- [ ] Choose a single owner for each connection. Existing frame-pump clients keep their protected driver and receipt ordering; managed clients must not feed `syntra_ingest`/`syntra_emit` or attach the old recovery ABI to their new owner.
- [ ] Deploy the host methods (including `Read` at `offset == length`), shared admission policy, object ACL, and any required recovery service **before** enabling clients. A server without EOF support cannot complete an online download for this client; do not fall back to `Describe` or cached bytes.
- [ ] Budget for two runtimes/sockets, encoded replies, jobs retained by slow consumers, downstream copies, and private storage. Verify interactive progress under your actual load; separate sockets do not reserve network bandwidth or disk time.
- [ ] Persist the manifest and account scope, keep the source immutable, and separate transfer progress from durable update checkpoints. Exercise loss after Put/Finalize, corrupt local data, revocation between admission and commit, and callback shutdown in your deployment.
- [ ] Run the isolated checks above and record the actual targets/results. On rollback, stop and join the managed owners, retain databases/tombstones, and reconcile unknown outcomes before switching clients. Do not migrate live keys, request tokens, or subscription handles.
