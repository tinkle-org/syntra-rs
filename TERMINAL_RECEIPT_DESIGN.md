# Scoped terminal receipts

A scoped terminal receipt lets one authorized, self-withdrawing operation attempt
one fixed success result on its initiating encrypted connection. The native TCP
path is implemented and disabled by default. Withdrawal is not delayed until
client acknowledgement, and loss never restores authority or permits replay.

## Configure native TCP

Override `syntra_net::pump::AuthenticatorFactory::terminal_receipt(identity)` to
return `Some(syntra_runtime::terminal::Policy)` for the intended verified binding.
The default returns `None`. In `crates/syntra-net/src/pump.rs`, the factory runs
with the confirmed `VerifiedIdentity`; bind the adapter to that exact
scope/enrollment, not to untrusted request metadata.

The following helper constructs the policy after the application supplies its
per-binding authority. Return it from the factory hook; it does not replace
credential authentication or `Handler::authorize`:

```rust
use std::{sync::Arc, time::Duration};
use syntra_runtime::terminal::{Authority, Policy};

fn retirement_policy(authority: Arc<dyn Authority>) -> Policy {
    Policy {
        method: "/example.Authority/Retire".into(),
        // Non-sensitive only: remote denial can race delivery after the final read.
        payload: b"retired".to_vec(),
        authority,
        read_timeout: Duration::from_millis(100),
    }
}
```

The typed adapter supplies **complete operation-aware connection authority**.
It replaces the ordinary connection guard for this connection. TCP establishment
refuses a terminal policy combined with a separate generic
`ConnectionAuthorization`; an uncoordinated monitor cannot be ignored or treated
as owned-commit evidence. Include expiry, enrollment, application policy, and
every superseding denial in the typed adapter. Method authorization still runs.

## Return the handler outcome promptly

Override `Handler::handle_with_context` in `crates/syntra-runtime/src/host.rs`.
It receives the SDK-created `RequestContext` and execution lease. Existing
handlers default to `handle_with_execution`; forwarding adapters must preserve
that context and lease path. `AllowAll` forwards it, but is not a production
authorization policy.

For the configured method, call `context.retire(expected_revision).await`.
`Authority::commit` owns the application mutation, withdrawal, private owner,
and every condition represented by the fixed receipt in the same conditional
transaction. Do not mutate in the handler before or after this await. On success,
`retire` returns AFTER commit and fresh owned-evidence verification; return its
`HandlerOutcome` promptly.
For example, this helper can be called from the context-aware hook:

```rust
use syntra_runtime::{terminal::RequestContext, HandlerOutcome};

async fn retire_request(context: RequestContext, expected_revision: u64) -> HandlerOutcome {
    // Use a revision from current trusted authority, not a peer assertion.
    context.retire(expected_revision).await.unwrap_or_else(|_| {
        HandlerOutcome::error(syntra_core::ErrorCode::Unavailable, "retirement unavailable")
    })
}
```

`retire` returns the fixed outcome after the coordinated transition; it does
**not** await its own output. Waiting inside the handler for receipt delivery or
joined cleanup would block work that depends on that handler returning. A
refusal does not authorize mutation elsewhere. Before reservation, the handler
may return a normal correlated error (as above) if the connection is otherwise
valid. Once reserved, the connection is fenced: a failed retirement closes
without an ordinary fallback response, even if the handler returns an error.
Clients must handle that loss as an unknown operation outcome; it neither proves
rollback nor permits an automatic mutation retry.

Only a live, pending, authorized call on an authenticated binding can reserve.
Expected revision must be nonzero and below `u64::MAX`. Zero/exhausted revisions
are refused before fencing or commit. The private request context cannot be
constructed from public request IDs or transferred to a new connection.

## Implement fresh typed authority

`crates/syntra-runtime/src/host_terminal.rs` defines the public API, re-exported as
`syntra_runtime::terminal` by `crates/syntra-runtime/src/lib.rs`:

- `Authority::observe(Option<Transition>) -> BoxFuture<'_, Observation>` starts a
  fresh authoritative read. `None` requests ordinary pre-reservation validity.
- `Authority::commit(Transition, ExecutionLease) -> BoxFuture<'_, ()>` performs the
  conditional application transaction. Returning `()` is deliberately not proof.
- `Authority::observe_with_budget(Option<Transition>, ElapsedDeadline)` receives
  the fresh read's absolute bound, already restricted by `read_timeout`, prior
  freshness and (once reserved) the operation cutoff. The default calls `observe`.
- `Authority::commit_with_budget(Transition, ExecutionLease, ElapsedDeadline)`
  receives the operation cutoff with its teardown tail excluded. The default
  calls `commit`. Cooperative DB adapters should check the deadline and bound
  their I/O using its remaining time or `run`; neither hook starts a new budget.
- `Transition` carries the private `ReservationId`, expected revision,
  authenticated `Principal`, and fixed method. The adapter is already bound to
  the verified channel's scope/enrollment by its factory.

Atomically compare the expected active revision and persist the complete
transition owner, new revision, and every application condition represented by
the fixed receipt. `ReservationId::as_bytes()` is for private storage only, never
peer input, wire data, or diagnostics. The SDK cannot verify durability from a
trait implementation; unconditional revoke booleans and callback return are not
evidence.

Owned evidence must be visible when the transaction commits, even if `commit`
has not returned. Supervisory reads must recognize that exact owner during the
commit/return gap without restoring ordinary authority.

| Observation | Decision |
| --- | --- |
| `Active { revision }` | Before commit, require the expected active revision; no ordinary egress after fencing |
| `OwnedCommitted { reservation, expected_revision, revision }` | Exact owner/expected revision and strictly newer committed revision; eligible only for the reserved result |
| `HardDenied` | External withdrawal, expiry, or superseding denial; sticky abort |
| `Unknown`, timeout, stale read, or mismatched evidence | Sticky abort |

A revision increase need not be adjacent: `7 -> 11` is valid. The first accepted
owned revision is pinned; subsequent reads must still report `11`. Changing it
to `12`, even with the same owner, aborts in committed, selected, and consumed
phases. Active after commit also aborts, and restoring old evidence cannot clear
failure. A later external revoke must remain visible as `HardDenied`; an old
owner tombstone alone is insufficient.

Reads must cover current expiry, enrollment/key policy, and application authority.
Stale caches or replicas cannot supply proof. `read_timeout` is **100..=250 ms**,
including the start-based freshness bound. Idle refresh runs at half that interval.
The 100 ms implementation minimum leaves 50 ms from the scheduled refresh to
expiry for timer quantization, executor scheduling, and a prompt authority read.
[Tokio sleep](https://docs.rs/tokio/1.54.1/tokio/time/fn.sleep.html) has millisecond
granularity and documents coarser resolution on some platforms, including Windows;
the former 1 ms bound left only 0.5 ms, below even the documented granularity.
This conservative floor is not a real-time scheduling guarantee or a DB latency
allowance: timer delay plus read completion must fit the remaining prior freshness.
For example, the deterministic idle regression models a 15 ms late wake at the
minimum (65 ms between prompt reads) for six intervals. The real TCP regression
also keeps a native-clock connection idle for 350 ms before retirement. Neither
establishes a universal platform latency bound.
A new read must finish before prior freshness expires and the operation cutoff;
a late read cannot renew stale authority. Future construction and polling must
not block the executor.

Hot-path and partial-write repoll gates check local sticky freshness without
authority I/O or renewal. The watchdog and explicit barrier/receipt gates perform
authoritative reads. A queued refresh keeps a bounded serialization wait, then
recomputes its observation start/deadline from current state after acquiring the
read lock; an expired interval or published denial cannot be repaired by a read.

## Fencing, full-frame barrier, and handoff

The runtime coordinator in `crates/syntra-runtime/src/host_terminal.rs` and native
pump in `crates/syntra-net/src/pump.rs` implement this sequence:

1. Validate policy, native TCP support, call ownership, revision, time, and size.
2. Copy the complete correlated success `Frame` and reserve one private owner.
   The maximum is **1,024 serialized Frame bytes**, excluding the four-byte
   frame-stream prefix; it is not a payload-only allowance.
3. Fence ordinary dispatch and output, notifications, recovery, and sibling
   results. Discard unstarted ordinary output.
4. Wait for an active ordinary **whole frame**, including all its records, to
   complete while authority is valid. Otherwise abort without starting commit.
5. Invoke the conditional authority transition, obtain exact owned evidence, and
   select the result once under the existing first-terminal rules.
6. Carry the immutable result and retained output charge through the typed native
   writer channel. Freshly validate after encryption and immediately before the
   one-use raw TCP handoff. Blocked I/O repolls use local sticky checks without
   renewal; finish that ciphertext sequence or abort and retire.

The lifecycle fence serializes with application and prepared recovery dispatch.
Existing recovery attachments are closed before mutation; ordinary recovery
output cannot escape. Tests exercise the actual Host recovery attachment.

Reader, writer, watchdog, encryption, and raw I/O gates share one sticky
classifier. Fatal reader errors publish failure before completion/diagnostics,
so a retained partial write loses permission without waiting for task joining.
Encrypted input still receives framing and protocol validation.
An invalid ordinary-frame start is an error that closes the connection. Only a
valid but already-fenced frame is suppressed without consuming a nonce.

Encryption consumes a nonce. The writer retains exactly the same ciphertext and
write future across partial writes or `Pending`; it never re-encrypts, restarts,
splices, or transfers the receipt. No unstarted ordinary egress is permitted after
fencing; only the active whole frame may finish during the precommit barrier.
Canceling siblings does not roll back already-running application effects.

Cancellation selected before success aborts; late cancellation of selected
success is ignored. Hard denial, explicit close/withdrawal, deadline, fatal input,
and carrier loss can still prevent completion. Locally observed denial before
serialized handoff wins. Remote denial after the last authoritative read can race
even the first bytes; accepted bytes cannot be recalled. No atomic
database-to-socket transaction or delivery guarantee is implied.

The fixed payload must therefore be **non-sensitive**: a remote denial can happen
after the final authoritative read but before or during TCP handoff, and bytes
already accepted by the carrier cannot be recalled. The receipt must contain no
secret, fresh credential, or protected application data. Local sticky denial gates
reduce this race but cannot eliminate it.

## Deadline and retained cleanup

The optional `Handler::request_budget(principal, method, payload)` selects an
SDK-local cap before initial `authorize_with_budget`. It is measured from the
original complete bounded-frame receipt, including queueing, classification and
authorization time, not from dispatch or reservation. `None` preserves the
existing wire/default/deployment limit; zero expires, and even `Duration::MAX`
cannot extend or overflow that limit. Envelope/method validation and request-ID
ordering precede this prompt, nonblocking, side-effect-free classifier. Built-in
recovery retains its own routing. The classifier runs outside protocol/raw-I/O/
lifecycle locks, retaining FIFO admission. Immediately afterward, lifecycle state
is reacquired and rechecked, then held through authorization and registration.
This preserves the existing authorization/reservation barrier: an in-progress
hard denial cannot be overtaken and swallowed by terminal fencing. The same
deadline is registered for pending selection, dispatch and the request context.

`Handler::authorize_with_budget` remains synchronous/nonblocking and defaults to
the existing fail-closed `authorize`. `RequestContext::budget()` exposes a readonly
`ElapsedDeadline` on that same clock for ordinary handlers as well as retirement.
These hooks are additive: legacy handlers/authority adapters keep their methods,
and `AllowAll` forwards budget selection/context while keeping its explicit
authorization bypass. They do not change the wire contract.

```text
D = min(request-wide RPC deadline, reservation start + 5 seconds)
T = min(initial remaining time / 4, 250 milliseconds)
write cutoff = D - T
```

Quiescence, commit, proof, selection, and complete local writing share this
absolute budget. The raw gate stops record use at the cutoff; closure and cipher
retirement do not restart ordinary graceful-close budgets. Insufficient time
rejects before mutation. Suspend-inclusive elapsed time, clock continuity, and
authority freshness can shorten eligibility, never extend it.

The SDK installs retained cleanup before mutation. The authority callback runs in
its own retained task with an `ExecutionLease`; dropping a waiter, deadline, or
carrier loss does not abandon that task's charge. Additional spawned/blocking
work must keep its own lease copy until it actually ends. Selected output,
complete local writing, client observation, and joined cleanup are separate facts.
Neither an operation nor its receipt is automatically retried or replayed.
Passing a budget to an adapter is cooperative enforcement, not a transaction
rollback guarantee. An uncooperative authority can commit durably after expiry;
its retained execution charge survives until actual completion, while sticky
failure prevents late completion from restoring a receipt.

The current native pump also caps each ordinary frame's complete write by the
authority interval, `read_timeout / 2`, in addition to its configured I/O limits.
For a 100 ms read bound, this is a 50 ms whole-frame write budget, including
framing, encryption and backpressure. Successful background refresh does not
extend that frame's budget. Slow or large ordinary output can therefore close
before terminal commit even while authority remains fresh. Enable the policy
only for traffic that fits this implementation constraint; receipt tests do not
establish bulk-transfer capacity.

## Supported paths

| Composition | Terminal receipt status |
| --- | --- |
| Native encrypted TCP with factory policy and context-aware handler | Supported |
| Actual Host recovery attachment on the coordinated path | Fenced/retired before transition; runtime-tested |
| Raw/custom record or plaintext frame driver | Unsupported; refuses before terminal effects |
| WASM or FFI | Unsupported; portable compilation/ABI tests do not enable it |
| WS/WSS or HTTP/HTTPS | Unsupported; policy refused before terminal effects |
| Terminal policy plus independent generic connection guard | Configuration refused |

`Host::install_terminal_tcp` and the doc-hidden driver bridge are trusted SDK
internals, not an application escape hatch or arbitrary custom-driver support.
No new wire message, peer option, advertised capability, or client API is needed;
existing clients parse the correlated `RpcResult`. Protobuf sources and generated
bindings are unchanged. Ordinary withdrawal and close defaults remain unchanged.

## SDK tests and limits

Run the owned suites with Rust **1.88.0** and locked dependencies:

```sh
cargo +1.88.0 test --locked -p syntra-runtime
cargo +1.88.0 test --locked -p syntra-net --no-default-features --features tcp
cargo +1.88.0 test --locked --workspace
```

Runtime coverage includes `crates/syntra-runtime/src/host_terminal.rs`,
`crates/syntra-runtime/tests/terminal_receipt.rs`, and
`crates/syntra-runtime/src/host_recovery_tests.rs`. Native coverage is in
`crates/syntra-net/tests/terminal_receipt.rs` and
`crates/syntra-net/src/pump/terminal_failure_tests.rs`. These exercise:

- Exact/private ownership, stable newer revisions, disabled/unsupported preflight,
  and the 1,024/1,025-byte complete-frame boundary.
- Full-frame barriers, dispatch/recovery fencing, fatal-reader publication,
  cancellation, freshness/deadline ties, partial loss and retained work.
- `None`, zero, long and maximum-duration caps against wire/default/deployment
  limits; receipt-origin admission delay; selector/authorization time; exact
  dispatch/selection expiry; readonly budgets; bounded validation; built-in
  recovery routing; `AllowAll` forwarding and unrelated methods.
- Terminal cutoff/read-bound propagation and an explicitly uncooperative late
  commit whose execution charge survives timeout without a receipt.
- The authorization/reservation race: an initial hard denial cannot be overtaken
  and swallowed by terminal fencing. Its deterministic blocking barrier
  deliberately violates the production nonblocking callback contract.

The native target also owns `lookup_is_pure_and_validates_the_requested_binding`
and `wrong_key_failure_is_not_withdrawn_binding_evidence`. Lookup validates the
requested handle/epoch and returns the key only while active, recording no counters
or output. Tests inspect the bounded Returning first message, replay its exact
bytes through normal native acceptance, and require native authentication refusal
for the exact withdrawn context after one handler and one commit. Wrong
handle/epoch refusals and a wrong key on an active binding cannot count as
withdrawal evidence.

Fake elapsed sources and paused time drive runtime cases. The partial-ordinary-
frame success regression uses reservation notification and a driven elapsed clock
over real encrypted TCP. Its separate exact-cutoff case keeps authority fresh at
50 ms and proves partial output aborts with zero commits. Native idle tests cover
minimum-bound refresh and expiry independently of successful retirement.

Native TCP fixtures use in-memory authority and establish SDK integration, not
durable database behavior, application acceptance, platform suspend behavior or
bulk-transfer capacity. Unsupported carriers and ABI paths retain their separate
refusal checks. Feature-gated zero-test binaries are not execution coverage;
workspace tests leave Docker execution to its explicit integration lane. Local
tests do not establish formal conformance or independent security review.
Production adapters must preserve the passed clock/cutoff, bound their own storage
I/O, and retain execution leases until work actually stops. A timeout cannot prove
rollback or guarantee receipt delivery.

## Normative provenance

Upstream SDD commit
[`985d90eb5ee6d7aec0d20ea088430f271eed7cd7`](https://github.com/tinkle-org/syntra/commit/985d90eb5ee6d7aec0d20ea088430f271eed7cd7)
contains canonical adoption of RFC 0014. Its
[connection §6](https://github.com/tinkle-org/syntra/blob/985d90eb5ee6d7aec0d20ea088430f271eed7cd7/specifications/connection.md#6-scoped-terminal-receipt),
[RPC §7](https://github.com/tinkle-org/syntra/blob/985d90eb5ee6d7aec0d20ea088430f271eed7cd7/specifications/rpc.md#7-scoped-terminal-result),
[security §9](https://github.com/tinkle-org/syntra/blob/985d90eb5ee6d7aec0d20ea088430f271eed7cd7/specifications/security.md#9-terminal-transition-authority),
and [transports §8](https://github.com/tinkle-org/syntra/blob/985d90eb5ee6d7aec0d20ea088430f271eed7cd7/specifications/transports.md#8-terminal-only-output)
adopt thirteen `SNTR-TRC-*` requirements. The
[RFC](https://github.com/tinkle-org/syntra/blob/985d90eb5ee6d7aec0d20ea088430f271eed7cd7/rfcs/0014-scoped-terminal-receipt.md)
is marked **Implemented** for specification adoption and registration of fourteen
conformance case groups, which remain **NOT_EXECUTED**. It records sole-maintainer
human self-review/self-approval, not independent security review. Adoption does not
activate host policy or establish durable application integration.

`SNTR-RPC-004` already requires receipt-origin accounting and permits documented
bounded host policy. The optional SDK-local request-budget hooks require no wire
or normative specification change. Existing wire-input provenance pins remain
valid for their unchanged inputs; this normative reference does not repin those
inputs. See [input provenance](CONTRIBUTING.md#input-provenance-and-authority) for
the separate implementation-input checks and source attribution.
