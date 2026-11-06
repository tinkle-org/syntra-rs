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

```text
D = min(RPC deadline, reservation start + 5 seconds)
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

## Tests and recorded evidence

Source coverage includes `crates/syntra-runtime/src/host_terminal.rs`,
`crates/syntra-runtime/tests/terminal_receipt.rs`,
`crates/syntra-runtime/src/host_recovery_tests.rs`,
`crates/syntra-net/tests/terminal_receipt.rs`, and
`crates/syntra-net/src/pump/terminal_failure_tests.rs`. Tests cover exact/private
ownership, stable newer revisions, preflight, 1024/1025-byte boundaries, barriers,
dispatch fencing, fatal-reader publication, cancellation, freshness/deadline ties,
partial loss, retained work, and fresh Returning denial.

Recorded verification on 2026-11-06 includes the stable-newer-revision checks:

| Scope | Result and limit |
| --- | --- |
| Runtime default and no-default features | 434 passed in each; the same scope, not 868 distinct cases |
| Net with native TCP | 102 passed, including 17 receipt integration tests |
| Net without default features | 68 passed; raw-driver scope, not TCP coverage |
| FFI `production` | 14 passed; no receipt ABI support |
| Full `cargo test --locked --workspace` | 681 passing tests/doc-tests with one Docker fixture ignored; feature-gated zero-test entries are not coverage |
| WASM build and dependency isolation | Portable build and all six isolation graphs passed; no browser execution |
| Clippy | Completed, not warning-free; two existing runtime warnings remain in untouched code |

These are recorded results, not a fresh verification of subsequent edits.

Follow-up verification on 2026-11-06 with Rust **1.88.0**, `--locked`, on macOS
arm64 covers the lookup-purity and minimum-read-bound corrections:

| Command/scope | Fresh result |
| --- | --- |
| `cargo test --locked -p syntra-runtime` | 442 passed |
| Same runtime suite with `--no-default-features` | 442 passed; repeated configuration, not additional distinct cases |
| `cargo test --locked -p syntra-net --no-default-features --features tcp` | 110 passed, including 19 receipt integration tests |
| Same net features with `--example terminal_receipt` | 2 fixture regressions passed; examples are tested explicitly |
| `cargo test --locked --workspace` | 697 tests/doc-tests passed; 1 Docker fixture ignored |
| Rust CLI server/client/probe | `owned`, `deny`, `unknown`, `gap` passed with unchanged JSON result/summary fields and one exact-binding denial each |
| Rustfmt check, `git diff --check`, workspace rustdoc and all-target Clippy | Completed; Clippy retains existing warnings in untouched core/runtime code |

The policy regression first failed because 1 ms was accepted. The lookup
regression first failed because three refused lookups incremented the denial
counter three times. Five regressions were added: one policy, two idle TCP, and
two example tests. Counts above overlap and must not be summed. The Rust CLI
checks are same-implementation runs, not a fresh cross-language verdict.

The partial-ordinary-frame success test uses explicit reservation notification
and a driven elapsed clock over real encrypted TCP. A CPU-load run exposed that
its previous wall-time sleep and 200 KB frame could legitimately exceed the
existing 50 ms whole-frame write budget before commit. Production budgets were
not increased. A separate exact-cutoff test keeps authority fresh at 50 ms and
proves partial output aborts with zero commits. After correction, 500 focused
runs and 50 complete 17-test receipt-suite runs passed under owned CPU load;
repetitions are not additional distinct cases.

The cross-language report at `syntra-go/TERMINAL_RECEIPT_INTEROP.md`
(requires a sibling checkout) records
**14 distinct passing cases** in both TCP role directions: owned/gap over direct
and fragmented streams, denial, unknown authority, and partial loss. Every case
checks a fresh Returning denial with no RPC. Its run-2 report and source hashes
remain exact evidence for that run only; later trees require a fresh run.

`crates/syntra-net/examples/terminal_receipt.rs` is the loopback-only fixture used
there. Its public provisioning and in-memory authority are not production storage
or credentials. Fixture passes do not prove application durability, platform
suspend behavior, non-TCP support, application Logout acceptance, or formal
conformance.

The fixture's `KeyStore::lookup` validates the requested handle/epoch and returns
the key only while active; it records no counters or output. Fresh-denial evidence
is recorded outside lookup after inspecting the actual bounded Returning first
message, replaying those exact bytes through normal native acceptance, and
checking authentication refusal for the exact withdrawn fixture context. A wrong
handle/epoch or a wrong-key failure on an active binding is not withdrawal proof.
The existing JSON event names/fields and summary counts remain unchanged; the
parent-owned Go harness must rerun cross-language evidence for these source bytes.

Documentation checks are scoped to this repository's actual configuration:
`cargo doc --locked --workspace --no-deps` is informational, and scheduled
`cargo-llvm-cov` reports execution coverage with no threshold. Neither measures
doc-comment completeness. Branch-added public APIs, coordination helpers, fixture
helpers, and regression tests have descriptive Rust comments; no coverage or lint
threshold has been changed.

## Shared contract and release boundary

The shared connection contract at
`syntra/specifications/connection.md#6-scoped-terminal-receipt` (requires a
sibling checkout) links its RPC, security, and transport requirements. The
sibling branch contains
canonical adoption of thirteen `SNTR-TRC-*` requirements and fourteen registered
case groups, not a formal execution verdict. Uncommitted adoption must merge
before being cited as the merged reference. Existing wire-input provenance pins
remain valid for their unchanged inputs; they are not publication of this feature.

See `syntra-go/TERMINAL_RECEIPT_HANDOFF.md` (requires a sibling checkout) for
manual merge, release, and consumer order. The evidence/handoff files are absent
from the recorded run-2 Go commit `3993457af7d36ffdb0fbe7f6615ab597a1e95abe`,
and connection section 6 is absent from the accepted specification commit
`c6a28abf2c52b3f21a7362366d3f5891f33601d5`. These paths preserve the intended
destinations and anchor without inventing resolvable pinned URLs.
[Issue 17](https://github.com/tinkle-org/syntra-go/issues/17)
remains open: tested SDK capability does not by itself fix a consumer's Logout
flow or replace its authority adapter.
