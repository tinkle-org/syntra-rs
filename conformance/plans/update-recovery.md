# Update/recovery acceptance plan

- Status: non-executable acceptance plan for RFC 0006 §11. RFC 0006 is
  accepted per this wave's acceptance decision record; the plan itself
  remains prose, and the §11.8/§11.10 execution gates are pending.
- Proposal: [RFC 0006 decision amendment](../../rfcs/0006-update-recovery-profile.md#11-decision-amendment--release-inclusion-and-recovery-safety).
- Current draft owner: `specifications/profiles/recovery.md`.
- Representation inspected: `proto/syntra/v1/recovery_profile.proto`.
- Authority: `GOVERNANCE.md` §§3–5 and `rfcs/README.md`; acceptance is
  recorded by the acceptance decision record; no execution is claimed.
- Execution: **NOT EXECUTED** for every observation below. No runtime tests,
  interop results, conformance verdicts, or release readiness are asserted.

## 1. Scope and selection

`PLAN-URP-*` labels are document-local planning references, not registered
`CONF-*` cases or requirement IDs. This file introduces no runner syntax,
profile, manifest, schema, generated type, or normative owner change. The
recovery manifest (`conformance/manifest/recovery.yaml`) is the registered
definition of the reconciled `CONF-URP-001…017` cases, normalized in the
acceptance PR; registration is not execution, and implementers target those
registered cases. Where this plan and the manifest disagree, the manifest and
owning specifications hold; never declare an old fixture passing as
execution evidence for the replacement decision.

The target release bundle includes standardized recovery and independent
Rust/Go evidence after acceptance. Wire use remains optional and negotiated
after ACTIVE. A Core-only peer can conform without recovery over its named
transport; it cannot satisfy the recovery-inclusive release target by omitting
these observations. Current profile selection remains `SNTR-CORE-V1` (including
session/RPC/security requirements) plus a transport; recovery placeholders are
under capability-gated `SNTR-EVENTS-V1`. This plan registers no bundle profile.
Unclaimed recovery can be SKIP/UNSUPPORTED for a Core-only declaration, never
PASS. Missing recovery evidence blocks the proposed bundle's acceptance.

Roles: initiator maps to manifest `client`, host maps to `server`. Run initiator
validation against a controlled host, host validation against a controlled
initiator, then independent cross-language pairs in both directions. Carrier
adapters transport opaque envelopes; they do not own recovery or storage rules.
Use named production-eligible secure carriers for production evidence. A
restricted-development carrier run carries that restriction explicitly; it
does not establish a production claim. Other release work (RFC 0008, Core,
SC1 and audits) is outside this plan's changes and retains its own gates.

## 2. Fixture, ordering, and observers

### 2.1 Deterministic setup

Use neutral generic key/value state and generic subscriptions only. Create
principal scopes P and Q and stable stream identities S and T. Two subscribers
A (slow) and Z (healthy) share P/S/G; subscriber U observes Q's authorized view
of the same underlying source. Record the host's resolved identity, never
assume selector-byte equality establishes it. Use a fake provider with
explicit barriers for history append, prune, true history loss, rebase and
authorization decisions. The fake provider assigns opaque checkpoint byte
strings; only the fixture knows their history order.

Fixture notation `C0 -> C1 -> B1 -> C2 -> C3 -> B2 -> C4` describes provider
history, not arithmetic or lexicographic order on checkpoint bytes. Give
checkpoints deliberately non-sortable bytes. Use H1/H2 for round handles,
X1/X2 for snapshot handles, G for current generation and Gnext for a true
scoped continuity change. Each fixture records the actual assigned bytes and
their P/S/G binding. Fresh means new handle identity, even if B bytes repeat.

At every case start, establish authenticated ACTIVE unless the case explicitly
tests pre-ACTIVE behavior. Negotiate version 1 before profile operations.
Each RPC uses a distinct nonzero request ID; exact retries keep method and
decoded payload fields identical with a fresh request ID. Compare decoded
messages and opaque field bytes, not whole serialized Protobuf encodings.
Notification uses request ID zero and a `RecoveryNotification` discriminator
with matching outer/inner version. It never completes a pending RPC.

Default planned limits follow the RFC's proposed values: 64 subscriptions per
connection, 256 per principal, 16 pending RPCs, 256 KiB notification queue per
subscription, 1 MiB aggregate, replay 64 batches/256 KiB, snapshot 256 pages
of at most 256 KiB each, effective RPC deadline 5 s. Boundary tests use the
actual negotiated/documented deployment bounds, including serialized overhead.
Configure finite retries for deterministic tests: two retransmissions after
the original attempt, 100 ms then 200 ms backoff, and an absolute 2 s retry
budget (or the earlier effective RPC deadline). These are fixture settings,
not proposed universal protocol defaults. Document reply-cache capacity and
lifetime; test retained and expired paths independently with a fake clock.

### 2.2 Required observers

Capture a single ordered trace at barrier boundaries with these observers:

| Observer | Required evidence |
|---|---|
| Wire | Method, request correlation, decoded result type, notification outcome, H/X/G/boundary/marker exact equality and typed error; redact sensitive opaque values in public traces. |
| Initiator state | Active connection and H, immutable B, phase, retired-handle fence, validation outcome, held-queue bytes and local recovery-needed/loss counter. |
| Application | Offer count, applied logical operation identities, staging/active snapshot distinction, durable effects, durable P/S/G/checkpoint or fence journal, and recovery/reconciliation result. |
| Confirmation | Separate locally durable checkpoint, sent-confirm checkpoint and validated peer-acknowledged checkpoint; pending count, attempts, deadlines and backoff. |
| Host/provider | Authorization hook counts/outcomes, resolved scope, issued/committable checkpoint bindings, G changes and reason, retained reply/cache bytes, current offer, pagination advancement and notification queues. |
| Isolation | Z and U progress and checkpoints, unrelated echo RPC result, connection state and resource totals throughout A's failure. |

Host receipt of Confirm cannot prove that the application persisted safely;
that needs the durable-storage observer and persistence-contract review. A
volatile mock counter cannot prove crash durability. Crash cases require
restart against retained durable storage, with volatile state removed.

All event lists below are ordered. Release the next barrier only after the
preceding observation. Where two arrival orders are named, run both. Do not
use wall-clock sleeps to imply completion or absence of effects: inject clocks,
hold the appropriate barrier and inspect queues/state. “No offer” means zero
new application offers/effects before the specified gate, not merely no log.

### 2.3 Message shape constraints

- Subscribe result: `RecoverySubscribeResponse(H,G,B)` with non-empty B.
- Replay result: exactly one bare `RecoveryReplayPage`, whose `batch_payloads`
  entries decode as `RecoveryBatch`; completion arrives separately as a
  wrapped `replay_complete` or `trailer{catchup_complete=true}` Notification.
- CatchUp result: `RecoveryCatchUpAccepted(H,G,B)`; batches and completion
  trailer are Notifications. It has no from-checkpoint request field.
- SnapshotOffer result: `RecoverySnapshotDescriptor(H,X,S0,total_pages,
  page_bytes_max)`; it has no generation field. Bind its G through current H.
- SnapshotFetch result: exactly one `RecoverySnapshotChunk(X,index,bytes,S0)`.
  There is no defined carrier for `RecoverySnapshotComplete`; derive transfer
  coverage/counts locally. Do not invent an extra result or notification arm.
- Batch Confirm result: `RecoveryConfirmResponse(H,confirmed_checkpoint,G)`.
  SnapshotConfirm result: `RecoverySnapshotInstalled(H,boundary_checkpoint,G)`.
  The latter has no replacement-checkpoint field. Under the amendment both
  leave provider G unchanged; a provider rebase happens separately beforehand.
- Local-overflow terminal trailer: `generation=G`, `terminated=true`, non-empty
  `terminate_reason` equal to ASCII `local-queue-exhausted`, no
  `next_generation`. True shared-loss trailer:
  old `generation=G`, `next_generation=Gnext`, no second outcome selected.

## 3. Planned observations

### PLAN-URP-01 — release inclusion, negotiation and Core-only compatibility

Maps `SYN-URP-001`, `002`, `010`, `011`, `020`, `021`; RFC §11.1.

1. Connect profile-capable initiator to Core-only host, reach ACTIVE, invoke
   Negotiate. Observe correct refusal/no confirmation, no recovery batches,
   then successful neutral echo with mandatory-only behavior. Repeat with
   Core-only initiator and profile-capable host: no offer means no profile use.
2. On two separate connections to a capable host, negotiate on only the first.
   Invoke a known profile operation on the unconfirmed second: refusal, zero
   application effects and continued echo service. No capability leakage.
3. Offer 1..1 and confirm selected version 1; test no overlap, missing/wrong
   version on every other operation, outer/inner mismatch, unknown operation,
   ignorable unknown field and unset notification outcome. Expect the RFC's
   `FAILED_PRECONDITION` for invalid required version/shape, `UNIMPLEMENTED`
   for unknown operation, and safe ignoring of ordinary unknown fields.
4. Review declaration selection: Core-only absence is SKIP/UNSUPPORTED, not
   recovery PASS; a bundle missing accepted recovery or evidence is blocked.
   Negotiated fallback is recorded as no recovery guarantee. Verify reserved
   envelope numbers/names and all nine canonical method paths remain intact.

### PLAN-URP-02 — fixed-boundary replay, initial baseline and completion gates

Maps `SYN-URP-003`, `004`, `005`, `014`, `015`, `022`, `023`, `024`.

1. Persist state+C0; Subscribe(start=C0); accept H1/G/B1. Append C2 after
   acceptance and hold its live delivery. Request Replay(H1,C0,empty marker),
   receive a page C0->C1 at B1 with marker M. Validate, offer, durably persist
   effects+C1, then Confirm; observe echoed C1 and unchanged G.
2. Replay(H1,C1,M) returns final page C1->B1 with empty marker. Hold its
   persistence barrier; deliver completion(H1,G,B1). Observe completion cannot
   release C2 before persistence through B1. Release persistence; completion
   and validated chain allow live B1->C2, once. B remains B1 throughout.
3. Run opposite arrival order: final page persistence precedes completion;
   still no live offer until validated completion. Empty marker alone, idle,
   RPC success or transport receipt never opens that gate.
4. New initial subscription with empty start captures B. Assert no Replay;
   CatchUp obtains baseline completion and live starts from B. No historical
   application-state installation or restored-state claim is inferred.
5. Mutate page B, omit subscribe B, mutate completion G/H/version/B, send
   premature completion before data through B, or invalid batch predecessor.
   Observe no invalid offer/live release; protocol rejection/recovery-needed
   as applicable. A current valid duplicate completion has no repeated effects.
   Run both supported completion encodings and CatchUp streaming separately.

### PLAN-URP-03 — second gap after progress beyond old B and handle fencing

Maps `SYN-URP-004`, `006`, `013`, `017`, `022`, `023`, `024`; RFC §11.3.

1. Finish PLAN-URP-02 at H1/B1; durably persist and acknowledge C2 beyond B1.
   Provider appends C3 then B2; suppress C2->C3 and deliver C3->B2, causing a
   predecessor gap. Observe local recovery-needed, no application offer of
   the non-chaining batch, retirement of H1 and clearing of held state.
2. Issue best-effort Unsubscribe(H1), then Subscribe(start=C2) on the still
   ACTIVE connection. Receive H2 distinct from H1, G unchanged and freshly
   captured B2. First Replay(H2,C2,empty) recovers through B2, not toward B1.
   Complete/persist; only completion(H2,G,B2) permits subsequent B2->C4.
3. Between H2 acceptance and completion inject H1's late completion, page,
   batch, Confirm response and CatchUp acceptance. Observe no H2 cursor,
   durable/ack progress, application offer or held-queue release changes.
   Repeat with equal boundary bytes on two no-progress captures: H still fences.
4. Inject H1 marker on H2, attempt a new same-H1 CatchUp round or Replay
   reset after LIVE, and present C2 cross-stream/principal/generation. Reject
   stale/invalid work without mutation or disclosure. An exact retained old
   CatchUp request can only replay its original acceptance/completion, not
   create a new round; the initiator still fences it by H1. No generation
   increment results merely from replacement. Unknown retired handles may
   use the existing unknown-handle refusal; retained stale context fails
   precondition.

### PLAN-URP-04 — lost completion and bounded current-round retries

Maps `SYN-URP-014`, `015`, `018`, `022`, `024`.

1. Recover final page through B1, drop its completion and hold live. Retry
   the identical final Replay payload with a fresh request ID. Observe same
   decoded retained page, no pagination/application advancement, and re-emitted
   completion(H1,G,B1); then open the live gate. Duplicate page handling is
   idempotent under the same binding, after validation of H/G/version/bounds.
2. Separately use CatchUp from Subscribe's bound C0; drop completion, repeat
   identical CatchUp. Observe retained acceptance and completion at B1, no
   duplicate recovery side effects or moving B. Repeat empty initial baseline.
3. Drop all completions and expire the reply cache; advance fake time through
   the two-retransmission/absolute-budget limits. Observe no tight loop or
   idle-as-complete; retire H1, start H2 with fresh B from durable-safe C.
   Expired retry state fails explicitly instead of starting a same-H round.
4. Drop a Replay result instead of completion: retry only the immediately
   preceding request, then continue using its original marker/result. A stale
   earlier request or altered bounds/marker/from-checkpoint is not the exact
   retry exception; fail precondition, without cursor advancement.

### PLAN-URP-05 — local overflow with slow and healthy subscribers

Maps `SYN-URP-007`, `012`, `017`, `018`, `026`; RFC §§11.2/11.4.

1. Establish A and Z on P/S/G and U on Q's view. Keep Z/U draining. Pause A
   catching up while provider appends live entries. Fill A's holding queue to
   exact MAX then MAX+1, below aggregate exhaustion. Observe targeted terminal
   trailer at G with local-queue reason (or explicit initiator-local
   recovery-needed for that variant), clearing/fencing A, no G increment.
2. Send Z's next valid Confirm and replay its still-valid C on a fresh Z
   handle. Observe success at unchanged G; Z and U continue ordered delivery,
   echo succeeds and the shared connection stays ACTIVE. Retrying A uses a
   fresh handle and B. Repeat A's LIVE queue saturation and initiator-local
   notification loss counter, including dropped-final-update then silence.
3. Reject new work before acceptance with `RESOURCE_EXHAUSTED` plus backoff:
   existing subscriptions continue. Contrast an already accepted A unable to
   complete: a bare error with no terminal/recovery-needed transition fails.
4. At exact aggregate MAX/MAX+1, block the terminal writer too. Observe
   bounded reserved control capacity or explicit connection exhaustion/close,
   bounded cleanup and in-flight RPC failure, never an indefinitely live A or
   fabricated shared rebase. Do not require Z on the same actually exhausted
   connection to survive that connection close; its durable binding stays valid.

### PLAN-URP-06 — provider history loss, shared rebase and retention miss

Maps `SYN-URP-012`, `013`, `015`, `019`, `025`, `026`.

1. Establish A/Z on P/S/G with outstanding page, offer and Confirm; preserve
   U's unrelated Q binding. Trigger true provider loss for P/S. Observe one
   scoped change to Gnext and explicit old-G/next-G invalidation for A/Z.
   All old-generation operations fail `FAILED_PRECONDITION` without effects;
   no mixed-generation page or install survives. U continues unchanged.
   Repeat with actual provider loss spanning both P and Q: invalidate both
   affected scopes, preserving only subscriptions whose history remains valid.
2. Drop the invalidation trailer then submit old C on reconnect. Observe
   explicit rejection and current-generation recovery path, never reinterpretation
   of C. New Subscribe then snapshot uses Gnext and a provider-issued S0 bound
   to Gnext; no old handles/markers/offers survive.
3. Separately prune replay before C0 while P/S/G and checkpoint binding remain
   valid. Subscribe binds the attempt; Replay fails `FAILED_PRECONDITION` and
   emits snapshot-required for its H/G. Run result-before-trailer and
   trailer-before-result arrival; neither becomes success. G stays unchanged
   for a retention-window miss, and Z's retained checkpoint remains usable.
4. Explicit provider shared rebase follows step 1 before a new snapshot offer.
   Verify SnapshotConfirm does not perform a second generation increment.

### PLAN-URP-07 — snapshot transfer shape, supersede and local install

Maps `SYN-URP-016`, `017`, `021`, `025`, `026`; RFC §11.5.

1. Put A in snapshot-required at G; Z continues live. SnapshotOffer(Ha,G)
   returns descriptor(Ha,X1,S0,N=2,page bound). Observe host/provider persisted
   or reconstructible resumable S0 binding before descriptor exposure.
2. Fetch(X1,0) and Fetch(X1,1) each yield one correlated chunk result at S0.
   Hold the last chunk: no complete coverage or active install yet. Release
   it; derive coverage of indices 0/1 and total bytes locally. No
   RecoverySnapshotComplete Notification or second RpcResult is awaited.
3. Stage the image, validate it above Syntra, atomically persist image and
   P/S/G/S0 (or reconcile via declared fence); only then SnapshotConfirm.
   Result is RecoverySnapshotInstalled(Ha,S0,G), unchanged G and exact S0,
   not a new token. Deliver S0->Cnext at G; it passes the normal pipeline.
   Z continues its own predecessor chain without checkpoint invalidation.
   Hold/drop the installed response in a separate run: local durable S0 is
   visible, but the snapshot live gate stays closed until a matching retained
   reply arrives or a fresh-handle reconnect recovers from S0.
4. Inject missing/duplicate/wrong-index chunks, wrong X, mixed S0, conflicting
   duplicate page bytes, oversized page/total, invalid version, and result
   correlation mismatch. Identical retry counts once; invalid input never
   activates a partial snapshot or sends SnapshotConfirm.
5. Supersede X1 while Fetch(X1,1) is in flight: retire Ha and Subscribe for
   fresh Hb before offering X2. Repeat with exactly equal S0 and unchanged G.
   Old fetch fails precondition; discard X1 staging and reject late success
   after the local fence. SnapshotConfirm(Ha,G,S0) cannot install while
   SnapshotConfirm(Hb,G,S0) can after durable X2 installation. Exact offer retry
   under an active H returns its original descriptor, not another X. Repeat
   generation loss, targeted termination, and offer expiry during transfer.
6. Deliver old replay completion at original B while A installs at S0.
   It cannot open the snapshot gate or release from B. After installation,
   held batches chain from S0; any later catch-up needs fresh H/B.

### PLAN-URP-08 — confirm method separation, idempotency and retry fencing

Maps `SYN-URP-005`, `013`, `016`, `018`, `025`.

1. After batch effects+C1 are durable, Confirm(H,G,C1); drop response after
   host accepts. Exact retry with fresh request ID returns C1/G without new
   effects, queue/cursor movement or generation change. Observe durable=C1,
   sent=C1, peer-acknowledged still C0 until validated response arrives.
2. After durable snapshot+S0, SnapshotConfirm(H,G,S0); drop response. Exact
   retained retry returns original SnapshotInstalled(S0,G) without reinstall.
   Batch/snapshot requests have compatible field shapes, so send each on
   the wrong method with a checkpoint not authorized for that other purpose;
   it fails the method-specific committable/offer check.
3. Vary version, H, principal, G or boundary, use an unoffered checkpoint,
   supersede/terminate, expire reply retention or trigger true G change before
   retry. Reject with no advancement. Matching boundary bytes alone do not
   authorize retry; old pre-install-generation exceptions do not apply.
4. Drop every response; stop-and-wait prevents later Confirm overtaking the
   pending one. At retry budget/deadline exhaustion, preserve durable state,
   reconnect and Subscribe with C1/S0 under host validation. No infinite
   retry, implicit acknowledgement or replay of old H on new connection.

### PLAN-URP-09 — crash cuts and application persistence contract

Maps `SYN-URP-005`, `006`, `013`, `016`, `025`; RFC §11.6.

Run each row for a batch C0->C1 and for snapshot replacement C0->S0, both with
atomic persistence and with a separately reviewed durable idempotent fence.
Crash means kill the process at the barrier, discard volatile state, reopen
the same durable store and start a new connection/negotiation/subscription.

| Ordered crash cut / fault | Expected durable observer and recovery |
|---|---|
| After receive, after validate, after offer; before durable success | No Confirm. Atomic variant retains old state+C0; restart resumes C0. Fence variant reconciles journal before selecting safe C. |
| During atomic transaction or snapshot staging | Either old effects+C0 or complete new effects+C1/S0, never checkpoint ahead of effects; partial snapshot never active. |
| Application write succeeds but checkpoint write fails (non-atomic variant) | Durable fence identifies incomplete operation; replay/reconcile does not repeat logical effects. Without such a fence the contract fails acceptance, even if the wire exchange succeeds. |
| Checkpoint write succeeds but application write fails | No safe C1/S0 or Confirm. Fence repairs/rolls back the staged binding before resume; unfenced checkpoint-ahead-of-state fails acceptance. |
| Both durable, before Confirm send | durable=C1/S0, sent/ack still C0. Restart resumes exact new C with preserved P/S/G and host validation. |
| After send, before host receive | Locally durable and sent differ from acknowledged; resume new C without asserting old request execution. |
| After host commit, before result send; after result send but dropped | Host may have acknowledged internally; local peer-ack remains C0. Exact same-H retry while retained or reconnect from durable new C works without extra effects. |
| After validated response, before durable ack bookkeeping | Durable effects+C survives; missing ack bookkeeping cannot force duplicate effects or reinterpret the binding. |
| Host restarts after issuing S0, before any Confirm; or after accepting Confirm | Provider/host reconstructs issued S0 binding independent of H cache, or explicitly reports history/binding loss. Never invent a new generation/token to fit persisted client state. |

Review the application's transaction/fence implementation and inject repeated
crashes during fence reconciliation itself. Assert stable logical effect count
under its declared contract, not generic exactly-once delivery. If external
effects cannot be covered by the atomic transaction, their application fence
must cover replay; Syntra supplies no distributed transaction.

### PLAN-URP-10 — reconnect binding matrix

Maps `SYN-URP-001`, `006`, `010`, `012`, `013`, `019`, `022`, `025`, `026`.

For each row: preserve listed durable data, end the old connection, reach
ACTIVE with newly validated credentials, and negotiate anew. For rows with
durable C or S0, Subscribe with exact checkpoint bytes. For the no-durable-safe-C
row, reconcile the application fence before choosing an explicit snapshot or
initial live-only baseline, without sending a checkpoint. Observe a fresh H/new
capture B or explicit rejection.
No automatic session, capability, cursor or snapshot-handle continuity.

| Reconnect input | Expected host and application observations |
|---|---|
| Same P/S/G, peer-acknowledged C | Validate authority/binding/retention; resume from C, not an empty start. |
| Same P/S/G, effects+C durable, Confirm unsent or response lost | Valid issued C may resume without a previous host confirmation record; represented effects remain durable and are not re-offered as new effects. |
| Same P/S/G, snapshot+S0 durable, install response lost | Coordinated S0 binding permits fresh-handle resume without old X or assumed replacement checkpoint. |
| Same P/S/G, host retry cache expired/restarted, provider binding intact | Resume independently of old reply cache; an expired same-H retry is not required to succeed. |
| Same scope/generation, outside retention | Explicit bound replay/catch-up failure plus snapshot-required; no silently truncated success. |
| Same P/S but G changed or binding cannot be recovered | Explicit invalidation/rejection, then current-generation recovery/snapshot; no re-labeling old C. |
| Different P; same selector bytes but different resolved S; changed authorization scope | Reject transplanted C without effects or leakage; selector equality/credential reuse does not authorize progress. |
| No durable safe C | Reconcile the application fence before choosing an explicit snapshot or deliberately initial live-only baseline, without sending a checkpoint. Never claim old state restored by empty start. |

Try every old H/X/marker on the new connection and inject old completion after
new subscription acceptance. No new-round progress or held-queue release.

### PLAN-URP-11 — principal revocation and authorization-hook races

Maps `SYN-URP-010`, `012`, `013`, `019`, `025`, `026`.

1. Pause P's operations separately immediately before subscribe, replay,
   continuation, CatchUp, SnapshotOffer, each SnapshotFetch, batch Confirm and
   SnapshotConfirm authorization hook. Revoke/expire P, release the barrier.
   Observe `PERMISSION_DENIED`/`UNAUTHENTICATED`, zero new authorized effects
   and targeted termination where possible. Repeat at queued-delivery boundary:
   no newly emitted batches after revocation is observed; already in-flight
   bytes cannot be recalled and do not bypass local freshness checks.
2. Keep Q authorized on the same source. Confirm/replay its valid checkpoint
   and advance U throughout P's revocation. No unrelated G change, termination,
   lost checkpoint, leaked source position or credential-bearing diagnostics.
3. Test both P policies: termination without history invalidation; explicit
   scoped history reset. Only the latter invalidates P's old checkpoint
   binding. Regrant P; reset-invalidated checkpoints still fail; Q is intact.
   Retained Confirm responses never bypass renewed authorization checks.

### PLAN-URP-12 — validation order, bounds, cancellation and cleanup

Maps `SYN-URP-002`–`007`, `011`, `013`, `017`–`023`, `025`.

1. Replay and live deliver the same malformed predecessor, wrong G/H/version,
   oversized serialized batch and unauthorized context. Observe identical
   validation-before-offer decisions. A duplicate result checkpoint is skipped
   only within its validated scope/generation; a cross-principal or retired-H
   equal-byte result never bypasses validation. No checkpoint parsing/order.
2. For each documented subscription, pending-RPC, queue, replay batch/byte,
   snapshot page/count/total, opaque-field and deadline bound, run MIN (where
   applicable), MAX and MAX+1. Include zero/missing required values and the
   permitted empty initial-start/first-marker sentinels. Observe bounded
   counters and typed rejection/targeted recovery, no partial install or burst.
3. Cancel an outstanding Replay/Fetch, then deliver its late result. RPC
   cancellation alone does not terminate the subscription; a retired or
   superseded context still fences the result. Unsubscribe only the named H;
   late Notifications are tolerated without offer or reconnect-wide teardown.
4. Stop new work and shut down at each pending-operation barrier. Observe
   finite drain/deadline cleanup, bounded retained replies/staging and no
   leaked pending calls or subscriptions. In-flight connection-loss outcomes
   remain unknown, not synthesized as application success. Run echo on a
   surviving connection to observe isolation from one subscriber's failure.

## 4. Decision trace and existing-fixture reconciliation

Every row is planned/not executed. Requirement numbers below all have the
`SYN-URP-` prefix; reserved `008/009` remain unassigned.

| Proposed decision | Requirement IDs | Planned observations |
|---|---|---|
| Required release inclusion / optional wire | `001`, `002`, `010`, `011`, `020`, `021` | 01, 10, 12 |
| Stable scoped identity / true shared invalidation | `003`, `006`, `012`, `013`, `019`, `026` | 03, 05, 06, 10, 11 |
| Fresh H/B rounds and lost completion | `004`, `006`, `014`, `015`, `022`, `023`, `024` | 02, 03, 04, 10 |
| Local overflow / healthy subscriber isolation | `007`, `017`, `018`, `026` | 05, 06, 12 |
| Local snapshot install / coordinated boundary | `016`, `021`, `025`, `026` | 06, 07, 08, 09, 10 |
| Atomic effects+checkpoint or durable fence / confirm stages | `005`, `006`, `013`, `016`, `022`, `025` | 02, 08, 09, 10, 12 |

After acceptance, reconcile `conformance/manifest/recovery.yaml` and
`conformance/recovery_profile/recovery.md` with these observations:

- `CONF-URP-001/002/003/007`: retain fallback, duplicate/gap and reconnect
  intent; add scope validation, fresh-round fencing and durable-safe resume.
- `CONF-URP-004/011`: correct page/result versus notification shape and extend
  fixed-B coverage with the second-gap-after-C2 and lost-completion cases.
- `CONF-URP-005/006`: preserve explicit snapshot fallback; add transfer shape,
  local same-G installation, binding coordination, retries and crash cuts.
- `CONF-URP-008/009/010`: distinguish reject-before-accept, local queue
  termination/recovery-needed and true provider loss. Replace local-overflow
  new-generation bytes and same-handle Replay expectation; neither is evidence
  for the amendment as currently written.

RFC §11.8 enumerates the exact owner/IDL follow-up. Review the manifest
schema's requirement-ID patterns before mapping `SYN-URP-*`: they currently
accept other families, not these IDs. No ad hoc keys or new registered
identifiers are proposed in this prose plan. Formal schema/registry and
fixture conversion is a separate accepted follow-up.

## 5. Independent evidence and acceptance gate

After formal approval, execute all applicable observations with:

1. Rust initiator against controlled fixtures and Rust host against controlled
   fixtures, then Go initiator and Go host against separately constructed
   fixtures. Codec round trips alone are insufficient.
2. Independent Rust initiator → Go host and Go initiator → Rust host, both
   with real application persistence boundaries and fault/crash hooks. Run
   all success/failure paths, including both retry retention outcomes and
   both atomic/fence persistence contracts used by the claim.
3. Core-only/profile-capable combinations in both directions, plus A/Z/U
   isolation and concurrent unrelated RPCs. A shared native core called by a
   Go wrapper is not an independent Go protocol implementation; fixtures
   produced solely by the same runtime are not independent verification.

Retain immutable source revisions, accepted RFC/owner/schema revision,
implementation provenance, role, profile/capability/carrier, configured
bounds/retention/retries, exact synthetic inputs, barrier/fault order, redacted
decoded packet traces, durable-store before/after records, observer counters
and expected-versus-actual outcomes for every subcase. Record NOT_EXECUTED
explicitly for absent evidence; a planned label never becomes PASS by
documentation review. Reviewers inspect storage/fence correctness and
principal isolation in addition to traces.

Formal blockers: assigned author/reviewers and public maintainer quorum;
protocol/security/compatibility and release-scope approval; accepted
owner/IDL/registry synchronization; approved bounds and documented finite
retry/cache policies; independent execution and evidence review; release
notes/migration and maintainer release authorization. These are approval
and evidence gates. The recovery design choices are specified in RFC §11,
not left for each implementation to decide.

Static repository validators can check document structure and links. They
cannot execute this plan, prove application durability, establish Rust/Go
interop, or authorize a conformance/release claim.
