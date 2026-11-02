# Conformance — update and recovery (`CONF-URP-001…017`)

Related normative requirements are cited per case; test IDs are not normative.
Neutral fixtures only: generic subscription, generic key and value read,
and echo round trip with opaque payloads.

RFC 0006 is accepted and its §11 decision amendment is authoritative. Cases
below are registered executable specifications; registration is not an
execution result, and no verdict, interop result, or release readiness is
asserted here.

Contract terms follow [Update/Recovery Profile](../../specifications/profiles/recovery.md)
and [RFC 0006 §11](../../rfcs/0006-update-recovery-profile.md#11-decision-amendment--release-inclusion-and-recovery-safety).
Machine-readable equivalents are in [recovery manifest](../manifest/recovery.yaml).
Guidance on fields is in [manifest format](../manifest/README.md).
Related event coverage is in [event conformance](../events/events.md).

Harness fault injection: `faults` keys (`emit_batches`, `skip_batch`,
`skip_batch_after_progress`, `emit_duplicate_event`, `flood_events`,
`slow_subscriber`, `provider_history_loss`, `drop_completion`,
`snapshot_supersede`, `crash_after_durable_persist`, `confirm_uncommittable`,
`install_snapshot`, `overflow_local_queue`) are harness-side instrumentation
that drives emission, withholds batches or completions, collapses or loses
durable state under barrier control, introduces a slow subscriber, forces a
snapshot supersede, or kills the process at a persistence barrier — except
`overflow_local_queue`, which overflows the initiator's local notification
queue (fault injected on the initiator side). They are not wire fields,
consistent with `emit_events`, `emit_duplicate_event`, `flood_events`
precedent in [event manifest](../manifest/events.yaml).

## Reconciliation record (RFC 0006 §11.8)

- `CONF-URP-001/002/003/007`: retained with their fallback, duplicate/gap, and
  reconnect intent, extended with scoped `(P, S, G)` identity, fresh-round
  fencing, and durable-safe resume.
- `CONF-URP-004`: corrected to the §11 shapes — replay pages are delivered as
  one bare `RecoveryReplayPage` per correlated `RpcResult`, never as page
  Notifications; previously the expected pages were Notification frames.
- `CONF-URP-009`: replaced. The pre-amendment case asserted a shared-overflow
  continuity loss with `next_generation`; under §11.2/§11.4 local saturation
  must NOT carry `next_generation`, so this identity now covers true scoped
  provider history loss with old-generation/`next_generation` trailer fencing.
- `CONF-URP-010`: replaced. The pre-amendment case ended with a same-handle
  Replay reset from the confirmed checkpoint; under §11.3 a new round requires
  a fresh handle via a new Subscribe. This identity now covers subscriber-local
  saturation isolation (`terminated=true`, ASCII `local-queue-exhausted`,
  current generation, no `next_generation`).
- `CONF-URP-011`: extended — single-round fixed-boundary replay in correlated
  `RpcResult`s plus the fresh-handle second-gap round after durable progress
  beyond the first boundary.
- `CONF-URP-005/006`: extended with binding/G-stability, local same-generation
  installation, no-wire transfer completion, and coordinated S0 binding.
- `CONF-URP-012…017`: added for lost-completion exact retries, supersede
  retiring the handle, the absent `RecoverySnapshotComplete` wire carrier,
  durable-known-safe crash resume, unoffered-Confirm validation, and
  same-generation installation.
- Pre-amendment payload encodings asserting the old semantics (shared-overflow
  `next_generation`, page-as-Notification) were replaced with encodings that
  decode as the §11 shapes.

## CONF-URP-001 mandatory-only fallback and negotiation isolation

- Related normative requirement: SYN-URP-001, SYN-URP-010, SYN-URP-020, SNTR-CAP-003, SNTR-CAP-010, SNTR-CAP-020, SNTR-EVENT-001, SNTR-EVENT-011.
- Preconditions: ACTIVE on both connections of the same recovery-capable Host (never a Core-only host: the control on the other connection negotiates and confirms the profile). On the probe connection no Negotiate is run and the profile is not confirmed; no handle or checkpoint is created there, including by the `checkpoint_issued_for_handle` path, because Subscribe itself requires confirmation.
- Input: the runner deliberately injects a complete and otherwise valid initial-subscription `RecoverySubscribeRequest` (profile_version 1, non-empty bounded `stream_selector`, the valid empty `start_checkpoint` initial-subscription sentinel per SYN-URP-021) as the unconfirmed `/syntra.v1.UpdateRecovery/Subscribe` operation on the `ACTIVE` probe connection — a conforming initiator MUST NOT send profile operations before confirmation (SYN-URP-001), so this injection is runner-driven only; and, on the machine-readable paired control scenario (`control_connection` in the manifest, beside `input`), Negotiate (`RecoveryNegotiateRequest`, selected_version 1 with confirmed deployment bounds) followed by the exact same valid Subscribe payload; repeated across two connections with negotiation on one only. The case's verdict applies to the server role (the runner drives both initiator connections); initiator-side conformance for SYN-URP-001 is exercised by the plan's initiator-validation runs against a controlled host.
- Expected output: `UNIMPLEMENTED` on the probe (SYN-URP-010: the operation belongs to a profile not confirmed on this connection; an unknown operation is likewise `UNIMPLEMENTED`, so the attribution to the confirmation gate comes from the paired control's success with the same valid payload, not from the error code alone; request-shape and bounds validation are not the refusal cause) and success on the control (confirmed negotiation with the deployment bounds, then a fresh connection-scoped handle with a newly captured boundary) — the confirmation gate is the sole delta; request IDs are independently valid within each connection (the probe's `request_id` 3 is nonzero and admitted as increasing, RFC 0004); no batches emitted; negotiation on one connection does not enable the profile on the other; partial acceptance falls back to mandatory-only plus previously confirmed options. RFC 0006 §11.1 makes recovery required in the release bundle without relaxing the per-connection gate: Core-only conformance cannot satisfy the bundle; the durable known-safe resumption shape is CONF-URP-015's coverage.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional; SKIP when unclaimed. Registered; not yet executed.

## CONF-URP-002 duplicate tolerance within a validated scope

- Related normative requirement: SYN-URP-003, SYN-URP-004, SNTR-EVENT-007, SNTR-REL-005.
- Preconditions: ACTIVE; subscription confirmed.
- Input: Host emits the same batch twice across the recovered and live boundary.
- Expected output: Initiator tolerates the duplicate with no violation and no error storm, skipping an already applied result checkpoint only after version, handle/scope, generation, authorization, and bounds validation; equal bytes from another connection, handle, generation, or principal context are not a duplicate.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-003 gap detection and local recovery-needed

- Related normative requirement: SYN-URP-003, SYN-URP-004, SYN-URP-012, SNTR-EVENT-006, SNTR-EVENT-021.
- Preconditions: ACTIVE; subscription confirmed.
- Input: Host emits batches that carry predecessor and result checkpoints; one batch is withheld to form a gap.
- Expected output: Initiator detects the gap by predecessor chaining with no arithmetic on and no structural parsing of checkpoint bytes and no claim of scope from selector equality; it reports local recovery-needed, does not treat idle as caught-up, and no generation change results.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-004 replay paging in correlated results

- Related normative requirement: SYN-URP-004, SYN-URP-014, SYN-URP-022, SYN-URP-023, SNTR-EVENT-008, SNTR-EVENT-009.
- Preconditions: ACTIVE; subscription confirmed; replay retained.
- Input: replay from the durable known-safe start checkpoint where retained history exceeds one page.
- Expected output: exactly one bare `RecoveryReplayPage` in the correlated `RpcResult` of each Replay invocation, each page stating its continuation marker and the round's fixed catch-up boundary; never burst beyond documented bounds and never a page Notification; Initiator echoes the marker verbatim and stops at the boundary; held live batches release only after a validated completion matching connection+handle+generation+version+exact boundary.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-005 expired continuation with snapshot-required, binding intact

- Related normative requirement: SYN-URP-012, SYN-URP-015, SNTR-EVENT-009.
- Preconditions: ACTIVE; checkpoint outside retention.
- Input: replay from the outside-retention checkpoint.
- Expected output: `FAILED_PRECONDITION` in the failed replay `RpcResult` plus the explicit snapshot-required trailer; recovery follows the snapshot path; the checkpoint binding `(P, S, G)` stays valid and the generation is NOT incremented for a retention-window miss (RFC 0006 §11.2); never a silent restart from an unrelated point.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-006 snapshot gate with coordinated binding

- Related normative requirement: SYN-URP-016, SYN-URP-021, SYN-URP-025, SNTR-EVENT-008.
- Preconditions: ACTIVE; subscription confirmed; snapshot required.
- Input: snapshot offer binding the descriptor to `(P, S, H, G, S0)` under a provider-proven boundary, bounded fetch pages, and boundary confirm.
- Expected output: one chunk per correlated `RpcResult`; transfer completion derived locally from complete index coverage and byte accounting (no wire `RecoverySnapshotComplete` carrier); installation is application-local at the unchanged generation; the initiator opens the snapshot live gate only after a validated `RecoverySnapshotInstalled` matching handle, generation, and exact boundary S0; no partial install; the snapshot gate is separate from the subscribe-B gate.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-007 reconnect with fresh handles and renegotiation

- Related normative requirement: SYN-URP-006, SYN-URP-010, SNTR-SESS-008, SNTR-EVENT-020.
- Preconditions: new transport connected with no prior subscription.
- Input: new transport and handshake; explicit reconnect driver — confirmed `/syntra.v1.UpdateRecovery/Negotiate` on the fresh connection, then the recovery `/syntra.v1.UpdateRecovery/Subscribe` invocation with a fresh connection-scoped handle and newly captured boundary before any other profile operation (SYN-URP-010 client-side ordering, RFC 0006 §11.6) — plus the stale-handle receive-without-re-subscribe hygiene probe.
- Expected output: the Negotiate returns the confirmed version and deployment bounds; the recovery Subscribe returns a fresh connection-scoped handle with newly captured boundary; the stale-handle subscription attempt carries no continuity and no checkpoint transfer; no batches arrive; reconnect always establishes a fresh authenticated connection, renegotiates again, and subscribes with a fresh connection-scoped handle and newly captured boundary; neither capability state nor pagination or snapshot handles transfer; stale handles carry no continuity and only a validated durable known-safe checkpoint can resume.
- Expected connection state: ACTIVE.
- Expected session state: active.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-008 reject-new-work before acceptance

- Related normative requirement: SYN-URP-007, SYN-URP-018, SNTR-EVENT-030, SNTR-REL-007.
- Preconditions: ACTIVE; bounded buffers ready for flood.
- Input: Host produces batches faster than the peer consumes, before the affected subscription is accepted.
- Expected output: `RESOURCE_EXHAUSTED` on new work with documented backoff while existing subscriptions continue; never unbounded queueing; never silent truncation without the documented signal. Rejecting new work before a saturated subscription is accepted remains valid (RFC 0006 §11.4).
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed or when the host does not document reject-new-work). Registered; not yet executed.

## CONF-URP-009 scoped provider loss with generation trailer fencing

- Related normative requirement: SYN-URP-012, SYN-URP-013, SYN-URP-026, SNTR-EVENT-030.
- Preconditions: ACTIVE; two stable scopes; provider loss barrier armed.
- Input: harness triggers true provider history loss for the affected `(P, S)` scope.
- Expected output: one explicit versioned `RecoveryBatchTrailer` whose `generation` is the old G (7) and `next_generation` the new G (8); outstanding old-generation pages, offers, confirmations, and batches are fenced and subsequently fail `FAILED_PRECONDITION`; no mixed-generation work; subscribers of unaffected scopes keep their valid bindings; ordinary retention pruning or local queue saturation never produces this trailer (the pre-amendment shared-overflow continuity-loss expectation was replaced).
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-010 subscriber-local saturation isolation

- Related normative requirement: SYN-URP-007, SYN-URP-017, SYN-URP-018, SYN-URP-026, SNTR-EVENT-030, SNTR-REL-007.
- Preconditions: ACTIVE; two subscribers on the same `(P, S, G)`; flood harness ready.
- Input: harness floods delivery while pausing one subscriber so its queue saturates.
- Expected output: ONLY the affected subscription ends, with `terminated=true` at the CURRENT generation and non-empty ASCII `terminate_reason` `local-queue-exhausted`; `next_generation` is NOT selected and shared G is NOT incremented; the other subscriber keeps its valid checkpoint and continues; an affected pending profile invocation may fail `RESOURCE_EXHAUSTED`; initiator-local overflow reports local recovery-needed and cannot manufacture a provider `next_generation` (replaces the pre-amendment local-overflow new-generation expectation).
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-011 fixed boundary plus fresh-handle second round

- Related normative requirement: SYN-URP-004, SYN-URP-006, SYN-URP-014, SYN-URP-022, SYN-URP-023, SYN-URP-024, SNTR-EVENT-008, SNTR-EVENT-009.
- Preconditions: ACTIVE; durable checkpoint beyond which the initiator resumes.
- Input: replay from the durable known-safe checkpoint while new live arrivals occur during paging, then a second gap after durable progress beyond the first boundary.
- Expected output: pages as one `RecoveryReplayPage` per correlated `RpcResult` (never page Notifications); held batches release only after a validated completion matching the round; boundary fixed during the round; after durable progress beyond the boundary a new gap retires the handle locally (queue, cursors, pending offers cleared) and a fresh `Subscribe(start_checkpoint=C2)` yields a new handle with a NEWLY captured boundary; recovery runs toward the new boundary, never toward the obsolete one; no same-handle second round and no marker reset.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-012 lost completion retries and handle retirement

- Related normative requirement: SYN-URP-014, SYN-URP-022, SYN-URP-024, SNTR-REL-005.
- Preconditions: ACTIVE; subscription confirmed; reply retention active.
- Input: harness drops the round's completion signal.
- Expected output: loss of completion is not evidence of catch-up; the initiator repeats the exact preceding Replay (or same CatchUp) request with fresh RPC request IDs under documented finite attempts, absolute deadline, and backoff; the host returns the retained page/acceptance verbatim without advancing pagination and re-emits the round's completion (same handle, generation, boundary); duplicate completions are idempotent and never re-offer data. On retry or deadline exhaustion the initiator retires the handle and starts a fresh round through a new Subscribe from the durable known-safe checkpoint; no same-handle second round and no marker reset.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-013 supersede retires the handle

- Related normative requirement: SYN-URP-016, SYN-URP-025, SNTR-EVENT-008.
- Preconditions: ACTIVE; subscription confirmed; snapshot pending.
- Input: harness forces a snapshot supersede (gap, continuity-loss, or continuation-expiry report) while a fetch is in flight.
- Expected output: in-flight `SnapshotFetch` under the superseded handle X or retired handle fails `FAILED_PRECONDITION`; supersede retires the subscription handle and requires a fresh Subscribe before a new snapshot handle is issued — even when the new boundary bytes equal the old S0 and the generation is unchanged; staged pages are discarded, never partially installed, never installed across boundaries; old confirmations under a retired handle cannot install; an exact duplicate `SnapshotOffer` under the active handle returns the retained descriptor rather than a second offer.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-014 no wire carrier for transfer completion

- Related normative requirement: SYN-URP-002, SYN-URP-016, SYN-URP-021, SNTR-EVENT-008.
- Preconditions: ACTIVE; subscription confirmed; snapshot required.
- Input: fetch every snapshot index exactly once logically.
- Expected output: one `RecoverySnapshotChunk` per correlated `RpcResult`; transfer completion is derived locally from complete index coverage 0..N-1 and bounded byte accounting; there is NO wire transmission for `RecoverySnapshotComplete` — no request method, no result slot, and no `RecoveryNotification` arm or Notification outcome — so an invented wire `complete` carrier is nonconformant; `SnapshotConfirm` afterward still requires the exact offered boundary and current generation.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-015 durable-known-safe resume after crash

- Related normative requirement: SYN-URP-005, SYN-URP-006, SYN-URP-013, SNTR-SESS-008.
- Preconditions: fresh transport connected against restart-capable retained durable storage with effects and checkpoint durable; volatile state discarded; the reconnection is not yet authenticated.
- Input: crash after durable persistence; then on the fresh connection the driver authenticates (hello with a valid credential), runs `/syntra.v1.UpdateRecovery/Negotiate` (request_id 1) and asserts the confirmed result, then sends the existing recovery `/syntra.v1.UpdateRecovery/Subscribe` (request_id 3) — negotiation precedes any profile operation (SYN-URP-010 client-side ordering, RFC 0006 §11.6).
- Expected output: the Negotiate result confirms `selected_version` 1 with the deployment bounds (neither capability state nor pagination or snapshot handles transfer to the fresh connection); the Subscribe request carries `start_checkpoint` equal to the durable known-safe checkpoint — which may be newer than the last peer-acknowledged checkpoint when the confirmation or its response was lost; the host validates the issued checkpoint binding `(P, S, G)`, current authority, binding, and retention and MAY accept a valid checkpoint without a previous confirmation record; reconnect uses a fresh authenticated connection, renegotiation, fresh handle and boundary; no rollback by guesswork and no invented generation.
- Expected connection state: ACTIVE.
- Expected session state: active.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-016 unoffered Confirm versus issued checkpoints

- Related normative requirement: SYN-URP-013, SYN-URP-025, SNTR-EVENT-009.
- Preconditions: ACTIVE; subscription confirmed; no matching committable batch result issued.
- Input: confirm checkpoint bytes that were never issued as a committable batch result for that handle and generation.
- Expected output: `FAILED_PRECONDITION` without advancing or leaking state; host validation of an issued checkpoint is distinct from accepting an unoffered Confirm on an active handle — batch Confirm requires a committable batch result issued for that handle/generation and `SnapshotConfirm` the current offered boundary; the provider establishes its recoverable issued binding to `(P, S, G)` independent of Confirm receipt and reports its loss explicitly; on resume the same issued checkpoint may be accepted without a confirmation record (contrast CONF-URP-015); exact snapshot Confirm retries use the CURRENT generation only with no pre-install-generation exception.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## CONF-URP-017 same-generation installation without a provider rebase

- Related normative requirement: SYN-URP-012, SYN-URP-016, SYN-URP-025, SNTR-EVENT-008.
- Preconditions: ACTIVE; two subscribers on independent checkpoints; snapshot staged durably.
- Input: install the snapshot locally, then confirm the exact offered boundary with the current generation.
- Expected output: `RecoverySnapshotInstalled` carries the UNCHANGED current generation (7 in the registered fixture) and exact boundary S0, with no separate replacement checkpoint field; installation does not rebase the shared provider stream and does not change G; subsequent batches for that subscription chain from S0 within the same generation; unrelated subscribers continue without invalidation; a provider needing a genuine shared rebase performs and signals it before any descriptor in the new generation, and install confirmation never creates that rebase as a side effect.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `syntra.update-recovery/1` (SKIP when unclaimed). Registered; not yet executed.

## Sequence view

```text
Initiator                              Host
    |                                     |
    |--- invocation{negotiate profile} --->|
    |<-- result{confirmed and bounds} -----|
    |--- invocation{subscribe generic,    |
    |         durable checkpoint} -------->|
    |<-- result{handle H, generation G,   |
    |         fixed boundary B} -----------|
    |<-- notification{batch held until    |
    |         completion} ----------------|
    |--- invocation{replay from C} ------->|
    |<-- result{one page per call} --------|
    |<-- notification{replay_complete at  |
    |         B} --------------------------|
    |--- invocation{confirm checkpoint} -->|
    |<-- result{confirmed and steady G} --|
    |--- invocation{subscribe(start=C2),  |
    |         after gap retired H} ------>|
    |<-- result{fresh H2, same G, new B2} |
    |<-- notification{snapshot-required} -|
    |--- invocation{snapshot offer} ----->|
    |<-- result{descriptor(H, X, S0)} ----|
    |--- invocation{fetch X per index} -->|
    |<-- result{one chunk per call} ------|
    |         (transfer done locally; no  |
    |          wire complete carrier)     |
    |--- invocation{SnapshotConfirm} ---->|
    |<-- result{installed(S0, same G)} ---|
```

## Traceability

| Test | Requirement family |
|---|---|
| CONF-URP-001 | URP-001/010/020 (negotiation gate and isolation), CAP-010/020 |
| CONF-URP-002 | URP-003/004 (scoped duplicate tolerance) |
| CONF-URP-003 | URP-003/004/012 (gap detection, no generation change) |
| CONF-URP-004 | URP-004/014/022/023 (paged results, continuation gate) |
| CONF-URP-005 | URP-012/015 (retention miss with binding intact) |
| CONF-URP-006 | URP-016/021/025 (snapshot gate, same-G install) |
| CONF-URP-007 | URP-006/010 (fresh reconnect) |
| CONF-URP-008 | URP-007/018 (reject-new-work before acceptance) |
| CONF-URP-009 | URP-012/013/026 (scoped loss, next_generation fencing) |
| CONF-URP-010 | URP-007/017/018/026 (local saturation isolation) |
| CONF-URP-011 | URP-004/006/014/022/023/024 (fresh-handle round) |
| CONF-URP-012 | URP-014/022/024 (lost completion retries) |
| CONF-URP-013 | URP-016/025 (supersede retires handle) |
| CONF-URP-014 | URP-002/016/021 (no wire complete carrier) |
| CONF-URP-015 | URP-005/006/013 (durable-safe crash resume) |
| CONF-URP-016 | URP-013/025 (unoffered Confirm distinction) |
| CONF-URP-017 | URP-012/016/025 (same-G non-rebase) |

Further detail is in [profile readme](README.md).
