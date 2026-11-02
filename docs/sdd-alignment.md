# Accepted SDD v1 alignment plan

## Status, scope and checkpoints

- Branch: `feat/accepted-sdd-v1-alignment`.
- Starting Rust revision: `73f9775043ba2625a823f5cca3fbe92cdf345293`.
- Actual upstream target: `8ede3810b29fbba4d0e6ae6751a0025ceedda140` in sibling `../syntra`.
- Phase 1 inputs, Phase 2 Core/RPC and the Phase 3 recovery implementation checkpoint are complete in the working tree; verification is recorded in `AUDIT.md`. [Phase 2](phase2-core-rpc.md) and [Phase 3](phase3-update-recovery.md) describe actual APIs and limits. This is not formal conformance or completion of the remaining SDD bundle.
- Research verified the starting revisions and clean worktrees. The upstream full SHA supplied in the original research was incorrect; the actual target above was resolved from `main` and independently checked in the local authoritative checkout.
- Keep all P0–P2 alignment work on this Rust branch, but **pause for an explicit scope checkpoint before each big phase** below. Approval of this plan does not authorize every later phase at once.
- Status vocabulary: **pending**, **partially implemented**, **evidence needed**. A helper, schema, registered case or historical passing test does not make its enclosing requirement complete.
- Code paths abbreviated as `syntra-*/...` below are relative to `crates/`; line references identify the starting Rust revision or pinned upstream research baseline, not promised post-edit locations.
- Classification: implementation alignment to accepted wire-visible contracts; independently verified cross-repository integration remains separate. New protocol behavior requires an upstream spec delta and conformance plan before implementation.

Initial supported production topology is **direct SC1 WSS with TLS terminated and verified by the Syntra host**: canonical `/syntra/v1/sc1/ws`, exactly `syntra.sc1.v1`, TLS 1.3 and provisioned Noise server pinning. No TCP/plaintext fallback, HTTP request-response transport, QUIC, or new standardized authentication/enrollment RPC is introduced by this plan.
Development TCP/loopback WS remain explicitly gated (`default = []`, `development-carriers`); the public carrier-neutral pump must not depend on the TCP module.
Existing baseline `syntra-ws` framing/endpoints remain distinct. Browser SC1 is included, with limits disclosed rather than a false native-profile claim.

## Authority and Phase 1 provenance

The authority is the pinned upstream accepted RFC dispositions and corresponding owner clauses/IDL/manifests, not Rust behavior or copied commentary. Relevant records are RFCs 0003–0008 and 0010 plus Decision 0002; RFC 0006 §11 and RFC 0007 §11 govern their amendments.
Upstream paths in this document resolve in `../syntra` **at the target revision**, not an unpinned future checkout. Copied snapshot-relative links resolve in that pinned upstream tree, not as newly authoritative Rust-local documents.

Phase 1 provides the following snapshot/provenance work. Actual commands and results are recorded separately in the audit:

| Deliverable | Required content / boundary | Status |
| --- | --- | --- |
| Exact input snapshot | All **69 proto + conformance files**, byte-for-byte from the target revision; preserve copied stale status/notes rather than silently rewriting source history | Git provenance verified |
| Lock record | `upstream.lock.json` records the full target and per-file digests; distinguish snapshot provenance from implementation coverage | Offline and Git checks passed |
| Explicit regeneration | `scripts/upstream_snapshot.py` requires explicit `--sync --upstream`; checking never silently synchronizes. Rust regenerated with the existing pinned plugin | Generation and drift checks passed |
| Pin checking | `scripts/check-upstream-pin.py`; optional `--upstream` verifies actual Git provenance, not merely a label | Checker regressions passed; wired into CI |
| Documentation/evidence | Companion docs and audit record actual commands/results and changed scope; no inherited test totals become target-revision evidence | Updated; no runtime alignment claimed |

Historical pins retain their meaning: extraction/schema `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`; SC1 proposal review `94404d7378136d8b6c88ece28bf945c88d1653ba`; earlier accepted SC1 `0e8b0f8a4a789cb3d6d00b993e281867d2325e06` (see `MIGRATION.md:14`, `:102`). The target above does not retroactively replace those evidence scopes.
The target is a research/alignment pin, **not a claim that a formal specification freeze or release authorization exists**. Decision 0002 still requests a successor freeze record (`../syntra/docs/decisions/0002-sdd-acceptance-wave.md:18`, `:213`).
Read `docs/implementation-status.md` before interpreting backlog or release scope. Phase 2 changes replace the initial parser/RPC gaps described below; recovery, identity, FFI/browser and independent-evidence disclaimers remain applicable.

## Phase 2 — Core / RPC

Current checkpoint: implemented and locally tested; pause before Phase 3.

| Current implementation | Status / remaining boundary |
| --- | --- |
| Full raw-wire walk, exact body/outcome partitions, field limits before generated allocation | Implemented; bounded singular occurrences, in-bound last-value semantics, narrow missing-outcome correlation. Local allocation/parser regressions passed |
| Permanent IDs, FIFO enqueue/emission, exhaustion close and received-order high-water admission | Implemented; local duplicate/reuse/overload/near-max and 16-way reverse-correlation tests passed |
| Deadline-first per-call result/cancel/loss gates, host receipt-time budgets | Implemented; exact-tie and buffered-vs-selected tests passed; SC1 batch timestamps precede delivery. Suspend-aware clocks remain Phase 5 |
| Core capacity floor, finite configuration, graceful-close bounds and fallible construction | Implemented; legacy `new*` wrappers panic on invalid config, `try_new*` return errors. Full D5 drain reserve/join/reporting remains Phase 5 |
| Separate correlation/execution/selected-output accounting and retained withdrawal continuation | Implemented; external work must retain `ExecutionLease`. Actual SC1 replacements consult a process-shared default or retained factory budget. Deployment per-principal fairness/quotas remain host integration |
| Formal validation / surrounding lifecycle scope | Not completed: manifest-driven conformance, remaining role/direction clarification, all handshake timing scenarios, separate recovery/control/event queues, mobile/FFI integration and release evidence |

The following table retains the **starting-revision gap inventory and planned
verification**, not the current completion status; current behavior is above and
in [phase2-core-rpc.md](phase2-core-rpc.md). Its old source line references refer
to the starting Rust revision. It must not relabel local tests as formal cases.
The earlier proposed immediate writer-saturation close is not a universal owner
requirement: Phase 2 retains finite writer backpressure with bounded reporting
slots and documents exhaustion behavior; separate control/event progress is
still part of the later recovery/lifecycle integration.

Initial checkpoint: validation classification, ordered admission, terminal-gate ownership and public configuration policy.
No new envelope tags or error numbers. Frame tags 10–15 remain known bodies, 16/17 forbidden at top-level Frame position, 18–31 future bodies; metadata is 3–9/32+. Nested 16/17 remain unassigned unknown fields, not globally forbidden numbers.

| Priority / status | Requirement → current code | Planned verification / case ownership |
| --- | --- | --- |
| P0 / Partially implemented | `SNTR-SER-003/005/006/007/008/008A`, `SNTR-WIRE-002/004/005`: complete bounded structural validation before semantic classification. `syntra-core/src/frame.rs:372,423,469` currently has early reserved/duplicate rejection and limited schema descent | `MV-WIRE`, `CONF-SEC-003`, raw codec fixtures: every known-field occurrence type-checked, including wrong-type then valid timeout; malformed tails cannot be hidden by earlier future/reserved/duplicate content; legal non-minimal varints, tag/width/length limits, depth 32 and unknown wire structure; opaque bytes never recursively parsed |
| P0 / Partially implemented | `SNTR-SER-003`, `SNTR-WIRE-004`, `SNTR-RPC-006`: raw body and result-outcome partitions/multiplicity. `syntra-core/src/frame.rs:113,285,385`; obsolete metadata-only expectation in `syntra-core/tests/codec_vectors.rs:189` | `CONF-CORE-002/003`, `CONF-RPC-010`, `MV-WIRE`: metadata-only/no body → `INVALID_ARGUMENT`; sole future body/outcome → `UNIMPLEMENTED`; repeated same/different or known+future alternatives → `INVALID_ARGUMENT`; selected empty success valid; preserve scalar last-wins only after each occurrence is structurally valid |
| P0 / Pending | `SNTR-RPC-002/020`, `SNTR-WIRE-010`, `SNTR-RPL-012`: initiator nonwrapping IDs in actual request emission order; host received-order high-water admission before method/auth/concurrency rejection. `syntra-core/src/rpc.rs:89`; `syntra-runtime/src/host.rs:680` | `CONF-RPC-004`, `MV-IDENTITY`: duplicate pending/completed, decreasing/skipped-below-H, concurrent validation, max-u64/exhaustion; no offending-ID result, local `FAILED_PRECONDITION` plus native close; other calls unknown. Replace obsolete original-continues test in `syntra-runtime/tests/integration.rs:220` |
| P0 / Partially implemented | `SNTR-RPC-004/005/031`, `SNTR-REL-006`: admission-anchored initiator deadline and complete-frame-receipt host deadline. `syntra-runtime/src/host.rs:625`; receipt must travel through adapters, not be created after validation/locking | `CONF-RPC-007/008`, `MV-DEADLINE/RACES`: validation/worker-queue time consumes host budget; expired work never dispatches; sub-ms remaining budget expires locally; zero never resets an expired call to host default; readiness/queue waiting cannot restart a budget |
| P0 / Partially implemented | RFC 0004 D4 terminal gate: deadline checked before every pending result/cancel/loss candidate. `syntra-runtime/src/emission.rs:138,182`; `host.rs:740`; `initiator.rs:674` | Barrier/injected-clock result/cancel/deadline/loss permutations and exact ties: deadline wins while pending; validated-selected result stays terminal through delayed callback/suspend; merely buffered result does not win retroactively; one map removal/terminal observation, no rollback claim |
| P0 / Partially implemented | RFC 0008 D2/D5 emission contract: `syntra-runtime/src/emission.rs:162`; `syntra-sc1-transport/src/pump.rs:480` | `MV-PARTIAL/DEADLINE`: dequeue original `Vec<u8>` without cloning, exactly one `prepare_outbound` immediately before handoff, floor to positive ms; no terminal queued emission; after handoff finish in order within budget or abort; never regate fragments/ciphertext or re-encrypt a consumed nonce |
| P1 / Pending | RFC 0005 D2; `SNTR-AUTH-003/030`, `SNTR-HS-004/006/013`, `SNTR-ERR-003/020/021`, `SNTR-RPC-008`: `syntra-core/src/handshake.rs:23,64`, `frame.rs:293`, `syntra-runtime/src/connection.rs:36`, `syntra-sc1-transport/src/pump.rs:68` | Exact/max+1 8,192-byte credential, 128-UTF-8-byte connection ID, 4,096-byte diagnostic; producer/pre-allocation receiver checks; valid UTF-8 truncation only for local diagnostics; ≥16 supported concurrent calls and documented max; default close 5 s, configurable 0–30 s, zero immediate; invalid configs fail without panic |
| P1 / Partially implemented | `SNTR-RPC-001/003/006/008`, `SNTR-WIRE-006/007`, `SNTR-ERR-005/010`: method policy, total serialized size and opaque carriage. `syntra-core/src/rpc.rs:38` has a local 512-byte method cap | `CONF-CORE-001/004`, `CONF-RPC-001/003/013`, existing exact-MAX codec tests: document any deployment method cap rather than a new universal bound; MAX total Frame accepted, MAX+1 rejected; empty/arbitrary bytes preserved; 16 distinct payloads reverse-complete correctly; future numeric error reports UNKNOWN, never success |
| P0/P1 / Partially implemented | `SNTR-REL-007/008/030/031`, `SNTR-ASEC-020`: count/byte/time budgets and independent terminal/control progress. `syntra-runtime/src/connection.rs:657` waits for writer capacity; `host.rs:716` tracks RPC workers | `CONF-SEC-011`, `MV-EXECUTIONS/PARTIAL/DRAIN`: writer saturation terminates with `RESOURCE_EXHAUSTED`; notification queue drops newest without blocking terminal RPC results; execution permits retained until actual stop, including external/noncooperative work; aggregate host/principal limits prevent repeated timeout/connection churn from escaping caps |
| P1 / Partially implemented | `SNTR-HS-002/012/040`, `SNTR-WIRE-003/011`, `SNTR-AUTH-007/008/010`, `SNTR-RPC-032`: role/state legality and denial classification. `syntra-core/src/frame.rs:50`; `syntra-runtime/src/initiator.rs:318`; `host.rs:453,695,909` | `CONF-CORE-005/008/009`, `CONF-SEC-005/007/010`, `MV-PRINCIPAL/RACES`: timer at transport establishment, no partial-input reset; no invented pre-ACTIVE error Frame; direction matrix; unknown-result tolerance; fixed principal; generic principal-change request returns `FAILED_PRECONDITION`; withdrawal settles others and closes, no late protected output |

Retain deny-by-default `Handler::authorize`; permissive wrappers require explicit opt-in. Credential verification remains host-owned; empty credentials never implicitly select an enrolled principal.
Existing withdrawal regressions in `syntra-runtime/tests/runtime_defects.rs:420–687` are useful starting points, not proof that every handler-result/authorization/transport path shares the accepted terminal contract.

## Phase 3 — Accepted Update/Recovery Profile

Current checkpoint: implemented and locally tested; pause before Phase 4.

| Current implementation | Status / remaining boundary |
| --- | --- |
| Same-G snapshots, explicit provider loss/rebase, subscribed-boundary gates | Implemented in legacy coordinators and the wired per-H client; no snapshot-triggered provider generation change |
| Nine RPCs and wrapped notifications, connection-local negotiation/principal | Attached to actual Host/Initiator and opt-in SC1/WSS factory configuration; Core-only service remains available without profile confirmation |
| Replay/CatchUp fixed rounds, exact retries, same-G snapshot install/retry/fencing | Local unit, actual Core-bridge and direct-WSS tests; additional recovery rounds use fresh H/B rather than resetting old pagination |
| Reserved controls, subscriber-local overflow, current-authority/G checks | Targeted local-queue-exhausted at unchanged G; revalidation after writer backpressure; detected principal Unauthenticated withdraws Core even on publication paths |
| Full-state P/S/G/C persistence, crash uncertainty and resume | Native FileRecoveryStore reference uses exclusive process locking and atomic replacement; real subprocess/reopen probes. Applications still own provider issued-binding/history durability and effects outside the full-state blob |
| Formal conformance and lifecycle integration | Not established: registered manifest execution, independent Go/device/human evidence, mixed notification demultiplexing, automatic recovered-service reconnect, browser persistence/SC1 and ABI v2 remain later gates |

The following table retains the **starting-revision gap inventory** and case
intent, not current completion status. Current APIs and trust/storage boundaries
are in [phase3-update-recovery.md](phase3-update-recovery.md); command results are
in `AUDIT.md`. In-memory/reconstructible fixture sources are not production stores.

Initial checkpoint: provider scope, application durable-success/fence contract, round/gate state machines and host/client integration.
Authority: `../syntra/specifications/profiles/recovery.md:55–112`; RFC 0006 §11. Recovery is optional per connection but required for the selected stable bundle; Core-only fallback must not be reported as recovered service.

| Priority / status | Requirement → current code | Planned verification / case ownership |
| --- | --- | --- |
| P0/P1 / Pending | `SYN-URP-001/002/010/011/020/021`: versioned standardized profile methods and connection/principal confirmation. Local `proto/syntra/v1/recovery_profile.proto` and generated types are representation, while `syntra-runtime/src/recovery/driver.rs:117` remains caller-driven | `CONF-URP-001` is **server-role**, with unconfirmed probe and fresh confirmed control connections; `007/015` are client+server. Implement Negotiate after ACTIVE, maximum overlap, explicit bounds, unknown/missing-version handling and fresh negotiation each generation; no generic capability enumeration or invented auth RPC |
| P0 / Partially implemented | `SYN-URP-003/005/006/013/019`: effects plus `(P,S,G,C)` durable binding and issued-checkpoint authority independent of Confirm. `syntra-runtime/src/recovery/store.rs:44,63`; `driver.rs:60,188,229` | `CONF-URP-015/016` (client+server), crash windows before/after effects/checkpoint/Confirm: real atomic application transaction or declared idempotent fence, durable-known-safe resume without prior ack, no cross-principal/stream restore, distinct durable/Confirm-sent/peer-acknowledged observations. A stored digest alone is not atomic application-effects proof |
| P0 / Contradiction pending correction | `SYN-URP-016/025/026`: same-G snapshot install and exact S0. `syntra-runtime/src/recovery/driver.rs:325` rejects `generation <= current`; `profile.rs:547` needs new-generation progress to clear snapshot gating | `CONF-URP-006/013/014/016/017` (client+server): unchanged G, no provider rebase/replacement token, exact S0, all chunk indices/byte accounting, no wire SnapshotComplete, durable local install then peer-installed gate, retained exact retry; supersede retires H even when S0 bytes equal |
| P1 / Partially implemented | `SYN-URP-004/014/022/023/024`: fixed B per connection+fresh H; replay/result/completion fences. `syntra-runtime/src/recovery/engine.rs:8` retains first-page boundary fallback; `driver.rs:388` has local route/page helpers | `CONF-URP-003/004/011/012` (client+server): initial empty checkpoint skips Replay; one bare page per correlated result; hold live until validated/persisted completion; exact marker/retry with fresh RPC IDs; lost completion re-emitted; second gap/retry exhaustion retires H and captures new B; late equal-B old-H output inert |
| P1 / Partially implemented | `SYN-URP-003/004/006/019/021`: validate scope/version/G/auth/bounds before duplicate suppression. `syntra-runtime/src/recovery/driver.rs:98,210`; context/stream helpers do not alone establish wire validation | `CONF-URP-002/007` (client+server): duplicate bytes across connection/H/G/principal are not automatically duplicates; fresh subscription/routing after reconnect; one targeted delivery instance, no broadcast or stale-generation application |
| P1 / Pending | `SYN-URP-007/012/015/017/018/019/026`: provider loss vs retention miss vs subscriber-local overflow/revocation. `syntra-runtime/src/recovery/driver.rs:375,454` owns in-memory routes/history, not a complete bounded service | `CONF-URP-005/008/009/010` (client+server; 008 only for documented reject-new-work policy): old-G/next-G trailer only for real scoped loss/rebase; retention miss uses explicit snapshot fallback; accepted overflow terminates only affected H with current G and ASCII `local-queue-exhausted`; every hook reauthorizes, unrelated scopes survive |
| P1 / Pending | `SYN-URP-018/020/021`: full profile schema validation and resource accounting, not only core-envelope validity | Boundaries from owner §8: 64 subscriptions/connection, 256/principal, 16 pending profile calls, 256 KiB queued/stream and 1 MiB/connection, replay ≤64 batches/256 KiB, snapshot ≤256 KiB/page and 256 pages; 5 s default profile deadline. Validate exact/excess bounds, payload versions/emptiness/unknown fields and retained-response count/bytes/lifetime |

`CONF-URP-002–017` declare client+server roles, but each observation must be attributed to its actual actor; a local coordinator test does not execute both roles or the full case. `CONF-URP-001` must not be mislabeled both-role.
Update/regenerate through the pinned Buf + prost pipeline when required; **never hand-edit `crates/syntra-core/src/generated/`**. Snapshot synchronization is separate from profile runtime validation.

## Phase 4 — RFC 0010 host lifecycle / SQLite reference

Checkpoint: deployment owner declares enrollment and independent recovery authorities, device persistence acknowledgement, key-protection boundary, rollback anchor and operational budgets before implementation.
**User-selected design:** SQLite durable enrollment reference with pluggable key protection and rollback anchor. These are implementation decisions, not new protocol-defined storage or wire formats. No default authority, wrapping key or trusted rollback service is invented here.

| Priority / status | Requirement → current code | Planned verification / case ownership |
| --- | --- | --- |
| P0 / Partially implemented | `SNTR-DAUTH-005/010/015/016/017`: current enrollment, trusted identity and same principal before ready. `syntra-secure-channel/src/lib.rs:194,366`; `syntra-sc1-transport/src/pump.rs:730` delegates policy, identity has context/hash rather than an enrollment principal | `CONF-SCW-011/016/029/030/031/042`, `MV-PRINCIPAL/REVOCATION`: fresh confirmed encrypted hello, lookup-to-ready revocation race, both mismatch directions, absent verifier/empty credentials, no privilege union; fixed established binding and per-method authorization |
| P1 / Pending | `SNTR-DAUTH-001/003/011/012`: designated authority and collision-safe immutable issuance. `syntra-secure-channel/src/lib.rs:65` generates material, not transactional authority | `CONF-SCW-015/025/026/039/040/041`, `PLAN-DAUTH-011/012`: CSPRNG failure/zero candidate, independent 8-byte handle collision, duplicate/concurrent tuple issuance, cross-principal/out-of-scope enroller; no denied staged record or protected effect |
| P1 / Pending | `SNTR-DAUTH-013/014`: SQLite staged → encrypted delivery → device durable persist/ack → durable host commit, attempt-idempotency and bounded cleanup | `CONF-SCW-027/028`, `PLAN-DAUTH-013/014` and fault matrix F1–F9: crash/withhold/duplicate each boundary; uncommitted state never authenticates; reconcile lost ack/commit; expired attempts cannot resurrect or double-issue |
| P0 / Pending | `SNTR-DAUTH-006/017/018/019`: admission and pre-ready current checks, push invalidation plus bounded freshness/revalidation | `CONF-SCW-031/032/033`, `MV-REVOCATION`: measure authoritative commit → enforcement, ≤300 s hard maximum, 60 s target; idle/dispatch/replay/snapshot/store-delay/failure/stale-cache; deny new admission on unknown validity, stop protected delivery and close established channels within bound |
| P0/P1 / Pending | `SNTR-DAUTH-007/020/021/022`: transactional fresh-AK/handle rotation, increasing epochs, overlap/cutoff, independent compromise/lost-device recovery | `CONF-SCW-034/035/036`, `PLAN-DAUTH-020/021/022`: crash/concurrent reconnect/lost ack, hard cutoff despite absent install, epoch exhaustion, restored pre-revocation/rotation DB and stale device. SQLite atomicity is not anti-rollback; user-declared anchor must be outside the rollback domain and fail closed when unverifiable |
| P1 / Partially implemented | `SNTR-DAUTH-004/023`, `SNTR-ASEC-001/003/024`, `SNTR-ERR-003`: end-to-end secret lifetime and disposal. `Secret32` redacts/zeroizes (`syntra-secure-channel/src/lib.rs:41`); FFI/protobuf/plaintext copies have separate ownership | `CONF-SCW-037`, synthetic-marker inspection: AK/credential buffers, SQLite DB/WAL/temp/backup/restore, wrapping keys, telemetry, errors, device backups; disposal at expiry/revoke/retire/timeout. Do not equate dropping one wrapper with erasing every allocator/library/platform copy |
| P1 / Pending | `SNTR-DAUTH-024`: independently authenticated bounded server-pin updates, activation/overlap/retirement and rollback protection | `CONF-SCW-038`, `PLAN-DAUTH-024`, `MV-LIFECYCLE`: peer-taught/stale/replayed/retired pins rejected even with valid TLS; trusted update success separately demonstrated; connecting peer cannot teach trust anchors |

Lifecycle cases are registered specifications, not executions. Preserve host-owned credential verification and independent authority boundaries; AK possession alone does not authorize enrollment, every method or recovery of a compromised credential.

## Phase 5 — Mobile / transport / versioned FFI v2

Checkpoint: agree elapsed-clock continuity, execution ownership, shutdown reporting and ABI v1/v2 compatibility/migration boundaries.

| Priority / status | Requirement → current code | Planned verification / scenario |
| --- | --- | --- |
| P0/P1 / Pending | RFC 0008 D2/D5; `SNTR-RPC-004/005`, `SNTR-REL-006/030/031`, `SNTR-SC-009/014`: `syntra-runtime/src/emission.rs:12`; `syntra-secure-channel/src/lib.rs:389` use target-dependent elapsed clocks | `MV-DEADLINE/LIMITS/EXECUTIONS/DRAIN`: suspension consumes budgets; wake validates expiry/auth/channel before buffered input/sends; unknown elapsed continuity fails live work and replaces connection; no persisted cipher/monotonic timestamp reuse; surviving work retains permits and shutdown ownership |
| P1 / Partially implemented | RFC 0008 D3/D4; `SNTR-SESS-008`, `SNTR-REL-003/009/020`: `syntra-sc1-transport/src/client.rs:451,503,565` already fences generations and retains reconnect ownership | `MV-HANDOVER/RECONNECT`: one opt-in bounded jittered reconnect owner, pause cancels dials/backoff, wake no burst, no reset on bare TCP, stale A callbacks/results/events cannot affect B; no mutation replay; independently renegotiate recovery after each CoreReady and expose service readiness honestly |
| P1 / Partially implemented | `SNTR-WS-070`, RFC 0008 D3: `syntra-ws/src/native.rs:384,471` currently credits any Pong; SC1 has absolute record/frame timers | `MV-BLACKHOLE/PARTIAL`: matching probe response only, unsolicited Pong/trickle/incomplete data cannot extend absolute deadlines; one-way blackholes, NAT expiry, small/large concurrent transfers; document idle policy and no always-running/background guarantee |
| P1 / Partially implemented | `SNTR-SCW-001–012`, `SNTR-SC-001–015`: native SC1 carrier/pump and limits; `syntra-sc1-transport/src/pump.rs:43,480,675` | Applicable `CONF-SCW-001–024`, `MV-SC-CONTEXT/CONFIRM/PARTIAL/LIMITS`: preserve TLS+Noise pins, 15 s total/5 s channel defaults, 65,535 ciphertext/65,519 plaintext, 24 h/2^32 records; fragments/control interleaving, exact hello boundary, partial writes, lifetime/counter exhaustion, no nonce reuse or fallback |
| P1 / Pending | **User-selected ABI v2**; Core/RPC timing/order/policy/ownership requirements do not automatically reach `syntra-ffi`. `syntra-ffi/src/production.rs:37,1180,1226,1279`; token contract is not wired through ABI v1 (`syntra-runtime/src/policy.rs:55`) | `MV-IDENTITY/DEADLINE/RACES/HANDOVER/DRAIN` through C ABI: generation+completion identity, receipt/emission/terminal gates, no expired dispatch, host auth/authz/withdrawal, cancel/loss and owned shutdown. Test v2 headers/version/build/foreign callers plus explicit v1 compatibility lane; no silent ABI signature replacement |

## Phase 6 — Browser SC1 and mobile harness

Checkpoint: declare supported browser/mobile capabilities and unsupported enforcement surfaces before API/conformance claims; application owner supplies lifecycle/storage integrations.

| Priority / status | Requirement → current code | Planned verification / limits |
| --- | --- | --- |
| P1 / Pending | Browser SC1 included by user decision; `syntra-web/src/lib.rs:70` currently uses baseline `syntra.v1`, not SC1 | Both NK/NKpsk0, canonical context/endpoint/subprotocol, pinned Noise identity, protected hello, record/frame bounds and generation-safe recovery; no native fallback. Browser controls TLS negotiation/roots, implicit cookies and control frames: document deployment isolation and inability to assert all native TLS/header/probe properties |
| P1/P2 / Evidence needed | Browser resource/ownership truthfulness: `syntra-ws/src/wasm.rs:17` disclaims pre-reassembly bounds and configurable internal message-byte caps | Real browser execution, hidden queues/buffering, send stall/close cancellation, timers/freeze/resume, storage/secret-copy limits and callback teardown. Post-assembly checks and WASM compilation do not prove bounded browser/network assembly or full native-profile conformance |
| P2 / Pending external integration | RFC 0008; `SNTR-SESS-008`, `SNTR-REL-006/030/031`, `SNTR-DAUTH-004/021/023`; mobile acceptance plan §mobile/operational evidence | Real iOS/Android harness: background/foreground, suspend/wake, Wi-Fi/cellular, process kill/relaunch, cancel/destroy/logout/credential change, protected storage and lost device; record device/OS/bridge, callback thread/ownership and allowed background policy. Simulated clocks are not energy/device evidence |
| P2 / Evidence needed | Destination count/byte/time/energy budgets; `SNTR-REL-031`, RFC 0008 D5; `BENCHMARKS.md:72` is in-process pipe work | Declare budgets before measurement; seeded latency/jitter/bandwidth/reset/outage/blackhole/NAT/bufferbloat and churn/soaks; latency percentiles, recovered-service readiness, CPU/wakes, memory, descriptors/tasks/threads, queued bytes and application-defined duplicate effects |

## Phase 7 — Formal conformance and external gates

Checkpoint: freeze exact spec/suite/implementation inputs and claim scope; arrange independent peers, devices and reviewers. Registration, source consistency and local round trips remain separate from formal observations.

| Priority / status | Gate | Required evidence |
| --- | --- | --- |
| P1 / Evidence needed | Executable accepted-case coverage: `SNTR-CORE-901`, applicable Core/RPC/security/transport cases, `CONF-URP-001–017`, `CONF-SCW-001–042` | Role/profile/optional-policy-aware execution, exact faults/barriers and detector-vs-peer observations; explicit PASS/FAIL/SKIP/UNSUPPORTED/NOT_EXECUTED. Existing `syntra-runtime/tests/conformance_runner.rs:1` covers selected local scenarios only, not the full manifest |
| P1 / Pending external dependency | **Go sibling currently draft1; Go alignment is external** | Independent pure-Go/Rust initiator+host pairings, both bootstrap/returning modes and recovery; exact commits/crypto versions. Go using Rust FFI is an ABI lane, not independent crypto/interoperability proof; never claim sibling synchronization from Rust-only changes |
| P1 / Evidence needed | Independent cryptographic fixtures, `MV-SC-CRYPTO`, `SNTR-SC-001/003/004/005/010` | Independently derived public test-only static/PSK/ephemeral inputs; exact M1/M2, handshake hash where available, first/later directional ciphertext and negatives. Context/prologue examples alone are not Noise vectors; deterministic production RNG injection is not authorized |
| P1/P2 / Evidence needed | Topology and trust boundaries: `SNTR-SCW-007`, `SNTR-TSEC-008`, `CONF-SCW-007`, `MV-PROXY` | Initial positive topology is direct host-owned TLS only; proxy TLS termination/forwarded identity/carrier assertions remain refused. Test spoofing and refusal; any later proxy support needs separately accepted trust/binding authority and both-role evidence, not a reverse-proxy header workaround |
| P2 / Pending external gates | Formal freeze/release decision, real-device runs and independent human security/composition/persistence review | Arrange reviewer/device owners; record limitations and dispositions. Review RFC10 authority/rollback/disposal and recovery application persistence, not just Noise primitives. No release-readiness, exactly-once, performance/energy superiority or completed independent-review claim from this plan |

## Authority inconsistencies and verification discipline

- Accepted serialization specifies the body partition and nested-16/17 tolerance (`../syntra/specifications/core/serialization.md:19–39`); older Rust unknown-only classification and broad summaries must not override it. Decision 0002's RFC 0008 summary incorrectly describes 10–15 as metadata; RFC 0008 D1 and the owner specifications explicitly define those as known bodies. Complete structural validation must precede partition errors, without treating arbitrary opaque length-delimited bytes as embedded messages.
- `CONF-RPC-008` still says the tie-break is open (`../syntra/conformance/manifest/rpc.yaml:154`); accepted RFC 0004 D4 and owner `rpc.md:103–111` decide deadline-first pending ties. Correct/extend executable expectations through the upstream owner, not by preserving the obsolete note as authority. Keep vendored inputs byte-identical and label supplemental local probes separately.
- Direction ownership is stated in handshake rows (`../syntra/specifications/core/handshake.md:85–90`), but the reviewed clauses do not completely prescribe every ACTIVE wrong-direction error/closure. Resolve exact negative scenarios before inventing a universal close policy; unknown results retain their explicit tolerance.
- Generic forbidden principal-change requests use `FAILED_PRECONDITION` (`authentication.md:66`); `CONF-SCW-042` uses `PERMISSION_DENIED` for enrollment rebinding. Keep scenario ownership distinct or seek clarification rather than flattening all authorization errors.
- RFC 0005 D2 carries concrete credential/ID/diagnostic/grace limits (`../syntra/rfcs/0005-negotiation-bounds-identifiers.md:98`); some owner headings/text and older fixture comments retain draft history or incomplete restatements. Parent records reconciliation/freeze issues; copied stale notes are preserved and non-authoritative.
- `MV-*` are acceptance-plan scenario labels, **not registered CONF IDs** (`../syntra/conformance/plans/mobile-v1.md:13`). Missing executable coverage must be registered/reviewed; no invented case ID or test verdict is implied here.
- The upstream lifecycle manifest explicitly labels registration as planned/not executed. `automation_status` metadata is not run evidence. Historical Rust totals in `AUDIT.md:87–110` describe their recorded worktree/configuration, not this target revision.
- Findings above are targeted source observations and missing demonstrations, not an exhaustive security audit. Unchecked paths are planned verification, not asserted vulnerabilities or implied passes.

## Planned wire assertions and phase exit evidence

Extend reviewed protobuf fixtures and the consumer in `tests/interoperability/vectors.rs`; these seed bytes are **proposed assertions, not newly registered/executed fixtures**:

| Frame hex | Expected result |
| --- | --- |
| `0801d2050178` | Metadata 90 only, no body: `INVALID_ARGUMENT` |
| `0801920100` | Sole future body 18: `UNIMPLEMENTED` |
| `08017a00920100` | Known notification plus future body: `INVALID_ARGUMENT` |
| `080110076a040a000a00` | Repeated empty-success outcome: `INVALID_ARGUMENT` |
| `080110076a021a00` | Sole future result outcome 3: `UNIMPLEMENTED` |
| `0801100762041a001801` | Wrong-type timeout then valid timeout: structural `INVALID_ARGUMENT` |

Add reordered/malformed-tail/boundary variants and exact-MAX/MAX+1 total-frame assertions; sequence fixtures must assert emitted IDs, absence of illegal results, native closes and same-G recovery bytes, not merely API return values.
Later changes preserve Frame/schema allocations and SC1 context bytes; observable changes are accepted validation/error precedence, IDs/order/closure, remaining budgets, bounds, recovery payload/state behavior and lifecycle cutoffs. ABI v2 is separately versioned.
At each checkpoint record actual changed files, spec/case traces, commands/results, remaining gaps and external dependencies in the audit. This document invents no test results and marks no behavioral or formal-conformance phase complete.
