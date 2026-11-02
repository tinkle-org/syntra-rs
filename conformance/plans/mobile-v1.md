# Mobile v1 acceptance plan

Status: planned but not executed. Owner: [RFC 0008](../../rfcs/0008-mobile-lifecycle-and-v1-acceptance.md),
with [SC1 RFC 0007 §11](../../rfcs/0007-secure-channel-device-authorization.md#11-accepted-interoperability-contract-2026-10-29),
the host authorization lifecycle of [RFC 0010](../../rfcs/0010-sc1-host-authorization-lifecycle.md),
the accepted [recovery decision amendment, RFC 0006 §11](../../rfcs/0006-update-recovery-profile.md#11-decision-amendment--release-inclusion-and-recovery-safety)
and the accepted [Decision 0002](../../docs/decisions/0002-sdd-acceptance-wave.md)
wave, plus the [recovery plan](update-recovery.md). Acceptance anchoring:
RFCs 0006 §11, 0007 §11, 0008, 0010 and 0004 are accepted, so the behavioral
outcomes below derive from accepted normative requirements — unlike the
pre-acceptance draft, they are no longer bare proposals awaiting
acceptance. Each executed outcome still cites the owning requirement ID
at run time. The `MV-*` entries are scenario labels, not registered
conformance IDs; registered `CONF-*` cases live in the manifests.
Execution of this plan is a release gate, and none of the outcomes below
is an execution verdict.

## Required matrix and provenance

Run independent pure Go and Rust peers as Go initiator/Rust host and Rust
initiator/Go host. The first public target is SC1 over verified WSS, both NK
bootstrap and NKpsk0 returning modes, followed by core readiness, recovery
negotiation and generic RPC/updates. Both modes still require host admission;
NK alone never proves an enrolled client identity. Every additional claimed
carrier gets both role assignments and all applicable tests. Raw TCP/WS tests
remain restricted fixtures unless separately authorized public profiles exist.

Record exact specification/schema and implementation commits, language/crypto
dependency versions, roles, profile selections, bounds, fault configuration,
seed, commands, terminal outcomes and resource cleanup. FFI-backed Go is an ABI
lane, not the independent Go lane. Local fake-peer tests, vectors, actual TLS
sockets and mobile-device runs are separate evidence layers. Keep credentials
and traffic secrets out of retained traces; test-only vector inputs are public.

## Scenarios

| Label | Ordered input / fault | Required observations (cite owning accepted requirements at execution) |
|---|---|---|
| MV-WIRE | Raw known/same/unknown body alternatives; reserved 16/17; ordinary metadata reordered; wrong types for nested known fields including wrong-type then valid timeout; malformed lengths; every short-frame split point | D1 precedence, unknown metadata accepted, no malformed dispatch, same logical result across codecs |
| MV-SC-CONTEXT | All public context fixtures plus negative mutation recipes; wrong configured carrier/scope/key selector; legacy endpoints/subprotocols | Exact prologue/context; bounded pre-Noise rejection of malformed context; no format sniff/fallback |
| MV-SC-CRYPTO | Independent test-only static, PSK and ephemeral inputs in both Noise implementations | Exact published M1/M2 and first/later directional records; handshake hash if available; wrong pin/PSK/tag fails; deterministic RNG is unavailable in production API |
| MV-SC-CONFIRM | Replay valid M1 to a fresh responder; stop after M2; then valid encrypted hello in a separate run | No authenticated-device activity, ready or protected effect before fresh client record and current policy |
| MV-PRINCIPAL | Confirm enrollment P, host hello policy returns Q; missing verifier; empty credential; revoked/stale enrollment | Mismatch/missing authority fails before ready, no privilege union; allowed empty credential requires explicit host policy |
| MV-IDENTITY | Emit requests 1,3 with reversed host-validation completion; duplicate 3 while pending, reuse after completion, decreasing 2, max-u64 then wrap attempt | Admit in wire order; increasing requests dispatch once; violations close without misleading same-ID result; calls settle once with unknown outcomes as applicable |
| MV-DEADLINE | Hold call before writer handoff past deadline; expire during host validation/queueing; cancel concurrently with handoff; sleep beyond deadline with buffered result; wall-clock jumps; sub-millisecond remainder | No terminal queued emission or expired dispatch, no zero-as-expired budget, suspension counts, no wall-clock extension; already selected result retained |
| MV-RACES | Barrier-controlled result/cancel/deadline/loss/drain in each order, including equal logical time | RFC 0004 winner, exactly one terminal completion/map removal; no rollback claim; late frame cannot complete another call |
| MV-PARTIAL | Cancel/fail at each prefix/body write offset; encrypted frame spans records; full queue; reader/writer stalled | Finish unit within budget or close; never restart/interleave partial frame or reuse consumed nonce; bounds and terminal cleanup hold |
| MV-BLACKHOLE | No FIN/RST, each one-way blackhole, matching and unrelated Pong, byte trickle, expired NAT after idle | Advertised detection budget holds while scheduled; no unrelated-control satisfaction or indefinite deadline extension; no false processing success |
| MV-HANDOVER | Establish B while A has work; retire A; deliver late A result/event/confirmation; repeat network hints | A cannot mutate B state, calls complete once; fresh keys/auth/negotiation; old remote effects remain unknown |
| MV-RECONNECT | Refused connects, immediately closed links, outage, cancellation during dial/backoff, pause then long sleep/wake | One bounded reconnect owner; jitter/cap honored; no wake burst, no reset on bare TCP success, no arbitrary mutation replay |
| MV-EXECUTIONS | Non-cooperative handlers survive deadline/cancel; repeat calls/connections until count/byte caps | Live-execution permits retained; excess rejected; other principals isolated; no unbounded surviving work or false successful teardown |
| MV-RECOVERY | Run every recovery-plan scenario during reconnect, overload, loss and crashes | Negotiated feature state isolated; durable progress and snapshot boundaries correct; no silent history truncation |
| MV-REVOCATION | Revoke while idle, before ready, during dispatch/replay/snapshot; delay/cache/fail store; reconnect to another host | Measured declared commit-to-cutoff bound, deny admission on unknown validity, no new protected delivery after cutoff; committed effects not rolled back |
| MV-LIFECYCLE | Crash at host/device key persistence, activation, acknowledgement, old/new overlap; no install/ack through expiry or emergency revocation; simultaneous reconnect/rotation; pin changes | Routine rotation preserves recovery while authorized; expiry/revocation/hard cutoff can lock out pending independent recovery, never extend authorization; no revoked-epoch rollback; unknown pins fail closed |
| MV-LIMITS | Inject test state at record ceiling/lifetime, expire while suspended or assembling a multi-record frame; epoch maximum | No counter wrap or expired delivery; discard incomplete frame; fresh handshake and explicit recovery, no cipher restore |
| MV-PROXY | Direct WSS; accepted proxied topology; spoof forwarded identity/carrier; wrong SAN/expired/untrusted cert; upgrade mismatch | TLS identity and authenticated external carrier contract enforced, spoofing rejected; no credential before secure verification |
| MV-DRAIN | Stop admission with queued results, writer blocked until drain cutoff, peer never closes, uncooperative callback/task | Teardown time reserved within total budget; selected outcomes preserved, pending settled; tasks joined or shutdown-incomplete with ownership/accounting retained |

For remote failures assert only the profile-observable signal; a detector-local
typed cause does not imply that TCP EOF delivered that same code to its peer.
All socket cases have an outer harness timeout and teardown on assertion failure.
Use barriers/injected clocks rather than timing guesses for race ordering.

## Mobile and operational evidence

On supported iOS and Android integration layers exercise background/foreground,
OS suspension/wake, Wi-Fi/cellular replacement, process termination/relaunch,
call cancellation, client destruction, credential change/logout and recovery
from durable progress. Record OS/device/bridge build, lifecycle event order,
callback thread/ownership and allowed background execution conditions. No
always-running connection or push delivery guarantee is inferred while suspended.

Run seeded latency/jitter/bandwidth/reset/blackhole/outage/NAT-expiry scenarios,
including bufferbloat and small calls concurrent with large opaque transfers.
Measure latency percentiles, time to usable recovered service, reconnect count,
duplicate effects (application-defined operation keys only), CPU/wakeups,
peak/steady memory, open descriptors, threads/tasks and retained queue bytes.
Declare pass budgets before runs, including idle/paused cost and overload
recovery. Long soaks include repeated connection/subscription churn and time
changes. A simulated run does not establish mobile energy behavior.

## Activation and completion

Before implementation, accepted owner clauses get permanent IDs and each
scenario becomes runner-executable cases with exact faults, inputs, observations
and applicable roles/profiles. Preserve existing case IDs; extend manifest
schemas only through review when lifecycle/fault semantics need new fields.
Run mandatory case selection with no skipped/unexecuted applicable cases;
correct Core-only optionality refusal is not SC1/recovery support.

Retain independent security design/composition review, deployment lifecycle
contract and measured revocation bound alongside results. Context JSON lint
and repository/schema checks establish data consistency only. This plan is
not a conformance profile, executable runner or security certification.
