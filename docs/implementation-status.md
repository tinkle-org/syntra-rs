# Rust implementation status

## Accepted SDD alignment target

The active specification/schema/conformance target is
`syntra@8ede3810b29fbba4d0e6ae6751a0025ceedda140` (PR #20).
The implementation branch starts at
`syntra-rs@73f9775043ba2625a823f5cca3fbe92cdf345293`.
Phase 1 synchronizes all 69 upstream proto/conformance inputs, regenerates Rust
with the existing pinned plugin, and adds content-verified provenance and the
[complete P0–P2 trace matrix](sdd-alignment.md). It changes no runtime behavior.

The target registers 42 SC1 and 17 recovery cases. The accepted contract is not
yet a formal freeze, and neither copied manifests nor historical unit tests
establish a conformance verdict. [Phase 2](phase2-core-rpc.md) now implements
request-ID/high-water ordering, deadline-first terminal gates, bounded execution
leases/output ownership, raw body/outcome validation, preallocation field caps,
the concurrency floor and graceful-close configuration bounds. The local tests
and remaining limits are recorded in `AUDIT.md` and that contract document.
[Phase 3](phase3-update-recovery.md) now adds same-generation snapshots,
connection-local negotiation, all nine wire methods, bounded per-H queues and
round fences, actual Core/SC1-WSS attachment and full-state native persistence.
Applications still supply recoverable provider-side history/issued bindings and
their declared persistence integration; no generic business database is implied.
RFC 0010, full mobile/shutdown integration and ABI v2 remain open. The pre-wave
records below are historical starting-point evidence, not the current contract.

The selected subsequent scope includes a SQLite enrollment reference with
deployment-supplied key protection/rollback authority, runtime-backed ABI v2,
browser SC1 with explicit browser limits, and mobile evidence harnesses.
Go alignment is coordinated separately. Physical-device evidence, independent
human security review and the future upstream freeze remain external release
gates. Execution pauses for approval before each major phase.

## Pre-wave implementation scope and evidence

The native experimental, unpublished `syntra-sc1-transport` targets the
accepted RFC 0007 SC1 v1 profile `SNTR-SC1-WSS-V1` (24 cases
`CONF-SCW-001…024`), merged as upstream commit
`0e8b0f8a4a789cb3d6d00b993e281867d2325e06` (PR #18, accepted 2026-10-29).
It provides WSS, a carrier-neutral pump, opt-in development TCP/loopback WS,
and an opt-in reconnecting client. [MIGRATION.md](../MIGRATION.md) distinguishes
the accepted contract from proposal-review history and extraction provenance.
Baseline `syntra-ws` framing/endpoints stay unchanged; custom runtime writers
have the `Initiator::prepare_outbound` original-`Vec` behavior contract.

[SC1.md](../SC1.md) documents wire and lifecycle contracts.
[AUDIT.md](../AUDIT.md#current-recorded-verification) records the latest local
alignment results for the uncommitted working tree on
`feature/sc1-v1-acceptance-alignment`, based on `1d1916a`: 377 workspace tests
passed, 0 failed, 2 ignored; isolated WSS-only and development-carrier runs
passed 52 and 60 tests respectively. The workspace result includes 10 unit and
12 integration tests for `syntra-secure-channel`. Clippy exited 0 with 43 unique
warnings; formatting and upstream-pin checks passed.

Earlier explicit FFI/WASM, security, generation, workflow-lint and Criterion
smoke checks were not rerun for alignment. The earlier emission-gate results
(372 workspace, 50 WSS-only, 58 development-carrier tests) retain their own
scope in the audit record. Docker and the container suite were not executed;
no Docker availability check was recorded for this run. Browser execution
remains ignored. Local automated source reviews
do not establish independent human review.

### Acceptance alignment coverage

- The shared `ConnectionConfig::default().max_outstanding` changes from 64 to
  32 for all runtime users relying on the default, including non-SC1 transports.
  Explicit overrides remain available; writer and notification capacities stay
  at 256 each. SC1 `Limits::validate` enforces `1..=1024` for these capacities;
  that range is not a universal runtime bound. The new test asserts the default
  value only and adds no 33rd-call admission boundary test.
- Returning-mode clients reject an all-zero authorization key with `Error::Invalid`
  before Noise construction or RNG use. The responder returns
  `Error::Authentication` after store lookup and before Noise construction.
  `Secret32::new` is unchanged; this is not validation of every key construction
  path. Secure provisioning, randomness, handle collision checks, current
  enrollment validation and same-principal binding remain host obligations.
- Two new WSS tests cover fragmented M1 and M2 in bootstrap and returning modes.
  The real server receives M1 from a raw client through an active session; the
  real client receives M2 from a raw server through ready and an echo RPC.
  Each handshake message uses two fragments; exhaustive fragmentation and
  interleaved Ping behavior are not demonstrated. Fixture bytes are unchanged.

This evidence does not establish release readiness. Upstream acceptance is
complete, but formal conformance remains unexecuted and no conformance verdict
is claimed.
Exact context/prologue fixtures test public encoding only. They are not
independent Noise cryptographic vectors or independent cross-language interop.
Historical extraction, local-revision-1 tests and timing captures retain their
original scope in the audit and migration records.

## Historical pre-wave backlog

This retained inventory described the starting revision. The current Phase 2
contract and remaining-phase matrix above supersede its parser/RPC/accounting
entries; its historical wording is not a claim those changes are still absent.

### Host identity, validity and revocation

- Implement and demonstrate actual same-principal binding between the confirmed
  SC1 identity/enrollment and independently verified application credentials.
  `AuthenticatorFactory`, `Authenticator` and `Handler::authorize` are host
  extension contracts, not a supplied identity system.
- Define and enforce current-validity/expiry/revocation checks before `ready`
  and effects, including periodic host revalidation and bounded revocation
  propagation. One lookup or a successful handshake does not establish continuing
  authorization.
- Complete enrollment issuance, atomic storage, secure delivery, acknowledgement,
  lost-delivery recovery and rotation workflows.

### Accepted protocol and execution accounting

- Complete and validate the full accepted parser contract, request-ID rules,
  host-receipt budget semantics and execution accounting. Existing bounded codec,
  correlation and emission-gate tests cover their stated local behaviors; they
  do not establish full protocol conformance.
- Preserve the distinction between local queued-to-emitting handoff, host receipt,
  execution and observed completion. The emission gate reduces remaining request
  time at handoff; it is not an execution receipt or proof of a terminal effect.

### Durable recovery and client/mobile integration

- Implement durable wire recovery end to end, including persistence, wire
  negotiation, generation/principal binding, replay bounds, subscription recovery
  and execution-terminal evidence. In-memory session/recovery helpers are
  insufficient to claim a durable recovery service or exactly-once effects.
- Renegotiate application recovery after every `CoreReady` generation. The
  reconnecting client never restores durable application state or automatically
  replays mutations; unknown outcomes need application-level resolution.
- Unify or explicitly integrate the production FFI state machine with the intended
  runtime/SC1 SDK contract. Async runtime fixes and SC1 support do not automatically
  reach the separate production C ABI.
- Complete mobile integration and validate lifecycle/network/wake handling,
  protected credential storage, shutdown ownership and resource use on devices.
  Browser SC1 remains unimplemented.

### Independent interoperability and release evidence

- Execute the 42 registered `CONF-SCW` cases against the accepted profile and
  record results and remaining gaps. Upstream acceptance alone does not establish
  implementation conformance.
- Execute independent pure-Go/Rust SC1 interoperability with both initiator and
  responder roles and both bootstrap and returning modes, plus independent
  cryptographic vectors. Same-library round trips and public encoding fixtures
  do not replace this evidence.
- Validate direct host-owned SC1/WSS TLS termination and identity
  boundaries, real devices, connection/resource limits and adverse network
  conditions. SC1 proxy termination remains deferred upstream, not an enabled
  topology awaiting only tests. Container execution and browser runtime checks remain outstanding;
  the current pipe benchmark is not a WSS/network performance measurement.
- Obtain independent human composition/security review and address its findings.
  Automated source reviews do not satisfy this gate.

Release remains gated on these implementation and evidence requirements,
including recovery and mobile validation. No performance, energy, independent
interoperability or production-readiness claim follows from the local checks.
