# Syntra v1 Conformance Suite — Implementation-Independent Definition

- Version: 1.0.0-draft.1 (2026-10-26)
- Status: Draft (pending conformance-suite RFC; informative until accepted, then normative for claims)
- Scope: How any independent implementation proves Syntra v1 conformance without
  Rust, Go, private servers, private credentials, or private infrastructure.
- Normative references: `specifications/core/requirements.md`,
  `specifications/security/requirements.md`, `specifications/core/conformance.md`,
  `proto/syntra/v1/*.proto`, transport specifications in `specifications/transports/`.
- Terminology: BCP 14 keywords per `specifications/core/protocol.md`.

This directory is the **sole executable definition of conformance**.
Language implementations are separate projects, out of scope for this
repository; complete manifest-driven conformance runs remain a pending
verification goal (CI currently validates manifests and vectors only).
Implementation tests are evidence, never the source of truth
(ADR-010, SYN-ARCH-041). This
repository is pre-release.

RFC 0007 is accepted. `SNTR-SC1-WSS-V1` is registered in
[`profiles.yaml`](profiles.yaml) with executable case specifications in
[`manifest/sc1-wss.yaml`](manifest/sc1-wss.yaml); the companion
[`plans/secure-channel.md`](plans/secure-channel.md) retains historical
manual-observation mapping. Registration is not execution: no `CONF-SCW-*`
verdict is claimed. Rust implementation tests and measured in-memory benchmarks
are recorded separately in the [implementation evidence ledger](../docs/sc1-implementation.md);
they are not full conformance or independent interoperability. The profile is
additive and does not remove the TLS policy.

> A completely separate repository or a third-party implementation in any
> language MUST be able to read these files and build its own conformance
> runner. No language-specific runtime is required to understand the tests.

---

## 1. Conformance model (Section A)

### 1.1 Normative Requirement

A `MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `SHOULD NOT`,
`RECOMMENDED`, `MAY`, or `OPTIONAL` statement in a `specifications/` document,
carrying a stable `SNTR-*-*` identifier (for example `SNTR-RPC-002`).
Only the defining document owns the requirement; this suite never restates
normative force. Requirement IDs are permanent; prose may be clarified only by
RFC.

### 1.2 Conformance Test

A portable, language-neutral test case with a stable `CONF-*-*` identifier
(for example `CONF-RPC-001`). A test cites one or more normative requirements,
states preconditions, a neutral input, and an exact expected observable outcome
(connection state, session state, wire bytes or logical envelope, error code).
Test IDs are **not** normative: if a test and its cited requirement disagree,
the requirement prevails and the test is a bug (file an RFC).

Human-readable test prose lives in `conformance/rpc/*.md`,
`conformance/auth-session/*.md`, `conformance/errors/*.md`,
`conformance/events/*.md`, and `conformance/requirements/*.md`.
Machine-readable equivalents live in `conformance/manifest/*.yaml` and are
authoritative for runners (same IDs, same expectations; prose is commentary).

### 1.3 Conformance Profile

A named, versioned claim boundary (for example `SNTR-CORE-V1`). A profile
lists the requirement families it covers, the transport or capability binding
it exercises, and whether it is mandatory for a given claim level.
Profiles are defined in `conformance/profiles.yaml` and summarized in §2 below.
An implementation claims conformance **per profile**, never by a single vague
word (see §8).

### 1.4 Implementation Under Test (IUT)

The Syntra peer being evaluated: a client endpoint (initiator), a server
endpoint (host), or both. Every manifest case declares `roles` (`client`,
`server`, or `client-server`) stating which side(s) the verdict applies to.
A client-only IUT runs initiator halves; a server-only IUT runs host halves;
a full-stack IUT runs both plus loopback self-interop.

### 1.5 Capability

A named optional behavior (for example `syntra.update-recovery/1`) that MUST
be explicitly negotiated per `specifications/core/capabilities.md`
(SNTR-CAP-001/002). Capabilities are never assumed. There is no generic
capability advertisement carrier (accepted RFC 0005 D1): a capability is
declared per profile and confirmed per connection through that profile's own
accepted post-`ACTIVE` negotiation RPC. A capability-gated test is evaluated
only when the IUT declares support for the capability and follows that
profile's negotiation contract; otherwise the runner reports `UNSUPPORTED`
or `SKIP` (see §6), never `FAIL`. No event, resumption, or replay capability
identifier is allocated in default v1; the names in manifests
(`events-v1`, `events-replay-v1`, `resume-v1`) are **placeholders for the
future RFC binding** and MUST NOT be negotiated until that RFC is accepted.

### 1.6 Mandatory Test

A test whose `mandatory: true` flag means: every IUT claiming a profile that
selects the case MUST execute it for its applicable role and MUST report `PASS`
(or the specified `UNSUPPORTED` verdict for a correct optionality refusal).
Mandatory tests cover all mandatory interop (handshake, envelope, RPC, errors,
auth interface, bounds)
and all documented rejections. A mandatory test MUST NOT be skipped because a
transport makes it inconvenient.

### 1.7 Optional Test

A test whose `mandatory: false` flag and non-empty `capabilities` list mean:
evaluate it only when the IUT claims the capability. Passing is required to
claim the capability; skipping is correct when the capability is unclaimed.
Example: `CONF-EVT-008` (replay) is Optional, gated on `events-replay-v1`.

### 1.8 Unsupported Test (per-case verdict, not a test kind)

`UNSUPPORTED` is a **result**, not a test category. It means the IUT correctly
rejected or declined an unnegotiated option (for example a mandatory-only host
answering a subscription with `UNIMPLEMENTED`). `UNSUPPORTED` is a passing
signal for optionality handling; it MUST NOT be counted as `PASS` for the
capability itself, and MUST NOT be confused with `SKIP` (see §6).

---

## 2. Conformance profiles (Section B)

Full definitions: `conformance/profiles.yaml`. Summary:

| Profile ID      | Kind                 | What it proves                                              | Required for … |
|-----------------|----------------------|-------------------------------------------------------------|----------------|
| `SNTR-CORE-V1`  | MANDATORY CORE       | Envelope, serialization, handshake machine, RPC, errors, auth interface, bounds, security, capability-free event handling | **every** conformance claim |
| `SNTR-SESS-V1`  | MANDATORY CORE       | Session = connection, close/loss, expiry, no-implicit-resumption | every claim (runs over any claimed transport) |
| `SNTR-RPC-V1`   | MANDATORY CORE       | Correlation, concurrency, deadlines, cancel, idempotency discipline | every claim |
| `SNTR-EVENTS-V1`| OPTIONAL CAPABILITY  | Gated subscribe/delivery/unsubscribe, ordering, replay/cursor, recovery; mandatory capability-free cases also selected by Core | only `events-v1` / `events-replay-v1` / `syntra.update-recovery/1` claims (recovery: accepted RFC 0006 §11 — `CONF-URP-001…017` cases and `SYN-URP-*` requirements are registered, not executed; a supported claim still requires executed verdicts) |
| `SNTR-TCP-V1`   | TRANSPORT PROFILE    | Plaintext TCP framing (restricted development only)         | only TCP claims; never sufficient for production |
| `SNTR-TLS-TCP-V1` | TRANSPORT PROFILE  | Same framing over TLS 1.3                                   | TLS/TCP claims |
| `SNTR-HTTP-V1` | TRANSPORT PROFILE    | HTTP/1.1 request/response RPC binding (restricted dev only) | HTTP/1.1 claims |
| `SNTR-HTTPS-H1-V1` | TRANSPORT PROFILE | HTTPS with HTTP/1.1                                         | HTTPS/H1 claims |
| `SNTR-HTTPS-H2-V1` | TRANSPORT PROFILE | HTTPS with HTTP/2 (streams, refusal semantics)              | HTTPS/H2 claims |
| `SNTR-WS-V1` | TRANSPORT PROFILE    | WebSocket over HTTP/1.1 (restricted dev only)               | WS claims |
| `SNTR-WSS-H1-V1` | TRANSPORT PROFILE   | Secure WebSocket over HTTP/1.1 (TLS 1.3)                    | WSS claims |

Rules:

- Claiming `SNTR-CORE-V1` REQUIRES passing its selected core, session, RPC,
  security, and mandatory capability-free event cases, including `SNTR-SESS-V1` and `SNTR-RPC-V1`,
  over **at least one** transport profile (secure transport required for any
  production claim; SYN-ARCH-030).
- No implementation is required to support every transport to claim Core
  conformance. Each additional transport profile is claimed independently by
  passing its applicable manifest cases plus Core's selected cases over that transport
  (SNTR-WIRE-901 interop proof needs at least two profiles).
- An `SNTR-EVENTS-V1` capability claim is never required for Core. Core selects
  every event case with `mandatory: true` and `capabilities: []`:
  `CONF-EVT-002`, `CONF-EVT-005`, `CONF-EVT-010`, `CONF-EVT-011`,
  `CONF-EVT-012`, `CONF-EVT-014`, and `CONF-EVT-015`. A mandatory-only host
  correctly refuses subscription probes with `UNIMPLEMENTED` (reported as
  `UNSUPPORTED`); the other cases retain their manifest expectations. This
  selection does not enable any capability-gated event case.
- Resume-accept cases are Optional and gated on `resume-v1` (no such RFC
  exists; in default v1 only resume-**rejection** cases are Mandatory).
- The accepted update/recovery profile (`syntra.update-recovery/1`,
  [RFC 0006](../rfcs/0006-update-recovery-profile.md) §11) is registered in
  `manifest/recovery.yaml` with `CONF-URP-001…017` cases and `SYN-URP-*`
  requirement rows; registration is not execution, so no recovery verdict is
  claimed today. A Core-only conformance result stays valid as a per-profile
  claim, but Core-only cannot satisfy the stable release bundle, which is
  recovery-inclusive (RFC 0006 §11.1).

### 2.1 Manifest and case selection

In `profiles.yaml`, each `manifests` entry is either a path (load all cases,
subject to capability gating) or `{path, select}`. A `select` map matches every
listed field by exact equality. Thus `select: {mandatory: true, capabilities: []}`
selects only mandatory capability-free cases; an empty capability list is an
exact empty-list match, not a wildcard. These entries follow
`schema.profile_manifests` in `manifest/schema.yaml`.

A manifest's or case's `profile` is one profile ID or a non-empty list of
independently applicable profile IDs. Within a multi-profile transport manifest,
run only cases whose profile includes the selected transport; a shared case
runs separately for each claimed transport in its list. The manifest-level list
describes the file's coverage; the case-level value determines applicability.
Explicitly included single-profile manifests may belong to another profile
(for example Core's session/RPC/event cases or WSS's shared WS cases).
Deduplicate overlapping selections by case ID within each transport/role run.
Apply `roles` and capability gates
after selection; loading a manifest never negotiates a capability.

For HTTPS, `CONF-HTTPS-001` is H1-only; `002`, `003`, `009`, `010`, `012`, and
`013` are H2-only; `004`…`008`, `011`, and `014` apply independently to both.
Shared probes use the selected binding's exchange/header representation.

---

## 3. How external projects consume this suite

1. **Read the profiles** (`profiles.yaml`) and decide which profiles to claim.
2. **Read the manifest schema** (`manifest/README.md`, `manifest/schema.yaml`).
   Every case is plain YAML/JSON: `id`, `requirement`, `profile`, `roles`,
   `capabilities`, `mandatory`, `preconditions`, `input`, `expected`.
   No protobuf toolchain, no Rust, no Go, and no test framework is required
   to parse them — any YAML 1.2 parser suffices.
3. **Load the fixtures** in `test-vectors/`:
   `protobuf/` (golden logical encodings), `tcp/` (exact wire bytes),
   `http/` (request/response text), `websocket/` (Upgrade + framing).
   All names, hosts (`example.com`, `syntra.example`), and credentials
   (`opaque-test-credential-A`) are throwaway documentation values.
4. **Implement a runner** in any language that drives the IUT through the
   selected cases for the claimed profiles (§2.1), compares observables to `expected`, and
   emits one of the §6 verdicts per case. A minimal runner is ~300 lines:
   YAML load → transport connect → send `input` → assert `expected`.
5. **Publish a declaration** (`declaration.example.yaml`) listing name,
   version, claimed profiles, capabilities, bounds, and per-case verdicts with
   logs. Reviewers re-run any case from the declaration using only this repo.

Language-specific helpers (if any) MUST remain non-normative conveniences;
the YAML manifests are the normative executable form.

---

## 4. Directory map (deliverables)

```text
conformance/
  README.md                  — this file (model, profiles, results, claims)
  profiles.yaml              — machine-readable profile definitions (§2)
  claims.md                  — badge / claim wording rules (§8)
  declaration.example.yaml   — implementation declaration template (§7)
  plans/secure-channel.md    — RFC 0007 companion plan and historical observation mapping
  manifest/
    README.md                — manifest format + field reference (§C)
    schema.yaml              — machine-readable schema for manifests
    core.yaml                — CONF-CORE-* portable cases (§E envelope/core)
    session.yaml             — CONF-SESS-* portable cases (§F)
    rpc.yaml                 — CONF-RPC-* portable cases (§G)
    events.yaml            — CONF-EVT-* portable cases (§H)
    recovery.yaml            — CONF-URP-* update/recovery cases (registered per accepted RFC 0006 §11; execution pending)
    transport-tcp.yaml       — CONF-TCP-* (§I TCP)
    transport-tls.yaml       — CONF-TLS-* (§I TLS)
    transport-http.yaml      — CONF-HTTP-* (§I HTTP/1.1)
    transport-https.yaml     — CONF-HTTPS-* (§I HTTPS/H1 + H2)
    transport-ws.yaml        — CONF-WS-* (§I WS)
    transport-wss.yaml       — CONF-WSS-* (§I WSS)
    security.yaml            — CONF-SEC-* negative cases (§Q)
    requirements.yaml        — requirement → test traceability matrix (§D)
  requirements/              — human-readable transport cases (prose companions)
  rpc/, auth-session/, errors/, events/
                             — human-readable core cases (prose companions)
  test-vectors/
    README.md                — vector conventions + index
    protobuf/                — golden logical encodings (§J)
    tcp/                     — exact [length][protobuf] bytes (§K)
    http/                    — request/response fixtures (§L)
    websocket/               — Upgrade + framing fixtures (§M)
  interoperability/
    README.md                — two-implementation proof procedure
    matrix.yaml              — required interop pairs
    scenarios.yaml           — cross-implementation scenarios
```

`conformance/requirements/*.md` and the `rpc/`, `auth-session/`, `errors/`,
`events/` prose files are companions, not duplicates: IDs match the manifests
one-to-one.

---

## 5. Test-vector conventions

- Neutral applications only: `echo` (`/example.Echo/Echo`), generic key/value
  (`/example.KV/Get`), generic subscriptions (`/example.Events/Subscribe`).
  No chat, contact, receipt, payment, or social concept appears anywhere.
- Hosts `syntra.example`, `example.com`; never production names.
- Credentials are throwaway opaque bytes (`opaque-test-credential-A`,
  32-byte `0x41`/`0x42` patterns); never real secrets.
- Protobuf golden vectors assert **logical equality** (decoded fields), never
  byte equality across encoders (SNTR-SER-002/901). Only the TCP framing
  prefix + chosen fixture bytes are byte-exact — and only for that fixture.
- No raw TLS byte vectors are defined (TLS is negotiated, not frozen).
  WSS vectors cover Upgrade/framing; TLS behavior is referenced by harness
  name to `specifications/security/*`.

---

## 6. Result model (Section N)

Every case yields exactly one verdict:

| Verdict       | Meaning | Counts as pass? |
|---------------|---------|-----------------|
| `PASS`        | Executed; every `expected` assertion held; logs retained. | **Yes** |
| `FAIL`        | Executed; at least one `expected` assertion did not hold, or the IUT crashed, hung past its documented bound, or emitted an unlisted error. | No |
| `SKIP`        | Not executed because a stated precondition is absent (capability unclaimed, transport unclaimed, harness lacks a facility such as raw-certificate injection). The reason MUST cite the missing precondition. `SKIP` MUST NOT be used for a mandatory case of a claimed profile, except when the case declares `applicable_transports` whose families intersect none of the claimed transports (transport applicability per the manifest README's field reference): then `SKIP` is the correct verdict and the reason MUST cite the `applicable_transports` key. | **No** — neutral, excluded from pass-rate |
| `UNSUPPORTED` | Executed the optionality probe and the IUT correctly declined it (for example `UNIMPLEMENTED` for an unnegotiated subscription, or rejection of a resume attempt without the capability). The IUT behaved correctly **by refusing**. | **No** — correct refusal, excluded from capability pass-rate |
| `NOT_EXECUTED`| Listed but never run (planned, blocked, or omitted). The default state before a run. MUST NOT appear in a final claim. | **No** |

Critical rules (normative for reporting):

- `UNSUPPORTED != PASS`. A refusal proves optionality handling, not capability support.
- `SKIP != PASS`. An unrun case proves nothing.
- `NOT_EXECUTED != PASS`. A claim containing any `NOT_EXECUTED` case is incomplete.
- `PASS` MUST NOT be reported unless executed with logs (SNTR-CORE-901,
  SNTR-STEST-900). Replayed, copied, or inferred passes are non-conformant.
- Pass-rate is computed over executed mandatory cases:
  `PASS / (PASS + FAIL)` for the claimed profiles. `SKIP`/`UNSUPPORTED` cases
  are listed separately and MUST NOT enter the denominator.

---

## 7. Implementation declaration (Section O)

Implementations publish a declaration (template:
`conformance/declaration.example.yaml`) with:

```yaml
implementation: { name, version, repository, languages }
syntra_core: v1
profiles: [SNTR-WSS-H1-V1, SNTR-HTTPS-H2-V1]   # claimed transport profiles
capabilities: [events-v1]                       # empty when mandatory-only
bounds: { max_frame_bytes, max_concurrent_rpcs, handshake_timeout_ms, … }
results: [{ test_id, verdict, log_ref }]        # one row per manifest case
```

The declaration MUST live with the implementation (not in this repository),
MUST NOT claim source residence here, and MUST link logs sufficient for an
independent party to re-run any `PASS`. Bounds and defaults MUST be documented
(SNTR-REL-031); undocumented unbounded behavior is non-conformant.

---

## 8. Conformance badge and claims (Section P)

Full wording rules: `conformance/claims.md`. Summary:

- Say exactly which profiles passed, for example:

  > "Conforms to Syntra Core v1 and WSS/H1 v1"

  or with two transports plus events:

  > "Conforms to Syntra Core v1 with transports WSS/H1 v1, HTTPS/H2 v1 and
  > capability events-v1 (replay excluded)"

- NEVER use a bare "Syntra compliant" / "Syntra certified" / "Syntra compatible"
  without the profile list. A bare claim is non-conformant wording even when
  the technical results pass.
- Production claims MUST name only secure transports. A claim naming
  `SNTR-TCP-V1`, `SNTR-HTTP-V1`, or `SNTR-WS-V1` MUST carry the suffix
  "(restricted development only; not for public production traffic)".
- Capability claims MUST cite the capability identifier and its RFC. Until the
  events/resume RFCs are accepted, no implementation may claim `events-v1`,
  `events-replay-v1`, or `resume-v1` support — only correct **absence**
  handling (`UNSUPPORTED` on probes).

---

## 9. Security posture of this suite

- Every `CONF-SEC-*` case in `manifest/security.yaml` is Mandatory for the
  profile it guards (STEST-001…011 map in `specifications/security/test-plan.md`).
- Negative cases (oversize, truncation, replay, fixation, downgrade, invalid
  state) MUST be executed; absence of attack fixtures is not evidence of safety.
- No private key, production credential, or production hostname appears in any
  fixture. Certificate fixtures are harness-named references
  (`test-pki:valid-leaf`, `test-pki:wrong-san`, …), never embedded PEM bytes.
- Error-message hygiene is asserted by negative grep in every security case:
  no credential, token, path, SQL text, stack trace, or raw untrusted bytes in
  any `RpcError.message`, log, or diagnostic visible to the peer.

---

## 10. Acceptance criteria for this suite itself

- A separate repository can build a runner from these files alone (no
  language runtime implied).
- Every `SNTR-*` normative ID appears in `manifest/requirements.yaml` with a
  non-empty disposition (`automated`, `partially_automated`, `manual`, or
  `not_testable` with a stated reason). No mandatory ID is silently uncovered.
- Profiles, manifests, vectors, and the declaration template validate as YAML
  1.2 and cross-reference consistently (IDs cited exist; vectors decode).
- No domain-specific concept (chat, receipt, contact, profile, group) and no
  private dependency appears in any fixture or test.
