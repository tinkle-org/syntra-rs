# Implementation audit notes

## Accepted SDD alignment phase 3

The uncommitted branch now includes the negotiated update/recovery runtime in
[docs/phase3-update-recovery.md](docs/phase3-update-recovery.md): all nine RPCs,
wrapped notifications, immutable per-connection profile binding, per-H fixed
rounds, same-G snapshot installation, explicit scoped loss, bounded data/control
queues and typed client orchestration. Host/Initiator routing and the opt-in
SC1 factory adapter are attached, including actual direct-WSS tests in both modes.

The native full-state persistence reference adds only `fs2 = "=0.4.3"` to the
native runtime dependency surface. File synchronization, atomic replacement,
exclusive process locking, CAS, uncertain-commit fencing and actual subprocess
crash/reopen probes cover the declared local full-record storage contract.
Applications still own provider-side durable issued bindings/history and effects
outside the opaque state blob. This is not an encrypted enrollment store.

Automated review found publication-path authentication withdrawal and ignored
continuation expiry during snapshot staging/install. Both were fixed and
regression-tested. Earlier integration probes also caught retired-inbox fallback
and prompted post-writer-wait authority/generation revalidation. These automated
reviews do not satisfy independent human security review. Pinned fixtures remain
byte-identical; their known replay-completion wrapper discrepancy is documented,
not hidden behind a permissive decoder. Phase 4 RFC 0010 work has not begun.

## Accepted SDD alignment phase 2

The current uncommitted branch also implements the Core/RPC checkpoint described
in [docs/phase2-core-rpc.md](docs/phase2-core-rpc.md). This includes raw parser and
preallocation bounds, permanent ordered IDs, host high-water admission,
deadline-first terminal gates, receipt-time budgeting, validated configuration,
independent execution leases and bounded selected output. SC1 default factories
now share a process-wide 1024-execution cap; custom quotas must be reused across
connections. A retained withdrawal owner survives handler/caller cancellation.

Automated implementation review found and prompted fixes for an exhaustion
read-to-write lock upgrade, an unshared SC1 execution budget, cancellation of a
self-withdrawal close continuation, and receive-field allocation before bounds.
Regression tests cover these paths. This review is not independent human security
review, and the working-tree tests are not a formal conformance declaration.
At that checkpoint Phase 3 recovery had not begun; its subsequent results below
are separate from the Phase 2 run. Other later-phase gates remain open.

## Accepted SDD alignment phase 1

Branch `feat/accepted-sdd-v1-alignment`, starting Rust revision
`73f9775043ba2625a823f5cca3fbe92cdf345293`, targets accepted upstream
`8ede3810b29fbba4d0e6ae6751a0025ceedda140` (PR #20). The work is uncommitted.
The new scope is schema/suite snapshot provenance and implementation tracking,
not Core/RPC, recovery or host-lifecycle behavior. The active suite registers
`CONF-SCW-001…042` and `CONF-URP-001…017`; no formal verdict is claimed.
See [the SDD matrix](docs/sdd-alignment.md) and
[snapshot procedure](MIGRATION.md#accepted-sdd-snapshot-and-alignment-target).

Phase-one verification is recorded under [current recorded verification](#current-recorded-verification).
Older scope descriptions and test counts below retain their original meaning;
they are not evidence that the PR #20 contracts have been implemented.

## Historical pre-wave migration scope

The current prerelease migration consolidates `syntra-tcp` and `syntra-ws-sc1`
into the experimental, unpublished `syntra-sc1-transport`. The empty default
feature set exposes native WSS; `development-carriers` adds restricted TCP and
plaintext loopback WS. Its public root `pump` is carrier-neutral with no TCP
module dependency. Baseline `syntra-ws` retains its framing/endpoints; custom
runtime writers must honor the added emission-gate behavior contract.

The review target is the accepted upstream SC1 v1 contract: profile
`SNTR-SC1-WSS-V1` (24 cases `CONF-SCW-001…024`), merged as upstream commit
`0e8b0f8a4a789cb3d6d00b993e281867d2325e06` (PR #18, accepted 2026-10-29).
The earlier proposal pin `94404d7378136d8b6c88ece28bf945c88d1653ba` is retained
as proposal-review history, distinct from the unchanged extraction/schema pin
`2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`. Formal conformance remains
unexecuted and no conformance verdict is claimed. [SC1.md](SC1.md) specifies
`syntra.sc1.v1`, modes 1/2, TCP/WS/WSS codes 1/2/3, context-only prologue,
M1 86–340 bytes, M2 48 bytes,
and `/syntra/v1/sc1/ws` with exactly the `syntra.sc1.v1` subprotocol. Historical
local-revision-1 bytes and aliases are rejected rather than supported by fallback.
The prerelease source/API/wire break is intentional.

The runtime also adds the original-`Vec` `Initiator::prepare_outbound` emission
gate while preserving the byte-pump API. The opt-in `ReconnectingClient` owns
bounded retry and generation-fenced operations; [SC1.md](SC1.md#reconnecting-client)
documents its controls, owned status snapshots and retained shutdown ownership.
Partial establishment stays inline until ready, with complete ready-batch ingestion
and preserved partial-frame deadlines. Browser SC1 is not added; production FFI
retains a separate state machine and is not automatically an SC1 SDK.

The exact context/prologue fixtures are public encoding examples only, not
independent cryptographic vectors or executed pure-Go/Rust interoperability.
Integration peer/tests now use the consolidated modules and canonical endpoint.
Root `default-members` excludes integration; `--workspace` intentionally enables
development carriers through integration. CI tests WSS-only defaults separately.

Release requirements include formal conformance and independent pure-Go/Rust
interoperability in both roles and modes; recovery, including issuance/delivery/ack
and rotation workflows; mobile validation; and independent security review.
Upstream acceptance is complete.
No MTProto implementation code was copied. The root manifest and `LICENSE`
identify the repository implementation as Apache-2.0, not MIT.

### Acceptance alignment changes and test scope

The working tree on `feature/sc1-v1-acceptance-alignment`, based on `1d1916a`,
contains the following changes:

- `crates/syntra-runtime/src/connection.rs` changes the shared
  `ConnectionConfig::default().max_outstanding` from 64 to 32. All runtime users
  relying on this default are affected, including non-SC1 transports. Explicit
  overrides remain available; writer and notification defaults stay at 256 each.
  The new `default_max_outstanding_is_32_per_sntr_scw_012` test asserts the
  configuration value only, not admission behavior at a 33rd call. The
  `1..=1024` capacity validation remains in SC1 `Limits::validate`; it is not a
  universal runtime bound.
- `crates/syntra-secure-channel/src/lib.rs` rejects an all-zero returning-mode
  authorization key at the client with `Error::Invalid` before Noise construction
  or RNG use. The responder returns `Error::Authentication` after
  `KeyStore::lookup` returns a zero key and before Noise construction. The tests
  `returning_zero_ak_client_rejects_before_noise_rng` and
  `returning_zero_ak_store_rejects_before_noise` cover these paths.
  `Secret32::new` still accepts any 32-byte input. Secure provisioning, random
  key and independent handle generation, collision checks, current enrollment
  validation and application same-principal binding remain host obligations.
- `crates/syntra-sc1-transport/tests/wss.rs` adds
  `fragmented_m1_reassembles_before_noise_server_role_both_modes` and
  `fragmented_m2_reassembles_before_noise_client_role_both_modes`. Both exercise
  bootstrap and returning modes. The M1 test sends from a raw client to the real
  server and reaches an active session; the M2 test sends from a raw server to
  the real client and reaches ready plus an echo RPC. Each handshake message
  uses two fragments. These are not exhaustive fragmentation tests and do not
  probe interleaved Ping handling.
- Context/prologue fixture bytes are unchanged. Their updated provenance
  comments identify the accepted upstream registration; they remain public
  encoding examples rather than independent cryptographic or interoperability
  evidence. The pin checker has a fixed file scope, described in
  [MIGRATION.md](MIGRATION.md#acceptance-alignment-changes); it does not scan the
  repository, validate comment syntax or compare snapshot contents with upstream.

## Current recorded verification

### Accepted SDD phase-three run

Executed on darwin/arm64 with Rust 1.88.0 on the uncommitted
`feat/accepted-sdd-v1-alignment` tree based on
`73f9775043ba2625a823f5cca3fbe92cdf345293`, targeting
`syntra@8ede3810b29fbba4d0e6ae6751a0025ceedda140`. These are working-tree,
same-implementation checks, not revision-pinned release or formal `CONF-*` verdicts.

| Command | Result / scope |
| --- | --- |
| `cargo test --locked --workspace --quiet` | 606 passed, 0 failed, 2 ignored (Docker/browser). Includes 275 runtime unit tests, 28 recovery-driver tests, 12 source-inclusion persistence tests, 24 actual Core-bridge recovery tests and 3 actual direct-SC1/WSS recovery tests |
| `cargo test --locked -p syntra-sc1-transport --no-default-features --quiet` | 63 passed: 37 library + 3 recovery WSS + 23 WSS; isolated production/default feature boundary |
| `cargo test --locked -p syntra-sc1-transport --features development-carriers --quiet` | 71 passed: 37 library + 6 connectivity + 3 WS + 3 recovery WSS + 22 WSS |
| `cargo test --locked -p syntra-ffi --no-default-features --features production --quiet` | 13 passed; existing ABI v1 scope, not recovery/SC1 ABI v2 integration |
| `cargo test --locked -p syntra-ffi --no-default-features --features test-fixture --quiet` | 11 passed |
| `python3 crates/syntra-ffi/tests/build_contract.py` | 5 passed: C smoke/export isolation/header checks and expected FFI WASM rejection |
| `cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown` | Passed compilation; no browser execution, persistence or real suspend claim |
| `cargo clippy --locked --workspace --all-targets -- --no-deps` | Exit 0 with existing warnings; no warning-clean workspace result |
| `cargo deny --locked check advisories licenses sources` | Passed with cargo-deny 0.20.2 |
| `cargo audit --deny warnings` | Passed with cargo-audit 0.22.2; scanned the current 335-dependency lockfile using the fetched RustSec database |
| `python3 scripts/check-upstream-pin.py --upstream ../syntra` | Passed: all 69 managed schema/suite inputs match the locked committed source blobs |
| `python3 scripts/check-generated.py` | Passed: generated Rust matches the pinned Buf output |
| `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -q` | 54 passed; snapshot-checker scope |
| `buf format --diff --exit-code`; `buf lint`; `buf build`; `buf breaking --against '.git#ref=73f9775043ba2625a823f5cca3fbe92cdf345293'` | Passed; original FILE compatibility policy retained |
| `cargo fmt --all -- --check`; `git diff --check`; `actionlint -color` | Passed; local actionlint 1.7.12, not CI-pinned 1.7.7 |
| `cargo doc --locked -p syntra-runtime -p syntra-sc1-transport --no-deps` | Completed; existing compiler warnings remain, redundant driver doc-link warnings were corrected |

The local acceptance probes exercise negotiation isolation, initial live-only
baseline, durable resume and no-op C==B replay, exact reply/completion retries,
fixed-boundary replay/CatchUp, all nine methods, retention fallback, S0 differing
from B, unchanged-G installation, supersede fencing, provider loss, targeted
overflow, cross-scope rejection, lost acknowledgement with retained disk state,
and root withdrawal while another RPC is pending. Separate controlled-peer tests
cover expiry during a blocking successful install commit: no stale SnapshotConfirm,
while durable full-state evidence survives. Writer-barrier tests change policy/G
after pop but before writer capacity, proving stale protected output is discarded.

Native persistence tests include actual child-process termination at ten write
cuts across initial/replacement records and process-lock crash release. This is
evidence under the documented local-filesystem/flush/cooperating-writer assumptions,
not a proof for arbitrary business transactions, hostile storage or source backends.
No memory fixture is relabeled as durable storage. Existing warning classes such
as `baseline`, `issued_at_ms` and older style warnings remain.

Formal manifest execution, independent Rust/Go/crypto evidence, real devices,
operational budgets/soaks, independent human review and the future upstream freeze
remain open. Automatic recovered-service reconnect, mixed-notification routing,
browser/mobile storage and ABI v2 remain later integration phases. RFC 0010
enrollment/revocation/rotation/pin lifecycle remains Phase 4.

### Accepted SDD phase-two run

Executed on darwin/arm64 using Rust 1.88.0 on the uncommitted
`feat/accepted-sdd-v1-alignment` working tree, based on
`73f9775043ba2625a823f5cca3fbe92cdf345293`. Specification and schema/suite remain
pinned to `8ede3810b29fbba4d0e6ae6751a0025ceedda140`. The 69 managed inputs remain
byte-identical to that revision. No commits or release artifacts were created.

| Command | Result / scope |
| --- | --- |
| `cargo test --locked --workspace --quiet` | 450 passed, 0 failed, 2 ignored (Docker and browser). Includes 68 Core tests, 166 runtime unit tests and local integration regressions; not a manifest-driven run |
| `cargo test --locked -p syntra-sc1-transport --no-default-features --quiet` | 60 passed: 37 library + 23 WSS; isolated default feature boundary |
| `cargo test --locked -p syntra-sc1-transport --features development-carriers --quiet` | 68 passed: 37 library + 6 connectivity + 3 WS + 22 WSS |
| `cargo test --locked -p syntra-ffi --no-default-features --features production --quiet` | 13 passed; existing ABI v1 regression scope, not ABI v2 alignment |
| `cargo test --locked -p syntra-ffi --no-default-features --features test-fixture --quiet` | 11 passed; test-fixture-only ABI |
| `python3 crates/syntra-ffi/tests/build_contract.py` | 5 passed: export isolation, C smoke, header checks and expected FFI WASM rejection |
| `cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown` | Passed compilation; no real browser/mobile execution or suspend-time evidence |
| `cargo clippy --locked --workspace --all-targets -- --no-deps` | Exit 0 with warnings; no warning-clean result claimed |
| `python3 scripts/check-upstream-pin.py --upstream ../syntra` | Passed: all 69 inputs match the locked committed Git blobs |
| `python3 scripts/check-generated.py` | Passed: generated output matches the existing pinned Buf plugin |
| `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -q` | 54 passed; snapshot-checker regressions unchanged |
| `buf format --diff --exit-code`; `buf lint`; `buf build`; `buf breaking --against '.git#ref=73f9775043ba2625a823f5cca3fbe92cdf345293'` | Passed; existing FILE compatibility policy retained |
| `cargo fmt --all -- --check`; `git diff --check`; `actionlint -color` | Passed; local actionlint 1.7.12, not CI-pinned 1.7.7 |

Allocation-observer regressions reject 8,193-byte credentials, 129-byte
connection IDs and 4,097-byte diagnostics with zero allocations at or above the
oversized field lengths, including both duplicate orders. Exact-bound positive
controls demonstrate observation is active. Structural errors retain precedence;
in-bound singular duplicates retain last-value semantics. Explicit barriers and
paused clocks cover terminal ordering, receipt delay, actual 16-way admission and
reverse correlation; near-maximum IDs exercise prompt exhaustion/close.

Existing Clippy warnings remain, including `baseline`/`issued_at_ms` and older
style warnings. No dependency versions changed. Dependency security, Criterion,
Docker, real browser, physical devices, independent Go/crypto vectors and
independent human review were not executed for this checkpoint. Full conformance,
control/event queue integration, suspend-aware clocks, complete shutdown D5
reporting, recovery, RFC 0010 and FFI v2 remain later-phase/release gates.

### Accepted SDD phase-one run

Executed on darwin/arm64 with Rust 1.88.0, Python 3.14.7 and Buf 1.59.0,
against the uncommitted `feat/accepted-sdd-v1-alignment` working tree based on
`73f9775043ba2625a823f5cca3fbe92cdf345293`. These are working-tree checks, not a
revision-pinned release or full manifest-driven conformance run.

| Command | Result / scope |
| --- | --- |
| `python3 scripts/upstream_snapshot.py --sync --upstream ../syntra` | Generated 69 snapshot inputs plus the digest lock from committed upstream blobs at `8ede3810b29fbba4d0e6ae6751a0025ceedda140`; local source worktree content was not copied |
| `python3 scripts/check-upstream-pin.py` | Passed: all 69 inventory entries and digests match offline |
| `python3 scripts/check-upstream-pin.py --upstream ../syntra` | Passed: all inventory entries also match the exact committed upstream Git blobs |
| `python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v` | 54 passed, 0 failed, 0 skipped; synthetic offline/mocked-Git fixtures test read-only checks, drift, invalid locks/paths, symlinks, sync preflight and no-op reproduction. Two initially failing sync-safety probes were fixed; automated review prompted lock-symlink and jointly-edited-file/lock protections with additional regressions |
| `buf generate --template buf.gen.yaml` | Succeeded with the existing pinned `neoeinstein-prost:v0.4.0` revision 1; generated changes are comments, not Rust type/field changes |
| `python3 scripts/check-generated.py` | Passed: regenerated filenames and bytes match committed-path working-tree output |
| `buf format --diff --exit-code`; `buf lint`; `buf build` | All passed |
| `buf breaking --against '.git#ref=73f9775043ba2625a823f5cca3fbe92cdf345293'` | Passed the existing FILE configuration against the starting Rust schema; no Go option migration or field/tag/type changes |
| `cargo test --locked --workspace` | 377 passed, 0 failed, 2 ignored (Docker and browser). No production-FFI feature was enabled by this command |
| `cargo test --locked -p syntra-sc1-transport --no-default-features` | 52 passed, 0 failed: 29 library + 23 WSS; isolated WSS-only defaults |
| `cargo test --locked -p syntra-sc1-transport --features development-carriers` | 60 passed, 0 failed: 29 library + 6 connectivity + 3 WS + 22 WSS |
| `cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown` | Passed compilation only; no browser execution or browser SC1 claim |
| `cargo fmt --all -- --check`; `git diff --check` | Passed |
| `actionlint -color` | Passed with locally installed 1.7.12, not the CI-pinned 1.7.7 |

Rust runs emitted the existing unused `baseline` assignment and `issued_at_ms`
warnings. No warning-free result is claimed. Production/test-fixture FFI,
C build-contract, dependency security, Criterion, Docker, browser, real-device,
independent Go, and independent security-review runs were not executed in this
phase. No formal `CONF-*` case verdict follows from the workspace test names:
some tests explicitly preserve older ID/race/snapshot behavior pending Phase 2/3.
The full P0–P2 implementation and external evidence gates remain open in
[the SDD matrix](docs/sdd-alignment.md).

### Historical RFC 0007 acceptance alignment run

These results were recorded for the uncommitted working tree on
`feature/sc1-v1-acceptance-alignment`, based on `1d1916a`. They are local
working-tree evidence, not revision-pinned release evidence. The index is empty.

| Check | Recorded result |
| --- | --- |
| `cargo test --locked --workspace` | 377 passed, 0 failed, 2 ignored (Docker and browser) |
| `cargo test --locked -p syntra-sc1-transport --no-default-features` | 52 passed: library 29, WSS 23 |
| `cargo test --locked -p syntra-sc1-transport --features development-carriers` | 60 passed: library 29, TCP connectivity 6, WS 3, WSS 22 |
| `syntra-secure-channel` tests included in the workspace run | 10 unit and 12 integration tests passed; not an additional run |
| `cargo clippy --workspace --locked --all-targets` | Exit 0 with 43 unique warnings; no warning-free or `-D warnings` result |
| `cargo fmt --all -- --check` | Passed |
| `python3 scripts/check-upstream-pin.py` | Passed within the script's fixed file scope |
| Docker / browser execution | Not executed; both remain ignored in the workspace run |

The transport results are separate feature-configuration runs, not additive
counts for one run. Workspace feature unification includes development carriers
and does not replace isolated WSS-only testing. Formal `CONF-SCW-001…024`
conformance has not been executed.

Explicit production/test-fixture FFI suites and the C build contract, WASM
compilation, security checks, generation drift, workflow lint and Criterion smoke
targets were not rerun for alignment. Their earlier results retain the scope
recorded below. Passing local checks does not close the release requirements in
[implementation status](docs/implementation-status.md).

The documentation-only follow-up passed `python3 scripts/check-upstream-pin.py`
and `git diff --check`. Rust tests and other checks above were not rerun during
that follow-up.

### Earlier emission-gate verification

The following dated record predates the acceptance alignment run. Its counts
and broader checks describe that earlier working tree.

Executed locally on 2026-10-29 with **Rust 1.88.0, darwin/arm64**, on
`feat/canonical-sc1-wss-lifecycle` based on `ce4db11`. The changes remain
uncommitted; these are worktree results, not revision-pinned release evidence.
Post-documentation formatting, diff, workflow-lint and upstream-pin checks passed.

| Check | Recorded result |
| --- | --- |
| `cargo test --locked --workspace --quiet` | 372 passed, 0 failed, 2 ignored (Docker and browser) |
| `cargo test --locked -p syntra-sc1-transport --no-default-features` | 50 passed: library 29, WSS 21; development-only test binaries ran 0 tests |
| `cargo test --locked -p syntra-sc1-transport --features development-carriers` | 58 passed: library 29, TCP 6, WS 3, WSS 20 |
| Explicit production FFI / test-fixture FFI suites | 13 / 11 passed, in separate feature invocations |
| `python3 crates/syntra-ffi/tests/build_contract.py` | 5 checks passed |
| Locked `wasm32-unknown-unknown` check for `syntra-core`, `syntra-runtime`, `syntra-ws`, `syntra-web` | Passed compilation; no browser execution |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets -- --no-deps` | Passed with inherited warnings; no suppressions added |
| `python3 scripts/check-generated.py` / `python3 scripts/check-upstream-pin.py` | Both passed |
| Actionlint for CI, benchmarks and integration workflows | Passed |
| `cargo audit --deny warnings` | Passed |
| `cargo deny --locked check advisories licenses sources` | Passed |
| Criterion `frame_codec`, `channel`, `pipe` smoke targets | All three passed; `pipe` used `development-carriers`; no performance superiority claim |
| Docker availability / container execution | `docker info` failed: daemon missing; container suite **not executed** |
| Browser execution | Ignored; no runtime/browser evidence |

The WSS counts above are separate feature-configuration runs, not additive claims
about a single run. Workspace feature unification intentionally exercises development
carriers and does not replace the isolated default-feature result.

Two code-agent source reviews reported findings that have all been fixed. These
are local automated review evidence, **not independent human security review**.
Passing local checks does not close the release gates. The current Rust backlog
and missing independent/protocol/deployment evidence are listed in
[implementation status](docs/implementation-status.md).

## Historical evidence ledger (pre-consolidation)

Everything below records earlier extraction/local-revision-1 work and its stated
review scope. Old source paths, specification pins and test outcomes are retained
as historical evidence, not silently reinterpreted as results for the current
canonical-context/WSS migration. The original entries include separate container
observations from different points in development; none is current-branch proof.

This is an implementation review and evidence ledger for
`feat/sc1-connectivity-and-benchmarks`. It is **not an independent security
audit, certification or complete conformance report**. Findings below describe
source and regression coverage; passing local tests does not establish
absence of vulnerabilities.

## Historical final working-tree verification

The following passed on `feat/sc1-connectivity-and-benchmarks`, using Rust
1.88.0 on darwin/arm64 unless another lane is named:

- Locked workspace tests, including the new `syntra-secure-channel`,
  `syntra-tcp` and `syntra-integration` members: `cargo test --locked
  --workspace` passed with no failures and one ignored test (the Docker
  container suite, which runs in the integration job).
- Docker container integration across TCP and WS was not run for this
  tree: no macOS Docker Desktop platform, revision or outcome is claimed
  here. The Linux container lane in the integration job is the
  authoritative gate (the container suite stays ignored in workspace runs).
- Production and test-fixture FFI suites plus the C build contract, each in a
  separate invocation with no `--all-features`: production (13 tests),
  test-fixture (11 tests) and `build_contract.py` (5 checks, including both C
  smoke programs, feature isolation, no-default ABI checks and WASM
  rejection) all passed.
- `cargo fmt --all -- --check` passed for the feature tree.
- Locked WASM compile check for the non-FFI crates
  (`syntra-core`, `syntra-runtime`, `syntra-ws`, `syntra-web`) on
  `wasm32-unknown-unknown` passed; execution still requires the opt-in
  real-browser fixture.
- All in-memory Criterion benchmarks smoke-ran (`--test` selectors) for
  `frame_codec`, `channel` and `pipe`.
- `cargo deny --locked check` and `cargo audit --deny warnings` passed with
  the pinned tool versions.
- `git diff --check` passed.

Clippy reports the inherited baseline warnings documented in `docs/ci.md`;
the strict `-D warnings` lane stays informational until that cleanup lands.
No `allow` suppressions were added for new code.

The container suite (`syntra-integration/tests/sc1_containers.rs`) is
ignored by workspace runs and executes only in the integration job or on
explicit request. No macOS Docker Desktop run is reported for this tree, so
no macOS container platform, revision or outcome is presented as validation.
The Linux container lane remains the authoritative gate; see the remaining
findings below.

## Historical authority and source pins

- Upstream specification review reference:
  [`tinkle-org/syntra@e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02).
  RFC 0007 and the secure-channel/device-authorization companion documents
  are drafts. [SC1.md](SC1.md) records this implementation's exact local
  revision 1 domain, context encoding and carrier choices; upstream
  acceptance is pending.
- Schema/fixture provenance: [MIGRATION.md](MIGRATION.md), including the
  immutable source snapshot at `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`.
- SC1 cryptography: `snow =0.10.0` with its standard providers, `getrandom
  0.3`, `zeroize 1`. Native adapters use Tokio 1 with the existing
  Tungstenite 0.26/rustls 0.23 stack. No new network dependency enters the
  channel or protocol core. Current CI and recommended production toolchain:
  **Rust 1.88.0**. The 1.88 MSRV floor establishes build compatibility
  only, not production security. Production binaries require a
  security-patched toolchain and standard library.

The specification pin, schema snapshot and native implementation pins
serve different purposes. Wire agreement is not behavioral conformance, and
the container round trip does not provide independent cross-language SC1
interoperability.

## Historical completed implementation reviews

"Completed" identifies the stated local review/fix and its regression
evidence. It does not close the broader TODOs listed below.

| Area | Reviewed behavior | Evidence |
| --- | --- | --- |
| SC1 channel and context boundary | Exact local context bytes, NK/NKpsk0 suite selection, wrong keys/contexts, empty handshake payloads, replayed M1 without fresh confirmation, record ordering/failure/limits and redacted key formatting. | `syntra-secure-channel`, `channel allocation/entropy/handshake/record tests` |
| Ordered carrier boundary | Prefixes across records, coalesced frames, absolute frame clocks, admission limits, cancellation, lifetime and confirmed-peer rechecks. | `syntra-tcp/src/pump.rs`, pump tests including lifetime/confirmation/batch-backpressure deadlines and close-watch handling |
| TCP and WS/SC1 binding | TCP short writes, coalescing, partial record deadlines and real sockets; WS binary-message boundaries, fragmentation, origin/subprotocol rejection. | `syntra-tcp/tests/connectivity.rs`, `syntra-ws-sc1/tests/sc1.rs`, `syntra-ws/tests/websocket_vectors.rs` |
| Runtime correlation and lifecycle | Malformed correlated results settle only their RPC; handshake frames and version mismatches in ACTIVE close immediately; structural faults never become semantic RPC errors. | `crates/syntra-runtime/tests/runtime_defects.rs` |
| Graceful drain and withdrawal | Draining tolerates queued notifications; withdrawal is resumable across cancellation; graceful close waits for inflight RPCs and pending withdrawal terminals. | `runtime_defects.rs`: drain-tolerates-notifications, cancelled-withdrawal retry, graceful-waits-for-withdrawal regressions |
| Production FFI correctness | Normal host answers queue success and error results; bounded outbound admission before retiring pending work; stale dispatch entries cleared; output pointers validated before mutation; CSPRNG connection IDs. | `crates/syntra-ffi` production tests and `production_smoke.c` complete request/take/answer/outbound/client round trips |
| Codec emission and decode | Reserved top-level tags cannot be emitted; body/outcome multiplicity and malformed unknown wire data rejected; credential/frame sizes bounded; opaque payloads untouched. | `syntra-core`, `codec_vectors.rs`, `encode_allocation.rs` |
| Benchmark and container harness | In-memory Criterion benches for codec, channel and pipe paths; Testcontainers SC1 TCP/WS peer with echo, concurrency, denial and wrong-key coverage. | `BENCHMARKS.md`, `crates/syntra-integration/` |

Test names abbreviated after the first name retain that row's file prefix.
Coverage is local unit/integration evidence, not a result from an external
reviewer.

## Historical remaining gaps and audited TODOs

### Container fixture handle retention

During development the container suite completed the SC1 handshake inside
the container, then observed transport loss on the first RPC on both sides
with `UnexpectedEof` on the client read, while loopback TCP with identical
code paths passed. The cause was fixture-side, not framing or Docker
networking: the peer accepted each connection and then spawned a detached
waiter task that only touched `h.host`, so Rust's disjoint async-block
capture moved only the `Arc<Host>` field into the waiter future and dropped
the rest of the `HostHandle` — including its `Pump` — at the end of the
accept-loop iteration. Dropping the pump is an intentional abort; the owner
tore the connection down and both sides reported transport loss. Retaining
whole handles in the peer accept loop fixed it, and the suite passes on
macOS Docker Desktop. Detached waiters that only borrow a sub-path of a
connection handle must not be used; the `Listener`/`accept` examples in
[SC1.md](SC1.md#api-sketch) retain the handle. The Linux container lane in
`.github/workflows/integration.yml` remains the authoritative gate.

### Enrollment issuance, revocation and rotation

Only explicit authenticated out-of-band provisioning is supported. Generate
the 32-byte authorization key with `Enrollment::generate` and an independent
random eight-byte handle; check handle collisions in the scoped store.
`KeyStore::lookup` is host-owned and must honor cancellation. There is no
enrollment RPC, atomic issuance/delivery/ack recovery, client storage
implementation, or complete key-rotation workflow. Hosts must check current
enrollment and separately verified identity before `ready`, then check
current method policy on every call. Revocation propagation has no bound
beyond the lookup path; the one-second-style periodic recheck used by the
sibling Go implementation is not implemented here.

### Browser SC1 and UDP

Browser SC1 is not implemented; the WASM adapter documents its platform
limits. UDP has no binding: no datagram mapping, counters, replay window,
path validation, anti-amplification, reliability or fragmentation is
specified. Do not describe either as supported.

### Memory erasure and FFI ABI gaps

`Secret32`, record scratch and parser staging use zeroizing storage, and the
Snow resolver overwrites retained DH and cipher keys before destruction.
Snow 0.10.0 exposes no erasure interface for its internal chaining key,
handshake/KDF temporaries or PSK construction copies. Rust moves, allocator
copies, runtime-owned protobuf credentials, application stores and caller
copies are outside a complete erasure guarantee. The production FFI keeps
its own state machine; completion-generation tokens remain deferred, so
request IDs must stay distinct for the connection lifetime to prevent stale
completions targeting reused IDs.

### Fuzz and long-horizon campaigns

Fuzz and sanitizer campaigns are scheduled/manual only, never required PR
checks. No checked-in fuzz targets, property-testing harness, Loom or Miri
runs cover the new channel, pump or FFI paths. Coverage reporting stays
informational with no threshold.
