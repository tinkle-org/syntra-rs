# Implementation audit notes

## Current migration scope

The current prerelease migration consolidates `syntra-tcp` and `syntra-ws-sc1`
into the experimental, unpublished `syntra-sc1-transport`. The empty default
feature set exposes native WSS; `development-carriers` adds restricted TCP and
plaintext loopback WS. Its public root `pump` is carrier-neutral with no TCP
module dependency. Baseline `syntra-ws` retains its framing/endpoints; custom
runtime writers must honor the added emission-gate behavior contract.

The review target is the RFC 0007 section 11 canonical-context **proposal** at
`94404d7378136d8b6c88ece28bf945c88d1653ba`, distinct from the historical
extraction/schema pin. [SC1.md](SC1.md) specifies `syntra.sc1.v1`, modes 1/2,
TCP/WS/WSS codes 1/2/3, context-only prologue, M1 86–340 bytes, M2 48 bytes,
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

Release gates remain upstream activation; independent pure-Go/Rust
interoperability in both roles and modes; recovery, including issuance/delivery/ack
and rotation workflows; mobile validation; and independent security review.
No MTProto implementation code was copied. The root manifest and `LICENSE`
identify the repository implementation as Apache-2.0, not MIT.

## Current recorded verification

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
