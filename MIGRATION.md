# Rust repository extraction

## Accepted SDD snapshot and alignment target

The active specification/schema/suite target is upstream PR #20 at
`8ede3810b29fbba4d0e6ae6751a0025ceedda140`. The Rust branch
`feat/accepted-sdd-v1-alignment` starts from
`73f9775043ba2625a823f5cca3fbe92cdf345293`. The target is the accepted SDD wave,
not an upstream specification-freeze or release decision. Phase 1 updates
inputs, generated comments and tracking only; it does not fix runtime contracts.
See [the implementation matrix](docs/sdd-alignment.md) for subsequent phases.

`proto/` and `conformance/` now contain all 69 regular input files from that
upstream commit, byte-for-byte. `upstream.lock.json` records the source identity
and each file's SHA-256. Copied prose and fixture notes retain historical/stale
wording and relative links. Resolve links to owner documents in the
[pinned upstream tree](https://github.com/tinkle-org/syntra/tree/8ede3810b29fbba4d0e6ae6751a0025ceedda140),
not in an assumed Rust-local specification tree. Snapshotting a manifest is not
executing it. Local implementation reports belong outside the managed snapshot
roots (for example in `docs/` or `evidence/`).

The active suite registers 42 SC1 cases and 17 recovery cases. Historical
24-case SC1 results below are not relabeled as evidence for the new cases.
The original extraction pin `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`, proposal
review pin `94404d7378136d8b6c88ece28bf945c88d1653ba`, and previous accepted SC1
pin `0e8b0f8a4a789cb3d6d00b993e281867d2325e06` remain provenance, not the active
schema or suite source.

To check without writing or needing a sibling checkout:

```sh
python3 scripts/check-upstream-pin.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

To verify source provenance or deliberately reproduce the snapshot, use a local
authoritative Git checkout containing the exact pinned commit:

```sh
python3 scripts/check-upstream-pin.py --upstream ../syntra
python3 scripts/upstream_snapshot.py --sync --upstream ../syntra
buf generate --template buf.gen.yaml
python3 scripts/check-generated.py
```

The checker never fetches or follows `main`; `--upstream` reads committed blobs,
not the source worktree. Offline checking compares the exact file inventory and
digests against the reviewed lock; only the Git comparison establishes that the
inventory matches the pinned source. Neither check establishes conformance or
acceptance. Sync refuses dirty snapshots, untracked conflicts and deletions
requiring review. Source revisions, digest inventory, copied inputs and generated
output must be reviewed together; changing an upstream pin is not a label-only
update. `buf.gen.yaml` retains the extracted plugin/version, not an obligation
to preserve obsolete generated comments. No schema field/tag/type allocation or
deferred Go import-path migration is authorized by this refresh.

## Core/RPC phase-two migration

[Phase 2](docs/phase2-core-rpc.md) documents the behavioral/source changes now in
this branch: permanent increasing request IDs, ordered host high-water admission,
deadline-first terminal selection, preallocation/raw-wire/diagnostic bounds,
validated configuration, receipt timestamps and separate execution/output
accounting. `RequestIdAllocator::next_candidate` is fallible and has no reset.
Use runtime `try_new*` constructors for fallible configuration and transfer an
`ExecutionLease` into any job that can outlive its handler future. Custom host
adapters must supply complete-frame receipt time and preserve receive order.
Custom initiator writers retain the original-`Vec`, single ordered handoff rule.

The production ABI v1 still has its own state machine: its shared Core field
bounds change, but the full RPC/order/lifecycle migration requires ABI v2 in the
later phase. This refresh does not claim v1 is now aligned. At the Phase 2
checkpoint, recovery snapshot reconciliation was still pending (now covered by
Phase 3 below); RFC 0010 lifecycle remains pending. Existing peers expecting ID
reuse or completion-over-expiry races are not compatible; these mandatory
baseline rules are not remotely toggleable profile options.

## Update/recovery phase-three migration

The [Phase 3 runtime](docs/phase3-update-recovery.md) replaces the former
new-generation-snapshot behavior with same-generation installation. Explicit
provider-loss/shared-rebase methods alone advance scoped generation. Replay
helpers require a previously subscribed boundary rather than inferring it from
the first page; `HostDriver::append_batch` is now fallible and bounded.

Host configuration before hello enables the nine profile RPCs; the SC1 factory
adapter supplies the same configuration on actual WSS accepts. The typed client
owns one immutable recovery inbox per connection and must negotiate afresh.
No profile state moves to another connection, and a retired attachment never
reverts to generic notification delivery. The earlier manual helpers remain
local coordinator APIs, not an alternative accepted wire binding.

The new `RecoveryPersistence` contract commits full opaque application state and
P/S/G/C together, not merely an effects digest. Native `FileRecoveryStore` adds
`fs2 = "=0.4.3"` for exclusive process locking; this is a local reference store
with documented filesystem/flush assumptions, not encrypted AK storage or a
durable provider-history implementation. Unknown commit outcomes fence further
work pending reconciliation. Old checkpoint-only/digest persistence cannot be
silently promoted to durable-effect evidence.

Pinned recovery manifests 011/012 appear to encode a bare inner replay completion
instead of the required `RecoveryNotification` wrapper. Their bytes are preserved;
the runtime does not add a permissive fallback. Formal role/profile execution,
independent peers and the upstream freeze remain later gates.

## Historical pre-wave SC1 migration scope

The following scope and run descriptions predate the PR #20 alignment. They
explain the implementation at the starting Rust revision, not completion of the
new accepted contracts. The phase-one snapshot/checker section above supersedes
their descriptions of the active schema/suite pin and old pin-checker scope.

The experimental, unpublished `syntra-sc1-transport` consolidates the prerelease
`syntra-tcp` and `syntra-ws-sc1` crates. `websocket` provides native WSS;
`pump` is public and carrier-neutral, with no dependency on the gated `tcp`
module. The default feature set is empty (`default = []`) and exposes WSS as
the default carrier. `development-carriers` adds restricted-development TCP
and plaintext loopback WS. Baseline `syntra-ws` retains its framing/endpoints;
runtime writers gain the emission-gate behavior contract described below.

This migration intentionally permits prerelease source/API/wire breaks. The
canonical context targets the accepted RFC 0007 SC1 v1 contract pinned at
`0e8b0f8a4a789cb3d6d00b993e281867d2325e06` (upstream PR #18, profile
`SNTR-SC1-WSS-V1`, 24 cases `CONF-SCW-001…024` in
`conformance/manifest/sc1-wss.yaml`). The earlier proposal review pin
`94404d7378136d8b6c88ece28bf945c88d1653ba` is retained as history only.
The extraction/schema pin below remains unchanged. Formal conformance has not
been executed; the registered cases do not establish implementation conformance.
The `syntra.sc1.v1` context is the entire Noise prologue, with modes 1/2,
carriers TCP 1 / WS 2 / WSS 3 and M1 length
86–340 bytes. The endpoint is `/syntra/v1/sc1/ws` and the subprotocol is
`syntra.sc1.v1`; old local-revision formats, endpoints and tokens have no aliases
or fallback. [SC1.md](SC1.md) gives the exact field order and API signatures.

Current source locations replace the historical paths recorded below:

| Historical local path | Consolidated path |
| --- | --- |
| `crates/syntra-tcp/src/lib.rs` | `crates/syntra-sc1-transport/src/tcp.rs` (development feature) |
| `crates/syntra-tcp/src/pump.rs` and `src/pump/tests.rs` | `crates/syntra-sc1-transport/src/pump.rs` and `src/pump/tests.rs` |
| `crates/syntra-ws-sc1/src/lib.rs` | `crates/syntra-sc1-transport/src/websocket.rs` |
| `crates/syntra-tcp/tests/connectivity.rs` | `crates/syntra-sc1-transport/tests/connectivity.rs` |
| `crates/syntra-ws-sc1/tests/sc1.rs` | `crates/syntra-sc1-transport/tests/websocket.rs`; WSS cases in `tests/wss.rs` |
| `crates/syntra-tcp/benches/pipe.rs` | `crates/syntra-sc1-transport/benches/pipe.rs` (development feature) |

The runtime byte-pump API still uses `Vec<u8>` items, with an explicit
`Initiator::prepare_outbound` original-allocation emission gate; custom writers
must adopt its contract. The opt-in `client::ReconnectingClient` adds bounded
reconnection, owned status snapshots and generation-fenced calls; see
[SC1.md](SC1.md#reconnecting-client) for its lifecycle and shutdown contract.
It does not replay mutations or establish recovery readiness. Browser SC1 is not
added, and the production FFI remains a separate state machine rather than
automatically becoming an SC1 SDK.

### Acceptance alignment changes

The uncommitted changes on `feature/sc1-v1-acceptance-alignment`, based on
`1d1916a`, change `ConnectionConfig::default().max_outstanding` from 64 to 32.
This shared default affects all runtime users that rely on it, including
non-SC1 transports. Explicit overrides remain available; writer and notification
capacities still default to 256 each. SC1 `Limits::validate` retains its
`1..=1024` validation for these three capacities; the runtime does not enforce
that range universally. The new runtime test asserts the default value only;
it does not add a 33rd-call admission boundary test.

Returning-mode clients reject an all-zero authorization key with `Error::Invalid`
before Noise construction or RNG use. The responder rejects an all-zero key
returned by `KeyStore::lookup` with `Error::Authentication`, after lookup and
before Noise construction. `Secret32::new` remains unchanged and still accepts
any 32-byte input. Secure provisioning, random key and independent handle
generation, collision checks, current enrollment validation and application
same-principal binding remain host obligations.

Two new WSS tests exercise fragmented handshakes in both bootstrap and returning
modes: M1 from a raw client to the real server through an active session, and M2
from a raw server to the real client through ready and an echo RPC. Each
handshake message is split into two fragments. These tests do not exhaust
fragmentation patterns or probe interleaved Ping handling.

Public context/prologue fixtures were transcribed from
`conformance/plans/sc1-context-v1.json` at the proposal review pin into
`crates/syntra-secure-channel/tests/fixtures/sc1_context_v1.rs`. Their bytes
are unchanged and match upstream `conformance/test-vectors/sc1/context-vectors.yaml`
at the accepted contract pin; upstream retains the plans JSON. They are public
encoding examples only, not independent Noise cryptographic vectors or executed
interoperability evidence. No MTProto implementation code was copied. Repository
implementation licensing remains Apache-2.0; references to external design
documents do not relicense it as MIT.

The peer and container tests now use the consolidated modules and canonical
endpoint. Root `default-members` excludes integration; `--workspace` intentionally
unifies its development-carrier dependency. Isolated WSS-only default tests run
separately in CI. Latest executed local results are recorded in
[AUDIT.md](AUDIT.md#current-recorded-verification); Docker and browser execution
remain outstanding. The latest alignment run is separate from the earlier broader
FFI/WASM, security, generation and benchmark checks. The records below describe
extraction and pre-consolidation work only. Formal conformance, independent
pure-Go/Rust interoperability in both roles and modes, recovery and mobile
validation, and independent human review remain release requirements. Upstream
acceptance is complete. The remaining Rust implementation
backlog is tracked in [implementation status](docs/implementation-status.md).

The current `scripts/check-upstream-pin.py` reads only `README.md`, `MIGRATION.md`,
`SC1.md`, `buf.gen.yaml`, `buf.yaml`, `proto/syntra/v1/envelope.proto` and the SC1
fixture file. It checks required pin references, extraction-file pin exclusivity,
known upstream pin URLs, selected snapshot links and local snapshot directory
presence within that scope. It does not scan the repository, enforce comment
syntax or compare snapshot contents with upstream.

## Provenance

Source repository: <https://github.com/tinkle-org/syntra>.
Exact source commit:
[`2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`](https://github.com/tinkle-org/syntra/commit/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c).
Destination: <https://github.com/tinkle-org/syntra-rs>, branch
`feat/extract-rust-implementation`.

The source paths below were restored from that commit, retaining their
repository-relative layout:

| Source path in `syntra` | Destination path in `syntra-rs` |
| --- | --- |
| `Cargo.toml` | `Cargo.toml` (repository/homepage URLs updated) |
| `Cargo.lock` | `Cargo.lock` (unchanged) |
| `crates/` | `crates/` (only split-broken root-document references in rustdoc updated) |
| `tests/integration/` | `tests/integration/` |
| `tests/interoperability/` | `tests/interoperability/` |
| `conformance/test-vectors/` | `conformance/test-vectors/` |
| `proto/` | `proto/` |
| `buf.yaml` | `buf.yaml` |
| `LICENSE` | `LICENSE` |

The destination bootstrap README was replaced with standalone Rust
instructions. Contributor/security guidance, ignore rules, a pinned
development toolchain, Rust-only generation tooling and validation CI were
added locally. `buf.gen.yaml` retains only the source template's Rust
plugin: `buf.build/community/neoeinstein-prost:v0.4.0`, revision 1.
The Buf CLI remains pinned to 1.59.0 and the prost runtime to `=0.13.5`.

## Ownership and authority

The [upstream specifications](https://github.com/tinkle-org/syntra/tree/main/specifications),
RFC process and conformance definitions remain authoritative. This repo
owns the extracted Rust implementation and native C headers. The
[Go implementation](https://github.com/tinkle-org/syntra-go) is a sibling
repository; its native adapter consumes the `production` FFI library.

Local `proto/` and `conformance/test-vectors/` are exact snapshots from the
source commit, retained so Cargo tests and Rust regeneration work without
a monorepo checkout. They do not establish a second protocol authority.
Synchronize them through reviewed upstream commits, recording provenance
and regenerating Rust with the pinned template when needed.

Copied snapshot comments and vector documentation may refer to upstream
paths such as `specifications/`, `docs/`, `conformance/manifest/` or
`compatibility/`. Resolve those paths in the
[source tree at the extraction commit](https://github.com/tinkle-org/syntra/tree/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c).
Those files and the full monorepo validators are not standalone Rust inputs.

## Historical extraction build and validation boundary

[README.md](README.md) gives standalone default, production FFI,
test-fixture FFI and WASM commands, plus Linux/macOS Go sibling linking.
[CONTRIBUTING.md](CONTRIBUTING.md) lists the check commands. Rust 1.88.0
retains the source CI toolchain and the package MSRV declaration stays
1.88. Locked workspace tests and the non-FFI WASM check passed on 1.88.0
with the preserved lockfile.

The restored source has existing `cargo fmt --all -- --check` differences.
They are retained to preserve source bytes during extraction; formatting
cleanup is a separate change. CI runs locked workspace and explicit FFI
tests, the non-FFI WASM compile check, the FFI build contract (including
expected WASM rejection), and temporary Rust generation drift checking.
Browser execution and cross-repository Go/native testing are separate.

Crate names, versions, dependencies, lockfile, generated Rust, source logic
and test fixtures retain the source baseline. This migration adds no Noise
or SC1 implementation and makes no protocol behavior changes.

## Historical post-extraction local additions

On `feat/sc1-connectivity-and-benchmarks`, the workspace adds local-only
crates that did not exist in the extraction commit: `syntra-secure-channel`
(the SC1 Noise channel), `syntra-tcp` (the native TCP adapter and shared
frame pump), `syntra-ws-sc1` plus `syntra-ws-sc1/tests/sc1.rs` (the native
WebSocket SC1 binding), `syntra-integration` (the Docker-based connectivity
suite and echo peer) and Criterion benchmarks under
`crates/syntra-core/benches`, `crates/syntra-secure-channel/benches` and
`crates/syntra-tcp/benches`. Root documents `SC1.md`, `BENCHMARKS.md` and
`AUDIT.md` record this branch's implementation-specific SC1 local revision
1 contract, timing boundaries and evidence ledger. None of these additions
reinterprets the pinned upstream schema, and no upstream snapshot files were
modified for them.

The local-revision-1 format and crate paths in this historical record have been
superseded by the current scope above; recorded tests and benchmarks must not
be silently relabeled as canonical-context/WSS validation.
