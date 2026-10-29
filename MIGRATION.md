# Rust repository extraction

## Current SC1 migration scope

The experimental, unpublished `syntra-sc1-transport` consolidates the prerelease
`syntra-tcp` and `syntra-ws-sc1` crates. `websocket` provides native WSS;
`pump` is public and carrier-neutral, with no dependency on the gated `tcp`
module. The default feature set is empty (`default = []`) and exposes WSS as
the default carrier. `development-carriers` adds restricted-development TCP
and plaintext loopback WS. Baseline `syntra-ws` retains its framing/endpoints;
runtime writers gain the emission-gate behavior contract described below.

This migration intentionally permits prerelease source/API/wire breaks. The
canonical context follows the RFC 0007 section 11 proposal reviewed at
`94404d7378136d8b6c88ece28bf945c88d1653ba`. That is a proposal review pin,
not the extraction/schema pin below. The `syntra.sc1.v1` context is the entire
Noise prologue, with modes 1/2, carriers TCP 1 / WS 2 / WSS 3 and M1 length
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

Public context/prologue fixture bytes come from `conformance/plans/sc1-context-v1.json`
at the proposal review pin and are transcribed in
`crates/syntra-secure-channel/tests/fixtures/sc1_context_v1.rs`. They are public
encoding examples only, not independent Noise cryptographic vectors or executed
interoperability evidence. No MTProto implementation code was copied. Repository
implementation licensing remains Apache-2.0; references to external design
documents do not relicense it as MIT.

The peer and container tests now use the consolidated modules and canonical
endpoint. Root `default-members` excludes integration; `--workspace` intentionally
unifies its development-carrier dependency. Isolated WSS-only default tests run
separately in CI. Latest executed local results are recorded in
[AUDIT.md](AUDIT.md#current-recorded-verification); Docker and browser execution
remain outstanding. Post-documentation checks passed. The records below
describe extraction and pre-consolidation work only. Release gates remain upstream
activation, pure-Go/Rust interoperability in both roles and modes, recovery and mobile
validation, and independent human review. The remaining Rust implementation
backlog is tracked in [implementation status](docs/implementation-status.md).

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
