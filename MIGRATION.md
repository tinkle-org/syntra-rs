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
