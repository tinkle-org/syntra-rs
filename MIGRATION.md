# Rust repository extraction

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

## Build and validation boundary

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

## Post-extraction local additions

On `feat/sc1-connectivity-and-benchmarks`, the workspace adds local-only
crates that did not exist in the extraction commit: `syntra-secure-channel`
(the SC1 Noise channel), `syntra-tcp` (the native TCP adapter and shared
frame pump), `syntra-ws::sc1` plus `syntra-ws/tests/sc1.rs` (the native
WebSocket SC1 binding), `syntra-integration` (the Docker-based connectivity
suite and echo peer) and Criterion benchmarks under
`crates/syntra-core/benches`, `crates/syntra-secure-channel/benches` and
`crates/syntra-tcp/benches`. Root documents `SC1.md`, `BENCHMARKS.md` and
`AUDIT.md` record this branch's implementation-specific SC1 local revision
1 contract, timing boundaries and evidence ledger. None of these additions
reinterprets the pinned upstream schema, and no upstream snapshot files were
modified for them.
