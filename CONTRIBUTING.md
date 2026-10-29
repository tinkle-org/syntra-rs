# Contributing to Syntra Rust

Run commands from the repository root. **Rust 1.88.0 is the toolchain**;
the crate MSRV floor of **1.88** is an API/build compatibility constraint,
not a secure-runtime recommendation. Production binaries must be built with
a security-patched toolchain. Current pins are `prost =0.13.5`,
`snow =0.10.0`, `getrandom 0.3`, `tokio 1`, `tungstenite`/`tokio-tungstenite`
0.26 and `rustls 0.23`. Keep dependency versions and checksums consistent
unless updating them is part of the change.

Read [SC1.md](SC1.md) for the implementation-specific local-revision-1
contract and [AUDIT.md](AUDIT.md) for completed local reviews and open gaps.
Keep claims tied to evidence: this channel is neither accepted upstream nor
independently audited. Reference upstream specification commit
[`e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02)
when discussing draft requirements and identify a new reviewed pin when that
reference changes.

## Checks

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo fmt --all -- --check           # informational while the formatting
                                     # baseline is uncleared; the CI fmt job
                                     # does not gate
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- --no-deps
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
python3 crates/syntra-ffi/tests/build_contract.py
cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown
git diff --check
```

Install the `wasm32-unknown-unknown` target for this toolchain first. The
FFI contract also requires Python 3, `nm` and a C compiler. Run the relevant
focused tests while iterating. The container suite is ignored by workspace
runs; follow its own tooling instructions and record the actual peer
revision. A same-implementation container round trip does not establish
independent cross-language SC1 interoperability.

Security checks:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-audit --version 0.22.2
cargo deny --locked check advisories licenses sources
cargo audit --deny warnings
```

`cargo deny` gates licenses, advisories and sources; `cargo audit` gates
RustSec advisories. Recheck when dependencies or reachable code paths
change; dependency presence and code reachability are different scan
findings. See `.github/SECURITY.md` for private vulnerability reports.

Fuzz and negative tests:

Fuzz and sanitizer campaigns are scheduled/manual only, never required PR
checks. Run the negative and regression suites explicitly when touching
their parsers: `codec_vectors`, `encode_allocation`, `runtime_defects`,
pump split-point and fault-injection tests. Conformance vectors in
`conformance/test-vectors/` must keep passing. Local fixture tests, carrier
integration tests and true independent Rust wire interop are separate
evidence; name the level actually exercised.

Workflows (all actions SHA-pinned, `contents: read`, timeouts, concurrency
cancel for PRs):

- `CI` – fast required PR/main checks (`fmt`, `clippy`, `rust`,
  `generated-rust`, `package`, `security`, `actionlint`,
  `dependency-review`, aggregator `required`). Require `required` in the
  main-branch ruleset; do not require individual jobs.
- `Scheduled` – extended validation on Linux/macOS/Windows, coverage and
  vulnerability scans (does not gate).
- `Integration` – separate Docker-based connectivity checks; see
  [crates/syntra-integration/README.md](crates/syntra-integration/README.md).
- `Benchmarks` – report-only Criterion samples across workspace benches,
  including codec, channel and pipe cases; see [BENCHMARKS.md](BENCHMARKS.md).
- `Release Please` – push-to-main-only automation using conventional
  commits. Merging a release PR pushes the root `vX.Y.Z` tag; no binaries
  are published and PRs cannot trigger it.

Dependabot updates `cargo` and `github-actions` weekly; update SHAs via
Dependabot PRs after review, never floating tags.

Use neutral opaque payloads and local test fixtures. For behavior changes,
include a focused regression that asserts observable behavior. Report existing
test failures separately rather than changing semantics to make unrelated
checks pass. Describe which checks you exercised in your pull request.

For channel changes, preserve fresh RNG use, exact context bytes, carrier
binding, record ordering, bounds, cancellation and abortive close ownership.
Exercise fragmented prefixes/messages, partial I/O, invalid tags, stalled
writes and revocation as appropriate. Keep host callbacks nonblocking and
verify policy before handler effects. Exercise `Listener` admission through
the ready write and owned shutdown when changing orchestration. Writer tests
must preserve FIFO snapshot ownership, admission accounting, loop progress
during stalls, bounded terminal drains and cancellation/join behavior. SC1
issuance/delivery/ack recovery, rotation, subscription routing and
execution-terminal proofs remain open integration work; do not describe them
as implemented merely because a primitive/helper regression passes. Snow and
runtime secret-erasure limits must remain explicit until evidence changes.

## Schema and generated code

Read [MIGRATION.md](MIGRATION.md) for source provenance and import mappings.
Schema and fixture updates should record their upstream source revision.
Normative protocol changes belong in the upstream RFC/specification process
first.

Use Buf CLI 1.59.0 with the remote Rust plugin `neoeinstein-prost:v0.4.0`
revision 1 configured in `buf.gen.yaml`. Generated files are committed and
must not be hand-edited.

```sh
buf format --diff --exit-code
buf lint
buf build
python3 scripts/check-generated.py
python3 scripts/check-upstream-pin.py
```

The drift script uses Python's standard library and only writes to a
temporary directory. To intentionally regenerate committed Rust output, run
`buf generate --template buf.gen.yaml`, then inspect the resulting diff.
Wire compatibility and cross-language conformance remain upstream concerns;
the local fixture tests and byte-drift checks cover only their stated scope.

## Reports and releases

Open ordinary Rust implementation issues and pull requests in
[`tinkle-org/syntra-rs`](https://github.com/tinkle-org/syntra-rs). There are
no releases yet. Future releases use repository-root `vX.Y.Z` tags.
