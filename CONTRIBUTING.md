# Contributing to Syntra Rust

Run commands from the repository root. **Rust 1.88.0 is the toolchain**;
the crate MSRV floor of **1.88** is an API/build compatibility constraint,
not a secure-runtime recommendation. Production binaries must be built with
a security-patched toolchain. Current pins are `prost =0.13.5`,
`snow =0.10.0`, `getrandom 0.3`, `tokio 1`, `tungstenite`/`tokio-tungstenite`
0.26 and `rustls 0.23`. Keep dependency versions and checksums consistent
unless updating them is part of the change.

Read [SC1.md](SC1.md) for the RFC 0007 section 11 canonical-context proposal
contract and [AUDIT.md](AUDIT.md) for historical local reviews and current gaps.
The proposal review pin is `94404d7378136d8b6c88ece28bf945c88d1653ba`;
identify a new reviewed pin when that reference changes. Keep it distinct from
the extraction/schema pin in [MIGRATION.md](MIGRATION.md), which is checked by
`scripts/check-upstream-pin.py`. This channel is neither activated upstream nor
independently audited. Latest local results are recorded in
[AUDIT.md](AUDIT.md#current-recorded-verification); historical runs remain
separate. Post-documentation checks passed.

`syntra-sc1-transport` is experimental and unpublished, replacing the prerelease
`syntra-tcp` and `syntra-ws-sc1` crates with an intentional source/API/wire break.
Its empty default feature set exposes native WSS; `development-carriers` adds
restricted TCP and plaintext loopback WS. The public `pump` stays carrier-neutral
and independent of the gated TCP module. Keep baseline `syntra-ws` framing and
endpoints unchanged while honoring the runtime writer emission-gate contract.
Browser SC1 is not implemented, and production FFI has its own state machine
rather than automatically becoming an SC1 SDK. The opt-in reconnecting client's
owned-status, generation, retry and close contracts are in
[SC1.md](SC1.md#reconnecting-client).

## Checks

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo fmt --all -- --check
cargo test --locked --workspace
cargo test --locked -p syntra-sc1-transport --no-default-features
cargo test --locked -p syntra-sc1-transport --features development-carriers
cargo bench --locked -p syntra-sc1-transport --features development-carriers --bench pipe -- --test
cargo clippy --locked --workspace --all-targets -- --no-deps
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
python3 crates/syntra-ffi/tests/build_contract.py
cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown
git diff --check
```

Root builds/tests without `--workspace` use `default-members`, excluding the
container integration crate. `--workspace` intentionally includes integration
and unifies `development-carriers` into `syntra-sc1-transport`. Keep the isolated
`--no-default-features` and explicit development-feature invocations separate;
CI has separate steps for them. Workspace success alone is not WSS-default
isolation evidence.

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

The exact context/prologue fixture tests cover **public encoding only**, not
independent Noise cryptographic vectors. Release gates remain upstream activation,
independent pure-Go/Rust interoperability in both roles and modes, recovery and
mobile validation, and independent security review. Do not infer completion from
same-library round trips or public fixture matches.

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

Custom initiator writers must preserve the byte-pump's original `Vec<u8>`
allocation and pass it once to `Initiator::prepare_outbound` immediately before
synchronous carrier handoff/encryption. Skip `None`; after `Some`, finish that
unit in order or abort. Never re-gate fragments or ciphertext. Check the source
doc comment and [SC1.md](SC1.md#runtime-emission-gate) when changing a writer;
the gate preserves the byte-pump API while adding an emission contract.

For reconnect changes, preserve single-dial ownership, cancellation-safe inline
establishment, complete ready-batch ingestion and existing partial-frame deadlines.
Status snapshots must stay owned, not borrowed watch guards; generation-fenced
calls must never migrate/replay into a successor. Exercise explicit controls,
elapsed outage budgets through pauses, terminal blocking and retained cleanup
ownership on close timeout. Passing source reviews by code agents does not replace
independent human review. Track protocol/host-policy, durable recovery and FFI/mobile
work in [implementation status](docs/implementation-status.md).

Repository implementation licensing is Apache-2.0 (`LICENSE` and the root
manifest). No MTProto implementation code was copied; do not conflate external
design-document references or their licensing with source-code provenance.

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
