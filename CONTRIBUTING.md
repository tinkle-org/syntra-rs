# Contributing to Syntra Rust

Run commands from the repository root. **Rust 1.88.0 is the toolchain**;
the crate MSRV floor of **1.88** is an API/build compatibility constraint,
not a secure-runtime recommendation. Production binaries must be built with
a security-patched toolchain. Current pins are `prost =0.14.4`,
`snow =0.10.0`, `getrandom 0.3`, `tokio 1`, `tungstenite`/`tokio-tungstenite`
0.30 and `rustls 0.23`. Keep dependency versions and checksums consistent
unless updating them is part of the change.

Read [CONNECTION.md](CONNECTION.md) for Syntra 1.0 encryption and connection
guidance. Keep pinned upstream inputs distinct from the candidate implementation
and its verification; see [input provenance](#input-provenance-and-authority).
The implementation remains experimental and unpublished; formal conformance has
not been executed and independent security review remains outstanding.

`syntra-transport` has an empty default feature set: the native carrier-neutral
record driver is available without socket dependencies. Select `tcp` or `websocket`
explicitly for native carriers; `websocket` includes WSS and loopback-only WS
dials, both carrying protected records. Reconnection requires the separate
`reconnect` feature. `native-enrollment` is also explicitly opt-in.

Keep the ownership boundaries: `syntra-core` owns framing and record protection
through `syntra_core::secure_channel`, `syntra-runtime` owns sessions, `syntra-transport`
owns native I/O, and `syntra-web` owns the browser-local driver. The browser's
default `browser-connection` feature exposes protected WSS with provisioned
Noise pins and encrypted ClientHello; it has no plaintext connect API. See
[browser procedures](crates/syntra-web/tests/browser.md) for separate build,
synthetic-carrier and real WSS checks. FFI features require their own checks.

## Checks

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo fmt --all -- --check
cargo test --locked
cargo test --locked --workspace
cargo test --locked -p syntra-runtime --no-default-features --features file-store
cargo test --locked -p syntra-transport --no-default-features
cargo test --locked -p syntra-transport --no-default-features --features tcp
cargo test --locked -p syntra-transport --no-default-features --features websocket
cargo test --locked -p syntra-transport --no-default-features --features tcp,websocket,reconnect
cargo bench --locked -p syntra-transport --no-default-features --features tcp --bench pipe -- --test
python3 scripts/cargo_contracts.py isolation
cargo clippy --locked --workspace --all-targets -- --no-deps
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
python3 crates/syntra-ffi/tests/build_contract.py
cargo check --locked -p syntra-core -p syntra-runtime --target wasm32-unknown-unknown
cargo check --locked -p syntra-web --no-default-features --features browser-connection --target wasm32-unknown-unknown
cargo check --locked -p syntra-web --no-default-features --features browser-test-fixture --target wasm32-unknown-unknown
git diff --check
```

Root builds/tests without package selectors or `--workspace` use
the four `default-members` (`syntra-core`, `syntra-runtime`, `syntra-transport`,
`syntra-ffi`), excluding only `syntra-web` and `syntra-integration` from
the six-member workspace. `--workspace` includes those members and unifies the
integration crate's `tcp` and `websocket` features into `syntra-transport`.
Keep the isolated default and explicit carrier/reconnect invocations separate;
workspace success alone does not establish socket-free default isolation.
The isolation script checks normal dependency graphs on host and WASM targets.
Native transport driver APIs require Tokio; WASM applications use `syntra-web`.
The transport's native features must be disabled on WASM.

Install the `wasm32-unknown-unknown` target for this toolchain first. The
FFI contract also requires Python 3, `nm` and a C compiler. Run the relevant
focused tests while iterating. The container suite is ignored by workspace
runs; follow its own tooling instructions and record the actual peer
revision. A same-implementation container round trip does not establish
independent cross-language Syntra interoperability.

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
findings. See [the security policy](.github/SECURITY.md) for private vulnerability reports.

Fuzz and negative tests:

The checked-in workflows do not provide fuzz or sanitizer campaigns. Run the
negative and regression suites explicitly when touching
their parsers: `codec_vectors`, `encode_allocation`, `runtime_defects`,
pump split-point and fault-injection tests. Pinned upstream conformance vectors
and the selected local assets in `tests/interoperability/fixtures/` must retain
their provenance. Local fixture tests, carrier
integration tests and true independent Rust wire interop are separate
evidence; name the level actually exercised.

The exact context/prologue fixture tests cover **public encoding only**, not
independent Noise cryptographic vectors. Preserve the scope and contract revision
of each result. Same-library round trips, candidate agreement checks and pinned
input checks do not establish formal conformance, independent cross-language
interoperability, device validation or independent security review.

Workflows (all actions SHA-pinned, `contents: read`, timeouts, concurrency
cancel for PRs):

- `CI` – PR/main validation (`clippy`, `rust`, `generated-rust`,
  `manifest-cases`, `package`, `security`, `actionlint`, `dependency-review`,
  aggregator `required`). `fmt` is informational. Require `required` in the
  main-branch ruleset. The retained `manifest-cases` job ID produces unified
  implementation evidence and ten supplemental WSS scenarios; it does not execute
  an upstream transport-profile suite.
- `Scheduled` – extended validation on Linux/macOS/Windows, coverage and
  vulnerability scans (does not gate).
- `Integration` – separate Docker-based connectivity checks; see
  [crates/syntra-integration/README.md](crates/syntra-integration/README.md).
- `Benchmarks` – report-only Criterion samples across workspace benches,
  including codec, channel and pipe cases; see [BENCHMARKS.md](BENCHMARKS.md).
- `Release-plz` – validated release PRs, per-package `syntra-<crate>-vX.Y.Z`
  tags and gated Cargo publishing for eligible packages. Packages marked
  `publish = false` are excluded. Protocol releases remain separate; see
  [release-plz.toml](release-plz.toml) and the workflow's credential gates.

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
during stalls, bounded terminal drains and cancellation/join behavior. Validate
enrollment, recovery, rotation and lifecycle changes at their actual integration
boundaries; a primitive/helper regression alone does not prove the complete
flow. Snow and runtime secret-erasure limits must remain explicit until
evidence changes.

Custom initiator writers must preserve the byte-pump's original `Vec<u8>`
allocation and pass it once to `Initiator::prepare_outbound` immediately before
synchronous carrier handoff/encryption. Skip `None`; after `Some`, finish that
unit in order or abort. Never re-gate fragments or ciphertext. Check the source
doc comment and [CONNECTION.md](CONNECTION.md) when changing a writer;
the gate is part of the byte-pump emission contract.

For reconnect changes, preserve single-dial ownership, cancellation-safe inline
establishment, complete ready-batch ingestion and existing partial-frame deadlines.
Status snapshots must stay owned, not borrowed watch guards; generation-fenced
calls must never migrate/replay into a successor. Exercise explicit controls,
elapsed outage budgets through pauses, terminal blocking and retained cleanup
ownership on close timeout. Automated source reviews do not replace
independent human review. Record remaining protocol/host-policy, durable recovery
and FFI/mobile work with the source revision and evidence scope in implementation
issues. Scope each verification claim to the code and boundary exercised.

Repository implementation licensing is Apache-2.0 ([LICENSE](LICENSE) and the root
manifest). Preserve source provenance when updating schemas and fixtures.

## Input provenance and authority

Original Rust source extraction credit:
[`tinkle-org/syntra` at `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`](https://github.com/tinkle-org/syntra/commit/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c).

[`upstream.lock.json`](upstream.lock.json) identifies the reviewed source repository
`https://github.com/tinkle-org/syntra` and exact commit
`8ede3810b29fbba4d0e6ae6751a0025ceedda140`. Lock format v2 has scope
`implementation-inputs` and exactly **11 declared paths**: eight schemas, the
Protobuf corpus, WebSocket fixtures and TCP byte vectors. The existing revision
and input digests are preserved. It records consumed inputs rather than a complete
upstream suite or root inventory.

Local implementation inputs are the eight `.proto` files under `proto/` and one
test asset, [`protobuf-vectors.yaml`](tests/interoperability/fixtures/protobuf-vectors.yaml),
copied from upstream `conformance/test-vectors/protobuf/vectors.yaml`. The explicit
allowlist and digest/Git verification live in
[`scripts/sdd_inputs.py`](scripts/sdd_inputs.py) and
[`scripts/upstream_snapshot.py`](scripts/upstream_snapshot.py). The two other
declared vector sources are read from committed upstream blobs to verify
handwritten transcriptions in [`vectors.rs`](tests/interoperability/vectors.rs);
they are not additional local corpus copies. Resolve upstream-only document
paths in the [pinned source tree](https://github.com/tinkle-org/syntra/tree/8ede3810b29fbba4d0e6ae6751a0025ceedda140).

```sh
python3 scripts/check-upstream-pin.py --offline
python3 scripts/check-upstream-pin.py --upstream ../syntra
```

`--offline` checks local input inventory and digests against the reviewed lock; it
does not establish Git provenance. Default checking uses `SYNTRA_SDD_ROOT` or
`../syntra`; `--upstream PATH` selects an explicit local Git object database.
That database must contain the exact pinned commit. The checker compares the
11 declared inputs with committed Git blobs, never HEAD or worktree files, and
never fetches or writes. Unrelated upstream paths are intentionally ignored;
the local `proto/` inventory must still match exactly, including filenames and
bytes. The checks do not establish protocol acceptance or conformance. Review
intentional source-revision, declared-input, copied-input and generated-output
updates together; do not edit pinned bytes or their hashes just to make checks pass.

### Candidate agreement

The separate v2 [`protocol-contract.json`](protocol-contract.json) records the
current Syntra 1.0 candidate's domain, carrier bindings and context layout. Its
`committed-candidate` record pins upstream commit
`3f7e8ea037fefcc5c86101d23e7722c83e28a0d3`, whose four machine-input blobs match
the previously recorded bytes exactly. The original baseline HEAD, branch and
dirty state remain in `source.worktree_observation` as historical provenance;
the baseline HEAD is not the candidate commit. Release-pin verification checks
the actual committed blobs, not the current upstream worktree. A successful
agreement check does not authorize publication or freeze the candidate SDD.

The candidate context fixture is a **derived** artifact at
[`syntra-1.0-context.json`](tests/interoperability/fixtures/syntra-1.0-context.json).
The explicit `syntra-context-identifiers-by-source-order-v1` transformation maps
context IDs to `SYNTRA-CONTEXT-01`, `SYNTRA-CONTEXT-02`, and so on, and negative
recipe IDs to `SYNTRA-N01`, `SYNTRA-N02`, and so on, updating their base references
by source-array order. Other fields, encoded bytes and mutation recipes are
preserved. Raw source hashes are recorded separately from the derived fixture's
hash. `carrier_bindings` uses `kind: CARRIER` through the recorded
`transport-registry-to-carrier-bindings-v1` projection of the source registry;
its canonical derived hash is separate from the raw registry hash. These are
carrier bindings of one protocol, not selectable transport profiles.

```sh
python3 -B scripts/protocol_contract.py --offline
python3 -B scripts/protocol_contract.py --release --upstream ../syntra
```

Offline candidate agreement checks the recorded local semantic artifacts and
compiled source encoding probe without verifying external bytes. Release mode
also verifies the exact candidate commit, baseline ancestry, machine-input Git
blobs and derived transformations. Neither mode runs a complete crate or carrier
suite. For a future uncommitted candidate, `--record-worktree` explicitly records
its bytes and `--worktree` verifies that observation; publication stays blocked.
Once those exact bytes are committed, use `--record-commit FULL_SHA --upstream
PATH` to verify them before promoting the record. Do not change its kind or
revision by hand to bypass failed verification.
The separate `--run-rust --output NEW_EXTERNAL_DIRECTORY` option adds five exact
supplemental Rust regressions with command logs. Candidate fixtures and
implementation checks must not be presented as execution of the pinned upstream
suite. Protocol specifications and conformance definitions remain upstream-owned;
normative changes belong in that process first.

## Implementation evidence

[`scripts/conformance_evidence.py`](scripts/conformance_evidence.py) produces a
unified implementation-evidence report. It verifies the 11 declared upstream Git
inputs and local copies, checks fixture transcriptions, and optionally adds
candidate agreement and supplemental local execution. It has no transport-profile
selection or full-suite inventory mode. Install the parser from
`scripts/requirements-evidence.txt` before running it.

```sh
python3 -B scripts/conformance_evidence.py --upstream ../syntra --candidate-agreement offline
python3 -B scripts/conformance_evidence.py --upstream ../syntra --candidate-agreement release
```

Here `offline` applies only to candidate agreement: the evidence runner still
requires the local Git object database containing the exact accepted-base commit.
It performs no network fetch. Omit `--candidate-agreement` to collect input and
transcription evidence without candidate agreement.

Repeat `--run-local` to select supplemental lanes. The following runs all 14
currently available lanes and writes command logs and `report.json` into a new
directory outside the worktree. Choose a fresh output path for each run.

```sh
python3 -B scripts/conformance_evidence.py --upstream ../syntra \
  --candidate-agreement offline \
  --run-local corpus --run-local echo \
  --run-local enrollment-preready --run-local enrollment-revocation \
  --run-local wss-envelope --run-local wss-unknown-field --run-local wss-ready \
  --run-local wss-reserved-method --run-local wss-payloads --run-local wss-duplicate-id \
  --run-local wss-deadline --run-local wss-internal-error \
  --run-local wss-reverse-completion --run-local wss-recovery-isolation \
  --output /tmp/syntra-implementation-evidence
```

Each local result records its command, test, artifact hash and execution verdict.
An exit code alone or a zero-test match does not prove execution. The runner
records implementation identity before and after execution; a changed worktree
invalidates passing execution claims and requires a stable-snapshot rerun.
Supplemental rows retain `formal_conformance: false`; the report retains
`formal_conformance_claimed: false` and an external formal-conformance gate of
`NOT_EXECUTED`. Browser/device execution, independent interoperability,
independent cryptographic vectors, security review and specification freeze
remain separate external evidence. A successful command does not turn those
gates into passes.

## Schema and generated code

Use Buf CLI 1.59.0 with the remote Rust plugin `neoeinstein-prost:v0.4.0`
revision 1 configured in `buf.gen.yaml`. Generated files are committed and
must not be hand-edited.

```sh
buf format --diff --exit-code
buf lint
buf build
python3 scripts/check-generated.py
python3 scripts/check-upstream-pin.py --offline
python3 -m pip install -r scripts/requirements-evidence.txt
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

The generated-code drift script uses Python's standard library and only writes to a
temporary directory. To intentionally regenerate committed Rust output, run
`buf generate --template buf.gen.yaml`, then inspect the resulting diff.
The eight logical schema paths have explicit Rust mappings in `buf.gen.yaml`.
Keep the pinned `.proto` options intact. Rust owns its compatibility and execution
evidence; local fixture and byte-drift checks cover only their stated scope.

## Reports and releases

Open ordinary Rust implementation issues and pull requests in
[`tinkle-org/syntra-rs`](https://github.com/tinkle-org/syntra-rs). Cargo packages
use the per-package release process in [release-plz.toml](release-plz.toml),
independently of upstream protocol specification releases.
There is no published previous package version. Release-plz manages future
per-package changelogs when preparing releases.

On pushes to `main`, Release-plz opens or updates a release PR. With
`release_always = false`, publication is attempted only when a release PR merges,
and requires the committed candidate pin and release validation to pass. The
release job publishes Cargo packages, creates immutable per-package tags, and
creates matching GitHub Releases with changelog notes. `git_release_type = "auto"`
marks `1.0.0-rc.x` releases as prereleases. Keep GitHub Releases and crates.io
versions aligned through this one job rather than creating a second release
workflow.

`crates-io-publish` is the protected GitHub Actions environment used by the job,
not a package registry or an alternative to the repository's Releases page.
Trusted publishing uses the job's `id-token: write` permission and requires a
publisher configured on crates.io for each package. New crates need an initial
manual publication before trusted publishing can publish later versions; merging
a release PR alone does not bootstrap a new crate. See the
[Release-plz quickstart](https://release-plz.dev/docs/github/quickstart) and
[release command](https://release-plz.dev/docs/usage/release).
