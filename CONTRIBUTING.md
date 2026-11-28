# Contributing to Syntra Rust

Run commands from the repository root. **Rust 1.89.0 is the toolchain**;
the crate MSRV floor of **1.89** is an API/build compatibility constraint,
not a secure-runtime recommendation. Production binaries must be built with
a security-patched toolchain. Current dependency versions include
`snow =0.10.0`, `getrandom 0.3`, `tokio 1`, `tungstenite`/`tokio-tungstenite`
0.30 and `rustls 0.23`. Keep dependency versions and checksums consistent
unless updating them is part of the change.

Read [CONNECTION.md](CONNECTION.md) for Syntra 1.0 encryption and connection
guidance. Review protocol changes in this repository; see
[schema and generated code](#schema-and-generated-code).
The implementation remains experimental despite RC publication; formal conformance has
not been executed and independent security review remains outstanding.

`syntra-net` has an empty default feature set: the native carrier-neutral
record driver is available without socket dependencies. `tcp` supplies TCP I/O;
`websocket` supplies framing/upgrade, loopback WS and the trusted application TLS
provider boundary without a production TLS implementation dependency. `tls-rustls`
adds optional rustls WSS convenience APIs. `reconnect` supplies reconnection;
`managed` enables TCP/reconnect and owns runtime/client/listener lifecycle.
Add `websocket` for managed loopback WS and application-provider WSS listeners.
The TCP-gated `routes` module composes explicit allowlisted endpoints with fresh
per-attempt inputs. `proxy` enables TCP with SOCKS5/HTTP CONNECT, forward metadata
helpers and proxied TCP/WSS routes.
`http` independently enables candidate HTTP/HTTPS connections with
Noise, hello/ready and RPC, a bounded listener/association registry and raw
codec/pair APIs. It enables `syntra-core/http-candidate`, `getrandom` and the
application TLS boundary without implying `websocket` or a TLS implementation.
With `managed,http`, `Network::listen_http`/`listen_https` own the inline listener
run; routes support direct, SOCKS5/CONNECT and real plain-HTTP forward paths.
These carriers are experimental; test the full connection separately from its raw codec.
`native-enrollment` is explicitly opt-in. See the [feature table](README.md#workspace-and-scope).

Keep the ownership boundaries: `syntra-core` owns framing and record protection
through `syntra_core::secure_channel`, `syntra-runtime` owns sessions, and
`syntra-net` owns native I/O. Core and runtime remain portable to WASM, with
platform I/O supplied by the embedder. `syntra-ffi` owns the native ABI and
`syntra-integration` supplies the Docker fixture peer. FFI features require their
own checks.

## Checks

SDK-owned tests and tooling must run without another SDK checkout, toolchain or
release. Keep developer experiments and their evidence in a developer-local cache
outside this repository and its public documentation.

```sh
export RUSTUP_TOOLCHAIN=1.89.0
cargo fmt --all -- --check
cargo test --locked
cargo test --locked --workspace
cargo test --locked -p syntra-runtime --no-default-features --features file-store
cargo test --locked -p syntra-net --no-default-features
cargo test --locked -p syntra-net --no-default-features --features tcp
cargo test --locked -p syntra-net --no-default-features --features http
cargo test --locked -p syntra-net --no-default-features --features managed,http,proxy --test http_connections --test network_http --test routes
cargo test --locked -p syntra-net --no-default-features --features managed,http,websocket,proxy --test http_connections --test network_http --test routes
cargo test --locked -p syntra-core --no-default-features --test http_candidate_context
cargo test --locked -p syntra-core --no-default-features --features http-candidate --test http_candidate_context
cargo test --locked -p syntra-net --no-default-features --features websocket
cargo test --locked -p syntra-net --no-default-features --features tls-rustls --test wss
cargo test --locked -p syntra-net --no-default-features --features tcp,tls-rustls,reconnect
cargo test --locked -p syntra-net --no-default-features --features managed
cargo test --locked -p syntra-net --no-default-features --features managed,websocket,proxy --test network_websocket --test routes
cargo test --locked -p syntra-net --no-default-features --features managed,tls-rustls,proxy --test network_websocket --test routes
cargo test --locked -p syntra-net --no-default-features --features proxy
cargo test --locked -p syntra-net --no-default-features --features tls-rustls,native-enrollment
cargo bench --locked -p syntra-net --no-default-features --features tcp --bench pipe -- --test
python3 scripts/cargo_contracts.py isolation
python3 scripts/cargo_contracts.py websocket
python3 scripts/cargo_contracts.py managed-websocket
python3 scripts/cargo_contracts.py http
python3 -B -m unittest discover -s scripts/tests -p 'test_*.py' -v
cargo clippy --locked --workspace --all-targets -- --no-deps
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
python3 crates/syntra-ffi/tests/build_contract.py
cargo check --locked -p syntra-core -p syntra-runtime --target wasm32-unknown-unknown
cargo check --locked -p syntra-core --no-default-features --features http-candidate --lib --target wasm32-unknown-unknown
python3 crates/syntra-net/tests/target_contract.py
sh crates/syntra-core/tests/run-kernel-browser.sh
git diff --check
```

Root builds/tests without package selectors or `--workspace` use
the four `default-members` (`syntra-core`, `syntra-runtime`, `syntra-net`,
`syntra-ffi`). The five-member workspace additionally includes
`syntra-integration`; `--workspace` unifies its `tcp` and `websocket` features into
`syntra-net`.
Keep the isolated default and explicit carrier/reconnect invocations separate;
workspace success alone does not establish socket-free default isolation.
The isolation lane checks normal/build dependency graphs on host and WASM targets.
The websocket lane selects only `websocket`; managed-websocket checks the
managed/WebSocket/proxy composition and its TCP/reconnect requirements. Both
reject production TLS dependencies and unification of `syntra-net/http` or
`syntra-core/http-candidate`; defaults reject these features too. The http lane
requires both HTTP feature gates, checking standalone, managed/proxy and mixed
WebSocket compositions. It rejects TLS implementations and state stores, and
rejects WebSocket dependencies in the non-WebSocket graphs. Dev dependencies
supplying test certificates/TLS peers are excluded from all graph checks.
The target contract compiles each native feature independently, checks native
WASM rejection and portable core candidate compilation, and requires nonzero
passing tests in `http_records`, `http_connections`, `network_http`, HTTP unit
tests, `tls_provider`, `wss`, `recovery_wss`, `network` and `proxy`.
It also runs `network_websocket` and `routes` with both `managed,websocket,proxy`
and `managed,tls-rustls,proxy`. Provider WSS is exercised in both; the first has
no production TLS implementation dependency. Convenience WSS selectors need
`tls-rustls`; recovery WSS also needs `reconnect`. Compilation or a zero-test
result is not execution. Candidate HTTP connection/listener/routes run separately
with `managed,http,proxy` and `managed,http,websocket,proxy`; three exact proxy/
forward regressions require the named single-test execution proof in both modes.
Core `http_candidate_context` runs without the feature to prove rejection and
with it to check the fixture hash, golden contexts and full Noise prologue.
Raw codec/record tests alone remain lower-level evidence; full-RPC tests are
implementation evidence, not independent interoperability or security review.
Low-level native driver APIs require Tokio; managed networking owns its runtime.
WASM embedders compose core/runtime with
platform I/O.
The net crate's native features must be disabled on WASM.

Install the `wasm32-unknown-unknown` target for this toolchain first. The
FFI contract also requires Python 3, `nm` and a C compiler. The kernel browser
runner requires `wasm-bindgen-test-runner` matching Cargo.lock and a browser/WebDriver;
set `NO_HEADLESS=1` for an interactive browser. It exercises kernel tests, not a
carrier. Run the relevant focused tests while iterating. The container suite is ignored by workspace
runs; follow its own tooling instructions and record the actual fixture revision.
A container round trip covers SDK-local connectivity, not formal conformance.

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

The isolated [parser checks](fuzz/README.md) use cargo-fuzz with AddressSanitizer.
The frame target compares structurally admitted raw requests and generated legal
requests with Prost. PRs and `main` cap inputs at 4 KiB and run for 60 seconds
per target. Scheduled runs use 900 seconds per target; `--large-frame` raises
only the frame input cap to 1 MiB + 1 byte. See the
[failure replay instructions](fuzz/README.md#retain-and-replay-a-failure)
for the one-day synthetic artifact and local `--failure-dir` usage. CI also checks
`fuzz/Cargo.lock` against RustSec and the workspace dependency policy.

For request decoder changes, run `cargo test --locked -p syntra-core --test phase2_wire`
for deterministic parity, varint, and envelope-size cases. Run `codec_vectors`,
`encode_allocation`, `runtime_defects`, and pump split-point and fault-injection
tests when touching their parsers. Keep fixture inputs and expected bytes together
in review; distinguish local parser checks from carrier integration tests.

The exact context/prologue fixture tests cover **public encoding only**, not
independent Noise cryptographic vectors. The separate [resolver known-answer tests](crates/syntra-core/tests/fixtures/resolver_kats/README.md)
check published primitive and Noise suite vectors through Syntra's Snow resolver;
they do not exercise Syntra's wrapped flights or assert interoperability with another SDK.
Record the source revision and scope of each result. Same-library round trips
and generated-byte checks do not establish formal conformance, device validation or independent
security review.

Workflows (all actions SHA-pinned, `contents: read`, timeouts, concurrency
cancel for PRs):

- `CI` – PR/main validation (`clippy`, `rust`, `generated-rust`,
  `manifest-cases`, `package`, `security`, `actionlint`, `dependency-review`,
  aggregator `required`), including required macOS native validation. `fmt` is
  informational. Require `required` in the main-branch ruleset.
- `Scheduled` – periodic Linux/macOS/Windows validation rechecks, coverage and
  vulnerability scans (does not gate PR/main validation).
- `Integration` – separate Docker-based connectivity checks; see
  [crates/syntra-integration/README.md](crates/syntra-integration/README.md).
- `Benchmarks` – same-runner Criterion comparisons for source and Cargo build-input changes on `main`,
  covering frame round trips and protected records; see [BENCHMARKS.md](BENCHMARKS.md).
- `CodeQL` – Rust and Actions analysis. After the initial scan, administrators
  should require CodeQL results on `main` with security severity **High or higher**.
  An uploaded scan alone does not block findings. Enable repository secret scanning
  and push protection in GitHub settings; never allowlist a whole fixture directory.
- `Release-plz` – validated release PRs, per-package `syntra-<crate>-vX.Y.Z`
  tags and gated Cargo publishing for eligible packages. Packages marked
  `publish = false` are excluded. See
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

The `.proto` files in [`proto/syntra/v1`](proto/syntra/v1) restore this
repository's `syntra.v1` schema from `b99f56b`, before the Bebop change in
[#54](https://github.com/tinkle-org/syntra-rs/pull/54), with local corrections
to the schema comments. The checked-in schema is the input for this
implementation. That revision identifies the schema's
history; it does not import an external protocol pin, test suite, or verdict.
Both encodings use Core wire version 1. Upgrade peers together; changing
carrier or negotiating recovery does not select a codec.

## Schema and generated code

[`envelope.proto`](proto/syntra/v1/envelope.proto) defines `Frame`;
[`rpc.proto`](proto/syntra/v1/rpc.proto) defines the RPC messages;
[`recovery_profile.proto`](proto/syntra/v1/recovery_profile.proto) defines the
negotiated service payloads. Preserve field numbers, reserved names and
numbers, and `oneof` membership. These determine which values a peer can
interpret, independently of Rust naming.

[`buf.yaml`](buf.yaml) defines a module rooted at `proto`; its schema imports
resolve locally. Use **Buf CLI 1.59.0** with [`buf.gen.yaml`](buf.gen.yaml),
which pins `buf.build/community/neoeinstein-prost:v0.4.0`, **revision 1**.
The Cargo runtime dependency is `prost = "=0.14.6"`. Normal builds
read [`syntra.v1.rs`](crates/syntra-core/src/generated/syntra.v1.rs) directly.
Do not hand-edit it. From the repository root, with `buf` on `PATH` and access
to `buf.build` for remote generation:

```sh
python3 scripts/check-generated.py --write  # Regenerate after editing a schema.
python3 scripts/check-generated.py          # Check for drift without changing the checkout.
```

Use the script rather than bare `buf generate`: it runs the pinned plugin in
a temporary directory and adds `#[prost(skip_debug)]` to `ClientHello` so its
credential is not included by a generated `Debug` implementation. The drift
check compares filenames and bytes after that step.

Use the public `syntra_core::proto` types. The crate root also re-exports
`Frame`, `RpcRequest`, and `RpcResult`. For example, this is a successful
empty RPC result; omitting `outcome` is invalid:

```rust
use syntra_core::proto::{frame::Body, rpc_result::Outcome, RpcResult};

let body = Body::Result(RpcResult { outcome: Some(Outcome::Payload(vec![])) });
```

Use `Body::Request(RpcRequest { .. })` for a request. Recovery uses names such
as `RecoverySubscribeRequest` and `RecoverySubscribeResponse`. In a wire error,
`proto::RpcError.code` is a raw `i32`; zero (`ErrorCode::Unspecified`) is invalid.

Use `syntra_core::encode_frame` and `syntra_core::decode_frame` at the frame
boundary. A generated type does not enforce raw-wire or connection-state
rules. Review the schema, generated bindings, validation, and local fixtures
together: compare expected bytes as well as decoded values, since a round
trip alone can pass when both sides change. See [records and carriers](CONNECTION.md#records-and-carriers)
for framing outside Protobuf.

## Implementation evidence

Use this checkout's [protocol contract](protocol-contract.json) and fixtures.
With the Python dependencies from `scripts/requirements-evidence.txt` installed,
run `python3 scripts/conformance_evidence.py` to check those inputs. This
default invocation is not a peer run or a formal conformance assessment.
Record the local revision, feature set, command, and named cases that actually
ran. Distinguish a generated-file comparison from a codec fixture and from an
encrypted round trip with this SDK on both ends. A zero-test filter or successful
compilation is not an executed test. Report performance only from measurements
with the setup and timing boundary described in [BENCHMARKS.md](BENCHMARKS.md).

## Reports and releases

Open ordinary Rust implementation issues and pull requests in
[`tinkle-org/syntra-rs`](https://github.com/tinkle-org/syntra-rs). Cargo packages
use the per-package release process in [release-plz.toml](release-plz.toml).
Release-plz manages per-package changelogs when preparing releases.

Make implementation and workflow changes on feature branches, never by pushing
directly to `main`. Open a pull request and wait for its current revision's CI
and Integration checks to pass before squash-merging. The same check requirement
applies to the generated release PR, including approving its workflow runs.

On pushes to `main`, Release-plz opens or updates a release PR. The same job
then updates `fuzz/Cargo.lock` on the generated branch: the standalone parser
workspace depends on the local core and runtime crates, but Release-plz only
updates the root workspace lockfile. Review and run checks on the final PR head.
With `release_always = false`, publication is attempted only when a release PR merges,
and requires release validation to pass. The
release job publishes Cargo packages, creates immutable per-package tags, and
creates matching GitHub Releases with changelog notes. `git_release_type = "auto"`
marks `1.0.0-rc.x` releases as prereleases. Keep GitHub Releases and crates.io
versions aligned through this one job rather than creating a second release
workflow.

Before merging an RC release PR, check its version and changelogs, including any
reported API breaks. Keep the `-rc.N` suffix until a stable release is intended;
do not create tags or GitHub Releases manually. Require CI and Integration to
pass on the current release PR revision, not only on its base branch. Generated
PR checks can require approval under GitHub's Actions policy. Approve the runs
after reviewing the diff; if no runs were created with the built-in token,
close and reopen the PR as a maintainer to trigger them.

Both Release-plz jobs use only GitHub's built-in `GITHUB_TOKEN` for GitHub access.
`RELEASE_PLZ_TOKEN` must never exist as a repository, organization, or environment
secret available to this repository, and must never be referenced as a credential
in its workflows. Do not add a PAT to bypass generated-PR workflow approval;
maintainers approve or retrigger the checks as described above. Cargo publication
uses the separate crates.io API token in the `CARGO_REGISTRY_TOKEN` Actions secret,
exposed only to the gated publication step, never to PR preparation or validation.
This is not a GitHub PAT. See the
[Release-plz token guidance](https://release-plz.dev/docs/github/token).

Prepublication package validation lists contents without generating archive
lockfiles that would require the new dependency versions to exist on crates.io
already. It does not prove packaged compilation. Release-plz keeps Cargo's
publication verification enabled and publishes in dependency order: core, then
runtime, then its dependents net and FFI. Net and FFI do not depend on each other.
Only `syntra-integration` remains non-publishable: it is a fixture peer and test suite,
not a downstream library. The public set is derived from package metadata; no
separate net publishing workflow or hard-coded package list is needed.

`crates-io-publish` is the GitHub Actions environment used by the job,
not a package registry or an alternative to the repository's Releases page.
Configure its required reviewers and deployment branch restrictions in GitHub;
the workflow's environment reference does not create those protections.
The crates.io token must belong to an account authorized to publish these crates
and permit publishing updates for core, runtime, net, and FFI. Restrict its crate scope
and lifetime; rotate it before expiry. No OIDC permission or trusted-publisher
configuration is required in this token-based workflow. Never log the token or
put its value in a command, file, PR, or commit. See the
[Release-plz quickstart](https://release-plz.dev/docs/github/quickstart) and
[release command](https://release-plz.dev/docs/usage/release).

After merging, monitor the Release-plz run for that merge commit and verify that
each eligible crate version, immutable tag, and GitHub prerelease agree. For a
transient runner, registry, or credential failure, resolve the external cause
and rerun the failed merge run after reviewing its revision. A rerun uses the
original source and workflow; it cannot pick up a later source fix. After a
reviewed workflow-only fix, use the Release-plz workflow's manual Run workflow
action on `main`, with `release_commit` set to the full lowercase SHA of the
original release-PR squash merge. The target must contain the Protobuf schema,
Buf configuration, and local generation and evidence scripts required by the
[release workflow](.github/workflows/release-plz.yml). This retry verifies that the commit is on
`main` and belongs to a merged release-plz PR, reruns all validation on that exact
commit, then publishes from the same revision with the current workflow. It
does not prepare another release PR or bypass `release_always = false`.
For implementation fixes, prepare a new release PR for the corrected revision,
accounting for any package versions already published.
After a partial publication, inspect every crate version, tag, and GitHub Release
before retrying: an already-published package can be skipped rather than having
missing GitHub metadata repaired automatically.
Never move existing tags or try to overwrite a published version. There is
deliberately no workflow-wide concurrency group that could replace a queued
merge run; only release-PR updates are serialized.
