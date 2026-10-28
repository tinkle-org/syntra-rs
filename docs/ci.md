# Production CI/CD for syntra-rs

This document records the audit, the implemented controls, and the remaining
manual steps. CI passing does not prove production readiness or protocol
conformance; it only proves the listed checks ran.

## 1. Audit findings (P0/P1/P2)

P0 — must fix before production use:

- Mutable action references and `persist-credentials: true` default in
  `ci.yml` allowed supply-chain substitution. Fixed by SHA-pinning every
  `uses:` to a reviewed full commit SHA with a version comment, setting
  `persist-credentials: false` on all checkouts, and documenting Dependabot
  updates through reviewed PRs.
- No dependency-security gate: no `cargo-deny`, no RustSec audit, no
  Dependabot, no PR dependency review. Fixed by `deny.toml`,
  `cargo-deny`/`cargo-audit` jobs (pinned 0.20.2/0.22.2), `dependabot.yml`,
  and `dependency-review-action` on PRs.
- Release credentials could leak into PR jobs. Fixed by separating
  release workflows (trusted publishing, `id-token: write` only on the
  release job) from PR CI, which has only `contents: read` and no secrets.
- Reproducibility relied on a floating upstream `main`. Fixed by
  `scripts/check-upstream-pin.py`, which verifies the checked-in snapshot
  matches pinned upstream `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c` and that
  `buf.yaml`/proto comments use pinned URLs instead of absent local paths.

P1 — should fix for production quality:

- No formatting policy: `cargo fmt --all -- --check` reports 244 inherited
  diffs (frame, reliable, ffi, runtime, recovery, ws). A failing fmt job was
  not added alone; see §2 migration plan. New code MUST be rustfmt-clean.
- No Clippy gate: `cargo clippy --locked --workspace --all-targets` reports
  45 warnings (21 `useless_conversion`, 4 `vec!`, 2 `single_match`, plus
  `field_reassign_with_default`, `match_result_ok`, `map_entry`,
  `too_many_arguments`, `complex-type`, `matches!`, doc-list, empty-doc-line,
  and 1 dead-code `ResumeEntry::issued_at_ms` never read). The `required` job
  runs Clippy on every PR; `-D warnings` is informational until the baseline
  cleanup lands. No global `allow`, no broad suppression.
- No packaging validation: added `cargo package --list` +
  `cargo package --no-verify` per crate, `cargo doc --no-deps`, and a public
  API drift guard on generated output. `cargo publish --dry-run` is documented
  as unsuitable while `1.0.0-rc.1` is already published; the non-publishing
  packaging check is the equivalent gate.
- WASM was compile-only with no browser-execution claim. Retained
  compile checks for `syntra-core/runtime/ws/web`; documented the opt-in
  real-browser fixture (`syntra-web/tests/browser.md`) as deferred, not
  claimed.
- FFI/`--all-features` risk: CI explicitly forbids `--all-features` and tests
  `default` (no ABI), `production`, and `test-fixture` separately, plus
  `build_contract.py` symbol and C-smoke checks.

P2 — hardening / deferred:

- Coverage has no baseline: added `cargo-llvm-cov` (pinned 0.9.1) reporting in
  `scheduled.yml` with an uploaded `lcov.info` artifact and no threshold.
  Coverage is not a security proof.
- Fuzz/sanitizer runs are scheduled/manual only, never required PR checks.
- macOS/Windows native compat runs in `scheduled.yml`; PRs stay Linux-only to
  avoid a large per-PR matrix. WASM execution remains deferred.
- Go interop pins the Rust revision explicitly (immutable per-crate tags or
  reviewed commits); Go-calls-Rust-through-FFI is not treated as wire-interop
  proof. See §7.

## 2. Formatting and Clippy migration plan

Rust 1.88.0, committed `Cargo.lock`, `rust-toolchain.toml` unchanged.

- `cargo fmt --all -- --check` (CI job `fmt`): currently fails on inherited
  diffs. Do not mix fmt fixes with behavior. Follow-up: one isolated
  formatting-only commit running `cargo fmt --all`, verifying
  `cargo test --locked --workspace` still passes and `generated/syntra.v1.rs`
  bytes change only if `buf generate` dictates (they must not be hand-edited).
- `cargo clippy --locked --workspace --all-targets` (CI job `clippy`): runs
  without `-D warnings` until the baseline is cleaned; a second step runs
  `-D warnings` as informational (`continue-on-error`). Genuine baseline:
  `issued_at_ms` never read (dead code — confirm whether resume-timing needs
  it before deleting or denying warnings). Other lints are mechanical
  (`useless_conversion`, `vec!`, `single_match`) and should be fixed in small
  batches, never with broad `#[allow]`.

## 3. Compatibility matrix

- Declared MSRV stays 1.88.0 unless a reviewed change updates
  `rust-version` and `rust-toolchain.toml` together.
- PR (`ci.yml`, Linux): fmt, Clippy, locked workspace tests, separate
  `default`/`production`/`test-fixture` FFI tests, WASM compile for
  non-FFI crates, `build_contract.py` (default no-ABI, production exports +
  C smoke, fixture exports + C smoke, header opt-in, expected WASM rejection),
  generation drift + upstream pin, packaging + rustdoc, deny/audit,
  dependency review, actionlint, fail-closed `required` status.
- `main` push: same as PR (no extra matrix).
- Scheduled (`scheduled.yml`, weekly + dispatch): full Linux validation,
  focused macOS-15 and Windows-2022 native tests, coverage artifact, and
  extended `cargo deny check` + `cargo audit`.
- Release (`release-plz.yml` on `main`): `validate-release` runs full
  validation plus release-profile FFI symbol and packaging checks, then
  `release-pr` opens a reviewed Release PR and `release` publishes with
  trusted publishing. No manual tag workflow remains.

## 4. Dependency security

- `deny.toml`: targets `x86_64-linux` + `wasm32-unknown-unknown`,
  `all-features = false`; advisories from RustSec; licenses allow only
  `Apache-2.0, MIT, BSD-2/3, ISC, Unicode-3.0, Unlicense` (Unlicense covers
  `memchr/pharos/ws_stream_wasm`; copyleft implicitly denied); bans allow
  duplicate versions (portability across native/WASM); sources allow only
  `crates.io-index`, deny unknown registries/git.
- Tools pinned: `cargo-deny 0.20.2`, `cargo-audit 0.22.2`,
  `cargo-llvm-cov 0.9.1`, `Buf 1.59.0`, `actionlint v1.7.7`,
  `rust-toolchain 1.88.0`. Security jobs run on PR, main, and scheduled.
- `dependabot.yml`: weekly `cargo` + `github-actions`, limit 5, labels
  `dependencies`. Dependabot updates pinned actions through reviewed PRs.
- Exceptions policy: any `ignore` in `deny.toml` or `cargo audit --ignore`
  MUST cite a reviewed issue/PR, severity, and expiry; unmaintained/yanked
  advisories are not blanket-ignored.

## 5. Tests and coverage

Covered: malformed/oversized frames, invalid handshakes, correlation,
cancellation, resource bounds, session/recovery, teardown, C ABI
pointer/length contracts, untrusted-input panics (via existing suites +
`build_contract.py` C smokes).

Determinism fix: `recovery/reconcile`, `reliable::poll_idle`,
`record_tombstone` ordering and similar timing-sensitive paths were reviewed;
the only test change in this CI PR is
`crates/syntra-runtime/tests/integration.rs`: the fixed 100 ms sleep before
`pending_len() == 1` is now a bounded 5 s async wait yielding until the
outstanding call registers. No production behavior changed.

Coverage: `cargo llvm-cov --locked --workspace --lcov` in scheduled CI,
artifact only, no threshold. Establish the baseline from that artifact before
adding any percentage gate. Longer fuzz/sanitizer campaigns are scheduled or
manual with explicit duration caps.

## 6. ABI and WASM boundaries

- `syntra-ffi` has no default ABI; `production` and `test-fixture` are
  mutually distinct; `--all-features` is forbidden in CI and docs.
- `build_contract.py` verifies: default artifact has no
  `syntra_open/syntra_abi_compatible/syntra_ffi_client_open/syntra_ffi_host_open`;
  explicit `production` exports the frame-pump symbols and passes
  `production_smoke.c`; explicit `test-fixture` exports the loopback symbols
  and passes `fixture_smoke.c`; header requires `SYNTRA_TEST_FIXTURE` opt-in;
  all three modes reject `wasm32-unknown-unknown` with
  `syntra-ffi does not support WASM`.
- Release validation rebuilds the production `.so` with `--release` and
  re-checks symbols separately from dev test libraries; it fails if
  test-only `syntra_open` appears in the production artifact.
- WASM: `cargo check --target wasm32-unknown-unknown` for
  `core/runtime/ws/web`; browser execution is explicitly deferred to the
  opt-in fixture, not claimed from compile checks.

## 7. Specification conformance and releases

Normative authority stays in `tinkle-org/syntra`. This repo owns the Rust
implementation + C headers. `proto/` and `conformance/test-vectors/` are exact
snapshots of upstream `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`; sync PRs must
record upstream commit + paths and update `MIGRATION.md`.

- Generation: `prost =0.13.5`, `neoeinstein-prost:v0.4.0` rev 1, Buf 1.59.0.
  `check-generated.py` verifies byte-identical regeneration in a temp dir.
  `check-upstream-pin.py` verifies the snapshot matches the pinned commit and
  comments use pinned URLs (no floating `main`, no absent
  `docs/schema-registry.md` / `compatibility/v1-initial/image.json` relative
  paths). Proto comment changes are regenerated via `buf generate`, never
  hand-edited in `generated/`.
- Publishing: crate names frozen (`syntra-core/runtime/ws/web/ffi`),
  versions from workspace `1.0.0-rc.1`, `Cargo.lock` committed, dependency
  order `core → runtime → ws/web → ffi` (resolved topologically by
  release-plz). Tags are immutable per-crate
  `syntra-<crate>-vX.Y.Z` (release-plz default `{{ package }}-v{{ version }}`);
  no global `vX.Y.Z`, no recreated tags, no overwriting published releases.
  `release-plz` is implemented via `release-plz.toml` and
  `.github/workflows/release-plz.yml`: `release-pr` opens a reviewed Release
  PR on pushes to main, `release` publishes only when that PR merges
  (`release_always = false`), using crates.io trusted publishing (OIDC,
  `id-token: write`, no long-lived token). `syntra-ffi` publishes with default
  features only (no ABI), never `--all-features`. The former hand-crafted
  `release.yml` tag workflow has been removed; release-plz is the sole release
  path.
- Provenance: binary artifacts are source-only crates (no required native
  binaries); attestations can be added via the release environment without
  changing PR CI.
- Go interop: `tinkle-org/syntra-go` native tests use an explicit Rust
  revision (this PR: `fca1063515d3966be71e9844346e7cbc53769c76`; going forward:
  immutable per-crate tags or reviewed commits, recorded in the Go PR). Test
  Rust-client/Go-host and Go-client/Rust-host only where transport/host APIs
  exist. FFI-link success is not wire-interop proof. Cross-language CI MUST
  fail if it silently validates the wrong Rust revision (pin + hash check).

Migration risks for existing `crates.io` users:

- Names/versions unchanged; `1.0.0-rc.1` consumers see no breaking import.
- Repository/homepage URLs moved to `tinkle-org/syntra-rs`; provenance docs
  (`MIGRATION.md`) record the extraction commit.
- No new required dependencies; `prost =0.13.5` pinned.
- FFI lifecycle unchanged in this CI PR (close-frees semantics preserved;
  proposed close/destroy split deferred — see §8). Embedders must not adopt
  `--all-features` or `test-fixture` in production.
- Any future version-validation, tombstone-ordering, or liveness-clock change
  would be a wire/behavior change requiring an RFC + major-version review,
  not part of CI maintenance.

## 8. Deferred behavior findings (verified, not changed here)

CI maintenance MUST NOT change wire compat, native ABI, or public APIs. The
following review suggestions were verified against current code and deferred
with reasons; each needs a reproducer + upstream RFC + coordinated release,
not a CI-side edit:

- `frame.rs` Closing version check: suggesting `negotiated_version` match in
  Closing tightens validation; `ctx()` already carries the version into
  Closing, but changing rejection strictness is a wire-behavior change owned
  by upstream. Deferred.
- `rpc.rs` `PendingTable::default()` zero bound: `Default` derives
  `max_outstanding = 0`, so `insert` always exhausts; production uses `new(n)`
  explicitly. Fixing `Default` to nonzero (or removing it) changes the public
  API contract. Deferred to a reviewed API RFC.
- `production.rs` close/destroy: `client_close`/`host_close` free via
  `Box::from_raw`, so double-close is UAF at the C layer (Go currently guards
  exactly-once). Adding `destroy` + header exports changes the ABI lifecycle
  and requires Go coordination + versioned bump. Deferred.
- `production.rs` `host_answer` success path: non-expired answers remove from
  `pending_map` but never push `bytes` to `outbound` (only expired pushes a
  synthesized deadline error). Likely a dropped-response bug, but fixing it
  changes production FFI behavior without a reproducer + Go sign-off.
  Deferred to a targeted ABI fix with C-smoke coverage.
- `recovery/reconcile.rs` tick, `reliable.rs` `poll_idle`/`record_tombstone`:
  proposed capacity/ordering changes alter backpressure and expiry semantics.
  Verified as plausible but normative recovery behavior; deferred pending
  recovery-profile review + regression tests.
- `native.rs` `now_millis()` SystemTime → Instant: monotonic clock is more
  robust for Pong liveness, but changes cross-platform (incl. WASM) timing
  sources. Deferred pending platform review.
- `close-codes.md` 1007 structural-decode path: mapping `InvalidArgument` to
  1002 vs 1007 for protobuf structural failures is a normative table change
  owned by upstream. Deferred.
- `recovery/driver.rs` generic `DurableStore`: API addition (nitpick).
  Deferred; `new`/`MemoryStore` behavior unchanged.

## 9. Manual repository settings and credentials

Branch ruleset for `main` (replace the current allowlist-only rule):

- Require PR, 1+ approving review, dismiss stale approvals, require
  conversation resolution.
- Require status checks: `required CI status`, plus `rust`,
  `generated-rust` (hard requirements). `fmt` is informational while
  inherited formatting differences remain and MUST NOT be a hard requirement
  until the formatting-only follow-up lands. Do not require `scheduled` or
  `release`.
- Require linear history or squash; block force pushes; require signed commits
  if the org mandates it.
- Restrict `crates-io-publish` environment to maintainers; OIDC Trusted
  Publishing for `tinkle-org/syntra-rs` crates; no long-lived crates.io tokens
  in repo or PR secrets. Document current `crates.io` owners and confirm
  publishing permissions before the first post-extraction release.
- Dependabot: auto-update pinned actions; each bump is a reviewed PR that
  re-runs `required`.
- Dependency graph and Dependabot alerts: enable Settings → Code security →
  Dependency graph plus Dependabot alerts and security updates. The
  `dependency review` job tolerates failures only when the base graph is
  unavailable and is excluded from `required CI status`. PR #1 adds the first
  Cargo manifests while main has only README, so no base graph exists to
  compare; after merge the graph populates and later PRs fail on high-severity
  or denied-license findings. `cargo-deny` + `cargo-audit` remain blocking in
  the security job.
- Secrets: none for PR CI (`contents: read` only). Release needs only the
  OIDC `id-token: write` + environment approval; provenance/SHA256 are
  informational artifacts.

## 10. Commands executed and real results

- `cargo test --locked --workspace`: pass (258 passed across suites, 1 ignored
  real-browser fixture: `configured_real_browser_fixture`).
- `cargo test -p syntra-ffi --features production`: 5 passed.
- `cargo test -p syntra-ffi --features test-fixture`: 11 passed.
- `python3 crates/syntra-ffi/tests/build_contract.py`: 5 passed (C smokes +
  expected WASM rejection in all three modes).
- `cargo check --target wasm32-unknown-unknown` (non-FFI): pass.
- `python3 scripts/check-generated.py`: `Generated Rust matches the pinned Buf output.`
- `python3 scripts/check-upstream-pin.py`: `Upstream snapshot pin matches …`
  (after proto-comment URL fix + `buf generate`).
- `cargo fmt --all -- --check`: 244 inherited diffs (see §2).
- `cargo clippy --locked --workspace --all-targets`: 45 warnings, 1 dead-code
  (`issued_at_ms`); strict `-D warnings` fails on baseline (see §2).
- `cargo deny check advisories licenses sources`: pass after allowing
  `Unlicense` (memchr/pharos/ws_stream_wasm); `cargo audit --deny warnings`:
  pass (152 crates, 1380 advisories loaded, no findings).
- `cargo package -p <each> --list` + `--no-verify`: pass for all five crates
  (e.g. `syntra-core` 16 files, 139.8 KiB).
- `actionlint`: runs in CI; local `git diff --check` clean for this change set
  except formatting baseline.

## 11. Remaining limitations and recommendations

- Do not claim production readiness or conformance from CI alone. Browser
  execution, full conformance certification, and Noise/SC1 remain out of scope
  (explicitly not implemented).
- Keep PR CI fast and Linux-only; relegate macOS/Windows, coverage, fuzz, and
  upstream-compat to scheduled/release.
- Avoid new third-party services; prefer `cargo install --locked` pinned tools
  over new actions. Every new `uses:` MUST be SHA-pinned with a version
  comment and `persist-credentials: false`.
- Next steps: isolated formatting-only commit; Clippy baseline cleanup with
  `-D warnings` enforced; coverage baseline review before any threshold;
  upstream RFCs for each §8 item with reproducers; first post-extraction
  release as a reviewed Release PR with OIDC + provenance.
