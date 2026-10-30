# SC1 container integration tests

## Current migration scope and execution boundary

The experimental, unpublished `syntra-sc1-transport` replaces `syntra-tcp` and
`syntra-ws-sc1`. Default features are empty and expose native WSS; this test
crate explicitly opts into `development-carriers` for restricted TCP and
plaintext WS fixtures. The shared `pump` is public and carrier-neutral. Baseline
`syntra-ws` keeps its framing/endpoints; runtime writers must honor the emission
gate behavior contract. See [SC1.md](../../SC1.md) for the accepted upstream
`SNTR-SC1-WSS-V1` contract at `0e8b0f8a4a789cb3d6d00b993e281867d2325e06`
(accepted 2026-10-29), the canonical endpoint `/syntra/v1/sc1/ws` and exact
subprotocol `syntra.sc1.v1`. [MIGRATION.md](../../MIGRATION.md) records the
historical proposal-review and separate extraction/schema pins.

The peer and tests now use `syntra_sc1_transport::{tcp, websocket}` and the
canonical endpoint via `websocket::ENDPOINT_PATH`. The container test dials mapped
ports on `127.0.0.1` to meet the plaintext WS loopback restriction; raw accepted
stream fixtures remain explicitly development-only.

The most recent recorded acceptance-alignment run reports
`cargo test --locked --workspace`: **377 passed, 0 failed, 2 ignored**
(Docker/browser). It compiled the migrated TCP/WS bootstrap fixture but did not
execute the container suite or browser tests. That run did not independently
check `docker info`. The earlier emission-gate run recorded a failed `docker info`
check because the daemon was unavailable; that is a previous-run observation.
See [AUDIT.md](../../AUDIT.md#current-recorded-verification) for the separate
run records. Record a new peer revision and actual carrier/mode results when
the container suite is executed.

Root `default-members` excludes this integration crate. Explicit `--workspace`
includes it and intentionally enables `development-carriers` through its dependency.
Isolated `syntra-sc1-transport --no-default-features` tests separately check
WSS-only defaults, both in CI and in the recorded alignment run. SC1 WSS tests
in `crates/syntra-sc1-transport/tests/wss.rs` run outside this container suite.
TCP/WS fixture results cannot establish WSS/TLS coverage.

The prior successful run below is historical local-revision-1 evidence, not
proof of the canonical context, WSS feature split or runtime emission gate.
The exact public context/prologue fixtures are encoding examples only, not
independent cryptographic vectors. Upstream acceptance is complete. Remaining
release requirements include formal conformance, independent pure-Go/Rust
interoperability in both roles and modes, recovery and mobile validation, and
independent security review. Formal conformance has not been executed. Browser
SC1 is not added, and production FFI remains a separate state machine rather
than automatically an SC1 SDK.

## Running the fixture suite

This is a separate test crate with a **running Docker daemon** requirement.
The root library retains its own toolchain and has no Testcontainers/Docker
dependency. The fixture peer builds from the current worktree, including
uncommitted production changes.

From the repository root:

```sh
export RUSTUP_TOOLCHAIN=1.88.0

# Compile the test package and the fixture without contacting Docker:
cargo test -p syntra-integration --no-run
cargo build -p syntra-integration --bin peer

# Run the real suite (missing/unhealthy Docker FAILS; it never skips unless
# SYNTRA_INTEGRATION_REQUIRE_DOCKER is unset and no daemon is reachable):
cargo test -p syntra-integration --test sc1_containers -- --ignored --nocapture

# Narrow to the container suite while still requiring Docker:
SYNTRA_INTEGRATION_REQUIRE_DOCKER=1 cargo test -p syntra-integration --test sc1_containers -- --ignored --nocapture
```

The fixture image builds with the pinned `rust:1.88-bookworm` builder from
the repository root context (`Dockerfile` is inline in the test via
`GenericBuildableImage`), then reuses the built peer for TCP and WS groups.
Each test opens its own connections. Peers are torn down with the
container. Mapped endpoints are rediscovered rather than assumed stable.

## Current fixture targets (container execution outstanding)

The consolidated development adapters are `syntra_sc1_transport::tcp` and
`syntra_sc1_transport::websocket`, using the shared root handles and runtime
`Initiator`/`Host` sessions. The opt-in reconnecting client's lifecycle contract
is documented [separately](../../SC1.md#reconnecting-client). This container
fixture does not exercise that wrapper. WSS uses
`websocket::connect`/`connect_with_roots`, `TlsServerSettings::new` and
`accept_tls_stream`; see the [source-backed API sketch](../../SC1.md#api-sketch).

The migrated source targets the following **TCP and WS bootstrap** cases.
These are compiled test intentions, not a recorded current Docker execution:

- Structured listener-bound readiness followed by real SC1 handshake,
  confirmed ClientHello/ServerReady and echo RPC; port readiness alone
  cannot pass.
- TCP: empty and 1 KiB echoes, one authorization denial
  (`/test.Denied/Denied`, observed as `PermissionDenied`), and eight
  concurrent 2 KiB echo callers with independent payload checks over the
  same connection.
- WS: a single 1 KiB echo RPC over the mapped port.
- Closing the client after the suite; the peer is torn down with the
  container.

HTTP/HTTPS are not protocol test targets; HTTP is used only as the WS
upgrade mechanism. UDP and browser SC1 are excluded. This suite does not
yet cover packet-level tampering, malformed-record fuzzing, enrollment
revocation, automatic reconnection/backoff, or exhaustive fault
combinations. A container round trip through the same Noise library is not
independent cross-language SC1 interoperability or a security audit.

## Logs and CI

Set `RUST_LOG=debug` for pump-level diagnostics. Provisioning keys are
generated per test run and passed to the container as environment; the
fixture prints structured lifecycle events and neutral call tokens only.
No private keys or credentials appear in retained logs.

`.github/workflows/integration.yml` runs on a Docker-capable Ubuntu runner
and executes the ignored test explicitly. It is a separate check; branch
protection must require `Integration / integration` if integration should
gate merging.

`.github/workflows/benchmarks.yml` runs the in-memory benchmark suite with
Criterion smoke/reporting settings; timing is report-only and no container
or baseline comparison gate is used.

## Historical local verification (pre-consolidation)

Recorded before this migration on 2026-10-29: Docker Desktop on darwin/arm64,
Rust 1.88.0 host toolchain, the then-current worktree (no immutable revision
recorded here). This is not a run against the current consolidated crate.

```text
cargo test -p syntra-integration --test sc1_containers -- --ignored --nocapture
test sc1_tcp_and_ws_over_containers ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 18.29s
```

That run built the container, started it, printed both readiness lines, and
completed SC1 handshakes and echo (including concurrent callers), denial,
wrong-key and WebSocket cases with no skips. An earlier macOS failure — handshake
completed, then transport loss on the first RPC — was a fixture bug: the
peer spawned a detached waiter touching only `h.host`, so disjoint
async-block capture moved just the `Arc<Host>` and dropped the rest of the
`HostHandle` (including its pump) at the end of the accept-loop iteration.
Retaining whole handles in the accept loop fixed it; see
[AUDIT.md](../../AUDIT.md). The Linux container lane remains authoritative.
Bounded build/container logs were retained through the test output above.
