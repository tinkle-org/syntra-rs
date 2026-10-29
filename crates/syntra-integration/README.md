# SC1 container integration tests

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

## Coverage

Both production adapters (`syntra-tcp` and `syntra-ws-sc1`) are used
directly with root `Initiator`/`Host` sessions. There is no dependency on a
high-level connection wrapper.

For **TCP and WS**, in **bootstrap** mode:

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

## Local verification status

Latest run: 2026-10-29, Docker Desktop on darwin/arm64, Rust 1.88.0 host
toolchain, current worktree.

```text
cargo test -p syntra-integration --test sc1_containers -- --ignored --nocapture
test sc1_tcp_and_ws_over_containers ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 18.29s
```

The container builds, starts, prints both readiness lines, completes SC1
handshakes and echo (including concurrent callers), denial, wrong-key and
WebSocket cases with no skips. An earlier macOS failure — handshake
completed, then transport loss on the first RPC — was a fixture bug: the
peer spawned a detached waiter touching only `h.host`, so disjoint
async-block capture moved just the `Arc<Host>` and dropped the rest of the
`HostHandle` (including its pump) at the end of the accept-loop iteration.
Retaining whole handles in the accept loop fixed it; see
[AUDIT.md](../../AUDIT.md). The Linux container lane remains authoritative.
Bounded build/container logs were retained through the test output above.
