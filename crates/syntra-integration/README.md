# Syntra container integration tests

## Scope

`syntra-integration` is an unpublished Docker fixture peer and connectivity
test package. Its current harness is `tests/syntra_containers.rs`. Maintain
the peer and its tests together; a successful run is same-implementation
connectivity evidence, not a conformance verdict.

The peer and tests use `syntra_transport::{tcp, websocket}`. Core owns message
mechanics and record protection through `syntra_core::secure_channel`; runtime
scheduling and native I/O remain separate responsibilities. Transport defaults enable no
sockets; this package explicitly selects `tcp` and `websocket`. Reconnection
requires a separate `reconnect` opt-in and is not exercised here.

The WS endpoint is `/syntra/1.0/ws` (`websocket::ENDPOINT_PATH`) with exact
subprotocol `syntra.1.0`. The harness dials mapped ports on `127.0.0.1` to meet
the WS dial restriction. Both TCP and WS carry Syntra encrypted records;
the WebSocket fixture has no outer TLS. See [CONNECTION.md](../../CONNECTION.md) for
encryption and connection guidance. Native encrypted TCP is also a production
carrier; the WS dial restriction applies specifically to WS.

The four root `default-members` are `syntra-core`, `syntra-runtime`,
`syntra-transport` and `syntra-ffi`, excluding only `syntra-web` and
`syntra-integration` from the six-member workspace. Explicit `--workspace` includes
them and unifies this package's carrier features into `syntra-transport`. Test the transport's
`--no-default-features` configuration separately for default isolation.
WSS tests in `crates/syntra-transport/tests/wss.rs` are outside this Docker
suite and require `websocket`. Protected browser WSS has its own
[procedures](../syntra-web/tests/browser.md). TCP/WS fixture results do not
establish TLS, browser, independent cryptographic-vector or cross-language
interoperability coverage.

Record the peer revision, dirty-worktree state and actual carrier/mode results
when executing the suite.
The [unified implementation-evidence runner](../../CONTRIBUTING.md#implementation-evidence)
has separate supplemental lanes; it does not run this Docker suite. Preserve each
result's execution scope and candidate provenance. The candidate record now pins
committed inputs; that pin does not turn fixture execution into formal conformance.

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

# Run the fixture suite (without the require variable, unavailable Docker skips):
cargo test -p syntra-integration --test syntra_containers -- --ignored --nocapture

# Narrow to the container suite while still requiring Docker:
SYNTRA_INTEGRATION_REQUIRE_DOCKER=1 cargo test -p syntra-integration --test syntra_containers -- --ignored --nocapture
```

The optional-Docker path returns success after printing its skip message;
a green Cargo result on that path is not proof that containers ran.

The fixture image builds with the pinned `rust:1.88-bookworm` builder from
the repository root context (`Dockerfile` is inline in the test via
`GenericBuildableImage`), then reuses the built peer for TCP and WS groups.
Each test opens its own connections. Peers are torn down with the
container. Mapped endpoints are rediscovered rather than assumed stable.

## Fixture targets

The adapters are `syntra_transport::tcp` and `syntra_transport::websocket`,
using shared transport handles and runtime `Initiator`/`Host` sessions.
The opt-in reconnecting client's lifecycle contract is documented in
[CONNECTION.md](../../CONNECTION.md). This container fixture does not exercise
that wrapper. Separate WSS tests use
`websocket::connect`/`connect_with_roots`, `TlsServerSettings::new` and
`accept_tls_stream` with `Carrier::SecureWebSocket`.

The current source targets the following **TCP and WS bootstrap** cases.
This list describes test code, not a recorded current Docker execution:

- Listener-bound readiness messages followed by a protected Syntra handshake,
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
upgrade mechanism. UDP and browser connections are excluded. This suite does not
yet cover packet-level tampering, malformed-record fuzzing, enrollment
revocation, automatic reconnection/backoff, or exhaustive fault
combinations. A container round trip through the same Noise library is not
independent cross-language Syntra interoperability or a security audit.

## Logs and CI

Set `RUST_LOG=debug` for pump-level diagnostics. Provisioning keys are
generated per test run and passed to the container as environment; the
fixture prints readiness, handshake and handler diagnostics. Review captured
output before retaining it, and keep provisioning keys and credentials out of
published logs.

`.github/workflows/integration.yml` runs on a Docker-capable Ubuntu runner
and executes the ignored harnesses explicitly with
`cargo test --locked -p syntra-integration --test '*' -- --ignored --nocapture`,
with `SYNTRA_INTEGRATION_REQUIRE_DOCKER=1`. It is a separate check; branch
protection must require `Integration / integration` if integration should
gate merging.

`.github/workflows/benchmarks.yml` runs the in-memory benchmark suite with
Criterion smoke/reporting settings; timing is report-only and no container
or baseline comparison gate is used.
