# Syntra container integration tests

## Scope

`syntra-integration` is an unpublished Docker fixture peer and connectivity
test package. Its current harness is `tests/syntra_containers.rs`. Maintain
the peer and its tests together; a successful run is same-implementation
connectivity evidence, not a conformance verdict.

The peer and tests use `syntra_net::{tcp, websocket}`. Core owns message
mechanics and record protection through `syntra_core::secure_channel`; runtime
scheduling and native I/O remain separate responsibilities. Transport defaults enable no
sockets; this package explicitly selects `tcp` and `websocket` for framing/upgrade,
with no production TLS implementation dependency. `tls-rustls` is the optional
rustls WSS convenience feature. Managed networking (`managed`), proxy helpers
(`proxy`) and reconnection (`reconnect`) have separate net-crate regressions.
`network_websocket` covers managed loopback WS/application-provider WSS listeners;
`routes` covers explicit allowlisted endpoint composition. CI selects both
`managed,websocket,proxy` and `managed,tls-rustls,proxy` for those targets.
Candidate HTTP/HTTPS uses `http_connections`, `network_http` and `routes` with
`managed,http,proxy`, plus a separate `managed,http,websocket,proxy` combination.
These are native test lanes, outside this TCP/WS Docker fixture.

The WS endpoint is `/syntra/1.0/ws` (`websocket::ENDPOINT_PATH`) with exact
subprotocol `syntra.1.0`. The harness dials mapped ports on `127.0.0.1` to meet
the WS dial restriction. Both TCP and WS carry Syntra encrypted records;
the WebSocket fixture has no outer TLS. See [CONNECTION.md](../../CONNECTION.md) for
encryption and connection guidance. Native encrypted TCP is also a production
carrier; the WS dial restriction applies specifically to WS.

The four root `default-members` are `syntra-core`, `syntra-runtime`,
`syntra-net` and `syntra-ffi`. The five-member workspace additionally includes
`syntra-integration`; explicit `--workspace` unifies this package's carrier features
into `syntra-net`. Test the net crate's
`--no-default-features` configuration separately for default isolation.
WSS tests in `crates/syntra-net/tests/wss.rs` are outside this Docker
suite and require `tls-rustls`; `recovery_wss` also needs `reconnect`.
The `tls_provider` suite uses `websocket` with a real test TLS provider supplied
through dev dependencies. The provider is trusted application code responsible
for real certificate chain/hostname/time/current-policy checks; metadata checks
alone do not establish that it performed TLS. TCP/WS fixture results do not
establish TLS, browser, independent cryptographic-vector or cross-language
interoperability coverage.

Record the peer revision, dirty-worktree state and actual carrier/mode results
when executing the suite.
The [unified implementation-evidence runner](../../CONTRIBUTING.md#implementation-evidence)
has separate supplemental lanes; it does not run this Docker suite. Preserve each
result's execution scope and candidate provenance. The candidate record pins
committed inputs; that pin does not turn fixture execution into formal conformance.

## Running the fixture suite

This is a separate test crate requiring the **Docker CLI and a running local
Docker daemon**. The harness invokes the CLI directly; it has no Testcontainers
dependency. Remote Docker hosts are not supported: mapped ports are dialed on
the local loopback interface.
The root library retains its own toolchain and has no Testcontainers/Docker
dependency. The fixture peer builds from the current worktree, including
uncommitted production changes.

From the repository root:

```sh
export RUSTUP_TOOLCHAIN=1.88.0

# Compile the test package and the fixture without contacting Docker:
cargo test -p syntra-integration --no-run
cargo build -p syntra-integration --bin peer

# Run port/readiness and injected CLI/cleanup regressions without Docker:
cargo test --locked -p syntra-integration --test syntra_containers

# Run the fixture suite (without the require variable, unavailable Docker skips):
cargo test -p syntra-integration --test syntra_containers -- --ignored --nocapture

# Narrow to the container suite while still requiring Docker:
SYNTRA_INTEGRATION_REQUIRE_DOCKER=1 cargo test -p syntra-integration --test syntra_containers -- --ignored --nocapture
```

The optional-Docker path returns success after printing its skip message;
a green Cargo result on that path is not proof that containers ran.

The fixture image builds with the pinned `rust:1.88-bookworm` builder from
the repository root context using this crate's `Dockerfile`, then reuses the
built peer for TCP and WS groups. The root `.dockerignore` whitelists only
workspace manifests, the lockfile and crate Rust sources; `.git`, `target`,
environment files and other local files are excluded from the context.
Each test opens its own connections. Peers are torn down with the
container. The CLI creates a uniquely named container before starting it and
publishes both ports dynamically on `127.0.0.1` only. Mapped endpoints are
rediscovered rather than assumed stable. Both actual `peer tcp ready on ...`
and `peer ws ready on ...` log lines are required before protocol checks.

Docker commands have a 10-second budget (image build: 10 minutes); readiness
has one 30-second budget. Timed-out CLI children are killed, with a bounded
kill/reap wait. Cleanup ownership starts before `docker create`, including
create/start errors and assertion panics. Successful tests await forced removal;
on failure/unwind the guard collects the last 100 log lines and attempts forced
removal on a separate, joined executor. Cleanup failures are reported with the
container name, never silently treated as success. An unreachable daemon or
external process termination can prevent cleanup; inspect/remove the reported
container manually in that case. The generated private key is inherited by
`docker create` through an environment-variable name, not placed in argv, and
is redacted from diagnostics. As with other Docker environment provisioning,
daemon administrators can inspect container configuration.

Non-Docker regressions exercise strict loopback port parsing, both readiness
markers and (on Unix) injected command failures, timeout, redaction, explicit
removal and panic cleanup. They do not stand in for real Docker execution.

## Fixture targets

The adapters are `syntra_net::tcp` and `syntra_net::websocket`,
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

The separate `http` opt-in supplies candidate HTTP/HTTPS Noise/hello-ready/RPC
connections and a bounded listener/association registry, alongside raw codec/pair
APIs. `managed,http` owns the listener run through `ManagedHttpServer`; candidate
routes include direct, SOCKS5/CONNECT and real HTTP forward requests. HTTPS uses
application TLS on both streams without a production TLS implementation dependency.
Raw `http_records` tests remain distinct from the full-connection lanes.
RFC0013 is Draft upstream; this candidate remains under resource review, without
carrier registration, approval, accepted-spec shipping status or conformance claims.
HTTP also supports WS upgrade and CONNECT tunneling. `HttpForwardTarget` alone is
metadata; the explicit candidate `Route::HttpForward` sends forward requests.
UDP and browser connections are excluded. This suite does not
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
