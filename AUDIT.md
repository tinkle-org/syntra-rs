# Implementation audit notes

This is an implementation review and evidence ledger for
`feat/sc1-connectivity-and-benchmarks`. It is **not an independent security
audit, certification or complete conformance report**. Findings below describe
source and regression coverage; passing local tests does not establish
absence of vulnerabilities.

## Final working-tree verification

The following passed on `feat/sc1-connectivity-and-benchmarks`, using Rust
1.88.0 on darwin/arm64 unless another lane is named:

- Locked workspace tests, including the new `syntra-secure-channel`,
  `syntra-tcp` and `syntra-integration` members: `cargo test --locked
  --workspace` passed with no failures and one ignored test (the Docker
  container suite, which runs in the integration job).
- Actual Docker container integration across TCP and WS in bootstrap mode,
  including echo, concurrency, denial and wrong-key handling, passed on
  macOS Docker Desktop in 18 seconds with no skipped container cases.
- Production and test-fixture FFI suites plus the C build contract, each in a
  separate invocation with no `--all-features`: production (13 tests),
  test-fixture (11 tests) and `build_contract.py` (5 checks, including both C
  smoke programs, feature isolation, no-default ABI checks and WASM
  rejection) all passed.
- `cargo fmt --all -- --check` passed for the feature tree.
- Locked WASM compile check for the non-FFI crates
  (`syntra-core`, `syntra-runtime`, `syntra-ws`, `syntra-web`) on
  `wasm32-unknown-unknown` passed; execution still requires the opt-in
  real-browser fixture.
- All in-memory Criterion benchmarks smoke-ran (`--test` selectors) for
  `frame_codec`, `channel` and `pipe`.
- `cargo deny --locked check` and `cargo audit --deny warnings` passed with
  the pinned tool versions.
- `git diff --check` passed.

Clippy reports the inherited baseline warnings documented in `docs/ci.md`;
the strict `-D warnings` lane stays informational until that cleanup lands.
No `allow` suppressions were added for new code.

The container suite (`syntra-integration/tests/sc1_containers.rs`) is
ignored by workspace runs and executes only in the integration job or on
explicit request. The latest macOS Docker Desktop run completed the image
build, container start, SC1 handshakes and echo, concurrency, denial and
wrong-key cases for both TCP and WS with no skipped container cases. The
Linux container lane remains the authoritative gate; see the remaining
findings below.

## Authority and source pins

- Upstream specification review reference:
  [`tinkle-org/syntra@e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02).
  RFC 0007 and the secure-channel/device-authorization companion documents
  are drafts. [SC1.md](SC1.md) records this implementation's exact local
  revision 1 domain, context encoding and carrier choices; upstream
  acceptance is pending.
- Schema/fixture provenance: [MIGRATION.md](MIGRATION.md), including the
  immutable source snapshot at `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`.
- SC1 cryptography: `snow =0.10.0` with its standard providers, `getrandom
  0.3`, `zeroize 1`. Native adapters use Tokio 1 with the existing
  Tungstenite 0.26/rustls 0.23 stack. No new network dependency enters the
  channel or protocol core. Current CI and recommended production toolchain:
  **Rust 1.88.0**. The 1.88 MSRV floor establishes build compatibility
  only, not production security. Production binaries require a
  security-patched toolchain and standard library.

The specification pin, schema snapshot and native implementation pins
serve different purposes. Wire agreement is not behavioral conformance, and
the container round trip does not provide independent cross-language SC1
interoperability.

## Completed implementation reviews

"Completed" identifies the stated local review/fix and its regression
evidence. It does not close the broader TODOs listed below.

| Area | Reviewed behavior | Evidence |
| --- | --- | --- |
| SC1 channel and context boundary | Exact local context bytes, NK/NKpsk0 suite selection, wrong keys/contexts, empty handshake payloads, replayed M1 without fresh confirmation, record ordering/failure/limits and redacted key formatting. | `syntra-secure-channel`, `channel allocation/entropy/handshake/record tests` |
| Ordered carrier boundary | Prefixes across records, coalesced frames, absolute frame clocks, admission limits, cancellation, lifetime and confirmed-peer rechecks. | `syntra-tcp/src/pump.rs`, pump tests including lifetime/confirmation/batch-backpressure deadlines and close-watch handling |
| TCP and WS/SC1 binding | TCP short writes, coalescing, partial record deadlines and real sockets; WS binary-message boundaries, fragmentation, origin/subprotocol rejection. | `syntra-tcp/tests/connectivity.rs`, `syntra-ws/tests/sc1.rs`, `syntra-ws/tests/websocket_vectors.rs` |
| Runtime correlation and lifecycle | Malformed correlated results settle only their RPC; handshake frames and version mismatches in ACTIVE close immediately; structural faults never become semantic RPC errors. | `crates/syntra-runtime/tests/runtime_defects.rs` |
| Graceful drain and withdrawal | Draining tolerates queued notifications; withdrawal is resumable across cancellation; graceful close waits for inflight RPCs and pending withdrawal terminals. | `runtime_defects.rs`: drain-tolerates-notifications, cancelled-withdrawal retry, graceful-waits-for-withdrawal regressions |
| Production FFI correctness | Normal host answers queue success and error results; bounded outbound admission before retiring pending work; stale dispatch entries cleared; output pointers validated before mutation; CSPRNG connection IDs. | `crates/syntra-ffi` production tests and `production_smoke.c` complete request/take/answer/outbound/client round trips |
| Codec emission and decode | Reserved top-level tags cannot be emitted; body/outcome multiplicity and malformed unknown wire data rejected; credential/frame sizes bounded; opaque payloads untouched. | `syntra-core`, `codec_vectors.rs`, `encode_allocation.rs` |
| Benchmark and container harness | In-memory Criterion benches for codec, channel and pipe paths; Testcontainers SC1 TCP/WS peer with echo, concurrency, denial and wrong-key coverage. | `BENCHMARKS.md`, `crates/syntra-integration/` |

Test names abbreviated after the first name retain that row's file prefix.
Coverage is local unit/integration evidence, not a result from an external
reviewer.

## Remaining gaps and audited TODOs

### Container fixture handle retention

During development the container suite completed the SC1 handshake inside
the container, then observed transport loss on the first RPC on both sides
with `UnexpectedEof` on the client read, while loopback TCP with identical
code paths passed. The cause was fixture-side, not framing or Docker
networking: the peer accepted each connection and then spawned a detached
waiter task that only touched `h.host`, so Rust's disjoint async-block
capture moved only the `Arc<Host>` field into the waiter future and dropped
the rest of the `HostHandle` — including its `Pump` — at the end of the
accept-loop iteration. Dropping the pump is an intentional abort; the owner
tore the connection down and both sides reported transport loss. Retaining
whole handles in the peer accept loop fixed it, and the suite passes on
macOS Docker Desktop. Detached waiters that only borrow a sub-path of a
connection handle must not be used; the `Listener`/`accept` examples in
[SC1.md](SC1.md#api-sketch) retain the handle. The Linux container lane in
`.github/workflows/integration.yml` remains the authoritative gate.

### Enrollment issuance, revocation and rotation

Only explicit authenticated out-of-band provisioning is supported. Generate
the 32-byte authorization key with `Enrollment::generate` and an independent
random eight-byte handle; check handle collisions in the scoped store.
`KeyStore::lookup` is host-owned and must honor cancellation. There is no
enrollment RPC, atomic issuance/delivery/ack recovery, client storage
implementation, or complete key-rotation workflow. Hosts must check current
enrollment and separately verified identity before `ready`, then check
current method policy on every call. Revocation propagation has no bound
beyond the lookup path; the one-second-style periodic recheck used by the
sibling Go implementation is not implemented here.

### Browser SC1 and UDP

Browser SC1 is not implemented; the WASM adapter documents its platform
limits. UDP has no binding: no datagram mapping, counters, replay window,
path validation, anti-amplification, reliability or fragmentation is
specified. Do not describe either as supported.

### Memory erasure and FFI ABI gaps

`Secret32`, record scratch and parser staging use zeroizing storage, and the
Snow resolver overwrites retained DH and cipher keys before destruction.
Snow 0.10.0 exposes no erasure interface for its internal chaining key,
handshake/KDF temporaries or PSK construction copies. Rust moves, allocator
copies, runtime-owned protobuf credentials, application stores and caller
copies are outside a complete erasure guarantee. The production FFI keeps
its own state machine; completion-generation tokens remain deferred, so
request IDs must stay distinct for the connection lifetime to prevent stale
completions targeting reused IDs.

### Fuzz and long-horizon campaigns

Fuzz and sanitizer campaigns are scheduled/manual only, never required PR
checks. No checked-in fuzz targets, property-testing harness, Loom or Miri
runs cover the new channel, pump or FFI paths. Coverage reporting stays
informational with no threshold.
