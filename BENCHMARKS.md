# Wire, session and connection benchmarks

Use **Rust 1.89.0** for current benchmarks and the current CI configuration,
selecting it with `export RUSTUP_TOOLCHAIN=1.89.0`. The crate MSRV floor of 1.89
is a build compatibility constraint; production binaries need a security-patched
toolchain.
Benchmarks use Criterion 0.5 with `--bench` targets and report timing plus
throughput. Root benchmarks require no Docker. Session cases exercise the
linked Tokio runtime; channel and transport cases exercise local Syntra 1.0
record protection.

Transport cases live in `syntra-net`. Its `pipe` bench
requires `tcp` and uses in-memory duplex I/O. Default features enable no socket
carrier. `websocket` supplies framing/upgrade without a production TLS
implementation; `tls-rustls` adds optional WSS convenience APIs. `managed`,
`proxy`, `reconnect` and candidate `http` HTTP/HTTPS connections are
explicit opt-ins. Pipe timings cover no managed WS/WSS listeners, route selection,
HTTP/HTTPS connections or raw adapters, TLS/provider composition, managed runtime,
proxies or reconnect behavior. Candidate full-RPC tests are separate from these
timings and do not establish RFC0013 adoption, completed review or conformance. See
[CONNECTION.md](CONNECTION.md) for encryption and connection guidance. These local
harnesses do not establish operational budgets or real-device/network results.
Retain the implementation revision and dirty-worktree state with measurements.
The [candidate record](protocol-contract.json) pins committed candidate inputs;
benchmark success does not authorize publication or satisfy the formal-conformance gate in
[implementation evidence](CONTRIBUTING.md#implementation-evidence).

## Cases and accounting

- `syntra-core/frame_codec` scans, decodes and encodes requests with empty,
  64B, 1KiB and 64KiB payloads. Notification/result round-trip fixtures cap
  payloads at 1KiB. The near-limit request payload is `1_048_448 - 128`
  (1,048,320 bytes), below the 1MiB frame limit including its envelope.
  Fixture creation happens outside timing. `Throughput::Bytes` is set from
  each request's serialized size (and the near-limit request's size); the
  notification/result cases inherit that setting rather than measuring their
  own byte counts. Scans skip opaque contents: their MB/s is logical envelope
  throughput, not memory bandwidth.
- `syntra-core/channel` measures canonical context encoding and
  parsing, full NK bootstrap handshakes plus one client-to-server verified
  record, and returning-mode warm record encrypt/decrypt pairs at 64, 1,024
  and 65,519 plaintext bytes. Nonces advance without reset; payload comparison
  happens inside timing. See the setup/allocation boundaries below.
- `syntra-net/pipe` measures preallocated u16 carrier-prefix and u32
  frame-prefix writes without socket or crypto work, plus serial encrypted
  echo RPCs over in-memory duplex streams. Handshake and fixture allocation
  are outside timing for header cases; establishment and echo payload
  verification are timed for pipe cases. `Throughput::Bytes` counts twice
  the application payload length for echo (both directions), excluding envelopes,
  encrypted prefixes, tags and carrier overhead.

Session shutdown cancels pumps and joins with bounded budgets before releasing
transports. RPCs use five-second budgets. No pooling is introduced.

### Channel and transport cases

These names describe functions in the benchmark source. Criterion currently
groups channel cases under `connection`, pipe prefix/echo cases under `tcp`,
and pipe establishment under `connection`.

- `channel::append_context` times `Context::encode`, including allocation;
  `channel::parse_context` times parsing a prebuilt M1-sized public wrapper,
  including owned scope reconstruction and validation. The parser suffix is
  dummy bytes, not a Noise vector. `Throughput::Bytes` counts context bytes.
- `channel::handshake_bootstrap` times a full NK handshake with real OS
  randomness and server-key/config setup inside timing, followed by one
  client-to-server encrypted record and payload comparison. Channel destruction
  is included; there is no measured server-to-client confirmation record.
- `channel::record_warm/*` measures one returning-mode client-to-server
  encrypt/decrypt pair at 64, 1,024 and 65,519 plaintext bytes. Cipher setup,
  the initial confirmation record and payload allocation are outside timing.
  Returned ciphertext/plaintext buffer allocations and payload comparison are
  inside timing; nonces advance without reset. `Throughput::Bytes` counts one
  plaintext length per complete pair.
- `pipe::prefix_u16_preallocated` and `pipe::prefix_u32_preallocated` measure
  preallocated carrier-prefix writes without socket or crypto work.
- `pipe::duplex_echo/{64,1024,65536}` sends/reassembles frames through the
  shared encrypted pump over `tokio::io::duplex`. Each timed
  iteration includes server-key/config and duplex setup, returning-mode protection,
  Syntra readiness, one echo RPC, payload comparison and bounded teardown.
  The initial payload and Tokio runtime are created outside timing; the per-call
  payload clone is inside timing. This is in-process carrier work, not a network
  deployment benchmark.
- `pipe::establishment_duplex` times the complete duplex lifecycle, from
  server-key/config and duplex setup through returning-mode channel handshake,
  Syntra readiness and teardown. It sends no application RPC.

## Targeted checks

These selectors execute the three benchmark harnesses:

```sh
cargo bench --locked -p syntra-core --bench frame_codec -- --test
cargo bench --locked -p syntra-core --bench channel -- --test
cargo bench --locked -p syntra-net --no-default-features --features tcp --bench pipe -- --test
```

To smoke-test every benchmark in the workspace:

```sh
cargo bench --locked --workspace --features syntra-net/tcp -- --test
```

## Benchmark workflow

`.github/workflows/benchmarks.yml` uses Rust 1.89.0 and runs the three
Criterion benchmark targets with short report-only settings (the compile
step still covers every bench target with the harness-neutral `--test`
selector, since Criterion timing flags are rejected by the default libtest
harness):

```sh
cargo bench --locked -p syntra-core --bench frame_codec -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
cargo bench --locked -p syntra-core --bench channel -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
cargo bench --locked -p syntra-net --no-default-features --features tcp --bench pipe -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
```

The artifact records raw samples, source revision and toolchain. Timing is
report-only: no fixed ns/op threshold or automatic baseline-comparison gate
is used; execution errors still fail the job.

## Comparing changes

Use the same benchmark harness, Rust version, build profile and fixture sizes
for both revisions. Keep setup and measurement boundaries identical. On an
otherwise idle, externally powered host, collect at least ten samples per
revision, preferably interleaving before/after runs. The short CI samples are
smoke/reporting evidence, not a statistically significant performance claim.

```sh
cargo bench -p syntra-core --bench frame_codec -- --save-baseline main
# After changes:
cargo bench -p syntra-core --bench frame_codec -- --baseline main
```

Inspect both timing and allocation behavior before introducing pools.
Full Protobuf decoding owns messages and byte fields; zero-allocation header
scanning does not mean full decoding or RPC dispatch is allocation-free.
Do not trade buffer ownership, authentication, or nonce safety for a lower
allocation count.

Socket macrobenchmarks belong on dedicated hardware, outside shared-runner
timing gates. Record OS, CPU, toolchain, payload distribution, parallelism
and repeated-run distributions. These in-memory benchmarks are not end-to-end
network measurements.
