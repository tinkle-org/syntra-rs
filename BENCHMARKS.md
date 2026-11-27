# Wire, session and connection benchmarks

Use **Rust 1.89.0** for current benchmarks and the current CI configuration,
selecting it with `export RUSTUP_TOOLCHAIN=1.89.0`. The crate MSRV floor of 1.89
is a build compatibility constraint; production binaries need a security-patched
toolchain.
Benchmarks use the locked Criterion 0.8 with `--bench` targets and report timing plus
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
timings. See
[CONNECTION.md](CONNECTION.md) for encryption and connection guidance. These local
harnesses do not establish operational budgets or real-device/network results.
Retain the implementation revision and dirty-worktree state with measurements.

## Cases and accounting

- `syntra-core/frame_codec` scans, decodes and encodes requests with empty,
  64B, 1KiB and 64KiB payloads. Notification/result round-trip fixtures cap
  payloads at 1KiB. The near-limit request payload is `1_048_448 - 128`
  (1,048,320 bytes), below the 1MiB frame limit including its envelope.
  `frame/roundtrip_request/{0,1048320}` decodes and re-encodes a prebuilt
  request, including validation, owned buffers and destruction. Byte equality
  is checked outside timing. Each frame case counts one serialized envelope
  per operation, not the sum of reads and writes. Fixture creation is untimed.
  Scans skip opaque contents: their MB/s is logical envelope
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
- `channel::handshake_bootstrap` uses batched setup: server-key/config creation
  and client handshake start are untimed. It times the response and client finish, then one
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

## Main-push CPU baseline

When source or build inputs change on `main`, `benchmarks.yml` checks out the
SHA before the push (not `HEAD^`) and the pushed SHA on one
`blacksmith-4vcpu-ubuntu-2404-arm` runner. Both builds use default features,
the optimized bench profile, Rust 1.89.0 and each revision's lockfile. On the
introducing push only, it copies the measurement harnesses into the old checkout
and measures that same revision twice to check noise on the actual runner.
Thereafter each harness compiles against its own codec; keep the five workloads
and timing boundaries stable across comparisons. No prior artifact is needed.
If the push creates `main`, the job skips because there is no previous tip.
An incompatible build, missing case, or unreadable comparison fails the job.

The gate covers only the two request round trips and three warm records above.
Each gets 0.5 s warmup, 1 s measurement and 30 samples on each side. CI builds
both revisions with symbols stripped and records each benchmark executable's
SHA-256 in `comparison.txt`. These workloads use in-memory fixtures. If an
executable is byte-identical across checkouts, its timings are still collected
and validated, but a timing difference cannot be attributed to the push. The
same-tree calibration still checks for noise even with identical executables.

For changed executables the decision uses Criterion's two-sided 95% bootstrap
interval for the relative change in **mean time per operation** (new/old − 1), not throughput or a
tail-latency percentile. Only a lower bound **strictly above +10%** triggers
a second fresh old/new pair. The same case must cross that bound twice to
fail for regression. Review the raw samples before attributing a slowdown.

`bench_allocations` runs separately for each checkout. It reports allocation,
zeroed-allocation and reallocation calls combined per operation on the executing
thread. Fixture construction, handshake RNG, session teardown and reporting
are excluded; the timed benchmarks never install the counting allocator.
Counts are diagnostic, not a timing threshold. Artifacts retain both revisions,
worktree status, runner/toolchain, counts, samples and intervals for 14 days.

To reproduce an unchanged comparison locally, start with a fresh output directory:

```sh
cargo test --locked --release -p syntra-core --test bench_allocations -- --ignored --nocapture
python3 scripts/benchmark_baseline.py . . "$(mktemp -d)"
python3 -m unittest scripts.tests.test_benchmark_baseline
```

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
Measure full frame decoding separately from header scanning; a scan does not
account for buffer ownership or RPC dispatch.
Do not trade buffer ownership, authentication, or nonce safety for a lower
allocation count.

Socket macrobenchmarks belong on dedicated hardware, outside shared-runner
timing gates. Record OS, CPU, toolchain, payload distribution, parallelism
and repeated-run distributions. These in-memory benchmarks are not end-to-end
network measurements.
