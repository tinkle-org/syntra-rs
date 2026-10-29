# Wire, session and SC1 benchmarks

Use **Rust 1.88.0** for current benchmarks, CI and production builds, selecting
it with `export RUSTUP_TOOLCHAIN=1.88.0`. The crate MSRV floor of 1.88 is a
build compatibility constraint, not a secure-runtime recommendation.
Benchmarks use Criterion 0.5 with `--bench` targets and report timing plus
throughput. Root benchmarks require no Docker. Session cases exercise the
linked Tokio runtime; securechannel and transport cases exercise the local
SC1 implementation.

## Cases and accounting

- `syntra-core/frame_codec` uses validated hello, ready, error and cancel
  fixtures, plus request, success and notification fixtures at empty, 64B,
  1KiB and 64KiB payload sizes, plus a near-limit request at
  `MaxFrameBytes - 128` (1,048,448 bytes). Serialized envelopes remain below
  the 1MiB limit. Fixture creation happens outside timing.
  `Throughput::Bytes` is the actual serialized size. Scans skip opaque byte
  contents: their MB/s is logical envelope throughput, not memory bandwidth.
- `syntra-secure-channel/channel` measures canonical context append and parse,
  plus full NK bootstrap handshakes with one verified record in each
  direction, and warm record encrypt/decrypt pairs at 64, 1,024 and 65,519
  plaintext bytes with buffer reuse outside timing. Nonce state advances
  without reset. Payload comparison happens inside timing to keep the
  optimizer honest; provisioning and cipher setup remain outside.
- `syntra-tcp/pipe` measures preallocated u16 carrier-prefix and u32
  frame-prefix writes without socket or crypto work, plus serial encrypted
  echo RPCs over in-memory duplex streams. Handshake and fixture allocation
  are outside timing for header cases; establishment and echo payload
  verification are timed for pipe cases. `Throughput::Bytes` counts twice
  the application-frame length for echo (both directions).

Session shutdown cancels pumps and joins with bounded budgets before releasing
transports. RPCs use five-second budgets. No pooling is introduced.

### SC1 and transport cases

- `channel::append_context` and `channel::parse_context` time the exact
  canonical context bytes into preallocated storage; `Throughput::Bytes`
  counts context bytes. Fixture setup and the final canonical-byte comparison
  are outside timing.
- `channel::handshake_bootstrap` times a full NK handshake with real OS
  randomness, one verified record in each direction, and channel close.
  Static provisioning fixtures are outside timing.
- `channel::record_warm/*` measures one encrypt/decrypt pair for bootstrap
  and returning modes, both directions, at 64, 1,024 and 65,519 plaintext
  bytes. Cipher setup and one warmup pair are outside timing. Buffers are
  reused, nonces advance without reset, and final payload/nonce checks happen
  outside timing. `Throughput::Bytes` counts one plaintext length per
  complete pair.
- `pipe::prefix_u16_preallocated` and `pipe::prefix_u32_preallocated` measure
  preallocated carrier-prefix writes without socket or crypto work.
- `pipe::duplex_echo/{64,1024,65536}` sends/reassembles frames through the
  production encrypted pump over `tokio::io::duplex`. Handshake and fixture
  allocation are outside timing; send/receive and worker synchronization are
  timed. This is in-process carrier work, not a network deployment benchmark.
- `pipe::establishment_duplex` times the complete duplex lifecycle, from
  channel handshake through Syntra readiness and teardown. It sends no
  application RPC.

## Targeted checks

These selectors execute only the benchmark harnesses added in the three
benchmark files:

```sh
cargo bench -p syntra-core --bench frame_codec -- --test
cargo bench -p syntra-secure-channel --bench channel -- --test
cargo bench -p syntra-tcp --bench pipe -- --test
```

To smoke-test every benchmark in the workspace:

```sh
cargo bench --workspace -- --test
```

## Benchmark workflow

`.github/workflows/benchmarks.yml` uses Rust 1.88.0 and runs the three
Criterion benchmark targets with short report-only settings (the compile
step still covers every bench target with the harness-neutral `--test`
selector, since Criterion timing flags are rejected by the default libtest
harness):

```sh
cargo bench -p syntra-core --bench frame_codec -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
cargo bench -p syntra-secure-channel --bench channel -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
cargo bench -p syntra-tcp --bench pipe -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
```

The artifact records raw samples, source revision and toolchain. Timing is
report-only: no fixed ns/op threshold or automatic baseline-comparison gate
is used; execution errors still fail the job.

## Initial baseline

The initial capture started from the feature branch tip with the
benchmarked code paths in place. It covers the frame codec cases,
the channel handshake/record cases and the TCP pipe cases, each with short
100ms-target samples. It was captured with Rust 1.88.0, darwin/arm64,
Apple M4. This short local baseline is for subsequent comparison, not a
performance claim.

The run command, from the repository root with an empty output directory
verified with `ls` before writing results, was:

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo bench -p syntra-core --bench frame_codec -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
cargo bench -p syntra-secure-channel --bench channel -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
cargo bench -p syntra-tcp --bench pipe -- --measurement-time 0.1 --warm-up-time 0.05 --sample-size 10
```

 Representative observed ranges (see the workflow artifact for full samples):

| Case | Time | Throughput |
| --- | ---: | ---: |
| frame/scan/1024 | ~0.19 us | ~5.3 GiB/s logical envelope scan |
| frame/decode_request/1024 | ~0.29 us | ~3.4 GiB/s |
| frame/encode_request/1024 | ~0.11 us | ~8.7 GiB/s |
| sc1/handshake_bootstrap | ~293 us | handshake plus two verified records |
| sc1/record_warm/1024 | ~8.8 us | ~111 MiB/s per encrypt/decrypt pair |
| tcp/duplex_echo/1024 | ~363 us | ~5.4 MiB/s round trip |
| connection/establishment_duplex | ~385 us | complete lifecycle, no application RPC |

Compare like-for-like toolchains, CPU settings, selectors and timing
boundaries. Concurrent development and machine load can affect timing. The
saved capture records the starting revision and working-tree status; it does
not freeze later production edits by other contributors.

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
