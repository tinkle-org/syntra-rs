# Wire, session and connection benchmarks

Use **Rust 1.89.0** for current benchmarks and the current CI configuration,
selecting it with `export RUSTUP_TOOLCHAIN=1.89.0`. The crate MSRV floor of 1.89
is a build compatibility constraint; production binaries need a security-patched
toolchain.
The `--bench` targets use the locked Criterion 0.8 and report timing plus
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
proxies or reconnect behavior. The separate full-RPC tests exercise the draft
RFC0013 HTTP/HTTPS bindings. Neither the timings nor those tests establish
adoption, conformance, or completion of security review. See
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
  echo RPCs over in-memory duplex streams. Prefix cases have no handshake.
  Both echo cases time payload verification; only the cold echo times
  establishment and teardown. `Throughput::Bytes` counts twice
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
- `tcp/duplex_echo_warm/{64,1024,65536}` uses the same stream capacity, key setup,
  handler, runtime configuration and payloads as `duplex_echo`. Each measurement
  loop starts with a fresh, ready pair and one verified echo outside timing.
  A timed iteration clones the request payload, makes one serial RPC over that
  pair and compares the response. Both directions use the live encrypted pumps;
  nonces advance normally. Setup, key generation and both closes are untimed.
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

To smoke-test every Criterion benchmark in the workspace:

```sh
cargo bench --locked --workspace --features syntra-net/tcp -- --test
```

## Mixed traffic on TCP loopback

The unpublished `syntra-integration` package includes a standalone
[`mixed_traffic` runner](crates/syntra-integration/src/bin/mixed_traffic.rs).
It measures how long small RPCs take to return when bulk traffic shares their
connection or uses a separate one. The [fixture](crates/syntra-integration/src/lib.rs)
uses one IPv4 loopback listener. Each connection authenticates independently in
returning mode with the same test credential and fresh traffic keys. With one connection,
all calls share it; with two, echoes use the first and both bulk directions use
the second (idle for `None`). There is no wire change.

Run from the workspace root; no Docker is needed:

```sh
export RUSTUP_TOOLCHAIN=1.89.0
cargo test --locked -p syntra-integration --features measure-heap --bin mixed_traffic --test connection_purpose
cargo run --locked --release -p syntra-integration --bin mixed_traffic -- --smoke
cargo run --locked --release -p syntra-integration --bin mixed_traffic
# Separate process: use this run for heap bytes, not latency or throughput.
cargo run --locked --release -p syntra-integration --features measure-heap --bin mixed_traffic
```

The binary tests check whole-block verification, percentile rank, paired
timestamps, overlap, and the heap measurement window. The
[`connection_purpose` tests](crates/syntra-integration/tests/connection_purpose.rs)
check method and object access on both connections, shared caller quota and
permit reuse, result correlation, and continued interactive use after bulk
closes. After the fixture marks the account revoked, each connection's next RPC
fails authorization and that connection closes. A separate test pauses an
admitted handler, revokes the account, and resumes the handler. Its own check
under the effect lock returns `PermissionDenied` without incrementing the effect
counter. Neither test demonstrates proactive withdrawal of an idle connection.

**Workload.** Each burst starts at a common barrier. One caller submits four
8-byte echoes sequentially, waiting for each reply before submitting the next.
At most one echo is in flight. Independent callers upload one tagged 256 KiB block
for an 8-byte receipt, download one such block for an 8-byte request, do both,
or do neither. Every burst drains before the next; faster cases get no extra
work. Each trial warms up for one burst, then measures 64 (256 echoes). The
second pass reverses case order. `--smoke` uses two measured bursts per case
and one pass; it checks the workload, not performance. CI executes this smoke
run in debug mode and runs the binary's unit tests with `measure-heap` enabled.

**Reading the output:**

- Echo times are nearest-rank p50/p95/p99 in µs: `queue_us` is burst offer to
  call start, including earlier echoes' round trips, not transport queue time.
  `rtt_us` is call start to return, and `offer_to_result_us` is
  offer to that echo's return, not a sum of percentiles. `overlap` counts echoes
  with a positive call interval common to *all* enabled bulk directions. A bulk
  trial fails if none overlap or the verified workload is incomplete.
- `up_MiB_s` and `down_MiB_s` divide verified bulk payload bytes in each
  direction by `active_s`, the sum of burst times from offer to last verified
  completion. Timing includes scheduling, encrypted I/O, and payload generation
  and checks by the host; the active interval also includes client verification.
  Connection setup, warmup, task creation, client input staging, and shutdown
  are outside the timed intervals.
- `staged_input_bytes` is the largest per-burst sum of client input `Vec`
  capacities at offer. The separate `measure-heap` run reports
  `peak_rust_heap_bytes`: peak live Rust heap across the process during the
  measured burst loop, including bytes already live after warmup. It is neither
  RSS nor an allocation delta.

### Local mixed-traffic baseline

Full runs at `805284d4e8d265858b20d4ab784152df03425579`, dirty (new harness
only; unchanged transport). Apple M4 on AC, macOS 27.2.1 (26B131), rustc
1.89.0 targeting `aarch64-apple-darwin`, four Tokio workers, `--release --locked`.
Cells show pass 1 / pass 2. Latency and throughput come from the uninstrumented run.

| Bulk load | Echo offer-to-result p95, 1 connection (µs) | Echo offer-to-result p95, 2 connections (µs) |
| --- | ---: | ---: |
| None | 194 / 197 | 197 / 198 |
| Upload | 1678 / 1640 | 217 / 215 |
| Download | 1661 / 1661 | 416 / 212 |
| Both | 3004 / 3021 | 377 / 233 |

| Both directions active | 1 connection | 2 connections |
| --- | ---: | ---: |
| Verified MiB/s per direction, uninstrumented (approx.) | 99.86 / 100.16 | 105.37 / 104.98 |
| `peak_rust_heap_bytes`, separate process | 2137636 / 2137594 | 2190737 / 2193513 |

Separating bulk calls lowered echo p95 under load in both passes; the no-bulk
control was similar. This compares two topologies on the same transport, not a
candidate/baseline speedup or a CI threshold. Fixed, drained bursts do not
model open-loop arrivals, streaming, or an actual client. These measurements
establish no production limits, physical-network throughput, or mobile energy costs.

### Production lanes: matched loopback comparison

`--production-lanes` adds a third topology and **one tagged 8-byte host notification
per burst in all three topologies**. Without that flag, the runner keeps the original
workload and output, even when built with `managed-media`. The comparison uses the
[same burst driver](crates/syntra-integration/src/bin/mixed_traffic.rs) for
one direct connection, two manually opened connections, and the native
[`LaneClient::tcp` path](crates/syntra-integration/src/production_lanes.rs).
The latter submits echoes via `call_interactive` and bulk RPCs via media
reservations with exact request/response bounds. Every accepted socket serves all
three methods with the same authentication and payload checks. The separate
[`managed_media_fault` integration test](crates/syntra-integration/tests/managed_media_fault.rs)
checks which socket received each call by logging dispatches of the *same* method.
The timed workload exercises generic RPCs, not file transfers, FFI or durable recovery.

Each trial gets a fresh listener and four Tokio **workers total**: one shared pool
of four for the direct cases; two for host/burst tasks plus one per client pool
for `LaneClient`. Runtime ownership, scheduling and cross-pool submission differ.
This measures **scheduler + topology**, not a pure wire effect. After one warmup,
each case verifies 64 drained bursts (256 echoes, 64 updates, 16 MiB per enabled
bulk direction). Pass 2 reverses all 12 cases. `update_us` starts immediately before
host `notify` and ends when the interactive receive returns; `update_overlap` counts
those intervals overlapping all enabled bulk calls. Rates use the same denominator
as above, now including notification verification if it finishes last.

`cold_media_open_us` is first demand on a parked media lane to observed authenticated
readiness, before warmup. The no-bulk case makes no media demand. `media_idle_close_us`
is measured after the last drain until both the lane is parked and the host sees closure,
with `media_idle` set to 250 ms. An interactive echo then checks that the owner is
still usable. The heap run counts live Rust allocations for the whole process: a
peak during measured bursts and a snapshot at idle before teardown. It does not measure RSS.

**Local release measurement (2026-11-28 UTC).** Apple M4 on AC, macOS 27.2.1
(26B131), `aarch64-apple-darwin`, rustc 1.89.0 (`29483883e`), `--locked --release`.
Both passes used this PR's uncommitted implementation on `b0b9fdc`,
not the historical runner at that SHA. Values are pass 1 / pass 2.

| Metric | One connection | Manual two | Managed lanes |
| --- | ---: | ---: | ---: |
| No bulk: echo offer-to-result p95 (µs) | 194 / 494 | 498 / 525 | 554 / 252 |
| Upload + download: echo offer-to-result p95 (µs) | 3,145 / 3,122 | 1,444 / 1,336 | 315 / 617 |
| Upload + download: notification delay p95 (µs) | 302 / 305 | 53 / 62 | 51 / 45 |
| Upload + download: verified MiB/s per direction | 87.23 / 89.33 | 93.76 / 91.56 | 97.52 / 96.48 |
| Upload + download: peak live process Rust heap (bytes) | 1,838,333 / 1,772,798 | 1,833,354 / 1,886,234 | 1,983,936 / 2,000,241 |

The managed client reduced loaded echo and notification p95 in both passes;
the no-bulk passes did not show a consistent latency advantage. In the bidirectional
managed case, the cold open was 1.65 / 1.45 ms, and media closed after 253 / 255 ms
of idle time. These figures do not measure battery use or predict WAN latency.
The [timing stdout](crates/syntra-integration/measurements/production-lanes-release.txt)
and [separate heap stdout](crates/syntra-integration/measurements/production-lanes-heap.txt)
each contain all 24 rows, including p99. The [provenance record](crates/syntra-integration/measurements/provenance.txt)
includes hashes of both stdout files. The [release](crates/syntra-integration/measurements/release.sha256)
and [heap](crates/syntra-integration/measurements/heap.sha256) checksums identify the executables,
not their stdout; checking either executable hash requires the corresponding binary.

**Reproduce from a clean checkout.** Use a revision containing the final runtime,
the uniform-handler runner, the routing test and their `Cargo.lock`; the base SHA
alone does not reproduce uncommitted sources. From that checkout's repository root,
on an otherwise idle host, use the installed rustup toolchain, no custom sysroot
and a fresh target directory. The following macOS commands stop on the first failure:

```sh
set -eu
test "$(pwd -P)" = "$(git rev-parse --show-toplevel)"
test -z "$(git status --porcelain)"
out=$(mktemp -d)
export CARGO_TARGET_DIR="$out/target"
export RUSTC="$(rustup which --toolchain 1.89.0 rustc)"
export RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER='' CARGO_ENCODED_RUSTFLAGS=''
test "$("$RUSTC" --print sysroot)" = "$(dirname "$(dirname "$RUSTC")")"
{
  date -u; git rev-parse HEAD; git status --porcelain; shasum -a 256 Cargo.lock
  "$RUSTC" -Vv; "$RUSTC" --print sysroot; cargo +1.89.0 -V
  sw_vers; sysctl -n machdep.cpu.brand_string; pmset -g batt
} > "$out/provenance.txt"

cargo +1.89.0 test --locked -p syntra-integration --features managed-media --test managed_media_fault
cargo +1.89.0 test --locked -p syntra-integration --features managed-media,measure-heap --bin mixed_traffic --test connection_purpose
cargo +1.89.0 run --locked -p syntra-integration --features managed-media --bin mixed_traffic -- --production-lanes --smoke

for mode in release heap; do
  features=managed-media
  if [ "$mode" = heap ]; then features=managed-media,measure-heap; fi
  cargo +1.89.0 run --locked --release -p syntra-integration --features "$features" --bin mixed_traffic -- --production-lanes > "$out/production-lanes-$mode.txt"
  shasum -a 256 "$CARGO_TARGET_DIR/release/mixed_traffic" > "$out/$mode.sha256"
  test "$(grep -c '^pass=' "$out/production-lanes-$mode.txt")" -eq 24
done
```

Keep both complete stdout files with the provenance and executable hashes. Read
`offer_to_result_us_p95` for `bulk=None` and `bulk=Both` from the **release**
file only; use the heap file only for bytes. A timeout, failed overlap check or
partial file is a failed run, not a sample to omit.

To measure a **dirty** implementation before it has a commit, omit only the
clean-status assertion. Before building, save `git diff --binary HEAD` and copies
of the untracked runtime, integration fixture, test and runner sources alongside
the provenance. Keep the working tree unchanged through both processes. Label
those results dirty; do not identify them as a measurement of unmodified `HEAD`.

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
The normal test suite also checks the two request fixtures against their
Protobuf wire lengths and allocation ceilings; these are not latency thresholds.
Artifacts retain both revisions,
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

### Local protobuf candidate comparison (2026-11-27)

Each version was built with Rust 1.89.0 and its own lockfile on an Apple M4
(arm64, macOS 27.2.1, AC power). A is `b99f56b`, before #54; B is the
`feat/protobuf-wire` worktree on `34ece84`; C is unmodified Bebop from
`34ece84`. A and C used B's `pipe.rs` to measure the same established RPC.

| Measured quantity | A: old Protobuf | B: optimized Protobuf | C: Bebop |
| --- | ---: | ---: | ---: |
| Empty request: serialized bytes | 29 | 29 | 50 |
| Near-limit request: serialized bytes | 1,048,355 | 1,048,355 | 1,048,375 |
| Empty / near-limit round trip: allocation calls | 6 / 8 | 2 / 4 | 2 / 3 |
| Empty request round trip (ns) | 229 / 229 | 196 / 194 | 194 / 167 |
| Near-limit request round trip (µs) | 191 / 191 | 43 / 195 | 188 / 185 |
| Established 64 B echo (µs) | 33.8 / 30.2 | 30.4 / 29.5 | 30.1 / 30.4 |
| Established 64 KiB echo (ms) | 1.223 / 1.163 | 1.185 / 1.212 | 1.153 / 1.173 |

Timings are Criterion means in forward / reverse build order per case. The
candidate reduced empty-frame time by 14–16% versus old Protobuf. Its much
lower first near-limit timing did not repeat. Neither the large-frame data
nor the established echoes show a repeatable latency win over Bebop. Sizes
exclude outer framing and encryption; the allocation counts cover only the
in-memory decoder/encoder. No mobile device or network was involved.

To repeat, prebuild both harnesses in each worktree with `--no-run`, run the
allocation test separately, then run each exact case serially in both orders:

```sh
cargo test --locked --release -p syntra-core --test bench_allocations -- --ignored --nocapture
# BIN is the frame_codec or pipe executable; use a fresh CRITERION_HOME per build/pass.
# CASE: frame/roundtrip_request/{0,1048320} or tcp/duplex_echo_warm/{64,65536}.
"$BIN" --bench "^${CASE}$" --warm-up-time 0.5 --measurement-time 1 --sample-size 30 --noplot
```

### Follow-up: Protobuf request decoding on Linux ARM64

The [main-push run after #55](https://github.com/tinkle-org/syntra-rs/actions/runs/46076555674)
compared `34ece84` (Bebop) to `a85467a` (Protobuf). Empty request time rose
21% and 19% on the two passes; near-limit request time rose 64% and 57%.
None of the three encrypted-record cases crossed the gate. Both codecs made
two allocations for empty requests, but Protobuf made four instead of three
for near-limit requests. After the structural scan it parsed the request again,
and prost's borrowed-slice to `Vec<u8>` decode copied the payload twice.

With Rust 1.89.0 in a four-CPU Linux ARM64 Docker container on an M4, the
unchanged `benchmark_baseline.py` reproduced both failures. Reusing the scanned
request fields and checking method syntax in one pass cut empty and near-limit
request times by 55% and 40% versus `a85467a`. Against `34ece84`, the empty
case was 40–42% faster and the near-limit case ranged from 2% slower to 3%
faster across two passes. The repeat was triggered by a warm-record control,
not a frame case. The full gate passed against both baselines. Allocation calls
are now 2 / 3 at the same 29 / 1,048,355 encoded bytes. These are in-memory
results from a local Linux VM, not a rerun on the hosted runner or an RPC
latency measurement.

### One-byte varint experiment (2026-11-27)

On an Apple M4 (arm64, macOS 27.2.1, AC power), Rust 1.89.0 built two
versions of `frame_codec` with the same harness and lockfile. A used the
decoder from `cfdf38c`; B differed only in `read_varint`: read the first
byte, return if it is below 128, otherwise continue the checked loop from
byte two. Each column is a separate Criterion run, in execution order.
Values are time per operation (Criterion slope point estimate).

| Case | A1 | B1 | B2 | A2 |
| --- | ---: | ---: | ---: | ---: |
| Request, empty, ID 7 (ns) | 58.54 | 53.62 | 54.59 | 57.13 |
| Request, 64 B, ID 7 (ns) | 72.66 | 68.92 | 69.25 | 71.05 |
| Request, 64 B, ID 128 (ns) | 78.77 | 75.88 | 74.14 | 74.80 |
| Request, 64 B, 10-byte ID (ns) | 81.96 | 74.60 | 78.68 | 79.72 |
| Request, near 1 MiB, ID 7 (µs) | 14.52 | 14.50 | 14.83 | 14.51 |
| Notification, 64 B (ns) | 79.15 | 82.74 | 82.94 | 78.79 |
| Structural scan only, 64 B request (ns) | 41.41 | 36.37 | 36.97 | 40.91 |

The full 64 B request decode with ID 7 took 2.5–5.2% less time, but the
notification took 4.5–5.3% more in the paired runs. Its 95% slope intervals
did not overlap between builds in either order. The decoder therefore retains
the shared loop. These measurements cover in-memory decoding, not RPC latency.

To measure the same workloads, build with `cargo +1.89.0 bench --locked
-p syntra-core --bench frame_codec --no-run`, then invoke the executable it
prints for each build, with a distinct `RUN` label:

```sh
"$BIN" --bench '^frame/(decode_request/(0|64)|decode_request_64B_by_id/.*|decode_notification/64|decode_near_1MiB|scan/64)$' \
  --warm-up-time 0.5 --measurement-time 1 --sample-size 30 --noplot --save-baseline "$RUN"
```
