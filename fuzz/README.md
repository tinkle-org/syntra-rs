# In-process parser checks

These checks use synthetic inputs and no sockets, live sessions, credentials, or
stores. They exercise local parsers, not carrier behavior or protocol conformance.
From the repository root, with rustup, Python 3, and a native C++ compiler:

```sh
rustup toolchain install 1.89.0 nightly-2026-03-15 --profile minimal
cargo +1.89.0 install --locked cargo-fuzz --version 0.13.1
python3 fuzz/check.py 60
```

The three targets run sequentially. The time budget excludes setup and
compilation. The pinned nightly builds the targets using `fuzz/Cargo.lock`.

| CI run | Local invocation | Maximum fuzz input |
| --- | --- | --- |
| PRs and `main` | `python3 fuzz/check.py 60` | 4 KiB for each target |
| Weekly | `python3 fuzz/check.py 900 --large-frame` | 1 MiB + 1 byte for `frame`; 4 KiB for `stream` and `recovery` |

The numeric argument is seconds **per target**. Each `seeds/*.hex` line is one
synthetic input. `--large-frame` adds a request with an 8 KiB payload and two
envelopes at the 1 MiB decoder limit and one byte over it. The extra byte tests
rejection; it does not raise the decoder limit.

## What the targets check

- **[Frame](fuzz_targets/frame.rs):** If `decode_frame_structure` accepts the raw bytes as a request,
  the decoded `Frame` must equal Prost's `Frame::decode` on those bytes. From
  the same input, the target also constructs a legal request of at most 1 MiB,
  varying field order, omissions, and duplicates. `decode_frame` must accept
  it in `ValidationContext::active(1)` and return the same value as Prost.
  Inputs up to 4 KiB also exercise frame round trips in three connection contexts.
- **Stream:** Varies chunk width and the boundary between two nonempty bodies;
  checks partial state, output order, and contents.
- **Recovery:** Round-trips accepted service payloads from the local
  [`syntra.v1` schema](../proto/syntra/v1), comparing decoded values rather
  than bytes. This target does not decode the outer `Frame`.

The deterministic [`phase2_wire` tests](../crates/syntra-core/tests/phase2_wire.rs)
check field defaults and which value wins for duplicate fields. For request IDs
and payload lengths, they cover 127/128 and 16,383/16,384, accept legal
non-minimal varints, and reject truncated, overlong, or overflowing varints.
Discarded metadata counts toward the envelope size: otherwise legal requests
pass one byte below and at 1 MiB, and fail one byte above it.

## Retain and replay a failure

If a failed target emits a bounded synthetic input, CI retains only `input.bin`
and `replay.txt` for one day. It does not upload raw logs or cache the corpus.
To replay, unpack the artifact and follow `replay.txt` from a clean checkout on
the same host platform. Set `INPUT` in those instructions to the absolute path
to `input.bin`; the commands use the recorded revision and run the target once.

To retain a failure from a local run, pass a path that does **not** exist, for
example `python3 fuzz/check.py 60 --failure-dir "$HOME/parser-failure"`.
The runner creates the private directory only when it saves a failing input.
Without `--failure-dir`, it discards the input.
