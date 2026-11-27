# In-process parser checks

From the repository root, with rustup, Python 3 and a native C++ compiler:

```sh
rustup toolchain install 1.89.0 nightly-2026-03-15 --profile minimal
cargo +1.89.0 install --locked cargo-fuzz --version 0.13.1
python3 fuzz/check.py 60
```

The reusable `.github/workflows/parser-checks.yml` takes numeric `seconds`:
use `60` for PRs or `900` for weekly runs. The budget is **per target**;
the three checks run sequentially. Setup and compilation are additional.
Rust 1.89 builds the CLI; the dated nightly builds the instrumented targets
from this workspace's `Cargo.lock`, not the production workspace lockfile.

Each `seeds/*.hex` line is one synthetic input. Frame seeds exercise Bebop
envelopes, including both success and error results. Recovery seeds target the
service payload decoder, not the outer envelope. Stream seeds exercise
byte-at-a-time and coalesced delivery of two nonempty bodies.
The stream target varies the chunk width and frame boundary and checks
partial state, output order and contents. Frame and recovery targets check
that accepted values survive encoding and decoding in the same context.

Inputs are capped at 4 KiB. Only the reviewed seeds persist: mutations and
runtime logs stay in private temporary directories and are discarded after
each target. There is no failure replay, artifact upload or corpus cache.
The checks use no sockets, live sessions, credentials or stores. They cover
local parser properties, not carrier behavior or protocol conformance.
