# syntra-rs

Rust implementation of the Syntra protocol, extracted from
[`tinkle-org/syntra`](https://github.com/tinkle-org/syntra) at
[`2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`](https://github.com/tinkle-org/syntra/commit/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c).
See [MIGRATION.md](MIGRATION.md) for provenance and the path mapping.

## Workspace

| Crate | Purpose |
| --- | --- |
| `syntra-core` | Envelope codec, validation, handshake and protocol state |
| `syntra-runtime` | Transport-independent client/host runtime |
| `syntra-ws` | Native and browser WebSocket adapters |
| `syntra-web` | Browser-facing WASM client; native fixtures for tests |
| `syntra-ffi` | Native C ABI with explicit production and test-fixture modes |

The [upstream specifications](https://github.com/tinkle-org/syntra/tree/main/specifications)
remain the protocol authority. Local `proto/` and
`conformance/test-vectors/` are copied snapshots for standalone generation
and tests. This extraction preserves the existing implementation; it does
not implement the newer Noise/SC1 design.

## Build and check

Run from this repository's root. Development and CI retain Rust **1.88.0**
(`rust-toolchain.toml`); the declared crate MSRV remains **1.88**. The
unchanged lockfile is used by all commands below.

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo build --locked --workspace
cargo test --locked --workspace
cargo fmt --all -- --check
```

### Native FFI

Default `syntra-ffi` builds export no Syntra C ABI. Select the production
frame-pump ABI explicitly; its header is
[`syntra_production.h`](crates/syntra-ffi/include/syntra_production.h).

```sh
cargo build --locked -p syntra-ffi --no-default-features
cargo build --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
python3 crates/syntra-ffi/tests/build_contract.py
```

`test-fixture` exports the separate blocking loopback ABI for tests only;
do not ship it or enable it through `--all-features`. The build-contract
check needs Python 3, `nm`, a C compiler and the WASM target. It builds
isolated artifacts, checks exports, runs C smoke tests and verifies the
expected FFI WASM rejection in all three modes.

### WASM

```sh
rustup target add --toolchain 1.88.0 wasm32-unknown-unknown
cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown
```

`syntra-ffi` is native-only. Compilation checks do not run a browser;
the opt-in [real-browser fixture](crates/syntra-web/tests/browser.md)
documents the separate browser procedure.

### Go native sibling

For sibling checkouts `syntra-rs/` and
[`syntra-go/`](https://github.com/tinkle-org/syntra-go), first build the
production library above. From the **syntra-go root**, use an absolute
library path (adjust it if `CARGO_TARGET_DIR` is set):

```sh
LIBDIR="$(realpath ../syntra-rs/target/debug)"
# Linux
CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR -lsyntra_ffi" LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" go test -tags syntranative -count=1 ./...
# macOS (use this command instead on macOS)
CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR -lsyntra_ffi" DYLD_LIBRARY_PATH="$LIBDIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" go test -tags syntranative -count=1 ./...
```

This requires a Go toolchain and C compiler for the same architecture as
the Rust library. Pure-Go builds need no Rust library. Cross-repository
integration is checked separately from this repository's Rust CI.

## Generated Rust

Normal Cargo builds consume committed generated Rust without Buf. To
check regeneration, install **Buf 1.59.0** and run:

```sh
python3 scripts/check-generated.py
```

The standard-library-only script generates into a temporary directory and
compares filenames and bytes without updating the committed output. Remote
generation requires access to `buf.build`. For an intentional, reviewed
snapshot update, `buf generate --template buf.gen.yaml` regenerates only
Rust using `neoeinstein-prost:v0.4.0`, revision 1, with runtime `prost =0.13.5`.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[security reporting policy](.github/SECURITY.md). Licensed under
[Apache-2.0](LICENSE).
