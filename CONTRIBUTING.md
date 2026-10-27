# Contributing

Keep implementation changes focused and include the affected tests and
check results in your pull request. Preserve crate names, public APIs and
wire compatibility unless the change explicitly addresses them.

Protocol specifications, RFCs, schema decisions and conformance definitions
are maintained in [`tinkle-org/syntra`](https://github.com/tinkle-org/syntra).
Follow its [contribution process](https://github.com/tinkle-org/syntra/blob/main/CONTRIBUTING.md)
for normative changes. A draft design is not implementation authority.

## Local checks

Use the pinned Rust 1.88.0 toolchain and the committed lockfile:

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo fmt --all -- --check
cargo test --locked --workspace
cargo test --locked -p syntra-ffi --no-default-features --features production
cargo test --locked -p syntra-ffi --no-default-features --features test-fixture
cargo check --locked -p syntra-core -p syntra-runtime -p syntra-ws -p syntra-web --target wasm32-unknown-unknown
python3 crates/syntra-ffi/tests/build_contract.py
```

Install `wasm32-unknown-unknown` for this toolchain first. The FFI contract
also requires Python 3, `nm` and a C compiler. Run the relevant focused
tests while iterating. Root `tests/integration/` and `tests/interoperability/`
are imported by crate test targets and are covered by workspace tests.
See [README.md](README.md) for build modes and Go sibling linking.

## Snapshot updates

`proto/` and `conformance/test-vectors/` are upstream snapshots. Record the
upstream commit and affected paths in any synchronization PR and update
[MIGRATION.md](MIGRATION.md) accordingly. Preserve generated output bytes;
do not hand-edit or independently format
`crates/syntra-core/src/generated/`.

With Buf 1.59.0 installed, run `python3 scripts/check-generated.py` to
check drift. An authorized regeneration uses
`buf generate --template buf.gen.yaml`; inspect and commit the schema and
generated changes together. The local template generates Rust only.

Report vulnerabilities through the [private reporting policy](.github/SECURITY.md).
