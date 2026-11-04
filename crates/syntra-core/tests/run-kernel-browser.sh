#!/bin/sh
# The wasm-bindgen-test-runner must match Cargo.lock's wasm-bindgen version.
# Set NO_HEADLESS=1 to visit the printed test URL with a normal browser instead
# of a WebDriver. Chrome tools can inspect that page's actual test verdict.
set -eu
export WASM_BINDGEN_USE_BROWSER=1
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=${WASM_BINDGEN_TEST_RUNNER:-wasm-bindgen-test-runner}
cargo test --locked -p syntra-core --target wasm32-unknown-unknown --lib "$@"
