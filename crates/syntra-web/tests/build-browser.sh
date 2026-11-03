#!/bin/sh
# Run from the workspace root. Outputs are ignored under target/, not sources.
# CLI version MUST match Cargo.lock's wasm-bindgen. No TLS-validation bypasses.
set -eu
WASM_BINDGEN=${WASM_BINDGEN:-wasm-bindgen}
cargo build --locked --release -p syntra-web --target wasm32-unknown-unknown --no-default-features --features browser-connection
mkdir -p target/syntra-browser-production
"$WASM_BINDGEN" target/wasm32-unknown-unknown/release/syntra_web.wasm --target web --out-dir target/syntra-browser-production
node crates/syntra-web/tests/check-wasm-imports.mjs target/syntra-browser-production/syntra_web_bg.wasm --production
cargo build --locked --release -p syntra-web --target wasm32-unknown-unknown --features browser-test-fixture
mkdir -p target/syntra-browser-fixture
"$WASM_BINDGEN" target/wasm32-unknown-unknown/release/syntra_web.wasm --target web --out-dir target/syntra-browser-fixture
node crates/syntra-web/tests/check-wasm-imports.mjs target/syntra-browser-fixture/syntra_web_bg.wasm --fixture
python3 -c 'print("Serve the workspace with python3 -m http.server 8765 --bind 127.0.0.1, then open http://127.0.0.1:8765/crates/syntra-web/tests/connection-browser.html?module=/target/syntra-browser-production/syntra_web.js&fixtureModule=/target/syntra-browser-fixture/syntra_web.js ; inspect window.syntraEvidence. The client is a production-feature artifact and the separate peer uses test-fixture exports. Synthetic carrier evidence is not WSS/TLS conformance.")'
