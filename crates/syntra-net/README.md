# syntra-net

Native networking for the Syntra Rust implementation: encrypted TCP and
WebSocket connections, record I/O, bounded reconnect, and optional managed
client/server lifecycle. It composes `syntra-core` protocol/encryption state and
the transport-independent `syntra-runtime` with native I/O.

The implementation is experimental. Publication does not establish formal
conformance, independent interoperability, or independent security review.
HTTP/HTTPS and cross-carrier failover remain opt-in implementation candidates,
not accepted-spec or conformance claims.

## Using TCP

For an application that already owns a native Tokio runtime, select `tcp`:

```toml
[dependencies]
syntra-net = { version = "=1.0.0-rc.2", default-features = false, features = ["tcp"] }
```

This is the intended dependency shape after the first net publication. Until
that release is available, use a reviewed Git revision or a local path rather
than assuming the registry package exists. Select the version actually released
by the release PR, and align any direct `syntra-core` and `syntra-runtime` pins
with it; prereleases can contain breaking changes.

`syntra_net::tcp::connect` establishes an encrypted connection and returns a
`ClientHandle` exposing the runtime `Initiator`. Provision the server public key,
scope, mode, key identifier, and application credentials through a trusted path;
do not learn a trusted server pin from an unauthenticated connection. Native TCP
uses Syntra's integral encryption and is not a plaintext fallback for WSS.

For a library-owned runtime and reconnect lifecycle, select `managed` instead;
it includes `tcp` and `reconnect`. Do not add a second reconnect owner if the
embedding application already supervises connections. The packaged
[`managed_tcp` example](examples/managed_tcp.rs) demonstrates a loopback encrypted
echo with explicit local provisioning. From the extracted `syntra-net` package
directory (or `crates/syntra-net` in a source checkout), run:

```sh
cargo run --no-default-features --features managed --example managed_tcp
```

From the repository workspace root, select the package explicitly:

```sh
cargo run -p syntra-net --no-default-features --features managed --example managed_tcp
```

A downstream application cannot run this example through its `syntra-net`
dependency. Obtain the package sources and run it there; adding a dependency
does not make its example targets part of the application's package.

These demo credentials and generated keys are not deployment configuration.
Downstream migrations from the older `syntra-ws` package need explicit connection,
configuration, and shutdown changes; this is not a drop-in package rename.

## Feature and target boundaries

Defaults are empty: the native carrier-neutral record `pump` does not open sockets.
`tcp` enables TCP clients/listeners and routes. `websocket` adds WebSocket framing
and application TLS-provider composition; plain WS is restricted to loopback
development use. `tls-rustls` adds optional rustls WSS convenience APIs. `proxy`
adds SOCKS5/HTTP CONNECT routes, and `native-enrollment` selects the SQLite
enrollment reference explicitly. `http` and `cross-carrier-candidate` select
separate candidate APIs; neither is enabled by a TCP dependency.

Every explicit feature requires a non-wasm32 target. On wasm32, default builds
expose no drivers; browser embedders use core/runtime with platform-owned I/O.
Rust 1.89 is the build compatibility floor, not a security recommendation; build
production binaries with a security-patched toolchain.

See the [API documentation](https://docs.rs/syntra-net),
[connection guide](https://github.com/tinkle-org/syntra-rs/blob/main/CONNECTION.md),
and [source workspace](https://github.com/tinkle-org/syntra-rs) for architecture,
feature composition, provenance and verification scope. The `syntra-integration`
workspace member is test infrastructure and is deliberately not published.

Licensed under Apache-2.0; the package includes the license text.
