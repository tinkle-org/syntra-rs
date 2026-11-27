# Security policy

Use [GitHub private vulnerability reporting for syntra-rs](https://github.com/tinkle-org/syntra-rs/security/advisories/new)
instead of a public issue. Identify `tinkle-org/syntra-rs`, the affected
crate and commit, and include a minimal reproduction without credentials
or private data.

For a wire-format issue, identify the encoding as well as the version: the
current Protobuf schema and the incompatible Bebop format from #54 both use
wire version 1. State whether the issue occurs in `syntra_core::decode_frame`,
the recovery decoder, or a carrier. Use synthetic input. A serialized
`ClientHello` contains the credential bytes even if its debug output omits them;
do not attach a live frame or traffic capture.
