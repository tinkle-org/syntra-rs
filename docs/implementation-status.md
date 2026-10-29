# Rust implementation status

## Current scope and evidence

The native experimental, unpublished `syntra-sc1-transport` implements the RFC
0007 section 11 canonical-context proposal reviewed at
`94404d7378136d8b6c88ece28bf945c88d1653ba`. It provides WSS, a carrier-neutral
pump, opt-in development TCP/loopback WS, and an opt-in reconnecting client.
Baseline `syntra-ws` framing/endpoints stay unchanged; custom runtime writers
have the `Initiator::prepare_outbound` original-`Vec` behavior contract.

[SC1.md](../SC1.md) documents wire and lifecycle contracts.
[AUDIT.md](../AUDIT.md#current-recorded-verification) records the latest local
execution results on Rust 1.88.0, darwin/arm64: 372 workspace tests passed,
0 failed, 2 ignored; separate default/development transport runs; FFI/WASM,
formatting, clippy, generation/pin, workflow-lint and security checks; and all
three Criterion smoke targets. Post-documentation formatting, diff, workflow-lint
and upstream-pin checks also passed.
Docker was unavailable and the container suite was not executed; browser
execution was ignored. Two code-agent source reviews had their reported findings
fixed, but no independent human review is established by those reviews.

This evidence does **not** unblock release or activate the upstream profile.
Exact context/prologue fixtures test public encoding only. They are not
independent Noise cryptographic vectors or independent cross-language interop.
Historical extraction, local-revision-1 tests and timing captures retain their
original scope in the audit and migration records.

## Remaining Rust implementation backlog

### Host identity, validity and revocation

- Implement and demonstrate actual same-principal binding between the confirmed
  SC1 identity/enrollment and independently verified application credentials.
  `AuthenticatorFactory`, `Authenticator` and `Handler::authorize` are host
  extension contracts, not a supplied identity system.
- Define and enforce current-validity/expiry/revocation checks before `ready`
  and effects, including periodic host revalidation and bounded revocation
  propagation. One lookup or a successful handshake does not establish continuing
  authorization.
- Complete enrollment issuance, atomic storage, secure delivery, acknowledgement,
  lost-delivery recovery and rotation workflows.

### Activated protocol and execution accounting

- Complete and validate the full activated parser contract, request-ID rules,
  host-receipt budget semantics and execution accounting. Existing bounded codec,
  correlation and emission-gate tests cover their stated local behaviors; they
  do not establish full activated protocol conformance.
- Preserve the distinction between local queued-to-emitting handoff, host receipt,
  execution and observed completion. The emission gate reduces remaining request
  time at handoff; it is not an execution receipt or proof of a terminal effect.

### Durable recovery and client/mobile integration

- Implement durable wire recovery end to end, including persistence, wire
  negotiation, generation/principal binding, replay bounds, subscription recovery
  and execution-terminal evidence. In-memory session/recovery helpers are
  insufficient to claim a durable recovery service or exactly-once effects.
- Renegotiate application recovery after every `CoreReady` generation. The
  reconnecting client never restores durable application state or automatically
  replays mutations; unknown outcomes need application-level resolution.
- Unify or explicitly integrate the production FFI state machine with the intended
  runtime/SC1 SDK contract. Async runtime fixes and SC1 support do not automatically
  reach the separate production C ABI.
- Complete mobile integration and validate lifecycle/network/wake handling,
  protected credential storage, shutdown ownership and resource use on devices.
  Browser SC1 remains unimplemented.

### Independent interoperability and release evidence

- Obtain upstream activation of the reviewed profile; the review pin remains a
  proposal, separate from the historical extraction/schema pin.
- Execute independent pure-Go/Rust SC1 interoperability with both initiator and
  responder roles and both bootstrap and returning modes, plus independent
  cryptographic vectors. Same-library round trips and public encoding fixtures
  do not replace this evidence.
- Validate supported direct/proxy topologies, TLS termination and identity
  boundaries, real devices, connection/resource limits and adverse network
  conditions. Container execution and browser runtime checks remain outstanding;
  the current pipe benchmark is not a WSS/network performance measurement.
- Obtain independent human composition/security review and address its findings.
  Automated code-agent reviews do not satisfy this gate.

Release remains gated on these implementation and evidence requirements,
including recovery and mobile validation. No performance, energy, independent
interoperability or production-readiness claim follows from the local checks.
