# Conformance claim wording (Section P)

These rules are normative for any public statement that cites this suite.
A technically passing run with non-conformant wording is a non-conformant claim.

Evidence reporting is machine-verifiable: a claim naming conformance results
MUST name the executed manifest case IDs (`CONF-*`), the runner/tool that
executed them, the exact specification and suite revision pinned at
execution, and the per-case results. Results use the suite verdict
vocabulary only (PASS, FAIL, SKIP, UNSUPPORTED, NOT_EXECUTED); missing
execution is NOT_EXECUTED, never PASS. Registered, planned, not-executed
rows (such as the RFC 0010 `CONF-SCW-025`–`042` lifecycle rows) must not be
cited as passing or as satisfied.

RFC 0007 and RFC 0010 are accepted and `SNTR-SC1-WSS-V1` is registered with
case specifications. Registration is not execution: no `CONF-SCW-*` PASS or
claimable SC1 result exists yet, and stable-release authorization remains
separate. The claim rules below retain their existing scope and add the
SC1/WSS profile only for an implementation that actually passes its applicable
cases and release gates. A single-transport Core claim on one named secure
profile is permitted and self-contained (see the allowed forms and
`specifications/core/conformance.md`), but a Core-only claim cannot satisfy
the recovery-inclusive stable bundle (RFC 0006 §11.1: the target release
bundle requires the recovery contract and its own evidence).

## Allowed forms

- Single secure transport:

  > "Conforms to Syntra Core v1 and WSS/H1 v1"

- Two secure transports:

  > "Conforms to Syntra Core v1 with transports WSS/H1 v1, HTTPS/H2 v1"

- With the (future) event capability, replay explicitly scoped:

  > "Conforms to Syntra Core v1 with transports WSS/H1 v1, HTTPS/H2 v1 and
  > capability events-v1 (replay excluded)"

- Mandatory-only host (no event support — this is conformant):

  > "Conforms to Syntra Core v1 (mandatory-only; event subscriptions correctly
  > declined with UNIMPLEMENTED) over TLS/TCP v1"

## Forbidden forms

- Bare "Syntra compliant", "Syntra certified", "Syntra compatible",
  "Syntra-conformant", or any wording that omits the profile list.
- "Syntra Core" without the version (`v1`).
- Naming a capability (`events-v1`, `events-replay-v1`, `resume-v1`) without
  its RFC reference, or before its RFC is accepted.
- Implying production readiness from a development-only transport.

## Development-only suffix rule

Any claim naming `SNTR-TCP-V1`, `SNTR-HTTP-V1`, or `SNTR-WS-V1` MUST append:

> "(restricted development only; not for public production traffic)"

Example:

> "Conforms to Syntra Core v1 over TCP v1 (restricted development only;
> not for public production traffic)"

## Placement rules

- The declaration (`declaration.example.yaml`) lists exact profile IDs
  (`SNTR-WSS-H1-V1`), per-case verdicts, bounds, and log references.
- Marketing pages, READMEs, and datasheets MUST use the §Allowed-forms prose
  and link the declaration.
- Capability exclusions MUST be stated ("replay excluded") rather than left
  ambiguous. Silence about replay means replay was not evaluated, not that it
  passed.
