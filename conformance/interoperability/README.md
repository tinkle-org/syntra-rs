# Interoperability proof (SNTR-WIRE-901, SNTR-VER-901, SNTR-TCP-901, SNTR-TLS-901, …)

A conformance claim requires more than self-loopback: shared logical RPC
requests and outcomes MUST interoperate across implementations. Comparing
transports tests those same RPC semantics with only adapter changes, not an
identical on-wire `Frame` sequence. Handshake and event assertions follow each
transport's binding. This directory defines the pairings and the
cross-implementation scenarios. "Pass" MUST NOT be reported unless executed
with logs from both sides.

## Procedure

1. Pick an applicable row from `matrix.yaml` (transport pair × implementation
   pair); do not require an unclaimed transport for a Core claim.
2. Run the scenario from `scenarios.yaml` with implementation A as initiator
   and B as host, then swap roles. Apply each transport's handshake, framing,
   concurrency, and event rules to the scenario steps rather than replaying
   the persistent-connection sequence unchanged on HTTP.
3. The logical assertions are the same cases as the single-implementation
   manifests for RPC request/result correlation, opaque payloads, and typed
   outcomes. TCP/TLS and WS/WSS exchange `hello`→`ready` before RPCs; HTTP/HTTPS
   synthesizes negotiation/authentication per exchange from headers and carries
   no `hello`/`ready` or `Notification` frames. Test notifications only on
   transports that support them and only with an approved, claimed event
   capability; otherwise record the step as not applicable with a reason.
4. Record per-leg verdicts plus the pairing (A version, B version, profiles,
   bounds) in the declaration. Compare decoded RPC fields and outcomes across
   legs, preserving opaque bytes exactly; do not compare serialized bytes
   (SNTR-SER-002/901). Record transport-specific handshake and event assertions
   separately, including skipped steps and their reasons.

## Minimum bar for a Core claim

- Core MAY be claimed over a single transport profile; no implementation must
  support every transport (`../profiles.yaml`). A single secure profile can
  satisfy the independent-implementation bar below in both role assignments.
- One secure transport leg (TLS-TCP, HTTPS/H1, HTTPS/H2, or WSS/H1) against a
  **second, independent implementation** (a genuinely different codebase;
  implementations in two different languages count, two checkouts of the
  same code do not).

## Additional transport-independence goal

- A second transport leg (another claimed profile, possibly loopback) proves
  transport-independence with only adapter changes (INTEROP-CORE-2T,
  SNTR-WIRE-901). This is a separate goal, not a prerequisite for a
  single-transport Core claim; do not claim the two-transport proof without
  executing both legs.
- WS/WSS legs additionally prove the no-length-prefix rule using the concrete
  malformed prefixed inputs in VEC-WS-009. Where a TCP/TLS leg is available,
  the same valid protobuf payload succeeds there with its required 4-byte
  prefix — proving framing lives in the adapter, not the core. Valid appended
  unknown protobuf fields remain accepted per SNTR-SER-003.
