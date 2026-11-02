# Conformance manifest format (Section C)

Machine-readable test manifests live in this directory. They are the normative
executable form of the suite; the `*.md` prose companions explain the same
cases for humans. Both share identical test IDs. If they disagree, the cited
`SNTR-*` requirement prevails and the manifest/prose is a bug.

## Design goals

- **Neutral:** YAML 1.2 only (`.yaml` files also parse as JSON-equivalent maps;
  runners MUST NOT need a Protobuf toolchain, Rust, Go, or any test framework
  to read them).
- **Deterministic:** every case states `preconditions`, a concrete `input`,
  and an exact `expected` outcome. No wall-clock flakiness: deadlines use fixed
  budgets with injected-slow handlers or generous margins; expiry uses
  short-lived fixture credentials or injected clocks.
- **Separable:** transport framing (`transport-*.yaml`) is distinct from core
  envelopes (`core.yaml`, `rpc.yaml`); the same logical `Frame` runs over any
  claimed transport with only adapter changes (SNTR-WIRE-901).

## Conceptual example (informative)

```yaml
- id: CONF-RPC-001
  requirement: [SNTR-RPC-001, SNTR-RPC-002, SNTR-RPC-003, SNTR-RPC-006]
  profile: SNTR-RPC-V1
  roles: [client, server]
  capabilities: []
  mandatory: true
  preconditions: [active_session]
  input:
    frames:
      - { request_id: 7, body: request, method: "/example.Echo/Echo",
          payload_b64: "aGVsbG8=", timeout_ms: 500 }
  expected:
    connection_state: ACTIVE
    session_state: unchanged
    frames:
      - { request_id: 7, body: result, payload_b64: "aGVsbG8=" }
```

## Field reference (normative for manifest authors)

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | string `CONF-[A-Z]+-[0-9]+` | yes | Stable test identifier. Never reused; never renumbered. |
| `requirement` | string list `SNTR-*` | yes | Normative requirements under test. Test MUST NOT invent behavior beyond them. |
| `profile` | profile ID or list | yes | One applicable profile, or a non-empty list of independently applicable profiles, from `conformance/profiles.yaml`. |
| `roles` | subset of `client, server` | yes | Which IUT side(s) the verdict applies to. `client-server` in prose = `[client, server]` here. |
| `capabilities` | string list | yes (may be empty) | Capability identifiers required to *execute* (not merely handle absence). Empty = always executed. Placeholder names (`events-v1`, `events-replay-v1`, `resume-v1`) gate Optional cases until their RFCs exist. |
| `mandatory` | boolean | yes | `true` = MUST pass to claim the profile; `false` = Optional (SKIP when capability unclaimed). |
| `applicable_transports` | string list, subset of `tcp_tls, ws_wss, http_1_1, https_h2` | no | Machine-readable transport applicability for transport-scoped requirements (e.g. RFC 0004 D3 persistent-carrier exemptions: SNTR-HTTP-070 — SC1 multiplexes within `ws_wss`). Absent (the default for every pre-existing case) = applies on any claimed transport. Present = the case executes exactly over the listed families; a claim whose transport profiles resolve to none of them reports `SKIP` for the case with a reason citing this key (conformance README §6), which is a valid verdict for a mandatory case. Not a capability gate: it never changes capability negotiation or mandatory-service handling. |
| `preconditions` | string list | yes | Symbolic setup states (see vocabulary below). |
| `input` | map | yes | Stimulus: `frames` (envelope list), `transport` (raw bytes / HTTP / WS actions), `faults` (loss, delay, tamper, structured coordination), `credentials` (throwaway fixture names). |
| `expected` | map | yes | Observable outcome: `connection_state`, `session_state`, `frames`, `error` (`{code, message_pattern, observer, carriage}`), `transport` (status/close/alert plus the two-observer extensions below), `hygiene` (negative-grep list). |
| `control_connection` | map | no | Runner-recognized paired-control scenario for cases whose outcome depends on per-connection negotiation isolation. The runner executes it on a fresh connection with the same host, bound principal, authorization scope, and selector basis as the case-level scenario, then asserts its outcomes in addition to the case-level results. Required `keys`: `preconditions`, `expected`; optional `keys`: `frames`, `subscriptions`, `replay`, `transport`, `faults`, `credentials`, `notes`. Structured fields supersede prose-only controls; a case whose gate attribution relies on a paired control MUST declare it here (e.g., `CONF-URP-001`), and validation rejects prose-only controls for such cases. |
| `notes` | string | no | Human guidance; never adds normative force. |

Precondition vocabulary (closed list; manifests MUST NOT invent new tokens
without an RFC): `no_transport`, `transport_connected`, `handshake_started`,
`active_session`, `anonymous_session`, `expired_credential`,
`revoked_credential`, `valid_chain`, `invalid_chain`, `wrong_hostname`,
`expired_certificate`, `weak_tls_only`, `oversize_ready`, `flood_ready`,
`subscription_confirmed`, `cursor_expired`, `connection_lost`.

Connection-state vocabulary: `CONNECTED`, `NEGOTIATING`, `AUTHENTICATING`,
`ACTIVE`, `CLOSING`, `CLOSED`. Session-state vocabulary: `none`, `active`,
`unchanged`, `terminated_normally`, `terminated_abnormally`, `withdrawn`.

Error codes use the `proto/syntra/v1/errors.proto` enum names
(`UNAUTHENTICATED`, `RESOURCE_EXHAUSTED`, …). `message_pattern` is a
case-insensitive substring that MUST appear (for generic-text checks) or a
`NEGATIVE:` list of substrings that MUST NOT appear (for hygiene checks).

### Two-observer handshake-failure vocabulary (RFC 0003 D1)

Handshake failures are recorded on two axes — the detecting side's local
typed cause and the peer's transport-native signal — and these are
different observers of the same rejection, not contradictory outcomes.
When both must be asserted, use:

- `expected.error.observer`: `detecting_host` or `detecting_peer`. It
  binds the `error.code` assertion to the detecting side's local record.
  Absent `observer` (the default in all pre-existing cases) means the
  error is the initiator's terminal result within the exchange context.
- `expected.error.carriage`: `wire` (default) or `local_only`.
  `local_only` is executable: the cause never crosses the wire from the
  responding side, so the runner asserts that no Syntra `Frame` envelope
  is emitted in response to the stimulus. Pair it with
  `expected.frames: []` — `expected.frames` lists only Frames emitted in
  response to the stimulus (the stimulus Frame itself — including the
  harness-injected one, e.g. `CONF-CORE-005`'s `hello` — is never a
  member), so an empty frames list means "the responding side emits no
  Syntra Frames for this input" (RFC 6455 Close frames, HTTP statuses,
  and TLS alerts are transport-native signals, not Syntra Frames, and
  are asserted under `transport`). No `RpcResult`, zero-ID result,
  error-bearing `ready`, or second `hello` may be invented as an error
  carrier.
- `expected.transport.peer_observation`: map keyed by transport family
  (`tcp_tls`, `ws_wss`, `http_1_1`, `https_h2`); each entry asserts the
  peer's observable outcome with optional `signal`
  (`transport_close` | `ws_close` | `http_status` | `connection_loss`),
  `close_code` (RFC 6455 application code), `status` (integer HTTP
  status), and `local_report`. `local_report` is either a known
  ErrorCode (`UNAVAILABLE`, `INVALID_ARGUMENT`, …) or one of the
  documented generic marks `generic_protocol_rejection` /
  `generic_policy_rejection`, used exactly where the native signal
  cannot distinguish the host's typed cause (handshake.md §5: "a
  generic close does NOT reveal the host's precise rejection cause").
- `expected.transport.result_envelope`: `absent` or `present` — the HTTP
  binding's no-invented-Syntra-envelope assertion for non-`200`
  exchanges.

### expected.frames entries (normative for manifest authors)

`expected.frames` lists Frames emitted in response to the stimulus.
Entries carry only the emitted Frame's own keys (`request_id`, `body`,
`payload_b64`) plus the documented assertion helpers (`shape`, `note`,
`has_connection_id`); repository validation rejects any other key. Fixture metadata never rides
inside an expected frame row: `credentials` is not a `syntra.v1.Frame`
field and is declared on the input side only — case-level, or per-exchange
as in `CONF-HTTP-013`'s structured exchange rows. Runners associate each
expected result row with its originating exchange by the echoed
`request_id`; the assertion that a distinct payload is echoed identically
proves response-to-exchange association, not which credential subject
executed the handler — proving per-exchange principal binding would need a
principal-sensitive authorization assertion instead.

### Structured harness coordination faults

Race-sensitive cases MUST coordinate through structured `input.faults`
maps, never through wall-clock sleeps or prose-only assumptions. The
documented coordination faults follow the established
`reverse_completion_order: {barrier: ...}` shape (see `rpc.yaml`
`CONF-RPC-013`, and its transport-manifest cousins `CONF-HTTP-013` /
`CONF-HTTPS-003`, the per-exchange and per-stream floor fixtures):

- `duplicate_while_pending: {barrier: first_terminal_result,
  release_after: violation_and_closure}` — used by the persistent-carrier
  duplicate-ID case (`CONF-RPC-004`). Semantics: the harness admits the
  first request and starts its handler with the handler's terminal-result
  commitment and emission held behind the barrier; the harness then
  injects the duplicate stimulus while the original is outstanding; the
  host must detect and process the violation and terminate the
  connection while the barrier stays closed; only then is the barrier
  released, and the held outcome is discarded with the connection rather
  than emitted. This makes the "no result under the duplicate's ID"
  prediction deterministic instead of scheduling-dependent. The duplicate
  stimulus is harness-injected: a conforming client implementation never
  generates a duplicate ID (RFC 0004 D1 initiator discipline is a
  separate client-side obligation), and the host-side rule (reject the
  duplicate at admission, never dispatch it) is what the case verifies.

Cases whose stimulus is a wire `hello` `Frame` (`CONF-CORE-005`,
`CONF-CORE-006`) never apply to HTTP/HTTPS directly: those profiles
synthesize the handshake from headers, and their per-exchange coverage
lives in the transport manifests (`CONF-HTTP-001`, `CONF-HTTPS-001` for
the positive path; `CONF-HTTP-008` for version mismatch), not an
exchange of the same fixture. Both cases therefore declare
`applicable_transports: [tcp_tls, ws_wss]`.

`CONF-RPC-002` (per-connection concurrency floor) scopes to persistent
carriers for the same reason (one RPC per HTTP exchange; SNTR-HTTP-070)
and declares `applicable_transports: [tcp_tls, ws_wss]`; an
HTTP/HTTPS-only claim reports `SKIP` for it and cites the key. Its
HTTP/HTTPS floor coverage is transport-owned instead: `CONF-HTTP-013`
(SNTR-HTTP-072) and `CONF-HTTPS-003` (SNTR-HTTPS-041), which run the
16-concurrent fixture with the same reverse-completion barrier and
distinct-payload identical-echo assertions as `CONF-RPC-013`.
`CONF-RPC-003` (out-of-order correlation) is likewise persistent-carrier
scoped (`applicable_transports: [tcp_tls, ws_wss]`): its connection holds
an ACTIVE session, which the per-exchange HTTP model never provides, and
its HTTP/HTTPS ordering coverage is transport-owned by `CONF-HTTP-013` /
`CONF-HTTPS-003` (RFC 0004 D3). The remaining frame-based `CONF-CORE-*`
and `CONF-RPC-*` cases with `active_session`/ACTIVE expectations are
persistent-carrier scoped for the same consistency reason; each manifest
note names the per-exchange analogue owned by the transport profiles
where one exists.

## Base64 and hex conventions

- `*_b64` fields are RFC 4648 §4 standard-alphabet base64 of exact bytes.
- `*_hex` fields are lowercase hex without prefixes or separators, except
  where a vector table uses space-separated groups for readability (runners
  MUST strip whitespace before decoding).
- `payload_b64: ""` (empty string) is a meaningful empty payload, distinct
  from an absent `payload_b64` (unset outcome — always a failure).

## Schema validation

`schema.yaml` in this directory is the machine-readable schema. Validate with
any YAML parser plus the `required` / `pattern` rules stated there, for
example:

```sh
python3 scripts/validate-conformance.py conformance/manifest/*.yaml conformance/profiles.yaml
```

(The script is illustrative; any equivalent check in any language satisfies
the requirement. What matters is that the files parse and cross-reference:
every `requirement` exists in `requirements.yaml`, every `profile` exists in
`profiles.yaml`, every `vector_ref` exists in `test-vectors/`.)

In `conformance/profiles.yaml`, each `manifests` entry is either a path or
a `{path, select}` map that filters by exact field equality (for example
`select: {mandatory: true, capabilities: []}` selects only mandatory
capability-free cases; see `conformance/README.md` §2.1).

## Manifest index

RFC 0007 is accepted. `sc1-wss.yaml` registers the `SNTR-SC1-WSS-V1` cases
against `SNTR-SCW-*`, `SNTR-SC-*` and `SNTR-DAUTH-*`. The companion
[`../plans/secure-channel.md`](../plans/secure-channel.md) retains historical
manual-observation mapping. Registration is not execution: no `CONF-SCW-*`
verdict is claimed, and implementation tests are not a substitute for the
registered cases. Lifecycle rows whose host transaction is not implemented
remain manual in `requirements.yaml` rather than being marked automated.

| File | Cases | Section |
|---|---|---|
| `core.yaml` | CONF-CORE-001…010 | §E valid/invalid envelope, unknown field/enum, version, capability, ordering, protocol error, close |
| `session.yaml` | CONF-SESS-001…010 + CONF-SESS-R01 (Optional resume-accept) | §F |
| `rpc.yaml` | CONF-RPC-001…013 | §G |
| `events.yaml` | CONF-EVT-001…015 | §H (Optional rows gated) |
| `transport-tcp.yaml` | CONF-TCP-001…008 | §I TCP |
| `transport-tls.yaml` | CONF-TLS-001…004 | §I TLS |
| `transport-http.yaml` | CONF-HTTP-001…018 | §I HTTP/1.1 |
| `transport-https.yaml` | CONF-HTTPS-001…014 | §I HTTPS/H1 + H2 |
| `transport-ws.yaml` | CONF-WS-001…017 | §I WS |
| `transport-wss.yaml` | CONF-WSS-001…010 | §I WSS |
| `security.yaml` | CONF-SEC-001…011 | §Q negative cases (STEST-001…011) |
| `requirements.yaml` | SNTR-* → test traceability | §D |
