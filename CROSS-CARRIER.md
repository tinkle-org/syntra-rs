# Sequential cross-carrier failover candidate

Status: opt-in implementation candidate. This document describes the implemented
policy, proposed normative changes and reproducible validation commands. Local
regressions are not formal adoption, conformance or human security approval.

See [README.md](README.md#candidate-cross-carrier-failover) for the feature overview
and [CONNECTION.md](CONNECTION.md#candidate-cross-carrier-failover) for composition.

## Current authority and scope

Current upstream requirements conflict with automatic cross-carrier failover:

| Owner | Current rule | Proposed change location |
| --- | --- | --- |
| [`specifications/security.md`](../syntra/specifications/security.md), `SNTR-TSEC-007` | Forbids automatically retrying another carrier, format or unprotected mode after failure; forbids lowering WSS below TLS 1.3 | Narrow exception for separately opted-in carrier policy after transient availability loss |
| [`specifications/transports.md`](../syntra/specifications/transports.md), `SNTR-WS-202` / `SNTR-WSS-201` | Forbids automatic carrier/format fallback and identical rejected-trust retries | Cross-reference the same bounded exception while preserving terminal trust handling |
| [Draft RFC0013](../syntra/rfcs/0013-http-tls-carriers.md), `R13-01`, `R13-26` | Forbids automatic carrier/format/mode fallback; automatic endpoint failover sets must select the same carrier | Permit mixed descriptors only under the separate explicit policy; retain endpoint-scoped inputs and fresh establishment |

These links refer to the sibling upstream checkout for review. The active
[candidate contract](protocol-contract.json) and [input lock](upstream.lock.json)
remain the provenance authorities for this implementation. No active contract
pin, source hash or protocol registry is edited by this documentation change.
HTTP/HTTPS remain unregistered candidate bindings; RFC0013 remains Draft and
does not already authorize mixed-carrier failover. Candidate code or passing
local tests cannot constitute acceptance of this proposed exception.

## Feature and API boundary

The new Cargo feature is exactly:

```toml
cross-carrier-candidate = ["tcp"]
```

It adds only TCP and the candidate route API. It does not implicitly add `http`,
`websocket`, a TLS implementation, `managed`, `reconnect` or enrollment. Select
`websocket` for application-provider WSS, `http` for candidate HTTP/HTTPS,
`proxy` for proxy routes, and the appropriate owner feature separately.
Cargo features are additive and can be unified across dependencies; runtime
policy is still explicit. Existing `routes::client_routes` remains same-carrier
even when this feature is unified into its build. Its homogeneous loopback WS
fixture support remains available; WS is never permitted in the new candidate.

The new public policy is:

```rust,ignore
pub struct CrossCarrierPolicy {
    pub permitted_carriers: Vec<Carrier>,
}
```

`routes::client_routes_cross_carrier(config: RouteConfig, policy, inputs)`
returns a connector of shape `Fn(EstablishmentBudget) -> routes::DialFuture`,
wrapped in `Result<_, Error>`, with `Send + Sync + 'static` bounds.
The nonblocking callback has shape
`Fn(&Endpoint) -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static`.
`DialFuture` is an owned, `Send` establishment future returning
`Result<ClientHandle, Error>`.

The callback receives the selected endpoint so the application can provide its
fresh `ClientConfig` and explicit encrypted-hello credential. It must use
independently provisioned scope, pin, authentication mode and credential policy;
the connector neither infers these from endpoint failures nor rewrites them.
The returned context carrier must match the selected endpoint before any dial.
Returning mode never silently changes to bootstrap. Fresh inputs do not mean
rotating a provisioned pin or authorization key on every attempt.

### Composition and ownership

Pass the returned connector directly to one of these owner APIs:

| Owner entry point | Feature | Responsibility |
| --- | --- | --- |
| `Network::client_with_budget(config, connector)` | `managed` | Managed registration/runtime ownership, delegating retries to one reconnect supervisor |
| `ReconnectingClient::new_with_budget(config, connector)` | `reconnect` | One bounded supervisor on the caller's runtime |
| `ReconnectingClient::new_with_recovery_and_budget(config, connector, principal_scope, store, limits)` | `reconnect` | Same owner plus fresh wire recovery negotiation per connection generation |

The connector accepts the owner's budget rather than manufacturing an independent
one. Do not adapt it to the older zero-argument constructors by creating a new
budget inside a closure. Recovery uses the remaining attempt/outage cutoff;
`CoreReady` and recovery readiness remain separate. Applications explicitly
restore subscriptions and reconcile durable progress after negotiation.

## Proposed normative delta

The uppercase obligations in this section are proposed candidate obligations
only. They are not registered upstream requirements. The intended owner edits
are the three narrowly scoped rule changes listed above, subject to upstream
review and synchronized acceptance.

### 1. Explicit exception; default prohibition retained

Replace the blanket carrier-retry prohibition in `SNTR-TSEC-007` with:

> Peers MUST NOT downgrade WSS below TLS 1.3, change protocol format or
> authentication mode, or use an unprotected mode after failure. Automatic
> carrier changes MUST remain disabled unless the application explicitly selects
> a cross-carrier policy with a finite nonempty permitted-carrier set and a
> separately provisioned route allowlist. Under that policy, only retryable
> availability loss MAY select a different permitted carrier on a fresh attempt.
> Detected trust, protocol, credential or authorization failure MUST block
> automatic continuation for that policy generation until explicit recovery.
> Version/capability negotiation MUST NOT weaken the selected carrier's security.

For `SNTR-WS-202` / `SNTR-WSS-201`, replace only their blanket carrier-fallback
sentence with:

> Automatic carrier changes MUST follow the explicit-policy exception in
> `SNTR-TSEC-007`; otherwise they MUST NOT occur. Format fallback and identical
> rejected-trust retries MUST NOT occur automatically. Each successor MUST
> revalidate its endpoint and perform fresh authentication and explicit recovery.

For Draft RFC0013 `R13-26`, replace its same-carrier-set requirement with:

> Descriptors in an automatic failover set MUST select the same carrier unless
> the application separately opts into the cross-carrier policy defined here.
> Under that policy, every descriptor and every allowlist entry MUST select a
> permitted carrier, and WS MUST be excluded. Both HTTP streams MUST remain on
> one descriptor and use its carrier, authority and security policy for the whole
> attempt. The explicit-policy exception MUST NOT permit cross-origin
> association, carrier guessing, format or mode fallback, or credential forwarding.

`R13-01`'s prohibition would cross-reference the same carrier-only exception;
its format/mode prohibition remains. Existing transient-only failover, terminal
rejection, endpoint-scoped credential and no-transfer obligations in `R13-26`
continue to apply. The exception does not excuse downgrade/proxy inconsistency
under `SNTR-WS-220` / `SNTR-WSS-220` or any selected carrier's trust checks.

### 2. Whole-configuration validation before effects

- Construction MUST validate runtime/transport limits and all routes and all
  allowlist entries, including unused entries, before inputs, providers or dialing.
  Each route list and allowlist MUST have `1..=routes::MAX_ROUTES` entries
  (currently 256); endpoint socket, URL, authority and proxy-target bounds apply.
- `permitted_carriers` MUST be bounded, nonempty and duplicate-free, with no
  implicit permissions. It MUST contain only recognized candidate permissions:
  TCP, WSS and, with `http`, HTTP/HTTPS. WS MUST be rejected, including in an
  otherwise unused allowlist entry or policy permission. Permission does not
  enable an implementation's Cargo feature.
- Every route and allowlist endpoint MUST be valid and permitted. Each route
  MUST match an independently supplied allowlist identity; proxy identities MUST
  include both the proxy socket and destination. A malformed later route or
  unused entry MUST fail the whole configuration before the first attempt.
- Direct routes MUST be listed, allowlisted and carrier-permitted separately.
  A failed proxy route MUST NOT synthesize a direct path or another proxy route.

### 3. Sequential selection and shared budgets

- Each dial future admitted by its budget MUST select exactly one route when
  polled, in round-robin order, obtaining fresh inputs outside the selection lock.
  It MUST NOT attempt a second route internally. An unpolled future MUST
  NOT advance the cursor, invoke inputs or perform I/O. Selection MUST NOT
  introduce priority failback, a health cache, racing or an internal retry loop.
- One supervisor MUST own sequential attempts, attempt counts, total elapsed
  outage, bounded backoff, pause/network/wake controls and generation fencing.
  An application MUST NOT add a competing per-carrier retry loop. Selection
  order is route order, not permission-list priority or a reachability prediction.
- Each attempt MUST carry the same owner `EstablishmentBudget` through socket
  dialing, proxy negotiation, TLS, upgrade/HTTP setup, Noise and ready to raw
  I/O polls. Both HTTP streams MUST share it. Shortening for a stricter route
  limit MUST preserve owner/elapsed-clock identity; resetting or extending the
  deadline at a layer boundary MUST NOT occur.
- When recovery negotiation is required, the raw I/O cutoff MUST remain enforced
  after CoreReady and release only after the owner accepts recovery under the
  current control revision. Both HTTP streams MUST retain that cutoff. Releasing
  setup MUST NOT restart selected I/O, extend exchange deadlines or impose the
  setup timeout on a successfully activated connection's remaining lifetime.
- Rotation MUST NOT reset attempts or outage origin. Outage accounting MUST
  include waits, paused/offline time and cleanup. Cancelled or superseded attempts
  MUST retire their partial connections and fence late completion. A new route
  MUST NOT bypass stop, exhaustion, terminal failure or a control-generation gate.

### 4. Failure classification and trust limits

| Observed failure | Candidate obligation |
| --- | --- |
| Trust/pin/certificate rejection, credential/authorization rejection | Terminal policy-generation block; no automatic successor |
| Protocol mismatch, local AEAD/record authentication failure, malformed framing | Terminal policy-generation block; no automatic successor |
| Proxy HTTP 403/407 or explicit SOCKS ruleset denial | Terminal authorization block; no automatic direct or other-route continuation |
| `Io`, `Timeout`, `Closed` | Availability-loss categories eligible for the next route only within the supervisor's remaining retry/outage/control budget |

Typed terminal failures MUST retain their classification through establishment
and active transport teardown; they MUST NOT be flattened into retryable close.
Ordinary per-RPC application errors are not a carrier failover signal. A terminal
block requires explicit application/operator recovery of the rejected policy;
route rotation, wake or generic restart MUST NOT silently clear it.

An arbitrary application TLS provider may return only opaque I/O after its
handshake. The connector cannot infer whether such an error concealed a typed
trust/protocol failure. Provider trust, verification and error fidelity remain
application responsibilities. Neither generic close nor sanitized reconnect
status proves a credential verdict, complete failure detection or a fixed
security status. Local tests can verify typed propagation, not arbitrary provider
behavior.

### 5. Provisioning, TLS, enrollment and fresh state

- Permitting TCP MUST be understood as explicitly permitting absence of outer
  TLS. Noise remains mandatory on every carrier. Plain candidate HTTP also has
  no outer TLS. A deployment requiring outer TLS MUST permit only WSS/HTTPS and
  list only those routes; enabling TLS support alone is not a runtime restriction.
- WSS and HTTPS MUST perform their full independently verified TLS establishment;
  HTTPS MUST verify both streams. TLS/provider metadata, proxy authority and an
  HTTP success MUST NOT replace provisioned Noise trust or host authentication.
- Scope, pin, authentication mode and credentials MUST be independently
  provisioned and MUST NOT be modified or inferred by failover. Proxy credentials
  remain hop-specific and MUST NOT become origin credentials.
- The native enrollment backend MUST retain its immutable TCP/WSS permission
  boundary. Cross-carrier permission MUST NOT expand enrollment permissions.
  Candidate HTTP/HTTPS host authentication and current-validity policy MUST be
  application-provided; automatic enrollment permission expansion is excluded.
- Every successor MUST create fresh Noise, live cipher state, correlation
  namespace and authentication. Required recovery MUST negotiate afresh under
  the owner budget. RPCs, live ciphers, sockets, principals, unfinished requests
  and subscriptions MUST NOT migrate or replay. Connection loss leaves an
  unfinished RPC's remote outcome unknown; failover does not make it safe to retry.

## Validation

Run from the repository root using the pinned Rust 1.88.0 toolchain. The focused
target contract requires named passing policy, mixed-carrier, budget, recovery and
WebSocket-loss regressions, rather than accepting compilation or zero-case runs.
The matrix below identifies coverage responsibilities; a successful command is
not independent interoperability or a security-review verdict.

| Lane | Assertions |
| --- | --- |
| Default and isolated feature builds | Defaults remain socket-free; candidate enables TCP only, with no HTTP/TLS implementation/managed/reconnect dependency activation |
| Whole-policy validation | Empty/oversized lists, duplicate/empty permissions, WS, invalid unused entries, missing route allowlisting, bad authorities/proxy targets and context-carrier mismatch fail before inputs/provider/dial as applicable |
| Selection and compatibility | Unpolled futures are inert; one endpoint per polled future; round-robin order; callbacks outside selection lock; homogeneous API still rejects mixed carriers with unified features; old loopback WS still works |
| Real mixed-carrier establishment | TCP to application-provider WSS and HTTPS, and later rotation back where permitted; bootstrap and returning modes with endpoint-scoped fresh inputs, real Noise, hello/ready and RPC |
| Terminal and retryable paths | Trust/protocol/local AEAD/framing and proxy 403/407/ruleset failures leave successors untouched; transient I/O/timeout/close alone permit bounded continuation; typed active failures survive teardown |
| Owner budgets and controls | Exact owner/clock identity reaches raw polls, both HTTP streams and recovery; stricter limits only shorten; expiry/overrun emits no late I/O; cancellation, pause/offline, wake, exhaustion and stale generations cannot bypass gates |
| Recovery and loss | Fresh recovery negotiation per generation, no live-state transfer or RPC replay, unknown outcomes retained; explicit subscription restoration remains application-owned |
| Enrollment and proxy policy | Immutable native TCP/WSS permissions; application-provided HTTP/HTTPS host auth; no inferred direct route, credential forwarding or permission expansion |

Feature checks and production dependency inspection (inspect feature edges,
not only a workspace-wide unified build):

```sh
cargo check --locked -p syntra-net --no-default-features
cargo check --locked -p syntra-net --no-default-features --features tcp
cargo check --locked -p syntra-net --no-default-features --features cross-carrier-candidate
cargo tree --locked -p syntra-net --no-default-features --features cross-carrier-candidate -e normal,features
cargo check --locked -p syntra-net --no-default-features --features cross-carrier-candidate,reconnect,websocket
cargo check --locked -p syntra-net --no-default-features --features cross-carrier-candidate,reconnect,http
cargo check --locked -p syntra-net --no-default-features --features cross-carrier-candidate,managed,websocket,http,proxy
```

Targeted behavioral and isolation runs:

```sh
cargo test --locked -p syntra-net --no-default-features --features cross-carrier-candidate --test cross_carrier
cargo test --locked -p syntra-net --no-default-features --features cross-carrier-candidate,reconnect,websocket --test cross_carrier --test routes
cargo test --locked -p syntra-net --no-default-features --features cross-carrier-candidate,reconnect,http --test cross_carrier --test http_connections
cargo test --locked -p syntra-net --no-default-features --features cross-carrier-candidate,managed,websocket,http,proxy --lib --test cross_carrier --test routes --test network --test network_http --test proxy --test tls_provider
cargo test --locked -p syntra-net --no-default-features --features cross-carrier-candidate,native-enrollment --lib
python3 scripts/cargo_contracts.py cross-carrier-candidate
python3 crates/syntra-net/tests/target_contract.py
```

The managed example runs on an ordinary thread, deliberately times out one local
TCP route, then verifies a WSS echo and complete shutdown:

```sh
cargo run --locked -p syntra-net --no-default-features --features managed,websocket,cross-carrier-candidate --example managed_wss -- --failover
```

Record exact revision, feature set, executed cases and results separately. A
zero-case filtered run is not behavioral evidence; same-library fixtures are not
independent interoperability or security review.

## Design reference

[RFC 8305, Happy Eyeballs Version 2](https://www.rfc-editor.org/rfc/rfc8305.html),
especially sections 2, 5 and 9, addresses racing connections to resolved network
addresses. Its staggered attempts can overlap, and initial TCP success does not
prove application-layer success. It is inspiration for bounded, explicit
candidate handling only. This design is sequential cross-carrier establishment,
with no address discovery or racing, and claims no RFC 8305 conformance.

The [Cargo feature-unification documentation](https://doc.rust-lang.org/cargo/reference/features.html#feature-unification)
explains why a build feature cannot itself serve as runtime failover consent.
