# Conformance — Secure WebSocket Transport (`CONF-WSS-001…010`)

Related normative requirements are cited per case; test IDs are not normative. All cases Mandatory for any implementation claiming the WSS profile. Neutral fixtures only. All WS cases in `conformance/requirements/websocket.md` MUST additionally pass over WSS (same IDs, `wss://` endpoint, TLS active); the cases below are WSS-specific and do not duplicate them. No case embeds private key material: certificate fixtures are referenced by test-harness name, never pasted.

## CONF-WSS-001 valid WSS Upgrade over TLS 1.3

- Related normative requirement: SNTR-WSS-001/010/040/041, SNTR-TSEC-002/003/004.
- Preconditions: WSS host at `wss://host[:port]/syntra/v1/ws` with a valid chain for the claimed hostname; initiator trusts the root.
- Input: TCP + TLS 1.3 handshake (SNI = intended hostname, ALPN `http/1.1` where negotiated) with successful chain + hostname + expiry validation, then the RFC 6455 Upgrade offering `syntra.v1`, then `Frame{hello}` as the first binary message.
- Expected output: TLS establishes; 101 selects `syntra.v1`; Syntra handshake completes (`ready` or a typed handshake error); no Syntra byte was sent before validation succeeded.
- Expected connection state: WSS established → CONNECTED → NEGOTIATING → ACTIVE on accept.
- Expected session state: principal bound only at `ready`.
- Mandatory/optional: Mandatory.

## CONF-WSS-002 invalid chain rejected before credentials

- Related normative requirement: SNTR-WSS-110/111, SNTR-TSEC-003/020.
- Preconditions: host presents an invalid chain (untrusted root, or revoked per policy); initiator configured to validate.
- Input: attempt a WSS handshake to the endpoint.
- Expected output: terminal TLS failure (alert, no Syntra `hello` sent, no credential transmitted); fail-closed locally with a non-oracle error; no plaintext retry, no validation skip.
- Expected connection state: no WSS connection.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WSS-003 wrong hostname rejected

- Related normative requirement: SNTR-WSS-112, SNTR-TSEC-004.
- Preconditions: host presents a chain-valid certificate for a different hostname.
- Input: attempt a WSS handshake to the intended endpoint.
- Expected output: rejected even though the chain validates; no credential sent to the unverified endpoint; fail-closed.
- Expected connection state: no WSS connection.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WSS-004 expired certificate rejected

- Related normative requirement: SNTR-WSS-111, SNTR-TSEC-003.
- Preconditions: host presents an expired certificate (or outside its validity window per test clock).
- Input: attempt a WSS handshake.
- Expected output: rejected before any credential is sent; no Syntra `hello`; fail-closed.
- Expected connection state: no WSS connection.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WSS-005 TLS below 1.3 refused

- Related normative requirement: SNTR-WSS-110/113, SNTR-TSEC-002/007.
- Preconditions: peer offers only TLS 1.2 or lower (simulated by harness).
- Input: attempt negotiation to the WSS endpoint.
- Expected output: negotiation fails; no Syntra session; no fallback to `ws://`.
- Expected connection state: no WSS connection.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WSS-006 WSS-to-WS downgrade absent

- Related normative requirement: SNTR-WSS-113, SNTR-TSEC-007, SNTR-WSS-901.
- Preconditions: ACTIVE-capable WSS endpoint; active attacker (or harness) offers a weaker version/profile, strips the Upgrade to `ws://`, or replays a redirect to plaintext.
- Input: TLS failure followed by an automatic-plaintext temptation; and separately a `wss`→`ws` redirect response.
- Expected output: no credential disclosure, no session establishment over plaintext; the client refuses the downgrade and reports a terminal transport failure; the `wss`→`ws` redirect is not followed.
- Expected connection state: no Syntra connection on the downgraded path.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WSS-007 secure redirect rules

- Related normative requirement: SNTR-WSS-013.
- Preconditions: WSS host that redirects (documented) to a second `wss` URL.
- Input: Upgrade receives 3xx to `wss://other/syntra/v1/ws`.
- Expected output: client re-validates the new endpoint from scratch (chain + hostname), does not forward `Authorization`/`Cookie` automatically, and re-issues the Upgrade only with explicit consent; undocumented or `wss`→`ws` redirects are refused.
- Expected connection state: new WSS connection only after re-validation; otherwise none.
- Expected session state: none until fresh handshake.
- Mandatory/optional: Mandatory (vacuously passes with "no redirects emitted" where the deployment serves the path directly).

## CONF-WSS-008 proxy / termination mismatch rejected

- Related normative requirement: SNTR-WSS-114, SNTR-TSEC-008/031.
- Preconditions: TLS terminating at a reverse proxy before the Syntra host (harness simulates mismatched SNI, stripped identity, or plaintext proxy-to-host leg without documented isolation).
- Input: WSS handshake through the misconfigured proxy.
- Expected output: handshake failure (no session, no silent fallback); correctly configured termination (secured backend leg + consistent `Host`/SNI/ALPN propagation) succeeds.
- Expected connection state: no Syntra connection on mismatch.
- Expected session state: none.
- Mandatory/optional: Mandatory.

## CONF-WSS-009 rotation accepted

- Related normative requirement: SNTR-WSS-115, SNTR-TSEC-006.
- Preconditions: host rotates from an old to a new valid chain with an overlapping validity window; initiator does not pin the leaf.
- Input: WSS handshakes before, during, and after rotation.
- Expected output: every handshake with a currently valid chain succeeds; no hard-coded-leaf rejection.
- Expected connection state: WSS established in each window.
- Expected session state: fresh session per connection (no cross-connection continuity implied).
- Mandatory/optional: Mandatory.

## CONF-WSS-010 WSS reconnect and resume

- Related normative requirement: SNTR-WSS-120, SNTR-SESS-003/006/008/010.
- Preconditions: WSS session on connection A ends (close or loss); default v1 (no resumption capability).
- Input: new TCP + new TLS 1.3 handshake (re-validated) + new Upgrade + new `hello{fresh credential}`; plus a resumption-presentation attempt.
- Expected output: new session with a fresh `connection_id`; `request_id` space fresh; subscriptions re-established explicitly; resumption attempt without a negotiated capability rejected (`UNAUTHENTICATED`/`FAILED_PRECONDITION` + close). Cross-transport presentation (e.g., a TLS/TCP-session token over WSS) rejected identically.
- Expected connection state: A CLOSED; B ACTIVE after fresh handshake.
- Expected session state: A's session ended; B's session independent.
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-WSS-001 | WSS-001/010/040/041, TSEC-002/003/004 (valid establishment) |
| CONF-WSS-002 | WSS-110/111, TSEC-003 (invalid chain) |
| CONF-WSS-003 | WSS-112, TSEC-004 (hostname) |
| CONF-WSS-004 | WSS-111, TSEC-003 (expiry) |
| CONF-WSS-005 | WSS-110/113, TSEC-002/007 (version floor) |
| CONF-WSS-006 | WSS-113, TSEC-007 (downgrade proof) |
| CONF-WSS-007 | WSS-013 (secure redirect) |
| CONF-WSS-008 | WSS-114, TSEC-008/031 (proxy/termination) |
| CONF-WSS-009 | WSS-115, TSEC-006 (rotation) |
| CONF-WSS-010 | WSS-120, SESS-003/006/008 (reconnect/resume) |
| WS suite over WSS | WS-030…102 run over `wss://` (mapping, close, Ping/Pong, backpressure unchanged) |
