# Conformance — TLS/TCP (`CONF-TLS-001…004`)

Test-case IDs use the `CONF-TLS-*` prefix. They are **test identifiers, not normative requirement IDs**: normative force stays with the cited `SNTR-TLS-*` and `SNTR-TSEC-*` requirements.

All cases use neutral envelopes (verified `hello` vectors). No Syntra bytes are sent or expected before TLS completes. “Pass” MUST NOT be reported unless executed with logs.

## CONF-TLS-001 TLS success

- Related normative requirement: SNTR-TLS-001, SNTR-TLS-002, SNTR-TLS-003, SNTR-TLS-004, SNTR-TLS-005, SNTR-TLS-009.
- Preconditions: valid chain for the endpoint to a trusted root; correct hostname; TLS 1.3 offered by both sides.
- Input: TCP connect → TLS 1.3 handshake (no ALPN required) → first Syntra unit `Frame{hello}` only after TLS completes.
- Expected output: TLS completes; `hello` accepted for version/credential evaluation; framing identical to `tcp.md` §3 (records are not frames — split one unit across records and coalesce two units in one record as part of this case).
- Expected connection state: TLS established, then Syntra NEGOTIATING → per policy.
- Expected session state: none until `ready`.
- Mandatory/optional: Mandatory for any `SNTR-TLS-TCP-V1` claim.

## CONF-TLS-002 invalid certificate

- Related normative requirement: SNTR-TLS-003, SNTR-TSEC-003, SNTR-TSEC-020.
- Preconditions: server presents an invalid/expired/revoked/self-signed-untrusted chain (one sub-case each).
- Input: attempt TLS with each bad chain.
- Expected output: terminal TLS failure; no Syntra `hello` sent; no credential disclosed; no fallback to plaintext.
- Expected connection state: no TLS session; Syntra never starts.
- Expected session state: none.
- Mandatory/optional: Mandatory for any `SNTR-TLS-TCP-V1` claim.

## CONF-TLS-003 wrong hostname

- Related normative requirement: SNTR-TLS-004, SNTR-TSEC-004/021.
- Preconditions: chain valid for a different name (SAN mismatch; IP mismatch as a second sub-case).
- Input: connect to the intended endpoint with the mismatched certificate.
- Expected output: rejection even though the chain validates; no credential or application payload sent.
- Expected connection state: no TLS session; Syntra never starts.
- Expected session state: none.
- Mandatory/optional: Mandatory for any `SNTR-TLS-TCP-V1` claim.

## CONF-TLS-004 TLS version failure

- Related normative requirement: SNTR-TLS-002, SNTR-TSEC-002/007.
- Preconditions: peer offers only TLS 1.2 or lower (or attempts downgrade to plaintext on failure).
- Input: negotiate with the weak-only peer; separately, fail TLS and observe retry behavior.
- Expected output: negotiation fails; automatic retry over plaintext is absent (FORBIDDEN); no Syntra bytes exchanged.
- Expected connection state: no TLS session; Syntra never starts.
- Expected session state: none.
- Mandatory/optional: Mandatory for any `SNTR-TLS-TCP-V1` claim.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-TLS-001 | TLS-001/002/003/004/005/009 (success path) |
| CONF-TLS-002 | TLS-003 (certificate validation) |
| CONF-TLS-003 | TLS-004 (hostname verification) |
| CONF-TLS-004 | TLS-002/005 (version floor, no downgrade) |
