# Conformance — authentication framework (`CONF-AUTH-001…006`)

Test IDs are test identifiers, not normative requirement IDs. All cases Mandatory. Neutral fixtures only.

## CONF-AUTH-001 anonymous attempt honored per policy

- Related normative requirement: SNTR-AUTH-003, SNTR-AUTH-005, SNTR-AUTH-007.
- Preconditions: host policy documented (accept or deny anonymous).
- Input: `Frame{hello{credential=""}}` (empty bytes).
- Expected output: if accepted, one `ready` binding an anonymous principal with least privilege; if denied, handshake failure `UNAUTHENTICATED`. Empty MUST NOT crash, MUST NOT be treated as success without `ready`.
- Expected connection state: ACTIVE (accepted) or CLOSING→CLOSED (denied).
- Expected session state: anonymous session bound to the connection, or none.
- Mandatory/optional: Mandatory.

## CONF-AUTH-002 opaque carriage bit-preserved

- Related normative requirement: SNTR-AUTH-001, SNTR-AUTH-002, SNTR-ASEC-001/003, SNTR-OPQ-001.
- Preconditions: two distinct opaque credentials (e.g., 32-byte value A vs B, plus empty and 1 MiB-boundary values within envelope limits).
- Input: present A on one connection, B on another (fresh transports).
- Expected output: both traverse bit-preserved; core makes no syntax decision; acceptance differs only by application policy; credential bytes never appear in logs, errors, diagnostics, or URLs (negative grep of implementation output + wire traces excluding the credential field itself).
- Expected connection state: per policy (ACTIVE or closed with typed error).
- Expected session state: principal bound only on acceptance, per connection.
- Mandatory/optional: Mandatory.

## CONF-AUTH-003 principal binding fixed per connection

- Related normative requirement: SNTR-AUTH-007, SNTR-SESS-007, SNTR-RPC-032.
- Preconditions: authenticated ACTIVE session for principal P.
- Input: invoke a protected method as P (allowed), then attempt to act as Q on the same connection (different credential bytes in RPC payload or reordered handshake bytes).
- Expected output: all authorization uses P; Q-actions on P's connection denied (`PERMISSION_DENIED`/`UNAUTHENTICATED`); principal change requires a new connection + handshake.
- Expected connection state: ACTIVE (P's work continues unless revocation closes it).
- Expected session state: still bound to P.
- Mandatory/optional: Mandatory.

## CONF-AUTH-004 same-connection re-authentication refused

- Related normative requirement: SNTR-AUTH-010, SNTR-HS-012.
- Preconditions: ACTIVE session.
- Input: second `hello`, re-auth RPC claiming a principal change, or `ready` sent by the initiator.
- Expected output: handshake/state failure `FAILED_PRECONDITION` (+ close where the profile requires); no principal change; original binding intact until close.
- Expected connection state: CLOSING→CLOSED (for `hello`/`ready` in ACTIVE) or RPC-level `FAILED_PRECONDITION` for unauthorized re-auth RPC shapes that do not alter the binding.
- Expected session state: unchanged until close; new credentials require a new connection.
- Mandatory/optional: Mandatory.

## CONF-AUTH-005 expiry and revocation enforced

- Related normative requirement: SNTR-AUTH-008, SNTR-AUTH-009, SNTR-ASEC-005/006/041.
- Preconditions: short-lived credential and a revocable credential, each accepted initially.
- Input: allow expiry to elapse, then RPC; revoke the second credential mid-session, then RPC and subscription action.
- Expected output: per-RPC `UNAUTHENTICATED`; binding withdrawal closes the connection by default; no silent success; no further dispatch for the revoked principal.
- Expected connection state: CLOSED (default) after enforcement.
- Expected session state: terminated; fresh handshake required.
- Mandatory/optional: Mandatory.

## CONF-AUTH-006 generic principals (non-user)

- Related normative requirement: SNTR-AUTH-007, SNTR-ASEC-004, SNTR-ASEC-901.
- Preconditions: application policies for a service key and a device token (opaque bytes, non-user).
- Input: authenticate with the service key on one connection and the device token on another; invoke the same neutral method (`/example.Echo/Echo`) under each.
- Expected output: identical core mechanics (ready/binding/error codes) for both; no user-account assumption in any wire field, log, or error; authorization applied uniformly through the same hooks.
- Expected connection state: ACTIVE per accepted binding.
- Expected session state: one session per connection, principals isolated (no cross-connection authorization).
- Mandatory/optional: Mandatory.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-AUTH-001 | AUTH-003/005/007 (anonymous attempt) |
| CONF-AUTH-002 | AUTH-001/002, ASEC-001/003 (opaque carriage) |
| CONF-AUTH-003 | AUTH-007, SESS-007, RPC-032 (binding) |
| CONF-AUTH-004 | AUTH-010, HS-012 (re-auth refusal) |
| CONF-AUTH-005 | AUTH-008/009, ASEC-005/006/041 (expiry/revocation) |
| CONF-AUTH-006 | AUTH-007, ASEC-004 (generic principals) |
