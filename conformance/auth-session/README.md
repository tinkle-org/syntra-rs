# Auth/session conformance (approved equivalent)

Test-case IDs use the `CONF-SESS-*` / `CONF-AUTH-*` prefixes requested for this task. They are **test identifiers, not normative requirement IDs**: normative force stays with the cited `SNTR-*` requirements (single-definition rule in `specifications/core/requirements.md` and `specifications/security/requirements.md`). Location `conformance/auth-session/` is the approved equivalent of `conformance/requirements/session.*` per `specifications/core/conformance.md` (§Trace: `SNTR-AUTH-*`, `SNTR-SESS-*` → `conformance/auth-session/`).

- [Session lifecycle cases](session.md) — `CONF-SESS-001…010` (creation, invalid state, rejection, version, expiry, close, loss, resume abuse, pre-ACTIVE RPC).
- [Authentication framework cases](authentication.md) — `CONF-AUTH-001…006` (anonymous, opaque carriage, principal binding, re-auth refusal, expiry/revocation, generic principals).

All cases use neutral fixtures (`/example.Echo/Echo`, generic key/value, generic subscription). “Pass” MUST NOT be reported unless executed with logs. Resumption-success is NOT claimed: resume cases assert rejection under default v1.
