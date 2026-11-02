# Event conformance (approved equivalent)

Test-case IDs use the `CONF-EVT-*` prefix. They are **test identifiers, not normative requirement IDs**: normative force stays with the cited `SNTR-*` requirements. Location `conformance/events/` is the approved equivalent of `conformance/requirements/events.*` per `specifications/core/conformance.md` (§Trace: `SNTR-EVENT-*` → `conformance/events/`).

- [Event tests](events.md) — `CONF-EVT-001…015` (capability, subscribe, delivery, ordering, duplicates, unsubscribe, disconnect, reconnect, replay, cursors, backpressure).

Optional functionality results in `UNSUPPORTED` or `SKIP`, never `FAIL`, when the implementation does not advertise it. No fixture uses chat updates, message delivery/read receipts, presence, or typing events.
