# Conformance — generic events and optional replay (`CONF-EVT-001…015`)

Related normative requirements are cited per case; test IDs are not normative. Neutral fixtures only (generic topics/filters, opaque payloads such as `{"seq":N, "data":"..."}`). No fixture references chat, delivery receipts, presence, or typing.

Conformance rule for optionality: any case exercising a capability the implementation does not advertise MUST result in `UNSUPPORTED` (host correctly rejects with `UNIMPLEMENTED`) or `SKIP` (harness records the option as unclaimed), never `FAIL`.

## CONF-EVT-001 subscribe

- Related normative requirement: SNTR-CAP-001, SNTR-CAP-002, SNTR-EVENT-001.
- Preconditions: ACTIVE; `events-v1` negotiated (only where claimed); authorized principal.
- Input: application-defined `/example.Events/Subscribe` RPC with opaque filter bytes.
- Expected output: opaque subscription handle; authorization evaluated before any delivery.
- Expected connection state: ACTIVE.
- Expected session state: unchanged; subscription registered for this connection only.
- Mandatory/optional: Optional, gated on `events-v1` (SKIP when unclaimed).

## CONF-EVT-002 capability absent

- Related normative requirement: SNTR-CAP-003, SNTR-EVENT-001, SNTR-EVENT-011.
- Preconditions: host supports mandatory-only behavior (no event streams).
- Input: attempt a subscription RPC for a generic topic.
- Expected output: `UNIMPLEMENTED`; no events emitted; mandatory RPC interop unaffected.
- Expected connection state: ACTIVE, usable.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory.

## CONF-EVT-003 event delivery

- Related normative requirement: SNTR-EVENT-002, SNTR-EVENT-005, SNTR-WIRE-003.
- Preconditions: ACTIVE; subscription confirmed (where claimed).
- Input: host emits one event.
- Expected output: `Frame{request_id=0, notification{opaque payload}}`; the notification completes no RPC; payload bit-preserved including empty and non-UTF-8 variants.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `events-v1` (SKIP when unclaimed).

## CONF-EVT-004 unsubscribe

- Related normative requirement: SNTR-EVENT-004, SNTR-EVENT-010.
- Preconditions: ACTIVE; subscription confirmed (where claimed).
- Input: application-defined unsubscribe RPC for the handle; host may still have one event in flight (race).
- Expected output: terminal confirmation; post-cancel events tolerated without completing any RPC.
- Expected connection state: ACTIVE.
- Expected session state: unchanged; subscription removed.
- Mandatory/optional: Optional, gated on `events-v1` (SKIP when unclaimed).

## CONF-EVT-005 duplicate event

- Related normative requirement: SNTR-EVENT-007, SNTR-REL-005.
- Preconditions: ACTIVE.
- Input: deliver the same opaque event twice.
- Expected output: initiator tolerates the duplicate; no protocol violation, no error storm.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory; no capability prerequisite.

## CONF-EVT-006 ordering

- Related normative requirement: SNTR-EVENT-006.
- Preconditions: subscription confirmed (where claimed).
- Input: host emits events 1, 2, 3.
- Expected output: arrival order 1, 2, 3 on order-preserving transports; on other bindings order is undefined unless the stream spec adds payload sequence metadata — the test records which behavior the deployment documents and MUST NOT assert global ordering.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `events-v1` (SKIP when unclaimed).

## CONF-EVT-007 queue overflow / slow consumer

- Related normative requirement: SNTR-EVENT-030, SNTR-REL-007.
- Preconditions: ACTIVE; subscription confirmed (where claimed); bounded event buffer with a documented slow-receiver policy.
- Input: host produces events faster than the initiator consumes.
- Expected output: `RESOURCE_EXHAUSTED` on new work and/or per-policy drops with a documented signal; never unbounded queueing or silent deadlock.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `events-v1` (SKIP when unclaimed).

## CONF-EVT-008 replay

- Related normative requirement: SNTR-EVENT-008, SNTR-EVENT-009.
- Preconditions: ACTIVE; subscription confirmed; replay capability negotiated with a documented cursor, retention, and coordination strategy (only where claimed).
- Input: re-subscribe with the last confirmed cursor; host replays retained events then the replay terminator; live events generated during replay follow the documented strategy.
- Expected output: replayed events tolerated including boundary duplicates; initiator continues live after the terminator with none missed per the documented strategy.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `events-replay-v1` (SKIP when unclaimed; correct `UNIMPLEMENTED` refusal is `UNSUPPORTED`, not a capability pass).

## CONF-EVT-009 expired cursor

- Related normative requirement: SNTR-EVENT-009.
- Preconditions: ACTIVE; replay negotiated with a documented retention window (only where claimed); cursor older than retention.
- Input: re-subscribe with the expired cursor.
- Expected output: `FAILED_PRECONDITION` for the manifest fixture (the notes also describe documented `NOT_FOUND`); recovery is re-subscribing from the documented point; never silent restart from an unrelated point.
- Expected connection state: ACTIVE.
- Expected session state: unchanged; subscription attempt rejected.
- Mandatory/optional: Optional, gated on `events-replay-v1` (SKIP when unclaimed).

## CONF-EVT-010 disconnect

- Related normative requirement: SNTR-EVENT-004, SNTR-SESS-004, SNTR-REL-009.
- Preconditions: ACTIVE; subscription confirmed; in-flight RPC 9.
- Input: abrupt transport loss.
- Expected output: in-flight RPCs get `UNAVAILABLE` (outcome unknown); no further events; no assumption of continuity.
- Expected connection state: CLOSED (via loss).
- Expected session state: terminated abnormally including subscriptions.
- Mandatory/optional: Mandatory; no capability prerequisite.

## CONF-EVT-011 reconnect

- Related normative requirement: SNTR-SESS-008, SNTR-EVENT-020.
- Preconditions: prior session ended (graceful or abrupt) with a subscription.
- Input: new transport + handshake; attempt to receive events without re-subscribing.
- Expected output: no events arrive; initiator re-subscribes explicitly with a fresh handle; old cursors/handles are meaningless without a negotiated replay/resumption binding.
- Expected connection state: new connection ACTIVE.
- Expected session state: new session; nothing inherited.
- Mandatory/optional: Mandatory; no capability prerequisite.

## CONF-EVT-012 invalid subscription

- Related normative requirement: SNTR-EVENT-011.
- Preconditions: ACTIVE.
- Input: subscribe to an unknown stream type.
- Expected output: `UNIMPLEMENTED`; hosts MUST NOT silently ignore or emit unrelated events.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory; no capability prerequisite.

## CONF-EVT-013 unauthorized subscription

- Related normative requirement: SNTR-EVENT-030, SNTR-ASEC-022.
- Preconditions: ACTIVE; `events-v1` negotiated (only where claimed).
- Input: subscribe to a protected topic with `fixture:valid-but-insufficient` credentials.
- Expected output: `PERMISSION_DENIED` before any delivery (the manifest notes also describe `UNAUTHENTICATED` where the binding is invalid).
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Optional, gated on `events-v1` (SKIP when unclaimed).

## CONF-EVT-014 pre-ACTIVE notification

- Related normative requirement: SNTR-EVENT-005.
- Roles: client only (the initiator's local outcome is the observable; no host-side variant is registered).
- Preconditions: handshake started.
- Input: host emits a notification before ACTIVE.
- Expected output: the pre-ACTIVE notification is a protocol violation (SNTR-EVENT-005, RFC 0003 D2). The initiator records local FAILED_PRECONDITION, discards the notification without application delivery, does not queue it and does not establish a subscription; no error Frame crosses the wire and the peer observes only the transport-native close signal.
- Expected connection state: CLOSING then CLOSED (no ACTIVE).
- Expected session state: none (no session was established).
- Mandatory/optional: Mandatory; no capability prerequisite.

## CONF-EVT-015 generic payload proof

- Related normative requirement: SNTR-EVENT-901.
- Preconditions: ACTIVE; subscription confirmed.
- Input: host emits one neutral opaque event.
- Expected output: generic payload proof across fixtures, wire traces, and logs; `expected.hygiene.absent_from` is `[chat, receipt, presence, typing]`.
- Expected connection state: ACTIVE.
- Expected session state: unchanged.
- Mandatory/optional: Mandatory; no capability prerequisite.

## Traceability

| Test | Requirement family |
|---|---|
| CONF-EVT-001 | CAP-001/002, EVENT-001 (subscribe) |
| CONF-EVT-002 | CAP-003, EVENT-001/011 (capability absent) |
| CONF-EVT-003 | EVENT-002/005, WIRE-003 (delivery) |
| CONF-EVT-004 | EVENT-004/010 (unsubscribe race) |
| CONF-EVT-005 | EVENT-007, REL-005 (duplicates) |
| CONF-EVT-006 | EVENT-006 (ordering scope) |
| CONF-EVT-007 | EVENT-030, REL-007 (queue overflow / slow consumer) |
| CONF-EVT-008 | EVENT-008/009 (replay) |
| CONF-EVT-009 | EVENT-009 (expired cursor) |
| CONF-EVT-010 | EVENT-004, SESS-004, REL-009 (disconnect) |
| CONF-EVT-011 | SESS-008, EVENT-020 (reconnect) |
| CONF-EVT-012 | EVENT-011 (invalid subscription) |
| CONF-EVT-013 | EVENT-030, ASEC-022 (unauthorized subscription) |
| CONF-EVT-014 | EVENT-005 (pre-ACTIVE notification) |
| CONF-EVT-015 | EVENT-901 (generic payload proof) |
