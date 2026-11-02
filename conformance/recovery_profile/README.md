# Recovery profile conformance — update and recovery

Additive conformance material for the optional update and recovery contract.

RFC 0006 is accepted and its §11 decision amendment is authoritative. The
contract is described in [Update/Recovery Profile](../../specifications/profiles/recovery.md)
and [RFC 0006](../../rfcs/0006-update-recovery-profile.md).

This directory does not change mandatory behavior. It only adds optional
coverage that is evaluated when the capability is claimed. Registration is
not an execution result: cases are registered executable specifications,
not executed observations.

## Files

- [recovery prose](recovery.md) — human-readable cases `CONF-URP-001…017`,
  including the RFC 0006 §11.8 reconciliation record.
- [recovery manifest](../manifest/recovery.yaml) — machine-readable cases for runners.
- Related event material: [event conformance](../events/events.md).
- Manifest guidance: [manifest format](../manifest/README.md).
- Claimed profile definition: [profiles](../profiles.yaml).

## Profile and capability

- Profile: `SNTR-EVENTS-V1`.
- Capability: `syntra.update-recovery/1` (RFC 0006 accepted; still explicitly
  negotiated per connection and not global).
- Every case in [recovery manifest](../manifest/recovery.yaml) sets `mandatory: false`.
- Every case in [recovery manifest](../manifest/recovery.yaml) sets `capabilities: [syntra.update-recovery/1]`.
- Every case in [recovery manifest](../manifest/recovery.yaml) sets `profile: SNTR-EVENTS-V1`.
- Case requirement traces use the accepted `SYN-URP-*` family (with
  `SYN-URP-008/009` reserved and unassigned) plus meaningful `SNTR-*` core IDs.

## Optionality rule

Any case exercising a capability the implementation does not advertise
MUST result in `UNSUPPORTED` or `SKIP`, never `FAIL`.

A mandatory-only implementation that correctly refuses profile use with
`UNIMPLEMENTED` satisfies `CONF-URP-001` as `UNSUPPORTED`. Core-only
conformance without recovery stays valid; it cannot satisfy the
RFC 0006 §11.1 recovery-inclusive release bundle, and recovery cases report
SKIP/UNSUPPORTED for it, never PASS.

## Preconditions and expected states

Preconditions use descriptive harness setup labels from [manifest format](../manifest/README.md)
and the case bodies, including the recovery-specific ones:

- `active_session`
- `subscription_confirmed`
- `replay_retained`
- `cursor_expired`
- `snapshot_required`
- `snapshot_pending`/`snapshot_durable`
- `two_subscribers_stable`/`two_scopes_stable`
- `flood_ready`
- `provider_loss_barrier`
- `durable_checkpoint_c1`/`durable_effects_plus_checkpoint`/`known_safe_checkpoint`
- `restart_from_durable_store`
- `fresh_checkpoint_issue`
- `transport_connected`

Expected states use the closed vocabularies for connection and session:

- Connection: `ACTIVE`.
- Session: `unchanged` or `active` for a new session after reconnect.

## Coverage

| Test | Topic |
|---|---|
| `CONF-URP-001` | Mandatory-only fallback and per-connection negotiation isolation |
| `CONF-URP-002` | Scoped duplicate tolerance across the recovered/live boundary |
| `CONF-URP-003` | Gap detection and local recovery-needed with no generation change |
| `CONF-URP-004` | Replay paging as one page per correlated RpcResult |
| `CONF-URP-005` | Retention-window miss: snapshot-required with binding and G intact |
| `CONF-URP-006` | Snapshot gate: `(P, S, H, G, S0)` binding, local completion, same-G install |
| `CONF-URP-007` | Reconnect with renegotiation, fresh handle and boundary |
| `CONF-URP-008` | Reject-new-work before acceptance |
| `CONF-URP-009` | True scoped provider loss with next_generation trailer fencing |
| `CONF-URP-010` | Subscriber-local saturation: terminated + `local-queue-exhausted`, no next_generation |
| `CONF-URP-011` | Fixed-boundary round plus fresh-handle second gap |
| `CONF-URP-012` | Lost completion: bounded exact retry, re-emission, then retire handle |
| `CONF-URP-013` | Supersede retires the handle even at an equal boundary |
| `CONF-URP-014` | No wire carrier for `RecoverySnapshotComplete` |
| `CONF-URP-015` | Durable-known-safe resume after crash without confirmation |
| `CONF-URP-016` | Unoffered Confirm versus issued-checkpoint validation |
| `CONF-URP-017` | Same-generation installation without a provider rebase |

Details are in [recovery prose](recovery.md). Neutral fixtures only:
generic subscription, generic key and value read, and echo round trip.
