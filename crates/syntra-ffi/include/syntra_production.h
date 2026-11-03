#ifndef SYNTRA_PRODUCTION_H
#define SYNTRA_PRODUCTION_H

#ifdef SYNTRA_FIXTURE_H
#error "fixture and production headers describe mutually exclusive ABI modes"
#endif

/* Apache-2.0. Syntra 1.0 shared-runtime production native ABI 1. Build with production;
 * default and test-fixture-only artifacts do NOT export these symbols.
 *
 * The native ABI version is independent of the negotiated Core wire version.
 *
 * This low-level embedding boundary adapts plaintext Core frames to the shared
 * runtime. It does NOT establish a canonical connection or an end-to-end secure
 * session, and implements no cryptographic record protection. The embedding
 * application's protected-I/O driver owns Syntra encrypted establishment and
 * record protection, carrier framing, transport security, peer verification,
 * close, partial writes and trustworthy receipt ordering. This plaintext frame
 * boundary is not an unencrypted Syntra mode. WSS additionally requires verified
 * TLS supplied by that driver; TLS does not replace Syntra encryption.
 * No recovery host/provider, reconnect or enrollment API is exposed. The typed
 * recovery CLIENT/storage contract is in syntra_recovery.h.
 *
 * Memory/concurrency contract:
 * - Every non-NULL pointer must be aligned, live and valid for its stated
 *   length. All scalar/output pointers are required, independently writable,
 *   and cannot overlap inputs/other outputs. Input NULL is valid iff len==0.
 * - Inputs are copied during the call. Returned buffers are owned immutable
 *   byte slices (not NUL-terminated), freed exactly once with syntra_free
 *   and their original length. (NULL,0) is valid. No callback retains pointers.
 * - Handles support concurrent non-destructive calls; receipt/emit ordering
 *   still requires one reader and one writer. Destroy requires exclusive use,
 *   succeeds only after shutdown_poll joined the owner, and consumes exactly
 *   once. Never use the pointer after successful destroy, even with an old
 *   generation. Generation checking cannot make use-after-free safe.
 * - No function waits for network or foreign execution. Mutex contention and
 *   native runtime/thread creation are synchronous. Policy callbacks must not
 *   block, unwind, retain borrowed buffers, or reenter ANY function on an owner.
 *   Allocation aborts, panic=abort and invalid pointers cannot be contained.
 *
 * Policy callbacks run on the owner's dedicated Tokio thread. context and
 * function pointers must remain live/thread-safe through successful destroy.
 * authenticate returns 0 and writes a UTF-8 principal of 1..capacity bytes;
 * writes MUST stay within capacity. Return 7 or 16 for generic rejection.
 * authorize checks the actual bound principal/method before every dispatch:
 * 0 permits, 16 withdraws authority, all other values deny. No fixture or
 * implicit anonymous/allow-all policy is installed. Dispatch delivery is not
 * permission to skip application-side effect/revocation checks.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__wasm__) || defined(__wasm32__) || defined(__wasm64__)
#error "syntra-ffi does not support WASM: native ABIs only"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SYNTRA_ABI_VERSION 1u
#define SYNTRA_CAP_CORE UINT64_C(1)
/* Reserved; this plaintext frame adapter leaves record protection UNSET. */
#define SYNTRA_CAP_RECORD_PROTECTION UINT64_C(2)
#define SYNTRA_CAP_RECOVERY_CLIENT UINT64_C(4)
#define SYNTRA_CAP_LIFECYCLE UINT64_C(8)
#define SYNTRA_OK 0
#define SYNTRA_PENDING 1 /* empty queue, or operation still pending */
#define SYNTRA_SHUTDOWN_INCOMPLETE 2
#define SYNTRA_INVALID (-1)
#define SYNTRA_CLOSED (-2)
#define SYNTRA_ABI_MISMATCH (-3)
#define SYNTRA_INTERNAL (-6) /* includes observed runtime task panic */
#define SYNTRA_STALE (-7) /* generation/token unknown, consumed or retired */
#define SYNTRA_BUSY (-8) /* bounded capacity / outstanding emission */

#ifndef SYNTRA_OWNER_DEFINED
#define SYNTRA_OWNER_DEFINED
typedef struct syntra_t syntra_t;
#endif
typedef int32_t (*syntra_authenticate_fn)(uintptr_t context,
    const uint8_t *credential, uintptr_t credential_len,
    uint8_t *principal, uintptr_t capacity, uintptr_t *principal_len);
typedef int32_t (*syntra_authorize_fn)(uintptr_t context,
    const uint8_t *principal, uintptr_t principal_len,
    const uint8_t *method, uintptr_t method_len);
typedef struct syntra_policy_t {
    uintptr_t context;
    syntra_authenticate_fn authenticate;
    syntra_authorize_fn authorize;
} syntra_policy_t;

uint32_t syntra_abi_version(void);
/* Local implementation availability, NOT peer negotiation or security status.
 * Returns CORE | RECOVERY_CLIENT | LIFECYCLE; RECORD_PROTECTION stays unset. */
uint64_t syntra_capabilities(void);
/* Fixed bounded defaults: 32 Core calls, 32 writer/notification entries,
 * 32 foreign operations (including unread results), 32 receipt tickets,
 * 32 foreign dispatch leases; shared process host execution budget 1024.
 * Core timers use ConnectionConfig defaults (handshake 5s, RPC 30s, cap 120s).
 * Each input/output frame is bounded to 1 MiB; credentials to 8192 bytes.
 * Tokens/generations are nonzero, process-unique and never wrap/reuse. */
int32_t syntra_client_open(uint32_t abi, syntra_t **out, uint64_t *generation);
int32_t syntra_host_open(uint32_t abi, syntra_policy_t policy,
    syntra_t **out, uint64_t *generation);

/* Default owners use shared ElapsedClock (BOOTTIME on Linux/Android, mach
 * continuous time on Apple). A client may supply trusted, process-scoped,
 * suspend-inclusive elapsed nanoseconds; NEVER peer/adjustable wall time.
 * sample returns 0 and writes monotonically increasing nanoseconds, or nonzero
 * on unknown continuity. Regression/failure is sticky. Context/function remain
 * live until destroy, including storage workers. Sampling may occur on ANY
 * thread under protocol locks: prompt, thread-safe, nonblocking, no unwind,
 * no FFI reentry. Do not persist monotonic timestamps. Custom host clocks retain
 * the same shared process execution budget through the runtime's combined
 * budget+clock constructor; they never reset cross-replacement accounting.
 */
typedef int32_t (*syntra_clock_sample_fn)(uintptr_t, uint64_t *nanoseconds);
typedef struct syntra_clock_t {
    uintptr_t context;
    syntra_clock_sample_fn sample;
} syntra_clock_t;
int32_t syntra_client_open_clock(uint32_t abi, syntra_clock_t clock,
    syntra_t **out, uint64_t *generation);
int32_t syntra_host_open_clock(uint32_t abi, syntra_policy_t policy,
    syntra_clock_t clock, syntra_t **out, uint64_t *generation);
/* suspend calls shared suspend() synchronously, fencing FFI admission, receipt,
 * Host/Initiator emission and dispatch delivery. Previously committed units
 * cannot be retracted: abort their carrier; never resume partial writes.
 * platform_wake also fences synchronously, then retains shared platform_wake.
 * continuity_known is 0 or 1; 0 invalidates the clock before wake. Wake ALWAYS
 * retires the connection, never reopens it. Shared gates expire pending calls
 * before loss; already selected Core results remain selected. No buffered input
 * or send can run on this owner. Poll old Core terminals, acknowledge stopped
 * foreign work, close carrier, shutdown/join/destroy. Open a fresh authenticated
 * generation and renegotiate recovery; no handle transfers.
 */
int32_t syntra_suspend(syntra_t *, uint64_t generation);
int32_t syntra_platform_wake(syntra_t *, uint64_t generation, int32_t continuity_known);

/* Submit returns an operation token, NOT a wire request ID. Poll consumes
 * exactly one terminal outcome (grpc_code==0 success; otherwise Core code
 * 1..16, no private diagnostics). Handshake success bytes are connection_id;
 * RPC success bytes are opaque payload. RPC budget starts at FFI call entry;
 * runtime scheduling delay is subtracted before shared Core admission (positive
 * floored milliseconds, no extension). request_id is diagnostic, 0 if no
 * allocation occurred or for non-RPC operations. A completion candidate is
 * selected by shared Core gates; successful FFI submission is not a wire ack.
 * Poll after deadlines still returns a previously selected result unchanged.
 * No arbitrary RPC/mutation is retried/replayed automatically. */
int32_t syntra_handshake(syntra_t *, uint64_t generation,
    const uint8_t *credential, uintptr_t len, uint64_t *token);
int32_t syntra_call(syntra_t *, uint64_t generation,
    const uint8_t *method, uintptr_t method_len,
    const uint8_t *payload, uintptr_t len, uint32_t timeout_ms, uint64_t *token);
/* Core RPC and typed recovery operation tokens only (not handshake/notify).
 * Core local cancellation is terminal subject to the
 * Core deadline/selected-result gate. Remote Cancel is advisory; effects may
 * already have occurred. Never rewrites a handed-off unit. */
int32_t syntra_cancel(syntra_t *, uint64_t generation, uint64_t token);
int32_t syntra_poll(syntra_t *, uint64_t generation, uint64_t token,
    int32_t *grpc_code, uint64_t *request_id, uint8_t **out, uintptr_t *len);

/* Call receipt immediately when a complete bounded Frame is reconstructed,
 * before validation/queueing/earlier delivery. Feed receipt tickets FIFO into
 * ingest, once each; BUSY leaves the oldest ticket retryable. A ticket contains
 * a local trusted monotonic timestamp, not a peer clock. Host budgets start
 * there. Initiator selection occurs on actual ingest, NOT receipt marking:
 * buffered results cannot win retroactively. One inbound task first-polls in
 * ticket order. OK means queued; inspect status/operation results for protocol
 * failure. Unused tickets retire at shutdown; already-queued ingress may finish
 * under Core closing/drain gates. Remaining input drops at runtime teardown. */
int32_t syntra_receipt(syntra_t *, uint64_t generation, uint64_t *token);
int32_t syntra_ingest(syntra_t *, uint64_t generation, uint64_t receipt,
    const uint8_t *data, uintptr_t len);

/* emit is the queued->emitting commitment boundary, immediately before
 * synchronous carrier handoff/encryption. Do not use for speculative peek or
 * prefetch. It passes the ORIGINAL runtime Vec through prepare_outbound once,
 * floors remaining time and suppresses retired calls. Only one unit may be
 * outstanding. Retain the immutable returned bytes across partial writes;
 * finish this unit in order, or abort the carrier. No retry/re-encryption of a
 * committed unit. emitted acknowledges full unit handoff; it is not peer
 * receipt and does not free the byte buffer. On I/O failure close the carrier
 * and call transport_closed instead, never emitted. */
int32_t syntra_emit(syntra_t *, uint64_t generation,
    uint64_t *token, uint8_t **out, uintptr_t *len);
int32_t syntra_emitted(syntra_t *, uint64_t generation, uint64_t token);

/* Host dispatches are correlated only by token, never by foreign wire ID.
 * take_dispatch transfers method/payload but RETAINS a runtime execution lease.
 * After delivery the embedding MUST eventually call complete exactly once,
 * even if cancelled/expired/withdrawn/closed, and only once its external work
 * actually stops. Cancellation does not release its execution charge.
 * complete code 0 carries payload; 1..16 carries no payload, generic diagnostic.
 * STALE may acknowledge stopped late work (lease released, no new wire result).
 * OK accepts a candidate, not a promise of remote success: Core deadline-first
 * selection remains authoritative. Undelivered cancelled slots are reclaimed.
 */
int32_t syntra_take_dispatch(syntra_t *, uint64_t generation,
    uint64_t *token, uint8_t **method, uintptr_t *method_len,
    uint8_t **payload, uintptr_t *payload_len);
int32_t syntra_dispatch_cancelled(syntra_t *, uint64_t generation,
    uint64_t token, int32_t *cancelled);
int32_t syntra_complete(syntra_t *, uint64_t generation, uint64_t token,
    int32_t grpc_code, const uint8_t *payload, uintptr_t len);
int32_t syntra_notify(syntra_t *, uint64_t generation,
    const uint8_t *data, uintptr_t len, uint64_t *token);
/* One outstanding next_notification operation; poll it before requesting next.
 * Core's bounded lossy notification queue/loss accounting is preserved. */
int32_t syntra_next_notification(syntra_t *, uint64_t generation, uint64_t *token);
/* Schedules shared Host withdrawal once; no new application operation
 * submissions afterwards (receive/emit/control paths remain available).
 * Shared Host commits revocation on its next poll, settles unfinished calls,
 * unbinds principal and retains its close owner. Already selected output is
 * not replaced. status reason 16 reports committed withdrawal. */
int32_t syntra_withdraw(syntra_t *, uint64_t generation);

/* Begin retained shutdown, total_ms 2..30000. No new FFI admissions. Drain
 * uses shared runtime ShutdownBudget's cutoff, reserving positive time for
 * teardown/join (min(total/4,1s)); repeated calls never extend it. Keep pumping
 * selected
 * output to cutoff, then CLOSE the foreign carrier and attest transport_closed.
 * The library cannot close a carrier it does not own. No emission after total
 * expiry. Incomplete retains owner/leases and can later be reconciled, never
 * silently detached/freed. Later OK means observed eventual completion, NOT
 * meeting the original shutdown budget. Callback blocking can delay runtime
 * progress indefinitely; callers must obey the nonblocking hook contract.
 * transport_closed also initiates abortive shutdown on unexpected loss.
 * shutdown_poll returns OK only after external leases stop, close/FFI tasks
 * settle, and native runtime teardown/thread join are observed. Unread outcomes
 * remain pollable until destroy (destroy explicitly discards them).
 * INTERNAL reports an observed panic/failure, never successful shutdown; if
 * thread join nevertheless finished, destroy may release that failed owner.
 */
int32_t syntra_shutdown(syntra_t *, uint64_t generation, uint32_t total_ms);
int32_t syntra_transport_closed(syntra_t *, uint64_t generation);
int32_t syntra_shutdown_poll(syntra_t *, uint64_t generation);
int32_t syntra_status(syntra_t *, uint64_t generation, int32_t *closed,
    int32_t *terminal_grpc_code, uintptr_t *external_work,
    uint64_t *notification_lost_count, uint64_t *notification_lost_bytes);
/* external_work counts retained dispatch AND storage ownership, including
 * undelivered slots not yet pruned. Neither CLOSED nor zero pending Core calls
 * proves foreign work has stopped; shutdown_poll is the join/ownership gate. */
int32_t syntra_destroy(syntra_t *, uint64_t generation);
void syntra_free(uint8_t *, uintptr_t len);

#ifdef __cplusplus
}
#endif
#include "syntra_recovery.h"
#endif
