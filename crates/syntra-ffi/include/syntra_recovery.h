#ifndef SYNTRA_RECOVERY_H
#define SYNTRA_RECOVERY_H
#include <stddef.h>
#include <stdint.h>
#ifndef SYNTRA_OWNER_DEFINED
#define SYNTRA_OWNER_DEFINED
typedef struct syntra_t syntra_t;
#endif
#if defined(__wasm__) || defined(__wasm32__) || defined(__wasm64__)
#error "syntra-ffi does not support WASM: native ABIs only"
#endif

/* Apache-2.0. Typed RecoveryClient, NOT a provider or a durability substitute.
 * All production owner/pointer rules apply. Attach once BEFORE handshake with an
 * explicit provisioned principal storage namespace (1..1024 bytes), not a
 * credential or authority. Authenticate Core normally. Only validated real
 * profile Negotiate enables the immutable inbox. CAP_RECOVERY_CLIENT means
 * implementation availability, never peer support. An FFI Host with no attached
 * RecoveryService correctly returns UNIMPLEMENTED; no fallback/demux is added.
 *
 * Bounds: 4 subscriptions, 32 lifetime H slots, 4 snapshot pages <=256 KiB,
 * full application state <=1 MiB, 1 typed operation (including unread result),
 * 1 storage request/client. Other shared RecoveryLimits remain at defaults.
 * Free aggregates BEFORE reusing them as outputs. Matching aggregate free zeros
 * the struct and frees all owned buffers (not NUL-terminated).
 *
 * Wire H/X never cross this ABI. stream is an opaque local token bound to the
 * owner/generation and an actual runtime H. Retired rounds remain subject to
 * shared runtime fences; token/checkpoint equality never revives them. Selected
 * profile results are fenced on owner retirement, unlike selected Core terminals.
 */
#ifdef __cplusplus
extern "C" {
#endif
typedef struct syntra_bytes_t { uint8_t *data; uintptr_t len; } syntra_bytes_t;
typedef struct syntra_recovery_result_t {
    uint32_t kind;
    int32_t grpc_code;
    uint32_t event, flags;
    uint64_t stream, generation, next_generation;
    uint32_t index, total_pages, page_bytes_max;
    uint64_t restored_generation;
    syntra_bytes_t data, checkpoint, predecessor, restored_checkpoint, restored_state;
} syntra_recovery_result_t;
typedef struct syntra_storage_request_t {
    uint64_t token;
    uint32_t kind, expected_present;
    uint64_t expected_generation, generation;
    syntra_bytes_t principal_scope, stable_stream, expected_checkpoint;
    syntra_bytes_t checkpoint, application_state;
} syntra_storage_request_t;
typedef struct syntra_record_t {
    uint64_t generation;
    const uint8_t *checkpoint;
    uintptr_t checkpoint_len;
    const uint8_t *application_state;
    uintptr_t application_state_len;
} syntra_record_t;

#define SYNTRA_REC_NEGOTIATE 1u
#define SYNTRA_REC_SUBSCRIBE 2u
#define SYNTRA_REC_REPLAY 3u
#define SYNTRA_REC_CATCH_UP 4u
#define SYNTRA_REC_RETRY_COMPLETION 5u
#define SYNTRA_REC_NEXT_EVENT 6u
#define SYNTRA_REC_PERSIST_CONFIRM 7u
#define SYNTRA_REC_SNAPSHOT_OFFER 8u
#define SYNTRA_REC_SNAPSHOT_FETCH 9u
#define SYNTRA_REC_SNAPSHOT_BYTES 10u
#define SYNTRA_REC_INSTALL_CONFIRM 11u
#define SYNTRA_REC_UNSUBSCRIBE 12u
#define SYNTRA_REC_INITIAL_LIVE 1u
#define SYNTRA_REC_RESUME_DURABLE 2u
#define SYNTRA_REC_SNAPSHOT_CURRENT 3u

int32_t syntra_recovery_attach(syntra_t *, uint64_t generation,
    const uint8_t *principal_scope, uintptr_t len);
int32_t syntra_recovery_negotiate(syntra_t *, uint64_t generation, uint64_t *operation);
int32_t syntra_recovery_subscribe(syntra_t *, uint64_t generation,
    const uint8_t *selector, uintptr_t selector_len, const uint8_t *stable_stream,
    uintptr_t stable_len, uint32_t intent, uint64_t *operation);
/* kind 3..12. stream required except NEXT_EVENT (zero). index only for Fetch;
 * full transformed state only for Persist/Install; otherwise len must be zero.
 * wait_ms 1..30000 is one absolute elapsed budget. NEXT_EVENT timeout/cancel is
 * cancellation-safe; interruption of stateful work requires a fresh owner and
 * reconciliation. No implicit mutation replay. Cancel via syntra_cancel;
 * consume ONLY via recovery_poll (ordinary poll rejects profile operations).
 */
int32_t syntra_recovery_step(syntra_t *, uint64_t generation, uint32_t kind,
    uint64_t stream, uint32_t index, const uint8_t *data, uintptr_t len,
    uint32_t wait_ms, uint64_t *operation);
int32_t syntra_recovery_poll(syntra_t *, uint64_t generation,
    uint64_t operation, syntra_recovery_result_t *out);
void syntra_recovery_result_free(syntra_recovery_result_t *);
/* Successful result fields (others zero):
 * Negotiate: flags bit0 confirmed, total_pages/page_bytes_max negotiated caps.
 * Subscribe: stream/G/checkpoint=B; flags bit0 restored full state in restored_*.
 * Restore that state BEFORE applying offers. Replay: flags bit0 final page,
 * index=batch count, predecessor/checkpoint page bounds. Entries are offered
 * ONLY via NEXT_EVENT. CatchUp accepts a trigger, NOT completion. RetryCompletion
 * is an exact retry. NEXT_EVENT event: 1 Batch (data, predecessor/checkpoint,G),
 * 2 CaughtUp, 3 InitialLiveBaseline (checkpoint=B, no restoration/durability
 * claim), 4 SnapshotRequired, 5 RecoveryNeeded (old G, optional next G or zero).
 * All events carry stream. Terminal reason strings are not disclosed.
 * Persist: checkpoint/G after durable commit AND matching Confirm response.
 * SnapshotOffer: total_pages/page_bytes_max/checkpoint=S0, G stays Subscribe G.
 * Fetch: index/data/checkpoint. SnapshotBytes: complete bytes for application
 * validation/transformation, NOT installation. Install: checkpoint/G after
 * durable full-state installation AND matching SnapshotInstalled. Empty pages
 * are rejected by shared runtime. UNIMPLEMENTED negotiation is explicit
 * mandatory-only unavailability, never recovery success. UNKNOWN commit errors
 * require reload/reconciliation; a failed Confirm never rolls back durable state.
 */

#define SYNTRA_STORAGE_LOAD 1u
#define SYNTRA_STORAGE_CAS_COMMIT 2u
#define SYNTRA_STORAGE_ABSENT 0u
#define SYNTRA_STORAGE_FOUND 1u
#define SYNTRA_STORAGE_DURABLE 2u
#define SYNTRA_STORAGE_UNAVAILABLE 3u
#define SYNTRA_STORAGE_CORRUPT 4u
#define SYNTRA_STORAGE_CONFLICT 5u
#define SYNTRA_STORAGE_COMMIT_UNKNOWN 6u
#define SYNTRA_STORAGE_OVER_LIMIT 7u
/* Asynchronous foreign persistence receipts, NOT a cache. Native RecoveryClient
 * invokes its sync Persistence trait on spawn_blocking; one request is polled
 * here, never blocking Tokio or calling user storage under a protocol lock.
 * LOAD reads exact P/S atomically; return ABSENT(NULL) or FOUND(full record).
 * CAS_COMMIT atomically persists ALL application_state + G/C under exact P/S.
 * expected_present==0 expects absence; otherwise exact expected G/C. An exact
 * FULL-record duplicate is idempotent even with stale expected G/C; all other
 * stale writes MUST return CONFLICT. No checkpoint arithmetic or G relabeling.
 * DURABLE attests effects + state/position ACTUALLY committed under the app's
 * durability contract, not async submission. The library cannot verify fsync
 * or transactions. Uncertain visibility/durability MUST be COMMIT_UNKNOWN.
 *
 * Requests expire after 5 elapsed seconds. Receipt selection and expiry share
 * one storage ownership gate; equality is expired. A timely selected receipt
 * remains selected even if the persistence worker consumes it after expiry.
 * An at/after-deadline DURABLE receipt returns STALE and releases stopped
 * foreign work, but only CommitUnknown reaches the shared client, never Confirm.
 * Cancellation/suspend/wake/shutdown
 * fences the wrapper; a late write cannot Confirm. After take, foreign work is
 * retained until storage_complete even if retired/expired: acknowledge only
 * once work ACTUALLY stops. Freeing bytes is not acknowledgement. Late receipt
 * returns STALE, releases accounting, never revives H/G. A write may remain
 * durable: fresh generation + LOAD reconciles it. No receipt transfers between
 * owners/generations. Unacknowledged storage prevents successful shutdown/free.
 */
int32_t syntra_storage_take(syntra_t *, uint64_t generation,
    syntra_storage_request_t *out);
int32_t syntra_storage_complete(syntra_t *, uint64_t generation,
    uint64_t receipt, uint32_t status, const syntra_record_t *record);
void syntra_storage_request_free(syntra_storage_request_t *);
#ifdef __cplusplus
}
#endif
#endif
