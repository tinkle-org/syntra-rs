#ifndef SYNTRA_MANAGED_H
#define SYNTRA_MANAGED_H
#include "syntra_production.h"
#ifdef __cplusplus
extern "C" {
#endif

/* Optional protected TCP client (managed-media). Owner IDs and operation tokens
 * are local, nonzero and never reused. Connection generations are lane-local.
 * Do not cast this owner to syntra_t or pass it to the frame-pump API.
 * All pointer, alignment, nonaliasing and exclusive-destroy obligations of
 * syntra_production.h apply. Inputs are counted slices, never C strings. */
typedef struct syntra_managed_t syntra_managed_t;
typedef struct syntra_view_t { const uint8_t *data; uintptr_t len; } syntra_view_t;
#define SYNTRA_MANAGED_RETURNING 2u
typedef struct syntra_managed_config_t {
    /* Exact trusted numeric IP:port (bracket IPv6), UTF-8 scope (1..255),
     * pinned public key (32), encrypted hello credential (0..8192 bytes).
     * No discovery, pin learning, carrier fallback or bootstrap downgrade. */
    syntra_view_t address, scope, server_pin, credential;
    uint32_t mode, server_key_id;
    uint64_t epoch;
    /* Returning only: nonzero lookup handle (8), authorization key (32)
     * and epoch. Bootstrap is rejected. */
    syntra_view_t handle, authorization_key;
} syntra_managed_config_t;

#define SYNTRA_MANAGED_INTERACTIVE 1u
#define SYNTRA_MANAGED_BULK 2u
#define SYNTRA_MANAGED_STARTING 0u
#define SYNTRA_MANAGED_CONNECTING 1u
#define SYNTRA_MANAGED_READY 2u
#define SYNTRA_MANAGED_BACKOFF 3u
#define SYNTRA_MANAGED_PAUSED 4u
#define SYNTRA_MANAGED_OFFLINE 5u
#define SYNTRA_MANAGED_BLOCKED 6u
#define SYNTRA_MANAGED_EXHAUSTED 7u
#define SYNTRA_MANAGED_STOPPING 8u
#define SYNTRA_MANAGED_STOPPED 9u
#define SYNTRA_MANAGED_SHUTDOWN_INCOMPLETE 10u
#define SYNTRA_MANAGED_RETIRED 11u
typedef struct syntra_lane_status_t {
    uint32_t state, attempt;
    uint64_t generation; /* nonzero only when ready */
} syntra_lane_status_t;
typedef struct syntra_managed_result_t {
    int32_t grpc_code; /* 0 success, otherwise generic Core code; no error bytes */
    uint32_t has_data; /* distinguishes empty notification from end of stream */
    uint64_t generation, dropped_count, dropped_bytes;
    syntra_bytes_t data; /* caller owns; release once with syntra_free(data,len) */
} syntra_managed_result_t;

/* Open copies all provisioning during the call; OK means admitted, not ready.
 * Rust owns protected I/O and retries connections; application RPCs are never
 * replayed. No call waits for readiness, network I/O or callback completion.
 * Runtime registration runs on a worker. Bounded copies, OS thread creation
 * and short locks are synchronous. PENDING on submission means no job/token;
 * cold bulk demand starts a connection. Retry admission only, never a submitted
 * mutation. The two lanes have independent generations, queues and lifecycles.
 * Provisioning is immutable. To replace a credential/key/pin, shut down,
 * poll and destroy the owner, then open with fresh trusted provisioning. Retry,
 * wake and reconnect never rotate credentials. Reuse a store scope only for
 * the same authenticated account and authority. No token transfers to a new owner. */
int32_t syntra_managed_open(uint32_t abi, const syntra_managed_config_t *,
    syntra_managed_t **out, uint64_t *owner_id);

/* Opt-in, interactive ResumeDurable subscription. Provision a nonempty scope,
 * stable stream and selector (each <=1024 bytes) and seed a real full record
 * in the application store. Missing state/profile/history fails closed.
 * Restore receives that record; apply computes a complete replacement for a
 * batch. SDK owns persist-and-confirm. Neither callback may publish independent
 * irreversible effects. Connection generation (g) differs from record/batch G.
 * Serial callbacks on an SDK worker: return promptly, no reentry/unwind. Views
 * and record/output pointers live only for the call. Return zero on success;
 * apply writes at most capacity (1 MiB) and sets used. Retain function/context
 * until terminal shutdown. All other open inputs are copied before return. */
typedef int32_t (*syntra_update_restore_fn)(uintptr_t context, uint64_t g, const syntra_record_t *);
typedef int32_t (*syntra_update_apply_fn)(uintptr_t context, uint64_t g, uint64_t batch_generation,
    syntra_view_t predecessor, syntra_view_t checkpoint, syntra_view_t payload,
    uint8_t *full_state, uintptr_t capacity, uintptr_t *used);
typedef struct syntra_updates_t {
    syntra_view_t principal_scope, stable_stream, selector;
    uintptr_t context;
    syntra_update_restore_fn restore;
    syntra_update_apply_fn apply;
} syntra_updates_t;
int32_t syntra_managed_open_updates(uint32_t abi, const syntra_managed_config_t *,
    const syntra_updates_t *, syntra_managed_t **out, uint64_t *owner_id);
#define SYNTRA_UPDATES_DISABLED 0u
#define SYNTRA_UPDATES_WAITING 1u
#define SYNTRA_UPDATES_RESTORING 2u
#define SYNTRA_UPDATES_RESTORED 3u
#define SYNTRA_UPDATES_FAILED 4u
typedef struct syntra_update_status_t {uint32_t state; int32_t grpc_code; uint64_t generation;} syntra_update_status_t;
/* RESTORED means actual CaughtUp on this interactive generation. Inspect lane
 * status too (e.g. recovery negotiation blocked). No connection_id or ready
 * state substitutes for restoration. */
int32_t syntra_managed_update_status(syntra_managed_t *, uint64_t owner_id, syntra_update_status_t *out);
/* Same P/S, LOAD/CAS_COMMIT, expiry, status, receipt and request-free rules as
 * syntra_recovery.h. Service the one request promptly even during reconnect.
 * A delivered request must be acknowledged after external work actually stops;
 * shutdown_poll remains incomplete until then. Timed-out bridges need a new
 * owner and reconciliation. Never acknowledge an uncertain commit as DURABLE. */
int32_t syntra_managed_storage_take(syntra_managed_t *, uint64_t owner_id, syntra_storage_request_t *out);
int32_t syntra_managed_storage_complete(syntra_managed_t *, uint64_t owner_id,
    uint64_t receipt, uint32_t status, const syntra_record_t *record);
int32_t syntra_managed_status(syntra_managed_t *, uint64_t owner_id,
    uint32_t lane, syntra_lane_status_t *out);
/* At most 32 operations per owner, including completed but unconsumed results.
 * Raw bulk calls and transfers together use at most 6 of those slots.
 * Interactive calls and notification pulls also share 32 slots and 32 MiB:
 * one slot and 1 MiB per operation, plus method and payload bytes per call.
 * BUSY can therefore precede the 32-job limit. Poll to consume unread results.
 * Method <=512 bytes, payload/result <=1 MiB. Poll consumes exactly once.
 * Free a prior result's data before reusing the output. */
int32_t syntra_managed_call(syntra_managed_t *, uint64_t owner_id, uint32_t lane,
    syntra_view_t method, syntra_view_t payload, uint32_t timeout_ms, uint64_t *token);
/* INTERACTIVE only; one outstanding pull, bound to its submission generation.
 * Poll its token to read the bounded inbox; a PENDING poll dequeues nothing. */
int32_t syntra_managed_next_notification(syntra_managed_t *, uint64_t owner_id,
    uint32_t lane, uint64_t *token);
int32_t syntra_managed_poll(syntra_managed_t *, uint64_t owner_id,
    uint64_t token, syntra_managed_result_t *out);

typedef struct syntra_manifest_t {
    uint8_t object[16], transfer_id[16], sha256[32];
    uint64_t version, length;
} syntra_manifest_t;
/* Optional verified-download export: synchronous, bounded borrowed chunk.
 * Consume/copy before return; return 0 for success, any other value stops
 * export. Keep function and context live until terminal poll consumes this
 * token, or shutdown_poll observes completion. Cancellation is NOT that fence.
 * Runs on a transfer worker; must return promptly, never unwind or reenter.
 * Output may be partial on cancel/sink failure; the SQLite copy is retained. */
typedef int32_t (*syntra_chunk_fn)(uintptr_t context, const uint8_t *data, uintptr_t len);
typedef struct syntra_sink_t { uintptr_t context; syntra_chunk_fn chunk; } syntra_sink_t;
typedef struct syntra_progress_t {
    uint64_t completed_rpcs, request_bytes, response_bytes, object_bytes;
} syntra_progress_t;
/* <=2 transfer jobs including unread terminals. MediaClient streams through
 * the bulk lane. Pin the immutable manifest (<=1 GiB, nonzero version) across
 * explicit resumes. Supply trusted UTF-8 paths (1..4096), private regular files;
 * the download DB is bound to a stable authority+account scope (1..1024).
 * Download requires an authorized Read at EOF even for cached or empty objects;
 * Describe grants metadata access only.
 * All inputs except the callback/context are copied before return. Progress
 * counts successful media RPC payloads in this job, including protocol fields,
 * not a durable checkpoint or completion. Poll for the terminal grpc_code.
 * Cancel is local/advisory: a submitted write may commit. No abort or replay.
 * Shutdown requests cancellation and waits via poll for all callbacks/work. */
int32_t syntra_managed_upload(syntra_managed_t *, uint64_t owner_id,
    const syntra_manifest_t *, syntra_view_t source_path, uint64_t *token);
int32_t syntra_managed_download(syntra_managed_t *, uint64_t owner_id,
    const syntra_manifest_t *, syntra_view_t database_path, syntra_view_t store_scope,
    syntra_sink_t sink, uint64_t *token);
int32_t syntra_managed_progress(syntra_managed_t *, uint64_t owner_id,
    uint64_t token, syntra_progress_t *out);
/* For raw calls cancel discards local interest in an unread RPC result. It
 * does not abort execution, retract a mutation or release admission. Poll the
 * same token: it remains pending until the underlying operation settles, then
 * yields CANCELLED without data. Transfer cancellation is described above. */
int32_t syntra_managed_cancel(syntra_managed_t *, uint64_t owner_id, uint64_t token);

#define SYNTRA_MANAGED_PAUSE 1u
#define SYNTRA_MANAGED_RESUME 2u
#define SYNTRA_MANAGED_NETWORK_DOWN 3u
#define SYNTRA_MANAGED_NETWORK_UP 4u
#define SYNTRA_MANAGED_WAKE 5u
#define SYNTRA_MANAGED_RETRY 6u
int32_t syntra_managed_control(syntra_managed_t *, uint64_t owner_id, uint32_t action);
int32_t syntra_managed_shutdown(syntra_managed_t *, uint64_t owner_id);
int32_t syntra_managed_shutdown_poll(syntra_managed_t *, uint64_t owner_id);
/* shutdown_poll returns SHUTDOWN_INCOMPLETE until registration, both lane
 * runtimes and all transfer workers finish. OK (or INTERNAL for an observed
 * worker/supervisor failure) is terminal. Results remain available to poll.
 * Destroy requires shutdown_poll to have observed terminal shutdown. Discards any
 * unread results. Successful destruction consumes the live pointer exactly once. */
int32_t syntra_managed_destroy(syntra_managed_t *, uint64_t owner_id);

#ifdef __cplusplus
}
#endif
#endif
