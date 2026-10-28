#ifndef SYNTRA_PRODUCTION_H
#define SYNTRA_PRODUCTION_H

/* Syntra production native ABI (transport-agnostic frame pump).
 *
 * The embedding application owns transport bytes, authentication policy,
 * authorization policy, method dispatch, persistence, and recovery.
 * Rust owns version negotiation, frame validation, correlation tracking,
 * deadlines, cancellation observation, and outbound queueing.
 *
 * Build the Rust library with:
 *   cargo build -p syntra-ffi --features production
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYNTRA_FFI_ABI_VERSION 1u
#define SYNTRA_FFI_OK 0
#define SYNTRA_FFI_INVALID (-1)
#define SYNTRA_FFI_CLOSED (-2)
/* Reserved: compare syntra_ffi_abi_version() against SYNTRA_FFI_ABI_VERSION
 * out of band; not returned. */
#define SYNTRA_FFI_ABI_MISMATCH (-3)
#define SYNTRA_FFI_NOMEM (-4)
/* Reserved as a return code: expiry is reported via expired=1 (host_answer)
 * and reap lists with SYNTRA_FFI_OK; not returned. */
#define SYNTRA_FFI_EXPIRED (-5)
#define SYNTRA_FFI_INTERNAL (-6)

/* Opaque handles. Open exactly once, close exactly once. */
typedef struct syntra_ffi_client syntra_ffi_client_t;
typedef struct syntra_ffi_host syntra_ffi_host_t;

uint32_t syntra_ffi_abi_version(void);
/* Frees an owned (ptr,len) buffer exactly once with its original length.
 * (NULL,0) is valid and does nothing. Use for every out buffer below. */
void syntra_ffi_free(uint8_t *ptr, uintptr_t len);

/* Initiator core. credential (may be NULL iff len==0, max 16 KiB) is copied.
 * default_timeout_ms==0 defaults to 3000; max_concurrent==0 defaults to 16. */
/* hello/out buffers below are owned: free exactly once with syntra_ffi_free. */
int32_t syntra_ffi_client_open(uint32_t min_version, uint32_t max_version,
    const uint8_t *credential, uintptr_t credential_len,
    uint32_t default_timeout_ms, uint32_t max_concurrent,
    syntra_ffi_client_t **out);
int32_t syntra_ffi_client_hello_frame(syntra_ffi_client_t *c,
    uint8_t **out, uintptr_t *out_len);
int32_t syntra_ffi_client_activate(syntra_ffi_client_t *c,
    const uint8_t *ready_frame, uintptr_t len);
/* Ingests max 1 MiB frame. terminal_ids must hold terminal_cap entries;
 * terminal_n always written. If terminal_ids==NULL or terminal_cap==0 the
 * completed id is consumed but not reported. notifications is always
 * written: 1 if a notification arrived, else 0. */
int32_t syntra_ffi_client_on_frame(syntra_ffi_client_t *c,
    const uint8_t *frame, uintptr_t len,
    uint64_t *terminal_ids, uintptr_t terminal_cap, uintptr_t *terminal_n,
    int32_t *notifications);
/* method (1..512 bytes) and payload (max 1 MiB) are borrowed. Returns owned
 * request frame. */
int32_t syntra_ffi_client_begin_call(syntra_ffi_client_t *c, uint64_t request_id,
    const uint8_t *method, uintptr_t method_len,
    const uint8_t *payload, uintptr_t payload_len, uint32_t timeout_ms,
    uint8_t **out_req_frame, uintptr_t *out_len);
int32_t syntra_ffi_client_cancel(syntra_ffi_client_t *c, uint64_t request_id,
    uint8_t **out_cancel_frame, uintptr_t *out_len);
int32_t syntra_ffi_client_take_outcome(syntra_ffi_client_t *c, uint64_t request_id,
    uint8_t **out, uintptr_t *out_len, int32_t *present);
int32_t syntra_ffi_client_poll_notification(syntra_ffi_client_t *c,
    uint8_t **out, uintptr_t *out_len, int32_t *present);
/* Cumulative notification-loss totals: (dropped_count, dropped_bytes) for
 * notifications discarded when the bounded queue was full. The queue stays
 * non-blocking and drops the newest notification; counters advance exactly
 * once per drop (no double-counting), unifying with the async Rust
 * notification_loss and the Go LossTotals signals. */
int32_t syntra_ffi_client_notification_loss(syntra_ffi_client_t *c,
    uint64_t *dropped_out, uint64_t *dropped_bytes_out);
int32_t syntra_ffi_client_reap_expired(syntra_ffi_client_t *c,
    uint64_t *ids, uintptr_t cap, uintptr_t *n);
int32_t syntra_ffi_client_close(syntra_ffi_client_t *c);

/* Responder core. Dispatch lives in the embedding application.
 * host_accept_hello rejects a second hello (negotiated already set or active).
 * host_auth_complete: principal is borrowed UTF-8, 1..512 bytes; returns owned
 * ready frame and activates the host. host_answer: expired=1 (with OK) means
 * the id was unknown or past deadline; still returns OK. host_on_frame:
 * cancel_ids must hold cancel_cap entries; cancel_n always written. If
 * cancel_ids==NULL or cancel_cap==0 cancels are consumed but not reported. */
int32_t syntra_ffi_host_open(uint32_t min_version, uint32_t max_version,
    uint32_t max_concurrent, syntra_ffi_host_t **out);
int32_t syntra_ffi_host_accept_hello(syntra_ffi_host_t *h,
    const uint8_t *frame, uintptr_t len, uint32_t *version_out);
int32_t syntra_ffi_host_auth_complete(syntra_ffi_host_t *h,
    const char *principal, uintptr_t principal_len,
    uint8_t **out_ready_frame, uintptr_t *out_len);
int32_t syntra_ffi_host_on_frame(syntra_ffi_host_t *h,
    const uint8_t *frame, uintptr_t len,
    uint8_t **out_response, uintptr_t *out_len, int32_t *has_response,
    uint64_t *cancel_ids, uintptr_t cancel_cap, uintptr_t *cancel_n);
int32_t syntra_ffi_host_take_pending(syntra_ffi_host_t *h,
    uint64_t *request_id_out, uint8_t **out_req_frame, uintptr_t *out_len,
    int32_t *present);
int32_t syntra_ffi_host_is_cancelled(syntra_ffi_host_t *h, uint64_t request_id,
    int32_t *cancelled);
int32_t syntra_ffi_host_version(syntra_ffi_host_t *h, uint32_t *version_out);
int32_t syntra_ffi_host_answer(syntra_ffi_host_t *h,
    const uint8_t *result_frame, uintptr_t len, int32_t *expired);
int32_t syntra_ffi_host_notify(syntra_ffi_host_t *h,
    const uint8_t *payload, uintptr_t len);
int32_t syntra_ffi_host_next_outbound(syntra_ffi_host_t *h,
    uint8_t **out, uintptr_t *out_len, int32_t *present);
int32_t syntra_ffi_host_reap_expired(syntra_ffi_host_t *h,
    uint64_t *ids, uintptr_t cap, uintptr_t *n);
int32_t syntra_ffi_host_close(syntra_ffi_host_t *h);

/* Reliable-session validation parity (syntra.reliable-session/1, no wire change).
 * Pure shape checks over opaque bytes; no handles. Inputs are copied into a
 * bounded temporary allocation (at most 256 B per call) before validation. */
int32_t syntra_ffi_reliable_session_id_valid(const uint8_t *id, uintptr_t len);
int32_t syntra_ffi_reliable_delivery_id_valid(const uint8_t *id, uintptr_t len);
int32_t syntra_ffi_reliable_resume_credential_valid(const uint8_t *cred, uintptr_t len);
int32_t syntra_ffi_reliable_epoch_advance_valid(uint64_t current, uint64_t proposed);
int32_t syntra_ffi_reliable_negotiate_lease(uint32_t idle_ms, uint32_t keepalive_ms, uint32_t *idle_out, uint32_t *keepalive_out);

#ifdef __cplusplus
}
#endif
#endif
