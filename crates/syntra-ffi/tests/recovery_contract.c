#define _POSIX_C_SOURCE 200809L
#include "syntra_production.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test-only function table: calls the ACTUAL exported C signatures in the Rust
 * test binary, not a parallel library instance or a replacement wire engine.
 * POSIX function/data pointer representation is checked by the test loader.
 */
typedef struct {
    __typeof__(&syntra_handshake) handshake;
    __typeof__(&syntra_poll) poll;
    __typeof__(&syntra_emit) emit;
    __typeof__(&syntra_emitted) emitted;
    __typeof__(&syntra_receipt) receipt;
    __typeof__(&syntra_ingest) ingest;
    __typeof__(&syntra_free) free_bytes;
    __typeof__(&syntra_recovery_attach) attach;
    __typeof__(&syntra_recovery_negotiate) negotiate;
    __typeof__(&syntra_recovery_subscribe) subscribe;
    __typeof__(&syntra_recovery_step) step;
    __typeof__(&syntra_recovery_poll) recovery_poll;
    __typeof__(&syntra_recovery_result_free) result_free;
    __typeof__(&syntra_storage_take) storage_take;
    __typeof__(&syntra_storage_complete) storage_complete;
    __typeof__(&syntra_storage_request_free) request_free;
    __typeof__(&syntra_cancel) cancel;
    __typeof__(&syntra_suspend) suspend;
    __typeof__(&syntra_platform_wake) wake;
    __typeof__(&syntra_shutdown) shutdown;
    __typeof__(&syntra_transport_closed) transport_closed;
    __typeof__(&syntra_shutdown_poll) shutdown_poll;
} api;
_Static_assert(sizeof(api) == 22 * sizeof(void *), "POSIX test function table layout");
typedef struct { syntra_t *p; uint64_t g; } peer;
static const api *f;
static void tick(void) { struct timespec t = {0, 1000000}; (void)nanosleep(&t, NULL); }
static void pump(peer a, peer b) {
    uint64_t token = 0, receipt = 0;
    uint8_t *bytes = NULL;
    uintptr_t len = 0;
    int rc = f->emit(a.p, a.g, &token, &bytes, &len);
    if (rc == SYNTRA_PENDING) return;
    assert(rc == 0);
    assert(f->receipt(b.p, b.g, &receipt) == 0);
    assert(f->ingest(b.p, b.g, receipt, bytes, len) == 0);
    assert(f->emitted(a.p, a.g, token) == 0);
    f->free_bytes(bytes, len);
}
static void handshake(peer c, peer h) {
    assert(f->attach(c.p, c.g, (const uint8_t *)"P", 1) == 0);
    uint64_t token = 0;
    assert(f->handshake(c.p, c.g, (const uint8_t *)"token", 5, &token) == 0);
    int rc = 1;
    for (int i = 0; i < 3000 && rc == 1; ++i) {
        pump(c, h); pump(h, c);
        int32_t code = 0;
        uint64_t id = 0;
        uint8_t *data = NULL;
        uintptr_t len = 0;
        rc = f->poll(c.p, c.g, token, &code, &id, &data, &len);
        assert(rc == 0 || rc == 1);
        if (rc == 0) { assert(code == 0); f->free_bytes(data, len); }
        tick();
    }
    assert(rc == 0);
}
static syntra_recovery_result_t wait_result(peer c, peer h, uint64_t token, int expected) {
    syntra_recovery_result_t result = {0};
    int rc = 1;
    for (int i = 0; i < 3000 && rc == 1; ++i) {
        pump(c, h); pump(h, c);
        rc = f->recovery_poll(c.p, c.g, token, &result);
        assert(rc == 0 || rc == 1); tick();
    }
    assert(rc == 0 && result.grpc_code == expected);
    return result;
}
static syntra_storage_request_t wait_storage(peer c, peer h, uint32_t kind) {
    syntra_storage_request_t r = {0};
    int rc = 1;
    for (int i = 0; i < 3000 && rc == 1; ++i) {
        pump(c, h); pump(h, c);
        rc = f->storage_take(c.p, c.g, &r);
        assert(rc == 0 || rc == 1); tick();
    }
    assert(rc == 0 && r.kind == kind && r.token != 0);
    assert(r.principal_scope.len == 1 && r.principal_scope.data[0] == 'P');
    assert(r.stable_stream.len == 1 && r.stable_stream.data[0] == 'S');
    return r;
}
typedef struct { uint64_t g; uint32_t cp_len, state_len; uint8_t cp[16], state[128]; } record;
static record read_record(FILE *file) {
    record r;
    rewind(file); assert(fread(&r, sizeof(r), 1, file) == 1);
    return r;
}
static void durable(FILE *file, const record *r) {
    /* A real local file receipt, not a memory-store claim. Fixed-size private
     * test record; production deployments must provide their own atomic CAS,
     * crash consistency, effects binding and durable storage implementation. */
    rewind(file); assert(fwrite(r, sizeof(*r), 1, file) == 1);
    assert(fflush(file) == 0 && fsync(fileno(file)) == 0);
}
static void load(peer c, peer h, FILE *file) {
    syntra_storage_request_t request = wait_storage(c, h, SYNTRA_STORAGE_LOAD);
    record r = read_record(file);
    syntra_record_t value = {r.g, r.cp, r.cp_len, r.state, r.state_len};
    assert(f->storage_complete(c.p, c.g, request.token, SYNTRA_STORAGE_DURABLE, NULL) == SYNTRA_INVALID);
    assert(f->storage_complete(c.p, c.g, request.token, SYNTRA_STORAGE_FOUND, &value) == 0);
    assert(f->storage_complete(c.p, c.g, request.token, SYNTRA_STORAGE_FOUND, &value) == SYNTRA_STALE);
    f->request_free(&request);
}
static void negotiate(peer c, peer h) {
    uint64_t token = 0;
    assert(f->negotiate(c.p, c.g, &token) == 0);
    syntra_recovery_result_t r = wait_result(c, h, token, 0);
    assert(r.kind == 1 && (r.flags & 1) && r.total_pages > 0);
    f->result_free(&r);
}
static uint64_t step(peer c, uint32_t kind, uint64_t stream, uint32_t index, const char *data) {
    uint64_t token = 0;
    assert(f->step(c.p, c.g, kind, stream, index, (const uint8_t *)data,
        data == NULL ? 0 : strlen(data), 2000, &token) == 0);
    return token;
}

/* modes: normal Replay, CommitUnknown, cancel during commit, wake during commit,
 * same-G snapshot install with S0!=B, and streamed CatchUp. Fresh generation
 * resumes the file's FULL state, not a digest or relabelled checkpoint.
 */
void syntra_c_recovery_contract(const api *functions, syntra_t **owners,
    const uint64_t *generations, uint32_t mode,
    void (*schedule)(uintptr_t context, uint32_t phase), uintptr_t context) {
    f = functions;
    peer c = {owners[0], generations[0]}, h = {owners[1], generations[1]};
    peer replacement = {owners[2], generations[2]}, host2 = {owners[3], generations[3]};
    FILE *file = tmpfile(); assert(file != NULL);
    record initial = {7, 1, 14, {'a'}, "old full state"};
    durable(file, &initial);
    uint64_t token = 0;
    handshake(c, h);
    if (mode == 7) {
        assert(f->negotiate(c.p, c.g, &token) == 0);
        syntra_recovery_result_t unavailable = wait_result(c, h, token, 12);
        assert(unavailable.flags == 0 && unavailable.stream == 0);
        f->result_free(&unavailable);
        assert(f->subscribe(c.p, c.g, (const uint8_t *)"selector", 8,
            (const uint8_t *)"S", 1, 2, &token) == 0);
        unavailable = wait_result(c, h, token, 12);
        f->result_free(&unavailable);
        assert(fclose(file) == 0);
        return;
    }
    negotiate(c, h);
    assert(f->subscribe(c.p, c.g, (const uint8_t *)"selector", 8,
        (const uint8_t *)"S", 1, mode == 4 ? 3 : 2, &token) == 0);
    load(c, h, file);
    syntra_recovery_result_t r = wait_result(c, h, token, 0);
    assert(r.stream != 0 && r.generation == 7 && (r.flags & 1));
    assert(r.restored_generation == 7 && r.restored_checkpoint.len == 1);
    assert(r.restored_checkpoint.data[0] == 'a');
    assert(r.restored_state.len == 14 && memcmp(r.restored_state.data, "old full state", 14) == 0);
    uint64_t stream = r.stream;
    f->result_free(&r);
    const int snapshot = mode == 4 || mode == 6;
    const char *full_state = snapshot ? "snapshot transformed full state" : "new complete application state";
    const char *restored_state = mode == 8 ? "concurrent full application state" : full_state;
    if (mode == 6) {
        r = wait_result(c, h, step(c, 3, stream, 0, NULL), 9);
        f->result_free(&r);
        r = wait_result(c, h, step(c, 6, 0, 0, NULL), 0);
        assert(r.event == 4 && r.stream == stream); f->result_free(&r);
    }
    if (snapshot) {
        r = wait_result(c, h, step(c, 8, stream, 0, NULL), 0);
        assert(r.total_pages == 2 && r.checkpoint.len == 2 && memcmp(r.checkpoint.data, "s0", 2) == 0);
        f->result_free(&r);
        for (uint32_t i = 0; i < 2; ++i) {
            r = wait_result(c, h, step(c, 9, stream, i, NULL), 0);
            assert(r.index == i && r.data.len > 0); f->result_free(&r);
        }
        r = wait_result(c, h, step(c, 10, stream, 0, NULL), 0);
        assert(r.data.len == 13 && memcmp(r.data.data, "snapshot-data", 13) == 0);
        f->result_free(&r);
    } else {
        r = wait_result(c, h, step(c, mode == 5 ? 4 : 3, stream, 0, NULL), 0);
        if (mode != 5) assert((r.flags & 1) && r.index == 1);
        f->result_free(&r);
        r = wait_result(c, h, step(c, 6, 0, 0, NULL), 0);
        assert(r.event == 1 && r.stream == stream && r.generation == 7);
        assert(r.predecessor.len == 1 && r.predecessor.data[0] == 'a');
        assert(r.checkpoint.len == 1 && r.checkpoint.data[0] == 'b');
        f->result_free(&r);
    }
    if (mode >= 9) schedule(context, 0); /* arm worker rendezvous before spawn */
    if (mode >= 9) {
        /* Deliberately longer than the 5s STORAGE budget. Its expiry must be
         * selected by the storage receipt gate, not the outer operation timer. */
        assert(f->step(c.p, c.g, 7, stream, 0, (const uint8_t *)full_state,
            strlen(full_state), 30000, &token) == 0);
    } else token = step(c, snapshot ? 11 : 7, stream, 0, full_state);
    syntra_storage_request_t request = wait_storage(c, h, SYNTRA_STORAGE_CAS_COMMIT);
    assert(request.expected_present == 1 && request.expected_generation == 7);
    record current = read_record(file), next = {0};
    assert(current.g == request.expected_generation && current.cp_len == request.expected_checkpoint.len);
    assert(memcmp(current.cp, request.expected_checkpoint.data, current.cp_len) == 0);
    assert(request.application_state.len == strlen(full_state));
    assert(memcmp(request.application_state.data, full_state, strlen(full_state)) == 0);
    next.g = request.generation; next.cp_len = (uint32_t)request.checkpoint.len;
    next.state_len = (uint32_t)request.application_state.len;
    assert(next.g == 7 && next.cp_len <= sizeof(next.cp) && next.state_len <= sizeof(next.state));
    memcpy(next.cp, request.checkpoint.data, next.cp_len);
    memcpy(next.state, request.application_state.data, next.state_len);
    if (mode == 8) {
        /* A concurrent writer installed a different full record at the same
         * proposed checkpoint: stale expected is NOT an idempotent duplicate. */
        next.state_len = (uint32_t)strlen(restored_state);
        memcpy(next.state, restored_state, next.state_len);
    }
    /* The engine MUST NOT Confirm while the receipt has not completed. */
    uint64_t emission = 0; uint8_t *bytes = NULL; uintptr_t len = 0;
    assert(f->emit(c.p, c.g, &emission, &bytes, &len) == SYNTRA_PENDING);
    assert(f->storage_complete(c.p, replacement.g, request.token, 2, NULL) == SYNTRA_STALE);
    durable(file, &next);
    if (mode >= 9) {
        /* The worker is parked AFTER checking its deadline, BEFORE receiving.
         * No sleeps or waits for its timeout precede this public ABI receipt. */
        schedule(context, 1);
        int rc = f->storage_complete(c.p, c.g, request.token,
            SYNTRA_STORAGE_DURABLE, NULL);
        assert(rc == (mode == 11 ? SYNTRA_OK : SYNTRA_STALE));
        schedule(context, 2); /* advance timely control, then release worker */
        assert(f->storage_complete(c.p, c.g, request.token, 2, NULL) == SYNTRA_STALE);
        if (mode != 11) {
            /* Do NOT let the generic pump consume a forbidden /Confirm. Check
             * every emission while waiting for the storage terminal instead. */
            int completed = SYNTRA_PENDING;
            for (int i = 0; i < 3000 && completed == SYNTRA_PENDING; ++i) {
                assert(f->emit(c.p, c.g, &emission, &bytes, &len) == SYNTRA_PENDING);
                completed = f->recovery_poll(c.p, c.g, token, &r);
                assert(completed == 0 || completed == SYNTRA_PENDING);
                tick();
            }
            assert(completed == 0 && r.grpc_code == 2); /* CommitUnknown */
            assert(f->emit(c.p, c.g, &emission, &bytes, &len) == SYNTRA_PENDING);
        } else {
            r = wait_result(c, h, token, 0);
            assert(r.generation == 7 && r.checkpoint.len == next.cp_len);
        }
        f->result_free(&r);
    } else if (mode == 2 || mode == 3) {
        if (mode == 2) assert(f->cancel(c.p, c.g, token) == 0);
        else { assert(f->suspend(c.p, c.g) == 0); assert(f->wake(c.p, c.g, 1) == 0); }
        /* No more pumps on the retired connection; reconcile in a NEW one. */
        int rc = 1;
        for (int i = 0; i < 3000 && rc == 1; ++i) { rc = f->recovery_poll(c.p, c.g, token, &r); tick(); }
        assert(rc == 0 && r.grpc_code == (mode == 2 ? 1 : 14)); f->result_free(&r);
        assert(f->shutdown(c.p, c.g, 2) == 0 && f->transport_closed(c.p, c.g) == 0);
        for (int i = 0; i < 10; ++i) tick();
        assert(f->shutdown_poll(c.p, c.g) == SYNTRA_SHUTDOWN_INCOMPLETE);
        assert(f->storage_complete(c.p, c.g, request.token, 2, NULL) == SYNTRA_STALE);
    } else {
        uint32_t receipt_status = mode == 1 ? 6 : (mode == 8 ? 5 : 2);
        if (mode == 8) {
            record rival = read_record(file);
            assert(rival.cp_len != request.expected_checkpoint.len ||
                memcmp(rival.cp, request.expected_checkpoint.data, rival.cp_len) != 0);
            assert(rival.state_len != request.application_state.len ||
                memcmp(rival.state, request.application_state.data, rival.state_len) != 0);
        }
        assert(f->storage_complete(c.p, c.g, request.token, receipt_status, NULL) == 0);
        r = wait_result(c, h, token, mode == 1 ? 2 : (mode == 8 ? 10 : 0));
        if (mode != 1 && mode != 8) assert(r.generation == 7 && r.checkpoint.len == next.cp_len);
        f->result_free(&r);
        if ((mode == 0 || mode == 5) && !snapshot) {
            r = wait_result(c, h, step(c, 6, 0, 0, NULL), 0);
            assert(r.event == 2 && r.stream == stream); f->result_free(&r);
            assert(f->step(c.p, c.g, 6, 0, 0, NULL, 0, 2, &token) == 0);
            r = wait_result(c, h, token, 4); f->result_free(&r);
            /* Cancellation-safe timeout did not poison the shared client. */
            r = wait_result(c, h, step(c, 12, stream, 0, NULL), 0);
            f->result_free(&r);
        }
    }
    f->request_free(&request);
    handshake(replacement, host2); negotiate(replacement, host2);
    assert(f->subscribe(replacement.p, replacement.g, (const uint8_t *)"selector", 8,
        (const uint8_t *)"S", 1, 2, &token) == 0);
    load(replacement, host2, file);
    r = wait_result(replacement, host2, token, 0);
    assert(r.stream != stream && r.restored_generation == 7);
    assert(r.restored_state.len == strlen(restored_state));
    assert(memcmp(r.restored_state.data, restored_state, strlen(restored_state)) == 0);
    assert(r.restored_checkpoint.len == next.cp_len && memcmp(r.restored_checkpoint.data, next.cp, next.cp_len) == 0);
    f->result_free(&r);
    assert(f->step(replacement.p, replacement.g, 3, stream, 0, NULL, 0, 1000, &token) == SYNTRA_STALE);
    assert(fclose(file) == 0);
}
