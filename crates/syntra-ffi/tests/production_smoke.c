#define _POSIX_C_SOURCE 200809L
#include "syntra_production.h"
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

/* Actual foreign caller over shared Host/Initiator. No fixture exports, wire
 * engine or application echo is built into the library under test. */
typedef struct { syntra_t *p; uint64_t generation; } peer;

static void tick(void) {
    struct timespec ts = {0, 1000000};
    (void)nanosleep(&ts, NULL);
}
static int32_t authenticate(uintptr_t context, const uint8_t *credential,
    uintptr_t len, uint8_t *principal, uintptr_t cap, uintptr_t *out_len) {
    assert(context == 42);
    if (len != 5 || memcmp(credential, "token", 5) != 0) return 16;
    assert(cap >= 4);
    memcpy(principal, "user", 4);
    *out_len = 4;
    return 0;
}
static int32_t authorize(uintptr_t context, const uint8_t *principal,
    uintptr_t len, const uint8_t *method, uintptr_t method_len) {
    assert(context == 42 && len == 4 && memcmp(principal, "user", 4) == 0);
    return method_len == 18 && memcmp(method, "/test.Service/Echo", 18) == 0 ? 0 : 7;
}
static void pump(peer a, peer b) {
    uint64_t emission = 0, receipt = 0;
    uint8_t *frame = NULL;
    uintptr_t len = 0;
    int32_t rc = syntra_emit(a.p, a.generation, &emission, &frame, &len);
    if (rc == SYNTRA_PENDING) return;
    assert(rc == 0 && frame != NULL && len > 0 && emission != 0);
    assert(syntra_receipt(b.p, b.generation, &receipt) == 0);
    assert(syntra_ingest(b.p, b.generation, receipt, frame, len) == 0);
    assert(syntra_emitted(a.p, a.generation, emission) == 0);
    assert(syntra_emitted(a.p, a.generation, emission) == SYNTRA_STALE);
    syntra_free(frame, len);
}
static int32_t poll(peer p, uint64_t token, int32_t expected,
    const char *payload, uintptr_t payload_len) {
    int32_t code = -1;
    uint64_t request_id = 0;
    uint8_t *out = NULL;
    uintptr_t len = 0;
    int32_t rc = syntra_poll(p.p, p.generation, token, &code, &request_id, &out, &len);
    if (rc == SYNTRA_PENDING) return rc;
    assert(rc == 0 && code == expected);
    if (payload != NULL) {
        assert(len == payload_len && memcmp(out, payload, len) == 0);
    }
    syntra_free(out, len);
    return rc;
}
static void stop(peer p) {
    assert(syntra_shutdown(p.p, p.generation, 100) == 0);
    assert(syntra_transport_closed(p.p, p.generation) == 0);
    int32_t rc = 1;
    for (int i = 0; i < 3000 && rc != 0; ++i) {
        rc = syntra_shutdown_poll(p.p, p.generation);
        assert(rc >= 0);
        tick();
    }
    assert(rc == 0);
    assert(syntra_shutdown_poll(p.p, p.generation) == 0);
    assert(syntra_destroy(p.p, p.generation) == 0);
}
typedef struct { _Atomic uint64_t nanos; _Atomic int failed; } elapsed_source;
static int32_t sample(uintptr_t context, uint64_t *out) {
    elapsed_source *s = (elapsed_source *)context;
    *out = atomic_load(&s->nanos);
    return atomic_load(&s->failed);
}
static void lifecycle(int unknown) {
    elapsed_source source = {UINT64_C(1000000000), 0};
    syntra_clock_t clock = {(uintptr_t)&source, sample};
    peer client = {NULL, 0}, host = {NULL, 0};
    assert(syntra_client_open_clock(SYNTRA_ABI_VERSION, clock, &client.p, &client.generation) == 0);
    syntra_policy_t policy = {42, authenticate, authorize};
    assert(syntra_host_open_clock(SYNTRA_ABI_VERSION, policy, clock, &host.p, &host.generation) == 0);
    uint64_t handshake = 0, call = 0;
    assert(syntra_handshake(client.p, client.generation,
        (const uint8_t *)"token", 5, &handshake) == 0);
    int32_t rc = 1;
    for (int i = 0; i < 3000 && rc != 0; ++i) {
        pump(client, host); pump(host, client);
        rc = poll(client, handshake, 0, NULL, 0); tick();
    }
    assert(rc == 0);
    assert(syntra_call(client.p, client.generation,
        (const uint8_t *)"/test.Service/Echo", 18, NULL, 0, 1000, &call) == 0);
    tick(); tick(); /* allow shared admission; no request is handed off */
    assert(syntra_suspend(client.p, client.generation) == 0);
    if (!unknown) atomic_fetch_add(&source.nanos, UINT64_C(2000000000));
    else if (unknown == 1) atomic_store(&source.failed, 1);
    else if (unknown == 2) atomic_store(&source.nanos, 0); /* regression */
    uint64_t token = 0;
    uint8_t *out = NULL;
    uintptr_t len = 0;
    assert(syntra_emit(client.p, client.generation, &token, &out, &len) == SYNTRA_CLOSED);
    assert(syntra_receipt(client.p, client.generation, &token) == SYNTRA_CLOSED);
    assert(syntra_platform_wake(client.p, client.generation, unknown ? 0 : 1) == 0);
    rc = 1;
    for (int i = 0; i < 3000 && rc != 0; ++i) {
        rc = poll(client, call, unknown ? 14 : 4, NULL, 0); tick();
    }
    assert(rc == 0);
    assert(syntra_call(client.p, client.generation,
        (const uint8_t *)"/test.Service/Echo", 18, NULL, 0, 1000, &token) == SYNTRA_CLOSED);
    stop(client); stop(host);
}
int main(void) {
    assert(syntra_abi_version() == SYNTRA_ABI_VERSION && SYNTRA_ABI_VERSION == 1);
    assert(syntra_capabilities() == (SYNTRA_CAP_CORE | SYNTRA_CAP_LIFECYCLE | SYNTRA_CAP_RECOVERY_CLIENT));
    assert(SYNTRA_CAP_RECORD_PROTECTION == UINT64_C(2));
    assert((syntra_capabilities() & SYNTRA_CAP_RECORD_PROTECTION) == 0);
    peer client = {NULL, 0}, host = {NULL, 0};
    assert(syntra_client_open(2, &client.p, &client.generation) == SYNTRA_ABI_MISMATCH);
    assert(client.p == NULL && client.generation == 0);
    assert(syntra_client_open(SYNTRA_ABI_VERSION, &client.p, &client.generation) == 0);
    syntra_policy_t policy = {42, authenticate, authorize};
    assert(syntra_host_open(SYNTRA_ABI_VERSION, policy, &host.p, &host.generation) == 0);
    assert(client.generation != host.generation);
    assert(syntra_destroy(host.p, host.generation) == SYNTRA_BUSY);
    uint64_t handshake = 0;
    assert(syntra_handshake(client.p, client.generation,
        (const uint8_t *)"token", 5, &handshake) == 0);
    int32_t rc = 1;
    for (int i = 0; i < 3000 && rc != 0; ++i) {
        pump(client, host); pump(host, client);
        rc = poll(client, handshake, 0, NULL, 0);
        tick();
    }
    assert(rc == 0);
    uint64_t call = 0, dispatch = 0;
    assert(syntra_call(client.p, client.generation,
        (const uint8_t *)"/test.Service/Echo", 18,
        (const uint8_t *)"payload", 7, 2000, &call) == 0);
    for (int i = 0; i < 3000 && dispatch == 0; ++i) {
        pump(client, host);
        uint8_t *method = NULL, *payload = NULL;
        uintptr_t ml = 0, pl = 0;
        rc = syntra_take_dispatch(host.p, host.generation,
            &dispatch, &method, &ml, &payload, &pl);
        assert(rc == 0 || rc == SYNTRA_PENDING);
        if (rc == 0) {
            assert(ml == 18 && memcmp(method, "/test.Service/Echo", 18) == 0);
            assert(pl == 7 && memcmp(payload, "payload", 7) == 0);
            syntra_free(method, ml); syntra_free(payload, pl);
        }
        tick();
    }
    assert(dispatch != 0);
    assert(syntra_complete(host.p, client.generation, dispatch, 0, NULL, 0) == SYNTRA_STALE);
    assert(syntra_complete(host.p, host.generation, dispatch, 0,
        (const uint8_t *)"answer", 6) == 0);
    assert(syntra_complete(host.p, host.generation, dispatch, 0, NULL, 0) == SYNTRA_STALE);
    rc = 1;
    for (int i = 0; i < 3000 && rc != 0; ++i) {
        pump(host, client);
        rc = poll(client, call, 0, "answer", 6);
        tick();
    }
    assert(rc == 0);
    stop(client); stop(host);
    lifecycle(0); lifecycle(1); lifecycle(2); lifecycle(3);
    return 0;
}
