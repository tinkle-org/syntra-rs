#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "syntra_production.h"

static void rpc_round_trip(syntra_ffi_client_t *c, syntra_ffi_host_t *h,
                          uint64_t id, const uint8_t *result, uintptr_t result_len) {
    const char *method = "/example.Echo/Echo";
    const uint8_t payload[] = {0, 0xff};
    uint8_t *request = NULL;
    uintptr_t request_len = 0;
    assert(syntra_ffi_client_begin_call(c, id, (const uint8_t *)method,
        strlen(method), payload, sizeof(payload), 30000, &request, &request_len) == SYNTRA_FFI_OK);
    assert(request != NULL && request_len > 0);

    uint8_t *out = NULL;
    uintptr_t len = 0;
    int32_t has_response = -1;
    uintptr_t cancel_n = 99;
    assert(syntra_ffi_host_on_frame(h, request, request_len, &out, &len,
        &has_response, NULL, 0, &cancel_n) == SYNTRA_FFI_OK);
    assert(has_response == 0 && cancel_n == 0 && out == NULL && len == 0);

    uint64_t taken_id = 0;
    int32_t present = 0;
    assert(syntra_ffi_host_take_pending(h, NULL, &out, &len, &present) == SYNTRA_FFI_INVALID);
    assert(syntra_ffi_host_take_pending(h, &taken_id, &out, &len, &present) == SYNTRA_FFI_OK);
    assert(present == 1 && taken_id == id);
    assert(len == request_len && memcmp(out, request, len) == 0);
    syntra_ffi_free(out, len);
    syntra_ffi_free(request, request_len);

    int32_t expired = -1;
    assert(syntra_ffi_host_answer(h, result, result_len, NULL) == SYNTRA_FFI_INVALID);
    assert(syntra_ffi_host_answer(h, result, result_len, &expired) == SYNTRA_FFI_OK);
    assert(expired == 0);
    assert(syntra_ffi_host_next_outbound(h, NULL, &len, &present) == SYNTRA_FFI_INVALID);
    assert(syntra_ffi_host_next_outbound(h, &out, &len, &present) == SYNTRA_FFI_OK);
    assert(present == 1 && len == result_len && memcmp(out, result, len) == 0);

    uint64_t terminal_id = 0;
    uintptr_t terminal_n = 99;
    int32_t notifications = -1;
    assert(syntra_ffi_client_on_frame(c, out, len, NULL, 1,
        &terminal_n, &notifications) == SYNTRA_FFI_INVALID);
    assert(syntra_ffi_client_on_frame(c, out, len, &terminal_id, 1,
        &terminal_n, &notifications) == SYNTRA_FFI_OK);
    assert(terminal_id == id && terminal_n == 1 && notifications == 0);
    syntra_ffi_free(out, len);

    assert(syntra_ffi_client_take_outcome(c, id, &out, NULL, &present) == SYNTRA_FFI_INVALID);
    assert(syntra_ffi_client_take_outcome(c, id, &out, &len, &present) == SYNTRA_FFI_OK);
    assert(present == 1 && len == result_len && memcmp(out, result, len) == 0);
    syntra_ffi_free(out, len);
    assert(syntra_ffi_client_take_outcome(c, id, &out, &len, &present) == SYNTRA_FFI_OK);
    assert(present == 0 && out == NULL && len == 0);
    assert(syntra_ffi_host_next_outbound(h, &out, &len, &present) == SYNTRA_FFI_OK);
    assert(present == 0 && out == NULL && len == 0);
}

int main(void) {
    int32_t rc;
    assert(syntra_ffi_abi_version() == SYNTRA_FFI_ABI_VERSION);

    syntra_ffi_client_t *c = NULL;
    rc = syntra_ffi_client_open(1, 1, NULL, 0, 3000, 16, &c);
    assert(rc == SYNTRA_FFI_OK);
    assert(c != NULL);

    uint8_t *hello = NULL;
    uintptr_t hello_len = 0;
    rc = syntra_ffi_client_hello_frame(c, &hello, &hello_len);
    assert(rc == SYNTRA_FFI_OK);
    assert(hello != NULL && hello_len > 0);

    syntra_ffi_host_t *h = NULL;
    rc = syntra_ffi_host_open(1, 1, 16, &h);
    assert(rc == SYNTRA_FFI_OK);
    assert(h != NULL);

    uint32_t version = 0;
    rc = syntra_ffi_host_accept_hello(h, hello, hello_len, &version);
    assert(rc == SYNTRA_FFI_OK);
    assert(version == 1);

    const char *principal = "svc-test";
    uint8_t *ready = NULL;
    uintptr_t ready_len = 0;
    rc = syntra_ffi_host_auth_complete(h, principal, strlen(principal), &ready, &ready_len);
    assert(rc == SYNTRA_FFI_OK);
    assert(ready != NULL && ready_len > 0);
    rc = syntra_ffi_client_activate(c, ready, ready_len);
    assert(rc == SYNTRA_FFI_OK);

    syntra_ffi_free(hello, hello_len);
    syntra_ffi_free(ready, ready_len);

    /* Frame(version=1, id=1, result.payload="ok"). */
    const uint8_t success[] = {0x08, 1, 0x10, 1, 0x6a, 4, 0x0a, 2, 'o', 'k'};
    /* Frame(version=1, id=2, result.error={code:7, message:"denied"}). */
    const uint8_t error[] = {0x08, 1, 0x10, 2, 0x6a, 12, 0x12, 10,
        0x08, 7, 0x12, 6, 'd', 'e', 'n', 'i', 'e', 'd'};
    rpc_round_trip(c, h, 1, success, sizeof(success));
    rpc_round_trip(c, h, 2, error, sizeof(error));

    rc = syntra_ffi_client_close(c);
    assert(rc == SYNTRA_FFI_OK);
    rc = syntra_ffi_host_close(h);
    assert(rc == SYNTRA_FFI_OK);
    printf("production smoke ok\n");
    return 0;
}
