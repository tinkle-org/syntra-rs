#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "syntra_production.h"

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
    rc = syntra_ffi_client_close(c);
    assert(rc == SYNTRA_FFI_OK);
    rc = syntra_ffi_host_close(h);
    assert(rc == SYNTRA_FFI_OK);
    printf("production smoke ok\n");
    return 0;
}
