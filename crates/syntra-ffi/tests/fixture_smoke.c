/* Test the actual header, linker symbols, C sizes and ownership together. */
#include "syntra.h"
#include <assert.h>
#include <string.h>

int main(void) {
    assert(syntra_abi_version() == (1u << 16));
    assert(syntra_abi_compatible(1, 0));
    assert(!syntra_abi_compatible(2, 0));
    int64_t opened = syntra_open(0, NULL, 0);
    assert(opened > 0);
    uint64_t handle = (uint64_t)opened;
    assert(syntra_handshake(handle, NULL, 0) == SYNTRA_OK);

    const uint8_t payload[] = {0, 0xff, 0x80, 1};
    uint8_t *out = NULL;
    size_t len = 0;
    assert(syntra_call(handle, "/example.Echo/Echo", payload, sizeof(payload),
                       2000, &out, &len) == SYNTRA_OK);
    assert(len == sizeof(payload));
    assert(memcmp(out, payload, len) == 0);
    syntra_free(out, len);

    uint8_t sentinel = 0;
    out = &sentinel;
    len = 123;
    assert(syntra_call(handle, NULL, NULL, 0, 1, &out, &len) == SYNTRA_E_ARG);
    assert(out == NULL && len == 0);
    const char invalid_utf8[] = {(char)0xff, 0};
    out = &sentinel;
    len = 123;
    assert(syntra_call(handle, invalid_utf8, NULL, 0, 1, &out, &len) == SYNTRA_E_UTF8);
    assert(out == NULL && len == 0);

    assert(syntra_poll_notify(handle, 1, &out, &len) == SYNTRA_AGAIN);
    assert(out == NULL && len == 0);
    assert(syntra_close(handle) == SYNTRA_OK);
    assert(syntra_close(handle) == SYNTRA_OK);
    syntra_free(NULL, 0);
    return 0;
}
