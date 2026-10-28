#ifndef SYNTRA_FIXTURE_H
#define SYNTRA_FIXTURE_H

/* TEST FIXTURE ONLY. No supported production native or browser ABI exists.
 * Default Rust builds export none of these functions. To use the fixture:
 *   cargo build -p syntra-ffi --features test-fixture
 *   compile the C test with -DSYNTRA_TEST_FIXTURE
 * Do not distribute that artifact as a production Syntra transport.
 * syntra_open always creates an in-process echo/get-put host, not a network
 * peer. There is NO API here to attach syntra-ws or another real transport.
 * ABI version checks describe fixture layout, not transport support.
 */
#ifndef SYNTRA_TEST_FIXTURE
#error "syntra.h is test-only: define SYNTRA_TEST_FIXTURE and enable Cargo test-fixture; no production FFI is available"
#endif
#if defined(__wasm__)
#error "syntra-ffi does not support WASM: the blocking fixture ABI is native-only"
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYNTRA_OK 0
#define SYNTRA_AGAIN 1
#define SYNTRA_E_PANIC (-1)
#define SYNTRA_E_ARG (-2)
#define SYNTRA_E_HANDSHAKE (-3)
#define SYNTRA_E_RPC (-4)
#define SYNTRA_E_TIMEOUT (-5)
#define SYNTRA_E_CANCELLED (-6)
#define SYNTRA_E_UNAVAILABLE (-7)
#define SYNTRA_E_RESOURCE (-8)
#define SYNTRA_E_VERSION (-9)
#define SYNTRA_E_UTF8 (-10)

/* Caller memory contract: all non-null pointers must be valid, aligned and
 * live for the full call; method must be NUL-terminated. Byte inputs must
 * cover their lengths. Outputs must be writable and disjoint from each other
 * and inputs. NULL byte input is allowed only with length 0. Invalid pointers
 * cannot be made safe by Rust panic containment. Blocking calls must not run
 * inside a Tokio async execution context. WASM/browser use is unsupported.
 */
uint32_t syntra_abi_version(void);
bool syntra_abi_compatible(uint32_t want_major, uint32_t want_minor);

/* Returns a positive fixture handle or a negative status. auth_mode 0 is
 * anonymous (empty token required); 1 is a static fixture token comparison.
 * This is not production authentication/authorization. */
int64_t syntra_open(uint32_t auth_mode, const uint8_t *token, size_t token_len);
int32_t syntra_handshake(uint64_t handle, const uint8_t *credential, size_t credential_len);

/* Both output pointers are required. If either is NULL, returns E_ARG without
 * reading inputs or writing outputs. Otherwise initializes NULL/0 BEFORE
 * reading inputs, including on invalid UTF-8, invalid handle or other error.
 * On success, free exactly once with syntra_free using the returned length.
 * Failure does not imply rollback; never blindly retry non-idempotent work. */
int32_t syntra_call(uint64_t handle, const char *method,
                    const uint8_t *payload, size_t payload_len, uint32_t timeout_ms,
                    uint8_t **out_ptr, size_t *out_len);
int32_t syntra_cancel(uint64_t handle, uint64_t request_id);
/* Only the most recently tracked call can be signalled locally. */
int32_t syntra_cancel_current(uint64_t handle);
/* Same output ownership as syntra_call; AGAIN means timeout/no notification. */
int32_t syntra_poll_notify(uint64_t handle, uint32_t timeout_ms,
                           uint8_t **out_ptr, size_t *out_len);
int32_t syntra_close(uint64_t handle);
void syntra_free(uint8_t *ptr, size_t len);
/* Writes a NUL-terminated public error, truncated to buflen-1. Returns bytes
 * written excluding NUL; NULL/zero-length output writes nothing, returns 0. */
size_t syntra_last_error(uint64_t handle, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif
#endif
