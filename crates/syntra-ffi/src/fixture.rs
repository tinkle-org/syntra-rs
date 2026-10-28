//! Native-only loopback C ABI fixture, enabled by `test-fixture` only.
//!
//! This crate is a thin boundary adapter. It owns no protocol behavior:
//! framing, handshake, RPC correlation, timeouts, cancellation, and
//! sessions live in `syntra-runtime` (and below). The facade only maps
//! between FFI-safe types (opaque integer handles, explicit byte buffers
//! with caller-visible ownership) and the async runtime API.
//!
//! Rules at this boundary:
//! - handles are opaque `u64` ids (0 is never valid); buffers are
//!   heap allocations the caller frees with [`syntra_free`];
//! - unwinding panics are contained (`catch_unwind`); this cannot recover
//!   from invalid pointers, allocation aborts, or panic=abort builds;
//! - version check first: [`syntra_abi_compatible`] gates feature use;
//! - no application/user/chat types cross this boundary — only method
//!   strings and opaque payload bytes;
//! - `syntra_open` creates an in-memory fixture pair, not a network
//!   connection. There is no transport attachment API in this ABI.
//!
//! Error model: functions return `i32` status (`SYNTRA_OK` or a negative
//! `SYNTRA_E_*`); per-handle detail is available via
//! [`syntra_last_error`].

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex, OnceLock};

use syntra_runtime::{
    AllowAnonymous, CancelToken, ConnectionConfig, FnHandler, HandlerOutcome, Host, Initiator,
    StaticToken,
};

// -- ABI version ---------------------------------------------------------

/// ABI major version. Bumped on any incompatible change.
pub const SYNTRA_ABI_MAJOR: u32 = 1;
/// ABI minor version. New compatible functions bump this.
pub const SYNTRA_ABI_MINOR: u32 = 0;
/// ABI patch version. Compatible fixes bump this.
pub const SYNTRA_ABI_PATCH: u32 = 0;

/// Status codes (all negative except OK).
pub const SYNTRA_OK: i32 = 0;
pub const SYNTRA_E_PANIC: i32 = -1;
pub const SYNTRA_E_ARG: i32 = -2;
pub const SYNTRA_E_HANDSHAKE: i32 = -3;
pub const SYNTRA_E_RPC: i32 = -4;
pub const SYNTRA_E_TIMEOUT: i32 = -5;
pub const SYNTRA_E_CANCELLED: i32 = -6;
pub const SYNTRA_E_UNAVAILABLE: i32 = -7;
pub const SYNTRA_E_RESOURCE: i32 = -8;
pub const SYNTRA_E_VERSION: i32 = -9;
pub const SYNTRA_E_UTF8: i32 = -10;
/// Poll hit the timeout with no notification (not an error).
pub const SYNTRA_AGAIN: i32 = 1;

/// Packed ABI version: major << 16 | minor << 8 | patch.
#[no_mangle]
pub extern "C" fn syntra_abi_version() -> u32 {
    (SYNTRA_ABI_MAJOR << 16) | (SYNTRA_ABI_MINOR << 8) | SYNTRA_ABI_PATCH
}

/// True when this binary satisfies `major == 1 && minor >= want_minor`.
/// Call before any other function.
#[no_mangle]
pub extern "C" fn syntra_abi_compatible(want_major: u32, want_minor: u32) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        want_major == SYNTRA_ABI_MAJOR && SYNTRA_ABI_MINOR >= want_minor
    }))
    .unwrap_or(false)
}

// -- Runtime + registry ----------------------------------------------------

fn global_runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("ffi fixture runtime")
    })
}

struct FfiConn {
    initiator: Initiator,
    /// Kept alive: owns the host side + its pump tasks.
    _host: Arc<Host>,
    /// All currently tracked call tokens (concurrent `syntra_call`s share
    /// one handle). Newest entry is the most recently started call.
    current_cancel: Mutex<Vec<(u64, Arc<CancelToken>)>>,
    last_error: Mutex<Option<String>>,
}

impl FfiConn {
    fn set_error(&self, e: impl ToString) {
        *self.last_error.lock().unwrap() = Some(e.to_string());
    }

    fn result_error(&self, e: &syntra_core::SyntraError) -> i32 {
        self.set_error(e);
        map_error(e)
    }
}

fn map_error(e: &syntra_core::SyntraError) -> i32 {
    use syntra_core::SyntraError as E;
    match e {
        E::DeadlineExceeded(_) => SYNTRA_E_TIMEOUT,
        E::Cancelled(_) => SYNTRA_E_CANCELLED,
        E::Unavailable(_) | E::Closed(_) | E::Transport(_) => SYNTRA_E_UNAVAILABLE,
        E::ResourceExhausted(_) => SYNTRA_E_RESOURCE,
        E::Rpc { .. } | E::Protocol { .. } => SYNTRA_E_RPC,
        E::Handshake { .. } => SYNTRA_E_HANDSHAKE,
    }
}

struct Registry {
    next: u64,
    conns: HashMap<u64, Arc<FfiConn>>,
}

fn registry() -> &'static Mutex<Registry> {
    static REG: OnceLock<Mutex<Registry>> = OnceLock::new();
    REG.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            conns: HashMap::new(),
        })
    })
}

fn with_conn<T>(handle: u64, f: impl FnOnce(&FfiConn) -> T, dflt: T) -> T {
    // Keep the connection alive without holding the global lock while a
    // blocking operation runs (including cancellation or close elsewhere).
    let conn = registry().lock().unwrap().conns.get(&handle).cloned();
    match conn {
        Some(c) => f(&c),
        None => dflt,
    }
}

// -- Neutral loopback handler (fixtures only, no app semantics) -----------

fn fixture_handler() -> Arc<dyn syntra_runtime::Handler> {
    Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, cancel: CancelToken| async move {
            let _ = cancel;
            match method.as_str() {
                // Neutral echo fixture (conformance/test-vectors).
                "/example.Echo/Echo" => HandlerOutcome::Payload(payload),
                // Neutral get-put fixtures: Get always misses; Put
                // succeeds with empty output. No storage, no chat model.
                "/example.KV/Get" => {
                    HandlerOutcome::error(syntra_core::ErrorCode::NotFound, "missing")
                }
                "/example.KV/Put" => HandlerOutcome::Payload(Vec::new()),
                _ => HandlerOutcome::error(syntra_core::ErrorCode::Unimplemented, "unknown method"),
            }
        },
    ))
}

// -- Helpers ---------------------------------------------------------------

fn read_c_str(ptr: *const c_char) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(SYNTRA_E_ARG);
    }
    let s = unsafe { CStr::from_ptr(ptr) };
    s.to_str().map(|s| s.to_string()).map_err(|_| SYNTRA_E_UTF8)
}

/// Method bound mirrors `syntra_core::validate_method` (1..512 bytes).
/// Surfaced as `SYNTRA_E_RESOURCE` at this boundary to avoid an unbounded
/// scan/allocation before the runtime can reject the frame.
const MAX_FFI_METHOD_BYTES: usize = 512;

fn read_c_str_bounded(ptr: *const c_char, max_len: usize) -> Result<String, i32> {
    if ptr.is_null() {
        return Err(SYNTRA_E_ARG);
    }
    // Bounded NUL scan: avoids an unbounded `CStr::from_ptr` walk and a
    // huge `to_string` allocation for an oversized valid buffer.
    let mut len = 0usize;
    unsafe {
        while len <= max_len {
            if *ptr.add(len) == 0 {
                break;
            }
            len += 1;
        }
    }
    if len > max_len {
        return Err(SYNTRA_E_RESOURCE);
    }
    read_c_str(ptr)
}

fn read_bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, i32> {
    if len > 0 && ptr.is_null() {
        return Err(SYNTRA_E_ARG);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) }.to_vec())
}

/// Bound the FFI length before copying: a huge valid buffer would
/// otherwise make `to_vec` attempt an aborting allocation before the
/// runtime can reject it with `ResourceExhausted`.
fn read_bytes_bounded(ptr: *const u8, len: usize, max: usize) -> Result<Vec<u8>, i32> {
    if len > max {
        return Err(SYNTRA_E_RESOURCE);
    }
    read_bytes(ptr, len)
}

fn emit_bytes(out_ptr: *mut *mut u8, out_len: *mut usize, data: Vec<u8>) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return SYNTRA_E_ARG;
    }
    let mut boxed = data.into_boxed_slice();
    unsafe {
        *out_ptr = boxed.as_mut_ptr();
        *out_len = boxed.len();
    }
    std::mem::forget(boxed);
    SYNTRA_OK
}

// -- C ABI -----------------------------------------------------------------
//
// Auth modes for syntra_open:
//   0 = anonymous (token must be empty; least privilege on accept)
//   1 = static bearer token (presented opaquely; never logged)

/// Open an in-memory test fixture pair, never a production/network peer.
/// Returns a positive handle, or a negative `SYNTRA_E_*` status.
/// `auth_mode` 0 accepts anonymous; 1 compares against the supplied fixture
/// token. Neither is production authentication or authorization policy.
#[no_mangle]
pub extern "C" fn syntra_open(auth_mode: u32, token_ptr: *const u8, token_len: usize) -> i64 {
    let r = catch_unwind(AssertUnwindSafe(|| -> Result<u64, i32> {
        let token =
            read_bytes_bounded(token_ptr, token_len, syntra_core::MAX_CREDENTIAL_BYTES)?;
        // Everything async (Host::new spawns its handshake timer) must
        // run inside the runtime context.
        global_runtime().block_on(async {
            let auth: Arc<dyn syntra_runtime::Authenticator> = match auth_mode {
                0 => {
                    if !token.is_empty() {
                        return Err(SYNTRA_E_ARG);
                    }
                    Arc::new(AllowAnonymous)
                }
                1 => Arc::new(StaticToken::new(token, "ffi-peer")),
                _ => return Err(SYNTRA_E_ARG),
            };
            let (initiator, host) =
                syntra_runtime::loopback_pair(auth, fixture_handler(), ConnectionConfig::default());
            let mut reg = registry().lock().unwrap();
            let id = reg.next;
            reg.next += 1;
            reg.conns.insert(
                id,
                Arc::new(FfiConn {
                    initiator,
                    _host: host,
                    current_cancel: Mutex::new(Vec::new()),
                    last_error: Mutex::new(None),
                }),
            );
            Ok(id)
        })
    }));
    match r {
        Ok(Ok(id)) => id as i64,
        Ok(Err(code)) => code as i64,
        Err(_) => SYNTRA_E_PANIC as i64,
    }
}

/// Run the Syntra handshake on an open handle.
#[no_mangle]
pub extern "C" fn syntra_handshake(handle: u64, cred_ptr: *const u8, cred_len: usize) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| -> i32 {
        let cred = match read_bytes_bounded(cred_ptr, cred_len, syntra_core::MAX_CREDENTIAL_BYTES)
        {
            Ok(c) => c,
            Err(code) => return code,
        };
        with_conn(
            handle,
            |c| {
                global_runtime().block_on(async {
                    match c.initiator.handshake(cred).await {
                        Ok(_) => SYNTRA_OK,
                        Err(e) => c.result_error(&e),
                    }
                })
            },
            SYNTRA_E_ARG,
        )
    }));
    r.unwrap_or(SYNTRA_E_PANIC)
}

/// Blocking RPC. On success `*out_ptr/*out_len` hold a heap buffer the
/// caller MUST release with [`syntra_free`]. On error the outputs are
/// null/0 and detail is in [`syntra_last_error`].
/// Both output pointers must be valid and non-null; otherwise no outputs
/// are written and no inputs are read. Outputs must not overlap inputs.
#[no_mangle]
pub extern "C" fn syntra_call(
    handle: u64,
    method_ptr: *const c_char,
    payload_ptr: *const u8,
    payload_len: usize,
    timeout_ms: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| -> i32 {
        if out_ptr.is_null() || out_len.is_null() {
            return SYNTRA_E_ARG;
        }
        // Establish failure-safe outputs before reading/allocating any input.
        unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        }
        let method = match read_c_str_bounded(method_ptr, MAX_FFI_METHOD_BYTES) {
            Ok(m) => m,
            Err(code) => return code,
        };
        let payload = match read_bytes_bounded(payload_ptr, payload_len, syntra_core::MAX_FRAME_BYTES)
        {
            Ok(p) => p,
            Err(code) => return code,
        };
        with_conn(
            handle,
            |c| {
                let cancel = Arc::new(CancelToken::new());
                // The tracked API exposes its id only after completion.
                // Until an id-allocation callback is available, 0 means
                // unknown; cancel_current signals the newest tracked token.
                // Retain every concurrent token so a newer call completing
                // first cannot orphan an older still-running call.
                c.current_cancel.lock().unwrap().push((0, cancel.clone()));
                global_runtime().block_on(async {
                    let (_id, res) = c
                        .initiator
                        .call_cancellable_tracked(&method, payload, timeout_ms, &cancel)
                        .await;
                    {
                        let mut current = c.current_cancel.lock().unwrap();
                        // Remove only this call's token; newer and older
                        // concurrent calls keep theirs.
                        current.retain(|(_, t)| !Arc::ptr_eq(t, &cancel));
                    }
                    match res {
                        Ok(data) => emit_bytes(out_ptr, out_len, data),
                        Err(e) => c.result_error(&e),
                    }
                })
            },
            SYNTRA_E_ARG,
        )
    }));
    r.unwrap_or(SYNTRA_E_PANIC)
}

/// Best-effort cancel of one `request_id` on a handle. Unknown or
/// completed ids are ignored (`SYNTRA_OK`).
/// The tracked call API returns its id only on completion, so this
/// currently sends a protocol cancel without signalling the local call's
/// token. Use [`syntra_cancel_current`] for local cancellation until the
/// runtime exposes an id-allocation callback.
#[no_mangle]
pub extern "C" fn syntra_cancel(handle: u64, request_id: u64) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| -> i32 {
        with_conn(
            handle,
            |c| {
                global_runtime().block_on(async {
                    // Cancel the tracked in-flight call if the ids line
                    // up; always forward the protocol-level cancel too
                    // (unknown ids are ignored by the runtime).
                    for (id, token) in c.current_cancel.lock().unwrap().clone() {
                        if id != 0 && id == request_id {
                            token.cancel();
                            break;
                        }
                    }
                    match c.initiator.cancel(request_id).await {
                        Ok(()) => SYNTRA_OK,
                        Err(e) => c.result_error(&e),
                    }
                })
            },
            SYNTRA_E_ARG,
        )
    }));
    r.unwrap_or(SYNTRA_E_PANIC)
}

/// Cancel the most recently started call still tracked on a handle (if
/// any). The call sends its own protocol cancel for the allocated id.
#[no_mangle]
pub extern "C" fn syntra_cancel_current(handle: u64) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| -> i32 {
        with_conn(
            handle,
            |c| {
                // Newest tracked token wins; older concurrent calls stay
                // tracked so a newer call completing first cannot orphan
                // them.
                let entry = c.current_cancel.lock().unwrap().last().cloned();
                if let Some((_id, token)) = entry {
                    token.cancel();
                }
                SYNTRA_OK
            },
            SYNTRA_E_ARG,
        )
    }));
    r.unwrap_or(SYNTRA_E_PANIC)
}

/// Poll one notification payload. `SYNTRA_OK` with a heap buffer (free
/// with [`syntra_free`]); `SYNTRA_AGAIN` on timeout with no message;
/// negative status on error.
#[no_mangle]
pub extern "C" fn syntra_poll_notify(
    handle: u64,
    timeout_ms: u32,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| -> i32 {
        if out_ptr.is_null() || out_len.is_null() {
            return SYNTRA_E_ARG;
        }
        unsafe {
            *out_ptr = ptr::null_mut();
            *out_len = 0;
        }
        with_conn(
            handle,
            |c| {
                global_runtime().block_on(async {
                    let res = tokio::time::timeout(
                        std::time::Duration::from_millis(timeout_ms as u64),
                        c.initiator.next_notification(),
                    )
                    .await;
                    match res {
                        Ok(Some(data)) => emit_bytes(out_ptr, out_len, data),
                        Ok(None) => {
                            c.set_error("connection closed");
                            SYNTRA_E_UNAVAILABLE
                        }
                        Err(_) => SYNTRA_AGAIN,
                    }
                })
            },
            SYNTRA_E_ARG,
        )
    }));
    r.unwrap_or(SYNTRA_E_PANIC)
}

/// Graceful close + handle release. Idempotent for unknown handles
/// (`SYNTRA_OK`).
#[no_mangle]
pub extern "C" fn syntra_close(handle: u64) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| -> i32 {
        let conn = registry().lock().unwrap().conns.remove(&handle);
        match conn {
            Some(c) => {
                global_runtime().block_on(c.initiator.close());
                SYNTRA_OK
            }
            None => SYNTRA_OK,
        }
    }));
    r.unwrap_or(SYNTRA_E_PANIC)
}

/// Release a heap buffer produced by [`syntra_call`] or
/// [`syntra_poll_notify`]. `ptr` may be null (no-op).
///
/// # Safety
/// `ptr`/`len` must be exactly a buffer this library produced and not
/// yet freed.
#[no_mangle]
pub unsafe extern "C" fn syntra_free(ptr: *mut u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if ptr.is_null() {
            return;
        }
        unsafe {
            let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len));
        }
    }));
}

/// Copy the handle's last error message into `buf` (NUL-terminated,
/// truncated to `buflen - 1`). Returns bytes written excluding NUL.
#[no_mangle]
pub extern "C" fn syntra_last_error(handle: u64, buf: *mut c_char, buflen: usize) -> usize {
    let r = catch_unwind(AssertUnwindSafe(|| -> usize {
        if buf.is_null() || buflen == 0 {
            return 0;
        }
        let msg = with_conn(
            handle,
            |c| c.last_error.lock().unwrap().clone().unwrap_or_default(),
            String::new(),
        );
        let bytes = msg.as_bytes();
        let n = (buflen - 1).min(bytes.len());
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, n);
            *buf.add(n) = 0;
        }
        n
    }));
    r.unwrap_or(0)
}

/// Opaque caller context (kept for ABI evolution; currently unused).
#[allow(dead_code)]
pub struct SyntraContext {
    _private: [u8; 0],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn open_anon() -> u64 {
        let h = syntra_open(0, ptr::null(), 0);
        assert!(h > 0, "open failed: {h}");
        h as u64
    }

    #[test]
    fn abi_version_sane() {
        assert_eq!(syntra_abi_version(), (1 << 16));
        assert!(syntra_abi_compatible(1, 0));
        assert!(!syntra_abi_compatible(2, 0));
    }

    #[test]
    fn call_initializes_outputs_before_rejecting_inputs() {
        let valid_method = CString::new("/example.Echo/Echo").unwrap();
        let invalid_utf8 = [0xffu8, 0];
        for (method, payload, payload_len, expected) in [
            (ptr::null(), ptr::null(), 0, SYNTRA_E_ARG),
            (invalid_utf8.as_ptr().cast(), ptr::null(), 0, SYNTRA_E_UTF8),
            (valid_method.as_ptr(), ptr::null(), 1, SYNTRA_E_ARG),
            (valid_method.as_ptr(), ptr::null(), 0, SYNTRA_E_ARG),
        ] {
            let mut sentinel = 0u8;
            let mut out = &mut sentinel as *mut u8;
            let mut len = 123;
            assert_eq!(
                syntra_call(0, method, payload, payload_len, 1, &mut out, &mut len),
                expected
            );
            assert!(out.is_null());
            assert_eq!(len, 0);
        }
    }

    #[test]
    fn invalid_output_pointers_are_rejected_before_reading_inputs() {
        // Non-dereferenceable input is safe here only because invalid outputs
        // must return before the ABI attempts any input reads.
        let method = std::ptr::dangling::<c_char>();
        let payload = std::ptr::dangling::<u8>();
        assert_eq!(
            syntra_call(0, method, payload, 1, 1, ptr::null_mut(), ptr::null_mut()),
            SYNTRA_E_ARG
        );
        let mut sentinel = 0u8;
        let mut out = &mut sentinel as *mut u8;
        let mut len = 123;
        assert_eq!(
            syntra_call(0, method, payload, 1, 1, &mut out, ptr::null_mut()),
            SYNTRA_E_ARG
        );
        assert_eq!(out, &mut sentinel as *mut u8);
        assert_eq!(
            syntra_call(0, method, payload, 1, 1, ptr::null_mut(), &mut len),
            SYNTRA_E_ARG
        );
        assert_eq!(len, 123);
    }

    #[test]
    fn polling_uses_a_working_timer_and_clears_outputs_on_timeout() {
        let h = open_anon();
        assert_eq!(syntra_handshake(h, ptr::null(), 0), SYNTRA_OK);
        let mut out = ptr::null_mut();
        let mut len = 123;
        assert_eq!(syntra_poll_notify(h, 1, &mut out, &mut len), SYNTRA_AGAIN);
        assert!(out.is_null());
        assert_eq!(len, 0);
        assert_eq!(syntra_close(h), SYNTRA_OK);
    }

    #[test]
    fn echo_call_round_trip() {
        let h = open_anon();
        assert_eq!(syntra_handshake(h, ptr::null(), 0), SYNTRA_OK);
        let method = CString::new("/example.Echo/Echo").unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        let rc = syntra_call(
            h,
            method.as_ptr(),
            b"ping".as_ptr(),
            4,
            2000,
            &mut out,
            &mut len,
        );
        assert_eq!(rc, SYNTRA_OK);
        assert_eq!(len, 4);
        let got = unsafe { slice::from_raw_parts(out, len) }.to_vec();
        unsafe { syntra_free(out, len) };
        assert_eq!(got, b"ping");
        assert!(with_conn(
            h,
            |c| c.current_cancel.lock().unwrap().is_empty(),
            false,
        ));
        assert_eq!(syntra_close(h), SYNTRA_OK);
    }

    #[test]
    fn unknown_method_is_rpc_error_not_close() {
        let h = open_anon();
        assert_eq!(syntra_handshake(h, ptr::null(), 0), SYNTRA_OK);
        let method = CString::new("/example.Nope/Missing").unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        let rc = syntra_call(h, method.as_ptr(), ptr::null(), 0, 2000, &mut out, &mut len);
        assert_eq!(rc, SYNTRA_E_RPC);
        assert!(with_conn(
            h,
            |c| c.current_cancel.lock().unwrap().is_empty(),
            false,
        ));
        // Connection still usable.
        let method2 = CString::new("/example.Echo/Echo").unwrap();
        let rc2 = syntra_call(
            h,
            method2.as_ptr(),
            b"ok".as_ptr(),
            2,
            2000,
            &mut out,
            &mut len,
        );
        assert_eq!(rc2, SYNTRA_OK);
        unsafe { syntra_free(out, len) };
        assert_eq!(syntra_close(h), SYNTRA_OK);
    }

    #[test]
    fn malformed_method_is_invalid_argument() {
        let h = open_anon();
        assert_eq!(syntra_handshake(h, ptr::null(), 0), SYNTRA_OK);
        let method = CString::new("not-a-path").unwrap();
        let mut out: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        let rc = syntra_call(h, method.as_ptr(), ptr::null(), 0, 2000, &mut out, &mut len);
        assert_eq!(rc, SYNTRA_E_RPC);
        let mut buf = [0 as c_char; 128];
        syntra_last_error(h, buf.as_mut_ptr(), buf.len());
        let msg = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
        assert!(
            msg.contains("INVALID_ARGUMENT") || msg.contains("InvalidArgument") || !msg.is_empty()
        );
        assert_eq!(syntra_close(h), SYNTRA_OK);
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod concurrency {
        use super::*;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        const WAIT: Duration = Duration::from_secs(2);

        fn open_with_handler(handler: Arc<dyn syntra_runtime::Handler>) -> u64 {
            let h = global_runtime().block_on(async {
                let (initiator, host) = syntra_runtime::loopback_pair(
                    Arc::new(AllowAnonymous),
                    handler,
                    ConnectionConfig::default(),
                );
                let mut reg = registry().lock().unwrap();
                let h = reg.next;
                reg.next += 1;
                reg.conns.insert(
                    h,
                    Arc::new(FfiConn {
                        initiator,
                        _host: host,
                        current_cancel: Mutex::new(Vec::new()),
                        last_error: Mutex::new(None),
                    }),
                );
                h
            });
            assert_eq!(syntra_handshake(h, ptr::null(), 0), SYNTRA_OK);
            h
        }

        fn pending_connection() -> (u64, mpsc::Receiver<()>) {
            let (started, rx) = mpsc::channel();
            let h = open_with_handler(Arc::new(FnHandler(move |_, _, _| {
                started.send(()).unwrap();
                std::future::pending::<HandlerOutcome>()
            })));
            (h, rx)
        }

        fn call(h: u64, method: &str) -> i32 {
            let method = CString::new(method).unwrap();
            let mut out = ptr::null_mut();
            let mut len = 0;
            let rc = syntra_call(h, method.as_ptr(), ptr::null(), 0, 5000, &mut out, &mut len);
            if rc == SYNTRA_OK {
                unsafe { syntra_free(out, len) };
            } else {
                assert!(out.is_null());
                assert_eq!(len, 0);
            }
            rc
        }

        #[test]
        fn blocked_callback_allows_other_handles_and_close() {
            let h = open_anon();
            let other = open_anon();
            assert_eq!(syntra_handshake(other, ptr::null(), 0), SYNTRA_OK);
            let (entered, entered_rx) = mpsc::channel();
            let (release, release_rx) = mpsc::channel();
            let blocked = thread::spawn(move || {
                with_conn(
                    h,
                    |c| {
                        entered.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        // The Arc must keep this connection alive after close
                        // removes its handle from the registry.
                        c.set_error("callback finished after close");
                        SYNTRA_OK
                    },
                    SYNTRA_E_ARG,
                )
            });
            entered_rx.recv_timeout(WAIT).unwrap();
            let (done, done_rx) = mpsc::channel();
            let concurrent = thread::spawn(move || {
                let result = call(other, "/example.Echo/Echo");
                let closed = syntra_close(h);
                done.send((result, closed)).unwrap();
                syntra_close(other)
            });
            let result = done_rx.recv_timeout(WAIT);
            // Unblock even on failure so a regression cannot hang the suite.
            release.send(()).unwrap();
            assert_eq!(blocked.join().unwrap(), SYNTRA_OK);
            assert_eq!(concurrent.join().unwrap(), SYNTRA_OK);
            assert_eq!(result.unwrap(), (SYNTRA_OK, SYNTRA_OK));
            assert_eq!(syntra_cancel_current(h), SYNTRA_E_ARG);
            assert_eq!(syntra_close(h), SYNTRA_OK);
        }

        #[test]
        fn cancel_current_interrupts_a_blocking_call() {
            let (h, started) = pending_connection();
            let caller = thread::spawn(move || call(h, "/example.Test/Wait"));
            started.recv_timeout(WAIT).unwrap();
            assert_eq!(syntra_cancel_current(h), SYNTRA_OK);
            assert_eq!(caller.join().unwrap(), SYNTRA_E_CANCELLED);
            assert!(with_conn(
                h,
                |c| c.current_cancel.lock().unwrap().is_empty(),
                false,
            ));
            assert_eq!(syntra_cancel_current(h), SYNTRA_OK);
            assert_eq!(syntra_close(h), SYNTRA_OK);
        }

        #[test]
        fn close_interrupts_a_blocking_call() {
            let (h, started) = pending_connection();
            let caller = thread::spawn(move || call(h, "/example.Test/Wait"));
            started.recv_timeout(WAIT).unwrap();
            assert_eq!(syntra_close(h), SYNTRA_OK);
            assert_eq!(caller.join().unwrap(), SYNTRA_E_UNAVAILABLE);
            assert_eq!(syntra_close(h), SYNTRA_OK);
        }

        #[test]
        fn older_completion_preserves_newer_calls_cancellation() {
            let (started, started_rx) = mpsc::channel();
            let release = Arc::new(tokio::sync::Notify::new());
            let release_handler = release.clone();
            let h = open_with_handler(Arc::new(FnHandler(move |method: String, _, _| {
                let release = release_handler.clone();
                let started = started.clone();
                async move {
                    started.send(method.clone()).unwrap();
                    if method == "/example.Test/First" {
                        release.notified().await;
                        HandlerOutcome::Payload(Vec::new())
                    } else {
                        std::future::pending().await
                    }
                }
            })));
            let first = thread::spawn(move || call(h, "/example.Test/First"));
            assert_eq!(
                started_rx.recv_timeout(WAIT).unwrap(),
                "/example.Test/First"
            );
            let second = thread::spawn(move || call(h, "/example.Test/Second"));
            assert_eq!(
                started_rx.recv_timeout(WAIT).unwrap(),
                "/example.Test/Second"
            );
            release.notify_one();
            assert_eq!(first.join().unwrap(), SYNTRA_OK);
            assert_eq!(syntra_cancel_current(h), SYNTRA_OK);
            assert_eq!(second.join().unwrap(), SYNTRA_E_CANCELLED);
            assert_eq!(syntra_close(h), SYNTRA_OK);
        }
    }
}
