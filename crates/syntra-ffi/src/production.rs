//! Production native C ABI over transport-agnostic protocol cores.
//!
//! This module owns protocol mechanics only: version negotiation, frame
//! validation, correlation tracking, deadlines, cancellation observation,
//! and outbound queueing. The embedding application owns transport bytes,
//! authentication policy, authorization policy, method dispatch, persistence,
//! and recovery.
//!
//! Design:
//! - Stable opaque pointer handles, opened exactly once, closed exactly once.
//! - Explicit `(ptr, len)` buffer ownership: inputs are borrowed for the call,
//!   outputs are owned and released exactly once with `syntra_ffi_free`.
//! - Status codes are FFI-layer failures only. Per-RPC failures travel inside
//!   `RpcResult` frames.
//! - Host authentication completes asynchronously in the embedding
//!   application. `host_accept_hello` validates shape and selects a version;
//!   the application resolves policy, then calls `host_auth_complete` with
//!   the bound principal to receive the `ServerReady` frame.

use std::collections::{HashMap, HashSet, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::{atomic::AtomicU64, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use prost::Message;

use syntra_core::{
    validate_hello_range, validate_method, validate_wire_structure, ConnectionState, Frame,
    ValidationContext, MAX_CREDENTIAL_BYTES, MAX_FRAME_BYTES,
};

// -- ABI version and status -----------------------------------------------

/// Production ABI version. Bumped on any incompatible change.
pub const SYNTRA_FFI_ABI_VERSION: u32 = 1;

/// FFI-layer success.
pub const SYNTRA_FFI_OK: i32 = 0;
/// Invalid argument, malformed frame, or protocol violation.
pub const SYNTRA_FFI_INVALID: i32 = -1;
/// Operation on a closed handle.
pub const SYNTRA_FFI_CLOSED: i32 = -2;
/// ABI version mismatch. Reserved for future use; not returned. Compare
/// `syntra_ffi_abi_version()` against `SYNTRA_FFI_ABI_VERSION` out of band.
pub const SYNTRA_FFI_ABI_MISMATCH: i32 = -3;
/// Allocation failure.
pub const SYNTRA_FFI_NOMEM: i32 = -4;
/// Deadline expired. Reserved as a return code; expiration is reported via
/// out-params (`expired=1`) and reap lists, with `SYNTRA_FFI_OK` returned.
pub const SYNTRA_FFI_EXPIRED: i32 = -5;
/// Internal failure (including contained panic).
pub const SYNTRA_FFI_INTERNAL: i32 = -6;

/// Maximum RPC timeout enforced at this boundary (30 s).
const MAX_RPC_TIMEOUT_MS: u32 = 30_000;
/// Maximum concurrent RPCs enforced when the opener requests zero.
const DEFAULT_MAX_PENDING: u32 = 16;
/// Hard cap for concurrent RPCs at this boundary.
const HARD_MAX_PENDING: u32 = 256;
/// Cap for drained terminal IDs per call.
const MAX_DRAIN_IDS: usize = 256;

static CONNECTION_SEQ: AtomicU64 = AtomicU64::new(1);

// -- Opaque handles --------------------------------------------------------

/// Opaque initiator core. Transport pump lives in the embedding application.
#[repr(C)]
pub struct syntra_ffi_client_t {
    inner: Mutex<ClientInner>,
}

/// Opaque responder core. Dispatch lives in the embedding application.
#[repr(C)]
pub struct syntra_ffi_host_t {
    inner: Mutex<HostInner>,
}

struct PendingCall {
    deadline: Instant,
    #[allow(dead_code)]
    method: String,
}

struct ClientInner {
    min_version: u32,
    max_version: u32,
    credential: Vec<u8>,
    default_timeout_ms: u32,
    max_pending: u32,
    negotiated: u32,
    active: bool,
    pending: HashMap<u64, PendingCall>,
    outcomes: HashMap<u64, Vec<u8>>,
    notifications: VecDeque<Vec<u8>>,
    /// Cumulative notifications dropped under overflow (bounded queue,
    /// non-blocking drop-newest). Paired with `notification_dropped_bytes`;
    /// both advance exactly once per drop (no double-counting).
    notification_dropped: u64,
    notification_dropped_bytes: u64,
    closed: bool,
}

struct HostCall {
    deadline: Instant,
}

struct HostInner {
    min_version: u32,
    max_version: u32,
    max_pending: u32,
    negotiated: u32,
    active: bool,
    principal: String,
    connection_id: String,
    pending_queue: VecDeque<(u64, Vec<u8>)>,
    pending_map: HashMap<u64, HostCall>,
    cancelled: HashSet<u64>,
    outbound: VecDeque<Vec<u8>>,
    closed: bool,
}

// -- Buffer helpers --------------------------------------------------------

fn borrow_bytes(ptr: *const u8, len: usize) -> Result<Vec<u8>, i32> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(SYNTRA_FFI_INVALID);
    }
    unsafe { Ok(slice::from_raw_parts(ptr, len).to_vec()) }
}

fn alloc_owned(bytes: &[u8], out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return SYNTRA_FFI_INVALID;
    }
    unsafe {
        *out_ptr = ptr::null_mut();
        *out_len = 0;
    }
    if bytes.is_empty() {
        return SYNTRA_FFI_OK;
    }
    if bytes.len() > MAX_FRAME_BYTES {
        return SYNTRA_FFI_INVALID;
    }
    let mut boxed = bytes.to_vec().into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    SYNTRA_FFI_OK
}

fn alloc_owned_vec(
    bytes: Vec<u8>,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return SYNTRA_FFI_INVALID;
    }
    unsafe {
        *out_ptr = ptr::null_mut();
        *out_len = 0;
    }
    if bytes.is_empty() {
        return SYNTRA_FFI_OK;
    }
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
    SYNTRA_FFI_OK
}

fn effective_timeout_ms(requested: u32, def: u32) -> u64 {
    let base = if requested == 0 { def } else { requested };
    let clamped = base.min(MAX_RPC_TIMEOUT_MS);
    if clamped == 0 { 1 } else { clamped as u64 }
}

fn generate_connection_id() -> String {
    let seq = CONNECTION_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("c-{seq:x}-{nanos:x}")
}

fn decode_frame(bytes: &[u8], ctx: ValidationContext) -> Result<Frame, i32> {
    syntra_core::codec::decode_frame(bytes, ctx).map_err(|_| SYNTRA_FFI_INVALID)
}

fn client_lock<'a>(
    c: *mut syntra_ffi_client_t,
) -> Result<std::sync::MutexGuard<'a, ClientInner>, i32> {
    if c.is_null() {
        return Err(SYNTRA_FFI_INVALID);
    }
    let handle = unsafe { &*c };
    handle.inner.lock().map_err(|_| SYNTRA_FFI_INTERNAL)
}

fn host_lock<'a>(
    h: *mut syntra_ffi_host_t,
) -> Result<std::sync::MutexGuard<'a, HostInner>, i32> {
    if h.is_null() {
        return Err(SYNTRA_FFI_INVALID);
    }
    let handle = unsafe { &*h };
    handle.inner.lock().map_err(|_| SYNTRA_FFI_INTERNAL)
}

// -- Version and memory -----------------------------------------------------

/// Returns the production ABI version (`1`).
#[no_mangle]
pub extern "C" fn syntra_ffi_abi_version() -> u32 {
    SYNTRA_FFI_ABI_VERSION
}

/// Releases an owned `(ptr, len)` buffer exactly once.
/// `(NULL, 0)` is valid and does nothing.
#[no_mangle]
pub extern "C" fn syntra_ffi_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

// -- Client session ----------------------------------------------------------

/// Opens an initiator core. The credential is retained for hello construction.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_open(
    min_version: u32,
    max_version: u32,
    credential: *const u8,
    credential_len: usize,
    default_timeout_ms: u32,
    max_concurrent: u32,
    out: *mut *mut syntra_ffi_client_t,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *out = ptr::null_mut() };
        if min_version == 0 || max_version == 0 || min_version > max_version {
            return SYNTRA_FFI_INVALID;
        }
        // Bound the caller length before copying: a huge valid buffer would
        // otherwise make `borrow_bytes` attempt an aborting allocation.
        if credential_len > MAX_CREDENTIAL_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let cred = match borrow_bytes(credential, credential_len) {
            Ok(v) => v,
            Err(c) => return c,
        };
        if cred.len() > MAX_CREDENTIAL_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let max_pending = if max_concurrent == 0 {
            DEFAULT_MAX_PENDING
        } else if max_concurrent > HARD_MAX_PENDING {
            return SYNTRA_FFI_INVALID;
        } else {
            max_concurrent
        };
        let def = if default_timeout_ms == 0 {
            3000
        } else {
            default_timeout_ms.min(MAX_RPC_TIMEOUT_MS)
        };
        let core = Box::new(syntra_ffi_client_t {
            inner: Mutex::new(ClientInner {
                min_version,
                max_version,
                credential: cred,
                default_timeout_ms: def,
                max_pending,
                negotiated: 0,
                active: false,
                pending: HashMap::new(),
                outcomes: HashMap::new(),
                notifications: VecDeque::new(),
                notification_dropped: 0,
                notification_dropped_bytes: 0,
                closed: false,
            }),
        });
        unsafe { *out = Box::into_raw(core) };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Builds the hello frame for transport transmission.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_hello_frame(
    c: *mut syntra_ffi_client_t,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        let inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if validate_hello_range(inner.min_version, inner.max_version).is_err() {
            return SYNTRA_FFI_INVALID;
        }
        let hello = syntra_core::proto::ClientHello {
            min_version: inner.min_version,
            max_version: inner.max_version,
            credential: inner.credential.clone().into(),
        };
        let frame = Frame {
            version: inner.max_version,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Hello(hello)),
        };
        let bytes = frame.encode_to_vec();
        if bytes.len() > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        alloc_owned(&bytes, out, out_len)
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Activates the initiator from a ready frame.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_activate(
    c: *mut syntra_ffi_client_t,
    ready_frame: *const u8,
    len: usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let bytes = match borrow_bytes(ready_frame, len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let frame = match decode_frame(
            &bytes,
            ValidationContext::pre_handshake(ConnectionState::Authenticating),
        ) {
            Ok(f) => f,
            Err(code) => return code,
        };
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if inner.active {
            return SYNTRA_FFI_INVALID;
        }
        if frame.request_id != 0 {
            return SYNTRA_FFI_INVALID;
        }
        match frame.body {
            Some(syntra_core::proto::frame::Body::Ready(_)) => {},
            _ => return SYNTRA_FFI_INVALID,
        }
        if frame.version < inner.min_version || frame.version > inner.max_version {
            return SYNTRA_FFI_INVALID;
        }
        if frame.version == 0 {
            return SYNTRA_FFI_INVALID;
        }
        inner.negotiated = frame.version;
        inner.active = true;
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Ingests one transport frame. Reports completed RPC ids and notifications.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_on_frame(
    c: *mut syntra_ffi_client_t,
    frame: *const u8,
    len: usize,
    terminal_ids: *mut u64,
    terminal_cap: usize,
    terminal_n: *mut usize,
    notifications: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if terminal_n.is_null() || notifications.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe {
            *terminal_n = 0;
            *notifications = 0;
        }
        if len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let bytes = match borrow_bytes(frame, len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if bytes.is_empty() {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if !inner.active || inner.negotiated == 0 {
            return SYNTRA_FFI_INVALID;
        }
        let decoded = match decode_frame(&bytes, ValidationContext::active(inner.negotiated)) {
            Ok(f) => f,
            Err(code) => return code,
        };
        if decoded.version != inner.negotiated {
            return SYNTRA_FFI_INVALID;
        }
        match decoded.body {
            Some(syntra_core::proto::frame::Body::Result(_)) => {
                let id = decoded.request_id;
                if id == 0 || !inner.pending.contains_key(&id) {
                    return SYNTRA_FFI_OK;
                }
                inner.pending.remove(&id);
                inner.outcomes.insert(id, bytes);
                if !terminal_ids.is_null() && terminal_cap > 0 {
                    unsafe {
                        *terminal_ids = id;
                        *terminal_n = 1;
                    }
                }
                SYNTRA_FFI_OK
            },
            Some(syntra_core::proto::frame::Body::Notification(n)) => {
                if decoded.request_id != 0 {
                    return SYNTRA_FFI_INVALID;
                }
                // Bounded non-blocking queue with cumulative loss accounting
                // (unified with async Rust `record_notification_loss` and the
                // Go cores): when full, the incoming (newest) notification
                // drops and the cumulative counters advance by exactly one
                // drop plus its payload bytes. Previously queued items are
                // preserved; no silent oldest-eviction.
                if inner.notifications.len() >= 256 {
                    let payload_bytes = n.payload.len() as u64;
                    inner.notification_dropped += 1;
                    inner.notification_dropped_bytes += payload_bytes;
                    return SYNTRA_FFI_OK;
                }
                inner.notifications.push_back(bytes);
                unsafe { *notifications = 1 };
                SYNTRA_FFI_OK
            },
            _ => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Begins an RPC and returns the request frame for transport.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_begin_call(
    c: *mut syntra_ffi_client_t,
    request_id: u64,
    method: *const u8,
    method_len: usize,
    payload: *const u8,
    payload_len: usize,
    timeout_ms: u32,
    out_req_frame: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if request_id == 0 {
            return SYNTRA_FFI_INVALID;
        }
        // Bound caller lengths before copying (see borrow_bytes).
        if method_len > 512 {
            return SYNTRA_FFI_INVALID;
        }
        if payload_len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let method_bytes = match borrow_bytes(method, method_len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let method_str = match String::from_utf8(method_bytes) {
            Ok(s) => s,
            Err(_) => return SYNTRA_FFI_INVALID,
        };
        if validate_method(&method_str).is_err() {
            return SYNTRA_FFI_INVALID;
        }
        let payload_bytes = match borrow_bytes(payload, payload_len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        if payload_bytes.len() > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        if timeout_ms > MAX_RPC_TIMEOUT_MS {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if !inner.active || inner.negotiated == 0 {
            return SYNTRA_FFI_INVALID;
        }
        if inner.pending.contains_key(&request_id) {
            return SYNTRA_FFI_INVALID;
        }
        if (inner.pending.len() as u32) >= inner.max_pending {
            return SYNTRA_FFI_NOMEM;
        }
        let budget = effective_timeout_ms(timeout_ms, inner.default_timeout_ms);
        let req = syntra_core::proto::RpcRequest {
            method: method_str.clone(),
            payload: payload_bytes.into(),
            timeout_ms: budget as u32,
        };
        let frame = Frame {
            version: inner.negotiated,
            request_id,
            body: Some(syntra_core::proto::frame::Body::Request(req)),
        };
        let bytes = frame.encode_to_vec();
        if bytes.len() > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        inner.pending.insert(request_id, PendingCall {
            deadline: Instant::now() + Duration::from_millis(budget),
            method: method_str,
        });
        alloc_owned(&bytes, out_req_frame, out_len)
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Builds a cancel frame for an outstanding RPC.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_cancel(
    c: *mut syntra_ffi_client_t,
    request_id: u64,
    out_cancel_frame: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if request_id == 0 {
            return SYNTRA_FFI_INVALID;
        }
        let inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if !inner.active || !inner.pending.contains_key(&request_id) {
            if !out_cancel_frame.is_null() {
                unsafe { *out_cancel_frame = ptr::null_mut() };
            }
            if !out_len.is_null() {
                unsafe { *out_len = 0 };
            }
            return SYNTRA_FFI_OK;
        }
        let frame = Frame {
            version: inner.negotiated,
            request_id,
            body: Some(syntra_core::proto::frame::Body::Cancel(
                syntra_core::proto::Cancel {},
            )),
        };
        let bytes = frame.encode_to_vec();
        alloc_owned(&bytes, out_cancel_frame, out_len)
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Takes a completed RPC outcome frame.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_take_outcome(
    c: *mut syntra_ffi_client_t,
    request_id: u64,
    out: *mut *mut u8,
    out_len: *mut usize,
    present: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if present.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *present = 0 };
        if out.is_null() || out_len.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        match inner.outcomes.remove(&request_id) {
            Some(bytes) => {
                let rc = alloc_owned_vec(bytes, out, out_len);
                if rc != SYNTRA_FFI_OK {
                    return rc;
                }
                unsafe { *present = 1 };
                SYNTRA_FFI_OK
            },
            None => SYNTRA_FFI_OK,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Takes the next queued notification frame.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_poll_notification(
    c: *mut syntra_ffi_client_t,
    out: *mut *mut u8,
    out_len: *mut usize,
    present: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if present.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *present = 0 };
        if out.is_null() || out_len.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        match inner.notifications.pop_front() {
            Some(bytes) => {
                let rc = alloc_owned_vec(bytes, out, out_len);
                if rc != SYNTRA_FFI_OK {
                    return rc;
                }
                unsafe { *present = 1 };
                SYNTRA_FFI_OK
            },
            None => SYNTRA_FFI_OK,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Reports cumulative notification-loss totals for the initiator core:
/// `(dropped_count, dropped_bytes)` for notifications discarded when the
/// bounded queue was full. The queue stays non-blocking and drops the newest
/// notification. Counters advance exactly once per drop (no double-counting)
/// and unify with the async Rust `notification_loss` and Go `LossTotals`.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_notification_loss(
    c: *mut syntra_ffi_client_t,
    dropped_out: *mut u64,
    dropped_bytes_out: *mut u64,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if dropped_out.is_null() || dropped_bytes_out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        unsafe {
            *dropped_out = inner.notification_dropped;
            *dropped_bytes_out = inner.notification_dropped_bytes;
        }
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Drains expired RPC ids.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_reap_expired(
    c: *mut syntra_ffi_client_t,
    ids: *mut u64,
    cap: usize,
    n: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if n.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *n = 0 };
        if ids.is_null() && cap != 0 {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        let now = Instant::now();
        let mut expired = Vec::new();
        for (id, call) in inner.pending.iter() {
            if call.deadline <= now {
                expired.push(*id);
            }
        }
        expired.sort_unstable();
        let limit = cap.min(MAX_DRAIN_IDS);
        let mut written = 0usize;
        for id in expired.into_iter().take(limit) {
            inner.pending.remove(&id);
            unsafe { *ids.add(written) = id };
            written += 1;
        }
        unsafe { *n = written };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Closes an initiator core exactly once.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_close(c: *mut syntra_ffi_client_t) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if c.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let boxed: Box<syntra_ffi_client_t> = unsafe { Box::from_raw(c) };
        let result = match boxed.inner.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    SYNTRA_FFI_CLOSED
                } else {
                    inner.closed = true;
                    inner.pending.clear();
                    inner.outcomes.clear();
                    inner.notifications.clear();
                    SYNTRA_FFI_OK
                }
            },
            Err(_) => SYNTRA_FFI_INTERNAL,
        };
        // Guard is dropped here; Box frees the allocation on scope exit.
        // A second close would use-after-free at the C layer; Go guards
        // double-close before reaching here.
        let _ = &boxed;
        result
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

// -- Host session ------------------------------------------------------------

/// Opens a responder core for one connection.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_open(
    min_version: u32,
    max_version: u32,
    max_concurrent: u32,
    out: *mut *mut syntra_ffi_host_t,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *out = ptr::null_mut() };
        if min_version == 0 || max_version == 0 || min_version > max_version {
            return SYNTRA_FFI_INVALID;
        }
        let max_pending = if max_concurrent == 0 {
            DEFAULT_MAX_PENDING
        } else if max_concurrent > HARD_MAX_PENDING {
            return SYNTRA_FFI_INVALID;
        } else {
            max_concurrent
        };
        let core = Box::new(syntra_ffi_host_t {
            inner: Mutex::new(HostInner {
                min_version,
                max_version,
                max_pending,
                negotiated: 0,
                active: false,
                principal: String::new(),
                connection_id: String::new(),
                pending_queue: VecDeque::new(),
                pending_map: HashMap::new(),
                cancelled: HashSet::new(),
                outbound: VecDeque::new(),
                closed: false,
            }),
        });
        unsafe { *out = Box::into_raw(core) };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Validates a hello frame and selects a version. No policy is evaluated here.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_accept_hello(
    h: *mut syntra_ffi_host_t,
    frame: *const u8,
    len: usize,
    version_out: *mut u32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if version_out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *version_out = 0 };
        if len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let bytes = match borrow_bytes(frame, len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let decoded = match decode_frame(
            &bytes,
            ValidationContext::pre_handshake(ConnectionState::Connected),
        ) {
            Ok(f) => f,
            Err(code) => return code,
        };
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if inner.active || inner.negotiated != 0 {
            return SYNTRA_FFI_INVALID;
        }
        if decoded.request_id != 0 {
            return SYNTRA_FFI_INVALID;
        }
        let hello = match decoded.body {
            Some(syntra_core::proto::frame::Body::Hello(v)) => v,
            _ => return SYNTRA_FFI_INVALID,
        };
        if decoded.version != hello.max_version {
            return SYNTRA_FFI_INVALID;
        }
        if validate_hello_range(hello.min_version, hello.max_version).is_err() {
            return SYNTRA_FFI_INVALID;
        }
        if hello.credential.len() > MAX_CREDENTIAL_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        // Intersect contiguous ranges arithmetically; never materialize
        // `(min..=max)` which a peer or embedder could make arbitrarily
        // large. Highest overlap wins, matching `negotiate_version`
        // semantics for contiguous host support.
        let lo = hello.min_version.max(inner.min_version);
        let hi = hello.max_version.min(inner.max_version);
        if lo > hi {
            return SYNTRA_FFI_INVALID;
        }
        let selected = hi;
        inner.negotiated = selected;
        unsafe { *version_out = selected };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Completes authentication with a host-resolved principal and returns ready.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_auth_complete(
    h: *mut syntra_ffi_host_t,
    principal: *const ::std::os::raw::c_char,
    principal_len: usize,
    out_ready_frame: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if principal_len > 512 {
            return SYNTRA_FFI_INVALID;
        }
        let princ_bytes = match borrow_bytes(principal as *const u8, principal_len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let princ = match String::from_utf8(princ_bytes) {
            Ok(s) => s,
            Err(_) => return SYNTRA_FFI_INVALID,
        };
        if princ.is_empty() || princ.len() > 512 {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if inner.active || inner.negotiated == 0 {
            return SYNTRA_FFI_INVALID;
        }
        let connection_id = generate_connection_id();
        let ready = syntra_core::proto::ServerReady {
            connection_id: connection_id.clone(),
        };
        let frame = Frame {
            version: inner.negotiated,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Ready(ready)),
        };
        let bytes = frame.encode_to_vec();
        if bytes.len() > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INTERNAL;
        }
        inner.principal = princ;
        inner.connection_id = connection_id;
        inner.active = true;
        alloc_owned(&bytes, out_ready_frame, out_len)
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Ingests one transport frame. Queues dispatchable requests and reports cancels.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_on_frame(
    h: *mut syntra_ffi_host_t,
    frame: *const u8,
    len: usize,
    out_response: *mut *mut u8,
    out_len: *mut usize,
    has_response: *mut i32,
    cancel_ids: *mut u64,
    cancel_cap: usize,
    cancel_n: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if has_response.is_null() || cancel_n.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe {
            *has_response = 0;
            *cancel_n = 0;
            if !out_response.is_null() {
                *out_response = ptr::null_mut();
            }
            if !out_len.is_null() {
                *out_len = 0;
            }
        }
        if len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let bytes = match borrow_bytes(frame, len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if !inner.active || inner.negotiated == 0 {
            return SYNTRA_FFI_INVALID;
        }
        let decoded = match decode_frame(&bytes, ValidationContext::active(inner.negotiated)) {
            Ok(f) => f,
            Err(_) => {
                // Core validation is the primary gate, but a well-formed
                // Request envelope with a malformed method stays a per-RPC
                // error, never a fatal connection failure. Raw-wire
                // structural violations (reserved tags, duplicate bodies,
                // truncation, alloc/depth bounds) are rejected first: only
                // a structurally sound envelope qualifies for per-RPC
                // method-error mapping. The prost fallback below is error
                // mapping only and is never dispatched without validation.
                if validate_wire_structure(&bytes).is_err() {
                    return SYNTRA_FFI_INVALID;
                }
                match Frame::decode(bytes.as_slice()) {
                    Ok(fallback)
                        if fallback.version == inner.negotiated
                            && fallback.request_id != 0 =>
                    {
                        match fallback.body {
                            Some(syntra_core::proto::frame::Body::Request(req))
                                if validate_method(&req.method).is_err() =>
                            {
                                let id = fallback.request_id;
                                let err_frame = Frame {
                                    version: inner.negotiated,
                                    request_id: id,
                                    body: Some(
                                        syntra_core::proto::frame::Body::Result(
                                            syntra_core::proto::RpcResult {
                                                outcome: Some(
                                                    syntra_core::proto::rpc_result::Outcome::Error(
                                                        syntra_core::proto::RpcError {
                                                            code: syntra_core::ErrorCode::InvalidArgument.as_i32(),
                                                            message: "invalid method".to_string(),
                                                        },
                                                    ),
                                                ),
                                            },
                                        ),
                                    ),
                                };
                                let out = err_frame.encode_to_vec();
                                unsafe { *has_response = 1 };
                                return alloc_owned(&out, out_response, out_len);
                            },
                            _ => return SYNTRA_FFI_INVALID,
                        }
                    },
                    _ => return SYNTRA_FFI_INVALID,
                }
            },
        };
        if decoded.version != inner.negotiated {
            return SYNTRA_FFI_INVALID;
        }
        match decoded.body {
            Some(syntra_core::proto::frame::Body::Request(req)) => {
                let id = decoded.request_id;
                if id == 0 {
                    return SYNTRA_FFI_INVALID;
                }
                if validate_method(&req.method).is_err() {
                    let err_frame = Frame {
                        version: inner.negotiated,
                        request_id: id,
                        body: Some(syntra_core::proto::frame::Body::Result(
                            syntra_core::proto::RpcResult {
                                outcome: Some(
                                    syntra_core::proto::rpc_result::Outcome::Error(
                                        syntra_core::proto::RpcError {
                                            code: syntra_core::ErrorCode::InvalidArgument.as_i32(),
                                            message: "invalid method".to_string(),
                                        },
                                    ),
                                ),
                            },
                        )),
                    };
                    let out = err_frame.encode_to_vec();
                    unsafe { *has_response = 1 };
                    return alloc_owned(&out, out_response, out_len);
                }
                if inner.pending_map.contains_key(&id) {
                    let err_frame = Frame {
                        version: inner.negotiated,
                        request_id: id,
                        body: Some(syntra_core::proto::frame::Body::Result(
                            syntra_core::proto::RpcResult {
                                outcome: Some(
                                    syntra_core::proto::rpc_result::Outcome::Error(
                                        syntra_core::proto::RpcError {
                                            code: syntra_core::ErrorCode::FailedPrecondition.as_i32(),
                                            message: "duplicate request_id".to_string(),
                                        },
                                    ),
                                ),
                            },
                        )),
                    };
                    let out = err_frame.encode_to_vec();
                    unsafe { *has_response = 1 };
                    return alloc_owned(&out, out_response, out_len);
                }
                if (inner.pending_map.len() as u32) >= inner.max_pending {
                    let err_frame = Frame {
                        version: inner.negotiated,
                        request_id: id,
                        body: Some(syntra_core::proto::frame::Body::Result(
                            syntra_core::proto::RpcResult {
                                outcome: Some(
                                    syntra_core::proto::rpc_result::Outcome::Error(
                                        syntra_core::proto::RpcError {
                                            code: syntra_core::ErrorCode::ResourceExhausted.as_i32(),
                                            message: "too many outstanding RPCs".to_string(),
                                        },
                                    ),
                                ),
                            },
                        )),
                    };
                    let out = err_frame.encode_to_vec();
                    unsafe { *has_response = 1 };
                    return alloc_owned(&out, out_response, out_len);
                }
                let timeout = if req.timeout_ms == 0 { 3000 } else { req.timeout_ms.min(MAX_RPC_TIMEOUT_MS) };
                inner.pending_map.insert(id, HostCall {
                    deadline: Instant::now() + Duration::from_millis(timeout as u64),
                });
                inner.pending_queue.push_back((id, bytes));
                SYNTRA_FFI_OK
            },
            Some(syntra_core::proto::frame::Body::Cancel(_)) => {
                let id = decoded.request_id;
                if id == 0 {
                    return SYNTRA_FFI_OK;
                }
                if inner.pending_map.contains_key(&id) {
                    inner.cancelled.insert(id);
                    if !cancel_ids.is_null() && cancel_cap > 0 {
                        unsafe {
                            *cancel_ids = id;
                            *cancel_n = 1;
                        }
                    }
                }
                SYNTRA_FFI_OK
            },
            _ => SYNTRA_FFI_INVALID,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Takes the next pending request for application dispatch.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_take_pending(
    h: *mut syntra_ffi_host_t,
    request_id_out: *mut u64,
    out_req_frame: *mut *mut u8,
    out_len: *mut usize,
    present: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if present.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *present = 0 };
        if out_req_frame.is_null() || out_len.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        match inner.pending_queue.pop_front() {
            Some((id, bytes)) => {
                let rc = alloc_owned_vec(bytes, out_req_frame, out_len);
                if rc != SYNTRA_FFI_OK {
                    return rc;
                }
                unsafe {
                    *present = 1;
                    if !request_id_out.is_null() {
                        *request_id_out = id;
                    }
                }
                SYNTRA_FFI_OK
            },
            None => SYNTRA_FFI_OK,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Reports whether a request was cancelled.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_is_cancelled(
    h: *mut syntra_ffi_host_t,
    request_id: u64,
    cancelled: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if cancelled.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *cancelled = 0 };
        let inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if inner.cancelled.contains(&request_id) {
            unsafe { *cancelled = 1 };
        }
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Returns the negotiated version.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_version(
    h: *mut syntra_ffi_host_t,
    version_out: *mut u32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if version_out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        unsafe { *version_out = inner.negotiated };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Records a result frame. Returns expired=1 when the RPC already expired.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_answer(
    h: *mut syntra_ffi_host_t,
    result_frame: *const u8,
    len: usize,
    expired: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if expired.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *expired = 0 };
        if len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let bytes = match borrow_bytes(result_frame, len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if inner.negotiated == 0 {
            return SYNTRA_FFI_INVALID;
        }
        let decoded = match decode_frame(&bytes, ValidationContext::active(inner.negotiated)) {
            Ok(f) => f,
            Err(code) => return code,
        };
        let id = decoded.request_id;
        if id == 0 {
            return SYNTRA_FFI_INVALID;
        }
        match decoded.body {
            Some(syntra_core::proto::frame::Body::Result(_)) => {},
            _ => return SYNTRA_FFI_INVALID,
        }
        if decoded.version != inner.negotiated {
            return SYNTRA_FFI_INVALID;
        }
        match inner.pending_map.remove(&id) {
            Some(call) => {
                inner.cancelled.remove(&id);
                if call.deadline <= Instant::now() {
                    let version = inner.negotiated;
                    let frame = Frame {
                        version,
                        request_id: id,
                        body: Some(syntra_core::proto::frame::Body::Result(
                            syntra_core::proto::RpcResult {
                                outcome: Some(
                                    syntra_core::proto::rpc_result::Outcome::Error(
                                        syntra_core::proto::RpcError {
                                            code: syntra_core::ErrorCode::DeadlineExceeded.as_i32(),
                                            message: "deadline exceeded".to_string(),
                                        },
                                    ),
                                ),
                            },
                        )),
                    };
                    let encoded = frame.encode_to_vec();
                    if encoded.len() <= MAX_FRAME_BYTES {
                        inner.outbound.push_back(encoded);
                    }
                    unsafe { *expired = 1 };
                }
                SYNTRA_FFI_OK
            },
            None => {
                unsafe { *expired = 1 };
                SYNTRA_FFI_OK
            },
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Queues a notification payload for outbound transmission.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_notify(
    h: *mut syntra_ffi_host_t,
    payload: *const u8,
    len: usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if len > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        let bytes = match borrow_bytes(payload, len) {
            Ok(v) => v,
            Err(code) => return code,
        };
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if !inner.active {
            return SYNTRA_FFI_INVALID;
        }
        let frame = Frame {
            version: inner.negotiated,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Notification(
                syntra_core::proto::Notification { payload: bytes.into() },
            )),
        };
        let encoded = frame.encode_to_vec();
        if encoded.len() > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        if inner.outbound.len() >= 256 {
            return SYNTRA_FFI_NOMEM;
        }
        inner.outbound.push_back(encoded);
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Takes the next outbound frame.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_next_outbound(
    h: *mut syntra_ffi_host_t,
    out: *mut *mut u8,
    out_len: *mut usize,
    present: *mut i32,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if present.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *present = 0 };
        if out.is_null() || out_len.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        match inner.outbound.pop_front() {
            Some(bytes) => {
                let rc = alloc_owned_vec(bytes, out, out_len);
                if rc != SYNTRA_FFI_OK {
                    return rc;
                }
                unsafe { *present = 1 };
                SYNTRA_FFI_OK
            },
            None => SYNTRA_FFI_OK,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Drains expired host RPC ids.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_reap_expired(
    h: *mut syntra_ffi_host_t,
    ids: *mut u64,
    cap: usize,
    n: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if n.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *n = 0 };
        if ids.is_null() && cap != 0 {
            return SYNTRA_FFI_INVALID;
        }
        let mut inner = match host_lock(h) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        let now = Instant::now();
        let mut expired = Vec::new();
        for (id, call) in inner.pending_map.iter() {
            if call.deadline <= now {
                expired.push(*id);
            }
        }
        expired.sort_unstable();
        let limit = cap.min(MAX_DRAIN_IDS);
        let mut written = 0usize;
        let to_reap: Vec<u64> = expired.into_iter().take(limit).collect();
        // Remove queue entries for the same IDs so a reaped RPC is never
        // returned later by `host_take_pending`.
        if !to_reap.is_empty() {
            let reaped: HashSet<u64> = to_reap.iter().copied().collect();
            inner.pending_queue.retain(|(id, _)| !reaped.contains(id));
        }
        for id in to_reap {
            inner.pending_map.remove(&id);
            inner.cancelled.remove(&id);
            let version = inner.negotiated;
            let frame = Frame {
                version,
                request_id: id,
                body: Some(syntra_core::proto::frame::Body::Result(
                    syntra_core::proto::RpcResult {
                        outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(
                            syntra_core::proto::RpcError {
                                code: syntra_core::ErrorCode::DeadlineExceeded.as_i32(),
                                message: "deadline exceeded".to_string(),
                            },
                        )),
                    },
                )),
            };
            let encoded = frame.encode_to_vec();
            if encoded.len() <= MAX_FRAME_BYTES {
                inner.outbound.push_back(encoded);
            }
            unsafe { *ids.add(written) = id };
            written += 1;
        }
        unsafe { *n = written };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Closes a responder core exactly once.
#[no_mangle]
pub extern "C" fn syntra_ffi_host_close(h: *mut syntra_ffi_host_t) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if h.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        let boxed: Box<syntra_ffi_host_t> = unsafe { Box::from_raw(h) };
        let result = match boxed.inner.lock() {
            Ok(mut inner) => {
                if inner.closed {
                    SYNTRA_FFI_CLOSED
                } else {
                    inner.closed = true;
                    inner.pending_queue.clear();
                    inner.pending_map.clear();
                    inner.cancelled.clear();
                    inner.outbound.clear();
                    SYNTRA_FFI_OK
                }
            },
            Err(_) => SYNTRA_FFI_INTERNAL,
        };
        let _ = &boxed;
        result
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_client() -> *mut syntra_ffi_client_t {
        let mut out: *mut syntra_ffi_client_t = ptr::null_mut();
        let rc = syntra_ffi_client_open(1, 1, ptr::null(), 0, 3000, 16, &mut out);
        assert_eq!(rc, SYNTRA_FFI_OK);
        assert!(!out.is_null());
        out
    }

    #[test]
    fn abi_version_is_one() {
        assert_eq!(syntra_ffi_abi_version(), 1);
    }

    #[test]
    fn client_hello_activate_round_trip() {
        let c = open_client();
        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        assert_eq!(syntra_ffi_client_hello_frame(c, &mut ptr, &mut len), SYNTRA_FFI_OK);
        assert!(!ptr.is_null() && len > 0);
        let hello = unsafe { slice::from_raw_parts(ptr, len).to_vec() };
        syntra_ffi_free(ptr, len);

        let mut h: *mut syntra_ffi_host_t = ptr::null_mut();
        assert_eq!(syntra_ffi_host_open(1, 1, 16, &mut h), SYNTRA_FFI_OK);
        let mut ver = 0u32;
        assert_eq!(
            syntra_ffi_host_accept_hello(h, hello.as_ptr(), hello.len(), &mut ver),
            SYNTRA_FFI_OK
        );
        assert_eq!(ver, 1);

        let princ = b"svc-test";
        let mut rptr: *mut u8 = ptr::null_mut();
        let mut rlen = 0usize;
        assert_eq!(
            syntra_ffi_host_auth_complete(h, princ.as_ptr() as *const _, princ.len(), &mut rptr, &mut rlen),
            SYNTRA_FFI_OK
        );
        let ready = unsafe { slice::from_raw_parts(rptr, rlen).to_vec() };
        syntra_ffi_free(rptr, rlen);
        assert_eq!(syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()), SYNTRA_FFI_OK);

        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    fn open_active_host() -> *mut syntra_ffi_host_t {
        let c = open_client();
        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        assert_eq!(syntra_ffi_client_hello_frame(c, &mut ptr, &mut len), SYNTRA_FFI_OK);
        let hello = unsafe { slice::from_raw_parts(ptr, len).to_vec() };
        syntra_ffi_free(ptr, len);
        let mut h: *mut syntra_ffi_host_t = ptr::null_mut();
        assert_eq!(syntra_ffi_host_open(1, 1, 16, &mut h), SYNTRA_FFI_OK);
        let mut ver = 0u32;
        assert_eq!(
            syntra_ffi_host_accept_hello(h, hello.as_ptr(), hello.len(), &mut ver),
            SYNTRA_FFI_OK
        );
        let princ = b"svc-test";
        let mut rptr: *mut u8 = ptr::null_mut();
        let mut rlen = 0usize;
        assert_eq!(
            syntra_ffi_host_auth_complete(h, princ.as_ptr() as *const _, princ.len(), &mut rptr, &mut rlen),
            SYNTRA_FFI_OK
        );
        syntra_ffi_free(rptr, rlen);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        h
    }

    fn on_frame_status(
        h: *mut syntra_ffi_host_t,
        bytes: &[u8],
    ) -> (i32, i32) {
        let mut out: *mut u8 = ptr::null_mut();
        let mut out_len = 0usize;
        let mut has_response = 0i32;
        let mut cancel_n = 0usize;
        let rc = syntra_ffi_host_on_frame(
            h,
            bytes.as_ptr(),
            bytes.len(),
            &mut out,
            &mut out_len,
            &mut has_response,
            ptr::null_mut(),
            0,
            &mut cancel_n,
        );
        if has_response != 0 {
            syntra_ffi_free(out, out_len);
        }
        (rc, has_response)
    }

    #[test]
    fn notification_overflow_drops_newest_with_cumulative_loss() {
        let c = open_client();
        let mut h: *mut syntra_ffi_host_t = ptr::null_mut();
        assert_eq!(syntra_ffi_host_open(1, 1, 16, &mut h), SYNTRA_FFI_OK);
        let mut hello_ptr: *mut u8 = ptr::null_mut();
        let mut hello_len = 0usize;
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut hello_ptr, &mut hello_len),
            SYNTRA_FFI_OK
        );
        let hello = unsafe { slice::from_raw_parts(hello_ptr, hello_len).to_vec() };
        syntra_ffi_free(hello_ptr, hello_len);
        let mut ver = 0u32;
        assert_eq!(
            syntra_ffi_host_accept_hello(h, hello.as_ptr(), hello.len(), &mut ver),
            SYNTRA_FFI_OK
        );
        let princ = b"svc-test";
        let mut rptr: *mut u8 = ptr::null_mut();
        let mut rlen = 0usize;
        assert_eq!(
            syntra_ffi_host_auth_complete(h, princ.as_ptr() as *const _, princ.len(), &mut rptr, &mut rlen),
            SYNTRA_FFI_OK
        );
        let ready = unsafe { slice::from_raw_parts(rptr, rlen).to_vec() };
        syntra_ffi_free(rptr, rlen);
        assert_eq!(syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()), SYNTRA_FFI_OK);
        let notif = |payload: &[u8]| Frame {
            version: 1,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Notification(
                syntra_core::proto::Notification { payload: payload.to_vec().into() },
            )),
        }
        .encode_to_vec();
        let mut terminal_n = 0usize;
        let mut was_queued = 0i32;
        for i in 0..256u32 {
            let bytes = notif(format!("n-{i}").as_bytes());
            assert_eq!(
                syntra_ffi_client_on_frame(
                    c,
                    bytes.as_ptr(),
                    bytes.len(),
                    ptr::null_mut(),
                    0,
                    &mut terminal_n,
                    &mut was_queued
                ),
                SYNTRA_FFI_OK
            );
            assert_eq!(was_queued, 1);
        }
        let dropped_bytes = notif(b"0123456789");
        assert_eq!(
            syntra_ffi_client_on_frame(
                c,
                dropped_bytes.as_ptr(),
                dropped_bytes.len(),
                ptr::null_mut(),
                0,
                &mut terminal_n,
                &mut was_queued
            ),
            SYNTRA_FFI_OK
        );
        assert_eq!(was_queued, 0, "overflow must not report a queued notification");
        let mut dropped = 0u64;
        let mut dropped_bytes_out = 0u64;
        assert_eq!(
            syntra_ffi_client_notification_loss(c, &mut dropped, &mut dropped_bytes_out),
            SYNTRA_FFI_OK
        );
        assert_eq!(dropped, 1);
        assert_eq!(dropped_bytes_out, 10);
        let dropped2 = notif(b"ab");
        assert_eq!(
            syntra_ffi_client_on_frame(
                c,
                dropped2.as_ptr(),
                dropped2.len(),
                ptr::null_mut(),
                0,
                &mut terminal_n,
                &mut was_queued
            ),
            SYNTRA_FFI_OK
        );
        assert_eq!(
            syntra_ffi_client_notification_loss(c, &mut dropped, &mut dropped_bytes_out),
            SYNTRA_FFI_OK
        );
        assert_eq!((dropped, dropped_bytes_out), (2, 12));
        let mut first: *mut u8 = ptr::null_mut();
        let mut first_len = 0usize;
        let mut present = 0i32;
        assert_eq!(
            syntra_ffi_client_poll_notification(c, &mut first, &mut first_len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!(present, 1);
        syntra_ffi_free(first, first_len);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    #[test]
    fn invalid_method_with_structural_violation_is_fatal() {
        let h = open_active_host();
        // Control: prost-encoded bad-method request is a per-RPC error.
        let bad = Frame {
            version: 1,
            request_id: 7,
            body: Some(syntra_core::proto::frame::Body::Request(
                syntra_core::proto::RpcRequest {
                    method: "not-a-method".to_string(),
                    payload: Vec::new().into(),
                    timeout_ms: 1000,
                },
            )),
        };
        let bad_bytes = bad.encode_to_vec();
        let (rc, has_response) = on_frame_status(h, &bad_bytes);
        assert_eq!(rc, SYNTRA_FFI_OK);
        assert_eq!(has_response, 1);
        // Same malformed method plus a duplicate body field on the raw
        // wire: structural violation, so the connection fails instead of
        // reporting a per-RPC error. The version/request_id prefix for
        // small ids is four bytes; the remainder is the body field.
        let mut raw = bad_bytes.clone();
        raw.extend_from_slice(&bad_bytes[4..]);
        let (rc, has_response) = on_frame_status(h, &raw);
        assert_eq!(rc, SYNTRA_FFI_INVALID);
        assert_eq!(has_response, 0);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }
}
