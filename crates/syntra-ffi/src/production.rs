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
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Shared admission limits for host results, expiry results and notifications.
const MAX_OUTBOUND_FRAMES: usize = 256;
const MAX_OUTBOUND_BYTES: usize = 16 * MAX_FRAME_BYTES;

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
    hello_sent: bool,
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
    outbound_bytes: usize,
    closed: bool,
}

impl HostInner {
    /// Reserve before retiring any pending call so backpressure is retryable.
    fn reserve_outbound(&mut self, frames: usize, bytes: usize) -> Result<(), i32> {
        if frames > MAX_OUTBOUND_FRAMES - self.outbound.len()
            || bytes > MAX_OUTBOUND_BYTES - self.outbound_bytes
        {
            return Err(SYNTRA_FFI_NOMEM);
        }
        self.outbound
            .try_reserve(frames)
            .map_err(|_| SYNTRA_FFI_NOMEM)
    }

    fn push_outbound(&mut self, bytes: Vec<u8>) {
        self.outbound_bytes += bytes.len();
        self.outbound.push_back(bytes);
    }
}

// -- Buffer helpers --------------------------------------------------------

fn init_output(out: *mut *mut u8, out_len: *mut usize) -> Result<(), i32> {
    if out.is_null() || out_len.is_null() {
        return Err(SYNTRA_FFI_INVALID);
    }
    unsafe {
        *out = ptr::null_mut();
        *out_len = 0;
    }
    Ok(())
}

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

fn alloc_owned_vec(bytes: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) -> i32 {
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
    if clamped == 0 {
        1
    } else {
        clamped as u64
    }
}

fn generate_connection_id() -> Result<String, i32> {
    connection_id_with_rng(getrandom::fill)
}

fn connection_id_with_rng<E>(fill: impl FnOnce(&mut [u8]) -> Result<(), E>) -> Result<String, i32> {
    let mut random = [0u8; 16];
    fill(&mut random).map_err(|_| SYNTRA_FFI_INTERNAL)?;
    let mut id = String::with_capacity(32);
    for byte in random {
        use std::fmt::Write;
        write!(&mut id, "{byte:02x}").map_err(|_| SYNTRA_FFI_INTERNAL)?;
    }
    Ok(id)
}

fn deadline_result(version: u32, request_id: u64) -> Vec<u8> {
    Frame {
        version,
        request_id,
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
    }
    .encode_to_vec()
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

fn host_lock<'a>(h: *mut syntra_ffi_host_t) -> Result<std::sync::MutexGuard<'a, HostInner>, i32> {
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
                hello_sent: false,
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

/// Builds the hello frame once for transport transmission, then drops the stored credential.
#[no_mangle]
pub extern "C" fn syntra_ffi_client_hello_frame(
    c: *mut syntra_ffi_client_t,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let r = catch_unwind(AssertUnwindSafe(|| {
        if let Err(code) = init_output(out, out_len) {
            return code;
        }
        let mut inner = match client_lock(c) {
            Ok(g) => g,
            Err(code) => return code,
        };
        if inner.closed {
            return SYNTRA_FFI_CLOSED;
        }
        if inner.hello_sent
            || inner.active
            || validate_hello_range(inner.min_version, inner.max_version).is_err()
        {
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
        let rc = alloc_owned_vec(bytes, out, out_len);
        if rc == SYNTRA_FFI_OK {
            inner.hello_sent = true;
            inner.credential = Vec::new();
        }
        rc
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
        if inner.active || !inner.hello_sent {
            return SYNTRA_FFI_INVALID;
        }
        if frame.request_id != 0 {
            return SYNTRA_FFI_INVALID;
        }
        match frame.body {
            Some(syntra_core::proto::frame::Body::Ready(_)) => {}
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
        if terminal_n.is_null()
            || notifications.is_null()
            || (terminal_ids.is_null() && terminal_cap != 0)
        {
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
            }
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
            }
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
        if let Err(code) = init_output(out_req_frame, out_len) {
            return code;
        }
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
        if inner.pending.contains_key(&request_id) || inner.outcomes.contains_key(&request_id) {
            return SYNTRA_FFI_INVALID;
        }
        // Unread results retain their admission slots, bounding both their
        // count and bytes (each result is at most MAX_FRAME_BYTES).
        if inner.pending.len() + inner.outcomes.len() >= inner.max_pending as usize {
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
        inner.pending.insert(
            request_id,
            PendingCall {
                deadline: Instant::now() + Duration::from_millis(budget),
                method: method_str,
            },
        );
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
        if let Err(code) = init_output(out_cancel_frame, out_len) {
            return code;
        }
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
        if let Err(code) = init_output(out, out_len) {
            return code;
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
            }
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
        if let Err(code) = init_output(out, out_len) {
            return code;
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
            }
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

/// Consumes the initiator handle, including on INTERNAL. No concurrent or subsequent use is valid.
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
            }
            Err(_) => SYNTRA_FFI_INTERNAL,
        };
        // The allocation is freed on scope exit; callers must discard the pointer.
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
                outbound_bytes: 0,
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
        if let Err(code) = init_output(out_ready_frame, out_len) {
            return code;
        }
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
        let connection_id = match generate_connection_id() {
            Ok(id) => id,
            Err(code) => return code,
        };
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
        let rc = alloc_owned_vec(bytes, out_ready_frame, out_len);
        if rc != SYNTRA_FFI_OK {
            return rc;
        }
        inner.principal = princ;
        inner.connection_id = connection_id;
        inner.active = true;
        SYNTRA_FFI_OK
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
        if has_response.is_null() || cancel_n.is_null() || (cancel_ids.is_null() && cancel_cap != 0)
        {
            return SYNTRA_FFI_INVALID;
        }
        if let Err(code) = init_output(out_response, out_len) {
            return code;
        }
        unsafe {
            *has_response = 0;
            *cancel_n = 0;
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
                        if fallback.version == inner.negotiated && fallback.request_id != 0 =>
                    {
                        match fallback.body {
                            Some(syntra_core::proto::frame::Body::Request(req))
                                if validate_method(&req.method).is_err() =>
                            {
                                let id = fallback.request_id;
                                let err_frame = Frame {
                                    version: inner.negotiated,
                                    request_id: id,
                                    body: Some(syntra_core::proto::frame::Body::Result(
                                        syntra_core::proto::RpcResult {
                                            outcome: Some(
                                                syntra_core::proto::rpc_result::Outcome::Error(
                                                    syntra_core::proto::RpcError {
                                                        code:
                                                            syntra_core::ErrorCode::InvalidArgument
                                                                .as_i32(),
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
                            _ => return SYNTRA_FFI_INVALID,
                        }
                    }
                    _ => return SYNTRA_FFI_INVALID,
                }
            }
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
                                outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(
                                    syntra_core::proto::RpcError {
                                        code: syntra_core::ErrorCode::InvalidArgument.as_i32(),
                                        message: "invalid method".to_string(),
                                    },
                                )),
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
                                outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(
                                    syntra_core::proto::RpcError {
                                        code: syntra_core::ErrorCode::FailedPrecondition.as_i32(),
                                        message: "duplicate request_id".to_string(),
                                    },
                                )),
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
                                outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(
                                    syntra_core::proto::RpcError {
                                        code: syntra_core::ErrorCode::ResourceExhausted.as_i32(),
                                        message: "too many outstanding RPCs".to_string(),
                                    },
                                )),
                            },
                        )),
                    };
                    let out = err_frame.encode_to_vec();
                    unsafe { *has_response = 1 };
                    return alloc_owned(&out, out_response, out_len);
                }
                let timeout = if req.timeout_ms == 0 {
                    3000
                } else {
                    req.timeout_ms.min(MAX_RPC_TIMEOUT_MS)
                };
                inner.pending_map.insert(
                    id,
                    HostCall {
                        deadline: Instant::now() + Duration::from_millis(timeout as u64),
                    },
                );
                inner.pending_queue.push_back((id, bytes));
                SYNTRA_FFI_OK
            }
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
            }
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
        if present.is_null() || request_id_out.is_null() {
            return SYNTRA_FFI_INVALID;
        }
        unsafe { *present = 0 };
        if let Err(code) = init_output(out_req_frame, out_len) {
            return code;
        }
        unsafe { *request_id_out = 0 };
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
                    *request_id_out = id;
                }
                SYNTRA_FFI_OK
            }
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
pub extern "C" fn syntra_ffi_host_version(h: *mut syntra_ffi_host_t, version_out: *mut u32) -> i32 {
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

/// Queues a result frame, or a deadline error if expired. NOMEM leaves the call retryable.
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
            Some(syntra_core::proto::frame::Body::Result(_)) => {}
            _ => return SYNTRA_FFI_INVALID,
        }
        if decoded.version != inner.negotiated {
            return SYNTRA_FFI_INVALID;
        }
        let is_expired = match inner.pending_map.get(&id) {
            Some(call) => call.deadline <= Instant::now(),
            None => {
                unsafe { *expired = 1 };
                return SYNTRA_FFI_OK;
            }
        };
        let encoded = if is_expired {
            deadline_result(inner.negotiated, id)
        } else {
            bytes
        };
        if let Err(code) = inner.reserve_outbound(1, encoded.len()) {
            return code;
        }
        inner.pending_map.remove(&id);
        inner.cancelled.remove(&id);
        inner
            .pending_queue
            .retain(|(queued_id, _)| *queued_id != id);
        inner.push_outbound(encoded);
        unsafe { *expired = i32::from(is_expired) };
        SYNTRA_FFI_OK
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
                syntra_core::proto::Notification {
                    payload: bytes.into(),
                },
            )),
        };
        let encoded = frame.encode_to_vec();
        if encoded.len() > MAX_FRAME_BYTES {
            return SYNTRA_FFI_INVALID;
        }
        if let Err(code) = inner.reserve_outbound(1, encoded.len()) {
            return code;
        }
        inner.push_outbound(encoded);
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
        if let Err(code) = init_output(out, out_len) {
            return code;
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
                inner.outbound_bytes -= bytes.len();
                let rc = alloc_owned_vec(bytes, out, out_len);
                if rc != SYNTRA_FFI_OK {
                    return rc;
                }
                unsafe { *present = 1 };
                SYNTRA_FFI_OK
            }
            None => SYNTRA_FFI_OK,
        }
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Drains expired host RPC ids and queues deadline results atomically.
/// NOMEM leaves all selected calls pending until outbound capacity is drained.
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
        let to_reap: Vec<(u64, Vec<u8>)> = expired
            .into_iter()
            .take(limit)
            .map(|id| (id, deadline_result(inner.negotiated, id)))
            .collect();
        let bytes = to_reap.iter().map(|(_, frame)| frame.len()).sum();
        if let Err(code) = inner.reserve_outbound(to_reap.len(), bytes) {
            return code;
        }
        // Remove queue entries for the same IDs so a reaped RPC is never
        // returned later by `host_take_pending`.
        if !to_reap.is_empty() {
            let reaped: HashSet<u64> = to_reap.iter().map(|(id, _)| *id).collect();
            inner.pending_queue.retain(|(id, _)| !reaped.contains(id));
        }
        for (id, encoded) in to_reap {
            inner.pending_map.remove(&id);
            inner.cancelled.remove(&id);
            inner.push_outbound(encoded);
            unsafe { *ids.add(written) = id };
            written += 1;
        }
        unsafe { *n = written };
        SYNTRA_FFI_OK
    }));
    r.unwrap_or(SYNTRA_FFI_INTERNAL)
}

/// Consumes the responder handle, including on INTERNAL. No concurrent or subsequent use is valid.
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
            }
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
    use syntra_core::proto::{frame::Body, rpc_result::Outcome, RpcError, RpcResult};

    fn take_bytes(out: *mut u8, len: usize) -> Vec<u8> {
        let bytes = if len == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(out, len).to_vec() }
        };
        syntra_ffi_free(out, len);
        bytes
    }

    fn active_pair() -> (*mut syntra_ffi_client_t, *mut syntra_ffi_host_t) {
        let c = open_client();
        let mut h = ptr::null_mut();
        assert_eq!(syntra_ffi_host_open(1, 1, 16, &mut h), SYNTRA_FFI_OK);
        let mut out = ptr::null_mut();
        let mut len = 0;
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut out, &mut len),
            SYNTRA_FFI_OK
        );
        let hello = take_bytes(out, len);
        let mut version = 0;
        assert_eq!(
            syntra_ffi_host_accept_hello(h, hello.as_ptr(), hello.len(), &mut version),
            SYNTRA_FFI_OK
        );
        assert_eq!(
            syntra_ffi_host_auth_complete(h, b"svc".as_ptr().cast(), 3, &mut out, &mut len),
            SYNTRA_FFI_OK
        );
        let ready = take_bytes(out, len);
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_OK
        );
        (c, h)
    }

    fn begin_status(c: *mut syntra_ffi_client_t, id: u64) -> (i32, Vec<u8>) {
        let mut out = ptr::null_mut();
        let mut len = 0;
        let method = b"/example.Echo/Echo";
        let rc = syntra_ffi_client_begin_call(
            c,
            id,
            method.as_ptr(),
            method.len(),
            b"req".as_ptr(),
            3,
            30000,
            &mut out,
            &mut len,
        );
        (rc, take_bytes(out, len))
    }

    fn result(id: u64, error: bool) -> Vec<u8> {
        Frame {
            version: 1,
            request_id: id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(if error {
                    Outcome::Error(RpcError {
                        code: 7,
                        message: "denied".to_string(),
                    })
                } else {
                    Outcome::Payload(b"response\0\xff".to_vec().into())
                }),
            })),
        }
        .encode_to_vec()
    }

    fn next_outbound(h: *mut syntra_ffi_host_t) -> Vec<u8> {
        let mut out = ptr::null_mut();
        let mut len = 0;
        let mut present = 0;
        assert_eq!(
            syntra_ffi_host_next_outbound(h, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!(present, 1);
        take_bytes(out, len)
    }

    fn ingest_result(c: *mut syntra_ffi_client_t, bytes: &[u8], id: u64) {
        let mut terminal = 0;
        let mut n = 0;
        let mut notifications = 0;
        assert_eq!(
            syntra_ffi_client_on_frame(
                c,
                bytes.as_ptr(),
                bytes.len(),
                &mut terminal,
                1,
                &mut n,
                &mut notifications
            ),
            SYNTRA_FFI_OK
        );
        assert_eq!((terminal, n, notifications), (id, 1, 0));
    }

    #[test]
    fn request_dispatch_answer_outbound_client_outcome_round_trip() {
        let (c, h) = active_pair();
        for (id, error, expired) in [(1, false, false), (2, true, false), (3, false, true)] {
            let (rc, request) = begin_status(c, id);
            assert_eq!(rc, SYNTRA_FFI_OK);
            assert_eq!(on_frame_status(h, &request), (SYNTRA_FFI_OK, 0));
            let mut taken_id = 0;
            let mut out = ptr::null_mut();
            let mut len = 0;
            let mut present = 0;
            assert_eq!(
                syntra_ffi_host_take_pending(h, &mut taken_id, &mut out, &mut len, &mut present),
                SYNTRA_FFI_OK
            );
            assert_eq!((taken_id, present), (id, 1));
            assert_eq!(take_bytes(out, len), request);
            if expired {
                host_lock(h)
                    .unwrap()
                    .pending_map
                    .get_mut(&id)
                    .unwrap()
                    .deadline = Instant::now();
            }
            let supplied = result(id, error);
            let mut was_expired = -1;
            assert_eq!(
                syntra_ffi_host_answer(h, supplied.as_ptr(), supplied.len(), &mut was_expired),
                SYNTRA_FFI_OK
            );
            assert_eq!(was_expired, i32::from(expired));
            let expected = if expired {
                deadline_result(1, id)
            } else {
                supplied
            };
            let outbound = next_outbound(h);
            assert_eq!(outbound, expected);
            ingest_result(c, &outbound, id);
            assert_eq!(
                syntra_ffi_client_take_outcome(c, id, &mut out, &mut len, &mut present),
                SYNTRA_FFI_OK
            );
            assert_eq!(present, 1);
            assert_eq!(take_bytes(out, len), expected);
            assert_eq!(
                syntra_ffi_client_take_outcome(c, id, &mut out, &mut len, &mut present),
                SYNTRA_FFI_OK
            );
            assert_eq!((out.is_null(), len, present), (true, 0, 0));
        }
        assert_eq!(host_lock(h).unwrap().outbound_bytes, 0);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    #[test]
    fn outbound_count_backpressure_preserves_answer_and_expiry_batch() {
        let (c, h) = active_pair();
        for id in 1..=2 {
            let (rc, request) = begin_status(c, id);
            assert_eq!(rc, SYNTRA_FFI_OK);
            assert_eq!(on_frame_status(h, &request), (SYNTRA_FFI_OK, 0));
        }
        {
            let mut inner = host_lock(h).unwrap();
            inner.cancelled.insert(1);
        }
        for _ in 0..MAX_OUTBOUND_FRAMES {
            assert_eq!(syntra_ffi_host_notify(h, ptr::null(), 0), SYNTRA_FFI_OK);
        }
        assert_eq!(syntra_ffi_host_notify(h, ptr::null(), 0), SYNTRA_FFI_NOMEM);
        let supplied = result(1, false);
        let mut expired = -1;
        assert_eq!(
            syntra_ffi_host_answer(h, supplied.as_ptr(), supplied.len(), &mut expired),
            SYNTRA_FFI_NOMEM
        );
        assert_eq!(expired, 0);
        {
            let mut inner = host_lock(h).unwrap();
            assert_eq!(inner.pending_map.len(), 2);
            assert_eq!(inner.pending_queue.len(), 2);
            assert!(inner.cancelled.contains(&1));
            for call in inner.pending_map.values_mut() {
                call.deadline = Instant::now();
            }
        }
        let mut ids = [0; 2];
        let mut n = 99;
        assert_eq!(
            syntra_ffi_host_reap_expired(h, ids.as_mut_ptr(), 2, &mut n),
            SYNTRA_FFI_NOMEM
        );
        assert_eq!((ids, n), ([0, 0], 0));
        assert_eq!(
            syntra_ffi_host_answer(h, supplied.as_ptr(), supplied.len(), &mut expired),
            SYNTRA_FFI_NOMEM
        );
        assert_eq!(expired, 0);
        assert_eq!(host_lock(h).unwrap().pending_queue.len(), 2);
        next_outbound(h);
        assert_eq!(
            syntra_ffi_host_reap_expired(h, ids.as_mut_ptr(), 2, &mut n),
            SYNTRA_FFI_NOMEM
        );
        assert_eq!(host_lock(h).unwrap().pending_map.len(), 2);
        // An expired answer also needs admission before retiring its call.
        assert_eq!(
            syntra_ffi_host_answer(h, supplied.as_ptr(), supplied.len(), &mut expired),
            SYNTRA_FFI_OK
        );
        assert_eq!(expired, 1);
        assert_eq!(
            syntra_ffi_host_reap_expired(h, ids.as_mut_ptr(), 2, &mut n),
            SYNTRA_FFI_NOMEM
        );
        next_outbound(h);
        assert_eq!(
            syntra_ffi_host_reap_expired(h, ids.as_mut_ptr(), 2, &mut n),
            SYNTRA_FFI_OK
        );
        assert_eq!((ids[0], n), (2, 1));
        {
            let inner = host_lock(h).unwrap();
            assert!(
                inner.pending_map.is_empty()
                    && inner.pending_queue.is_empty()
                    && inner.cancelled.is_empty()
            );
            assert_eq!(inner.outbound.len(), MAX_OUTBOUND_FRAMES);
        }
        for _ in 0..MAX_OUTBOUND_FRAMES - 2 {
            next_outbound(h);
        }
        assert_eq!(next_outbound(h), deadline_result(1, 1));
        assert_eq!(next_outbound(h), deadline_result(1, 2));
        assert_eq!(host_lock(h).unwrap().outbound_bytes, 0);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    #[test]
    fn outbound_byte_backpressure_and_answer_without_dispatch() {
        let (c, h) = active_pair();
        let (_, request) = begin_status(c, 1);
        assert_eq!(on_frame_status(h, &request), (SYNTRA_FFI_OK, 0));
        let large = vec![0; MAX_FRAME_BYTES - 32];
        let mut accepted = 0;
        while syntra_ffi_host_notify(h, large.as_ptr(), large.len()) == SYNTRA_FFI_OK {
            accepted += 1;
            assert!(accepted <= MAX_OUTBOUND_FRAMES);
        }
        assert!(accepted < MAX_OUTBOUND_FRAMES);
        let supplied = Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(large.into())),
            })),
        }
        .encode_to_vec();
        let mut expired = 0;
        assert_eq!(
            syntra_ffi_host_answer(h, supplied.as_ptr(), supplied.len(), &mut expired),
            SYNTRA_FFI_NOMEM
        );
        assert_eq!(host_lock(h).unwrap().pending_queue.len(), 1);
        next_outbound(h);
        assert_eq!(
            syntra_ffi_host_answer(h, supplied.as_ptr(), supplied.len(), &mut expired),
            SYNTRA_FFI_OK
        );
        assert_eq!(expired, 0);
        assert!(host_lock(h).unwrap().pending_queue.is_empty());
        for _ in 1..accepted {
            next_outbound(h);
        }
        assert_eq!(next_outbound(h), supplied);
        assert_eq!(host_lock(h).unwrap().outbound_bytes, 0);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    #[test]
    fn unread_outcomes_retain_admission_and_cannot_be_overwritten() {
        let (c, h) = active_pair();
        client_lock(c).unwrap().max_pending = 2;
        for id in 1..=2 {
            assert_eq!(begin_status(c, id).0, SYNTRA_FFI_OK);
            ingest_result(c, &result(id, false), id);
        }
        assert_eq!(begin_status(c, 3).0, SYNTRA_FFI_NOMEM);
        assert_eq!(begin_status(c, 1).0, SYNTRA_FFI_INVALID);
        let mut out = ptr::null_mut();
        let mut len = 0;
        let mut present = 0;
        assert_eq!(
            syntra_ffi_client_take_outcome(c, 1, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!(take_bytes(out, len), result(1, false));
        assert_eq!(begin_status(c, 3).0, SYNTRA_FFI_OK);
        assert_eq!(begin_status(c, 4).0, SYNTRA_FFI_NOMEM);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    #[test]
    fn hello_is_once_and_ready_requires_hello_and_outputs() {
        let mut c = ptr::null_mut();
        let credential = b"private-token";
        assert_eq!(
            syntra_ffi_client_open(
                1,
                1,
                credential.as_ptr(),
                credential.len(),
                3000,
                16,
                &mut c
            ),
            SYNTRA_FFI_OK
        );
        let ready = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Ready(syntra_core::proto::ServerReady {
                connection_id: "0123456789abcdef0123456789abcdef".to_string(),
            })),
        }
        .encode_to_vec();
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_INVALID
        );
        let mut out = ptr::null_mut();
        let mut len = 0;
        assert_eq!(
            syntra_ffi_client_hello_frame(c, ptr::null_mut(), &mut len),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut out, ptr::null_mut()),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(client_lock(c).unwrap().credential, credential);
        assert!(!client_lock(c).unwrap().hello_sent);
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut out, &mut len),
            SYNTRA_FFI_OK
        );
        let hello = take_bytes(out, len);
        let frame = Frame::decode(hello.as_slice()).unwrap();
        match frame.body {
            Some(Body::Hello(hello)) => assert_eq!(&hello.credential[..], credential),
            _ => panic!("expected hello"),
        }
        assert_eq!(client_lock(c).unwrap().credential.capacity(), 0);
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut out, &mut len),
            SYNTRA_FFI_INVALID
        );
        assert_eq!((out.is_null(), len), (true, 0));
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_OK
        );
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut out, &mut len),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
    }

    #[test]
    fn connection_ids_use_128_random_bits_and_fail_closed() {
        let id = connection_id_with_rng(|bytes| {
            assert_eq!(bytes.len(), 16);
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = i as u8;
            }
            Ok::<_, ()>(())
        })
        .unwrap();
        assert_eq!(id, "000102030405060708090a0b0c0d0e0f");
        assert_eq!(
            connection_id_with_rng(|_| Err(())),
            Err(SYNTRA_FFI_INTERNAL)
        );
        let first = generate_connection_id().unwrap();
        let second = generate_connection_id().unwrap();
        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn invalid_read_outputs_preserve_queued_items_and_empty_reads_clear_buffers() {
        let (c, h) = active_pair();
        let (_, request) = begin_status(c, 1);
        assert_eq!(on_frame_status(h, &request), (SYNTRA_FFI_OK, 0));
        ingest_result(c, &result(1, false), 1);
        let notification = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Notification(syntra_core::proto::Notification {
                payload: b"notice".to_vec().into(),
            })),
        }
        .encode_to_vec();
        let mut n = 0;
        let mut queued = 0;
        assert_eq!(
            syntra_ffi_client_on_frame(
                c,
                notification.as_ptr(),
                notification.len(),
                ptr::null_mut(),
                0,
                &mut n,
                &mut queued
            ),
            SYNTRA_FFI_OK
        );
        assert_eq!(
            syntra_ffi_host_notify(h, b"notice".as_ptr(), 6),
            SYNTRA_FFI_OK
        );
        for missing in 0..3 {
            let mut out = ptr::null_mut();
            let mut len = 0;
            let mut present = 0;
            let mut id = 0;
            let out_arg = if missing == 0 {
                ptr::null_mut()
            } else {
                &mut out
            };
            let len_arg = if missing == 1 {
                ptr::null_mut()
            } else {
                &mut len
            };
            let present_arg = if missing == 2 {
                ptr::null_mut()
            } else {
                &mut present
            };
            assert_eq!(
                syntra_ffi_client_take_outcome(c, 1, out_arg, len_arg, present_arg),
                SYNTRA_FFI_INVALID
            );
            assert_eq!(
                syntra_ffi_client_poll_notification(c, out_arg, len_arg, present_arg),
                SYNTRA_FFI_INVALID
            );
            assert_eq!(
                syntra_ffi_host_take_pending(h, &mut id, out_arg, len_arg, present_arg),
                SYNTRA_FFI_INVALID
            );
            assert_eq!(
                syntra_ffi_host_next_outbound(h, out_arg, len_arg, present_arg),
                SYNTRA_FFI_INVALID
            );
        }
        let mut out = ptr::null_mut();
        let mut len = 0;
        let mut present = 0;
        assert_eq!(
            syntra_ffi_host_take_pending(h, ptr::null_mut(), &mut out, &mut len, &mut present),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(client_lock(c).unwrap().outcomes.len(), 1);
        assert_eq!(client_lock(c).unwrap().notifications.len(), 1);
        assert_eq!(host_lock(h).unwrap().pending_queue.len(), 1);
        assert_eq!(host_lock(h).unwrap().outbound.len(), 1);
        assert_eq!(
            syntra_ffi_client_take_outcome(c, 1, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!(present, 1);
        assert_eq!(take_bytes(out, len), result(1, false));
        assert_eq!(
            syntra_ffi_client_poll_notification(c, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!(present, 1);
        assert_eq!(take_bytes(out, len), notification);
        let mut id = 0;
        assert_eq!(
            syntra_ffi_host_take_pending(h, &mut id, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!((id, present), (1, 1));
        assert_eq!(take_bytes(out, len), request);
        assert_eq!(next_outbound(h), notification);
        // Sentinel pointers are never dereferenced; empty reads overwrite them.
        out = ptr::dangling_mut();
        len = 99;
        present = 99;
        assert_eq!(
            syntra_ffi_client_take_outcome(c, 1, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!((out.is_null(), len, present), (true, 0, 0));
        out = ptr::dangling_mut();
        len = 99;
        assert_eq!(
            syntra_ffi_client_poll_notification(c, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!((out.is_null(), len, present), (true, 0, 0));
        out = ptr::dangling_mut();
        len = 99;
        assert_eq!(
            syntra_ffi_host_take_pending(h, &mut id, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!((id, out.is_null(), len, present), (0, true, 0, 0));
        out = ptr::dangling_mut();
        len = 99;
        assert_eq!(
            syntra_ffi_host_next_outbound(h, &mut out, &mut len, &mut present),
            SYNTRA_FFI_OK
        );
        assert_eq!((out.is_null(), len, present), (true, 0, 0));
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    #[test]
    fn invalid_outputs_do_not_activate_admit_complete_cancel_or_reap() {
        let c = open_client();
        let mut h = ptr::null_mut();
        assert_eq!(syntra_ffi_host_open(1, 1, 16, &mut h), SYNTRA_FFI_OK);
        let mut out = ptr::null_mut();
        let mut len = 0;
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut out, &mut len),
            SYNTRA_FFI_OK
        );
        let hello = take_bytes(out, len);
        let mut version = 0;
        assert_eq!(
            syntra_ffi_host_accept_hello(h, hello.as_ptr(), hello.len(), &mut version),
            SYNTRA_FFI_OK
        );
        for missing in 0..2 {
            let out_arg = if missing == 0 {
                ptr::null_mut()
            } else {
                &mut out
            };
            let len_arg = if missing == 1 {
                ptr::null_mut()
            } else {
                &mut len
            };
            assert_eq!(
                syntra_ffi_host_auth_complete(h, b"svc".as_ptr().cast(), 3, out_arg, len_arg),
                SYNTRA_FFI_INVALID
            );
            let inner = host_lock(h).unwrap();
            assert!(!inner.active && inner.principal.is_empty() && inner.connection_id.is_empty());
        }
        assert_eq!(
            syntra_ffi_host_auth_complete(h, b"svc".as_ptr().cast(), 3, &mut out, &mut len),
            SYNTRA_FFI_OK
        );
        let ready = take_bytes(out, len);
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_OK
        );
        let method = b"/example.Echo/Echo";
        for missing in 0..2 {
            let out_arg = if missing == 0 {
                ptr::null_mut()
            } else {
                &mut out
            };
            let len_arg = if missing == 1 {
                ptr::null_mut()
            } else {
                &mut len
            };
            assert_eq!(
                syntra_ffi_client_begin_call(
                    c,
                    1,
                    method.as_ptr(),
                    method.len(),
                    ptr::null(),
                    0,
                    30000,
                    out_arg,
                    len_arg
                ),
                SYNTRA_FFI_INVALID
            );
            assert!(client_lock(c).unwrap().pending.is_empty());
            assert_eq!(
                syntra_ffi_client_cancel(c, 999, out_arg, len_arg),
                SYNTRA_FFI_INVALID
            );
        }
        let (_, request) = begin_status(c, 1);
        let mut response = 0;
        let mut n = 0;
        for missing in 0..4 {
            let out_arg = if missing == 0 {
                ptr::null_mut()
            } else {
                &mut out
            };
            let len_arg = if missing == 1 {
                ptr::null_mut()
            } else {
                &mut len
            };
            let response_arg = if missing == 2 {
                ptr::null_mut()
            } else {
                &mut response
            };
            let n_arg = if missing == 3 {
                ptr::null_mut()
            } else {
                &mut n
            };
            assert_eq!(
                syntra_ffi_host_on_frame(
                    h,
                    request.as_ptr(),
                    request.len(),
                    out_arg,
                    len_arg,
                    response_arg,
                    ptr::null_mut(),
                    0,
                    n_arg
                ),
                SYNTRA_FFI_INVALID
            );
            assert!(host_lock(h).unwrap().pending_map.is_empty());
        }
        assert_eq!(on_frame_status(h, &request), (SYNTRA_FFI_OK, 0));
        let cancel = Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Cancel(syntra_core::proto::Cancel {})),
        }
        .encode_to_vec();
        assert_eq!(
            syntra_ffi_host_on_frame(
                h,
                cancel.as_ptr(),
                cancel.len(),
                &mut out,
                &mut len,
                &mut response,
                ptr::null_mut(),
                1,
                &mut n
            ),
            SYNTRA_FFI_INVALID
        );
        assert!(host_lock(h).unwrap().cancelled.is_empty());
        let supplied = result(1, false);
        let mut notifications = 0;
        assert_eq!(
            syntra_ffi_client_on_frame(
                c,
                supplied.as_ptr(),
                supplied.len(),
                ptr::null_mut(),
                1,
                &mut n,
                &mut notifications
            ),
            SYNTRA_FFI_INVALID
        );
        assert!(client_lock(c).unwrap().pending.contains_key(&1));
        assert!(client_lock(c).unwrap().outcomes.is_empty());
        client_lock(c)
            .unwrap()
            .pending
            .get_mut(&1)
            .unwrap()
            .deadline = Instant::now();
        host_lock(h)
            .unwrap()
            .pending_map
            .get_mut(&1)
            .unwrap()
            .deadline = Instant::now();
        assert_eq!(
            syntra_ffi_client_reap_expired(c, ptr::null_mut(), 1, &mut n),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(
            syntra_ffi_host_reap_expired(h, ptr::null_mut(), 1, &mut n),
            SYNTRA_FFI_INVALID
        );
        assert_eq!(client_lock(c).unwrap().pending.len(), 1);
        assert_eq!(host_lock(h).unwrap().pending_map.len(), 1);
        assert!(host_lock(h).unwrap().outbound.is_empty());
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

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
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut ptr, &mut len),
            SYNTRA_FFI_OK
        );
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
            syntra_ffi_host_auth_complete(
                h,
                princ.as_ptr() as *const _,
                princ.len(),
                &mut rptr,
                &mut rlen
            ),
            SYNTRA_FFI_OK
        );
        let ready = unsafe { slice::from_raw_parts(rptr, rlen).to_vec() };
        syntra_ffi_free(rptr, rlen);
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_OK
        );

        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        assert_eq!(syntra_ffi_host_close(h), SYNTRA_FFI_OK);
    }

    fn open_active_host() -> *mut syntra_ffi_host_t {
        let c = open_client();
        let mut ptr: *mut u8 = ptr::null_mut();
        let mut len = 0usize;
        assert_eq!(
            syntra_ffi_client_hello_frame(c, &mut ptr, &mut len),
            SYNTRA_FFI_OK
        );
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
            syntra_ffi_host_auth_complete(
                h,
                princ.as_ptr() as *const _,
                princ.len(),
                &mut rptr,
                &mut rlen
            ),
            SYNTRA_FFI_OK
        );
        syntra_ffi_free(rptr, rlen);
        assert_eq!(syntra_ffi_client_close(c), SYNTRA_FFI_OK);
        h
    }

    fn on_frame_status(h: *mut syntra_ffi_host_t, bytes: &[u8]) -> (i32, i32) {
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
            syntra_ffi_host_auth_complete(
                h,
                princ.as_ptr() as *const _,
                princ.len(),
                &mut rptr,
                &mut rlen
            ),
            SYNTRA_FFI_OK
        );
        let ready = unsafe { slice::from_raw_parts(rptr, rlen).to_vec() };
        syntra_ffi_free(rptr, rlen);
        assert_eq!(
            syntra_ffi_client_activate(c, ready.as_ptr(), ready.len()),
            SYNTRA_FFI_OK
        );
        let notif = |payload: &[u8]| {
            Frame {
                version: 1,
                request_id: 0,
                body: Some(syntra_core::proto::frame::Body::Notification(
                    syntra_core::proto::Notification {
                        payload: payload.to_vec().into(),
                    },
                )),
            }
            .encode_to_vec()
        };
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
        assert_eq!(
            was_queued, 0,
            "overflow must not report a queued notification"
        );
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
