//! Host (server) engine: handshake acceptance, request dispatch,
//! cancellation, and connection-bound sessions.
//!
//! The host validates `hello` shape and size bounds BEFORE policy
//! evaluation, selects (or rejects) deterministically, emits exactly one
//! terminal handshake outcome, binds exactly one principal for the
//! connection lifetime, and never dispatches handlers or emits
//! notifications before ACTIVE.
//!
//! Spec mapping:
//! - version-range check first, credential semantics second
//!   (SNTR-HS-003); mismatch → `UNIMPLEMENTED` + close;
//! - auth rejection → `UNAUTHENTICATED`/`PERMISSION_DENIED` (generic
//!   message, no oracle) + close;
//! - handshake timeout and transport loss abort with `DEADLINE_EXCEEDED`
//!   / `UNAVAILABLE` and explicitly close the core;
//! - unexpected messages pre-`ACTIVE` (second `hello`, `ready`,
//!   `request`, `result`, `cancel`, `notification`, unknown variant)
//!   → `FAILED_PRECONDITION` (`UNIMPLEMENTED` for unknown variants,
//!   which arrive as decode errors) + close (handshake.md section 1B;
//!   carrier B1: the typed code is surfaced locally, no `Frame` is
//!   emitted to carry it, and re-handshake on the transport is
//!   forbidden);
//! - malformed methods in ACTIVE → terminal `INVALID_ARGUMENT`
//!   `result`, connection stays usable (no socket close);
//! - unknown methods (valid shape, no handler) → terminal
//!   `UNIMPLEMENTED`, connection stays usable;
//! - overload → terminal `RESOURCE_EXHAUSTED`, connection stays usable
//!   (offenders isolated, SNTR-REL-007/008);
//! - per-RPC responder deadlines start BEFORE queue admission
//!   (measured from receipt of the complete validated frame);
//!   completion wins races; cancel-vs-deadline ties prefer `CANCELLED`
//!   (recorded tie-break for open B10);
//! - every accepted RPC ends with exactly one terminal `result`
//!   (SNTR-RPC-002/006/030); a second `result` for the same id is never
//!   sent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use prost::Message;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use syntra_core::{
    decode_frame, proto::frame::Body, validate_frame, ConnectionState, ErrorCode, Frame,
    RpcRequest, RpcResult, StateEvent, SyntraError,
};

use crate::connection::{
    fill_random, sleep_until, spawn_task, Connection, ConnectionConfig, Role, Shared, TaskHandle,
    SHUTDOWN_GRACE,
};
use crate::session::{AuthError, Authenticator, Principal, Session, SessionManager};

/// Handler outcome for one dispatched RPC.
#[derive(Debug, Clone)]
pub enum HandlerOutcome {
    Payload(Vec<u8>),
    Error { code: ErrorCode, message: String },
}

impl HandlerOutcome {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Application handler: owns method semantics. Payloads are opaque bytes;
/// the core never validates them. Handlers SHOULD honor `cancel` promptly
/// but completion still wins races at the core layer.
///
/// Authorization is fail-closed by default: the provided `authorize`
/// default denies every RPC with `PERMISSION_DENIED` (generic message, no
/// oracle). This is a deliberate compatibility break for handlers written
/// against the pre-policy trait, which only implemented `handle` and were
/// implicitly permissive. Migration paths:
/// - implement `authorize` with a principal-aware per-method policy
///   (preferred for protected methods; must be nonblocking and may
///   re-check expiry/revocation);
/// - wrap a legacy permissive handler in [`AllowAll`] to restore the old
///   allow behavior explicitly (tests, trusted embeds);
/// - use [`FnHandler`] for closures, which remains allow-all by
///   construction and is unchanged by this default.
/// Only generic authentication/authorization codes and messages are
/// exposed on the wire; policy internals must never leak.
pub trait Handler: Send + Sync {
    /// Host-owned per-method policy, evaluated for every RPC using the
    /// connection's bound principal, before handler effects. Implementations
    /// must be nonblocking and may re-check expiry/revocation here. The
    /// default denies access (fail-closed); only generic
    /// authentication/authorization codes and messages are exposed on the
    /// wire.
    fn authorize(&self, _principal: &Principal, _method: &str) -> Result<(), AuthError> {
        Err(AuthError::denied())
    }

    fn handle(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
    ) -> HandlerFut;
}

pub type HandlerFut = std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send>>;

/// Explicit opt-in allow-all wrapper for migration. Wrapping a legacy
/// permissive `Handler` in `AllowAll` restores the pre-policy behavior
/// (every bound principal may invoke every method) without changing the
/// inner handler's method semantics. Prefer a principal-aware `authorize`
/// implementation for protected methods; use this wrapper only for trusted
/// tests/embeds where the allow-all posture is intentional and documented
/// at the construction site.
pub struct AllowAll<H>(pub H);

impl<H> Handler for AllowAll<H>
where
    H: Handler,
{
    fn authorize(&self, _principal: &Principal, _method: &str) -> Result<(), AuthError> {
        Ok(())
    }

    fn handle(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
    ) -> HandlerFut {
        self.0.handle(method, payload, cancel)
    }
}

/// Legacy allow-all adapter so closures can serve as handlers in tests and
/// embeds. Constructing this adapter explicitly allows every bound principal
/// (including anonymous) to invoke the closure. Behavior is unchanged by
/// the fail-closed `Handler::authorize` default: `FnHandler` overrides
/// `authorize` to allow. For protected methods use a
/// `Handler` implementation with a principal-aware `authorize` policy instead.
pub struct FnHandler<F>(pub F);

impl<F, Fut> Handler for FnHandler<F>
where
    F: Fn(String, Vec<u8>, crate::connection::CancelToken) -> Fut + Send + Sync,
    Fut: std::future::Future<Output = HandlerOutcome> + Send + 'static,
{
    fn authorize(&self, _principal: &Principal, _method: &str) -> Result<(), AuthError> {
        Ok(())
    }

    fn handle(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
    ) -> HandlerFut {
        Box::pin((self.0)(method, payload, cancel))
    }
}

struct InflightEntry {
    cancel: crate::connection::CancelToken,
    task: TaskHandle,
}

/// Transport-independent Syntra host.
pub struct Host {
    conn: Connection,
    auth: Arc<dyn Authenticator>,
    handler: Arc<dyn Handler>,
    sessions: SessionManager,
    host_supported: Vec<u32>,
    inflight: Arc<Mutex<HashMap<u64, InflightEntry>>>,
    /// The `connection_id` bound by this connection's handshake, if any.
    bound_id: Mutex<Option<String>>,
    handshake_task: Mutex<Option<TaskHandle>>,
    /// Signalled when the handshake commits ACTIVE so the detached
    /// handshake timer exits promptly instead of retaining the
    /// `Connection` until the handshake deadline.
    handshake_done: Arc<Notify>,
}

impl Host {
    /// Create a host in `CONNECTED`. Returns the host plus the receiver
    /// the transport pump must drain (one serialized `Frame` per item).
    /// Starts the handshake timer: if ACTIVE is not reached in time the
    /// core is explicitly closed with `DEADLINE_EXCEEDED`.
    pub fn new(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        Self::new_with_versions(config, auth, handler, vec![syntra_core::MAX_VERSION])
    }

    pub fn new_with_versions(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        host_supported: Vec<u32>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (wtx, wrx) = mpsc::channel(config.writer_capacity);
        let (shared, notif_rx) = Shared::new(
            Role::Host,
            wtx,
            config.clone(),
            syntra_core::MIN_VERSION,
            syntra_core::MAX_VERSION,
        );
        let handshake_done = Arc::new(Notify::new());
        let host = Arc::new(Self {
            conn: Connection::wrap(shared, notif_rx),
            auth,
            handler,
            sessions: SessionManager::new(),
            host_supported,
            inflight: Arc::new(Mutex::new(HashMap::new())),
            bound_id: Mutex::new(None),
            handshake_task: Mutex::new(None),
            handshake_done: handshake_done.clone(),
        });
        // Handshake timer (SNTR-HS-002/011): ACTIVE or explicit close.
        // The `handshake_done` signal lets a successful handshake stop the
        // detached timer immediately; otherwise dropping an ACTIVE `Host`
        // would retain the `Connection` until the handshake deadline.
        let timer_conn = host.conn.clone();
        let mut closed = timer_conn.subscribe_close();
        let done = handshake_done.clone();
        let deadline = Instant::now() + config.handshake_timeout;
        let task = spawn_task(async move {
            tokio::select! {
                biased;
                _ = closed.changed() => {},
                _ = done.notified() => {},
                _ = sleep_until(deadline) => timer_conn.expire_handshake().await,
            }
        });
        *host
            .handshake_task
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(task);
        (host, wrx)
    }

    /// Current state (for diagnostics; not a wire value).
    pub async fn state(&self) -> ConnectionState {
        self.conn.state().await
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Subscribe to the close broadcast (transport-pump use).
    pub fn subscribe_close(&self) -> tokio::sync::watch::Receiver<bool> {
        self.conn.subscribe_close()
    }

    pub fn sessions(&self) -> &SessionManager {
        &self.sessions
    }

    /// Number of in-flight (accepted, unterminated) RPCs.
    pub fn inflight_len(&self) -> usize {
        self.inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Ingest one transport unit (exactly one serialized `Frame`).
    pub async fn ingest(&self, bytes: &[u8]) {
        let ctx = self.conn.ctx().await;
        let frame = match decode_frame(bytes, ctx) {
            Ok(f) => f,
            Err(e) => {
                self.on_decode_error(bytes, e).await;
                return;
            }
        };
        self.dispatch(frame).await;
    }

    async fn on_decode_error(&self, raw: &[u8], e: SyntraError) {
        let st = self.conn.state().await;
        if !st.is_active() {
            // Handshake-phase failures are terminal for the connection
            // (handshake.md section 5; carrier B1: code surfaced locally,
            // connection closed, no Frame emitted).
            let (code, message) = match e {
                SyntraError::Protocol { code, message } => (code, message),
                other => (other.code(), other.to_string()),
            };
            self.fail_handshake_and_close(code, message).await;
            return;
        }
        // ACTIVE-phase: a well-formed `request` that failed semantic
        // validation (method shape) still gets its terminal RPC error —
        // the connection stays usable. Classify from the raw bytes
        // (prost decode only; validation already ran).
        if let Ok(frame) = Frame::decode(raw) {
            match &frame.body {
                // hello/ready in ACTIVE: fatal protocol violation + close.
                Some(Body::Hello(_)) | Some(Body::Ready(_)) => {
                    warn!("hello/ready in ACTIVE; closing");
                    let _ = self
                        .conn
                        .transition(StateEvent::ProtocolViolationFatal)
                        .await;
                    self.close().await;
                    return;
                }
                _ => {}
            }
            if frame.version != self.version_or_zero().await {
                warn!("version mismatch in ACTIVE; closing");
                let _ = self
                    .conn
                    .transition(StateEvent::ProtocolViolationFatal)
                    .await;
                self.close().await;
                return;
            }
            if let Some(Body::Request(_)) = &frame.body {
                if frame.request_id != 0 {
                    let code = e.code();
                    if code == ErrorCode::InvalidArgument {
                        // Method-shape failure (or sibling shape error):
                        // terminal INVALID_ARGUMENT, no dispatch, no close.
                        self.send_result(
                            frame.request_id,
                            outcome_error(ErrorCode::InvalidArgument, "invalid request"),
                        )
                        .await;
                        return;
                    }
                    if code == ErrorCode::ResourceExhausted {
                        // Oversize envelope: connection-level exhaustion.
                        warn!("oversize envelope in ACTIVE; closing");
                        self.close().await;
                        return;
                    }
                }
            }
        }
        // Any other ACTIVE-phase decode failure: count misbehavior;
        // close only on exhaustion or repeated abuse.
        if matches!(e.code(), ErrorCode::ResourceExhausted) {
            self.close().await;
            return;
        }
        let n = self
            .conn
            .shared
            .misbehavior
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        debug!(error = ?e, "ACTIVE decode failure");
        if n >= 8 {
            warn!("too many malformed frames; closing");
            self.close().await;
        }
    }

    async fn version_or_zero(&self) -> u32 {
        self.conn.negotiated_version().await.unwrap_or(0)
    }

    async fn dispatch(&self, frame: Frame) {
        let st = self.conn.state().await;
        match frame.body {
            Some(Body::Hello(h)) => {
                if st != ConnectionState::Connected {
                    // Second hello (or hello outside handshake): terminal
                    // handshake failure / ACTIVE violation.
                    self.protocol_violation(ErrorCode::FailedPrecondition, "unexpected hello")
                        .await;
                    return;
                }
                self.on_hello(frame.version, h).await;
            }
            Some(Body::Ready(_)) => {
                // Hosts never receive ready.
                self.protocol_violation(ErrorCode::FailedPrecondition, "unexpected ready")
                    .await;
            }
            Some(Body::Request(req)) => {
                if !st.is_active() {
                    self.protocol_violation(ErrorCode::FailedPrecondition, "request before ACTIVE")
                        .await;
                    return;
                }
                self.on_request(frame.request_id, frame.version, req).await;
            }
            Some(Body::Result(_)) => {
                if !st.is_active() {
                    // Pre-ACTIVE results fail the handshake (SNTR-HS-012;
                    // carrier B1: local code + close, emit nothing).
                    self.protocol_violation(ErrorCode::FailedPrecondition, "result before ACTIVE")
                        .await;
                    return;
                }
                // Hosts send no requests: unknown-id diagnostic, no storm.
                debug!("result for unknown request_id; ignoring");
            }
            Some(Body::Cancel(_)) => {
                if !st.is_active() {
                    self.protocol_violation(ErrorCode::FailedPrecondition, "cancel before ACTIVE")
                        .await;
                    return;
                }
                self.on_cancel(frame.request_id).await;
            }
            Some(Body::Notification(_)) => {
                if !st.is_active() {
                    // Handshake.md section 1B governs (fail/close);
                    // the events-draft ignore default is recorded as
                    // conflict B2 and NOT applied here.
                    self.protocol_violation(
                        ErrorCode::FailedPrecondition,
                        "notification before ACTIVE",
                    )
                    .await;
                    return;
                }
                // Initiator->host notifications have no meaning; ignore
                // with a diagnostic (never complete an RPC).
                debug!("initiator notification ignored");
            }
            None => {}
        }
    }

    /// Pre-ACTIVE: terminal handshake failure + explicit close.
    /// ACTIVE: fatal protocol violation + close.
    async fn protocol_violation(&self, code: ErrorCode, message: &str) {
        if self.conn.state().await.is_active() {
            let _ = self
                .conn
                .transition(StateEvent::ProtocolViolationFatal)
                .await;
            self.close().await;
        } else {
            self.fail_handshake_and_close(code, message.to_string())
                .await;
        }
    }

    async fn fail_handshake_and_close(&self, code: ErrorCode, message: String) {
        self.conn.fail_handshake_and_close(code, message).await;
        self.unbind_session().await;
        self.shutdown_tasks().await;
    }

    async fn on_hello(&self, frame_version: u32, hello: syntra_core::proto::ClientHello) {
        if frame_version != hello.max_version {
            self.fail_handshake_and_close(
                ErrorCode::InvalidArgument,
                "hello frame version must equal proposed maximum".to_string(),
            )
            .await;
            return;
        }
        // Shape BEFORE policy (SNTR-HS-030): range first...
        if let Err(e) = syntra_core::validate_hello_range(hello.min_version, hello.max_version) {
            let (code, message) = err_parts(e);
            self.fail_handshake_and_close(code, message).await;
            return;
        }
        // ...version selection (highest overlap) before any credential
        // semantics (SNTR-HS-003).
        let selected = match syntra_core::negotiate_version(
            hello.min_version,
            hello.max_version,
            &self.host_supported,
        ) {
            Ok(v) => v,
            Err(e) => {
                let (code, message) = err_parts(e);
                self.fail_handshake_and_close(code, message).await;
                return;
            }
        };
        {
            let mut state = self.conn.shared.state.write().await;
            if *state != ConnectionState::Connected || self.conn.is_closed() {
                drop(state);
                self.protocol_violation(ErrorCode::FailedPrecondition, "unexpected hello")
                    .await;
                return;
            }
            let next = state
                .transition(StateEvent::HelloSent)
                .and_then(|s| s.transition(StateEvent::VersionAccepted));
            let Ok(next) = next else {
                return;
            };
            *state = next;
        }
        // A live `connection_id` presented as a credential is rejected
        // outright (SNTR-SESS-002/020): it is a diagnostic, never auth.
        if credential_is_live_session(&self.sessions, &hello.credential) {
            self.fail_handshake_and_close(
                ErrorCode::Unauthenticated,
                "credential not accepted".to_string(),
            )
            .await;
            return;
        }
        // ...then authentication (SNTR-HS-004).
        let principal = match self.auth.authenticate(&hello.credential) {
            Ok(p) => p,
            Err(AuthError { code, message }) => {
                self.fail_handshake_and_close(code, message).await;
                return;
            }
        };
        // Exactly one terminal success outcome: ready + ACTIVE.
        let connection_id = match generate_connection_id() {
            Ok(id) => id,
            Err(e) => {
                self.fail_handshake_and_close(ErrorCode::Internal, e).await;
                return;
            }
        };
        let ready = Frame {
            version: selected,
            request_id: 0,
            body: Some(Body::Ready(syntra_core::proto::ServerReady {
                connection_id: connection_id.clone(),
            })),
        };
        if validate_frame(&ready, self.conn.ctx().await).is_err() {
            self.fail_handshake_and_close(
                ErrorCode::Internal,
                "ready validation failed".to_string(),
            )
            .await;
            return;
        }
        // Reserve capacity without holding lifecycle locks. Authentication
        // and backpressure may suspend while close/timeout wins the race.
        let permit = match self.conn.reserve_writer().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        let mut state = self.conn.shared.state.write().await;
        if *state != ConnectionState::Authenticating || self.conn.is_closed() {
            return;
        }
        let Ok(active) = state.transition(StateEvent::ReadyReceived) else {
            return;
        };
        *self.conn.shared.version.write().await = Some(selected);
        // Bind before exposing ACTIVE or queueing ready. Close uses the
        // same state lock, then unbinds; it can never miss a late binding.
        self.sessions.bind(Session {
            connection_id: connection_id.clone(),
            principal,
            version: selected,
            established_at: Instant::now(),
        });
        *self.bound_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(connection_id.clone());
        *state = active;
        permit.send(ready.encode_to_vec());
        drop(state);
        self.conn
            .complete_handshake(crate::connection::HandshakeDone { connection_id })
            .await;
        // Handshake committed ACTIVE: wake the timer so it exits
        // promptly, then reclaim it. Without this a dropped ACTIVE
        // `Host` leaves the detached timer retaining the `Connection`
        // until the handshake deadline.
        self.handshake_done.notify_one();
        self.stop_handshake_timer().await;
    }

    fn effective_timeout(&self, timeout_ms: u32) -> Duration {
        let budget = if timeout_ms == 0 {
            self.conn.shared.config.default_timeout
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        // Documented policy: clamp to the deployment maximum (never
        // silently unbounded). The alternative (reject) would need an
        // RFC-level error contract; clamping keeps one terminal path.
        budget.min(self.conn.shared.config.max_rpc_timeout)
    }

    async fn on_request(&self, id: u64, version: u32, req: RpcRequest) {
        let deadline = Instant::now() + self.effective_timeout(req.timeout_ms);
        let negotiated = self.version_or_zero().await;
        if version != negotiated {
            warn!("version mismatch in ACTIVE; closing");
            let _ = self
                .conn
                .transition(StateEvent::ProtocolViolationFatal)
                .await;
            self.close().await;
            return;
        }
        // Method shape was validated at decode; re-check cheaply so a
        // direct dispatch path can never skip it (defense in depth).
        if syntra_core::validate_method(&req.method).is_err() {
            self.send_result(
                id,
                outcome_error(ErrorCode::InvalidArgument, "invalid method"),
            )
            .await;
            return;
        }
        let state = self.conn.shared.state.read().await;
        if *state != ConnectionState::Active || self.conn.is_closed() {
            return;
        }
        let session = {
            let bound = self.bound_id.lock().unwrap_or_else(|e| e.into_inner());
            bound.as_deref().and_then(|id| self.sessions.get(id))
        };
        let Some(session) = session else {
            drop(state);
            self.send_result(
                id,
                outcome_error(ErrorCode::Unauthenticated, "credential not accepted"),
            )
            .await;
            return;
        };
        let admitted = self.start_request(id, negotiated, req, session, deadline);
        drop(state);
        if let Err((code, message)) = admitted {
            self.send_result(id, outcome_error(code, message)).await;
        }
    }

    // Synchronous admission makes it impossible to hold the blocking table
    // lock over an await. Caller holds the state read lock through insertion.
    fn start_request(
        &self,
        id: u64,
        negotiated: u32,
        req: RpcRequest,
        session: Session,
        deadline: Instant,
    ) -> Result<(), (ErrorCode, &'static str)> {
        // Concurrency bound: reject excess, keep usable (SNTR-RPC-008).
        let mut inflight_guard = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        let rejection = if inflight_guard.contains_key(&id) {
            Some((ErrorCode::FailedPrecondition, "duplicate request_id"))
        } else if inflight_guard.len() >= self.conn.shared.config.max_outstanding {
            Some((ErrorCode::ResourceExhausted, "too many outstanding RPCs"))
        } else {
            None
        };
        if let Some((code, message)) = rejection {
            return Err((code, message));
        }
        // Responder deadline starts BEFORE queue admission (measured from
        // receipt of the complete validated frame, SNTR-RPC-004/1F).
        let cancel = crate::connection::CancelToken::new();
        // Duplicate outstanding id on the host side (retransmit storm):
        // keep the original, reject the duplicate attempt. Locks are
        // scoped tightly and never held across an await (the guard is
        // !Send; holding it would poison every spawned future).
        let handler = self.handler.clone();
        let method = req.method.clone();
        let payload = req.payload.to_vec();
        let sender = self.conn.clone();
        let inflight = self.inflight.clone();
        let cancel_task = cancel.clone();
        let sessions = self.sessions.clone();
        let task = spawn_task(async move {
            if sender.is_closed() {
                cancel_task.cancel();
                sessions.unbind(&session.connection_id);
                inflight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&id);
                return;
            }
            // Completion wins races (biased, handler branch first);
            // cancel-vs-deadline ties prefer CANCELLED (recorded B10).
            // Single terminal send: this task is the ONLY sender for the
            // id. Cancellation only sets the token (no abort, no second
            // send), so at most one result frame is ever emitted — on
            // every target, including wasm where abort is unavailable.
            let outcome = tokio::select! {
                biased;
                res = async {
                    match handler.authorize(&session.principal, &method) {
                        Ok(()) => handler.handle(method.clone(), payload, cancel_task.clone()).await,
                        Err(e) if e.code == ErrorCode::Unauthenticated => HandlerOutcome::error(ErrorCode::Unauthenticated, "credential not accepted"),
                        Err(_) => HandlerOutcome::error(ErrorCode::PermissionDenied, "access denied"),
                    }
                } => res,
                _ = cancel_task.cancelled() => HandlerOutcome::error(ErrorCode::Cancelled, "cancelled"),
                _ = sleep_until(deadline) => {
                    if cancel_task.is_cancelled() {
                        HandlerOutcome::error(ErrorCode::Cancelled, "cancelled")
                    } else {
                        HandlerOutcome::error(ErrorCode::DeadlineExceeded, "deadline exceeded")
                    }
                }
            };
            cancel_task.cancel();
            let outcome_value = match outcome {
                HandlerOutcome::Payload(b) => outcome_payload(b),
                HandlerOutcome::Error { code, message } => {
                    outcome_error(sanitize_code(code), &message)
                }
            };
            let mut frame = Frame {
                version: negotiated,
                request_id: id,
                body: Some(Body::Result(RpcResult {
                    outcome: Some(outcome_value),
                })),
            };
            let mut bytes = frame.encode_to_vec();
            if bytes.len() > syntra_core::MAX_FRAME_BYTES {
                frame = Frame {
                    version: negotiated,
                    request_id: id,
                    body: Some(Body::Result(RpcResult {
                        outcome: Some(outcome_error(
                            ErrorCode::ResourceExhausted,
                            "result exceeds bound",
                        )),
                    })),
                };
                bytes = frame.encode_to_vec();
            }
            if sender.send_bytes(bytes).await.is_err() {
                sessions.unbind(&session.connection_id);
            }
            // Release the id only after the terminal result is queued:
            // until now, a duplicate id is a duplicate (original wins).
            inflight
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        });
        // Admission, task ownership, and insertion share one short lock.
        // A fast worker cannot remove an entry before it is installed;
        // close cannot drain a placeholder and miss the real worker.
        inflight_guard.insert(id, InflightEntry { cancel, task });
        Ok(())
    }

    async fn on_cancel(&self, id: u64) {
        if id == 0 {
            return;
        }
        // Best-effort: signal the handler. Unknown or already-completed
        // ids are ignored (race tolerance). The request task remains the
        // sole sender of the terminal result, so completion still wins
        // and no second `result` is ever emitted.
        if let Some(entry) = self
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
        {
            entry.cancel.cancel();
        }
    }

    async fn send_result(&self, id: u64, outcome: syntra_core::proto::rpc_result::Outcome) {
        let version = self.version_or_zero().await;
        let frame = Frame {
            version,
            request_id: id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(outcome),
            })),
        };
        let bytes = frame.encode_to_vec();
        if self.conn.send_bytes(bytes).await.is_err() {
            self.on_transport_lost().await;
        }
    }

    /// Emit a host->initiator notification (opaque application bytes).
    /// Only legal in ACTIVE; notifications never complete an RPC
    /// (SNTR-RPC-020, SNTR-EVENT-005). Empty payloads are valid events.
    pub async fn notify(&self, payload: Vec<u8>) -> Result<(), SyntraError> {
        if self.conn.state().await != ConnectionState::Active {
            return Err(SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: "notifications require ACTIVE connection".to_string(),
            });
        }
        let version = self.version_or_zero().await;
        let frame = Frame {
            version,
            request_id: 0,
            body: Some(Body::Notification(syntra_core::proto::Notification {
                payload,
            })),
        };
        validate_frame(&frame, self.conn.ctx().await)?;
        let bytes = frame.encode_to_vec();
        let result = self.conn.send_bytes(bytes).await;
        if result.is_err() {
            self.on_transport_lost().await;
        }
        result
    }

    /// Graceful close: stop new RPCs, drain already-queued results via the
    /// transport pump, then teardown (SNTR-HS-006/013). Already-queued
    /// terminal results are delivered by the pump drain in `loopback_pair`
    /// (real adapters drain the writer before teardown); in-flight handlers
    /// that complete after close observe `is_closed` and their late sends
    /// fail, mapping to UNAVAILABLE/CANCELLED per spec. Bounded by the
    /// shared SHUTDOWN_GRACE in `shutdown_tasks`.
    pub async fn close(&self) {
        // Move ACTIVE->CLOSING first so new RPCs fail fast at admission
        // while already-queued frames still drain (sends succeed until
        // CLOSED). Best-effort: ignore transition errors (already closing).
        let _ = self.conn.transition(StateEvent::GracefulClose).await;
        self.conn.close().await;
        self.unbind_session().await;
        self.shutdown_tasks().await;
    }

    /// Abrupt transport loss: `UNAVAILABLE` (unknown outcome) to all
    /// in-flight RPCs, session discarded (SNTR-SESS-004).
    /// Bounded by one shared `SHUTDOWN_GRACE` (see `close`).
    pub async fn on_transport_lost(&self) {
        self.conn.on_transport_lost().await;
        self.unbind_session().await;
        self.shutdown_tasks().await;
    }

    /// Drain in-flight workers and the handshake timer under one shared
    /// shutdown deadline. Sequential per-task `SHUTDOWN_GRACE` joins would
    /// let `close` exceed 1s on wasm (N workers + timer); sharing the
    /// deadline keeps the total bounded.
    async fn shutdown_tasks(&self) {
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        self.abort_inflight_until(deadline).await;
        self.stop_handshake_timer_until(deadline).await;
    }

    async fn abort_inflight_until(&self, deadline: Instant) {
        let entries: Vec<InflightEntry> = {
            let mut g = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            g.drain().map(|(_, e)| e).collect()
        };
        for e in &entries {
            // Signalling the initiating handler's own token would make
            // its select! drop this shutdown future at the first join.
            // Let it complete cleanup and unwind naturally instead.
            if !e.task.is_current() {
                e.cancel.cancel();
                e.task.abort();
            }
        }
        for e in entries {
            // Bounded wait: native `abort` preempts so the join completes
            // immediately (fast path unchanged); on wasm `abort` is a
            // no-op and a non-cooperative handler would otherwise hang
            // `close` forever. The wait shares the shutdown deadline with
            // the handshake timer (mirroring Go `handlerShutdownGrace`
            // and WS `shutdown_grace`) and detaches best-effort.
            e.task
                .join_bounded(deadline.saturating_duration_since(Instant::now()))
                .await;
        }
    }

    async fn stop_handshake_timer(&self) {
        self.stop_handshake_timer_until(Instant::now() + SHUTDOWN_GRACE)
            .await;
    }

    async fn stop_handshake_timer_until(&self, deadline: Instant) {
        let task = self
            .handshake_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = task {
            task.abort();
            // Shares the shutdown deadline with the in-flight drain: the
            // timer observes close/handshake-done and exits promptly, but
            // a stalled wasm timer must not hang shutdown.
            task.join_bounded(deadline.saturating_duration_since(Instant::now()))
                .await;
        }
    }

    async fn unbind_session(&self) {
        // Hosts own exactly one connection and bind at most one session
        // for it; unbind that id (if any) so CLOSED discards all
        // per-connection state except diagnostics (SNTR-HS-006).
        if let Some(id) = self
            .bound_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            self.sessions.unbind(&id);
        }
    }

    /// Test hook: inject raw bytes as the transport would deliver them.
    #[cfg(test)]
    pub async fn inject(&self, bytes: &[u8]) {
        self.ingest(bytes).await;
    }
}

fn outcome_payload(b: Vec<u8>) -> syntra_core::proto::rpc_result::Outcome {
    syntra_core::proto::rpc_result::Outcome::Payload(b)
}

fn outcome_error(code: ErrorCode, message: &str) -> syntra_core::proto::rpc_result::Outcome {
    syntra_core::proto::rpc_result::Outcome::Error(syntra_core::proto::RpcError {
        code: code.as_i32(),
        message: message.to_string(),
    })
}

/// UNSPECIFIED (0) MUST NOT appear in a failure outcome (SNTR-ERR-001);
/// normalize it to UNKNOWN defensively.
fn sanitize_code(code: ErrorCode) -> ErrorCode {
    match code {
        ErrorCode::Unspecified => ErrorCode::Unknown,
        other => other,
    }
}

fn err_parts(e: SyntraError) -> (ErrorCode, String) {
    match e {
        SyntraError::Protocol { code, message } => (code, message),
        SyntraError::Handshake { code, message } => (code, message),
        other => (other.code(), other.to_string()),
    }
}

/// 128-bit unguessable connection diagnostic (SNTR-HS-004), hex-encoded.
/// Never encodes principal or session information (SNTR-SESS-002).
fn generate_connection_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    let mut s = String::with_capacity(32);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    Ok(s)
}

/// A live `connection_id` presented as a credential is rejected
/// outright (SNTR-SESS-002/020): it is a diagnostic, never auth.
fn credential_is_live_session(sessions: &SessionManager, credential: &[u8]) -> bool {
    if credential.is_empty() || credential.len() > 256 {
        return false;
    }
    if let Ok(s) = std::str::from_utf8(credential) {
        if sessions.get(s).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{AllowAnonymous, RejectAll};
    use syntra_core::proto::ClientHello;
    use syntra_core::ValidationContext;

    fn hello_frame(min: u32, max: u32, cred: Vec<u8>) -> Vec<u8> {
        Frame {
            version: max,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: min,
                max_version: max,
                credential: cred.into(),
            })),
        }
        .encode_to_vec()
    }

    fn echo_handler() -> Arc<dyn Handler> {
        Arc::new(FnHandler(
            |method: String, payload: Vec<u8>, _cancel| async move {
                let _ = method;
                HandlerOutcome::Payload(payload)
            },
        ))
    }

    #[tokio::test]
    async fn hello_frame_version_must_equal_proposed_max_before_auth() {
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        let mut frame = Frame::decode(hello_frame(1, 1, vec![]).as_slice()).unwrap();
        frame.version = 2;
        host.ingest(&frame.encode_to_vec()).await;
        assert!(host.is_closed());
        assert_eq!(host.sessions.count(), 0);
        assert!(writer.try_recv().is_err());
    }

    #[tokio::test]
    async fn close_while_ready_is_backpressured_cannot_bind_session() {
        let (host, mut writer) = Host::new(
            ConnectionConfig {
                writer_capacity: 1,
                ..ConnectionConfig::default()
            },
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.conn.shared.writer.try_send(vec![0]).unwrap();
        let hello = hello_frame(1, 1, vec![]);
        let mut handshake = Box::pin(host.ingest(&hello));
        assert!(futures_util::poll!(&mut handshake).is_pending());
        host.close().await;
        assert_eq!(writer.try_recv().unwrap(), vec![0]);
        handshake.await;
        assert_eq!(host.state().await, ConnectionState::Closed);
        assert_eq!(
            host.sessions.count(),
            0,
            "authentication must not resurrect a binding"
        );
        assert!(host.bound_id.lock().unwrap().is_none());
        assert!(writer.try_recv().is_err(), "no ready after close");
    }

    #[tokio::test]
    async fn handlers_without_authorization_fail_closed() {
        struct NoPolicy;
        impl Handler for NoPolicy {
            fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
                panic!("a handler without an authorization policy must not execute")
            }
        }
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(NoPolicy),
        );
        host.ingest(&hello_frame(1, 1, vec![])).await;
        writer.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![],
                timeout_ms: 500,
            },
        )
        .await;
        let bytes = tokio::time::timeout(Duration::from_secs(1), writer.recv())
            .await
            .unwrap()
            .unwrap();
        let frame = Frame::decode(bytes.as_slice()).unwrap();
        assert!(
            matches!(frame.body, Some(Body::Result(RpcResult { outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(e)) })) if e.code == ErrorCode::PermissionDenied.as_i32())
        );
        assert_eq!(host.state().await, ConnectionState::Active);
        host.close().await;
    }

    #[tokio::test]
    async fn allow_all_wrapper_restores_explicit_permissive_behavior() {
        struct Legacy {
            effects: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Handler for Legacy {
            fn handle(&self, _: String, payload: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
                self.effects
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async move { HandlerOutcome::Payload(payload) })
            }
        }
        let effects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Without the wrapper the fail-closed default denies without effects.
        let (denied, mut denied_rx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(Legacy {
                effects: effects.clone(),
            }),
        );
        denied.ingest(&hello_frame(1, 1, vec![])).await;
        denied_rx.recv().await.unwrap();
        denied
            .on_request(
                1,
                1,
                RpcRequest {
                    method: "/example.Echo/Echo".into(),
                    payload: b"deny-me".to_vec(),
                    timeout_ms: 500,
                },
            )
            .await;
        let bytes = tokio::time::timeout(Duration::from_secs(1), denied_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let frame = Frame::decode(bytes.as_slice()).unwrap();
        assert!(
            matches!(frame.body, Some(Body::Result(RpcResult { outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(e)) })) if e.code == ErrorCode::PermissionDenied.as_i32())
        );
        assert_eq!(
            effects.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "denied call must not execute handler effects"
        );
        denied.close().await;
        // With explicit AllowAll the same handler executes (opt-in legacy).
        let (allowed, mut allowed_rx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(AllowAll(Legacy {
                effects: effects.clone(),
            })),
        );
        allowed.ingest(&hello_frame(1, 1, vec![])).await;
        allowed_rx.recv().await.unwrap();
        allowed
            .on_request(
                2,
                1,
                RpcRequest {
                    method: "/example.Echo/Echo".into(),
                    payload: b"allow-me".to_vec(),
                    timeout_ms: 500,
                },
            )
            .await;
        let bytes = tokio::time::timeout(Duration::from_secs(1), allowed_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let frame = Frame::decode(bytes.as_slice()).unwrap();
        assert!(
            matches!(frame.body, Some(Body::Result(RpcResult { outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(p)) })) if p == b"allow-me".to_vec())
        );
        assert_eq!(
            effects.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "AllowAll must restore handler effects exactly once"
        );
        allowed.close().await;
    }

    #[tokio::test]
    async fn explicit_authorize_allow_permits_handler_effects() {
        struct ExplicitAllow;
        impl Handler for ExplicitAllow {
            fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
                Ok(())
            }
            fn handle(&self, _: String, payload: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
                Box::pin(async move { HandlerOutcome::Payload(payload) })
            }
        }
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(ExplicitAllow),
        );
        host.ingest(&hello_frame(1, 1, vec![])).await;
        writer.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: b"explicit".to_vec(),
                timeout_ms: 500,
            },
        )
        .await;
        let bytes = tokio::time::timeout(Duration::from_secs(1), writer.recv())
            .await
            .unwrap()
            .unwrap();
        let frame = Frame::decode(bytes.as_slice()).unwrap();
        assert!(
            matches!(frame.body, Some(Body::Result(RpcResult { outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(p)) })) if p == b"explicit".to_vec())
        );
        host.close().await;
    }

    #[tokio::test]
    async fn fn_handler_behavior_unchanged_allow_all() {
        // FnHandler remains allow-all for closures; regression guard for
        // the fail-closed default change.
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.ingest(&hello_frame(1, 1, vec![])).await;
        writer.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: b"fn".to_vec(),
                timeout_ms: 500,
            },
        )
        .await;
        let bytes = tokio::time::timeout(Duration::from_secs(1), writer.recv())
            .await
            .unwrap()
            .unwrap();
        let frame = Frame::decode(bytes.as_slice()).unwrap();
        assert!(
            matches!(frame.body, Some(Body::Result(RpcResult { outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(p)) })) if p == b"fn".to_vec())
        );
        host.close().await;
    }

    #[tokio::test]
    async fn authorization_uses_bound_principal_and_method_on_every_call() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Policy {
            calls: AtomicUsize,
            effects: AtomicUsize,
        }
        impl Handler for Policy {
            fn authorize(&self, principal: &Principal, method: &str) -> Result<(), AuthError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if principal.subject == "svc-allowed" && method == "/example.Echo/Echo" {
                    Ok(())
                } else {
                    Err(AuthError {
                        code: ErrorCode::PermissionDenied,
                        message: "private-policy-details".into(),
                    })
                }
            }
            fn handle(&self, _: String, payload: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
                self.effects.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { HandlerOutcome::Payload(payload) })
            }
        }
        let policy = Arc::new(Policy {
            calls: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
        });
        for (auth, credential, allowed) in [
            (
                Arc::new(crate::StaticToken::new(b"token-a".to_vec(), "svc-allowed"))
                    as Arc<dyn Authenticator>,
                b"token-a".to_vec(),
                true,
            ),
            (
                Arc::new(crate::StaticToken::new(b"token-b".to_vec(), "svc-denied")),
                b"token-b".to_vec(),
                false,
            ),
            (Arc::new(AllowAnonymous), vec![], false),
        ] {
            let (client, host) =
                crate::loopback_pair(auth, policy.clone(), ConnectionConfig::default());
            client.handshake(credential).await.unwrap();
            for method in ["/example.Echo/Echo", "/example.KV/Put"] {
                let result = client.call(method, b"opaque".to_vec(), 1000).await;
                if allowed && method == "/example.Echo/Echo" {
                    assert_eq!(result.unwrap(), b"opaque");
                } else {
                    let error = result.unwrap_err();
                    assert_eq!(error.code(), ErrorCode::PermissionDenied);
                    assert!(!error.to_string().contains("private-policy-details"));
                }
                assert_eq!(host.state().await, ConnectionState::Active);
            }
            host.close().await;
        }
        assert_eq!(policy.calls.load(Ordering::SeqCst), 6);
        assert_eq!(policy.effects.load(Ordering::SeqCst), 1);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn close_during_authentication_does_not_wait_for_policy_or_bind_late() {
        struct BlockedAuth {
            started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl Authenticator for BlockedAuth {
            fn authenticate(&self, _: &[u8]) -> Result<Principal, AuthError> {
                self.started
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release.lock().unwrap().recv().unwrap();
                Ok(Principal::new("svc-a"))
            }
        }
        let (started, observed) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(BlockedAuth {
                started: Mutex::new(Some(started)),
                release: Mutex::new(released),
            }),
            echo_handler(),
        );
        let runtime = tokio::runtime::Handle::current();
        let worker_host = host.clone();
        let worker = tokio::task::spawn_blocking(move || {
            runtime.block_on(worker_host.ingest(&hello_frame(1, 1, vec![])))
        });
        observed.await.unwrap();
        // Always release/join the worker even when shutdown fails, so a
        // failing lock-order regression cannot strand spawn_blocking.
        let closed = tokio::time::timeout(Duration::from_secs(1), host.close()).await;
        release.send(()).unwrap();
        worker.await.unwrap();
        closed.expect("shutdown must not hold a lifecycle lock across authentication");
        assert!(host.is_closed());
        assert_eq!(host.sessions.count(), 0);
        assert!(writer.try_recv().is_err());
    }

    #[tokio::test]
    async fn handshake_timer_closes_backpressured_ready_without_binding() {
        let (host, mut writer) = Host::new(
            ConnectionConfig {
                writer_capacity: 1,
                handshake_timeout: Duration::from_millis(10),
                ..ConnectionConfig::default()
            },
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.conn.shared.writer.try_send(vec![0]).unwrap();
        let hello = hello_frame(1, 1, vec![]);
        tokio::time::timeout(Duration::from_secs(1), host.ingest(&hello))
            .await
            .expect("timer must interrupt ready queueing");
        assert!(host.is_closed());
        assert_eq!(host.sessions.count(), 0);
        assert_eq!(writer.try_recv().unwrap(), vec![0]);
        assert!(writer.try_recv().is_err());
        host.close().await;
    }

    #[tokio::test]
    async fn close_cancels_and_joins_owned_workers() {
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (started, mut observed) = mpsc::channel(1);
        let handler = Arc::new(FnHandler({
            let dropped = dropped.clone();
            move |_, _, cancel: crate::CancelToken| {
                let guard = Dropped(dropped.clone());
                let started = started.clone();
                async move {
                    let _guard = guard;
                    started.send(cancel).await.unwrap();
                    std::future::pending::<HandlerOutcome>().await
                }
            }
        }));
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            handler,
        );
        host.ingest(&hello_frame(1, 1, vec![])).await;
        writer.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![],
                timeout_ms: 5000,
            },
        )
        .await;
        let cancel = observed.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), host.close())
            .await
            .unwrap();
        assert!(cancel.is_cancelled());
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "close must join the aborted worker"
        );
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.sessions.count(), 0);
    }

    #[tokio::test]
    async fn close_with_non_cooperative_handler_completes_bounded() {
        // Native simulation of the wasm hang shape: the handler ignores its
        // `CancelToken` entirely (no select on cancel/deadline) and pends
        // forever. `close` must still return promptly: natively via
        // preemptive `abort`, on wasm via the bounded `SHUTDOWN_GRACE`
        // detach. Guards against reintroducing an unbounded join.
        let handler = Arc::new(FnHandler(|_, _, _: crate::CancelToken| async move {
            std::future::pending::<HandlerOutcome>().await
        }));
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            handler,
        );
        host.ingest(&hello_frame(1, 1, vec![])).await;
        writer.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![],
                timeout_ms: 5000,
            },
        )
        .await;
        tokio::time::timeout(Duration::from_secs(1), host.close())
            .await
            .expect("close must not hang on a non-cooperative handler");
        assert!(host.is_closed());
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.sessions.count(), 0);
    }

    #[tokio::test]
    async fn handler_initiated_close_does_not_join_itself() {
        let weak_host = Arc::new(Mutex::new(std::sync::Weak::<Host>::new()));
        let (finished, mut observed) = mpsc::channel(1);
        let handler = Arc::new(FnHandler({
            let weak_host = weak_host.clone();
            move |_, _, _| {
                let host = weak_host.lock().unwrap().upgrade().unwrap();
                let finished = finished.clone();
                async move {
                    host.close().await;
                    finished.send(()).await.unwrap();
                    HandlerOutcome::Payload(vec![])
                }
            }
        }));
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            handler,
        );
        *weak_host.lock().unwrap() = Arc::downgrade(&host);
        host.ingest(&hello_frame(1, 1, vec![])).await;
        writer.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![],
                timeout_ms: 5000,
            },
        )
        .await;
        tokio::time::timeout(Duration::from_secs(1), observed.recv())
            .await
            .expect("handler shutdown must finish without self-join")
            .unwrap();
        assert!(host.is_closed());
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.sessions.count(), 0);
    }

    #[tokio::test]
    async fn accept_anonymous_binds_session() {
        let (host, mut wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.inject(&hello_frame(1, 1, vec![])).await;
        let bytes = wrx.recv().await.expect("ready sent");
        let ctx = ValidationContext::pre_handshake(ConnectionState::Negotiating);
        let ready = decode_frame(&bytes, ctx).expect("valid ready");
        assert_eq!(ready.version, 1);
        assert_eq!(host.state().await, ConnectionState::Active);
        assert_eq!(host.sessions.count(), 1);
        let _ = ready;
    }

    #[tokio::test]
    async fn version_mismatch_rejected() {
        let (host, _wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.inject(&hello_frame(2, 3, vec![])).await;
        assert!(host.conn.is_closed());
    }

    #[tokio::test]
    async fn auth_rejection_closes() {
        let (host, _wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(RejectAll),
            echo_handler(),
        );
        host.inject(&hello_frame(1, 1, vec![])).await;
        assert!(host.conn.is_closed());
        assert_eq!(host.sessions.count(), 0);
    }

    #[tokio::test]
    async fn pre_active_request_fails() {
        let (host, _wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        let req = Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![].into(),
                timeout_ms: 100,
            })),
        }
        .encode_to_vec();
        host.inject(&req).await;
        assert!(host.conn.is_closed());
    }

    #[tokio::test]
    async fn malformed_method_terminal_without_close() {
        let (host, mut wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.inject(&hello_frame(1, 1, vec![])).await;
        let _ready = wrx.recv().await.unwrap();
        // Valid envelope shape, bad method: prost-decodes fine, semantic
        // validation fails -> terminal INVALID_ARGUMENT, usable conn.
        let bad = Frame {
            version: 1,
            request_id: 9,
            body: Some(Body::Request(RpcRequest {
                method: "nope".into(),
                payload: vec![].into(),
                timeout_ms: 100,
            })),
        }
        .encode_to_vec();
        host.inject(&bad).await;
        let out = wrx.recv().await.expect("terminal result");
        let ctx = ValidationContext::active(1);
        let res = decode_frame(&out, ctx).expect("valid result");
        match res.body {
            Some(Body::Result(r)) => match r.outcome {
                Some(syntra_core::proto::rpc_result::Outcome::Error(e)) => {
                    assert_eq!(e.code, ErrorCode::InvalidArgument.as_i32())
                }
                other => panic!("expected error, got {other:?}"),
            },
            other => panic!("expected result, got {other:?}"),
        }
        assert_eq!(host.state().await, ConnectionState::Active);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn immediate_handlers_do_not_resurrect_completed_requests() {
        const REQUESTS: u64 = 4096;
        let config = ConnectionConfig {
            max_outstanding: REQUESTS as usize,
            writer_capacity: REQUESTS as usize,
            ..ConnectionConfig::default()
        };
        let (host, mut wrx) = Host::new(config, Arc::new(AllowAnonymous), echo_handler());
        host.inject(&hello_frame(1, 1, vec![])).await;
        wrx.recv().await.unwrap();
        let dispatcher = host.clone();
        let runtime = tokio::runtime::Handle::current();
        // Dispatch on a separate OS thread while this executor runs the
        // handlers, exercising completion before task-handle attachment.
        let dispatch = tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                for id in 1..=REQUESTS {
                    dispatcher
                        .on_request(
                            id,
                            1,
                            RpcRequest {
                                method: "/example.Echo/Echo".into(),
                                payload: vec![].into(),
                                timeout_ms: 5000,
                            },
                        )
                        .await;
                }
            });
        });
        tokio::time::timeout(Duration::from_secs(10), async {
            for _ in 0..REQUESTS {
                let bytes = wrx.recv().await.expect("terminal result");
                let frame = decode_frame(&bytes, ValidationContext::active(1)).unwrap();
                assert!(matches!(
                    frame.body,
                    Some(Body::Result(RpcResult {
                        outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(_))
                    }))
                ));
            }
            dispatch.await.unwrap();
        })
        .await
        .expect("all immediate handlers should complete");
        assert_eq!(host.inflight_len(), 0, "completed ids must stay removed");
        assert!(wrx.try_recv().is_err(), "no duplicate terminal results");
        host.close().await;
    }

    #[tokio::test]
    async fn attached_task_preserves_request_cancellation_token() {
        let (started, mut started_rx) = mpsc::unbounded_channel();
        let handler = Arc::new(FnHandler(move |_, _, cancel| {
            started.send(cancel).unwrap();
            std::future::pending::<HandlerOutcome>()
        }));
        let (host, mut wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            handler,
        );
        host.inject(&hello_frame(1, 1, vec![])).await;
        wrx.recv().await.unwrap();
        host.on_request(
            1,
            1,
            RpcRequest {
                method: "/example.Test/Wait".into(),
                payload: vec![].into(),
                timeout_ms: 5000,
            },
        )
        .await;
        let token = started_rx.recv().await.unwrap();
        host.on_cancel(1).await;
        assert!(token.is_cancelled());
        let bytes = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
            .await
            .expect("cancel should promptly end the request")
            .unwrap();
        let frame = decode_frame(&bytes, ValidationContext::active(1)).unwrap();
        match frame.body {
            Some(Body::Result(RpcResult {
                outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(e)),
            })) => assert_eq!(e.code, ErrorCode::Cancelled.as_i32()),
            other => panic!("expected CANCELLED result, got {other:?}"),
        }
        assert_eq!(host.inflight_len(), 0);
        assert!(wrx.try_recv().is_err());
        host.close().await;
    }
}
