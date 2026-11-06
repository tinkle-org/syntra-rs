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
//! - per-RPC responder deadlines start at complete bounded-frame receipt,
//!   before validation/admission waiting; the terminal gate checks elapsed
//!   expiry first, including exact ties (RFC 0004 D4 / RFC 0008 D2);
//! - request IDs strictly increase in received order, including rejected calls;
//!   reuse is a local FAILED_PRECONDITION + close, never a same-ID result;
//! - every accepted RPC ends with exactly one terminal `result`
//!   (SNTR-RPC-002/006/030); a second `result` for the same id is never
//!   sent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use web_time::{Duration, Instant};

use futures_util::FutureExt;
use prost::Message;
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, warn};

use syntra_core::{
    decode_frame, proto::frame::Body, validate_frame, ConnectionState, ErrorCode, Frame,
    RpcRequest, RpcResult, StateEvent, SyntraError,
};

use crate::connection::{
    fill_random, spawn_task, Connection, ConnectionConfig, Role, Shared, TaskHandle, SHUTDOWN_GRACE,
};
use crate::emission::{now, sleep_until};
use crate::session::{AuthError, Authenticator, Principal, Session, SessionManager};

#[path = "host_execution.rs"]
mod execution;
pub use execution::{ExecutionBudget, ExecutionLease};

#[path = "host_terminal.rs"]
pub mod terminal;

#[path = "host_recovery.rs"]
mod recovery;

/// Handler outcome for one dispatched RPC.
#[derive(Debug, Clone)]
pub enum HandlerOutcome {
    Payload(Vec<u8>),
    Error { code: ErrorCode, message: String },
}

impl HandlerOutcome {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code: sanitize_code(code),
            message: syntra_core::bounded_diagnostic(message),
        }
    }
}

/// Application handler: owns method semantics. Payloads are opaque bytes;
/// the core never validates them. Handlers SHOULD honor `cancel` promptly
/// but local reporting and actual execution lifetime are independent.
///
/// Authorization is fail-closed by default: the provided `authorize`
/// default denies every RPC with `PERMISSION_DENIED` (generic message, no
/// oracle). Protected methods require a principal-aware per-method policy;
/// it must be nonblocking and may re-check expiry/revocation. [`AllowAll`]
/// and [`FnHandler`] explicitly allow every bound principal to invoke every
/// method and are intended for tests or trusted embeds where that policy
/// is intentional.
///
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

    /// Execution-lifetime hook. Override this when work can outlive
    /// the returned future (spawned tasks, blocking jobs, external operations),
    /// transferring a lease copy into that work until it actually stops.
    /// The default treats dropping the returned future as cooperative stop.
    /// Both handler hooks must return promptly; deliberately spawned blocking
    /// or external work must retain a lease for its entire actual lifetime.
    fn handle_with_execution(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        let work = self.handle(method, payload, cancel);
        Box::pin(async move {
            let _lease = lease;
            work.await
        })
    }

    /// Request-scoped hook for optional terminal retirement. The private context
    /// cannot be constructed from a wire request ID. Existing handlers keep their
    /// execution hook and lease behavior through this default delegation.
    fn handle_with_context(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
        lease: ExecutionLease,
        _context: terminal::RequestContext,
    ) -> HandlerFut {
        self.handle_with_execution(method, payload, cancel, lease)
    }
}

pub type HandlerFut = std::pin::Pin<Box<dyn std::future::Future<Output = HandlerOutcome> + Send>>;

/// Explicit opt-in allow-all wrapper: every bound principal may invoke every
/// method without changing the inner handler's method semantics or execution
/// lease handling. Prefer a principal-aware `authorize` implementation for
/// protected methods; use this wrapper only for trusted tests/embeds where the
/// allow-all posture is intentional and documented at the construction site.
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

    fn handle_with_execution(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        self.0.handle_with_execution(method, payload, cancel, lease)
    }

    fn handle_with_context(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: crate::connection::CancelToken,
        lease: ExecutionLease,
        context: terminal::RequestContext,
    ) -> HandlerFut {
        self.0
            .handle_with_context(method, payload, cancel, lease, context)
    }
}

/// Explicit allow-all adapter so closures can serve as handlers in tests and
/// embeds. Constructing this adapter explicitly allows every bound principal
/// (including anonymous) to invoke the closure. `FnHandler` overrides
/// the fail-closed `Handler::authorize` default to allow. For protected methods
/// use a `Handler` implementation with a principal-aware `authorize` policy instead.
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

struct PendingCall {
    deadline: Instant,
    cancel: crate::connection::CancelToken,
    selected: oneshot::Sender<HandlerOutcome>,
}

struct WithdrawalOwner {
    // One retained continuation per connection, never aborted by cancellation
    // of the initiating handler/caller. Completion below is bounded protocol
    // cleanup, not a claim that external execution stopped or this task joined.
    _task: TaskHandle,
    done: tokio::sync::watch::Receiver<bool>,
}

/// Deterministic test-only preemption after the worker's last dispatch check.
#[cfg(all(test, not(target_arch = "wasm32")))]
struct DispatchPause {
    id: u64,
    checked: Notify,
    release: Notify,
}

#[derive(Default)]
struct Calls {
    terminal: Option<Arc<terminal::Coordinator>>,
    clock: crate::elapsed::ElapsedClock,
    pending: HashMap<u64, PendingCall>,
    delivery_stopped: bool,
    // Owned until BOTH execution (including transferred leases) and output
    // finish. Never drained just because correlation has become terminal.
    workers: HashMap<u64, TaskHandle>,
}

impl Calls {
    fn select(&mut self, id: u64, candidate: HandlerOutcome) {
        if let Some(call) = self.pending.remove(&id) {
            let outcome = if self.clock.now() >= call.deadline {
                HandlerOutcome::error(ErrorCode::DeadlineExceeded, "deadline exceeded")
            } else if !self.clock.is_continuous() {
                HandlerOutcome::error(ErrorCode::Unavailable, "elapsed continuity lost")
            } else {
                candidate
            };
            if let Some(terminal) = &self.terminal {
                terminal.select(id, &outcome);
            }
            call.cancel.cancel();
            // Receiver ownership is the worker's; a panic is still surfaced by
            // the task runtime, not converted to a fabricated success/result.
            let _ = call.selected.send(outcome);
        }
    }

    fn select_all(&mut self, code: ErrorCode, message: &str) {
        let ids: Vec<_> = self.pending.keys().copied().collect();
        for id in ids {
            self.select(id, HandlerOutcome::error(code, message));
        }
    }

    fn stop_delivery(&mut self, message: &str) {
        // Loss settles reporting, not another wire result. In particular an ID
        // violation must not cause a new UNAVAILABLE result under that same ID.
        self.delivery_stopped = true;
        if let Some(terminal) = &self.terminal {
            terminal.abort();
        }
        self.select_all(ErrorCode::Unavailable, message);
    }
}

/// Transport-independent Syntra host.
pub struct Host {
    conn: Connection,
    auth: Arc<dyn Authenticator>,
    handler: Arc<dyn Handler>,
    sessions: SessionManager,
    host_supported: Vec<u32>,
    calls: Arc<Mutex<Calls>>,
    progress: Arc<Notify>,
    /// FIFO gate: acquired at the first ingest await, never held for result I/O.
    admission: tokio::sync::Mutex<()>,
    highwater: Mutex<u64>,
    execution: ExecutionBudget,
    shared_execution: Option<ExecutionBudget>,
    /// Bound pending/selected responses independently of live executions. Limit:
    /// max_outstanding + writer_capacity, each at most MAX_FRAME_BYTES. The
    /// extra writer_capacity allows overload rejections while executions are
    /// full. The writer channel has its own writer_capacity frame ceiling.
    /// Exhaustion closes rather than growing detached sends.
    output: ExecutionBudget,
    /// The `connection_id` bound by this connection's handshake, if any.
    bound_id: Mutex<Option<String>>,
    handshake_task: Arc<Mutex<Option<TaskHandle>>>,
    /// Signalled when the handshake commits ACTIVE so the detached
    /// handshake timer exits promptly instead of retaining the
    /// `Connection` until the handshake deadline.
    handshake_done: Arc<Notify>,
    withdrawal: Mutex<Option<WithdrawalOwner>>,
    recovery: Mutex<Option<recovery::Attachment>>,
    weak_self: Weak<Host>,
    terminal: Mutex<Option<Arc<terminal::Coordinator>>>,
    terminal_commands: Mutex<Option<mpsc::Receiver<terminal::DriverCommand>>>,
    #[cfg(all(test, not(target_arch = "wasm32")))]
    dispatch_pause: Mutex<Option<Arc<DispatchPause>>>,
}

impl Host {
    /// Create a host in `CONNECTED`. Returns the host plus the receiver
    /// the transport pump must drain (one serialized `Frame` per item).
    /// Starts the handshake timer: if ACTIVE is not reached in time the
    /// core is explicitly closed with `DEADLINE_EXCEEDED`.
    ///
    /// # Panics
    /// Panics on invalid configuration. Use [`Host::try_new`] for fallible
    /// construction. Valid construction requires a running executor.
    pub fn new(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        Self::try_new(config, auth, handler)
            .expect("invalid Syntra configuration; use Host::try_new for fallible construction")
    }

    /// Create a host with an explicit supported-version set.
    ///
    /// # Panics
    /// Panics on invalid configuration. Use [`Host::try_new_with_versions`]
    /// for fallible construction. Valid construction requires a running executor.
    pub fn new_with_versions(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        host_supported: Vec<u32>,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        Self::try_new_with_versions(config, auth, handler, host_supported).expect(
            "invalid Syntra configuration; use Host::try_new_with_versions for fallible construction",
        )
    }

    /// Share this budget across every connection/replacement belonging to the
    /// host or principal being limited. `max_outstanding` remains the per-host
    /// execution ceiling (default 32) until a separate execution config lands.
    ///
    /// # Panics
    /// Panics on invalid configuration. Use
    /// [`Host::try_new_with_execution_budget`] for fallible construction.
    /// Valid construction requires a running executor.
    pub fn new_with_execution_budget(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        budget: ExecutionBudget,
    ) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        Self::try_new_with_execution_budget(config, auth, handler, budget).expect(
            "invalid Syntra configuration; use Host::try_new_with_execution_budget for fallible construction",
        )
    }

    /// Validate limits before creating channels or spawning the handshake timer.
    pub fn try_new(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Vec<u8>>), SyntraError> {
        Self::try_new_with_versions(config, auth, handler, vec![syntra_core::MAX_VERSION])
    }

    /// Fallible counterpart of [`Host::new_with_versions`].
    pub fn try_new_with_versions(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        host_supported: Vec<u32>,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Vec<u8>>), SyntraError> {
        Self::try_build(
            config,
            auth,
            handler,
            host_supported,
            None,
            crate::elapsed::ElapsedClock::new(),
        )
    }

    pub fn try_new_with_clock(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        clock: crate::elapsed::ElapsedClock,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Vec<u8>>), SyntraError> {
        Self::try_build(
            config,
            auth,
            handler,
            vec![syntra_core::MAX_VERSION],
            None,
            clock,
        )
    }

    pub fn elapsed_clock(&self) -> crate::elapsed::ElapsedClock {
        self.conn.shared.clock.clone()
    }

    pub fn carrier_io_allowed(&self) -> bool {
        self.conn.carrier_io_allowed()
    }
    pub fn with_carrier_io<R>(&self, poll: impl FnOnce() -> R) -> Option<R> {
        self.conn.with_carrier_io(poll)
    }
    pub(crate) fn retain_runtime_task(&self, task: TaskHandle) {
        self.conn.shared.tasks.register(task);
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub fn own_native_task(
        &self,
        handle: tokio::task::JoinHandle<()>,
    ) -> crate::shutdown::OwnedTask {
        self.conn.own_native_task(handle)
    }
    pub fn register_transport_tasks(&self, count: usize) -> Result<(), SyntraError> {
        self.conn.register_transport_tasks(count)
    }
    pub fn acknowledge_transport_task_joined(&self) -> Result<(), SyntraError> {
        self.conn.acknowledge_transport_task_joined()
    }
    pub fn acknowledge_transport_closed(&self) {
        self.conn.acknowledge_transport_closed();
    }

    /// Stop admission synchronously and retain one drain/close/join continuation.
    /// Requires a running/entered executor on native. Cancelling a waiter neither
    /// cancels this owner nor releases external execution leases.
    pub fn begin_shutdown(&self, total: Duration) -> Result<crate::ShutdownReport, SyntraError> {
        let host = self.weak_self.upgrade().expect("live Host owner");
        self.conn.start_shutdown(total, move |budget| {
            spawn_task(async move {
                host.conn.begin_closing().await;
                host.close_recovery();
                host.conn
                    .drain_until(budget.drain_cutoff, || {
                        host.inflight_len() == 0 && host.output.in_use() == 0
                    })
                    .await;
                host.stop_delivery("connection shutdown");
                host.conn.close().await;
                host.unbind_session().await;
                host.conn
                    .shared
                    .tasks
                    .join_until(&budget.clock, budget.deadline)
                    .await;
            })
        })?;
        Ok(self.shutdown_report())
    }

    pub async fn shutdown(&self, total: Duration) -> Result<crate::ShutdownReport, SyntraError> {
        self.begin_shutdown(total)?;
        self.conn.await_shutdown_owner().await;
        Ok(self.shutdown_report())
    }

    pub fn shutdown_report(&self) -> crate::ShutdownReport {
        self.conn
            .shutdown_report_for(self.inflight_len(), self.execution_len())
    }
    pub fn shutdown_budget(&self) -> Option<crate::ShutdownBudget> {
        self.conn.shutdown_budget()
    }

    pub fn suspend(&self) {
        self.conn.suspend();
    }

    pub async fn platform_wake(&self) {
        self.suspend();
        self.conn.shared.clock.wake();
        self.on_transport_lost().await;
    }

    /// Fallible counterpart of [`Host::new_with_execution_budget`]. The shared
    /// budget may impose a stricter execution quota without lowering the core
    /// protocol's configured pending-RPC capacity below 16.
    pub fn try_new_with_execution_budget(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        budget: ExecutionBudget,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Vec<u8>>), SyntraError> {
        Self::try_build(
            config,
            auth,
            handler,
            vec![syntra_core::MAX_VERSION],
            Some(budget),
            crate::elapsed::ElapsedClock::new(),
        )
    }

    /// Preserve a host/principal aggregate execution budget while sharing one
    /// elapsed domain with the carrier, channel lifetime and authority checks.
    pub fn try_new_with_execution_budget_and_clock(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        budget: ExecutionBudget,
        clock: crate::elapsed::ElapsedClock,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Vec<u8>>), SyntraError> {
        Self::try_build(
            config,
            auth,
            handler,
            vec![syntra_core::MAX_VERSION],
            Some(budget),
            clock,
        )
    }

    fn try_build(
        config: ConnectionConfig,
        auth: Arc<dyn Authenticator>,
        handler: Arc<dyn Handler>,
        host_supported: Vec<u32>,
        shared_execution: Option<ExecutionBudget>,
        clock: crate::elapsed::ElapsedClock,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Vec<u8>>), SyntraError> {
        config.validate()?;
        let (wtx, wrx) = mpsc::channel(config.writer_capacity);
        let (shared, notif_rx) = Shared::new_with_clock(
            Role::Host,
            wtx,
            config.clone(),
            syntra_core::MIN_VERSION,
            syntra_core::MAX_VERSION,
            clock.clone(),
        );
        let handshake_done = Arc::new(Notify::new());
        let host = Arc::new_cyclic(|weak_self| Self {
            conn: Connection::wrap(shared, notif_rx),
            auth,
            handler,
            sessions: SessionManager::new(),
            host_supported,
            calls: Arc::new(Mutex::new(Calls {
                clock: clock.clone(),
                ..Calls::default()
            })),
            progress: Arc::new(Notify::new()),
            admission: tokio::sync::Mutex::new(()),
            highwater: Mutex::new(0),
            execution: ExecutionBudget::new(config.max_outstanding),
            shared_execution,
            output: ExecutionBudget::new(
                config
                    .max_outstanding
                    .saturating_add(config.writer_capacity),
            ),
            bound_id: Mutex::new(None),
            handshake_task: Arc::new(Mutex::new(None)),
            handshake_done: handshake_done.clone(),
            withdrawal: Mutex::new(None),
            recovery: Mutex::new(None),
            weak_self: weak_self.clone(),
            terminal: Mutex::new(None),
            terminal_commands: Mutex::new(None),
            #[cfg(all(test, not(target_arch = "wasm32")))]
            dispatch_pause: Mutex::new(None),
        });
        // Handshake timer (SNTR-HS-002/011): ACTIVE or explicit close.
        // The `handshake_done` signal lets a successful handshake stop the
        // detached timer immediately; otherwise dropping an ACTIVE `Host`
        // would retain the `Connection` until the handshake deadline.
        let timer_conn = host.conn.clone();
        let mut closed = timer_conn.subscribe_close();
        let done = handshake_done.clone();
        let deadline = clock.now() + config.handshake_timeout;
        *host.conn.shared.handshake_deadline.lock().unwrap() = Some(deadline);
        let task = spawn_task(async move {
            tokio::select! {
                biased;
                _ = closed.changed() => {},
                _ = done.notified() => {},
                _ = clock.sleep_until(deadline) => timer_conn.expire_handshake().await,
            }
        });
        *host
            .handshake_task
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(task.clone());
        host.conn.shared.tasks.register(task);
        Ok((host, wrx))
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
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pending
            .len()
    }

    /// Actual live execution charge, including work surviving timeout/close.
    pub fn execution_len(&self) -> usize {
        self.execution.in_use()
    }

    /// Retained worker owners, including external-execution completion waiters.
    /// Shutdown cannot complete while retained workers remain unjoined;
    /// `close()` is not a claim that external application work has stopped.
    pub fn worker_len(&self) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .workers
            .len()
    }

    /// Ingest one transport unit (exactly one serialized `Frame`).
    /// One ordered receiver must call/poll ingest in reconstructed-frame order;
    /// spawning unordered ingest tasks cannot preserve transport receive order.
    pub async fn ingest(&self, bytes: &[u8]) {
        self.ingest_received_at(bytes, self.conn.shared.clock.now())
            .await;
    }

    /// Adapter hook: timestamp immediately on reconstructing a complete bounded
    /// frame, BEFORE queueing/validation, using the same elapsed clock as timers.
    /// Timestamp with `host.elapsed_clock().now()` on complete-frame receipt.
    /// An adapter using another clock domain is only partially integrated for
    /// suspension and must retire its connection on wake before buffered input.
    /// Like `ingest`, this must be first-polled by one ordered receiver. Dropping
    /// an ingest before admission discards that unit; adapters must then close.
    /// A future timestamp is invalid local adapter input and closes with local
    /// `INVALID_ARGUMENT`, rather than extending the effective RPC budget.
    pub async fn ingest_received_at(&self, bytes: &[u8], received_at: Instant) {
        // Preserve first-poll FIFO admission: no lifecycle/state await
        // may move in front of this ordered receive gate.
        let _ordered = self.admission.lock().await;
        if !self.conn.accept_inbound().await {
            if self.conn.is_closed() {
                self.on_transport_lost().await;
            }
            return;
        }
        if received_at > self.conn.shared.clock.now() {
            self.fail_protocol_and_close(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "receipt timestamp must not be in the future".into(),
            })
            .await;
            return;
        }
        let ctx = self.conn.ctx().await;
        let frame = match decode_frame(bytes, ctx) {
            Ok(f) => f,
            Err(e) => {
                self.on_decode_error(bytes, e, received_at).await;
                return;
            }
        };
        self.dispatch(frame, received_at).await;
    }

    async fn on_decode_error(&self, raw: &[u8], e: SyntraError, received_at: Instant) {
        let st = self.conn.state().await;
        if st == ConnectionState::Closed {
            return;
        }
        if !matches!(st, ConnectionState::Active | ConnectionState::Closing) {
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
        // Structural violations cannot supply a trusted correlation id.
        if syntra_core::validate_wire_structure(raw).is_err() {
            self.record_decode_failure(e).await;
            return;
        }
        // Only a structurally valid request can receive a semantic RPC error.
        if let Ok(frame) = Frame::decode(raw) {
            match &frame.body {
                // hello/ready in ACTIVE: fatal protocol violation + close.
                Some(Body::Hello(_)) | Some(Body::Ready(_)) => {
                    warn!("hello/ready in ACTIVE; closing");
                    self.fail_protocol_and_close(e).await;
                    return;
                }
                _ => {}
            }
            if frame.version != self.version_or_zero().await {
                warn!("version mismatch in ACTIVE; closing");
                self.fail_protocol_and_close(e).await;
                return;
            }
            if st == ConnectionState::Closing {
                return;
            }
            if let Some(Body::Request(req)) = &frame.body {
                if frame.request_id != 0 {
                    let code = e.code();
                    if code == ErrorCode::InvalidArgument
                        && st == ConnectionState::Active
                        && syntra_core::validate_method(&req.method).is_err()
                    {
                        // Prove that ONLY method semantics failed, preserving
                        // every bounded structural/version/id/state precedence.
                        let mut probe = frame.clone();
                        if let Some(Body::Request(req)) = &mut probe.body {
                            req.method = "/example.Echo/Echo".into();
                        }
                        if validate_frame(&probe, self.conn.ctx().await).is_err() {
                            self.record_decode_failure(e).await;
                            return;
                        }
                        if self.consume_request_id(frame.request_id).await {
                            self.reject_request(
                                frame.request_id,
                                frame.version,
                                received_at + self.request_timeout(req),
                                HandlerOutcome::error(
                                    ErrorCode::InvalidArgument,
                                    "invalid request",
                                ),
                            )
                            .await;
                        }
                        return;
                    }
                    if code == ErrorCode::ResourceExhausted {
                        // Oversize envelope: connection-level exhaustion.
                        warn!("oversize envelope in ACTIVE; closing");
                        self.fail_protocol_and_close(e).await;
                        return;
                    }
                }
            }
        }
        self.record_decode_failure(e).await;
    }

    async fn record_decode_failure(&self, e: SyntraError) {
        // Any other ACTIVE-phase decode failure: count misbehavior;
        // close only on exhaustion or repeated abuse.
        if matches!(e.code(), ErrorCode::ResourceExhausted) {
            self.fail_protocol_and_close(e).await;
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
            self.fail_protocol_and_close(e).await;
        }
    }

    async fn version_or_zero(&self) -> u32 {
        self.conn.negotiated_version().await.unwrap_or(0)
    }

    async fn dispatch(&self, frame: Frame, received_at: Instant) {
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
                if self.consume_request_id(frame.request_id).await {
                    self.on_request_received_at(frame.request_id, frame.version, req, received_at)
                        .await;
                }
            }
            Some(Body::Result(_)) => {
                if !matches!(st, ConnectionState::Active | ConnectionState::Closing) {
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
                if !matches!(st, ConnectionState::Active | ConnectionState::Closing) {
                    self.protocol_violation(ErrorCode::FailedPrecondition, "cancel before ACTIVE")
                        .await;
                    return;
                }
                self.on_cancel(frame.request_id).await;
            }
            Some(Body::Notification(_)) => {
                if !matches!(st, ConnectionState::Active | ConnectionState::Closing) {
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
                // with a diagnostic (never complete an RPC). In CLOSING
                // they are tolerated for drain rather than treated as a
                // violation.
                debug!("initiator notification ignored");
            }
            None => {}
        }
    }

    /// Pre-ACTIVE: terminal handshake failure + explicit close.
    /// ACTIVE: fatal protocol violation + close.
    async fn protocol_violation(&self, code: ErrorCode, message: &str) {
        if self.conn.state().await.is_active() {
            self.fail_protocol_and_close(SyntraError::Protocol {
                code,
                message: message.to_string(),
            })
            .await;
        } else {
            self.fail_handshake_and_close(code, message.to_string())
                .await;
        }
    }

    async fn fail_protocol_and_close(&self, failure: SyntraError) {
        self.stop_delivery("connection closed");
        self.conn.fail_protocol_and_close(failure).await;
        self.unbind_session().await;
        self.shutdown_tasks().await;
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
        if *state != ConnectionState::Authenticating
            || self.conn.is_closed()
            || self.conn.lifecycle_blocked()
        {
            return;
        }
        let expired = self
            .conn
            .shared
            .handshake_deadline
            .lock()
            .unwrap()
            .is_some_and(|deadline| self.conn.shared.clock.now() >= deadline);
        if expired {
            drop(state);
            self.conn.expire_handshake().await;
            return;
        }
        let Ok(active) = state.transition(StateEvent::ReadyReceived) else {
            return;
        };
        let mut version = self.conn.shared.version.write().await;
        let committed = {
            let _handoff = self.conn.shared.emissions.lock().unwrap();
            if !self.conn.carrier_io_allowed() {
                return;
            }
            if self.conn.handshake_expired() {
                false
            } else {
                *version = Some(selected);
                // Bind before exposing ACTIVE or queueing ready. Close uses the
                // same state lock, then unbinds; it can never miss a late binding.
                self.sessions.bind(Session {
                    connection_id: connection_id.clone(),
                    principal,
                    version: selected,
                    established_at: Instant::now(),
                });
                *self.bound_id.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(connection_id.clone());
                *state = active;
                permit.send(ready.encode_to_vec());
                true
            }
        };
        drop(version);
        if !committed {
            drop(state);
            self.conn.expire_handshake().await;
            return;
        }
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

    async fn consume_request_id(&self, id: u64) -> bool {
        let increasing = {
            let mut highwater = self.highwater.lock().unwrap_or_else(|e| e.into_inner());
            if id <= *highwater {
                false
            } else {
                *highwater = id;
                true
            }
        };
        if !increasing {
            self.fail_protocol_and_close(SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: "non-increasing request_id".into(),
            })
            .await;
        }
        increasing
    }

    // Compatibility for the existing colocated tests; real input always goes
    // through the ordered, bounded decode path above.
    #[cfg(test)]
    async fn on_request(&self, id: u64, version: u32, req: RpcRequest) {
        let received_at = now();
        let _ordered = self.admission.lock().await;
        if self.consume_request_id(id).await {
            self.on_request_received_at(id, version, req, received_at)
                .await;
        }
    }

    async fn on_request_received_at(
        &self,
        id: u64,
        version: u32,
        req: RpcRequest,
        received_at: Instant,
    ) {
        let deadline = received_at + self.request_timeout(&req);
        let state = self.conn.shared.state.read().await;
        if *state != ConnectionState::Active
            || self.conn.terminal_fenced()
            || self.conn.is_closed()
            || self.conn.lifecycle_blocked()
            || self
                .conn
                .shared
                .shutdown_requested
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        let session = {
            let bound = self.bound_id.lock().unwrap_or_else(|e| e.into_inner());
            bound.as_deref().and_then(|id| self.sessions.get(id))
        };
        // Check before policy AND after synchronous policy; even a policy that
        // exceeds its nonblocking contract cannot cause expired handler effects.
        let mut rejection = if self.conn.shared.clock.now() >= deadline {
            Some(HandlerOutcome::error(
                ErrorCode::DeadlineExceeded,
                "deadline exceeded",
            ))
        } else if syntra_core::validate_method(&req.method).is_err() {
            Some(HandlerOutcome::error(
                ErrorCode::InvalidArgument,
                "invalid method",
            ))
        } else if recovery::is_profile(&req.method) {
            // Built-in profile policy belongs to RecoverySource, not to the
            // unrelated application's fail-closed Handler policy.
            if !self.recovery_configured() || !recovery::known_method(&req.method) {
                Some(recovery::outcome(recovery::ProviderError::Unimplemented))
            } else if session.is_none() {
                Some(recovery::outcome(recovery::ProviderError::Unauthenticated))
            } else {
                None
            }
        } else {
            match session
                .as_ref()
                .map(|s| self.handler.authorize(&s.principal, &req.method))
            {
                Some(Ok(())) => None,
                Some(Err(e)) if e.code == ErrorCode::FailedPrecondition => {
                    Some(HandlerOutcome::error(
                        ErrorCode::FailedPrecondition,
                        "principal change not permitted",
                    ))
                }
                Some(Err(e)) if e.code != ErrorCode::Unauthenticated => Some(
                    HandlerOutcome::error(ErrorCode::PermissionDenied, "access denied"),
                ),
                _ => Some(HandlerOutcome::error(
                    ErrorCode::Unauthenticated,
                    "credential not accepted",
                )),
            }
        };
        let profile = if rejection.is_none()
            && self.conn.shared.clock.now() < deadline
            && recovery::is_profile(&req.method)
        {
            match self.prepare_recovery(&session.as_ref().expect("checked binding").principal) {
                Ok(call) => Some(call),
                Err(error) => {
                    rejection = Some(recovery::outcome(error));
                    None
                }
            }
        } else {
            None
        };
        let withdraw = matches!(
            &rejection,
            Some(HandlerOutcome::Error {
                code: ErrorCode::Unauthenticated,
                ..
            })
        );
        // Withdrawal is a connection policy action even if the elapsed RPC
        // deadline wins its terminal result. Never turn revocation back into a
        // valid binding merely because synchronous policy returned late.
        let rejection = if self.conn.shared.clock.now() >= deadline {
            Some(HandlerOutcome::error(
                ErrorCode::DeadlineExceeded,
                "deadline exceeded",
            ))
        } else {
            rejection
        };
        let admitted = self.start_request(id, version, req, deadline, rejection, profile);
        drop(state);
        if !admitted {
            self.output_exhausted().await;
        } else if withdraw {
            self.withdraw_principal().await;
        }
    }

    async fn reject_request(
        &self,
        id: u64,
        version: u32,
        deadline: Instant,
        outcome: HandlerOutcome,
    ) {
        let state = self.conn.shared.state.read().await;
        if *state != ConnectionState::Active || self.conn.is_closed() {
            return;
        }
        let admitted = self.start_request(
            id,
            version,
            RpcRequest::default(),
            deadline,
            Some(outcome),
            None,
        );
        drop(state);
        if !admitted {
            self.output_exhausted().await;
        }
    }

    async fn output_exhausted(&self) {
        self.fail_protocol_and_close(SyntraError::ResourceExhausted(
            "terminal output capacity exhausted".into(),
        ))
        .await;
    }

    // Admission never waits for a writer. Both accepted work and ordinary
    // rejections own bounded output slots, distinct from execution permits.
    // Caller holds lifecycle read + ordered admission; the std mutex below is
    // only a short terminal/registry gate, never held over an await/user code.
    fn start_request(
        &self,
        id: u64,
        version: u32,
        req: RpcRequest,
        deadline: Instant,
        mut rejection: Option<HandlerOutcome>,
        profile: Option<recovery::Call>,
    ) -> bool {
        if self
            .conn
            .shared
            .shutdown_requested
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return true;
        }
        if self.conn.terminal_fenced() {
            return true;
        }
        let Some(output) = self.output.try_acquire() else {
            return false;
        };
        let mut calls = self.calls.lock().unwrap_or_else(|e| e.into_inner());
        if calls.delivery_stopped {
            return true;
        }
        // Correlation has its own explicit ceiling, independent of execution
        // and output. Rejections below select terminal under this same gate
        // before becoming visible to another registry reader.
        if rejection.is_none() && calls.pending.len() >= self.conn.shared.config.max_outstanding {
            rejection = Some(HandlerOutcome::error(
                ErrorCode::ResourceExhausted,
                "too many outstanding RPCs",
            ));
        }
        let execution = if rejection.is_none() {
            match ExecutionLease::acquire(&self.execution, self.shared_execution.as_ref()) {
                Some(execution) => Some(execution),
                None => {
                    rejection = Some(HandlerOutcome::error(
                        ErrorCode::ResourceExhausted,
                        "too many live executions",
                    ));
                    None
                }
            }
        } else {
            None
        };
        let cancel = crate::connection::CancelToken::new();
        let (selected, mut result) = oneshot::channel();
        calls.pending.insert(
            id,
            PendingCall {
                deadline,
                cancel: cancel.clone(),
                selected,
            },
        );
        if let Some(outcome) = rejection {
            calls.select(id, outcome);
        }
        let registry = self.calls.clone();
        let handler = self.handler.clone();
        let sender = self.conn.clone();
        let (lease, observer) = match execution {
            Some((lease, observer)) => (Some(lease), Some(observer)),
            None => (None, None),
        };
        let owner_registry = registry.clone();
        let owner_sender = sender.clone();
        let progress = self.progress.clone();
        let output_progress = progress.clone();
        let sessions = self.sessions.clone();
        let bound_id = self
            .bound_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let request_context = terminal::RequestContext::new(
            self.weak_self.clone(),
            id,
            version,
            req.method.clone(),
            deadline,
        );
        #[cfg(all(test, not(target_arch = "wasm32")))]
        let dispatch_pause = self.dispatch_pause.lock().unwrap().clone();
        let body = async move {
            // Keep the independent profile charge through output, not just the
            // synchronous callback. Backpressure cannot grow replacement work.
            let selected_outcome = if let Some(lease) = lease {
                let mut closed = sender.subscribe_close();
                let cancelled = cancel.clone();
                let work = async {
                    // Keep the lifecycle read guard through synchronous hook
                    // construction / prepared recovery dispatch. Reservation
                    // takes the exclusive side, so its fence cannot cross this
                    // final check/callback gap. No raw-I/O gate spans callbacks.
                    let state = sender.shared.state.read().await;
                    {
                        let mut calls = registry.lock().unwrap_or_else(|e| e.into_inner());
                        if sender.is_closed()
                            || sender.lifecycle_blocked()
                            || sender.terminal_fenced()
                            || sender
                                .shared
                                .principal_withdrawn
                                .load(std::sync::atomic::Ordering::Acquire)
                        {
                            calls.select(
                                id,
                                HandlerOutcome::error(ErrorCode::Unavailable, "connection closed"),
                            );
                        } else if sender.shared.clock.now() >= deadline {
                            calls.select(
                                id,
                                HandlerOutcome::error(
                                    ErrorCode::DeadlineExceeded,
                                    "deadline exceeded",
                                ),
                            );
                        }
                        if !calls.pending.contains_key(&id) {
                            return;
                        }
                    }
                    #[cfg(all(test, not(target_arch = "wasm32")))]
                    if let Some(pause) = dispatch_pause.as_ref().filter(|pause| pause.id == id) {
                        pause.checked.notify_one();
                        pause.release.notified().await;
                    }
                    let work: HandlerFut = if let Some(profile) = &profile {
                        Box::pin(std::future::ready(profile.handle(
                            &req.method,
                            &req.payload,
                            deadline.saturating_duration_since(sender.shared.clock.now()),
                            &sender,
                        )))
                    } else {
                        handler.handle_with_context(
                            req.method,
                            req.payload,
                            cancel,
                            lease.clone(),
                            request_context.with_lease(lease.clone()),
                        )
                    };
                    drop(state);
                    let outcome = bounded_outcome(id, version, work.await);
                    registry
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .select(id, outcome);
                };
                // Timer polling priority is not sufficient: every select above
                // also checks now under the synchronous terminal gate.
                let selected_outcome = tokio::select! {
                    biased;
                    _ = sender.shared.clock.sleep_until(deadline) => {
                        registry.lock().unwrap_or_else(|e| e.into_inner()).select(id,
                            HandlerOutcome::error(ErrorCode::DeadlineExceeded, "deadline exceeded"));
                        None
                    }
                    outcome = &mut result => {
                        Some(outcome.expect("host terminal sender lost"))
                    }
                    _ = cancelled.cancelled() => {
                        registry.lock().unwrap_or_else(|e| e.into_inner()).select(id,
                            HandlerOutcome::error(ErrorCode::Cancelled, "cancelled"));
                        None
                    }
                    _ = closed.changed() => {
                        registry.lock().unwrap_or_else(|e| e.into_inner()).stop_delivery("transport lost");
                        None
                    }
                    _ = work => None,
                };
                // The losing cooperative future has now been dropped. External
                // copies retain their execution charge regardless of reporting.
                drop(lease);
                selected_outcome
            } else {
                None
            };
            let outcome = match selected_outcome {
                Some(outcome) => outcome,
                None => result.await.expect("host terminal sender lost"),
            };
            Self::emit_selected(&sender, &registry, id, version, outcome, output).await;
            drop(profile);
            output_progress.notify_waiters();
        };
        let task = spawn_task(async move {
            // A panicking hook/future must not leave an immortal pending entry
            // and allow unbounded replacement workers. Close, retain external
            // execution ownership, then resume the panic (never a silent drop).
            let completed = std::panic::AssertUnwindSafe(body).catch_unwind().await;
            progress.notify_waiters(); // includes output released while unwinding
            if completed.is_err() {
                owner_registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .stop_delivery("host worker panicked");
                owner_sender
                    .fail_protocol_and_close(SyntraError::Protocol {
                        code: ErrorCode::Internal,
                        message: "host worker panicked".into(),
                    })
                    .await;
            }
            if owner_sender.is_closed() {
                if let Some(id) = bound_id {
                    sessions.unbind(&id);
                }
            }
            if let Some(mut observer) = observer {
                let _ = observer.changed().await;
            }
            owner_registry
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .workers
                .remove(&id);
            progress.notify_waiters();
            if let Err(panic) = completed {
                std::panic::resume_unwind(panic);
            }
        });
        self.conn.shared.tasks.register(task.clone());
        calls.workers.insert(id, task);
        true
    }

    async fn emit_selected(
        sender: &Connection,
        registry: &Mutex<Calls>,
        id: u64,
        version: u32,
        outcome: HandlerOutcome,
        _output: execution::BudgetPermit,
    ) {
        let outcome = match outcome {
            HandlerOutcome::Payload(payload) => outcome_payload(payload),
            HandlerOutcome::Error { code, message } => outcome_error(code, &message),
        };
        let frame = Frame {
            version,
            request_id: id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(outcome),
            })),
        };
        // Selection is immutable BEFORE this wait. Withdrawal may close delivery
        // but cannot fence away/replace an earlier selected success with an error.
        let bytes = frame.encode_to_vec();
        let terminal = registry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .terminal
            .clone();
        if let Some(terminal) = terminal {
            if terminal.fenced() {
                terminal.emit(id, bytes, _output);
                return;
            }
        }
        let permit = match sender.reserve_writer().await {
            Ok(permit) => permit,
            Err(_) => {
                registry
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .stop_delivery("transport lost");
                if !sender.shared.clock.is_continuous() {
                    sender.on_transport_lost().await;
                }
                return;
            }
        };
        let _state = sender.shared.state.read().await;
        let calls = registry.lock().unwrap_or_else(|e| e.into_inner());
        if !calls.delivery_stopped
            && !sender.is_closed()
            && !sender.writer_is_fenced()
            && !sender.terminal_fenced()
            && !sender.lifecycle_blocked()
        {
            permit.send(bytes);
        }
    }

    async fn on_cancel(&self, id: u64) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .select(id, HandlerOutcome::error(ErrorCode::Cancelled, "cancelled"));
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
        let permit = match self.conn.reserve_writer().await {
            Ok(permit) => permit,
            Err(error) => {
                self.on_transport_lost().await;
                return Err(error);
            }
        };
        let state = self.conn.shared.state.read().await;
        if *state != ConnectionState::Active
            || self.conn.is_closed()
            || self.conn.writer_is_fenced()
            || self.conn.terminal_fenced()
            || self.conn.lifecycle_blocked()
            || self
                .conn
                .shared
                .shutdown_requested
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(SyntraError::Closed("connection closing".to_string()));
        }
        permit.send(bytes);
        Ok(())
    }

    /// Abortive close: stop admission and drop cooperative handler futures.
    /// Transferred external execution leases/owners remain live until actual
    /// completion; inspect `execution_len`/`worker_len` for incomplete shutdown.
    pub async fn close(&self) {
        self.stop_delivery("connection closed");
        // Move ACTIVE->CLOSING first so new RPCs fail fast at admission
        // while already-queued frames still drain (sends succeed until
        // CLOSED). Best-effort: ignore transition errors (already closing).
        let _ = self.conn.transition(StateEvent::GracefulClose).await;
        self.conn.close().await;
        self.unbind_session().await;
        self.shutdown_tasks().await;
    }

    /// Stop admission, continue processing cancellation and queueing terminal
    /// results in CLOSING, then close after workers and the writer drain or
    /// `grace` expires. The pump must keep running and flush dequeued bytes
    /// before releasing the carrier. The entire drain and task cleanup share
    /// one deadline; unfinished handlers are cancelled at expiry.
    /// Zero skips drain. Invalid grace records `INVALID_ARGUMENT` and closes
    /// immediately; use [`Host::try_close_gracefully`] to handle it explicitly.
    pub async fn close_gracefully(&self, grace: Duration) {
        if let Err(error) = self.try_close_gracefully(grace).await {
            self.conn.record_terminal_reason(error);
            self.close().await;
        }
    }

    /// Validate the 0..=30s drain grace before lifecycle changes or deadline
    /// arithmetic. Invalid grace leaves the connection unchanged. Zero performs
    /// abortive close; retained external execution still follows `close`'s contract.
    pub async fn try_close_gracefully(&self, grace: Duration) -> Result<(), SyntraError> {
        crate::connection::validate_close_grace(grace)?;
        if grace.is_zero() {
            self.close().await;
            return Ok(());
        }
        let deadline = self.conn.shared.clock.now() + grace;
        let reserve = (grace / 4)
            .max(Duration::from_nanos(1))
            .min(Duration::from_secs(1));
        let drain_cutoff = deadline - reserve;
        self.conn.begin_closing().await;
        self.close_recovery();
        self.conn
            .drain_until(drain_cutoff, || {
                self.inflight_len() == 0 && self.output.in_use() == 0
            })
            .await;
        self.stop_delivery("connection closed");
        self.conn.close().await;
        self.unbind_session().await;
        self.abort_inflight_until(deadline).await;
        self.stop_handshake_timer_until(deadline).await;
        self.stop_recovery_until(deadline).await;
        Ok(())
    }

    /// First terminal local reason, retained for transport-adapter diagnostics.
    pub fn terminal_reason(&self) -> Option<SyntraError> {
        self.conn.terminal_reason()
    }

    /// Withdraw the bound principal, stop admission, and settle unfinished
    /// RPCs with generic UNAUTHENTICATED results before closing. Queueing and
    /// cleanup share a one-second shutdown budget; an unavailable writer can
    /// prevent delivery. Already-queued terminal results remain authoritative.
    /// Once committed, withdrawal has one retained owner and continues even if
    /// this future is dropped; subsequent callers share its original deadline.
    /// An initiating handler returns after transferring ownership, rather than
    /// waiting for its own result slot to drain. Other callers await the bounded
    /// continuation, not termination/join of retained external execution.
    pub async fn withdraw_principal(&self) {
        use std::sync::atomic::Ordering;
        if let Some(terminal) = self.terminal.lock().unwrap().as_ref() {
            terminal.abort();
        }
        let deadline = self.conn.shared.clock.now() + SHUTDOWN_GRACE;
        let (mut done, from_handler) = {
            let mut state = self.conn.shared.state.write().await;
            let from_handler = self
                .calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .workers
                .values()
                .any(TaskHandle::is_current);
            // The lifecycle lock serializes initialization with admission and
            // close. The std mutex only protects the single owner registration;
            // no await or application callback occurs while holding it.
            let mut owner = self.withdrawal.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(owner) = owner.as_ref() {
                (owner.done.clone(), from_handler)
            } else {
                if self.conn.is_closed() {
                    return;
                }
                self.conn
                    .shared
                    .principal_withdrawn
                    .store(true, Ordering::Release);
                *state = ConnectionState::Closing;
                self.conn.record_terminal_reason(SyntraError::Protocol {
                    code: ErrorCode::Unauthenticated,
                    message: "credential not accepted".into(),
                });
                if let Some(id) = self
                    .bound_id
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    self.sessions.unbind(&id);
                }
                self.settle_pending(ErrorCode::Unauthenticated, "credential not accepted");
                self.close_recovery();

                let conn = self.conn.clone();
                let calls = self.calls.clone();
                let output = self.output.clone();
                let progress = self.progress.clone();
                let handshake_task = self.handshake_task.clone();
                let (complete, done) = tokio::sync::watch::channel(false);
                // No &Host / Arc<Host> capture: dropping the handler must neither
                // drop this continuation nor leave a Host/task ownership cycle.
                let task = spawn_task(async move {
                    let mut closed = conn.subscribe_close();
                    loop {
                        let changed = progress.notified();
                        tokio::pin!(changed);
                        changed.as_mut().enable();
                        if output.in_use() == 0 || conn.is_closed() {
                            break;
                        }
                        tokio::select! {
                            biased;
                            _ = conn.shared.clock.sleep_until(deadline) => break,
                            _ = closed.changed() => break,
                            _ = changed => {},
                        }
                    }
                    calls
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .stop_delivery("connection closed");
                    conn.close().await;
                    Self::wait_workers_until(&calls, &progress, deadline).await;
                    Self::stop_owned_handshake_timer_until(
                        &handshake_task,
                        deadline,
                        &conn.shared.clock,
                    )
                    .await;
                    complete.send_replace(true);
                });
                self.conn.shared.tasks.register(task.clone());
                let observer = done.clone();
                *owner = Some(WithdrawalOwner { _task: task, done });
                (observer, from_handler)
            }
        };
        // No await between selecting this worker's terminal outcome and
        // returning to its handler. Awaiting done here would depend on this
        // very future being dropped before its output can be emitted.
        if from_handler {
            return;
        }
        while !*done.borrow_and_update() {
            done.changed()
                .await
                .expect("host withdrawal owner stopped before completing");
        }
    }

    /// Abrupt transport loss: `UNAVAILABLE` (unknown outcome) to all
    /// in-flight RPCs, session discarded (SNTR-SESS-004).
    /// Bounded by one shared `SHUTDOWN_GRACE` (see `close`).
    pub async fn on_transport_lost(&self) {
        self.stop_delivery("transport lost");
        self.conn.on_transport_lost().await;
        self.unbind_session().await;
        self.shutdown_tasks().await;
    }

    /// Drain in-flight workers and the handshake timer under one shared
    /// shutdown deadline. Sequential per-task `SHUTDOWN_GRACE` joins would
    /// let `close` exceed 1s on wasm (N workers + timer); sharing the
    /// deadline keeps the total bounded.
    async fn shutdown_tasks(&self) {
        let deadline = self.conn.shared.clock.now() + SHUTDOWN_GRACE;
        self.abort_inflight_until(deadline).await;
        self.stop_handshake_timer_until(deadline).await;
        self.stop_recovery_until(deadline).await;
    }

    async fn abort_inflight_until(&self, deadline: Instant) {
        self.settle_pending(ErrorCode::Unavailable, "connection closed");
        Self::wait_workers_until(&self.calls, &self.progress, deadline).await;
    }

    async fn wait_workers_until(calls: &Mutex<Calls>, progress: &Notify, deadline: Instant) {
        let clock = calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clock
            .clone();
        // Do NOT abort/drain owners of transferred execution. They retain their
        // handles and accounting through actual completion, even after close.
        // Self-initiated shutdown cannot wait for its own handler to return.
        // Shutdown retains join ownership and reports incomplete if work remains
        // at the deadline or elapsed-clock continuity is lost.
        loop {
            let changed = progress.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let waiting = calls
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .workers
                .values()
                .any(|task| !task.is_current());
            if !waiting || clock.now() >= deadline || !clock.is_continuous() {
                break;
            }
            tokio::select! {
                biased;
                _ = clock.sleep_until(deadline) => break,
                _ = changed => {},
            }
        }
    }

    fn settle_pending(&self, code: ErrorCode, message: &str) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .select_all(code, message);
    }

    fn stop_delivery(&self, message: &str) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop_delivery(message);
    }

    async fn stop_handshake_timer(&self) {
        self.stop_handshake_timer_until(self.conn.shared.clock.now() + SHUTDOWN_GRACE)
            .await;
    }

    async fn stop_handshake_timer_until(&self, deadline: Instant) {
        Self::stop_owned_handshake_timer_until(
            &self.handshake_task,
            deadline,
            &self.conn.shared.clock,
        )
        .await;
    }

    async fn stop_owned_handshake_timer_until(
        handshake_task: &Mutex<Option<TaskHandle>>,
        deadline: Instant,
        clock: &crate::elapsed::ElapsedClock,
    ) {
        let task = handshake_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(task) = task {
            task.abort();
            // Shares the shutdown deadline with the in-flight drain: the
            // timer observes close/handshake-done and exits promptly, but
            // a stalled wasm timer must not hang shutdown.
            let _ = clock.timeout_until(deadline, task.join()).await;
        }
    }

    async fn unbind_session(&self) {
        self.close_recovery();
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

impl Drop for Host {
    fn drop(&mut self) {
        self.close_recovery();
    }
}

fn outcome_payload(b: Vec<u8>) -> syntra_core::proto::rpc_result::Outcome {
    syntra_core::proto::rpc_result::Outcome::Payload(b)
}

fn bounded_outcome(id: u64, version: u32, outcome: HandlerOutcome) -> HandlerOutcome {
    match outcome {
        HandlerOutcome::Error { code, message } => HandlerOutcome::error(code, message),
        HandlerOutcome::Payload(payload) => {
            let frame = Frame {
                version,
                request_id: id,
                body: Some(Body::Result(RpcResult {
                    outcome: Some(outcome_payload(payload)),
                })),
            };
            if frame.encoded_len() > syntra_core::MAX_FRAME_BYTES {
                HandlerOutcome::error(ErrorCode::ResourceExhausted, "result exceeds bound")
            } else {
                let Some(Body::Result(RpcResult {
                    outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(payload)),
                })) = frame.body
                else {
                    unreachable!("constructed payload result")
                };
                HandlerOutcome::Payload(payload)
            }
        }
    }
}

fn outcome_error(code: ErrorCode, message: &str) -> syntra_core::proto::rpc_result::Outcome {
    syntra_core::proto::rpc_result::Outcome::Error(syntra_core::proto::RpcError {
        code: sanitize_code(code).as_i32(),
        message: syntra_core::bounded_diagnostic(message),
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

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "host_phase2_tests.rs"]
mod phase2_tests;

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
                credential: cred,
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
                payload: vec![],
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
                payload: vec![],
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
        const WINDOW: usize = 1024;
        let config = ConnectionConfig {
            max_outstanding: WINDOW,
            writer_capacity: WINDOW,
            ..ConnectionConfig::default()
        };
        let (host, mut wrx) = Host::new(config, Arc::new(AllowAnonymous), echo_handler());
        host.inject(&hello_frame(1, 1, vec![])).await;
        wrx.recv().await.unwrap();
        let dispatcher = host.clone();
        let runtime = tokio::runtime::Handle::current();
        // Keep the long stress run within validated production capacities.
        // A consumed result opens one more dispatch slot, without serializing
        // worker completion/task attachment across the two executor threads.
        let window = Arc::new(tokio::sync::Semaphore::new(WINDOW));
        let dispatch_window = window.clone();
        // Dispatch on a separate OS thread while this executor runs the
        // handlers, exercising completion before task-handle attachment.
        let dispatch = tokio::task::spawn_blocking(move || {
            runtime.block_on(async {
                for id in 1..=REQUESTS {
                    dispatch_window.acquire().await.unwrap().forget();
                    dispatcher
                        .on_request(
                            id,
                            1,
                            RpcRequest {
                                method: "/example.Echo/Echo".into(),
                                payload: vec![],
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
                window.add_permits(1);
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
                payload: vec![],
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
