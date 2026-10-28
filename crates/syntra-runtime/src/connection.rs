//! Shared transport-agnostic connection engine.
//!
//! A `Connection` owns one half of a Syntra conversation: the six-state
//! machine, the negotiated version, the bounded pending-RPC table, the
//! notification queue, and the outbound byte channel. `Initiator` and
//! `Host` wrap it with role-specific handshake/RPC behavior.
//!
//! Timing rules enforced here (SNTR-RPC-004, SNTR-HS-011):
//! - every effective deadline is computed as an absolute `Instant`
//!   BEFORE queue admission, so queueing can never silently consume the
//!   caller's budget;
//! - completion wins races: all `select!` sites are `biased` with the
//!   completion branch first (cancel-vs-deadline ties prefer `CANCELLED`;
//!   open tie-break B10 is recorded, not invented);
//! - handshake timeout explicitly closes the core
//!   (`fail_handshake_and_close`);
//! - pending entries are removed on validation failure, send failure,
//!   timeout, cancellation, transport loss, and dropped futures
//!   (`PendingGuard`).

use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, RwLock};
use tracing::debug;

use syntra_core::{ConnectionState, PendingTable, RequestIdAllocator, StateEvent, SyntraError};

/// Tunables. All bounds are documented per deployment (SNTR-REL-031).
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Max concurrent RPCs. Peers MUST support >=16 (SNTR-RPC-008).
    pub max_outstanding: usize,
    /// Default call budget when `timeout_ms == 0` (bounded, documented).
    pub default_timeout: Duration,
    /// Absolute clamp for any single RPC budget (documented policy:
    /// larger requested budgets are clamped, never silently unbounded).
    pub max_rpc_timeout: Duration,
    /// Handshake deadline (SNTR-HS-002/011).
    pub handshake_timeout: Duration,
    /// Outgoing notification channel capacity.
    pub notification_capacity: usize,
    /// Outgoing writer channel capacity (backpressure bound).
    pub writer_capacity: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_outstanding: 64,
            default_timeout: Duration::from_secs(30),
            max_rpc_timeout: Duration::from_secs(120),
            handshake_timeout: syntra_core::HANDSHAKE_TIMEOUT_DEFAULT,
            notification_capacity: 256,
            writer_capacity: 256,
        }
    }
}

/// Which half of the conversation this engine plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Initiator,
    Host,
}

/// Cooperative cancellation token (no executor dependency).
#[derive(Debug, Clone)]
pub struct CancelToken {
    inner: Arc<CancelInner>,
}

#[derive(Debug)]
struct CancelInner {
    notify: Notify,
    flag: AtomicBool,
}

impl CancelToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CancelInner {
                notify: Notify::new(),
                flag: AtomicBool::new(false),
            }),
        }
    }

    pub fn cancel(&self) {
        self.inner.flag.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.flag.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        // notify_waiters remembers every Notified created before it, even
        // before polling. Register before checking the flag so a cancel
        // between that check and the await cannot lose its notification.
        let notified = self.inner.notify.notified();
        if self.is_cancelled() {
            return;
        }
        notified.await;
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod cancel_tests {
    use super::*;

    fn connection() -> Connection {
        let (writer, _rx) = mpsc::channel(1);
        let (shared, notifications) =
            Shared::new(Role::Initiator, writer, ConnectionConfig::default(), 1, 1);
        Connection::wrap(shared, notifications)
    }

    #[tokio::test]
    async fn notification_waiters_wake_on_close_and_late_subscribers_see_close() {
        let conn = connection();
        let mut first = Box::pin(conn.next_notification());
        let mut second = Box::pin(conn.next_notification());
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());
        conn.close().await;
        assert!(*conn.subscribe_close().borrow());
        tokio::time::timeout(Duration::from_secs(1), async {
            assert_eq!(first.await, None);
            assert_eq!(second.await, None);
            assert_eq!(conn.next_notification().await, None);
        })
        .await
        .expect("close must wake all notification consumers");
    }

    #[tokio::test]
    async fn notifications_drain_in_order_after_transport_loss() {
        let conn = connection();
        conn.shared
            .notif_tx
            .try_send(Bytes::from_static(b"one"))
            .unwrap();
        conn.shared.notif_tx.try_send(Bytes::new()).unwrap();
        conn.on_transport_lost().await;
        tokio::time::timeout(Duration::from_secs(1), async {
            assert_eq!(conn.next_notification().await, Some(b"one".to_vec()));
            assert_eq!(conn.next_notification().await, Some(vec![]));
            assert_eq!(conn.next_notification().await, None);
        })
        .await
        .expect("closed notification queue must terminate after draining");
    }

    #[tokio::test]
    async fn transitions_never_reopen_a_closed_connection() {
        for _ in 0..256 {
            let conn = connection();
            let (result, ()) = tokio::join!(conn.transition(StateEvent::HelloSent), conn.close());
            let _ = result;
            assert_eq!(conn.state().await, ConnectionState::Closed);
            assert!(conn.transition(StateEvent::VersionAccepted).await.is_err());
        }
    }

    #[tokio::test]
    async fn ready_transition_races_close_on_another_thread() {
        const ROUNDS: usize = 4096;
        let connections: Arc<Vec<_>> = Arc::new((0..ROUNDS).map(|_| connection()).collect());
        for conn in connections.iter() {
            *conn.shared.state.write().await = ConnectionState::Authenticating;
        }
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let runtime = tokio::runtime::Handle::current();
        let other = connections.clone();
        let other_barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            for conn in other.iter() {
                other_barrier.wait();
                let _ = runtime.block_on(conn.transition(StateEvent::ReadyReceived));
                other_barrier.wait();
            }
        });
        let mut reopened = Vec::new();
        for (round, conn) in connections.iter().enumerate() {
            barrier.wait();
            conn.close().await;
            barrier.wait();
            if conn.state().await != ConnectionState::Closed {
                reopened.push(round);
            }
        }
        worker.join().unwrap();
        assert!(
            reopened.is_empty(),
            "terminal state overwritten in rounds {reopened:?}"
        );
    }

    #[tokio::test]
    async fn cancellation_wakes_all_waiters_and_future_waiters() {
        let token = CancelToken::new();
        let mut waiters: Vec<_> = (0..16).map(|_| Box::pin(token.cancelled())).collect();
        for waiter in &mut waiters {
            assert!(futures_util::poll!(waiter.as_mut()).is_pending());
        }
        token.cancel();
        tokio::time::timeout(
            Duration::from_secs(2),
            futures_util::future::join_all(waiters),
        )
        .await
        .expect("all registered waiters should wake");
        // Cancellation is sticky and idempotent, including on clones.
        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), token.clone().cancelled())
            .await
            .expect("a waiter created after cancellation should complete");
    }

    #[tokio::test]
    async fn cancellation_racing_waiter_registration_never_loses_wakeup() {
        const ROUNDS: usize = 4096;
        let tokens: Arc<Vec<_>> = Arc::new((0..ROUNDS).map(|_| CancelToken::new()).collect());
        let start = Arc::new(std::sync::Barrier::new(2));
        let cancel_tokens = tokens.clone();
        let cancel_start = start.clone();
        let canceller = std::thread::spawn(move || {
            for token in cancel_tokens.iter() {
                cancel_start.wait();
                token.cancel();
            }
        });
        let mut missed = None;
        for (round, token) in tokens.iter().enumerate() {
            start.wait();
            if tokio::time::timeout(Duration::from_secs(2), token.cancelled())
                .await
                .is_err()
            {
                // Complete the barriers even on failure so the worker exits.
                missed.get_or_insert(round);
            }
        }
        canceller.join().unwrap();
        assert_eq!(missed, None, "cancellation notification was lost");
    }

    /// Regression for the wasm `Host::close` hang: `TaskHandle::abort` is a
    /// no-op on wasm, so a handler that ignores its `CancelToken` would hang
    /// `abort_inflight`/`stop_handshake_timer` forever without a bound. This
    /// natively simulates that non-cooperative case by intentionally *not*
    /// aborting a pending task and asserting `join_bounded` still returns
    /// within the grace (best-effort detach, mirroring the 1s Go
    /// `handlerShutdownGrace` and WS `shutdown_grace`).
    #[tokio::test]
    async fn join_bounded_detaches_non_cooperative_task_within_grace() {
        // Pending forever, never observes cancellation: the wasm hang shape.
        let task = spawn_task(async {
            std::future::pending::<()>().await;
        });
        // Deliberately do not call `abort` (wasm no-op simulation).
        tokio::time::timeout(
            Duration::from_secs(1),
            task.join_bounded(Duration::from_millis(50)),
        )
        .await
        .expect("bounded join must not hang on a non-cooperative task");
    }

    /// Cooperative tasks still join promptly through the bounded path (no
    /// added delay on the native fast path).
    #[tokio::test]
    async fn join_bounded_joins_completed_task_immediately() {
        let task = spawn_task(async {});
        tokio::time::timeout(Duration::from_secs(1), task.join_bounded(SHUTDOWN_GRACE))
            .await
            .expect("completed task must join without waiting for the grace");
    }
}

/// Sleep without depending on a timer driver (works on native and wasm).
pub(crate) async fn sleep(d: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::sleep(d).await;
    }
    #[cfg(target_arch = "wasm32")]
    {
        wasm_sleep(d).await;
    }
}

#[cfg(target_arch = "wasm32")]
async fn wasm_sleep(d: Duration) {
    use wasm_bindgen::prelude::*;
    if d.is_zero() {
        return;
    }
    let ms = d.as_millis().min(u32::MAX as u128) as u32;
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        let set_timeout =
            js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout")).expect("setTimeout");
        let func: &js_sys::Function = set_timeout.unchecked_ref();
        let cb = Closure::once(move |_: JsValue| {
            let _ = resolve.call0(&JsValue::NULL);
        });
        let _ = func.call2(&global, cb.as_ref().unchecked_ref(), &JsValue::from(ms));
        // The closure must outlive the timer; the timer holds the only
        // other reference once scheduled.
        cb.forget();
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// Sleep until an absolute deadline (no-op when already past).
pub(crate) async fn sleep_until(deadline: std::time::Instant) {
    let now = std::time::Instant::now();
    if deadline > now {
        sleep(deadline - now).await;
    }
}

/// Bounded shutdown grace for targets where `TaskHandle::abort` is
/// cooperative-only (wasm32 `spawn_local` has no preemptive cancel).
/// Mirrors the Go binding's `handlerShutdownGrace` (1s) and the WS
/// `close_grace`/`shutdown_grace` budgets: shutdown signals cancellation,
/// then waits at most this long before detaching. Native `abort` still
/// preempts immediately, so the fast path is unchanged; the bound only
/// decides how long a non-cooperative wasm task can delay `close`.
pub(crate) const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Spawn a background task. Native uses the tokio runtime; wasm uses the
/// browser microtask queue (`spawn_local`). The returned handle aborts
/// the task on native; on wasm cancellation is cooperative only
/// (documented: browser handlers MUST honor `CancelToken`).
pub(crate) struct TaskHandle {
    scope: Arc<()>,
    #[cfg(not(target_arch = "wasm32"))]
    inner: Option<tokio::task::JoinHandle<()>>,
    #[cfg(target_arch = "wasm32")]
    done: oneshot::Receiver<()>,
}

tokio::task_local! {
    // Works with both native tasks and browser spawn_local futures; never
    // expose this runtime ownership marker as a protocol/session identity.
    static TASK_SCOPE: Arc<()>;
}

impl TaskHandle {
    pub(crate) fn is_current(&self) -> bool {
        TASK_SCOPE
            .try_with(|scope| Arc::ptr_eq(scope, &self.scope))
            .unwrap_or(false)
    }

    pub(crate) fn abort(&self) {
        // A handler can initiate shutdown. Let that task finish its
        // cleanup instead of cancelling itself at the next join await.
        if self.is_current() {
            return;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(h) = &self.inner {
            h.abort();
        }
    }

    pub(crate) async fn join(self) {
        // Awaiting our own JoinHandle would deadlock forever. It will
        // unwind naturally once the initiating handler returns.
        if self.is_current() {
            return;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(h) = self.inner {
            let _ = h.await;
        }
        #[cfg(target_arch = "wasm32")]
        let _ = self.done.await;
    }

    /// Join with a bounded wait. Native callers still `abort` first, so the
    /// join completes immediately and the grace never fires (fast path
    /// unchanged). On wasm `abort` is a no-op: a handler that ignores its
    /// `CancelToken` would otherwise hang `close` forever, so the grace
    /// bounds the wait and detaches best-effort (the `spawn_local` future
    /// keeps running; its completion send is ignored). Dropping the losing
    /// branch is the detach: no owned task is left joined.
    pub(crate) async fn join_bounded(self, grace: Duration) {
        tokio::select! {
            biased;
            _ = self.join() => {},
            _ = sleep(grace) => {},
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn spawn_task<F>(fut: F) -> TaskHandle
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let scope = Arc::new(());
    TaskHandle {
        inner: Some(tokio::spawn(TASK_SCOPE.scope(scope.clone(), fut))),
        scope,
    }
}

/// Browser tasks run on the microtask queue (`spawn_local`), which does
/// not require `Send` (single-threaded). Cancellation there is
/// cooperative only — see `TaskHandle::abort`.
#[cfg(target_arch = "wasm32")]
pub(crate) fn spawn_task<F>(fut: F) -> TaskHandle
where
    F: std::future::Future<Output = ()> + 'static,
{
    let scope = Arc::new(());
    let (done_tx, done) = oneshot::channel();
    wasm_bindgen_futures::spawn_local(TASK_SCOPE.scope(scope.clone(), async move {
        fut.await;
        let _ = done_tx.send(());
    }));
    TaskHandle { scope, done }
}

/// Fill `buf` with cryptographic randomness (OS-backed on every target).
pub(crate) fn fill_random(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::fill(buf).map_err(|e| e.to_string())
    }
    #[cfg(target_arch = "wasm32")]
    {
        getrandom::getrandom(buf).map_err(|e| e.to_string())
    }
}

/// Remove a pending entry unless the RPC already completed. Guards every
/// path after queue admission: validation failure, send failure,
/// timeout, cancellation, and dropped futures (SNTR-REL-007).
pub(crate) struct PendingGuard<'a> {
    table: &'a PendingTable,
    id: u64,
}

impl<'a> PendingGuard<'a> {
    pub(crate) fn new(table: &'a PendingTable, id: u64) -> Self {
        Self { table, id }
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.table.abandon(self.id);
    }
}

/// Successful handshake output observed by the waiter.
#[derive(Debug, Clone)]
pub(crate) struct HandshakeDone {
    pub connection_id: String,
}

pub(crate) struct Shared {
    pub role: Role,
    pub state: RwLock<ConnectionState>,
    pub version: RwLock<Option<u32>>,
    pub proposed_min: u32,
    pub proposed_max: u32,
    pub pending: PendingTable,
    pub ids: RequestIdAllocator,
    pub writer: mpsc::Sender<Vec<u8>>,
    pub notif_tx: mpsc::Sender<Bytes>,
    pub handshake_tx: AsyncMutex<Option<oneshot::Sender<Result<HandshakeDone, SyntraError>>>>,
    pub config: ConnectionConfig,
    pub closed: AtomicBool,
    /// Intentional outbound admission fence. Unlike CLOSED, this leaves
    /// inbound validation and existing RPC waiters live until the pump drains.
    writer_fenced: AtomicBool,
    /// ACTIVE-phase decode failures (misbehavior counter, SNTR-ASEC-020).
    pub misbehavior: AtomicU32,
    /// Notification queue overflow observability for the Initiator path.
    /// Counts dropped notifications and their bytes; the queue stays
    /// bounded and drops remain non-blocking.
    pub notification_dropped: AtomicU64,
    pub notification_dropped_bytes: AtomicU64,
    /// Serializes concurrent `record_notification_loss` updates so the
    /// count/byte increments and the `notification_loss_tx` publication
    /// form one atomic snapshot. Without this, two concurrent drops can
    /// interleave increments and publish mismatched totals or publish a
    /// stale snapshot that moves the watch channel backwards.
    pub(crate) notification_loss_lock: StdMutex<()>,
    /// Carries the latest loss totals so every loss waiter observes a
    /// drop. Published on every drop alongside the counters; late
    /// subscribers read the current totals instead of missing a signal.
    pub notification_loss_tx: watch::Sender<(u64, u64)>,
    /// Close broadcast: fired on every path to CLOSED so transport pumps
    /// (which only hold byte channels) learn remote teardown promptly.
    /// Pumps `select!` on this alongside reads; firing is idempotent.
    pub closed_tx: watch::Sender<bool>,
}

impl Shared {
    pub fn new(
        role: Role,
        writer: mpsc::Sender<Vec<u8>>,
        config: ConnectionConfig,
        proposed_min: u32,
        proposed_max: u32,
    ) -> (Arc<Self>, mpsc::Receiver<Bytes>) {
        let (notif_tx, notif_rx) = mpsc::channel(config.notification_capacity);
        let (closed_tx, _) = watch::channel(false);
        let (notification_loss_tx, _) = watch::channel((0, 0));
        let shared = Arc::new(Self {
            role,
            state: RwLock::new(ConnectionState::Connected),
            version: RwLock::new(None),
            proposed_min,
            proposed_max,
            pending: PendingTable::new(config.max_outstanding),
            ids: RequestIdAllocator::new(),
            writer,
            notif_tx,
            handshake_tx: AsyncMutex::new(None),
            config,
            closed: AtomicBool::new(false),
            writer_fenced: AtomicBool::new(false),
            misbehavior: AtomicU32::new(0),
            notification_dropped: AtomicU64::new(0),
            notification_dropped_bytes: AtomicU64::new(0),
            notification_loss_lock: StdMutex::new(()),
            notification_loss_tx,
            closed_tx,
        });
        (shared, notif_rx)
    }
}

impl Shared {
    /// Record one dropped Syntra notification: advance the cumulative
    /// loss counters and publish the latest totals as one atomic
    /// snapshot. The short critical section serializes concurrent drops
    /// so count/byte totals stay paired and the watch channel never moves
    /// backwards; every loss waiter observes the new totals and late
    /// subscribers read them as current state.
    pub(crate) fn record_notification_loss(&self, payload_bytes: u64) -> (u64, u64) {
        let _guard = self.notification_loss_lock.lock().unwrap();
        let dropped = self.notification_dropped.fetch_add(1, Ordering::Relaxed) + 1;
        let dropped_bytes = self
            .notification_dropped_bytes
            .fetch_add(payload_bytes, Ordering::Relaxed)
            + payload_bytes;
        self.notification_loss_tx
            .send_replace((dropped, dropped_bytes));
        (dropped, dropped_bytes)
    }
}

/// Transport-agnostic half-connection: state machine, version, pending
/// correlation, notification queue, outbound byte channel.
#[derive(Clone)]
pub struct Connection {
    pub(crate) shared: Arc<Shared>,
    notif_rx: Arc<AsyncMutex<mpsc::Receiver<Bytes>>>,
}

impl Connection {
    pub(crate) fn wrap(shared: Arc<Shared>, notif_rx: mpsc::Receiver<Bytes>) -> Self {
        Self {
            shared,
            notif_rx: Arc::new(AsyncMutex::new(notif_rx)),
        }
    }

    /// Current state (for diagnostics; not a wire value).
    pub async fn state(&self) -> ConnectionState {
        *self.shared.state.read().await
    }

    pub async fn negotiated_version(&self) -> Option<u32> {
        *self.shared.version.read().await
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    pub(crate) fn writer_is_fenced(&self) -> bool {
        self.shared.writer_fenced.load(Ordering::Acquire)
    }

    /// Stop new sends without failing admitted RPCs or inbound frames.
    /// The pump must fence BEFORE closing its writer receiver and must
    /// report transport loss once the inbound drain has completed.
    pub(crate) async fn fence_writer(&self) {
        // Same linearization point as send_bytes and RPC queue admission.
        let _state = self.shared.state.write().await;
        self.shared.writer_fenced.store(true, Ordering::Release);
    }

    pub(crate) async fn ctx(&self) -> syntra_core::ValidationContext {
        let s = self.shared.state.read().await;
        let v = *self.shared.version.read().await;
        syntra_core::ValidationContext {
            state: *s,
            negotiated_version: v,
        }
    }

    pub(crate) async fn transition(&self, ev: StateEvent) -> Result<(), SyntraError> {
        // Read/validate/write is one operation. In particular a suspended
        // transition must never write a pre-close snapshot over CLOSED.
        let mut state = self.shared.state.write().await;
        let cur = *state;
        let next = cur.transition(ev)?;
        *state = next;
        debug!(from = ?cur, to = ?next, event = ?ev, role = ?self.shared.role, "syntra state");
        Ok(())
    }

    pub(crate) async fn send_bytes(&self, bytes: Vec<u8>) -> Result<(), SyntraError> {
        let permit = self.reserve_writer().await?;
        // Close and queue admission linearize on state. No lifecycle lock
        // is held while waiting for channel capacity.
        let _state = self.shared.state.read().await;
        if self.is_closed() || self.writer_is_fenced() {
            return Err(SyntraError::Closed("connection closed".to_string()));
        }
        permit.send(bytes);
        Ok(())
    }

    pub(crate) async fn reserve_writer(&self) -> Result<mpsc::Permit<'_, Vec<u8>>, SyntraError> {
        let mut closed = self.subscribe_close();
        if self.is_closed() || self.writer_is_fenced() {
            return Err(SyntraError::Closed("connection closed".to_string()));
        }
        tokio::select! {
            biased;
            _ = closed.changed() => Err(SyntraError::Closed("connection closed".to_string())),
            result = self.shared.writer.reserve() => match result {
                Ok(permit) => Ok(permit),
                Err(_) => {
                    // An intentional receiver-close rejects new/blocked
                    // sends but must not erase queued inbound outcomes.
                    // Unexpected writer disappearance still fails globally.
                    if !self.writer_is_fenced() {
                        self.on_transport_lost().await;
                    }
                    Err(SyntraError::Closed("transport writer gone".to_string()))
                }
            },
        }
    }

    /// Terminal handshake failure: surface the typed code locally to the
    /// waiter (B1: NO zero-`request_id` `result` and NO second `hello` is
    /// emitted to carry it), then explicitly close the core
    /// (CLOSING -> CLOSED, pending drained with `TransportLost`).
    pub(crate) async fn fail_handshake_and_close(
        &self,
        code: syntra_core::ErrorCode,
        message: String,
    ) {
        self.finish_close(SyntraError::Handshake { code, message }, false, false)
            .await;
    }

    pub(crate) async fn complete_handshake(&self, done: HandshakeDone) {
        if let Some(tx) = self.shared.handshake_tx.lock().await.take() {
            let _ = tx.send(Ok(done));
        }
    }

    /// Graceful close from ACTIVE: stop new RPCs, then teardown.
    /// Transport adapters observe CLOSING for the close handshake before
    /// dropping; the core itself ends at CLOSED with in-flight RPCs
    /// mapped to `UNAVAILABLE` (SNTR-HS-006/013).
    pub async fn close(&self) {
        self.finish_close(
            SyntraError::Closed("connection closed".to_string()),
            false,
            false,
        )
        .await;
    }

    /// Abrupt transport loss: `UNAVAILABLE` (unknown outcome) to all
    /// in-flight RPCs, handshake waiter fails, state moves to CLOSED.
    pub async fn on_transport_lost(&self) {
        self.finish_close(
            SyntraError::Unavailable("transport lost (outcome unknown)".to_string()),
            true,
            false,
        )
        .await;
    }

    async fn finish_close(&self, failure: SyntraError, abrupt: bool, handshake_only: bool) {
        let mut state = self.shared.state.write().await;
        if handshake_only
            && matches!(
                *state,
                ConnectionState::Active | ConnectionState::Closing | ConnectionState::Closed
            )
        {
            return;
        }
        // Same lock order as handshake registration and ready commit.
        // Take the waiter before mutating state, so cancellation while
        // acquiring locks cannot leave a half-closed connection. No new
        // handshake can register between waiter failure and terminal state.
        let mut waiter = self.shared.handshake_tx.lock().await;
        let cur = *state;
        let next = if abrupt {
            ConnectionState::Closed
        } else {
            match cur {
                ConnectionState::Closed => ConnectionState::Closed,
                ConnectionState::Closing => ConnectionState::Closed,
                _ => {
                    // Handshake failures and graceful close pass through
                    // CLOSING first (SNTR-HS-006/040).
                    match cur.transition(StateEvent::HandshakeFailed) {
                        Ok(s) => s,
                        Err(_) => match cur.transition(StateEvent::GracefulClose) {
                            Ok(s) => s,
                            Err(_) => ConnectionState::Closed,
                        },
                    }
                }
            }
        };
        *state = next;
        if next == ConnectionState::Closing {
            *state = ConnectionState::Closed;
        }
        self.shared.closed.store(true, Ordering::Release);
        self.shared.pending.drain_transport_lost();
        if let Some(tx) = waiter.take() {
            let _ = tx.send(Err(failure));
        }
        self.fire_closed();
    }

    /// Atomically arbitrate ready vs. the handshake timer. A timer that
    /// observed AUTHENTICATING must not later close a committed ACTIVE.
    pub(crate) async fn expire_handshake(&self) {
        self.finish_close(
            SyntraError::DeadlineExceeded("handshake timed out".to_string()),
            false,
            true,
        )
        .await;
    }

    /// Subscribe to the close broadcast. Fires (with `true`) on every
    /// path to CLOSED so transport pumps learn remote teardown without
    /// polling. Resolves immediately if already closed.
    pub fn subscribe_close(&self) -> watch::Receiver<bool> {
        self.shared.closed_tx.subscribe()
    }

    fn fire_closed(&self) {
        // Retain the terminal value even when no subscribers exist yet.
        self.shared.closed_tx.send_replace(true);
    }

    /// Test hook: hold the notification receiver lock so loss-wake tests
    /// can park waiters without them consuming the queued notification.
    #[cfg(test)]
    pub(crate) async fn hold_notification_receiver_for_test(
        &self,
    ) -> tokio::sync::MutexGuard<'_, mpsc::Receiver<Bytes>> {
        self.notif_rx.lock().await
    }

    /// Take the next notification payload (opaque application bytes).
    /// Returns None when the connection is closed and drained.
    pub async fn next_notification(&self) -> Option<Vec<u8>> {
        let mut closed = self.subscribe_close();
        let mut rx = self.notif_rx.lock().await;
        if !self.is_closed() {
            tokio::select! {
                biased;
                _ = closed.changed() => {},
                value = rx.recv() => return value.map(|b| b.to_vec()),
            }
        }
        // Closing the receiver rejects future producers but preserves the
        // already admitted queue. Never take this mutex on the close path:
        // an idle consumer holds it while waiting for the close broadcast.
        rx.close();
        rx.recv().await.map(|b| b.to_vec())
    }

    /// Number of outstanding RPCs (for backpressure observability).
    pub fn pending_len(&self) -> usize {
        self.shared.pending.len()
    }

    /// Notification queue overflow observability.
    /// Returns `(dropped_count, dropped_bytes)` for notifications
    /// discarded when the bounded notification queue was full.
    /// Bounds are unchanged; the queue stays non-blocking and drops.
    /// Reads under the loss lock so the paired totals are never torn.
    pub fn notification_loss(&self) -> (u64, u64) {
        let _guard = self.shared.notification_loss_lock.lock().unwrap();
        (
            self.shared
                .notification_dropped
                .load(Ordering::Relaxed),
            self.shared
                .notification_dropped_bytes
                .load(Ordering::Relaxed),
        )
    }
}
