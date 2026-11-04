//! Opt-in reconnecting Syntra client. This owns one dial loop and one
//! `ClientHandle`; the connector must build fresh security settings and credentials
//! on every invocation (in particular, `Secret32` is not cloned).
//!
//! Core readiness is not recovery readiness. `new_with_recovery` performs fresh
//! profile negotiation each generation; applications still restore subscriptions
//! and confirm durable progress explicitly. No requests, cipher/key
//! state, resume state, or notifications are replayed into a replacement connection.
//! Validated Core credential withdrawal blocks until explicit policy retry. Other
//! remote closes remain generic when the carrier supplies no typed reason.
//!
//! Call `platform_wake` after a platform wake: it explicitly retires the old
//! connection. Native outage/attempt budgets use the runtime continuous clock;
//! downstream channel/authorization/recovery clocks have separate integration gates.
use crate::{pump::EstablishmentBudget, ClientHandle, Error};
use std::{any::Any, pin::Pin};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use syntra_core::secure_channel::Secret32;
use syntra_core::SyntraError;
use syntra_runtime::recovery::{
    persistence::RecoveryPersistence,
    wire::RecoveryLimits,
    wire_client::{Negotiation, RecoveryClient, RecoveryClientError},
};
use syntra_runtime::{elapsed::ElapsedClock, Initiator};
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
    time::Instant,
};

/// Explicit limits; there is deliberately no implicit production retry policy.
#[derive(Clone, Debug)]
pub struct ReconnectConfig {
    pub attempt_timeout: Duration,
    /// Total elapsed outage time, including backoff and time paused/offline.
    pub reconnect_budget: Duration,
    pub max_attempts: u32,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub close_timeout: Duration,
    pub start_paused: bool,
    pub initial_network_available: bool,
}

impl ReconnectConfig {
    pub fn validate(&self) -> Result<(), Error> {
        // Also cap durations to make all Instant arithmetic representable.
        if self.max_attempts == 0
            || self.close_timeout > syntra_runtime::MAX_CLOSE_GRACE
            || self.attempt_timeout > Duration::from_secs(15)
            || self.base_backoff > self.max_backoff
            || [
                self.attempt_timeout,
                self.reconnect_budget,
                self.base_backoff,
                self.max_backoff,
                self.close_timeout,
            ]
            .iter()
            .any(|d| d.is_zero() || *d > Duration::from_secs(86_400))
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Sanitized categories: never retain credentials or arbitrary connector errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Configuration,
    Authentication,
    Channel,
    Runtime,
    LocalProtocol(syntra_core::ErrorCode),
    Framing,
    Io,
    Timeout,
    Closed,
    GenerationExhausted,
    RevisionExhausted,
    ElapsedContinuity,
    RecoveryUnavailable,
    Recovery,
}

impl Failure {
    fn of(error: &Error) -> Self {
        Self::transport(crate::pump::TransportFailure::of(error))
    }

    fn transport(failure: crate::pump::TransportFailure) -> Self {
        use crate::pump::TransportFailure as Transport;
        match failure {
            Transport::Configuration => Self::Configuration,
            Transport::Authentication => Self::Authentication,
            Transport::Channel => Self::Channel,
            Transport::Runtime => Self::Runtime,
            Transport::LocalProtocol(code) => Self::LocalProtocol(code),
            Transport::Framing => Self::Framing,
            Transport::Io => Self::Io,
            Transport::Timeout => Self::Timeout,
            Transport::Closed => Self::Closed,
        }
    }

    fn closure(handle: &ClientHandle, fallback: Self) -> Self {
        let transport = handle.transport_failure().map(Self::transport);
        if let Some(failure) = transport.filter(|failure| failure.terminal()) {
            return failure;
        }
        match handle.conn.terminal_reason().map(|e| e.code()) {
            Some(syntra_core::ErrorCode::Unauthenticated) => Self::Authentication,
            Some(
                syntra_core::ErrorCode::InvalidArgument
                | syntra_core::ErrorCode::FailedPrecondition,
            ) => Self::Runtime,
            _ if fallback == Self::Closed => transport.unwrap_or(fallback),
            _ => fallback,
        }
    }

    fn terminal(self) -> bool {
        !matches!(self, Self::Io | Self::Timeout | Self::Closed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreReady {
    pub generation: u64,
    pub connection_id: String,
    pub version: u32,
}

/// A watch of the current state, not an event log. Slow observers can miss states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleStatus {
    Starting,
    Paused,
    Offline,
    Connecting {
        attempt: u32,
    },
    Backoff {
        attempts: u32,
        delay: Duration,
        last_failure: Failure,
    },
    /// Only secure channel + core runtime ready; recovery must be re-negotiated by caller.
    CoreReady(CoreReady),
    /// Exact profile negotiation succeeded on this fresh generation. This is
    /// NOT restored subscriptions, durable catch-up, or full service readiness.
    RecoveryNegotiated(CoreReady),
    Blocked(Failure),
    Exhausted {
        attempts: u32,
        last_failure: Option<Failure>,
    },
    Stopping,
    Stopped,
    /// Teardown exceeded the lifecycle budget; ownership is retained until done.
    ShutdownIncomplete,
    Retired(Failure),
}

/// Current lifecycle state, with owned snapshots rather than borrowed watch guards.
/// Snapshots may be retained while calling client methods or across awaits without
/// blocking lifecycle publication. Slow observers can miss intermediate states.
#[derive(Clone)]
pub struct StatusReceiver {
    receiver: watch::Receiver<LifecycleStatus>,
}

impl StatusReceiver {
    /// Clone the current state and mark it seen by this receiver. The watch read
    /// guard is released before returning, including before any client callback.
    pub fn snapshot(&mut self) -> LifecycleStatus {
        self.receiver.borrow_and_update().clone()
    }

    /// Wait for an unseen state and return an owned snapshot, marking it seen.
    /// Cancellation is safe; closure is reported after any final unseen state.
    pub async fn changed(&mut self) -> Result<LifecycleStatus, watch::error::RecvError> {
        self.receiver.changed().await?;
        Ok(self.snapshot())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct GenerationValue<T> {
    pub generation: u64,
    pub value: T,
}

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// With a generation, the operation may have reached that peer: outcome unknown.
    #[error("client unavailable (generation {generation:?}; no automatic replay)")]
    Unavailable { generation: Option<u64> },
    #[error("RPC failed in generation {generation}: {source}")]
    Rpc {
        generation: u64,
        #[source]
        source: SyntraError,
    },
}

/// Loss totals are local to the tagged generation, not durable recovery progress.
#[derive(Debug, PartialEq, Eq)]
pub struct Notification {
    pub payload: Option<Vec<u8>>,
    pub dropped_count: u64,
    pub dropped_bytes: u64,
}

#[derive(Clone, Copy)]
struct Controls {
    revision: u64,
    retry_revision: u64,
    permit_revision: Option<u64>,
    paused: bool,
    online: bool,
    stopped: bool,
    invalidated_at: Option<Instant>,
}

#[derive(Clone)]
struct Active {
    generation: u64,
    revision: u64,
    conn: Initiator,
    recovery: Option<Arc<dyn Any + Send + Sync>>,
    recovery_required: bool,
}

struct State {
    controls: Controls,
    active: Option<Active>,
}

struct Shared {
    clock: ElapsedClock,
    recovery_required: bool,
    state: Mutex<State>,
    changed: Notify,
    // Private watch: all reads are cloned in status_snapshot/StatusReceiver.
    // No read guard escapes or acquires state. Publications can therefore stay
    // serialized with controls under state, preserving revision/staleness checks
    // on every path (including ready, stop, retirement and owner teardown).
    status: watch::Sender<LifecycleStatus>,
}

impl Shared {
    fn now(&self) -> Instant {
        Instant::from_std(self.clock.now())
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn status_snapshot(&self) -> LifecycleStatus {
        self.status.borrow().clone()
    }

    fn publish(&self, revision: u64, status: LifecycleStatus) {
        let state = self.lock();
        if state.controls.revision == revision && !state.controls.stopped {
            self.status.send_replace(status);
        }
    }

    async fn revised(&self, revision: u64) {
        loop {
            let controls = self.lock().controls;
            if controls.revision != revision || controls.stopped {
                return;
            }
            // notify_one stores at most one permit, including a signal between
            // the check and this await. Only the owner consumes this Notify.
            self.changed.notified().await;
        }
    }

    fn current(state: &State, active: &Active) -> bool {
        !state.controls.stopped
            && !state.controls.paused
            && state.controls.revision == active.revision
            && state
                .active
                .as_ref()
                .is_some_and(|a| a.generation == active.generation)
            && !active.conn.is_closed()
            && (!active.recovery_required || active.recovery.is_some())
    }

    fn stop(&self) {
        let mut state = self.lock();
        if !state.controls.stopped {
            state.controls.stopped = true;
            if let Some(active) = state.active.take() {
                active.conn.suspend();
            }
            self.status.send_replace(LifecycleStatus::Stopping);
        }
        self.changed.notify_one();
    }
}

/// Non-clone owner. Share with `Arc` for concurrent calls/controls if desired.
///
/// Connector futures must be cancellation-safe and cooperatively asynchronous:
/// dropping one must release its partial dial. Do not spawn detached work or block
/// in the factory/poll method. The native WSS connector satisfies this model.
/// Tokio must keep running for asynchronous teardown, including after `Drop`.
pub struct ReconnectingClient {
    shared: Arc<Shared>,
    owner: Option<JoinHandle<Result<(), Error>>>,
    close_timeout: Duration,
}

type RecoveryFactory = Arc<
    dyn Fn(
            Initiator,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Arc<dyn Any + Send + Sync>, RecoveryClientError>> + Send,
            >,
        > + Send
        + Sync,
>;

/// Shared durable state across connection-local profile clients. Locks run on
/// RecoveryClient's persistence worker, never across I/O or application awaits.
pub struct SharedRecoveryStore<S>(Arc<Mutex<S>>);

/// A typed profile client owned by exactly one authenticated Core generation.
pub type NegotiatedRecoveryClient<S> =
    Arc<tokio::sync::Mutex<RecoveryClient<SharedRecoveryStore<S>>>>;

impl<S: RecoveryPersistence> RecoveryPersistence for SharedRecoveryStore<S> {
    fn load(
        &self,
        scope: &syntra_runtime::recovery::persistence::PersistenceScope,
    ) -> Result<
        Option<syntra_runtime::recovery::persistence::DurableRecord>,
        syntra_runtime::recovery::persistence::PersistenceError,
    > {
        self.0
            .lock()
            .map_err(|_| syntra_runtime::recovery::persistence::PersistenceError::Unavailable)?
            .load(scope)
    }
    fn commit(
        &mut self,
        scope: &syntra_runtime::recovery::persistence::PersistenceScope,
        expected: Option<&syntra_runtime::recovery::persistence::ExpectedPosition>,
        record: syntra_runtime::recovery::persistence::DurableRecord,
    ) -> Result<(), syntra_runtime::recovery::persistence::PersistenceError> {
        self.0
            .lock()
            .map_err(|_| syntra_runtime::recovery::persistence::PersistenceError::Unavailable)?
            .commit(scope, expected, record)
    }
}

impl ReconnectingClient {
    pub fn new<F, Fut>(config: ReconnectConfig, connector: F) -> Result<Self, Error>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        Self::new_with_budget(config, move |_| connector())
    }

    /// Compose with the owner's exact attempt/outage cutoff and elapsed source.
    /// The connector must carry this budget through every establishment layer;
    /// unlike `new`, it need not create an independent carrier budget.
    pub fn new_with_budget<F, Fut>(config: ReconnectConfig, connector: F) -> Result<Self, Error>
    where
        F: Fn(EstablishmentBudget) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        #[cfg(test)]
        let clock = ElapsedClock::lifecycle_driven();
        #[cfg(not(test))]
        let clock = ElapsedClock::new();
        Self::new_inner(config, connector, clock, None)
    }

    pub fn new_with_clock<F, Fut>(
        config: ReconnectConfig,
        connector: F,
        clock: ElapsedClock,
    ) -> Result<Self, Error>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        Self::new_inner(config, move |_| connector(), clock, None)
    }

    /// Require actual wire profile negotiation after every fresh CoreReady.
    /// No mandatory-only fallback and no arbitrary mutation/subscription replay.
    /// The attempt/outage budget also bounds negotiation. Applications use the
    /// generation-bound client below to restore their declared durable streams.
    pub fn new_with_recovery<F, Fut, S>(
        config: ReconnectConfig,
        connector: F,
        principal_scope: Vec<u8>,
        store: Arc<Mutex<S>>,
        limits: RecoveryLimits,
    ) -> Result<Self, Error>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
        S: RecoveryPersistence + Send + Sync + 'static,
    {
        Self::new_with_recovery_and_budget(
            config,
            move |_| connector(),
            principal_scope,
            store,
            limits,
        )
    }

    /// Budget-aware establishment with fresh wire recovery negotiation on every
    /// generation. Recovery shares the owner's remaining attempt/outage cutoff.
    pub fn new_with_recovery_and_budget<F, Fut, S>(
        config: ReconnectConfig,
        connector: F,
        principal_scope: Vec<u8>,
        store: Arc<Mutex<S>>,
        limits: RecoveryLimits,
    ) -> Result<Self, Error>
    where
        F: Fn(EstablishmentBudget) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
        S: RecoveryPersistence + Send + Sync + 'static,
    {
        limits.validate().map_err(|_| Error::Configuration)?;
        if principal_scope.is_empty() || principal_scope.len() > 1024 {
            return Err(Error::Configuration);
        }
        let factory: RecoveryFactory = Arc::new(move |conn| {
            let scope = principal_scope.clone();
            let store = store.clone();
            let limits = limits.clone();
            Box::pin(async move {
                let mut recovery =
                    RecoveryClient::new(conn, scope, SharedRecoveryStore(store), limits)?;
                match recovery.negotiate().await? {
                    Negotiation::Confirmed(_) => {
                        Ok(Arc::new(tokio::sync::Mutex::new(recovery))
                            as Arc<dyn Any + Send + Sync>)
                    }
                    Negotiation::RecoveryUnavailable => {
                        Err(RecoveryClientError::RecoveryUnavailable)
                    }
                }
            })
        });
        Self::new_inner(config, connector, ElapsedClock::new(), Some(factory))
    }

    fn new_inner<F, Fut>(
        config: ReconnectConfig,
        connector: F,
        clock: ElapsedClock,
        recovery: Option<RecoveryFactory>,
    ) -> Result<Self, Error>
    where
        F: Fn(EstablishmentBudget) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        config.validate()?;
        let initial = if config.start_paused {
            LifecycleStatus::Paused
        } else if !config.initial_network_available {
            LifecycleStatus::Offline
        } else {
            LifecycleStatus::Starting
        };
        let (status, _) = watch::channel(initial);
        let shared = Arc::new(Shared {
            clock,
            recovery_required: recovery.is_some(),
            state: Mutex::new(State {
                controls: Controls {
                    revision: 0,
                    retry_revision: 0,
                    permit_revision: None,
                    paused: config.start_paused,
                    online: config.initial_network_available,
                    stopped: false,
                    invalidated_at: None,
                },
                active: None,
            }),
            changed: Notify::new(),
            status,
        });
        let owner = tokio::spawn(run(shared.clone(), config.clone(), connector, recovery));
        Ok(Self {
            shared,
            owner: Some(owner),
            close_timeout: config.close_timeout,
        })
    }

    /// Subscribe with owned snapshots; no public watch read lock can be retained
    /// while invoking controls, taking a call snapshot, closing or dropping.
    pub fn subscribe_status(&self) -> StatusReceiver {
        StatusReceiver {
            receiver: self.shared.status.subscribe(),
        }
    }

    pub fn status(&self) -> LifecycleStatus {
        self.shared.status_snapshot()
    }

    /// Fence application callbacks/completions obtained through recovery_client.
    pub fn is_generation_current(&self, generation: u64) -> bool {
        let state = self.shared.lock();
        state.active.as_ref().is_some_and(|active| {
            active.generation == generation && Shared::current(&state, active)
        })
    }

    fn control(&self, update: impl FnOnce(&mut Controls)) {
        let mut state = self.shared.lock();
        if state.controls.stopped {
            return;
        }
        // No wrap/ABA even for a pathological stream of coalesced controls.
        let Some(revision) = state.controls.revision.checked_add(1) else {
            state.controls.stopped = true;
            if let Some(active) = state.active.take() {
                active.conn.suspend();
            }
            self.shared
                .status
                .send_replace(LifecycleStatus::Retired(Failure::RevisionExhausted));
            self.shared.changed.notify_one();
            return;
        };
        state.controls.revision = revision;
        update(&mut state.controls);
        // Fence synchronously; the owner retires the handle before publishing any
        // successor. A pause followed immediately by resume still invalidates it.
        if let Some(active) = state.active.take() {
            state
                .controls
                .invalidated_at
                .get_or_insert_with(|| self.shared.now());
            active.conn.suspend();
        }
        self.shared.status.send_replace(if state.controls.paused {
            LifecycleStatus::Paused
        } else if !state.controls.online && state.controls.permit_revision.is_none() {
            LifecycleStatus::Offline
        } else {
            LifecycleStatus::Starting
        });
        self.shared.changed.notify_one();
    }

    pub fn pause(&self) {
        self.control(|c| {
            c.paused = true;
            c.permit_revision = None;
        });
    }

    /// Resume, granting one immediate attempt even if the network hint is offline.
    /// Does not clear terminal errors/exhaustion; `retry` does that explicitly.
    pub fn resume(&self) {
        self.control(|c| {
            c.paused = false;
            c.permit_revision = Some(c.revision);
        });
    }

    /// Every update invalidates the old dial/connection, even if the boolean is
    /// unchanged (e.g. switching networks). Offline suppresses automatic retries.
    pub fn network_available(&self, available: bool) {
        self.control(|c| {
            c.online = available;
            c.permit_revision = None;
        });
    }

    /// Apply the managed pool's complete state in one reconnect revision. Unlike
    /// an explicit standalone resume/retry, this must not grant an offline dial.
    #[cfg(feature = "managed")]
    pub(crate) fn apply_network_controls(&self, paused: bool, available: bool) {
        self.control(|c| {
            c.paused = paused;
            c.online = available;
            c.permit_revision = None;
        });
    }

    /// Explicitly unblock errors/exhaustion and start a fresh attempt/time budget.
    /// Unpauses and permits one offline attempt. Backoff exponent is preserved
    /// until actual core readiness; repeated retries coalesce, never queue dials.
    pub fn retry(&self) {
        self.control(|c| {
            c.paused = false;
            c.retry_revision = c.revision;
            c.permit_revision = Some(c.revision);
        });
    }

    /// Call after platform wake; always retire existing security/transport state.
    pub fn platform_wake(&self) {
        self.control(|c| {
            c.permit_revision = None;
        });
        self.shared.clock.wake();
    }

    /// Obtain the freshly negotiated, connection-bound profile client. A retained
    /// old client cannot emit after retirement: its Core and inbox are closed.
    /// Completion/application delivery still needs the returned generation fence.
    pub fn recovery_client<S: RecoveryPersistence + Send + Sync + 'static>(
        &self,
    ) -> Result<GenerationValue<NegotiatedRecoveryClient<S>>, CallError> {
        let active = self.snapshot()?;
        let recovery = active.recovery.ok_or(CallError::Unavailable {
            generation: Some(active.generation),
        })?;
        let value = recovery
            .downcast::<tokio::sync::Mutex<RecoveryClient<SharedRecoveryStore<S>>>>()
            .map_err(|_| CallError::Unavailable {
                generation: Some(active.generation),
            })?;
        Ok(GenerationValue {
            generation: active.generation,
            value,
        })
    }

    pub fn stop(&self) {
        self.shared.stop();
    }

    fn snapshot(&self) -> Result<Active, CallError> {
        let state = self.shared.lock();
        state
            .active
            .as_ref()
            .filter(|a| Shared::current(&state, a))
            .cloned()
            .ok_or(CallError::Unavailable { generation: None })
    }

    async fn forward<T>(
        &self,
        active: &Active,
        future: impl Future<Output = T>,
    ) -> Result<GenerationValue<T>, CallError> {
        let mut status = self.subscribe_status();
        tokio::pin!(future);
        loop {
            let result = tokio::select! {
                biased;
                _ = status.changed() => None,
                result = std::future::poll_fn(|cx| {
                    // Serialize each poll (including first admission and final
                    // delivery) with controls. Never hold this lock across await.
                    let state = self.shared.lock();
                    if !Shared::current(&state, active) {
                        return Poll::Ready(Err(CallError::Unavailable {
                            generation: Some(active.generation),
                        }));
                    }
                    future.as_mut().poll(cx).map(|value| Ok(GenerationValue {
                        generation: active.generation, value,
                    }))
                }) => Some(result),
            };
            if let Some(result) = result {
                return result;
            }
            if !Shared::current(&self.shared.lock(), active) {
                return Err(CallError::Unavailable {
                    generation: Some(active.generation),
                });
            }
        }
    }

    /// Snapshot synchronously at invocation, then forward once when polled. Even
    /// an unpolled future cannot migrate to a replacement generation. Never wait
    /// for readiness or retry a mutation. A lost outcome remains unknown.
    pub fn call<'a>(
        &'a self,
        method: &'a str,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> impl Future<Output = Result<GenerationValue<Vec<u8>>, CallError>> + Send + 'a {
        let snapshot = self.snapshot();
        async move {
            let active = snapshot?;
            let delivered = self
                .forward(&active, active.conn.call(method, payload, timeout_ms))
                .await?;
            delivered
                .value
                .map(|value| GenerationValue {
                    generation: delivered.generation,
                    value,
                })
                .map_err(|source| CallError::Rpc {
                    generation: delivered.generation,
                    source,
                })
        }
    }

    /// Notification/loss delivery is fenced and tagged, including buffered data
    /// from an old connection. Concurrent consumers share the core bounded queue.
    /// Like `call`, the snapshot is taken at invocation, before polling/awaiting.
    pub fn next_notification(
        &self,
    ) -> impl Future<Output = Result<GenerationValue<Notification>, CallError>> + Send + '_ {
        let snapshot = self.snapshot();
        async move {
            let active = snapshot?;
            let delivered = self
                .forward(&active, active.conn.next_notification_with_loss())
                .await?;
            let (payload, (dropped_count, dropped_bytes)) = delivered.value;
            Ok(GenerationValue {
                generation: delivered.generation,
                value: Notification {
                    payload,
                    dropped_count,
                    dropped_bytes,
                },
            })
        }
    }

    /// Signal stop and join the sole owner within `close_timeout`. On timeout the
    /// join handle stays owned, so another close can finish joining. Cancelling
    /// this future also retains ownership. `Timeout` means shutdown incomplete,
    /// never success. Drop signals the same owner to complete asynchronous teardown.
    pub async fn close(&mut self) -> Result<(), Error> {
        self.stop();
        let Some(owner) = self.owner.as_mut() else {
            return Ok(());
        };
        match self
            .shared
            .clock
            .timeout_until(self.shared.clock.now() + self.close_timeout, owner)
            .await
        {
            Ok(result) => {
                self.owner = None;
                result.map_err(|_| Error::Closed)?
            }
            Err(_) => {
                self.shared
                    .status
                    .send_replace(LifecycleStatus::ShutdownIncomplete);
                Err(Error::Timeout)
            }
        }
    }
}

impl Drop for ReconnectingClient {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Ensure a panic cannot leave a usable published connection/status behind.
struct OwnerGuard(Arc<Shared>);
impl Drop for OwnerGuard {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.active = None;
        state.controls.stopped = true;
        if !matches!(
            self.0.status_snapshot(),
            LifecycleStatus::Stopped
                | LifecycleStatus::Retired(_)
                | LifecycleStatus::ShutdownIncomplete
        ) {
            self.0
                .status
                .send_replace(LifecycleStatus::ShutdownIncomplete);
        }
    }
}

async fn closed(conn: &Initiator) {
    let mut rx = conn.subscribe_close();
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

async fn retire(shared: &Shared, handle: &mut ClientHandle, grace: Duration) -> bool {
    // The mutable pump API retains its JoinHandle and policy jobs on timeout.
    // The sole reconnect owner retains the whole old handle until BOTH transport
    // and runtime report actual completion.
    let cleanup = async {
        handle.conn.on_transport_lost().await;
        if handle.conn.begin_shutdown(grace).is_err() {
            return false;
        }
        loop {
            let transport = handle.shutdown_transport(grace).await;
            let report = handle.conn.shutdown_report();
            if matches!(transport, Ok(crate::pump::TransportShutdown::Complete))
                && report.phase == syntra_runtime::ShutdownPhase::Complete
            {
                return report.failed_tasks == 0;
            }
            // A passed/unknown deadline stops replacement but not ownership.
            // Scheduling this reaper does not extend any protocol budget.
            syntra_runtime::sleep_for(Duration::from_millis(10)).await;
        }
    };
    tokio::pin!(cleanup);
    let first = shared
        .clock
        .timeout_until(shared.clock.now() + grace, &mut cleanup)
        .await;
    if matches!(first, Ok(true)) {
        return true;
    }
    {
        let mut state = shared.lock();
        state.controls.stopped = true;
        state.active = None;
        shared
            .status
            .send_replace(LifecycleStatus::ShutdownIncomplete);
    }
    // If a completed cleanup returned false, do not poll that future twice.
    // That case is a joined task failure, not an unowned running carrier.
    if first.is_err() {
        cleanup.await;
    }
    false
}

enum Publication {
    Ready,
    Obsolete,
    Exhausted,
}

fn publish_ready(
    shared: &Shared,
    revision: u64,
    generation: &mut u64,
    handle: &ClientHandle,
    deadline: Instant,
) -> Publication {
    let mut state = shared.lock();
    if state.controls.revision != revision
        || state.controls.stopped
        || state.controls.paused
        || handle.is_closed()
        || Instant::from_std(shared.clock.now()) >= deadline
    {
        return Publication::Obsolete;
    }
    let Some(next) = generation.checked_add(1) else {
        state.controls.stopped = true;
        shared
            .status
            .send_replace(LifecycleStatus::Retired(Failure::GenerationExhausted));
        return Publication::Exhausted;
    };
    *generation = next;
    state.controls.invalidated_at = None;
    state.active = Some(Active {
        generation: next,
        revision,
        conn: handle.conn.clone(),
        recovery: None,
        recovery_required: shared.recovery_required,
    });
    shared
        .status
        .send_replace(LifecycleStatus::CoreReady(CoreReady {
            generation: next,
            connection_id: handle.connection_id.clone(),
            version: handle.version,
        }));
    Publication::Ready
}

fn jitter(base: Duration, maximum: Duration, failures: u32) -> Result<Duration, Error> {
    let cap = base
        .saturating_mul(1u32 << failures.saturating_sub(1).min(31))
        .min(maximum);
    // Equal jitter in [cap/2, cap], with a positive minimum even for 1ns.
    // This OS RNG sample is nonsecret; drop/zeroize the temporary immediately.
    let sample = Secret32::generate()?;
    let random = u64::from_le_bytes(sample.expose()[..8].try_into().expect("eight bytes"));
    drop(sample);
    let nanos = cap.as_nanos() as u64; // validate caps at one day
    let lower = nanos.div_ceil(2);
    Ok(Duration::from_nanos(lower + random % (nanos - lower + 1)))
}

async fn run<F, Fut>(
    shared: Arc<Shared>,
    config: ReconnectConfig,
    connector: F,
    recovery: Option<RecoveryFactory>,
) -> Result<(), Error>
where
    F: Fn(EstablishmentBudget) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
{
    let _guard = OwnerGuard(shared.clone());
    let mut active: Option<(u64, ClientHandle)> = None;
    let mut revision = 0;
    let mut retry_revision = 0;
    let mut consumed_permit = None;
    let mut generation = 0u64;
    let mut attempts = 0u32;
    let mut failures = 0u32;
    let mut outage: Option<Instant> = None;
    let mut next_attempt: Option<Instant> = None;
    let mut last_failure = None;
    let mut blocked = None;
    loop {
        if !shared.clock.is_continuous() {
            shared.stop();
            shared
                .status
                .send_replace(LifecycleStatus::Retired(Failure::ElapsedContinuity));
        }
        let controls = shared.lock().controls;
        if controls.stopped || controls.revision != revision {
            if let Some((_, mut handle)) = active.take() {
                outage
                    .get_or_insert_with(|| controls.invalidated_at.unwrap_or_else(|| shared.now()));
                if !retire(&shared, &mut handle, config.close_timeout).await {
                    return Err(Error::Timeout);
                }
                let reason = Failure::closure(&handle, Failure::Closed);
                if reason.terminal() {
                    blocked = Some(reason);
                    last_failure = Some(reason);
                }
            }
            revision = controls.revision;
            // Explicit controls may expedite a single attempt, but never reset
            // the backoff exponent or hide consumed attempts/elapsed outage.
            next_attempt = None;
        }
        if controls.stopped {
            break;
        }
        if controls.retry_revision != retry_revision {
            retry_revision = controls.retry_revision;
            attempts = 0;
            outage = None;
            blocked = None;
        }
        if let Some((_, handle)) = &active {
            tokio::select! {
                biased;
                _ = shared.revised(revision) => continue,
                _ = closed(&handle.conn) => {}
            }
            shared.lock().active = None;
            outage = Some(shared.now());
            let (_, mut handle) = active.take().expect("active handle");
            if !retire(&shared, &mut handle, config.close_timeout).await {
                return Err(Error::Timeout);
            }
            // Join before the final category read: peer close and another task's
            // already-observed security failure may race the owner's select.
            let reason = Failure::closure(&handle, Failure::Closed);
            last_failure = Some(reason);
            if reason.terminal() {
                blocked = Some(reason);
                continue;
            }
            failures = failures.saturating_add(1);
            match jitter(config.base_backoff, config.max_backoff, failures) {
                Ok(delay) => next_attempt = Some(shared.now() + delay),
                Err(_) => blocked = Some(Failure::Channel),
            }
            continue;
        }
        if controls.paused {
            shared.publish(revision, LifecycleStatus::Paused);
            shared.revised(revision).await;
            continue;
        }
        if let Some(reason) = blocked {
            shared.publish(revision, LifecycleStatus::Blocked(reason));
            shared.revised(revision).await;
            continue;
        }
        let manual =
            controls.permit_revision.is_some() && controls.permit_revision != consumed_permit;
        if !controls.online && !manual {
            shared.publish(revision, LifecycleStatus::Offline);
            shared.revised(revision).await;
            continue;
        }
        let now = shared.now();
        if attempts >= config.max_attempts
            || outage.is_some_and(|start| now >= start + config.reconnect_budget)
        {
            shared.publish(
                revision,
                LifecycleStatus::Exhausted {
                    attempts,
                    last_failure,
                },
            );
            shared.revised(revision).await;
            continue;
        }
        if let Some(next) = next_attempt.take().filter(|next| *next > now) {
            shared.publish(
                revision,
                LifecycleStatus::Backoff {
                    attempts,
                    delay: next - now,
                    last_failure: last_failure.unwrap_or(Failure::Closed),
                },
            );
            let end = next.min(outage.unwrap_or(now) + config.reconnect_budget);
            tokio::select! {
                biased;
                _ = shared.revised(revision) => {},
                _ = shared.clock.sleep_until(end.into_std()) => {},
            }
            continue;
        }
        if manual {
            consumed_permit = controls.permit_revision;
        }
        let start = *outage.get_or_insert(now);
        let end = (now + config.attempt_timeout).min(start + config.reconnect_budget);
        attempts += 1; // checked against a nonzero u32 max above
        shared.publish(revision, LifecycleStatus::Connecting { attempt: attempts });
        let mut completion = None;
        let result = match EstablishmentBudget::until(shared.clock.clone(), end.into_std()) {
            Ok(budget) => {
                if recovery.is_some() {
                    completion = Some(budget.defer_completion());
                }
                tokio::select! {
                biased;
                _ = shared.revised(revision) => continue,
                result = shared.clock.timeout_until(end.into_std(), async { connector(budget).await }) => result.unwrap_or(Err(Error::Timeout)),
                }
            }
            Err(_) if !shared.clock.is_continuous() => {
                shared.stop();
                shared
                    .status
                    .send_replace(LifecycleStatus::Retired(Failure::ElapsedContinuity));
                continue;
            }
            Err(error) => Err(error),
        };
        let error = match result {
            Ok(mut handle) => {
                // A completed dial can race a control update. Never publish it
                // (nor reset budgets) if its inputs or readiness are obsolete.
                match publish_ready(&shared, revision, &mut generation, &handle, end) {
                    Publication::Obsolete => {
                        let expired = shared.now() >= end;
                        if !retire(&shared, &mut handle, config.close_timeout).await {
                            return Err(Error::Timeout);
                        }
                        let reason = Failure::closure(&handle, Failure::Closed);
                        if reason.terminal() {
                            blocked = Some(reason);
                            last_failure = Some(reason);
                            continue;
                        }
                        if shared.lock().controls.revision != revision {
                            continue;
                        }
                        if expired {
                            Error::Timeout
                        } else {
                            Error::Closed
                        }
                    }
                    Publication::Ready => {
                        if let Some(factory) = &recovery {
                            let negotiated = tokio::select! {
                                biased;
                                _ = shared.revised(revision) => None,
                                _ = closed(&handle.conn) => Some(Err(RecoveryClientError::ReconnectRequired)),
                                result = shared.clock.timeout_until(end.into_std(), factory(handle.conn.clone())) =>
                                    Some(result.unwrap_or(Err(RecoveryClientError::Rpc(syntra_core::ErrorCode::DeadlineExceeded)))),
                            };
                            let mut accepted = false;
                            let mut completion_expired = false;
                            if let Some(Ok(profile)) = &negotiated {
                                let mut state = shared.lock();
                                if state.controls.revision == revision
                                    && !state.controls.stopped
                                    && !state.controls.paused
                                    && !handle.is_closed()
                                    && shared.now() < end
                                {
                                    if let Some(active) = state.active.as_mut() {
                                        // Release both carrier gates only after acceptance
                                        // under this revision, before publishing readiness.
                                        if completion
                                            .as_ref()
                                            .is_none_or(|guard| guard.finish().is_ok())
                                        {
                                            active.recovery = Some(profile.clone());
                                            shared.status.send_replace(
                                                LifecycleStatus::RecoveryNegotiated(CoreReady {
                                                    generation: active.generation,
                                                    connection_id: handle.connection_id.clone(),
                                                    version: handle.version,
                                                }),
                                            );
                                            accepted = true;
                                        } else {
                                            completion_expired = true;
                                        }
                                    }
                                }
                            }
                            if !accepted {
                                {
                                    let mut state = shared.lock();
                                    if let Some(active) = state.active.take() {
                                        active.conn.suspend();
                                    }
                                }
                                if !retire(&shared, &mut handle, config.close_timeout).await {
                                    return Err(Error::Timeout);
                                }
                                let transport_reason = Failure::closure(&handle, Failure::Closed);
                                if shared.lock().controls.revision != revision {
                                    if transport_reason.terminal() {
                                        blocked = Some(transport_reason);
                                        last_failure = Some(transport_reason);
                                    }
                                    continue;
                                }
                                let reason = match negotiated {
                                    Some(Err(RecoveryClientError::Rpc(
                                        syntra_core::ErrorCode::DeadlineExceeded,
                                    ))) => Failure::Timeout,
                                    Some(Ok(_)) if shared.now() >= end || completion_expired => {
                                        Failure::Timeout
                                    }
                                    Some(Err(RecoveryClientError::ReconnectRequired)) => {
                                        Failure::Closed
                                    }
                                    Some(Err(RecoveryClientError::RecoveryUnavailable)) => {
                                        Failure::RecoveryUnavailable
                                    }
                                    Some(Err(RecoveryClientError::Rpc(
                                        syntra_core::ErrorCode::Unauthenticated,
                                    ))) => Failure::Authentication,
                                    _ => Failure::Recovery,
                                };
                                let reason = Failure::closure(&handle, reason);
                                last_failure = Some(reason);
                                if reason.terminal() {
                                    blocked = Some(reason);
                                } else {
                                    failures = failures.saturating_add(1);
                                    match jitter(config.base_backoff, config.max_backoff, failures)
                                    {
                                        Ok(delay) => next_attempt = Some(shared.now() + delay),
                                        Err(_) => blocked = Some(Failure::Channel),
                                    }
                                }
                                continue;
                            }
                        }
                        active = Some((revision, handle));
                        attempts = 0;
                        failures = 0;
                        outage = None;
                        last_failure = None;
                        next_attempt = None;
                        continue;
                    }
                    Publication::Exhausted => {
                        if !retire(&shared, &mut handle, config.close_timeout).await {
                            return Err(Error::Timeout);
                        }
                        return Ok(());
                    }
                }
            }
            Err(error) => error,
        };
        let reason = Failure::of(&error);
        last_failure = Some(reason);
        if reason.terminal() {
            blocked = Some(reason);
        } else {
            failures = failures.saturating_add(1);
            match jitter(config.base_backoff, config.max_backoff, failures) {
                Ok(delay) => next_attempt = Some(shared.now() + delay),
                Err(_) => blocked = Some(Failure::Channel),
            }
        }
    }
    let state = shared.lock();
    if !matches!(shared.status_snapshot(), LifecycleStatus::Retired(_)) {
        shared.status.send_replace(LifecycleStatus::Stopped);
    }
    drop(state);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pump::{self, RecordReader, RecordWriter};
    use crate::{AuthenticatorFactory, HostHandle, Limits};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use syntra_core::secure_channel::{
        generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, ServerConfig,
        VerifiedIdentity,
    };
    use syntra_runtime::recovery::wire::*;
    use syntra_runtime::Principal;
    use syntra_runtime::{
        AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler, Handler,
        HandlerOutcome,
    };
    use tokio::sync::mpsc;

    #[cfg(feature = "http")]
    mod http_recovery {
        use super::*;
        use crate::http::{self, Authority};
        use std::task::{Context as TaskContext, Poll};
        use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
        use tokio::net::TcpStream;

        // The native HTTP fixture charges shared per-principal admission.
        static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

        struct Probe {
            armed: AtomicBool,
            advance_on: usize,
            advanced: AtomicBool,
            partial: AtomicUsize,
            late: [AtomicUsize; 2],
            dropped: AtomicUsize,
            completion: Mutex<Option<Arc<crate::pump::EstablishmentCompletion>>>,
        }
        impl Probe {
            fn new(advance_on: usize) -> Arc<Self> {
                Arc::new(Self {
                    armed: AtomicBool::new(false),
                    advance_on,
                    advanced: AtomicBool::new(false),
                    partial: AtomicUsize::new(0),
                    late: [AtomicUsize::new(0), AtomicUsize::new(0)],
                    dropped: AtomicUsize::new(0),
                    completion: Mutex::new(None),
                })
            }
        }
        struct TickIo {
            inner: TcpStream,
            probe: Arc<Probe>,
            stream: usize,
            cutoff: std::time::Instant,
        }
        impl TickIo {
            fn check_poll(&self) {
                if self.probe.armed.load(Ordering::SeqCst)
                    && Instant::now().into_std() >= self.cutoff
                {
                    self.probe.late[self.stream].fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        impl Drop for TickIo {
            fn drop(&mut self) {
                self.probe.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl AsyncRead for TickIo {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.check_poll();
                Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for TickIo {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
                bytes: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.check_poll();
                let this = self.get_mut();
                if this.probe.armed.load(Ordering::SeqCst)
                    && this.stream == this.probe.advance_on
                    && !this.probe.advanced.swap(true, Ordering::SeqCst)
                {
                    // The first recovery write starts in budget and returns one
                    // byte after virtual elapsed time crosses the owner's cutoff.
                    let mut advance = Box::pin(tokio::time::advance(Duration::from_secs(3)));
                    let _ = advance.as_mut().poll(cx);
                    let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..1]);
                    if matches!(result, Poll::Ready(Ok(1))) {
                        this.probe.partial.fetch_add(1, Ordering::SeqCst);
                    }
                    return result;
                }
                Pin::new(&mut this.inner).poll_write(cx, bytes)
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.check_poll();
                Pin::new(&mut self.get_mut().inner).poll_flush(cx)
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                cx: &mut TaskContext<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.check_poll();
                Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
            }
        }

        async fn server(
            recovery: bool,
        ) -> (
            http::ServerHandle,
            JoinHandle<http::ServerStatus>,
            Authority,
            [u8; 32],
        ) {
            let (private_key, public) = generate_server_key().unwrap();
            let security = Arc::new(ServerConfig {
                mode: Mode::Bootstrap,
                carrier: Carrier::Http,
                server_key_id: 1,
                scope: b"recovery-budget-fixture".to_vec(),
                private_key,
                store: None,
            });
            let base = |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                Ok(Arc::new(AllowAnonymous))
            };
            let auth: Arc<dyn AuthenticatorFactory> = if recovery {
                Arc::new(crate::RecoveryAuthenticatorFactory::new(
                    base,
                    RecoveryService::new(
                        Arc::new(RecoverySourceFixture),
                        RecoveryLimits::default(),
                    )
                    .unwrap(),
                ))
            } else {
                Arc::new(base)
            };
            let authority = Authority::new("127.0.0.1:38080").unwrap();
            let handler = Arc::new(FnHandler(|_, payload, _| async move {
                HandlerOutcome::Payload(payload)
            }));
            let settings = http::ServerConfig::new(
                "127.0.0.1:0".parse().unwrap(),
                authority.clone(),
                security,
                auth,
                handler,
            );
            let (server, run) = http::bind(settings).await.unwrap();
            (server, tokio::spawn(run), authority, public)
        }

        fn connector(
            address: std::net::SocketAddr,
            authority: Authority,
            public: [u8; 32],
            probe: Arc<Probe>,
            arm: bool,
        ) -> impl Fn(
            EstablishmentBudget,
        ) -> Pin<Box<dyn Future<Output = Result<ClientHandle, Error>> + Send>>
               + Send
               + Sync
               + 'static {
            move |budget| {
                let authority = authority.clone();
                let probe = probe.clone();
                Box::pin(async move {
                    *probe.completion.lock().unwrap() = Some(budget.io.completion.clone());
                    let upload = budget.run(TcpStream::connect(address)).await??;
                    let download = budget.run(TcpStream::connect(address)).await??;
                    let cutoff = budget.deadline();
                    let upload = TickIo {
                        inner: upload,
                        probe: probe.clone(),
                        stream: 0,
                        cutoff,
                    };
                    let download = TickIo {
                        inner: download,
                        probe: probe.clone(),
                        stream: 1,
                        cutoff,
                    };
                    let security = ClientConfig {
                        context: Context {
                            mode: Mode::Bootstrap,
                            carrier: Carrier::Http,
                            server_key_id: 1,
                            scope: b"recovery-budget-fixture".to_vec(),
                            handle: [0; 8],
                            epoch: 0,
                        },
                        server_public_key: public,
                        authorization_key: None,
                    };
                    let handle = http::connect_streams_with_budget(
                        upload,
                        download,
                        authority,
                        security,
                        vec![],
                        (ConnectionConfig::default(), Limits::default()),
                        budget,
                    )
                    .await?;
                    probe.armed.store(arm, Ordering::SeqCst);
                    Ok(handle)
                })
            }
        }

        async fn status(
            client: &ReconnectingClient,
            predicate: impl Fn(&LifecycleStatus) -> bool,
        ) -> LifecycleStatus {
            // Keep the virtual scheduler runnable while real loopback I/O settles;
            // only the fault injection below advances the attempt past its cutoff.
            for _ in 0..20_000 {
                let status = client.status();
                if predicate(&status) {
                    return status;
                }
                tokio::task::yield_now().await;
            }
            panic!("expected HTTP lifecycle state, got {:?}", client.status());
        }

        #[tokio::test(start_paused = true)]
        async fn recovery_http_partial_write_keeps_owner_cutoff_on_both_streams() {
            use syntra_runtime::recovery::persistence::MemoryRecoveryStore;
            let _serial = SERIAL.lock().await;
            for advance_on in [0, 1] {
                let (server, run, authority, public) = server(false).await;
                let probe = Probe::new(advance_on);
                let mut cfg = config();
                cfg.reconnect_budget = Duration::from_secs(2);
                cfg.max_attempts = 1;
                let mut client = ReconnectingClient::new_with_recovery_and_budget(
                    cfg,
                    connector(server.local_addr(), authority, public, probe.clone(), true),
                    b"scope".to_vec(),
                    Arc::new(Mutex::new(MemoryRecoveryStore::new())),
                    RecoveryLimits::default(),
                )
                .unwrap();
                let final_status = status(&client, |s| {
                    matches!(
                        s,
                        LifecycleStatus::Exhausted { .. } | LifecycleStatus::Blocked(_)
                    )
                })
                .await;
                assert!(probe.armed.load(Ordering::SeqCst));
                assert!(probe.advanced.load(Ordering::SeqCst));
                assert_eq!(probe.partial.load(Ordering::SeqCst), 1);
                assert_eq!(probe.late[0].load(Ordering::SeqCst), 0, "late upload I/O");
                assert_eq!(probe.late[1].load(Ordering::SeqCst), 0, "late download I/O");
                assert_eq!(
                    final_status,
                    LifecycleStatus::Exhausted {
                        attempts: 1,
                        last_failure: Some(Failure::Timeout)
                    }
                );
                assert_eq!(probe.dropped.load(Ordering::SeqCst), 2);
                assert!(probe.completion.lock().unwrap().as_ref().unwrap().pending());
                client.close().await.unwrap();
                server.stop();
                run.await.unwrap();
            }
        }

        #[tokio::test(start_paused = true)]
        async fn ordinary_and_recovery_http_release_setup_only_at_their_readiness_boundary() {
            use syntra_runtime::recovery::persistence::MemoryRecoveryStore;
            let _serial = SERIAL.lock().await;
            for recovery in [false, true] {
                let (server, run, authority, public) = server(recovery).await;
                let probe = Probe::new(0);
                let connect =
                    connector(server.local_addr(), authority, public, probe.clone(), false);
                let mut client = if recovery {
                    ReconnectingClient::new_with_recovery_and_budget(
                        config(),
                        connect,
                        b"scope".to_vec(),
                        Arc::new(Mutex::new(MemoryRecoveryStore::new())),
                        RecoveryLimits::default(),
                    )
                } else {
                    ReconnectingClient::new_with_budget(config(), connect)
                }
                .unwrap();
                status(&client, |s| {
                    if recovery {
                        matches!(s, LifecycleStatus::RecoveryNegotiated(_))
                    } else {
                        matches!(s, LifecycleStatus::CoreReady(_))
                    }
                })
                .await;
                assert!(!probe.completion.lock().unwrap().as_ref().unwrap().pending());
                tokio::time::advance(Duration::from_secs(3)).await;
                let mut call = Box::pin(client.call("/test.Service/Echo", vec![9], 1000));
                let mut response = None;
                for _ in 0..20_000 {
                    if let Poll::Ready(result) = futures_util::poll!(&mut call) {
                        response = Some(result);
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(response.unwrap().unwrap().value, vec![9]);
                drop(call);
                client.close().await.unwrap();
                assert_eq!(probe.dropped.load(Ordering::SeqCst), 2);
                server.stop();
                run.await.unwrap();
            }
        }

        #[tokio::test(start_paused = true)]
        async fn cancelling_required_http_recovery_keeps_gate_closed_to_application_calls() {
            let _serial = SERIAL.lock().await;
            let (server, run, authority, public) = server(false).await;
            let probe = Probe::new(0);
            let factory: RecoveryFactory = Arc::new(|_| Box::pin(std::future::pending()));
            let mut client = ReconnectingClient::new_inner(
                config(),
                connector(server.local_addr(), authority, public, probe.clone(), false),
                ElapsedClock::lifecycle_driven(),
                Some(factory),
            )
            .unwrap();
            status(&client, |s| matches!(s, LifecycleStatus::CoreReady(_))).await;
            assert!(probe.completion.lock().unwrap().as_ref().unwrap().pending());
            assert!(matches!(
                client.call("/test.Service/Echo", vec![7], 1000).await,
                Err(CallError::Unavailable { generation: None })
            ));
            client.close().await.unwrap();
            assert!(probe.completion.lock().unwrap().as_ref().unwrap().pending());
            assert_eq!(probe.dropped.load(Ordering::SeqCst), 2);
            server.stop();
            run.await.unwrap();
        }
    }

    fn config() -> ReconnectConfig {
        ReconnectConfig {
            attempt_timeout: Duration::from_secs(2),
            reconnect_budget: Duration::from_secs(100),
            max_attempts: 4,
            base_backoff: Duration::from_secs(10),
            max_backoff: Duration::from_secs(40),
            close_timeout: Duration::from_secs(1),
            start_paused: false,
            initial_network_available: true,
        }
    }

    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    async fn until(
        client: &ReconnectingClient,
        predicate: impl Fn(&LifecycleStatus) -> bool,
    ) -> LifecycleStatus {
        let mut rx = client.subscribe_status();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = rx.snapshot();
                if predicate(&status) {
                    return status;
                }
                rx.changed().await.expect("owner status");
            }
        })
        .await
        .expect("expected lifecycle state")
    }

    #[derive(Default)]
    struct Meter {
        started: AtomicUsize,
        in_flight: AtomicUsize,
        maximum: AtomicUsize,
    }
    struct Dial(Arc<Meter>);
    impl Meter {
        fn enter(self: &Arc<Self>) -> Dial {
            self.started.fetch_add(1, Ordering::SeqCst);
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(current, Ordering::SeqCst);
            Dial(self.clone())
        }
        fn count(&self) -> usize {
            self.started.load(Ordering::SeqCst)
        }
    }
    impl Drop for Dial {
        fn drop(&mut self) {
            self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn stalled(
        meter: Arc<Meter>,
    ) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = Result<ClientHandle, Error>> + Send>>
           + Send
           + Sync
           + 'static {
        move || {
            let meter = meter.clone();
            Box::pin(async move {
                let _dial = meter.enter();
                std::future::pending().await
            })
        }
    }

    #[tokio::test]
    async fn status_receiver_marks_snapshots_seen_and_preserves_unseen_changes() {
        let (sender, receiver) = watch::channel(LifecycleStatus::Starting);
        let mut status = StatusReceiver { receiver };
        let initial: LifecycleStatus = status.snapshot();
        let mut independent = status.clone();

        // Reading marks the current version seen. Cancelling a pending wait
        // must leave the next publication observable.
        let mut changed = Box::pin(status.changed());
        assert!(futures_util::poll!(&mut changed).is_pending());
        drop(changed);
        sender.send_replace(LifecycleStatus::Paused);
        let paused: LifecycleStatus = status.changed().await.unwrap();
        assert_eq!(paused, LifecycleStatus::Paused);
        assert_eq!(
            independent.changed().await.unwrap(),
            LifecycleStatus::Paused
        );

        sender.send_replace(LifecycleStatus::Offline);
        assert_eq!(status.snapshot(), LifecycleStatus::Offline);
        let mut changed = Box::pin(status.changed());
        assert!(futures_util::poll!(&mut changed).is_pending());
        drop(changed);

        // An unseen final value survives sender closure, then changed reports
        // closure. Previously returned values remain owned and unchanged.
        sender.send_replace(LifecycleStatus::Stopped);
        drop(sender);
        assert_eq!(status.changed().await.unwrap(), LifecycleStatus::Stopped);
        assert!(status.changed().await.is_err());
        assert_eq!(status.snapshot(), LifecycleStatus::Stopped);
        assert_eq!(initial, LifecycleStatus::Starting);
        assert_eq!(paused, LifecycleStatus::Paused);
    }

    #[tokio::test]
    async fn retained_status_snapshot_cannot_block_controls_or_call_snapshots() {
        let mut cfg = config();
        cfg.start_paused = true;
        let client =
            Arc::new(ReconnectingClient::new(cfg, stalled(Arc::new(Meter::default()))).unwrap());
        let mut status = client.subscribe_status();
        // The explicit owned type is part of the regression: no watch guard can
        // escape the API, including through a match scrutinee or an async wait.
        let retained: LifecycleStatus = status.snapshot();
        let (completed, completion) = std::sync::mpsc::channel();
        let control_client = client.clone();
        let controller = std::thread::spawn(move || {
            control_client.pause();
            // The wrapper must not weaken serialized revision checks: a stale
            // publisher still cannot overwrite the control's current status.
            control_client
                .shared
                .publish(0, LifecycleStatus::Connecting { attempt: 1 });
            assert_eq!(control_client.status(), LifecycleStatus::Paused);
            control_client.stop();
            completed.send(()).unwrap();
        });

        // No scheduler sleep: retain the observation until the other thread
        // finishes publication, then synchronously take both operation snapshots.
        // A bounded channel wait diagnoses a regression without waiting on join.
        completion
            .recv_timeout(Duration::from_secs(5))
            .expect("retaining an owned status must not block controls");
        match retained {
            LifecycleStatus::Paused => {
                drop(client.call("/test.Service/Echo", vec![], 1000));
                drop(client.next_notification());
            }
            other => panic!("unexpected retained status: {other:?}"),
        }
        assert_eq!(status.snapshot(), LifecycleStatus::Stopping);
        controller.join().unwrap();

        let mut client = Arc::try_unwrap(client).ok().unwrap();
        client.close().await.unwrap();
        let stopped: LifecycleStatus = status.changed().await.unwrap();
        drop(client);
        assert_eq!(stopped, LifecycleStatus::Stopped);
        assert!(status.changed().await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn pause_cancels_stalled_dial_and_controls_coalesce() {
        let meter = Arc::new(Meter::default());
        let mut client = ReconnectingClient::new(config(), stalled(meter.clone())).unwrap();
        settle().await;
        assert_eq!(meter.count(), 1);
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 1);
        client.pause();
        settle().await;
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(meter.count(), 1);
        assert_eq!(client.status(), LifecycleStatus::Paused);
        // A burst in one scheduler turn uses bounded memory and permits one dial.
        for _ in 0..10_000 {
            client.retry();
        }
        settle().await;
        assert_eq!(meter.count(), 2);
        assert_eq!(meter.maximum.load(Ordering::SeqCst), 1);
        client.network_available(true); // invalidate an in-flight dial
        settle().await;
        assert_eq!(meter.count(), 3);
        assert_eq!(meter.maximum.load(Ordering::SeqCst), 1);
        client.close().await.unwrap();
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        assert_eq!(client.status(), LifecycleStatus::Stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn initially_paused_offline_and_manual_retry_have_no_timer_loop() {
        let meter = Arc::new(Meter::default());
        let mut cfg = config();
        cfg.start_paused = true;
        cfg.initial_network_available = false;
        let mut client = ReconnectingClient::new(cfg, {
            let meter = meter.clone();
            move || {
                let meter = meter.clone();
                async move {
                    let _dial = meter.enter();
                    Err(Error::Closed)
                }
            }
        })
        .unwrap();
        settle().await;
        tokio::time::advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(meter.count(), 0);
        client.resume(); // one explicitly requested offline attempt
        settle().await;
        assert_eq!(meter.count(), 1);
        assert_eq!(client.status(), LifecycleStatus::Offline);
        tokio::time::advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(meter.count(), 1);
        client.retry(); // fresh budget and one offline attempt
        settle().await;
        assert_eq!(meter.count(), 2);
        tokio::time::advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(meter.count(), 2);
        client.network_available(true); // elapsed budget is not silently reset
        settle().await;
        assert!(matches!(client.status(), LifecycleStatus::Exhausted { .. }));
        assert_eq!(meter.count(), 2);
        client.close().await.unwrap();
    }

    #[cfg(feature = "managed")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_controls_publish_one_revision_without_an_offline_permit() {
        let mut cfg = config();
        cfg.initial_network_available = false;
        let meter = Arc::new(Meter::default());
        let mut client = ReconnectingClient::new(cfg, stalled(meter.clone())).unwrap();
        let published = Arc::new(tokio::sync::Barrier::new(2));
        let inspected = Arc::new(tokio::sync::Barrier::new(2));
        let controls = [(false, false), (true, true), (true, false), (false, false)];
        let observer = tokio::spawn({
            let shared = client.shared.clone();
            let meter = meter.clone();
            let published = published.clone();
            let inspected = inspected.clone();
            async move {
                let mut observations = Vec::with_capacity(32);
                for _ in 1..=32 {
                    published.wait().await;
                    let observed = {
                        let state = shared.lock();
                        (
                            state.controls.revision,
                            state.controls.paused,
                            state.controls.online,
                            state.controls.permit_revision,
                            state.controls.retry_revision,
                        )
                    };
                    observations.push((observed, meter.count()));
                    inspected.wait().await;
                }
                observations
            }
        });
        let check = async {
            for revision in 1..=32 {
                let (paused, available) = controls[(revision - 1) % controls.len()];
                client.apply_network_controls(paused, available);
                published.wait().await;
                inspected.wait().await;
            }
            observer.await.unwrap()
        };
        let observations = tokio::time::timeout(Duration::from_secs(5), check)
            .await
            .expect("bounded control/observer handoff");
        for (index, (observed, attempts)) in observations.into_iter().enumerate() {
            let revision = index as u64 + 1;
            let (paused, available) = controls[index % controls.len()];
            assert_eq!(observed, (revision, paused, available, None, 0));
            assert_eq!(attempts, 0, "managed controls never permit offline dials");
        }
        assert_eq!(meter.count(), 0);
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn offline_cancels_dial_and_true_network_hint_permits_one_owner_attempt() {
        let meter = Arc::new(Meter::default());
        let mut client = ReconnectingClient::new(config(), stalled(meter.clone())).unwrap();
        settle().await;
        client.network_available(false);
        settle().await;
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(50)).await;
        settle().await;
        assert_eq!(meter.count(), 1);
        assert_eq!(client.status(), LifecycleStatus::Offline);
        for _ in 0..1000 {
            client.network_available(true);
        }
        settle().await;
        assert_eq!(meter.count(), 2);
        assert_eq!(meter.maximum.load(Ordering::SeqCst), 1);
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn close_timeout_and_cancelled_close_retain_the_owner_join() {
        let mut client =
            ReconnectingClient::new(config(), stalled(Arc::new(Meter::default()))).unwrap();
        client.close().await.unwrap();
        // Isolate the public close/join contract with a deliberately slow owner.
        // No transport or previous owner task is left running by this fixture.
        let finished = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        client.owner = Some(tokio::spawn({
            let finished = finished.clone();
            let release = release.clone();
            async move {
                release.notified().await;
                finished.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
        assert!(matches!(client.close().await, Err(Error::Timeout)));
        assert_eq!(client.status(), LifecycleStatus::ShutdownIncomplete);
        assert!(client.owner.is_some());
        assert_eq!(finished.load(Ordering::SeqCst), 0);
        let mut closing = Box::pin(client.close());
        assert!(futures_util::poll!(&mut closing).is_pending());
        drop(closing);
        assert!(client.owner.is_some());
        release.notify_one();
        client.close().await.unwrap();
        assert_eq!(finished.load(Ordering::SeqCst), 1);
        assert!(client.owner.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn attempt_timeout_and_elapsed_outage_are_both_bounded() {
        let meter = Arc::new(Meter::default());
        let mut cfg = config();
        cfg.reconnect_budget = Duration::from_secs(3);
        cfg.base_backoff = Duration::from_nanos(1);
        cfg.max_backoff = Duration::from_nanos(1);
        let mut client = ReconnectingClient::new(cfg, stalled(meter.clone())).unwrap();
        settle().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        settle().await;
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_millis(1)).await;
        settle().await;
        assert_eq!(meter.count(), 2);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        assert!(matches!(
            client.status(),
            LifecycleStatus::Exhausted {
                attempts: 2,
                last_failure: Some(Failure::Timeout),
            }
        ));
        assert_eq!(meter.maximum.load(Ordering::SeqCst), 1);
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn budget_factory_receives_shorter_outage_cutoff_and_pause_does_not_renew_it() {
        let source = Arc::new(ElapsedFixture(std::sync::atomic::AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let origin = clock.now();
        let meter = Arc::new(Meter::default());
        let deadlines = Arc::new(Mutex::new(Vec::new()));
        let mut cfg = config();
        cfg.reconnect_budget = Duration::from_secs(3);
        let mut client = ReconnectingClient::new_inner(
            cfg,
            {
                let meter = meter.clone();
                let deadlines = deadlines.clone();
                move |budget: EstablishmentBudget| {
                    deadlines.lock().unwrap().push(budget.deadline());
                    let meter = meter.clone();
                    async move {
                        let _dial = meter.enter();
                        budget
                            .run(std::future::pending::<Result<ClientHandle, Error>>())
                            .await?
                    }
                }
            },
            clock.clone(),
            None,
        )
        .unwrap();
        settle().await;
        assert_eq!(
            deadlines.lock().unwrap().as_slice(),
            &[origin + Duration::from_secs(2)]
        );
        client.pause();
        settle().await;
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        source.0.store(2500, Ordering::SeqCst);
        client.resume();
        settle().await;
        assert_eq!(
            deadlines.lock().unwrap().as_slice(),
            &[
                origin + Duration::from_secs(2),
                origin + Duration::from_secs(3),
            ]
        );
        source.0.store(3000, Ordering::SeqCst);
        clock.wake();
        until(&client, |s| matches!(s, LifecycleStatus::Exhausted { .. })).await;
        assert_eq!(meter.count(), 2);
        assert_eq!(meter.maximum.load(Ordering::SeqCst), 1);
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        client.resume();
        settle().await;
        assert_eq!(meter.count(), 2, "resume cannot reset the outage budget");
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn budget_factory_uses_the_same_max_attempts_and_explicit_retry_controls() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut cfg = config();
        cfg.max_attempts = 2;
        cfg.base_backoff = Duration::from_nanos(1);
        cfg.max_backoff = Duration::from_nanos(1);
        let mut client = ReconnectingClient::new_with_budget(cfg, {
            let calls = calls.clone();
            move |budget| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move { budget.run(async { Err(Error::Closed) }).await? }
            }
        })
        .unwrap();
        until(&client, |s| {
            matches!(s, LifecycleStatus::Exhausted { attempts: 2, .. })
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        client.network_available(true);
        client.resume();
        settle().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        client.retry();
        until(&client, |s| {
            matches!(s, LifecycleStatus::Exhausted { attempts: 2, .. })
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        client.close().await.unwrap();
    }

    #[cfg(feature = "tcp")]
    #[tokio::test(start_paused = true)]
    async fn synchronous_budget_factory_overrun_emits_no_socket_bytes() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stream, accepted) = tokio::join!(
            tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
            listener.accept()
        );
        let stream = Arc::new(Mutex::new(Some(stream.unwrap())));
        let (mut peer, _) = accepted.unwrap();
        let pairs = Pairs::new();
        let source = Arc::new(ElapsedFixture(std::sync::atomic::AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let expected = clock.now() + Duration::from_millis(100);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut cfg = config();
        cfg.reconnect_budget = Duration::from_millis(100);
        let mut client = ReconnectingClient::new_inner(
            cfg,
            {
                let calls = calls.clone();
                move |budget: EstablishmentBudget| {
                    assert_eq!(budget.deadline(), expected);
                    calls.fetch_add(1, Ordering::SeqCst);
                    let stream = stream.lock().unwrap().take().unwrap();
                    let security = ClientConfig {
                        context: Context {
                            mode: Mode::Bootstrap,
                            carrier: Carrier::Tcp,
                            server_key_id: 1,
                            scope: b"budget-fixture".to_vec(),
                            handle: [0; 8],
                            epoch: 0,
                        },
                        server_public_key: pairs.public_key,
                        authorization_key: None,
                    };
                    // Simulate synchronous input provisioning crossing the parent's
                    // remaining outage cutoff before its future gets a first poll.
                    source.0.store(100, Ordering::SeqCst);
                    async move {
                        crate::tcp::connect_stream_with_budget(
                            stream,
                            security,
                            vec![],
                            ConnectionConfig::default(),
                            Limits::default(),
                            budget,
                        )
                        .await
                    }
                }
            },
            clock,
            None,
        )
        .unwrap();
        until(&client, |s| matches!(s, LifecycleStatus::Exhausted { .. })).await;
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "no first-flight bytes after the owner's cutoff"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        client.close().await.unwrap();
    }

    #[cfg(feature = "tcp")]
    #[tokio::test(start_paused = true)]
    async fn parent_outage_budget_gates_every_raw_poll_within_one_write() {
        use std::{pin::Pin, task::Context as TaskContext};
        use tokio::io::{AsyncWrite, AsyncWriteExt};
        struct PartialWrite {
            source: Arc<ElapsedFixture>,
            polls: Arc<AtomicUsize>,
        }
        impl AsyncWrite for PartialWrite {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
                _: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                self.polls.fetch_add(1, Ordering::SeqCst);
                self.source.0.store(100, Ordering::SeqCst);
                Poll::Ready(Ok(1))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<std::io::Result<()>> {
                panic!("expired gate must not flush")
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let source = Arc::new(ElapsedFixture(std::sync::atomic::AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let polls = Arc::new(AtomicUsize::new(0));
        let mut cfg = config();
        cfg.reconnect_budget = Duration::from_millis(100);
        let mut client = ReconnectingClient::new_inner(
            cfg,
            {
                let polls = polls.clone();
                move |budget: EstablishmentBudget| {
                    let mut stream = crate::stream::EstablishmentIo {
                        inner: PartialWrite {
                            source: source.clone(),
                            polls: polls.clone(),
                        },
                        budget: budget.io.clone(),
                    };
                    async move {
                        budget
                            .run(async {
                                stream.write_all(&[1, 2, 3]).await?;
                                Err(Error::Closed)
                            })
                            .await?
                    }
                }
            },
            clock,
            None,
        )
        .unwrap();
        until(&client, |s| {
            matches!(
                s,
                LifecycleStatus::Exhausted {
                    attempts: 1,
                    last_failure: Some(Failure::Timeout)
                }
            )
        })
        .await;
        assert_eq!(
            polls.load(Ordering::SeqCst),
            1,
            "no second raw poll after the parent's cutoff"
        );
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn continuity_lost_during_budget_creation_retires_without_calling_factory() {
        struct RegressingSource(AtomicUsize);
        impl syntra_runtime::elapsed::ElapsedSource for RegressingSource {
            fn elapsed(&self) -> Option<Duration> {
                // Construction and the loop's first continuity gate succeed.
                // A later sample while constructing/admitting this attempt fails.
                (self.0.fetch_add(1, Ordering::SeqCst) < 4).then_some(Duration::ZERO)
            }
        }
        let clock = ElapsedClock::with_source(Arc::new(RegressingSource(AtomicUsize::new(0))));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = ReconnectingClient::new_inner(
            config(),
            {
                let calls = calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err(Error::Closed) }
                }
            },
            clock,
            None,
        )
        .unwrap();
        until(&client, |s| {
            matches!(s, LifecycleStatus::Retired(Failure::ElapsedContinuity))
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(matches!(client.close().await, Err(Error::Timeout)));
        tokio::time::timeout(Duration::from_secs(1), client.owner.take().unwrap())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_is_capped_and_only_retry_reopens_exhaustion() {
        let meter = Arc::new(Meter::default());
        let mut client = ReconnectingClient::new(config(), {
            let meter = meter.clone();
            move || {
                let meter = meter.clone();
                async move {
                    let _dial = meter.enter();
                    Err(Error::Closed)
                }
            }
        })
        .unwrap();
        for attempt in 1..=4 {
            settle().await;
            assert_eq!(meter.count(), attempt);
            if attempt < 4 {
                let LifecycleStatus::Backoff {
                    delay, attempts, ..
                } = client.status()
                else {
                    panic!("missing backoff: {:?}", client.status());
                };
                assert_eq!(attempts as usize, attempt);
                let cap = Duration::from_secs((10 << (attempt - 1)).min(40));
                assert!(delay >= cap / 2 && delay <= cap);
                tokio::time::advance(delay - Duration::from_millis(1)).await;
                settle().await;
                assert_eq!(meter.count(), attempt);
                tokio::time::advance(Duration::from_millis(2)).await;
            }
        }
        assert!(matches!(
            client.status(),
            LifecycleStatus::Exhausted { attempts: 4, .. }
        ));
        tokio::time::advance(Duration::from_secs(1000)).await;
        client.resume();
        client.network_available(true);
        settle().await;
        assert_eq!(meter.count(), 4);
        client.retry();
        settle().await;
        assert_eq!(meter.count(), 5);
        let LifecycleStatus::Backoff { delay, .. } = client.status() else {
            panic!("backoff")
        };
        // Explicit retry resets the budget, NOT the exponent.
        assert!((Duration::from_secs(20)..=Duration::from_secs(40)).contains(&delay));
        client.pause();
        settle().await;
        tokio::time::advance(Duration::from_secs(1000)).await;
        settle().await;
        assert_eq!(meter.count(), 5);
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn terminal_errors_require_retry_even_after_network_or_wake() {
        for reason in [
            Failure::Authentication,
            Failure::LocalProtocol(syntra_core::ErrorCode::Unauthenticated),
            Failure::LocalProtocol(syntra_core::ErrorCode::PermissionDenied),
            Failure::Configuration,
            Failure::Channel,
            Failure::Runtime,
            Failure::Framing,
        ] {
            let meter = Arc::new(Meter::default());
            let mut client = ReconnectingClient::new(config(), {
                let meter = meter.clone();
                move || {
                    let meter = meter.clone();
                    async move {
                        let _dial = meter.enter();
                        Err(match reason {
                            Failure::Authentication => Error::Authentication,
                            Failure::LocalProtocol(code) => Error::LocalProtocol(code),
                            Failure::Configuration => Error::Configuration,
                            Failure::Channel => {
                                Error::Channel(syntra_core::secure_channel::Error::Authentication)
                            }
                            Failure::Runtime => Error::Runtime,
                            _ => Error::Framing,
                        })
                    }
                }
            })
            .unwrap();
            settle().await;
            assert_eq!(client.status(), LifecycleStatus::Blocked(reason));
            client.pause();
            client.resume();
            client.network_available(true);
            client.platform_wake();
            settle().await;
            tokio::time::advance(Duration::from_secs(1000)).await;
            settle().await;
            assert_eq!(meter.count(), 1);
            assert_eq!(client.status(), LifecycleStatus::Blocked(reason));
            client.retry();
            settle().await;
            assert_eq!(meter.count(), 2);
            client.close().await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn drop_stops_and_retires_owner_and_revision_never_wraps() {
        let meter = Arc::new(Meter::default());
        let mut client = ReconnectingClient::new(config(), stalled(meter.clone())).unwrap();
        settle().await;
        client.shared.lock().controls.revision = u64::MAX;
        client.retry();
        settle().await;
        assert_eq!(
            client.status(),
            LifecycleStatus::Retired(Failure::RevisionExhausted)
        );
        assert_eq!(client.shared.lock().controls.revision, u64::MAX);
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
        client.close().await.unwrap();

        let mut client = ReconnectingClient::new(config(), stalled(meter.clone())).unwrap();
        settle().await;
        let owner = client.owner.take().unwrap(); // observe Drop's owner completion
        drop(client);
        owner.await.unwrap().unwrap();
        assert_eq!(meter.in_flight.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn explicit_config_validation_and_jitter_bounds() {
        let good = config();
        for field in 0..6 {
            let mut bad = good.clone();
            match field {
                0 => bad.attempt_timeout = Duration::ZERO,
                1 => bad.reconnect_budget = Duration::ZERO,
                2 => bad.base_backoff = Duration::ZERO,
                3 => bad.max_backoff = Duration::ZERO,
                4 => bad.close_timeout = Duration::ZERO,
                _ => bad.max_attempts = 0,
            }
            assert!(matches!(bad.validate(), Err(Error::Configuration)));
        }
        let mut bad = good.clone();
        bad.base_backoff = good.max_backoff + Duration::from_secs(1);
        assert!(bad.validate().is_err());
        for failures in [0, 1, 2, 32, u32::MAX] {
            for _ in 0..16 {
                let delay = jitter(good.base_backoff, good.max_backoff, failures).unwrap();
                assert!(!delay.is_zero() && delay <= good.max_backoff);
            }
        }
    }

    // Real ordered, bounded record pairs run the canonical secure channel and runtime
    // handshakes/pumps without an OS socket or wall-clock scheduling dependency.
    struct Reader(mpsc::Receiver<Vec<u8>>);
    struct Writer(mpsc::Sender<Vec<u8>>, Option<Arc<AtomicUsize>>);
    struct FaultReader(Reader, Arc<AtomicUsize>);
    struct FaultWriter(Writer, Arc<AtomicUsize>);
    impl RecordReader for FaultReader {
        async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
            let bytes = self.0.read_record(maximum).await?;
            assert_ne!(
                self.1.load(Ordering::SeqCst),
                3,
                "local reader panic fixture"
            );
            Ok(bytes)
        }
    }
    impl RecordWriter for FaultWriter {
        async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
            let mut bytes = bytes.to_vec();
            match self.1.load(Ordering::SeqCst) {
                1 => bytes.resize(syntra_core::secure_channel::MAX_CIPHERTEXT + 1, 0),
                2 => *bytes.last_mut().unwrap() ^= 1,
                _ => {}
            }
            self.0.write_record(&bytes).await
        }
        async fn shutdown(&mut self) -> Result<(), Error> {
            self.0.shutdown().await
        }
    }
    impl Drop for Writer {
        fn drop(&mut self) {
            if let Some(live) = &self.1 {
                live.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
    impl RecordReader for Reader {
        async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
            let bytes = self.0.recv().await.ok_or(Error::Closed)?;
            if bytes.len() > maximum {
                return Err(Error::Framing);
            }
            Ok(bytes)
        }
    }
    impl RecordWriter for Writer {
        async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.0.send(bytes.to_vec()).await.map_err(|_| Error::Closed)
        }
        async fn shutdown(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }
    struct Store;
    impl KeyStore for Store {
        fn lookup(&self, _: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
            Ok(Secret32::new([8; 32]))
        }
    }
    struct RecoverySourceFixture;
    impl RecoverySource for RecoverySourceFixture {
        fn authorize(
            &self,
            _: &Principal,
            _: &[u8],
            _: AuthorizationHook,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
        fn capture(&self, _: &Principal, s: &[u8]) -> Result<ProviderStream, ProviderError> {
            ProviderStream::new(s.to_vec(), 1, b"c0".to_vec())
        }
        fn current_generation(&self, _: &Principal, _: &[u8]) -> Result<u64, ProviderError> {
            Ok(1)
        }
        fn validate_issued(
            &self,
            _: &Principal,
            _: &ProviderStream,
            _: &[u8],
        ) -> Result<(), ProviderError> {
            Ok(())
        }
        fn replay(
            &self,
            _: &Principal,
            s: &ProviderStream,
            _: &[u8],
            _: &[u8],
            _: PageBudget,
        ) -> Result<ProviderPage, ProviderError> {
            ProviderPage::new(vec![], s.boundary().to_vec(), vec![])
        }
        fn snapshot(
            &self,
            _: &Principal,
            _: &ProviderStream,
        ) -> Result<ProviderSnapshot, ProviderError> {
            Err(ProviderError::Unimplemented)
        }
        fn snapshot_page(
            &self,
            _: &Principal,
            _: &ProviderStream,
            _: &ProviderSnapshot,
            _: u32,
        ) -> Result<Vec<u8>, ProviderError> {
            Err(ProviderError::Unimplemented)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn required_recovery_performs_real_negotiation_every_generation_and_refuses_fallback() {
        use syntra_runtime::recovery::persistence::MemoryRecoveryStore;
        let pairs = Pairs::new();
        pairs.recovery.store(true, Ordering::Release);
        let store = Arc::new(Mutex::new(MemoryRecoveryStore::new()));
        let mut client = ReconnectingClient::new_with_recovery(
            config(),
            pairs.connector(),
            b"principal-scope".to_vec(),
            store,
            RecoveryLimits::default(),
        )
        .unwrap();
        let first = until(&client, |s| {
            matches!(s, LifecycleStatus::RecoveryNegotiated(_))
        })
        .await;
        let LifecycleStatus::RecoveryNegotiated(first) = first else {
            unreachable!()
        };
        let old = client.recovery_client::<MemoryRecoveryStore>().unwrap();
        assert_eq!(old.generation, first.generation);
        let subscribed = old
            .value
            .lock()
            .await
            .subscribe(
                b"stream".to_vec(),
                b"stream".to_vec(),
                syntra_runtime::recovery::wire_client::SubscribeIntent::InitialLiveOnly,
            )
            .await
            .unwrap();
        let old_handle = subscribed.response.subscription_handle;
        client.network_available(true);
        let second = until(&client, |s| matches!(s, LifecycleStatus::RecoveryNegotiated(info) if info.generation > first.generation)).await;
        let LifecycleStatus::RecoveryNegotiated(second) = second else {
            unreachable!()
        };
        assert!(!client.is_generation_current(old.generation));
        assert_eq!(
            old.value
                .lock()
                .await
                .replay_page(&old_handle)
                .await
                .unwrap_err(),
            RecoveryClientError::ReconnectRequired
        );
        let fresh = client.recovery_client::<MemoryRecoveryStore>().unwrap();
        assert_eq!(fresh.generation, second.generation);
        assert!(!Arc::ptr_eq(&old.value, &fresh.value));
        let subscribed = fresh
            .value
            .lock()
            .await
            .subscribe(
                b"stream".to_vec(),
                b"stream".to_vec(),
                syntra_runtime::recovery::wire_client::SubscribeIntent::InitialLiveOnly,
            )
            .await
            .unwrap();
        assert_ne!(subscribed.response.subscription_handle, old_handle);
        client.close().await.unwrap();
        pairs.cleanup().await;

        let pairs = Pairs::new(); // mandatory-only peer
        let mut client = ReconnectingClient::new_with_recovery(
            config(),
            pairs.connector(),
            b"scope".to_vec(),
            Arc::new(Mutex::new(MemoryRecoveryStore::new())),
            RecoveryLimits::default(),
        )
        .unwrap();
        until(&client, |s| {
            matches!(s, LifecycleStatus::Blocked(Failure::RecoveryUnavailable))
        })
        .await;
        assert!(client.recovery_client::<MemoryRecoveryStore>().is_err());
        assert!(client
            .call("/test.Service/Mutate", vec![], 1000)
            .await
            .is_err());
        client.platform_wake();
        settle().await;
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
        assert_eq!(pairs.mutations.load(Ordering::SeqCst), 0);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn budget_aware_recovery_negotiates_fresh_generation_bound_clients() {
        use syntra_runtime::recovery::persistence::MemoryRecoveryStore;
        let pairs = Pairs::new();
        pairs.recovery.store(true, Ordering::SeqCst);
        let mut client = ReconnectingClient::new_with_recovery_and_budget(
            config(),
            {
                let pairs = pairs.clone();
                move |budget| pairs.clone().connect_with_budget(budget)
            },
            b"scope".to_vec(),
            Arc::new(Mutex::new(MemoryRecoveryStore::new())),
            RecoveryLimits::default(),
        )
        .unwrap();
        until(&client, |s| {
            matches!(s, LifecycleStatus::RecoveryNegotiated(_))
        })
        .await;
        let first = client.recovery_client::<MemoryRecoveryStore>().unwrap();
        client.network_available(true);
        until(&client, |s| matches!(s, LifecycleStatus::RecoveryNegotiated(info) if info.generation > first.generation)).await;
        let second = client.recovery_client::<MemoryRecoveryStore>().unwrap();
        assert!(!client.is_generation_current(first.generation));
        assert!(!Arc::ptr_eq(&first.value, &second.value));
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 2);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_negotiation_transient_failures_back_off_and_retry() {
        for case in 0..5 {
            let pairs = Pairs::new();
            let source = Arc::new(ElapsedFixture(std::sync::atomic::AtomicU64::new(0)));
            let clock = ElapsedClock::with_source(source.clone());
            let entered = Arc::new(Notify::new());
            let factory: RecoveryFactory = Arc::new({
                let source = source.clone();
                let entered = entered.clone();
                move |conn| {
                    let source = source.clone();
                    let entered = entered.clone();
                    Box::pin(async move {
                        entered.notify_one();
                        match case {
                            0 => std::future::pending().await,
                            1 => Err(RecoveryClientError::Rpc(
                                syntra_core::ErrorCode::DeadlineExceeded,
                            )),
                            2 => Err(RecoveryClientError::ReconnectRequired),
                            3 => {
                                // Complete within one poll, but after the elapsed
                                // deadline: the profile must not be published.
                                source.0.fetch_add(2000, Ordering::SeqCst);
                                Ok(Arc::new(()) as Arc<dyn Any + Send + Sync>)
                            }
                            _ => {
                                conn.on_transport_lost().await;
                                std::future::pending().await
                            }
                        }
                    })
                }
            });
            let mut client = ReconnectingClient::new_inner(
                config(),
                {
                    let connector = pairs.connector();
                    move |_| connector()
                },
                clock.clone(),
                Some(factory),
            )
            .unwrap();
            let expected = if case == 2 || case == 4 {
                Failure::Closed
            } else {
                Failure::Timeout
            };
            for attempt in 1..=2 {
                entered.notified().await;
                if case == 0 {
                    source.0.fetch_add(2000, Ordering::SeqCst);
                    clock.wake();
                }
                let status = until(&client, |s| matches!(s, LifecycleStatus::Backoff { .. })).await;
                let LifecycleStatus::Backoff {
                    attempts,
                    delay,
                    last_failure,
                } = status
                else {
                    unreachable!()
                };
                assert_eq!(attempts, attempt);
                assert_eq!(last_failure, expected);
                let cap = Duration::from_secs(10 * u64::from(attempt));
                assert!((cap / 2..=cap).contains(&delay));
                assert_eq!(pairs.dials.load(Ordering::SeqCst), attempt as usize);
                assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
                assert!(client.shared.lock().active.is_none());
                if attempt == 1 {
                    source.0.fetch_add(40_000, Ordering::SeqCst);
                    clock.wake();
                }
            }
            client.close().await.unwrap();
            pairs.cleanup().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_negotiation_terminal_failures_do_not_retry() {
        for (error, expected) in [
            (
                RecoveryClientError::RecoveryUnavailable,
                Failure::RecoveryUnavailable,
            ),
            (
                RecoveryClientError::Rpc(syntra_core::ErrorCode::Unauthenticated),
                Failure::Authentication,
            ),
            (RecoveryClientError::InvalidState, Failure::Recovery),
            (RecoveryClientError::RecoveryNeeded, Failure::Recovery),
            (
                RecoveryClientError::Rpc(syntra_core::ErrorCode::Unavailable),
                Failure::Recovery,
            ),
        ] {
            let pairs = Pairs::new();
            let factory: RecoveryFactory = Arc::new(move |_| Box::pin(async move { Err(error) }));
            let mut client = ReconnectingClient::new_inner(
                config(),
                {
                    let connector = pairs.connector();
                    move |_| connector()
                },
                ElapsedClock::lifecycle_driven(),
                Some(factory),
            )
            .unwrap();
            assert_eq!(
                until(&client, |s| matches!(s, LifecycleStatus::Blocked(_))).await,
                LifecycleStatus::Blocked(expected)
            );
            client.network_available(true);
            client.platform_wake();
            settle().await;
            tokio::time::advance(Duration::from_secs(1000)).await;
            settle().await;
            assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
            assert_eq!(client.status(), LifecycleStatus::Blocked(expected));
            client.close().await.unwrap();
            pairs.cleanup().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn active_credential_withdrawal_blocks_automatic_reconnect_until_explicit_retry() {
        let pairs = Pairs::new();
        let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
        ready(&client).await;
        let _ = client.call("/test.Service/Revoke", vec![], 1000).await;
        until(&client, |s| {
            matches!(s, LifecycleStatus::Blocked(Failure::Authentication))
        })
        .await;
        client.network_available(true);
        client.platform_wake();
        settle().await;
        tokio::time::advance(Duration::from_secs(100)).await;
        settle().await;
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
        client.retry();
        ready(&client).await;
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 2);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    struct ElapsedFixture(std::sync::atomic::AtomicU64);
    impl syntra_runtime::elapsed::ElapsedSource for ElapsedFixture {
        fn elapsed(&self) -> Option<Duration> {
            Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_outage_budget_includes_pause_without_scheduler_advance() {
        let source = Arc::new(ElapsedFixture(std::sync::atomic::AtomicU64::new(10_000)));
        let clock = ElapsedClock::with_source(source.clone());
        let meter = Arc::new(Meter::default());
        let mut client =
            ReconnectingClient::new_with_clock(config(), stalled(meter.clone()), clock).unwrap();
        settle().await;
        assert_eq!(meter.count(), 1);
        client.pause();
        settle().await;
        source.0.fetch_add(100_001, Ordering::SeqCst);
        client.platform_wake();
        client.resume();
        settle().await;
        assert!(matches!(
            client.status(),
            LifecycleStatus::Exhausted { attempts: 1, .. }
        ));
        assert_eq!(meter.count(), 1);
        client.close().await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn pause_timestamp_precedes_owner_poll_and_counts_elapsed_suspension() {
        let pairs = Pairs::new();
        let source = Arc::new(ElapsedFixture(std::sync::atomic::AtomicU64::new(10_000)));
        let mut client = ReconnectingClient::new_with_clock(
            config(),
            pairs.connector(),
            ElapsedClock::with_source(source.clone()),
        )
        .unwrap();
        ready(&client).await;
        client.pause(); // the owner does not get a scheduler turn before sleep
        source.0.fetch_add(100_001, Ordering::SeqCst);
        client.resume();
        until(&client, |s| matches!(s, LifecycleStatus::Exhausted { .. })).await;
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
        assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }
    struct Pairs {
        fault: Arc<AtomicUsize>,
        security: ServerConfig,
        public_key: [u8; 32],
        hosts: Mutex<Vec<HostHandle>>,
        mutations: AtomicUsize,
        release: Notify,
        dials: AtomicUsize,
        live_clients: Arc<AtomicUsize>,
        recovery: AtomicBool,
    }
    impl Pairs {
        fn new() -> Arc<Self> {
            let (private_key, public_key) = generate_server_key().unwrap();
            Arc::new(Self {
                fault: Arc::new(AtomicUsize::new(0)),
                security: ServerConfig {
                    mode: Mode::Returning,
                    carrier: Carrier::Tcp,
                    server_key_id: 1,
                    scope: b"lifecycle/ordered-fixture".to_vec(),
                    private_key,
                    store: Some(Arc::new(Store)),
                },
                public_key,
                hosts: Mutex::new(Vec::new()),
                mutations: AtomicUsize::new(0),
                release: Notify::new(),
                dials: AtomicUsize::new(0),
                live_clients: Arc::new(AtomicUsize::new(0)),
                recovery: AtomicBool::new(false),
            })
        }

        async fn connect(self: Arc<Self>) -> Result<ClientHandle, Error> {
            let budget = EstablishmentBudget::new(
                pump::default_elapsed_clock(),
                Limits::default().attempt_timeout,
            )?;
            self.connect_with_budget(budget).await
        }

        async fn connect_with_budget(
            self: Arc<Self>,
            budget: EstablishmentBudget,
        ) -> Result<ClientHandle, Error> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                self.live_clients.fetch_add(1, Ordering::SeqCst),
                0,
                "old carrier must be dropped/joined before another dial"
            );
            let (a_tx, a_rx) = mpsc::channel(4);
            let (b_tx, b_rx) = mpsc::channel(4);
            let security = ClientConfig {
                context: Context {
                    mode: Mode::Returning,
                    carrier: Carrier::Tcp,
                    server_key_id: 1,
                    scope: self.security.scope.clone(),
                    handle: [7; 8],
                    epoch: 2,
                },
                server_public_key: self.public_key,
                authorization_key: Some(Secret32::new([8; 32])), // rebuilt every attempt
            };
            let base = |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                Ok(Arc::new(AllowAnonymous))
            };
            let auth: Arc<dyn AuthenticatorFactory> = if self.recovery.load(Ordering::Acquire) {
                Arc::new(crate::RecoveryAuthenticatorFactory::new(
                    base,
                    RecoveryService::new(
                        Arc::new(RecoverySourceFixture),
                        RecoveryLimits::default(),
                    )
                    .unwrap(),
                ))
            } else {
                Arc::new(base)
            };
            let fixture = self.clone();
            let handler: Arc<dyn Handler> =
                Arc::new(FnHandler(move |method: String, payload, _| {
                    let fixture = fixture.clone();
                    async move {
                        if method == "/test.Service/Mutate" {
                            fixture.mutations.fetch_add(1, Ordering::SeqCst);
                            fixture.release.notified().await;
                        }
                        if method == "/test.Service/Revoke" {
                            return HandlerOutcome::error(
                                syntra_core::ErrorCode::Unauthenticated,
                                "credential not accepted",
                            );
                        }
                        HandlerOutcome::Payload(payload)
                    }
                }));
            let limits = Limits {
                record_timeout: Duration::from_secs(3600),
                ..Limits::default()
            };
            let (client, host) = tokio::join!(
                pump::connect_records_with_budget(
                    FaultReader(Reader(b_rx), self.fault.clone()),
                    Writer(a_tx, Some(self.live_clients.clone())),
                    security,
                    vec![],
                    ConnectionConfig::default(),
                    limits.clone(),
                    budget
                ),
                pump::accept_records(
                    Reader(a_rx),
                    FaultWriter(Writer(b_tx, None), self.fault.clone()),
                    &self.security,
                    auth,
                    handler,
                    ConnectionConfig::default(),
                    limits
                ),
            );
            let host = host?;
            self.hosts.lock().unwrap().push(host);
            client
        }

        fn connector(
            self: &Arc<Self>,
        ) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = Result<ClientHandle, Error>> + Send>>
               + Send
               + Sync
               + 'static {
            let fixture = self.clone();
            move || Box::pin(fixture.clone().connect())
        }

        async fn notify(&self, index: usize, bytes: Vec<u8>) {
            let host = self.hosts.lock().unwrap()[index].host.clone();
            host.notify(bytes).await.unwrap();
            settle().await;
        }

        async fn cleanup(&self) {
            let hosts = std::mem::take(&mut *self.hosts.lock().unwrap());
            for host in hosts {
                host.close().await;
            }
        }
    }

    async fn ready(client: &ReconnectingClient) -> u64 {
        match until(client, |s| matches!(s, LifecycleStatus::CoreReady(_))).await {
            LifecycleStatus::CoreReady(info) => info.generation,
            _ => unreachable!(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn live_security_failures_block_without_touching_the_next_connector() {
        for (fault, expected) in [(1, Failure::Framing), (2, Failure::Channel)] {
            let pairs = Pairs::new();
            let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
            ready(&client).await;
            pairs.fault.store(fault, Ordering::SeqCst);
            pairs.notify(0, vec![1]).await;
            assert_eq!(
                until(&client, |s| matches!(s, LifecycleStatus::Blocked(_))).await,
                LifecycleStatus::Blocked(expected)
            );
            client.network_available(true);
            client.platform_wake();
            settle().await;
            tokio::time::advance(Duration::from_secs(100)).await;
            settle().await;
            assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
            assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
            assert_eq!(client.status(), LifecycleStatus::Blocked(expected));
            client.close().await.unwrap();
            pairs.cleanup().await;
        }
    }

    #[cfg(feature = "proxy")]
    #[tokio::test(start_paused = true)]
    async fn proxy_denials_block_but_refusal_and_unavailability_retry() {
        use crate::proxy::{self, ProxyConfig, ProxyTarget};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (code, expected) in [
            (2, Failure::Authentication),
            (7, Failure::Configuration),
            (8, Failure::Configuration),
            (401, Failure::Authentication),
            (403, Failure::Authentication),
            (407, Failure::Authentication),
            (5, Failure::Io),
            (502, Failure::Io),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut client = ReconnectingClient::new(config(), {
                let calls = calls.clone();
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let (stream, mut peer) = tokio::io::duplex(4096);
                        let endpoint = "127.0.0.1:1080".parse().unwrap();
                        let proxy = if code < 10 {
                            ProxyConfig::socks5(endpoint, None)
                        } else {
                            ProxyConfig::http_connect(endpoint, None)
                        }
                        .unwrap();
                        let target = ProxyTarget::ip("127.0.0.1".parse().unwrap(), 443).unwrap();
                        let budget = pump::EstablishmentBudget::new(
                            ElapsedClock::lifecycle_driven(),
                            Duration::from_secs(1),
                        )
                        .unwrap();
                        let reply = async {
                            if code < 10 {
                                let mut greeting = [0; 3];
                                peer.read_exact(&mut greeting).await.unwrap();
                                peer.write_all(&[5, 0]).await.unwrap();
                                let mut request = [0; 10];
                                peer.read_exact(&mut request).await.unwrap();
                                peer.write_all(&[5, code as u8, 0, 1]).await.unwrap();
                            } else {
                                let mut request = Vec::new();
                                while !request.ends_with(b"\r\n\r\n") {
                                    request.push(peer.read_u8().await.unwrap());
                                }
                                peer.write_all(
                                    format!("HTTP/1.1 {code} Denied\r\n\r\n").as_bytes(),
                                )
                                .await
                                .unwrap();
                            }
                        };
                        let (result, ()) = tokio::join!(
                            proxy::tunnel_stream_with_budget(stream, &proxy, &target, &budget),
                            reply
                        );
                        match result {
                            Err(error) => Err(error),
                            Ok(_) => panic!("denial must not establish a tunnel"),
                        }
                    }
                }
            })
            .unwrap();
            if expected.terminal() {
                assert_eq!(
                    until(&client, |s| matches!(s, LifecycleStatus::Blocked(_))).await,
                    LifecycleStatus::Blocked(expected)
                );
                tokio::time::advance(Duration::from_secs(100)).await;
                settle().await;
                assert_eq!(calls.load(Ordering::SeqCst), 1);
            } else {
                let status = until(&client, |s| matches!(s, LifecycleStatus::Backoff { .. })).await;
                let LifecycleStatus::Backoff {
                    delay,
                    last_failure,
                    ..
                } = status
                else {
                    unreachable!()
                };
                assert_eq!(last_failure, expected);
                tokio::time::advance(delay + Duration::from_millis(1)).await;
                settle().await;
                assert_eq!(calls.load(Ordering::SeqCst), 2);
            }
            client.close().await.unwrap();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_wire_security_failures_block_instead_of_retrying_closed() {
        use syntra_runtime::recovery::persistence::MemoryRecoveryStore;
        for (fault, expected) in [(1, Failure::Framing), (2, Failure::Channel)] {
            let pairs = Pairs::new();
            pairs.recovery.store(true, Ordering::SeqCst);
            let connector = {
                let pairs = pairs.clone();
                move || {
                    let pairs = pairs.clone();
                    async move {
                        let handle = pairs.clone().connect().await?;
                        pairs.fault.store(fault, Ordering::SeqCst);
                        Ok(handle)
                    }
                }
            };
            let mut client = ReconnectingClient::new_with_recovery(
                config(),
                connector,
                b"scope".to_vec(),
                Arc::new(Mutex::new(MemoryRecoveryStore::new())),
                RecoveryLimits::default(),
            )
            .unwrap();
            assert_eq!(
                until(&client, |s| matches!(s, LifecycleStatus::Blocked(_))).await,
                LifecycleStatus::Blocked(expected)
            );
            tokio::time::advance(Duration::from_secs(100)).await;
            settle().await;
            assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
            assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
            client.close().await.unwrap();
            pairs.cleanup().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn local_pump_panic_stops_replacement_and_keeps_shutdown_failure_visible() {
        let pairs = Pairs::new();
        let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
        ready(&client).await;
        pairs.fault.store(3, Ordering::SeqCst);
        pairs.notify(0, vec![1]).await;
        until(&client, |s| {
            matches!(s, LifecycleStatus::ShutdownIncomplete)
        })
        .await;
        tokio::time::advance(Duration::from_secs(100)).await;
        settle().await;
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
        assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
        assert!(client.close().await.is_err());
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_fences_pending_calls_and_never_replays_mutations() {
        let pairs = Pairs::new();
        let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
        assert!(matches!(
            client.call("/test.Service/Echo", vec![], 1000).await,
            Err(CallError::Unavailable { generation: None })
        ));
        let first = ready(&client).await;
        let old = client.snapshot().unwrap();
        let mut mutation = Box::pin(client.call("/test.Service/Mutate", vec![7], 5000));
        assert!(futures_util::poll!(&mut mutation).is_pending());
        settle().await;
        assert_eq!(pairs.mutations.load(Ordering::SeqCst), 1);
        client.network_available(true);
        let second = ready(&client).await;
        assert_eq!(second, first + 1);
        assert!(
            old.conn.is_closed(),
            "old runtime retired before new publication"
        );
        assert_eq!(old.conn.pending_len(), 0);
        assert!(
            matches!(mutation.await, Err(CallError::Unavailable { generation: Some(g) }) if g == first)
        );
        let result = client
            .call("/test.Service/Echo", vec![9], 1000)
            .await
            .unwrap();
        assert_eq!(
            result,
            GenerationValue {
                generation: second,
                value: vec![9]
            }
        );
        pairs.release.notify_waiters();
        settle().await;
        assert_eq!(pairs.mutations.load(Ordering::SeqCst), 1);
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 2);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn notifications_are_tagged_and_old_pending_or_buffered_delivery_is_rejected() {
        let pairs = Pairs::new();
        let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
        let first = ready(&client).await;
        pairs.notify(0, vec![1]).await;
        assert_eq!(client.next_notification().await.unwrap().generation, first);
        let mut pending = Box::pin(client.next_notification());
        assert!(futures_util::poll!(&mut pending).is_pending());
        client.pause();
        assert!(
            matches!(pending.await, Err(CallError::Unavailable { generation: Some(g) }) if g == first)
        );
        settle().await;
        client.resume();
        let second = ready(&client).await;
        let old = client.snapshot().unwrap();
        pairs.notify(1, vec![2]).await; // now buffered in the old core
        client.platform_wake();
        let third = ready(&client).await;
        assert_eq!(third, second + 1);
        assert!(
            matches!(client.forward(&old, old.conn.next_notification_with_loss()).await,
            Err(CallError::Unavailable { generation: Some(g) }) if g == second)
        );
        pairs.notify(2, vec![3]).await;
        assert_eq!(
            client.next_notification().await.unwrap(),
            GenerationValue {
                generation: third,
                value: Notification {
                    payload: Some(vec![3]),
                    dropped_count: 0,
                    dropped_bytes: 0
                },
            }
        );
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn unpolled_calls_and_notifications_cannot_wait_for_or_migrate_to_readiness() {
        let pairs = Pairs::new();
        let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
        let not_ready = client.call("/test.Service/Mutate", vec![0], 1000);
        let first = ready(&client).await;
        assert!(matches!(
            not_ready.await,
            Err(CallError::Unavailable { generation: None })
        ));
        let delayed_mutation = client.call("/test.Service/Mutate", vec![1], 1000);
        let delayed_notification = client.next_notification();
        pairs.notify(0, vec![1]).await;
        client.network_available(true);
        assert_eq!(ready(&client).await, first + 1);
        assert!(matches!(delayed_mutation.await,
            Err(CallError::Unavailable { generation: Some(g) }) if g == first));
        assert!(matches!(delayed_notification.await,
            Err(CallError::Unavailable { generation: Some(g) }) if g == first));
        assert_eq!(pairs.mutations.load(Ordering::SeqCst), 0);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn actual_core_readiness_resets_backoff_and_remote_close_is_generic() {
        let pairs = Pairs::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = ReconnectingClient::new(config(), {
            let pairs = pairs.clone();
            let calls = calls.clone();
            move || {
                let pairs = pairs.clone();
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n != 2 {
                        Err(Error::Closed)
                    } else {
                        pairs.connect().await
                    }
                }
            }
        })
        .unwrap();
        for _ in 0..2 {
            until(&client, |s| matches!(s, LifecycleStatus::Backoff { .. })).await;
            let LifecycleStatus::Backoff { delay, .. } = client.status() else {
                unreachable!()
            };
            tokio::time::advance(delay + Duration::from_millis(1)).await;
            settle().await;
        }
        assert_eq!(ready(&client).await, 1);
        let host = pairs.hosts.lock().unwrap().pop().unwrap();
        host.close().await;
        until(&client, |s| matches!(s, LifecycleStatus::Backoff { .. })).await;
        let LifecycleStatus::Backoff {
            attempts,
            delay,
            last_failure,
        } = client.status()
        else {
            unreachable!()
        };
        assert_eq!(attempts, 0);
        assert_eq!(last_failure, Failure::Closed);
        assert!((Duration::from_secs(5)..=Duration::from_secs(10)).contains(&delay));
        tokio::time::advance(delay + Duration::from_millis(1)).await;
        settle().await;
        assert!(matches!(
            client.status(),
            LifecycleStatus::Backoff { attempts: 1, .. }
        ));
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn generation_overflow_retires_instead_of_wrapping() {
        let pairs = Pairs::new();
        let mut client =
            ReconnectingClient::new(config(), stalled(Arc::new(Meter::default()))).unwrap();
        let mut handle = pairs.clone().connect().await.unwrap();
        let mut generation = u64::MAX;
        assert!(matches!(
            publish_ready(
                &client.shared,
                0,
                &mut generation,
                &handle,
                Instant::now() + Duration::from_secs(1)
            ),
            Publication::Exhausted
        ));
        assert_eq!(generation, u64::MAX);
        assert!(client.shared.lock().active.is_none());
        assert_eq!(
            client.status(),
            LifecycleStatus::Retired(Failure::GenerationExhausted)
        );
        assert!(retire(&client.shared, &mut handle, Duration::from_secs(1)).await);
        client.close().await.unwrap();
        pairs.cleanup().await;
    }

    #[tokio::test(start_paused = true)]
    async fn offline_and_drop_retire_real_owned_connection_without_redial() {
        let pairs = Pairs::new();
        let mut client = ReconnectingClient::new(config(), pairs.connector()).unwrap();
        ready(&client).await;
        let old = client.snapshot().unwrap();
        client.network_available(false);
        settle().await;
        assert!(old.conn.is_closed());
        assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(50)).await;
        settle().await;
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 1);
        assert_eq!(client.status(), LifecycleStatus::Offline);
        client.retry();
        let second = ready(&client).await;
        assert_eq!(second, old.generation + 1);
        let active = client.snapshot().unwrap();
        let owner = client.owner.take().unwrap();
        drop(client);
        owner.await.unwrap().unwrap();
        assert!(active.conn.is_closed());
        assert_eq!(pairs.live_clients.load(Ordering::SeqCst), 0);
        assert_eq!(pairs.dials.load(Ordering::SeqCst), 2);
        pairs.cleanup().await;
    }
}
