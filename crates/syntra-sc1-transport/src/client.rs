//! Opt-in experimental reconnecting SC1 client. This owns one dial loop and one
//! `ClientHandle`; the connector must build fresh security settings and credentials
//! on every invocation (in particular, `Secret32` is not cloned).
//!
//! Core readiness is not recovery readiness. After **every** generation the caller
//! must explicitly negotiate application recovery again. No requests, cipher/key
//! state, resume state, or notifications are replayed into a replacement connection.
//! Remote termination is observable only as generic `Closed` with the current pump
//! API; a remote authentication/protocol failure cannot be distinguished from a
//! transient close, so those closes receive only the bounded retry policy.
//!
//! Call `platform_wake` after a platform wake: it explicitly retires the old
//! connection. Neither this layer nor its monotonic timers claim suspend continuity.
use crate::{ClientHandle, Error};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};
use syntra_core::SyntraError;
use syntra_runtime::Initiator;
use syntra_secure_channel::Secret32;
use tokio::{
    sync::{watch, Notify},
    task::JoinHandle,
    time::{timeout_at, Instant},
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
    Framing,
    Io,
    Timeout,
    Closed,
    GenerationExhausted,
    RevisionExhausted,
}

impl Failure {
    fn of(error: &Error) -> Self {
        match error {
            Error::Configuration => Self::Configuration,
            Error::Authentication => Self::Authentication,
            Error::Channel(_) => Self::Channel,
            Error::Runtime => Self::Runtime,
            Error::Framing => Self::Framing,
            Error::Io(_) => Self::Io,
            Error::Timeout => Self::Timeout,
            Error::Closed => Self::Closed,
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
    /// Only SC1 + core runtime ready; recovery must be re-negotiated by caller.
    CoreReady(CoreReady),
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
}

#[derive(Clone)]
struct Active {
    generation: u64,
    revision: u64,
    conn: Initiator,
}

struct State {
    controls: Controls,
    active: Option<Active>,
}

struct Shared {
    state: Mutex<State>,
    changed: Notify,
    // Private watch: all reads are cloned in status_snapshot/StatusReceiver.
    // No read guard escapes or acquires state. Publications can therefore stay
    // serialized with controls under state, preserving revision/staleness checks
    // on every path (including ready, stop, retirement and owner teardown).
    status: watch::Sender<LifecycleStatus>,
}

impl Shared {
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
    }

    fn stop(&self) {
        let mut state = self.lock();
        if !state.controls.stopped {
            state.controls.stopped = true;
            state.active = None;
            self.status.send_replace(LifecycleStatus::Stopping);
        }
        self.changed.notify_one();
    }
}

/// Non-clone owner. Share with `Arc` for concurrent calls/controls if desired.
///
/// Connector futures must be cancellation-safe and cooperatively asynchronous:
/// dropping one must release its partial dial. Do not spawn detached work or block
/// in the factory/poll method. The existing SC1/WSS connector satisfies this model.
/// Tokio must keep running for asynchronous teardown, including after `Drop`.
pub struct ReconnectingClient {
    shared: Arc<Shared>,
    owner: Option<JoinHandle<Result<(), Error>>>,
    close_timeout: Duration,
}

impl ReconnectingClient {
    pub fn new<F, Fut>(config: ReconnectConfig, connector: F) -> Result<Self, Error>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
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
            state: Mutex::new(State {
                controls: Controls {
                    revision: 0,
                    retry_revision: 0,
                    permit_revision: None,
                    paused: config.start_paused,
                    online: config.initial_network_available,
                    stopped: false,
                },
                active: None,
            }),
            changed: Notify::new(),
            status,
        });
        let owner = tokio::spawn(run(shared.clone(), config.clone(), connector));
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

    fn control(&self, update: impl FnOnce(&mut Controls)) {
        let mut state = self.shared.lock();
        if state.controls.stopped {
            return;
        }
        // No wrap/ABA even for a pathological stream of coalesced controls.
        let Some(revision) = state.controls.revision.checked_add(1) else {
            state.controls.stopped = true;
            state.active = None;
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
        state.active = None;
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
        match timeout_at(Instant::now() + self.close_timeout, owner).await {
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

async fn retire(shared: &Shared, handle: ClientHandle, grace: Duration) -> bool {
    // Do not drop a close future on timeout: ClientHandle::close takes its
    // internal pump JoinHandle while joining it. Keep polling it to completion,
    // retaining ownership, and prohibit replacement if this budget was exceeded.
    let cleanup = async move {
        handle.conn.on_transport_lost().await;
        handle.close().await;
    };
    tokio::pin!(cleanup);
    if timeout_at(Instant::now() + grace, &mut cleanup)
        .await
        .is_ok()
    {
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
    cleanup.await;
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
        || Instant::now() >= deadline
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
    state.active = Some(Active {
        generation: next,
        revision,
        conn: handle.conn.clone(),
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
) -> Result<(), Error>
where
    F: Fn() -> Fut + Send + Sync + 'static,
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
        let controls = shared.lock().controls;
        if controls.stopped || controls.revision != revision {
            if let Some((_, handle)) = active.take() {
                outage.get_or_insert_with(Instant::now);
                if !retire(&shared, handle, config.close_timeout).await {
                    return Err(Error::Timeout);
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
            outage = Some(Instant::now());
            let (_, handle) = active.take().expect("active handle");
            if !retire(&shared, handle, config.close_timeout).await {
                return Err(Error::Timeout);
            }
            last_failure = Some(Failure::Closed);
            failures = failures.saturating_add(1);
            match jitter(config.base_backoff, config.max_backoff, failures) {
                Ok(delay) => next_attempt = Some(Instant::now() + delay),
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
        let now = Instant::now();
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
                _ = tokio::time::sleep_until(end) => {},
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
        let result = tokio::select! {
            biased;
            _ = shared.revised(revision) => continue,
            result = timeout_at(end, async { connector().await }) => result.unwrap_or(Err(Error::Timeout)),
        };
        let error = match result {
            Ok(handle) => {
                // A completed dial can race a control update. Never publish it
                // (nor reset budgets) if its inputs or readiness are obsolete.
                match publish_ready(&shared, revision, &mut generation, &handle, end) {
                    Publication::Obsolete => {
                        let expired = Instant::now() >= end;
                        if !retire(&shared, handle, config.close_timeout).await {
                            return Err(Error::Timeout);
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
                        active = Some((revision, handle));
                        attempts = 0;
                        failures = 0;
                        outage = None;
                        last_failure = None;
                        next_attempt = None;
                        continue;
                    }
                    Publication::Exhausted => {
                        if !retire(&shared, handle, config.close_timeout).await {
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
                Ok(delay) => next_attempt = Some(Instant::now() + delay),
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use syntra_runtime::{
        AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler, Handler,
        HandlerOutcome,
    };
    use syntra_secure_channel::{
        generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, ServerConfig,
        VerifiedIdentity,
    };
    use tokio::sync::mpsc;

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
                            Failure::Configuration => Error::Configuration,
                            Failure::Channel => {
                                Error::Channel(syntra_secure_channel::Error::Authentication)
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

    // Real ordered, bounded record pairs run the canonical SC1 and runtime
    // handshakes/pumps without an OS socket or wall-clock scheduling dependency.
    struct Reader(mpsc::Receiver<Vec<u8>>);
    struct Writer(mpsc::Sender<Vec<u8>>, Option<Arc<AtomicUsize>>);
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
        fn lookup(&self, _: &Context) -> Result<Secret32, syntra_secure_channel::Error> {
            Ok(Secret32::new([8; 32]))
        }
    }
    struct Pairs {
        security: ServerConfig,
        public_key: [u8; 32],
        hosts: Mutex<Vec<HostHandle>>,
        mutations: AtomicUsize,
        release: Notify,
        dials: AtomicUsize,
        live_clients: Arc<AtomicUsize>,
    }
    impl Pairs {
        fn new() -> Arc<Self> {
            let (private_key, public_key) = generate_server_key().unwrap();
            Arc::new(Self {
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
            })
        }

        async fn connect(self: Arc<Self>) -> Result<ClientHandle, Error> {
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
            let auth: Arc<dyn AuthenticatorFactory> = Arc::new(
                |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                    Ok(Arc::new(AllowAnonymous))
                },
            );
            let fixture = self.clone();
            let handler: Arc<dyn Handler> =
                Arc::new(FnHandler(move |method: String, payload, _| {
                    let fixture = fixture.clone();
                    async move {
                        if method == "/test.Service/Mutate" {
                            fixture.mutations.fetch_add(1, Ordering::SeqCst);
                            fixture.release.notified().await;
                        }
                        HandlerOutcome::Payload(payload)
                    }
                }));
            let limits = Limits {
                record_timeout: Duration::from_secs(3600),
                ..Limits::default()
            };
            let (client, host) = tokio::join!(
                pump::connect_records(
                    Reader(b_rx),
                    Writer(a_tx, Some(self.live_clients.clone())),
                    security,
                    vec![],
                    ConnectionConfig::default(),
                    limits.clone()
                ),
                pump::accept_records(
                    Reader(a_rx),
                    Writer(b_tx, None),
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
        let handle = pairs.clone().connect().await.unwrap();
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
        assert!(retire(&client.shared, handle, Duration::from_secs(1)).await);
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
