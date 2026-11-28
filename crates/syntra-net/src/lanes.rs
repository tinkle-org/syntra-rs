//! Two independently authenticated TCP connections to one provisioned address. No
//! wire purpose flag, implicit routing, fallback or RPC replay. Both lanes require
//! fresh returning-mode inputs. A media reservation is local capacity, not remote
//! authorization. Host policy must enforce shared principal quotas on both sockets.

use crate::{
    client::{
        CallError, GenerationValue, LifecycleStatus, Notification, ReconnectConfig,
        ReconnectingClient,
    },
    network::{
        CallOperation, DialFuture, ManagedClient, Network, NetworkConfig, Operation, ResultCredit,
        ShutdownReport, WaitError,
    },
    tcp, Error, EstablishmentBudget, Limits,
};
use futures_util::future::BoxFuture;
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{mpsc, Arc, Mutex, MutexGuard, TryLockError},
    task::{Context as TaskContext, Poll, Wake, Waker},
    time::{Duration, Instant},
};
use syntra_core::{
    proto::RecoveryBatch,
    secure_channel::{Carrier, ClientConfig, Mode},
    MAX_FRAME_BYTES,
};
use syntra_runtime::{
    recovery::{
        persistence::{DurableRecord, PersistenceScope, RecoveryPersistence},
        wire::RecoveryLimits,
        wire_client::{RecoveryClientError, RecoveryEvent, SubscribeIntent},
    },
    ConnectionConfig,
};
use tokio::sync::{watch, Notify, Semaphore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Interactive,
    Media,
}

#[derive(Clone, Debug)]
pub struct LaneConfig {
    /// Each lane gets its own pool with these limits, not half of a shared pool.
    pub network: NetworkConfig,
    pub reconnect: ReconnectConfig,
    pub runtime: ConnectionConfig,
    pub limits: Limits,
    /// Combined slots for interactive RPCs and notification observers, including
    /// completed but unread RPC results. Separate from network supervisor slots.
    pub interactive_operations: usize,
    /// Per owner: each observer reserves one maximum frame; each call also
    /// reserves its compact method and request. The interactive generation's
    /// ordinary push inbox is independently capped at this many payload bytes
    /// in maximum-frame slots, and at min(notification_capacity, interactive_operations)
    /// entries. Neither allowance includes transport buffers or caller-owned data.
    pub interactive_bytes: usize,
    pub media_idle: Duration,
    pub media_operations: usize,
    /// Logical request + maximum response payload bytes, including queued results.
    /// Transport frames, cipher buffers, runtime queues and caller copies are separate.
    pub media_bytes: usize,
}

impl Default for LaneConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            reconnect: ReconnectConfig {
                attempt_timeout: Duration::from_secs(15),
                reconnect_budget: Duration::from_secs(60),
                max_attempts: 5,
                base_backoff: Duration::from_millis(100),
                max_backoff: Duration::from_secs(2),
                close_timeout: Duration::from_secs(2),
                start_paused: false,
                initial_network_available: true,
            },
            runtime: ConnectionConfig::default(),
            limits: Limits::default(),
            interactive_operations: 32,
            interactive_bytes: 32 * MAX_FRAME_BYTES,
            media_idle: Duration::from_secs(15),
            media_operations: 8,
            media_bytes: 8 * MAX_FRAME_BYTES,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LaneError {
    #[error("lane is not ready; no payload admitted")]
    NotReady,
    #[error("media admission busy or at capacity")]
    Busy,
    #[error("invalid method, timeout or payload bounds")]
    Invalid,
    #[error("response exceeded admitted size (generation {generation}; do not replay)")]
    ResponseTooLarge { generation: u64 },
    #[error("call deadline elapsed before dispatch")]
    Expired,
    #[error(transparent)]
    Call(#[from] CallError),
    #[error(transparent)]
    Network(#[from] Error),
    #[error(transparent)]
    Wait(#[from] WaitError),
}

type MediaCompletion = (MediaReservation, Result<Box<[u8]>, LaneError>);

/// Like `network::Operation`, but retains the reservation with every completion,
/// including a queued RPC error. A successful read transfers it to MediaResponse.
pub struct MediaOperation(Operation<MediaCompletion>);

impl MediaOperation {
    fn consume((reservation, result): MediaCompletion) -> Result<MediaResponse, LaneError> {
        result.map(|bytes| MediaResponse { bytes, reservation })
    }
    pub fn wait(self, timeout: Duration) -> Result<Result<MediaResponse, LaneError>, WaitError> {
        self.0.wait(timeout).map(Self::consume)
    }
    pub fn try_take(&mut self) -> Option<Result<Result<MediaResponse, LaneError>, WaitError>> {
        self.0.try_take().map(|v| v.map(Self::consume))
    }
}
impl std::future::Future for MediaOperation {
    type Output = Result<Result<MediaResponse, LaneError>, WaitError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::Pin::new(&mut self.0)
            .poll(cx)
            .map(|v| v.map(Self::consume))
    }
}
type NotificationResult = Result<GenerationValue<Notification>, CallError>;

/// Unlike an RPC job this is a pull: only the observer polls the generation's
/// bounded inbox. A pending poll does not dequeue anything. Dropping the observer
/// (including a timed out `wait`) drops the receive future synchronously.
pub struct NotificationOperation {
    read: Option<BoxFuture<'static, NotificationResult>>,
}

impl NotificationOperation {
    pub fn try_take(&mut self) -> Option<Result<NotificationResult, WaitError>> {
        self.read.as_ref()?;
        match Pin::new(self).poll(&mut TaskContext::from_waker(Waker::noop())) {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        }
    }

    pub fn wait(mut self, timeout: Duration) -> Result<NotificationResult, WaitError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(WaitError::WouldBlockRuntime);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(WaitError::Timeout)?;
        struct Signal(mpsc::SyncSender<()>);
        impl Wake for Signal {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                let _ = self.0.try_send(());
            }
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let waker = Waker::from(Arc::new(Signal(tx)));
        loop {
            if let Poll::Ready(value) =
                Pin::new(&mut self).poll(&mut TaskContext::from_waker(&waker))
            {
                return value;
            }
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| WaitError::Timeout)?;
            if Instant::now() >= deadline {
                return Err(WaitError::Timeout);
            }
        }
    }
}

impl Future for NotificationOperation {
    type Output = Result<NotificationResult, WaitError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let Some(read) = &mut self.read else {
            return Poll::Ready(Err(WaitError::OwnerFailed));
        };
        let value = std::task::ready!(read.as_mut().poll(cx));
        self.read = None;
        Poll::Ready(Ok(value))
    }
}
type Inputs = Arc<dyn Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync>;
type Connector = Box<dyn Fn(EstablishmentBudget) -> DialFuture + Send + Sync>;

struct Provision {
    inputs: Inputs,
    // Set once, by the first valid INTERACTIVE provisioning (not a peer reply).
    // Only a fingerprint is retained; it includes the high-entropy returning AK.
    authority: watch::Sender<Option<[u8; 32]>>,
}

impl Provision {
    async fn fresh(&self, lane: Lane) -> Result<(ClientConfig, Vec<u8>), Error> {
        if lane == Lane::Media {
            self.authority
                .subscribe()
                .wait_for(Option::is_some)
                .await
                .map_err(|_| Error::Closed)?;
        }
        let (security, credential) = (self.inputs)()?;
        let key = security
            .authorization_key
            .as_ref()
            .ok_or(Error::Configuration)?;
        if security.context.mode != Mode::Returning
            || security.context.carrier != Carrier::Tcp
            || security.server_public_key == [0; 32]
            || key.expose().iter().fold(0, |a, b| a | b) == 0
            || credential.len() > syntra_core::MAX_CREDENTIAL_BYTES
        {
            return Err(Error::Configuration);
        }
        // Canonical, length-delimited context, then two fixed-size keys and one
        // terminal credential. Do not log or export this account binding.
        let identity: [u8; 32] = Sha256::new()
            .chain_update(b"Syntra LaneClient authority v1")
            .chain_update(
                security
                    .context
                    .encode()
                    .map_err(|_| Error::Configuration)?,
            )
            .chain_update(security.server_public_key)
            .chain_update(key.expose())
            .chain_update(&credential)
            .finalize()
            .into();
        if lane == Lane::Interactive {
            self.authority.send_if_modified(|bound| {
                if bound.is_none() {
                    *bound = Some(identity);
                    true
                } else {
                    false
                }
            });
        }
        if *self.authority.borrow() != Some(identity) {
            return Err(Error::Configuration);
        }
        Ok((security, credential))
    }
}

fn connector(
    address: SocketAddr,
    lane: Lane,
    inputs: Arc<Provision>,
    config: &LaneConfig,
) -> Connector {
    let (mut runtime, limits) = (config.runtime.clone(), config.limits.clone());
    if lane == Lane::Interactive {
        // Core enforces a count queue and a frame size. Leave overflow/loss
        // handling there rather than draining pushes into a second lane queue.
        runtime.notification_capacity = runtime
            .notification_capacity
            .min(config.interactive_operations)
            .min(config.interactive_bytes / MAX_FRAME_BYTES);
    }
    Box::new(move |budget| {
        let (inputs, runtime, limits) = (inputs.clone(), runtime.clone(), limits.clone());
        Box::pin(async move {
            let (security, credential) = budget.run(inputs.fresh(lane)).await??;
            let socket = budget
                .run(tokio::net::TcpStream::connect(address))
                .await??;
            socket.set_nodelay(true)?;
            tcp::connect_stream_with_budget(socket, security, credential, runtime, limits, budget)
                .await
        })
    })
}

struct State {
    paused: bool,
    online: bool,
    stopped: bool,
    demanded: bool,
    first_ready: bool,
    operations: usize,
    active_generation: u64,
    active: usize,
    bytes: usize,
    last_use: Instant,
}

impl State {
    fn observe(&mut self, generation: u64) {
        if self.active_generation != generation {
            self.active_generation = generation;
            self.active = 0;
        }
    }
}

struct Media {
    client: ManagedClient,
    state: Mutex<State>,
    changed: Notify,
    config: LaneConfig,
}

impl Media {
    fn finish(&self, s: &mut State, generation: u64) {
        if s.active_generation == generation {
            s.active -= 1;
            // Retirement can precede the idle worker observing the successor.
            if self.client.is_generation_current(generation) {
                s.last_use = Instant::now();
            }
        }
    }
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The idle decision and new admission serialize on the same lock. One timer
    /// task per owner; no timer or cleanup task is spawned by reservation Drop.
    async fn idle(self: Arc<Self>) {
        let mut lifecycle = self.client.subscribe_status();
        loop {
            let deadline = {
                let mut s = self.lock();
                let status = lifecycle.snapshot();
                if s.stopped || terminal(&status) {
                    return;
                }
                if let LifecycleStatus::CoreReady(r) = status {
                    s.observe(r.generation);
                    if s.first_ready {
                        // A slow cold dial gets a usable interval. Subsequent
                        // reconnects without demand cannot renew the idle timer.
                        s.first_ready = false;
                        s.last_use = Instant::now();
                    }
                    if s.demanded && s.active == 0 && !s.paused && s.online {
                        let until = s.last_use + self.config.media_idle;
                        if Instant::now() >= until {
                            if self
                                .client
                                .active()
                                .is_ok_and(|c| c.park_idle(r.generation))
                            {
                                s.demanded = false;
                            }
                            None
                        } else {
                            Some(until)
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            tokio::select! {
                _ = self.changed.notified() => {},
                changed = lifecycle.changed() => if changed.is_err() { return; },
                _ = async { if let Some(d) = deadline { tokio::time::sleep_until(d.into()).await } else { std::future::pending().await } } => {},
            }
        }
    }
}

fn terminal(s: &LifecycleStatus) -> bool {
    matches!(
        s,
        LifecycleStatus::Stopped
            | LifecycleStatus::Stopping
            | LifecycleStatus::ShutdownIncomplete
            | LifecycleStatus::Retired(_)
    )
}

/// Share the owner via Arc. Drop stops both pools; incomplete runtime owners
/// remain observable via `network::retired_networks`. No executor is needed.
pub struct LaneClient {
    interactive: ManagedClient,
    interactive_slots: Arc<Semaphore>,
    interactive_bytes: Arc<Semaphore>,
    media: Arc<Media>,
    interactive_pool: Network,
    media_pool: Network,
    recovery: Arc<Mutex<UpdateStatus>>,
}

impl LaneClient {
    /// Construct on an ordinary thread. Returns after supervisor registration,
    /// not remote readiness. The trusted provider must not block or spawn work.
    /// Its first valid interactive inputs pin the entire authority and account
    /// for this owner's lifetime. A key, pin, scope or credential change requires
    /// an explicitly provisioned new owner, not pause, retry or reconnection.
    /// The authority must not reassign an unchanged credential to another account.
    pub fn tcp(
        address: SocketAddr,
        config: LaneConfig,
        inputs: impl Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static,
    ) -> Result<Self, LaneError> {
        Self::open(
            address,
            config,
            Arc::new(inputs),
            ReconnectingClient::new_with_budget,
        )
    }

    fn open(
        address: SocketAddr,
        config: LaneConfig,
        inputs: Inputs,
        create: impl FnOnce(ReconnectConfig, Connector) -> Result<ReconnectingClient, Error>
            + Send
            + 'static,
    ) -> Result<Self, LaneError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(WaitError::WouldBlockRuntime.into());
        }
        config.limits.validate(&config.runtime)?;
        config.reconnect.validate()?;
        if address.port() == 0
            || address.ip().is_unspecified()
            || address.ip().is_multicast()
            || config.media_idle.is_zero()
            || config.media_idle > Duration::from_secs(86400)
            || config.media_operations == 0
            || config.media_bytes == 0
            || !(1..=Semaphore::MAX_PERMITS).contains(&config.interactive_operations)
            || !(MAX_FRAME_BYTES..=Semaphore::MAX_PERMITS).contains(&config.interactive_bytes)
            || config.media_operations > config.network.maximum_operations.saturating_sub(2)
            || config.reconnect.attempt_timeout > config.limits.attempt_timeout
        {
            return Err(Error::Configuration.into());
        }
        let interactive_pool = Network::new(config.network.clone())?;
        let media_pool = Network::new(config.network.clone())?;
        // Wait only for local registration. The media manager starts parked and
        // has exactly one dial loop across every cold start and idle close.
        let wait = config.reconnect.attempt_timeout;
        let inputs = Arc::new(Provision {
            inputs,
            authority: watch::channel(None).0,
        });
        let dial = connector(address, Lane::Media, inputs.clone(), &config);
        let media_client = media_pool
            .client_with_budget(
                ReconnectConfig {
                    start_paused: true,
                    ..config.reconnect.clone()
                },
                dial,
            )?
            .wait(wait)??;
        let dial = connector(address, Lane::Interactive, inputs, &config);
        let interactive = interactive_pool
            .client_from_factory(config.reconnect.clone(), move |cfg| create(cfg, dial))?
            .wait(wait)??;
        let state = Mutex::new(State {
            paused: config.reconnect.start_paused,
            online: config.reconnect.initial_network_available,
            stopped: false,
            demanded: false,
            first_ready: false,
            operations: 0,
            active_generation: 0,
            active: 0,
            bytes: 0,
            last_use: Instant::now(),
        });
        let interactive_bytes = Arc::new(Semaphore::new(config.interactive_bytes));
        let interactive_slots = Arc::new(Semaphore::new(config.interactive_operations));
        let media = Arc::new(Media {
            client: media_client,
            state,
            config,
            changed: Notify::new(),
        });
        drop(media.client.operation(media.clone().idle())?);
        Ok(Self {
            interactive,
            interactive_bytes,
            interactive_slots,
            media,
            interactive_pool,
            media_pool,
            recovery: Arc::new(Mutex::new(UpdateStatus::Disabled)),
        })
    }

    pub fn status(&self, lane: Lane) -> LifecycleStatus {
        self.client(lane).status()
    }
    pub fn subscribe_status(&self, lane: Lane) -> crate::client::StatusReceiver {
        self.client(lane).subscribe_status()
    }
    fn client(&self, lane: Lane) -> &ManagedClient {
        match lane {
            Lane::Interactive => &self.interactive,
            Lane::Media => &self.media.client,
        }
    }

    pub fn call_interactive(
        &self,
        method: String,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<CallOperation, Error> {
        if syntra_core::validate_method(&method).is_err() || payload.len() > MAX_FRAME_BYTES {
            return Err(Error::LocalProtocol(
                syntra_core::ErrorCode::InvalidArgument,
            ));
        }
        let credit = self
            .interactive_credit(method.len() + payload.len())
            .map_err(|_| Error::Configuration)?;
        let method = method.into_boxed_str().into_string();
        let payload = payload.into_boxed_slice().into_vec();
        self.interactive
            .call_with_credit(method, payload, timeout_ms, Some(credit))
    }

    fn interactive_credit(&self, request: usize) -> Result<ResultCredit, LaneError> {
        let charge = u32::try_from(MAX_FRAME_BYTES + request).map_err(|_| LaneError::Invalid)?;
        let slot = self
            .interactive_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| LaneError::Busy)?;
        let bytes = self
            .interactive_bytes
            .clone()
            .try_acquire_many_owned(charge)
            .map_err(|_| LaneError::Busy)?;
        Ok((slot, bytes))
    }

    /// Read ordinary updates only from the interactive connection. A receive is
    /// bound to its submission generation. Unread payloads stay in the runtime's
    /// bounded queue until `wait`, `try_take` or `.await` actually returns one.
    pub fn next_notification(&self) -> Result<NotificationOperation, LaneError> {
        let client = self.interactive.active()?;
        let generation = ready(&client.status()).ok_or(LaneError::NotReady)?;
        let credit = self.interactive_credit(0)?;
        // Don't retain an unpolled generation's Initiator (and its old inbox).
        let managed = self.interactive.clone();
        Ok(NotificationOperation {
            read: Some(Box::pin(async move {
                let _credit = credit;
                let current = managed.active().map_err(|_| unavailable(generation))?;
                let receive = current.next_notification();
                if !current.is_generation_current(generation) {
                    return Err(unavailable(generation));
                }
                drop(current); // never pin the reconnect supervisor across a user wait
                receive.await
            })),
        })
    }

    /// Non-waiting admission. Cold demand starts a dial and returns NotReady;
    /// retry *admission* after a ready status, never retry an uncertain RPC.
    /// Both sizes are bounds, not promises about an untrusted peer's wire frame.
    pub fn try_reserve_media(
        &self,
        request_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<MediaReservation, LaneError> {
        let media = &self.media;
        let charge = request_bytes
            .checked_add(max_response_bytes)
            .ok_or(LaneError::Invalid)?;
        if request_bytes > MAX_FRAME_BYTES
            || max_response_bytes > MAX_FRAME_BYTES
            || charge > media.config.media_bytes
        {
            return Err(LaneError::Invalid);
        }
        let mut s = match media.state.try_lock() {
            Ok(s) => s,
            Err(TryLockError::WouldBlock) => return Err(LaneError::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(Error::Closed.into()),
        };
        if s.stopped {
            return Err(Error::Closed.into());
        }
        if s.paused || !s.online {
            return Err(LaneError::NotReady);
        }
        if s.operations >= media.config.media_operations
            || charge > media.config.media_bytes - s.bytes
        {
            return Err(LaneError::Busy);
        }
        if !s.demanded {
            s.demanded = true;
            s.first_ready = true;
            media.client.active()?.apply_network_controls(false, true);
        }
        s.last_use = Instant::now();
        media.changed.notify_one();
        let generation = ready(&media.client.status()).ok_or(LaneError::NotReady)?;
        if !media.client.is_generation_current(generation) {
            return Err(LaneError::NotReady);
        }
        s.operations += 1;
        s.observe(generation);
        s.active += 1;
        s.bytes += charge;
        Ok(MediaReservation {
            media: media.clone(),
            generation,
            request_bytes,
            max_response_bytes,
            active: true,
        })
    }

    fn control(&self, change: impl FnOnce(&mut State)) {
        let mut s = self.media.lock();
        if s.stopped {
            return;
        }
        change(&mut s);
        if let Ok(c) = self.interactive.active() {
            c.apply_network_controls(s.paused, s.online);
        }
        if let Ok(c) = self.media.client.active() {
            c.apply_network_controls(s.paused || !s.demanded, s.online);
        }
        self.media.changed.notify_one();
    }
    pub fn pause(&self) {
        self.control(|s| s.paused = true);
    }
    pub fn resume(&self) {
        self.control(|s| s.paused = false);
    }
    pub fn network_available(&self, available: bool) {
        self.control(|s| s.online = available);
    }
    pub fn platform_wake(&self) {
        let s = self.media.lock();
        if !s.stopped {
            self.interactive.platform_wake();
            self.media.client.platform_wake();
        }
    }
    pub fn retry(&self) {
        let s = self.media.lock();
        if !s.stopped && !s.paused && s.online {
            self.interactive.retry();
            if s.demanded {
                self.media.client.retry();
            }
        }
    }
    pub fn stop(&self) {
        let mut s = self.media.lock();
        if !s.stopped {
            s.stopped = true;
            self.interactive_pool.stop();
            self.media_pool.stop();
            self.media.changed.notify_one();
        }
    }
    /// One total wait for both runtime owners. Zero duration is a poll. Complete
    /// includes runtime destruction; inspect failed_supervisors independently.
    pub fn shutdown(&self, timeout: Duration) -> ShutdownReport {
        let start = Instant::now();
        self.stop();
        let a = self
            .interactive_pool
            .wait_stopped(timeout.saturating_sub(start.elapsed()));
        let b = self
            .media_pool
            .wait_stopped(timeout.saturating_sub(start.elapsed()));
        ShutdownReport {
            complete: a.complete && b.complete,
            pending_operations: a.pending_operations + b.pending_operations,
            failed_supervisors: a.failed_supervisors.saturating_add(b.failed_supervisors),
        }
    }
}

impl Drop for LaneClient {
    fn drop(&mut self) {
        self.stop();
    }
}

fn ready(status: &LifecycleStatus) -> Option<u64> {
    match status {
        LifecycleStatus::CoreReady(r) | LifecycleStatus::RecoveryNegotiated(r) => {
            Some(r.generation)
        }
        _ => None,
    }
}
fn unavailable(generation: u64) -> CallError {
    CallError::Unavailable {
        generation: Some(generation),
    }
}

/// Non-cloneable. Dropping without submitting returns the entire charge. Once
/// submitted, the job (not the caller's Operation) owns the charge until failure
/// or transfer to the queued response. A timed-out waiter cannot free it early.
pub struct MediaReservation {
    media: Arc<Media>,
    generation: u64,
    request_bytes: usize,
    max_response_bytes: usize,
    active: bool,
}

impl MediaReservation {
    /// Lane-local generation selected at admission and fenced again at dispatch.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn call(
        mut self,
        method: &str,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<MediaOperation, LaneError> {
        if payload.len() > self.request_bytes || syntra_core::validate_method(method).is_err() {
            return Err(LaneError::Invalid);
        }
        let method = method.to_owned();
        let managed = self.media.client.clone();
        let active = managed.active()?;
        let generation = self.generation;
        if !active.is_generation_current(generation) {
            return Err(unavailable(generation).into());
        }
        let runtime = &self.media.config.runtime;
        let timeout = if timeout_ms == 0 {
            runtime.default_timeout
        } else {
            Duration::from_millis(timeout_ms.into())
        }
        .min(runtime.max_rpc_timeout);
        let deadline = Instant::now() + timeout;
        // Do not enqueue caller-owned spare capacity against a smaller reservation.
        let payload = if payload.capacity() > self.request_bytes {
            payload.into_boxed_slice().into_vec()
        } else {
            payload
        };
        Ok(MediaOperation(managed.operation(async move {
            let response = async {
                let left = u32::try_from(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .unwrap_or(u32::MAX);
                if left == 0 {
                    return Err(LaneError::Expired);
                }
                let call = active.call(&method, payload, left);
                if !active.is_generation_current(generation) {
                    return Err(unavailable(generation).into());
                }
                let response = call.await?;
                if response.value.len() > self.max_response_bytes {
                    return Err(LaneError::ResponseTooLarge { generation });
                }
                Ok(response.value.into_boxed_slice())
            }
            .await;
            // A queued result still consumes memory/operation credit, but it
            // does not need a live socket. Idle may park it from this point.
            {
                let mut s = self.media.lock();
                self.media.finish(&mut s, generation);
                self.active = false;
                self.media.changed.notify_one();
            }
            (self, response)
        })?))
    }
}

impl Drop for MediaReservation {
    fn drop(&mut self) {
        let mut s = self.media.lock();
        s.operations -= 1;
        s.bytes -= self.request_bytes + self.max_response_bytes;
        if self.active {
            self.media.finish(&mut s, self.generation);
        }
        self.media.changed.notify_one();
    }
}

/// Keep this object in downstream queues to retain admission through consumption.
pub struct MediaResponse {
    bytes: Box<[u8]>,
    reservation: MediaReservation,
}
impl MediaResponse {
    pub fn generation(&self) -> u64 {
        self.reservation.generation
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the allocation to the application, ending managed accounting.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes.into_vec()
    }
}

/// One explicitly provisioned durable update stream on the interactive lane.
/// Missing history or an incompatible stream generation fails closed, never
/// silently selecting a live-only baseline or replacing local state.
pub struct UpdateStream<S> {
    pub principal_scope: Vec<u8>,
    pub stable_stream: Vec<u8>,
    pub selector: Vec<u8>,
    pub store: Arc<Mutex<S>>,
    pub limits: RecoveryLimits,
}

/// Callbacks run serially on the interactive executor, outside lifecycle locks.
/// Futures must be nonblocking and cancellation-safe: control/loss discards the
/// old generation and the next restore reloads the full authoritative record.
/// Do not publish irreversible effects outside the store's conditional commit.
pub trait UpdateApplication: Send + Sync + 'static {
    fn restore(
        &self,
        generation: u64,
        record: DurableRecord,
    ) -> BoxFuture<'_, Result<(), RecoveryClientError>>;
    /// Compute the full replacement application state for this offered delta.
    /// The SDK persists it and its checkpoint atomically *before* confirming.
    fn apply(
        &self,
        generation: u64,
        batch: RecoveryBatch,
    ) -> BoxFuture<'_, Result<Vec<u8>, RecoveryClientError>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateStatus {
    Disabled,
    Waiting,
    Restoring(u64),
    Restored(u64),
    Failed(u64, RecoveryClientError),
}

impl LaneClient {
    pub fn tcp_with_updates<S: RecoveryPersistence + Send + Sync + 'static>(
        address: SocketAddr,
        config: LaneConfig,
        inputs: impl Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static,
        stream: UpdateStream<S>,
        app: Arc<dyn UpdateApplication>,
    ) -> Result<Self, LaneError> {
        let UpdateStream {
            principal_scope,
            stable_stream,
            selector,
            store,
            limits,
        } = stream;
        limits.validate().map_err(|_| Error::Configuration)?;
        PersistenceScope::new(principal_scope.clone(), stable_stream.clone())
            .map_err(|_| Error::Configuration)?;
        if selector.is_empty() || selector.len() > 1024 {
            return Err(Error::Configuration.into());
        }
        let owner = Self::open(address, config, Arc::new(inputs), move |cfg, dial| {
            ReconnectingClient::new_with_recovery_and_budget(
                cfg,
                dial,
                principal_scope,
                store,
                limits,
            )
        })?;
        *owner.recovery.lock().unwrap() = UpdateStatus::Waiting;
        let client = owner.interactive.clone();
        let progress = owner.recovery.clone();
        drop(owner.interactive.operation(async move {
            let mut watch = client.subscribe_status();
            loop {
                match watch.snapshot() {
                    LifecycleStatus::RecoveryNegotiated(r) => {
                        let generation = r.generation;
                        *progress.lock().unwrap() = UpdateStatus::Restoring(generation);
                        let run = drive_updates::<S>(&client, generation, &selector, &stable_stream, app.as_ref(), &progress);
                        use futures_util::FutureExt;
                        tokio::select! {
                            biased;
                            changed = watch.changed() => { if changed.is_err() { return; } continue; },
                            // A callback panic must not leave a live generation labelled restored.
                            result = std::panic::AssertUnwindSafe(run).catch_unwind() => {
                                let err = result.ok().and_then(Result::err).unwrap_or(RecoveryClientError::WorkerStopped);
                                *progress.lock().unwrap() = UpdateStatus::Failed(generation, err);
                            }
                        }
                    }
                    status if terminal(&status) => return,
                    _ => *progress.lock().unwrap() = UpdateStatus::Waiting,
                }
                if watch.changed().await.is_err() { return; }
            }
        })?);
        Ok(owner)
    }

    /// A status snapshot, not durable evidence to reuse after another generation.
    pub fn update_status(&self) -> UpdateStatus {
        let s = *self.recovery.lock().unwrap();
        match s {
            UpdateStatus::Restoring(g) | UpdateStatus::Restored(g) | UpdateStatus::Failed(g, _)
                if !self.interactive.is_generation_current(g) =>
            {
                UpdateStatus::Waiting
            }
            _ => s,
        }
    }
}

async fn drive_updates<S: RecoveryPersistence + Send + Sync + 'static>(
    client: &ManagedClient,
    generation: u64,
    selector: &[u8],
    stream: &[u8],
    app: &dyn UpdateApplication,
    progress: &Mutex<UpdateStatus>,
) -> Result<(), RecoveryClientError> {
    let active = client
        .active()
        .map_err(|_| RecoveryClientError::ReconnectRequired)?;
    let negotiated = active
        .recovery_client::<S>()
        .map_err(|_| RecoveryClientError::ReconnectRequired)?;
    if negotiated.generation != generation {
        return Err(RecoveryClientError::ReconnectRequired);
    }
    let mut profile = negotiated.value.lock().await;
    let sub = profile
        .subscribe(
            selector.to_vec(),
            stream.to_vec(),
            SubscribeIntent::ResumeDurable,
        )
        .await?;
    let h = sub.response.subscription_handle;
    let current = || {
        if active.is_generation_current(generation) {
            Ok(())
        } else {
            Err(RecoveryClientError::ReconnectRequired)
        }
    };
    current()?;
    app.restore(
        generation,
        sub.restored.ok_or(RecoveryClientError::InvalidState)?,
    )
    .await?;
    current()?;
    profile.catch_up(&h).await?;
    loop {
        let event = profile.next_event().await?;
        current()?;
        match event {
            RecoveryEvent::CaughtUp { handle } if handle == h => {
                *progress.lock().unwrap() = UpdateStatus::Restored(generation);
            }
            RecoveryEvent::Batch { batch } if batch.subscription_handle == h => {
                let full_state = app.apply(generation, batch).await?;
                current()?;
                profile.persist_and_confirm(&h, full_state).await?;
            }
            _ => return Err(RecoveryClientError::RecoveryNeeded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthenticatorFactory, HostHandle, RecoveryAuthenticatorFactory};
    use std::{
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
            Barrier,
        },
        thread,
    };
    use syntra_core::secure_channel::{
        generate_server_key, Context, KeyStore, Secret32, ServerConfig, VerifiedIdentity,
    };
    use syntra_runtime::recovery::{persistence::MemoryRecoveryStore, wire::*};
    use syntra_runtime::{
        AuthError, Authenticator, FnHandler, Handler, HandlerOutcome, Principal, StaticToken,
    };
    use tokio::{net::TcpListener, runtime::Runtime, sync::Semaphore};

    const WAIT: Duration = Duration::from_secs(5);
    const ECHO: &str = "/fixture.Lanes/Echo";

    fn until<T>(mut probe: impl FnMut() -> Option<T>) -> T {
        let end = Instant::now() + WAIT;
        loop {
            if let Some(value) = probe() {
                return value;
            }
            assert!(Instant::now() < end, "fixture wait expired");
            thread::sleep(Duration::from_millis(2));
        }
    }

    struct Key;
    impl KeyStore for Key {
        fn lookup(&self, ctx: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
            assert_eq!(ctx.epoch, 1);
            Ok(Secret32::new([3; 32]))
        }
    }

    struct Peer {
        listener: TcpListener,
        rt: Runtime,
        config: ServerConfig,
        pin: [u8; 32],
        dials: Arc<AtomicUsize>,
    }
    impl Peer {
        fn new() -> Self {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
            let (private_key, pin) = generate_server_key().unwrap();
            let config = ServerConfig {
                mode: Mode::Returning,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: b"fixture".to_vec(),
                private_key,
                store: Some(Arc::new(Key)),
            };
            Self {
                listener,
                rt,
                config,
                pin,
                dials: Default::default(),
            }
        }
        fn address(&self) -> SocketAddr {
            self.listener.local_addr().unwrap()
        }
        fn inputs(
            &self,
        ) -> impl Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static + use<>
        {
            let (pin, dials) = (self.pin, self.dials.clone());
            move || {
                dials.fetch_add(1, SeqCst);
                Ok((
                    ClientConfig {
                        context: Context {
                            mode: Mode::Returning,
                            carrier: Carrier::Tcp,
                            server_key_id: 1,
                            scope: b"fixture".to_vec(),
                            handle: [1; 8],
                            epoch: 1,
                        },
                        server_public_key: pin,
                        authorization_key: Some(Secret32::new([3; 32])),
                    },
                    vec![77],
                ))
            }
        }
        fn accept(
            &self,
            handler: Arc<dyn Handler>,
            recovery: Option<Arc<RecoveryService>>,
        ) -> HostHandle {
            let factory = |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                Ok(Arc::new(StaticToken::new(vec![77], "caller")))
            };
            let auth: Arc<dyn AuthenticatorFactory> = match recovery {
                Some(service) => Arc::new(RecoveryAuthenticatorFactory::new(factory, service)),
                None => Arc::new(factory),
            };
            self.rt.block_on(async {
                tokio::time::timeout(WAIT, async {
                    let (socket, _) = self.listener.accept().await.unwrap();
                    tcp::accept_stream(
                        socket,
                        &self.config,
                        auth,
                        handler,
                        Default::default(),
                        Default::default(),
                    )
                    .await
                    .unwrap()
                })
                .await
                .unwrap()
            })
        }
    }
    fn echo() -> Arc<dyn Handler> {
        Arc::new(FnHandler(
            |_, p, _| async move { HandlerOutcome::Payload(p) },
        ))
    }
    fn first_demand(c: &LaneClient) {
        until(|| match c.try_reserve_media(1, 1) {
            Err(LaneError::Busy) => None,
            Err(LaneError::NotReady) => Some(()),
            _ => panic!("expected cold admission"),
        });
    }
    fn reserve(c: &LaneClient, req: usize, resp: usize) -> MediaReservation {
        until(|| match c.try_reserve_media(req, resp) {
            Ok(r) => Some(r),
            Err(LaneError::Busy | LaneError::NotReady) => None,
            Err(e) => panic!("{e}"),
        })
    }
    fn stopped(c: &LaneClient) {
        assert_eq!(
            c.shutdown(WAIT),
            ShutdownReport {
                complete: true,
                pending_operations: 0,
                failed_supervisors: 0
            }
        );
    }

    #[test]
    fn interactive_unread_calls_and_observers_share_both_budgets() {
        for (slots, bytes) in [
            (2, 5 * MAX_FRAME_BYTES),
            (5, 2 * MAX_FRAME_BYTES + ECHO.len() + 1),
        ] {
            let peer = Peer::new();
            let c = LaneClient::tcp(
                peer.address(),
                LaneConfig {
                    interactive_operations: slots,
                    interactive_bytes: bytes,
                    ..Default::default()
                },
                peer.inputs(),
            )
            .unwrap();
            let _host = peer.accept(echo(), None);
            until(|| ready(&c.status(Lane::Interactive)));
            let mut tiny = Vec::with_capacity(5 * MAX_FRAME_BYTES);
            tiny.push(1);
            let mut method = String::with_capacity(MAX_FRAME_BYTES);
            method.push_str(ECHO);
            let mut unread = c.call_interactive(method, tiny, 1000).unwrap();
            until(|| (c.interactive_pool.report().pending_operations == 1).then_some(()));
            let observer = c.next_notification().unwrap();
            assert_eq!(
                c.interactive_bytes.available_permits(),
                bytes - (2 * MAX_FRAME_BYTES + ECHO.len() + 1)
            );
            assert!(matches!(c.next_notification(), Err(LaneError::Busy)));
            assert!(matches!(
                c.call_interactive(ECHO.into(), vec![], 1000),
                Err(Error::Configuration)
            ));
            assert_eq!(unread.try_take().unwrap().unwrap().unwrap().value, [1]);
            // Consuming, not dropping the handle, is the release point.
            let next = c.next_notification().unwrap();
            drop((observer, next));
            assert_eq!(c.interactive_bytes.available_permits(), bytes);
            assert_eq!(c.interactive_slots.available_permits(), slots);
            stopped(&c);
        }
    }

    #[test]
    fn unsolicited_inbox_respects_the_interactive_byte_and_slot_ceilings() {
        for (slots, bytes) in [(2, 5 * MAX_FRAME_BYTES), (5, 2 * MAX_FRAME_BYTES)] {
            let peer = Peer::new();
            let c = LaneClient::tcp(
                peer.address(),
                LaneConfig {
                    interactive_operations: slots,
                    interactive_bytes: bytes,
                    ..Default::default()
                },
                peer.inputs(),
            )
            .unwrap();
            let host = peer.accept(echo(), None);
            until(|| ready(&c.status(Lane::Interactive)));
            peer.rt.block_on(async {
                for i in 0..3 {
                    host.host.notify(vec![i; 8]).await.unwrap();
                }
            });
            c.call_interactive(ECHO.into(), vec![], 1000)
                .unwrap()
                .wait(WAIT)
                .unwrap()
                .unwrap();
            for i in 0..2 {
                let note = c
                    .next_notification()
                    .unwrap()
                    .wait(WAIT)
                    .unwrap()
                    .unwrap()
                    .value;
                assert_eq!((note.dropped_count, note.dropped_bytes), (1, 8));
                assert_eq!(note.payload, Some(vec![i; 8]));
            }
            stopped(&c);
        }
    }

    #[test]
    fn timed_out_mutation_keeps_credit_and_executes_once() {
        let peer = Peer::new();
        let c = LaneClient::tcp(
            peer.address(),
            LaneConfig {
                interactive_operations: 1,
                ..Default::default()
            },
            peer.inputs(),
        )
        .unwrap();
        let gate = Arc::new(Semaphore::new(0));
        let effects = Arc::new(AtomicUsize::new(0));
        let (g, n) = (gate.clone(), effects.clone());
        let _host = peer.accept(
            Arc::new(FnHandler(move |_, p, _| {
                let (g, n) = (g.clone(), n.clone());
                async move {
                    g.acquire().await.unwrap().forget();
                    n.fetch_add(1, SeqCst);
                    HandlerOutcome::Payload(p)
                }
            })),
            None,
        );
        until(|| ready(&c.status(Lane::Interactive)));
        let op = c.call_interactive(ECHO.into(), vec![7], 3000).unwrap();
        assert!(matches!(op.wait(Duration::ZERO), Err(WaitError::Timeout)));
        assert!(matches!(c.next_notification(), Err(LaneError::Busy)));
        gate.add_permits(1);
        until(|| (c.interactive_slots.available_permits() == 1).then_some(()));
        assert_eq!(effects.load(SeqCst), 1);
        stopped(&c);
    }

    #[test]
    fn abandoned_notification_observers_do_not_consume_updates_or_hold_shutdown() {
        let peer = Peer::new();
        let c = LaneClient::tcp(peer.address(), Default::default(), peer.inputs()).unwrap();
        let host = peer.accept(echo(), None);
        let generation = until(|| ready(&c.status(Lane::Interactive)));
        assert!(matches!(
            c.next_notification()
                .unwrap()
                .wait(Duration::from_millis(10)),
            Err(WaitError::Timeout)
        ));
        let mut abandoned = c.next_notification().unwrap();
        assert!(abandoned.try_take().is_none());
        peer.rt.block_on(host.host.notify(vec![9])).unwrap();
        // Same host writer FIFO: the update is in the inbox before we abandon
        // an already-woken but unpolled read. It must not have been dequeued.
        c.call_interactive(ECHO.into(), vec![], 1000)
            .unwrap()
            .wait(WAIT)
            .unwrap()
            .unwrap();
        drop(abandoned);
        let delivered = c.next_notification().unwrap().wait(WAIT).unwrap().unwrap();
        assert_eq!(
            (delivered.generation, delivered.value.payload),
            (generation, Some(vec![9]))
        );
        let mut late = c.next_notification().unwrap();
        assert!(late.try_take().is_none());
        stopped(&c);
        assert!(
            matches!(late.try_take(), Some(Ok(Err(CallError::Unavailable {generation:Some(g)}))) if g==generation)
        );
    }

    #[test]
    fn retired_reservations_keep_bytes_but_cannot_pin_or_retire_the_new_socket() {
        let peer = Peer::new();
        let idle = Duration::from_millis(120);
        let c = LaneClient::tcp(
            peer.address(),
            LaneConfig {
                media_idle: idle,
                media_bytes: 18,
                ..Default::default()
            },
            peer.inputs(),
        )
        .unwrap();
        let _interactive = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Interactive)));
        first_demand(&c);
        let first = peer.accept(echo(), None);
        let old_a = reserve(&c, 1, 7);
        let old_b = reserve(&c, 1, 7);
        peer.rt.block_on(first.close());
        let _second = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Media)).filter(|g| *g > old_a.generation));
        let fresh = reserve(&c, 1, 1);
        assert_eq!(c.media.lock().bytes, 18);
        assert!(matches!(c.try_reserve_media(0, 1), Err(LaneError::Busy)));
        let last_use = c.media.lock().last_use;
        drop(old_a);
        assert_eq!(c.media.lock().last_use, last_use);
        thread::sleep(2 * idle);
        assert_eq!(ready(&c.status(Lane::Media)), Some(fresh.generation));
        drop(fresh);
        until(|| (c.status(Lane::Media) == LifecycleStatus::Paused).then_some(()));
        assert_eq!(c.media.lock().bytes, 8);
        drop(old_b);
        assert_eq!(c.media.lock().bytes, 0);
        stopped(&c);
    }

    #[test]
    fn only_interactive_inputs_can_pin_and_every_binding_component_is_immutable() {
        let peer = Peer::new();
        let inputs = peer.inputs();
        let field = Arc::new(AtomicUsize::new(0));
        let change = field.clone();
        let provision = Provision {
            authority: watch::channel(None).0,
            inputs: Arc::new(move || {
                let (mut cfg, mut credential) = inputs()?;
                match change.load(SeqCst) {
                    0 => (),
                    1 => cfg.server_public_key[0] ^= 1,
                    2 => cfg.context.scope.push(42),
                    3 => cfg.context.server_key_id += 1,
                    4 => cfg.context.handle[0] ^= 1,
                    5 => cfg.context.epoch += 1,
                    6 => cfg.authorization_key = Some(Secret32::new([5; 32])),
                    7 => credential.push(42),
                    _ => unreachable!(),
                }
                Ok((cfg, credential))
            }),
        };
        peer.rt.block_on(async {
            let media = provision.fresh(Lane::Media);
            tokio::pin!(media);
            assert!(futures_util::poll!(&mut media).is_pending());
            assert_eq!(peer.dials.load(SeqCst), 0);
            provision.fresh(Lane::Interactive).await.unwrap();
            media.await.unwrap();
            for i in 1..=7 {
                field.store(i, SeqCst);
                for lane in [Lane::Media, Lane::Interactive] {
                    assert!(
                        matches!(provision.fresh(lane).await, Err(Error::Configuration)),
                        "field {i}, lane {lane:?}"
                    );
                }
            }
        });
    }

    #[test]
    fn changed_account_is_rejected_before_either_replacement_dials() {
        let peer = Peer::new();
        let inputs = peer.inputs();
        let changed = Arc::new(AtomicBool::new(false));
        let switch = changed.clone();
        let c = LaneClient::tcp(peer.address(), Default::default(), move || {
            let (cfg, mut cred) = inputs()?;
            if switch.load(SeqCst) {
                cred.push(1);
            }
            Ok((cfg, cred))
        })
        .unwrap();
        let _interactive = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Interactive)));
        first_demand(&c);
        let _media = peer.accept(echo(), None);
        drop(reserve(&c, 1, 1));
        c.pause();
        changed.store(true, SeqCst);
        c.resume();
        for _ in 0..2 {
            for lane in [Lane::Interactive, Lane::Media] {
                until(|| {
                    (c.status(lane) == LifecycleStatus::Blocked(crate::Failure::Configuration))
                        .then_some(())
                });
            }
            c.retry();
        }
        assert!(peer
            .rt
            .block_on(async {
                tokio::time::timeout(Duration::from_millis(40), peer.listener.accept()).await
            })
            .is_err());
        stopped(&c);
    }

    #[test]
    fn incomplete_shutdown_retains_the_runtime_until_a_stalled_provider_returns() {
        let (entered, started) = std::sync::mpsc::sync_channel(1);
        let (release, gate) = std::sync::mpsc::sync_channel(1);
        let gate = Mutex::new(gate);
        let c = LaneClient::tcp(
            "127.0.0.1:1".parse().unwrap(),
            Default::default(),
            move || {
                // Deliberate violation of the nonblocking callback contract. Shutdown
                // cannot attest completion or destroy the runtime under this worker.
                entered.send(()).unwrap();
                gate.lock().unwrap().recv_timeout(WAIT).unwrap();
                Err(Error::Configuration)
            },
        )
        .unwrap();
        started.recv_timeout(WAIT).unwrap();
        assert!(!c.shutdown(Duration::ZERO).complete);
        c.resume();
        c.retry();
        assert!(matches!(
            c.try_reserve_media(0, 0),
            Err(LaneError::Network(Error::Closed) | LaneError::Busy)
        ));
        release.send(()).unwrap();
        stopped(&c);
    }

    #[test]
    fn cold_demand_is_single_flight_and_idle_close_cannot_invalidate_a_reservation() {
        let peer = Peer::new();
        let mut cfg = LaneConfig {
            media_idle: Duration::from_millis(100),
            ..Default::default()
        };
        cfg.reconnect.reconnect_budget = Duration::from_millis(600);
        let c = LaneClient::tcp(peer.address(), cfg, peer.inputs()).unwrap();
        let _interactive = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Interactive)));
        assert_eq!(peer.dials.load(SeqCst), 1);
        let barrier = Barrier::new(8);
        thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    barrier.wait();
                    first_demand(&c);
                });
            }
        });
        let media = peer.accept(echo(), None);
        let held = reserve(&c, 1, 1);
        let first = held.generation;
        thread::sleep(Duration::from_millis(200));
        assert_eq!(ready(&c.status(Lane::Media)), Some(first));
        let response = held
            .call(ECHO, vec![42], 1000)
            .unwrap()
            .wait(WAIT)
            .unwrap()
            .unwrap();
        assert_eq!(response.bytes(), &[42]);
        drop(response);
        until(|| (c.status(Lane::Media) == LifecycleStatus::Paused).then_some(()));
        assert_eq!(peer.dials.load(SeqCst), 2);
        until(|| media.is_closed().then_some(()));
        // Healthy, intentional idleness must not spend a reconnect outage budget.
        thread::sleep(Duration::from_millis(650));
        first_demand(&c);
        let _second = peer.accept(echo(), None);
        assert!(reserve(&c, 0, 0).generation > first);
        assert_eq!(peer.dials.load(SeqCst), 3);
        stopped(&c);
    }

    #[test]
    fn media_load_does_not_block_updates_and_queued_responses_stay_charged() {
        let peer = Peer::new();
        let c = LaneClient::tcp(
            peer.address(),
            LaneConfig {
                media_bytes: 18,
                media_operations: 2,
                ..Default::default()
            },
            peer.inputs(),
        )
        .unwrap();
        let interactive = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Interactive)));
        first_demand(&c);
        let gate = Arc::new(Semaphore::new(0));
        let entered = Arc::new(AtomicUsize::new(0));
        let (g, n) = (gate.clone(), entered.clone());
        let _media = peer.accept(
            Arc::new(FnHandler(move |_, _, _| {
                let g = g.clone();
                n.fetch_add(1, SeqCst);
                async move {
                    g.acquire().await.unwrap().forget();
                    HandlerOutcome::Payload(vec![17; 8])
                }
            })),
            None,
        );
        let submit = || reserve(&c, 1, 8).call(ECHO, vec![5], 4000).unwrap();
        let mut keep = submit();
        drop(submit()); // abandon the waiter while the job is still running
        until(|| (entered.load(SeqCst) == 2).then_some(()));
        assert!(matches!(c.try_reserve_media(0, 0), Err(LaneError::Busy)));
        let update = c.next_notification().unwrap();
        peer.rt.block_on(interactive.host.notify(vec![99])).unwrap();
        assert_eq!(
            update.wait(WAIT).unwrap().unwrap().value.payload,
            Some(vec![99])
        );
        assert_eq!(
            c.call_interactive(ECHO.into(), vec![7], 1000)
                .unwrap()
                .wait(WAIT)
                .unwrap()
                .unwrap()
                .value,
            vec![7]
        );
        gate.add_permits(2);
        until(|| (c.media.lock().operations == 1).then_some(()));
        assert!(
            matches!(c.try_reserve_media(1, 9), Err(LaneError::Busy)),
            "queued reply lost its charge"
        );
        let response = until(|| keep.try_take()).unwrap().unwrap();
        assert_eq!(response.bytes(), &[17; 8]);
        assert!(matches!(c.try_reserve_media(1, 9), Err(LaneError::Busy)));
        drop(response);
        gate.add_permits(1);
        assert!(matches!(
            reserve(&c, 1, 7)
                .call(ECHO, vec![5], 1000)
                .unwrap()
                .wait(WAIT)
                .unwrap(),
            Err(LaneError::ResponseTooLarge { .. })
        ));
        stopped(&c);
    }

    #[test]
    fn blocked_media_never_downgrades_and_stale_reservations_do_not_dispatch() {
        let peer = Peer::new();
        let inputs = peer.inputs();
        let bad = Arc::new(AtomicBool::new(false));
        let b = bad.clone();
        let c = LaneClient::tcp(peer.address(), Default::default(), move || {
            let (mut cfg, cred) = inputs()?;
            if b.load(SeqCst) {
                cfg.context.mode = Mode::Bootstrap;
            }
            Ok((cfg, cred))
        })
        .unwrap();
        let _int = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Interactive)));
        bad.store(true, SeqCst);
        first_demand(&c);
        until(|| {
            (c.status(Lane::Media) == LifecycleStatus::Blocked(crate::Failure::Configuration))
                .then_some(())
        });
        assert_eq!(peer.dials.load(SeqCst), 2);
        assert_eq!(
            c.call_interactive(ECHO.into(), vec![], 1000)
                .unwrap()
                .wait(WAIT)
                .unwrap()
                .unwrap()
                .value,
            vec![]
        );
        c.network_available(false);
        c.retry();
        c.resume();
        assert!(matches!(
            c.try_reserve_media(1, 1),
            Err(LaneError::NotReady | LaneError::Busy)
        ));
        bad.store(false, SeqCst);
        c.network_available(true);
        // Let the interactive online dial finish before explicitly replacing it.
        let _online = peer.accept(echo(), None);
        until(|| ready(&c.status(Lane::Interactive)));
        c.retry();
        let _a = peer.accept(echo(), None);
        let _b = peer.accept(echo(), None);
        let stale = reserve(&c, 1, 1);
        c.pause();
        assert!(matches!(
            stale.call(ECHO, vec![9], 1000),
            Err(LaneError::Call(CallError::Unavailable { .. }))
        ));
        stopped(&c);
        assert!(matches!(
            c.try_reserve_media(1, 1),
            Err(LaneError::Network(Error::Closed))
        ));
    }

    // A fixed, one-delta history exercises actual subscribe/catch-up/confirm
    // across the encrypted connection. The memory store is a CAS fixture, not
    // evidence about a deployment's disk durability.
    struct History;
    impl RecoverySource for History {
        fn authorize(
            &self,
            p: &Principal,
            selector: &[u8],
            _: AuthorizationHook,
        ) -> Result<(), ProviderError> {
            if p.subject == "caller" && selector == b"stream" {
                Ok(())
            } else {
                Err(ProviderError::PermissionDenied)
            }
        }
        fn capture(&self, _: &Principal, selector: &[u8]) -> Result<ProviderStream, ProviderError> {
            ProviderStream::new(selector.to_vec(), 3, b"to".to_vec())
        }
        fn current_generation(&self, _: &Principal, _: &[u8]) -> Result<u64, ProviderError> {
            Ok(3)
        }
        fn validate_issued(
            &self,
            _: &Principal,
            _: &ProviderStream,
            c: &[u8],
        ) -> Result<(), ProviderError> {
            if c == b"from" || c == b"to" {
                Ok(())
            } else {
                Err(ProviderError::FailedPrecondition)
            }
        }
        fn replay(
            &self,
            _: &Principal,
            _: &ProviderStream,
            from: &[u8],
            _: &[u8],
            _: PageBudget,
        ) -> Result<ProviderPage, ProviderError> {
            assert_eq!(from, b"from");
            ProviderPage::new(
                vec![StoredBatch {
                    generation: 3,
                    predecessor: from.to_vec(),
                    result: b"to".to_vec(),
                    payload: vec![2],
                }],
                b"to".to_vec(),
                vec![],
            )
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
    struct App {
        loaded: Mutex<Vec<DurableRecord>>,
        applying: AtomicBool,
        resume: Semaphore,
    }
    impl UpdateApplication for App {
        fn restore(
            &self,
            _: u64,
            record: DurableRecord,
        ) -> BoxFuture<'_, Result<(), RecoveryClientError>> {
            self.loaded.lock().unwrap().push(record);
            Box::pin(async { Ok(()) })
        }
        fn apply(
            &self,
            _: u64,
            b: RecoveryBatch,
        ) -> BoxFuture<'_, Result<Vec<u8>, RecoveryClientError>> {
            Box::pin(async move {
                assert_eq!(b.batch_payload, &[2]);
                self.applying.store(true, SeqCst);
                self.resume.acquire().await.unwrap().forget();
                Ok(vec![1, 2])
            })
        }
    }

    #[test]
    fn restored_requires_durable_application_and_caught_up_on_each_generation() {
        let peer = Peer::new();
        let app = Arc::new(App {
            loaded: Mutex::default(),
            applying: false.into(),
            resume: Semaphore::new(0),
        });
        let store = Arc::new(Mutex::new(MemoryRecoveryStore::new()));
        let scope = PersistenceScope::new(b"caller".to_vec(), b"stream".to_vec()).unwrap();
        let initial = DurableRecord {
            generation: 3,
            checkpoint: b"from".to_vec(),
            application_state: vec![1],
        };
        store
            .lock()
            .unwrap()
            .commit(&scope, None, initial.clone())
            .unwrap();
        let service = RecoveryService::new(Arc::new(History), Default::default()).unwrap();
        let c = LaneClient::tcp_with_updates(
            peer.address(),
            Default::default(),
            peer.inputs(),
            UpdateStream {
                principal_scope: b"caller".to_vec(),
                stable_stream: b"stream".to_vec(),
                selector: b"stream".to_vec(),
                store: store.clone(),
                limits: Default::default(),
            },
            app.clone(),
        )
        .unwrap();
        let _first = peer.accept(echo(), Some(service.clone()));
        until(|| app.applying.load(SeqCst).then_some(()));
        assert_eq!(
            app.loaded.lock().unwrap().as_slice(),
            std::slice::from_ref(&initial)
        );
        assert_eq!(store.lock().unwrap().load(&scope).unwrap(), Some(initial));
        assert_eq!(c.update_status(), UpdateStatus::Restoring(1));
        app.resume.add_permits(1);
        until(|| (c.update_status() == UpdateStatus::Restored(1)).then_some(()));
        let full = store.lock().unwrap().load(&scope).unwrap().unwrap();
        assert_eq!(full.checkpoint, b"to");
        assert_eq!(full.application_state, &[1, 2]);
        c.pause();
        assert_eq!(c.update_status(), UpdateStatus::Waiting);
        c.resume();
        let _second = peer.accept(echo(), Some(service));
        until(|| (c.update_status() == UpdateStatus::Restored(2)).then_some(()));
        assert_eq!(app.loaded.lock().unwrap().get(1), Some(&full));
        c.platform_wake();
        let _mandatory_only = peer.accept(echo(), None);
        until(|| {
            (c.status(Lane::Interactive)
                == LifecycleStatus::Blocked(crate::Failure::RecoveryUnavailable))
            .then_some(())
        });
        assert_eq!(c.update_status(), UpdateStatus::Waiting);
        stopped(&c);
    }
}
