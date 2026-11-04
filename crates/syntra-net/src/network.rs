//! Owned native networking. No caller Tokio runtime is needed, including for RPCs.
//!
//! `Network` owns a configured I/O/time-enabled worker pool. Clients delegate all
//! reconnection, jitter and generation fencing to `ReconnectingClient`; listeners
//! use the carrier drivers and retain whole host handles until teardown completes.
//! Connector futures must obey the cancellation/nonblocking contract in `client`.
//! No operation is replayed. Dropping an operation only discards its result.
//!
//! Shutdown is abortive, not an assertion about remote effects. A timed-out shutdown
//! retains the runtime and its supervisors. Drop transfers the OS join owner to a
//! process registry, observable/reapable with `retired_networks`. Runtime destruction
//! happens only on its dedicated OS owner thread, never on a Tokio worker. A stuck
//! synchronous callback can therefore keep an explicitly reported owner alive.

use crate::client::{
    CallError, GenerationValue, LifecycleStatus, ReconnectConfig, ReconnectingClient,
};
#[cfg(feature = "http")]
use crate::http;
use crate::{
    tcp, AuthenticatorFactory, ClientHandle, Error, EstablishmentBudget, HostHandle, Limits,
    TransportShutdown,
};
#[cfg(feature = "websocket")]
use crate::{tls, websocket};
use futures_util::task::AtomicWaker;
use std::{
    collections::BTreeMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak},
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};
use syntra_core::secure_channel::{Carrier, ClientConfig, ServerConfig};
use syntra_runtime::{ConnectionConfig, Handler, Host, ShutdownPhase};
use tokio::{
    runtime::{Builder, Handle},
    sync::{broadcast, mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}

/// Bounds are counts, not byte-memory limits. Application callbacks must not block
/// async workers. Blocking pool threads are separately bounded and joined on exit.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub worker_threads: usize,
    pub max_blocking_threads: usize,
    /// Shared bound for client/listener supervisors and outstanding RPC jobs.
    /// Exhaustion rejects admission before work starts with `Error::Configuration`.
    pub maximum_operations: usize,
    pub event_capacity: usize,
    pub close_grace: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            worker_threads: 2,
            max_blocking_threads: 4,
            maximum_operations: 256,
            event_capacity: 128,
            close_grace: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkEvent {
    ClientStarted,
    ClientStopped,
    ListenerStarted(SocketAddr),
    ConnectionReady(SocketAddr),
    ConnectionRejected(SocketAddr),
    ListenerStopped(SocketAddr),
    Stopping,
    Stopped,
    /// A supervisor panicked or an owned service reported task failure.
    SupervisorFailed,
}

/// Bounded event log; lag is explicit in Tokio's `Lagged` error. Client lifecycle
/// state is separately available through its owned status snapshots/watch.
pub struct Events(broadcast::Receiver<NetworkEvent>);
impl Events {
    pub fn try_recv(&mut self) -> Result<NetworkEvent, broadcast::error::TryRecvError> {
        self.0.try_recv()
    }
    pub async fn recv(&mut self) -> Result<NetworkEvent, broadcast::error::RecvError> {
        self.0.recv().await
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Includes runtime destruction and completion of its blocking workers.
    pub complete: bool,
    pub pending_operations: usize,
    pub failed_supervisors: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkStatus {
    pub paused: bool,
    pub network_available: bool,
    pub stopping: bool,
    pub shutdown: ShutdownReport,
}

struct ResultCell<T> {
    value: Mutex<Option<Result<T, WaitError>>>,
    changed: Condvar,
    waker: AtomicWaker,
}

/// A result driven on the library pool, usable from std threads or any executor.
/// `wait` refuses to block inside a Tokio context (including library callbacks).
pub struct Operation<T>(Arc<ResultCell<T>>);

pub type CallOperation = Operation<Result<GenerationValue<Vec<u8>>, CallError>>;
pub type DialFuture = Pin<Box<dyn Future<Output = Result<ClientHandle, Error>> + Send>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WaitError {
    #[error("managed operation wait timed out; its owner remains supervised")]
    Timeout,
    #[error("blocking wait is not allowed in a Tokio context; await the operation instead")]
    WouldBlockRuntime,
    /// The supervised producer panicked or was unexpectedly cancelled.
    #[error("managed operation owner failed")]
    OwnerFailed,
}

impl<T> Operation<T> {
    pub fn wait(self, timeout: Duration) -> Result<T, WaitError> {
        if Handle::try_current().is_ok() {
            return Err(WaitError::WouldBlockRuntime);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(WaitError::Timeout)?;
        let mut value = lock(&self.0.value);
        loop {
            if let Some(value) = value.take() {
                return value;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(WaitError::Timeout);
            }
            value = self
                .0
                .changed
                .wait_timeout(value, remaining)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

impl<T> Future for Operation<T> {
    type Output = Result<T, WaitError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.waker.register(cx.waker());
        match lock(&self.0.value).take() {
            Some(value) => Poll::Ready(value),
            None => Poll::Pending,
        }
    }
}

struct ResultSender<T> {
    cell: Arc<ResultCell<T>>,
    sent: bool,
}
impl<T> Drop for ResultSender<T> {
    fn drop(&mut self) {
        if !self.sent {
            *lock(&self.cell.value) = Some(Err(WaitError::OwnerFailed));
            self.cell.changed.notify_all();
            self.cell.waker.wake();
        }
    }
}

fn result_pair<T>() -> (Operation<T>, ResultSender<T>) {
    let cell = Arc::new(ResultCell {
        value: Mutex::new(None),
        changed: Condvar::new(),
        waker: AtomicWaker::new(),
    });
    (Operation(cell.clone()), ResultSender { cell, sent: false })
}
fn deliver<T>(mut sender: ResultSender<T>, value: T) {
    *lock(&sender.cell.value) = Some(Ok(value));
    sender.sent = true;
    sender.cell.changed.notify_all();
    sender.cell.waker.wake();
}

#[derive(Clone, Copy, Default)]
struct Controls {
    revision: u64,
    paused: bool,
    offline: bool,
    stopped: bool,
}
trait Controlled: Send + Sync {
    fn apply(&self, controls: Controls);
}
struct State {
    controls: Controls,
    services: Vec<Weak<dyn Controlled>>,
    report: ShutdownReport,
}
type Job = Pin<Box<dyn Future<Output = ()> + Send>>;
struct Shared {
    state: Mutex<State>,
    completed: Condvar,
    changed: watch::Sender<Controls>,
    jobs: mpsc::Sender<Job>,
    admission: Arc<Semaphore>,
    events: broadcast::Sender<NetworkEvent>,
    grace: Duration,
}

impl Shared {
    // Serializes task admission with stop. No futures or callbacks are polled here.
    fn submit(&self, job: impl Future<Output = ()> + Send + 'static) -> Result<(), Error> {
        let mut state = lock(&self.state);
        if state.controls.stopped {
            return Err(Error::Closed);
        }
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Configuration)?;
        self.jobs
            .try_send(Box::pin(async move {
                let _permit = permit;
                job.await;
            }))
            .map_err(|_| Error::Configuration)?;
        state.report.pending_operations += 1;
        Ok(())
    }

    fn register(&self, service: Arc<dyn Controlled>) {
        let mut state = lock(&self.state);
        state.services.retain(|s| s.strong_count() != 0);
        service.apply(state.controls);
        state.services.push(Arc::downgrade(&service));
    }

    fn control(&self, update: impl FnOnce(&mut Controls)) {
        let mut state = lock(&self.state);
        if state.controls.stopped {
            return;
        }
        update(&mut state.controls);
        match state.controls.revision.checked_add(1) {
            Some(next) => state.controls.revision = next,
            None => state.controls.stopped = true,
        }
        for service in state.services.iter().filter_map(Weak::upgrade) {
            service.apply(state.controls);
        }
        self.changed.send_replace(state.controls);
        if state.controls.stopped {
            let _ = self.events.send(NetworkEvent::Stopping);
        }
    }
}

/// Non-clone runtime owner. Client/server handles are thread-safe and cloneable.
/// Dropping this owner stops all its services, even if handles remain elsewhere.
pub struct Network {
    shared: Arc<Shared>,
    owner: Option<thread::JoinHandle<()>>,
}

impl Network {
    pub fn new(config: NetworkConfig) -> Result<Self, Error> {
        if config.worker_threads == 0
            || config.worker_threads > 256
            || config.max_blocking_threads == 0
            || config.max_blocking_threads > 1024
            || config.maximum_operations == 0
            || config.maximum_operations > 1_000_000
            || config.event_capacity == 0
            || config.event_capacity > 1_000_000
            || config.close_grace.is_zero()
            || config.close_grace > syntra_runtime::MAX_CLOSE_GRACE
        {
            return Err(Error::Configuration);
        }
        let _ = retired_networks();
        let (ready, receive) = std::sync::mpsc::sync_channel(1);
        let owner = thread::Builder::new()
            .name("syntra-net-owner".into())
            .spawn(move || {
                let runtime = match Builder::new_multi_thread()
                    .worker_threads(config.worker_threads)
                    .max_blocking_threads(config.max_blocking_threads)
                    .thread_name("syntra-net-worker")
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready.send(Err(Error::Io(error)));
                        return;
                    }
                };
                let (jobs, receiver) = mpsc::channel(config.maximum_operations);
                let (changed, _) = watch::channel(Controls::default());
                let (events, _) = broadcast::channel(config.event_capacity);
                let shared = Arc::new(Shared {
                    state: Mutex::new(State {
                        controls: Controls::default(),
                        services: Vec::new(),
                        report: ShutdownReport::default(),
                    }),
                    completed: Condvar::new(),
                    changed,
                    jobs,
                    admission: Arc::new(Semaphore::new(config.maximum_operations)),
                    events,
                    grace: config.close_grace,
                });
                if ready.send(Ok(shared.clone())).is_err() {
                    return;
                }
                runtime.block_on(supervise(shared.clone(), receiver));
                // Never shutdown_timeout/background: they can leave blocking jobs alive.
                // This thread retains runtime ownership even if a bounded waiter left.
                drop(runtime);
                lock(&shared.state).report.complete = true;
                let _ = shared.events.send(NetworkEvent::Stopped);
                shared.completed.notify_all();
            })?;
        match receive.recv() {
            Ok(Ok(shared)) => Ok(Self {
                shared,
                owner: Some(owner),
            }),
            Ok(Err(error)) => {
                let _ = owner.join();
                Err(error)
            }
            Err(_) => {
                let _ = owner.join();
                Err(Error::Closed)
            }
        }
    }

    pub fn events(&self) -> Events {
        Events(self.shared.events.subscribe())
    }
    pub fn report(&self) -> ShutdownReport {
        lock(&self.shared.state).report
    }
    pub fn status(&self) -> NetworkStatus {
        let state = lock(&self.shared.state);
        NetworkStatus {
            paused: state.controls.paused,
            network_available: !state.controls.offline,
            stopping: state.controls.stopped,
            shutdown: state.report,
        }
    }
    /// Retire active connections and cancel partial handshakes. Resume establishes
    /// fresh channels; it does not replay RPCs or restore recovery subscriptions.
    pub fn pause(&self) {
        self.shared.control(|c| c.paused = true);
    }
    pub fn resume(&self) {
        self.shared.control(|c| c.paused = false);
    }
    pub fn network_available(&self, available: bool) {
        self.shared.control(|c| c.offline = !available);
    }
    pub fn stop(&self) {
        self.shared.control(|c| c.stopped = true);
    }

    /// Bound caller waiting, not resource ownership. On a Tokio thread this signals
    /// stop and returns immediately, avoiding self-join and single-worker deadlock.
    /// Repeated waits do not extend any connection's first shutdown grace budget.
    pub fn shutdown(&mut self, timeout: Duration) -> ShutdownReport {
        self.stop();
        if Handle::try_current().is_ok() {
            return self.report();
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut state = lock(&self.shared.state);
        while !state.report.complete {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            state = self
                .shared
                .completed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let report = state.report;
        drop(state);
        if report.complete
            && self
                .owner
                .as_ref()
                .is_some_and(thread::JoinHandle::is_finished)
        {
            if let Some(owner) = self.owner.take() {
                let _ = owner.join();
            }
        }
        report
    }

    /// The connector creates fresh security inputs per attempt. Its routes and
    /// trust policy are application-provisioned; no implicit carrier fallback.
    /// Completion returns the manager, not Core readiness. Observe its status
    /// separately; RPC admission never waits for or migrates into readiness.
    pub fn client<F, Fut>(
        &self,
        config: ReconnectConfig,
        connector: F,
    ) -> Result<Operation<Result<ManagedClient, Error>>, Error>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        self.client_inner(config, move |_| connector())
    }

    /// Give every attempt the reconnect owner's original absolute budget. Carry
    /// it through dial, carrier setup and protected readiness without resetting it.
    /// Registration, controls and teardown use the same owner path as `client`.
    pub fn client_with_budget<F, Fut>(
        &self,
        config: ReconnectConfig,
        connector: F,
    ) -> Result<Operation<Result<ManagedClient, Error>>, Error>
    where
        F: Fn(EstablishmentBudget) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        self.client_inner(config, connector)
    }

    fn client_inner<F, Fut>(
        &self,
        config: ReconnectConfig,
        connector: F,
    ) -> Result<Operation<Result<ManagedClient, Error>>, Error>
    where
        F: Fn(EstablishmentBudget) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ClientHandle, Error>> + Send + 'static,
    {
        config.validate()?;
        let (operation, result) = result_pair();
        let network = self.shared.clone();
        // Reserve before constructing ReconnectingClient: even creation racing
        // shutdown or operation admission failure cannot orphan its owner task.
        self.shared.submit(async move {
            let owned = {
                // Registration and initial controls form one admission decision.
                // A constructor on a paused/stopped pool cannot transiently dial
                // on a second worker before register has applied its pause fence.
                let mut state = lock(&network.state);
                let mut config = config;
                config.start_paused |= state.controls.paused || state.controls.stopped;
                config.initial_network_available &= !state.controls.offline;
                let reconnect = match ReconnectingClient::new_with_budget(config, connector) {
                    Ok(client) => client,
                    Err(error) => {
                        deliver(result, Err(error));
                        return;
                    }
                };
                let status = reconnect.subscribe_status();
                let owned = Arc::new(ClientState {
                    client: Mutex::new(Some(Arc::new(reconnect))),
                    status: Mutex::new(status),
                });
                if state.controls.stopped {
                    owned.apply(state.controls);
                }
                state.services.retain(|s| s.strong_count() != 0);
                let service: Arc<dyn Controlled> = owned.clone();
                state.services.push(Arc::downgrade(&service));
                owned
            };
            deliver(
                result,
                Ok(ManagedClient {
                    state: owned.clone(),
                    network: network.clone(),
                }),
            );
            let _ = network.events.send(NetworkEvent::ClientStarted);
            let mut controls = network.changed.subscribe();
            let mut lifecycle = lock(&owned.status).clone();
            loop {
                let stopped = controls.borrow_and_update().stopped;
                if stopped
                    || matches!(
                        lifecycle.snapshot(),
                        LifecycleStatus::Stopping
                            | LifecycleStatus::Stopped
                            | LifecycleStatus::ShutdownIncomplete
                            | LifecycleStatus::Retired(_)
                    )
                {
                    break;
                }
                tokio::select! {
                    _ = controls.changed() => {},
                    _ = lifecycle.changed() => {},
                }
            }
            let active = lock(&owned.client).take();
            if let Some(mut active) = active {
                active.stop();
                // Forwarded calls release their Arc after the stop fence. Never
                // detach the reconnect owner's JoinHandle when a waiter times out.
                loop {
                    match Arc::try_unwrap(active) {
                        Ok(mut reconnect) => {
                            loop {
                                match reconnect.close().await {
                                    Ok(()) => break,
                                    Err(Error::Timeout) => {}
                                    Err(_) => lock(&network.state).report.failed_supervisors += 1,
                                }
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                            break;
                        }
                        Err(retained) => {
                            active = retained;
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
            let _ = network.events.send(NetworkEvent::ClientStopped);
        })?;
        Ok(operation)
    }

    /// Bind and supervise concurrent encrypted TCP connections. The returned
    /// operation and all socket work run on the owned pool, not the caller executor.
    pub fn listen_tcp(
        &self,
        config: TcpServerConfig,
    ) -> Result<Operation<Result<ManagedServer, Error>>, Error> {
        config.limits.validate(&config.runtime)?;
        if config.security.carrier != Carrier::Tcp {
            return Err(Error::Configuration);
        }
        self.listen(async move {
            let listener = tcp::Listener::bind(config.address, config.admission.maximum).await?;
            Ok(TcpAcceptor {
                listener,
                settings: ServerSettings {
                    admission: config.admission,
                    security: config.security,
                    authenticator: config.authenticator,
                    handler: config.handler,
                    runtime: config.runtime,
                    limits: config.limits,
                },
            })
        })
    }

    /// Bind native WS on an explicit loopback address. Both the actual socket
    /// binding and every accepted peer are checked. No TLS claim is made.
    #[cfg(feature = "websocket")]
    pub fn listen_ws(
        &self,
        config: WebSocketServerConfig,
    ) -> Result<Operation<Result<ManagedServer, Error>>, Error> {
        if !matches!(config.tls, WebSocketTls::Loopback)
            || config.security.carrier != Carrier::WebSocket
            || !config.address.ip().is_loopback()
        {
            return Err(Error::Configuration);
        }
        self.listen_websocket(config)
    }

    /// Bind WSS using a trusted application TLS provider and provisioned local
    /// authority. TLS 1.3, upgrade, Noise and readiness share the budget created
    /// when the socket is accepted, before it waits for shared admission.
    #[cfg(feature = "websocket")]
    pub fn listen_wss(
        &self,
        config: WebSocketServerConfig,
    ) -> Result<Operation<Result<ManagedServer, Error>>, Error> {
        if !matches!(config.tls, WebSocketTls::Provider { .. })
            || config.security.carrier != Carrier::SecureWebSocket
        {
            return Err(Error::Configuration);
        }
        self.listen_websocket(config)
    }

    #[cfg(feature = "websocket")]
    fn listen_websocket(
        &self,
        config: WebSocketServerConfig,
    ) -> Result<Operation<Result<ManagedServer, Error>>, Error> {
        config.limits.validate(&config.runtime)?;
        self.listen(async move {
            let socket = tokio::net::TcpListener::bind(config.address).await?;
            let loopback = matches!(config.tls, WebSocketTls::Loopback);
            if loopback && !socket.local_addr()?.ip().is_loopback() {
                return Err(Error::Configuration);
            }
            Ok(WebSocketAcceptor {
                socket,
                local_admission: Arc::new(Semaphore::new(config.admission.maximum)),
                tls: config.tls,
                settings: ServerSettings {
                    admission: config.admission,
                    security: config.security,
                    authenticator: config.authenticator,
                    handler: config.handler,
                    runtime: config.runtime,
                    limits: config.limits,
                },
            })
        })
    }

    fn listen<A: Acceptor>(
        &self,
        bind: impl Future<Output = Result<A, Error>> + Send + 'static,
    ) -> Result<Operation<Result<ManagedServer, Error>>, Error> {
        let (operation, result) = result_pair();
        let network = self.shared.clone();
        self.shared.submit(async move {
            let acceptor = match bind.await {
                Ok(acceptor) => acceptor,
                Err(error) => {
                    deliver(result, Err(error));
                    return;
                }
            };
            let address = match acceptor.local_addr() {
                Ok(address) => address,
                Err(error) => {
                    deliver(result, Err(error));
                    return;
                }
            };
            let (controls, _) = watch::channel(Controls::default());
            let state = Arc::new(ServerState {
                controls,
                hosts: Mutex::new(BTreeMap::new()),
                status: Mutex::new(ServerStatus::default()),
            });
            network.register(state.clone());
            deliver(
                result,
                Ok(ManagedServer {
                    state: state.clone(),
                    address,
                }),
            );
            let _ = network.events.send(NetworkEvent::ListenerStarted(address));
            serve(acceptor, state, network, address).await;
        })?;
        Ok(operation)
    }

    /// Own an opt-in candidate HTTP association registry on this worker pool.
    /// The explicit Http binding requires no outer TLS; integral Noise remains
    /// mandatory. Completion means bound/registered, not a ready association.
    #[cfg(feature = "http")]
    pub fn listen_http(
        &self,
        config: http::ServerConfig,
    ) -> Result<Operation<Result<ManagedHttpServer, Error>>, Error> {
        if config.security.carrier != Carrier::Http || config.tls.is_some() {
            return Err(Error::Configuration);
        }
        self.listen_http_candidate(config)
    }

    /// Own an opt-in candidate HTTPS registry using the configured trusted
    /// application TLS provider on both streams. No plaintext or carrier fallback.
    #[cfg(feature = "http")]
    pub fn listen_https(
        &self,
        config: http::ServerConfig,
    ) -> Result<Operation<Result<ManagedHttpServer, Error>>, Error> {
        if config.security.carrier != Carrier::Https || config.tls.is_none() {
            return Err(Error::Configuration);
        }
        self.listen_http_candidate(config)
    }

    #[cfg(feature = "http")]
    fn listen_http_candidate(
        &self,
        config: http::ServerConfig,
    ) -> Result<Operation<Result<ManagedHttpServer, Error>>, Error> {
        config.validate()?;
        let (operation, result) = result_pair();
        let network = self.shared.clone();
        self.shared.submit(async move {
            let (handle, run) = match http::bind(config).await {
                Ok(bound) => bound,
                Err(error) => {
                    deliver(result, Err(error));
                    return;
                }
            };
            let address = handle.local_addr();
            let state = Arc::new(HttpState {
                handle,
                controls: Mutex::new(HttpControls::default()),
            });
            // Neither the control handle nor the inline accept owner escapes
            // before current combined Network controls have been applied.
            network.register(state.clone());
            deliver(
                result,
                Ok(ManagedHttpServer {
                    state: state.clone(),
                }),
            );
            let _ = network.events.send(NetworkEvent::ListenerStarted(address));
            // Deliberately no select/timeout: ServerRun owns its association
            // registry, paired drivers, whole HostHandles and incomplete cleanup.
            // Bounded Network shutdown waits elsewhere and retains this job.
            let status = run.await;
            // Keep the registered Controlled owner alive even when every public
            // handle/result is dropped; Network stop must still reach ServerRun.
            drop(state);
            record_http_completion(&network, status);
            let _ = network.events.send(NetworkEvent::ListenerStopped(address));
        })?;
        Ok(operation)
    }
}

#[cfg(feature = "http")]
fn record_http_completion(network: &Shared, status: http::ServerStatus) {
    let failures = usize::try_from(status.failed_tasks)
        .unwrap_or(usize::MAX)
        .saturating_add(usize::from(!status.stopped));
    if failures != 0 {
        let mut state = lock(&network.state);
        state.report.failed_supervisors = state.report.failed_supervisors.saturating_add(failures);
        let _ = network.events.send(NetworkEvent::SupervisorFailed);
    }
}

#[cfg(feature = "http")]
#[derive(Default)]
struct HttpControls {
    network: Controls,
    paused: bool,
    offline: bool,
    stopped: bool,
}

#[cfg(feature = "http")]
struct HttpState {
    handle: http::ServerHandle,
    controls: Mutex<HttpControls>,
}

#[cfg(feature = "http")]
impl HttpState {
    fn update(&self, update: impl FnOnce(&mut HttpControls)) {
        let mut controls = lock(&self.controls);
        update(&mut controls);
        self.handle.apply_controls(
            controls.network.paused || controls.paused,
            !controls.network.offline && !controls.offline,
            controls.network.stopped || controls.stopped,
        );
    }
}

#[cfg(feature = "http")]
impl Controlled for HttpState {
    fn apply(&self, controls: Controls) {
        self.update(|current| current.network = controls);
    }
}

/// Cloneable control/status handle for a managed candidate HTTP/HTTPS listener.
/// The Network retains ServerRun; hosts() snapshots never transfer pump ownership.
/// Local resume/online cannot override the parent Network's admission controls.
#[cfg(feature = "http")]
#[derive(Clone)]
pub struct ManagedHttpServer {
    state: Arc<HttpState>,
}

#[cfg(feature = "http")]
impl ManagedHttpServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.state.handle.local_addr()
    }
    pub fn status(&self) -> http::ServerStatus {
        self.state.handle.status()
    }
    pub fn hosts(&self) -> Vec<Arc<Host>> {
        self.state.handle.hosts()
    }
    pub fn pause(&self) {
        self.state.update(|c| c.paused = true);
    }
    pub fn resume(&self) {
        self.state.update(|c| c.paused = false);
    }
    pub fn network_available(&self, available: bool) {
        self.state.update(|c| c.offline = !available);
    }
    /// Stop only this listener. Terminal even if Network controls later change.
    pub fn stop(&self) {
        self.state.update(|c| c.stopped = true);
    }
}

async fn supervise(shared: Arc<Shared>, mut receiver: mpsc::Receiver<Job>) {
    let mut tasks = JoinSet::new();
    let mut controls = shared.changed.subscribe();
    loop {
        if controls.borrow_and_update().stopped {
            receiver.close();
        }
        tokio::select! {
            biased;
            result = tasks.join_next(), if !tasks.is_empty() => {
                let mut state = lock(&shared.state);
                state.report.pending_operations -= 1;
                if result.is_some_and(|r| r.is_err()) {
                    state.report.failed_supervisors += 1;
                    let _ = shared.events.send(NetworkEvent::SupervisorFailed);
                }
            }
            _ = controls.changed(), if !receiver.is_closed() => {},
            job = receiver.recv() => match job {
                Some(job) => { tasks.spawn(job); }
                None => break,
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        let mut state = lock(&shared.state);
        state.report.pending_operations -= 1;
        if result.is_err() {
            state.report.failed_supervisors += 1;
        }
    }
}

struct Retired {
    shared: Arc<Shared>,
    owner: thread::JoinHandle<()>,
}
static RETIRED: OnceLock<Mutex<Vec<Retired>>> = OnceLock::new();

/// Reports dropped runtime owners and reaps only finished OS threads. It never
/// blocks on a live worker, including when invoked from a library callback.
pub fn retired_networks() -> Vec<ShutdownReport> {
    let mut retired = lock(RETIRED.get_or_init(Default::default));
    let mut reports = Vec::with_capacity(retired.len());
    let mut index = 0;
    while index < retired.len() {
        reports.push(lock(&retired[index].shared.state).report);
        if retired[index].owner.is_finished() {
            let owner = retired.swap_remove(index);
            let _ = owner.owner.join();
        } else {
            index += 1;
        }
    }
    reports
}

impl Drop for Network {
    fn drop(&mut self) {
        self.stop();
        if let Some(owner) = self.owner.take() {
            lock(RETIRED.get_or_init(Default::default)).push(Retired {
                shared: self.shared.clone(),
                owner,
            });
        }
    }
}

struct ClientState {
    client: Mutex<Option<Arc<ReconnectingClient>>>,
    status: Mutex<crate::client::StatusReceiver>,
}
impl Controlled for ClientState {
    fn apply(&self, controls: Controls) {
        if let Some(client) = lock(&self.client).as_ref() {
            if controls.stopped {
                client.stop();
            } else if controls.revision != 0 || controls.paused || controls.offline {
                client.apply_network_controls(controls.paused, !controls.offline);
            }
        }
    }
}

#[derive(Clone)]
pub struct ManagedClient {
    state: Arc<ClientState>,
    network: Arc<Shared>,
}
impl ManagedClient {
    fn active(&self) -> Result<Arc<ReconnectingClient>, CallError> {
        lock(&self.state.client)
            .clone()
            .ok_or(CallError::Unavailable { generation: None })
    }
    pub fn status(&self) -> LifecycleStatus {
        lock(&self.state.status).snapshot()
    }
    pub fn subscribe_status(&self) -> crate::client::StatusReceiver {
        lock(&self.state.status).clone()
    }
    pub fn pause(&self) {
        if let Ok(c) = self.active() {
            c.pause();
        }
    }
    pub fn resume(&self) {
        let state = lock(&self.network.state);
        if !state.controls.paused && !state.controls.offline && !state.controls.stopped {
            if let Ok(c) = self.active() {
                c.resume();
            }
        }
    }
    pub fn retry(&self) {
        let state = lock(&self.network.state);
        if !state.controls.paused && !state.controls.offline && !state.controls.stopped {
            if let Ok(c) = self.active() {
                c.retry();
            }
        }
    }
    pub fn stop(&self) {
        if let Ok(c) = self.active() {
            c.stop();
        }
    }
    pub fn platform_wake(&self) {
        if let Ok(c) = self.active() {
            c.platform_wake();
        }
    }
    pub fn is_generation_current(&self, generation: u64) -> bool {
        self.active()
            .is_ok_and(|c| c.is_generation_current(generation))
    }

    /// Snapshot at submission, not when a pool worker eventually polls the call.
    /// Only the original generation may admit/deliver this RPC. Never retry it.
    pub fn call(
        &self,
        method: String,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<CallOperation, Error> {
        let active = self.active();
        let generation = active.as_ref().ok().and_then(|c| match c.status() {
            LifecycleStatus::CoreReady(r) | LifecycleStatus::RecoveryNegotiated(r) => {
                Some(r.generation)
            }
            _ => None,
        });
        let (operation, result) = result_pair();
        self.network.submit(async move {
            let value = match (active, generation) {
                (Ok(client), Some(generation)) => {
                    // Construct the underlying synchronous snapshot FIRST, then
                    // verify our submission generation. Controls on another thread
                    // cannot slip a successor between this check and the snapshot.
                    let call = client.call(&method, payload, timeout_ms);
                    if client.is_generation_current(generation) {
                        call.await
                    } else {
                        Err(CallError::Unavailable {
                            generation: Some(generation),
                        })
                    }
                }
                _ => Err(CallError::Unavailable { generation }),
            };
            deliver(result, value);
        })?;
        Ok(operation)
    }
}

/// Explicit TCP routes share one provisioned trust input factory. Addresses are
/// selected round-robin per dial attempt, never within an RPC. Authentication and
/// protocol errors remain terminal under ReconnectingClient's policy. There is no
/// discovered endpoint, downgrade, pin learning or implicit bootstrap fallback.
pub fn tcp_routes<F>(
    routes: Vec<SocketAddr>,
    allowlist: Vec<SocketAddr>,
    inputs: F,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<impl Fn() -> DialFuture + Send + Sync, Error>
where
    F: Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static,
{
    limits.validate(&runtime)?;
    if routes.is_empty() || routes.len() > 256 || routes.iter().any(|r| !allowlist.contains(r)) {
        return Err(Error::Configuration);
    }
    let cursor = Mutex::new(0usize);
    Ok(move || {
        let address = {
            let mut index = lock(&cursor);
            let address = routes[*index];
            *index = (*index + 1) % routes.len();
            address
        };
        let inputs = inputs();
        let runtime = runtime.clone();
        let limits = limits.clone();
        Box::pin(async move {
            let (security, credential) = inputs?;
            tcp::connect(address, security, credential, runtime, limits).await
        }) as DialFuture
    })
}

/// Share across listeners for one aggregate handshake/live/teardown bound.
/// Each listener may additionally hold one locally admitted socket waiting for
/// this shared permit, without reading handshake bytes. Idle listeners do not
/// reserve shared capacity or starve a different listening endpoint.
pub struct Admission {
    maximum: usize,
    permits: Arc<Semaphore>,
}
impl Admission {
    pub fn new(maximum: usize) -> Result<Arc<Self>, Error> {
        if maximum == 0 || maximum > Semaphore::MAX_PERMITS {
            return Err(Error::Configuration);
        }
        Ok(Arc::new(Self {
            maximum,
            permits: Arc::new(Semaphore::new(maximum)),
        }))
    }
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }
}

pub struct TcpServerConfig {
    pub address: SocketAddr,
    pub admission: Arc<Admission>,
    pub security: Arc<ServerConfig>,
    pub authenticator: Arc<dyn AuthenticatorFactory>,
    pub handler: Arc<dyn Handler>,
    pub runtime: ConnectionConfig,
    pub limits: Limits,
}

/// TLS is selected explicitly; WS is never a fallback for failed WSS policy.
#[cfg(feature = "websocket")]
#[derive(Clone)]
pub enum WebSocketTls {
    /// Native development/local I/O only, checked at bind and socket acceptance.
    Loopback,
    /// The provider must meet `tls::TlsProvider`'s real TLS/current-policy and
    /// cancellation contracts. Authority is provisioned, not learned from HTTP.
    Provider {
        provider: Arc<dyn tls::TlsProvider>,
        authority: tls::TlsAuthority,
    },
}

/// Managed WebSocket server configuration. `listen_ws` requires Loopback and a
/// WebSocket channel binding; `listen_wss` requires Provider and SecureWebSocket.
/// Admission can be shared with TCP and other WS/WSS listeners on this pool.
#[cfg(feature = "websocket")]
pub struct WebSocketServerConfig {
    pub address: SocketAddr,
    pub admission: Arc<Admission>,
    pub security: Arc<ServerConfig>,
    pub authenticator: Arc<dyn AuthenticatorFactory>,
    pub handler: Arc<dyn Handler>,
    pub runtime: ConnectionConfig,
    pub limits: Limits,
    pub tls: WebSocketTls,
}

#[derive(Clone)]
struct ServerSettings {
    admission: Arc<Admission>,
    security: Arc<ServerConfig>,
    authenticator: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
}

/// Only carrier setup varies. Admission, controls, publication and whole-handle
/// cleanup below use one supervisor for every listener kind.
trait Acceptor: Send + Sync + 'static {
    type Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static;
    fn settings(&self) -> &ServerSettings;
    fn local_addr(&self) -> Result<SocketAddr, Error>;
    fn accept_socket(&self) -> impl Future<Output = Result<Option<Self::Stream>, Error>> + Send;
    fn establish(
        &self,
        stream: Self::Stream,
        budget: EstablishmentBudget,
    ) -> impl Future<Output = Result<HostHandle, Error>> + Send + 'static;
}

struct TcpAcceptor {
    listener: tcp::Listener,
    settings: ServerSettings,
}
impl Acceptor for TcpAcceptor {
    type Stream = tcp::AdmittedStream;
    fn settings(&self) -> &ServerSettings {
        &self.settings
    }
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.listener.local_addr()
    }
    async fn accept_socket(&self) -> Result<Option<Self::Stream>, Error> {
        self.listener.accept_socket().await.map(Some)
    }
    fn establish(
        &self,
        stream: Self::Stream,
        budget: EstablishmentBudget,
    ) -> impl Future<Output = Result<HostHandle, Error>> + Send + 'static {
        let settings = self.settings.clone();
        async move {
            tcp::accept_stream_with_budget(
                stream,
                &settings.security,
                settings.authenticator.clone(),
                settings.handler.clone(),
                (settings.runtime.clone(), settings.limits.clone()),
                budget,
            )
            .await
        }
    }
}

#[cfg(feature = "websocket")]
struct WebSocketAcceptor {
    socket: tokio::net::TcpListener,
    local_admission: Arc<Semaphore>,
    tls: WebSocketTls,
    settings: ServerSettings,
}
#[cfg(feature = "websocket")]
impl Acceptor for WebSocketAcceptor {
    type Stream = WebSocketSocket;
    fn settings(&self) -> &ServerSettings {
        &self.settings
    }
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.socket.local_addr()?)
    }
    async fn accept_socket(&self) -> Result<Option<Self::Stream>, Error> {
        let permit = self
            .local_admission
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Closed)?;
        let (socket, peer) = self.socket.accept().await?;
        if matches!(self.tls, WebSocketTls::Loopback)
            && !loopback_socket(self.socket.local_addr()?, peer)
        {
            // Reject this socket without stopping the listening service.
            return Ok(None);
        }
        socket.set_nodelay(true)?;
        Ok(Some(WebSocketSocket {
            socket,
            _permit: permit,
        }))
    }
    fn establish(
        &self,
        stream: Self::Stream,
        budget: EstablishmentBudget,
    ) -> impl Future<Output = Result<HostHandle, Error>> + Send + 'static {
        let settings = self.settings.clone();
        let tls = self.tls.clone();
        async move {
            match &tls {
                WebSocketTls::Loopback => {
                    websocket::accept_stream_with_budget(
                        stream,
                        &settings.security,
                        settings.authenticator.clone(),
                        settings.handler.clone(),
                        (settings.runtime.clone(), settings.limits.clone()),
                        budget,
                    )
                    .await
                }
                WebSocketTls::Provider {
                    provider,
                    authority,
                } => {
                    let stream = tls::accept_stream_with_budget(
                        stream,
                        provider.as_ref(),
                        authority.clone(),
                        budget,
                    )
                    .await?;
                    websocket::accept_verified_tls_stream(
                        stream,
                        authority,
                        &settings.security,
                        settings.authenticator.clone(),
                        settings.handler.clone(),
                        (settings.runtime.clone(), settings.limits.clone()),
                    )
                    .await
                }
            }
        }
    }
}

#[cfg(feature = "websocket")]
fn loopback_socket(binding: SocketAddr, peer: SocketAddr) -> bool {
    binding.ip().is_loopback() && peer.ip().is_loopback()
}

/// Local socket admission follows the stream through TLS, splitting and pump
/// teardown. The separate shared permit survives even runtime execution leases.
#[cfg(feature = "websocket")]
struct WebSocketSocket {
    socket: tokio::net::TcpStream,
    _permit: OwnedSemaphorePermit,
}
#[cfg(feature = "websocket")]
impl tokio::io::AsyncRead for WebSocketSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_read(cx, buf)
    }
}
#[cfg(feature = "websocket")]
impl tokio::io::AsyncWrite for WebSocketSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().socket).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStatus {
    /// Locally accepted socket awaiting shared admission; at most one/listener.
    pub waiting_admission: usize,
    pub admitted: usize,
    pub ready: usize,
    pub completed: u64,
    pub rejected: u64,
    pub failed_tasks: u64,
    pub stopped: bool,
}
struct ServerState {
    controls: watch::Sender<Controls>,
    hosts: Mutex<BTreeMap<u64, Arc<Host>>>,
    status: Mutex<ServerStatus>,
}
impl Controlled for ServerState {
    fn apply(&self, controls: Controls) {
        // Publish before taking hosts: publication takes a watch write lock,
        // whereas ready publication holds its read lock before taking hosts.
        self.controls.send_modify(|current| {
            let stopped = current.stopped || controls.stopped;
            *current = controls;
            current.stopped = stopped;
        });
        // Suspend synchronously before returning controls to the application.
        if controls.revision != 0 || controls.stopped || controls.paused || controls.offline {
            for host in lock(&self.hosts).values() {
                host.suspend();
            }
        }
    }
}
#[derive(Clone)]
pub struct ManagedServer {
    state: Arc<ServerState>,
    address: SocketAddr,
}
impl ManagedServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn status(&self) -> ServerStatus {
        *lock(&self.state.status)
    }
    pub fn stop(&self) {
        let mut controls = *self.state.controls.borrow();
        controls.stopped = true;
        self.state.apply(controls);
    }
}

struct Accepted<S> {
    permit: OwnedSemaphorePermit,
    stream: S,
    budget: EstablishmentBudget,
}

async fn accept_admitted<A: Acceptor>(
    acceptor: &A,
    state: Arc<ServerState>,
) -> Result<Option<Accepted<A::Stream>>, Error> {
    let Some(stream) = acceptor.accept_socket().await? else {
        return Ok(None);
    };
    let settings = acceptor.settings();
    // Start at socket acceptance, not after queueing, TLS or upgrade. All
    // subsequent stages consume this same elapsed source and absolute deadline.
    let budget = match EstablishmentBudget::new(
        settings.authenticator.elapsed_clock(),
        settings.limits.attempt_timeout,
    ) {
        Ok(budget) => budget,
        Err(_) => return Ok(None),
    };
    lock(&state.status).waiting_admission += 1;
    let _waiting = WaitingAdmission(state);
    let permit = match budget
        .run(settings.admission.permits.clone().acquire_owned())
        .await
    {
        Ok(Ok(permit)) => permit,
        _ => return Ok(None),
    };
    Ok(Some(Accepted {
        permit,
        stream,
        budget,
    }))
}

async fn serve<A: Acceptor>(
    acceptor: A,
    state: Arc<ServerState>,
    network: Arc<Shared>,
    address: SocketAddr,
) {
    let mut controls = state.controls.subscribe();
    let mut tasks = JoinSet::new();
    let mut next_id = 0u64;
    // The pending accept owns its socket and shared-admission queue position.
    // Joining a different connection must not cancel either. Only a lifecycle
    // update or listener shutdown discards an unfinished admission.
    let mut accepting = Box::pin(accept_admitted(&acceptor, state.clone()));
    let mut accepting_revision = controls.borrow().revision;
    loop {
        let current = *controls.borrow_and_update();
        if current.stopped {
            break;
        }
        // A revision can arrive after a task-join branch wins but before this
        // snapshot; do not depend on selecting changed() to cancel admission.
        if current.revision != accepting_revision {
            accepting
                .as_mut()
                .set(accept_admitted(&acceptor, state.clone()));
            accepting_revision = current.revision;
        }
        tokio::select! {
            biased;
            _ = controls.changed() => {},
            result = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_some_and(|r| r.is_err()) { lock(&state.status).failed_tasks += 1; }
            }
            accepted = &mut accepting, if !current.paused && !current.offline => {
                accepting.as_mut().set(accept_admitted(&acceptor, state.clone()));
                let Accepted { permit, stream, budget } = match accepted {
                    Ok(Some(accepted)) => accepted,
                    Ok(None) => {
                        lock(&state.status).rejected += 1;
                        let _ = network.events.send(NetworkEvent::ConnectionRejected(address));
                        continue;
                    }
                    Err(_) => { lock(&state.status).failed_tasks += 1; break; }
                };
                let Some(id) = next_id.checked_add(1) else { break; };
                next_id = id;
                lock(&state.status).admitted += 1;
                let state = state.clone();
                let establishment = acceptor.establish(stream, budget);
                let network = network.clone();
                tasks.spawn(async move {
                    let _admission = ConnectionOwner { state: state.clone(), id, _permit: permit };
                    let mut changed = state.controls.subscribe();
                    let mut host = tokio::select! {
                        biased;
                        _ = revised(&mut changed, current.revision) => return,
                        result = establishment => match result {
                            Ok(host) => host,
                            Err(_) => {
                                lock(&state.status).rejected += 1;
                                let _ = network.events.send(NetworkEvent::ConnectionRejected(address));
                                return;
                            }
                        }
                    };
                    // Publication is serialized with controls to avoid making a
                    // connection usable after a pause raced message readiness.
                    {
                        let latest = state.controls.borrow();
                        if latest.revision == current.revision && !latest.stopped {
                            lock(&state.hosts).insert(id, host.host.clone());
                            lock(&state.status).ready += 1;
                            let _ = network.events.send(NetworkEvent::ConnectionReady(address));
                        } else { host.suspend(); }
                    }
                    let mut closed = host.host.subscribe_close();
                    tokio::select! {
                        biased;
                        _ = revised(&mut changed, current.revision) => {},
                        _ = async { while !*closed.borrow_and_update() { if closed.changed().await.is_err() { break; } } } => {},
                    }
                    let failures = retire_host(&mut host, network.grace).await;
                    lock(&state.status).failed_tasks += failures;
                });
            }
        }
    }
    // Close listener first; all accepted owners remain in the JoinSet until joined.
    drop(accepting);
    drop(acceptor);
    let mut stopped = *state.controls.borrow();
    stopped.stopped = true;
    state.apply(stopped);
    while let Some(result) = tasks.join_next().await {
        if result.is_err() {
            lock(&state.status).failed_tasks += 1;
        }
    }
    lock(&state.status).stopped = true;
    lock(&network.state).report.failed_supervisors += lock(&state.status).failed_tasks as usize;
    let _ = network.events.send(NetworkEvent::ListenerStopped(address));
}

async fn revised(receiver: &mut watch::Receiver<Controls>, revision: u64) {
    loop {
        let controls = *receiver.borrow_and_update();
        if controls.revision != revision || controls.stopped {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}

struct ConnectionOwner {
    state: Arc<ServerState>,
    id: u64,
    _permit: OwnedSemaphorePermit,
}

struct WaitingAdmission(Arc<ServerState>);
impl Drop for WaitingAdmission {
    fn drop(&mut self) {
        lock(&self.0.status).waiting_admission -= 1;
    }
}
impl Drop for ConnectionOwner {
    fn drop(&mut self) {
        let ready = lock(&self.state.hosts).remove(&self.id).is_some();
        let mut status = lock(&self.state.status);
        status.admitted -= 1;
        status.ready -= usize::from(ready);
        status.completed = status.completed.saturating_add(1);
    }
}

async fn retire_host(host: &mut HostHandle, grace: Duration) -> u64 {
    host.suspend();
    // The first pump/runtime shutdown deadline remains authoritative. Polling an
    // incomplete owner again observes completion; it never refreshes that budget.
    loop {
        let transport = host.shutdown_transport(grace).await;
        let report = host.host.shutdown_report();
        if matches!(transport, Ok(TransportShutdown::Complete))
            && report.phase == ShutdownPhase::Complete
        {
            return report.failed_tasks as u64;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_and_budget_clients_share_registration_controls_and_owned_shutdown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        for budget_aware in [false, true] {
            let mut network = Network::new(NetworkConfig::default()).unwrap();
            network.pause();
            network.network_available(false);
            let calls = Arc::new(AtomicUsize::new(0));
            let config = ReconnectConfig {
                attempt_timeout: Duration::from_secs(1),
                reconnect_budget: Duration::from_millis(200),
                max_attempts: 1,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(1),
                close_timeout: Duration::from_secs(1),
                start_paused: false,
                initial_network_available: true,
            };
            let (reported, receive) = std::sync::mpsc::channel();
            let operation = if budget_aware {
                let calls = calls.clone();
                network.client_with_budget(config, move |budget| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    reported
                        .send(Some(
                            budget
                                .deadline()
                                .saturating_duration_since(budget.clock.now()),
                        ))
                        .unwrap();
                    async move {
                        budget
                            .run(std::future::pending::<Result<ClientHandle, Error>>())
                            .await?
                    }
                })
            } else {
                let calls = calls.clone();
                network.client(config, move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    reported.send(None).unwrap();
                    std::future::pending::<Result<ClientHandle, Error>>()
                })
            }
            .unwrap();
            let client = operation.wait(Duration::from_secs(2)).unwrap().unwrap();
            assert_eq!(client.status(), LifecycleStatus::Paused);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let external = Builder::new_current_thread().enable_all().build().unwrap();
            let wait_for = |predicate: fn(&LifecycleStatus) -> bool| {
                let mut status = client.subscribe_status();
                external.block_on(async {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            if predicate(&status.snapshot()) {
                                break;
                            }
                            status.changed().await.unwrap();
                        }
                    })
                    .await
                    .unwrap();
                });
            };
            network.resume();
            wait_for(|s| matches!(s, LifecycleStatus::Offline));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            network.network_available(true);
            wait_for(|s| {
                matches!(
                    s,
                    LifecycleStatus::Exhausted {
                        attempts: 1,
                        last_failure: Some(crate::client::Failure::Timeout)
                    }
                )
            });
            let remaining = receive.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(remaining.is_some(), budget_aware);
            if let Some(remaining) = remaining {
                assert!(remaining <= Duration::from_millis(200));
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let report = network.shutdown(Duration::from_secs(2));
            assert!(report.complete);
            assert_eq!(report.pending_operations, 0);
            assert_eq!(report.failed_supervisors, 0);
        }
    }

    #[cfg(feature = "http")]
    #[test]
    fn http_owner_failures_propagate_to_network_report_and_events() {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let mut events = network.events();
        record_http_completion(
            &network.shared,
            http::ServerStatus {
                failed_tasks: 2,
                stopped: true,
                ..Default::default()
            },
        );
        record_http_completion(&network.shared, http::ServerStatus::default());
        assert_eq!(network.report().failed_supervisors, 3);
        assert_eq!(events.try_recv().unwrap(), NetworkEvent::SupervisorFailed);
        assert_eq!(events.try_recv().unwrap(), NetworkEvent::SupervisorFailed);
        let report = network.shutdown(Duration::from_secs(2));
        assert!(report.complete);
        assert_eq!(report.failed_supervisors, 3);
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn managed_ws_checks_actual_binding_and_peer() {
        for (binding, peer, allowed) in [
            ("127.0.0.1:1234", "127.0.0.2:5678", true),
            ("[::1]:1234", "[::1]:5678", true),
            ("127.0.0.1:1234", "192.0.2.1:5678", false),
            ("[::1]:1234", "[2001:db8::1]:5678", false),
            ("0.0.0.0:1234", "127.0.0.1:5678", false),
            ("[::]:1234", "[::1]:5678", false),
        ] {
            assert_eq!(
                loopback_socket(binding.parse().unwrap(), peer.parse().unwrap()),
                allowed
            );
        }
    }

    struct ObserveStatus {
        status: Mutex<crate::client::StatusReceiver>,
        observed: Mutex<Vec<LifecycleStatus>>,
    }
    impl std::task::Wake for ObserveStatus {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let status = lock(&self.status).snapshot();
            lock(&self.observed).push(status);
        }
    }

    #[test]
    fn managed_offline_updates_never_publish_an_implicit_resume() {
        let mut network = Network::new(NetworkConfig {
            worker_threads: 2,
            ..Default::default()
        })
        .unwrap();
        let external = Builder::new_current_thread().enable_all().build().unwrap();
        // Keep the reconnect owner unpolled while inspecting the synchronous
        // control publications. This makes an intermediate resume observable
        // deterministically, rather than hoping a worker wins a race.
        let reconnect = {
            let _entered = external.enter();
            Arc::new(
                ReconnectingClient::new(
                    ReconnectConfig {
                        attempt_timeout: Duration::from_secs(1),
                        reconnect_budget: Duration::from_secs(10),
                        max_attempts: 2,
                        base_backoff: Duration::from_millis(10),
                        max_backoff: Duration::from_millis(20),
                        close_timeout: Duration::from_secs(1),
                        start_paused: false,
                        initial_network_available: false,
                    },
                    || async { panic!("offline managed controls must not dial") },
                )
                .unwrap(),
            )
        };
        let state = Arc::new(ClientState {
            status: Mutex::new(reconnect.subscribe_status()),
            client: Mutex::new(Some(reconnect.clone())),
        });
        network.shared.register(state.clone());
        network.network_available(false);
        let observer = Arc::new(ObserveStatus {
            status: Mutex::new(reconnect.subscribe_status()),
            observed: Mutex::new(Vec::new()),
        });
        let waker = std::task::Waker::from(observer.clone());
        let mut cx = Context::from_waker(&waker);
        for update in 0..32 {
            let mut status = reconnect.subscribe_status();
            status.snapshot();
            let mut changed = Box::pin(status.changed());
            assert!(changed.as_mut().poll(&mut cx).is_pending());
            match update % 3 {
                0 => network.network_available(false),
                1 => network.pause(),
                _ => network.resume(), // Remains offline; not a manual dial permit.
            }
            assert!(changed.as_mut().poll(&mut cx).is_ready());
        }
        let observed = lock(&observer.observed);
        assert_eq!(observed.len(), 32);
        assert!(
            observed
                .iter()
                .all(|status| matches!(status, LifecycleStatus::Offline | LifecycleStatus::Paused)),
            "unexpected intermediate control publication: {observed:?}"
        );
        drop(observed);
        assert!(network.shutdown(Duration::from_secs(1)).complete);
        lock(&state.client).take();
        let mut reconnect = Arc::try_unwrap(reconnect).ok().unwrap();
        external.block_on(reconnect.close()).unwrap();
    }

    #[test]
    fn abandoned_result_producer_wakes_a_std_waiter_with_failure() {
        let (operation, producer) = result_pair::<()>();
        drop(producer);
        assert_eq!(
            operation.wait(Duration::from_secs(1)),
            Err(WaitError::OwnerFailed)
        );
    }
}
