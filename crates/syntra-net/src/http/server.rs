//! Bounded candidate association registry and inline listener owner. No route is
//! a principal, diagnostic ID or resumable token. No cipher state leaves its job.
use super::{
    codec::{self, Operation, Rejection},
    pair::Control,
    server_pair, Authority, OpenEnvelope, OriginPolicy, Route,
};
#[path = "io.rs"]
mod io;
#[path = "panic.rs"]
mod panic;
#[path = "policy.rs"]
mod policy;
use crate::{
    pump,
    tls::{self, BoxIo, TlsProvider},
    AuthenticatorFactory, Error, EstablishmentBudget, HostHandle, Limits, TransportShutdown,
};
use futures_util::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use io::{Admitted, Attached, Contained, DeferredDownload, ReplayStream};
use panic::Failure;
use policy::{Bucket, LimitedFactory, Principals};
use std::{
    collections::BTreeMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    task::{Context, Poll},
    time::Duration,
};
use syntra_core::secure_channel::{
    Carrier, Context as ChannelContext, ServerConfig as Security, MAX_FRAME, MAX_WRAPPER,
};
use syntra_runtime::{ConnectionConfig, Host, ShutdownPhase};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{oneshot, watch, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value.lock().unwrap_or_else(|e| e.into_inner())
}
const UNBOUND_KIB: usize = (codec::MAX_HEADERS + MAX_WRAPPER).div_ceil(1024);
/// Shared across candidate HTTP listeners in this process, not per listener.
pub const MAX_HOST_BUFFER_BYTES: usize = 256 * 1024 * 1024;
static HOST_MEMORY: OnceLock<Arc<Semaphore>> = OnceLock::new();
static HOST_PRINCIPALS: OnceLock<Principals> = OnceLock::new();
static HOST_SOCKETS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static HOST_TLS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static HOST_HANDSHAKES: OnceLock<Arc<Semaphore>> = OnceLock::new();
static HOST_ASSOCIATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();
fn host_memory() -> Arc<Semaphore> {
    HOST_MEMORY
        .get_or_init(|| Arc::new(Semaphore::new(MAX_HOST_BUFFER_BYTES / 1024)))
        .clone()
}

/// Finite local quotas. The byte reservation is conservative: queued and active
/// maximum-sized runtime frames, terminal slots and carrier copies are reserved
/// before M1/lookup, not misreported as an item-count byte cap. Application-owned
/// handler/store/TLS allocations need independent bounded provider policies.
#[derive(Clone, Debug)]
pub struct ServerLimits {
    pub associations: usize,
    pub handshakes: usize,
    pub unbound_streams: usize,
    pub sockets: usize,
    pub aggregate_bytes: usize,
    pub principal_associations: usize,
    pub source_entries: usize,
    pub opens_per_second: u32,
    pub open_burst: u32,
    pub source_opens_per_second: u32,
    pub source_open_burst: u32,
}
impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            associations: 128,
            handshakes: 32,
            unbound_streams: 32,
            sockets: 288,
            aggregate_bytes: 256 * 1024 * 1024,
            principal_associations: 16,
            source_entries: 256,
            opens_per_second: 32,
            open_burst: 32,
            source_opens_per_second: 4,
            source_open_burst: 8,
        }
    }
}

/// One explicit listener/authority/security policy generation. `None` TLS is
/// allowed only with candidate `Carrier::Http`; a provider is mandatory for
/// `Carrier::Https`. Neither option weakens the independent Noise pin/scope.
pub struct ServerConfig {
    pub address: SocketAddr,
    pub authority: Authority,
    pub security: Arc<Security>,
    pub authenticator: Arc<dyn AuthenticatorFactory>,
    pub handler: Arc<dyn syntra_runtime::Handler>,
    pub runtime: ConnectionConfig,
    pub limits: Limits,
    pub admission: ServerLimits,
    pub origins: OriginPolicy,
    pub tls: Option<Arc<dyn TlsProvider>>,
}
impl ServerConfig {
    /// Bounded candidate defaults, deliberately smaller than the general
    /// runtime's queues. Aggregate byte reservations may reduce simultaneous
    /// admissions below the independent logical association ceiling.
    pub fn new(
        address: SocketAddr,
        authority: Authority,
        security: Arc<Security>,
        authenticator: Arc<dyn AuthenticatorFactory>,
        handler: Arc<dyn syntra_runtime::Handler>,
    ) -> Self {
        Self {
            address,
            authority,
            security,
            authenticator,
            handler,
            runtime: ConnectionConfig {
                max_outstanding: 64,
                writer_capacity: 16,
                notification_capacity: 64,
                ..ConnectionConfig::default()
            },
            limits: Limits {
                record_timeout: Duration::from_secs(60),
                close_timeout: Duration::from_secs(2),
                ..Limits::default()
            },
            admission: ServerLimits::default(),
            origins: OriginPolicy::default(),
            tls: None,
        }
    }
    fn reservation(&self) -> Result<u32, Error> {
        self.limits.validate(&self.runtime)?;
        // Runtime Host::output admits O = M + W independent terminal owners,
        // including selected replies after their execution/correlation ended.
        // emit_selected retains both the payload-bearing Frame and its encoded
        // Vec while reserve_writer waits: 2*O maximum frames, NOT merely 2*M.
        // Add the distinct W encoded queue entries and conservatively M active
        // requests. Eight frame units cover the active pump's encoded/plaintext
        // copies, decode/ingest assembly and bounded validation scratch. Carrier
        // record/header copies are charged separately below. Handler/provider
        // private allocations and application-owned concurrent notify futures
        // require their own owner budgets; they are not counted as queued frames.
        let terminals = self
            .runtime
            .max_outstanding
            .checked_add(self.runtime.writer_capacity)
            .ok_or(Error::Configuration)?;
        let frames = terminals
            .checked_mul(2)
            .and_then(|n| n.checked_add(self.runtime.writer_capacity))
            .and_then(|n| n.checked_add(self.runtime.max_outstanding))
            .and_then(|n| n.checked_add(8))
            .ok_or(Error::Configuration)?;
        let bytes = frames
            .checked_mul(MAX_FRAME)
            .and_then(|n| n.checked_add(8 * codec::MAX_RECORD + 2 * codec::MAX_HEADERS))
            .ok_or(Error::Configuration)?;
        u32::try_from(bytes.div_ceil(1024)).map_err(|_| Error::Configuration)
    }
    pub fn validate(&self) -> Result<(), Error> {
        let a = &self.admission;
        let counts = [
            a.associations,
            a.handshakes,
            a.unbound_streams,
            a.sockets,
            a.principal_associations,
            a.source_entries,
        ];
        if counts.iter().any(|n| *n == 0 || *n > 65_536)
            || a.associations
                .checked_mul(2)
                .and_then(|n| n.checked_add(a.unbound_streams))
                .is_none_or(|n| a.sockets < n)
            || a.aggregate_bytes > 1024 * 1024 * 1024
            || a.opens_per_second == 0
            || a.open_burst == 0
            || a.source_opens_per_second == 0
            || a.source_open_burst == 0
            || a.unbound_streams
                .checked_mul(UNBOUND_KIB)
                .and_then(|n| n.checked_add(self.reservation().ok()? as usize))
                .is_none_or(|n| n > a.aggregate_bytes / 1024)
            || !matches!(
                (self.security.carrier, self.tls.is_some()),
                (Carrier::Http, false) | (Carrier::Https, true)
            )
        {
            return Err(Error::Configuration);
        }
        self.authority.tls_authority()?;
        self.authenticator
            .validate_server_config(&self.security)
            .map_err(|_| Error::Authentication)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerStatus {
    pub associations: usize,
    pub ready: usize,
    pub unbound_streams: usize,
    /// Socket reservations, including the one held by a pending accept.
    pub sockets: usize,
    pub reserved_bytes: usize,
    pub completed: u64,
    pub rejected: u64,
    pub failed_tasks: u64,
    /// True only after all inline association owners and their pumps joined.
    pub stopped: bool,
}
#[derive(Clone, Copy, Default)]
struct Controls {
    paused: bool,
    offline: bool,
    stop: bool,
    revision: u64,
}
impl Controls {
    fn admits(self) -> bool {
        !self.paused && !self.offline && !self.stop
    }
}
struct Slot {
    attach: Option<oneshot::Sender<Attached>>,
    control: Control,
    host: Option<Arc<Host>>,
    setup: Instant,
    failure: Arc<Failure>,
}
struct Registry {
    slots: BTreeMap<String, Slot>,
    global: Bucket,
    sources: BTreeMap<IpAddr, Bucket>,
}
struct State {
    registry: Mutex<Registry>,
    status: Mutex<ServerStatus>,
    controls: watch::Sender<Controls>,
    associations: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    unbound: Arc<Semaphore>,
    sockets: Arc<Semaphore>,
    memory: Arc<Semaphore>,
    memory_capacity: usize,
    principals: Principals,
    limits: ServerLimits,
}
impl State {
    fn control(&self, update: impl FnOnce(&mut Controls)) {
        let mut changed = false;
        self.controls.send_modify(|c| {
            let before = *c;
            update(c);
            c.stop |= before.stop;
            changed =
                c.paused != before.paused || c.offline != before.offline || c.stop != before.stop;
            if changed {
                match c.revision.checked_add(1) {
                    Some(next) => c.revision = next,
                    None => c.stop = true,
                }
            }
        });
        if !changed {
            return;
        }
        // Synchronous retirement prevents a fast resume from publishing old work.
        for slot in lock(&self.registry).slots.values() {
            slot.control.abort();
            if let Some(host) = &slot.host {
                host.suspend();
            }
        }
    }
    fn rate(&self, source: IpAddr, now: std::time::Instant) -> Result<(), Rejection> {
        let a = &self.limits;
        let mut r = lock(&self.registry);
        r.sources
            .retain(|_, b| !b.expired(now, a.source_opens_per_second, a.source_open_burst));
        if !r.sources.contains_key(&source) && r.sources.len() == a.source_entries {
            return Err(Rejection::Unavailable);
        }
        if !r
            .sources
            .entry(source)
            .or_insert_with(|| Bucket::new(a.source_open_burst, now))
            .take(now, a.source_opens_per_second, a.source_open_burst)
        {
            return Err(Rejection::Rate);
        }
        if !r.global.take(now, a.opens_per_second, a.open_burst) {
            return Err(Rejection::Rate);
        }
        Ok(())
    }
}

/// Control/status only. Keep the `ServerRun` owner, and drive it until stopped.
/// Stop/pause/offline retire existing slots; resuming admits only fresh channels.
#[derive(Clone)]
pub struct ServerHandle {
    state: Arc<State>,
    address: SocketAddr,
}
impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn status(&self) -> ServerStatus {
        let mut s = *lock(&self.state.status);
        s.associations =
            self.state.limits.associations - self.state.associations.available_permits();
        s.unbound_streams =
            self.state.limits.unbound_streams - self.state.unbound.available_permits();
        s.sockets = self.state.limits.sockets - self.state.sockets.available_permits();
        s.reserved_bytes = (self.state.memory_capacity - self.state.memory.available_permits()
            + s.unbound_streams * UNBOUND_KIB)
            * 1024;
        s
    }
    /// Bounded snapshot of currently ready runtime hosts, e.g. for application
    /// notifications. These clones do not own the driver; ServerRun still does.
    pub fn hosts(&self) -> Vec<Arc<Host>> {
        lock(&self.state.registry)
            .slots
            .values()
            .filter(|slot| !slot.control.is_retired())
            .filter_map(|slot| slot.host.clone())
            .collect()
    }
    pub fn pause(&self) {
        self.state.control(|c| c.paused = true);
    }
    pub fn resume(&self) {
        self.state.control(|c| c.paused = false);
    }
    pub fn network_available(&self, available: bool) {
        self.state.control(|c| c.offline = !available);
    }
    pub fn stop(&self) {
        self.state.control(|c| c.stop = true);
    }

    /// Apply a managed admission decision in one revision. In particular, an
    /// offline resume must not publish a transient online/unpaused generation.
    #[cfg(feature = "managed")]
    pub(crate) fn apply_controls(&self, paused: bool, available: bool, stop: bool) {
        self.state.control(|c| {
            c.paused = paused;
            c.offline = !available;
            c.stop |= stop;
        });
    }
}

// The fallback is deliberately observable and retains JoinHandles. It is used
// only if a caller drops/cancels the inline owner. Managed Network should retain
// and await ServerRun instead, keeping its runtime alive through incomplete wait.
struct Retired {
    task: tokio::task::JoinHandle<ServerStatus>,
    handle: ServerHandle,
}
static RETIRED: Mutex<Vec<Retired>> = Mutex::new(Vec::new());
static LISTENERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
pub fn retired_servers() -> Vec<ServerStatus> {
    let mut retired = lock(&RETIRED);
    let mut reports = Vec::new();
    let mut pending = Vec::new();
    for mut entry in retired.drain(..) {
        if entry.task.is_finished() {
            match (&mut entry.task).now_or_never() {
                Some(Ok(status)) => reports.push(status),
                _ => {
                    let mut status = entry.handle.status();
                    status.failed_tasks += 1;
                    reports.push(status);
                }
            }
        } else {
            reports.push(entry.handle.status());
            pending.push(entry);
        }
    }
    *retired = pending;
    reports
}

/// Inline long-running owner. Cancellation/drop signals stop and transfers its
/// *whole remaining future* to an observable retained owner; it does not abort a
/// JoinSet or detach a writer. The surrounding Tokio runtime must remain alive.
#[must_use = "drive this owner until stopped, or dropping it signals retained shutdown"]
pub struct ServerRun {
    future: Option<BoxFuture<'static, ServerStatus>>,
    handle: ServerHandle,
    executor: tokio::runtime::Handle,
}
impl Future for ServerRun {
    type Output = ServerStatus;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.future.as_mut() {
            Some(future) => match future.as_mut().poll(cx) {
                Poll::Ready(status) => {
                    this.future = None;
                    Poll::Ready(status)
                }
                Poll::Pending => Poll::Pending,
            },
            None => Poll::Ready(this.handle.status()),
        }
    }
}
impl Drop for ServerRun {
    fn drop(&mut self) {
        if let Some(future) = self.future.take() {
            self.handle.stop();
            lock(&RETIRED).push(Retired {
                task: self.executor.spawn(future),
                handle: self.handle.clone(),
            });
        }
    }
}

/// Bind only; no detached accept loop. Poll `ServerRun` on the owning executor.
pub async fn bind(config: ServerConfig) -> Result<(ServerHandle, ServerRun), Error> {
    bind_with_accept(config, |listener, state| Box::pin(accept(listener, state))).await
}

type Accepted = (BoxIo, IpAddr, OwnedSemaphorePermit);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

// Private socket-operation seam for deterministic accept/setup failure tests.
async fn bind_with_accept<A>(
    config: ServerConfig,
    accept: A,
) -> Result<(ServerHandle, ServerRun), Error>
where
    A: for<'a> Fn(&'a TcpListener, &'a State) -> BoxFuture<'a, Result<Accepted, Error>>
        + Send
        + Sync
        + 'static,
{
    config.validate()?;
    retired_servers();
    let owner = LISTENERS
        .get_or_init(|| Arc::new(Semaphore::new(64)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error::Closed)?;
    let head_memory = host_memory()
        .try_acquire_many_owned(
            u32::try_from(config.admission.unbound_streams * UNBOUND_KIB)
                .map_err(|_| Error::Configuration)?,
        )
        .map_err(|_| Error::Closed)?;
    let listener = TcpListener::bind(config.address).await?;
    let address = listener.local_addr()?;
    let now = config.authenticator.elapsed_clock().now();
    let a = config.admission.clone();
    // Keep the bounded unbound-head pool separate, so full association byte
    // reservations cannot prevent D from presenting its first poll. The sum of
    // both pools never exceeds the configured aggregate input/output budget.
    let memory_capacity = a.aggregate_bytes / 1024 - a.unbound_streams * UNBOUND_KIB;
    let state = Arc::new(State {
        registry: Mutex::new(Registry {
            slots: BTreeMap::new(),
            global: Bucket::new(a.open_burst, now),
            sources: BTreeMap::new(),
        }),
        status: Mutex::new(ServerStatus::default()),
        controls: watch::channel(Controls::default()).0,
        associations: Arc::new(Semaphore::new(a.associations)),
        handshakes: Arc::new(Semaphore::new(a.handshakes)),
        unbound: Arc::new(Semaphore::new(a.unbound_streams)),
        sockets: Arc::new(Semaphore::new(a.sockets)),
        memory: Arc::new(Semaphore::new(memory_capacity)),
        memory_capacity,
        principals: HOST_PRINCIPALS
            .get_or_init(|| Arc::new(Mutex::new(BTreeMap::new())))
            .clone(),
        limits: a,
    });
    let handle = ServerHandle {
        state: state.clone(),
        address,
    };
    let run = ServerRun {
        future: Some(Box::pin(serve(
            listener,
            Arc::new(config),
            state,
            owner,
            head_memory,
            accept,
        ))),
        handle: handle.clone(),
        executor: tokio::runtime::Handle::current(),
    };
    Ok((handle, run))
}

async fn serve<A>(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    state: Arc<State>,
    _owner: OwnedSemaphorePermit,
    _head_memory: OwnedSemaphorePermit,
    accept: A,
) -> ServerStatus
where
    A: for<'a> Fn(&'a TcpListener, &'a State) -> BoxFuture<'a, Result<Accepted, Error>>
        + Send
        + Sync,
{
    let mut jobs = FuturesUnordered::<BoxFuture<'static, ()>>::new();
    let mut controls = state.controls.subscribe();
    let mut retry_not_before = None;
    loop {
        let current = *controls.borrow_and_update();
        if current.stop {
            break;
        }
        tokio::select! {
            biased;
            _ = controls.changed() => {},
            _ = jobs.next(), if !jobs.is_empty() => {},
            _ = tokio::time::sleep_until(retry_not_before.unwrap_or_else(Instant::now)), if retry_not_before.is_some() => {
                retry_not_before = None;
            },
            accepted = accept(&listener, &state), if current.admits() && retry_not_before.is_none() => match accepted {
                Ok((stream, source, unbound)) => {
                    let state = state.clone(); let config = config.clone();
                    // Capture the accepted-socket budget now, not when a queued
                    // job first gets polled. Clock-provider panics are contained
                    // here too; no active owner has escaped to Network unwind.
                    let mut owner = AssociationOwner::new();
                    let budget = owner.failure.catch(|| EstablishmentBudget::new(config.authenticator.elapsed_clock(), config.limits.attempt_timeout));
                    jobs.push(Box::pin(async move {
                        // Owners live OUTSIDE the caught continuation. Unwinding
                        // drops partial local I/O, never the retained driver,
                        // runtime host, admission permits or cleanup future.
                        let failure = owner.failure.clone();
                        let result = match budget {
                            Some(Ok(budget)) => failure.catch_async(initial((stream, source, unbound), config.clone(), state.clone(), current.revision, budget, &mut owner)).await,
                            Some(Err(error)) => Some(Err(error)),
                            None => None,
                        };
                        let runtime = lock(&owner.accept.host).clone();
                        if runtime.as_ref().is_some_and(|host| host.terminal_reason().is_some_and(|reason| reason.code() == syntra_core::ErrorCode::Internal)) {
                            failure.mark();
                        }
                        let recorded = u64::from(failure.failed());
                        {
                            let mut status = lock(&state.status);
                            status.failed_tasks = status.failed_tasks.saturating_add(recorded);
                            if !matches!(result, Some(Ok(()))) { status.rejected = status.rejected.saturating_add(1); }
                        }
                        let failures = owner.cleanup(config.limits.close_timeout).await.max(u64::from(failure.failed()));
                        let mut status = lock(&state.status);
                        status.failed_tasks = status.failed_tasks.saturating_add(failures.saturating_sub(recorded));
                    }));
                },
                Err(Error::Closed) => { lock(&state.status).failed_tasks += 1; break; }
                Err(error) => {
                    // Failed accept/setup drops all socket reservations before
                    // backing off; controls and existing jobs stay polled.
                    tracing::warn!(%error, "HTTP listener accept failed; retrying");
                    retry_not_before = Some(Instant::now() + ACCEPT_RETRY_DELAY);
                }
            },
        }
    }
    drop(listener);
    state.control(|c| c.stop = true);
    while jobs.next().await.is_some() {}
    lock(&state.status).stopped = true;
    *lock(&state.status)
}

async fn accept(listener: &TcpListener, state: &State) -> Result<Accepted, Error> {
    accept_with(state, listener.accept(), |stream| stream.set_nodelay(true)).await
}

async fn accept_with(
    state: &State,
    raw_socket: impl Future<Output = std::io::Result<(tokio::net::TcpStream, SocketAddr)>>,
    configure: impl FnOnce(&tokio::net::TcpStream) -> std::io::Result<()>,
) -> Result<Accepted, Error> {
    let unbound = state
        .unbound
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Error::Closed)?;
    let socket = state
        .sockets
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Error::Closed)?;
    let global_socket = HOST_SOCKETS
        .get_or_init(|| Arc::new(Semaphore::new(288)))
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| Error::Closed)?;
    let (stream, peer) = raw_socket.await?;
    configure(&stream)?;
    Ok((
        Box::new(Admitted {
            inner: stream,
            _permit: socket,
            _global_permit: global_socket,
        }),
        peer.ip(),
        unbound,
    ))
}

/// Nested result distinguishes a safely reportable bound from uncertain I/O or
/// CR/LF desynchronization. No read-ahead, resynchronization or enlarged buffer.
async fn first_header(stream: &mut BoxIo) -> Result<Result<Vec<u8>, Rejection>, Error> {
    let mut bytes = Vec::with_capacity(codec::MAX_HEADERS);
    let mut start = 0;
    let mut fields = 0;
    loop {
        if bytes.len() == codec::MAX_HEADERS {
            return Ok(Err(Rejection::HeaderBound));
        }
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        let limit = if start == 0 {
            codec::MAX_START_LINE
        } else {
            codec::MAX_FIELD_LINE
        };
        if bytes.len() - start > limit {
            return Ok(Err(Rejection::HeaderBound));
        }
        if bytes.ends_with(b"\r\n") {
            if bytes.len() - start == 2 {
                return Ok(Ok(bytes));
            }
            if start != 0 {
                fields += 1;
            }
            if fields > codec::MAX_FIELDS {
                return Ok(Err(Rejection::HeaderBound));
            }
            start = bytes.len();
        } else if byte == b'\n' || (bytes.len() >= 2 && bytes[bytes.len() - 2] == b'\r') {
            return Err(Error::Framing);
        }
    }
}

/// A native rejection is one immutable, empty response on the still-owned
/// original stream. This does not restart any phase, drain an attacker body,
/// reflect a header, or turn HTTP admission into an authenticated RPC verdict.
async fn reject_initial<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    rejection: Rejection,
    budget: &EstablishmentBudget,
    first: Instant,
    controls: (&State, u64),
) -> Result<(), Error> {
    budget.io.check().map_err(|_| Error::Timeout)?;
    let mut changed = controls.0.controls.subscribe();
    tokio::select! {
        biased;
        _ = revised(&mut changed, controls.1) => Err(Error::Closed),
        result = pump::elapsed_timeout(&budget.clock, first, async {
            stream.write_all(rejection.response()).await?;
            stream.flush().await.map_err(Error::Io)
        }) => result?,
    }
}

struct Admission {
    reservations: Arc<Reservations>,
    handshake: OwnedSemaphorePermit,
    global_handshake: OwnedSemaphorePermit,
}
fn admit(state: &State, reserved: u32) -> Result<Admission, Rejection> {
    let association = state
        .associations
        .clone()
        .try_acquire_owned()
        .map_err(|_| Rejection::Unavailable)?;
    let global_association = HOST_ASSOCIATIONS
        .get_or_init(|| Arc::new(Semaphore::new(128)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| Rejection::Unavailable)?;
    let handshake = state
        .handshakes
        .clone()
        .try_acquire_owned()
        .map_err(|_| Rejection::Unavailable)?;
    let global_handshake = HOST_HANDSHAKES
        .get_or_init(|| Arc::new(Semaphore::new(32)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| Rejection::Unavailable)?;
    let memory = state
        .memory
        .clone()
        .try_acquire_many_owned(reserved)
        .map_err(|_| Rejection::Unavailable)?;
    let global_memory = host_memory()
        .try_acquire_many_owned(reserved)
        .map_err(|_| Rejection::Unavailable)?;
    Ok(Admission {
        reservations: Arc::new(Reservations {
            _association: association,
            _global_association: global_association,
            _memory: memory,
            _global_memory: global_memory,
        }),
        handshake,
        global_handshake,
    })
}

async fn initial(
    accepted: (BoxIo, IpAddr, OwnedSemaphorePermit),
    config: Arc<ServerConfig>,
    state: Arc<State>,
    revision: u64,
    budget: EstablishmentBudget,
    owner: &mut AssociationOwner,
) -> Result<(), Error> {
    let (mut stream, source, unbound) = accepted;
    let failure = owner.failure.clone();
    stream = Box::new(Contained {
        inner: stream,
        failure: failure.clone(),
    });
    let first = budget.initial_deadline(Duration::from_secs(5));
    let clock = budget.clock.clone();
    // The timeout future alone cannot preempt a provider/read loop that keeps
    // returning Ready. Gate every raw AND buffered-plaintext poll at this phase.
    budget.io.until(first)?;
    let mut controls = state.controls.subscribe();
    let setup = async {
        if let Some(provider) = &config.tls {
            let _tls = HOST_TLS
                .get_or_init(|| Arc::new(Semaphore::new(32)))
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Closed)?;
            let verified = tls::accept_stream_with_budget(
                stream,
                provider.as_ref(),
                config.authority.tls_authority()?,
                budget.clone(),
            )
            .await?;
            let (io, _, _) = verified.into_parts();
            stream = Box::new(Contained {
                inner: io,
                failure: failure.clone(),
            });
        } else {
            stream = Box::new(crate::stream::EstablishmentIo {
                inner: stream,
                budget: budget.io.clone(),
            });
        }
        Ok::<_, Error>(stream)
    };
    let mut stream = tokio::select! {
        biased;
        _ = revised(&mut controls, revision) => return Err(Error::Closed),
        result = pump::elapsed_timeout(&clock, first, setup) => result??,
    };
    // Unlike TLS failure/expiry, a classified header error must not drop the
    // owned stream before its bounded native response can finish or abort.
    let header = tokio::select! {
        biased;
        _ = revised(&mut controls, revision) => return Err(Error::Closed),
        result = pump::elapsed_timeout(&clock, first, first_header(&mut stream)) => result??,
    };
    let mut header = match header {
        Ok(header) => header,
        Err(rejection) => {
            reject_initial(&mut stream, rejection, &budget, first, (&state, revision)).await?;
            return Err(Error::Closed);
        }
    };
    let head = match codec::parse_initial_request(&header, &config.authority, &config.origins) {
        Ok(head) => head,
        Err(rejection) => {
            reject_initial(&mut stream, rejection, &budget, first, (&state, revision)).await?;
            return Err(Error::Closed);
        }
    };
    if head.operation == Operation::Poll {
        let route = head.route.ok_or(Error::Framing)?;
        let attach = {
            // The initial head has already validated authority and Origin. This
            // lookup allocates no slot and performs no crypto for arbitrary H.
            let mut registry = lock(&state.registry);
            let slot = registry.slots.get_mut(route.as_str());
            match slot {
                Some(slot)
                    if slot.control.is_retired()
                        || slot.attach.is_none()
                        || Instant::from_std(clock.now()) >= slot.setup =>
                {
                    slot.control.abort();
                    if let Some(host) = &slot.host {
                        host.suspend();
                    }
                    Err(Rejection::Gone)
                }
                Some(slot) if head.counter != Some(0) => {
                    slot.control.abort();
                    if let Some(host) = &slot.host {
                        host.suspend();
                    }
                    Err(Rejection::BadRequest)
                }
                Some(slot) => {
                    // Header admission completed before its first deadline.
                    // Join only the existing association's absolute setup cap,
                    // still clamped by D's original accepted-socket budget.
                    budget.io.check().map_err(|_| Error::Timeout)?;
                    budget.io.until(slot.setup)?;
                    failure.bind(&slot.failure);
                    slot.attach.take().ok_or(Rejection::Gone)
                }
                None => Err(Rejection::Gone),
            }
        };
        match attach {
            Ok(attach) => match attach.send(Attached {
                stream: ReplayStream::new(stream, header),
                budget,
            }) {
                Ok(()) => {
                    drop(unbound);
                    return Ok(());
                }
                Err(mut attached) => {
                    // Failed one-shot transfer returns the original owned wire.
                    // Keep its association-clamped gate; never restore time to
                    // emit a 410 after that gate has expired.
                    reject_initial(
                        &mut attached.stream,
                        Rejection::Gone,
                        &attached.budget,
                        first,
                        (&state, revision),
                    )
                    .await?;
                }
            },
            Err(rejection) => {
                reject_initial(&mut stream, rejection, &budget, first, (&state, revision)).await?;
            }
        }
        return Err(Error::Closed);
    }
    if head.operation != Operation::Open {
        // A fully validated send/close on an unbound replacement stream is not
        // U. Retire only the explicitly named live slot, never another slot or
        // a route recovered from malformed/foreign-authority headers.
        if let Some(route) = &head.route {
            if let Some(slot) = lock(&state.registry).slots.get(route.as_str()) {
                slot.control.abort();
                if let Some(host) = &slot.host {
                    host.suspend();
                }
            }
        }
        reject_initial(
            &mut stream,
            Rejection::BadRequest,
            &budget,
            first,
            (&state, revision),
        )
        .await?;
        return Err(Error::Closed);
    }
    if let Err(rejection) = state.rate(source, clock.now()) {
        reject_initial(&mut stream, rejection, &budget, first, (&state, revision)).await?;
        return Err(Error::Closed);
    }
    let reserved = config.reservation()?;
    let admission = match admit(&state, reserved) {
        Ok(admission) => admission,
        Err(rejection) => {
            reject_initial(&mut stream, rejection, &budget, first, (&state, revision)).await?;
            return Err(Error::Closed);
        }
    };
    // Body bound precedes allocation, context parsing and any KeyStore access.
    if head.body_len > MAX_WRAPPER {
        return Err(Error::Framing);
    }
    let mut body = vec![0; head.body_len];
    pump::elapsed_timeout(&clock, first, stream.read_exact(&mut body)).await??;
    let (context, _) = ChannelContext::parse_first(&body)?;
    if context.carrier != config.security.carrier
        || context.mode != config.security.mode
        || context.scope != config.security.scope
        || context.server_key_id != config.security.server_key_id
    {
        return Err(Error::Authentication);
    }
    let envelope = OpenEnvelope::new(context.encode()?)?;
    // TLS/header admission is over. Noise/first-hello gets its own existing
    // <=5s phase from M1 processing, within the unchanged total attempt budget.
    budget.io.check().map_err(|_| Error::Timeout)?;
    let setup = budget
        .deadline
        .min(Instant::from_std(clock.now()) + config.limits.channel_timeout);
    budget.io.until(setup)?;
    header.extend_from_slice(&body);
    let (attach, receiver) = oneshot::channel();
    let download_budget = Arc::new(Mutex::new(None));
    let download = DeferredDownload {
        receiver,
        stream: None,
        budget: download_budget.clone(),
    };
    let route = {
        let registry = lock(&state.registry);
        random_route(|route| registry.slots.contains_key(route))?
    };
    let (reader, writer, driver, control) = server_pair(
        ReplayStream::new(stream, header),
        download,
        config.authority.clone(),
        envelope,
        config.origins.clone(),
        route.clone(),
        budget,
    );
    {
        let current = state.controls.borrow();
        if current.revision != revision || !current.admits() {
            return Err(Error::Closed);
        }
        let mut registry = lock(&state.registry);
        if registry.slots.contains_key(route.as_str()) {
            return Err(Error::Closed);
        }
        registry.slots.insert(
            route.as_str().to_owned(),
            Slot {
                attach: Some(attach),
                control: control.clone(),
                host: None,
                setup,
                failure: failure.clone(),
            },
        );
    }
    drop(unbound);
    owner.slot = Some(SlotOwner {
        state: state.clone(),
        route,
        _reservations: admission.reservations,
    });
    owner.control = Some(control.clone());
    control.retain(
        owner
            .slot
            .as_ref()
            .ok_or(Error::Closed)?
            ._reservations
            .clone(),
    )?;
    let factory = Arc::new(LimitedFactory {
        base: config.authenticator.clone(),
        principals: state.principals.clone(),
        maximum: state.limits.principal_associations,
        lease: owner.lease.clone(),
        failure: failure.clone(),
    });
    let attempt = control.take_establishment_budget()?;
    let mut accept = Box::pin(pump::accept_records_owned(
        reader,
        writer,
        &config.security,
        factory,
        config.handler.clone(),
        (config.runtime.clone(), config.limits.clone()),
        (attempt, owner.accept.clone()),
    ));
    owner.driver = Some(Box::pin(driver.run()));
    let mut failed = failure.subscribe();
    let host = tokio::select! {
        biased;
        _ = revised(&mut controls, revision) => { control.abort(); return Err(Error::Closed); },
        _ = wait_closed(&mut failed) => return Err(Error::Closed),
        result = owner.driver.as_mut().ok_or(Error::Closed)? => {
            owner.driver.take(); result?; return Err(Error::Closed);
        },
        result = &mut accept => result?,
    };
    owner.host = Some(host);
    let host = owner.host.as_ref().ok_or(Error::Closed)?;
    control.finish_setup()?;
    if let Some(budget) = lock(&download_budget).take() {
        budget.io.finish();
    }
    drop(admission.handshake);
    drop(admission.global_handshake);
    {
        let current = state.controls.borrow();
        if current.revision == revision && current.admits() {
            if let Some(slot) = lock(&state.registry)
                .slots
                .get_mut(owner.slot.as_ref().ok_or(Error::Closed)?.route.as_str())
            {
                slot.host = Some(host.host.clone());
            }
            lock(&state.status).ready += 1;
        } else {
            control.abort();
            host.suspend();
        }
    }
    let mut closed = host.host.subscribe_close();
    let ended = tokio::select! {
        biased;
        _ = revised(&mut controls, revision) => false,
        _ = wait_closed(&mut failed) => false,
        _ = wait_closed(&mut closed) => false,
        _ = owner.driver.as_mut().ok_or(Error::Closed)? => true,
    };
    control.abort();
    if ended {
        owner.driver.take();
    }
    Ok(())
}

async fn wait_closed(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}
async fn revised(receiver: &mut watch::Receiver<Controls>, revision: u64) {
    loop {
        if receiver.borrow_and_update().revision != revision {
            return;
        }
        if receiver.changed().await.is_err() {
            return;
        }
    }
}
async fn retire_host(host: &mut HostHandle, grace: Duration) -> u64 {
    host.suspend();
    loop {
        let transport = host.shutdown_transport(grace).await;
        if matches!(transport, Ok(TransportShutdown::Complete))
            && host.host.shutdown_report().phase == ShutdownPhase::Complete
        {
            return host.host.shutdown_report().failed_tasks as u64;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// This guard's fields outlive each caught setup/active continuation. Cleanup
/// itself stays inline in ServerRun; bounded Network waiters can leave without
/// moving the work to the standalone drop fallback or discarding external leases.
struct AssociationOwner {
    control: Option<Control>,
    driver: Option<BoxFuture<'static, Result<(), Error>>>,
    host: Option<HostHandle>,
    accept: Arc<pump::AcceptOwner>,
    slot: Option<SlotOwner>,
    lease: Arc<Mutex<Option<policy::Lease>>>,
    failure: Arc<Failure>,
}
impl AssociationOwner {
    fn new() -> Self {
        Self {
            control: None,
            driver: None,
            host: None,
            accept: Arc::new(pump::AcceptOwner::default()),
            slot: None,
            lease: Arc::new(Mutex::new(None)),
            failure: Failure::new(),
        }
    }
    async fn cleanup(&mut self, grace: Duration) -> u64 {
        if let Some(control) = &self.control {
            control.abort();
        }
        let runtime = lock(&self.accept.host).clone();
        if let Some(host) = &runtime {
            host.suspend();
        }
        if let Some(driver) = self.driver.take() {
            // A panicked future must never be polled again. Disposing inline I/O
            // after abort is terminal; any wire moved into a pump write future
            // remains owned by that pump and is joined below.
            if !self.failure.failed() {
                let _ = self.failure.catch_async(driver).await;
            }
        }
        let mut failures = 0;
        if let Some(host) = &mut self.host {
            loop {
                if let Some(count) = self.failure.catch_async(retire_host(host, grace)).await {
                    failures = count;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } else if let Some(host) = runtime {
            loop {
                let joined = self
                    .failure
                    .catch_async(async {
                        // Establishment has been disposed and the inline driver is
                        // gone. A pre-pump Host has no carrier children to attest.
                        // If pump adoption occurred, only its actual joins can bring
                        // transport_tasks to zero; never acknowledge it in advance.
                        if host.shutdown_report().transport_tasks == 0 {
                            host.acknowledge_transport_closed();
                        }
                        host.shutdown(grace).await
                    })
                    .await;
                if let Some(Ok(report)) = joined {
                    if report.phase == ShutdownPhase::Complete {
                        failures = report.failed_tasks as u64;
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        // Pre-host blocking handshakes also retain their real joins and lane
        // permits when setup panics or is cancelled. Reaping can itself report a
        // worker panic; contain it, record failure, and continue owning the pool.
        let jobs = lock(&self.accept.jobs).clone();
        for pool in jobs {
            loop {
                if self.failure.catch(|| pool.pending()) == Some(0) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        lock(&self.lease).take();
        self.slot.take();
        failures.max(u64::from(self.failure.failed()))
    }
}
struct SlotOwner {
    state: Arc<State>,
    route: Route,
    _reservations: Arc<Reservations>,
}
struct Reservations {
    _association: OwnedSemaphorePermit,
    _global_association: OwnedSemaphorePermit,
    _memory: OwnedSemaphorePermit,
    _global_memory: OwnedSemaphorePermit,
}
impl Drop for SlotOwner {
    fn drop(&mut self) {
        let slot = lock(&self.state.registry).slots.remove(self.route.as_str());
        if let Some(slot) = slot {
            slot.control.abort();
            let mut status = lock(&self.state.status);
            status.ready -= usize::from(slot.host.is_some());
            status.completed = status.completed.saturating_add(1);
        }
    }
}
fn random_route(exists: impl FnMut(&str) -> bool) -> Result<Route, Error> {
    random_route_with(
        || {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).map_err(|_| syntra_core::secure_channel::Error::Entropy)?;
            Ok(bytes)
        },
        exists,
    )
}

// Private sampler seam for failure/collision regressions, never caller-supplied
// entropy or deterministic selectors on the protected listener surface.
fn random_route_with(
    mut draw: impl FnMut() -> Result<[u8; 32], Error>,
    mut exists: impl FnMut(&str) -> bool,
) -> Result<Route, Error> {
    for _ in 0..4 {
        let bytes = draw()?;
        let mut text = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in bytes {
            text.push(HEX[(byte >> 4) as usize] as char);
            text.push(HEX[(byte & 15) as usize] as char);
        }
        if !exists(&text) {
            return Route::parse(&text);
        }
    }
    Err(Error::Closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct AcceptFaults {
        sockets: Mutex<VecDeque<std::io::Result<(tokio::net::TcpStream, SocketAddr)>>>,
        attempts: AtomicUsize,
        fail_nodelay: AtomicBool,
    }
    impl AcceptFaults {
        async fn bind(self: Arc<Self>) -> (ServerHandle, ServerRun) {
            bind_with_accept(config(), move |_, state| {
                let faults = self.clone();
                Box::pin(async move {
                    let socket = async {
                        faults.attempts.fetch_add(1, Ordering::SeqCst);
                        let next = lock(&faults.sockets).pop_front();
                        match next {
                            Some(result) => result,
                            None => std::future::pending().await,
                        }
                    };
                    accept_with(state, socket, |stream| {
                        if faults.fail_nodelay.swap(false, Ordering::SeqCst) {
                            Err(std::io::ErrorKind::Other.into())
                        } else {
                            stream.set_nodelay(true)
                        }
                    })
                    .await
                })
            })
            .await
            .unwrap()
        }
    }

    fn poll_server(run: &mut ServerRun) {
        assert!(run.now_or_never().is_none(), "listener exited unexpectedly");
    }

    async fn socket_pair() -> (tokio::net::TcpStream, (tokio::net::TcpStream, SocketAddr)) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        (peer, listener.accept().await.unwrap())
    }

    fn assert_released(handle: &ServerHandle) {
        let status = handle.status();
        assert_eq!(status.sockets, 0);
        assert_eq!(status.unbound_streams, 0);
        assert_eq!(status.failed_tasks, 0);
        assert!(!status.stopped);
    }

    #[tokio::test(start_paused = true)]
    async fn transient_accept_errors_back_off_release_permits_and_keep_controls_live() {
        let faults = Arc::new(AcceptFaults::default());
        lock(&faults.sockets).extend([
            Err(std::io::ErrorKind::ConnectionAborted.into()),
            Err(std::io::ErrorKind::Other.into()),
        ]);
        let (handle, mut run) = faults.clone().bind().await;
        let start = Instant::now();
        poll_server(&mut run);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 1);
        assert_released(&handle);
        tokio::time::advance(ACCEPT_RETRY_DELAY - Duration::from_millis(1)).await;
        poll_server(&mut run);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 1);
        handle.pause();
        poll_server(&mut run);
        assert_released(&handle);
        handle.resume();
        poll_server(&mut run);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        poll_server(&mut run);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 2);
        assert_released(&handle);
        handle.stop();
        let status = run.now_or_never().expect("stop must interrupt backoff");
        assert!(status.stopped);
        assert_eq!(status.failed_tasks, 0);
        assert_eq!(Instant::now() - start, ACCEPT_RETRY_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn nodelay_failure_drops_only_its_socket_and_child_progresses_during_backoff() {
        let (mut rejected_peer, rejected) = socket_pair().await;
        let (mut peer, accepted) = socket_pair().await;
        let faults = Arc::new(AcceptFaults::default());
        faults.fail_nodelay.store(true, Ordering::SeqCst);
        lock(&faults.sockets).extend([
            Ok(rejected),
            Ok(accepted),
            Err(std::io::ErrorKind::Other.into()),
        ]);
        let (handle, mut run) = faults.clone().bind().await;
        poll_server(&mut run);
        assert_released(&handle);
        assert_eq!(
            rejected_peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        tokio::time::advance(ACCEPT_RETRY_DELAY).await;
        poll_server(&mut run);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 3);
        assert_eq!(handle.status().rejected, 0);
        let now = Instant::now();
        // Release the child's pending read only after the next accept failed.
        peer.write_all(b"\n").await.unwrap();
        for _ in 0..20 {
            tokio::task::yield_now().await;
            poll_server(&mut run);
            if handle.status().rejected == 1 {
                break;
            }
        }
        assert_eq!(
            handle.status().rejected,
            1,
            "accepted child must be driven during backoff"
        );
        assert_released(&handle);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 3);
        assert_eq!(Instant::now(), now);
        handle.stop();
        let status = run.now_or_never().expect("stop must interrupt backoff");
        assert!(status.stopped);
        assert_eq!(status.failed_tasks, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn closed_admission_is_fatal_without_retry_or_leaked_reservations() {
        let faults = Arc::new(AcceptFaults::default());
        let (handle, run) = faults.clone().bind().await;
        // Closed socket admission must release the earlier unbound reservation.
        handle.state.sockets.close();
        let status = run.now_or_never().expect("closed admission must stop");
        assert!(status.stopped);
        assert_eq!(status.failed_tasks, 1);
        assert_eq!(faults.attempts.load(Ordering::SeqCst), 0);
        assert_eq!(handle.status().sockets, 0);
        assert_eq!(handle.status().unbound_streams, 0);
    }

    fn config() -> ServerConfig {
        let (private_key, _) = syntra_core::secure_channel::generate_server_key().unwrap();
        ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            Authority::new("localhost:80").unwrap(),
            Arc::new(Security {
                mode: syntra_core::secure_channel::Mode::Bootstrap,
                carrier: Carrier::Http,
                server_key_id: 1,
                scope: b"reservation-test".to_vec(),
                private_key,
                store: None,
            }),
            Arc::new(|_: &syntra_core::secure_channel::VerifiedIdentity| -> Result<Arc<dyn syntra_runtime::Authenticator>, syntra_runtime::AuthError> {
                Ok(Arc::new(syntra_runtime::AllowAnonymous))
            }),
            Arc::new(syntra_runtime::FnHandler(|_, bytes, _| async {
                syntra_runtime::HandlerOutcome::Payload(bytes)
            })),
        )
    }

    #[tokio::test]
    async fn source_rate_rejections_preserve_global_tokens_for_other_sources() {
        let mut config = config();
        config.admission.open_burst = 3;
        config.admission.source_open_burst = 1;
        let (handle, run) = bind(config).await.unwrap();
        let now = std::time::Instant::now();
        let source = "127.0.0.1".parse().unwrap();
        assert_eq!(handle.state.rate(source, now), Ok(()));
        for _ in 0..100 {
            assert_eq!(handle.state.rate(source, now), Err(Rejection::Rate));
        }
        for source in ["127.0.0.2", "127.0.0.3"] {
            assert_eq!(handle.state.rate(source.parse().unwrap(), now), Ok(()));
        }
        assert_eq!(
            handle.state.rate("127.0.0.4".parse().unwrap(), now),
            Err(Rejection::Rate)
        );
        handle.stop();
        assert!(run.await.stopped);
    }

    #[tokio::test]
    async fn full_source_registry_preserves_unavailable_and_global_tokens() {
        let mut config = config();
        config.admission.source_entries = 1;
        config.admission.open_burst = 2;
        config.admission.source_open_burst = 3;
        let (handle, run) = bind(config).await.unwrap();
        let now = std::time::Instant::now();
        let source = "127.0.0.1".parse().unwrap();
        let other = "127.0.0.2".parse().unwrap();
        assert_eq!(handle.state.rate(source, now), Ok(()));
        for _ in 0..3 {
            assert_eq!(handle.state.rate(other, now), Err(Rejection::Unavailable));
        }
        assert_eq!(handle.state.rate(source, now), Ok(()));
        assert_eq!(handle.state.rate(other, now), Err(Rejection::Unavailable));
        assert_eq!(handle.state.rate(source, now), Err(Rejection::Rate));
        assert_eq!(lock(&handle.state.registry).sources.len(), 1);
        assert_eq!(
            handle.state.rate(other, now + Duration::from_secs(1)),
            Ok(())
        );
        handle.stop();
        assert!(run.await.stopped);
    }

    #[tokio::test]
    async fn global_rate_rejection_still_consumes_the_admitted_source_token() {
        let mut config = config();
        config.admission.open_burst = 1;
        config.admission.opens_per_second = 10;
        config.admission.source_open_burst = 1;
        config.admission.source_opens_per_second = 1;
        let (handle, run) = bind(config).await.unwrap();
        let now = std::time::Instant::now();
        let source = "127.0.0.2".parse().unwrap();
        assert_eq!(handle.state.rate("127.0.0.1".parse().unwrap(), now), Ok(()));
        assert_eq!(handle.state.rate(source, now), Err(Rejection::Rate));
        let refilled = now + Duration::from_millis(100);
        assert_eq!(handle.state.rate(source, refilled), Err(Rejection::Rate));
        assert_eq!(
            handle.state.rate("127.0.0.3".parse().unwrap(), refilled),
            Ok(())
        );
        handle.stop();
        assert!(run.await.stopped);
    }

    #[test]
    fn reservation_charges_terminal_payload_and_encoding_independently_of_executions() {
        let mut config = config();
        config.runtime.max_outstanding = 16;
        config.runtime.writer_capacity = 64;
        // Host::output is max_outstanding + writer_capacity, not execution_len.
        // Each selected terminal can retain a Frame payload AND encoded bytes
        // while reserve_writer waits. The separate channel retains another W.
        let terminals = config.runtime.max_outstanding + config.runtime.writer_capacity;
        let minimum = (2 * terminals + config.runtime.writer_capacity) * MAX_FRAME;
        assert!(config.reservation().unwrap() as usize * 1024 >= minimum);
        config.admission.aggregate_bytes = 128 * 1024 * 1024;
        assert!(matches!(config.validate(), Err(Error::Configuration)));
        // The default 256-MiB process budget must still permit a real connection.
        assert!(self::config().validate().is_ok());
    }

    #[test]
    fn route_collision_draws_are_bounded_and_never_overwrite_a_live_slot() {
        let mut draws = 0;
        let result = random_route_with(
            || {
                draws += 1;
                Ok([1; 32])
            },
            |_| true,
        );
        assert!(matches!(result, Err(Error::Closed)));
        assert_eq!(draws, 4);
        let route = random_route_with(|| Ok([0xab; 32]), |_| false).unwrap();
        assert_eq!(route.as_str(), "ab".repeat(32));
        assert!(!format!("{route:?}").contains(route.as_str()));
    }

    #[test]
    fn route_entropy_failure_has_no_lookup_or_retry() {
        let mut looked_up = false;
        let result = random_route_with(
            || Err(syntra_core::secure_channel::Error::Entropy.into()),
            |_| {
                looked_up = true;
                false
            },
        );
        assert!(matches!(
            result,
            Err(Error::Channel(syntra_core::secure_channel::Error::Entropy))
        ));
        assert!(!looked_up);
    }
}
