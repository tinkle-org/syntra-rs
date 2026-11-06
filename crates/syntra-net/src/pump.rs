//! Carrier-neutral bounded Syntra pump. Socket ownership stays in carrier modules.
use futures_util::future::BoxFuture;
use futures_util::task::{waker_ref, ArcWake, AtomicWaker};
use futures_util::FutureExt;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};
#[cfg(test)]
use syntra_core::secure_channel::respond;
use syntra_core::secure_channel::{
    frame_plaintext, respond_with_clock, Channel, ClientConfig, ClientHandshake,
    Clock as ChannelClock, FrameDecoder, ServerConfig, VerifiedIdentity, MAX_CIPHERTEXT,
    MAX_PLAINTEXT, MAX_WRAPPER,
};
use syntra_core::{
    decode_frame, proto::frame::Body, ConnectionState, ErrorCode, SyntraError, ValidationContext,
};
use syntra_runtime::connection::validate_close_grace;
use syntra_runtime::elapsed::ElapsedClock;
use syntra_runtime::recovery::wire::RecoveryService;
use syntra_runtime::terminal::{
    Coordinator, DriverCommand, Policy as TerminalPolicy, TerminalOutput,
};
use syntra_runtime::{
    AuthError, Authenticator, ConnectionConfig, ExecutionBudget, Handler, Host, Initiator,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::Instant,
};
use tracing::{debug, warn};
use zeroize::Zeroizing;

mod policy_jobs;
pub use policy_jobs::{PolicyJob, PolicyJobs};

/// Transport/policy ownership only, never an attestation that business effects
/// or external runtime execution leases have stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportShutdown {
    Complete,
    ShutdownIncomplete {
        carrier_tasks: usize,
        policy_jobs: usize,
    },
}

fn elapsed_now(clock: &ElapsedClock) -> Instant {
    Instant::from_std(clock.now())
}

pub(crate) fn default_elapsed_clock() -> ElapsedClock {
    #[cfg(test)]
    return ElapsedClock::lifecycle_driven();
    #[cfg(not(test))]
    ElapsedClock::new()
}

/// Recheck after polling too: a synchronous dependency may advance elapsed time
/// while returning Ready in the same poll. Expiry/continuity always wins.
pub(crate) async fn elapsed_timeout<T>(
    clock: &ElapsedClock,
    deadline: Instant,
    future: impl Future<Output = T>,
) -> Result<T, Error> {
    let value = clock
        .timeout_until(deadline.into_std(), future)
        .await
        .map_err(|_| Error::Timeout)?;
    if !clock.is_continuous() || elapsed_now(clock) >= deadline {
        return Err(Error::Timeout);
    }
    Ok(value)
}

/// One source and one absolute budget from outer carrier establishment through
/// secure channel/CoreReady, or required recovery retained by its owner. Moving
/// between layers must not mint another budget.
///
/// Create this before dialing, bound the dial with [`Self::run`], then move it to
/// [`connect_records_with_budget`] or [`accept_records_with_budget`]. It cannot be
/// cloned publicly or have its deadline reset. Dropping setup releases both record
/// halves; adapters must release partial I/O on cancellation and never detach it.
pub struct EstablishmentBudget {
    pub(crate) clock: ElapsedClock,
    started: Instant,
    channel_clock: ChannelClock,
    pub(crate) deadline: Instant,
    pub(crate) jobs: Option<Arc<PolicyJobs>>,
    pub(crate) io: Arc<AttemptIoBudget>,
}

/// Shared across every carrier stream, but separate from the exclusive I/O gate
/// so a route can still shorten its budget after the owner retains this phase.
pub(crate) struct EstablishmentCompletion {
    cutoff: Mutex<Instant>,
    deferred: AtomicBool,
    released: AtomicBool,
}

impl EstablishmentCompletion {
    pub(crate) fn pending(&self) -> bool {
        self.deferred.load(Ordering::Acquire) && !self.released.load(Ordering::Acquire)
    }

    #[cfg(any(feature = "http", feature = "cross-carrier-candidate", test))]
    pub(crate) fn restrict(&self, cutoff: Instant) -> Result<(), Error> {
        let mut current = self.cutoff.lock().map_err(|_| Error::Timeout)?;
        *current = (*current).min(cutoff);
        Ok(())
    }

    pub(crate) fn deadline(&self) -> Result<Instant, Error> {
        self.cutoff
            .lock()
            .map(|cutoff| *cutoff)
            .map_err(|_| Error::Timeout)
    }
}

/// Only the reconnect owner may release deferred establishment, after required
/// recovery is accepted. Dropping this handle never opens an unfinished gate.
#[cfg(any(feature = "reconnect", test))]
pub(crate) struct EstablishmentGuard(Arc<EstablishmentCompletion>, ElapsedClock);

#[cfg(any(feature = "reconnect", test))]
impl EstablishmentGuard {
    pub(crate) fn finish(&self) -> Result<(), Error> {
        let cutoff = self.0.cutoff.lock().map_err(|_| Error::Timeout)?;
        if !self.1.is_continuous() || elapsed_now(&self.1) >= *cutoff {
            return Err(Error::Timeout);
        }
        self.0.released.store(true, Ordering::Release);
        Ok(())
    }
}

/// Adapt the runtime's trusted elapsed domain without a dependency from the
/// kernel to the runtime. Sampling is synchronous and never invokes Core/I/O.
struct ChannelElapsed {
    clock: ElapsedClock,
    origin: std::time::Instant,
}
impl syntra_core::secure_channel::ElapsedSource for ChannelElapsed {
    fn elapsed(&self) -> Option<Duration> {
        if !self.clock.is_continuous() {
            return None;
        }
        self.clock.now().checked_duration_since(self.origin)
    }
}
pub(crate) struct AttemptIoBudget {
    terminal: Mutex<Option<Arc<Coordinator>>>,
    clock: ElapsedClock,
    deadline: Instant,
    phase_deadline: Mutex<Instant>,
    establishing: AtomicBool,
    pub(crate) completion: Arc<EstablishmentCompletion>,
}
impl AttemptIoBudget {
    pub fn check(&self) -> std::io::Result<()> {
        let unavailable = || {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Syntra establishment gate unavailable",
            )
        };
        if self
            .terminal
            .lock()
            .map_err(|_| unavailable())?
            .as_ref()
            .is_some_and(|c| !c.raw_allowed())
        {
            return Err(unavailable());
        }
        let phase = *self.phase_deadline.lock().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Syntra establishment gate unavailable",
            )
        })?;
        let establishing = self.establishing.load(Ordering::Acquire);
        let pending = self.completion.pending();
        let mut deadline = if establishing { phase } else { self.deadline };
        if pending {
            deadline = deadline.min(self.completion.deadline().map_err(|_| unavailable())?);
        }
        if !self.clock.is_continuous()
            || ((establishing || pending) && elapsed_now(&self.clock) >= deadline)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Syntra carrier establishment budget unavailable",
            ));
        }
        Ok(())
    }
    /// Setup is single-owner; native split I/O shares only this short per-poll
    /// gate. Phase changes never exceed the original total attempt deadline.
    pub(crate) fn until(&self, deadline: Instant) -> Result<(), Error> {
        *self.phase_deadline.lock().map_err(|_| Error::Timeout)? = deadline.min(self.deadline);
        self.check().map_err(|_| Error::Timeout)
    }
    pub(crate) fn finish(&self) {
        // CoreReady ends this phase, but an unreleased owner guard still gates
        // every raw poll through mandatory recovery using the original cutoff.
        self.establishing.store(false, Ordering::Release);
    }
}
impl EstablishmentBudget {
    pub fn new(clock: ElapsedClock, budget: Duration) -> Result<Self, Error> {
        if budget.is_zero() || budget > Duration::from_secs(15) {
            return Err(Error::Configuration);
        }
        let started = elapsed_now(&clock);
        let deadline = started.checked_add(budget).ok_or(Error::Configuration)?;
        Self::build(clock, started, deadline)
    }

    /// Adopt the owner's absolute cutoff, never a newly sampled duration.
    #[cfg(any(feature = "reconnect", test))]
    pub(crate) fn until(clock: ElapsedClock, deadline: std::time::Instant) -> Result<Self, Error> {
        let started = elapsed_now(&clock);
        Self::build(clock, started, Instant::from_std(deadline))
    }

    fn build(clock: ElapsedClock, started: Instant, deadline: Instant) -> Result<Self, Error> {
        if !clock.is_continuous() {
            return Err(Error::Timeout);
        }
        if elapsed_now(&clock) >= deadline {
            return Err(Error::Timeout);
        }
        if deadline.duration_since(started) > Duration::from_secs(15) {
            return Err(Error::Configuration);
        }
        let channel_clock = ChannelClock::with_source(Arc::new(ChannelElapsed {
            clock: clock.clone(),
            origin: started.into_std(),
        }));
        let completion = Arc::new(EstablishmentCompletion {
            cutoff: Mutex::new(deadline),
            deferred: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let io = Arc::new(AttemptIoBudget {
            terminal: Mutex::new(None),
            clock: clock.clone(),
            deadline,
            phase_deadline: Mutex::new(deadline),
            establishing: AtomicBool::new(true),
            completion: completion.clone(),
        });
        io.check().map_err(|_| Error::Timeout)?;
        Ok(Self {
            clock,
            started,
            channel_clock,
            deadline,
            jobs: None,
            io,
        })
    }

    #[cfg(any(feature = "reconnect", test))]
    pub(crate) fn defer_completion(&self) -> EstablishmentGuard {
        self.io.completion.deferred.store(true, Ordering::Release);
        EstablishmentGuard(self.io.completion.clone(), self.clock.clone())
    }

    /// Shrink before sharing the gate or starting I/O. Keep the original origin,
    /// channel clock and phase cutoff; a later cap cannot renew any allowance.
    #[cfg(any(feature = "cross-carrier-candidate", test))]
    pub(crate) fn cap(mut self, maximum: Duration) -> Result<Self, Error> {
        if maximum.is_zero() {
            return Err(Error::Configuration);
        }
        self.io.check().map_err(|_| Error::Timeout)?;
        let deadline = self
            .started
            .checked_add(maximum)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        let io = Arc::get_mut(&mut self.io).ok_or(Error::Configuration)?;
        if !io.establishing.load(Ordering::Acquire) {
            return Err(Error::Configuration);
        }
        let phase = io.phase_deadline.get_mut().map_err(|_| Error::Timeout)?;
        *phase = (*phase).min(deadline);
        io.deadline = deadline;
        self.deadline = deadline;
        io.completion.restrict(deadline)?;
        io.check().map_err(|_| Error::Timeout)?;
        Ok(self)
    }
    pub async fn run<T>(&self, future: impl Future<Output = T>) -> Result<T, Error> {
        elapsed_timeout(&self.clock, self.deadline, future).await
    }

    /// The absolute cutoff in this budget's elapsed-clock domain. Capping can
    /// only shorten it; no handoff creates a fresh allowance.
    pub fn deadline(&self) -> std::time::Instant {
        self.deadline.into_std()
    }

    /// Accepted-stream phases include time before their inline job first polls.
    /// This observes the immutable origin; it never creates another allowance.
    #[cfg(feature = "http")]
    pub(crate) fn initial_deadline(&self, maximum: Duration) -> Instant {
        self.started
            .checked_add(maximum)
            .unwrap_or(self.deadline)
            .min(self.deadline)
    }

    /// Native adapters gate each underlying poll, including opaque TLS loops.
    /// Only this crate may share that gate; finishing one connection must never
    /// disable establishment checks for an unrelated external dial.
    #[cfg(any(feature = "websocket", feature = "http"))]
    pub(crate) fn clone(&self) -> Self {
        Self {
            clock: self.clock.clone(),
            started: self.started,
            channel_clock: self.channel_clock.clone(),
            deadline: self.deadline,
            jobs: self.jobs.clone(),
            io: self.io.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Channel(#[from] syntra_core::secure_channel::Error),
    #[error("Syntra I/O failed")]
    Io(#[from] std::io::Error),
    #[error("Syntra carrier framing rejected")]
    Framing,
    #[error("Syntra operation timed out")]
    Timeout,
    #[error("Syntra authentication rejected")]
    Authentication,
    #[error("Syntra runtime handshake rejected")]
    Runtime,
    /// Locally detected Core failure. Dependency/peer diagnostic text is discarded;
    /// this code is never emitted as an error frame during establishment.
    #[error("Syntra local protocol failure ({0:?})")]
    LocalProtocol(ErrorCode),
    #[error("Syntra configuration rejected")]
    Configuration,
    #[error("Syntra connection closed")]
    Closed,
}

/// Local transport outcome only: no diagnostic text, secrets or fabricated wire error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportFailure {
    Configuration,
    Authentication,
    Channel,
    Runtime,
    LocalProtocol(ErrorCode),
    Framing,
    Io,
    Timeout,
    Closed,
}

impl TransportFailure {
    pub(crate) fn of(error: &Error) -> Self {
        match error {
            Error::Configuration => Self::Configuration,
            Error::Authentication => Self::Authentication,
            Error::Channel(_) => Self::Channel,
            Error::Runtime => Self::Runtime,
            Error::LocalProtocol(code) => Self::LocalProtocol(*code),
            Error::Framing => Self::Framing,
            Error::Io(_) => Self::Io,
            Error::Timeout => Self::Timeout,
            Error::Closed => Self::Closed,
        }
    }

    pub(crate) fn terminal(self) -> bool {
        !matches!(self, Self::Io | Self::Timeout | Self::Closed)
    }
}

#[derive(Clone, Default)]
struct TransportTerminal(Arc<Mutex<Option<TransportFailure>>>);

impl TransportTerminal {
    fn get(&self) -> Option<TransportFailure> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record(&self, failure: TransportFailure) {
        let mut current = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // A generic EOF/cleanup may win the first task race, but must never hide
        // the first locally observed security failure from the other direction.
        if current.is_none_or(|old| !old.terminal() && failure.terminal()) {
            *current = Some(failure);
        }
    }

    fn result(&self, result: &Result<(), Error>) {
        if let Err(error) = result {
            self.record(TransportFailure::of(error));
        }
    }
}

/// Record unwinding before the owner signals loss; cancellation alone is not panic.
struct TransportPanicGuard(TransportTerminal);
impl Drop for TransportPanicGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.record(TransportFailure::Runtime);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    /// Total carrier setup through Core readiness, positive and at most 15 s.
    pub attempt_timeout: Duration,
    /// Noise plus the first encrypted hello/confirmation, at most 5 s total.
    pub channel_timeout: Duration,
    /// Includes idle time before the next record; bounded silent connections.
    pub record_timeout: Duration,
    pub frame_timeout: Duration,
    /// One entire frame's output across all of its records, at most 10 s.
    pub write_timeout: Duration,
    /// Carrier shutdown/owner join budget, separate from application close grace.
    pub close_timeout: Duration,
    /// Channel age from original budget creation, including setup, at most 24 h.
    pub lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(15),
            channel_timeout: Duration::from_secs(5),
            record_timeout: Duration::from_secs(30),
            frame_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(1),
            lifetime: Duration::from_secs(86_400),
        }
    }
}
impl Limits {
    pub fn validate(&self, runtime: &ConnectionConfig) -> Result<(), Error> {
        runtime.validate().map_err(|_| Error::Configuration)?;
        let durations = [
            self.attempt_timeout,
            self.channel_timeout,
            self.record_timeout,
            self.frame_timeout,
            self.write_timeout,
            self.close_timeout,
            self.lifetime,
        ];
        if durations
            .iter()
            .any(|d| d.is_zero() || *d > Duration::from_secs(86_400))
        {
            return Err(Error::Configuration);
        }
        if self.attempt_timeout > Duration::from_secs(15)
            || self.channel_timeout > Duration::from_secs(5)
            || self.write_timeout > Duration::from_secs(10)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Process-wide aggregate execution cap for Syntra hosts using the default factory
/// budget, including external work retaining an execution lease. Independent of
/// each connection's `max_outstanding` and its protocol capacity floor of 16.
pub const DEFAULT_AGGREGATE_EXECUTION_LIMIT: usize = 1024;

static DEFAULT_EXECUTION_BUDGET: OnceLock<ExecutionBudget> = OnceLock::new();

/// Called only after authenticated client data reconstructs a valid first hello.
/// Returning authorization must re-check current enrollment policy here. A factory
/// can capture the private-constructed identity in an Authenticator wrapper.
pub trait AuthenticatorFactory: Send + Sync {
    /// Explicit per-verified-binding terminal policy, disabled by default. Only
    /// native TCP accepts this today. The adapter supplies complete operation-
    /// aware connection authority; configuring generic authorization alongside
    /// it is refused rather than interpreting an AuthError as commit evidence.
    fn terminal_receipt(&self, _identity: &VerifiedIdentity) -> Option<TerminalPolicy> {
        None
    }
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError>;

    /// One process-local clock shared by establishment, Core and policy checks.
    /// No timestamp from this clock is persisted in an enrollment record.
    fn elapsed_clock(&self) -> ElapsedClock {
        default_elapsed_clock()
    }

    /// Retained factory-scoped synchronous policy owners. Counts can include
    /// other connections sharing this factory; reporting is conservative.
    fn policy_jobs(&self) -> Option<Arc<PolicyJobs>> {
        None
    }

    /// Prompt configuration-only validation. Lifecycle factories can require the
    /// exact same enrollment store for Noise admission and pre-ready policy so a
    /// tuple from a different store cannot be spliced into their authorization.
    fn validate_server_config(&self, _security: &ServerConfig) -> Result<(), AuthError> {
        Ok(())
    }

    /// Async preparation for stores requiring blocking I/O. The default preserves
    /// existing prompt, synchronous factories; implementations may use a bounded
    /// blocking lane. Cancelling preparation must never create authorization.
    fn prepare<'a>(
        &'a self,
        identity: &'a VerifiedIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn Authenticator>, AuthError>> {
        Box::pin(async move { self.create(identity) })
    }

    /// Optional host-owned current-validity gate. The pump checks it before hello
    /// authentication, again before ready, before inbound dispatch and outbound
    /// delivery, and while idle. It does NOT replace per-method authorization or
    /// application effect-commit fencing inside an already-running handler.
    fn connection_authorization(
        &self,
        _identity: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        Ok(None)
    }

    /// Bounded lane for a synchronous enrollment KeyStore. A permit remains held
    /// by the blocking handshake until it actually exits, even if accept is
    /// cancelled. None keeps existing nonblocking/in-memory stores unchanged.
    fn blocking_admission(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        None
    }

    /// Aggregate execution policy for accepted hosts. All factories using this
    /// default (including closures) share one process-wide budget capped at
    /// [`DEFAULT_AGGREGATE_EXECUTION_LIMIT`], across connections and replacements.
    ///
    /// Override to clone a host- or principal-owned budget reused across every
    /// connection/replacement in that scope; never create a fresh budget here.
    /// Stricter quotas (including below 16) do not lower the core RPC capacity.
    /// This hook must return promptly without blocking. External work must retain
    /// its execution lease until it actually stops, independent of transport close.
    fn execution_budget(&self) -> ExecutionBudget {
        DEFAULT_EXECUTION_BUDGET
            .get_or_init(|| ExecutionBudget::new(DEFAULT_AGGREGATE_EXECUTION_LIMIT))
            .clone()
    }

    /// Server-owned recovery policy, disabled by default. Called once per accepted
    /// host before hello ingestion; must return promptly without blocking. Never
    /// derive this choice from client hints or unauthenticated carrier headers.
    /// The runtime binds the immutable service to the actual core principal only
    /// after authentication, not to an identity supplied by this hook.
    fn recovery_service(&self) -> Option<Arc<RecoveryService>> {
        None
    }
}

/// Current-validity checks never infer application identity from AK possession.
/// Implementations must use authoritative reads, fail closed, and keep actual
/// blocking work accounted for after cancellation of a check future.
pub trait ConnectionAuthorization: Send + Sync {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>>;
    fn interval(&self) -> Duration;
    fn read_timeout(&self) -> Duration;
    fn close_timeout(&self) -> Duration;
}

struct FreshAuthorization {
    terminal: Option<Arc<Coordinator>>,
    base: Arc<dyn ConnectionAuthorization>,
    clock: ElapsedClock,
    interval: Duration,
    read: Duration,
    close: Duration,
    state: Mutex<(Option<Instant>, bool)>,
}

/// Internal typed-authority bridge; generic authorization is never reclassified.
struct TerminalAuthorization(Arc<Coordinator>);
impl ConnectionAuthorization for TerminalAuthorization {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async {
            self.0
                .refresh()
                .await
                .map_err(|_| AuthError::unauthenticated())
        })
    }
    fn interval(&self) -> Duration {
        self.0.read_timeout() / 2
    }
    fn read_timeout(&self) -> Duration {
        self.0.read_timeout()
    }
    fn close_timeout(&self) -> Duration {
        Duration::from_millis(250)
    }
}

impl FreshAuthorization {
    fn new(base: Arc<dyn ConnectionAuthorization>, clock: ElapsedClock) -> Result<Self, Error> {
        let (interval, read, close) = (base.interval(), base.read_timeout(), base.close_timeout());
        let total = interval
            .checked_add(read)
            .and_then(|d| d.checked_add(close))
            .ok_or(Error::Configuration)?;
        if interval.is_zero()
            || read.is_zero()
            || read > interval
            || close.is_zero()
            || total > Duration::from_secs(300)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            terminal: None,
            base,
            clock,
            interval,
            read,
            close,
            state: Mutex::new((None, false)),
        })
    }

    /// Hot-path gate only: successful polls never renew authority. Establishment
    /// and the watchdog must call check() to perform authoritative reads.
    async fn check_cached(&self) -> Result<(), AuthError> {
        if let Some(terminal) = &self.terminal {
            return terminal
                .with_io(|| ())
                .ok_or_else(AuthError::unauthenticated);
        }
        {
            // No await or dependency I/O under this short synchronous state lock.
            let mut state = self
                .state
                .lock()
                .map_err(|_| AuthError::unauthenticated())?;
            if state.1
                || !self.clock.is_continuous()
                || state
                    .0
                    .is_some_and(|until| elapsed_now(&self.clock) >= until)
            {
                state.1 = true;
                return Err(AuthError::unauthenticated());
            }
            if state.0.is_some() {
                return Ok(());
            }
        }
        // An uninitialized cache is never evidence of authorization.
        self.check().await
    }
}

impl ConnectionAuthorization for FreshAuthorization {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async move {
            if let Some(terminal) = &self.terminal {
                return terminal
                    .refresh()
                    .await
                    .map_err(|_| AuthError::unauthenticated());
            }
            let start = elapsed_now(&self.clock);
            let deadline = {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| AuthError::unauthenticated())?;
                if state.1
                    || !self.clock.is_continuous()
                    || state.0.is_some_and(|until| start >= until)
                {
                    state.1 = true;
                    return Err(AuthError::unauthenticated());
                }
                (start + self.read).min(
                    state
                        .0
                        .map_or(start + self.read, |until| until - self.close),
                )
            };
            let result = elapsed_timeout(&self.clock, deadline, self.base.check()).await;
            let mut state = self
                .state
                .lock()
                .map_err(|_| AuthError::unauthenticated())?;
            if !matches!(result, Ok(Ok(())))
                || state.1
                || state
                    .0
                    .is_some_and(|until| elapsed_now(&self.clock) >= until)
            {
                state.1 = true;
                return Err(AuthError::unauthenticated());
            }
            // Start-of-read is conservative even when a store samples validity
            // early and its response is delayed. A failed/lapsed parallel check
            // is sticky and can never be resurrected by a later success.
            let until = start + self.interval + self.read + self.close;
            state.0 = Some(state.0.map_or(until, |old| old.max(until)));
            Ok(())
        })
    }
    fn interval(&self) -> Duration {
        self.interval
    }
    fn read_timeout(&self) -> Duration {
        self.read
    }
    fn close_timeout(&self) -> Duration {
        self.close
    }
}

async fn check_authorization(
    guard: &Option<Arc<FreshAuthorization>>,
    clock: &ElapsedClock,
) -> Result<(), Error> {
    if !clock.is_continuous() {
        return Err(Error::Authentication);
    }
    let Some(guard) = guard else { return Ok(()) };
    guard
        .check_cached()
        .await
        .map_err(|_| Error::Authentication)
}

async fn refresh_authorization(
    guard: &Option<Arc<FreshAuthorization>>,
    clock: &ElapsedClock,
) -> Result<(), Error> {
    if !clock.is_continuous() {
        return Err(Error::Authentication);
    }
    let Some(guard) = guard else { return Ok(()) };
    if guard.terminal.is_some() {
        // The coordinator bounds queue wait and the actual serialized read
        // separately against current freshness and the immutable cutoff.
        return guard.check().await.map_err(|_| Error::Authentication);
    }
    let deadline = elapsed_now(clock) + guard.read_timeout();
    elapsed_timeout(clock, deadline, guard.check())
        .await
        .map_err(|_| Error::Authentication)?
        .map_err(|_| Error::Authentication)
}
impl<F> AuthenticatorFactory for F
where
    F: Fn(&VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> + Send + Sync,
{
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        self(identity)
    }
}

/// Opt an existing factory (including a closure) into server-owned recovery.
/// Authentication and aggregate execution policy remain the base factory's.
pub struct RecoveryAuthenticatorFactory<F: AuthenticatorFactory> {
    base: F,
    service: Arc<RecoveryService>,
}

impl<F: AuthenticatorFactory> RecoveryAuthenticatorFactory<F> {
    pub fn new(base: F, service: Arc<RecoveryService>) -> Self {
        Self { base, service }
    }
}

impl<F: AuthenticatorFactory> AuthenticatorFactory for RecoveryAuthenticatorFactory<F> {
    fn terminal_receipt(&self, identity: &VerifiedIdentity) -> Option<TerminalPolicy> {
        self.base.terminal_receipt(identity)
    }
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        self.base.create(identity)
    }

    fn elapsed_clock(&self) -> ElapsedClock {
        self.base.elapsed_clock()
    }

    fn policy_jobs(&self) -> Option<Arc<PolicyJobs>> {
        self.base.policy_jobs()
    }

    fn validate_server_config(&self, security: &ServerConfig) -> Result<(), AuthError> {
        self.base.validate_server_config(security)
    }

    fn prepare<'a>(
        &'a self,
        identity: &'a VerifiedIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn Authenticator>, AuthError>> {
        self.base.prepare(identity)
    }

    fn connection_authorization(
        &self,
        identity: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        self.base.connection_authorization(identity)
    }

    fn blocking_admission(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        self.base.blocking_admission()
    }

    fn execution_budget(&self) -> ExecutionBudget {
        self.base.execution_budget()
    }

    fn recovery_service(&self) -> Option<Arc<RecoveryService>> {
        Some(self.service.clone())
    }
}

pub trait RecordReader: Send + 'static {
    /// Polling must be nonblocking and must not reenter Core or app callbacks;
    /// the pump serializes raw polls with suspend using Core's carrier I/O gate.
    fn read_record(
        &mut self,
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
}
pub trait RecordWriter: Send + 'static {
    /// Complete one retained ciphertext, including partial writes, or return a fatal error.
    /// Polls must not block, reenter Core, or invoke application callbacks.
    fn write_record(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
    fn shutdown(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Retain one immutable ciphertext future across backpressure. Before polling it
/// again after Pending, check cached freshness/withdrawal and the lifecycle gate.
/// The watchdog performs authoritative reads independently of carrier activity.
/// Withdrawal drops this partially written unit and aborts the carrier; it never
/// retries/re-encrypts/relabels a consumed nonce. No application effect atomicity
/// is implied by this transport handoff boundary.
async fn write_checked<W: RecordWriter>(
    writer: &mut W,
    bytes: &[u8],
    clock: &ElapsedClock,
    deadline: Instant,
    peer: Option<&Peer>,
    authorization: &Option<Arc<FreshAuthorization>>,
) -> Result<(), Error> {
    authorized_io(
        writer.write_record(bytes),
        clock,
        deadline,
        peer,
        authorization,
    )
    .await
}

struct IoWake {
    ready: AtomicBool,
    parent: AtomicWaker,
}
impl ArcWake for IoWake {
    fn wake_by_ref(this: &Arc<Self>) {
        this.ready.store(true, Ordering::Release);
        this.parent.wake();
    }
}

async fn authorized_io<T>(
    io: impl Future<Output = Result<T, Error>>,
    clock: &ElapsedClock,
    deadline: Instant,
    peer: Option<&Peer>,
    authorization: &Option<Arc<FreshAuthorization>>,
) -> Result<T, Error> {
    authorized_io_inner(io, clock, deadline, peer, authorization, None).await
}

async fn authorized_io_inner<T>(
    io: impl Future<Output = Result<T, Error>>,
    clock: &ElapsedClock,
    deadline: Instant,
    peer: Option<&Peer>,
    authorization: &Option<Arc<FreshAuthorization>>,
    receipt: Option<(&Coordinator, &TerminalOutput)>,
) -> Result<T, Error> {
    elapsed_timeout(clock, deadline, async {
        let mut first = true;
        tokio::pin!(io);
        let wake = Arc::new(IoWake {
            ready: AtomicBool::new(false),
            parent: AtomicWaker::new(),
        });
        loop {
            check_authorization(authorization, clock).await?;
            if peer.is_some_and(|p| !p.delivery_open()) {
                return Err(Error::Closed);
            }
            let mut polled = false;
            let result = futures_util::future::poll_fn(|cx| {
                wake.parent.register(cx.waker());
                if !clock.is_continuous() || elapsed_now(clock) >= deadline {
                    return std::task::Poll::Ready(Some(Err(Error::Timeout)));
                }
                if peer.is_some_and(|p| !p.delivery_open()) {
                    return std::task::Poll::Ready(Some(Err(Error::Closed)));
                }
                if polled {
                    // Elapsed timer slices also wake the parent. They must not
                    // turn an idle reader into a policy-store polling loop.
                    if !wake.ready.swap(false, Ordering::AcqRel) {
                        return std::task::Poll::Pending;
                    }
                    return std::task::Poll::Ready(None);
                }
                wake.ready.store(false, Ordering::Release);
                polled = true;
                let waker = waker_ref(&wake);
                let mut io_context = std::task::Context::from_waker(&waker);
                // Only the synchronous, nonblocking raw carrier poll belongs
                // inside this gate. Policy awaits and Core prepare/ingest stay
                // outside; suspend and this poll now have one linearization.
                let mut poll = || {
                    // Waiting to acquire the serialized gate can itself consume
                    // the remaining budget. Check inside, without reentering Core.
                    if !clock.is_continuous() || elapsed_now(clock) >= deadline {
                        return Ok(std::task::Poll::Ready(Err(Error::Timeout)));
                    }
                    // Preserve the panic, but release Core's serialized gate
                    // before unwinding so teardown can still join both children.
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        io.as_mut().poll(&mut io_context)
                    }))
                };
                let result = match (peer, receipt) {
                    (Some(Peer::Host(host)), Some((coordinator, output))) => coordinator
                        .with_receipt_io(output, &mut first, || host.with_carrier_io(poll))
                        .flatten()
                        .unwrap_or(Ok(std::task::Poll::Ready(Err(Error::Closed)))),
                    (Some(peer), _) => peer
                        .with_carrier_io(poll)
                        .unwrap_or(Ok(std::task::Poll::Ready(Err(Error::Closed)))),
                    (None, _) => poll(),
                };
                match result {
                    Ok(result) => result.map(Some),
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            })
            .await;
            if let Some(result) = result {
                return result;
            }
        }
    })
    .await?
}

async fn read_checked<R: RecordReader>(
    reader: &mut R,
    maximum: usize,
    clock: &ElapsedClock,
    deadline: Instant,
    peer: Option<&Peer>,
    authorization: &Option<Arc<FreshAuthorization>>,
) -> Result<Vec<u8>, Error> {
    // A split WS reader can flush queued protected writer data as well as
    // automatic Pong/Close bytes. Apply the same freshness/withdrawal boundary.
    authorized_io(
        reader.read_record(maximum),
        clock,
        deadline,
        peer,
        authorization,
    )
    .await
}

pub struct ClientHandle {
    pub conn: Initiator,
    pub connection_id: String,
    pub version: u32,
    pump: Option<Pump>,
}
impl ClientHandle {
    /// Sticky local category. Read again after joined teardown to settle task races.
    #[cfg(feature = "reconnect")]
    pub(crate) fn transport_failure(&self) -> Option<TransportFailure> {
        self.pump.as_ref().and_then(|pump| pump.terminal.get())
    }

    pub fn suspend(&self) {
        self.conn.suspend();
    }
    pub async fn platform_wake(&self) {
        self.conn.platform_wake().await;
    }

    /// Abort transport admission and join within one elapsed deadline. A timeout
    /// leaves the owner handle in `self`, so retry/drop does not detach it.
    /// Core's first shutdown budget is authoritative; retries never extend it.
    pub async fn shutdown_transport(
        &mut self,
        grace: Duration,
    ) -> Result<TransportShutdown, Error> {
        match &mut self.pump {
            Some(pump) => pump.shutdown_transport(grace).await,
            None => Ok(TransportShutdown::Complete),
        }
    }
    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }
    /// Compatibility stop/wait, not a full shutdown attestation. Core retains
    /// unfinished ownership; use shutdown_transport and conn.shutdown_report.
    pub async fn close(mut self) {
        if let Some(pump) = self.pump.take() {
            pump.close().await;
        }
    }
    /// Stop runtime admission and flush all admitted carrier output within one grace.
    /// Returns Timeout rather than success when a zero/expired budget cannot
    /// establish joined completion. Core retains any unfinished work.
    pub async fn close_gracefully(mut self, grace: Duration) -> Result<(), Error> {
        self.pump
            .take()
            .ok_or(Error::Closed)?
            .close_gracefully(grace)
            .await
    }
}

pub struct HostHandle {
    pub host: Arc<Host>,
    pub identity: VerifiedIdentity,
    pump: Option<Pump>,
}
impl HostHandle {
    pub fn suspend(&self) {
        self.host.suspend();
    }
    pub async fn platform_wake(&self) {
        self.host.platform_wake().await;
    }

    pub async fn shutdown_transport(
        &mut self,
        grace: Duration,
    ) -> Result<TransportShutdown, Error> {
        match &mut self.pump {
            Some(pump) => pump.shutdown_transport(grace).await,
            None => Ok(TransportShutdown::Complete),
        }
    }
    pub fn is_closed(&self) -> bool {
        self.host.is_closed()
    }
    /// Compatibility stop/wait; inspect host.shutdown_report for retained work.
    pub async fn close(mut self) {
        if let Some(pump) = self.pump.take() {
            pump.close().await;
        }
    }
    /// Stop runtime admission and flush terminal results, including a frame already
    /// dequeued by the pump. Failure or grace expiry aborts unfinished output.
    /// A zero budget may return Timeout while Core retains the closing owner.
    pub async fn close_gracefully(mut self, grace: Duration) -> Result<(), Error> {
        self.pump
            .take()
            .ok_or(Error::Closed)?
            .close_gracefully(grace)
            .await
    }
}

/// Dropping even a partially constructed connect future signals the owner task.
/// The owner stops both children, settles runtime callers, and drops the carrier.
struct GracefulClose {
    deadline: Instant,
    drain_cutoff: Instant,
    done: oneshot::Sender<Result<(), Error>>,
}

struct Pump {
    terminal: TransportTerminal,
    stop: Option<oneshot::Sender<()>>,
    graceful: mpsc::Sender<GracefulClose>,
    // Core retains the same join owner even if a consuming close/waiter drops.
    // OwnedTask::join_until uses completion-preserving timeout_until, not the
    // strict post-poll deadline helper used for unselected I/O/policy results.
    task: Option<syntra_runtime::shutdown::OwnedTask>,
    grace: Duration,
    clock: ElapsedClock,
    policy_jobs: Option<Arc<PolicyJobs>>,
    peer: Peer,
    shutdown_deadline: Option<Instant>,
}
impl Pump {
    async fn shutdown_transport(&mut self, grace: Duration) -> Result<TransportShutdown, Error> {
        validate_close_grace(grace).map_err(|_| Error::Configuration)?;
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let budget = self.peer.begin_shutdown(grace)?;
        let deadline = *self
            .shutdown_deadline
            .get_or_insert(Instant::from_std(budget.deadline));
        // Core is the sole pending join waiter for its retained task registry.
        // Do not replace its JoinHandle waker with a second pending join here.
        // shutdown() itself uses completion-preserving timeout_until.
        let _ = self.peer.shutdown(grace).await?;
        if let Some(task) = &self.task {
            if task.is_finished() && task.join_until(&self.clock, deadline.into_std()).await {
                self.task = None;
            }
        }
        loop {
            let carrier_tasks = usize::from(self.task.is_some());
            let policy_jobs = self.policy_jobs.as_ref().map_or(0, |jobs| jobs.pending());
            if carrier_tasks == 0 && policy_jobs == 0 {
                return Ok(TransportShutdown::Complete);
            }
            if !self.clock.is_continuous() || elapsed_now(&self.clock) >= deadline {
                return Ok(TransportShutdown::ShutdownIncomplete {
                    carrier_tasks,
                    policy_jobs,
                });
            }
            self.clock
                .sleep_until(
                    (elapsed_now(&self.clock) + Duration::from_millis(10))
                        .min(deadline)
                        .into_std(),
                )
                .await;
        }
    }
    async fn close_gracefully(mut self, grace: Duration) -> Result<(), Error> {
        validate_close_grace(grace).map_err(|_| Error::Configuration)?;
        if grace.is_zero() {
            return match self.shutdown_transport(grace).await? {
                TransportShutdown::Complete => Ok(()),
                TransportShutdown::ShutdownIncomplete { .. } => Err(Error::Timeout),
            };
        }
        let budget = self.peer.begin_shutdown(grace)?;
        let deadline = Instant::from_std(budget.deadline);
        let (done, completed) = oneshot::channel();
        self.graceful
            .try_send(GracefulClose {
                deadline,
                drain_cutoff: Instant::from_std(budget.drain_cutoff),
                done,
            })
            .map_err(|_| Error::Closed)?;
        let result = elapsed_timeout(&self.clock, deadline, completed)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Closed)?;
        let runtime = self.peer.shutdown(grace).await?;
        if let Some(task) = &self.task {
            if !task.is_finished() || !task.join_until(&self.clock, deadline.into_std()).await {
                return Err(Error::Timeout);
            }
            self.task = None;
        }
        result?;
        if self.shutdown_transport(grace).await? != TransportShutdown::Complete {
            return Err(Error::Timeout);
        }
        if runtime.failed_tasks != 0 {
            return Err(Error::Closed);
        }
        if runtime.phase != syntra_runtime::ShutdownPhase::Complete {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = &self.task {
            // The stop signal is sent before awaiting; the owner also finishes
            // teardown if this close future is cancelled while waiting.
            let budget = self.peer.begin_shutdown(self.grace);
            let deadline = budget
                .map(|b| b.deadline)
                .unwrap_or_else(|_| self.clock.now() + self.grace);
            // Never abort this owner: it is responsible for actually joining its
            // children. A timed-out consuming close leaves it in Core's registry.
            let _ = self.peer.shutdown(self.grace).await;
            if task.is_finished() {
                let _ = task.join_until(&self.clock, deadline).await;
            }
        }
    }
}
impl Drop for Pump {
    fn drop(&mut self) {
        // Signal stop without detaching the join: Core retains OwnedTask and can
        // report ShutdownIncomplete until carrier teardown and actual join.
        debug!(failure = ?self.terminal.get(), "Syntra pump dropped; signalling owner stop");
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[derive(Clone)]
enum Peer {
    Client(Initiator),
    Host(Arc<Host>),
}
impl Peer {
    /// Publish connection-fatal reader failure at the same serialized gate as
    /// receipt handoff, before diagnostics/completion can wake the parent owner.
    /// Poisoning a channel alone cannot stop an already-encrypted pending write.
    fn abort_terminal_output(&self) {
        if let Self::Host(host) = self {
            if let Some(coordinator) = host.terminal_coordinator() {
                coordinator.abort();
            }
        }
    }

    fn with_carrier_io<T>(&self, poll: impl FnOnce() -> T) -> Option<T> {
        match self {
            Self::Client(c) => c.with_carrier_io(poll),
            Self::Host(h) => match h.terminal_coordinator() {
                Some(c) => c.with_io(|| h.with_carrier_io(poll)).flatten(),
                None => h.with_carrier_io(poll),
            },
        }
    }

    fn own_task(&self, task: tokio::task::JoinHandle<()>) -> syntra_runtime::shutdown::OwnedTask {
        match self {
            Self::Client(c) => c.own_native_task(task),
            Self::Host(h) => h.own_native_task(task),
        }
    }

    fn begin_shutdown(&self, total: Duration) -> Result<syntra_runtime::ShutdownBudget, Error> {
        match self {
            Self::Client(c) => c.begin_shutdown(total),
            Self::Host(h) => h.begin_shutdown(total),
        }
        .map_err(|_| Error::Configuration)?;
        match self {
            Self::Client(c) => c.shutdown_budget(),
            Self::Host(h) => h.shutdown_budget(),
        }
        .ok_or(Error::Closed)
    }

    async fn shutdown(&self, total: Duration) -> Result<syntra_runtime::ShutdownReport, Error> {
        match self {
            Self::Client(c) => c.shutdown(total).await,
            Self::Host(h) => h.shutdown(total).await,
        }
        .map_err(|_| Error::Configuration)
    }
    fn register_tasks(&self, count: usize) -> Result<(), Error> {
        match self {
            Self::Client(c) => c.register_transport_tasks(count),
            Self::Host(h) => h.register_transport_tasks(count),
        }
        .map_err(|_| Error::Closed)
    }

    fn task_joined(&self) {
        let result = match self {
            Self::Client(c) => c.acknowledge_transport_task_joined(),
            Self::Host(h) => h.acknowledge_transport_task_joined(),
        };
        assert!(result.is_ok(), "Syntra transport task ownership underflow");
    }

    fn carrier_closed(&self) {
        match self {
            Self::Client(c) => c.acknowledge_transport_closed(),
            Self::Host(h) => h.acknowledge_transport_closed(),
        }
    }
    fn clock(&self) -> ElapsedClock {
        match self {
            Self::Client(c) => c.elapsed_clock(),
            Self::Host(h) => h.elapsed_clock(),
        }
    }

    fn delivery_open(&self) -> bool {
        let lifecycle = match self {
            Self::Client(c) => c.carrier_io_allowed(),
            Self::Host(h) => h.carrier_io_allowed(),
        };
        lifecycle && (!self.closed() || self.ordinary_close())
    }
    // Receipt affects host RPC budgets only; initiator correlation has its own clock.
    async fn ingest_received_at(&self, bytes: &[u8], received_at: std::time::Instant) {
        match self {
            Self::Client(c) => c.ingest(bytes).await,
            Self::Host(h) => h.ingest_received_at(bytes, received_at).await,
        }
    }
    async fn lost(&self) {
        match self {
            Self::Client(c) => c.on_transport_lost().await,
            Self::Host(h) => h.on_transport_lost().await,
        }
    }
    fn closed(&self) -> bool {
        match self {
            Self::Client(c) => c.is_closed(),
            Self::Host(h) => h.is_closed(),
        }
    }
    fn subscribe(&self) -> watch::Receiver<bool> {
        match self {
            Self::Client(c) => c.subscribe_close(),
            Self::Host(h) => h.subscribe_close(),
        }
    }
    fn ordinary_close(&self) -> bool {
        let reason = match self {
            Self::Client(c) => c.terminal_reason(),
            Self::Host(h) => h.terminal_reason(),
        };
        matches!(reason, Some(SyntraError::Closed(_)))
    }
}

/// Observe both the sticky initial value and later notifications. Subscribe before
/// inspecting the peer so a close between inspection and the first poll is retained.
async fn wait_closed(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
}

/// Outcome of the first pump task to finish, as observed by the owner.
type TerminalTask = Option<Result<(Direction, Result<(), Error>), tokio::task::JoinError>>;
type PumpTasks = JoinSet<(Direction, Result<(), Error>)>;

#[derive(Default)]
struct ReceiveState {
    decoder: FrameDecoder,
    frame_deadline: Option<Instant>,
}

impl From<FrameDecoder> for ReceiveState {
    fn from(decoder: FrameDecoder) -> Self {
        Self {
            decoder,
            frame_deadline: None,
        }
    }
}

type ReceivedFrame = (Zeroizing<Vec<u8>>, std::time::Instant);

/// Extract and timestamp the entire bounded batch before validation or delivery.
/// A lazy iterator here would renew later frames' budgets after an earlier await.
fn received_frames(
    decoder: &mut FrameDecoder,
    plaintext: &[u8],
    clock: &ElapsedClock,
) -> Result<Vec<ReceivedFrame>, Error> {
    Ok(decoder
        .push(plaintext)?
        .into_iter()
        .map(|frame| (Zeroizing::new(frame), clock.now()))
        .collect())
}

async fn read_frames<R, F, Fut>(
    mut reader: R,
    channel: Arc<Mutex<Channel>>,
    receive: ReceiveState,
    end: Instant,
    limits: Limits,
    context: ReadContext,
    mut ingest: F,
) -> Result<(), Error>
where
    R: RecordReader,
    F: FnMut(Zeroizing<Vec<u8>>, std::time::Instant) -> Fut,
    Fut: Future<Output = Result<(), Error>>,
{
    let ReadContext {
        clock,
        peer,
        authorization,
    } = context;
    let ReceiveState {
        mut decoder,
        frame_deadline,
    } = receive;
    let mut frame_deadline = frame_deadline.or_else(|| {
        decoder
            .is_partial()
            .then(|| elapsed_now(&clock) + limits.frame_timeout)
    });
    loop {
        let deadline = (elapsed_now(&clock) + limits.record_timeout)
            .min(frame_deadline.unwrap_or(end))
            .min(end);
        if !clock.is_continuous() || elapsed_now(&clock) >= deadline {
            return Err(Error::Timeout);
        }
        let ciphertext = read_checked(
            &mut reader,
            MAX_CIPHERTEXT,
            &clock,
            deadline,
            peer.as_ref(),
            &authorization,
        )
        .await?;
        let plaintext = channel
            .lock()
            .map_err(|_| Error::Closed)?
            .decrypt(&ciphertext)?;
        if !clock.is_continuous() || elapsed_now(&clock) >= deadline {
            return Err(Error::Timeout);
        }
        let frames = received_frames(&mut decoder, &plaintext, &clock)?;
        // A new partial frame starts at parsing, before any backpressured delivery.
        // Completion of an earlier frame in this batch permits a new assembly budget.
        if !decoder.is_partial() {
            frame_deadline = None;
        } else if frame_deadline.is_none() || !frames.is_empty() {
            frame_deadline = Some(elapsed_now(&clock) + limits.frame_timeout);
        }
        let delivery_deadline = (elapsed_now(&clock) + limits.write_timeout)
            .min(frame_deadline.unwrap_or(end))
            .min(end);
        for (frame, received_at) in frames {
            if !clock.is_continuous() || elapsed_now(&clock) >= delivery_deadline {
                return Err(Error::Timeout);
            }
            elapsed_timeout(&clock, delivery_deadline, ingest(frame, received_at))
                .await
                .map_err(|_| Error::Timeout)??;
            if !clock.is_continuous() || elapsed_now(&clock) >= delivery_deadline {
                return Err(Error::Timeout);
            }
        }
        tokio::task::yield_now().await;
    }
}

struct ReadContext {
    clock: ElapsedClock,
    peer: Option<Peer>,
    authorization: Option<Arc<FreshAuthorization>>,
}

/// The same owned reader continuation is used by the pump and deterministic
/// tests that withhold parent joining while repolling already-encrypted output.
struct ReaderTask {
    channel: Arc<Mutex<Channel>>,
    receive: ReceiveState,
    end: Instant,
    limits: Limits,
    peer: Peer,
    authorization: Option<Arc<FreshAuthorization>>,
    terminal: TransportTerminal,
}

async fn run_reader<R: RecordReader>(
    reader: R,
    state: ReaderTask,
) -> (Direction, Result<(), Error>) {
    let ReaderTask {
        channel,
        receive,
        end,
        limits,
        peer,
        authorization,
        terminal,
    } = state;
    let _panic_guard = TransportPanicGuard(terminal.clone());
    let clock = peer.clock();
    let ingest_peer = peer.clone();
    let read_clock = clock.clone();
    let read_authorization = authorization.clone();
    let result = read_frames(
        reader,
        channel,
        receive,
        end,
        limits,
        ReadContext {
            clock,
            peer: Some(peer.clone()),
            authorization,
        },
        move |frame, received_at| {
            let peer = ingest_peer.clone();
            let authorization = read_authorization.clone();
            let clock = read_clock.clone();
            async move {
                check_authorization(&authorization, &clock).await?;
                if !peer.delivery_open() {
                    return Err(Error::Closed);
                }
                peer.ingest_received_at(&frame, received_at).await;
                if peer.closed() {
                    Err(Error::Closed)
                } else {
                    Ok(())
                }
            }
        },
    )
    .await;
    if result.is_err() {
        // Every failed reader ends this connection, including retryable loss
        // categories. Never defer its local output cutoff to join_next/cleanup.
        peer.abort_terminal_output();
    }
    let result = result.map_err(|error| match error {
        // Local teardown can close the cipher before a buffered read resumes.
        Error::Channel(syntra_core::secure_channel::Error::Closed) if !peer.delivery_open() => {
            Error::Closed
        }
        error => error,
    });
    terminal.result(&result);
    (Direction::Read, result)
}

struct DrainDeadline<'a> {
    until: Instant,
    cutoff: Instant,
    clock: &'a ElapsedClock,
}

async fn drain_gracefully(
    peer: &Peer,
    tasks: &mut PumpTasks,
    reader_abort: &tokio::task::AbortHandle,
    drain: &watch::Sender<Option<Instant>>,
    closed: &mut watch::Receiver<bool>,
    stopped: &mut oneshot::Receiver<()>,
    budget: DrainDeadline<'_>,
) -> Result<(), Error> {
    let DrainDeadline {
        until: deadline,
        cutoff,
        clock,
    } = budget;
    if peer.closed() && !peer.ordinary_close() {
        return Err(Error::Closed);
    }
    let mut close_observed = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut *stopped => return Err(Error::Closed),
            _ = clock.sleep_until(deadline.into_std()) => return Err(Error::Timeout),
            _ = wait_closed(closed), if !close_observed => {
                if !peer.ordinary_close() { return Err(Error::Closed); }
                close_observed = true;
                reader_abort.abort();
                drain.send(Some(cutoff)).map_err(|_| Error::Closed)?;
            }
            result = tasks.join_next() => match result {
                Some(Ok((Direction::Write, result))) => { peer.task_joined(); return result; },
                Some(Ok((Direction::Read, Err(Error::Closed)))) if peer.closed() && peer.ordinary_close() => { peer.task_joined(); },
                Some(Ok((Direction::Read, result))) => { peer.task_joined(); return result.and(Err(Error::Closed)); },
                Some(Err(error)) if error.is_cancelled() && close_observed => { peer.task_joined(); },
                Some(Err(error)) if error.is_panic() => { peer.task_joined(); std::panic::resume_unwind(error.into_panic()); },
                Some(Err(_)) => { peer.task_joined(); return Err(Error::Closed); },
                _ => return Err(Error::Closed),
            },
        }
    }
}

struct PumpState {
    channel: Channel,
    receive: ReceiveState,
    peer: Peer,
    outbound: mpsc::Receiver<Vec<u8>>,
    limits: Limits,
    end: Instant,
    authorization: Option<Arc<FreshAuthorization>>,
    policy_jobs: Option<Arc<PolicyJobs>>,
}

/// Own accepted carrier halves until the registered owner is allowed to start.
/// An adoption racing Core shutdown can abort before its first poll; Drop must
/// still dispose both halves before attesting that the carrier is gone.
struct PendingCarrier<R, W> {
    reader: Option<R>,
    writer: Option<W>,
    peer: Peer,
}
impl<R, W> PendingCarrier<R, W> {
    fn take(&mut self) -> (R, W) {
        (
            self.reader.take().expect("reader owner"),
            self.writer.take().expect("writer owner"),
        )
    }
}
impl<R, W> Drop for PendingCarrier<R, W> {
    fn drop(&mut self) {
        if self.reader.is_some() || self.writer.is_some() {
            drop(self.reader.take());
            drop(self.writer.take());
            self.peer.task_joined();
            self.peer.task_joined();
            self.peer.carrier_closed();
        }
    }
}

fn spawn_pump<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    state: PumpState,
) -> Result<Pump, Error> {
    let PumpState {
        channel,
        receive,
        peer,
        mut outbound,
        limits,
        end,
        authorization,
        policy_jobs,
    } = state;
    let clock = peer.clock();
    let mut terminal_commands = match &peer {
        Peer::Host(host) => host.take_terminal_commands(),
        _ => None,
    };
    let coordinator = match &peer {
        Peer::Host(host) => host.terminal_coordinator(),
        _ => None,
    };
    let owner_clock = clock.clone();
    let retained_peer = peer.clone();
    // Register before publishing the handle. A caller may begin shutdown before
    // this spawned owner gets its first poll; registration after that point is
    // correctly refused by Core and used to strand an immediate graceful close.
    peer.register_tasks(2)?;
    let mut pending = PendingCarrier {
        reader: Some(reader),
        writer: Some(writer),
        peer: peer.clone(),
    };
    let (start, started) = oneshot::channel();
    let (stop, mut stopped) = oneshot::channel();
    let (graceful, mut graceful_rx) = mpsc::channel::<GracefulClose>(1);
    let (drain, mut draining) = watch::channel::<Option<Instant>>(None);
    let mut closed = peer.subscribe();
    let channel = Arc::new(Mutex::new(channel));
    let grace =
        (limits.close_timeout + Duration::from_secs(1)).min(syntra_runtime::MAX_CLOSE_GRACE);
    let terminal = TransportTerminal::default();
    let owner_terminal = terminal.clone();
    let task = tokio::spawn(async move {
        let _panic_guard = TransportPanicGuard(owner_terminal.clone());
        if started.await.is_err() {
            return;
        }
        let (reader, mut writer) = pending.take();
        if (*closed.borrow() || peer.closed()) && !peer.ordinary_close() {
            owner_terminal.record(TransportFailure::Closed);
            drop(reader);
            drop(writer);
            peer.task_joined();
            peer.task_joined();
            peer.carrier_closed();
            peer.lost().await;
            return;
        }
        let mut tasks = JoinSet::new();
        let reader_abort = tasks.spawn(run_reader(
            reader,
            ReaderTask {
                channel: channel.clone(),
                receive,
                end,
                limits: limits.clone(),
                peer: peer.clone(),
                authorization: authorization.clone(),
                terminal: owner_terminal.clone(),
            },
        ));
        let write_channel = channel.clone();
        let write_peer = peer.clone();
        let write_authorization = authorization.clone();
        let write_clock = clock.clone();
        let write_terminal = owner_terminal.clone();
        let write_coordinator = coordinator.clone();
        tasks.spawn(async move {
            let _panic_guard = TransportPanicGuard(write_terminal.clone());
            let mut teardown_deadline = end;
            let result = async {
                let mut drain_deadline = None;
                loop {
                    if let Some(deadline) = *draining.borrow_and_update() {
                        drain_deadline = Some(deadline);
                        teardown_deadline = deadline;
                        outbound.close();
                    }
                    let frame = tokio::select! {
                        biased;
                        command = async { match &mut terminal_commands { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                            let coordinator = write_coordinator.as_ref().ok_or(Error::Configuration)?;
                            match command.ok_or(Error::Closed)? {
                                DriverCommand::Barrier(ack) => {
                                    // Sole writer reached this arm only after its active full
                                    // frame completed; drop every unstarted ordinary frame.
                                    while outbound.try_recv().is_ok() {}
                                    coordinator.refresh().await.map_err(|_| Error::Authentication)?;
                                    ack.send(()).map_err(|_| Error::Closed)?;
                                    continue;
                                }
                                DriverCommand::Receipt(output) => {
                                    coordinator.refresh().await.map_err(|_| Error::Authentication)?;
                                    let deadline = Instant::from_std(coordinator.cutoff().ok_or(Error::Closed)?).min(end);
                                    teardown_deadline = Instant::from_std(coordinator.deadline().ok_or(Error::Closed)?).min(end);
                                    let plaintext = frame_plaintext(output.bytes())?;
                                    // The 1024-byte ceiling guarantees one record. Keep this
                                    // exact ciphertext/write future across all partial polls.
                                     let ciphertext = write_channel.lock().map_err(|_| Error::Closed)?.encrypt(&plaintext)?;
                                     // Explicit fresh proof after nonce consumption, immediately
                                     // before first handoff. Retained I/O repolls are cache-only.
                                     elapsed_timeout(&write_clock, deadline, coordinator.refresh()).await?
                                         .map_err(|_| Error::Authentication)?;
                                     authorized_io_inner(writer.write_record(&ciphertext), &write_clock, deadline,
                                        Some(&write_peer), &write_authorization, Some((coordinator, &output))).await?;
                                    coordinator.written();
                                    break;
                                }
                            }
                        },
                        _ = draining.changed(), if drain_deadline.is_none() => continue,
                        frame = outbound.recv() => match frame { Some(frame) => frame, None => break },
                    };
                    // Gate exactly once before framing/encryption. A selected
                    // frame's record sequence must finish in order or abort;
                    // never re-gate/rewrite after a nonce has been consumed.
                    // Policy may await; re-run the lifecycle/handoff gate only
                    // after that backpressure, immediately before encryption.
                    check_authorization(&write_authorization, &write_clock).await?;
                    if !write_peer.delivery_open() { return Err(Error::Closed); }
                    let frame = match &write_peer {
                        Peer::Client(client) => match client.prepare_outbound(frame) {
                            Some(frame) => frame,
                            None => continue,
                        },
                        Peer::Host(_) => frame,
                    };
                    let frame = Zeroizing::new(frame);
                    let authorization_end = write_authorization.as_ref().map_or(end, |g| elapsed_now(&write_clock) + g.interval());
                    let deadline = (elapsed_now(&write_clock) + limits.write_timeout).min(end).min(drain_deadline.unwrap_or(end)).min(authorization_end);
                    let plaintext = frame_plaintext(&frame)?;
                    // One frame's complete record sequence is owned until completion or abort.
                    elapsed_timeout(&write_clock, deadline, async {
                        for (index, chunk) in plaintext.chunks(MAX_PLAINTEXT).enumerate() {
                            if !write_peer.delivery_open() || elapsed_now(&write_clock) >= deadline { return Err(Error::Timeout); }
                            let encrypt = || write_channel.lock().map_err(|_| Error::Closed)?.encrypt(chunk).map_err(Error::from);
                            let ciphertext = if index == 0 {
                                match &write_coordinator {
                                    Some(c) => match c.start_ordinary(encrypt).map_err(|_| Error::Authentication)? { Some(result) => result?, None => return Ok(()) },
                                    None => encrypt()?,
                                }
                            } else { encrypt()? };
                            write_checked(&mut writer, &ciphertext, &write_clock, deadline, Some(&write_peer), &write_authorization).await?;
                            if elapsed_now(&write_clock) >= deadline { return Err(Error::Timeout); }
                            tokio::task::yield_now().await;
                        }
                        Ok::<(), Error>(())
                    }).await.map_err(|_| Error::Timeout)??;
                }
                Ok::<(), Error>(())
            }.await;
            write_terminal.result(&result);
            if let Ok(mut channel) = write_channel.lock() { channel.close(); }
            if result.is_ok() {
                let deadline = (elapsed_now(&write_clock) + limits.close_timeout).min(end).min(teardown_deadline);
                let shutdown = authorized_io(writer.shutdown(), &write_clock, deadline, Some(&write_peer), &None).await;
                write_terminal.result(&shutdown);
                return (Direction::Write, shutdown);
            }
            (Direction::Write, result)
        });
        let mut graceful_done = None;
        let mut terminal_task: TerminalTask = None;
        let watchdog = async {
            let Some(guard) = &authorization else {
                return std::future::pending::<Result<(), Error>>().await;
            };
            loop {
                // Freshness is measured from the start of the last check, not
                // from a late read's completion. Failed checks never renew it.
                let start = elapsed_now(&clock);
                if !peer.delivery_open() {
                    return Ok(());
                }
                if let Err(error) = refresh_authorization(&authorization, &clock).await {
                    owner_terminal.record(TransportFailure::of(&error));
                    return Err(error);
                }
                clock
                    .sleep_until(
                        (start + guard.interval())
                            .min(
                                coordinator
                                    .as_ref()
                                    .and_then(|c| c.cutoff())
                                    .map_or(end, Instant::from_std),
                            )
                            .into_std(),
                    )
                    .await;
            }
        };
        tokio::pin!(watchdog);
        // Policy/watchdog and graceful-drain panics must follow the same owned
        // child-join path as a reader/writer panic before being rethrown.
        let selection = std::panic::AssertUnwindSafe(async {
        tokio::select! {
            biased;
            result = &mut watchdog => {
                owner_terminal.result(&result);
                debug!("Syntra authorization watch ended");
            },
            _ = &mut stopped => debug!("Syntra pump owner stopped by close signal"),
            request = graceful_rx.recv() => if let Some(request) = request {
                let result = tokio::select! {
                    biased;
                    result = &mut watchdog => result.and(Err(Error::Closed)),
                    result = drain_gracefully(&peer, &mut tasks, &reader_abort, &drain,
                        &mut closed, &mut stopped, DrainDeadline { until: request.deadline.min(end), cutoff: request.drain_cutoff.min(end), clock: &clock }) => result,
                };
                owner_terminal.result(&result);
                graceful_done = Some((request.done, result));
            },
            _ = wait_closed(&mut closed) => debug!("Syntra pump owner stopped by peer closed"),
            _ = clock.sleep_until(end.into_std()) => {
                owner_terminal.record(TransportFailure::Timeout);
                debug!("Syntra pump owner stopped by lifetime/continuity end");
            },
            result = tasks.join_next() => {
                if result.is_some() { peer.task_joined(); }
                terminal_task = result;
            }
        }
        }).catch_unwind().await;
        if terminal_task.is_none() {
            debug!(
                graceful = graceful_done.is_some(),
                "Syntra pump owner exited without terminal task"
            );
        }
        let mut panic = selection.err();
        if panic.is_some() {
            owner_terminal.record(TransportFailure::Runtime);
        }
        match terminal_task {
            Some(Ok((direction, result))) => match result {
                Ok(()) => debug!(?direction, "Syntra pump task ended with clean shutdown"),
                Err(ref error) => warn!(?direction, error = ?error, "Syntra pump task ended"),
            },
            Some(Err(error)) if error.is_panic() => {
                owner_terminal.record(TransportFailure::Runtime);
                panic = Some(error.into_panic());
            }
            _ => {}
        }
        // No cipher state survives either direction's failure or cancelled output.
        if let Ok(mut channel) = channel.lock() {
            channel.close();
        }
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            peer.task_joined();
            if let Err(error) = result {
                if error.is_panic() && panic.is_none() {
                    owner_terminal.record(TransportFailure::Runtime);
                    panic = Some(error.into_panic());
                }
            }
        }
        owner_terminal.record(TransportFailure::Closed);
        peer.carrier_closed();
        peer.lost().await;
        if let Some((done, result)) = graceful_done {
            let _ = done.send(result);
        }
        if let Some(panic) = panic {
            std::panic::resume_unwind(panic);
        }
    });
    let task = retained_peer.own_task(task);
    let _ = start.send(());
    Ok(Pump {
        terminal,
        stop: Some(stop),
        graceful,
        task: Some(task),
        grace,
        clock: owner_clock,
        policy_jobs,
        peer: retained_peer,
        shutdown_deadline: None,
    })
}

pub async fn connect_records<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    connect_records_with_clock(
        reader,
        writer,
        security,
        credential,
        runtime,
        limits,
        default_elapsed_clock(),
    )
    .await
}

/// Inject one trusted elapsed source for Noise, Core, record and shutdown timers.
pub async fn connect_records_with_clock<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
    clock: ElapsedClock,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let attempt = EstablishmentBudget::new(clock, limits.attempt_timeout)?;
    connect_records_with_budget(
        reader, writer, security, credential, runtime, limits, attempt,
    )
    .await
}

pub async fn connect_records_with_budget<R: RecordReader, W: RecordWriter>(
    mut reader: R,
    mut writer: W,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
    establishment: EstablishmentBudget,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    establishment.io.check().map_err(|_| Error::Timeout)?;
    let EstablishmentBudget {
        clock,
        started,
        channel_clock,
        deadline: attempt,
        jobs,
        io,
    } = establishment;
    let channel_started = elapsed_now(&clock);
    let end = started + limits.lifetime;
    let channel_deadline = attempt
        .min(end)
        .min(channel_started + limits.channel_timeout);
    io.until(channel_deadline)?;
    let channel = elapsed_timeout(&clock, channel_deadline, async {
        let (handshake, first) = ClientHandshake::start_with_clock(security, channel_clock)?;
        write_checked(&mut writer, &first, &clock, channel_deadline, None, &None).await?;
        let second = read_checked(&mut reader, 48, &clock, channel_deadline, None, &None).await?;
        let channel = handshake.finish(&second)?;
        Ok::<_, Error>(channel)
    })
    .await
    .map_err(|_| Error::Timeout)??;
    if elapsed_now(&clock) >= channel_deadline {
        return Err(Error::Timeout);
    }
    let core_deadline = attempt
        .min(end)
        .min(elapsed_now(&clock) + runtime.handshake_timeout);
    let (conn, mut outbound) =
        Initiator::try_new_with_clock(runtime, clock.clone()).map_err(|_| Error::Configuration)?;
    let mut channel = channel;
    let mut receive = ReceiveState::default();
    // Establishment I/O stays in the caller's future. In particular, do not
    // spawn an owner before ready: cancelling a partial dial must synchronously
    // release both carrier halves before a lifecycle replacement can begin.
    let peer = Peer::Client(conn.clone());
    let id = elapsed_timeout(&clock, core_deadline, async {
        let handshake = conn.handshake(credential);
        tokio::pin!(handshake);
        let mut hello_sent = false;
        loop {
            let deadline = core_deadline
                .min(elapsed_now(&clock) + limits.record_timeout)
                .min(receive.frame_deadline.unwrap_or(core_deadline));
            tokio::select! {
                biased;
                _ = clock.sleep_until(core_deadline.into_std()) => return Err(Error::Timeout),
                result = &mut handshake => break result.map_err(runtime_error),
                hello = outbound.recv(), if !hello_sent => {
                    let hello = Zeroizing::new(hello.ok_or(Error::Closed)?);
                    let plaintext = frame_plaintext(&hello)?;
                    let write_deadline = core_deadline.min(channel_deadline).min(elapsed_now(&clock) + limits.write_timeout);
                    io.until(write_deadline)?;
                    for chunk in plaintext.chunks(MAX_PLAINTEXT) {
                        let encrypted = channel.encrypt(chunk)?;
                        write_checked(&mut writer, &encrypted, &clock, write_deadline, Some(&peer), &None).await?;
                    }
                    hello_sent = true;
                    io.until(core_deadline)?;
                }
                record = read_checked(&mut reader, MAX_CIPHERTEXT, &clock, deadline, Some(&peer), &None), if hello_sent => {
                    let record = record?;
                    if elapsed_now(&clock) >= deadline || !peer.delivery_open() { return Err(Error::Timeout); }
                    let plaintext = channel.decrypt(&record)?;
                    let frames = receive.decoder.push(&plaintext)?;
                    if !receive.decoder.is_partial() {
                        receive.frame_deadline = None;
                    } else if receive.frame_deadline.is_none() || !frames.is_empty() {
                        receive.frame_deadline = Some(elapsed_now(&clock) + limits.frame_timeout);
                    }
                    // This body is outside the select futures: ready cannot
                    // cancel delivery midway through a decoded batch. Yielding
                    // in ingest preserves the iterator until its whole batch
                    // has been accounted for (unless establishment itself fails).
                    for frame in frames {
                        if !peer.delivery_open() || elapsed_now(&clock) >= core_deadline { return Err(Error::Closed); }
                        conn.ingest(&Zeroizing::new(frame)).await;
                    }
                }
            }
        }
    }).await.map_err(|_| Error::Timeout)??;
    if elapsed_now(&clock) >= core_deadline || !peer.delivery_open() {
        return Err(Error::Timeout);
    }
    let version = conn.negotiated_version().await.ok_or(Error::Runtime)?;
    if !clock.is_continuous() || elapsed_now(&clock) >= core_deadline || !peer.delivery_open() {
        return Err(Error::Timeout);
    }
    io.finish();
    let pump = spawn_pump(
        reader,
        writer,
        PumpState {
            channel,
            receive,
            peer: Peer::Client(conn.clone()),
            outbound,
            limits,
            end,
            authorization: None,
            policy_jobs: jobs,
        },
    )?;
    Ok(ClientHandle {
        conn,
        connection_id: id,
        version,
        pump: Some(pump),
    })
}

fn runtime_error(error: SyntraError) -> Error {
    match error.code() {
        syntra_core::ErrorCode::DeadlineExceeded => Error::Timeout,
        syntra_core::ErrorCode::Unavailable => Error::Closed,
        code => Error::LocalProtocol(code),
    }
}

pub async fn accept_records<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error> {
    limits.validate(&runtime)?;
    let attempt = EstablishmentBudget::new(factory.elapsed_clock(), limits.attempt_timeout)?;
    accept_records_with_budget(
        reader,
        writer,
        security,
        factory,
        handler,
        (runtime, limits),
        attempt,
    )
    .await
}

/// An HTTP inline supervisor retains the partially constructed Host before any
/// hello authentication/recovery callback can unwind or cancel establishment.
/// These are ownership observations only, not a ready/authenticated handle.
#[derive(Default)]
pub(crate) struct AcceptOwner {
    pub(crate) host: Mutex<Option<Arc<Host>>>,
    pub(crate) jobs: Mutex<Vec<Arc<PolicyJobs>>>,
}

pub async fn accept_records_with_budget<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    config: (ConnectionConfig, Limits),
    establishment: EstablishmentBudget,
) -> Result<HostHandle, Error> {
    accept_records_impl(
        reader,
        writer,
        security,
        factory,
        handler,
        config,
        (establishment, None, false),
    )
    .await
}

/// Internal TCP entry point: custom record adapters never inherit this support.
#[cfg(feature = "tcp")]
pub(crate) async fn accept_tcp_records_with_budget<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    config: (ConnectionConfig, Limits),
    establishment: EstablishmentBudget,
) -> Result<HostHandle, Error> {
    accept_records_impl(
        reader,
        writer,
        security,
        factory,
        handler,
        config,
        (establishment, None, true),
    )
    .await
}

#[cfg(feature = "http")]
pub(crate) async fn accept_records_owned<R: RecordReader, W: RecordWriter>(
    reader: R,
    writer: W,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    config: (ConnectionConfig, Limits),
    setup: (EstablishmentBudget, Arc<AcceptOwner>),
) -> Result<HostHandle, Error> {
    accept_records_impl(
        reader,
        writer,
        security,
        factory,
        handler,
        config,
        (setup.0, Some(setup.1), false),
    )
    .await
}

async fn accept_records_impl<R: RecordReader, W: RecordWriter>(
    mut reader: R,
    mut writer: W,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    config: (ConnectionConfig, Limits),
    setup: (EstablishmentBudget, Option<Arc<AcceptOwner>>, bool),
) -> Result<HostHandle, Error> {
    let (establishment, owner, terminal_supported) = setup;
    let (runtime, limits) = config;
    limits.validate(&runtime)?;
    establishment.io.check().map_err(|_| Error::Timeout)?;
    let EstablishmentBudget {
        clock,
        started,
        channel_clock,
        deadline: attempt,
        jobs,
        io,
    } = establishment;
    let channel_started = elapsed_now(&clock);
    let end = started + limits.lifetime;
    let channel_deadline = attempt
        .min(end)
        .min(channel_started + limits.channel_timeout);
    io.until(channel_deadline)?;
    factory
        .validate_server_config(security)
        .map_err(|_| Error::Authentication)?;
    let established = elapsed_timeout(&clock, channel_deadline, async {
        let first = read_checked(
            &mut reader,
            MAX_WRAPPER,
            &clock,
            channel_deadline,
            None,
            &None,
        )
        .await?;
        let pool = factory.policy_jobs();
        if let (Some(owner), Some(pool)) = (&owner, &pool) {
            owner
                .jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(pool.clone());
        }
        let lane = factory.blocking_admission();
        let (mut channel, second) = if pool.is_some() || lane.is_some() {
            // The shared KeyStore API is synchronous. Explicitly offload the
            // handshake (including lookup), not just the later policy reads.
            // Secret32 is intentionally non-Clone: this bounded, zeroizing copy
            // exists only for the lifetime of the owned blocking operation.
            let owned = ServerConfig {
                mode: security.mode,
                carrier: security.carrier,
                server_key_id: security.server_key_id,
                scope: security.scope.clone(),
                private_key: syntra_core::secure_channel::Secret32::new(
                    *security.private_key.expose(),
                ),
                store: security.store.clone(),
            };
            if let Some(pool) = pool {
                pool.spawn(move || respond_with_clock(&owned, &first, channel_clock))?
                    .await
                    .map_err(|_| Error::Closed)??
            } else {
                let permit = lane
                    .ok_or(Error::Configuration)?
                    .try_acquire_owned()
                    .map_err(|_| Error::Authentication)?;
                if let Some(owner) = &owner {
                    // The HTTP supervisor can cancel this inline accept. Keep
                    // the blocking join as well as its external lane permit in
                    // a retained owner, even before there is a runtime Host.
                    let pool = PolicyJobs::new(1)?;
                    owner
                        .jobs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(pool.clone());
                    pool.spawn(move || {
                        let _permit = permit;
                        respond_with_clock(&owned, &first, channel_clock)
                    })?
                    .await
                    .map_err(|_| Error::Closed)??
                } else {
                    let task = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        respond_with_clock(&owned, &first, channel_clock)
                    });
                    match task.await {
                        Ok(result) => result?,
                        Err(join) if join.is_panic() => {
                            std::panic::resume_unwind(join.into_panic())
                        }
                        Err(_) => return Err(Error::Closed),
                    }
                }
            }
        } else {
            respond_with_clock(security, &first, channel_clock)?
        };
        write_checked(&mut writer, &second, &clock, channel_deadline, None, &None).await?;
        // M2 output completion starts Core's independent timer. Waiting for hello,
        // authorization, Host construction or ready output cannot reset it.
        let core_deadline = attempt
            .min(end)
            .min(elapsed_now(&clock) + runtime.handshake_timeout);
        let confirmation_deadline = channel_deadline.min(core_deadline);
        io.until(confirmation_deadline)?;
        let mut decoder = FrameDecoder::default();
        // Absolute confirmation deadline includes every partial record and frame.
        loop {
            if elapsed_now(&clock) >= confirmation_deadline {
                return Err(Error::Timeout);
            }
            let record = read_checked(
                &mut reader,
                MAX_CIPHERTEXT,
                &clock,
                confirmation_deadline,
                None,
                &None,
            )
            .await?;
            let plaintext = channel.decrypt(&record)?;
            let mut frames = received_frames(&mut decoder, &plaintext, &clock)?;
            if !frames.is_empty() {
                // The first envelope must be hello, with no pipelined application data.
                if frames.len() != 1 || decoder.is_partial() {
                    return Err(Error::LocalProtocol(ErrorCode::InvalidArgument));
                }
                break Ok::<_, Error>((channel, decoder, frames.remove(0), core_deadline));
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::Timeout)??;
    let (channel, mut decoder, (first_frame, received_at), core_deadline) = established;
    if elapsed_now(&clock) >= channel_deadline.min(core_deadline) {
        return Err(Error::Timeout);
    }
    io.until(core_deadline)?;
    let first = decode_frame(
        &first_frame,
        ValidationContext::pre_handshake(ConnectionState::Connected),
    )
    .map_err(runtime_error)?;
    if !matches!(first.body, Some(Body::Hello(_))) {
        return Err(Error::LocalProtocol(ErrorCode::FailedPrecondition));
    }
    let identity = channel.verified_identity().ok_or(Error::Authentication)?;
    if elapsed_now(&clock) >= core_deadline {
        return Err(Error::Timeout);
    }
    let mut authorization = factory
        .connection_authorization(&identity)
        .map_err(|_| Error::Authentication)?
        .map(|base| FreshAuthorization::new(base, clock.clone()).map(Arc::new))
        .transpose()?;
    if let Some(guard) = &authorization {
        let total = guard
            .interval()
            .checked_add(guard.read_timeout())
            .and_then(|d| d.checked_add(guard.close_timeout()))
            .ok_or(Error::Configuration)?;
        if guard.interval().is_zero()
            || guard.read_timeout().is_zero()
            || guard.read_timeout() > guard.interval()
            || guard.close_timeout().is_zero()
            || total > Duration::from_secs(300)
            || limits.close_timeout > guard.close_timeout()
        {
            return Err(Error::Configuration);
        }
    }
    elapsed_timeout(
        &clock,
        core_deadline,
        refresh_authorization(&authorization, &clock),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    let auth = elapsed_timeout(&clock, core_deadline, factory.prepare(&identity))
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|error| Error::LocalProtocol(error.code))?;
    if elapsed_now(&clock) >= core_deadline {
        return Err(Error::Timeout);
    }
    let (host, mut outbound) = Host::try_new_with_execution_budget_and_clock(
        runtime,
        auth,
        handler,
        factory.execution_budget(),
        clock.clone(),
    )
    .map_err(|_| Error::Configuration)?;
    if let Some(policy) = factory.terminal_receipt(&identity) {
        if !terminal_supported || authorization.is_some() {
            return Err(Error::Configuration);
        }
        // Only tcp::accept_stream enters with support. Its split stream
        // cannot flush output from reads; the sole writer/barrier/raw gates above
        // own all protected output and bounded retirement for this connection.
        let coordinator = host
            .install_terminal_tcp(policy)
            .map_err(|_| Error::Configuration)?;
        coordinator
            .refresh()
            .await
            .map_err(|_| Error::Authentication)?;
        *io.terminal.lock().map_err(|_| Error::Closed)? = Some(coordinator.clone());
        authorization = Some(Arc::new(FreshAuthorization {
            base: Arc::new(TerminalAuthorization(coordinator.clone())),
            clock: clock.clone(),
            interval: coordinator.read_timeout() / 2,
            read: coordinator.read_timeout(),
            close: limits.close_timeout,
            state: Mutex::new((None, false)),
            terminal: Some(coordinator),
        }));
    }
    if let Some(owner) = &owner {
        *owner.host.lock().unwrap_or_else(|e| e.into_inner()) = Some(host.clone());
    }
    if let Some(service) = factory.recovery_service() {
        elapsed_timeout(&clock, core_deadline, host.configure_recovery(service))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Configuration)?;
    }
    elapsed_timeout(
        &clock,
        core_deadline,
        host.ingest_received_at(&first_frame, received_at),
    )
    .await
    .map_err(|_| Error::Timeout)?;
    if host.is_closed() {
        return Err(host
            .terminal_reason()
            .map(runtime_error)
            .unwrap_or(Error::Closed));
    }
    // Flush ready before transferring the carrier to background tasks. A
    // cancelled accept owns/drops its partial carrier just like a cancelled dial.
    let ready = elapsed_timeout(&clock, core_deadline, outbound.recv())
        .await
        .map_err(|_| Error::Timeout)?
        .ok_or(Error::Closed)?;
    elapsed_timeout(
        &clock,
        core_deadline,
        refresh_authorization(&authorization, &clock),
    )
    .await
    .map_err(|_| Error::Timeout)??;
    let plaintext = frame_plaintext(&Zeroizing::new(ready))?;
    let mut channel = channel;
    let authorization_end = authorization
        .as_ref()
        .map_or(end, |guard| elapsed_now(&clock) + guard.interval());
    let deadline = core_deadline
        .min(elapsed_now(&clock) + limits.write_timeout)
        .min(authorization_end);
    io.until(deadline)?;
    for chunk in plaintext.chunks(MAX_PLAINTEXT) {
        let encrypted = channel.encrypt(chunk)?;
        write_checked(
            &mut writer,
            &encrypted,
            &clock,
            deadline,
            Some(&Peer::Host(host.clone())),
            &authorization,
        )
        .await?;
    }
    if elapsed_now(&clock) >= deadline {
        return Err(Error::Timeout);
    }
    io.finish();
    let pump = spawn_pump(
        reader,
        writer,
        PumpState {
            channel,
            receive: std::mem::take(&mut decoder).into(),
            peer: Peer::Host(host.clone()),
            outbound,
            limits,
            end,
            authorization,
            policy_jobs: factory.policy_jobs().or(jobs),
        },
    )?;
    Ok(HostHandle {
        host,
        identity,
        pump: Some(pump),
    })
}

#[cfg(test)]
mod tests;
