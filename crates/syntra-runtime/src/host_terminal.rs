//! Opt-in, connection-local terminal receipt coordination. No wire extension.
use super::*;
use crate::elapsed::ElapsedClock;
use futures_util::future::BoxFuture;
use std::sync::atomic::Ordering;

/// SDK-generated private operation owner. Persist `as_bytes()` atomically with
/// the conditional durable transition; never send it to a peer or log it.
#[derive(Clone, PartialEq, Eq)]
pub struct ReservationId([u8; 32]);
impl ReservationId {
    /// Private storage representation, for the trusted authority adapter only.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable claim issued by the actual host after method authorization. The
/// adapter is already bound to scope/enrollment through the factory's verified
/// identity. The fresh reservation binds that binding to this connection/call.
#[derive(Clone)]
pub struct Transition {
    /// Fresh private owner, recorded in the same transaction as withdrawal.
    pub reservation: ReservationId,
    /// Expected active revision, nonzero and below u64::MAX. The committed
    /// revision must be strictly newer; adjacent revisions are not required.
    pub expected_revision: u64,
    /// Authenticated application identity from this host's bound session.
    pub principal: Principal,
    /// Host-configured operation, never supplied by request payload bytes.
    pub method: String,
}

/// Operation-aware authoritative observation. Adapters must use bounded fresh
/// reads, record ownership atomically, and represent every superseding withdrawal
/// as HardDenied (including otherwise idempotent external revocation).
pub enum Observation {
    /// Binding remains active at this revision.
    Active {
        /// Current monotonically ordered active authority revision.
        revision: u64,
    },
    /// The exact conditional operation committed durably with receipt conditions.
    OwnedCommitted {
        /// Exact private owner recorded by the durable transition.
        reservation: ReservationId,
        /// Active revision conditionally replaced by this operation.
        expected_revision: u64,
        /// Strictly newer committed revision. The first accepted owned revision
        /// is pinned for this reservation; subsequent evidence must match it.
        revision: u64,
    },
    /// External withdrawal, expiry, or superseding denial.
    HardDenied,
    /// Error, stale/uncertain evidence, or unresolved transition cause.
    Unknown,
}

/// Trusted application durability boundary. A successful callback is deliberately
/// not commit evidence: all gates independently call `observe`. Commit ownership
/// must be visible there before `commit` returns. Retain a lease in any spawned
/// or blocking work until it actually ends. The SDK cannot prove DB durability.
pub trait Authority: Send + Sync {
    /// Read current authority; `None` is ordinary, pre-reservation validity.
    /// Each invocation must start a fresh authoritative read, with no stale
    /// replica/cache evidence. The whole read is bounded by Policy::read_timeout.
    /// Future construction/polls must be nonblocking. Independently spawned
    /// storage work remains the adapter's accounted-for cleanup responsibility.
    fn observe(&self, transition: Option<Transition>) -> BoxFuture<'_, Observation>;
    /// Conditionally commit expected revision plus private owner atomically.
    /// Return carries no proof; errors/uncertainty must be observable as Unknown.
    fn commit(&self, transition: Transition, lease: ExecutionLease) -> BoxFuture<'_, ()>;
}

/// Fixed host policy. No default policy exists. Payload must be non-sensitive.
#[derive(Clone)]
pub struct Policy {
    /// Exact method permitted to reserve a terminal result.
    pub method: String,
    /// Immutable success bytes copied and encoded before any transition.
    pub payload: Vec<u8>,
    /// Adapter bound to this verified connection's scope/enrollment authority.
    pub authority: Arc<dyn Authority>,
    /// Maximum time for each authoritative read and its start-based freshness
    /// bound, 1..=250 ms. Idle refresh runs at half this bound.
    /// Reads must finish before both prior freshness and the operation cutoff.
    pub read_timeout: Duration,
}

/// Local reservation failure; contains no storage diagnostics or private IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Default-disabled, unsupported driver, wrong method, or anonymous binding.
    Unsupported,
    /// Already reserved/selected, denied, expired, oversized, or unavailable.
    Unavailable,
}

/// Unforgeable request context, issued only for this admitted handler invocation.
/// Keeping a copy also keeps the actual execution lease. It grants no permission
/// on another host or generation and never accepts a peer-selected receipt.
#[derive(Clone)]
pub struct RequestContext {
    host: Weak<Host>,
    id: u64,
    version: u32,
    method: String,
    deadline: Instant,
    lease: Option<ExecutionLease>,
}
impl RequestContext {
    pub(super) fn new(
        host: Weak<Host>,
        id: u64,
        version: u32,
        method: String,
        deadline: Instant,
    ) -> Self {
        Self {
            host,
            id,
            version,
            method,
            deadline,
            lease: None,
        }
    }
    pub(super) fn with_lease(mut self, lease: ExecutionLease) -> Self {
        self.lease = Some(lease);
        self
    }

    /// Fence/quiesce, conditionally transition, and return the fixed handler
    /// outcome. Return this outcome promptly: this does not await its own output.
    /// A retained SDK owner closes on loss/deadline even if this waiter is dropped.
    /// Expected revision zero or u64::MAX is refused before mutation or fencing.
    pub async fn retire(&self, expected_revision: u64) -> Result<HandlerOutcome, Refused> {
        let host = self.host.upgrade().ok_or(Refused::Unavailable)?;
        let coordinator = host
            .terminal
            .lock()
            .unwrap()
            .clone()
            .ok_or(Refused::Unsupported)?;
        if coordinator.policy.method != self.method {
            return Err(Refused::Unsupported);
        }
        let session = host
            .bound_id
            .lock()
            .unwrap()
            .as_deref()
            .and_then(|id| host.sessions.get(id))
            .filter(|s| s.principal != Principal::anonymous())
            .ok_or(Refused::Unsupported)?;
        let lease = self.lease.clone().ok_or(Refused::Unavailable)?;
        let (done, completed) = oneshot::channel();
        // Workers retain a lifecycle read guard from their final dispatch check
        // through synchronous application-hook construction or recovery dispatch.
        // Exclusive acquisition closes that entire check/callback gap. Recheck
        // every precondition below after waiting, without holding the raw-I/O
        // coordinator gate across application code or this await.
        let state = host.conn.shared.state.write().await;
        {
            // Same gate as first-terminal selection; no await or app code here.
            let calls = host.calls.lock().unwrap();
            if *state != ConnectionState::Active
                || !calls.pending.contains_key(&self.id)
                || host.is_closed()
                || host.conn.lifecycle_blocked()
                || host.conn.writer_is_fenced()
                || host.conn.shared.shutdown_requested.load(Ordering::Acquire)
                || host.conn.shared.principal_withdrawn.load(Ordering::Acquire)
                || calls.delivery_stopped
            {
                return Err(Refused::Unavailable);
            }
            coordinator.reserve(
                self.id,
                self.version,
                self.deadline,
                expected_revision,
                session.principal,
            )?;
            host.conn
                .shared
                .terminal_fenced
                .store(true, Ordering::Release);
        }
        drop(state);
        host.close_recovery();
        // Install cleanup BEFORE mutation and keep it independently of the waiter.
        let owner = coordinator.clone();
        let sender = host.conn.clone();
        let calls = host.calls.clone();
        let sessions = host.sessions.clone();
        let bound = host.bound_id.lock().unwrap().clone();
        let task = spawn_task(async move {
            let result = owner.perform(lease, &sender).await;
            let _ = done.send(result);
            owner.wait_end().await;
            owner.abort();
            calls.lock().unwrap().stop_delivery("terminal retirement");
            sender.on_transport_lost().await;
            if let Some(bound) = bound {
                sessions.unbind(&bound);
            }
        });
        host.conn.shared.tasks.register(task);
        completed.await.map_err(|_| Refused::Unavailable)?
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Active,
    Reserved,
    Committed,
    Selected,
    Consumed,
    Finished,
    Aborted,
}
struct State {
    phase: Phase,
    claim: Option<Transition>,
    /// First accepted owned revision, immutable for the reservation and its output.
    committed_revision: Option<u64>,
    id: u64,
    bytes: Vec<u8>,
    cutoff: Instant,
    deadline: Instant,
    fresh_until: Option<Instant>,
}

/// Typed sole-writer message. Only a conforming native TCP driver may install
/// this bridge. Queue admission and complete local writing are distinct facts.
#[doc(hidden)]
pub enum DriverCommand {
    /// Acknowledge only after every active ordinary frame is complete; discard
    /// all unstarted ordinary frames. Never acknowledge a partial frame.
    Barrier(oneshot::Sender<()>),
    /// Single exact result with its retained output accounting charge.
    Receipt(TerminalOutput),
}

/// Non-cloneable exact selected output; its charge lives through carrier handoff.
#[doc(hidden)]
pub struct TerminalOutput {
    bytes: Vec<u8>,
    reservation: ReservationId,
    _charge: execution::BudgetPermit,
}
impl TerminalOutput {
    /// Immutable prevalidated frame, excluding the inner four-byte prefix.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Shared sticky classifier used by selection, reader, writer and watchdog.
#[doc(hidden)]
pub struct Coordinator {
    policy: Policy,
    clock: ElapsedClock,
    state: Mutex<State>,
    commands: mpsc::Sender<DriverCommand>,
    changed: Notify,
    reads: tokio::sync::Mutex<()>,
    io_gate: Mutex<()>,
}
impl Coordinator {
    pub(super) fn fenced(&self) -> bool {
        self.state.lock().unwrap().phase != Phase::Active
    }
    /// Whether ordinary frames may start. Call immediately before encryption.
    pub fn ordinary_allowed(&self) -> bool {
        !self.fenced()
    }
    /// Start an ordinary record sequence atomically with the reservation fence.
    /// A sequence started here must finish in full before Barrier is acknowledged.
    /// Valid fenced frames are suppressed; invalid authority is a fatal refusal.
    pub fn start_ordinary<T>(&self, start: impl FnOnce() -> T) -> Result<Option<T>, Refused> {
        let _io = self.io_gate.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        if !self.valid(&s) {
            s.phase = Phase::Aborted;
            self.changed.notify_waiters();
            return Err(Refused::Unavailable);
        }
        if s.phase != Phase::Active {
            return Ok(None);
        }
        drop(s);
        Ok(Some(start()))
    }
    /// Original final retirement deadline, never a new phase budget.
    pub fn deadline(&self) -> Option<Instant> {
        let s = self.state.lock().unwrap();
        (s.phase != Phase::Active).then_some(s.deadline)
    }
    /// Proof/output cutoff with the teardown tail excluded.
    pub fn cutoff(&self) -> Option<Instant> {
        let s = self.state.lock().unwrap();
        (s.phase != Phase::Active).then_some(s.cutoff)
    }
    /// Read bound shared with the native authorization wrapper.
    pub fn read_timeout(&self) -> Duration {
        self.policy.read_timeout
    }
    /// Linearize a nonblocking carrier poll with sticky local denial. No policy
    /// callback or await may occur in `poll`. Reader polls cannot flush TCP output.
    pub fn with_io<T>(&self, poll: impl FnOnce() -> T) -> Option<T> {
        let _io = self.io_gate.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        if !self.valid(&s) {
            s.phase = Phase::Aborted;
            self.changed.notify_waiters();
            return None;
        }
        drop(s);
        Some(poll())
    }
    /// Per-raw-poll check, including TCP prefix/payload polls in one future poll.
    pub fn raw_allowed(&self) -> bool {
        self.valid(&self.state.lock().unwrap())
    }
    /// First poll consumes the exact grant under the same local gate as denial.
    pub fn with_receipt_io<T>(
        &self,
        output: &TerminalOutput,
        first: &mut bool,
        poll: impl FnOnce() -> T,
    ) -> Option<T> {
        let _io = self.io_gate.lock().unwrap();
        if *first {
            self.consume(output).ok()?;
            *first = false;
        }
        let mut s = self.state.lock().unwrap();
        if s.phase != Phase::Consumed
            || s.bytes != output.bytes
            || !s
                .claim
                .as_ref()
                .is_some_and(|c| c.reservation == output.reservation)
            || !self.valid(&s)
        {
            s.phase = Phase::Aborted;
            self.changed.notify_waiters();
            return None;
        }
        drop(s);
        Some(poll())
    }
    fn valid(&self, s: &State) -> bool {
        self.clock.is_continuous()
            && !matches!(s.phase, Phase::Aborted | Phase::Finished)
            && (s.phase == Phase::Active || self.clock.now() < s.cutoff)
            && s.fresh_until.is_some_and(|until| self.clock.now() < until)
    }
    /// Sticky failure; a late owned observation cannot restore permission.
    pub fn abort(&self) {
        let _io = self.io_gate.lock().unwrap();
        self.state.lock().unwrap().phase = Phase::Aborted;
        self.changed.notify_waiters();
    }

    fn reserve(
        &self,
        id: u64,
        version: u32,
        request_deadline: Instant,
        revision: u64,
        principal: Principal,
    ) -> Result<(), Refused> {
        let now = self.clock.now();
        let deadline = request_deadline.min(now + Duration::from_secs(5));
        let budget = deadline.saturating_duration_since(now);
        let tail = (budget / 4).min(Duration::from_millis(250));
        let bytes = Frame {
            version,
            request_id: id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(outcome_payload(self.policy.payload.clone())),
            })),
        }
        .encode_to_vec();
        let _io = self.io_gate.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        if s.phase != Phase::Active
            || !self.valid(&s)
            || tail.is_zero()
            || budget <= self.policy.read_timeout * 2 + tail
            || bytes.len() > 1024
            || revision == 0
            || revision == u64::MAX
        {
            return Err(Refused::Unavailable);
        }
        let mut random = [0; 32];
        fill_random(&mut random).map_err(|_| Refused::Unavailable)?;
        s.claim = Some(Transition {
            reservation: ReservationId(random),
            expected_revision: revision,
            principal,
            method: self.policy.method.clone(),
        });
        s.phase = Phase::Reserved;
        s.id = id;
        s.bytes = bytes;
        s.deadline = deadline;
        s.cutoff = deadline - tail;
        Ok(())
    }

    /// Fresh typed read. Reads serialize, while the mutation uses no local lock;
    /// its durable ownership record bridges the commit/callback-return interval.
    pub async fn refresh(&self) -> Result<(), Refused> {
        let read_window = || {
            let _io = self.io_gate.lock().unwrap();
            let mut s = self.state.lock().unwrap();
            let start = self.clock.now();
            if !self.clock.is_continuous()
                || matches!(s.phase, Phase::Aborted | Phase::Finished)
                || s.fresh_until.is_some_and(|until| start >= until)
                || (s.phase != Phase::Active && start >= s.cutoff)
            {
                s.phase = Phase::Aborted;
                self.changed.notify_waiters();
                return Err(Refused::Unavailable);
            }
            let deadline = start + self.policy.read_timeout;
            let deadline =
                deadline
                    .min(s.fresh_until.unwrap_or(deadline))
                    .min(if s.phase == Phase::Active {
                        deadline
                    } else {
                        s.cutoff
                    });
            Ok((start, deadline, s.claim.clone()))
        };
        let (_, wait_deadline, _) = read_window()?;
        // Retain observation order through classification, not merely through
        // the adapter await. A later success must not overtake an earlier denial
        // waiting to publish at the serialized carrier gate.
        let _read = match self
            .clock
            .timeout_until(wait_deadline, self.reads.lock())
            .await
        {
            Ok(read) => read,
            Err(_) => {
                self.abort();
                return Err(Refused::Unavailable);
            }
        };
        // Queue entry bounds only the wait. The preceding serialized read may
        // have renewed freshness; start this observation against CURRENT state.
        // Recheck sticky denial/expiry before constructing any adapter future.
        let (start, deadline, claim) = read_window()?;
        let result = self
            .clock
            .timeout_until(deadline, self.policy.authority.observe(claim))
            .await;
        let _io = self.io_gate.lock().unwrap();
        let mut s = self.state.lock().unwrap();
        let good = if self.clock.now() >= deadline
            || !self.clock.is_continuous()
            || s.phase == Phase::Aborted
            || s.fresh_until.is_some_and(|until| self.clock.now() >= until)
        {
            false
        } else {
            match result {
                Ok(Observation::Active { revision }) => {
                    s.phase == Phase::Active
                        || (s.phase == Phase::Reserved
                            && s.claim
                                .as_ref()
                                .is_some_and(|c| c.expected_revision == revision))
                }
                Ok(Observation::OwnedCommitted {
                    reservation,
                    expected_revision,
                    revision,
                }) => {
                    let matches = s.claim.as_ref().is_some_and(|c| {
                        c.reservation == reservation
                            && c.expected_revision == expected_revision
                            && revision > expected_revision
                            && match s.committed_revision {
                                Some(first) => revision == first,
                                None => s.phase == Phase::Reserved,
                            }
                    });
                    if matches
                        && matches!(
                            s.phase,
                            Phase::Reserved | Phase::Committed | Phase::Selected | Phase::Consumed
                        )
                    {
                        if s.phase == Phase::Reserved {
                            s.committed_revision = Some(revision);
                            s.phase = Phase::Committed;
                        }
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            }
        };
        if !good {
            s.phase = Phase::Aborted;
            self.changed.notify_waiters();
            return Err(Refused::Unavailable);
        }
        s.fresh_until = Some(start + self.policy.read_timeout);
        Ok(())
    }

    async fn perform(
        &self,
        lease: ExecutionLease,
        sender: &Connection,
    ) -> Result<HandlerOutcome, Refused> {
        let cutoff = self.cutoff().ok_or(Refused::Unavailable)?;
        let result = self
            .clock
            .timeout_until(cutoff, async {
                self.refresh().await?;
                let (ack, boundary) = oneshot::channel();
                self.commands
                    .send(DriverCommand::Barrier(ack))
                    .await
                    .map_err(|_| Refused::Unavailable)?;
                boundary.await.map_err(|_| Refused::Unavailable)?;
                self.refresh().await?;
                let claim = {
                    let s = self.state.lock().unwrap();
                    if s.phase != Phase::Reserved || !self.valid(&s) {
                        return Err(Refused::Unavailable);
                    }
                    s.claim.clone().ok_or(Refused::Unavailable)?
                };
                let authority = self.policy.authority.clone();
                let (completed, completion) = oneshot::channel();
                // Actual authority work has its own retained task and lease. The
                // result/close deadline may drop this waiter, never that task.
                let task = spawn_task(async move {
                    let _lease = lease.clone();
                    authority.commit(claim, lease).await;
                    let _ = completed.send(());
                });
                sender.shared.tasks.register(task);
                completion.await.map_err(|_| Refused::Unavailable)?;
                self.refresh().await?;
                if self.state.lock().unwrap().phase != Phase::Committed {
                    return Err(Refused::Unavailable);
                }
                Ok(HandlerOutcome::Payload(self.policy.payload.clone()))
            })
            .await;
        match result {
            Ok(Ok(outcome)) if self.clock.now() < cutoff && self.clock.is_continuous() => {
                Ok(outcome)
            }
            _ => {
                self.abort();
                Err(Refused::Unavailable)
            }
        }
    }
    pub(super) fn select(&self, id: u64, outcome: &HandlerOutcome) {
        let mut s = self.state.lock().unwrap();
        if s.phase == Phase::Active || s.id != id {
            return;
        }
        if s.phase == Phase::Committed
            && self.valid(&s)
            && matches!(outcome, HandlerOutcome::Payload(p) if p == &self.policy.payload)
        {
            s.phase = Phase::Selected;
        } else {
            s.phase = Phase::Aborted;
            self.changed.notify_waiters();
        }
    }
    pub(super) fn emit(&self, id: u64, bytes: Vec<u8>, charge: execution::BudgetPermit) {
        let s = self.state.lock().unwrap();
        if s.id != id {
            return;
        }
        if s.phase != Phase::Selected || s.bytes != bytes || !self.valid(&s) {
            drop(s);
            self.abort();
            return;
        }
        let Some(claim) = &s.claim else {
            drop(s);
            self.abort();
            return;
        };
        if self
            .commands
            .try_send(DriverCommand::Receipt(TerminalOutput {
                bytes,
                reservation: claim.reservation.clone(),
                _charge: charge,
            }))
            .is_err()
        {
            drop(s);
            self.abort();
        }
    }
    /// Consume once at the final first carrier poll, after a fresh observation.
    /// Subsequent polls may finish only this retained ciphertext sequence.
    pub fn consume(&self, output: &TerminalOutput) -> Result<(), Refused> {
        let mut s = self.state.lock().unwrap();
        if s.phase != Phase::Selected
            || s.bytes != output.bytes
            || !s
                .claim
                .as_ref()
                .is_some_and(|c| c.reservation == output.reservation)
            || !self.valid(&s)
        {
            s.phase = Phase::Aborted;
            return Err(Refused::Unavailable);
        }
        s.phase = Phase::Consumed;
        Ok(())
    }
    /// Complete local handoff, not peer acknowledgement or joined cleanup.
    pub fn written(&self) {
        self.state.lock().unwrap().phase = Phase::Finished;
        self.changed.notify_waiters();
    }
    async fn wait_end(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let (phase, cutoff) = {
                let s = self.state.lock().unwrap();
                (s.phase, s.cutoff)
            };
            if matches!(phase, Phase::Aborted | Phase::Finished) {
                return;
            }
            tokio::select! { _ = changed => {}, _ = self.clock.sleep_until(cutoff) => return }
        }
    }
}

impl Host {
    /// Trusted driver integration boundary, not an application enable switch.
    ///
    /// Caller must own the sole encrypted TCP writer, implement every command's
    /// full-frame barrier, final fresh typed observation, one-use raw-poll gate,
    /// and bounded ciphertext retirement. Raw/FFI/WASM drivers cannot use this.
    /// Install before hello. Other authorization monitors must remain coordinated.
    #[doc(hidden)]
    pub fn install_terminal_tcp(&self, policy: Policy) -> Result<Arc<Coordinator>, Refused> {
        if cfg!(target_arch = "wasm32")
            || policy.read_timeout < Duration::from_millis(1)
            || policy.read_timeout > Duration::from_millis(250)
            || syntra_core::validate_method(&policy.method).is_err()
            || policy.payload.len() > 1024
        {
            return Err(Refused::Unsupported);
        }
        let mut slot = self.terminal.lock().unwrap();
        if slot.is_some() || self.bound_id.lock().unwrap().is_some() {
            return Err(Refused::Unsupported);
        }
        let (commands, receiver) = mpsc::channel(2);
        let now = self.conn.shared.clock.now();
        let coordinator = Arc::new(Coordinator {
            policy,
            clock: self.conn.shared.clock.clone(),
            commands,
            changed: Notify::new(),
            reads: tokio::sync::Mutex::new(()),
            io_gate: Mutex::new(()),
            state: Mutex::new(State {
                phase: Phase::Active,
                claim: None,
                committed_revision: None,
                id: 0,
                bytes: vec![],
                cutoff: now,
                deadline: now,
                fresh_until: None,
            }),
        });
        self.calls.lock().unwrap().terminal = Some(coordinator.clone());
        *slot = Some(coordinator.clone());
        *self.terminal_commands.lock().unwrap() = Some(receiver);
        Ok(coordinator)
    }
    /// Native driver's connection-local classifier; absent on ordinary hosts.
    #[doc(hidden)]
    pub fn terminal_coordinator(&self) -> Option<Arc<Coordinator>> {
        self.terminal.lock().unwrap().clone()
    }
    /// Move the typed channel into the sole installed writer, exactly once.
    #[doc(hidden)]
    pub fn take_terminal_commands(&self) -> Option<mpsc::Receiver<DriverCommand>> {
        self.terminal_commands.lock().unwrap().take()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    struct Fixture(Mutex<usize>);
    impl Authority for Fixture {
        fn observe(&self, claim: Option<Transition>) -> BoxFuture<'_, Observation> {
            Box::pin(async move {
                match *self.0.lock().unwrap() {
                    0 => Observation::Active { revision: 7 },
                    mode @ (1 | 5 | 6 | 7 | 8) => match claim {
                        Some(c) => Observation::OwnedCommitted {
                            reservation: c.reservation,
                            expected_revision: 7,
                            revision: match mode {
                                5 => 11,
                                6 => 12,
                                7 => 7,
                                8 => 6,
                                _ => 8,
                            },
                        },
                        None => Observation::HardDenied,
                    },
                    2 => Observation::HardDenied,
                    _ => Observation::Unknown,
                }
            })
        }
        fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
            Box::pin(async {})
        }
    }
    async fn coordinator() -> (Arc<Host>, Arc<Coordinator>, Arc<Fixture>) {
        let (host, _rx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(crate::AllowAnonymous),
            Arc::new(super::super::FnHandler(|_, p, _| async {
                HandlerOutcome::Payload(p)
            })),
        );
        let authority = Arc::new(Fixture(Mutex::new(0)));
        let c = host
            .install_terminal_tcp(Policy {
                method: "/example.Authority/Retire".into(),
                payload: b"retired".to_vec(),
                authority: authority.clone(),
                read_timeout: Duration::from_millis(100),
            })
            .unwrap();
        c.refresh().await.unwrap();
        (host, c, authority)
    }
    fn reserve(c: &Coordinator, seconds: u64) -> Result<(), Refused> {
        c.reserve(
            123,
            1,
            c.clock.now() + Duration::from_secs(seconds),
            7,
            Principal::new("fixture"),
        )
    }
    #[tokio::test(start_paused = true)]
    async fn original_five_second_budget_and_teardown_tail_cannot_renew() {
        let (host, c, _) = coordinator().await;
        let start = c.clock.now();
        reserve(&c, 20).unwrap();
        assert_eq!(c.deadline(), Some(start + Duration::from_secs(5)));
        assert_eq!(c.cutoff(), Some(start + Duration::from_millis(4750)));
        assert_eq!(reserve(&c, 20), Err(Refused::Unavailable));
        tokio::time::advance(Duration::from_millis(4750)).await;
        assert!(!c.raw_allowed());
        host.close().await;
    }
    #[tokio::test(start_paused = true)]
    async fn request_deadline_wins_and_short_budget_refuses_preflight() {
        let (host, c, _) = coordinator().await;
        let start = c.clock.now();
        assert_eq!(
            c.reserve(
                1,
                1,
                start + Duration::from_millis(200),
                7,
                Principal::new("fixture")
            ),
            Err(Refused::Unavailable)
        );
        assert!(c.ordinary_allowed());
        reserve(&c, 1).unwrap();
        assert_eq!(c.deadline(), Some(start + Duration::from_secs(1)));
        assert_eq!(c.cutoff(), Some(start + Duration::from_millis(750)));
        host.close().await;
    }
    #[tokio::test]
    async fn owned_evidence_is_exact_private_reservation_not_public_request_id() {
        let (h1, c1, a1) = coordinator().await;
        let (h2, c2, _) = coordinator().await;
        reserve(&c1, 2).unwrap();
        reserve(&c2, 2).unwrap();
        let first = c1.state.lock().unwrap().claim.clone().unwrap().reservation;
        let second = c2.state.lock().unwrap().claim.clone().unwrap().reservation;
        assert!(
            first != second,
            "same public ID on another host has no ownership"
        );
        *a1.0.lock().unwrap() = 1;
        c1.refresh().await.unwrap();
        assert!(c2.state.lock().unwrap().phase == Phase::Reserved);
        h1.close().await;
        h2.close().await;
    }
    #[tokio::test]
    async fn hard_denial_unknown_and_clock_loss_are_sticky() {
        for failure in [2, 3, 4] {
            let (host, c, a) = coordinator().await;
            reserve(&c, 2).unwrap();
            if failure == 4 {
                c.clock.invalidate();
            } else {
                *a.0.lock().unwrap() = failure;
            }
            assert!(c.refresh().await.is_err());
            *a.0.lock().unwrap() = 1;
            assert!(c.refresh().await.is_err());
            assert!(!c.raw_allowed());
            host.close().await;
        }
    }
    #[tokio::test]
    async fn cancelled_selection_is_not_replaced_by_late_commit() {
        let (host, c, a) = coordinator().await;
        reserve(&c, 2).unwrap();
        c.select(
            123,
            &HandlerOutcome::error(ErrorCode::Cancelled, "cancelled"),
        );
        *a.0.lock().unwrap() = 1;
        assert!(c.refresh().await.is_err());
        c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        assert!(!c.raw_allowed());
        host.close().await;
    }
    #[tokio::test]
    async fn typed_output_is_single_use_and_wrong_bytes_never_consume() {
        let (host, c, a) = coordinator().await;
        reserve(&c, 2).unwrap();
        *a.0.lock().unwrap() = 1;
        c.refresh().await.unwrap();
        c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        let bytes = c.state.lock().unwrap().bytes.clone();
        let budget = ExecutionBudget::new(2);
        let reservation = c.state.lock().unwrap().claim.clone().unwrap().reservation;
        let output = TerminalOutput {
            bytes,
            reservation,
            _charge: budget.try_acquire().unwrap(),
        };
        assert_eq!(budget.in_use(), 1);
        c.consume(&output).unwrap();
        assert_eq!(c.consume(&output), Err(Refused::Unavailable));
        drop(output);
        assert_eq!(budget.in_use(), 0);
        host.close().await;
        let (host, c, a) = coordinator().await;
        reserve(&c, 2).unwrap();
        *a.0.lock().unwrap() = 1;
        c.refresh().await.unwrap();
        c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        let wrong = TerminalOutput {
            bytes: b"wrong".to_vec(),
            reservation: c.state.lock().unwrap().claim.clone().unwrap().reservation,
            _charge: budget.try_acquire().unwrap(),
        };
        assert_eq!(c.consume(&wrong), Err(Refused::Unavailable));
        host.close().await;
    }
    #[tokio::test]
    async fn fresh_denial_after_selection_wins_before_first_raw_poll() {
        let (host, c, a) = coordinator().await;
        reserve(&c, 2).unwrap();
        *a.0.lock().unwrap() = 1;
        c.refresh().await.unwrap();
        c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        let output = {
            let s = c.state.lock().unwrap();
            TerminalOutput {
                bytes: s.bytes.clone(),
                reservation: s.claim.clone().unwrap().reservation,
                _charge: ExecutionBudget::new(1).try_acquire().unwrap(),
            }
        };
        *a.0.lock().unwrap() = 2;
        assert!(c.refresh().await.is_err());
        let mut first = true;
        assert!(c
            .with_receipt_io(&output, &mut first, || panic!("denied handoff"))
            .is_none());
        host.close().await;
    }

    #[tokio::test]
    async fn late_wire_cancel_and_internal_selection_token_do_not_abort_selected_receipt() {
        let (host, c, a) = coordinator().await;
        reserve(&c, 2).unwrap();
        *a.0.lock().unwrap() = 1;
        c.refresh().await.unwrap();
        let cancel = crate::CancelToken::new();
        let (selected, result) = oneshot::channel();
        host.calls.lock().unwrap().pending.insert(
            123,
            PendingCall {
                deadline: c.clock.now() + Duration::from_secs(2),
                cancel: cancel.clone(),
                selected,
            },
        );
        host.calls
            .lock()
            .unwrap()
            .select(123, HandlerOutcome::Payload(b"retired".to_vec()));
        assert!(
            cancel.is_cancelled(),
            "existing internal selection cancellation still occurs"
        );
        assert!(matches!(result.await.unwrap(), HandlerOutcome::Payload(_)));
        host.on_cancel(123).await;
        assert!(c.state.lock().unwrap().phase == Phase::Selected);
        assert!(c.raw_allowed());
        host.close().await;
        assert!(
            !c.raw_allowed(),
            "explicit host close always wins output eligibility"
        );
    }

    #[tokio::test]
    async fn another_generation_cannot_consume_same_public_result_bytes() {
        let (h1, c1, a1) = coordinator().await;
        let (h2, c2, a2) = coordinator().await;
        reserve(&c1, 2).unwrap();
        reserve(&c2, 2).unwrap();
        *a1.0.lock().unwrap() = 1;
        *a2.0.lock().unwrap() = 1;
        c1.refresh().await.unwrap();
        c2.refresh().await.unwrap();
        c1.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        c2.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        let output = {
            let s = c1.state.lock().unwrap();
            TerminalOutput {
                bytes: s.bytes.clone(),
                reservation: s.claim.clone().unwrap().reservation,
                _charge: ExecutionBudget::new(1).try_acquire().unwrap(),
            }
        };
        assert_eq!(c2.consume(&output), Err(Refused::Unavailable));
        h1.close().await;
        h2.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn missed_authority_freshness_is_sticky_even_before_any_io_poll() {
        let (host, c, a) = coordinator().await;
        reserve(&c, 2).unwrap();
        tokio::time::advance(Duration::from_millis(100)).await;
        *a.0.lock().unwrap() = 1;
        assert!(
            c.refresh().await.is_err(),
            "late durable evidence cannot renew lapsed authority"
        );
        assert!(!c.raw_allowed());
        host.close().await;
    }

    /// Build exact selected output without another reservation or wire field.
    fn reserved_output(c: &Coordinator) -> TerminalOutput {
        let state = c.state.lock().unwrap();
        TerminalOutput {
            bytes: state.bytes.clone(),
            reservation: state.claim.as_ref().unwrap().reservation.clone(),
            _charge: ExecutionBudget::new(1).try_acquire().unwrap(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn owned_revision_jump_7_to_11_allows_one_successful_receipt() {
        let (host, c, authority) = coordinator().await;
        reserve(&c, 2).unwrap();
        *authority.0.lock().unwrap() = 5;
        assert!(
            c.refresh().await.is_ok(),
            "a strictly newer owned revision need not be adjacent"
        );
        c.refresh().await.unwrap(); // Stable repeated proof while committed.
        c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
        c.refresh().await.unwrap(); // Stable proof after selection.
        let output = reserved_output(&c);
        let mut first = true;
        assert_eq!(c.with_receipt_io(&output, &mut first, || 1), Some(1));
        c.refresh().await.unwrap(); // Stable proof during retained ciphertext I/O.
        assert_eq!(c.with_receipt_io(&output, &mut first, || 2), Some(2));
        assert_eq!(
            c.consume(&output),
            Err(Refused::Unavailable),
            "the revision jump grants no second use"
        );
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn owned_revision_change_11_to_12_same_owner_aborts_stickily_in_every_phase() {
        for phase in [Phase::Committed, Phase::Selected, Phase::Consumed] {
            let (host, c, authority) = coordinator().await;
            reserve(&c, 2).unwrap();
            *authority.0.lock().unwrap() = 5;
            c.refresh()
                .await
                .expect("initial owned revision 11 must be accepted");
            let output = reserved_output(&c);
            let mut first = true;
            if phase != Phase::Committed {
                c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
            }
            if phase == Phase::Consumed {
                assert!(c.with_receipt_io(&output, &mut first, || ()).is_some());
            }
            *authority.0.lock().unwrap() = 6; // Same SDK owner/expected revision, different committed revision.
            assert_eq!(
                c.refresh().await,
                Err(Refused::Unavailable),
                "later revision 12 must not replace pinned revision 11"
            );
            *authority.0.lock().unwrap() = 5;
            assert!(
                c.refresh().await.is_err(),
                "returning to revision 11 cannot clear the abort"
            );
            c.select(123, &HandlerOutcome::Payload(b"retired".to_vec()));
            assert!(!c.raw_allowed());
            assert!(c
                .with_receipt_io(&output, &mut first, || panic!(
                    "aborted revision emitted bytes"
                ))
                .is_none());
            host.close().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn owned_revision_equal_or_lower_than_expected_is_rejected() {
        for mode in [7, 8] {
            let (host, c, authority) = coordinator().await;
            reserve(&c, 2).unwrap();
            *authority.0.lock().unwrap() = mode;
            assert_eq!(c.refresh().await, Err(Refused::Unavailable));
            assert!(!c.raw_allowed());
            host.close().await;
        }
    }

    /// Exercise RequestContext preflight and the actual retained commit path:
    /// if an invalid revision were admitted, this fixture would record a commit.
    async fn invalid_expected_revision_preflight(expected: u64) {
        use std::sync::atomic::AtomicUsize;
        struct AuthorityFixture {
            expected: u64,
            committed: Mutex<Option<Transition>>,
            commits: AtomicUsize,
        }
        impl Authority for AuthorityFixture {
            fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
                Box::pin(async {
                    match self.committed.lock().unwrap().as_ref() {
                        None => Observation::Active {
                            revision: self.expected,
                        },
                        Some(c) => Observation::OwnedCommitted {
                            reservation: c.reservation.clone(),
                            expected_revision: self.expected,
                            revision: self.expected.saturating_add(1),
                        },
                    }
                })
            }
            fn commit(&self, claim: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
                Box::pin(async move {
                    *self.committed.lock().unwrap() = Some(claim);
                    self.commits.fetch_add(1, Ordering::SeqCst);
                })
            }
        }
        let (host, mut ordinary) = Host::new(
            ConnectionConfig::default(),
            Arc::new(crate::StaticToken::new(
                b"fixture".to_vec(),
                "fixture-principal",
            )),
            Arc::new(super::super::FnHandler(|_, p, _| async {
                HandlerOutcome::Payload(p)
            })),
        );
        let authority = Arc::new(AuthorityFixture {
            expected,
            committed: Mutex::new(None),
            commits: AtomicUsize::new(0),
        });
        let c = host
            .install_terminal_tcp(Policy {
                method: "/example.Authority/Retire".into(),
                payload: b"retired".to_vec(),
                authority: authority.clone(),
                read_timeout: Duration::from_millis(100),
            })
            .unwrap();
        c.refresh().await.unwrap();
        host.ingest(
            &Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Hello(syntra_core::proto::ClientHello {
                    min_version: 1,
                    max_version: 1,
                    credential: b"fixture".to_vec(),
                })),
            }
            .encode_to_vec(),
        )
        .await;
        ordinary.recv().await.unwrap();
        let deadline = c.clock.now() + Duration::from_secs(2);
        let (selected, _selection) = oneshot::channel();
        host.calls.lock().unwrap().pending.insert(
            123,
            PendingCall {
                deadline,
                cancel: crate::CancelToken::new(),
                selected,
            },
        );
        let (lease, _observer) = ExecutionLease::acquire(&host.execution, None).unwrap();
        let context = RequestContext::new(
            Arc::downgrade(&host),
            123,
            1,
            "/example.Authority/Retire".into(),
            deadline,
        )
        .with_lease(lease);
        let mut commands = host.take_terminal_commands().unwrap();
        let mut retirement = Box::pin(context.retire(expected));
        let result = loop {
            tokio::select! {
                biased;
                result = &mut retirement => break result,
                command = commands.recv() => match command {
                    Some(DriverCommand::Barrier(ack)) => ack.send(()).unwrap(),
                    _ => panic!("invalid preflight reached terminal output"),
                }
            }
        };
        assert_eq!(
            authority.commits.load(Ordering::SeqCst),
            0,
            "invalid expected revision must never invoke the authority commit"
        );
        assert!(matches!(result, Err(Refused::Unavailable)));
        assert!(
            c.ordinary_allowed(),
            "invalid preflight must not reserve or fence"
        );
        assert!(c.state.lock().unwrap().claim.is_none());
        drop(retirement);
        drop(context);
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn expected_revision_zero_preflight_rejects_without_authority_commit() {
        invalid_expected_revision_preflight(0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn expected_revision_max_preflight_rejects_without_authority_commit() {
        invalid_expected_revision_preflight(u64::MAX).await;
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_active_ordinary_start_aborts_without_consuming_a_nonce() {
        let (host, c, _) = coordinator().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(
            c.start_ordinary(|| panic!("invalid authority consumed a nonce")),
            Err::<Option<()>, _>(Refused::Unavailable)
        );
        assert!(
            c.state.lock().unwrap().phase == Phase::Aborted,
            "invalid Active authority must fail stickily, not suppress a frame"
        );
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn valid_fenced_ordinary_start_does_not_consume_a_nonce_or_abort() {
        let (host, c, _) = coordinator().await;
        reserve(&c, 2).unwrap();
        assert_eq!(
            c.start_ordinary(|| panic!("fenced frame consumed a nonce")),
            Ok::<Option<()>, _>(None)
        );
        assert!(c.state.lock().unwrap().phase == Phase::Reserved);
        assert!(c.raw_allowed());
        host.close().await;
    }

    /// Hold each fresh read independently so queue wait and observation time can
    /// be advanced without scheduler races or wall-time sleeps.
    struct QueuedAuthority {
        calls: std::sync::atomic::AtomicUsize,
        release: tokio::sync::Semaphore,
        denied: std::sync::atomic::AtomicBool,
    }
    impl Authority for QueuedAuthority {
        fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                self.release.acquire().await.unwrap().forget();
                if self.denied.load(Ordering::SeqCst) {
                    Observation::HardDenied
                } else {
                    Observation::Active { revision: 7 }
                }
            })
        }
        fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
            panic!("refresh tests never commit")
        }
    }
    async fn queued_coordinator() -> (Arc<Host>, Arc<Coordinator>, Arc<QueuedAuthority>) {
        let (host, _) = Host::new(
            ConnectionConfig::default(),
            Arc::new(crate::AllowAnonymous),
            Arc::new(super::super::FnHandler(|_, p, _| async {
                HandlerOutcome::Payload(p)
            })),
        );
        let authority = Arc::new(QueuedAuthority {
            calls: std::sync::atomic::AtomicUsize::new(0),
            release: tokio::sync::Semaphore::new(1),
            denied: std::sync::atomic::AtomicBool::new(false),
        });
        let c = host
            .install_terminal_tcp(Policy {
                method: "/example.Authority/Retire".into(),
                payload: b"retired".to_vec(),
                authority: authority.clone(),
                read_timeout: Duration::from_millis(100),
            })
            .unwrap();
        c.refresh().await.unwrap();
        (host, c, authority)
    }

    #[tokio::test(start_paused = true)]
    async fn queued_refresh_uses_current_freshness_and_its_actual_read_start() {
        let (host, c, authority) = queued_coordinator().await;
        let origin = c.clock.now();
        tokio::time::advance(Duration::from_millis(20)).await;
        let mut first = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut first).is_pending());
        tokio::time::advance(Duration::from_millis(10)).await;
        let mut second = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut second).is_pending());
        assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
        tokio::time::advance(Duration::from_millis(30)).await;
        authority.release.add_permits(1);
        first.await.unwrap(); // t=60, current freshness is now t=120.
        assert!(futures_util::poll!(&mut second).is_pending());
        assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
        tokio::time::advance(Duration::from_millis(45)).await;
        authority.release.add_permits(1);
        assert_eq!(
            second.await,
            Ok(()),
            "t=105 is after the queued call's old t=100 deadline, before current t=120"
        );
        assert_eq!(
            c.state.lock().unwrap().fresh_until,
            Some(origin + Duration::from_millis(160)),
            "freshness starts at actual observation t=60, not queue entry t=30"
        );
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn queued_refresh_rechecks_expiry_before_constructing_an_authority_read() {
        let (host, c, authority) = queued_coordinator().await;
        let lock = c.reads.lock().await;
        let mut queued = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut queued).is_pending());
        tokio::time::advance(Duration::from_millis(100)).await;
        drop(lock);
        assert_eq!(queued.await, Err(Refused::Unavailable));
        authority.release.add_permits(1);
        assert_eq!(c.refresh().await, Err(Refused::Unavailable));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn queued_refresh_cannot_renew_at_current_freshness_deadline() {
        let (host, c, authority) = queued_coordinator().await;
        tokio::time::advance(Duration::from_millis(20)).await;
        let mut first = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut first).is_pending());
        tokio::time::advance(Duration::from_millis(10)).await;
        let mut second = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut second).is_pending());
        tokio::time::advance(Duration::from_millis(30)).await;
        authority.release.add_permits(1);
        first.await.unwrap();
        let current = c.state.lock().unwrap().fresh_until;
        assert!(futures_util::poll!(&mut second).is_pending());
        tokio::time::advance(Duration::from_millis(60)).await; // t=120 exact tie.
        authority.release.add_permits(1);
        assert_eq!(second.await, Err(Refused::Unavailable));
        assert_eq!(c.state.lock().unwrap().fresh_until, current);
        assert_eq!(c.refresh().await, Err(Refused::Unavailable));
        assert_eq!(authority.calls.load(Ordering::SeqCst), 3);
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn denial_before_queued_acquisition_cannot_start_a_read_or_renew() {
        let (host, c, authority) = queued_coordinator().await;
        let until = c.state.lock().unwrap().fresh_until;
        let mut first = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut first).is_pending());
        let mut second = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut second).is_pending());
        authority.denied.store(true, Ordering::SeqCst);
        authority.release.add_permits(1);
        assert_eq!(first.await, Err(Refused::Unavailable));
        authority.denied.store(false, Ordering::SeqCst);
        authority.release.add_permits(1);
        assert_eq!(second.await, Err(Refused::Unavailable));
        assert_eq!(
            authority.calls.load(Ordering::SeqCst),
            2,
            "queued caller must reject denial before even constructing observe"
        );
        assert_eq!(c.state.lock().unwrap().fresh_until, until);
        host.close().await;
    }

    #[tokio::test(start_paused = true)]
    async fn queued_refresh_preserves_initial_wait_bound_and_late_success_is_sticky() {
        let (host, c, authority) = queued_coordinator().await;
        let mut first = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut first).is_pending());
        let mut second = Box::pin(c.refresh());
        assert!(futures_util::poll!(&mut second).is_pending());
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(second.await, Err(Refused::Unavailable));
        authority.release.add_permits(1);
        assert_eq!(first.await, Err(Refused::Unavailable));
        assert!(!c.raw_allowed());
        assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
        host.close().await;
    }
}
