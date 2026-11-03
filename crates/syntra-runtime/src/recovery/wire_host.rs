//! Bounded, connection-local host state. Atomic operation ownership avoids
//! holding a mutex across provider callbacks; overlapping operations fail fast.
//! A std Mutex protects only short moves/registry bookkeeping, never an await.

use super::codec::{self, ProfileMessage};
use super::*;
use crate::emission::now;
use prost::Message;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use syntra_core::proto::*;
use tokio::sync::Notify;
use web_time::Instant;

struct Registration {
    principal: String,
    session: Weak<RecoveryHostSession>,
    subscriptions: usize,
}
struct Registry {
    next_connection: u64,
    connections: HashMap<u64, Registration>,
}

pub struct RecoveryService {
    source: Arc<dyn RecoverySource>,
    limits: RecoveryLimits,
    prefix: [u8; 16],
    registry: Mutex<Registry>,
}

impl RecoveryService {
    pub fn new(
        source: Arc<dyn RecoverySource>,
        limits: RecoveryLimits,
    ) -> Result<Arc<Self>, ProviderError> {
        limits.validate()?;
        let mut prefix = [0; 16];
        #[cfg(not(target_arch = "wasm32"))]
        getrandom::fill(&mut prefix).map_err(|_| ProviderError::Internal)?;
        #[cfg(target_arch = "wasm32")]
        getrandom::getrandom(&mut prefix).map_err(|_| ProviderError::Internal)?;
        Ok(Arc::new(Self {
            source,
            limits,
            prefix,
            registry: Mutex::new(Registry {
                next_connection: 0,
                connections: HashMap::new(),
            }),
        }))
    }

    pub fn limits(&self) -> &RecoveryLimits {
        &self.limits
    }

    pub fn open_connection(
        self: &Arc<Self>,
        principal: Principal,
    ) -> Result<Arc<RecoveryHostSession>, ProviderError> {
        if principal.subject.is_empty() || principal.subject.len() > 1024 {
            return Err(ProviderError::Unauthenticated);
        }
        let mut registry = self.registry.lock().expect("recovery registry poisoned");
        registry
            .connections
            .retain(|_, r| r.session.strong_count() != 0);
        if registry.connections.len() >= self.limits.max_connections
            || registry
                .connections
                .values()
                .filter(|r| r.principal == principal.subject)
                .count()
                >= self.limits.max_connections_per_principal
        {
            return Err(ProviderError::ResourceExhausted);
        }
        let token = registry
            .next_connection
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted)?;
        registry.next_connection = token;
        let session = Arc::new(RecoveryHostSession {
            service: Arc::clone(self),
            principal,
            token,
            closed: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            state: Mutex::new(Some(State::default())),
            terminal_error: Mutex::new(None),
            wake: Notify::new(),
        });
        registry.connections.insert(
            token,
            Registration {
                principal: session.principal.subject.clone(),
                session: Arc::downgrade(&session),
                subscriptions: 0,
            },
        );
        Ok(session)
    }

    fn reserve(self: &Arc<Self>, session: &RecoveryHostSession) -> Result<Quota, ProviderError> {
        let mut registry = self.registry.lock().expect("recovery registry poisoned");
        let count: usize = registry
            .connections
            .values()
            .filter(|r| r.principal == session.principal.subject)
            .map(|r| r.subscriptions)
            .sum();
        if count >= self.limits.subscriptions_per_principal {
            return Err(ProviderError::ResourceExhausted);
        }
        let r = registry
            .connections
            .get_mut(&session.token)
            .ok_or(ProviderError::Unavailable)?;
        if r.subscriptions >= self.limits.subscriptions_per_connection {
            return Err(ProviderError::ResourceExhausted);
        }
        r.subscriptions += 1;
        Ok(Quota {
            service: Arc::clone(self),
            token: session.token,
        })
    }

    fn sessions(&self, principal: &Principal) -> Vec<Arc<RecoveryHostSession>> {
        self.registry
            .lock()
            .expect("recovery registry poisoned")
            .connections
            .values()
            .filter(|r| r.principal == principal.subject)
            .filter_map(|r| r.session.upgrade())
            .collect()
    }

    fn observe_principal_source<T>(
        &self,
        principal: &Principal,
        result: Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        if matches!(&result, Err(ProviderError::Unauthenticated)) {
            // A detected principal withdrawal also fences idle, unnegotiated,
            // or currently busy connections owned by this service. No state
            // operation or provider callback runs under the registry lock.
            for session in self.sessions(principal) {
                session.record_terminal_error(ProviderError::Unauthenticated);
            }
        }
        result
    }

    /// Application-driven publication only; no polling or per-batch tasks.
    /// Caller must serialize publication with capture and retry ResourceExhausted
    /// with a bounded budget. A retry can duplicate already delivered batches;
    /// it must use identical issued bytes. Never ignore a publication error.
    /// Fanout is bounded by the principal connection/subscription quotas.
    pub fn publish(
        &self,
        principal: &Principal,
        stable_identity: &[u8],
        batch: StoredBatch,
    ) -> Result<(), ProviderError> {
        if stable_identity.is_empty() || stable_identity.len() > 1024 {
            return Err(ProviderError::FailedPrecondition);
        }
        if batch.payload.len() > 262_144
            || batch.predecessor.len() > 4096
            || batch.result.is_empty()
            || batch.result.len() > 4096
            || batch.generation == 0
        {
            return Err(ProviderError::Internal);
        }
        let mut error = None;
        for session in self.sessions(principal) {
            if let Err(e) = session.publish(stable_identity, &batch) {
                remember_error(&mut error, e);
            }
        }
        self.observe_principal_source(principal, error.map_or(Ok(()), Err))
    }

    /// Source must first commit the scoped epoch change, and declare why.
    /// Each affected P/S must be reported explicitly. A mismatch observed on a
    /// later hook is also fenced using the provider's current G, never guessed.
    pub fn provider_loss(
        &self,
        principal: &Principal,
        stable_identity: &[u8],
        old_generation: u64,
        next_generation: u64,
        _reason: ProviderLoss,
    ) -> Result<(), ProviderError> {
        if next_generation <= old_generation || old_generation == 0 {
            return Err(ProviderError::FailedPrecondition);
        }
        let current = self.observe_principal_source(
            principal,
            self.source.current_generation(principal, stable_identity),
        )?;
        if current != next_generation {
            return Err(ProviderError::FailedPrecondition);
        }
        let mut error = None;
        for session in self.sessions(principal) {
            match session.operation() {
                Ok(mut op) => {
                    for slot in &mut op.state.slots {
                        if slot.sub.as_ref().is_some_and(|s| {
                            s.stream.identity == stable_identity
                                && s.stream.generation == old_generation
                        }) {
                            slot.end(
                                recovery_batch_trailer::Outcome::NextGeneration(next_generation),
                                &[],
                            );
                        }
                    }
                }
                Err(e) => remember_error(&mut error, e),
            }
        }
        error.map_or(Ok(()), Err)
    }
}

struct Quota {
    service: Arc<RecoveryService>,
    token: u64,
}
impl Drop for Quota {
    fn drop(&mut self) {
        if let Some(r) = self
            .service
            .registry
            .lock()
            .expect("recovery registry poisoned")
            .connections
            .get_mut(&self.token)
        {
            r.subscriptions -= 1;
        }
    }
}

#[derive(Default)]
struct State {
    confirmed: bool,
    next_handle: u64,
    slots: Vec<Slot>,
    round_robin: usize,
}
struct Slot {
    handle: Vec<u8>,
    generation: u64,
    boundary: Vec<u8>,
    sub: Option<Subscription>,
    terminal: Option<Vec<u8>>,
}
struct Subscription {
    _quota: Quota,
    selector: Vec<u8>,
    stream: ProviderStream,
    start: Vec<u8>,
    cursor: Vec<u8>,
    marker: Vec<u8>,
    mode: Mode,
    complete: bool,
    completion: Option<Vec<u8>>,
    completion_pending: bool,
    replay_reply: Option<Reply>,
    catchup_reply: Option<Reply>,
    snapshot_reply: Option<Reply>,
    snapshot: Option<Snapshot>,
    data: VecDeque<Queued>,
    held: VecDeque<Queued>,
    live_tail: Vec<u8>,
    offered: VecDeque<Vec<u8>>,
    last_confirm: Option<Vec<u8>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Undecided,
    Replay,
    CatchUp,
    Snapshot,
}
struct Snapshot {
    handle: Vec<u8>,
    source: ProviderSnapshot,
    fetched: [bool; 256],
    installed: bool,
    installed_reply: Option<Reply>,
}
struct Queued {
    bytes: Vec<u8>,
    checkpoint: Vec<u8>,
}
struct Reply {
    request: Vec<u8>,
    bytes: Vec<u8>,
    expires: Instant,
    retries: u32,
}
impl Reply {
    fn new(request: Vec<u8>, bytes: Vec<u8>, limits: &RecoveryLimits) -> Self {
        Self {
            request,
            bytes,
            expires: now() + limits.reply_ttl,
            retries: limits.reply_retries,
        }
    }
    fn retry(&mut self, request: &[u8]) -> Result<Vec<u8>, ProviderError> {
        if request != self.request || self.retries == 0 || now() >= self.expires {
            return Err(ProviderError::FailedPrecondition);
        }
        self.retries -= 1;
        Ok(self.bytes.clone())
    }
    fn size(&self) -> usize {
        self.request.len() + self.bytes.len()
    }
}

impl Subscription {
    fn queued_bytes(&self) -> usize {
        self.data
            .iter()
            .chain(&self.held)
            .map(|q| q.bytes.len())
            .sum()
    }
    fn replies(&self) -> impl Iterator<Item = &Reply> {
        self.replay_reply
            .iter()
            .chain(self.catchup_reply.iter())
            .chain(self.snapshot_reply.iter())
            .chain(self.snapshot.iter().flat_map(|s| s.installed_reply.iter()))
    }
    fn offer(&mut self, cp: Vec<u8>, limits: &RecoveryLimits) -> Result<(), ProviderError> {
        if self.last_confirm.as_ref() == Some(&cp) || self.offered.back() == Some(&cp) {
            return Ok(());
        }
        if self.offered.len() >= limits.queued_messages_per_stream
            || self.offered.iter().map(Vec::len).sum::<usize>() + cp.len()
                > limits.queued_bytes_per_stream
        {
            return Err(ProviderError::ResourceExhausted);
        }
        self.offered.push_back(cp);
        Ok(())
    }

    /// Locate S0 in the bounded held chain without ordering opaque checkpoints.
    /// Return the prefix covered by the snapshot and the retained live tail.
    /// Validate before dropping anything: an unrelated queue needs a fresh H,
    /// not a guessed cut or a subscription silently waiting on obsolete B.
    fn snapshot_live_cut(
        &self,
        handle: &[u8],
        generation: u64,
        boundary: &[u8],
    ) -> Result<(usize, Vec<u8>), ProviderError> {
        if self.held.is_empty() {
            return Ok((0, boundary.to_vec()));
        }
        let mut cut = None;
        let mut previous = None;
        for (index, queued) in self.held.iter().enumerate() {
            // Decode only one bounded entry at a time, never copy the history.
            let event: RecoveryNotification = codec::decode(&queued.bytes)?;
            let Some(recovery_notification::Notification::Batch(batch)) = event.notification else {
                return Err(ProviderError::FailedPrecondition);
            };
            if batch.subscription_handle != handle
                || batch.generation != generation
                || batch.result_checkpoint != queued.checkpoint
                || previous
                    .as_ref()
                    .is_some_and(|p| *p != batch.predecessor_checkpoint)
            {
                return Err(ProviderError::FailedPrecondition);
            }
            if index == 0 && batch.predecessor_checkpoint == boundary {
                cut = Some(0);
            }
            if batch.result_checkpoint == boundary && cut.is_none() {
                cut = Some(index + 1);
            }
            previous = Some(batch.result_checkpoint);
        }
        Ok((
            cut.ok_or(ProviderError::FailedPrecondition)?,
            previous.expect("nonempty held chain"),
        ))
    }
}

impl Slot {
    fn trailer(&self, outcome: recovery_batch_trailer::Outcome, reason: &[u8]) -> Vec<u8> {
        notification(recovery_notification::Notification::Trailer(
            RecoveryBatchTrailer {
                profile_version: 1,
                subscription_handle: self.handle.clone(),
                generation: self.generation,
                boundary_checkpoint: self.boundary.clone(),
                outcome: Some(outcome),
                terminate_reason: reason.to_vec(),
            },
        ))
    }
    fn end(&mut self, outcome: recovery_batch_trailer::Outcome, reason: &[u8]) {
        self.terminal = Some(self.trailer(outcome, reason));
        self.sub = None; // drops quota, queues, confirmations, snapshot and replies
    }
    fn overflow(&mut self) {
        self.end(
            recovery_batch_trailer::Outcome::Terminated(true),
            b"local-queue-exhausted",
        );
    }
    fn snapshot_required(&mut self) {
        let trailer = self.trailer(recovery_batch_trailer::Outcome::SnapshotRequired(true), &[]);
        if let Some(s) = &mut self.sub {
            s.mode = Mode::Snapshot;
            s.complete = false;
            s.completion = Some(trailer);
            s.completion_pending = true;
            s.replay_reply = None;
            s.catchup_reply = None;
            s.offered.clear();
            s.data.clear();
        }
    }
    fn finish(&mut self, catchup: bool) {
        let done = if catchup {
            self.trailer(recovery_batch_trailer::Outcome::CatchupComplete(true), &[])
        } else {
            notification(recovery_notification::Notification::ReplayComplete(
                RecoveryReplayComplete {
                    profile_version: 1,
                    subscription_handle: self.handle.clone(),
                    generation: self.generation,
                    live_boundary_checkpoint: self.boundary.clone(),
                },
            ))
        };
        let s = self.sub.as_mut().expect("active slot");
        s.complete = true;
        s.completion = Some(done);
        s.completion_pending = true;
    }
}

fn notification(value: recovery_notification::Notification) -> Vec<u8> {
    RecoveryNotification {
        profile_version: 1,
        notification: Some(value),
    }
    .encode_to_vec()
}

/// Instrumentation counts data and reserved control separately. There are at
/// most two control records per admitted slot (completion and terminal), each
/// bounded by the profile metadata caps, outside the configurable data budget.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct QueueCounts {
    pub subscriptions: usize,
    pub data_messages: usize,
    pub data_bytes: usize,
    pub control_messages: usize,
    pub control_bytes: usize,
    pub retained_replies: usize,
    pub retained_reply_bytes: usize,
    pub offered_checkpoints: usize,
}

pub struct RecoveryHostSession {
    service: Arc<RecoveryService>,
    principal: Principal,
    token: u64,
    closed: AtomicBool,
    busy: AtomicBool,
    state: Mutex<Option<State>>,
    terminal_error: Mutex<Option<ProviderError>>,
    wake: Notify,
}

/// Exclusive ownership, not a mutex guard. Close can fence an in-flight callback
/// immediately; Drop never restores work to a closed connection. A provider panic
/// propagates and closes the session, rather than silently dropping half-state.
struct Operation<'a> {
    session: &'a RecoveryHostSession,
    state: State,
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.session.close();
        }
        let ready = self.state.slots.iter().any(|slot| {
            slot.terminal.is_some()
                || slot.sub.as_ref().is_some_and(|s| {
                    !s.data.is_empty()
                        || s.completion_pending
                        || (s.complete && !s.held.is_empty())
                        || (s.mode == Mode::CatchUp && !s.complete)
                })
        });
        let mut state = self.session.state.lock().expect("recovery state poisoned");
        if !self.session.closed.load(Ordering::Acquire) {
            *state = Some(std::mem::take(&mut self.state));
        }
        self.session.busy.store(false, Ordering::Release);
        if ready {
            self.session.wake.notify_one();
        }
    }
}

impl RecoveryHostSession {
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    /// Distinguishes production failure from normal close when the async
    /// notification worker returns None. No provider diagnostics are retained.
    pub fn terminal_error(&self) -> Option<ProviderError> {
        *self.terminal_error.lock().expect("recovery error poisoned")
    }

    fn record_terminal_error(&self, error: ProviderError) {
        let mut terminal = self.terminal_error.lock().expect("recovery error poisoned");
        // Authentication withdrawal is sticky, including when another failure
        // or a deadline is observed after its targeted trailer was consumed.
        if *terminal != Some(ProviderError::Unauthenticated) {
            *terminal = Some(error);
        }
        self.wake.notify_waiters();
    }

    fn observe_source<T>(&self, result: Result<T, ProviderError>) -> Result<T, ProviderError> {
        if matches!(&result, Err(ProviderError::Unauthenticated)) {
            self.record_terminal_error(ProviderError::Unauthenticated);
        }
        result
    }

    fn authorize(&self, selector: &[u8], hook: AuthorizationHook) -> Result<(), ProviderError> {
        self.observe_source(
            self.service
                .source
                .authorize(&self.principal, selector, hook),
        )
    }
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.service
                .registry
                .lock()
                .expect("recovery registry poisoned")
                .connections
                .remove(&self.token);
            self.state.lock().expect("recovery state poisoned").take();
            self.wake.notify_waiters();
        }
    }
    fn operation(&self) -> Result<Operation<'_>, ProviderError> {
        if self.is_closed() {
            return Err(ProviderError::Unavailable);
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ProviderError::ResourceExhausted)?;
        let state = self.state.lock().expect("recovery state poisoned").take();
        match state {
            Some(mut state) if !self.is_closed() => {
                expire_replies(&mut state);
                Ok(Operation {
                    session: self,
                    state,
                })
            }
            _ => {
                self.busy.store(false, Ordering::Release);
                Err(ProviderError::Unavailable)
            }
        }
    }
    fn handle_bytes(&self, state: &mut State) -> Result<Vec<u8>, ProviderError> {
        let next = state
            .next_handle
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted)?;
        if next > self.service.limits.handles_per_connection as u64 {
            return Err(ProviderError::ResourceExhausted);
        }
        state.next_handle = next;
        let mut handle = self.service.prefix.to_vec();
        handle.extend_from_slice(&self.token.to_be_bytes());
        handle.extend_from_slice(&next.to_be_bytes());
        Ok(handle)
    }
    fn check(&self, slot: &mut Slot, hook: AuthorizationHook) -> Result<(), ProviderError> {
        let s = slot.sub.as_ref().ok_or(ProviderError::FailedPrecondition)?;
        let auth = self.authorize(&s.selector, hook);
        if let Err(e) = auth {
            slot.end(
                recovery_batch_trailer::Outcome::Terminated(true),
                b"authorization-ended",
            );
            return Err(e);
        }
        let current = self.observe_source(
            self.service
                .source
                .current_generation(&self.principal, &s.stream.identity),
        );
        let current = match current {
            Ok(current) => current,
            Err(error) => {
                if matches!(
                    error,
                    ProviderError::PermissionDenied | ProviderError::Unauthenticated
                ) {
                    slot.end(
                        recovery_batch_trailer::Outcome::Terminated(true),
                        b"authorization-ended",
                    );
                }
                return Err(error);
            }
        };
        if current != slot.generation {
            if current > slot.generation {
                slot.end(
                    recovery_batch_trailer::Outcome::NextGeneration(current),
                    &[],
                );
            } else {
                slot.end(
                    recovery_batch_trailer::Outcome::Terminated(true),
                    b"provider-binding-lost",
                );
            }
            return Err(ProviderError::FailedPrecondition);
        }
        if self.is_closed() {
            return Err(ProviderError::Unavailable);
        }
        Ok(())
    }
    fn deadline(&self, deadline: Instant) -> Result<(), ProviderError> {
        if self.is_closed() {
            Err(ProviderError::Unavailable)
        } else if now() >= deadline {
            Err(ProviderError::DeadlineExceeded)
        } else {
            Ok(())
        }
    }

    /// Ordinary RPC payload in/out. Core envelope/path admission remains the
    /// parent's responsibility; this also rejects malformed method paths.
    pub fn handle(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, ProviderError> {
        self.handle_with_deadline(method, payload, self.service.limits.default_deadline)
    }

    /// Parent supplies the remaining bounded core RPC deadline. Synchronous
    /// provider calls must meet their fast contract; expiry wins before exposure.
    pub fn handle_with_deadline(
        &self,
        method: &str,
        payload: &[u8],
        remaining: Duration,
    ) -> Result<Vec<u8>, ProviderError> {
        if !canonical(method) {
            return Err(ProviderError::InvalidArgument);
        }
        if !METHODS.contains(&method) {
            return Err(ProviderError::Unimplemented);
        }
        let deadline = now()
            .checked_add(remaining.min(self.service.limits.default_deadline))
            .ok_or(ProviderError::DeadlineExceeded)?;
        self.deadline(deadline)?;
        let mut op = self.operation()?;
        if method != NEGOTIATE && !op.state.confirmed {
            return Err(ProviderError::Unimplemented);
        }
        let result = self.observe_source(self.dispatch(&mut op.state, method, payload, deadline));
        self.deadline(deadline)?;
        result
    }

    fn dispatch(
        &self,
        state: &mut State,
        method: &str,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        if method == NEGOTIATE {
            if state.confirmed {
                return Err(ProviderError::FailedPrecondition);
            }
            let r: RecoveryNegotiateRequest = codec::decode(payload)?;
            if r.min_version > 1 || r.max_version < 1 {
                return Err(ProviderError::FailedPrecondition);
            }
            let l = &self.service.limits;
            let reply = codec::encode(&RecoveryNegotiateResponse {
                profile_version: 1,
                selected_version: 1,
                max_subscriptions_per_connection: l.subscriptions_per_connection as u32,
                max_pending_rpcs_per_connection: l.pending_rpcs_per_connection as u32,
                max_page_bytes: l.replay_bytes as u32,
                max_snapshot_pages: l.snapshot_pages,
            })?;
            state.confirmed = true;
            return Ok(reply);
        }
        if method == SUBSCRIBE {
            return self.subscribe(state, codec::decode(payload)?, deadline);
        }
        let (handle, hook) = match method {
            REPLAY => (
                codec::decode::<RecoveryReplayRequest>(payload)?.subscription_handle,
                AuthorizationHook::Replay,
            ),
            CATCH_UP => (
                codec::decode::<RecoveryCatchUpRequest>(payload)?.subscription_handle,
                AuthorizationHook::CatchUp,
            ),
            CONFIRM => (
                codec::decode::<RecoveryConfirmRequest>(payload)?.subscription_handle,
                AuthorizationHook::Confirm,
            ),
            SNAPSHOT_OFFER => (
                codec::decode::<RecoverySnapshotOfferRequest>(payload)?.subscription_handle,
                AuthorizationHook::SnapshotOffer,
            ),
            SNAPSHOT_CONFIRM => (
                codec::decode::<RecoverySnapshotConfirmRequest>(payload)?.subscription_handle,
                AuthorizationHook::SnapshotConfirm,
            ),
            UNSUBSCRIBE => (
                codec::decode::<RecoveryUnsubscribeRequest>(payload)?.subscription_handle,
                AuthorizationHook::Unsubscribe,
            ),
            SNAPSHOT_FETCH => {
                let r: RecoverySnapshotFetchRequest = codec::decode(payload)?;
                let h = state
                    .slots
                    .iter()
                    .find(|slot| {
                        slot.sub
                            .as_ref()
                            .and_then(|s| s.snapshot.as_ref())
                            .is_some_and(|s| s.handle == r.snapshot_handle)
                    })
                    .map(|s| s.handle.clone())
                    .ok_or(ProviderError::FailedPrecondition)?;
                (h, AuthorizationHook::SnapshotFetch)
            }
            _ => return Err(ProviderError::Unimplemented),
        };
        let index = state
            .slots
            .iter()
            .position(|s| s.handle == handle)
            .ok_or(ProviderError::FailedPrecondition)?;
        self.check(&mut state.slots[index], hook)?;
        let result = match method {
            REPLAY => self.replay(&mut state.slots[index], codec::decode(payload)?, deadline),
            CATCH_UP => self.catch_up(&mut state.slots[index], codec::decode(payload)?, deadline),
            CONFIRM => self.confirm(&mut state.slots[index], codec::decode(payload)?, deadline),
            SNAPSHOT_OFFER => self.snapshot_offer(state, index, codec::decode(payload)?, deadline),
            SNAPSHOT_FETCH => {
                self.snapshot_fetch(&mut state.slots[index], codec::decode(payload)?, deadline)
            }
            SNAPSHOT_CONFIRM => {
                self.snapshot_confirm(&mut state.slots[index], codec::decode(payload)?, deadline)
            }
            UNSUBSCRIBE => {
                let reply = codec::encode(&RecoveryUnsubscribeResponse {
                    profile_version: 1,
                    subscription_handle: handle,
                    generation: state.slots[index].generation,
                })?;
                state.slots[index].end(
                    recovery_batch_trailer::Outcome::Terminated(true),
                    b"unsubscribed",
                );
                Ok(reply)
            }
            _ => unreachable!(),
        };
        if matches!(result, Err(ProviderError::ProviderRetentionMiss)) {
            state.slots[index].snapshot_required();
        }
        if matches!(result, Err(ProviderError::ResourceExhausted)) {
            state.slots[index].overflow();
        }
        self.enforce(state, index)?;
        result
    }

    fn subscribe(
        &self,
        state: &mut State,
        r: RecoverySubscribeRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        if state.slots.len() >= self.service.limits.subscriptions_per_connection {
            return Err(ProviderError::ResourceExhausted);
        }
        let quota = self.service.reserve(self)?;
        self.authorize(&r.stream_selector, AuthorizationHook::Subscribe)?;
        let stream = self
            .service
            .source
            .capture(&self.principal, &r.stream_selector)?;
        if !r.start_checkpoint.is_empty() {
            self.service
                .source
                .validate_issued(&self.principal, &stream, &r.start_checkpoint)?;
        }
        if self
            .service
            .source
            .current_generation(&self.principal, &stream.identity)?
            != stream.generation
        {
            return Err(ProviderError::FailedPrecondition);
        }
        self.authorize(&r.stream_selector, AuthorizationHook::Subscribe)?;
        self.deadline(deadline)?;
        let handle = self.handle_bytes(state)?;
        let reply = codec::encode(&RecoverySubscribeResponse {
            profile_version: 1,
            subscription_handle: handle.clone(),
            generation: stream.generation,
            catchup_boundary: stream.boundary.clone(),
        })?;
        let cursor = if r.start_checkpoint.is_empty() {
            stream.boundary.clone()
        } else {
            r.start_checkpoint.clone()
        };
        state.slots.push(Slot {
            handle,
            generation: stream.generation,
            boundary: stream.boundary.clone(),
            terminal: None,
            sub: Some(Subscription {
                _quota: quota,
                selector: r.stream_selector,
                live_tail: stream.boundary.clone(),
                stream,
                start: r.start_checkpoint,
                cursor,
                marker: vec![],
                mode: Mode::Undecided,
                complete: false,
                completion: None,
                completion_pending: false,
                replay_reply: None,
                catchup_reply: None,
                snapshot_reply: None,
                snapshot: None,
                data: VecDeque::new(),
                held: VecDeque::new(),
                offered: VecDeque::new(),
                last_confirm: None,
            }),
        });
        Ok(reply)
    }

    fn page(
        &self,
        slot: &Slot,
        max_batches: usize,
        max_bytes: usize,
    ) -> Result<RecoveryReplayPage, ProviderError> {
        let s = slot.sub.as_ref().ok_or(ProviderError::FailedPrecondition)?;
        let page = self.service.source.replay(
            &self.principal,
            &s.stream,
            &s.cursor,
            &s.marker,
            PageBudget {
                max_batches,
                max_entry_total_bytes: max_bytes,
                max_entry_bytes: max_bytes.min(262_144),
            },
        )?;
        if page.batches.len() > max_batches {
            return Err(ProviderError::Internal);
        }
        let mut batches = Vec::with_capacity(page.batches.len());
        let mut bytes = 0;
        let mut cursor = s.cursor.clone();
        for b in page.batches {
            if b.generation != slot.generation || b.predecessor != cursor {
                return Err(ProviderError::Internal);
            }
            self.service
                .source
                .validate_issued(&self.principal, &s.stream, &b.result)?;
            cursor = b.result.clone();
            let b = self.batch(slot, b)?;
            bytes += b.encoded_len();
            if bytes > max_bytes {
                return Err(ProviderError::Internal);
            }
            batches.push(codec::encode(&b)?);
        }
        if cursor != page.result
            || (page.marker.is_empty() != (page.result == slot.boundary))
            || (!page.marker.is_empty() && cursor == s.cursor)
        {
            return Err(ProviderError::Internal);
        }
        Ok(RecoveryReplayPage {
            profile_version: 1,
            subscription_handle: slot.handle.clone(),
            predecessor_checkpoint: s.cursor.clone(),
            result_checkpoint: page.result,
            continuation_marker: page.marker,
            catchup_boundary: slot.boundary.clone(),
            batch_payloads: batches,
        })
    }

    fn replay(
        &self,
        slot: &mut Slot,
        r: RecoveryReplayRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        let key = r.encode_to_vec(); // decoded request equality; unknown fields are ignored
        let s = slot.sub.as_mut().expect("checked");
        if s.mode == Mode::CatchUp || s.mode == Mode::Snapshot || s.start.is_empty() {
            return Err(ProviderError::FailedPrecondition);
        }
        if let Some(reply) = &mut s.replay_reply {
            if reply.request == key {
                let bytes = reply.retry(&key)?;
                if s.complete {
                    s.completion_pending = true;
                }
                return Ok(bytes);
            }
        }
        if s.complete || r.from_checkpoint != s.cursor || r.continuation_marker != s.marker {
            return Err(ProviderError::FailedPrecondition);
        }
        let l = &self.service.limits;
        if r.max_batches as usize > l.replay_batches || r.max_bytes as usize > l.replay_bytes {
            return Err(ProviderError::FailedPrecondition);
        }
        let page = self.page(slot, r.max_batches as usize, r.max_bytes as usize)?;
        let bytes = codec::encode(&page)?;
        self.check(slot, AuthorizationHook::Replay)?;
        self.deadline(deadline)?;
        let s = slot.sub.as_mut().expect("checked");
        for entry in &page.batch_payloads {
            let b: RecoveryBatch = codec::decode(entry)?;
            s.offer(b.result_checkpoint, l)?;
        }
        s.mode = Mode::Replay;
        s.cursor = page.result_checkpoint;
        s.marker = page.continuation_marker;
        s.replay_reply = Some(Reply::new(key, bytes.clone(), l));
        if s.marker.is_empty() {
            slot.finish(false);
        }
        Ok(bytes)
    }

    fn catch_up(
        &self,
        slot: &mut Slot,
        r: RecoveryCatchUpRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        let key = r.encode_to_vec();
        let s = slot.sub.as_mut().expect("checked");
        if s.mode == Mode::Replay || s.mode == Mode::Snapshot {
            return Err(ProviderError::FailedPrecondition);
        }
        if let Some(reply) = &mut s.catchup_reply {
            let bytes = reply.retry(&key)?;
            if s.complete {
                s.completion_pending = true;
            }
            return Ok(bytes);
        }
        if s.mode != Mode::Undecided {
            return Err(ProviderError::FailedPrecondition);
        }
        // One bounded page is prepared before acceptance so retention misses
        // can return the required failed RpcResult, not only a later trailer.
        let page = if s.cursor != slot.boundary {
            Some(self.page(
                slot,
                self.service.limits.replay_batches,
                self.service.limits.replay_bytes,
            )?)
        } else {
            None
        };
        self.check(slot, AuthorizationHook::CatchUp)?;
        self.deadline(deadline)?;
        let bytes = codec::encode(&RecoveryCatchUpAccepted {
            profile_version: 1,
            subscription_handle: slot.handle.clone(),
            generation: slot.generation,
            catchup_boundary: slot.boundary.clone(),
        })?;
        let s = slot.sub.as_mut().expect("checked");
        s.mode = Mode::CatchUp;
        s.catchup_reply = Some(Reply::new(key, bytes.clone(), &self.service.limits));
        if let Some(page) = page {
            self.stage_page(slot, page)?;
        } else {
            slot.finish(true);
        }
        Ok(bytes)
    }

    fn stage_page(&self, slot: &mut Slot, page: RecoveryReplayPage) -> Result<(), ProviderError> {
        let s = slot.sub.as_mut().expect("active");
        for bytes in page.batch_payloads {
            let b: RecoveryBatch = codec::decode(&bytes)?;
            let checkpoint = b.result_checkpoint.clone();
            s.data.push_back(Queued {
                bytes: notification(recovery_notification::Notification::Batch(b)),
                checkpoint,
            });
        }
        s.cursor = page.result_checkpoint;
        s.marker = page.continuation_marker;
        if s.marker.is_empty() {
            slot.finish(true);
        }
        Ok(())
    }

    fn confirm(
        &self,
        slot: &mut Slot,
        r: RecoveryConfirmRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        if r.generation != slot.generation {
            return Err(ProviderError::FailedPrecondition);
        }
        let s = slot.sub.as_mut().expect("checked");
        if s.mode == Mode::Snapshot && !s.snapshot.as_ref().is_some_and(|x| x.installed) {
            return Err(ProviderError::FailedPrecondition);
        }
        if s.last_confirm.as_ref() != Some(&r.checkpoint) {
            if s.offered.front() != Some(&r.checkpoint) {
                return Err(ProviderError::FailedPrecondition);
            }
            self.service
                .source
                .validate_issued(&self.principal, &s.stream, &r.checkpoint)?;
            self.check(slot, AuthorizationHook::Confirm)?;
            self.deadline(deadline)?;
            let s = slot.sub.as_mut().expect("checked");
            s.offered.pop_front();
            s.last_confirm = Some(r.checkpoint.clone());
        }
        codec::encode(&RecoveryConfirmResponse {
            profile_version: 1,
            subscription_handle: slot.handle.clone(),
            confirmed_checkpoint: r.checkpoint,
            generation: slot.generation,
        })
    }

    fn snapshot_offer(
        &self,
        state: &mut State,
        index: usize,
        r: RecoverySnapshotOfferRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        let slot = &mut state.slots[index];
        if r.generation != slot.generation {
            return Err(ProviderError::FailedPrecondition);
        }
        let key = r.encode_to_vec();
        let s = slot.sub.as_mut().expect("checked");
        if let Some(reply) = &mut s.snapshot_reply {
            return reply.retry(&key);
        }
        if s.snapshot.is_some() {
            return Err(ProviderError::FailedPrecondition);
        }
        let snapshot = self.service.source.snapshot(&self.principal, &s.stream)?;
        if snapshot.pages > self.service.limits.snapshot_pages
            || snapshot.page_bytes > self.service.limits.snapshot_page_bytes
        {
            return Err(ProviderError::Internal);
        }
        self.service
            .source
            .validate_issued(&self.principal, &s.stream, &snapshot.boundary)?;
        self.check(slot, AuthorizationHook::SnapshotOffer)?;
        self.deadline(deadline)?;
        let handle = self.handle_bytes(state)?;
        let slot = &mut state.slots[index];
        let bytes = codec::encode(&RecoverySnapshotDescriptor {
            profile_version: 1,
            subscription_handle: slot.handle.clone(),
            snapshot_handle: handle.clone(),
            boundary_checkpoint: snapshot.boundary.clone(),
            total_pages: snapshot.pages,
            page_bytes_max: snapshot.page_bytes as u32,
        })?;
        let s = slot.sub.as_mut().expect("checked");
        s.mode = Mode::Snapshot;
        s.complete = false;
        s.completion = None;
        s.completion_pending = false;
        s.replay_reply = None;
        s.catchup_reply = None;
        s.data.clear();
        s.offered.clear();
        s.last_confirm = None;
        // Preserve the old live chain while transfer is pending. Only the
        // provider-proven S0 at SnapshotConfirm can justify discarding a prefix
        // or resetting an empty queue's tail; changing it here can hide a gap.
        s.snapshot_reply = Some(Reply::new(key, bytes.clone(), &self.service.limits));
        s.snapshot = Some(Snapshot {
            handle,
            source: snapshot,
            fetched: [false; 256],
            installed: false,
            installed_reply: None,
        });
        Ok(bytes)
    }

    fn snapshot_fetch(
        &self,
        slot: &mut Slot,
        r: RecoverySnapshotFetchRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        let s = slot.sub.as_mut().expect("checked");
        let snapshot = s
            .snapshot
            .as_mut()
            .ok_or(ProviderError::FailedPrecondition)?;
        if r.snapshot_handle != snapshot.handle
            || r.page_index >= snapshot.source.pages
            || snapshot.installed
        {
            return Err(ProviderError::FailedPrecondition);
        }
        let page = self.service.source.snapshot_page(
            &self.principal,
            &s.stream,
            &snapshot.source,
            r.page_index,
        )?;
        if page.is_empty() || page.len() > snapshot.source.page_bytes {
            return Err(ProviderError::Internal);
        }
        self.deadline(deadline)?;
        let bytes = codec::encode(&RecoverySnapshotChunk {
            profile_version: 1,
            snapshot_handle: snapshot.handle.clone(),
            page_index: r.page_index,
            page_bytes: page,
            boundary_checkpoint: snapshot.source.boundary.clone(),
        })?;
        snapshot.fetched[r.page_index as usize] = true;
        self.check(slot, AuthorizationHook::SnapshotFetch)?;
        Ok(bytes)
    }

    fn snapshot_confirm(
        &self,
        slot: &mut Slot,
        r: RecoverySnapshotConfirmRequest,
        deadline: Instant,
    ) -> Result<Vec<u8>, ProviderError> {
        if r.generation != slot.generation {
            return Err(ProviderError::FailedPrecondition);
        }
        let key = r.encode_to_vec();
        let s = slot.sub.as_mut().expect("checked");
        let snapshot = s
            .snapshot
            .as_mut()
            .ok_or(ProviderError::FailedPrecondition)?;
        if r.boundary_checkpoint != snapshot.source.boundary {
            return Err(ProviderError::FailedPrecondition);
        }
        if snapshot.installed {
            let bytes = snapshot
                .installed_reply
                .as_mut()
                .ok_or(ProviderError::FailedPrecondition)?
                .retry(&key)?;
            return Ok(bytes);
        }
        if !snapshot.fetched[..snapshot.source.pages as usize]
            .iter()
            .all(|f| *f)
        {
            return Err(ProviderError::FailedPrecondition);
        }
        self.service
            .source
            .validate_issued(&self.principal, &s.stream, &r.boundary_checkpoint)?;
        self.check(slot, AuthorizationHook::SnapshotConfirm)?;
        self.deadline(deadline)?;
        let cut = slot.sub.as_ref().expect("checked").snapshot_live_cut(
            &slot.handle,
            slot.generation,
            &r.boundary_checkpoint,
        );
        let (covered, live_tail) = match cut {
            Ok(cut) => cut,
            Err(_) => {
                slot.end(
                    recovery_batch_trailer::Outcome::Terminated(true),
                    b"snapshot-chain-gap",
                );
                return Err(ProviderError::FailedPrecondition);
            }
        };
        self.deadline(deadline)?;
        let bytes = codec::encode(&RecoverySnapshotInstalled {
            profile_version: 1,
            subscription_handle: slot.handle.clone(),
            boundary_checkpoint: r.boundary_checkpoint.clone(),
            generation: slot.generation,
        })?;
        let s = slot.sub.as_mut().expect("checked");
        let snapshot = s.snapshot.as_mut().expect("offered");
        snapshot.installed = true;
        snapshot.installed_reply = Some(Reply::new(key, bytes.clone(), &self.service.limits));
        s.held.drain(..covered);
        s.live_tail = live_tail;
        s.cursor = r.boundary_checkpoint;
        s.marker.clear();
        s.data.clear();
        s.offered.clear();
        s.last_confirm = None; // S0 was snapshot-confirmed, not offered as a batch.
        s.replay_reply = None;
        s.catchup_reply = None;
        s.completion = None;
        s.completion_pending = false;
        // SnapshotInstalled itself opens the independent S0 gate (§11.5), even
        // when S0 != B. Never fabricate or re-emit a completion at subscribe B.
        // The dispatcher's quota check accounts for the retained suffix/reply.
        s.complete = true;
        Ok(bytes)
    }

    fn batch(&self, slot: &Slot, batch: StoredBatch) -> Result<RecoveryBatch, ProviderError> {
        let b = RecoveryBatch {
            profile_version: 1,
            subscription_handle: slot.handle.clone(),
            generation: batch.generation,
            predecessor_checkpoint: batch.predecessor,
            result_checkpoint: batch.result,
            batch_payload: batch.payload,
        };
        b.validate().map_err(|_| ProviderError::Internal)?;
        Ok(b)
    }

    fn enforce(&self, state: &mut State, affected: usize) -> Result<(), ProviderError> {
        let l = &self.service.limits;
        let counts = counts(state);
        let stream_overflow = state.slots[affected].sub.as_ref().is_some_and(|s| {
            s.queued_bytes() > l.queued_bytes_per_stream
                || s.data.len() + s.held.len() > l.queued_messages_per_stream
        });
        if stream_overflow
            || counts.data_bytes > l.queued_bytes_per_connection
            || counts.retained_replies > l.retained_replies
            || counts.retained_reply_bytes > l.retained_reply_bytes
        {
            state.slots[affected].overflow();
            return Err(ProviderError::ResourceExhausted);
        }
        Ok(())
    }

    fn publish(&self, identity: &[u8], batch: &StoredBatch) -> Result<(), ProviderError> {
        // Application-driven publication has no handle/pop result wrapper.
        // Observe every exit, including a late validate_issued failure after
        // Emit authorization and generation verification already succeeded.
        if self.terminal_error() == Some(ProviderError::Unauthenticated) {
            return Err(ProviderError::Unauthenticated);
        }
        let result = self.observe_source(self.publish_inner(identity, batch));
        if self.terminal_error() == Some(ProviderError::Unauthenticated) {
            Err(ProviderError::Unauthenticated)
        } else {
            result
        }
    }

    fn publish_inner(&self, identity: &[u8], batch: &StoredBatch) -> Result<(), ProviderError> {
        let mut op = self.operation()?;
        let mut error = None;
        for index in 0..op.state.slots.len() {
            let slot = &mut op.state.slots[index];
            if slot
                .sub
                .as_ref()
                .is_none_or(|s| s.stream.identity != identity)
            {
                continue;
            }
            if let Err(e) = self.check(slot, AuthorizationHook::Emit) {
                remember_error(&mut error, e);
                continue;
            }
            let s = slot.sub.as_ref().expect("checked");
            if batch.generation != slot.generation {
                remember_error(&mut error, ProviderError::FailedPrecondition);
                continue;
            }
            if batch.result == s.live_tail {
                continue;
            } // exact-tail retry, scoped and authorized
            if batch.predecessor != s.live_tail {
                slot.end(
                    recovery_batch_trailer::Outcome::Terminated(true),
                    b"provider-chain-gap",
                );
                remember_error(&mut error, ProviderError::FailedPrecondition);
                continue;
            }
            let issued =
                self.service
                    .source
                    .validate_issued(&self.principal, &s.stream, &batch.result);
            if let Err(error) = issued {
                if matches!(
                    error,
                    ProviderError::PermissionDenied | ProviderError::Unauthenticated
                ) {
                    slot.end(
                        recovery_batch_trailer::Outcome::Terminated(true),
                        b"authorization-ended",
                    );
                }
                return Err(error);
            }
            let b = self.batch(slot, batch.clone())?;
            let s = slot.sub.as_mut().expect("checked");
            s.live_tail = batch.result.clone();
            s.held.push_back(Queued {
                bytes: notification(recovery_notification::Notification::Batch(b)),
                checkpoint: batch.result.clone(),
            });
            if let Err(e) = self.enforce(&mut op.state, index) {
                remember_error(&mut error, e);
            }
        }
        error.map_or(Ok(()), Err)
    }

    /// Explicit snapshot supersede/gap fencing: no new X under the same H.
    pub fn retire(&self, handle: &[u8]) -> Result<(), ProviderError> {
        let mut op = self.operation()?;
        let slot = op
            .state
            .slots
            .iter_mut()
            .find(|s| s.handle == handle)
            .ok_or(ProviderError::FailedPrecondition)?;
        if slot.sub.is_none() {
            return Err(ProviderError::FailedPrecondition);
        }
        slot.end(
            recovery_batch_trailer::Outcome::Terminated(true),
            b"superseded",
        );
        Ok(())
    }

    pub fn queue_counts(&self) -> Result<QueueCounts, ProviderError> {
        let op = self.operation()?;
        Ok(counts(&op.state))
    }

    fn egress_open(&self) -> Result<(), ProviderError> {
        if self.terminal_error() == Some(ProviderError::Unauthenticated) {
            Err(ProviderError::Unauthenticated)
        } else if self.is_closed() {
            Err(ProviderError::Unavailable)
        } else {
            Ok(())
        }
    }

    /// Recheck one popped notification AFTER acquiring writer capacity, directly
    /// before the parent's core-state check and synchronous enqueue. Do not await
    /// between success and enqueue; any further wait requires another recheck.
    /// No service/session state mutex is held across source callbacks.
    ///
    /// Protected batches and completion/snapshot-required signals require a live
    /// H/G, its current phase, and fresh Emit authorization/provider generation.
    /// Revocation/loss queues the targeted terminal and rejects the old payload.
    /// Unauthenticated is sticky even if pop converted it to a typed trailer.
    /// ResourceExhausted on contention means retain this ONE unit and retry only
    /// within the parent's existing absolute output deadline, never repop/requeue
    /// it or restart that deadline. Other failures must not emit this payload.
    ///
    /// Terminated/next-generation controls contain no application data and may
    /// already have retired their slot. They require a well-formed typed trailer
    /// in this connection's private issued-handle namespace, not a retained
    /// pending-output registry. Old loss controls remain conservative if G has
    /// since advanced again. This is an egress fence, not a wire authentication API
    /// or a proof of arbitrary caller-supplied payload provenance.
    pub fn revalidate_notification(&self, payload: &[u8]) -> Result<(), ProviderError> {
        self.egress_open()?;
        let event: RecoveryNotification = codec::decode(payload)?;
        let event = event
            .notification
            .ok_or(ProviderError::FailedPrecondition)?;
        let (handle, generation, terminal) = match &event {
            recovery_notification::Notification::Batch(b) => {
                (&b.subscription_handle, b.generation, false)
            }
            recovery_notification::Notification::ReplayComplete(c) => {
                (&c.subscription_handle, c.generation, false)
            }
            recovery_notification::Notification::Trailer(t) => (
                &t.subscription_handle,
                t.generation,
                matches!(
                    t.outcome,
                    Some(
                        recovery_batch_trailer::Outcome::Terminated(true)
                            | recovery_batch_trailer::Outcome::NextGeneration(_)
                    )
                ),
            ),
        };
        let mut op = match self.operation() {
            Ok(op) => op,
            Err(error) => {
                self.egress_open()?;
                return Err(error);
            }
        };
        self.egress_open()?;
        // handle_bytes is prefix[16] || private connection token[8] || checked
        // allocation counter[8]. Snapshot handles share this allocation space;
        // namespace-only acceptance is restricted to unprotected terminal control.
        if handle.len() != 32
            || handle[..16] != self.service.prefix
            || handle[16..24] != self.token.to_be_bytes()
        {
            return Err(ProviderError::FailedPrecondition);
        }
        let counter = u64::from_be_bytes(handle[24..32].try_into().expect("fixed handle width"));
        if counter == 0 || counter > op.state.next_handle {
            return Err(ProviderError::FailedPrecondition);
        }
        if terminal {
            return self.egress_open();
        }
        let slot = op
            .state
            .slots
            .iter_mut()
            .find(|s| s.handle == *handle)
            .ok_or(ProviderError::FailedPrecondition)?;
        self.check(slot, AuthorizationHook::Emit)?;
        if generation != slot.generation {
            return Err(ProviderError::FailedPrecondition);
        }
        let s = slot.sub.as_ref().expect("checked active handle");
        let current_phase = match &event {
            recovery_notification::Notification::Batch(b) => {
                let gate =
                    s.mode != Mode::Snapshot || s.snapshot.as_ref().is_some_and(|x| x.installed);
                gate && (s.offered.iter().any(|c| *c == b.result_checkpoint)
                    || s.last_confirm.as_ref() == Some(&b.result_checkpoint))
            }
            recovery_notification::Notification::ReplayComplete(c) => {
                s.mode == Mode::Replay && s.complete && c.live_boundary_checkpoint == slot.boundary
            }
            recovery_notification::Notification::Trailer(t) => {
                t.boundary_checkpoint == slot.boundary
                    && match t.outcome {
                        Some(recovery_batch_trailer::Outcome::CatchupComplete(true)) => {
                            s.mode == Mode::CatchUp && s.complete
                        }
                        Some(recovery_batch_trailer::Outcome::SnapshotRequired(true)) => {
                            s.mode == Mode::Snapshot && s.snapshot.is_none()
                        }
                        _ => false,
                    }
            }
        };
        if !current_phase {
            return Err(ProviderError::FailedPrecondition);
        }
        self.egress_open()
    }

    /// One bounded production step, never a whole-history burst. Returns None
    /// when idle (not proof of completion); errors remain visible to the parent.
    pub fn pop_notification(&self) -> Result<Option<Vec<u8>>, ProviderError> {
        // Some provider failures (for example from bounded replay production)
        // bypass check's trailer conversion. Observe them before the parent can
        // replace the invocation/output outcome with a deadline or close error.
        let result = (|| {
            let mut op = self.operation()?;
            self.pop_notification_step(&mut op.state)
        })();
        self.observe_source(result)
    }

    fn pop_notification_step(&self, state: &mut State) -> Result<Option<Vec<u8>>, ProviderError> {
        let len = state.slots.len();
        for offset in 0..len {
            let index = (state.round_robin + offset) % len;
            let slot = &mut state.slots[index];
            if let Some(terminal) = slot.terminal.take() {
                if self.is_closed() {
                    return Err(ProviderError::Unavailable);
                }
                state.slots.remove(index);
                return Ok(Some(terminal));
            }
            if let Err(e) = self.check(slot, AuthorizationHook::Emit) {
                if let Some(terminal) = slot.terminal.take() {
                    state.slots.remove(index);
                    return Ok(Some(terminal));
                }
                return Err(e);
            }
            let s = slot.sub.as_ref().expect("checked");
            let produce = s.mode == Mode::CatchUp && !s.complete && s.data.is_empty();
            if produce {
                let deadline = now() + self.service.limits.default_deadline;
                match self.page(
                    slot,
                    self.service.limits.replay_batches,
                    self.service.limits.replay_bytes,
                ) {
                    Ok(page) => {
                        self.check(slot, AuthorizationHook::Emit)?;
                        self.deadline(deadline)?;
                        self.stage_page(slot, page)?;
                    }
                    Err(ProviderError::ProviderRetentionMiss) => slot.snapshot_required(),
                    Err(e) => return Err(e),
                }
                if self.enforce(state, index).is_err() {
                    let terminal = state.slots[index].terminal.take();
                    state.slots.remove(index);
                    return Ok(terminal);
                }
            }
            let slot = &mut state.slots[index];
            // The provider may have revoked authority or changed G while
            // returning a retention miss/page. Recheck after every callback,
            // including the completion/trailer path, not just batch paths.
            if let Err(e) = self.check(slot, AuthorizationHook::Emit) {
                if let Some(terminal) = slot.terminal.take() {
                    state.slots.remove(index);
                    return Ok(Some(terminal));
                }
                return Err(e);
            }
            let s = slot.sub.as_mut().expect("active");
            let queued = if let Some(q) = s.data.pop_front() {
                Some(q)
            } else if s.completion_pending {
                s.completion_pending = false;
                state.round_robin = (index + 1) % len;
                return Ok(s.completion.clone());
            } else if s.complete {
                s.held.pop_front()
            } else {
                None
            };
            if let Some(q) = queued {
                if s.offer(q.checkpoint, &self.service.limits).is_err() {
                    slot.overflow();
                    let terminal = slot.terminal.take();
                    state.slots.remove(index);
                    return Ok(terminal);
                }
                state.round_robin = (index + 1) % len;
                return Ok(Some(q.bytes));
            }
        }
        Ok(None)
    }

    /// Cancellation-safe wait: register before checking the queue, then await
    /// without a provider/state lock. The parent uses one bounded writer worker.
    /// Non-retryable production errors explicitly close the session; synchronous
    /// callers needing typed errors should use pop_notification instead.
    pub async fn next_notification(&self) -> Option<Vec<u8>> {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.terminal_error() == Some(ProviderError::Unauthenticated) {
                // A source callback on an application-driven path can withdraw
                // the principal while this worker has no data queued. Waking
                // only to wait again would leave Core and its RPCs active.
                self.close();
                return None;
            }
            if self.is_closed() {
                return None;
            }
            // Only operation-ownership contention is retryable here. A provider
            // ResourceExhausted/Unavailable is an actual production failure,
            // not a reason to leave Core idle or spin forever on a ready queue.
            let result = match self.operation() {
                Ok(mut op) => self.observe_source(self.pop_notification_step(&mut op.state)),
                Err(ProviderError::ResourceExhausted) => {
                    notified.await;
                    continue;
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(Some(bytes)) => return Some(bytes),
                Ok(None) => {}
                Err(ProviderError::Unavailable) if self.is_closed() => return None,
                Err(error) => {
                    self.record_terminal_error(error);
                    self.close();
                    return None;
                }
            }
            notified.await;
        }
    }
}

impl Drop for RecoveryHostSession {
    fn drop(&mut self) {
        self.close();
    }
}

fn counts(state: &State) -> QueueCounts {
    let mut c = QueueCounts::default();
    for slot in &state.slots {
        if let Some(t) = &slot.terminal {
            c.control_messages += 1;
            c.control_bytes += t.len();
        }
        if let Some(s) = &slot.sub {
            c.subscriptions += 1;
            c.data_messages += s.data.len() + s.held.len();
            c.data_bytes += s.queued_bytes();
            if s.completion_pending {
                c.control_messages += 1;
                c.control_bytes += s.completion.as_ref().map_or(0, Vec::len);
            }
            for r in s.replies() {
                c.retained_replies += 1;
                c.retained_reply_bytes += r.size();
            }
            c.offered_checkpoints += s.offered.len();
        }
    }
    c
}

fn expire_replies(state: &mut State) {
    let now = now();
    for slot in &mut state.slots {
        if let Some(s) = &mut slot.sub {
            for reply in [
                &mut s.replay_reply,
                &mut s.catchup_reply,
                &mut s.snapshot_reply,
            ] {
                if reply.as_ref().is_some_and(|r| now >= r.expires) {
                    *reply = None;
                }
            }
            if let Some(x) = &mut s.snapshot {
                if x.installed_reply.as_ref().is_some_and(|r| now >= r.expires) {
                    x.installed_reply = None;
                }
            }
            if !s.completion_pending
                && s.replay_reply.is_none()
                && s.catchup_reply.is_none()
                && s.snapshot
                    .as_ref()
                    .is_none_or(|x| x.installed_reply.is_none())
            {
                s.completion = None;
            }
        }
    }
}

fn canonical(method: &str) -> bool {
    let mut parts = method.split('/');
    parts.next() == Some("")
        && parts.next().is_some_and(|p| !p.is_empty())
        && parts.next().is_some_and(|p| !p.is_empty())
        && parts.next().is_none()
        && method.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn remember_error(current: &mut Option<ProviderError>, error: ProviderError) {
    if *current != Some(ProviderError::Unauthenticated) {
        *current = Some(error);
    }
}
