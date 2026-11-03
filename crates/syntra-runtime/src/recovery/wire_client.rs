//! RFC 0006 §11 initiator adapter. No reconnect state is carried by this object.
//!
//! Construction attaches an immutable inbox to the supplied Initiator; a second
//! attachment on that connection is rejected. Validated negotiation enables
//! ingress before `notif_tx.try_send`, and teardown closes the inbox. An enabled inbox
//! owns the notification stream: do not sniff failed decodes as other protocols.
//! Explicit application demultiplexing is required for mixed notification use.
//!
//! Authentication is the core connection's responsibility. `principal_scope`
//! and stable S are application binding labels, never credentials or authority.
//! Close the connection on authorization-context replacement; never attach an
//! inbox to another connection. The provider validates authority at every hook.
//!
//! Offers do NOT persist or confirm. Pass the FULL application state produced
//! by applying an offer to the atomic persistence contract, not a digest. On
//! wasm that synchronous contract must be nonblocking (e.g. an already durable
//! application adapter); synchronous filesystem/database I/O is not supported.
//!
//! Retry policy: `reply_retries` is the maximum total submissions INCLUDING the
//! first call; `reply_ttl` is an absolute elapsed budget starting at that first
//! request, not a retention guarantee. Exact retries keep their original budget
//! and payload, with bounded backoff/skew and fresh core RPC IDs. Subscription
//! allocation and application-state writes are never automatically retried.

#[path = "wire_inbox.rs"]
pub mod inbox;
pub use inbox::{InboxCounts, RecoveryInbox};

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use syntra_core::proto::*;
use syntra_core::proto::{recovery_batch_trailer::Outcome, recovery_notification::Notification};
use syntra_core::{ConnectionState, ErrorCode};
use web_time::Instant;

use super::persistence::{
    DurableRecord, ExpectedPosition, PersistenceError, PersistenceScope, RecoveryPersistence,
};
use super::wire::{self, codec, codec::ProfileMessage, ProviderError, RecoveryLimits};
use super::{
    DuplicateCache, ProfileAction, ProfileCheckpoint, ProfileInput, ProfileRecovery, StagedSnapshot,
};
use crate::emission::{now, sleep_until};
use crate::Initiator;

/// Sanitized failures: never retain peer diagnostic text, payloads, or store
/// diagnostics in an error. Durable data is never rolled back after RPC failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryClientError {
    #[error("recovery is unavailable; mandatory-only service has no recovery guarantee")]
    RecoveryUnavailable,
    #[error("recovery has not been negotiated")]
    Unconfirmed,
    #[error("invalid recovery state or response")]
    InvalidState,
    #[error("recovery resource bound reached")]
    ResourceExhausted,
    #[error("recovery round must be re-established")]
    RecoveryNeeded,
    #[error("a new authenticated connection and negotiation are required")]
    ReconnectRequired,
    #[error("durable generation does not match the subscribed generation")]
    StaleGeneration,
    #[error("recovery persistence failed")]
    Persistence(PersistenceError),
    #[error("persistence outcome unknown; reload durable evidence on a new connection")]
    CommitUnknown,
    #[error("persistence worker stopped during runtime shutdown")]
    WorkerStopped,
    #[error("recovery RPC failed [{0:?}]")]
    Rpc(ErrorCode),
}

impl RecoveryClientError {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::RecoveryUnavailable => ErrorCode::Unimplemented,
            Self::ResourceExhausted => ErrorCode::ResourceExhausted,
            Self::Persistence(error) => error.code(),
            Self::WorkerStopped => ErrorCode::Internal,
            Self::CommitUnknown => ErrorCode::Unknown,
            Self::ReconnectRequired => ErrorCode::Unavailable,
            Self::Rpc(code) => code,
            _ => ErrorCode::FailedPrecondition,
        }
    }
}

impl From<ProviderError> for RecoveryClientError {
    fn from(value: ProviderError) -> Self {
        match value {
            ProviderError::ResourceExhausted => Self::ResourceExhausted,
            ProviderError::Unavailable => Self::ReconnectRequired,
            _ => Self::InvalidState,
        }
    }
}

type ClientResult<T> = Result<T, RecoveryClientError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeIntent {
    /// Explicit live-only baseline; never claims restored historical state.
    InitialLiveOnly,
    /// Requires a durable record in exactly this P/S scope, acknowledged or not.
    ResumeDurable,
    /// Explicit replacement by a provider snapshot in the current G. Does not
    /// reinterpret an old durable C, nor claim an initial live-only baseline.
    SnapshotCurrentGeneration,
}

pub enum Negotiation {
    Confirmed(RecoveryNegotiateResponse),
    RecoveryUnavailable,
}

pub struct Subscription {
    pub response: RecoverySubscribeResponse,
    /// Full loaded application state, if resuming. The caller restores it before
    /// applying offers. No copy of application state is retained by the client.
    pub restored: Option<DurableRecord>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct RecoveryProgress {
    pub locally_durable: Option<ExpectedPosition>,
    /// Submission to Initiator::call, NOT proof of carrier handoff or receipt.
    pub confirm_sent: Option<ExpectedPosition>,
    pub peer_acknowledged: Option<ExpectedPosition>,
}

/// Application-facing offer/event; there is only one unpersisted offer per H.
/// Keeping an event does not keep its round alive after a terminal control.
pub enum RecoveryEvent {
    Batch {
        batch: RecoveryBatch,
    },
    CaughtUp {
        handle: Vec<u8>,
    },
    InitialLiveBaseline {
        handle: Vec<u8>,
        boundary: Vec<u8>,
    },
    SnapshotRequired {
        handle: Vec<u8>,
    },
    /// old G and optional provider-declared next G, never a locally minted G.
    RecoveryNeeded {
        handle: Vec<u8>,
        generation: u64,
        next_generation: Option<u64>,
        /// Validated terminal control, including an initiator-local queue
        /// exhaustion trailer. Local controls have no wire transmission.
        termination: Option<RecoveryBatchTrailer>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Undecided,
    Replay,
    CatchUp,
    Snapshot,
    Live,
    Retired,
}

struct RetainedCall {
    method: &'static str,
    bytes: Vec<u8>,
    started: Instant,
    attempts: u32,
    response: Option<Vec<u8>>,
}

impl RetainedCall {
    fn new<M: ProfileMessage>(method: &'static str, message: &M) -> ClientResult<Self> {
        Ok(Self {
            method,
            bytes: codec::encode(message)?,
            started: now(),
            attempts: 0,
            response: None,
        })
    }
}

struct Offer {
    checkpoint: ProfileCheckpoint,
    snapshot: bool,
    durable: bool,
    confirm: RetainedCall,
}

struct Round {
    scope: PersistenceScope,
    stable_stream: Vec<u8>,
    generation: u64,
    boundary: Vec<u8>,
    initial: bool,
    mode: Mode,
    profile: ProfileRecovery,
    progress: RecoveryProgress,
    expected: Option<ExpectedPosition>,
    pending: Option<Offer>,
    duplicates: DuplicateCache,
    replay: Option<RetainedCall>,
    replay_cursor: Vec<u8>,
    marker: Vec<u8>,
    replay_final: bool,
    catchup: Option<RetainedCall>,
    completion: bool,
    through_boundary: bool,
    stage: Option<StagedSnapshot>,
    fetched: [bool; 256],
    snapshot_installed: bool,
    retention_miss: bool,
    teardown_pending: bool,
    event: Option<RecoveryEvent>,
}

/// Not Clone. `&mut self` operations deliberately serialize stop-and-wait work.
/// S is visibly Send + Sync; native I/O is offloaded, never done under ingress.
pub struct RecoveryClient<S: RecoveryPersistence + Send + Sync + 'static> {
    initiator: Initiator,
    principal_scope: Vec<u8>,
    store: Arc<Mutex<S>>,
    limits: RecoveryLimits,
    inbox: Arc<RecoveryInbox>,
    interrupted: Arc<AtomicBool>,
    negotiated: Option<RecoveryNegotiateResponse>,
    negotiation_attempted: bool,
    unavailable: bool,
    rounds: BTreeMap<Vec<u8>, Round>,
}

/// Dropping an in-flight stateful operation fences the entire connection-local
/// wrapper. A blocking commit may still finish: only a fresh load can reconcile
/// it. No detached worker can silently publish a Confirm after cancellation.
struct OperationGuard {
    inbox: Arc<RecoveryInbox>,
    interrupted: Arc<AtomicBool>,
    armed: bool,
}

impl OperationGuard {
    fn finish(&mut self) {
        self.armed = false;
    }
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.interrupted.store(true, Ordering::Release);
            self.inbox.close();
        }
    }
}

impl<S: RecoveryPersistence + Send + Sync + 'static> RecoveryClient<S> {
    /// Fallible local construction. Parent attaches `inbox()` before negotiate;
    /// construction neither enables traffic nor inherits negotiation from core.
    pub fn new(
        initiator: Initiator,
        principal_scope: Vec<u8>,
        store: S,
        limits: RecoveryLimits,
    ) -> ClientResult<Self> {
        limits.validate()?;
        // Core RPC deadlines have millisecond granularity. Never round a
        // sub-millisecond configured deadline up into a longer wire budget.
        if limits.default_deadline.as_millis() == 0 {
            return Err(RecoveryClientError::InvalidState);
        }
        // Use the persistence constructor as the single scope-validation policy.
        PersistenceScope::new(principal_scope.clone(), b"scope-validation".to_vec())
            .map_err(|_| RecoveryClientError::InvalidState)?;
        if initiator.is_closed() {
            return Err(RecoveryClientError::ReconnectRequired);
        }
        let inbox = Arc::new(RecoveryInbox::new(limits.clone()));
        initiator
            .attach_recovery_inbox(inbox.clone())
            .map_err(|_| RecoveryClientError::InvalidState)?;
        Ok(Self {
            initiator,
            principal_scope,
            store: Arc::new(Mutex::new(store)),
            inbox,
            limits,
            interrupted: Arc::new(AtomicBool::new(false)),
            negotiated: None,
            negotiation_attempted: false,
            unavailable: false,
            rounds: BTreeMap::new(),
        })
    }

    pub fn inbox(&self) -> Arc<RecoveryInbox> {
        self.inbox.clone()
    }

    fn guard(&self) -> OperationGuard {
        OperationGuard {
            inbox: self.inbox.clone(),
            interrupted: self.interrupted.clone(),
            armed: true,
        }
    }

    fn ready(&self) -> ClientResult<()> {
        if self.interrupted.load(Ordering::Acquire)
            || self.initiator.is_closed()
            || self.inbox.is_closed()
        {
            return Err(RecoveryClientError::ReconnectRequired);
        }
        if self.negotiated.is_none() {
            return Err(if self.unavailable {
                RecoveryClientError::RecoveryUnavailable
            } else {
                RecoveryClientError::Unconfirmed
            });
        }
        Ok(())
    }

    /// Only ACTIVE, exact capability, version offer 1..1. An unknown host is an
    /// explicit mandatory-only outcome, not an implicit full-service fallback.
    pub async fn negotiate(&mut self) -> ClientResult<Negotiation> {
        if self.negotiation_attempted || self.initiator.state().await != ConnectionState::Active {
            return Err(RecoveryClientError::InvalidState);
        }
        self.negotiation_attempted = true;
        let mut guard = self.guard();
        let request = RecoveryNegotiateRequest {
            profile_version: 1,
            min_version: 1,
            max_version: 1,
            capability: wire::CAPABILITY.into(),
        };
        let result = self
            .once::<_, RecoveryNegotiateResponse>(wire::NEGOTIATE, &request)
            .await;
        guard.finish();
        match result {
            Err(RecoveryClientError::Rpc(ErrorCode::Unimplemented)) => {
                self.unavailable = true;
                Ok(Negotiation::RecoveryUnavailable)
            }
            Ok(response) => {
                // Profile quota is independent of the core admission floor.
                // &mut self emits at most one profile RPC, even at quota 1.
                if !(1..=16).contains(&response.max_pending_rpcs_per_connection) {
                    return Err(RecoveryClientError::InvalidState);
                }
                self.inbox.enable()?;
                self.negotiated = Some(response);
                Ok(Negotiation::Confirmed(response))
            }
            Err(e) => Err(e),
        }
    }

    pub async fn subscribe(
        &mut self,
        selector: Vec<u8>,
        stable_stream: Vec<u8>,
        intent: SubscribeIntent,
    ) -> ClientResult<Subscription> {
        self.ready()?;
        self.controls();
        // Retire locally first. Teardown is one bounded, best-effort request,
        // never a prerequisite for using durable C with a fresh H/B. Failed
        // remote teardown may exhaust host quota and require a new connection.
        self.teardown_one().await;
        self.ready()?;
        let bound = self
            .negotiated
            .as_ref()
            .expect("ready")
            .max_subscriptions_per_connection as usize;
        if self
            .rounds
            .values()
            .filter(|r| r.mode != Mode::Retired)
            .count()
            >= bound.min(self.limits.subscriptions_per_connection)
            || self.rounds.len() >= self.limits.handles_per_connection
        {
            return Err(RecoveryClientError::ResourceExhausted);
        }
        let scope = PersistenceScope::new(self.principal_scope.clone(), stable_stream.clone())
            .map_err(|_| RecoveryClientError::InvalidState)?;
        let mut guard = self.guard();
        let load_scope = scope.clone();
        let loaded = self.storage(move |store| store.load(&load_scope)).await;
        guard.finish();
        let restored = match loaded {
            Ok(v) => v,
            Err(e) => {
                guard.finish();
                return Err(e);
            }
        };
        // Never silently overwrite prior durable history with an empty start.
        if intent == SubscribeIntent::ResumeDurable && restored.is_none()
            || intent == SubscribeIntent::InitialLiveOnly && restored.is_some()
            || restored.as_ref().is_some_and(|r| {
                r.generation == 0 || r.checkpoint.is_empty() || r.checkpoint.len() > 4096
            })
        {
            return Err(RecoveryClientError::InvalidState);
        }
        let start = if intent == SubscribeIntent::ResumeDurable {
            restored.as_ref().expect("required").checkpoint.clone()
        } else {
            Vec::new()
        };
        let request = RecoverySubscribeRequest {
            profile_version: 1,
            stream_selector: selector,
            start_checkpoint: start.clone(),
        };
        // Validate before opening the speculative H window or submitting RPC.
        codec::encode(&request)?;
        let token = self.inbox.begin_subscribe()?;
        let mut guard = self.guard();
        let response = self
            .once::<_, RecoverySubscribeResponse>(wire::SUBSCRIBE, &request)
            .await;
        let response = match response {
            Ok(r) => r,
            Err(e) => {
                drop(token);
                // Subscribe is never automatically replayed. An ambiguous
                // allocation needs reconnect; even a bounded retry can leak H.
                let unknown = !matches!(e, RecoveryClientError::Rpc(code) if !matches!(code, ErrorCode::DeadlineExceeded | ErrorCode::Unavailable | ErrorCode::Unknown | ErrorCode::Internal));
                if unknown {
                    self.interrupted.store(true, Ordering::Release);
                    self.inbox.close();
                }
                guard.finish();
                return Err(if unknown {
                    RecoveryClientError::ReconnectRequired
                } else {
                    e
                });
            }
        };
        if intent == SubscribeIntent::ResumeDurable
            && restored
                .as_ref()
                .is_some_and(|r| r.generation != response.generation)
        {
            self.inbox.close();
            self.interrupted.store(true, Ordering::Release);
            guard.finish();
            return Err(RecoveryClientError::StaleGeneration);
        }
        token.register(
            &response.subscription_handle,
            response.generation,
            &stable_stream,
        )?;
        let expected = restored.as_ref().map(|r| ExpectedPosition {
            generation: r.generation,
            checkpoint: r.checkpoint.clone(),
        });
        let cursor = if intent == SubscribeIntent::InitialLiveOnly {
            response.catchup_boundary.clone()
        } else {
            start
        };
        let cache_capacity =
            (self.limits.retained_replies / self.limits.subscriptions_per_connection).min(
                self.limits.retained_reply_bytes / 4096 / self.limits.subscriptions_per_connection,
            );
        self.rounds.insert(
            response.subscription_handle.clone(),
            Round {
                scope,
                stable_stream: stable_stream.clone(),
                generation: response.generation,
                boundary: response.catchup_boundary.clone(),
                initial: intent == SubscribeIntent::InitialLiveOnly,
                mode: if intent == SubscribeIntent::SnapshotCurrentGeneration {
                    Mode::Snapshot
                } else {
                    Mode::Undecided
                },
                profile: ProfileRecovery::new(stable_stream, response.generation, cursor.clone()),
                progress: RecoveryProgress {
                    locally_durable: expected.clone(),
                    ..RecoveryProgress::default()
                },
                expected,
                pending: None,
                duplicates: DuplicateCache::new(cache_capacity),
                replay: None,
                replay_cursor: cursor.clone(),
                marker: Vec::new(),
                replay_final: false,
                catchup: None,
                completion: false,
                through_boundary: cursor == response.catchup_boundary,
                stage: None,
                fetched: [false; 256],
                snapshot_installed: false,
                retention_miss: false,
                teardown_pending: false,
                event: None,
            },
        );
        guard.finish();
        self.controls();
        Ok(Subscription { response, restored })
    }

    fn round(&mut self, handle: &[u8]) -> ClientResult<&mut Round> {
        self.ready()?;
        self.controls();
        let r = self
            .rounds
            .get_mut(handle)
            .ok_or(RecoveryClientError::InvalidState)?;
        if r.mode == Mode::Retired || !self.inbox.active(handle, r.generation) {
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        Ok(r)
    }

    pub fn progress(&self, handle: &[u8]) -> Option<&RecoveryProgress> {
        self.rounds.get(handle).map(|r| &r.progress)
    }

    /// Returns the correlated page as metadata/data for inspection. Entries are
    /// queued, NOT offered or committed here; consume them via next_event().
    pub async fn replay_page(&mut self, handle: &[u8]) -> ClientResult<RecoveryReplayPage> {
        let max_bytes = self.limits.replay_bytes.min(
            self.negotiated
                .as_ref()
                .map_or(0, |n| n.max_page_bytes as usize),
        );
        let max_batches = self.limits.replay_batches as u32;
        let inbox = self.inbox.clone();
        let r = self.round(handle)?;
        if r.initial
            || !matches!(r.mode, Mode::Undecided | Mode::Replay)
            || r.replay_final
            || r.pending.is_some()
            || !inbox.replay_empty(handle)
            || r.profile.committed() != r.replay_cursor
        {
            return Err(RecoveryClientError::InvalidState);
        }
        r.mode = Mode::Replay;
        let request = RecoveryReplayRequest {
            profile_version: 1,
            subscription_handle: handle.to_vec(),
            from_checkpoint: r.replay_cursor.clone(),
            max_batches,
            max_bytes: max_bytes as u32,
            continuation_marker: r.marker.clone(),
        };
        let mut call = RetainedCall::new(wire::REPLAY, &request)?;
        let mut guard = self.guard();
        let result = self.retained::<RecoveryReplayPage>(handle, &mut call).await;
        guard.finish();
        self.controls();
        let page = match result {
            Ok(page) => page,
            Err(e) => return Err(self.operation_error(handle, e).await),
        };
        self.accept_page(handle, &request, &page)?;
        self.cache_call(handle, call, true)?;
        Ok(page)
    }

    fn accept_page(
        &mut self,
        handle: &[u8],
        request: &RecoveryReplayRequest,
        page: &RecoveryReplayPage,
    ) -> ClientResult<()> {
        let r = self.round(handle)?;
        if page.subscription_handle != handle
            || page.catchup_boundary != r.boundary
            || page.predecessor_checkpoint != request.from_checkpoint
            || page.batch_payloads.len() > request.max_batches as usize
            || page.batch_payloads.iter().map(Vec::len).sum::<usize>() > request.max_bytes as usize
            || (!page.continuation_marker.is_empty()
                && page.result_checkpoint == page.predecessor_checkpoint)
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        let batches = page
            .batch_payloads
            .iter()
            .map(|b| codec::decode::<RecoveryBatch>(b))
            .collect::<Result<Vec<_>, _>>()?;
        if batches.iter().any(|b| b.generation != r.generation) {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        // Empty final page when from == B is valid and needs no synthetic batch.
        r.replay_cursor = page.result_checkpoint.clone();
        r.marker = page.continuation_marker.clone();
        r.replay_final = r.marker.is_empty();
        if let Err(e) = self.inbox.replay_page(handle, batches) {
            self.controls();
            return Err(e.into());
        }
        Ok(())
    }

    /// CatchUpAccepted only accepts the trigger. It is NEVER completion.
    /// Repeating this method retries the exact request under its original budget.
    pub async fn catch_up(&mut self, handle: &[u8]) -> ClientResult<RecoveryCatchUpAccepted> {
        let r = self.round(handle)?;
        if !matches!(r.mode, Mode::Undecided | Mode::CatchUp) {
            return Err(RecoveryClientError::InvalidState);
        }
        r.mode = Mode::CatchUp;
        let mut call = r.catchup.take().unwrap_or(RetainedCall::new(
            wire::CATCH_UP,
            &RecoveryCatchUpRequest {
                profile_version: 1,
                subscription_handle: handle.to_vec(),
            },
        )?);
        let mut guard = self.guard();
        let result = self
            .retained::<RecoveryCatchUpAccepted>(handle, &mut call)
            .await;
        guard.finish();
        self.controls();
        let accepted = match result {
            Ok(a) => a,
            Err(e) => return Err(self.operation_error(handle, e).await),
        };
        let r = self.round(handle)?;
        if accepted.subscription_handle != handle
            || accepted.generation != r.generation
            || accepted.catchup_boundary != r.boundary
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        self.cache_call(handle, call, false)?;
        self.open_live(handle);
        Ok(accepted)
    }

    /// Recover a lost terminal Replay completion without resetting pagination or
    /// re-offering page effects. Only the exact immediately preceding page RPC.
    pub async fn retry_completion(&mut self, handle: &[u8]) -> ClientResult<()> {
        let r = self.round(handle)?;
        if r.mode == Mode::CatchUp {
            return self.catch_up(handle).await.map(|_| ());
        }
        if r.mode != Mode::Replay || !r.replay_final {
            return Err(RecoveryClientError::InvalidState);
        }
        let mut call = r.replay.take().ok_or(RecoveryClientError::InvalidState)?;
        let mut guard = self.guard();
        let result = self.retained::<RecoveryReplayPage>(handle, &mut call).await;
        guard.finish();
        self.controls();
        let page = match result {
            Ok(p) => p,
            Err(e) => return Err(self.operation_error(handle, e).await),
        };
        let r = self.round(handle)?;
        // The codec validates the chain. Compare the complete canonical response
        // to the original, not only its B, before treating this as an exact retry.
        if page.subscription_handle != handle
            || page.catchup_boundary != r.boundary
            || page.result_checkpoint != r.replay_cursor
            || page.continuation_marker != r.marker
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        self.cache_call(handle, call, true)?;
        self.open_live(handle);
        Ok(())
    }

    /// Cancellation-safe waiter. No background task consumes or applies offers.
    /// Controls are drained before data, including while an offer awaits app I/O.
    pub async fn next_event(&mut self) -> ClientResult<RecoveryEvent> {
        loop {
            let inbox = self.inbox.clone();
            let changed = inbox.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.ready()?;
            self.controls();
            if let Some(event) = self.poll_event()? {
                return Ok(event);
            }
            let mut close = self.initiator.subscribe_close();
            if *close.borrow() {
                return Err(RecoveryClientError::ReconnectRequired);
            }
            tokio::select! {
                biased;
                _ = close.changed() => return Err(RecoveryClientError::ReconnectRequired),
                _ = changed => {},
            }
        }
    }

    fn poll_event(&mut self) -> ClientResult<Option<RecoveryEvent>> {
        let handles = self.rounds.keys().cloned().collect::<Vec<_>>();
        for handle in handles {
            self.open_live(&handle);
            let r = self.rounds.get_mut(&handle).expect("known");
            if let Some(event) = r.event.take() {
                return Ok(Some(event));
            }
            if r.pending.is_some()
                || matches!(r.mode, Mode::Retired | Mode::Undecided | Mode::Snapshot)
            {
                continue;
            }
            let replay = r.mode == Mode::Replay;
            let batch = self.inbox.take_batch(&handle, replay, |b| {
                if r.mode == Mode::Live || replay {
                    return true;
                }
                // CatchUp data and early live output share one ingress queue.
                // Live starts at B and remains held until both gates pass.
                !r.through_boundary && b.predecessor_checkpoint != r.boundary
                    || r.duplicates.contains(&b.result_checkpoint)
            });
            let Some(batch) = batch else {
                continue;
            };
            // Route/connection/version/G are checked BEFORE duplicate lookup.
            if batch.subscription_handle != handle
                || batch.generation != r.generation
                || batch.profile_version != 1
                || !self.inbox.active(&handle, r.generation)
            {
                self.retire(&handle, None);
                return Err(RecoveryClientError::RecoveryNeeded);
            }
            if r.duplicates.contains(&batch.result_checkpoint)
                || batch.result_checkpoint == r.profile.committed()
            {
                self.inbox.release_offer(&handle);
                continue;
            }
            let checkpoint = ProfileCheckpoint {
                stream_selector: r.stable_stream.clone(),
                generation: r.generation,
                base_cursor: batch.predecessor_checkpoint.clone(),
                result_cursor: batch.result_checkpoint.clone(),
            };
            if !matches!(
                r.profile
                    .observe(ProfileInput::BatchValidated {
                        checkpoint: checkpoint.clone()
                    })
                    .as_slice(),
                [ProfileAction::CommitCheckpoint { .. }]
            ) {
                self.retire(&handle, None);
                return Err(RecoveryClientError::RecoveryNeeded);
            }
            let confirm = RetainedCall::new(
                wire::CONFIRM,
                &RecoveryConfirmRequest {
                    profile_version: 1,
                    subscription_handle: handle.clone(),
                    generation: r.generation,
                    checkpoint: checkpoint.result_cursor.clone(),
                },
            )?;
            r.pending = Some(Offer {
                checkpoint,
                snapshot: false,
                durable: false,
                confirm,
            });
            return Ok(Some(RecoveryEvent::Batch { batch }));
        }
        Ok(None)
    }

    /// Atomic full-state write, THEN batch Confirm. A successful local write
    /// remains resume evidence even if sending/receiving confirmation fails.
    pub async fn persist_and_confirm(
        &mut self,
        handle: &[u8],
        application_state: Vec<u8>,
    ) -> ClientResult<RecoveryConfirmResponse> {
        if self
            .round(handle)?
            .pending
            .as_ref()
            .is_none_or(|p| p.snapshot)
        {
            return Err(RecoveryClientError::InvalidState);
        }
        self.persist_offer(handle, application_state).await?;
        let response: RecoveryConfirmResponse = self.confirm_offer(handle).await?;
        let r = self.round(handle)?;
        let cp = &r
            .pending
            .as_ref()
            .expect("offered")
            .checkpoint
            .result_cursor;
        if response.subscription_handle != handle
            || response.generation != r.generation
            || response.confirmed_checkpoint != *cp
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        self.acknowledge(handle, false)?;
        Ok(response)
    }

    pub async fn snapshot_offer(
        &mut self,
        handle: &[u8],
    ) -> ClientResult<RecoverySnapshotDescriptor> {
        let r = self.round(handle)?;
        if r.pending.is_some() || r.stage.is_some() {
            return Err(RecoveryClientError::InvalidState);
        }
        r.mode = Mode::Snapshot;
        r.retention_miss = false;
        r.completion = false;
        r.replay = None;
        r.catchup = None;
        r.duplicates.clear();
        let request = RecoverySnapshotOfferRequest {
            profile_version: 1,
            subscription_handle: handle.to_vec(),
            generation: r.generation,
        };
        self.inbox.clear_data(handle);
        let mut call = RetainedCall::new(wire::SNAPSHOT_OFFER, &request)?;
        let mut guard = self.guard();
        let result = self
            .retained::<RecoverySnapshotDescriptor>(handle, &mut call)
            .await;
        guard.finish();
        self.controls();
        let descriptor = match result {
            Ok(d) => d,
            Err(e) => return Err(self.operation_error(handle, e).await),
        };
        let max_page = self
            .limits
            .snapshot_page_bytes
            .min(self.negotiated.as_ref().expect("ready").max_page_bytes as usize);
        let max_pages = self
            .limits
            .snapshot_pages
            .min(self.negotiated.as_ref().expect("ready").max_snapshot_pages);
        if descriptor.subscription_handle != handle
            || descriptor.total_pages > max_pages
            || descriptor.page_bytes_max as usize > max_page
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        let stage = StagedSnapshot::new(
            descriptor.snapshot_handle.clone(),
            descriptor.boundary_checkpoint.clone(),
            descriptor.total_pages,
            descriptor.page_bytes_max,
        )
        .map_err(|_| RecoveryClientError::InvalidState)?;
        self.round(handle)?.stage = Some(stage);
        self.round(handle)?.fetched = [false; 256];
        Ok(descriptor)
    }

    /// Fetch one immutable page. Exact retries count once logically; no local
    /// SnapshotComplete is ever transmitted as a result or Notification.
    pub async fn snapshot_fetch(
        &mut self,
        handle: &[u8],
        page_index: u32,
    ) -> ClientResult<RecoverySnapshotChunk> {
        let r = self.round(handle)?;
        let stage = r.stage.as_ref().ok_or(RecoveryClientError::InvalidState)?;
        if r.mode != Mode::Snapshot || page_index >= stage.total_pages() || r.pending.is_some() {
            return Err(RecoveryClientError::InvalidState);
        }
        let request = RecoverySnapshotFetchRequest {
            profile_version: 1,
            snapshot_handle: stage.snapshot_handle().to_vec(),
            page_index,
        };
        let mut call = RetainedCall::new(wire::SNAPSHOT_FETCH, &request)?;
        let mut guard = self.guard();
        let result = self
            .retained::<RecoverySnapshotChunk>(handle, &mut call)
            .await;
        guard.finish();
        self.controls();
        let chunk = match result {
            Ok(c) => c,
            Err(e) => return Err(self.operation_error(handle, e).await),
        };
        let total = self
            .rounds
            .values()
            .filter_map(|r| r.stage.as_ref())
            .map(StagedSnapshot::total_bytes)
            .sum::<u64>();
        // Aggregate staging is one maximum negotiated snapshot, not one per H.
        let cap = u64::from(self.limits.snapshot_pages) * self.limits.snapshot_page_bytes as u64;
        let already_fetched = self.round(handle)?.fetched[page_index as usize];
        if total.saturating_add(if already_fetched {
            0
        } else {
            chunk.page_bytes.len() as u64
        }) > cap
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::ResourceExhausted);
        }
        let r = self.round(handle)?;
        let stage = r.stage.as_mut().ok_or(RecoveryClientError::InvalidState)?;
        if chunk.snapshot_handle != request.snapshot_handle
            || chunk.page_index != page_index
            || stage
                .stage_page(
                    &chunk.snapshot_handle,
                    chunk.page_index,
                    chunk.page_bytes.clone(),
                    &chunk.boundary_checkpoint,
                )
                .is_err()
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        r.fetched[page_index as usize] = true;
        Ok(chunk)
    }

    /// Complete immutable bytes for application validation/transformation. This
    /// is not installation and does not advance any checkpoint.
    pub fn snapshot_bytes(&mut self, handle: &[u8]) -> ClientResult<Vec<u8>> {
        self.round(handle)?
            .stage
            .as_ref()
            .ok_or(RecoveryClientError::InvalidState)?
            .install()
            .map_err(|_| RecoveryClientError::InvalidState)
    }

    pub async fn install_and_confirm(
        &mut self,
        handle: &[u8],
        application_state: Vec<u8>,
    ) -> ClientResult<RecoverySnapshotInstalled> {
        let r = self.round(handle)?;
        let stage = r.stage.as_ref().ok_or(RecoveryClientError::InvalidState)?;
        if r.mode != Mode::Snapshot || !stage.is_complete() || r.pending.is_some() {
            return Err(RecoveryClientError::InvalidState);
        }
        let checkpoint = ProfileCheckpoint {
            stream_selector: r.stable_stream.clone(),
            generation: r.generation,
            base_cursor: r.profile.committed().to_vec(),
            result_cursor: stage.boundary_checkpoint().to_vec(),
        };
        if !matches!(
            r.profile
                .observe(ProfileInput::SnapshotInstalled {
                    checkpoint: checkpoint.clone()
                })
                .as_slice(),
            [ProfileAction::CommitCheckpoint { .. }]
        ) {
            return Err(RecoveryClientError::InvalidState);
        }
        let confirm = RetainedCall::new(
            wire::SNAPSHOT_CONFIRM,
            &RecoverySnapshotConfirmRequest {
                profile_version: 1,
                subscription_handle: handle.to_vec(),
                generation: r.generation,
                boundary_checkpoint: checkpoint.result_cursor.clone(),
            },
        )?;
        r.pending = Some(Offer {
            checkpoint,
            snapshot: true,
            durable: false,
            confirm,
        });
        self.persist_offer(handle, application_state).await?;
        let installed: RecoverySnapshotInstalled = self.confirm_offer(handle).await?;
        let r = self.round(handle)?;
        if installed.subscription_handle != handle
            || installed.generation != r.generation
            || installed.boundary_checkpoint
                != r.pending
                    .as_ref()
                    .expect("offered")
                    .checkpoint
                    .result_cursor
        {
            self.retire(handle, None);
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        self.acknowledge(handle, true)?;
        Ok(installed)
    }

    async fn persist_offer(
        &mut self,
        handle: &[u8],
        application_state: Vec<u8>,
    ) -> ClientResult<()> {
        let r = self.round(handle)?;
        let offer = r
            .pending
            .as_ref()
            .ok_or(RecoveryClientError::InvalidState)?;
        if offer.durable {
            return Err(RecoveryClientError::InvalidState);
        }
        let position = ExpectedPosition {
            generation: r.generation,
            checkpoint: offer.checkpoint.result_cursor.clone(),
        };
        let record = DurableRecord {
            generation: position.generation,
            checkpoint: position.checkpoint.clone(),
            application_state,
        };
        let expected = r.expected.clone();
        let scope = r.scope.clone();
        let mut guard = self.guard();
        let result = self
            .storage(move |store| store.commit(&scope, expected.as_ref(), record))
            .await;
        if result.is_err() {
            // Includes CommitUnknown: never resend a mutation/guess rollback.
            self.interrupted.store(true, Ordering::Release);
            self.inbox.close();
            guard.finish();
            return Err(match result {
                Err(RecoveryClientError::WorkerStopped) => RecoveryClientError::WorkerStopped,
                Err(RecoveryClientError::Persistence(PersistenceError::CommitUnknown)) => {
                    RecoveryClientError::CommitUnknown
                }
                Err(error) => error,
                Ok(_) => unreachable!("checked error"),
            });
        }
        // Record the durable observation before processing a concurrently queued
        // invalidation. It remains evidence, but cannot authorize stale Confirm.
        let r = self.rounds.get_mut(handle).expect("known");
        r.expected = Some(position.clone());
        r.progress.locally_durable = Some(position);
        let offer = r.pending.as_mut().expect("offered");
        offer.durable = true;
        if !r.profile.can_confirm(&offer.checkpoint) {
            self.retire(handle, None);
            guard.finish();
            return Err(RecoveryClientError::RecoveryNeeded);
        }
        r.profile.confirm_persisted(&offer.checkpoint);
        if !offer.snapshot && offer.checkpoint.result_cursor == r.boundary {
            r.through_boundary = true;
        }
        guard.finish();
        self.round(handle)?;
        Ok(())
    }

    async fn confirm_offer<M: ProfileMessage>(&mut self, handle: &[u8]) -> ClientResult<M> {
        let r = self.round(handle)?;
        let mut offer = r.pending.take().ok_or(RecoveryClientError::InvalidState)?;
        if !offer.durable {
            return Err(RecoveryClientError::InvalidState);
        }
        r.progress.confirm_sent = r.progress.locally_durable.clone();
        // Retry budget starts at first submission, not while app computes/I/Os.
        offer.confirm.started = now();
        let mut guard = self.guard();
        let result = self.retained::<M>(handle, &mut offer.confirm).await;
        guard.finish();
        self.controls();
        match result {
            Ok(value) => {
                self.round(handle)?.pending = Some(offer);
                Ok(value)
            }
            Err(e) => Err(self.operation_error(handle, e).await),
        }
    }

    fn acknowledge(&mut self, handle: &[u8], snapshot: bool) -> ClientResult<()> {
        let r = self.round(handle)?;
        let offer = r.pending.take().ok_or(RecoveryClientError::InvalidState)?;
        r.progress.peer_acknowledged = r.progress.locally_durable.clone();
        r.duplicates.insert(offer.checkpoint.result_cursor);
        if snapshot {
            // S0 may differ from original B. Installed, not ReplayComplete,
            // opens this gate; another catch-up requires a fresh Subscribe.
            r.mode = Mode::Live;
            r.snapshot_installed = true;
            r.stage = None;
            r.completion = false;
        }
        self.inbox.release_offer(handle);
        self.open_live(handle);
        Ok(())
    }

    /// Local retirement is immediate, remote teardown is a single bounded call.
    /// Unknown Unsubscribe outcome does not resurrect H or roll back storage.
    pub async fn unsubscribe(
        &mut self,
        handle: &[u8],
    ) -> ClientResult<RecoveryUnsubscribeResponse> {
        self.ready()?;
        self.controls();
        let generation = self
            .rounds
            .get(handle)
            .ok_or(RecoveryClientError::InvalidState)?
            .generation;
        self.retire(handle, None);
        self.rounds.get_mut(handle).expect("known").teardown_pending = false;
        let mut guard = self.guard();
        let result = self
            .once::<_, RecoveryUnsubscribeResponse>(
                wire::UNSUBSCRIBE,
                &RecoveryUnsubscribeRequest {
                    profile_version: 1,
                    subscription_handle: handle.to_vec(),
                },
            )
            .await;
        guard.finish();
        let response = result?;
        if response.subscription_handle != handle || response.generation != generation {
            return Err(RecoveryClientError::InvalidState);
        }
        Ok(response)
    }

    async fn operation_error(
        &mut self,
        handle: &[u8],
        error: RecoveryClientError,
    ) -> RecoveryClientError {
        // RpcResult and Notification are distinct frames. A retention trailer
        // can follow the failed result, so allow one finite control-only grace;
        // absence is NOT snapshot authority. Cache expiry has no such trailer.
        if error == RecoveryClientError::Rpc(ErrorCode::FailedPrecondition) {
            let mut guard = self.guard();
            let deadline = now() + self.limits.default_deadline.min(self.limits.reply_ttl);
            loop {
                let inbox = self.inbox.clone();
                let changed = inbox.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                self.controls();
                if self.inbox.is_closed()
                    || self
                        .rounds
                        .get(handle)
                        .is_none_or(|r| r.retention_miss || r.mode == Mode::Retired)
                {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = sleep_until(deadline) => break,
                    _ = changed => {},
                }
            }
            guard.finish();
        }
        // Retention miss has both FailedPrecondition and a snapshot-required
        // control. It is the only precondition failure that keeps H usable.
        if self.rounds.get(handle).is_some_and(|r| r.retention_miss)
            && matches!(
                error,
                RecoveryClientError::Rpc(ErrorCode::FailedPrecondition)
                    | RecoveryClientError::RecoveryNeeded
            )
        {
            return error;
        }
        self.retire(handle, None);
        if matches!(
            error,
            RecoveryClientError::Rpc(ErrorCode::FailedPrecondition)
                | RecoveryClientError::ReconnectRequired
        ) {
            RecoveryClientError::ReconnectRequired
        } else {
            error
        }
    }

    fn retire(&mut self, handle: &[u8], next_generation: Option<u64>) {
        self.inbox.retire(handle);
        if let Some(r) = self.rounds.get_mut(handle) {
            if r.mode == Mode::Retired {
                return;
            }
            r.mode = Mode::Retired;
            r.teardown_pending = true;
            r.pending = None;
            r.stage = None;
            r.replay = None;
            r.catchup = None;
            r.marker.clear();
            r.duplicates.clear();
            r.event = Some(RecoveryEvent::RecoveryNeeded {
                handle: handle.to_vec(),
                generation: r.generation,
                next_generation,
                termination: None,
            });
        }
    }

    async fn teardown_one(&mut self) {
        let handle = self
            .rounds
            .iter()
            .find(|(_, r)| r.teardown_pending)
            .map(|(h, _)| h.clone());
        let Some(handle) = handle else {
            return;
        };
        self.rounds
            .get_mut(&handle)
            .expect("known")
            .teardown_pending = false;
        let mut guard = self.guard();
        // Explicitly best-effort, never retried and never interpreted as proof
        // that the remote allocation was reclaimed. Core closure remains visible
        // in ready(); local deadline failure does not resurrect the retired H.
        let _teardown = self
            .once::<_, RecoveryUnsubscribeResponse>(
                wire::UNSUBSCRIBE,
                &RecoveryUnsubscribeRequest {
                    profile_version: 1,
                    subscription_handle: handle,
                },
            )
            .await;
        guard.finish();
    }

    fn controls(&mut self) {
        let handles = self.rounds.keys().cloned().collect::<Vec<_>>();
        for handle in handles {
            while let Some(control) = self.inbox.take_control(&handle) {
                let Some(r) = self.rounds.get_mut(&handle) else {
                    break;
                };
                if r.mode == Mode::Retired {
                    break;
                }
                match control {
                    Notification::ReplayComplete(c) => {
                        if c.generation != r.generation || c.subscription_handle != handle {
                            self.retire(&handle, None);
                            break;
                        }
                        if r.mode == Mode::Snapshot || r.snapshot_installed {
                            continue;
                        }
                        if c.live_boundary_checkpoint != r.boundary {
                            self.retire(&handle, None);
                            break;
                        }
                        r.completion = true;
                    }
                    Notification::Trailer(t) => {
                        if t.generation != r.generation || t.subscription_handle != handle {
                            self.retire(&handle, None);
                            break;
                        }
                        match t.outcome {
                            Some(Outcome::NextGeneration(next)) => {
                                let stable = r.stable_stream.clone();
                                let affected = self
                                    .rounds
                                    .iter()
                                    .filter(|(_, r)| {
                                        r.stable_stream == stable && r.generation < next
                                    })
                                    .map(|(h, _)| h.clone())
                                    .collect::<Vec<_>>();
                                for h in affected {
                                    self.retire(&h, Some(next));
                                }
                            }
                            Some(Outcome::SnapshotRequired(true)) => {
                                if r.stage.is_some()
                                    || r.pending.as_ref().is_some_and(|offer| offer.snapshot)
                                {
                                    // No wire fence distinguishes a delayed old cause
                                    // from new continuation expiry (SYN-URP-025).
                                    // Conservatively invalidate X and retire H even
                                    // at unchanged G/S0. A concurrent successful
                                    // commit remains durable evidence, but cannot
                                    // authorize stale SnapshotConfirm or a same-H
                                    // re-offer; recovery needs a fresh Subscribe.
                                    self.retire(&handle, None);
                                    break;
                                }
                                r.mode = Mode::Snapshot;
                                r.retention_miss = true;
                                r.pending = None;
                                r.stage = None;
                                r.replay = None;
                                r.catchup = None;
                                r.completion = false;
                                r.duplicates.clear();
                                r.profile.observe(ProfileInput::ContinuationExpired {
                                    stream_selector: r.stable_stream.clone(),
                                    committed: r.profile.committed().to_vec(),
                                });
                                r.event = Some(RecoveryEvent::SnapshotRequired {
                                    handle: handle.clone(),
                                });
                            }
                            Some(Outcome::CatchupComplete(true)) => {
                                if r.mode == Mode::Snapshot || r.snapshot_installed {
                                    continue;
                                }
                                if t.boundary_checkpoint != r.boundary {
                                    self.retire(&handle, None);
                                    break;
                                }
                                r.completion = true;
                            }
                            _ => {
                                self.retire(&handle, None);
                                if let Some(Round {
                                    event: Some(RecoveryEvent::RecoveryNeeded { termination, .. }),
                                    ..
                                }) = self.rounds.get_mut(&handle)
                                {
                                    *termination = Some(t);
                                }
                                break;
                            }
                        }
                    }
                    Notification::Batch(_) => unreachable!("inbox separates data/control"),
                }
            }
        }
    }

    fn open_live(&mut self, handle: &[u8]) {
        let Some(r) = self.rounds.get_mut(handle) else {
            return;
        };
        let accepted = match r.mode {
            Mode::Replay => r.replay_final,
            Mode::CatchUp => r.catchup.is_some(),
            _ => false,
        };
        if accepted
            && r.completion
            && r.through_boundary
            && r.pending.is_none()
            && self.inbox.replay_empty(handle)
        {
            r.mode = Mode::Live;
            r.event = Some(if r.initial {
                RecoveryEvent::InitialLiveBaseline {
                    handle: handle.to_vec(),
                    boundary: r.boundary.clone(),
                }
            } else {
                RecoveryEvent::CaughtUp {
                    handle: handle.to_vec(),
                }
            });
        }
    }

    fn cache_call(&mut self, handle: &[u8], call: RetainedCall, replay: bool) -> ClientResult<()> {
        // Full canonical response equality, bounded across the connection.
        // Duplicate keys have a separate fixed per-H allocation, also bounded.
        let calls = self
            .rounds
            .iter()
            .flat_map(|(h, r)| {
                [&r.replay, &r.catchup]
                    .into_iter()
                    .enumerate()
                    .filter_map(move |(i, c)| {
                        if h.as_slice() == handle && (i == 0) == replay {
                            None
                        } else {
                            c.as_ref()
                        }
                    })
            })
            .collect::<Vec<_>>();
        let bytes = calls
            .iter()
            .map(|c| c.bytes.len() + c.response.as_ref().map_or(0, Vec::len))
            .sum::<usize>()
            + call.bytes.len()
            + call.response.as_ref().map_or(0, Vec::len);
        if calls.len() >= self.limits.retained_replies || bytes > self.limits.retained_reply_bytes {
            self.retire(handle, None);
            return Err(RecoveryClientError::ResourceExhausted);
        }
        let r = self.round(handle)?;
        if replay {
            r.replay = Some(call);
        } else {
            r.catchup = Some(call);
        }
        Ok(())
    }

    async fn once<Q: ProfileMessage, R: ProfileMessage>(
        &self,
        method: &'static str,
        request: &Q,
    ) -> ClientResult<R> {
        let bytes = codec::encode(request)?;
        let timeout = self.limits.default_deadline.as_millis().max(1) as u32;
        let bytes = self
            .initiator
            .call(method, bytes, timeout)
            .await
            .map_err(|e| RecoveryClientError::Rpc(e.code()))?;
        Ok(codec::decode(&bytes)?)
    }

    async fn retained<R: ProfileMessage>(
        &self,
        handle: &[u8],
        call: &mut RetainedCall,
    ) -> ClientResult<R> {
        let deadline = call.started + self.limits.reply_ttl;
        let generation = self
            .rounds
            .get(handle)
            .ok_or(RecoveryClientError::InvalidState)?
            .generation;
        let revision = self.inbox.revision(handle);
        loop {
            if now() >= deadline
                || call.attempts >= self.limits.reply_retries
                || self.initiator.is_closed()
            {
                return Err(RecoveryClientError::ReconnectRequired);
            }
            if call.attempts > 0 {
                let shift = call.attempts.min(5);
                // Bounded deterministic per-request skew dampens aligned peers;
                // no random/crypto dependency or wire field is introduced.
                let skew = call
                    .bytes
                    .iter()
                    .fold(0u64, |a, b| a.wrapping_add(u64::from(*b)))
                    % 17;
                let until = now() + Duration::from_millis((10u64 << shift) + skew);
                if until >= deadline {
                    return Err(RecoveryClientError::ReconnectRequired);
                }
                tokio::select! {
                    biased;
                    _ = sleep_until(deadline) => return Err(RecoveryClientError::ReconnectRequired),
                    _ = self.invalidated(handle, generation, revision) => return Err(RecoveryClientError::RecoveryNeeded),
                    _ = sleep_until(until) => {},
                }
            }
            call.attempts += 1;
            if !self.inbox.active(handle, generation) || self.inbox.revision(handle) != revision {
                return Err(RecoveryClientError::RecoveryNeeded);
            }
            let left = deadline
                .saturating_duration_since(now())
                .min(self.limits.default_deadline);
            if left.as_millis() == 0 {
                return Err(RecoveryClientError::ReconnectRequired);
            }
            let result = tokio::select! {
                biased;
                _ = sleep_until(deadline) => return Err(RecoveryClientError::ReconnectRequired),
                _ = self.invalidated(handle, generation, revision) => return Err(RecoveryClientError::RecoveryNeeded),
                r = self.initiator.call(call.method, call.bytes.clone(), left.as_millis() as u32) => r,
            };
            match result {
                Ok(bytes) => {
                    let value: R = codec::decode(&bytes)?;
                    let canonical = codec::encode(&value)?;
                    if call.response.as_ref().is_some_and(|old| *old != canonical) {
                        return Err(RecoveryClientError::InvalidState);
                    }
                    call.response = Some(canonical);
                    return Ok(value);
                }
                Err(e)
                    if matches!(
                        e.code(),
                        ErrorCode::DeadlineExceeded
                            | ErrorCode::Unavailable
                            | ErrorCode::ResourceExhausted
                    ) =>
                {
                    continue
                }
                Err(e) => return Err(RecoveryClientError::Rpc(e.code())),
            }
        }
    }

    async fn invalidated(&self, handle: &[u8], generation: u64, revision: Option<u64>) {
        loop {
            let changed = self.inbox.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self.inbox.active(handle, generation) || self.inbox.revision(handle) != revision {
                return;
            }
            changed.await;
        }
    }

    async fn storage<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut S) -> Result<T, PersistenceError> + Send + 'static,
    ) -> ClientResult<T> {
        let store = self.store.clone();
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Blocking work may finish after caller cancellation. OperationGuard
            // then fences this client; fresh load/CAS reconciles the full record.
            let result = tokio::task::spawn_blocking(move || {
                let mut store = store
                    .lock()
                    .map_err(|_| RecoveryClientError::Persistence(PersistenceError::Unavailable))?;
                f(&mut store).map_err(RecoveryClientError::Persistence)
            })
            .await;
            match result {
                Ok(value) => value,
                Err(error) => match error.try_into_panic() {
                    Ok(panic) => std::panic::resume_unwind(panic),
                    Err(_) => Err(RecoveryClientError::WorkerStopped),
                },
            }
        }
        #[cfg(target_arch = "wasm32")]
        {
            // Contract requires a nonblocking store on wasm. Never hide a
            // synchronous disk operation behind an async-looking interface.
            let mut store = store
                .try_lock()
                .map_err(|_| RecoveryClientError::Persistence(PersistenceError::Unavailable))?;
            f(&mut store).map_err(RecoveryClientError::Persistence)
        }
    }
}

impl<S: RecoveryPersistence + Send + Sync + 'static> Drop for RecoveryClient<S> {
    fn drop(&mut self) {
        self.inbox.close();
    }
}

#[cfg(test)]
#[path = "wire_client_tests.rs"]
mod tests;
