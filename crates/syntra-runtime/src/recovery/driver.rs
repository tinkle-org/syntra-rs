//! Non-wire recovery helpers around [`ProfileEngine`].
//!
//! The coordinator is transport-agnostic and never performs calls, never
//! persists, and never delivers. Drivers close that gap without widening
//! it: they carry the connection/principal context, check configured
//! [`RecoveryAuthorizer`] hooks for
//! initiator batch validation/confirm and host subscribe/replay/delivery,
//! persist through a
//! [`DurableStore`] with durable
//! position/effects atomicity, suppress duplicate re-application through a
//! bounded [`DuplicateCache`], stage snapshots
//! through [`StagedSnapshot`], and route
//! batches to exactly one subscription handle (directed delivery). There is
//! no broadcast path: a batch for handle A is never visible to handle B.
//!
//! - [`InitiatorDriver`] (initiator side): validates batches through the
//!   same pipeline as live batches, stages snapshots, polls cumulative
//!   loss, confirms only after atomic persistence.
//! - [`HostDriver`] (host side): authorizes every hook, serves bounded
//!   replay pages from stored batches, and emits
//!   [`TargetedEnvelope`]s addressed to one subscription handle.
//!
//! Persistence failure is reported by not confirming: the store error is
//! returned to the caller and the engine is untouched, so committed
//! progress never advances on a failed write.
//!
//! These helpers do not negotiate, fence wire rounds, or track peer acks. The
//! wire adapter owns fresh H/B per round, termination, and validated responses.
//! `confirm` below records LOCAL durable progress, not peer acknowledgement.
//! Snapshot provider authorization and binding validation remain caller-owned;
//! staging accepts already provider-trusted descriptors, never raw peer authority.

use std::collections::HashMap;
use std::sync::Arc;

use super::cache::DuplicateCache;
use super::engine::ProfileEngine;
use super::profile::{
    CommittedPosition, ProfileAction, ProfileCheckpoint, ProfileInput, ProviderError,
    RecoveryAuthorizer, ReplayPage,
};
use super::snapshot::{SnapshotError, StagedSnapshot};
use super::store::{DurableStore, MemoryStore, StoreError};
use crate::session::Principal;

/// Initiator-side failure: persistence failure or authorization denial.
///
/// `Store` preserves the underlying [`StoreError`] without carrying
/// checkpoint bytes; `Unauthorized` carries the denying [`ProviderError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InitiatorError {
    /// Durable store failure; retry from the last persisted position.
    #[error("durable recovery store failure: {0:?}")]
    Store(StoreError),
    /// Application authorizer denied the hook.
    #[error("recovery validation denied: {0}")]
    Unauthorized(ProviderError),
}

impl From<StoreError> for InitiatorError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl InitiatorError {
    /// Typed API-boundary status without exposing checkpoint/effects bytes.
    pub fn code(&self) -> syntra_core::ErrorCode {
        match self {
            Self::Store(e) => e.code(),
            Self::Unauthorized(e) => e.code(),
        }
    }
}

/// Connection/principal context bound at handshake and carried on every
/// recovery hook. Checkpoint and selector bytes are never authority by
/// themselves; the bound principal is checked at each hook.
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    /// Per-connection diagnostic id (never authority).
    pub connection_id: String,
    /// Bound principal authorized at every hook.
    pub principal: Principal,
    /// Negotiated version.
    pub version: u32,
}

impl ConnectionContext {
    /// Context for the bound connection/principal.
    pub fn new(connection_id: String, principal: Principal, version: u32) -> Self {
        Self {
            connection_id,
            principal,
            version,
        }
    }
}

/// Envelope addressed to exactly one subscription handle.
///
/// Directed delivery: the host routes this envelope to the connection that
/// owns `subscription_handle` and to no other. Broadcast (`NotifyAll`-style
/// fan-out) must never be used for recovery batches: it leaks stream state
/// across principals and breaks per-stream termination scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetedEnvelope {
    /// Subscription handle that must receive this batch.
    pub subscription_handle: Vec<u8>,
    /// Opaque batch bytes.
    pub payload: Vec<u8>,
}

/// Encode a checkpoint as a duplicate-cache key (opaque, equality only).
/// Length-prefixes each variable field so embedded 0x00 bytes cannot cause
/// collisions.
fn cache_key(checkpoint: &ProfileCheckpoint) -> Vec<u8> {
    let mut k = Vec::with_capacity(
        8 + 8 * 3
            + checkpoint.stream_selector.len()
            + checkpoint.base_cursor.len()
            + checkpoint.result_cursor.len(),
    );
    k.extend_from_slice(&checkpoint.generation.to_le_bytes());
    for field in [
        &checkpoint.stream_selector,
        &checkpoint.base_cursor,
        &checkpoint.result_cursor,
    ] {
        k.extend_from_slice(&(field.len() as u64).to_le_bytes());
        k.extend_from_slice(field);
    }
    k
}

/// Initiator-side recovery driver.
///
/// Owns one [`ProfileEngine`] (all tracked streams for this connection),
/// one durable [`DurableStore`] adapter (default [`MemoryStore`]), one bounded
/// [`DuplicateCache`], and one staged snapshot per stream. All methods are
/// synchronous and transport-free; the caller transmits returned envelopes.
pub struct InitiatorDriver<S = MemoryStore> {
    ctx: ConnectionContext,
    engine: ProfileEngine,
    store: S,
    cache: DuplicateCache,
    staged: HashMap<Vec<u8>, StagedSnapshot>,
    authorizer: Option<Arc<dyn RecoveryAuthorizer>>,
}

impl InitiatorDriver<MemoryStore> {
    /// Driver for the bound connection/principal with an empty store and a
    /// bounded duplicate cache of `cache_capacity` entries.
    pub fn new(ctx: ConnectionContext, cache_capacity: usize) -> Self {
        Self {
            ctx,
            engine: ProfileEngine::new(),
            store: MemoryStore::new(),
            cache: DuplicateCache::new(cache_capacity),
            staged: HashMap::new(),
            authorizer: None,
        }
    }
}

impl<S: DurableStore> InitiatorDriver<S> {
    /// Driver with an application-provided durable store.
    pub fn with_store(ctx: ConnectionContext, cache_capacity: usize, store: S) -> Self {
        Self {
            ctx,
            engine: ProfileEngine::new(),
            store,
            cache: DuplicateCache::new(cache_capacity),
            staged: HashMap::new(),
            authorizer: None,
        }
    }

    /// Install an application authorizer checked before cache/offer and confirm.
    pub fn with_authorizer(mut self, authorizer: Arc<dyn RecoveryAuthorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Bound connection/principal context.
    pub fn context(&self) -> &ConnectionContext {
        &self.ctx
    }

    /// Underlying engine (read-only hooks for tests/embeds).
    pub fn engine(&self) -> &ProfileEngine {
        &self.engine
    }

    /// Underlying store (read-only hooks for tests/embeds).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mutable store (failure injection for tests).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Track a stream from its last confirmed position, restoring durable
    /// state when the store already holds it.
    pub fn track_stream(
        &mut self,
        stream_selector: Vec<u8>,
        generation: u64,
        committed: Vec<u8>,
    ) -> Result<(), StoreError> {
        if let Some(saved) = self.store.load(&stream_selector)? {
            self.engine.insert_stream(
                saved.stream_selector.clone(),
                saved.generation,
                saved.committed.clone(),
            );
        } else {
            self.engine
                .insert_stream(stream_selector.clone(), generation, committed);
        }
        // Re-establishment is a new local scope/round, never inherited cache
        // authority or inherited snapshot pages.
        self.cache.clear();
        self.staged.remove(&stream_selector);
        Ok(())
    }

    /// Compatibility helper. Denial emits recovery-needed and cannot hit the
    /// cache. Use [`Self::try_on_batch_validated`] to retain the typed denial.
    pub fn on_batch_validated(&mut self, checkpoint: ProfileCheckpoint) -> Vec<ProfileAction> {
        match self.try_on_batch_validated(checkpoint.clone()) {
            Ok(actions) => actions,
            Err(_) => vec![ProfileAction::RecoveryNeeded {
                stream_selector: checkpoint.stream_selector.clone(),
                committed: self
                    .engine
                    .committed(&checkpoint.stream_selector)
                    .unwrap_or_default()
                    .to_vec(),
            }],
        }
    }

    /// Validate selector/current G and the configured authorization/validation
    /// hook BEFORE duplicate lookup. Cache hits suppress only reapplication,
    /// never a snapshot gate or pending snapshot source classification.
    pub fn try_on_batch_validated(
        &mut self,
        checkpoint: ProfileCheckpoint,
    ) -> Result<Vec<ProfileAction>, InitiatorError> {
        if self.engine.generation(&checkpoint.stream_selector) != Some(checkpoint.generation) {
            return Ok(self
                .engine
                .observe(ProfileInput::BatchValidated { checkpoint }));
        }
        if let Some(auth) = &self.authorizer {
            auth.authorize_validate(&checkpoint)
                .map_err(InitiatorError::Unauthorized)?;
        }
        if self.engine.snapshot_pending(&checkpoint.stream_selector)
            || self.engine.pending_is_snapshot(&checkpoint.stream_selector)
        {
            return Ok(self
                .engine
                .observe(ProfileInput::BatchValidated { checkpoint }));
        }
        let key = cache_key(&checkpoint);
        if self.cache.contains(&key) {
            return Ok(vec![]);
        }
        Ok(self
            .engine
            .observe(ProfileInput::BatchValidated { checkpoint }))
    }

    /// Confirm durable persistence of a previously offered checkpoint.
    ///
    /// Atomically stores the position plus `effects_digest` first; on store
    /// failure returns `Err` and never touches the engine, so committed
    /// progress cannot advance on a failed write. Rejected checkpoints are
    /// validated read-only first and return the engine's rejection without
    /// a store write, so rejected checkpoints never persist. On success
    /// delegates to the engine and records the cache key so a re-delivery
    /// across the recovered/live boundary is tolerated without re-applying
    /// effects.
    pub fn confirm(
        &mut self,
        checkpoint: &ProfileCheckpoint,
        effects_digest: &[u8],
    ) -> Result<Vec<ProfileAction>, InitiatorError> {
        if let Some(auth) = &self.authorizer {
            if let Err(e) = auth.authorize_confirm(checkpoint) {
                return Err(InitiatorError::Unauthorized(e));
            }
        }
        if !self.engine.can_confirm(checkpoint) {
            return Ok(self.engine.confirm_persisted(checkpoint));
        }
        let position = CommittedPosition {
            stream_selector: checkpoint.stream_selector.clone(),
            generation: checkpoint.generation,
            committed: checkpoint.result_cursor.clone(),
        };
        let is_snapshot = self.engine.pending_is_snapshot(&checkpoint.stream_selector);
        self.store.store_atomic(position, effects_digest)?;
        let actions = self.engine.confirm_persisted(checkpoint);
        if actions.is_empty() {
            if is_snapshot {
                self.staged.remove(&checkpoint.stream_selector);
                self.cache.clear();
            } else {
                self.cache.insert(cache_key(checkpoint));
            }
        }
        Ok(actions)
    }

    /// Poll a caller-supplied cumulative loss count for the stream.
    pub fn poll_loss(&mut self, stream_selector: &[u8], loss_count: u64) -> Vec<ProfileAction> {
        let actions = self.engine.poll_loss(stream_selector, loss_count);
        if !actions.is_empty() {
            self.staged.remove(stream_selector);
            self.cache.clear();
        }
        actions
    }

    /// Explicit scoped provider history loss/rebase; never local overflow,
    /// ordinary retention expiry, or revocation. The caller retires old H.
    pub fn provider_loss(
        &mut self,
        stream_selector: &[u8],
        next_generation: u64,
    ) -> Result<(), ProviderError> {
        self.engine
            .provider_loss(stream_selector, next_generation)?;
        self.staged.remove(stream_selector);
        self.cache.clear();
        Ok(())
    }

    /// Ordinary retention miss: require a snapshot without changing G.
    pub fn continuation_expired(&mut self, stream_selector: &[u8]) -> Vec<ProfileAction> {
        let Some(committed) = self.engine.committed(stream_selector) else {
            return vec![];
        };
        self.engine.observe(ProfileInput::ContinuationExpired {
            stream_selector: stream_selector.to_vec(),
            committed: committed.to_vec(),
        })
    }

    /// Record the subscribed catch-up boundary from the subscribe response.
    pub fn set_subscribed_boundary(
        &mut self,
        stream_selector: &[u8],
        boundary: Vec<u8>,
    ) -> Vec<ProfileAction> {
        self.engine
            .set_subscribed_boundary(stream_selector, boundary)
    }

    /// Track a replay page boundary.
    pub fn observe_replay_page(
        &mut self,
        stream_selector: &[u8],
        page: &ReplayPage,
    ) -> Vec<ProfileAction> {
        self.engine.observe_replay_page(stream_selector, page)
    }

    /// Validate a catch-up completion boundary before releasing live batches.
    pub fn observe_completion_boundary(
        &mut self,
        stream_selector: &[u8],
        completion_boundary: &[u8],
    ) -> Vec<ProfileAction> {
        self.engine
            .observe_completion_boundary(stream_selector, completion_boundary)
    }

    /// Begin staging a provider-trusted snapshot. Exact descriptor retries
    /// preserve pages. A different descriptor cannot overwrite active state;
    /// supersession requires retiring H in the wire adapter, then explicitly
    /// discarding staging. This helper does not authorize a same-H second offer.
    pub fn stage_snapshot(
        &mut self,
        stream_selector: Vec<u8>,
        snapshot_handle: Vec<u8>,
        boundary_checkpoint: Vec<u8>,
        total_pages: u32,
        page_bytes_max: u32,
    ) -> Result<(), SnapshotError> {
        let staged = StagedSnapshot::new(
            snapshot_handle,
            boundary_checkpoint,
            total_pages,
            page_bytes_max,
        )?;
        if !self.engine.contains_stream(&stream_selector) {
            return Err(SnapshotError::CoordinatorRejected);
        }
        if let Some(active) = self.staged.get(&stream_selector) {
            if active.snapshot_handle() == staged.snapshot_handle()
                && active.boundary_checkpoint() == staged.boundary_checkpoint()
                && active.total_pages() == staged.total_pages()
                && active.page_bytes_max() == staged.page_bytes_max()
            {
                return Ok(());
            }
            return Err(SnapshotError::ActiveStage);
        }
        if self.engine.pending(&stream_selector).is_some() {
            return Err(SnapshotError::CoordinatorRejected);
        }
        self.staged.insert(stream_selector, staged);
        Ok(())
    }

    /// Discard pages only after the owning round is retired. Handle retirement
    /// and fresh Subscribe are the wire adapter's responsibility.
    pub fn discard_snapshot(&mut self, stream_selector: &[u8]) {
        self.staged.remove(stream_selector);
    }

    /// Stage one snapshot page for the stream.
    pub fn stage_snapshot_page(
        &mut self,
        stream_selector: &[u8],
        snapshot_handle: &[u8],
        page_index: u32,
        bytes: Vec<u8>,
        boundary_checkpoint: &[u8],
    ) -> Result<(), SnapshotError> {
        match self.staged.get_mut(stream_selector) {
            Some(staged) => {
                staged.stage_page(snapshot_handle, page_index, bytes, boundary_checkpoint)
            }
            None => Err(SnapshotError::InvalidPage),
        }
    }

    /// Install the staged snapshot and offer it to the coordinator as a
    /// CURRENT-generation checkpoint. Returns the checkpoint and assembled
    /// bytes; retains staging for exact retries until local durable confirm.
    /// A different generation is rejected until explicit provider loss/rebase.
    /// The caller atomically installs effects plus S0 via [`Self::confirm`].
    /// Peer SnapshotInstalled validation/live release is owned by the wire adapter.
    pub fn install_snapshot(
        &mut self,
        stream_selector: &[u8],
        generation: u64,
    ) -> Result<(ProfileCheckpoint, Vec<u8>), SnapshotError> {
        if self.engine.generation(stream_selector) != Some(generation) {
            return Err(SnapshotError::StaleGeneration);
        }
        let staged = self
            .staged
            .get(stream_selector)
            .ok_or(SnapshotError::Incomplete)?;
        let bytes = staged.install()?;
        let boundary = staged.boundary_checkpoint().to_vec();
        let checkpoint = ProfileCheckpoint {
            stream_selector: stream_selector.to_vec(),
            generation,
            base_cursor: boundary.clone(),
            result_cursor: boundary,
        };
        let actions = self.engine.observe(ProfileInput::SnapshotInstalled {
            checkpoint: checkpoint.clone(),
        });
        let offered = actions.iter().any(|a| match a {
            ProfileAction::CommitCheckpoint { checkpoint: c } => c == &checkpoint,
            _ => false,
        });
        if offered {
            Ok((checkpoint, bytes))
        } else {
            Err(SnapshotError::CoordinatorRejected)
        }
    }
}

/// Host-side recovery driver.
///
/// Authorizes subscribe/replay/delivery with the bound principal, serves bounded replay
/// pages from stored batches, and emits [`TargetedEnvelope`]s addressed to
/// exactly one subscription handle. No broadcast path exists.
///
/// Non-wire, per-connection test/embed helper, not a protocol host. Limits:
/// 64 routes, 64 stored selectors, 4096 total historical batches, 16 MiB total
/// history bytes (selector/cursors/payload), 64 batches / 256 KiB per page.
/// History is never silently evicted (indices fence replay); saturation returns
/// `Overloaded`. Drop/rebuild the helper to release history. Each route retains
/// only its last request/page until unsubscribe/drop; there is no guaranteed
/// retry lifetime. Production adapters own principal-wide limits, deadlines,
/// authorization freshness, round retirement and retained-response expiry.
pub struct HostDriver {
    ctx: ConnectionContext,
    authorizer: Option<Arc<dyn RecoveryAuthorizer>>,
    /// Batches per stream selector (opaque bytes keyed by result cursor).
    batches: HashMap<Vec<u8>, Vec<StoredBatch>>,
    /// Subscription handle -> route (selector, fixed boundary, generation,
    /// and per-handle replay fencing state).
    routes: HashMap<Vec<u8>, Route>,
    next_handle: u64,
    max_batches_per_page: u32,
    max_bytes_per_page: u32,
    history_count: usize,
    history_bytes: usize,
}

/// Per-subscription route: fixed catch-up boundary and generation captured
/// at subscribe time, plus fencing state for verbatim retries.
#[derive(Debug, Clone)]
struct Route {
    /// Stream selector routed to this handle.
    selector: Vec<u8>,
    /// Fixed catch-up boundary captured at subscribe time.
    boundary: Vec<u8>,
    /// Continuity generation captured at subscribe time.
    generation: u64,
    /// Exclusive storage index captured with the boundary; later appends
    /// belong to live delivery, not this replay round.
    replay_end: usize,
    /// Exact request of the last served page, before clamping bounds.
    last_request: Option<ReplayRequest>,
    /// Last served page for verbatim duplicate retries.
    last_page: Option<ReplayPage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayRequest {
    from_checkpoint: Vec<u8>,
    generation: u64,
    max_batches: u32,
    max_bytes: u32,
    continuation_marker: Vec<u8>,
}

/// One stored batch: predecessor/result cursors plus opaque payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBatch {
    /// Checkpoint this batch continues from.
    pub predecessor: Vec<u8>,
    /// Checkpoint this batch advances to.
    pub result: Vec<u8>,
    /// Opaque batch bytes.
    pub payload: Vec<u8>,
    /// Continuity generation of this batch.
    pub generation: u64,
}

impl HostDriver {
    /// Driver for the bound connection/principal.
    pub fn new(ctx: ConnectionContext) -> Self {
        Self {
            ctx,
            authorizer: None,
            batches: HashMap::new(),
            routes: HashMap::new(),
            next_handle: 1,
            max_batches_per_page: 64,
            max_bytes_per_page: 262_144,
            history_count: 0,
            history_bytes: 0,
        }
    }

    /// Install an application authorizer checked at every hook.
    pub fn with_authorizer(mut self, authorizer: Arc<dyn RecoveryAuthorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Bound connection/principal context.
    pub fn context(&self) -> &ConnectionContext {
        &self.ctx
    }

    /// Append application-supplied history within the documented helper bounds.
    /// Rejection leaves history and replay indices untouched.
    pub fn append_batch(
        &mut self,
        stream_selector: Vec<u8>,
        batch: StoredBatch,
    ) -> Result<(), ProviderError> {
        if stream_selector.is_empty()
            || stream_selector.len() > 1024
            || batch.predecessor.is_empty()
            || batch.predecessor.len() > 4096
            || batch.result.is_empty()
            || batch.result.len() > 4096
        {
            return Err(ProviderError::StaleCheckpoint);
        }
        if batch.payload.len() > 262_144
            || self.history_count >= 4096
            || (!self.batches.contains_key(&stream_selector) && self.batches.len() >= 64)
        {
            return Err(ProviderError::Overloaded);
        }
        let added = stream_selector.len()
            + batch.predecessor.len()
            + batch.result.len()
            + batch.payload.len();
        let total = self
            .history_bytes
            .checked_add(added)
            .filter(|n| *n <= 16 * 1024 * 1024)
            .ok_or(ProviderError::Overloaded)?;
        self.batches.entry(stream_selector).or_default().push(batch);
        self.history_count += 1;
        self.history_bytes = total;
        Ok(())
    }

    /// Subscribe a stream selector. Authorizes with the bound principal,
    /// assigns a fresh connection-scoped handle, and records the routing
    /// entry with its fixed catch-up boundary and generation. Returns the
    /// handle plus the fixed catch-up boundary (latest result for the
    /// generation, or the start checkpoint when empty).
    pub fn subscribe(
        &mut self,
        stream_selector: Vec<u8>,
        start_checkpoint: Vec<u8>,
        generation: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        if let Some(auth) = &self.authorizer {
            auth.authorize_subscribe(&stream_selector)?;
        }
        if stream_selector.is_empty()
            || stream_selector.len() > 1024
            || start_checkpoint.len() > 4096
        {
            return Err(ProviderError::StaleCheckpoint);
        }
        if self.routes.len() >= 64 {
            return Err(ProviderError::Overloaded);
        }
        let (replay_end, boundary) = self
            .batches
            .get(&stream_selector)
            .and_then(|v| {
                v.iter()
                    .enumerate()
                    .rev()
                    .find(|(_, b)| b.generation == generation)
                    .map(|(i, b)| (i + 1, b.result.clone()))
            })
            .unwrap_or_else(|| (0, start_checkpoint.clone()));
        if boundary.is_empty() {
            return Err(ProviderError::StaleCheckpoint);
        }
        // Connection-scoped, non-wire identifier; never wraps or reuses a
        // retired value. Do not include unbounded diagnostic connection IDs.
        let next = self
            .next_handle
            .checked_add(1)
            .ok_or(ProviderError::Overloaded)?;
        let handle = format!("sub-{}", self.next_handle).into_bytes();
        self.next_handle = next;
        self.routes.insert(
            handle.clone(),
            Route {
                selector: stream_selector,
                boundary: boundary.clone(),
                generation,
                replay_end,
                last_request: None,
                last_page: None,
            },
        );
        Ok((handle, boundary))
    }

    /// Serve one bounded replay page continuing from `from_checkpoint`.
    /// The caller transmits the page inside the terminal `RpcResult`.
    /// Validates the generation against the subscription, enforces
    /// per-handle fencing (only an identical request returns the verbatim
    /// last page; any other request must continue from the last page's
    /// result), and serves only the captured generation through the fixed
    /// subscribe-time boundary. This compatibility entry point infers the
    /// continuation marker from the last request/page. Wire adapters must use
    /// [`Self::replay_page_with_continuation`] to validate the peer's marker.
    pub fn replay_page(
        &mut self,
        subscription_handle: &[u8],
        from_checkpoint: &[u8],
        generation: u64,
        max_batches: u32,
        max_bytes: u32,
    ) -> Result<ReplayPage, ProviderError> {
        let route = self
            .routes
            .get(subscription_handle)
            .ok_or(ProviderError::UnknownStream)?;
        let marker = match (&route.last_request, &route.last_page) {
            (Some(previous), _) if previous.from_checkpoint == from_checkpoint => {
                previous.continuation_marker.clone()
            }
            (_, Some(page)) => page.continuation_marker.clone(),
            _ => Vec::new(),
        };
        self.replay_page_with_continuation(
            subscription_handle,
            from_checkpoint,
            generation,
            max_batches,
            max_bytes,
            &marker,
        )
    }

    /// Serve a replay request carrying the peer's explicit continuation
    /// marker. Only an identical complete request retries the retained page;
    /// otherwise both the previous result and non-empty marker must chain.
    pub fn replay_page_with_continuation(
        &mut self,
        subscription_handle: &[u8],
        from_checkpoint: &[u8],
        generation: u64,
        max_batches: u32,
        max_bytes: u32,
        continuation_marker: &[u8],
    ) -> Result<ReplayPage, ProviderError> {
        if from_checkpoint.is_empty()
            || from_checkpoint.len() > 4096
            || continuation_marker.len() > 4096
        {
            return Err(ProviderError::StaleCheckpoint);
        }
        let route = self
            .routes
            .get(subscription_handle)
            .ok_or(ProviderError::UnknownStream)?;
        if generation != route.generation {
            return Err(ProviderError::StaleCheckpoint);
        }
        if let (Some(previous), Some(lp)) = (&route.last_request, &route.last_page) {
            if from_checkpoint == previous.from_checkpoint
                && generation == previous.generation
                && max_batches == previous.max_batches
                && max_bytes == previous.max_bytes
                && continuation_marker == previous.continuation_marker
            {
                let probe = ProfileCheckpoint {
                    stream_selector: route.selector.clone(),
                    generation: route.generation,
                    base_cursor: from_checkpoint.to_vec(),
                    result_cursor: from_checkpoint.to_vec(),
                };
                if let Some(auth) = &self.authorizer {
                    auth.authorize_replay(&probe)?;
                }
                return Ok(lp.clone());
            }
            if lp.continuation_marker.is_empty()
                || from_checkpoint != lp.result_checkpoint.as_slice()
                || continuation_marker != lp.continuation_marker
            {
                return Err(ProviderError::StaleCheckpoint);
            }
        } else if !continuation_marker.is_empty() {
            return Err(ProviderError::StaleCheckpoint);
        }
        if from_checkpoint == route.boundary {
            return Err(ProviderError::StaleCheckpoint);
        }
        let probe = ProfileCheckpoint {
            stream_selector: route.selector.clone(),
            generation: route.generation,
            base_cursor: from_checkpoint.to_vec(),
            result_cursor: from_checkpoint.to_vec(),
        };
        if let Some(auth) = &self.authorizer {
            auth.authorize_replay(&probe)?;
        }
        let batches = self
            .batches
            .get(&route.selector)
            .ok_or(ProviderError::OutsideRetention)?;
        let start = batches
            .iter()
            .take(route.replay_end)
            .position(|b| b.generation == route.generation && b.predecessor == from_checkpoint)
            .ok_or(ProviderError::StaleCheckpoint)?;
        let batch_limit = max_batches.clamp(1, self.max_batches_per_page).min(64);
        let byte_limit = max_bytes.clamp(1, self.max_bytes_per_page).min(262_144);
        let mut payloads = Vec::new();
        let mut bytes = 0u32;
        let mut end = start;
        let mut last_result = from_checkpoint.to_vec();
        for (i, b) in batches
            .iter()
            .enumerate()
            .take(route.replay_end)
            .skip(start)
            .filter(|(_, b)| b.generation == route.generation)
        {
            if payloads.len() as u32 >= batch_limit {
                break;
            }
            if b.predecessor != last_result {
                return Err(ProviderError::OutsideRetention);
            }
            if b.payload.len() > (byte_limit - bytes) as usize {
                if payloads.is_empty() {
                    return Err(ProviderError::Overloaded);
                }
                break;
            }
            bytes += b.payload.len() as u32;
            last_result = b.result.clone();
            payloads.push(b.payload.clone());
            end = i + 1;
            if last_result == route.boundary {
                break;
            }
        }
        if payloads.is_empty() {
            return Err(ProviderError::OutsideRetention);
        }
        let more = last_result != route.boundary;
        let page = ReplayPage {
            predecessor_checkpoint: from_checkpoint.to_vec(),
            result_checkpoint: last_result,
            continuation_marker: if more {
                format!("marker-{end}").into_bytes()
            } else {
                Vec::new()
            },
            catchup_boundary: route.boundary.clone(),
            batch_payloads: payloads,
        };
        if let Some(route) = self.routes.get_mut(subscription_handle) {
            route.last_request = Some(ReplayRequest {
                from_checkpoint: from_checkpoint.to_vec(),
                generation,
                max_batches,
                max_bytes,
                continuation_marker: continuation_marker.to_vec(),
            });
            route.last_page = Some(page.clone());
        }
        Ok(page)
    }

    /// Route a batch to exactly one subscription handle. Returns the
    /// addressed envelope; no other handle observes it.
    pub fn directed_delivery(
        &self,
        subscription_handle: &[u8],
        payload: Vec<u8>,
    ) -> Result<TargetedEnvelope, ProviderError> {
        let route = self
            .routes
            .get(subscription_handle)
            .ok_or(ProviderError::UnknownStream)?;
        if let Some(auth) = &self.authorizer {
            auth.authorize_subscribe(&route.selector)?;
        }
        if payload.len() > 262_144 {
            return Err(ProviderError::Overloaded);
        }
        Ok(TargetedEnvelope {
            subscription_handle: subscription_handle.to_vec(),
            payload,
        })
    }

    /// Terminate exactly one subscription. Connection state is untouched;
    /// other handles keep their routing entries.
    pub fn unsubscribe(&mut self, subscription_handle: &[u8]) -> Result<(), ProviderError> {
        self.routes
            .remove(subscription_handle)
            .map(|_| ())
            .ok_or(ProviderError::UnknownStream)
    }

    /// Handles currently routed.
    pub fn routed_handles(&self) -> Vec<Vec<u8>> {
        self.routes.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostDriver {
        HostDriver::new(ConnectionContext::new(
            "c".into(),
            Principal::new("test"),
            1,
        ))
    }

    #[test]
    fn handle_counter_exhaustion_never_wraps_or_inserts_a_route() {
        let mut h = host();
        h.next_handle = u64::MAX - 1;
        let (last, _) = h.subscribe(b"s".to_vec(), b"C".to_vec(), 7).unwrap();
        h.unsubscribe(&last).unwrap();
        for _ in 0..2 {
            assert_eq!(
                h.subscribe(b"s".to_vec(), b"C".to_vec(), 7),
                Err(ProviderError::Overloaded)
            );
            assert_eq!(h.next_handle, u64::MAX);
            assert!(h.routes.is_empty());
        }
    }

    #[test]
    fn history_byte_and_selector_limits_reject_without_partial_append() {
        let mut h = host();
        let batch = StoredBatch {
            predecessor: b"C".to_vec(),
            result: b"D".to_vec(),
            payload: vec![1],
            generation: 7,
        };
        for i in 0..64u8 {
            h.append_batch(vec![i], batch.clone()).unwrap();
        }
        assert_eq!(
            h.append_batch(b"new".to_vec(), batch.clone()),
            Err(ProviderError::Overloaded)
        );
        h.history_bytes = 16 * 1024 * 1024 - 4;
        h.append_batch(vec![0], batch.clone()).unwrap();
        let count = h.history_count;
        assert_eq!(
            h.append_batch(vec![0], batch),
            Err(ProviderError::Overloaded)
        );
        assert_eq!(h.history_count, count);
        assert_eq!(h.history_bytes, 16 * 1024 * 1024);
        assert_eq!(h.batches[&vec![0]].len(), 2);
    }
}
