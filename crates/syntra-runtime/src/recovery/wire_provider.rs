//! Application/provider contract. Constructors bound retained metadata; source
//! implementations must bound their own storage and work before constructing it.

use super::{Principal, ProviderError, StoredBatch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationHook {
    Subscribe,
    Replay,
    CatchUp,
    Confirm,
    SnapshotOffer,
    SnapshotFetch,
    SnapshotConfirm,
    Unsubscribe,
    Emit,
}

/// Explicit declaration of shared continuity loss, never local overflow/pruning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderLoss {
    HistoryLost,
    SharedRebase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderStream {
    pub(super) identity: Vec<u8>,
    pub(super) generation: u64,
    pub(super) boundary: Vec<u8>,
}

impl ProviderStream {
    pub fn new(
        identity: Vec<u8>,
        generation: u64,
        boundary: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        if identity.is_empty()
            || identity.len() > 1024
            || generation == 0
            || boundary.is_empty()
            || boundary.len() > 4096
        {
            return Err(ProviderError::Internal);
        }
        Ok(Self {
            identity,
            generation,
            boundary,
        })
    }
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn boundary(&self) -> &[u8] {
        &self.boundary
    }
}

/// Budget includes serialized RecoveryBatch entry overhead, not raw payload only.
#[derive(Debug, Clone, Copy)]
pub struct PageBudget {
    pub max_batches: usize,
    pub max_entry_total_bytes: usize,
    pub max_entry_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct ProviderPage {
    pub(super) batches: Vec<StoredBatch>,
    pub(super) result: Vec<u8>,
    pub(super) marker: Vec<u8>,
}

impl ProviderPage {
    /// Batches must chain from the requested C to result, in the requested G.
    /// Empty marker means result equals fixed B. No whole-history copies.
    pub fn new(
        batches: Vec<StoredBatch>,
        result: Vec<u8>,
        marker: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        let mut bytes = 0usize;
        if batches.len() > 64 || result.is_empty() || result.len() > 4096 || marker.len() > 4096 {
            return Err(ProviderError::Internal);
        }
        for b in &batches {
            if b.predecessor.len() > 4096
                || b.result.is_empty()
                || b.result.len() > 4096
                || b.generation == 0
            {
                return Err(ProviderError::Internal);
            }
            bytes = bytes
                .checked_add(b.payload.len() + b.predecessor.len() + b.result.len())
                .ok_or(ProviderError::Internal)?;
            if bytes > 262_144 {
                return Err(ProviderError::Internal);
            }
        }
        Ok(Self {
            batches,
            result,
            marker,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProviderSnapshot {
    pub(super) key: Vec<u8>,
    pub(super) boundary: Vec<u8>,
    pub(super) pages: u32,
    pub(super) page_bytes: usize,
}

impl ProviderSnapshot {
    /// `key` is source-local, never used as a client-visible routing handle.
    /// Before returning, establish the recoverable (P,S,G,S0,contents) binding.
    pub fn new(
        key: Vec<u8>,
        boundary: Vec<u8>,
        pages: u32,
        page_bytes: usize,
    ) -> Result<Self, ProviderError> {
        if key.is_empty()
            || key.len() > 256
            || boundary.is_empty()
            || boundary.len() > 4096
            || !(1..=256).contains(&pages)
            || !(1..=262_144).contains(&page_bytes)
        {
            return Err(ProviderError::Internal);
        }
        Ok(Self {
            key,
            boundary,
            pages,
            page_bytes,
        })
    }
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub fn boundary(&self) -> &[u8] {
        &self.boundary
    }
    pub fn total_pages(&self) -> u32 {
        self.pages
    }
    pub fn page_bytes_max(&self) -> usize {
        self.page_bytes
    }
}

/// Host-owned, bounded, synchronous provider; methods must not block or reenter
/// session work. No service/session state mutex is held across these callbacks.
///
/// `capture` resolves stable S within P, captures G and nonempty fixed B, and
/// coordinates publication so subsequent live batches chain from B. Publication
/// must be serialized with capture by the application (or recoverably retried).
/// Aliases of a selector must resolve to the same stable identity, not confer
/// authority. `current_generation` is scoped to P/S; G is never a local counter.
/// Sources must bound their own history, issued-binding indexes and immutable
/// snapshot retention in count, bytes and lifetime; a service handle is not a
/// durable record or an unbounded retention lease. Lost history/bindings require
/// explicit retention failure or a scoped epoch change, never reinterpretation.
///
/// Every returned batch result and S0 must have a recoverable issued binding
/// independently of Confirm, including across host restart. Validation must
/// reject cross-P/S/G transplants, not merely test bytes in a global history.
/// Ordinary replay pruning returns ProviderRetentionMiss from replay, NOT from
/// validate_issued. This adapter performs no durable write and makes no claim
/// that receipt or confirmation is application persistence.
pub trait RecoverySource: Send + Sync {
    fn authorize(
        &self,
        principal: &Principal,
        selector: &[u8],
        hook: AuthorizationHook,
    ) -> Result<(), ProviderError>;
    fn capture(
        &self,
        principal: &Principal,
        selector: &[u8],
    ) -> Result<ProviderStream, ProviderError>;
    fn current_generation(
        &self,
        principal: &Principal,
        identity: &[u8],
    ) -> Result<u64, ProviderError>;
    fn validate_issued(
        &self,
        principal: &Principal,
        stream: &ProviderStream,
        checkpoint: &[u8],
    ) -> Result<(), ProviderError>;
    fn replay(
        &self,
        principal: &Principal,
        stream: &ProviderStream,
        from: &[u8],
        marker: &[u8],
        budget: PageBudget,
    ) -> Result<ProviderPage, ProviderError>;
    fn snapshot(
        &self,
        principal: &Principal,
        stream: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError>;
    /// Return exactly the requested immutable page. Transfer counts are peer-local.
    fn snapshot_page(
        &self,
        principal: &Principal,
        stream: &ProviderStream,
        snapshot: &ProviderSnapshot,
        index: u32,
    ) -> Result<Vec<u8>, ProviderError>;
}
