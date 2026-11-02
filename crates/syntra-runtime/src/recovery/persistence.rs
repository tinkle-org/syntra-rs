//! Local atomic recovery persistence of (principal, stream, generation, checkpoint,
//! **full opaque application state**). This is not a wire format or an effects
//! digest adapter; the legacy `store` helper is independent.
//!
//! No source handles, client storage credentials, or authentication tokens belong
//! here. Scopes and checkpoints are sensitive application data, not credentials
//! granting access. Debug/error output deliberately excludes their contents.
//!
//! The synchronous boundary permits native filesystem implementations. Async
//! native clients MUST offload file operations (for example, `spawn_blocking`)
//! and await completion before confirming. Dropping that task's join handle does
//! not cancel its write. A failed/abandoned call is never permission to confirm;
//! `CommitUnknown` requires reconnect/reconciliation, not an assumption of rollback.

use std::{collections::HashMap, fmt};

use syntra_core::ErrorCode as SyntraErrorCode;
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
#[path = "persistence_file.rs"]
mod file;
#[cfg(not(target_arch = "wasm32"))]
pub use file::FileRecoveryStore;

pub const MAX_SCOPE_BYTES: usize = 1_024;
pub const MAX_CHECKPOINT_BYTES: usize = 4_096;
// Local encoding: magic/version, four lengths, generation, SHA-256 checksum.
pub(super) const RECORD_OVERHEAD: usize = 8 + 4 * 8 + 8 + 32;

/// A validated, nonempty principal namespace and stable stream identifier.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PersistenceScope {
    principal_scope: Vec<u8>,
    stable_stream: Vec<u8>,
}

impl PersistenceScope {
    pub fn new(principal_scope: Vec<u8>, stable_stream: Vec<u8>) -> Result<Self, PersistenceError> {
        for bytes in [&principal_scope, &stable_stream] {
            if bytes.is_empty() {
                return Err(PersistenceError::Corrupt);
            }
            if bytes.len() > MAX_SCOPE_BYTES {
                return Err(PersistenceError::OverLimit);
            }
        }
        Ok(Self {
            principal_scope,
            stable_stream,
        })
    }

    pub fn principal_scope(&self) -> &[u8] {
        &self.principal_scope
    }

    pub fn stable_stream(&self) -> &[u8] {
        &self.stable_stream
    }
}

impl fmt::Debug for PersistenceScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistenceScope([REDACTED])")
    }
}

/// One indivisible snapshot; public fields are revalidated at every commit.
#[derive(Clone, PartialEq, Eq)]
pub struct DurableRecord {
    pub generation: u64,
    pub checkpoint: Vec<u8>,
    pub application_state: Vec<u8>,
}

impl DurableRecord {
    pub fn validate(&self, limits: &StoreLimits) -> Result<(), PersistenceError> {
        limits.validate()?;
        validate_position(self.generation, &self.checkpoint)?;
        if self.application_state.len() > limits.max_state_bytes {
            return Err(PersistenceError::OverLimit);
        }
        Ok(())
    }
}

impl fmt::Debug for DurableRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DurableRecord([REDACTED])")
    }
}

/// Compare-and-swap position, never an authorization token.
#[derive(Clone, PartialEq, Eq)]
pub struct ExpectedPosition {
    pub generation: u64,
    pub checkpoint: Vec<u8>,
}

impl From<&DurableRecord> for ExpectedPosition {
    fn from(record: &DurableRecord) -> Self {
        Self {
            generation: record.generation,
            checkpoint: record.checkpoint.clone(),
        }
    }
}

impl fmt::Debug for ExpectedPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExpectedPosition([REDACTED])")
    }
}

/// Redacted, typed persistence failures. Invalid empty/zero positions are Corrupt;
/// length/capacity violations are OverLimit. No underlying OS paths are exposed.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceError {
    #[error("recovery persistence unavailable")]
    Unavailable,
    #[error("invalid or corrupt recovery persistence")]
    Corrupt,
    #[error("recovery persistence position conflict")]
    Conflict,
    /// A write may have become visible or durable. Do not confirm or blindly
    /// retry: reopen/reconnect and reconcile with the persisted full record.
    #[error("recovery persistence commit outcome unknown; reconciliation required")]
    CommitUnknown,
    #[error("recovery persistence limit exceeded")]
    OverLimit,
}

impl PersistenceError {
    pub fn code(&self) -> SyntraErrorCode {
        match self {
            Self::Unavailable => SyntraErrorCode::Unavailable,
            Self::Corrupt => SyntraErrorCode::DataLoss,
            Self::Conflict => SyntraErrorCode::Aborted,
            Self::CommitUnknown => SyntraErrorCode::Unknown,
            Self::OverLimit => SyntraErrorCode::ResourceExhausted,
        }
    }
}

/// Finite limits shared by memory and native stores. Total bytes count the
/// complete local record encoding, including both scope parts and the checksum,
/// not just application-state bytes. Atomic replacement needs temporary disk
/// headroom for one additional record (also bounded by these limits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    pub max_records: usize,
    pub max_state_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_records: 256,
            max_state_bytes: 64 * 1_024 * 1_024,
            max_total_bytes: 256 * 1_024 * 1_024,
        }
    }
}

impl StoreLimits {
    pub fn validate(&self) -> Result<(), PersistenceError> {
        let maximum = self
            .max_state_bytes
            .checked_add(RECORD_OVERHEAD + 2 * MAX_SCOPE_BYTES + MAX_CHECKPOINT_BYTES);
        if self.max_records == 0
            || self.max_records > isize::MAX as usize
            || self.max_state_bytes == 0
            || self.max_total_bytes == 0
            || self.max_total_bytes > isize::MAX as usize
            || maximum.is_none_or(|n| n > isize::MAX as usize)
        {
            return Err(PersistenceError::OverLimit);
        }
        Ok(())
    }
}

/// Stores whole state and position atomically within a scope. `None` expects
/// absence; `Some` must match the existing generation/checkpoint. An exact full
/// record duplicate is always an idempotent no-op, including after a lost reply
/// with a stale expected position. No other stale write is accepted. Positions
/// are opaque: ordering and provider-authorized generation changes are the
/// caller's responsibility, not inferred from checkpoint bytes.
pub trait RecoveryPersistence: Send + Sync {
    fn load(&self, scope: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError>;

    fn commit(
        &mut self,
        scope: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        record: DurableRecord,
    ) -> Result<(), PersistenceError>;
}

/// Bounded reference implementation for tests/embeds. **Not durable**: process
/// exit or dropping the store loses every record. Mutation requires `&mut self`,
/// so there is no internal async or blocking mutex to hold across an await.
pub struct MemoryRecoveryStore {
    records: HashMap<PersistenceScope, DurableRecord>,
    limits: StoreLimits,
    total_bytes: usize,
    fail_next: bool,
}

impl Default for MemoryRecoveryStore {
    fn default() -> Self {
        Self::with_limits(StoreLimits::default()).expect("default limits are valid")
    }
}

impl MemoryRecoveryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(limits: StoreLimits) -> Result<Self, PersistenceError> {
        limits.validate()?;
        Ok(Self {
            records: HashMap::new(),
            limits,
            total_bytes: 0,
            fail_next: false,
        })
    }

    /// Fail the next non-duplicate, otherwise-valid commit before mutation.
    pub fn fail_next_commit(&mut self) {
        self.fail_next = true;
    }
}

impl RecoveryPersistence for MemoryRecoveryStore {
    fn load(&self, scope: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError> {
        Ok(self.records.get(scope).cloned())
    }

    fn commit(
        &mut self,
        scope: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        record: DurableRecord,
    ) -> Result<(), PersistenceError> {
        record.validate(&self.limits)?;
        let current = self.records.get(scope);
        if check_expected(current, expected, &record)? {
            return Ok(());
        }
        let old_bytes = current.map_or(0, |r| record_bytes(scope, r));
        let total = preflight(
            self.limits,
            self.records.len() + usize::from(current.is_none()),
            self.total_bytes - old_bytes,
            record_bytes(scope, &record),
        )?;
        if std::mem::take(&mut self.fail_next) {
            return Err(PersistenceError::Unavailable);
        }
        self.records.insert(scope.clone(), record);
        self.total_bytes = total;
        Ok(())
    }
}

fn validate_position(generation: u64, checkpoint: &[u8]) -> Result<(), PersistenceError> {
    if generation == 0 || checkpoint.is_empty() {
        return Err(PersistenceError::Corrupt);
    }
    if checkpoint.len() > MAX_CHECKPOINT_BYTES {
        return Err(PersistenceError::OverLimit);
    }
    Ok(())
}

fn check_expected(
    current: Option<&DurableRecord>,
    expected: Option<&ExpectedPosition>,
    record: &DurableRecord,
) -> Result<bool, PersistenceError> {
    if let Some(expected) = expected {
        validate_position(expected.generation, &expected.checkpoint)?;
    }
    if current == Some(record) {
        return Ok(true);
    }
    match (current, expected) {
        (None, None) => Ok(false),
        (Some(current), Some(expected))
            if current.generation == expected.generation
                && current.checkpoint == expected.checkpoint =>
        {
            Ok(false)
        }
        _ => Err(PersistenceError::Conflict),
    }
}

fn record_bytes(scope: &PersistenceScope, record: &DurableRecord) -> usize {
    // All components are bounded before this is called; StoreLimits validates
    // that even a maximum-size encoding fits isize::MAX.
    RECORD_OVERHEAD
        + scope.principal_scope.len()
        + scope.stable_stream.len()
        + record.checkpoint.len()
        + record.application_state.len()
}

fn preflight(
    limits: StoreLimits,
    count: usize,
    retained_bytes: usize,
    new_bytes: usize,
) -> Result<usize, PersistenceError> {
    let total = retained_bytes
        .checked_add(new_bytes)
        .ok_or(PersistenceError::OverLimit)?;
    if count > limits.max_records || total > limits.max_total_bytes {
        return Err(PersistenceError::OverLimit);
    }
    Ok(total)
}
