//! Durable position/effects persistence adapter.
//!
//! The coordinator never persists. The application persists the checkpoint
//! *and* its effects atomically through this adapter, then confirms only
//! on success. A persistence failure is reported by simply not confirming:
//! [`ProfileEngine::confirm_persisted`](super::engine::ProfileEngine::confirm_persisted)
//! is never called, committed progress never advances, and the next replay
//! retries from the last persisted position. This module gives that
//! contract a concrete adapter shape so drivers and tests share one
//! atomicity rule.
//!
//! Atomicity rule: `store_atomic` either durably records both the position
//! and the effects digest, or records neither and returns an error. Partial
//! writes must never become visible to `load`.

use std::collections::HashMap;

use super::profile::CommittedPosition;

/// Persistence failure. Never carries checkpoint bytes or effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Transient I/O failure; retry from the last persisted position.
    Unavailable,
    /// Stored bytes are corrupt; recovery follows the snapshot path.
    Corrupt,
}

impl StoreError {
    /// Typed code for the failure (terminal for the affected call only).
    pub fn code(&self) -> syntra_core::ErrorCode {
        match self {
            Self::Unavailable => syntra_core::ErrorCode::Unavailable,
            Self::Corrupt => syntra_core::ErrorCode::DataLoss,
        }
    }
}

/// Durable position store with atomic position+effects writes.
///
/// Implementations must make `store_atomic` all-or-nothing: either both the
/// committed position and the effects digest are durable, or neither is and
/// an error is returned. `load` returns the last atomically stored position.
pub trait DurableStore: Send + Sync {
    /// Last durably stored position for the selector, if any.
    /// Returns `Err(Corrupt)` when stored bytes fail validation.
    fn load(&self, stream_selector: &[u8]) -> Result<Option<CommittedPosition>, StoreError>;
    /// Atomically record `position` and its effects. On error nothing is
    /// recorded and the caller must not confirm.
    fn store_atomic(
        &mut self,
        position: CommittedPosition,
        effects_digest: &[u8],
    ) -> Result<(), StoreError>;
}

/// In-memory store for drivers, embeds, and tests.
///
/// `fail_next` injects exactly one persistence failure (the next
/// `store_atomic` returns `Unavailable` and records nothing); `fail_always`
/// fails every write. Both model a crashed disk without advancing state.
#[derive(Debug, Default)]
pub struct MemoryStore {
    positions: HashMap<Vec<u8>, CommittedPosition>,
    /// Digests recorded alongside positions (atomicity witness for tests).
    digests: HashMap<Vec<u8>, Vec<u8>>,
    fail_next: bool,
    fail_always: bool,
}

impl MemoryStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail exactly the next write, then recover.
    pub fn fail_next_write(&mut self) {
        self.fail_next = true;
    }

    /// Fail every write until cleared.
    pub fn set_fail_always(&mut self, fail: bool) {
        self.fail_always = fail;
    }

    /// Digest recorded with the selector's position, if any.
    pub fn digest(&self, stream_selector: &[u8]) -> Option<&[u8]> {
        self.digests.get(stream_selector).map(|v| v.as_slice())
    }
}

impl DurableStore for MemoryStore {
    fn load(&self, stream_selector: &[u8]) -> Result<Option<CommittedPosition>, StoreError> {
        Ok(self.positions.get(stream_selector).cloned())
    }

    fn store_atomic(
        &mut self,
        position: CommittedPosition,
        effects_digest: &[u8],
    ) -> Result<(), StoreError> {
        if self.fail_always || self.fail_next {
            self.fail_next = false;
            return Err(StoreError::Unavailable);
        }
        self.digests
            .insert(position.stream_selector.clone(), effects_digest.to_vec());
        self.positions
            .insert(position.stream_selector.clone(), position);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pos() -> CommittedPosition {
        CommittedPosition {
            stream_selector: b"s".to_vec(),
            generation: 7,
            committed: b"c-43".to_vec(),
        }
    }

    #[test]
    fn atomic_store_and_load_round_trip() {
        let mut s = MemoryStore::new();
        assert_eq!(s.load(b"s").unwrap(), None);
        s.store_atomic(pos(), b"digest-1").unwrap();
        assert_eq!(s.load(b"s").unwrap(), Some(pos()));
        assert_eq!(s.digest(b"s"), Some(b"digest-1".as_slice()));
    }

    #[test]
    fn failing_write_records_nothing() {
        let mut s = MemoryStore::new();
        s.store_atomic(pos(), b"d0").unwrap();
        s.fail_next_write();
        assert_eq!(
            s.store_atomic(
                CommittedPosition {
                    stream_selector: b"s".to_vec(),
                    generation: 7,
                    committed: b"c-44".to_vec(),
                },
                b"d1"
            ),
            Err(StoreError::Unavailable)
        );
        assert_eq!(s.load(b"s").unwrap(), Some(pos()));
        assert_eq!(s.digest(b"s"), Some(b"d0".as_slice()));
    }
}
