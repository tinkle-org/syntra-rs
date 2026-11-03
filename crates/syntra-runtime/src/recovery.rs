//! Negotiated update/recovery runtime and generic coordination helpers.
//!
//! Non-wire recovery helpers. The profile wire adapter owns connection/handle
//! fencing and peer acknowledgements; these helpers track local persistence.
//!
//! `wire` and `wire_client` bind accepted RFC 0006 payloads to the actual
//! Host/Initiator, with connection/handle fencing and bounded ingress. The
//! application supplies scoped provider history/issued-binding authority and
//! full-state persistence through `persistence`; receipt is never durable commit.
//! The older selector/numeric coordinators remain local helpers, not a second
//! wire protocol or authority for checkpoint interpretation.

pub mod cache;
pub mod driver;
pub mod engine;
pub mod persistence;
pub mod profile;
pub mod reconcile;
pub mod snapshot;
pub mod store;
pub mod wire;
pub mod wire_client;

pub use cache::DuplicateCache;
pub use driver::{
    ConnectionContext, HostDriver, InitiatorDriver, InitiatorError, StoredBatch, TargetedEnvelope,
};
pub use engine::ProfileEngine;
pub use profile::{
    CommittedPosition, ProfileAction, ProfileCheckpoint, ProfileInput, ProfileRecovery,
    ProfileRecoveryAction, ProfileRecoveryInput, ProviderError, RecoveryAuthorizer, ReplayPage,
    ReplayProvider, SnapshotOffer, SnapshotProvider,
};
pub use reconcile::{CheckpointReconciler, ReconcilerConfig};
pub use snapshot::{SnapshotError, StagedSnapshot};
pub use store::{DurableStore, MemoryStore, StoreError};

/// Position within one independently ordered stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCheckpoint {
    /// Application-defined stream label, opaque to the core.
    pub stream: String,
    /// Scoped provider continuity epoch, unchanged by retention misses.
    pub generation: u64,
    /// State required before applying the next batch.
    pub base: u64,
    /// State reached after applying the complete batch.
    pub checkpoint: u64,
}

/// Input observed by the recovery coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryInput {
    /// A complete batch validated by the application, ready to commit.
    BatchValidated { checkpoint: StreamCheckpoint },
    /// A batch arrived without continuity from the committed position.
    GapDetected {
        stream: String,
        expected_base: u64,
        observed_base: u64,
    },
    /// Transport loss or explicit continuity loss for the stream.
    ContinuityLost { stream: String, committed: u64 },
    /// The application reports that continuation is expired or unavailable.
    ContinuationExpired { stream: String, committed: u64 },
    /// Explicit scoped provider history loss/rebase, not local queue loss.
    ProviderLoss {
        stream: String,
        next_generation: u64,
    },
    /// The application validated/installed a provider-trusted snapshot in current G.
    SnapshotInstalled { checkpoint: StreamCheckpoint },
}

/// Local action emitted by the coordinator. Never an RPC invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Apply the batch, then commit its checkpoint after effects persist.
    CommitCheckpoint { checkpoint: StreamCheckpoint },
    /// Recover from the committed checkpoint using an application RPC.
    RecoveryNeeded { stream: String, committed: u64 },
    /// Obtain an authoritative snapshot before resuming the stream.
    /// Emitted by `ContinuationExpired`; while pending, validated batches
    /// are blocked (see [`StreamRecovery`]) until a snapshot confirms.
    SnapshotRequired { stream: String, committed: u64 },
}

/// Minimal coordinator over one stream's committed progress.
///
/// The coordinator tracks committed progress and one pending offer. The application
/// applies effects, persists checkpoints, and reports inputs.
///
/// Snapshot gating: once [`RecoveryInput::ContinuationExpired`] reports a
/// live stream, `snapshot_pending` is set. While set, otherwise-valid
/// [`RecoveryInput::BatchValidated`] inputs return
/// [`RecoveryAction::SnapshotRequired`] instead of `CommitCheckpoint`, so
/// committed progress cannot advance via the batch path until a snapshot
/// in the current generation confirms via [`Self::confirm_persisted`].
/// [`RecoveryInput::SnapshotInstalled`] remains admissible while pending
/// (it is the provider-trusted snapshot path, which may jump to S0).
/// Only explicit [`Self::provider_loss`] changes the generation.
#[derive(Debug, Clone)]
pub struct StreamRecovery {
    stream: String,
    generation: u64,
    committed: u64,
    snapshot_pending: bool,
    pending: Option<(StreamCheckpoint, bool)>,
}

impl StreamRecovery {
    pub fn new(stream: impl Into<String>, generation: u64, committed: u64) -> Self {
        Self {
            stream: stream.into(),
            generation,
            committed,
            snapshot_pending: false,
            pending: None,
        }
    }

    pub fn committed(&self) -> u64 {
        self.committed
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether a snapshot is required before batch commits may resume.
    pub fn snapshot_pending(&self) -> bool {
        self.snapshot_pending
    }

    /// Report true scoped provider loss/rebase. Invalidates the active numeric
    /// cursor (reset to zero), pending offers and gates without changing the
    /// external durable store. Ordinary retention/local loss and revocation
    /// MUST NOT call this method; the caller re-establishes the scoped stream.
    pub fn provider_loss(&mut self, next_generation: u64) -> Result<(), ProviderError> {
        if next_generation <= self.generation {
            return Err(ProviderError::StaleCheckpoint);
        }
        self.generation = next_generation;
        self.committed = 0;
        self.pending = None;
        self.snapshot_pending = false;
        Ok(())
    }

    /// Observes coordinator inputs. A validated batch returns a
    /// `CommitCheckpoint` action without advancing `committed`; the caller
    /// advances via [`Self::confirm_persisted`] only after the checkpoint
    /// and its effects are durably persisted.
    ///
    /// Foreign streams are ignored (empty, no mutation), like `GapDetected`.
    /// Batches must chain from `committed`; provider-trusted snapshots may
    /// jump to S0 in current G. Neither observe nor confirm infers a rebase.
    pub fn observe(&mut self, input: RecoveryInput) -> Vec<RecoveryAction> {
        match input {
            RecoveryInput::BatchValidated { checkpoint } => {
                if checkpoint.stream != self.stream {
                    return vec![];
                }
                if self.snapshot_pending {
                    return vec![RecoveryAction::SnapshotRequired {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                if checkpoint.generation != self.generation
                    || checkpoint.base != self.committed
                    || checkpoint.checkpoint < checkpoint.base
                    || self
                        .pending
                        .as_ref()
                        .is_some_and(|(cp, snapshot)| *cp != checkpoint || *snapshot)
                {
                    return vec![RecoveryAction::RecoveryNeeded {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                self.pending = Some((checkpoint.clone(), false));
                vec![RecoveryAction::CommitCheckpoint { checkpoint }]
            }
            RecoveryInput::GapDetected {
                stream,
                expected_base: _,
                observed_base: _,
            } => {
                if stream != self.stream {
                    return vec![];
                }
                self.pending = None;
                vec![RecoveryAction::RecoveryNeeded {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }]
            }
            RecoveryInput::ContinuityLost {
                stream,
                committed: _,
            } => {
                if stream != self.stream {
                    return vec![];
                }
                self.pending = None;
                vec![RecoveryAction::RecoveryNeeded {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }]
            }
            RecoveryInput::ContinuationExpired { stream, committed } => {
                if stream != self.stream {
                    return vec![];
                }
                if committed != self.committed {
                    return vec![];
                }
                self.snapshot_pending = true;
                self.pending = None;
                vec![RecoveryAction::SnapshotRequired {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }]
            }
            RecoveryInput::SnapshotInstalled { checkpoint } => {
                if checkpoint.stream != self.stream {
                    return vec![];
                }
                if checkpoint.checkpoint < checkpoint.base
                    || checkpoint.generation != self.generation
                    || self
                        .pending
                        .as_ref()
                        .is_some_and(|(cp, snapshot)| *cp != checkpoint || !*snapshot)
                {
                    return vec![RecoveryAction::RecoveryNeeded {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                self.pending = Some((checkpoint.clone(), true));
                self.snapshot_pending = true;
                vec![RecoveryAction::CommitCheckpoint { checkpoint }]
            }
            RecoveryInput::ProviderLoss {
                stream,
                next_generation,
            } => {
                if stream != self.stream {
                    return vec![];
                }
                let _ = self.provider_loss(next_generation);
                vec![RecoveryAction::RecoveryNeeded {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }]
            }
        }
    }

    /// Confirms the application durably persisted `checkpoint` and its
    /// effects. Advances persisted progress on success; on mismatch the
    /// checkpoint is not adopted and a `RecoveryNeeded` action retries from
    /// the last persisted position. Call only with the checkpoint previously
    /// returned as a `CommitCheckpoint` action; a persistence failure is
    /// reported by simply not calling this method.
    ///
    /// Foreign streams are ignored (empty, no mutation), like `GapDetected`:
    /// a checkpoint for another stream never triggers recovery of this
    /// stream.
    ///
    /// Only an exact pending offer can confirm. A provider-trusted snapshot
    /// may jump from the old cursor and clear the gate, but never changes G.
    pub fn confirm_persisted(&mut self, checkpoint: &StreamCheckpoint) -> Vec<RecoveryAction> {
        if checkpoint.stream != self.stream {
            return vec![];
        }
        if checkpoint.checkpoint < checkpoint.base {
            return vec![RecoveryAction::RecoveryNeeded {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        if checkpoint.generation != self.generation {
            return vec![RecoveryAction::RecoveryNeeded {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        let is_snapshot = match &self.pending {
            Some((offered, snapshot)) if offered == checkpoint => *snapshot,
            _ => {
                return vec![RecoveryAction::RecoveryNeeded {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }];
            }
        };
        if self.snapshot_pending && !is_snapshot {
            return vec![RecoveryAction::SnapshotRequired {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        if !is_snapshot && checkpoint.base != self.committed {
            return vec![RecoveryAction::RecoveryNeeded {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        self.committed = checkpoint.checkpoint;
        self.pending = None;
        if is_snapshot {
            self.snapshot_pending = false;
        }
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(base: u64, at: u64) -> StreamCheckpoint {
        StreamCheckpoint {
            stream: "s".to_string(),
            generation: 1,
            base,
            checkpoint: at,
        }
    }

    #[test]
    fn snapshot_never_manufactures_generation_or_confirms_without_offer() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let current = checkpoint(0, 100);
        assert!(!r.confirm_persisted(&current).is_empty());
        let mut future = current.clone();
        future.generation = 2;
        assert!(matches!(
            r.observe(RecoveryInput::SnapshotInstalled {
                checkpoint: future.clone(),
            })[0],
            RecoveryAction::RecoveryNeeded { .. }
        ));
        assert!(!r.confirm_persisted(&future).is_empty());
        assert_eq!(r.generation(), 1);
        let _ = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: current.clone(),
        });
        assert_eq!(r.provider_loss(1), Err(ProviderError::StaleCheckpoint));
        assert!(r.snapshot_pending());
        r.provider_loss(2).unwrap();
        assert!(!r.snapshot_pending());
        assert!(!r.confirm_persisted(&current).is_empty());
        assert!(!r.confirm_persisted(&future).is_empty());
        assert!(matches!(
            r.observe(RecoveryInput::SnapshotInstalled {
                checkpoint: future.clone(),
            })[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        assert!(r.confirm_persisted(&future).is_empty());
        assert_eq!(r.generation(), 2);
        assert_eq!(r.committed(), 100);
    }

    #[test]
    fn contiguous_batch_commits_after_persistence() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let cp = checkpoint(40, 43);
        let actions = r.observe(RecoveryInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert_eq!(r.committed(), 40);
        assert!(matches!(
            actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        let confirmed = r.confirm_persisted(&cp);
        assert!(confirmed.is_empty());
        assert_eq!(r.committed(), 43);
    }

    #[test]
    fn persistence_failure_retries_from_last_committed() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let cp = checkpoint(40, 43);
        let actions = r.observe(RecoveryInput::BatchValidated { checkpoint: cp });
        assert!(matches!(
            actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        // Persistence failed: confirm_persisted is never called.
        assert_eq!(r.committed(), 40);
        let retry = r.observe(RecoveryInput::GapDetected {
            stream: "s".to_string(),
            expected_base: 40,
            observed_base: 45,
        });
        assert_eq!(r.committed(), 40);
        assert!(matches!(
            retry[0],
            RecoveryAction::RecoveryNeeded { committed: 40, .. }
        ));
    }

    #[test]
    fn gap_requires_recovery_without_advancing() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let actions = r.observe(RecoveryInput::GapDetected {
            stream: "s".to_string(),
            expected_base: 40,
            observed_base: 45,
        });
        assert_eq!(r.committed(), 40);
        assert!(matches!(actions[0], RecoveryAction::RecoveryNeeded { .. }));
    }

    #[test]
    fn expired_continuation_requires_snapshot() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let actions = r.observe(RecoveryInput::ContinuationExpired {
            stream: "s".to_string(),
            committed: 40,
        });
        assert!(matches!(
            actions[0],
            RecoveryAction::SnapshotRequired { .. }
        ));
    }

    #[test]
    fn stale_expiry_reports_no_actions() {
        let mut r = StreamRecovery::new("s", 1, 43);
        let actions = r.observe(RecoveryInput::ContinuationExpired {
            stream: "s".to_string(),
            committed: 40,
        });
        assert!(actions.is_empty());
        assert_eq!(r.committed(), 43);
    }

    #[test]
    fn snapshot_advances_only_after_persistence() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let snap = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 1,
            base: 0,
            checkpoint: 100,
        };
        let actions = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        assert!(matches!(
            actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        assert_eq!(r.committed(), 40);
        assert_eq!(r.generation(), 1);
        let confirmed = r.confirm_persisted(&snap);
        assert!(confirmed.is_empty());
        assert_eq!(r.generation(), 1);
        assert_eq!(r.committed(), 100);
    }

    #[test]
    fn stale_generation_confirm_cannot_roll_back() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let batch = checkpoint(40, 43);
        let snap = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 2,
            base: 0,
            checkpoint: 100,
        };
        let _ = r.observe(RecoveryInput::BatchValidated {
            checkpoint: batch.clone(),
        });
        r.provider_loss(2).unwrap();
        let _ = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        // Newer snapshot persists first.
        assert!(r.confirm_persisted(&snap).is_empty());
        assert_eq!(r.generation(), 2);
        assert_eq!(r.committed(), 100);
        // Stale older-generation batch must not roll the coordinator back.
        let retry = r.confirm_persisted(&batch);
        assert!(matches!(
            retry[0],
            RecoveryAction::RecoveryNeeded { committed: 100, .. }
        ));
        assert_eq!(r.generation(), 2);
        assert_eq!(r.committed(), 100);
    }

    #[test]
    fn snapshot_failure_retains_previous_position() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let snap = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 1,
            base: 0,
            checkpoint: 100,
        };
        let actions = r.observe(RecoveryInput::SnapshotInstalled { checkpoint: snap });
        assert!(matches!(
            actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        // Persistence failed: confirm_persisted is never called.
        assert_eq!(r.committed(), 40);
        assert_eq!(r.generation(), 1);
    }

    #[test]
    fn snapshot_required_blocks_batch_commits_until_snapshot_confirmed() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let expired = r.observe(RecoveryInput::ContinuationExpired {
            stream: "s".to_string(),
            committed: 40,
        });
        assert!(matches!(
            expired[0],
            RecoveryAction::SnapshotRequired { .. }
        ));
        assert!(r.snapshot_pending());

        // Otherwise-valid batch must not commit while the snapshot gate holds.
        let batch = checkpoint(40, 43);
        let blocked = r.observe(RecoveryInput::BatchValidated {
            checkpoint: batch.clone(),
        });
        assert!(matches!(
            blocked[0],
            RecoveryAction::SnapshotRequired { .. }
        ));
        assert_eq!(r.committed(), 40);

        // An unoffered batch confirm cannot clear the gate.
        let blocked_confirm = r.confirm_persisted(&batch);
        assert!(matches!(
            blocked_confirm[0],
            RecoveryAction::RecoveryNeeded { .. }
        ));
        assert_eq!(r.committed(), 40);
        assert!(r.snapshot_pending());

        let snap = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 1,
            base: 0,
            checkpoint: 100,
        };
        let snap_actions = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        assert!(matches!(
            snap_actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        assert!(r.confirm_persisted(&snap).is_empty());
        assert!(!r.snapshot_pending());
        assert_eq!(r.generation(), 1);
        assert_eq!(r.committed(), 100);

        // Gate cleared: batches commit again.
        let next = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 1,
            base: 100,
            checkpoint: 103,
        };
        let resumed = r.observe(RecoveryInput::BatchValidated {
            checkpoint: next.clone(),
        });
        assert!(matches!(
            resumed[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
    }

    #[test]
    fn snapshot_installed_same_generation_clears_gate_only_after_confirm() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let expired = r.observe(RecoveryInput::ContinuationExpired {
            stream: "s".to_string(),
            committed: 40,
        });
        assert!(matches!(
            expired[0],
            RecoveryAction::SnapshotRequired { .. }
        ));
        assert!(r.snapshot_pending());

        let same_gen = checkpoint(0, 100);
        let offered = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: same_gen.clone(),
        });
        assert!(matches!(
            offered[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        assert_eq!(r.committed(), 40);
        assert_eq!(r.generation(), 1);
        assert!(r.snapshot_pending());
        assert!(r.confirm_persisted(&same_gen).is_empty());
        assert!(!r.snapshot_pending());
        assert_eq!(r.committed(), 100);
        assert_eq!(r.generation(), 1);
    }

    #[test]
    fn snapshot_installed_rejects_stale_but_allows_current_generation_jump() {
        let mut r = StreamRecovery::new("s", 2, 100);

        // Stale generation snapshot is not committable.
        let stale = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 1,
            base: 0,
            checkpoint: 50,
        };
        let actions = r.observe(RecoveryInput::SnapshotInstalled { checkpoint: stale });
        assert!(matches!(actions[0], RecoveryAction::RecoveryNeeded { .. }));
        assert_eq!(r.committed(), 100);
        assert_eq!(r.generation(), 2);

        // A provider-trusted same-generation snapshot need not chain from C.
        let gapped = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 2,
            base: 90,
            checkpoint: 110,
        };
        let actions = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: gapped.clone(),
        });
        assert!(matches!(
            actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        assert_eq!(r.committed(), 100);
        assert!(r.confirm_persisted(&gapped).is_empty());
        assert_eq!(r.committed(), 110);

        // Contiguous same-generation snapshot is committable.
        let contiguous = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 2,
            base: 100,
            checkpoint: 110,
        };
        let actions = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: contiguous.clone(),
        });
        assert!(matches!(
            actions[0],
            RecoveryAction::CommitCheckpoint { .. }
        ));
        assert!(r.confirm_persisted(&contiguous).is_empty());
        assert_eq!(r.committed(), 110);
    }

    #[test]
    fn foreign_stream_checkpoints_are_ignored() {
        let mut r = StreamRecovery::new("s", 1, 40);
        let foreign = StreamCheckpoint {
            stream: "other".to_string(),
            generation: 1,
            base: 40,
            checkpoint: 43,
        };
        let actions = r.observe(RecoveryInput::BatchValidated {
            checkpoint: foreign.clone(),
        });
        assert!(actions.is_empty());
        assert_eq!(r.committed(), 40);
        assert_eq!(r.generation(), 1);

        let confirm = r.confirm_persisted(&foreign);
        assert!(confirm.is_empty());
        assert_eq!(r.committed(), 40);
        assert_eq!(r.generation(), 1);
    }
}
