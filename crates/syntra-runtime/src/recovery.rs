//! Generic synchronization and recovery boundary.
//!
//! The core transports opaque `Notification` bytes and reports observable
//! transport events. It does not interpret stream identity, checkpoint
//! syntax, replay methods, or snapshot formats.
//!
//! This module defines application-supplied checkpoint metadata and the
//! local actions a generic coordinator may emit. The application selects
//! recovery RPCs, constructs payloads, performs requests, persists
//! checkpoints, and installs snapshots.

pub mod cache;
pub mod driver;
pub mod engine;
pub mod profile;
pub mod reconcile;
pub mod snapshot;
pub mod store;

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
    /// Continuity epoch. Changes when an old checkpoint cannot continue.
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
    /// The application installed a snapshot at the given checkpoint.
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
/// The coordinator tracks the committed checkpoint only. The application
/// applies effects, persists checkpoints, and reports inputs.
///
/// Snapshot gating: once [`RecoveryInput::ContinuationExpired`] reports a
/// live stream, `snapshot_pending` is set. While set, otherwise-valid
/// [`RecoveryInput::BatchValidated`] inputs return
/// [`RecoveryAction::SnapshotRequired`] instead of `CommitCheckpoint`, so
/// committed progress cannot advance via the batch path until a snapshot
/// with a new generation confirms via [`Self::confirm_persisted`].
/// [`RecoveryInput::SnapshotInstalled`] remains admissible while pending
/// (it is the snapshot path). Generation changes happen only through
/// snapshot confirms, which the application treats as its explicit
/// continuity-epoch decision.
#[derive(Debug, Clone)]
pub struct StreamRecovery {
    stream: String,
    generation: u64,
    committed: u64,
    snapshot_pending: bool,
}

impl StreamRecovery {
    pub fn new(stream: impl Into<String>, generation: u64, committed: u64) -> Self {
        Self {
            stream: stream.into(),
            generation,
            committed,
            snapshot_pending: false,
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

    /// Observes coordinator inputs. A validated batch returns a
    /// `CommitCheckpoint` action without advancing `committed`; the caller
    /// advances via [`Self::confirm_persisted`] only after the checkpoint
    /// and its effects are durably persisted.
    ///
    /// Foreign streams are ignored (empty, no mutation), like `GapDetected`.
    /// Same-generation snapshots must continue exactly from `committed`
    /// (`base == committed`); new-generation snapshots may start from a
    /// fresh base as their proven synchronization cut. Stale generations
    /// and non-contiguous same-generation snapshots return
    /// `RecoveryNeeded` instead of a committable action.
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
                {
                    return vec![RecoveryAction::RecoveryNeeded {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
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
                vec![RecoveryAction::RecoveryNeeded {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }]
            }
            RecoveryInput::ContinuationExpired { stream, committed } => {
                if stream != self.stream {
                    return vec![];
                }
                if committed < self.committed {
                    return vec![];
                }
                self.snapshot_pending = true;
                vec![RecoveryAction::SnapshotRequired {
                    stream: self.stream.clone(),
                    committed: self.committed,
                }]
            }
            RecoveryInput::SnapshotInstalled { checkpoint } => {
                if checkpoint.stream != self.stream {
                    return vec![];
                }
                if self.snapshot_pending && checkpoint.generation == self.generation {
                    return vec![RecoveryAction::SnapshotRequired {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                if checkpoint.checkpoint < checkpoint.base {
                    return vec![RecoveryAction::RecoveryNeeded {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                if checkpoint.generation < self.generation {
                    return vec![RecoveryAction::RecoveryNeeded {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                if checkpoint.generation == self.generation && checkpoint.base != self.committed {
                    return vec![RecoveryAction::RecoveryNeeded {
                        stream: self.stream.clone(),
                        committed: self.committed,
                    }];
                }
                vec![RecoveryAction::CommitCheckpoint { checkpoint }]
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
    /// Snapshot actions (a generation change) follow their own continuity
    /// rules: only the stream and the checkpoint's internal consistency are
    /// validated, so a snapshot whose base differs from the pre-snapshot
    /// committed position is accepted. Same-generation checkpoints must
    /// continue exactly from `committed`. Generations move forward only: a
    /// confirmation from an older generation never rolls back newer
    /// progress and instead reports the current position for recovery.
    ///
    /// While `snapshot_pending` is set (see [`Self::snapshot_pending`]),
    /// same-generation confirmations are blocked with `SnapshotRequired`
    /// instead of advancing, so only a new-generation snapshot confirm
    /// clears the gate.
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
        if checkpoint.generation < self.generation {
            return vec![RecoveryAction::RecoveryNeeded {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        if self.snapshot_pending && checkpoint.generation == self.generation {
            return vec![RecoveryAction::SnapshotRequired {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        if checkpoint.generation != self.generation {
            self.generation = checkpoint.generation;
            self.committed = checkpoint.checkpoint;
            self.snapshot_pending = false;
            return vec![];
        }
        if checkpoint.base != self.committed {
            return vec![RecoveryAction::RecoveryNeeded {
                stream: self.stream.clone(),
                committed: self.committed,
            }];
        }
        self.committed = checkpoint.checkpoint;
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
            generation: 2,
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
        assert_eq!(r.generation(), 2);
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
            generation: 2,
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

        // Same-generation confirm is blocked as well; only a new-generation
        // snapshot confirm clears the gate.
        let blocked_confirm = r.confirm_persisted(&batch);
        assert!(matches!(
            blocked_confirm[0],
            RecoveryAction::SnapshotRequired { .. }
        ));
        assert_eq!(r.committed(), 40);
        assert!(r.snapshot_pending());

        let snap = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 2,
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
        assert_eq!(r.generation(), 2);
        assert_eq!(r.committed(), 100);

        // Gate cleared: batches commit again.
        let next = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 2,
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
    fn snapshot_installed_same_generation_blocked_while_gate_pending() {
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

        // Same-generation snapshot with base equal to committed would
        // otherwise commit; the pending gate holds it instead.
        let same_gen = checkpoint(40, 43);
        let blocked = r.observe(RecoveryInput::SnapshotInstalled {
            checkpoint: same_gen,
        });
        assert!(matches!(
            blocked[0],
            RecoveryAction::SnapshotRequired { committed: 40, .. }
        ));
        assert_eq!(r.committed(), 40);
        assert_eq!(r.generation(), 1);
        assert!(r.snapshot_pending());
    }

    #[test]
    fn snapshot_installed_rejects_stale_and_noncontiguous() {
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

        // Same-generation snapshot must continue exactly from committed.
        let gapped = StreamCheckpoint {
            stream: "s".to_string(),
            generation: 2,
            base: 90,
            checkpoint: 110,
        };
        let actions = r.observe(RecoveryInput::SnapshotInstalled { checkpoint: gapped });
        assert!(matches!(actions[0], RecoveryAction::RecoveryNeeded { .. }));
        assert_eq!(r.committed(), 100);

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
