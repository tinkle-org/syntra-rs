//! Ordered delivery, bounded replay, snapshot recovery, and committed
//! progress for one independent stream.
//!
//! The core carries opaque bytes and reports observable stream events. It
//! does not interpret stream identity, checkpoint syntax, replay methods,
//! or snapshot formats.
//!
//! This module defines application-supplied checkpoint bytes and the local
//! actions a coordinator may emit. The application selects recovery calls,
//! constructs payloads, performs requests, persists checkpoints, and
//! installs snapshots.
//!
//! Checkpoints are opaque bytes. The coordinator compares checkpoint bytes
//! and stream selector bytes by equality only. It never orders, increments,
//! decrements, or parses checkpoint bytes. One continuity generation is
//! tracked per stream. Generation changes happen only through snapshot
//! confirms, which the application treats as its explicit continuity-epoch
//! decision.
//!
//! Commit sequence: receive, validate, offer, persist, confirm. Observing a
//! validated batch returns a committable action without advancing committed
//! progress. The caller advances progress via confirmation only after the
//! checkpoint and its effects are durably persisted through the application
//! persistence point. Transport receipt is never reported as committed
//! progress.
//!
//! Recovered batches and live batches pass through the same application
//! validation pipeline. Duplicates across the recovered and live boundary
//! are tolerated and never treated as a violation.
//!
//! Snapshot gating: once continuation expiry reports a live stream, the
//! pending gate is set. While set, otherwise-valid validated batches return
//! a snapshot-required action instead of a committable action, so committed
//! progress cannot advance via the batch path until a snapshot with a new
//! generation confirms. New-generation snapshot installation remains
//! admissible while pending as the snapshot path.
//!
//! Commit sequencing is stop-and-wait with a single pending offer. While a
//! committable checkpoint awaits confirmation, a different committable
//! checkpoint returns a recovery-needed action without replacing the pending
//! offer, so confirming the first offer still succeeds. Gap, continuity-loss,
//! and continuation-expiry reports invalidate the pending offer.
//!
//! The coordinator compares selector and cursor bytes by equality only. An
//! older duplicate whose result cursor no longer equals the committed cursor
//! is indistinguishable from a gap and returns a recovery-needed action. The
//! application holds a bounded recent-result cache keyed by checkpoint bytes
//! to answer older duplicates without re-applying effects; the coordinator
//! never orders or parses cursor bytes.

use syntra_core::ErrorCode;

/// Checkpoint within one independently ordered stream.
///
/// The stream selector selects the stream. The generation is the continuity
/// epoch for the stream. The base cursor is the state required before
/// applying the next batch. The result cursor is the state reached after
/// applying the complete batch. Selector and cursor bytes are opaque to the
/// coordinator and compared by equality only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCheckpoint {
    /// Application-defined stream selector, opaque to the coordinator.
    pub stream_selector: Vec<u8>,
    /// Continuity epoch. Changes when an old checkpoint cannot continue.
    pub generation: u64,
    /// State required before applying the next batch.
    pub base_cursor: Vec<u8>,
    /// State reached after applying the complete batch.
    pub result_cursor: Vec<u8>,
}

/// Persisted progress for one stream.
///
/// Carries the stream selector, the continuity generation, and the last
/// confirmed cursor bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedPosition {
    /// Application-defined stream selector, opaque to the coordinator.
    pub stream_selector: Vec<u8>,
    /// Continuity epoch of the committed cursor.
    pub generation: u64,
    /// Last confirmed cursor bytes.
    pub committed: Vec<u8>,
}

/// Input observed by the profile coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileInput {
    /// A complete batch validated by the application, ready to commit.
    BatchValidated { checkpoint: ProfileCheckpoint },
    /// A batch arrived without continuity from the committed position.
    GapDetected {
        stream_selector: Vec<u8>,
        expected_base: Vec<u8>,
        observed_base: Vec<u8>,
    },
    /// Stream loss or explicit continuity loss for the stream.
    ContinuityLost {
        stream_selector: Vec<u8>,
        committed: Vec<u8>,
    },
    /// The application reports that continuation is expired or unavailable.
    ContinuationExpired {
        stream_selector: Vec<u8>,
        committed: Vec<u8>,
    },
    /// The application installed a snapshot at the given checkpoint.
    SnapshotInstalled { checkpoint: ProfileCheckpoint },
}

/// Alias for the coordinator input.
pub type ProfileRecoveryInput = ProfileInput;

/// Local action emitted by the coordinator. Never a call invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileAction {
    /// Apply the batch, then confirm its checkpoint after effects persist.
    CommitCheckpoint { checkpoint: ProfileCheckpoint },
    /// Recover from the committed position using an application call.
    RecoveryNeeded {
        stream_selector: Vec<u8>,
        committed: Vec<u8>,
    },
    /// Obtain an authoritative snapshot before resuming the stream.
    /// Emitted by continuation expiry; while pending, validated batches
    /// are blocked until a snapshot confirms.
    SnapshotRequired {
        stream_selector: Vec<u8>,
        committed: Vec<u8>,
    },
}

/// Alias for the coordinator action.
pub type ProfileRecoveryAction = ProfileAction;

/// Failure of an application provider operation.
///
/// Maps to typed codes without carrying sensitive bytes. Messages set by
/// the application must not contain credentials or private diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// Unknown stream selector or unknown operation.
    UnknownStream,
    /// Unknown profile operation.
    UnknownOperation,
    /// Use of an unconfirmed option on a confirmed connection.
    Unconfirmed,
    /// Bound principal is not authorized at this hook.
    Unauthorized,
    /// Bound principal is unknown or not authenticated at this hook.
    Unauthenticated,
    /// Stale, forged, malformed, cross-stream, cross-generation, or
    /// cross-principal checkpoint bytes.
    StaleCheckpoint,
    /// Requested checkpoint is outside retention or otherwise
    /// unrecoverable by replay. Recovery follows the snapshot path.
    OutsideRetention,
    /// Bound saturation. The caller backs off with a bounded budget.
    Overloaded,
    /// Connection loss with invocations outstanding. Outcome unknown.
    TransportLost,
    /// Effective deadline expiry for the operation.
    DeadlineExpired,
    /// Application-internal failure persisting or supplying state.
    Internal,
}

impl ProviderError {
    /// Typed code for the failure. Stale and malformed checkpoints share
    /// the precondition code. Outside retention shares the precondition
    /// code and travels with an explicit snapshot-required signal.
    /// Unknown streams and unknown operations share the unimplemented
    /// code. Each mapping is terminal for the affected call or stream.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownStream | Self::UnknownOperation => ErrorCode::Unimplemented,
            Self::Unconfirmed | Self::StaleCheckpoint | Self::OutsideRetention => {
                ErrorCode::FailedPrecondition
            }
            Self::Unauthorized => ErrorCode::PermissionDenied,
            Self::Unauthenticated => ErrorCode::Unauthenticated,
            Self::Overloaded => ErrorCode::ResourceExhausted,
            Self::TransportLost => ErrorCode::Unavailable,
            Self::DeadlineExpired => ErrorCode::DeadlineExceeded,
            Self::Internal => ErrorCode::Internal,
        }
    }

    /// True when recovery follows the snapshot path.
    pub fn requires_snapshot(&self) -> bool {
        matches!(self, Self::OutsideRetention)
    }
}

impl From<ProviderError> for ErrorCode {
    fn from(e: ProviderError) -> Self {
        e.code()
    }
}

/// One bounded replay page toward the catch-up boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPage {
    /// Checkpoint this page continues from.
    pub predecessor_checkpoint: Vec<u8>,
    /// Checkpoint this page advances to.
    pub result_checkpoint: Vec<u8>,
    /// Page cursor stating whether more pages remain. Empty means no
    /// further page.
    pub continuation_marker: Vec<u8>,
    /// Point where recovered history meets live delivery.
    pub catchup_boundary: Vec<u8>,
    /// Opaque batch bytes. Bounded by the deployment-documented page
    /// batch and byte limits.
    pub batch_payloads: Vec<Vec<u8>>,
}

/// Snapshot offer under a provider-proven boundary checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotOffer {
    /// Offered snapshot selector, opaque to the coordinator.
    pub snapshot_handle: Vec<u8>,
    /// Provider-proven boundary subsequent batches chain from.
    pub boundary_checkpoint: Vec<u8>,
    /// Page count bound for this offer.
    pub total_pages: u32,
    /// Byte bound for each page.
    pub page_bytes_max: u32,
}

/// Application supply of bounded replay pages.
///
/// Storage, retention, and page assembly remain above the coordinator. The
/// coordinator never calls this trait. The application calls it when the
/// coordinator emits a recovery-needed action.
pub trait ReplayProvider {
    /// Returns one bounded page continuing from `from`.
    fn replay_page(
        &self,
        from: &ProfileCheckpoint,
        max_batches: u32,
        max_bytes: u32,
    ) -> Result<ReplayPage, ProviderError>;
}

/// Application supply of snapshot transfer pages.
///
/// Snapshot formats remain application-defined. The coordinator defines
/// only the transfer, boundary, and confirmation mechanics. The
/// coordinator never calls this trait. The application calls it when the
/// coordinator emits a snapshot-required action.
pub trait SnapshotProvider {
    /// Offers a snapshot under a provider-proven boundary checkpoint.
    fn offer_snapshot(&self, committed: &CommittedPosition)
        -> Result<SnapshotOffer, ProviderError>;
    /// Returns one bounded snapshot page for storage without
    /// interpretation.
    fn snapshot_page(
        &self,
        snapshot_handle: &[u8],
        page_index: u32,
    ) -> Result<Vec<u8>, ProviderError>;
}

/// Application authorization at every profile hook.
///
/// The coordinator never calls this trait. The application evaluates the
/// bound principal at subscribe, replay, snapshot offer and transfer, and
/// continuation, catch-up, and confirm. Checkpoint and selector bytes are
/// never authority by themselves.
pub trait RecoveryAuthorizer {
    /// Authorizes establishment for the stream selector.
    fn authorize_subscribe(&self, stream_selector: &[u8]) -> Result<(), ProviderError>;
    /// Authorizes bounded replay from the checkpoint.
    fn authorize_replay(&self, from: &ProfileCheckpoint) -> Result<(), ProviderError>;
    /// Authorizes snapshot offer and transfer at the committed position.
    fn authorize_snapshot(&self, committed: &CommittedPosition) -> Result<(), ProviderError>;
    /// Authorizes confirmation of the checkpoint.
    fn authorize_confirm(&self, checkpoint: &ProfileCheckpoint) -> Result<(), ProviderError>;
}

/// Coordinator over one stream's committed progress.
///
/// The coordinator tracks the committed cursor only. The application
/// applies effects, persists checkpoints, and reports inputs.
///
/// Cursor bytes are compared by equality only. Generation is the
/// continuity epoch and is compared exactly. Generations move forward
/// only: a confirmation from an older generation never rolls back newer
/// progress and instead reports the current position for recovery.
/// Generation changes happen only through snapshot confirms.
///
/// Snapshot gating: once [`ProfileInput::ContinuationExpired`] reports a
/// live stream, the pending gate is set. While set, otherwise-valid
/// [`ProfileInput::BatchValidated`] inputs return
/// [`ProfileAction::SnapshotRequired`] instead of `CommitCheckpoint`, so
/// committed progress cannot advance via the batch path until a snapshot
/// with a new generation confirms via [`Self::confirm_persisted`].
/// New-generation [`ProfileInput::SnapshotInstalled`] remains admissible
/// while pending as the snapshot path.
///
/// Duplicate tolerance: a validated batch or snapshot whose result cursor
/// already equals the committed cursor is tolerated with no actions and
/// no mutation. A duplicate is never a violation. Duplicate confirmation
/// is idempotent and leaves progress unchanged. An older duplicate whose
/// result cursor no longer equals the committed cursor returns a
/// recovery-needed action; the application holds a bounded recent-result
/// cache keyed by checkpoint bytes to answer such duplicates without
/// re-applying effects. The coordinator compares bytes by equality only
/// and never orders or parses cursor bytes.
///
/// Stop-and-wait: at most one committable checkpoint is pending
/// confirmation. A different committable checkpoint while pending returns a
/// recovery-needed action without replacing the pending offer.
#[derive(Debug, Clone)]
pub struct ProfileRecovery {
    stream_selector: Vec<u8>,
    generation: u64,
    committed: Vec<u8>,
    snapshot_pending: bool,
    pending: Option<PendingOffer>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingOffer {
    checkpoint: ProfileCheckpoint,
    is_snapshot: bool,
}

/// Committable checkpoint returned by observe with its snapshot source.
///
/// Tracks whether the pending checkpoint was offered through the batch
/// path or the snapshot path. New-generation progress advances only
/// through the snapshot path.

impl ProfileRecovery {
    /// Starts tracking from the last confirmed position.
    pub fn new(stream_selector: Vec<u8>, generation: u64, committed: Vec<u8>) -> Self {
        Self {
            stream_selector,
            generation,
            committed,
            snapshot_pending: false,
            pending: None,
        }
    }

    /// Last confirmed cursor bytes.
    pub fn committed(&self) -> &[u8] {
        &self.committed
    }

    /// Continuity generation of the committed cursor.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Stream selector tracked by this coordinator.
    pub fn stream_selector(&self) -> &[u8] {
        &self.stream_selector
    }

    /// Last confirmed position as an owned value.
    pub fn position(&self) -> CommittedPosition {
        CommittedPosition {
            stream_selector: self.stream_selector.clone(),
            generation: self.generation,
            committed: self.committed.clone(),
        }
    }

    /// Whether a snapshot is required before batch commits may resume.
    pub fn snapshot_pending(&self) -> bool {
        self.snapshot_pending
    }

    fn recovery_needed(&self) -> Vec<ProfileAction> {
        vec![ProfileAction::RecoveryNeeded {
            stream_selector: self.stream_selector.clone(),
            committed: self.committed.clone(),
        }]
    }

    fn snapshot_required(&self) -> Vec<ProfileAction> {
        vec![ProfileAction::SnapshotRequired {
            stream_selector: self.stream_selector.clone(),
            committed: self.committed.clone(),
        }]
    }

    /// Observes coordinator inputs. A validated batch returns a
    /// committable action without advancing committed progress; the caller
    /// advances via [`Self::confirm_persisted`] only after the checkpoint
    /// and its effects are durably persisted.
    ///
    /// Selectors for other streams are ignored with no actions and no
    /// mutation, like gap reports for other streams. Same-generation
    /// batches and snapshots must continue exactly from the committed
    /// cursor. New-generation snapshots may start from a fresh base as
    /// their proven synchronization cut. Stale generations and
    /// non-contiguous same-generation checkpoints return a recovery-needed
    /// action instead of a committable action.
    ///
    /// Stop-and-wait: while one committable checkpoint is pending, a
    /// different committable checkpoint returns a recovery-needed action
    /// without replacing the pending offer. Gap, continuity-loss, and
    /// continuation-expiry reports invalidate the pending offer. An older
    /// duplicate whose result cursor no longer equals the committed cursor
    /// returns a recovery-needed action; the application answers it from a
    /// bounded recent-result cache keyed by checkpoint bytes.
    pub fn observe(&mut self, input: ProfileInput) -> Vec<ProfileAction> {
        match input {
            ProfileInput::BatchValidated { checkpoint } => {
                if checkpoint.stream_selector != self.stream_selector {
                    return vec![];
                }
                if checkpoint.generation != self.generation {
                    return self.recovery_needed();
                }
                if checkpoint.result_cursor == self.committed {
                    return vec![];
                }
                if self.snapshot_pending {
                    return self.snapshot_required();
                }
                if checkpoint.base_cursor != self.committed {
                    return self.recovery_needed();
                }
                if let Some(offer) = &self.pending {
                    if offer.checkpoint != checkpoint {
                        return self.recovery_needed();
                    }
                }
                self.pending = Some(PendingOffer {
                    checkpoint: checkpoint.clone(),
                    is_snapshot: false,
                });
                vec![ProfileAction::CommitCheckpoint { checkpoint }]
            }
            ProfileInput::GapDetected {
                stream_selector,
                expected_base: _,
                observed_base: _,
            } => {
                if stream_selector != self.stream_selector {
                    return vec![];
                }
                self.pending = None;
                self.recovery_needed()
            }
            ProfileInput::ContinuityLost {
                stream_selector,
                committed: _,
            } => {
                if stream_selector != self.stream_selector {
                    return vec![];
                }
                self.pending = None;
                self.recovery_needed()
            }
            ProfileInput::ContinuationExpired {
                stream_selector,
                committed,
            } => {
                if stream_selector != self.stream_selector {
                    return vec![];
                }
                // Only continuation expiry matching committed progress sets
                // the pending gate. Expiry carrying another committed cursor
                // is ignored with no actions and no mutation.
                if committed != self.committed {
                    return vec![];
                }
                self.pending = None;
                self.snapshot_pending = true;
                self.snapshot_required()
            }
            ProfileInput::SnapshotInstalled { checkpoint } => {
                if checkpoint.stream_selector != self.stream_selector {
                    return vec![];
                }
                if checkpoint.generation < self.generation {
                    return self.recovery_needed();
                }
                if checkpoint.generation == self.generation {
                    if checkpoint.result_cursor == self.committed {
                        return vec![];
                    }
                    if self.snapshot_pending {
                        return self.snapshot_required();
                    }
                    if checkpoint.base_cursor != self.committed {
                        return self.recovery_needed();
                    }
                    if let Some(offer) = &self.pending {
                        if offer.checkpoint != checkpoint {
                            return self.recovery_needed();
                        }
                    }
                    self.pending = Some(PendingOffer {
                        checkpoint: checkpoint.clone(),
                        is_snapshot: true,
                    });
                    return vec![ProfileAction::CommitCheckpoint { checkpoint }];
                }
                if let Some(offer) = &self.pending {
                    if offer.checkpoint != checkpoint {
                        return self.recovery_needed();
                    }
                }
                self.pending = Some(PendingOffer {
                    checkpoint: checkpoint.clone(),
                    is_snapshot: true,
                });
                vec![ProfileAction::CommitCheckpoint { checkpoint }]
            }
        }
    }

    /// Confirms the application durably persisted `checkpoint` and its
    /// effects. Advances persisted progress on success; on mismatch the
    /// checkpoint is not adopted and a recovery-needed action retries from
    /// the last persisted position. Call only with the checkpoint
    /// previously returned as a committable action; a persistence failure
    /// is reported by simply not calling this method. A checkpoint never
    /// returned as committable is rejected without advancing committed
    /// progress.
    ///
    /// Selectors for other streams are ignored with no actions and no
    /// mutation. Duplicate confirmation of the committed cursor is
    /// idempotent with no actions.
    ///
    /// Snapshot confirms carrying a new generation follow their own
    /// continuity rules: only the stream selector is validated, so a
    /// snapshot whose base differs from the pre-snapshot committed cursor
    /// is accepted as its proven synchronization cut. Same-generation
    /// checkpoints must continue exactly from the committed cursor.
    /// Generations move forward only. New-generation progress advances
    /// only through the snapshot path.
    ///
    /// While the pending gate is set, same-generation confirmations are
    /// blocked with a snapshot-required action instead of advancing, so
    /// only a new-generation snapshot confirm clears the gate.
    ///
    /// Stop-and-wait: only the pending committable checkpoint confirms.
    /// A different checkpoint returns a recovery-needed action without
    /// advancing committed progress.
    pub fn confirm_persisted(&mut self, checkpoint: &ProfileCheckpoint) -> Vec<ProfileAction> {
        if checkpoint.stream_selector != self.stream_selector {
            return vec![];
        }
        if checkpoint.generation < self.generation {
            return self.recovery_needed();
        }
        if checkpoint.generation == self.generation {
            if checkpoint.result_cursor == self.committed {
                return vec![];
            }
            if self.snapshot_pending {
                return self.snapshot_required();
            }
            // Only a checkpoint previously returned as committable advances
            // committed progress.
            match &self.pending {
                Some(offer) if offer.checkpoint == *checkpoint => {}
                _ => return self.recovery_needed(),
            }
            if checkpoint.base_cursor != self.committed {
                return self.recovery_needed();
            }
            self.committed = checkpoint.result_cursor.clone();
            self.pending = None;
            return vec![];
        }
        // New-generation progress advances only through a snapshot
        // previously returned as committable through the snapshot path.
        match &self.pending {
            Some(offer) if offer.checkpoint == *checkpoint && offer.is_snapshot => {}
            _ => return self.recovery_needed(),
        }
        self.generation = checkpoint.generation;
        self.committed = checkpoint.result_cursor.clone();
        self.snapshot_pending = false;
        self.pending = None;
        vec![]
    }

    /// Read-only pre-validation for [`Self::confirm_persisted`].
    ///
    /// Returns true only when [`Self::confirm_persisted`] would advance
    /// committed progress (empty result with mutation). Idempotent
    /// duplicates, rejected checkpoints, and untracked selectors return
    /// false. No mutation.
    pub fn can_confirm(&self, checkpoint: &ProfileCheckpoint) -> bool {
        if checkpoint.stream_selector != self.stream_selector {
            return false;
        }
        if checkpoint.generation < self.generation {
            return false;
        }
        if checkpoint.generation == self.generation {
            if checkpoint.result_cursor == self.committed {
                return false;
            }
            if self.snapshot_pending {
                return false;
            }
            match &self.pending {
                Some(offer) if offer.checkpoint == *checkpoint => {}
                _ => return false,
            }
            if checkpoint.base_cursor != self.committed {
                return false;
            }
            return true;
        }
        match &self.pending {
            Some(offer) if offer.checkpoint == *checkpoint && offer.is_snapshot => true,
            _ => false,
        }
    }

    /// Alias for [`Self::confirm_persisted`].
    pub fn confirm(&mut self, checkpoint: &ProfileCheckpoint) -> Vec<ProfileAction> {
        self.confirm_persisted(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector() -> Vec<u8> {
        b"stream-a".to_vec()
    }

    fn checkpoint(base: &[u8], result: &[u8]) -> ProfileCheckpoint {
        ProfileCheckpoint {
            stream_selector: selector(),
            generation: 7,
            base_cursor: base.to_vec(),
            result_cursor: result.to_vec(),
        }
    }

    fn coordinator(committed: &[u8]) -> ProfileRecovery {
        ProfileRecovery::new(selector(), 7, committed.to_vec())
    }

    #[test]
    fn profile_commit_order_persist_then_confirm() {
        let mut r = coordinator(b"cursor-40");
        let cp = checkpoint(b"cursor-40", b"cursor-43");
        let actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ProfileAction::CommitCheckpoint { .. }));
        // Observing alone must not advance committed progress.
        assert_eq!(r.committed(), b"cursor-40");
        let confirmed = r.confirm_persisted(&cp);
        assert!(confirmed.is_empty());
        assert_eq!(r.committed(), b"cursor-43");
        assert_eq!(r.generation(), 7);
        // Confirm alias reports the same idempotent result on duplicates.
        let again = r.confirm(&cp);
        assert!(again.is_empty());
        assert_eq!(r.committed(), b"cursor-43");
    }

    #[test]
    fn profile_gap_requires_recovery_without_advancing() {
        let mut r = coordinator(b"cursor-40");
        // Observed base does not continue from committed: gap path.
        let gapped = checkpoint(b"cursor-45", b"cursor-47");
        let actions = r.observe(ProfileInput::BatchValidated { checkpoint: gapped });
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(r.committed(), b"cursor-40");
        if let ProfileAction::RecoveryNeeded {
            stream_selector,
            committed,
        } = &actions[0]
        {
            assert_eq!(stream_selector, &selector());
            assert_eq!(committed, b"cursor-40");
        } else {
            panic!("expected recovery-needed action");
        }
        // Explicit gap report for the tracked stream also recovers.
        let reported = r.observe(ProfileInput::GapDetected {
            stream_selector: selector(),
            expected_base: b"cursor-40".to_vec(),
            observed_base: b"cursor-45".to_vec(),
        });
        assert!(matches!(reported[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(r.committed(), b"cursor-40");
        // Gap reports for other selectors are ignored.
        let foreign = r.observe(ProfileInput::GapDetected {
            stream_selector: b"other".to_vec(),
            expected_base: b"cursor-40".to_vec(),
            observed_base: b"cursor-45".to_vec(),
        });
        assert!(foreign.is_empty());
        assert_eq!(r.committed(), b"cursor-40");
    }

    #[test]
    fn profile_generation_change_only_via_snapshot() {
        let mut r = coordinator(b"cursor-40");
        // Batch from another generation is never committable via the batch path.
        let next_gen_batch = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"cursor-40".to_vec(),
            result_cursor: b"cursor-43".to_vec(),
        };
        let actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: next_gen_batch,
        });
        assert!(matches!(actions[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(r.generation(), 7);
        assert_eq!(r.committed(), b"cursor-40");
        // Snapshot from a stale generation cannot roll progress back.
        let stale = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 6,
            base_cursor: b"cursor-00".to_vec(),
            result_cursor: b"cursor-09".to_vec(),
        };
        let stale_actions = r.observe(ProfileInput::SnapshotInstalled { checkpoint: stale });
        assert!(matches!(
            stale_actions[0],
            ProfileAction::RecoveryNeeded { .. }
        ));
        // Snapshot under a new generation may start from a fresh base and,
        // once confirmed, moves the continuity epoch forward.
        let snap = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"boundary-00".to_vec(),
            result_cursor: b"boundary-100".to_vec(),
        };
        let snap_actions = r.observe(ProfileInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        assert!(matches!(
            snap_actions[0],
            ProfileAction::CommitCheckpoint { .. }
        ));
        assert_eq!(r.generation(), 7);
        assert_eq!(r.committed(), b"cursor-40");
        assert!(r.confirm_persisted(&snap).is_empty());
        assert_eq!(r.generation(), 8);
        assert_eq!(r.committed(), b"boundary-100");
        assert!(!r.snapshot_pending());
        // Batches now chain from the snapshot boundary under the new generation.
        let next = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"boundary-100".to_vec(),
            result_cursor: b"boundary-103".to_vec(),
        };
        let resumed = r.observe(ProfileInput::BatchValidated { checkpoint: next });
        assert!(matches!(resumed[0], ProfileAction::CommitCheckpoint { .. }));
    }

    #[test]
    fn profile_snapshot_gate_blocks_batches_until_snapshot_confirmed() {
        let mut r = coordinator(b"cursor-40");
        let expired = r.observe(ProfileInput::ContinuationExpired {
            stream_selector: selector(),
            committed: b"cursor-40".to_vec(),
        });
        assert!(matches!(expired[0], ProfileAction::SnapshotRequired { .. }));
        assert!(r.snapshot_pending());
        // Otherwise-valid batch must not commit while the gate holds.
        let batch = checkpoint(b"cursor-40", b"cursor-43");
        let blocked = r.observe(ProfileInput::BatchValidated {
            checkpoint: batch.clone(),
        });
        assert!(matches!(blocked[0], ProfileAction::SnapshotRequired { .. }));
        assert_eq!(r.committed(), b"cursor-40");
        // Same-generation confirm is blocked as well; only a new-generation
        // snapshot confirm clears the gate.
        let blocked_confirm = r.confirm_persisted(&batch);
        assert!(matches!(
            blocked_confirm[0],
            ProfileAction::SnapshotRequired { .. }
        ));
        assert_eq!(r.committed(), b"cursor-40");
        assert!(r.snapshot_pending());
        // Same-generation snapshot is held by the gate.
        let same_gen = checkpoint(b"cursor-40", b"cursor-43");
        let held = r.observe(ProfileInput::SnapshotInstalled {
            checkpoint: same_gen,
        });
        assert!(matches!(held[0], ProfileAction::SnapshotRequired { .. }));
        // New-generation snapshot commits and, once confirmed, clears the gate.
        let snap = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"boundary-00".to_vec(),
            result_cursor: b"boundary-100".to_vec(),
        };
        let snap_actions = r.observe(ProfileInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        assert!(matches!(
            snap_actions[0],
            ProfileAction::CommitCheckpoint { .. }
        ));
        assert!(r.confirm_persisted(&snap).is_empty());
        assert!(!r.snapshot_pending());
        assert_eq!(r.generation(), 8);
        assert_eq!(r.committed(), b"boundary-100");
    }

    #[test]
    fn profile_duplicate_tolerated_across_boundary() {
        let mut r = coordinator(b"cursor-40");
        let cp = checkpoint(b"cursor-40", b"cursor-43");
        let actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert!(matches!(actions[0], ProfileAction::CommitCheckpoint { .. }));
        assert!(r.confirm_persisted(&cp).is_empty());
        assert_eq!(r.committed(), b"cursor-43");
        // Replayed batch whose result is already committed is tolerated.
        let duplicate = checkpoint(b"cursor-40", b"cursor-43");
        let tolerated = r.observe(ProfileInput::BatchValidated {
            checkpoint: duplicate,
        });
        assert!(tolerated.is_empty());
        assert_eq!(r.committed(), b"cursor-43");
        // Live batch repeating the committed result is tolerated as well.
        let live_duplicate = checkpoint(b"cursor-43", b"cursor-43");
        let tolerated_live = r.observe(ProfileInput::BatchValidated {
            checkpoint: live_duplicate,
        });
        assert!(tolerated_live.is_empty());
        // Duplicate confirmation is idempotent.
        let reconfirm = r.confirm_persisted(&cp);
        assert!(reconfirm.is_empty());
        assert_eq!(r.committed(), b"cursor-43");
        assert_eq!(r.generation(), 7);
    }

    #[test]
    fn profile_stale_continuation_expiry_ignored() {
        let mut r = coordinator(b"cursor-40");
        let cp = checkpoint(b"cursor-40", b"cursor-43");
        let actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert!(matches!(actions[0], ProfileAction::CommitCheckpoint { .. }));
        assert!(r.confirm_persisted(&cp).is_empty());
        assert_eq!(r.committed(), b"cursor-43");
        // Continuation expiry carrying the previous committed cursor is
        // ignored with no actions and no mutation of the pending gate.
        let stale = r.observe(ProfileInput::ContinuationExpired {
            stream_selector: selector(),
            committed: b"cursor-40".to_vec(),
        });
        assert!(stale.is_empty());
        assert!(!r.snapshot_pending());
        assert_eq!(r.committed(), b"cursor-43");
        assert_eq!(r.generation(), 7);
        // Batch path remains committable from the committed cursor.
        let next = checkpoint(b"cursor-43", b"cursor-46");
        let offered = r.observe(ProfileInput::BatchValidated { checkpoint: next });
        assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
        assert!(!r.snapshot_pending());
    }

    #[test]
    fn profile_unoffered_snapshot_confirm_rejected() {
        let mut r = coordinator(b"cursor-40");
        let snap = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"boundary-00".to_vec(),
            result_cursor: b"boundary-100".to_vec(),
        };
        // Snapshot never returned as committable through the snapshot path
        // is rejected without advancing generation or committed progress.
        let rejected = r.confirm_persisted(&snap);
        assert!(matches!(rejected[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(r.generation(), 7);
        assert_eq!(r.committed(), b"cursor-40");
        assert!(!r.snapshot_pending());
        // Matching continuation expiry sets the pending gate.
        let expired = r.observe(ProfileInput::ContinuationExpired {
            stream_selector: selector(),
            committed: b"cursor-40".to_vec(),
        });
        assert!(matches!(expired[0], ProfileAction::SnapshotRequired { .. }));
        assert!(r.snapshot_pending());
        // Un-offered snapshot confirm does not clear the pending gate.
        let rejected_while_pending = r.confirm_persisted(&snap);
        assert!(matches!(
            rejected_while_pending[0],
            ProfileAction::RecoveryNeeded { .. }
        ));
        assert_eq!(r.generation(), 7);
        assert_eq!(r.committed(), b"cursor-40");
        assert!(r.snapshot_pending());
    }

    #[test]
    fn profile_offered_snapshot_confirm_advances_and_clears_gate() {
        let mut r = coordinator(b"cursor-40");
        let expired = r.observe(ProfileInput::ContinuationExpired {
            stream_selector: selector(),
            committed: b"cursor-40".to_vec(),
        });
        assert!(matches!(expired[0], ProfileAction::SnapshotRequired { .. }));
        assert!(r.snapshot_pending());
        let snap = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"boundary-00".to_vec(),
            result_cursor: b"boundary-100".to_vec(),
        };
        // Snapshot returned as committable through the snapshot path.
        let offered = r.observe(ProfileInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
        assert!(r.snapshot_pending());
        // Confirm advances generation and committed progress and clears
        // the pending gate.
        assert!(r.confirm_persisted(&snap).is_empty());
        assert!(!r.snapshot_pending());
        assert_eq!(r.generation(), 8);
        assert_eq!(r.committed(), b"boundary-100");
    }

    #[test]
    fn profile_stop_and_wait_pipelined_second_rejected_first_confirm_succeeds() {
        let mut r = coordinator(b"cursor-40");
        let first = checkpoint(b"cursor-40", b"cursor-43");
        let second = checkpoint(b"cursor-40", b"cursor-44");
        let first_actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: first.clone(),
        });
        assert!(matches!(
            first_actions[0],
            ProfileAction::CommitCheckpoint { .. }
        ));
        // Competing offer from the same base with a different result reaches
        // the pending-offer check, so it returns recovery-needed without
        // replacing the pending offer.
        let second_actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: second.clone(),
        });
        assert!(matches!(
            second_actions[0],
            ProfileAction::RecoveryNeeded { .. }
        ));
        // First confirm still succeeds under stop-and-wait.
        assert!(r.confirm_persisted(&first).is_empty());
        assert_eq!(r.committed(), b"cursor-43");
    }

    #[test]
    fn profile_gap_invalidates_pending_offer() {
        let mut r = coordinator(b"cursor-40");
        let cp = checkpoint(b"cursor-40", b"cursor-43");
        let actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert!(matches!(actions[0], ProfileAction::CommitCheckpoint { .. }));
        let gap = r.observe(ProfileInput::GapDetected {
            stream_selector: selector(),
            expected_base: b"cursor-40".to_vec(),
            observed_base: b"cursor-45".to_vec(),
        });
        assert!(matches!(gap[0], ProfileAction::RecoveryNeeded { .. }));
        // Pending offer was invalidated, so confirming it no longer advances.
        let after_gap = r.confirm_persisted(&cp);
        assert!(matches!(after_gap[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(r.committed(), b"cursor-40");
        // Continuity loss invalidates a pending offer the same way.
        let mut r = coordinator(b"cursor-40");
        let actions = r.observe(ProfileInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert!(matches!(actions[0], ProfileAction::CommitCheckpoint { .. }));
        let lost = r.observe(ProfileInput::ContinuityLost {
            stream_selector: selector(),
            committed: b"cursor-40".to_vec(),
        });
        assert!(matches!(lost[0], ProfileAction::RecoveryNeeded { .. }));
        let after_lost = r.confirm_persisted(&cp);
        assert!(matches!(
            after_lost[0],
            ProfileAction::RecoveryNeeded { .. }
        ));
        assert_eq!(r.committed(), b"cursor-40");
    }

    #[test]
    fn profile_provider_error_maps_to_typed_codes() {
        assert_eq!(
            ProviderError::UnknownStream.code(),
            ErrorCode::Unimplemented
        );
        assert_eq!(
            ProviderError::UnknownOperation.code(),
            ErrorCode::Unimplemented
        );
        assert_eq!(
            ProviderError::Unconfirmed.code(),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            ProviderError::StaleCheckpoint.code(),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(
            ProviderError::OutsideRetention.code(),
            ErrorCode::FailedPrecondition
        );
        assert!(ProviderError::OutsideRetention.requires_snapshot());
        assert!(!ProviderError::StaleCheckpoint.requires_snapshot());
        assert_eq!(
            ProviderError::Unauthorized.code(),
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            ProviderError::Unauthenticated.code(),
            ErrorCode::Unauthenticated
        );
        assert_eq!(
            ProviderError::Overloaded.code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(ProviderError::TransportLost.code(), ErrorCode::Unavailable);
        assert_eq!(
            ProviderError::DeadlineExpired.code(),
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(ProviderError::Internal.code(), ErrorCode::Internal);
        let code: ErrorCode = ProviderError::Overloaded.into();
        assert_eq!(code, ErrorCode::ResourceExhausted);
    }
}
