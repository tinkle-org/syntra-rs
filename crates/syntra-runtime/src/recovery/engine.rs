//! Reusable recovery orchestration above the profile coordinator.
//!
//! The profile coordinator tracks one stream. This engine owns one
//! coordinator per stream selector and adds caller-driven orchestration
//! state that stays transport-agnostic:
//!
//! - Per-stream coordinator map keyed by stream selector bytes.
//! - Fixed catch-up boundary per stream. The subscribed boundary from
//!   `RecoverySubscribeResponse.catchup_boundary` is recorded via
//!   [`ProfileEngine::set_subscribed_boundary`]; when set, every replay
//!   page and every catch-up completion boundary must equal it before held
//!   live batches are released (SYN-URP-023). Replay pages retain a
//!   backwards-compatible fallback where the first observed page records
//!   its boundary when no subscribed boundary was recorded; spec-compliant
//!   callers must still record the subscribed boundary first. Completion
//!   has no such fallback and returns recovery-needed until the subscribed
//!   boundary is recorded, so an unvalidated completion can never become
//!   the trusted boundary. A different or empty boundary returns a
//!   recovery-needed action and leaves the recorded boundary unchanged. The
//!   caller clears the boundary when recovery completes. Initial
//!   subscriptions (empty `start_checkpoint`) skip replay and validate
//!   completion directly against the subscribed boundary.
//! - Loss-counter polling hook. The caller supplies its cumulative loss
//!   count; an increment maps to a gap report for the stream.
//! - Stop-and-wait confirm tracking. The caller drives observe and
//!   confirm; the engine exposes the pending committable checkpoint.
//! - Snapshot gate surfacing. The caller reads whether the coordinator
//!   requires a snapshot before batch commits may resume.
//!
//! The engine never performs calls, never persists, and never interprets
//! selector, cursor, or boundary bytes beyond equality. The application
//! selects recovery calls, constructs payloads, performs requests,
//! persists checkpoints, and installs snapshots.

use std::collections::HashMap;

use super::profile::{
    CommittedPosition, ProfileAction, ProfileCheckpoint, ProfileInput, ProfileRecovery, ReplayPage,
};

/// Per-stream orchestration state.
#[derive(Debug)]
struct StreamState {
    recovery: ProfileRecovery,
    catchup_boundary: Option<Vec<u8>>,
    last_loss: u64,
    pending: Option<ProfileCheckpoint>,
}

/// Transport-agnostic orchestration over per-stream coordinators.
///
/// Owns one [`ProfileRecovery`] per stream selector. All methods are
/// synchronous and driver-free.
#[derive(Debug, Default)]
pub struct ProfileEngine {
    streams: HashMap<Vec<u8>, StreamState>,
}

impl ProfileEngine {
    /// Empty engine with no tracked streams.
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Tracks a stream from its last confirmed position, replacing any
    /// existing state for the selector. Resets the catch-up boundary,
    /// loss counter, and pending offer for the stream.
    pub fn insert_stream(&mut self, stream_selector: Vec<u8>, generation: u64, committed: Vec<u8>) {
        self.streams.insert(
            stream_selector.clone(),
            StreamState {
                recovery: ProfileRecovery::new(stream_selector, generation, committed),
                catchup_boundary: None,
                last_loss: 0,
                pending: None,
            },
        );
    }

    /// Stops tracking the stream. Returns true when a stream was removed.
    pub fn remove_stream(&mut self, stream_selector: &[u8]) -> bool {
        self.streams.remove(stream_selector).is_some()
    }

    /// True when the selector is tracked.
    pub fn contains_stream(&self, stream_selector: &[u8]) -> bool {
        self.streams.contains_key(stream_selector)
    }

    /// Number of tracked streams.
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// True when no streams are tracked.
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Last confirmed cursor for the stream, if tracked.
    pub fn committed(&self, stream_selector: &[u8]) -> Option<&[u8]> {
        self.streams
            .get(stream_selector)
            .map(|s| s.recovery.committed())
    }

    /// Continuity generation for the stream, if tracked.
    pub fn generation(&self, stream_selector: &[u8]) -> Option<u64> {
        self.streams
            .get(stream_selector)
            .map(|s| s.recovery.generation())
    }

    /// Last confirmed position for the stream, if tracked.
    pub fn position(&self, stream_selector: &[u8]) -> Option<CommittedPosition> {
        self.streams
            .get(stream_selector)
            .map(|s| s.recovery.position())
    }

    /// Pending committable checkpoint awaiting confirmation, if any.
    ///
    /// Set when [`Self::observe`] returns a commit action. Cleared on
    /// successful confirmation and on gap, continuity-loss, and matched
    /// continuation-expiry reports, mirroring the coordinator.
    pub fn pending(&self, stream_selector: &[u8]) -> Option<&ProfileCheckpoint> {
        self.streams
            .get(stream_selector)
            .and_then(|s| s.pending.as_ref())
    }

    /// Whether the stream requires a snapshot before batch commits resume.
    /// False for untracked selectors.
    pub fn snapshot_pending(&self, stream_selector: &[u8]) -> bool {
        self.streams
            .get(stream_selector)
            .map(|s| s.recovery.snapshot_pending())
            .unwrap_or(false)
    }

    /// Recorded catch-up boundary for the stream, if any.
    pub fn catchup_boundary(&self, stream_selector: &[u8]) -> Option<&[u8]> {
        self.streams
            .get(stream_selector)
            .and_then(|s| s.catchup_boundary.as_deref())
    }

    /// Forgets the recorded catch-up boundary for the stream.
    /// No effect for untracked selectors.
    pub fn clear_catchup_boundary(&mut self, stream_selector: &[u8]) {
        if let Some(state) = self.streams.get_mut(stream_selector) {
            state.catchup_boundary = None;
        }
    }

    /// Last loss count recorded by [`Self::poll_loss`], if tracked.
    pub fn last_loss(&self, stream_selector: &[u8]) -> Option<u64> {
        self.streams.get(stream_selector).map(|s| s.last_loss)
    }

    fn selector_of(input: &ProfileInput) -> &[u8] {
        match input {
            ProfileInput::BatchValidated { checkpoint }
            | ProfileInput::SnapshotInstalled { checkpoint } => &checkpoint.stream_selector,
            ProfileInput::GapDetected {
                stream_selector, ..
            }
            | ProfileInput::ContinuityLost {
                stream_selector, ..
            }
            | ProfileInput::ContinuationExpired {
                stream_selector, ..
            } => stream_selector,
        }
    }

    /// Observes a coordinator input on its stream.
    ///
    /// Untracked selectors return no actions with no mutation. Otherwise
    /// delegates to the stream coordinator without changing its semantics
    /// and mirrors stop-and-wait tracking: a commit action records the
    /// pending offer; gap, continuity-loss, and matched continuation-expiry
    /// reports clear it.
    pub fn observe(&mut self, input: ProfileInput) -> Vec<ProfileAction> {
        let key = Self::selector_of(&input).to_vec();
        let state = match self.streams.get_mut(&key) {
            Some(state) => state,
            None => return vec![],
        };
        let is_gap_like = matches!(
            input,
            ProfileInput::GapDetected { .. }
                | ProfileInput::ContinuityLost { .. }
                | ProfileInput::ContinuationExpired { .. }
        );
        let actions = state.recovery.observe(input);
        if let Some(ProfileAction::CommitCheckpoint { checkpoint }) = actions.first() {
            state.pending = Some(checkpoint.clone());
        } else if is_gap_like && !actions.is_empty() {
            state.pending = None;
        }
        actions
    }

    /// Confirms durable persistence of a previously offered checkpoint.
    ///
    /// Untracked selectors return no actions with no mutation. Otherwise
    /// delegates to the stream coordinator. An empty result (advance or
    /// idempotent duplicate) clears the mirrored pending offer only when
    /// the confirmed checkpoint matches it, preserving a different pending
    /// offer after an older duplicate confirmation; a recovery-needed or
    /// snapshot-required result leaves it unchanged.
    /// A generation advance also forgets the recorded catch-up boundary,
    /// since the new generation carries its own synchronization cut.
    pub fn confirm_persisted(&mut self, checkpoint: &ProfileCheckpoint) -> Vec<ProfileAction> {
        let state = match self.streams.get_mut(&checkpoint.stream_selector) {
            Some(state) => state,
            None => return vec![],
        };
        let before = state.recovery.generation();
        let actions = state.recovery.confirm_persisted(checkpoint);
        if actions.is_empty() {
            if state.pending.as_ref() == Some(checkpoint) {
                state.pending = None;
            }
            if state.recovery.generation() != before {
                state.catchup_boundary = None;
            }
        }
        actions
    }

    /// Read-only pre-validation for [`Self::confirm_persisted`].
    ///
    /// Returns true only when [`Self::confirm_persisted`] would advance
    /// committed progress. False for untracked selectors, idempotent
    /// duplicates, snapshot-gated or rejected checkpoints. No mutation.
    pub fn can_confirm(&self, checkpoint: &ProfileCheckpoint) -> bool {
        match self.streams.get(&checkpoint.stream_selector) {
            Some(state) => state.recovery.can_confirm(checkpoint),
            None => false,
        }
    }

    /// Alias for [`Self::confirm_persisted`].
    pub fn confirm(&mut self, checkpoint: &ProfileCheckpoint) -> Vec<ProfileAction> {
        self.confirm_persisted(checkpoint)
    }

    /// Polls a caller-supplied cumulative loss count for the stream.
    ///
    /// When `loss_count` exceeds the last recorded count, records it and
    /// maps the increment to a gap report from the committed cursor. The
    /// observed base is unknown at poll time, so the report carries the
    /// committed cursor as expected base and empty observed base; the
    /// coordinator treats any gap report for the stream as recovery-needed
    /// and invalidates the pending offer. Equal counts return no actions.
    /// A decreased count is treated as a counter reset: it is recorded
    /// with no actions.
    pub fn poll_loss(&mut self, stream_selector: &[u8], loss_count: u64) -> Vec<ProfileAction> {
        let committed = match self.streams.get(stream_selector) {
            Some(state) => {
                if loss_count < state.last_loss {
                    let state = self
                        .streams
                        .get_mut(stream_selector)
                        .expect("checked above");
                    state.last_loss = loss_count;
                    return vec![];
                }
                if loss_count == state.last_loss {
                    return vec![];
                }
                state.recovery.committed().to_vec()
            }
            None => return vec![],
        };
        {
            let state = self
                .streams
                .get_mut(stream_selector)
                .expect("checked above");
            state.last_loss = loss_count;
        }
        self.observe(ProfileInput::GapDetected {
            stream_selector: stream_selector.to_vec(),
            expected_base: committed,
            observed_base: Vec::new(),
        })
    }

    /// Records the subscribed catch-up boundary from the subscribe response.
    ///
    /// The boundary is fixed at subscribe accept (SYN-URP-023) and MUST be
    /// non-empty; an empty boundary returns a recovery-needed action and
    /// leaves state unchanged. When a boundary was already recorded from an
    /// earlier page, a different subscribed boundary returns recovery-needed
    /// without replacing it. Untracked selectors return no actions.
    pub fn set_subscribed_boundary(
        &mut self,
        stream_selector: &[u8],
        boundary: Vec<u8>,
    ) -> Vec<ProfileAction> {
        let state = match self.streams.get_mut(stream_selector) {
            Some(state) => state,
            None => return vec![],
        };
        if boundary.is_empty() {
            return vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }];
        }
        match &state.catchup_boundary {
            None => {
                state.catchup_boundary = Some(boundary);
                vec![]
            }
            Some(existing) if *existing == boundary => vec![],
            Some(_) => vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }],
        }
    }

    /// Tracks the fixed catch-up boundary across replay pages.
    ///
    /// The first page records its boundary and returns no actions when no
    /// subscribed boundary was recorded. Later pages with the same boundary
    /// return no actions. An empty or different boundary returns a
    /// recovery-needed action and leaves the recorded boundary unchanged.
    /// Untracked selectors return no actions.
    /// The caller clears the boundary with
    /// [`Self::clear_catchup_boundary`] when recovery completes.
    pub fn observe_replay_page(
        &mut self,
        stream_selector: &[u8],
        page: &ReplayPage,
    ) -> Vec<ProfileAction> {
        let state = match self.streams.get_mut(stream_selector) {
            Some(state) => state,
            None => return vec![],
        };
        if page.catchup_boundary.is_empty() {
            return vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }];
        }
        match &state.catchup_boundary {
            None => {
                state.catchup_boundary = Some(page.catchup_boundary.clone());
                vec![]
            }
            Some(boundary) if *boundary == page.catchup_boundary => vec![],
            Some(_) => vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }],
        }
    }

    /// Validates a catch-up completion boundary before releasing held live batches.
    ///
    /// The completion boundary (`RecoveryReplayComplete.live_boundary_checkpoint`,
    /// `RecoveryBatchTrailer.boundary_checkpoint` when `catchup_complete`, or
    /// `RecoveryCatchUpAccepted.catchup_boundary`) MUST equal the subscribed
    /// boundary (SYN-URP-023). An empty or mismatched boundary returns a
    /// recovery-needed action and MUST NOT release held batches; the recorded
    /// boundary is left unchanged. When no subscribed boundary was recorded
    /// yet, returns recovery-needed without recording, so an unvalidated
    /// completion signal can never become the trusted boundary. The caller
    /// must record B via `set_subscribed_boundary` first, including for
    /// initial subscriptions that skipped replay. Untracked selectors return
    /// no actions.
    pub fn observe_completion_boundary(
        &mut self,
        stream_selector: &[u8],
        completion_boundary: &[u8],
    ) -> Vec<ProfileAction> {
        let state = match self.streams.get_mut(stream_selector) {
            Some(state) => state,
            None => return vec![],
        };
        if completion_boundary.is_empty() {
            return vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }];
        }
        match &state.catchup_boundary {
            None => vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }],
            Some(boundary) if *boundary == completion_boundary => vec![],
            Some(_) => vec![ProfileAction::RecoveryNeeded {
                stream_selector: state.recovery.stream_selector().to_vec(),
                committed: state.recovery.committed().to_vec(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::profile::{ProfileCheckpoint, ProfileInput};
    use super::*;

    fn selector() -> Vec<u8> {
        b"stream-a".to_vec()
    }

    fn page_with_boundary(boundary: &[u8]) -> ReplayPage {
        ReplayPage {
            predecessor_checkpoint: b"cursor-40".to_vec(),
            result_checkpoint: b"cursor-43".to_vec(),
            continuation_marker: b"marker-1".to_vec(),
            catchup_boundary: boundary.to_vec(),
            batch_payloads: vec![b"batch-1".to_vec()],
        }
    }

    fn batch(base: &[u8], result: &[u8]) -> ProfileCheckpoint {
        ProfileCheckpoint {
            stream_selector: selector(),
            generation: 7,
            base_cursor: base.to_vec(),
            result_cursor: result.to_vec(),
        }
    }

    #[test]
    fn boundary_fixed_across_pages() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(selector(), 7, b"cursor-40".to_vec());

        let first = page_with_boundary(b"boundary-100");
        assert!(engine.observe_replay_page(&selector(), &first).is_empty());
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );

        let second = page_with_boundary(b"boundary-100");
        assert!(engine.observe_replay_page(&selector(), &second).is_empty());
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );

        let moved = page_with_boundary(b"boundary-101");
        let actions = engine.observe_replay_page(&selector(), &moved);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], ProfileAction::RecoveryNeeded { .. }));
        // Recorded boundary stays fixed at the first value.
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );

        engine.clear_catchup_boundary(&selector());
        assert_eq!(engine.catchup_boundary(&selector()), None);
        assert!(engine.observe_replay_page(&selector(), &moved).is_empty());
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-101".as_slice())
        );
    }

    #[test]
    fn subscribed_boundary_and_completion_validation() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(selector(), 7, b"cursor-40".to_vec());

        // Empty subscribed boundary is rejected.
        let empty = engine.set_subscribed_boundary(&selector(), Vec::new());
        assert!(matches!(empty[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(engine.catchup_boundary(&selector()), None);

        // Record subscribed boundary from subscribe response.
        assert!(engine
            .set_subscribed_boundary(&selector(), b"boundary-100".to_vec())
            .is_empty());
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );

        // Matching page passes; mismatched page fails without replacing.
        assert!(engine
            .observe_replay_page(&selector(), &page_with_boundary(b"boundary-100"))
            .is_empty());
        let moved = engine.observe_replay_page(&selector(), &page_with_boundary(b"boundary-101"));
        assert!(matches!(moved[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );

        // Matching completion passes; mismatched or empty completion fails.
        assert!(engine
            .observe_completion_boundary(&selector(), b"boundary-100")
            .is_empty());
        let bad = engine.observe_completion_boundary(&selector(), b"boundary-101");
        assert!(matches!(bad[0], ProfileAction::RecoveryNeeded { .. }));
        let empty_completion = engine.observe_completion_boundary(&selector(), b"");
        assert!(matches!(
            empty_completion[0],
            ProfileAction::RecoveryNeeded { .. }
        ));
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );
    }

    #[test]
    fn initial_subscription_skips_replay_validates_completion() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(selector(), 7, Vec::new());

        // Initial subscription records subscribed boundary with no pages.
        assert!(engine
            .set_subscribed_boundary(&selector(), b"boundary-100".to_vec())
            .is_empty());
        // Completion at the subscribed boundary passes and releases held batches.
        assert!(engine
            .observe_completion_boundary(&selector(), b"boundary-100")
            .is_empty());
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );
    }

    #[test]
    fn completion_without_subscribed_boundary_is_rejected() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(selector(), 7, b"cursor-40".to_vec());

        // No subscribed boundary recorded yet: completion must not become B.
        let untrusted = engine.observe_completion_boundary(&selector(), b"boundary-100");
        assert!(matches!(untrusted[0], ProfileAction::RecoveryNeeded { .. }));
        assert_eq!(engine.catchup_boundary(&selector()), None);

        // Recording B first makes the same completion succeed.
        assert!(engine
            .set_subscribed_boundary(&selector(), b"boundary-100".to_vec())
            .is_empty());
        assert!(engine
            .observe_completion_boundary(&selector(), b"boundary-100")
            .is_empty());
        assert_eq!(
            engine.catchup_boundary(&selector()),
            Some(b"boundary-100".as_slice())
        );
    }

    #[test]
    fn loss_increment_maps_to_gap() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(selector(), 7, b"cursor-40".to_vec());

        assert!(engine.poll_loss(&selector(), 0).is_empty());
        assert_eq!(engine.last_loss(&selector()), Some(0));

        let gap = engine.poll_loss(&selector(), 1);
        assert_eq!(gap.len(), 1);
        assert!(matches!(gap[0], ProfileAction::RecoveryNeeded { .. }));
        if let ProfileAction::RecoveryNeeded {
            stream_selector,
            committed,
        } = &gap[0]
        {
            assert_eq!(stream_selector, &selector());
            assert_eq!(committed, b"cursor-40");
        } else {
            panic!("expected recovery-needed action");
        }
        assert_eq!(engine.last_loss(&selector()), Some(1));
        assert_eq!(engine.committed(&selector()), Some(b"cursor-40".as_slice()));

        // Same count polls no further gap.
        assert!(engine.poll_loss(&selector(), 1).is_empty());

        // Next increment maps again.
        let gap2 = engine.poll_loss(&selector(), 2);
        assert!(matches!(gap2[0], ProfileAction::RecoveryNeeded { .. }));

        // Untracked selector polls nothing.
        assert!(engine.poll_loss(b"other", 99).is_empty());
    }

    #[test]
    fn pending_tracks_stop_and_wait_and_snapshot_gate_surfaces() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(selector(), 7, b"cursor-40".to_vec());
        assert_eq!(engine.pending(&selector()), None);
        assert!(!engine.snapshot_pending(&selector()));

        let cp = batch(b"cursor-40", b"cursor-43");
        let offered = engine.observe(ProfileInput::BatchValidated {
            checkpoint: cp.clone(),
        });
        assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
        assert_eq!(engine.pending(&selector()), Some(&cp));

        let expired = engine.observe(ProfileInput::ContinuationExpired {
            stream_selector: selector(),
            committed: b"cursor-40".to_vec(),
        });
        assert!(matches!(expired[0], ProfileAction::SnapshotRequired { .. }));
        assert!(engine.snapshot_pending(&selector()));
        assert_eq!(engine.pending(&selector()), None);

        let snap = ProfileCheckpoint {
            stream_selector: selector(),
            generation: 8,
            base_cursor: b"boundary-00".to_vec(),
            result_cursor: b"boundary-100".to_vec(),
        };
        let snap_offered = engine.observe(ProfileInput::SnapshotInstalled {
            checkpoint: snap.clone(),
        });
        assert!(matches!(
            snap_offered[0],
            ProfileAction::CommitCheckpoint { .. }
        ));
        assert_eq!(engine.pending(&selector()), Some(&snap));
        assert!(engine.confirm_persisted(&snap).is_empty());
        assert_eq!(engine.pending(&selector()), None);
        assert!(!engine.snapshot_pending(&selector()));
        assert_eq!(engine.generation(&selector()), Some(8));
        assert_eq!(
            engine.committed(&selector()),
            Some(b"boundary-100".as_slice())
        );
    }
}
