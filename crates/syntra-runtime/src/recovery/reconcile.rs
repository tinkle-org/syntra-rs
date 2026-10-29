//! Bounded checkpoint reconciliation.
//!
//! Stop-and-wait confirmation can lose its confirm (transport loss with
//! unknown outcome, crashed persister, dropped `Confirm` RPC): the batch
//! was durably applied but the coordinator never learned it, and no new
//! batch may ever arrive to surface the mismatch. Reconciliation discovers
//! such missing final updates without requiring another update: on an
//! independently scheduled tick it compares the last observed result
//! against the last confirmed position and reports recovery from the
//! confirmed cursor when they differ.
//!
//! The tick is bounded: at most `max_streams_per_tick` streams report per
//! tick, and the caller schedules ticks independently of batch arrival
//! (e.g. every N seconds or every M polls). Idle peers therefore converge
//! without any new batch. Reconciliation never advances committed progress
//! itself; it only emits `RecoveryNeeded` so the normal replay path runs.

use std::collections::HashMap;
use web_time::{Duration, Instant};

use super::engine::ProfileEngine;
use super::profile::{ProfileAction, ProfileCheckpoint};
use super::store::DurableStore;

/// Reconciliation schedule bounds.
#[derive(Debug, Clone)]
pub struct ReconcilerConfig {
    /// Minimum interval between ticks. Ticks closer than this are no-ops.
    pub tick_interval: Duration,
    /// Maximum streams that may report per tick.
    pub max_streams_per_tick: usize,
}

impl Default for ReconcilerConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(5),
            max_streams_per_tick: 16,
        }
    }
}

/// Tracks the last observed result per stream and reconciles it against
/// confirmed progress on an independent schedule.
#[derive(Debug)]
pub struct CheckpointReconciler {
    config: ReconcilerConfig,
    last_tick: Option<Instant>,
    observed: HashMap<Vec<u8>, ProfileCheckpoint>,
    next_cursor: Option<Vec<u8>>,
}

impl CheckpointReconciler {
    /// Reconciler with the given bounds.
    pub fn new(config: ReconcilerConfig) -> Self {
        Self {
            config,
            last_tick: None,
            observed: HashMap::new(),
            next_cursor: None,
        }
    }

    /// Bounds in force.
    pub fn config(&self) -> &ReconcilerConfig {
        &self.config
    }

    /// Record the last observed (validated or completed) checkpoint for the
    /// stream. Called on every batch/replay page, including the final batch
    /// of a stream that then goes idle.
    pub fn note_observed(&mut self, checkpoint: ProfileCheckpoint) {
        self.observed
            .insert(checkpoint.stream_selector.clone(), checkpoint);
    }

    /// Forget a stream (unsubscribe / generation advance clears it).
    pub fn forget(&mut self, stream_selector: &[u8]) {
        self.observed.remove(stream_selector);
    }

    /// True when a tick is due under the independent schedule.
    pub fn should_tick(&self, now: Instant) -> bool {
        match self.last_tick {
            None => true,
            Some(t) => now.duration_since(t) >= self.config.tick_interval,
        }
    }

    /// Reconcile up to `max_streams_per_tick` streams.
    ///
    /// For each tracked stream whose last observed result differs from the
    /// engine's committed position (generation and cursor), emits
    /// `RecoveryNeeded` from the committed cursor. Streams already converged
    /// emit nothing. The tick runs even when no batch arrived since the last
    /// tick, so a missing final update is discovered while peers are idle.
    /// Returns at most `max_streams_per_tick` actions in rotated selector
    /// order for fairness: sorted selectors rotate to start after
    /// `next_cursor` each tick, preventing starvation when the bound is
    /// smaller than the tracked set.
    pub fn tick<S: DurableStore>(
        &mut self,
        now: Instant,
        engine: &ProfileEngine,
        _store: &S,
    ) -> Vec<ProfileAction> {
        if !self.should_tick(now) {
            return vec![];
        }
        self.last_tick = Some(now);
        let mut selectors: Vec<Vec<u8>> = self.observed.keys().cloned().collect();
        selectors.sort();
        // Rotate to start after next_cursor for round-robin fairness.
        if let Some(cursor) = self.next_cursor.clone() {
            if let Some(pos) = selectors.iter().position(|s| *s > cursor) {
                let mut rotated = selectors.split_off(pos);
                rotated.extend(selectors);
                selectors = rotated;
            }
        }
        let mut out = Vec::new();
        for selector in selectors {
            if out.len() >= self.config.max_streams_per_tick {
                break;
            }
            let observed = match self.observed.get(&selector) {
                Some(o) => o.clone(),
                None => continue,
            };
            let pos = match engine.position(&selector) {
                Some(p) => p,
                None => continue,
            };
            if observed.generation == pos.generation && observed.result_cursor == pos.committed {
                continue;
            }
            out.push(ProfileAction::RecoveryNeeded {
                stream_selector: selector.clone(),
                committed: pos.committed.clone(),
            });
        }
        if let Some(last) = out.last() {
            let last_selector = match last {
                ProfileAction::RecoveryNeeded {
                    stream_selector, ..
                } => stream_selector.clone(),
                _ => return out,
            };
            self.next_cursor = Some(last_selector);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::profile::ProfileInput;
    use crate::recovery::store::MemoryStore;

    fn cp(sel: &[u8], base: &[u8], result: &[u8]) -> ProfileCheckpoint {
        ProfileCheckpoint {
            stream_selector: sel.to_vec(),
            generation: 7,
            base_cursor: base.to_vec(),
            result_cursor: result.to_vec(),
        }
    }

    #[test]
    fn discovers_missing_final_update_while_idle() {
        let mut engine = ProfileEngine::new();
        engine.insert_stream(b"s".to_vec(), 7, b"c-40".to_vec());
        let store = MemoryStore::new();
        let mut rec = CheckpointReconciler::new(ReconcilerConfig {
            tick_interval: Duration::from_secs(0),
            max_streams_per_tick: 8,
        });
        let now = Instant::now();
        let batch = cp(b"s", b"c-40", b"c-43");
        let offered = engine.observe(ProfileInput::BatchValidated {
            checkpoint: batch.clone(),
        });
        assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
        rec.note_observed(batch);
        let found = rec.tick(now, &engine, &store);
        assert_eq!(found.len(), 1);
        assert!(matches!(found[0], ProfileAction::RecoveryNeeded { .. }));
        engine.confirm_persisted(&cp(b"s", b"c-40", b"c-43"));
        let quiet = rec.tick(Instant::now(), &engine, &store);
        assert!(quiet.is_empty());
    }

    #[test]
    fn tick_is_bounded_and_independently_scheduled() {
        let mut engine = ProfileEngine::new();
        let store = MemoryStore::new();
        let mut rec = CheckpointReconciler::new(ReconcilerConfig {
            tick_interval: Duration::from_secs(60),
            max_streams_per_tick: 1,
        });
        for s in [b"a".as_slice(), b"b".as_slice()] {
            engine.insert_stream(s.to_vec(), 7, b"c-0".to_vec());
            rec.note_observed(cp(s, b"c-0", b"c-1"));
        }
        let now = Instant::now();
        assert_eq!(rec.tick(now, &engine, &store).len(), 1);
        assert!(rec.tick(now, &engine, &store).is_empty());
    }
}
