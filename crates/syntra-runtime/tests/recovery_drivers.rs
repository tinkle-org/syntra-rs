//! Integration tests for recovery drivers, loss unification, and bounded
//! checkpoint reconciliation.
//!
//! Covers the task-2/3/4 acceptance set over neutral fixtures (no messenger
//! semantics):
//! - persistence failure leaves committed progress unchanged and retries
//!   from the last persisted position;
//! - a lost confirm is discovered by independently scheduled reconciliation
//!   without requiring another update (idle peers converge);
//! - snapshot failure (incomplete install) never advances generation;
//! - directed delivery isolates subscription handles (no broadcast);
//! - final-batch loss with idle peers surfaces as recovery via cumulative
//!   loss polling plus reconciliation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use syntra_runtime::recovery::{
    CheckpointReconciler, ConnectionContext, HostDriver, InitiatorDriver, ProfileAction,
    ProfileCheckpoint, ProfileEngine, ProfileInput, ProviderError, ReconcilerConfig,
    RecoveryAuthorizer, SnapshotError, StagedSnapshot, StoredBatch,
};
use syntra_runtime::session::Principal;

fn ctx(id: &str) -> ConnectionContext {
    ConnectionContext::new(id.to_string(), Principal::new("svc-test"), 1)
}

fn append(h: &mut HostDriver, generation: u64, from: &[u8], to: &[u8], payload: &[u8]) {
    h.append_batch(
        b"s".to_vec(),
        StoredBatch {
            predecessor: from.to_vec(),
            result: to.to_vec(),
            payload: payload.to_vec(),
            generation,
        },
    );
}

#[test]
fn replay_filters_stored_generations_before_lookup_and_paging() {
    let mut h = HostDriver::new(ctx("c1"));
    append(&mut h, 6, b"start", b"old", b"old");
    append(&mut h, 7, b"start", b"middle", b"first");
    append(&mut h, 6, b"middle", b"old-end", b"old");
    append(&mut h, 7, b"middle", b"boundary", b"second");
    let (handle, boundary) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
    let page = h.replay_page(&handle, b"start", 7, 64, 1024).unwrap();
    assert_eq!(
        page.batch_payloads,
        vec![b"first".to_vec(), b"second".to_vec()]
    );
    assert_eq!(page.result_checkpoint, boundary);
    assert!(page.continuation_marker.is_empty());
}

#[test]
fn replay_rejects_predecessor_found_only_in_another_generation() {
    let mut h = HostDriver::new(ctx("c1"));
    append(&mut h, 6, b"old-start", b"old-end", b"old");
    append(&mut h, 7, b"start", b"boundary", b"current");
    let (handle, _) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
    assert_eq!(
        h.replay_page(&handle, b"old-start", 7, 64, 1024),
        Err(ProviderError::StaleCheckpoint)
    );
    assert_eq!(
        h.replay_page(&handle, b"start", 7, 64, 1024)
            .unwrap()
            .batch_payloads,
        vec![b"current".to_vec()]
    );
}

#[test]
fn replay_stops_at_subscribed_boundary_despite_later_appends() {
    for page_size in [1, 64] {
        let mut h = HostDriver::new(ctx("c1"));
        append(&mut h, 7, b"start", b"middle", b"first");
        append(&mut h, 7, b"middle", b"boundary", b"second");
        let (handle, boundary) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
        append(&mut h, 7, b"boundary", b"live", b"live");
        let first = h
            .replay_page(&handle, b"start", 7, page_size, 1024)
            .unwrap();
        assert_eq!(first.catchup_boundary, boundary);
        let last = if page_size == 1 {
            assert!(!first.continuation_marker.is_empty());
            h.replay_page(&handle, &first.result_checkpoint, 7, page_size, 1024)
                .unwrap()
        } else {
            assert_eq!(first.batch_payloads.len(), 2);
            first
        };
        assert_eq!(last.result_checkpoint, boundary);
        assert!(
            last.continuation_marker.is_empty(),
            "live data is not another replay page"
        );
        assert_eq!(
            h.replay_page(&handle, b"live", 7, page_size, 1024),
            Err(ProviderError::StaleCheckpoint)
        );
    }
}

#[test]
fn replay_retry_requires_identical_raw_batch_bound() {
    for changed in [1, 65] {
        let mut h = HostDriver::new(ctx("c1"));
        append(&mut h, 7, b"start", b"boundary", b"batch");
        let (handle, _) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
        let page = h.replay_page(&handle, b"start", 7, 64, 1024).unwrap();
        assert_eq!(
            h.replay_page(&handle, b"start", 7, changed, 1024),
            Err(ProviderError::StaleCheckpoint)
        );
        assert_eq!(h.replay_page(&handle, b"start", 7, 64, 1024), Ok(page));
    }
}

#[test]
fn replay_retry_requires_identical_raw_byte_bound() {
    for changed in [1, 262_145] {
        let mut h = HostDriver::new(ctx("c1"));
        append(&mut h, 7, b"start", b"boundary", b"batch");
        let (handle, _) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
        let page = h.replay_page(&handle, b"start", 7, 64, 262_144).unwrap();
        assert_eq!(
            h.replay_page(&handle, b"start", 7, 64, changed),
            Err(ProviderError::StaleCheckpoint)
        );
        assert_eq!(h.replay_page(&handle, b"start", 7, 64, 262_144), Ok(page));
    }
}

fn two_page_replay() -> (HostDriver, Vec<u8>) {
    let mut h = HostDriver::new(ctx("c1"));
    append(&mut h, 7, b"start", b"middle", b"first");
    append(&mut h, 7, b"middle", b"boundary", b"second");
    let (handle, _) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
    (h, handle)
}

#[test]
fn replay_first_request_rejects_nonempty_continuation() {
    let (mut h, handle) = two_page_replay();
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"forged"),
        Err(ProviderError::StaleCheckpoint)
    );
    assert!(h
        .replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"")
        .is_ok());
}

#[test]
fn replay_continuation_requires_echo_and_checkpoint_chain() {
    let (mut h, handle) = two_page_replay();
    let first = h
        .replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"")
        .unwrap();
    for marker in [b"".as_slice(), b"forged"] {
        assert_eq!(
            h.replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, marker),
            Err(ProviderError::StaleCheckpoint)
        );
    }
    assert_eq!(
        h.replay_page_with_continuation(
            &handle,
            b"unrelated",
            7,
            1,
            1024,
            &first.continuation_marker
        ),
        Err(ProviderError::StaleCheckpoint)
    );
    let last = h
        .replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, &first.continuation_marker)
        .unwrap();
    assert_eq!(last.batch_payloads, vec![b"second".to_vec()]);
    assert!(last.continuation_marker.is_empty());
}

#[test]
fn replay_retry_requires_identical_continuation_and_retains_last_request_only() {
    let (mut h, handle) = two_page_replay();
    let first = h
        .replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"")
        .unwrap();
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"forged"),
        Err(ProviderError::StaleCheckpoint)
    );
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b""),
        Ok(first.clone())
    );
    let last = h
        .replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, &first.continuation_marker)
        .unwrap();
    append(&mut h, 7, b"boundary", b"live", b"live");
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, b"forged"),
        Err(ProviderError::StaleCheckpoint)
    );
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, &first.continuation_marker),
        Ok(last)
    );
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b""),
        Err(ProviderError::StaleCheckpoint)
    );
}

#[test]
fn replay_continuation_retry_compares_bounds_and_generation_without_changing_cache() {
    let (mut h, handle) = two_page_replay();
    let first = h
        .replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"")
        .unwrap();
    let marker = &first.continuation_marker;
    let last = h
        .replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, marker)
        .unwrap();
    for (generation, batches, bytes) in [(6, 1, 1024), (7, 2, 1024), (7, 1, 1)] {
        assert_eq!(
            h.replay_page_with_continuation(&handle, b"middle", generation, batches, bytes, marker),
            Err(ProviderError::StaleCheckpoint)
        );
    }
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, marker),
        Ok(last)
    );
    h.unsubscribe(&handle).unwrap();
    assert_eq!(
        h.replay_page_with_continuation(&handle, b"middle", 7, 1, 1024, marker),
        Err(ProviderError::UnknownStream)
    );
}

#[test]
fn replay_byte_bound_pages_only_matching_generation_and_stops_at_boundary() {
    let mut h = HostDriver::new(ctx("c1"));
    append(&mut h, 6, b"start", b"old", &[0; 32]);
    append(&mut h, 7, b"start", b"middle", b"ab");
    append(&mut h, 6, b"middle", b"old-end", &[0; 32]);
    append(&mut h, 7, b"middle", b"boundary", b"cd");
    let (handle, _) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
    append(&mut h, 7, b"boundary", b"live", b"ef");
    assert_eq!(
        h.replay_page(&handle, b"start", 7, 64, 1),
        Err(ProviderError::Overloaded)
    );
    let first = h.replay_page(&handle, b"start", 7, 64, 2).unwrap();
    assert_eq!(first.batch_payloads, vec![b"ab".to_vec()]);
    let last = h
        .replay_page_with_continuation(&handle, b"middle", 7, 64, 2, &first.continuation_marker)
        .unwrap();
    assert_eq!(last.batch_payloads, vec![b"cd".to_vec()]);
    assert_eq!(last.result_checkpoint, b"boundary");
    assert!(last.continuation_marker.is_empty());
}

#[test]
fn snapshot_constructor_rejects_empty_handle() {
    assert!(matches!(
        StagedSnapshot::new(Vec::new(), b"boundary".to_vec(), 1, 1),
        Err(SnapshotError::HandleMismatch)
    ));
}

#[test]
fn snapshot_constructor_rejects_handle_over_256_bytes() {
    assert!(matches!(
        StagedSnapshot::new(vec![0; 257], b"boundary".to_vec(), 1, 1),
        Err(SnapshotError::OverLimit)
    ));
}

#[test]
fn snapshot_constructor_accepts_handle_at_both_valid_limits() {
    for len in [1, 256] {
        let handle = vec![0; len];
        let mut staged = StagedSnapshot::new(handle.clone(), b"boundary".to_vec(), 1, 1).unwrap();
        assert_eq!(staged.snapshot_handle(), handle);
        staged
            .stage_page(&handle, 0, vec![42], b"boundary")
            .unwrap();
        assert_eq!(staged.install().unwrap(), vec![42]);
    }
}

#[test]
fn invalid_snapshot_handle_does_not_replace_existing_staging() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"start".to_vec()).unwrap();
    d.stage_snapshot(b"s".to_vec(), b"valid".to_vec(), b"boundary".to_vec(), 1, 8)
        .unwrap();
    for handle in [Vec::new(), vec![0; 257]] {
        assert!(d
            .stage_snapshot(b"s".to_vec(), handle, b"other".to_vec(), 1, 8)
            .is_err());
    }
    d.stage_snapshot_page(b"s", b"valid", 0, b"snapshot".to_vec(), b"boundary")
        .unwrap();
    let (checkpoint, bytes) = d.install_snapshot(b"s", 8).unwrap();
    assert_eq!(checkpoint.result_cursor, b"boundary");
    assert_eq!(bytes, b"snapshot");
    assert_eq!(d.engine().generation(b"s"), Some(7));
    assert_eq!(d.engine().committed(b"s"), Some(b"start".as_slice()));
}

fn cp(sel: &[u8], gen: u64, base: &[u8], result: &[u8]) -> ProfileCheckpoint {
    ProfileCheckpoint {
        stream_selector: sel.to_vec(),
        generation: gen,
        base_cursor: base.to_vec(),
        result_cursor: result.to_vec(),
    }
}

struct AllowAll;
impl RecoveryAuthorizer for AllowAll {
    fn authorize_subscribe(&self, _s: &[u8]) -> Result<(), ProviderError> {
        Ok(())
    }
    fn authorize_replay(&self, _c: &ProfileCheckpoint) -> Result<(), ProviderError> {
        Ok(())
    }
    fn authorize_snapshot(
        &self,
        _c: &syntra_runtime::recovery::CommittedPosition,
    ) -> Result<(), ProviderError> {
        Ok(())
    }
    fn authorize_confirm(&self, _c: &ProfileCheckpoint) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[test]
fn persistence_failure_retries_from_last_committed() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"c-40".to_vec()).unwrap();
    let batch = cp(b"s", 7, b"c-40", b"c-43");
    let offered = d.on_batch_validated(batch.clone());
    assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
    d.store_mut().fail_next_write();
    assert!(d.confirm(&batch, b"fx-1").is_err());
    assert_eq!(d.engine().committed(b"s"), Some(b"c-40".as_slice()));
    let retry = d.on_batch_validated(batch.clone());
    assert!(matches!(retry[0], ProfileAction::CommitCheckpoint { .. }));
    assert!(d.confirm(&batch, b"fx-1").unwrap().is_empty());
    assert_eq!(d.engine().committed(b"s"), Some(b"c-43".as_slice()));
}

#[test]
fn lost_confirm_discovered_by_reconciliation_without_new_update() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"c-40".to_vec()).unwrap();
    let batch = cp(b"s", 7, b"c-40", b"c-43");
    let offered = d.on_batch_validated(batch.clone());
    assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
    let mut rec = CheckpointReconciler::new(ReconcilerConfig {
        tick_interval: Duration::from_secs(0),
        max_streams_per_tick: 8,
    });
    rec.note_observed(batch.clone());
    let found = rec.tick(Instant::now(), d.engine(), d.store());
    assert_eq!(found.len(), 1);
    assert!(matches!(found[0], ProfileAction::RecoveryNeeded { .. }));
    assert!(d.confirm(&batch, b"fx-1").unwrap().is_empty());
    let quiet = rec.tick(Instant::now(), d.engine(), d.store());
    assert!(quiet.is_empty());
}

#[test]
fn snapshot_failure_never_advances_generation() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"c-40".to_vec()).unwrap();
    d.stage_snapshot(b"s".to_vec(), b"h1".to_vec(), b"b-100".to_vec(), 2, 1024)
        .unwrap();
    d.stage_snapshot_page(b"s", b"h1", 0, b"half".to_vec(), b"b-100")
        .unwrap();
    assert!(d.install_snapshot(b"s", 8).is_err());
    assert_eq!(d.engine().generation(b"s"), Some(7));
    assert_eq!(d.engine().committed(b"s"), Some(b"c-40".as_slice()));
    d.stage_snapshot_page(b"s", b"h1", 1, b"rest".to_vec(), b"b-100")
        .unwrap();
    let (snap_cp, snap_bytes) = d.install_snapshot(b"s", 8).unwrap();
    assert_eq!(snap_cp.result_cursor, b"b-100");
    assert_eq!(snap_bytes, b"halfrest");
    assert!(
        d.install_snapshot(b"s", 9).is_err(),
        "staged entry removed after success"
    );
    assert!(
        d.install_snapshot(b"s", 7).is_err(),
        "stale generation rejected"
    );
    let mut engine = ProfileEngine::new();
    engine.insert_stream(b"s".to_vec(), 7, b"c-40".to_vec());
    let offered = engine.observe(ProfileInput::SnapshotInstalled {
        checkpoint: snap_cp.clone(),
    });
    assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
    let incomplete = StagedSnapshot::new(b"h".to_vec(), b"b".to_vec(), 2, 64).unwrap();
    assert!(!incomplete.is_complete());
    assert!(incomplete.install().is_err());
}

#[test]
fn directed_delivery_isolates_subscription_handles() {
    let mut h = HostDriver::new(ctx("c1")).with_authorizer(Arc::new(AllowAll));
    h.append_batch(
        b"stream-a".to_vec(),
        StoredBatch {
            predecessor: b"c-40".to_vec(),
            result: b"c-43".to_vec(),
            payload: b"batch-a".to_vec(),
            generation: 7,
        },
    );
    h.append_batch(
        b"stream-b".to_vec(),
        StoredBatch {
            predecessor: b"d-40".to_vec(),
            result: b"d-43".to_vec(),
            payload: b"batch-b".to_vec(),
            generation: 7,
        },
    );
    let (ha, _) = h
        .subscribe(b"stream-a".to_vec(), b"c-40".to_vec(), 7)
        .unwrap();
    let (hb, _) = h
        .subscribe(b"stream-b".to_vec(), b"d-40".to_vec(), 7)
        .unwrap();
    assert_ne!(ha, hb);
    let env_a = h.directed_delivery(&ha, b"batch-a".to_vec()).unwrap();
    assert_eq!(env_a.subscription_handle, ha);
    assert_ne!(env_a.subscription_handle, hb);
    let env_b = h.directed_delivery(&hb, b"batch-b".to_vec()).unwrap();
    assert_eq!(env_b.subscription_handle, hb);
    assert_ne!(env_a.payload, env_b.payload);
    assert!(h.directed_delivery(b"nope", b"x".to_vec()).is_err());
    h.unsubscribe(&ha).unwrap();
    assert!(h.directed_delivery(&ha, b"late".to_vec()).is_err());
    assert!(h.directed_delivery(&hb, b"still".to_vec()).is_ok());
}

#[test]
fn final_batch_loss_with_idle_peers_recovers_via_loss_and_reconcile() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"c-40".to_vec()).unwrap();
    assert!(d.poll_loss(b"s", 0).is_empty());
    let gap = d.poll_loss(b"s", 1);
    assert!(matches!(gap[0], ProfileAction::RecoveryNeeded { .. }));
    assert_eq!(d.engine().last_loss(b"s"), Some(1));
    assert!(d.poll_loss(b"s", 1).is_empty());
    let mut rec = CheckpointReconciler::new(ReconcilerConfig {
        tick_interval: Duration::from_secs(0),
        max_streams_per_tick: 8,
    });
    rec.note_observed(cp(b"s", 7, b"c-40", b"c-43"));
    let found = rec.tick(Instant::now(), d.engine(), d.store());
    assert_eq!(found.len(), 1);
    let batch = cp(b"s", 7, b"c-40", b"c-43");
    let offered = d.on_batch_validated(batch.clone());
    assert!(matches!(offered[0], ProfileAction::CommitCheckpoint { .. }));
    assert!(d.confirm(&batch, b"fx-1").unwrap().is_empty());
    assert!(
        d.on_batch_validated(batch.clone()).is_empty(),
        "confirmed duplicate must not re-offer"
    );
    let older = cp(b"s", 7, b"c-40", b"c-41");
    let older_actions = d.on_batch_validated(older);
    assert!(
        !older_actions
            .iter()
            .any(|a| matches!(a, ProfileAction::CommitCheckpoint { .. })),
        "older duplicate must not re-offer commit"
    );
}

struct RevocableReplay {
    revoked: std::sync::atomic::AtomicBool,
}

impl RecoveryAuthorizer for RevocableReplay {
    fn authorize_subscribe(&self, _s: &[u8]) -> Result<(), ProviderError> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProviderError::Unauthorized);
        }
        Ok(())
    }
    fn authorize_replay(&self, _c: &ProfileCheckpoint) -> Result<(), ProviderError> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProviderError::Unauthorized);
        }
        Ok(())
    }
    fn authorize_snapshot(
        &self,
        _c: &syntra_runtime::recovery::CommittedPosition,
    ) -> Result<(), ProviderError> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProviderError::Unauthorized);
        }
        Ok(())
    }
    fn authorize_confirm(&self, _c: &ProfileCheckpoint) -> Result<(), ProviderError> {
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProviderError::Unauthorized);
        }
        Ok(())
    }
}

#[test]
fn replay_exact_retry_reauthorizes_after_revocation() {
    let auth = Arc::new(RevocableReplay {
        revoked: std::sync::atomic::AtomicBool::new(false),
    });
    let mut h = HostDriver::new(ctx("c1")).with_authorizer(auth.clone());
    append(&mut h, 7, b"start", b"boundary", b"batch");
    let (handle, _) = h.subscribe(b"s".to_vec(), b"start".to_vec(), 7).unwrap();
    let first = h
        .replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"")
        .unwrap();
    assert_eq!(first.batch_payloads, vec![b"batch".to_vec()]);
    auth.revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let retry = h.replay_page_with_continuation(&handle, b"start", 7, 1, 1024, b"");
    assert_eq!(retry, Err(ProviderError::Unauthorized));
}
