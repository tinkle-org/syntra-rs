//! Integration tests for recovery drivers, loss unification, and bounded
//! checkpoint reconciliation.
//!
//! Covers the task-2/3/4 acceptance set over neutral fixtures (no messenger
//! semantics):
//! - persistence failure leaves committed progress unchanged and retries
//!   from the last persisted position;
//! - a lost confirm is discovered by independently scheduled reconciliation
//!   without requiring another update (idle peers converge);
//! - snapshots install at current G; only explicit provider loss changes G;
//! - directed delivery isolates subscription handles (no broadcast);
//! - final-batch loss with idle peers surfaces as recovery via cumulative
//!   loss polling plus reconciliation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use syntra_runtime::recovery::{
    CheckpointReconciler, ConnectionContext, DurableStore, HostDriver, InitiatorDriver,
    ProfileAction, ProfileCheckpoint, ProfileEngine, ProfileInput, ProviderError, ReconcilerConfig,
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
    )
    .unwrap();
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
    let (checkpoint, bytes) = d.install_snapshot(b"s", 7).unwrap();
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
    rec.note_observed(d.engine(), batch.clone());
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
    assert!(d.install_snapshot(b"s", 7).is_err());
    assert_eq!(d.engine().generation(b"s"), Some(7));
    assert_eq!(d.engine().committed(b"s"), Some(b"c-40".as_slice()));
    d.stage_snapshot_page(b"s", b"h1", 1, b"rest".to_vec(), b"b-100")
        .unwrap();
    let (snap_cp, snap_bytes) = d.install_snapshot(b"s", 7).unwrap();
    assert_eq!(snap_cp.result_cursor, b"b-100");
    assert_eq!(snap_bytes, b"halfrest");
    assert!(
        d.install_snapshot(b"s", 9).is_err(),
        "new generation is not inferred from installation"
    );
    assert_eq!(
        d.install_snapshot(b"s", 7).unwrap(),
        (snap_cp.clone(), snap_bytes)
    );
    assert!(d.confirm(&snap_cp, b"snapshot-effects").unwrap().is_empty());
    assert_eq!(d.engine().generation(b"s"), Some(7));
    assert!(
        d.install_snapshot(b"s", 7).is_err(),
        "stage removed after durable confirmation"
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
    )
    .unwrap();
    h.append_batch(
        b"stream-b".to_vec(),
        StoredBatch {
            predecessor: b"d-40".to_vec(),
            result: b"d-43".to_vec(),
            payload: b"batch-b".to_vec(),
            generation: 7,
        },
    )
    .unwrap();
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
    rec.note_observed(d.engine(), cp(b"s", 7, b"c-40", b"c-43"));
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
    assert_eq!(
        h.directed_delivery(&handle, b"batch".to_vec()),
        Err(ProviderError::Unauthorized)
    );
}

#[test]
fn equal_cursor_snapshot_still_passes_through_the_persistence_gate() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"S0".to_vec()).unwrap();
    d.continuation_expired(b"s");
    d.stage_snapshot(b"s".to_vec(), b"X".to_vec(), b"S0".to_vec(), 1, 8)
        .unwrap();
    d.stage_snapshot_page(b"s", b"X", 0, b"state".to_vec(), b"S0")
        .unwrap();
    let (snapshot, _) = d.install_snapshot(b"s", 7).unwrap();
    assert!(d.engine().can_confirm(&snapshot));
    d.store_mut().fail_next_write();
    assert!(d.confirm(&snapshot, b"state").is_err());
    assert!(d.engine().snapshot_pending(b"s"));
    assert!(d.store().load(b"s").unwrap().is_none());
    assert!(d.confirm(&snapshot, b"state").unwrap().is_empty());
    assert!(!d.engine().snapshot_pending(b"s"));
    assert_eq!(d.store().load(b"s").unwrap().unwrap().committed, b"S0");
}

struct ValidateHook {
    calls: std::sync::atomic::AtomicUsize,
}

impl RecoveryAuthorizer for ValidateHook {
    fn authorize_validate(&self, _cp: &ProfileCheckpoint) -> Result<(), ProviderError> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(ProviderError::StaleCheckpoint)
        }
    }
    fn authorize_subscribe(&self, s: &[u8]) -> Result<(), ProviderError> {
        AllowAll.authorize_subscribe(s)
    }
    fn authorize_replay(&self, cp: &ProfileCheckpoint) -> Result<(), ProviderError> {
        AllowAll.authorize_replay(cp)
    }
    fn authorize_snapshot(
        &self,
        pos: &syntra_runtime::recovery::CommittedPosition,
    ) -> Result<(), ProviderError> {
        AllowAll.authorize_snapshot(pos)
    }
    fn authorize_confirm(&self, cp: &ProfileCheckpoint) -> Result<(), ProviderError> {
        AllowAll.authorize_confirm(cp)
    }
}

#[test]
fn configured_validation_hook_runs_before_a_cache_hit_but_after_selector_and_g() {
    let auth = Arc::new(ValidateHook {
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let mut d = InitiatorDriver::new(ctx("c1"), 16).with_authorizer(auth.clone());
    d.track_stream(b"s".to_vec(), 7, b"C".to_vec()).unwrap();
    assert!(d
        .try_on_batch_validated(cp(b"foreign", 7, b"C", b"D"))
        .unwrap()
        .is_empty());
    assert!(!d
        .try_on_batch_validated(cp(b"s", 8, b"C", b"D"))
        .unwrap()
        .is_empty());
    assert_eq!(auth.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let checkpoint = cp(b"s", 7, b"C", b"D");
    d.try_on_batch_validated(checkpoint.clone()).unwrap();
    d.confirm(&checkpoint, b"effects").unwrap();
    let rejected = d.try_on_batch_validated(checkpoint.clone()).unwrap_err();
    assert_eq!(rejected.code(), syntra_core::ErrorCode::FailedPrecondition);
    assert_eq!(auth.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(matches!(
        d.on_batch_validated(checkpoint)[0],
        ProfileAction::RecoveryNeeded { .. }
    ));
    assert_eq!(d.engine().committed(b"s"), Some(b"D".as_slice()));
}

#[test]
fn current_generation_snapshot_jump_persists_before_clearing_gate() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"old-cursor".to_vec())
        .unwrap();
    d.set_subscribed_boundary(b"s", b"old-B".to_vec());
    assert!(matches!(
        d.continuation_expired(b"s")[0],
        ProfileAction::SnapshotRequired { .. }
    ));
    assert_eq!(d.engine().catchup_boundary(b"s"), None);
    d.stage_snapshot(b"s".to_vec(), b"X".to_vec(), b"S0".to_vec(), 1, 8)
        .unwrap();
    d.stage_snapshot_page(b"s", b"X", 0, b"state".to_vec(), b"S0")
        .unwrap();
    assert_eq!(
        d.install_snapshot(b"s", 8),
        Err(SnapshotError::StaleGeneration)
    );
    assert!(!d
        .confirm(&cp(b"s", 8, b"S0", b"S0"), b"wrong")
        .unwrap()
        .is_empty());
    let (snapshot, bytes) = d.install_snapshot(b"s", 7).unwrap();
    assert_eq!(snapshot, cp(b"s", 7, b"S0", b"S0"));
    assert_eq!(bytes, b"state");
    assert!(d.engine().can_confirm(&snapshot));
    assert!(d.engine().snapshot_pending(b"s"));
    assert_eq!(d.engine().generation(b"s"), Some(7));
    d.store_mut().fail_next_write();
    assert!(d.confirm(&snapshot, b"state").is_err());
    assert!(d.engine().snapshot_pending(b"s"));
    assert_eq!(d.engine().committed(b"s"), Some(b"old-cursor".as_slice()));
    assert_eq!(d.install_snapshot(b"s", 7).unwrap().0, snapshot);
    assert!(d.confirm(&snapshot, b"state").unwrap().is_empty());
    assert!(!d.engine().snapshot_pending(b"s"));
    assert_eq!(d.engine().generation(b"s"), Some(7));
    assert_eq!(d.engine().committed(b"s"), Some(b"S0".as_slice()));
    assert_eq!(d.store().digest(b"s"), Some(b"state".as_slice()));
    assert!(!d.observe_completion_boundary(b"s", b"old-B").is_empty());
    let next = cp(b"s", 7, b"S0", b"next");
    assert!(matches!(
        d.on_batch_validated(next.clone())[0],
        ProfileAction::CommitCheckpoint { .. }
    ));
    assert!(d.confirm(&next, b"next-effects").unwrap().is_empty());
}

#[test]
fn descriptor_retry_preserves_pages_and_conflicts_never_overwrite_active_stage() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"C".to_vec()).unwrap();
    d.stage_snapshot(b"s".to_vec(), b"X".to_vec(), b"S0".to_vec(), 2, 8)
        .unwrap();
    d.stage_snapshot_page(b"s", b"X", 0, b"first".to_vec(), b"S0")
        .unwrap();
    d.stage_snapshot(b"s".to_vec(), b"X".to_vec(), b"S0".to_vec(), 2, 8)
        .unwrap();
    for (handle, boundary, pages, bytes) in [
        (b"X".as_slice(), b"other".as_slice(), 2, 8),
        (b"other".as_slice(), b"S0".as_slice(), 2, 8),
        (b"X".as_slice(), b"S0".as_slice(), 1, 8),
        (b"X".as_slice(), b"S0".as_slice(), 2, 9),
    ] {
        assert_eq!(
            d.stage_snapshot(
                b"s".to_vec(),
                handle.to_vec(),
                boundary.to_vec(),
                pages,
                bytes
            ),
            Err(SnapshotError::ActiveStage)
        );
    }
    assert_eq!(
        d.stage_snapshot_page(b"s", b"X", 1, b"mixed".to_vec(), b"other"),
        Err(SnapshotError::BoundaryMismatch)
    );
    d.stage_snapshot_page(b"s", b"X", 1, b"last".to_vec(), b"S0")
        .unwrap();
    let (snapshot, bytes) = d.install_snapshot(b"s", 7).unwrap();
    assert_eq!(bytes, b"firstlast", "retry must preserve the first page");
    // Even an equal-boundary replacement cannot supersede an outstanding offer.
    assert_eq!(
        d.stage_snapshot(b"s".to_vec(), b"Y".to_vec(), b"S0".to_vec(), 2, 8),
        Err(SnapshotError::ActiveStage)
    );
    assert!(d.confirm(&snapshot, &bytes).unwrap().is_empty());
}

#[test]
fn explicit_provider_loss_invalidates_only_the_tracked_scope() {
    let mut d = InitiatorDriver::new(ctx("c1"), 16);
    d.track_stream(b"s".to_vec(), 7, b"C".to_vec()).unwrap();
    d.track_stream(b"other-scope".to_vec(), 7, b"other-C".to_vec())
        .unwrap();
    let durable = cp(b"s", 7, b"C", b"C1");
    d.on_batch_validated(durable.clone());
    d.confirm(&durable, b"durable-effects").unwrap();
    d.stage_snapshot(b"s".to_vec(), b"X".to_vec(), b"S0".to_vec(), 1, 8)
        .unwrap();
    d.stage_snapshot_page(b"s", b"X", 0, b"state".to_vec(), b"S0")
        .unwrap();
    let (old, _) = d.install_snapshot(b"s", 7).unwrap();
    for invalid in [6, 7] {
        assert_eq!(
            d.provider_loss(b"s", invalid),
            Err(ProviderError::StaleCheckpoint)
        );
        assert!(d.engine().can_confirm(&old));
        assert_eq!(d.engine().catchup_boundary(b"s"), None);
    }
    d.provider_loss(b"s", 9).unwrap();
    assert_eq!(d.engine().generation(b"s"), Some(9));
    assert_eq!(d.engine().pending(b"s"), None);
    assert!(!d.engine().snapshot_pending(b"s"));
    assert_eq!(d.engine().catchup_boundary(b"s"), None);
    assert_eq!(
        d.engine().committed(b"s"),
        Some(b"".as_slice()),
        "old cursor bytes must not be rebound to new G"
    );
    assert_eq!(d.engine().generation(b"other-scope"), Some(7));
    let saved = d.store().load(b"s").unwrap().unwrap();
    assert_eq!(saved.generation, 7);
    assert_eq!(
        saved.committed, b"C1",
        "provider loss does not rewrite durable evidence"
    );
    assert_eq!(
        d.engine().committed(b"other-scope"),
        Some(b"other-C".as_slice())
    );
    assert!(!d.confirm(&old, b"stale").unwrap().is_empty());
    assert_eq!(
        d.stage_snapshot_page(b"s", b"X", 0, b"state".to_vec(), b"S0"),
        Err(SnapshotError::InvalidPage)
    );
    d.stage_snapshot(b"s".to_vec(), b"new-X".to_vec(), b"new-S0".to_vec(), 1, 8)
        .unwrap();
    d.stage_snapshot_page(b"s", b"new-X", 0, b"state".to_vec(), b"new-S0")
        .unwrap();
    let (current, _) = d.install_snapshot(b"s", 9).unwrap();
    assert!(d.confirm(&current, b"state").unwrap().is_empty());
    assert_eq!(d.engine().generation(b"s"), Some(9));
}

#[test]
fn duplicate_cache_cannot_bypass_revocation_or_snapshot_gate() {
    let auth = Arc::new(RevocableReplay {
        revoked: std::sync::atomic::AtomicBool::new(false),
    });
    let mut d = InitiatorDriver::new(ctx("c1"), 16).with_authorizer(auth.clone());
    d.track_stream(b"s".to_vec(), 7, b"C0".to_vec()).unwrap();
    let first = cp(b"s", 7, b"C0", b"C1");
    let second = cp(b"s", 7, b"C1", b"C2");
    for checkpoint in [&first, &second] {
        assert!(matches!(
            d.try_on_batch_validated(checkpoint.clone()).unwrap()[0],
            ProfileAction::CommitCheckpoint { .. }
        ));
        assert!(d.confirm(checkpoint, b"effects").unwrap().is_empty());
    }
    assert!(
        d.try_on_batch_validated(first.clone()).unwrap().is_empty(),
        "old confirmed result is cached"
    );
    auth.revoked
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        d.try_on_batch_validated(first.clone()),
        Err(syntra_runtime::recovery::InitiatorError::Unauthorized(
            ProviderError::Unauthorized
        ))
    );
    assert_eq!(
        d.engine().generation(b"s"),
        Some(7),
        "revocation is not a provider reset"
    );
    auth.revoked
        .store(false, std::sync::atomic::Ordering::SeqCst);
    d.continuation_expired(b"s");
    for checkpoint in [first, second] {
        assert!(matches!(
            d.try_on_batch_validated(checkpoint).unwrap()[0],
            ProfileAction::SnapshotRequired { .. }
        ));
    }
    assert_eq!(
        d.engine().generation(b"s"),
        Some(7),
        "retention is not a provider reset"
    );
    assert_eq!(d.engine().committed(b"s"), Some(b"C2".as_slice()));
}

#[test]
fn snapshot_staging_enforces_all_descriptor_and_chunk_bounds() {
    let valid = StagedSnapshot::new(vec![1; 256], vec![2; 4096], 256, 262_144).unwrap();
    assert_eq!(valid.total_pages(), 256);
    for (boundary, pages, bytes) in [
        (vec![2; 4097], 1, 1),
        (vec![2], 0, 1),
        (vec![2], 257, 1),
        (vec![2], 1, 0),
        (vec![2], 1, 262_145),
    ] {
        assert!(matches!(
            StagedSnapshot::new(b"X".to_vec(), boundary, pages, bytes),
            Err(SnapshotError::OverLimit)
        ));
    }
    let mut staged = StagedSnapshot::new(b"X".to_vec(), b"S0".to_vec(), 2, 262_144).unwrap();
    assert_eq!(
        staged.stage_page(b"X", u32::MAX, vec![1], b"S0"),
        Err(SnapshotError::InvalidPage)
    );
    assert_eq!(
        staged.stage_page(b"X", 0, vec![1; 262_145], b"S0"),
        Err(SnapshotError::OverLimit)
    );
    assert_eq!(staged.total_bytes(), 0);
    staged.stage_page(b"X", 0, vec![1; 262_144], b"S0").unwrap();
    staged.stage_page(b"X", 0, vec![1; 262_144], b"S0").unwrap();
    assert_eq!(staged.received_pages(), 1);
    assert_eq!(staged.total_bytes(), 262_144);
    staged.stage_page(b"X", 1, vec![2; 262_144], b"S0").unwrap();
    assert_eq!(staged.total_bytes(), 524_288);
    assert_eq!(staged.install().unwrap().len(), 524_288);
}

#[test]
fn host_helper_routes_and_history_are_bounded_without_handle_reuse() {
    let mut h = HostDriver::new(ctx(&"diagnostic".repeat(100)));
    let mut handles = Vec::new();
    for _ in 0..64 {
        let (handle, _) = h.subscribe(b"s".to_vec(), b"C".to_vec(), 7).unwrap();
        assert!(handle.len() <= 256);
        handles.push(handle);
    }
    assert_eq!(
        h.subscribe(b"s".to_vec(), b"C".to_vec(), 7),
        Err(ProviderError::Overloaded)
    );
    h.unsubscribe(&handles[0]).unwrap();
    let (next, _) = h.subscribe(b"s".to_vec(), b"C".to_vec(), 7).unwrap();
    assert!(!handles.contains(&next));
    let batch = StoredBatch {
        predecessor: b"C".to_vec(),
        result: b"D".to_vec(),
        payload: vec![1],
        generation: 7,
    };
    for _ in 0..4096 {
        h.append_batch(b"s".to_vec(), batch.clone()).unwrap();
    }
    assert_eq!(
        h.append_batch(b"s".to_vec(), batch),
        Err(ProviderError::Overloaded)
    );
}
