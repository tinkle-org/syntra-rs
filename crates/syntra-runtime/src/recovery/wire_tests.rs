//! Source-independent host/codec tests using ordinary protobuf payloads.
//! SDK-owned transport integration and FFI contract tests run separately.

use super::*;
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;
use syntra_core::proto::*;

#[derive(Default)]
struct Fixture {
    scopes: HashMap<(String, Vec<u8>), (u64, usize)>,
    denied: HashSet<String>,
    unauthenticated: HashSet<String>,
    generation_error: Option<ProviderError>,
    generation_error_principal: Option<String>,
    issued_error: Option<ProviderError>,
    replay_error: Option<ProviderError>,
    retention_miss: bool,
    wrong_page: bool,
    snapshot_offset: bool,
    snapshot_checkpoint: Option<usize>,
    oversized_snapshot: bool,
}
#[derive(Default)]
struct Source {
    data: Mutex<Fixture>,
    replay_calls: AtomicUsize,
    issued_calls: AtomicUsize,
    snapshot_calls: AtomicUsize,
    fetch_calls: AtomicUsize,
    after_replay: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    after_emit_authorize: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

fn checkpoint(p: &Principal, identity: &[u8], g: u64, n: usize) -> Vec<u8> {
    format!(
        "{}|{}|{g}|{n}",
        p.subject,
        String::from_utf8_lossy(identity)
    )
    .into_bytes()
}
fn ordinal(c: &[u8]) -> usize {
    std::str::from_utf8(c)
        .unwrap()
        .rsplit('|')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
impl Source {
    fn scope(&self, p: &Principal, identity: &[u8], g: u64, n: usize) {
        self.data
            .lock()
            .unwrap()
            .scopes
            .insert((p.subject.clone(), identity.to_vec()), (g, n));
    }
    fn batch(&self, p: &Principal, identity: &[u8], n: usize, bytes: usize) -> StoredBatch {
        let g = self.current_generation(p, identity).unwrap();
        self.scope(p, identity, g, n);
        StoredBatch {
            predecessor: checkpoint(p, identity, g, n - 1),
            result: checkpoint(p, identity, g, n),
            generation: g,
            payload: vec![b'e'; bytes],
        }
    }
}
impl RecoverySource for Source {
    fn authorize(
        &self,
        p: &Principal,
        _: &[u8],
        hook: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        let data = self.data.lock().unwrap();
        let result = if data.unauthenticated.contains(&p.subject) {
            Err(ProviderError::Unauthenticated)
        } else if data.denied.contains(&p.subject) {
            Err(ProviderError::PermissionDenied)
        } else {
            Ok(())
        };
        drop(data);
        if hook == AuthorizationHook::Emit {
            if let Some(f) = self.after_emit_authorize.lock().unwrap().take() {
                f();
            }
        }
        result
    }
    fn capture(&self, p: &Principal, selector: &[u8]) -> Result<ProviderStream, ProviderError> {
        let identity = if selector == b"alias" {
            b"s".as_slice()
        } else {
            selector
        };
        let d = self.data.lock().unwrap();
        let &(g, n) = d
            .scopes
            .get(&(p.subject.clone(), identity.to_vec()))
            .ok_or(ProviderError::Unimplemented)?;
        ProviderStream::new(identity.to_vec(), g, checkpoint(p, identity, g, n))
    }
    fn current_generation(&self, p: &Principal, identity: &[u8]) -> Result<u64, ProviderError> {
        let data = self.data.lock().unwrap();
        if data
            .generation_error_principal
            .as_ref()
            .is_none_or(|subject| *subject == p.subject)
        {
            if let Some(error) = data.generation_error {
                return Err(error);
            }
        }
        data.scopes
            .get(&(p.subject.clone(), identity.to_vec()))
            .map(|s| s.0)
            .ok_or(ProviderError::Unimplemented)
    }
    fn validate_issued(
        &self,
        p: &Principal,
        s: &ProviderStream,
        c: &[u8],
    ) -> Result<(), ProviderError> {
        self.issued_calls.fetch_add(1, Ordering::SeqCst);
        let d = self.data.lock().unwrap();
        if let Some(error) = d.issued_error {
            return Err(error);
        }
        let &(g, n) = d
            .scopes
            .get(&(p.subject.clone(), s.identity.clone()))
            .ok_or(ProviderError::FailedPrecondition)?;
        // Test-only reconstructible issued bindings, deliberately independent of
        // Confirm/session state. This is not production durable storage.
        if g == s.generation && (0..=n).any(|i| checkpoint(p, &s.identity, g, i) == c) {
            Ok(())
        } else {
            Err(ProviderError::FailedPrecondition)
        }
    }
    fn replay(
        &self,
        p: &Principal,
        s: &ProviderStream,
        from: &[u8],
        _: &[u8],
        budget: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        self.replay_calls.fetch_add(1, Ordering::SeqCst);
        let d = self.data.lock().unwrap();
        if let Some(error) = d.replay_error {
            return Err(error);
        }
        if d.retention_miss {
            return Err(ProviderError::ProviderRetentionMiss);
        }
        let mut cursor = ordinal(from);
        let boundary = ordinal(s.boundary());
        let mut batches = Vec::new();
        let mut bytes = 0;
        while cursor < boundary && batches.len() < budget.max_batches {
            let b = StoredBatch {
                predecessor: checkpoint(p, s.identity(), s.generation(), cursor),
                result: checkpoint(p, s.identity(), s.generation(), cursor + 1),
                generation: s.generation(),
                payload: b"echo".to_vec(),
            };
            let encoded = RecoveryBatch {
                profile_version: 1,
                subscription_handle: vec![0; 32],
                generation: b.generation,
                predecessor_checkpoint: b.predecessor.clone(),
                result_checkpoint: b.result.clone(),
                batch_payload: b.payload.clone(),
            }
            .encoded_len();
            if bytes + encoded > budget.max_entry_total_bytes {
                break;
            }
            bytes += encoded;
            batches.push(b);
            cursor += 1;
        }
        let result = checkpoint(p, s.identity(), s.generation(), cursor);
        let marker = if cursor == boundary {
            vec![]
        } else {
            vec![cursor as u8]
        };
        let wrong = d.wrong_page;
        drop(d);
        if let Some(f) = self.after_replay.lock().unwrap().take() {
            f();
        }
        if wrong && !batches.is_empty() {
            batches[0].predecessor = b"wrong".to_vec();
        }
        ProviderPage::new(batches, result, marker)
    }
    fn snapshot(
        &self,
        p: &Principal,
        s: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
        let d = self.data.lock().unwrap();
        let n = d
            .snapshot_checkpoint
            .unwrap_or_else(|| ordinal(s.boundary()) - usize::from(d.snapshot_offset));
        ProviderSnapshot::new(
            b"source-snapshot".to_vec(),
            checkpoint(p, s.identity(), s.generation(), n),
            2,
            16,
        )
    }
    fn snapshot_page(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &ProviderSnapshot,
        index: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![
            index as u8;
            if self.data.lock().unwrap().oversized_snapshot {
                17
            } else {
                16
            }
        ])
    }
}

fn setup(
    limits: RecoveryLimits,
) -> (
    Arc<Source>,
    Arc<RecoveryService>,
    Arc<RecoveryHostSession>,
    Principal,
) {
    let source = Arc::new(Source::default());
    let principal = Principal::new("p");
    source.scope(&principal, b"s", 7, 3);
    let service = RecoveryService::new(source.clone(), limits).unwrap();
    let session = service.open_connection(principal.clone()).unwrap();
    negotiate(&session);
    (source, service, session, principal)
}
fn call<R: Message + Default>(
    s: &RecoveryHostSession,
    method: &str,
    request: &impl Message,
) -> Result<R, ProviderError> {
    let reply = s.handle(method, &request.encode_to_vec())?;
    Ok(R::decode(reply.as_slice()).unwrap())
}
fn negotiate(s: &RecoveryHostSession) {
    let n: RecoveryNegotiateResponse = call(
        s,
        NEGOTIATE,
        &RecoveryNegotiateRequest {
            profile_version: 1,
            min_version: 1,
            max_version: 1,
            capability: CAPABILITY.into(),
        },
    )
    .unwrap();
    assert_eq!(n.selected_version, 1);
    assert_eq!(n.max_pending_rpcs_per_connection, 16);
}
fn subscribe(
    s: &RecoveryHostSession,
    p: &Principal,
    start: Option<usize>,
) -> RecoverySubscribeResponse {
    call(
        s,
        SUBSCRIBE,
        &RecoverySubscribeRequest {
            profile_version: 1,
            stream_selector: b"s".to_vec(),
            start_checkpoint: start.map_or_else(Vec::new, |n| checkpoint(p, b"s", 7, n)),
        },
    )
    .unwrap()
}
fn replay(h: &[u8], p: &Principal, n: usize, marker: &[u8], max: u32) -> RecoveryReplayRequest {
    RecoveryReplayRequest {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        from_checkpoint: checkpoint(p, b"s", 7, n),
        continuation_marker: marker.to_vec(),
        max_batches: max,
        max_bytes: 262_144,
    }
}
fn catchup(h: &[u8]) -> RecoveryCatchUpRequest {
    RecoveryCatchUpRequest {
        profile_version: 1,
        subscription_handle: h.to_vec(),
    }
}
fn offer(h: &[u8]) -> RecoverySnapshotOfferRequest {
    RecoverySnapshotOfferRequest {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        generation: 7,
    }
}
fn event(s: &RecoveryHostSession) -> recovery_notification::Notification {
    codec::decode::<RecoveryNotification>(&s.pop_notification().unwrap().unwrap())
        .unwrap()
        .notification
        .unwrap()
}
fn trailer(s: &RecoveryHostSession) -> RecoveryBatchTrailer {
    match event(s) {
        recovery_notification::Notification::Trailer(t) => t,
        _ => panic!("expected trailer"),
    }
}
fn confirm(
    s: &RecoveryHostSession,
    h: &[u8],
    c: &[u8],
) -> Result<RecoveryConfirmResponse, ProviderError> {
    call(
        s,
        CONFIRM,
        &RecoveryConfirmRequest {
            profile_version: 1,
            subscription_handle: h.to_vec(),
            generation: 7,
            checkpoint: c.to_vec(),
        },
    )
}

#[test]
fn negotiation_is_connection_local_and_has_exact_methods() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    assert_eq!(METHODS.len(), 9);
    for m in METHODS {
        assert_eq!(m.bytes().filter(|b| *b == b'/').count(), 2);
    }
    let other = service.open_connection(p.clone()).unwrap();
    let request = RecoverySubscribeRequest {
        profile_version: 1,
        stream_selector: b"s".to_vec(),
        start_checkpoint: vec![],
    };
    assert_eq!(
        other.handle(SUBSCRIBE, &request.encode_to_vec()),
        Err(ProviderError::Unimplemented)
    );
    assert_eq!(
        s.handle("/syntra.v1.UpdateRecovery/Unknown", &[]),
        Err(ProviderError::Unimplemented)
    );
    assert_eq!(
        s.handle("bad/path", &[]),
        Err(ProviderError::InvalidArgument)
    );
    assert_eq!(
        s.handle("/syntra.v1.UpdateRecovery/Bad/Path", &[]),
        Err(ProviderError::InvalidArgument)
    );
    assert_eq!(
        s.handle(SUBSCRIBE, &[8, 2, 18, 1, b's']),
        Err(ProviderError::FailedPrecondition)
    );
    let no_overlap = RecoveryNegotiateRequest {
        profile_version: 1,
        min_version: 2,
        max_version: 2,
        capability: CAPABILITY.into(),
    };
    assert_eq!(
        other.handle(NEGOTIATE, &no_overlap.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    negotiate(&other);
    assert_eq!(
        other.handle(NEGOTIATE, &no_overlap.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    source.data.lock().unwrap().denied.insert(p.subject.clone());
    assert_eq!(
        s.handle(SUBSCRIBE, &request.encode_to_vec()),
        Err(ProviderError::PermissionDenied)
    );
}

#[test]
fn pages_are_bare_bounded_fixed_b_and_decoded_retries_do_not_advance() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let first = replay(&h.subscription_handle, &p, 0, &[], 1);
    let page: RecoveryReplayPage = call(&s, REPLAY, &first).unwrap();
    assert_eq!(page.batch_payloads.len(), 1);
    let batch: RecoveryBatch = codec::decode(&page.batch_payloads[0]).unwrap();
    assert_eq!(batch.batch_payload, b"echo");
    assert_eq!(batch.subscription_handle, h.subscription_handle);
    assert_eq!(s.pop_notification().unwrap(), None); // page was not a notification
    let mut unknown_retry = first.encode_to_vec();
    unknown_retry.extend_from_slice(&[0xa0, 0x06, 0x01]); // ignored field 100
    let retry = s.handle(REPLAY, &unknown_retry).unwrap();
    assert_eq!(retry, page.encode_to_vec());
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        s.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let wrong = replay(&h.subscription_handle, &p, 1, b"wrong", 1);
    assert_eq!(
        s.handle(REPLAY, &wrong.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    // Live progress cannot move the fixed boundary or leak before completion.
    let b = source.batch(&p, b"s", 4, 4);
    service.publish(&p, b"s", b).unwrap();
    let next = replay(&h.subscription_handle, &p, 1, &page.continuation_marker, 64);
    let final_page: RecoveryReplayPage = call(&s, REPLAY, &next).unwrap();
    assert_eq!(final_page.catchup_boundary, h.catchup_boundary);
    assert_eq!(final_page.result_checkpoint, checkpoint(&p, b"s", 7, 3));
    let completion = event(&s);
    assert!(
        matches!(&completion, recovery_notification::Notification::ReplayComplete(c) if c.live_boundary_checkpoint == h.catchup_boundary)
    );
    let _: RecoveryReplayPage = call(&s, REPLAY, &next).unwrap();
    assert_eq!(event(&s), completion);
    assert!(
        matches!(event(&s), recovery_notification::Notification::Batch(b) if b.result_checkpoint == checkpoint(&p, b"s", 7, 4))
    );
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        s.handle(REPLAY, &first.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let new = subscribe(&s, &p, Some(3));
    assert_ne!(new.subscription_handle, h.subscription_handle);
    assert_eq!(new.catchup_boundary, checkpoint(&p, b"s", 7, 4));
}

#[test]
fn confirms_are_stop_and_wait_and_not_authority_for_resume() {
    let (_, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let c1 = checkpoint(&p, b"s", 7, 1);
    assert_eq!(
        confirm(&s, &h.subscription_handle, &c1),
        Err(ProviderError::FailedPrecondition)
    );
    let _: RecoveryReplayPage =
        call(&s, REPLAY, &replay(&h.subscription_handle, &p, 0, &[], 64)).unwrap();
    assert_eq!(
        confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, 2)),
        Err(ProviderError::FailedPrecondition)
    );
    let one = confirm(&s, &h.subscription_handle, &c1).unwrap();
    assert_eq!(confirm(&s, &h.subscription_handle, &c1).unwrap(), one);
    assert_eq!(one.generation, 7);
    // C2 is durable-known-safe even though no Confirm for C2 was received.
    let fresh = service.open_connection(p.clone()).unwrap();
    negotiate(&fresh);
    let resumed = subscribe(&fresh, &p, Some(2));
    assert_ne!(resumed.subscription_handle, h.subscription_handle);
    assert_eq!(
        fresh.handle(
            CONFIRM,
            &RecoveryConfirmRequest {
                profile_version: 1,
                subscription_handle: resumed.subscription_handle,
                generation: 7,
                checkpoint: c1
            }
            .encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn principal_and_resolved_stream_scope_are_checked_not_selector_equality() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let q = Principal::new("q");
    source.scope(&q, b"s", 7, 3);
    source.scope(&p, b"other", 7, 3);
    let foreign = service.open_connection(q.clone()).unwrap();
    negotiate(&foreign);
    let stolen = RecoverySubscribeRequest {
        profile_version: 1,
        stream_selector: b"s".to_vec(),
        start_checkpoint: checkpoint(&p, b"s", 7, 1),
    };
    assert_eq!(
        foreign.handle(SUBSCRIBE, &stolen.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let other_stream = RecoverySubscribeRequest {
        stream_selector: b"other".to_vec(),
        ..stolen.clone()
    };
    assert_eq!(
        s.handle(SUBSCRIBE, &other_stream.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let h: RecoverySubscribeResponse = call(
        &s,
        SUBSCRIBE,
        &RecoverySubscribeRequest {
            stream_selector: b"alias".to_vec(),
            start_checkpoint: vec![],
            ..stolen
        },
    )
    .unwrap();
    let _: RecoveryCatchUpAccepted = call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    event(&s);
    let b = source.batch(&p, b"s", 4, 1);
    service.publish(&p, b"s", b).unwrap();
    assert!(
        matches!(event(&s), recovery_notification::Notification::Batch(b) if b.subscription_handle == h.subscription_handle)
    );
    assert_eq!(foreign.pop_notification().unwrap(), None);
    assert_eq!(
        foreign.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn catchup_is_pull_driven_bounded_and_exact_acceptance_retries_are_effect_free() {
    let limits = RecoveryLimits {
        replay_batches: 1,
        ..RecoveryLimits::default()
    };
    let (source, _, s, p) = setup(limits);
    let h = subscribe(&s, &p, Some(0));
    let r = catchup(&h.subscription_handle);
    let accepted = s.handle(CATCH_UP, &r.encode_to_vec()).unwrap();
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.queue_counts().unwrap().data_messages, 1);
    assert_eq!(s.handle(CATCH_UP, &r.encode_to_vec()).unwrap(), accepted);
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    for n in 1..=3 {
        assert!(
            matches!(event(&s), recovery_notification::Notification::Batch(b) if b.result_checkpoint == checkpoint(&p, b"s", 7, n))
        );
        assert!(s.queue_counts().unwrap().data_messages <= 1);
    }
    let done = trailer(&s);
    assert_eq!(
        done.outcome,
        Some(recovery_batch_trailer::Outcome::CatchupComplete(true))
    );
    assert_eq!(done.boundary_checkpoint, h.catchup_boundary);
    assert_eq!(s.handle(CATCH_UP, &r.encode_to_vec()).unwrap(), accepted);
    assert_eq!(trailer(&s), done);
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        s.handle(
            REPLAY,
            &replay(&h.subscription_handle, &p, 0, &[], 1).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn initial_skips_replay_and_requires_explicit_baseline_completion() {
    let (source, _, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, None);
    assert_eq!(
        s.handle(
            REPLAY,
            &replay(&h.subscription_handle, &p, 0, &[], 64).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(s.pop_notification().unwrap(), None);
    let _: RecoveryCatchUpAccepted = call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    assert_eq!(
        trailer(&s).outcome,
        Some(recovery_batch_trailer::Outcome::CatchupComplete(true))
    );
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn retention_miss_has_failed_result_and_snapshot_required_at_unchanged_g() {
    for method in [REPLAY, CATCH_UP] {
        let (source, _, s, p) = setup(RecoveryLimits::default());
        source.data.lock().unwrap().retention_miss = true;
        let h = subscribe(&s, &p, Some(0));
        let payload = if method == REPLAY {
            replay(&h.subscription_handle, &p, 0, &[], 64).encode_to_vec()
        } else {
            catchup(&h.subscription_handle).encode_to_vec()
        };
        assert_eq!(
            s.handle(method, &payload),
            Err(ProviderError::ProviderRetentionMiss)
        );
        let t = trailer(&s);
        assert_eq!(t.generation, 7);
        assert_eq!(
            t.outcome,
            Some(recovery_batch_trailer::Outcome::SnapshotRequired(true))
        );
        assert!(t.terminate_reason.is_empty());
        let _: RecoverySnapshotDescriptor =
            call(&s, SNAPSHOT_OFFER, &offer(&h.subscription_handle)).unwrap();
    }
}

fn snapshot(s: &RecoveryHostSession, h: &[u8]) -> RecoverySnapshotDescriptor {
    let d: RecoverySnapshotDescriptor = call(s, SNAPSHOT_OFFER, &offer(h)).unwrap();
    for i in 0..d.total_pages {
        let r = RecoverySnapshotFetchRequest {
            profile_version: 1,
            snapshot_handle: d.snapshot_handle.clone(),
            page_index: i,
        };
        let chunk: RecoverySnapshotChunk = call(s, SNAPSHOT_FETCH, &r).unwrap();
        assert_eq!(chunk.page_index, i);
        assert_eq!(chunk.snapshot_handle, d.snapshot_handle);
        assert_eq!(chunk.boundary_checkpoint, d.boundary_checkpoint);
        assert_eq!(
            call::<RecoverySnapshotChunk>(s, SNAPSHOT_FETCH, &r).unwrap(),
            chunk
        );
    }
    d
}
fn install_request(h: &[u8], d: &RecoverySnapshotDescriptor) -> RecoverySnapshotConfirmRequest {
    RecoverySnapshotConfirmRequest {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        generation: 7,
        boundary_checkpoint: d.boundary_checkpoint.clone(),
    }
}

#[test]
fn snapshots_bind_s0_and_same_g_with_no_wire_complete_and_retained_install_retry() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let d: RecoverySnapshotDescriptor =
        call(&s, SNAPSHOT_OFFER, &offer(&h.subscription_handle)).unwrap();
    let r = install_request(&h.subscription_handle, &d);
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &r.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(snapshot(&s, &h.subscription_handle), d);
    assert_eq!(source.snapshot_calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.pop_notification().unwrap(), None); // no transfer-complete event
    assert_eq!(
        s.handle("/syntra.v1.UpdateRecovery/SnapshotComplete", &[]),
        Err(ProviderError::Unimplemented)
    );
    let installed = s.handle(SNAPSHOT_CONFIRM, &r.encode_to_vec()).unwrap();
    let decoded: RecoverySnapshotInstalled = codec::decode(&installed).unwrap();
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.boundary_checkpoint, d.boundary_checkpoint);
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &r.encode_to_vec()).unwrap(),
        installed
    );
    let mut wrong = r.clone();
    wrong.generation = 8;
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &wrong.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(s.pop_notification().unwrap(), None); // Installed is the gate, not a B completion.
    assert_eq!(
        confirm(&s, &h.subscription_handle, &d.boundary_checkpoint),
        Err(ProviderError::FailedPrecondition)
    );
    let b = source.batch(&p, b"s", 4, 2);
    service.publish(&p, b"s", b).unwrap();
    assert!(
        matches!(event(&s), recovery_notification::Notification::Batch(b) if b.predecessor_checkpoint == d.boundary_checkpoint)
    );
    confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, 4)).unwrap();
    assert_eq!(source.current_generation(&p, b"s").unwrap(), 7);
    // S0 remains resumable independently of the old install-reply cache.
    s.close();
    let fresh = service.open_connection(p.clone()).unwrap();
    negotiate(&fresh);
    subscribe(&fresh, &p, Some(3));
}

#[test]
fn supersede_retires_h_and_x_even_at_equal_s0() {
    let (_, _, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let d = snapshot(&s, &h.subscription_handle);
    s.retire(&h.subscription_handle).unwrap();
    assert_eq!(
        s.handle(
            SNAPSHOT_FETCH,
            &RecoverySnapshotFetchRequest {
                profile_version: 1,
                snapshot_handle: d.snapshot_handle.clone(),
                page_index: 0
            }
            .encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.handle(
            SNAPSHOT_CONFIRM,
            &install_request(&h.subscription_handle, &d).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    let h2 = subscribe(&s, &p, Some(0));
    let d2 = snapshot(&s, &h2.subscription_handle);
    assert_eq!(d.boundary_checkpoint, d2.boundary_checkpoint);
    assert_ne!(h.subscription_handle, h2.subscription_handle);
    assert_ne!(d.snapshot_handle, d2.snapshot_handle);
}

#[test]
fn s0_different_from_b_opens_empty_snapshot_live_gate_without_old_completion() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let request = replay(&h.subscription_handle, &p, 0, &[], 64);
    let _: RecoveryReplayPage = call(&s, REPLAY, &request).unwrap(); // completion queued
    source.data.lock().unwrap().snapshot_offset = true;
    let d = snapshot(&s, &h.subscription_handle);
    assert_eq!(ordinal(&d.boundary_checkpoint), 2);
    assert_ne!(d.boundary_checkpoint, h.catchup_boundary);
    assert_eq!(s.queue_counts().unwrap().control_messages, 0);
    assert_eq!(s.queue_counts().unwrap().offered_checkpoints, 0);
    assert_eq!(s.pop_notification().unwrap(), None); // queued old ReplayComplete was discarded
    assert_eq!(
        s.handle(REPLAY, &request.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let install = install_request(&h.subscription_handle, &d);
    let installed: RecoverySnapshotInstalled = call(&s, SNAPSHOT_CONFIRM, &install).unwrap();
    assert_eq!(installed.generation, 7);
    assert_eq!(installed.boundary_checkpoint, d.boundary_checkpoint);
    assert_eq!(s.pop_notification().unwrap(), None);
    assert_eq!(s.queue_counts().unwrap().control_messages, 0);
    assert_eq!(
        confirm(&s, &h.subscription_handle, &d.boundary_checkpoint),
        Err(ProviderError::FailedPrecondition)
    );
    let b = StoredBatch {
        predecessor: d.boundary_checkpoint.clone(),
        result: h.catchup_boundary.clone(),
        generation: 7,
        payload: vec![1],
    };
    service.publish(&p, b"s", b).unwrap();
    assert!(
        matches!(event(&s), recovery_notification::Notification::Batch(b)
        if b.predecessor_checkpoint == d.boundary_checkpoint && b.generation == 7)
    );
    let acknowledged = confirm(&s, &h.subscription_handle, &h.catchup_boundary).unwrap();
    assert_eq!(
        call::<RecoverySnapshotInstalled>(&s, SNAPSHOT_CONFIRM, &install).unwrap(),
        installed
    );
    assert_eq!(s.pop_notification().unwrap(), None); // retry emits neither completion nor duplicate data
    assert_eq!(
        confirm(&s, &h.subscription_handle, &h.catchup_boundary).unwrap(),
        acknowledged
    );
    assert_eq!(
        s.handle(REPLAY, &request.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(source.current_generation(&p, b"s").unwrap(), 7);
}

#[test]
fn snapshot_confirm_drops_only_the_held_prefix_proven_through_s0() {
    for before_offer in [false, true] {
        for retain_suffix in [false, true] {
            let limits = RecoveryLimits {
                queued_messages_per_stream: 3,
                retained_replies: 2,
                ..RecoveryLimits::default()
            };
            let (source, service, s, p) = setup(limits);
            let h = subscribe(&s, &p, Some(0));
            let request = replay(&h.subscription_handle, &p, 0, &[], 64);
            let _: RecoveryReplayPage = call(&s, REPLAY, &request).unwrap();
            confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, 1)).unwrap();
            assert_eq!(s.queue_counts().unwrap().offered_checkpoints, 2);
            source.scope(&p, b"s", 7, 7);
            source.data.lock().unwrap().snapshot_checkpoint = Some(5);
            let batch = |n| StoredBatch {
                predecessor: checkpoint(&p, b"s", 7, n - 1),
                result: checkpoint(&p, b"s", 7, n),
                generation: 7,
                payload: vec![b'e'; 16],
            };
            let last_held = if retain_suffix { 6 } else { 5 };
            if before_offer {
                for n in 4..=last_held {
                    service.publish(&p, b"s", batch(n)).unwrap();
                }
            }
            let d = snapshot(&s, &h.subscription_handle);
            assert_ne!(d.boundary_checkpoint, h.catchup_boundary);
            if !before_offer {
                for n in 4..=last_held {
                    service.publish(&p, b"s", batch(n)).unwrap();
                }
            }
            let before = s.queue_counts().unwrap();
            assert_eq!(before.data_messages, last_held - 3);
            assert_eq!(before.offered_checkpoints, 0);
            assert_eq!(before.control_messages, 0);
            assert_eq!(before.retained_replies, 1); // old replay reply is no longer retained
            assert_eq!(s.pop_notification().unwrap(), None); // no old completion may release held data
            let install = install_request(&h.subscription_handle, &d);
            let installed = s
                .handle(SNAPSHOT_CONFIRM, &install.encode_to_vec())
                .unwrap();
            let after = s.queue_counts().unwrap();
            assert_eq!(after.data_messages, usize::from(retain_suffix));
            assert!(after.data_bytes < before.data_bytes);
            let expected_bytes = if retain_suffix {
                RecoveryNotification {
                    profile_version: 1,
                    notification: Some(recovery_notification::Notification::Batch(RecoveryBatch {
                        profile_version: 1,
                        subscription_handle: h.subscription_handle.clone(),
                        generation: 7,
                        predecessor_checkpoint: checkpoint(&p, b"s", 7, 5),
                        result_checkpoint: checkpoint(&p, b"s", 7, 6),
                        batch_payload: vec![b'e'; 16],
                    })),
                }
                .encoded_len()
            } else {
                0
            };
            assert_eq!(after.data_bytes, expected_bytes);
            assert_eq!(after.control_messages, 0);
            assert_eq!(after.offered_checkpoints, 0);
            assert_eq!(after.retained_replies, 2);
            // Snapshot S0 and the old batch ledger/acknowledgement are distinct.
            for n in [1, 3, 5] {
                assert_eq!(
                    confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, n)),
                    Err(ProviderError::FailedPrecondition)
                );
            }
            assert_eq!(
                s.handle(SNAPSHOT_CONFIRM, &install.encode_to_vec())
                    .unwrap(),
                installed
            );
            assert_eq!(s.queue_counts().unwrap(), after);
            // Reclaimed queue count/bytes permit new work; the tail is either
            // S0 (empty suffix) or the last retained result, never obsolete B.
            service.publish(&p, b"s", batch(last_held + 1)).unwrap();
            let first = 6;
            for n in first..=last_held + 1 {
                assert!(
                    matches!(event(&s), recovery_notification::Notification::Batch(b)
                    if b.predecessor_checkpoint == checkpoint(&p, b"s", 7, n - 1)
                        && b.result_checkpoint == checkpoint(&p, b"s", 7, n))
                );
            }
            assert_eq!(
                s.handle(SNAPSHOT_CONFIRM, &install.encode_to_vec())
                    .unwrap(),
                installed
            );
            assert_eq!(s.queue_counts().unwrap().offered_checkpoints, last_held - 4);
            for n in first..=last_held + 1 {
                confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, n)).unwrap();
            }
            assert_eq!(s.pop_notification().unwrap(), None);
            assert_eq!(source.current_generation(&p, b"s").unwrap(), 7);
            assert_eq!(source.snapshot_calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn snapshot_confirm_keeps_a_held_chain_already_starting_at_s0_not_old_b() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, None);
    let _: RecoveryCatchUpAccepted = call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    event(&s);
    service
        .publish(&p, b"s", source.batch(&p, b"s", 4, 16))
        .unwrap();
    let delivered = event(&s);
    assert!(matches!(
        delivered,
        recovery_notification::Notification::Batch(_)
    ));
    confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, 4)).unwrap();
    source.data.lock().unwrap().snapshot_checkpoint = Some(4);
    let d = snapshot(&s, &h.subscription_handle);
    assert_ne!(d.boundary_checkpoint, h.catchup_boundary);
    service
        .publish(&p, b"s", source.batch(&p, b"s", 5, 16))
        .unwrap();
    let before = s.queue_counts().unwrap();
    assert_eq!(before.data_messages, 1);
    assert_eq!(s.pop_notification().unwrap(), None);
    let install = install_request(&h.subscription_handle, &d);
    let installed = s
        .handle(SNAPSHOT_CONFIRM, &install.encode_to_vec())
        .unwrap();
    assert_eq!(s.queue_counts().unwrap().data_bytes, before.data_bytes);
    // The old batch confirmation of these same bytes was retired by the offer;
    // snapshot confirmation must not revive it as a batch acknowledgement.
    assert_eq!(
        confirm(&s, &h.subscription_handle, &d.boundary_checkpoint),
        Err(ProviderError::FailedPrecondition)
    );
    service
        .publish(&p, b"s", source.batch(&p, b"s", 6, 16))
        .unwrap();
    for n in [5, 6] {
        assert!(
            matches!(event(&s), recovery_notification::Notification::Batch(b)
            if b.predecessor_checkpoint == checkpoint(&p, b"s", 7, n - 1)
                && b.result_checkpoint == checkpoint(&p, b"s", 7, n))
        );
    }
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &install.encode_to_vec())
            .unwrap(),
        installed
    );
    for n in [5, 6] {
        confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, n)).unwrap();
    }
    assert_eq!(s.pop_notification().unwrap(), None);
}

#[tokio::test]
async fn irreconcilable_snapshot_held_chain_terminates_only_h_and_requires_a_fresh_round() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let healthy = subscribe(&s, &p, None);
    let _: RecoveryCatchUpAccepted =
        call(&s, CATCH_UP, &catchup(&healthy.subscription_handle)).unwrap();
    event(&s);
    service
        .publish(&p, b"s", source.batch(&p, b"s", 4, 16))
        .unwrap();
    assert!(
        matches!(event(&s), recovery_notification::Notification::Batch(b)
        if b.subscription_handle == healthy.subscription_handle)
    );
    source.data.lock().unwrap().snapshot_offset = true; // S0=2, held chain starts at B=3
    let d = snapshot(&s, &h.subscription_handle);
    assert_eq!(s.queue_counts().unwrap().data_messages, 1); // offer must not silently erase it
    let install = install_request(&h.subscription_handle, &d);
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &install.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let counts = s.queue_counts().unwrap();
    assert_eq!(counts.subscriptions, 1);
    assert_eq!(counts.data_bytes, 0);
    assert_eq!(counts.data_messages, 0);
    assert_eq!(counts.control_messages, 1);
    assert_eq!(counts.retained_replies, 1); // only healthy CatchUp acceptance remains
    let bytes = tokio::time::timeout(Duration::from_secs(1), s.next_notification())
        .await
        .unwrap()
        .unwrap(); // explicit control signal, not an idle wait
    let notification: RecoveryNotification = codec::decode(&bytes).unwrap();
    let Some(recovery_notification::Notification::Trailer(t)) = notification.notification else {
        panic!("expected targeted termination");
    };
    assert_eq!(t.subscription_handle, h.subscription_handle);
    assert_eq!(t.generation, 7);
    assert_eq!(
        t.outcome,
        Some(recovery_batch_trailer::Outcome::Terminated(true))
    );
    assert_eq!(t.terminate_reason, b"snapshot-chain-gap");
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &install.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.handle(
            SNAPSHOT_FETCH,
            &RecoverySnapshotFetchRequest {
                profile_version: 1,
                snapshot_handle: d.snapshot_handle,
                page_index: 0,
            }
            .encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    service
        .publish(&p, b"s", source.batch(&p, b"s", 5, 16))
        .unwrap();
    assert!(
        matches!(event(&s), recovery_notification::Notification::Batch(b)
        if b.subscription_handle == healthy.subscription_handle)
    );
    let fresh = subscribe(&s, &p, Some(2));
    assert_ne!(fresh.subscription_handle, h.subscription_handle);
    assert_eq!(fresh.catchup_boundary, checkpoint(&p, b"s", 7, 5));
    let _: RecoveryReplayPage = call(
        &s,
        REPLAY,
        &replay(&fresh.subscription_handle, &p, 2, &[], 64),
    )
    .unwrap();
    assert!(
        matches!(event(&s), recovery_notification::Notification::ReplayComplete(c)
        if c.subscription_handle == fresh.subscription_handle)
    );
    assert_eq!(source.current_generation(&p, b"s").unwrap(), 7);
    assert!(!s.is_closed());
}

#[test]
fn local_overflow_terminates_only_the_slow_handle_and_reserves_control_capacity() {
    let limits = RecoveryLimits {
        queued_bytes_per_stream: 180,
        ..RecoveryLimits::default()
    };
    let (source, service, slow, p) = setup(limits);
    let fast = service.open_connection(p.clone()).unwrap();
    negotiate(&fast);
    let hs = subscribe(&slow, &p, None);
    let hf = subscribe(&fast, &p, None);
    let _: RecoveryCatchUpAccepted =
        call(&slow, CATCH_UP, &catchup(&hs.subscription_handle)).unwrap();
    event(&slow);
    let _: RecoveryCatchUpAccepted =
        call(&fast, CATCH_UP, &catchup(&hf.subscription_handle)).unwrap();
    event(&fast);
    for n in 4..=5 {
        let b = source.batch(&p, b"s", n, 60);
        let result = service.publish(&p, b"s", b);
        if n == 5 {
            assert_eq!(result, Err(ProviderError::ResourceExhausted));
        }
        assert!(matches!(
            event(&fast),
            recovery_notification::Notification::Batch(_)
        ));
    }
    let counts = slow.queue_counts().unwrap();
    assert_eq!(counts.data_bytes, 0);
    assert_eq!(counts.subscriptions, 0);
    assert_eq!(counts.control_messages, 1);
    let t = trailer(&slow);
    assert_eq!(t.subscription_handle, hs.subscription_handle);
    assert_eq!(t.generation, 7);
    assert_eq!(
        t.outcome,
        Some(recovery_batch_trailer::Outcome::Terminated(true))
    );
    assert_eq!(t.terminate_reason, b"local-queue-exhausted");
    assert_eq!(source.current_generation(&p, b"s").unwrap(), 7);
    assert_eq!(fast.queue_counts().unwrap().subscriptions, 1);
}

#[test]
fn provider_loss_fences_old_generation_only_in_the_declared_principal_scope() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let q = Principal::new("q");
    source.scope(&q, b"s", 7, 3);
    let other = service.open_connection(q.clone()).unwrap();
    negotiate(&other);
    let h = subscribe(&s, &p, Some(0));
    let hq = subscribe(&other, &q, Some(0));
    let d = snapshot(&s, &h.subscription_handle);
    source.scope(&p, b"s", 8, 3);
    service
        .provider_loss(&p, b"s", 7, 8, ProviderLoss::HistoryLost)
        .unwrap();
    let t = trailer(&s);
    assert_eq!(t.generation, 7);
    assert_eq!(
        t.outcome,
        Some(recovery_batch_trailer::Outcome::NextGeneration(8))
    );
    assert_eq!(
        s.handle(
            SNAPSHOT_CONFIRM,
            &install_request(&h.subscription_handle, &d).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.handle(
            REPLAY,
            &replay(&h.subscription_handle, &p, 0, &[], 64).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    let _: RecoveryReplayPage = call(
        &other,
        REPLAY,
        &replay(&hq.subscription_handle, &q, 0, &[], 64),
    )
    .unwrap();
}

#[test]
fn revocation_is_rechecked_before_emission_and_never_manufactures_an_epoch() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, None);
    let _: RecoveryCatchUpAccepted = call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    event(&s);
    let b = source.batch(&p, b"s", 4, 1);
    service.publish(&p, b"s", b).unwrap();
    source.data.lock().unwrap().denied.insert(p.subject.clone());
    let t = trailer(&s);
    assert_eq!(t.generation, 7);
    assert_eq!(
        t.outcome,
        Some(recovery_batch_trailer::Outcome::Terminated(true))
    );
    assert_eq!(t.terminate_reason, b"authorization-ended");
    assert_eq!(s.queue_counts().unwrap().data_bytes, 0);
}

#[test]
fn aggregate_principal_quotas_drop_and_close_release_state() {
    let limits = RecoveryLimits {
        subscriptions_per_principal: 2,
        max_connections: 2,
        ..RecoveryLimits::default()
    };
    let (_, service, s, p) = setup(limits);
    let second = service.open_connection(p.clone()).unwrap();
    negotiate(&second);
    let h = subscribe(&s, &p, None);
    subscribe(&second, &p, None);
    let request = RecoverySubscribeRequest {
        profile_version: 1,
        stream_selector: b"s".to_vec(),
        start_checkpoint: vec![],
    };
    assert_eq!(
        s.handle(SUBSCRIBE, &request.encode_to_vec()),
        Err(ProviderError::ResourceExhausted)
    );
    assert!(matches!(
        service.open_connection(p.clone()),
        Err(ProviderError::ResourceExhausted)
    ));
    drop(second);
    subscribe(&s, &p, None);
    s.close();
    assert_eq!(
        s.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::Unavailable)
    );
    let fresh = service.open_connection(p).unwrap();
    assert_eq!(
        fresh.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::Unimplemented)
    );
    negotiate(&fresh);
    assert_eq!(
        fresh.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn retained_reply_expiry_and_retry_budget_never_repeat_installation_or_catchup() {
    let limits = RecoveryLimits {
        reply_ttl: Duration::from_millis(200),
        reply_retries: 1,
        ..RecoveryLimits::default()
    };
    let (source, _, s, p) = setup(limits);
    let h = subscribe(&s, &p, None);
    let r = catchup(&h.subscription_handle);
    s.handle(CATCH_UP, &r.encode_to_vec()).unwrap();
    s.handle(CATCH_UP, &r.encode_to_vec()).unwrap();
    assert_eq!(
        s.handle(CATCH_UP, &r.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    let d = snapshot(&s, &h.subscription_handle);
    let r = install_request(&h.subscription_handle, &d);
    s.handle(SNAPSHOT_CONFIRM, &r.encode_to_vec()).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        s.handle(SNAPSHOT_CONFIRM, &r.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(source.snapshot_calls.load(Ordering::SeqCst), 1);
    assert_eq!(s.queue_counts().unwrap().retained_reply_bytes, 0);
}

#[test]
fn handles_and_snapshot_handles_never_reuse_and_exhaustion_is_checked() {
    let limits = RecoveryLimits {
        subscriptions_per_connection: 1,
        handles_per_connection: 2,
        ..RecoveryLimits::default()
    };
    let (_, _, s, p) = setup(limits);
    let h = subscribe(&s, &p, None);
    let _: RecoverySnapshotDescriptor =
        call(&s, SNAPSHOT_OFFER, &offer(&h.subscription_handle)).unwrap();
    let _: RecoveryUnsubscribeResponse = call(
        &s,
        UNSUBSCRIBE,
        &RecoveryUnsubscribeRequest {
            profile_version: 1,
            subscription_handle: h.subscription_handle.clone(),
        },
    )
    .unwrap();
    trailer(&s);
    assert_eq!(
        s.handle(
            SUBSCRIBE,
            &RecoverySubscribeRequest {
                profile_version: 1,
                stream_selector: b"s".to_vec(),
                start_checkpoint: vec![]
            }
            .encode_to_vec()
        ),
        Err(ProviderError::ResourceExhausted)
    );
    assert_eq!(
        s.handle(CATCH_UP, &catchup(&h.subscription_handle).encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn invalid_provider_outputs_and_deadline_do_not_expose_partial_pages() {
    let (source, _, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    source.data.lock().unwrap().wrong_page = true;
    let r = replay(&h.subscription_handle, &p, 0, &[], 64);
    assert_eq!(
        s.handle(REPLAY, &r.encode_to_vec()),
        Err(ProviderError::Internal)
    );
    assert_eq!(s.queue_counts().unwrap().offered_checkpoints, 0);
    source.data.lock().unwrap().wrong_page = false;
    *source.after_replay.lock().unwrap() =
        Some(Box::new(|| std::thread::sleep(Duration::from_millis(5))));
    assert_eq!(
        s.handle_with_deadline(REPLAY, &r.encode_to_vec(), Duration::from_millis(1)),
        Err(ProviderError::DeadlineExceeded)
    );
    assert_eq!(s.queue_counts().unwrap().offered_checkpoints, 0);
    assert_eq!(
        s.handle_with_deadline(REPLAY, &r.encode_to_vec(), Duration::ZERO),
        Err(ProviderError::DeadlineExceeded)
    );
    let _: RecoveryReplayPage = call(&s, REPLAY, &r).unwrap();
}

#[test]
fn close_and_generation_change_during_provider_callback_fence_the_result() {
    for close in [false, true] {
        let (source, _, s, p) = setup(RecoveryLimits::default());
        let h = subscribe(&s, &p, Some(0));
        let weak = Arc::downgrade(&s);
        let source_weak = Arc::downgrade(&source);
        let principal = p.clone();
        *source.after_replay.lock().unwrap() = Some(Box::new(move || {
            // Reentrant close is legal, and must not deadlock on a state mutex.
            if close {
                weak.upgrade().unwrap().close();
            } else {
                source_weak.upgrade().unwrap().scope(&principal, b"s", 8, 3);
            }
        }));
        let error = if close {
            ProviderError::Unavailable
        } else {
            ProviderError::FailedPrecondition
        };
        assert_eq!(
            s.handle(
                REPLAY,
                &replay(&h.subscription_handle, &p, 0, &[], 64).encode_to_vec()
            ),
            Err(error)
        );
        if !close {
            assert_eq!(
                trailer(&s).outcome,
                Some(recovery_batch_trailer::Outcome::NextGeneration(8))
            );
        }
    }
}

#[tokio::test]
async fn notification_wait_has_no_idle_spin_or_lost_wakeup_and_close_is_final() {
    let (_, _, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, None);
    assert!(
        tokio::time::timeout(Duration::from_millis(10), s.next_notification())
            .await
            .is_err()
    );
    let task = {
        let s = s.clone();
        tokio::spawn(async move { s.next_notification().await })
    };
    tokio::task::yield_now().await;
    let _: RecoveryCatchUpAccepted = call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(codec::decode::<RecoveryNotification>(&bytes).is_ok());
    let task = {
        let s = s.clone();
        tokio::spawn(async move { s.next_notification().await })
    };
    tokio::task::yield_now().await;
    s.close();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap(),
        None
    );
    assert_eq!(s.next_notification().await, None);
}

#[test]
fn finite_limits_and_bounded_provider_constructors() {
    assert!(RecoveryLimits::default().validate().is_ok());
    for pending in [0, 17, usize::MAX] {
        assert!(RecoveryLimits {
            pending_rpcs_per_connection: pending,
            ..RecoveryLimits::default()
        }
        .validate()
        .is_err());
    }
    for pending in [1, 15, 16] {
        assert!(RecoveryLimits {
            pending_rpcs_per_connection: pending,
            ..RecoveryLimits::default()
        }
        .validate()
        .is_ok());
    }
    assert!(RecoveryLimits {
        replay_bytes: 262_145,
        ..RecoveryLimits::default()
    }
    .validate()
    .is_err());
    assert!(RecoveryLimits {
        queued_messages_per_stream: 0,
        ..RecoveryLimits::default()
    }
    .validate()
    .is_err());
    assert!(ProviderStream::new(vec![1], 0, vec![1]).is_err());
    assert!(ProviderStream::new(vec![1], 1, vec![]).is_err());
    assert!(ProviderSnapshot::new(vec![1], vec![1], 257, 1).is_err());
    assert!(ProviderSnapshot::new(vec![1], vec![1], 1, 262_145).is_err());
}

#[test]
fn pending_profile_quota_one_is_accepted_and_negotiated() {
    let service = RecoveryService::new(
        Arc::new(Source::default()),
        RecoveryLimits {
            pending_rpcs_per_connection: 1,
            ..RecoveryLimits::default()
        },
    )
    .unwrap();
    let session = service.open_connection(Principal::new("p")).unwrap();
    let response: RecoveryNegotiateResponse = call(
        &session,
        NEGOTIATE,
        &RecoveryNegotiateRequest {
            profile_version: 1,
            min_version: 1,
            max_version: 1,
            capability: CAPABILITY.into(),
        },
    )
    .unwrap();
    assert_eq!(response.max_pending_rpcs_per_connection, 1);
}

fn len_field(tag: u32, bytes: &[u8]) -> Vec<u8> {
    fn var(mut n: u64, out: &mut Vec<u8>) {
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    let mut v = Vec::new();
    var(u64::from(tag) << 3 | 2, &mut v);
    var(bytes.len() as u64, &mut v);
    v.extend(bytes);
    v
}

#[test]
fn codec_preflight_checks_types_lengths_recursion_and_unknown_fields() {
    let valid = RecoverySubscribeRequest {
        profile_version: 1,
        stream_selector: vec![1; 1024],
        start_checkpoint: vec![1; 4096],
    };
    assert_eq!(
        codec::decode::<RecoverySubscribeRequest>(&valid.encode_to_vec()).unwrap(),
        valid
    );
    let too_big = RecoverySubscribeRequest {
        stream_selector: vec![1; 1025],
        ..valid.clone()
    };
    assert!(codec::decode::<RecoverySubscribeRequest>(&too_big.encode_to_vec()).is_err());
    assert!(codec::decode::<RecoverySubscribeRequest>(&[8, 1, 16, 1]).is_err()); // bytes with varint type
    assert!(codec::decode::<RecoverySubscribeRequest>(&[8, 1, 18, 0xff, 0xff]).is_err()); // truncated length
    assert!(codec::decode::<RecoverySubscribeRequest>(&[8, 1, 0]).is_err()); // tag zero
    assert!(codec::decode::<RecoverySubscribeRequest>(&[8, 0xff, 0xff, 0xff, 0xff, 0x1f]).is_err()); // u32 overflow
    let mut unknown = valid.encode_to_vec();
    unknown.extend(len_field(100, &[0xff, 0]));
    assert_eq!(
        codec::decode::<RecoverySubscribeRequest>(&unknown).unwrap(),
        valid
    );
    unknown.extend_from_slice(&[0xab, 0x06, 8, 1, 0xac, 0x06]); // unknown group tag 101
    assert_eq!(
        codec::decode::<RecoverySubscribeRequest>(&unknown).unwrap(),
        valid
    );
    let mut group = vec![];
    for _ in 0..34 {
        group.extend_from_slice(&[0xab, 0x06]);
    }
    for _ in 0..34 {
        group.extend_from_slice(&[0xac, 0x06]);
    }
    assert!(codec::decode::<RecoverySubscribeRequest>(&group).is_err());
    let nested = len_field(2, &[8, 1, 18, 0xff, 0xff, 0x7f]);
    assert!(codec::decode::<RecoveryNotification>(&[vec![8, 1], nested].concat()).is_err());
    assert!(codec::decode::<RecoveryNotification>(&[8, 1]).is_err()); // unset arm
    assert_eq!(
        codec::decode::<RecoveryNotification>(&vec![0; syntra_core::MAX_FRAME_BYTES]),
        Err(ProviderError::ResourceExhausted)
    );
}

#[test]
fn profile_oneofs_follow_protobuf_last_arm_semantics_not_core_raw_partition() {
    let complete = RecoveryReplayComplete {
        profile_version: 1,
        subscription_handle: vec![1],
        generation: 7,
        live_boundary_checkpoint: vec![2],
    };
    let trailer = RecoveryBatchTrailer {
        profile_version: 1,
        subscription_handle: vec![1],
        generation: 7,
        boundary_checkpoint: vec![2],
        outcome: Some(recovery_batch_trailer::Outcome::SnapshotRequired(true)),
        terminate_reason: vec![],
    };
    let bytes = [
        vec![8, 1],
        len_field(3, &complete.encode_to_vec()),
        len_field(4, &trailer.encode_to_vec()),
    ]
    .concat();
    let n: RecoveryNotification = codec::decode(&bytes).unwrap();
    assert_eq!(
        n.notification,
        Some(recovery_notification::Notification::Trailer(trailer))
    );
    // Same message arm merges ordinary fields across occurrences.
    let split = [
        vec![8, 1],
        len_field(3, &[8, 1, 18, 1, 1]),
        len_field(3, &[24, 7, 34, 1, 2]),
    ]
    .concat();
    assert_eq!(
        codec::decode::<RecoveryNotification>(&split)
            .unwrap()
            .notification,
        Some(recovery_notification::Notification::ReplayComplete(
            complete
        ))
    );
}

#[test]
fn pinned_payload_field_mapping_vectors_are_envelope_neutral() {
    // Literal protobuf field mappings from the pinned accepted IDL, not an
    // encode/decode roundtrip generated by the implementation under test.
    let negotiate = b"\x08\x01\x10\x01\x18\x01\x22\x18syntra.update-recovery/1";
    assert_eq!(
        codec::decode::<RecoveryNegotiateRequest>(negotiate)
            .unwrap()
            .capability,
        CAPABILITY
    );
    let subscribe = b"\x08\x01\x12\x01s\x1a\x01c";
    assert_eq!(
        codec::decode::<RecoverySubscribeRequest>(subscribe)
            .unwrap()
            .start_checkpoint,
        b"c"
    );
    let batch = b"\x08\x01\x12\x01h\x18\x07\x22\x01c\x2a\x01d\x32\x04echo";
    let decoded: RecoveryBatch = codec::decode(batch).unwrap();
    assert_eq!(decoded.batch_payload, b"echo");
    assert_eq!(decoded.predecessor_checkpoint, b"c");
    assert_eq!(decoded.result_checkpoint, b"d");
    let page = [
        b"\x08\x01\x12\x01h\x1a\x01c\x22\x01d\x32\x01d\x3a\x13".as_slice(),
        batch,
    ]
    .concat();
    assert_eq!(
        codec::decode::<RecoveryReplayPage>(&page)
            .unwrap()
            .batch_payloads,
        vec![batch.to_vec()]
    );
    let notification = [b"\x08\x01\x12\x13".as_slice(), batch].concat();
    assert_eq!(
        codec::decode::<RecoveryNotification>(&notification)
            .unwrap()
            .notification,
        Some(recovery_notification::Notification::Batch(decoded))
    );
    let local_full = b"\x08\x01\x12\x01h\x18\x07\x40\x01\x4a\x15local-queue-exhausted";
    let t: RecoveryBatchTrailer = codec::decode(local_full).unwrap();
    assert_eq!(
        t.outcome,
        Some(recovery_batch_trailer::Outcome::Terminated(true))
    );
    let loss: RecoveryBatchTrailer = codec::decode(b"\x08\x01\x12\x01h\x18\x07\x28\x08").unwrap();
    assert_eq!(
        loss.outcome,
        Some(recovery_batch_trailer::Outcome::NextGeneration(8))
    );
}

#[test]
fn serialized_entry_limits_include_tags_and_page_overhead_is_separate_core_bound() {
    let mut b = RecoveryBatch {
        profile_version: 1,
        subscription_handle: vec![b'h'],
        generation: 7,
        predecessor_checkpoint: vec![b'c'],
        result_checkpoint: vec![b'd'],
        batch_payload: vec![0; 262_120],
    };
    while b.encoded_len() != 262_144 {
        let length = b.batch_payload.len() as isize + 262_144 - b.encoded_len() as isize;
        b.batch_payload.resize(length as usize, 0);
    }
    let exact = codec::encode(&b).unwrap();
    assert_eq!(exact.len(), 262_144);
    b.batch_payload.push(0);
    assert!(codec::encode(&b).is_err());
    assert!(codec::decode::<RecoveryBatch>(&b.encode_to_vec()).is_err());
    let mut page = RecoveryReplayPage {
        profile_version: 1,
        subscription_handle: vec![b'h'],
        predecessor_checkpoint: vec![b'c'],
        result_checkpoint: vec![b'd'],
        catchup_boundary: vec![b'd'],
        continuation_marker: vec![],
        batch_payloads: vec![exact],
    };
    let encoded = codec::encode(&page).unwrap();
    assert!(encoded.len() > 262_144); // entry-total limit is not the complete page bound
    assert!(encoded.len() <= codec::MAX_PAYLOAD_BYTES);
    assert!(codec::decode::<RecoveryReplayPage>(&encoded).is_ok());
    page.batch_payloads.push(vec![0]);
    assert!(codec::decode::<RecoveryReplayPage>(&page.encode_to_vec()).is_err());
}

#[test]
fn aggregate_queue_and_retained_reply_count_overflow_remain_targeted() {
    let limits = RecoveryLimits {
        queued_bytes_per_connection: 150,
        ..RecoveryLimits::default()
    };
    let (source, service, s, p) = setup(limits);
    let first = subscribe(&s, &p, None);
    let second = subscribe(&s, &p, None);
    for h in [&first, &second] {
        let _: RecoveryCatchUpAccepted =
            call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
        event(&s);
    }
    let b = source.batch(&p, b"s", 4, 60);
    assert_eq!(
        service.publish(&p, b"s", b),
        Err(ProviderError::ResourceExhausted)
    );
    assert!(s.queue_counts().unwrap().data_bytes <= 150);
    // Round-robin permits a batch for the unaffected H before the other trailer.
    let events = [event(&s), event(&s)];
    assert!(events.iter().any(|e| matches!(e, recovery_notification::Notification::Trailer(t)
        if t.subscription_handle == second.subscription_handle && t.terminate_reason == b"local-queue-exhausted")));
    assert_eq!(s.queue_counts().unwrap().subscriptions, 1);

    let limits = RecoveryLimits {
        retained_replies: 1,
        ..RecoveryLimits::default()
    };
    let (_, _, s, p) = setup(limits);
    let first = subscribe(&s, &p, None);
    let second = subscribe(&s, &p, None);
    let _: RecoveryCatchUpAccepted =
        call(&s, CATCH_UP, &catchup(&first.subscription_handle)).unwrap();
    assert_eq!(
        s.handle(
            CATCH_UP,
            &catchup(&second.subscription_handle).encode_to_vec()
        ),
        Err(ProviderError::ResourceExhausted)
    );
    assert_eq!(s.queue_counts().unwrap().retained_replies, 1);
    assert_eq!(s.queue_counts().unwrap().subscriptions, 1);
}

#[test]
fn callback_reentrancy_is_fail_fast_and_provider_panics_propagate_and_close() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let weak = Arc::downgrade(&s);
    *source.after_replay.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(
            weak.upgrade().unwrap().queue_counts(),
            Err(ProviderError::ResourceExhausted)
        );
    }));
    let r = replay(&h.subscription_handle, &p, 0, &[], 1);
    let page: RecoveryReplayPage = call(&s, REPLAY, &r).unwrap();
    *source.after_replay.lock().unwrap() = Some(Box::new(|| panic!("test-only provider panic")));
    let next = replay(&h.subscription_handle, &p, 1, &page.continuation_marker, 1);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || s.handle(REPLAY, &next.encode_to_vec())
    ))
    .is_err());
    assert!(s.is_closed());
    // Panic did not leak admission quota or keep a strong session registry entry.
    let fresh = service.open_connection(p).unwrap();
    negotiate(&fresh);
}

#[test]
fn snapshot_chunk_bounds_and_cross_connection_x_are_checked_without_partial_install() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let d: RecoverySnapshotDescriptor =
        call(&s, SNAPSHOT_OFFER, &offer(&h.subscription_handle)).unwrap();
    let fetch = RecoverySnapshotFetchRequest {
        profile_version: 1,
        snapshot_handle: d.snapshot_handle.clone(),
        page_index: 0,
    };
    let other = service.open_connection(p.clone()).unwrap();
    negotiate(&other);
    assert_eq!(
        other.handle(SNAPSHOT_FETCH, &fetch.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    source.data.lock().unwrap().oversized_snapshot = true;
    assert_eq!(
        s.handle(SNAPSHOT_FETCH, &fetch.encode_to_vec()),
        Err(ProviderError::Internal)
    );
    assert_eq!(
        s.handle(
            SNAPSHOT_CONFIRM,
            &install_request(&h.subscription_handle, &d).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    source.data.lock().unwrap().oversized_snapshot = false;
    let _: RecoverySnapshotChunk = call(&s, SNAPSHOT_FETCH, &fetch).unwrap();
    let invalid = RecoverySnapshotFetchRequest {
        page_index: 2,
        ..fetch
    };
    assert_eq!(
        s.handle(SNAPSHOT_FETCH, &invalid.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.handle(
            SNAPSHOT_CONFIRM,
            &install_request(&h.subscription_handle, &d).encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
}

fn popped_live_batch(
    source: &Source,
    service: &RecoveryService,
    session: &RecoveryHostSession,
    principal: &Principal,
) -> (RecoverySubscribeResponse, Vec<u8>) {
    let h = subscribe(session, principal, None);
    let _: RecoveryCatchUpAccepted =
        call(session, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    let baseline = session.pop_notification().unwrap().unwrap();
    session.revalidate_notification(&baseline).unwrap();
    service
        .publish(principal, b"s", source.batch(principal, b"s", 4, 16))
        .unwrap();
    (h, session.pop_notification().unwrap().unwrap())
}

#[tokio::test]
async fn egress_reauthorization_after_writer_barrier_denies_popped_batch_and_targets_h() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let (h, bytes) = popped_live_batch(&source, &service, &s, &p);
    let other = subscribe(&s, &p, None);
    let (writer_reserved, reservation) = tokio::sync::oneshot::channel();
    let output = {
        let session = s.clone();
        tokio::spawn(async move {
            reservation.await.unwrap(); // model the parent's bounded writer-reservation barrier
            session.revalidate_notification(&bytes)
        })
    };
    source.data.lock().unwrap().denied.insert(p.subject.clone());
    writer_reserved.send(()).unwrap();
    assert_eq!(output.await.unwrap(), Err(ProviderError::PermissionDenied));
    assert!(!s.is_closed());
    assert_eq!(s.terminal_error(), None); // permission denial is not core withdrawal
    assert_eq!(s.queue_counts().unwrap().subscriptions, 1);
    source.data.lock().unwrap().denied.clear();
    let terminal = s.pop_notification().unwrap().unwrap();
    s.revalidate_notification(&terminal).unwrap(); // H's slot was removed by pop
    let t: RecoveryNotification = codec::decode(&terminal).unwrap();
    assert!(
        matches!(t.notification, Some(recovery_notification::Notification::Trailer(t))
        if t.subscription_handle == h.subscription_handle && t.generation == 7
            && t.outcome == Some(recovery_batch_trailer::Outcome::Terminated(true))
            && t.terminate_reason == b"authorization-ended")
    );
    let _: RecoveryCatchUpAccepted =
        call(&s, CATCH_UP, &catchup(&other.subscription_handle)).unwrap();
    let unaffected = s.pop_notification().unwrap().unwrap();
    s.revalidate_notification(&unaffected).unwrap();
}

#[tokio::test]
async fn egress_generation_recheck_after_writer_barrier_fences_popped_batch() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let (h, bytes) = popped_live_batch(&source, &service, &s, &p);
    let (writer_reserved, reservation) = tokio::sync::oneshot::channel();
    let output = {
        let session = s.clone();
        tokio::spawn(async move {
            reservation.await.unwrap();
            session.revalidate_notification(&bytes)
        })
    };
    source.scope(&p, b"s", 8, 4); // no explicit service loss call: final Emit must discover it
    writer_reserved.send(()).unwrap();
    assert_eq!(
        output.await.unwrap(),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(s.queue_counts().unwrap().subscriptions, 0);
    let loss = s.pop_notification().unwrap().unwrap();
    let t: RecoveryNotification = codec::decode(&loss).unwrap();
    assert!(
        matches!(t.notification, Some(recovery_notification::Notification::Trailer(t))
        if t.subscription_handle == h.subscription_handle && t.generation == 7
            && t.outcome == Some(recovery_batch_trailer::Outcome::NextGeneration(8)))
    );
    source.scope(&p, b"s", 9, 4);
    s.revalidate_notification(&loss).unwrap(); // old control is conservative, not protected data
    assert!(!s.is_closed());
}

#[test]
fn egress_normal_batch_and_both_completion_forms_revalidate_without_progress_effects() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let (h, bytes) = popped_live_batch(&source, &service, &s, &p);
    let before = s.queue_counts().unwrap();
    s.revalidate_notification(&bytes).unwrap();
    s.revalidate_notification(&bytes).unwrap();
    assert_eq!(s.queue_counts().unwrap(), before);
    confirm(&s, &h.subscription_handle, &checkpoint(&p, b"s", 7, 4)).unwrap();
    s.revalidate_notification(&bytes).unwrap(); // valid, scoped already-confirmed duplicate

    let resumed = subscribe(&s, &p, Some(3));
    let request = replay(&resumed.subscription_handle, &p, 3, &[], 64);
    let _: RecoveryReplayPage = call(&s, REPLAY, &request).unwrap();
    let completion = s.pop_notification().unwrap().unwrap();
    s.revalidate_notification(&completion).unwrap();
    source.scope(&p, b"s", 8, 4);
    assert_eq!(
        s.revalidate_notification(&completion),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        trailer(&s).outcome,
        Some(recovery_batch_trailer::Outcome::NextGeneration(8))
    );
}

#[test]
fn egress_completion_from_either_mode_is_fenced_when_generation_changes_after_pop() {
    for method in [REPLAY, CATCH_UP] {
        let (source, _, s, p) = setup(RecoveryLimits::default());
        let h = subscribe(&s, &p, Some(3));
        if method == REPLAY {
            let _: RecoveryReplayPage =
                call(&s, REPLAY, &replay(&h.subscription_handle, &p, 3, &[], 64)).unwrap();
        } else {
            let _: RecoveryCatchUpAccepted =
                call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
        }
        let completion = s.pop_notification().unwrap().unwrap();
        s.revalidate_notification(&completion).unwrap();
        source.scope(&p, b"s", 8, 3);
        assert_eq!(
            s.revalidate_notification(&completion),
            Err(ProviderError::FailedPrecondition)
        );
        let t = trailer(&s);
        assert_eq!(t.subscription_handle, h.subscription_handle);
        assert_eq!(t.generation, 7);
        assert_eq!(
            t.outcome,
            Some(recovery_batch_trailer::Outcome::NextGeneration(8))
        );
    }
}

#[test]
fn egress_snapshot_required_is_active_control_and_old_b_completion_cannot_bypass_snapshot_gate() {
    for before_install in [false, true] {
        let (source, service, s, p) = setup(RecoveryLimits::default());
        let h = subscribe(&s, &p, None);
        let _: RecoveryCatchUpAccepted =
            call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
        let old_completion = s.pop_notification().unwrap().unwrap();
        s.revalidate_notification(&old_completion).unwrap();
        let d = snapshot(&s, &h.subscription_handle);
        if !before_install {
            let _: RecoverySnapshotInstalled = call(
                &s,
                SNAPSHOT_CONFIRM,
                &install_request(&h.subscription_handle, &d),
            )
            .unwrap();
        }
        assert_eq!(
            s.revalidate_notification(&old_completion),
            Err(ProviderError::FailedPrecondition)
        );
        assert_eq!(s.queue_counts().unwrap().subscriptions, 1); // stale phase cannot kill current snapshot
        if before_install {
            let _: RecoverySnapshotInstalled = call(
                &s,
                SNAPSHOT_CONFIRM,
                &install_request(&h.subscription_handle, &d),
            )
            .unwrap();
        }
        service
            .publish(&p, b"s", source.batch(&p, b"s", 4, 1))
            .unwrap();
        let live = s.pop_notification().unwrap().unwrap();
        s.revalidate_notification(&live).unwrap();
    }
    let (source, _, s, p) = setup(RecoveryLimits::default());
    source.data.lock().unwrap().retention_miss = true;
    let h = subscribe(&s, &p, Some(0));
    assert_eq!(
        s.handle(
            REPLAY,
            &replay(&h.subscription_handle, &p, 0, &[], 64).encode_to_vec()
        ),
        Err(ProviderError::ProviderRetentionMiss)
    );
    let required = s.pop_notification().unwrap().unwrap();
    s.revalidate_notification(&required).unwrap();
    let _: RecoverySnapshotDescriptor =
        call(&s, SNAPSHOT_OFFER, &offer(&h.subscription_handle)).unwrap();
    assert_eq!(
        s.revalidate_notification(&required),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn egress_rejects_cross_session_protected_and_terminal_payloads_and_invalid_namespace() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let (h, bytes) = popped_live_batch(&source, &service, &s, &p);
    let other = service.open_connection(p.clone()).unwrap();
    negotiate(&other);
    assert_eq!(
        other.revalidate_notification(&bytes),
        Err(ProviderError::FailedPrecondition)
    );
    let mut wrong_g: RecoveryNotification = codec::decode(&bytes).unwrap();
    if let Some(recovery_notification::Notification::Batch(b)) = &mut wrong_g.notification {
        b.generation = 8;
    }
    assert_eq!(
        s.revalidate_notification(&wrong_g.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    s.retire(&h.subscription_handle).unwrap();
    assert_eq!(
        s.revalidate_notification(&bytes),
        Err(ProviderError::FailedPrecondition)
    );
    let terminal = s.pop_notification().unwrap().unwrap();
    s.revalidate_notification(&terminal).unwrap();
    assert_eq!(
        other.revalidate_notification(&terminal),
        Err(ProviderError::FailedPrecondition)
    );
    let template: RecoveryNotification = codec::decode(&terminal).unwrap();
    for handle in [
        vec![0; 31],
        {
            let mut h = h.subscription_handle.clone();
            h[0] ^= 1;
            h
        },
        {
            let mut h = h.subscription_handle.clone();
            h[24..].copy_from_slice(&0u64.to_be_bytes());
            h
        },
        {
            let mut h = h.subscription_handle.clone();
            h[24..].copy_from_slice(&u64::MAX.to_be_bytes());
            h
        },
    ] {
        let mut invalid = template.clone();
        if let Some(recovery_notification::Notification::Trailer(t)) = &mut invalid.notification {
            t.subscription_handle = handle;
        }
        assert_eq!(
            s.revalidate_notification(&invalid.encode_to_vec()),
            Err(ProviderError::FailedPrecondition)
        );
    }
    let mut unset = template;
    if let Some(recovery_notification::Notification::Trailer(t)) = &mut unset.notification {
        t.outcome = None;
    }
    assert_eq!(
        s.revalidate_notification(&unset.encode_to_vec()),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.revalidate_notification(&[8, 1]),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        s.revalidate_notification(&vec![0; syntra_core::MAX_FRAME_BYTES]),
        Err(ProviderError::ResourceExhausted)
    );
}

#[test]
fn egress_contended_unit_is_retryable_and_callbacks_hold_no_state_mutex() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let (_, bytes) = popped_live_batch(&source, &service, &s, &p);
    let other = subscribe(&s, &p, Some(3));
    let weak = Arc::downgrade(&s);
    let retained = bytes.clone();
    *source.after_replay.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(
            weak.upgrade().unwrap().revalidate_notification(&retained),
            Err(ProviderError::ResourceExhausted)
        );
    }));
    let _: RecoveryReplayPage = call(
        &s,
        REPLAY,
        &replay(&other.subscription_handle, &p, 3, &[], 64),
    )
    .unwrap();
    let before = s.queue_counts().unwrap();
    s.revalidate_notification(&bytes).unwrap();
    assert_eq!(s.queue_counts().unwrap(), before);
    let weak = Arc::downgrade(&s);
    let source_weak = Arc::downgrade(&source);
    *source.after_emit_authorize.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(
            weak.upgrade().unwrap().queue_counts(),
            Err(ProviderError::ResourceExhausted)
        );
        source_weak
            .upgrade()
            .unwrap()
            .scope(&Principal::new("p"), b"s", 8, 4);
    }));
    assert_eq!(
        s.revalidate_notification(&bytes),
        Err(ProviderError::FailedPrecondition)
    );
}

#[test]
fn egress_unauthenticated_is_sticky_on_authorize_and_generation_callbacks() {
    for generation_callback in [false, true] {
        let (source, service, s, p) = setup(RecoveryLimits::default());
        let (h, bytes) = popped_live_batch(&source, &service, &s, &p);
        if generation_callback {
            source.data.lock().unwrap().generation_error = Some(ProviderError::Unauthenticated);
        } else {
            source
                .data
                .lock()
                .unwrap()
                .unauthenticated
                .insert(p.subject.clone());
        }
        assert_eq!(
            s.revalidate_notification(&bytes),
            Err(ProviderError::Unauthenticated)
        );
        assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));
        let terminal = s.pop_notification().unwrap().unwrap();
        let t: RecoveryNotification = codec::decode(&terminal).unwrap();
        assert!(
            matches!(t.notification, Some(recovery_notification::Notification::Trailer(t))
            if t.subscription_handle == h.subscription_handle && t.generation == 7
                && t.outcome == Some(recovery_batch_trailer::Outcome::Terminated(true)))
        );
        source.data.lock().unwrap().unauthenticated.clear();
        source.data.lock().unwrap().generation_error = None;
        assert_eq!(
            s.revalidate_notification(&terminal),
            Err(ProviderError::Unauthenticated)
        );
        assert_eq!(
            s.revalidate_notification(&bytes),
            Err(ProviderError::Unauthenticated)
        );
        s.close();
        assert_eq!(
            s.revalidate_notification(&terminal),
            Err(ProviderError::Unauthenticated)
        );
    }
}

#[tokio::test]
async fn pop_converted_unauthenticated_trailer_and_async_production_failure_remain_observable() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    let _ = popped_live_batch(&source, &service, &s, &p);
    source
        .data
        .lock()
        .unwrap()
        .unauthenticated
        .insert(p.subject.clone());
    let terminal = s.pop_notification().unwrap().unwrap(); // pop consumes the trailer, not Err
    assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));
    assert_eq!(
        s.revalidate_notification(&terminal),
        Err(ProviderError::Unauthenticated)
    );
    s.close();
    assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));

    for error in [
        ProviderError::Internal,
        ProviderError::Unavailable,
        ProviderError::Unauthenticated,
        ProviderError::ResourceExhausted,
    ] {
        let limits = RecoveryLimits {
            replay_batches: 1,
            ..RecoveryLimits::default()
        };
        let (source, _, s, p) = setup(limits);
        let h = subscribe(&s, &p, Some(0));
        let _: RecoveryCatchUpAccepted =
            call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
        s.next_notification().await.unwrap();
        source.data.lock().unwrap().replay_error = Some(error);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), s.next_notification())
                .await
                .unwrap(),
            None
        );
        assert!(s.is_closed());
        assert_eq!(s.terminal_error(), Some(error)); // parent can close Core rather than leave it idle
        assert_eq!(s.next_notification().await, None);
    }
}

#[derive(Default)]
struct NotificationWakeProbe(AtomicUsize);

impl Wake for NotificationWakeProbe {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll_notification(
    future: Pin<&mut impl Future<Output = Option<Vec<u8>>>>,
    probe: &Arc<NotificationWakeProbe>,
) -> Poll<Option<Vec<u8>>> {
    let waker = Waker::from(probe.clone());
    future.poll(&mut Context::from_waker(&waker))
}

#[test]
fn publication_late_issued_unauthenticated_is_sticky_and_wakes_actual_principal_sessions() {
    let (source, service, first, p) = setup(RecoveryLimits::default());
    subscribe(&first, &p, None);
    let second = service.open_connection(p.clone()).unwrap();
    negotiate(&second);
    subscribe(&second, &p, None);
    let idle = service.open_connection(p.clone()).unwrap(); // no negotiation or routing entry
    let q = Principal::new("q");
    source.scope(&q, b"s", 7, 3);
    let unaffected = service.open_connection(q.clone()).unwrap();
    negotiate(&unaffected);
    subscribe(&unaffected, &q, None);
    let batch = source.batch(&p, b"s", 4, 16);
    let sessions = [first, second, idle];
    let mut workers: Vec<_> = sessions
        .iter()
        .map(|s| Box::pin(s.next_notification()))
        .collect();
    let probes: Vec<_> = sessions
        .iter()
        .map(|_| Arc::new(NotificationWakeProbe::default()))
        .collect();
    for (worker, probe) in workers.iter_mut().zip(&probes) {
        assert_eq!(poll_notification(worker.as_mut(), probe), Poll::Pending);
        assert_eq!(probe.0.load(Ordering::SeqCst), 0);
    }
    let mut unaffected_worker = Box::pin(unaffected.next_notification());
    let unaffected_probe = Arc::new(NotificationWakeProbe::default());
    assert_eq!(
        poll_notification(unaffected_worker.as_mut(), &unaffected_probe),
        Poll::Pending
    );
    source.data.lock().unwrap().issued_error = Some(ProviderError::Unauthenticated);
    assert_eq!(source.authorize(&p, b"s", AuthorizationHook::Emit), Ok(()));
    assert_eq!(source.current_generation(&p, b"s"), Ok(7));
    let issued_before = source.issued_calls.load(Ordering::SeqCst);
    assert_eq!(
        service.publish(&p, b"s", batch),
        Err(ProviderError::Unauthenticated)
    );
    assert_eq!(
        source.issued_calls.load(Ordering::SeqCst) - issued_before,
        2
    );
    for ((session, worker), probe) in sessions.iter().zip(&mut workers).zip(&probes) {
        assert_eq!(
            session.terminal_error(),
            Some(ProviderError::Unauthenticated)
        );
        assert!(
            probe.0.load(Ordering::SeqCst) > 0,
            "idle notification worker was not woken"
        );
        // Parent can observe None + the sticky cause and withdraw Core without
        // relying on another batch, RPC, or provider callback to wake the worker.
        assert_eq!(poll_notification(worker.as_mut(), probe), Poll::Ready(None));
        assert!(session.is_closed());
    }
    assert_eq!(unaffected.terminal_error(), None);
    assert!(!unaffected.is_closed());
    assert_eq!(unaffected_probe.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        poll_notification(unaffected_worker.as_mut(), &unaffected_probe),
        Poll::Pending
    );
}

#[test]
fn provider_loss_verification_unauthenticated_fans_out_to_all_actual_sessions_for_only_p() {
    let (source, service, first, p) = setup(RecoveryLimits::default());
    subscribe(&first, &p, None);
    source.scope(&p, b"other", 7, 3);
    let other_stream = service.open_connection(p.clone()).unwrap();
    negotiate(&other_stream);
    let _: RecoverySubscribeResponse = call(
        &other_stream,
        SUBSCRIBE,
        &RecoverySubscribeRequest {
            profile_version: 1,
            stream_selector: b"other".to_vec(),
            start_checkpoint: vec![],
        },
    )
    .unwrap();
    let idle = service.open_connection(p.clone()).unwrap();
    let q = Principal::new("q");
    source.scope(&q, b"s", 7, 3);
    let unaffected = service.open_connection(q.clone()).unwrap();
    let sessions = [first, other_stream, idle];
    let mut workers: Vec<_> = sessions
        .iter()
        .map(|s| Box::pin(s.next_notification()))
        .collect();
    let probes: Vec<_> = sessions
        .iter()
        .map(|_| Arc::new(NotificationWakeProbe::default()))
        .collect();
    for (worker, probe) in workers.iter_mut().zip(&probes) {
        assert_eq!(poll_notification(worker.as_mut(), probe), Poll::Pending);
    }
    {
        let mut data = source.data.lock().unwrap();
        data.generation_error = Some(ProviderError::Unauthenticated);
        data.generation_error_principal = Some(p.subject.clone());
    }
    assert_eq!(
        service.provider_loss(&p, b"s", 7, 8, ProviderLoss::HistoryLost),
        Err(ProviderError::Unauthenticated)
    );
    for ((session, worker), probe) in sessions.iter().zip(&mut workers).zip(&probes) {
        assert_eq!(
            session.terminal_error(),
            Some(ProviderError::Unauthenticated)
        );
        assert!(probe.0.load(Ordering::SeqCst) > 0);
        assert_eq!(poll_notification(worker.as_mut(), probe), Poll::Ready(None));
    }
    assert_eq!(unaffected.terminal_error(), None);
    assert_eq!(source.current_generation(&q, b"s"), Ok(7));
    assert!(!unaffected.is_closed());
}

#[test]
fn application_source_unauthenticated_fanout_also_reaches_a_busy_session() {
    for publication in [false, true] {
        let (source, service, busy, p) = setup(RecoveryLimits::default());
        let h = subscribe(&busy, &p, Some(0));
        let other = service.open_connection(p.clone()).unwrap();
        negotiate(&other);
        subscribe(&other, &p, None);
        let batch = source.batch(&p, b"s", 4, 16);
        let source_weak = Arc::downgrade(&source);
        let service_weak = Arc::downgrade(&service);
        let session_weak = Arc::downgrade(&busy);
        *source.after_replay.lock().unwrap() = Some(Box::new(move || {
            let source = source_weak.upgrade().unwrap();
            let service = service_weak.upgrade().unwrap();
            if publication {
                source.data.lock().unwrap().issued_error = Some(ProviderError::Unauthenticated);
                // Busy and unauthenticated results must not depend on the
                // registry's HashMap iteration order: withdrawal is strongest.
                assert_eq!(
                    service.publish(&Principal::new("p"), b"s", batch.clone()),
                    Err(ProviderError::Unauthenticated)
                );
            } else {
                source.data.lock().unwrap().generation_error = Some(ProviderError::Unauthenticated);
                assert_eq!(
                    service.provider_loss(
                        &Principal::new("p"),
                        b"s",
                        7,
                        8,
                        ProviderLoss::SharedRebase
                    ),
                    Err(ProviderError::Unauthenticated)
                );
            }
            assert_eq!(
                session_weak.upgrade().unwrap().terminal_error(),
                Some(ProviderError::Unauthenticated)
            );
        }));
        assert_eq!(
            busy.handle(
                REPLAY,
                &replay(&h.subscription_handle, &p, 0, &[], 64).encode_to_vec()
            ),
            Err(ProviderError::Unauthenticated)
        );
        assert_eq!(busy.terminal_error(), Some(ProviderError::Unauthenticated));
        assert_eq!(other.terminal_error(), Some(ProviderError::Unauthenticated));
    }
}

#[test]
fn publication_permission_denial_is_targeted_and_other_source_errors_are_not_withdrawal() {
    for error in [
        ProviderError::PermissionDenied,
        ProviderError::Unavailable,
        ProviderError::Internal,
        ProviderError::ResourceExhausted,
    ] {
        let (source, service, s, p) = setup(RecoveryLimits::default());
        let h = subscribe(&s, &p, None);
        let idle = service.open_connection(p.clone()).unwrap();
        let batch = source.batch(&p, b"s", 4, 16);
        source.data.lock().unwrap().issued_error = Some(error);
        assert_eq!(service.publish(&p, b"s", batch), Err(error));
        assert_eq!(s.terminal_error(), None);
        assert_eq!(idle.terminal_error(), None);
        assert!(!s.is_closed());
        assert!(!idle.is_closed());
        assert_eq!(s.queue_counts().unwrap().data_bytes, 0);
        if error == ProviderError::PermissionDenied {
            let t = trailer(&s);
            assert_eq!(t.subscription_handle, h.subscription_handle);
            assert_eq!(t.generation, 7);
            assert_eq!(
                t.outcome,
                Some(recovery_batch_trailer::Outcome::Terminated(true))
            );
            assert_eq!(t.terminate_reason, b"authorization-ended");
        } else {
            assert_eq!(s.queue_counts().unwrap().subscriptions, 1);
        }
        source.data.lock().unwrap().generation_error = Some(error);
        assert_eq!(
            service.provider_loss(&p, b"s", 7, 8, ProviderLoss::HistoryLost),
            Err(error)
        );
        assert_eq!(s.terminal_error(), None);
        assert_eq!(idle.terminal_error(), None);
    }
}

#[test]
fn application_withdrawal_remains_strongest_after_later_generic_errors() {
    let (source, service, s, p) = setup(RecoveryLimits::default());
    subscribe(&s, &p, None);
    let batch = source.batch(&p, b"s", 4, 16);
    source.data.lock().unwrap().issued_error = Some(ProviderError::Unauthenticated);
    assert_eq!(
        service.publish(&p, b"s", batch),
        Err(ProviderError::Unauthenticated)
    );
    {
        let mut data = source.data.lock().unwrap();
        data.issued_error = None;
        data.generation_error = Some(ProviderError::Unavailable);
        data.replay_error = Some(ProviderError::Internal);
    }
    assert_eq!(
        service.provider_loss(&p, b"s", 7, 8, ProviderLoss::HistoryLost),
        Err(ProviderError::Unavailable)
    );
    assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));
    let before = source.replay_calls.load(Ordering::SeqCst);
    let mut worker = Box::pin(s.next_notification());
    let probe = Arc::new(NotificationWakeProbe::default());
    assert_eq!(
        poll_notification(worker.as_mut(), &probe),
        Poll::Ready(None)
    );
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), before);
    assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));
}

#[test]
fn pop_source_unauthenticated_error_and_deadline_conversion_keep_sticky_withdrawal() {
    let limits = RecoveryLimits {
        replay_batches: 1,
        ..RecoveryLimits::default()
    };
    let (source, _, s, p) = setup(limits);
    let h = subscribe(&s, &p, Some(0));
    let _: RecoveryCatchUpAccepted = call(&s, CATCH_UP, &catchup(&h.subscription_handle)).unwrap();
    let pending = s.pop_notification().unwrap().unwrap();
    source.data.lock().unwrap().replay_error = Some(ProviderError::Unauthenticated);
    assert_eq!(s.pop_notification(), Err(ProviderError::Unauthenticated));
    assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));
    assert_eq!(
        s.revalidate_notification(&pending),
        Err(ProviderError::Unauthenticated)
    );

    let (source, _, s, p) = setup(RecoveryLimits::default());
    let h = subscribe(&s, &p, Some(0));
    let weak = Arc::downgrade(&source);
    *source.after_replay.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade()
            .unwrap()
            .data
            .lock()
            .unwrap()
            .unauthenticated
            .insert("p".into());
        std::thread::sleep(Duration::from_millis(5));
    }));
    let request = replay(&h.subscription_handle, &p, 0, &[], 64);
    assert_eq!(
        s.handle_with_deadline(REPLAY, &request.encode_to_vec(), Duration::from_millis(1)),
        Err(ProviderError::DeadlineExceeded)
    );
    assert_eq!(s.terminal_error(), Some(ProviderError::Unauthenticated));
    let terminal = s.pop_notification().unwrap().unwrap();
    assert_eq!(
        s.revalidate_notification(&terminal),
        Err(ProviderError::Unauthenticated)
    );
}
