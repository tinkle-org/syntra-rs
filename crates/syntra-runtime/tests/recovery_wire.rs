//! Local acceptance probes, NOT full CONF verdicts. Real authenticated
//! core endpoints and registered recovery service; no fake peer. All captured
//! bytes are public fixtures. Retained memory exercises store-boundary protocol
//! behavior by default; `file-store` uses native files for the same scenarios.
//! Real process-crash cuts belong to recovery_persistence with `file-store`.
#[path = "recovery_wire/support.rs"]
mod support;

use std::future::Future;
use std::sync::atomic::Ordering;
use std::time::Duration;

use prost::Message;
use support::*;
use syntra_core::proto::{recovery_batch_trailer::Outcome, recovery_notification::Notification, *};
use syntra_core::ErrorCode;
use syntra_runtime::recovery::persistence::*;
use syntra_runtime::recovery::wire::{self, *};
use syntra_runtime::recovery::wire_client::*;

fn neg() -> RecoveryNegotiateRequest {
    RecoveryNegotiateRequest {
        profile_version: 1,
        min_version: 1,
        max_version: 1,
        capability: wire::CAPABILITY.into(),
    }
}
fn sub(stream: &[u8], start: &[u8]) -> RecoverySubscribeRequest {
    RecoverySubscribeRequest {
        profile_version: 1,
        stream_selector: stream.to_vec(),
        start_checkpoint: start.to_vec(),
    }
}
fn replay(s: &RecoverySubscribeResponse, from: &[u8]) -> RecoveryReplayRequest {
    RecoveryReplayRequest {
        profile_version: 1,
        subscription_handle: s.subscription_handle.clone(),
        from_checkpoint: from.to_vec(),
        max_batches: 2,
        max_bytes: 262_144,
        continuation_marker: vec![],
    }
}
fn catch(s: &RecoverySubscribeResponse) -> RecoveryCatchUpRequest {
    RecoveryCatchUpRequest {
        profile_version: 1,
        subscription_handle: s.subscription_handle.clone(),
    }
}
fn confirm(s: &RecoverySubscribeResponse, cp: &[u8]) -> RecoveryConfirmRequest {
    RecoveryConfirmRequest {
        profile_version: 1,
        subscription_handle: s.subscription_handle.clone(),
        generation: s.generation,
        checkpoint: cp.to_vec(),
    }
}
async fn raw_sub(b: &Bridge, stream: &[u8], cp: &[u8]) -> RecoverySubscribeResponse {
    RecoverySubscribeResponse::decode(
        b.raw(wire::SUBSCRIBE, sub(stream, cp))
            .await
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}
async fn raw_negotiate(b: &Bridge) {
    RecoveryNegotiateResponse::decode(b.raw(wire::NEGOTIATE, neg()).await.unwrap().as_slice())
        .unwrap();
}

#[tokio::test]
async fn local_acceptance_unconfirmed_and_unsupported_are_paired_with_fresh_confirmed_control() {
    let source = Source::new(0);
    let service = source.service(RecoveryLimits::default());
    let unconfirmed = Bridge::new(Some(service.clone())).await;
    // Valid raw payloads must be refused before confirmation, not interpreted as
    // implicit capability support. Core still owns IDs and result correlation.
    let unbound = RecoverySubscribeResponse {
        profile_version: 1,
        subscription_handle: b"public-unbound-h".to_vec(),
        generation: 7,
        catchup_boundary: CP[0].to_vec(),
    };
    let requests = [
        (wire::SUBSCRIBE, sub(A, &[]).encode_to_vec()),
        (wire::REPLAY, replay(&unbound, CP[0]).encode_to_vec()),
        (wire::CATCH_UP, catch(&unbound).encode_to_vec()),
        (wire::CONFIRM, confirm(&unbound, CP[0]).encode_to_vec()),
        (
            wire::SNAPSHOT_OFFER,
            RecoverySnapshotOfferRequest {
                profile_version: 1,
                subscription_handle: unbound.subscription_handle.clone(),
                generation: 7,
            }
            .encode_to_vec(),
        ),
        (
            wire::SNAPSHOT_FETCH,
            RecoverySnapshotFetchRequest {
                profile_version: 1,
                snapshot_handle: b"public-unbound-x".to_vec(),
                page_index: 0,
            }
            .encode_to_vec(),
        ),
        (
            wire::SNAPSHOT_CONFIRM,
            RecoverySnapshotConfirmRequest {
                profile_version: 1,
                subscription_handle: unbound.subscription_handle.clone(),
                generation: 7,
                boundary_checkpoint: CP[0].to_vec(),
            }
            .encode_to_vec(),
        ),
        (
            wire::UNSUBSCRIBE,
            RecoveryUnsubscribeRequest {
                profile_version: 1,
                subscription_handle: unbound.subscription_handle,
            }
            .encode_to_vec(),
        ),
    ];
    for (method, payload) in &requests {
        assert_eq!(
            bounded(unconfirmed.init.call(*method, payload.clone(), 2000))
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Unimplemented
        );
    }
    unconfirmed.echo().await;
    let supported = Bridge::new(Some(service)).await;
    let mut client = supported.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    let n = negotiate(&mut client).await;
    assert_eq!(
        n,
        RecoveryNegotiateResponse {
            profile_version: 1,
            selected_version: 1,
            max_subscriptions_per_connection: 64,
            max_pending_rpcs_per_connection: 16,
            max_page_bytes: 262_144,
            max_snapshot_pages: 256
        }
    );
    assert_eq!(
        supported.trace.requests(wire::NEGOTIATE)[0].1,
        neg().encode_to_vec()
    );
    subscribe(&mut client, A, SubscribeIntent::InitialLiveOnly).await;
    supported.echo().await;
    let unsupported = Bridge::new(None).await;
    let mut mandatory = unsupported.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    assert!(matches!(
        bounded(mandatory.negotiate()).await.unwrap(),
        Negotiation::RecoveryUnavailable
    ));
    assert_eq!(
        mandatory
            .subscribe(A.to_vec(), A.to_vec(), SubscribeIntent::InitialLiveOnly)
            .await
            .err(),
        Some(RecoveryClientError::RecoveryUnavailable)
    );
    unsupported.echo().await;
    for (method, payload) in requests {
        assert_eq!(
            bounded(unsupported.init.call(method, payload, 2000))
                .await
                .unwrap_err()
                .code(),
            ErrorCode::Unimplemented
        );
    }
    drop((client, mandatory));
    unconfirmed.finish().await;
    supported.finish().await;
    unsupported.finish().await;
}

#[tokio::test]
async fn local_acceptance_exact_v1_negotiation_and_connected_only_registration() {
    let source = Source::new(0);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    assert_eq!(
        b.host.configure_recovery(service).await.unwrap_err().code(),
        ErrorCode::FailedPrecondition
    );
    for request in [
        RecoveryNegotiateRequest {
            capability: "syntra.update-recovery/2".into(),
            ..neg()
        },
        RecoveryNegotiateRequest {
            min_version: 2,
            max_version: 2,
            ..neg()
        },
        RecoveryNegotiateRequest {
            profile_version: 2,
            ..neg()
        },
    ] {
        assert_eq!(
            b.raw(wire::NEGOTIATE, request).await,
            Err(ErrorCode::FailedPrecondition)
        );
        assert_eq!(
            b.raw(wire::SUBSCRIBE, sub(A, &[])).await,
            Err(ErrorCode::Unimplemented)
        );
        b.echo().await;
    }
    raw_negotiate(&b).await;
    raw_sub(&b, A, &[]).await;
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_confirmation_is_connection_local_and_second_wrapper_is_denied() {
    let source = Source::new(0);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let mut c = b.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    assert!(matches!(
        RecoveryClient::new(
            b.init.clone(),
            P.as_bytes().to_vec(),
            MemoryRecoveryStore::new(),
            RecoveryLimits::default()
        ),
        Err(RecoveryClientError::InvalidState)
    ));
    negotiate(&mut c).await;
    let old = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    b.finish().await;
    assert_eq!(
        c.catch_up(&old.subscription_handle).await.err(),
        Some(RecoveryClientError::ReconnectRequired)
    );
    let fresh = Bridge::new(Some(service)).await;
    assert_eq!(
        fresh.raw(wire::SUBSCRIBE, sub(A, &[])).await,
        Err(ErrorCode::Unimplemented)
    );
    raw_negotiate(&fresh).await;
    assert_eq!(
        fresh.raw(wire::CATCH_UP, catch(&old)).await,
        Err(ErrorCode::FailedPrecondition)
    );
    fresh.echo().await;
    fresh.finish().await;
}

#[tokio::test]
async fn local_acceptance_initial_empty_never_replays_and_acceptance_is_not_completion() {
    let source = Source::new(1);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    b.faults.hold_completion.store(true, Ordering::SeqCst);
    let mut c = b.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    assert_eq!(
        c.replay_page(&s.subscription_handle).await.err(),
        Some(RecoveryClientError::InvalidState)
    );
    assert_eq!(
        c.catch_up(&s.subscription_handle)
            .await
            .unwrap()
            .catchup_boundary,
        CP[1]
    );
    b.trace.wait_notifications(1, false).await;
    pending(c.next_event()).await;
    assert!(c
        .progress(&s.subscription_handle)
        .unwrap()
        .locally_durable
        .is_none());
    assert!(b.trace.requests(wire::REPLAY).is_empty());
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 0);
    b.release_completions().await;
    assert!(
        matches!(bounded(c.next_event()).await.unwrap(), RecoveryEvent::InitialLiveBaseline { handle, boundary } if handle == s.subscription_handle && boundary == CP[1])
    );
    assert!(b.trace.requests(wire::CONFIRM).is_empty());
    bounded(c.unsubscribe(&s.subscription_handle))
        .await
        .unwrap();
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_replay_pages_fixed_boundary_durable_gate_and_lost_completion() {
    let fixture = StoreFixture::new();
    let store = fixture.seeded(0).await;
    let source = Source::new(3);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    b.faults.hold_completion.store(true, Ordering::SeqCst);
    let mut c = b.client(store, RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    assert_eq!(s.catchup_boundary, CP[3]);
    let page = bounded(c.replay_page(&s.subscription_handle))
        .await
        .unwrap();
    assert_eq!(page.batch_payloads.len(), 2);
    assert!(!page.continuation_marker.is_empty());
    source.append(&service, A); // live 3 -> 4 does not change the captured B.
    for index in 1..=2 {
        let offer = batch(&mut c).await;
        assert_eq!(offer.result_checkpoint, CP[index]);
        assert!(c
            .progress(&s.subscription_handle)
            .unwrap()
            .peer_acknowledged
            .as_ref()
            .is_none_or(|p| p.checkpoint != offer.result_checkpoint));
        bounded(c.persist_and_confirm(&s.subscription_handle, [STATE, &[index as u8]].concat()))
            .await
            .unwrap();
    }
    let final_page = bounded(c.replay_page(&s.subscription_handle))
        .await
        .unwrap();
    assert_eq!(final_page.catchup_boundary, CP[3]);
    assert!(final_page.continuation_marker.is_empty());
    b.trace.wait_notifications(2, false).await; // held completion plus live batch
    assert_eq!(batch(&mut c).await.result_checkpoint, CP[3]);
    pending(c.next_event()).await; // outstanding B offer; live must not leak
    bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    pending(c.next_event()).await; // durable B alone is not wire completion
                                   // Lose the original completion by keeping it held; exact last-page retry
                                   // emits another completion, without re-reading Source or reapplying effects.
    let calls = source.replay_calls.load(Ordering::SeqCst);
    b.faults.hold_completion.store(false, Ordering::SeqCst);
    bounded(c.retry_completion(&s.subscription_handle))
        .await
        .unwrap();
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), calls);
    assert!(
        matches!(bounded(c.next_event()).await.unwrap(), RecoveryEvent::CaughtUp { handle } if handle == s.subscription_handle)
    );
    assert_eq!(batch(&mut c).await.predecessor_checkpoint, CP[3]);
    bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    b.release_completions().await; // late original is inert
    pending(c.next_event()).await;
    let requests = b.trace.requests(wire::REPLAY);
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].1, requests[2].1);
    drop(c);
    b.finish().await;
    let reopened = fixture.open().await;
    let loaded = tokio::task::spawn_blocking(move || reopened.load(&scope(A)).unwrap().unwrap())
        .await
        .unwrap();
    assert_eq!(loaded.generation, 7);
    assert_eq!(loaded.checkpoint, CP[4]);
    assert_eq!(loaded.application_state, STATE);
}

#[tokio::test]
async fn local_acceptance_raw_exact_retries_cache_bytes_do_not_advance_source() {
    let source = Source::new(1);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    raw_negotiate(&b).await;
    let s = raw_sub(&b, A, CP[0]).await;
    assert_eq!(
        b.raw(wire::CONFIRM, confirm(&s, b"never-issued")).await,
        Err(ErrorCode::FailedPrecondition)
    );
    let request = replay(&s, CP[0]);
    let bytes = b.raw(wire::REPLAY, request.clone()).await.unwrap();
    b.trace.wait_notifications(1, true).await;
    assert_eq!(b.raw(wire::REPLAY, request).await.unwrap(), bytes);
    b.trace.wait_notifications(2, true).await;
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    let ack = b.raw(wire::CONFIRM, confirm(&s, CP[1])).await.unwrap();
    assert_eq!(b.raw(wire::CONFIRM, confirm(&s, CP[1])).await.unwrap(), ack);
    assert_eq!(
        b.raw(wire::CONFIRM, confirm(&s, CP[0])).await,
        Err(ErrorCode::FailedPrecondition)
    );
    let other = raw_sub(&b, B, &checkpoint(B, 1)).await;
    let accepted = b.raw(wire::CATCH_UP, catch(&other)).await.unwrap();
    b.trace.wait_notifications(3, true).await;
    assert_eq!(
        b.raw(wire::CATCH_UP, catch(&other)).await.unwrap(),
        accepted
    );
    b.trace.wait_notifications(4, true).await;
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    b.echo().await;
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_noop_page_c_equals_b_is_empty_and_needs_no_confirm() {
    let source = Source::new(1);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    let mut c = b.client(memory(1), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    let page = bounded(c.replay_page(&s.subscription_handle))
        .await
        .unwrap();
    assert!(page.batch_payloads.is_empty() && page.continuation_marker.is_empty());
    assert_eq!(page.predecessor_checkpoint, page.result_checkpoint);
    assert!(matches!(
        bounded(c.next_event()).await.unwrap(),
        RecoveryEvent::CaughtUp { .. }
    ));
    assert!(b.trace.requests(wire::CONFIRM).is_empty());
    drop(c);
    b.finish().await;
}

#[tokio::test(start_paused = true)]
async fn local_acceptance_exact_retry_exhaustion_is_bounded_not_new_source_work() {
    let source = Source::new(0);
    let limits = RecoveryLimits {
        reply_retries: 1,
        ..RecoveryLimits::default()
    };
    let b = Bridge::new(Some(source.service(limits))).await;
    raw_negotiate(&b).await;
    let s = raw_sub(&b, A, CP[0]).await;
    let request = replay(&s, CP[0]);
    let first = b.raw(wire::REPLAY, request.clone()).await.unwrap();
    assert_eq!(b.raw(wire::REPLAY, request.clone()).await.unwrap(), first);
    assert_eq!(
        b.raw(wire::REPLAY, request).await,
        Err(ErrorCode::FailedPrecondition)
    );
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    b.echo().await;
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_retention_snapshot_all_indices_current_g_s0_differs_from_b() {
    let source = Source::new(2);
    source.retention_miss.store(true, Ordering::SeqCst);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let mut c = b.client(memory(0), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    // The separate trailer can invalidate the waiter before its failed result
    // wins the select; both typed paths retain the same precondition code.
    assert_eq!(
        bounded(c.replay_page(&s.subscription_handle))
            .await
            .unwrap_err()
            .code(),
        ErrorCode::FailedPrecondition
    );
    assert!(matches!(
        bounded(c.next_event()).await.unwrap(),
        RecoveryEvent::SnapshotRequired { .. }
    ));
    assert_eq!(source.generation[0].load(Ordering::SeqCst), 7);
    source.append(&service, A);
    source.snapshot_at.store(3, Ordering::SeqCst);
    let d = bounded(c.snapshot_offer(&s.subscription_handle))
        .await
        .unwrap();
    assert_ne!(d.boundary_checkpoint, s.catchup_boundary);
    assert_eq!(d.boundary_checkpoint, CP[3]);
    assert!(c.snapshot_bytes(&s.subscription_handle).is_err());
    bounded(c.snapshot_fetch(&s.subscription_handle, 1))
        .await
        .unwrap();
    assert!(c.snapshot_bytes(&s.subscription_handle).is_err());
    let snapshot_confirm = RecoverySnapshotConfirmRequest {
        profile_version: 1,
        subscription_handle: s.subscription_handle.clone(),
        generation: 7,
        boundary_checkpoint: d.boundary_checkpoint.clone(),
    };
    assert_eq!(
        b.raw(wire::SNAPSHOT_CONFIRM, snapshot_confirm.clone())
            .await,
        Err(ErrorCode::FailedPrecondition)
    );
    bounded(c.snapshot_fetch(&s.subscription_handle, 0))
        .await
        .unwrap();
    assert_eq!(
        c.snapshot_bytes(&s.subscription_handle).unwrap(),
        b"public snapshot rows\0public snapshot indexes"
    );
    // Fetch complete is LOCAL only: no SnapshotConfirm or completion on the wire.
    assert!(b.trace.requests(wire::SNAPSHOT_CONFIRM).len() == 1);
    assert!(!b
        .trace
        .notifications(false)
        .iter()
        .any(|n| matches!(n, Notification::ReplayComplete(_))));
    source.append(&service, A); // covered prefix 2->3 must be cut; retain 3->4
    pending(c.next_event()).await;
    let installed = bounded(c.install_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    assert_eq!(installed.generation, 7);
    assert_eq!(installed.boundary_checkpoint, CP[3]);
    let live = batch(&mut c).await;
    assert_eq!(live.predecessor_checkpoint, CP[3]);
    assert_eq!(live.result_checkpoint, CP[4]);
    bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    assert_eq!(
        b.trace.responses(wire::REPLAY),
        vec![Err(ErrorCode::FailedPrecondition)]
    );
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_snapshot_installed_not_old_completion_unlocks_s0() {
    let source = Source::new(0);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    b.faults.hold_completion.store(true, Ordering::SeqCst);
    let mut c = b.client(memory(0), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    bounded(c.catch_up(&s.subscription_handle)).await.unwrap();
    b.trace.wait_notifications(1, false).await;
    source.append(&service, A);
    source.snapshot_at.store(1, Ordering::SeqCst);
    bounded(c.snapshot_offer(&s.subscription_handle))
        .await
        .unwrap();
    for i in 0..2 {
        bounded(c.snapshot_fetch(&s.subscription_handle, i))
            .await
            .unwrap();
    }
    bounded(c.install_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    b.release_completions().await;
    pending(c.next_event()).await;
    source.append(&service, A);
    assert_eq!(batch(&mut c).await.predecessor_checkpoint, CP[1]);
    bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_snapshot_supersede_fresh_h_same_s0_stale_x_and_confirm_denied() {
    let source = Source::new(1);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    let mut c = b.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    negotiate(&mut c).await;
    let old = subscribe(&mut c, A, SubscribeIntent::SnapshotCurrentGeneration).await;
    let first = bounded(c.snapshot_offer(&old.subscription_handle))
        .await
        .unwrap();
    bounded(c.snapshot_fetch(&old.subscription_handle, 0))
        .await
        .unwrap();
    bounded(c.unsubscribe(&old.subscription_handle))
        .await
        .unwrap();
    let fresh = subscribe(&mut c, A, SubscribeIntent::SnapshotCurrentGeneration).await;
    let second = bounded(c.snapshot_offer(&fresh.subscription_handle))
        .await
        .unwrap();
    assert_ne!(old.subscription_handle, fresh.subscription_handle);
    assert_ne!(first.snapshot_handle, second.snapshot_handle);
    assert_eq!(first.boundary_checkpoint, second.boundary_checkpoint);
    assert_eq!(
        b.raw(
            wire::SNAPSHOT_FETCH,
            RecoverySnapshotFetchRequest {
                profile_version: 1,
                snapshot_handle: first.snapshot_handle,
                page_index: 0
            }
        )
        .await,
        Err(ErrorCode::FailedPrecondition)
    );
    assert_eq!(
        b.raw(
            wire::SNAPSHOT_CONFIRM,
            RecoverySnapshotConfirmRequest {
                profile_version: 1,
                subscription_handle: old.subscription_handle,
                generation: 7,
                boundary_checkpoint: first.boundary_checkpoint
            }
        )
        .await,
        Err(ErrorCode::FailedPrecondition)
    );
    for i in 0..2 {
        bounded(c.snapshot_fetch(&fresh.subscription_handle, i))
            .await
            .unwrap();
    }
    bounded(c.install_and_confirm(&fresh.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    b.echo().await;
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_provider_loss_fences_aliases_pages_offers_confirms_not_other_stream() {
    let source = Source::new(1);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let other_principal = Bridge::new_as(Some(service.clone()), OTHER_P).await;
    raw_negotiate(&other_principal).await;
    let separate = raw_sub(&other_principal, A, CP[1]).await;
    raw_negotiate(&b).await;
    let a = raw_sub(&b, A, CP[0]).await;
    let alias = raw_sub(&b, ALIAS, CP[0]).await;
    let other = raw_sub(&b, B, &checkpoint(B, 0)).await;
    let page = b.raw(wire::REPLAY, replay(&a, CP[0])).await.unwrap();
    assert!(!page.is_empty());
    source.generation[0].store(19, Ordering::SeqCst);
    service
        .provider_loss(&Principal::new(P), A, 7, 19, ProviderLoss::HistoryLost)
        .unwrap();
    for s in [&a, &alias] {
        assert_eq!(
            b.raw(wire::REPLAY, replay(s, CP[0])).await,
            Err(ErrorCode::FailedPrecondition)
        );
        assert_eq!(
            b.raw(wire::CONFIRM, confirm(s, CP[1])).await,
            Err(ErrorCode::FailedPrecondition)
        );
        assert_eq!(
            b.raw(
                wire::SNAPSHOT_OFFER,
                RecoverySnapshotOfferRequest {
                    profile_version: 1,
                    subscription_handle: s.subscription_handle.clone(),
                    generation: 7
                }
            )
            .await,
            Err(ErrorCode::FailedPrecondition)
        );
    }
    b.raw(wire::REPLAY, replay(&other, &checkpoint(B, 0)))
        .await
        .unwrap();
    b.raw(wire::CONFIRM, confirm(&other, &checkpoint(B, 1)))
        .await
        .unwrap();
    let fresh = raw_sub(&b, A, &[]).await;
    assert_eq!(fresh.generation, 19);
    b.echo().await;
    b.trace.wait_matching(2, true, |n| matches!(n, Notification::Trailer(t) if t.outcome == Some(Outcome::NextGeneration(19)))).await;
    let next = b.trace.notifications(false).iter().filter(|n| matches!(n, Notification::Trailer(t) if t.outcome == Some(Outcome::NextGeneration(19)))).count();
    assert_eq!(next, 2);
    other_principal
        .raw(wire::REPLAY, replay(&separate, CP[1]))
        .await
        .unwrap();
    assert!(!other_principal.trace.notifications(false).iter().any(|n| matches!(n, Notification::Trailer(t) if matches!(t.outcome, Some(Outcome::NextGeneration(_))))));
    other_principal.echo().await;
    other_principal.finish().await;
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_local_overflow_has_no_next_g_and_other_subscription_core_confirm_progress(
) {
    let source = Source::new(0);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let limits = RecoveryLimits {
        queued_messages_per_stream: 1,
        ..RecoveryLimits::default()
    };
    let mut c = b.client(MemoryRecoveryStore::new(), limits);
    negotiate(&mut c).await;
    let slow = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    let healthy = subscribe(&mut c, B, SubscribeIntent::InitialLiveOnly).await;
    for s in [&slow, &healthy] {
        bounded(c.catch_up(&s.subscription_handle)).await.unwrap();
        assert!(matches!(
            bounded(c.next_event()).await.unwrap(),
            RecoveryEvent::InitialLiveBaseline { .. }
        ));
    }
    let before = b.trace.notifications(true).len();
    source.append(&service, A);
    b.trace.wait_notifications(before + 1, true).await;
    let leased = batch(&mut c).await;
    assert_eq!(leased.subscription_handle, slow.subscription_handle);
    source.append(&service, A); // application has not persisted the first offer
    b.trace.wait_notifications(before + 2, true).await;
    b.echo().await;
    match bounded(c.next_event()).await.unwrap() {
        RecoveryEvent::RecoveryNeeded {
            handle,
            generation,
            next_generation,
            termination: Some(t),
        } => {
            assert_eq!(handle, slow.subscription_handle);
            assert_eq!(generation, 7);
            assert_eq!(next_generation, None);
            assert_eq!(t.terminate_reason, b"local-queue-exhausted");
            assert_eq!(t.outcome, Some(Outcome::Terminated(true)));
        }
        _ => panic!("expected local reserved overflow control"),
    }
    assert!(b.trace.requests(wire::CONFIRM).is_empty());
    source.append(&service, B);
    assert_eq!(
        batch(&mut c).await.subscription_handle,
        healthy.subscription_handle
    );
    bounded(c.persist_and_confirm(&healthy.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    assert_eq!(b.init.notification_loss(), (0, 0)); // capacity-one generic queue never owned these notifications
    pending(b.init.next_notification()).await;
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_provider_gap_is_terminal_bounded_and_fresh_handle_recovers() {
    let source = Source::new(2);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let mut c = b.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    negotiate(&mut c).await;
    let old = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    bounded(c.catch_up(&old.subscription_handle)).await.unwrap();
    bounded(c.next_event()).await.unwrap();
    assert_eq!(
        service.publish(&Principal::new(P), A, source.batch(A, 0, 1)),
        Err(ProviderError::FailedPrecondition)
    );
    assert!(
        matches!(bounded(c.next_event()).await.unwrap(), RecoveryEvent::RecoveryNeeded { next_generation: None, termination: Some(t), .. } if t.terminate_reason == b"provider-chain-gap")
    );
    let fresh = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    assert_ne!(fresh.subscription_handle, old.subscription_handle);
    bounded(c.catch_up(&fresh.subscription_handle))
        .await
        .unwrap();
    assert!(matches!(
        bounded(c.next_event()).await.unwrap(),
        RecoveryEvent::InitialLiveBaseline { .. }
    ));
    b.echo().await;
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_permission_denial_is_targeted_unauthenticated_revokes_core() {
    let source = Source::new(0);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    raw_negotiate(&b).await;
    let denied = raw_sub(&b, A, CP[0]).await;
    let healthy = raw_sub(&b, B, &checkpoint(B, 0)).await;
    *source.denied.lock().unwrap() = Some((A.to_vec(), ProviderError::PermissionDenied));
    assert_eq!(
        b.raw(wire::REPLAY, replay(&denied, CP[0])).await,
        Err(ErrorCode::PermissionDenied)
    );
    b.raw(wire::REPLAY, replay(&healthy, &checkpoint(B, 0)))
        .await
        .unwrap();
    b.echo().await;
    *source.denied.lock().unwrap() = Some((B.to_vec(), ProviderError::Unauthenticated));
    assert!(b
        .raw(wire::CONFIRM, confirm(&healthy, CP[0]))
        .await
        .is_err());
    bounded(async {
        let mut closed = b.init.subscribe_close();
        while !*closed.borrow_and_update() {
            closed.changed().await.unwrap();
        }
    })
    .await;
    assert!(b.init.call(ECHO, vec![], 2000).await.is_err());
    b.finish().await;
}

/// Injects only the client store boundary, not a protocol peer. Unknown writes
/// really commit the full record; precommit failure leaves the previous record.
struct CutStore {
    store: FixtureStore,
    unknown: bool,
}
impl RecoveryPersistence for CutStore {
    fn load(&self, s: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError> {
        self.store.load(s)
    }
    fn commit(
        &mut self,
        s: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        r: DurableRecord,
    ) -> Result<(), PersistenceError> {
        if self.unknown {
            self.store.commit(s, expected, r)?;
            Err(PersistenceError::CommitUnknown)
        } else {
            Err(PersistenceError::Unavailable)
        }
    }
}

#[tokio::test]
async fn local_acceptance_failed_and_unknown_commit_never_confirm_fresh_connection_loads_record() {
    for unknown in [false, true] {
        let fixture = StoreFixture::new();
        let store = CutStore {
            store: fixture.seeded(0).await,
            unknown,
        };
        let source = Source::new(1);
        let service = source.service(RecoveryLimits::default());
        let b = Bridge::new(Some(service.clone())).await;
        let mut c = b.client(store, RecoveryLimits::default());
        negotiate(&mut c).await;
        let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
        bounded(c.replay_page(&s.subscription_handle))
            .await
            .unwrap();
        batch(&mut c).await;
        assert_eq!(
            bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
                .await
                .err(),
            Some(if unknown {
                RecoveryClientError::CommitUnknown
            } else {
                RecoveryClientError::Persistence(PersistenceError::Unavailable)
            })
        );
        assert!(b.trace.requests(wire::CONFIRM).is_empty());
        assert_eq!(
            c.next_event().await.err(),
            Some(RecoveryClientError::ReconnectRequired)
        );
        assert!(matches!(
            RecoveryClient::new(
                b.init.clone(),
                P.as_bytes().to_vec(),
                MemoryRecoveryStore::new(),
                RecoveryLimits::default()
            ),
            Err(RecoveryClientError::InvalidState)
        ));
        pending(b.init.next_notification()).await;
        drop(c);
        b.finish().await;
        drop(service);
        drop(source);
        // Reconstruct issued history without the old source or service cache,
        // including the CommitUnknown branch which never sent any Confirm.
        let fresh = Bridge::new(Some(Source::new(1).service(RecoveryLimits::default()))).await;
        let mut c = fresh.client(fixture.open().await, RecoveryLimits::default());
        negotiate(&mut c).await;
        let restored = bounded(c.subscribe(A.to_vec(), A.to_vec(), SubscribeIntent::ResumeDurable))
            .await
            .unwrap()
            .restored
            .unwrap();
        assert_eq!(restored, record(usize::from(unknown)));
        drop(c);
        fresh.finish().await;
    }
}

#[tokio::test]
async fn local_acceptance_wire_lost_ack_store_reopen_host_restart_reconstructs_issued_bindings() {
    let fixture = StoreFixture::new();
    let source = Source::new(1);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    let limits = RecoveryLimits {
        reply_retries: 1,
        default_deadline: Duration::from_millis(500),
        reply_ttl: Duration::from_secs(5),
        ..RecoveryLimits::default()
    };
    let mut c = b.client(fixture.seeded(0).await, limits);
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    bounded(c.replay_page(&s.subscription_handle))
        .await
        .unwrap();
    batch(&mut c).await;
    *b.faults.drop_results.lock().unwrap() = Some(wire::CONFIRM);
    assert_eq!(
        bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
            .await
            .err(),
        Some(RecoveryClientError::ReconnectRequired)
    );
    let sent = b.trace.requests(wire::CONFIRM);
    assert_eq!(sent.len(), 1);
    let results = b.trace.responses(wire::CONFIRM);
    assert_eq!(
        results.len(),
        1,
        "Host really acknowledged; this is lost wire output, not an unexecuted request"
    );
    assert_eq!(
        RecoveryConfirmResponse::decode(results[0].as_ref().unwrap().as_slice())
            .unwrap()
            .confirmed_checkpoint,
        CP[1]
    );
    assert_eq!(
        RecoveryConfirmRequest::decode(sent[0].1.as_slice())
            .unwrap()
            .checkpoint,
        CP[1]
    );
    assert_eq!(
        c.progress(&s.subscription_handle)
            .unwrap()
            .locally_durable
            .as_ref()
            .unwrap()
            .checkpoint,
        CP[1]
    );
    assert!(c
        .progress(&s.subscription_handle)
        .unwrap()
        .peer_acknowledged
        .is_none());
    drop(c);
    b.finish().await;
    drop(source);
    // Fresh Source + fresh RecoveryService: no connection/reply cache survives.
    let reconstructed = Source::new(1);
    let fresh = Bridge::new(Some(reconstructed.service(RecoveryLimits::default()))).await;
    let mut c = fresh.client(fixture.open().await, RecoveryLimits::default());
    negotiate(&mut c).await;
    let resumed = bounded(c.subscribe(A.to_vec(), A.to_vec(), SubscribeIntent::ResumeDurable))
        .await
        .unwrap();
    assert_eq!(resumed.restored.unwrap(), record(1));
    assert_ne!(resumed.response.subscription_handle, s.subscription_handle);
    assert!(
        bounded(c.replay_page(&resumed.response.subscription_handle))
            .await
            .unwrap()
            .batch_payloads
            .is_empty()
    );
    assert!(matches!(
        bounded(c.next_event()).await.unwrap(),
        RecoveryEvent::CaughtUp { .. }
    ));
    fresh.echo().await;
    drop(c);
    fresh.finish().await;
}

#[tokio::test]
async fn local_acceptance_nonempty_catchup_pages_completion_does_not_replace_durable_b() {
    let source = Source::new(3);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let mut c = b.client(memory(0), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    source.append(&service, A);
    let accepted = bounded(c.catch_up(&s.subscription_handle)).await.unwrap();
    assert_eq!(accepted.catchup_boundary, CP[3]);
    b.trace.wait_matching(1, true, |n| matches!(n, Notification::Trailer(t) if t.outcome == Some(Outcome::CatchupComplete(true)))).await;
    for index in 1..=3 {
        let offered = batch(&mut c).await;
        assert_eq!(offered.predecessor_checkpoint, CP[index - 1]);
        assert_eq!(offered.result_checkpoint, CP[index]);
        pending(c.next_event()).await;
        b.echo().await; // application is still holding its uncommitted offer
        bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
            .await
            .unwrap();
    }
    assert!(
        matches!(bounded(c.next_event()).await.unwrap(), RecoveryEvent::CaughtUp { handle } if handle == s.subscription_handle)
    );
    let live = batch(&mut c).await;
    assert_eq!(live.predecessor_checkpoint, CP[3]);
    assert_eq!(live.result_checkpoint, CP[4]);
    bounded(c.persist_and_confirm(&s.subscription_handle, STATE.to_vec()))
        .await
        .unwrap();
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 2);
    assert!(b.trace.requests(wire::REPLAY).is_empty());
    assert_eq!(b.init.notification_loss(), (0, 0));
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_lost_catchup_completion_exact_retry_reemits_without_source_work() {
    let source = Source::new(0);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    b.faults.hold_completion.store(true, Ordering::SeqCst);
    let mut c = b.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    bounded(c.catch_up(&s.subscription_handle)).await.unwrap();
    b.trace.wait_notifications(1, false).await;
    pending(c.next_event()).await;
    b.faults.hold_completion.store(false, Ordering::SeqCst);
    bounded(c.retry_completion(&s.subscription_handle))
        .await
        .unwrap();
    assert!(matches!(
        bounded(c.next_event()).await.unwrap(),
        RecoveryEvent::InitialLiveBaseline { .. }
    ));
    b.release_completions().await;
    pending(c.next_event()).await;
    let requests = b.trace.requests(wire::CATCH_UP);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].1, requests[1].1);
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 0);
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_client_completion_retry_budget_fences_old_h_and_fresh_h_is_usable() {
    let source = Source::new(0);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    b.faults.hold_completion.store(true, Ordering::SeqCst);
    let limits = RecoveryLimits {
        reply_retries: 1,
        ..RecoveryLimits::default()
    };
    let mut c = b.client(MemoryRecoveryStore::new(), limits);
    negotiate(&mut c).await;
    let old = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    bounded(c.catch_up(&old.subscription_handle)).await.unwrap();
    b.trace.wait_notifications(1, false).await;
    assert_eq!(
        bounded(c.retry_completion(&old.subscription_handle)).await,
        Err(RecoveryClientError::ReconnectRequired)
    );
    assert!(
        matches!(bounded(c.next_event()).await.unwrap(), RecoveryEvent::RecoveryNeeded { handle, .. } if handle == old.subscription_handle)
    );
    assert_eq!(b.trace.requests(wire::CATCH_UP).len(), 1);
    let fresh = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    assert_ne!(fresh.subscription_handle, old.subscription_handle);
    b.release_completions().await;
    bounded(c.catch_up(&fresh.subscription_handle))
        .await
        .unwrap();
    assert!(
        matches!(bounded(c.next_event()).await.unwrap(), RecoveryEvent::InitialLiveBaseline { handle, .. } if handle == fresh.subscription_handle)
    );
    drop(c);
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_raw_paged_retry_marker_binding_and_confirm_offered_order() {
    let source = Source::new(3);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    raw_negotiate(&b).await;
    // Identical-looking positions in another scope are not globally issued.
    assert_eq!(
        b.raw(wire::SUBSCRIBE, sub(B, CP[0])).await,
        Err(ErrorCode::FailedPrecondition)
    );
    let s = raw_sub(&b, A, CP[0]).await;
    let first = replay(&s, CP[0]);
    let bytes = b.raw(wire::REPLAY, first.clone()).await.unwrap();
    let page = RecoveryReplayPage::decode(bytes.as_slice()).unwrap();
    assert_eq!(page.batch_payloads.len(), 2);
    assert_eq!(b.raw(wire::REPLAY, first).await.unwrap(), bytes);
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        b.raw(wire::CONFIRM, confirm(&s, CP[2])).await,
        Err(ErrorCode::FailedPrecondition)
    );
    let mut next = replay(&s, &page.result_checkpoint);
    // Empty marker, transplanted cursor, and widened negotiated bounds fail
    // without advancing source or losing the immediately preceding reply.
    assert_eq!(
        b.raw(wire::REPLAY, next.clone()).await,
        Err(ErrorCode::FailedPrecondition)
    );
    next.continuation_marker = page.continuation_marker;
    let mut wrong = next.clone();
    wrong.from_checkpoint = CP[1].to_vec();
    assert_eq!(
        b.raw(wire::REPLAY, wrong).await,
        Err(ErrorCode::FailedPrecondition)
    );
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 1);
    let last =
        RecoveryReplayPage::decode(b.raw(wire::REPLAY, next).await.unwrap().as_slice()).unwrap();
    assert_eq!(last.result_checkpoint, CP[3]);
    assert!(last.continuation_marker.is_empty());
    for cp in &CP[1..=3] {
        b.raw(wire::CONFIRM, confirm(&s, cp)).await.unwrap();
    }
    assert_eq!(source.replay_calls.load(Ordering::SeqCst), 2);
    b.echo().await;
    b.finish().await;
}

#[tokio::test]
async fn local_acceptance_snapshot_replaces_old_generation_only_with_current_g_and_full_state() {
    let fixture = StoreFixture::new();
    let source = Source::new(2);
    source.generation[0].store(19, Ordering::SeqCst);
    let b = Bridge::new(Some(source.service(RecoveryLimits::default()))).await;
    let mut c = b.client(fixture.seeded(0).await, RecoveryLimits::default());
    negotiate(&mut c).await;
    let subscription = bounded(c.subscribe(
        A.to_vec(),
        A.to_vec(),
        SubscribeIntent::SnapshotCurrentGeneration,
    ))
    .await
    .unwrap();
    assert_eq!(subscription.restored.unwrap(), record(0));
    let s = subscription.response;
    assert_eq!(s.generation, 19);
    bounded(c.snapshot_offer(&s.subscription_handle))
        .await
        .unwrap();
    for i in [1, 0] {
        bounded(c.snapshot_fetch(&s.subscription_handle, i))
            .await
            .unwrap();
    }
    let full_state = [STATE, b"\0validated CURRENT generation rows"].concat();
    let installed = bounded(c.install_and_confirm(&s.subscription_handle, full_state.clone()))
        .await
        .unwrap();
    assert_eq!(installed.generation, 19);
    assert!(b.trace.requests(wire::CONFIRM).is_empty());
    drop(c);
    b.finish().await;
    let store = fixture.open().await;
    let (loaded, wrong_p, wrong_s) = bounded(tokio::task::spawn_blocking(move || {
        (
            store.load(&scope(A)).unwrap().unwrap(),
            store
                .load(&PersistenceScope::new(OTHER_P.as_bytes().to_vec(), A.to_vec()).unwrap())
                .unwrap(),
            store.load(&scope(B)).unwrap(),
        )
    }))
    .await
    .unwrap();
    assert_eq!(
        loaded,
        DurableRecord {
            generation: 19,
            checkpoint: CP[2].to_vec(),
            application_state: full_state
        }
    );
    assert!(wrong_p.is_none() && wrong_s.is_none());
}

#[tokio::test]
async fn local_acceptance_closed_attached_inbox_never_falls_back_to_generic_notifications() {
    let source = Source::new(0);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let mut c = b.client(MemoryRecoveryStore::new(), RecoveryLimits::default());
    negotiate(&mut c).await;
    let s = subscribe(&mut c, A, SubscribeIntent::InitialLiveOnly).await;
    bounded(c.catch_up(&s.subscription_handle)).await.unwrap();
    assert!(matches!(
        bounded(c.next_event()).await.unwrap(),
        RecoveryEvent::InitialLiveBaseline { .. }
    ));
    drop(c); // closes the already negotiated connection-owned inbox
    assert!(matches!(
        RecoveryClient::new(
            b.init.clone(),
            P.as_bytes().to_vec(),
            MemoryRecoveryStore::new(),
            RecoveryLimits::default()
        ),
        Err(RecoveryClientError::InvalidState)
    ));
    let before = b.trace.notifications(true).len();
    source.append(&service, A);
    b.trace.wait_notifications(before + 1, true).await; // actual Host publication reached Initiator
    let leaked = {
        let notification = b.init.next_notification();
        tokio::pin!(notification);
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match notification.as_mut().poll(cx) {
                std::task::Poll::Ready(Some(_)) => true,
                std::task::Poll::Ready(None) | std::task::Poll::Pending => false,
            })
        })
        .await
    };
    b.finish().await;
    assert!(
        !leaked,
        "negotiated recovery data leaked into the generic capacity-one queue after inbox closure"
    );
}

#[tokio::test]
async fn local_acceptance_provider_loss_revokes_pending_offer_and_all_same_s_aliases() {
    let source = Source::new(1);
    let service = source.service(RecoveryLimits::default());
    let b = Bridge::new(Some(service.clone())).await;
    let mut c = b.client(memory(0), RecoveryLimits::default());
    negotiate(&mut c).await;
    let first = subscribe(&mut c, A, SubscribeIntent::ResumeDurable).await;
    let alias = subscribe(&mut c, ALIAS, SubscribeIntent::ResumeDurable).await;
    bounded(c.replay_page(&first.subscription_handle))
        .await
        .unwrap();
    assert_eq!(
        batch(&mut c).await.subscription_handle,
        first.subscription_handle
    );
    // The application holds an unpersisted old-G offer during continuity loss.
    source.generation[0].store(19, Ordering::SeqCst);
    service
        .provider_loss(&Principal::new(P), A, 7, 19, ProviderLoss::SharedRebase)
        .unwrap();
    b.trace.wait_matching(2, true, |n| matches!(n, Notification::Trailer(t) if t.outcome == Some(Outcome::NextGeneration(19)))).await;
    assert_eq!(
        bounded(c.persist_and_confirm(&first.subscription_handle, STATE.to_vec()))
            .await
            .err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    assert!(b.trace.requests(wire::CONFIRM).is_empty());
    assert_eq!(
        c.progress(&first.subscription_handle)
            .unwrap()
            .locally_durable
            .as_ref()
            .unwrap()
            .checkpoint,
        CP[0]
    );
    let mut handles = Vec::new();
    for _ in 0..2 {
        match bounded(c.next_event()).await.unwrap() {
            RecoveryEvent::RecoveryNeeded {
                handle,
                generation: 7,
                next_generation: Some(19),
                ..
            } => handles.push(handle),
            _ => panic!("provider G must fence every same-P/S alias"),
        }
    }
    handles.sort();
    let mut expected = vec![first.subscription_handle, alias.subscription_handle];
    expected.sort();
    assert_eq!(handles, expected);
    b.echo().await;
    drop(c);
    b.finish().await;
}
