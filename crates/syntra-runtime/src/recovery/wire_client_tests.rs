//! Controlled core peer tests. Initiator::call, core handshake/correlation and
//! emission gates are real. Recovery-host attachment is outside this fixture's
//! scope and is exercised separately by the SDK's Host integration tests.

use super::super::persistence::MemoryRecoveryStore;
use super::*;
use prost::Message;
use std::future::Future;
use std::sync::atomic::AtomicUsize;
use syntra_core::{proto::frame::Body, proto::rpc_result, Frame, RpcRequest};
use tokio::sync::mpsc;

// This store is intentionally process-local, not a durability claim. It exposes
// the indivisible full-state record to assertions and fault injection only.
type CommitHook = Box<dyn FnOnce() + Send>;

#[derive(Clone, Default)]
struct Store {
    records: Arc<Mutex<MemoryRecoveryStore>>,
    unknown: Arc<AtomicBool>,
    hook: Arc<Mutex<Option<CommitHook>>>,
    commits: Arc<AtomicUsize>,
}

impl RecoveryPersistence for Store {
    fn load(&self, scope: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError> {
        self.records.lock().unwrap().load(scope)
    }
    fn commit(
        &mut self,
        scope: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        record: DurableRecord,
    ) -> Result<(), PersistenceError> {
        self.commits.fetch_add(1, Ordering::AcqRel);
        if let Some(hook) = self.hook.lock().unwrap().take() {
            hook();
        }
        self.records
            .lock()
            .unwrap()
            .commit(scope, expected, record)?;
        if self.unknown.load(Ordering::Acquire) {
            return Err(PersistenceError::CommitUnknown);
        }
        Ok(())
    }
}

fn scope(stream: &[u8]) -> PersistenceScope {
    PersistenceScope::new(b"P".to_vec(), stream.to_vec()).unwrap()
}
fn seed(store: &mut Store, stream: &[u8], generation: u64, checkpoint: &[u8]) {
    store
        .commit(
            &scope(stream),
            None,
            DurableRecord {
                generation,
                checkpoint: checkpoint.to_vec(),
                application_state: b"full old state".to_vec(),
            },
        )
        .unwrap();
}
fn negotiated() -> RecoveryNegotiateResponse {
    RecoveryNegotiateResponse {
        profile_version: 1,
        selected_version: 1,
        max_subscriptions_per_connection: 64,
        max_pending_rpcs_per_connection: 16,
        max_page_bytes: 262_144,
        max_snapshot_pages: 256,
    }
}
fn subscribed(h: &[u8], b: &[u8]) -> RecoverySubscribeResponse {
    RecoverySubscribeResponse {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        generation: 7,
        catchup_boundary: b.to_vec(),
    }
}
fn batch(h: &[u8], from: &[u8], to: &[u8]) -> RecoveryBatch {
    RecoveryBatch {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        generation: 7,
        predecessor_checkpoint: from.to_vec(),
        result_checkpoint: to.to_vec(),
        batch_payload: b"opaque update".to_vec(),
    }
}
fn complete(h: &[u8], b: &[u8]) -> Notification {
    Notification::ReplayComplete(RecoveryReplayComplete {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        generation: 7,
        live_boundary_checkpoint: b.to_vec(),
    })
}
fn trailer(h: &[u8], outcome: Outcome) -> Notification {
    Notification::Trailer(RecoveryBatchTrailer {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        generation: 7,
        boundary_checkpoint: Vec::new(),
        outcome: Some(outcome),
        terminate_reason: Vec::new(),
    })
}
fn notify(inbox: &RecoveryInbox, n: Notification) {
    inbox
        .push(
            &codec::encode(&RecoveryNotification {
                profile_version: 1,
                notification: Some(n),
            })
            .unwrap(),
        )
        .unwrap();
}
fn bytes<M: ProfileMessage>(message: &M) -> Result<Vec<u8>, ErrorCode> {
    Ok(codec::encode(message).unwrap())
}
fn final_page(h: &[u8], from: &[u8], b: &[u8], entries: Vec<RecoveryBatch>) -> RecoveryReplayPage {
    RecoveryReplayPage {
        profile_version: 1,
        subscription_handle: h.to_vec(),
        predecessor_checkpoint: from.to_vec(),
        result_checkpoint: b.to_vec(),
        continuation_marker: Vec::new(),
        catchup_boundary: b.to_vec(),
        batch_payloads: entries.iter().map(|b| codec::encode(b).unwrap()).collect(),
    }
}

struct Peer {
    initiator: Initiator,
    writer: mpsc::Receiver<Vec<u8>>,
    seen: Vec<(u64, RpcRequest)>,
}

impl Peer {
    async fn active() -> Self {
        let (initiator, mut writer) = Initiator::new(crate::ConnectionConfig::default());
        let handshake = initiator.handshake(Vec::new());
        let accept = async {
            let hello = initiator
                .prepare_outbound(writer.recv().await.unwrap())
                .unwrap();
            assert!(matches!(
                Frame::decode(hello.as_slice()).unwrap().body,
                Some(Body::Hello(_))
            ));
            initiator
                .ingest(
                    &Frame {
                        version: 1,
                        request_id: 0,
                        body: Some(Body::Ready(ServerReady {
                            connection_id: "controlled-peer".into(),
                        })),
                    }
                    .encode_to_vec(),
                )
                .await;
        };
        let (result, ()) = tokio::join!(handshake, accept);
        result.unwrap();
        Self {
            initiator,
            writer,
            seen: Vec::new(),
        }
    }

    async fn request(&mut self, method: &str) -> (u64, RpcRequest) {
        let original = self.writer.recv().await.unwrap();
        let frame = Frame::decode(
            self.initiator
                .prepare_outbound(original)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let Some(Body::Request(request)) = frame.body else {
            panic!("expected RPC");
        };
        assert_eq!(request.method, method);
        self.seen.push((frame.request_id, request.clone()));
        (frame.request_id, request)
    }

    async fn result(&self, id: u64, payload: Result<Vec<u8>, ErrorCode>) {
        let outcome = match payload {
            Ok(payload) => rpc_result::Outcome::Payload(payload),
            Err(code) => rpc_result::Outcome::Error(syntra_core::proto::RpcError {
                code: code.as_i32(),
                message: "public failure".into(),
            }),
        };
        self.initiator
            .ingest(
                &Frame {
                    version: 1,
                    request_id: id,
                    body: Some(Body::Result(RpcResult {
                        outcome: Some(outcome),
                    })),
                }
                .encode_to_vec(),
            )
            .await;
    }

    async fn rpc<T>(
        &mut self,
        operation: impl Future<Output = T>,
        method: &str,
        response: impl FnOnce(&RpcRequest) -> Result<Vec<u8>, ErrorCode>,
    ) -> T {
        let peer = async {
            let (id, request) = self.request(method).await;
            self.result(id, response(&request)).await;
        };
        let (value, ()) = tokio::join!(operation, peer);
        value
    }

    async fn client(&mut self, store: Store, limits: RecoveryLimits) -> RecoveryClient<Store> {
        let mut client =
            RecoveryClient::new(self.initiator.clone(), b"P".to_vec(), store, limits).unwrap();
        let result = self
            .rpc(client.negotiate(), wire::NEGOTIATE, |r| {
                let request: RecoveryNegotiateRequest = codec::decode(&r.payload).unwrap();
                assert_eq!((request.min_version, request.max_version), (1, 1));
                assert_eq!(request.capability, wire::CAPABILITY);
                bytes(&negotiated())
            })
            .await
            .unwrap();
        assert!(matches!(result, Negotiation::Confirmed(_)));
        client
    }

    async fn subscribe(
        &mut self,
        client: &mut RecoveryClient<Store>,
        h: &[u8],
        b: &[u8],
        stream: &[u8],
        intent: SubscribeIntent,
    ) -> Subscription {
        self.rpc(
            client.subscribe(b"selector-or-alias".to_vec(), stream.to_vec(), intent),
            wire::SUBSCRIBE,
            |_| bytes(&subscribed(h, b)),
        )
        .await
        .unwrap()
    }

    async fn catchup(&mut self, client: &mut RecoveryClient<Store>, h: &[u8], b: &[u8]) {
        self.rpc(client.catch_up(h), wire::CATCH_UP, |_| {
            bytes(&RecoveryCatchUpAccepted {
                profile_version: 1,
                subscription_handle: h.to_vec(),
                generation: 7,
                catchup_boundary: b.to_vec(),
            })
        })
        .await
        .unwrap();
    }

    async fn persist(
        &mut self,
        client: &mut RecoveryClient<Store>,
        h: &[u8],
        cp: &[u8],
        state: &[u8],
    ) {
        self.rpc(
            client.persist_and_confirm(h, state.to_vec()),
            wire::CONFIRM,
            |request| {
                let r: RecoveryConfirmRequest = codec::decode(&request.payload).unwrap();
                assert_eq!(r.checkpoint, cp);
                bytes(&RecoveryConfirmResponse {
                    profile_version: 1,
                    subscription_handle: h.to_vec(),
                    generation: 7,
                    confirmed_checkpoint: cp.to_vec(),
                })
            },
        )
        .await
        .unwrap();
    }
}

async fn event(client: &mut RecoveryClient<Store>) -> RecoveryEvent {
    tokio::time::timeout(Duration::from_secs(1), client.next_event())
        .await
        .unwrap()
        .unwrap()
}
async fn no_event(client: &mut RecoveryClient<Store>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(3), client.next_event())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invalid_limits_are_fallible() {
    let (initiator, _) = Initiator::new(crate::ConnectionConfig::default());
    let limits = RecoveryLimits {
        reply_retries: 0,
        ..RecoveryLimits::default()
    };
    assert!(matches!(
        RecoveryClient::new(
            initiator,
            b"P".to_vec(),
            super::super::persistence::MemoryRecoveryStore::new(),
            limits
        ),
        Err(RecoveryClientError::InvalidState)
    ));
}

#[tokio::test]
async fn unconfirmed_operations_emit_nothing_and_unknown_host_is_explicit() {
    let mut peer = Peer::active().await;
    let mut client = RecoveryClient::new(
        peer.initiator.clone(),
        b"P".to_vec(),
        Store::default(),
        RecoveryLimits::default(),
    )
    .unwrap();
    assert_eq!(
        client.catch_up(b"H").await.err(),
        Some(RecoveryClientError::Unconfirmed)
    );
    assert!(peer.writer.try_recv().is_err());
    assert!(!client.inbox.is_enabled());
    let unavailable = peer
        .rpc(client.negotiate(), wire::NEGOTIATE, |_| {
            Err(ErrorCode::Unimplemented)
        })
        .await
        .unwrap();
    assert!(matches!(unavailable, Negotiation::RecoveryUnavailable));
    assert!(!client.inbox.is_enabled());
    assert!(
        !peer.initiator.is_closed(),
        "mandatory-only core remains usable"
    );
    assert_eq!(
        client
            .subscribe(
                b"s".to_vec(),
                b"S".to_vec(),
                SubscribeIntent::InitialLiveOnly
            )
            .await
            .err(),
        Some(RecoveryClientError::RecoveryUnavailable)
    );
    let (other, mut writer) = Initiator::new(crate::ConnectionConfig::default());
    let mut other = RecoveryClient::new(
        other,
        b"P".to_vec(),
        Store::default(),
        RecoveryLimits::default(),
    )
    .unwrap();
    assert_eq!(
        other.negotiate().await.err(),
        Some(RecoveryClientError::InvalidState)
    );
    assert!(writer.try_recv().is_err(), "no pre-ACTIVE negotiation");
}

#[tokio::test]
async fn selected_quota_above_sixteen_is_not_accepted() {
    let mut peer = Peer::active().await;
    let mut client = RecoveryClient::new(
        peer.initiator.clone(),
        b"P".to_vec(),
        Store::default(),
        RecoveryLimits::default(),
    )
    .unwrap();
    let mut response = negotiated();
    response.max_pending_rpcs_per_connection = 17;
    assert_eq!(
        peer.rpc(client.negotiate(), wire::NEGOTIATE, |_| Ok(
            response.encode_to_vec()
        ))
        .await
        .err(),
        Some(RecoveryClientError::InvalidState)
    );
    assert!(!client.inbox.is_enabled());
}

#[test]
fn inbox_version_wrapper_unknown_fields_and_registration_window() {
    let inbox = Arc::new(RecoveryInbox::new(RecoveryLimits::default()));
    assert_eq!(inbox.push(&[]), Err(ProviderError::FailedPrecondition));
    inbox.enable().unwrap();
    assert_eq!(
        inbox.push(
            &RecoveryNotification {
                profile_version: 1,
                notification: None
            }
            .encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    let mut wrong = batch(b"H", b"A", b"B");
    wrong.profile_version = 2;
    assert_eq!(
        inbox.push(
            &RecoveryNotification {
                profile_version: 1,
                notification: Some(Notification::Batch(wrong))
            }
            .encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    notify(&inbox, Notification::Batch(batch(b"unknown", b"A", b"B")));
    assert_eq!(inbox.counts().handles, 0);
    let pending = inbox.begin_subscribe().unwrap();
    let mut payload = codec::encode(&RecoveryNotification {
        profile_version: 1,
        notification: Some(Notification::Batch(batch(b"H", b"A", b"B"))),
    })
    .unwrap();
    payload.extend_from_slice(&[0xa0, 0x06, 1]); // ignorable field 100, varint
    inbox.push(&payload).unwrap();
    assert_eq!(inbox.counts().data_messages, 1);
    drop(pending);
    assert_eq!(inbox.counts().handles, 0);
    let pending = inbox.begin_subscribe().unwrap();
    notify(&inbox, Notification::Batch(batch(b"H", b"A", b"B")));
    notify(&inbox, Notification::Batch(batch(b"other", b"A", b"B")));
    pending.register(b"H", 7, b"S").unwrap();
    assert_eq!(inbox.counts().handles, 1);
    assert_eq!(inbox.counts().data_messages, 1);
    inbox.retire(b"H");
    notify(&inbox, complete(b"H", b"B"));
    assert_eq!(inbox.counts().control_messages, 0);
    assert_eq!(
        inbox.begin_subscribe().unwrap().register(b"H", 7, b"S"),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(
        inbox.push(&vec![0; codec::MAX_PAYLOAD_BYTES + 1]),
        Err(ProviderError::ResourceExhausted)
    );
}

#[test]
fn inbox_overflow_is_targeted_reserved_and_unchanged_generation_even_with_leased_offer() {
    let inbox = Arc::new(RecoveryInbox::new(RecoveryLimits {
        queued_messages_per_stream: 1,
        ..RecoveryLimits::default()
    }));
    inbox.enable().unwrap();
    inbox
        .begin_subscribe()
        .unwrap()
        .register(b"H", 7, b"S")
        .unwrap();
    inbox
        .begin_subscribe()
        .unwrap()
        .register(b"J", 7, b"T")
        .unwrap();
    notify(&inbox, Notification::Batch(batch(b"H", b"A", b"B")));
    assert!(inbox.take_batch(b"H", false, |_| true).is_some());
    assert_eq!(
        inbox.counts().data_messages,
        1,
        "leased offer remains charged"
    );
    notify(&inbox, Notification::Batch(batch(b"J", b"A", b"B")));
    notify(&inbox, Notification::Batch(batch(b"H", b"B", b"C")));
    let Some(Notification::Trailer(t)) = inbox.take_control(b"H") else {
        panic!("reserved terminal");
    };
    assert_eq!(t.generation, 7);
    assert_eq!(t.outcome, Some(Outcome::Terminated(true)));
    assert_eq!(t.terminate_reason, b"local-queue-exhausted");
    assert!(inbox.active(b"J", 7));
    assert_eq!(inbox.counts().data_messages, 1);
    notify(&inbox, complete(b"J", b"B"));
    assert!(
        inbox.take_control(b"J").is_some(),
        "completion not behind application data"
    );
}

#[tokio::test]
async fn initial_baseline_holds_early_live_and_acceptance_is_not_completion() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    let inbox = client.inbox();
    peer.rpc(
        client.subscribe(
            b"alias".to_vec(),
            b"S".to_vec(),
            SubscribeIntent::InitialLiveOnly,
        ),
        wire::SUBSCRIBE,
        |request| {
            let request: RecoverySubscribeRequest = codec::decode(&request.payload).unwrap();
            assert!(request.start_checkpoint.is_empty());
            notify(&inbox, Notification::Batch(batch(b"H", b"B", b"L")));
            bytes(&subscribed(b"H", b"B"))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        client.replay_page(b"H").await.err(),
        Some(RecoveryClientError::InvalidState)
    );
    peer.catchup(&mut client, b"H", b"B").await;
    no_event(&mut client).await;
    assert!(store.load(&scope(b"S")).unwrap().is_none());
    notify(&inbox, complete(b"H", b"B"));
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::InitialLiveBaseline { .. }
    ));
    let RecoveryEvent::Batch { batch } = event(&mut client).await else {
        panic!("live offer");
    };
    assert_eq!(batch.result_checkpoint, b"L");
    assert!(
        store.load(&scope(b"S")).unwrap().is_none(),
        "offer is not durable"
    );
    assert!(peer.writer.try_recv().is_err(), "offer never auto-confirms");
    peer.persist(
        &mut client,
        b"H",
        b"L",
        b"full state including live effects",
    )
    .await;
    assert_eq!(
        store.load(&scope(b"S")).unwrap().unwrap().application_state,
        b"full state including live effects"
    );
    let progress = client.progress(b"H").unwrap();
    assert_eq!(progress.locally_durable, progress.confirm_sent);
    assert_eq!(progress.confirm_sent, progress.peer_acknowledged);
}

#[tokio::test]
async fn replay_and_live_use_same_pipeline_with_durable_boundary_and_duplicates() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"A");
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    let restored = peer
        .subscribe(
            &mut client,
            b"H",
            b"B",
            b"S",
            SubscribeIntent::ResumeDurable,
        )
        .await;
    assert_eq!(
        restored.restored.unwrap().application_state,
        b"full old state"
    );
    let inbox = client.inbox();
    notify(&inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let page = final_page(b"H", b"A", b"B", vec![batch(b"H", b"A", b"B")]);
    peer.rpc(client.replay_page(b"H"), wire::REPLAY, |request| {
        let r: RecoveryReplayRequest = codec::decode(&request.payload).unwrap();
        assert_eq!(r.from_checkpoint, b"A");
        assert!(r.continuation_marker.is_empty());
        bytes(&page)
    })
    .await
    .unwrap();
    notify(&inbox, complete(b"H", b"B"));
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::Batch { .. }
    ));
    no_event(&mut client).await;
    assert_eq!(
        client
            .progress(b"H")
            .unwrap()
            .locally_durable
            .as_ref()
            .unwrap()
            .checkpoint,
        b"A"
    );
    peer.persist(&mut client, b"H", b"B", b"state at B").await;
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::CaughtUp { .. }
    ));
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::Batch { .. }
    ));
    peer.persist(&mut client, b"H", b"L", b"state at L").await;
    notify(&inbox, Notification::Batch(batch(b"H", b"A", b"B")));
    no_event(&mut client).await;
    let mut stale = batch(b"H", b"A", b"B");
    stale.generation = 6;
    assert_eq!(
        inbox.push(
            &RecoveryNotification {
                profile_version: 1,
                notification: Some(Notification::Batch(stale))
            }
            .encode_to_vec()
        ),
        Err(ProviderError::FailedPrecondition)
    );
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().checkpoint, b"L");
}

#[tokio::test]
async fn noop_replay_at_boundary_and_exact_completion_retry_use_fresh_ids() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"B");
    let mut client = peer.client(store, RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::ResumeDurable,
    )
    .await;
    let page = final_page(b"H", b"B", b"B", vec![]);
    peer.rpc(client.replay_page(b"H"), wire::REPLAY, |_| bytes(&page))
        .await
        .unwrap();
    no_event(&mut client).await;
    let original = peer.seen.last().unwrap().clone();
    let inbox = client.inbox();
    peer.rpc(client.retry_completion(b"H"), wire::REPLAY, |_| {
        notify(&inbox, complete(b"H", b"B"));
        bytes(&page)
    })
    .await
    .unwrap();
    let retry = peer.seen.last().unwrap();
    assert_ne!(original.0, retry.0);
    assert_eq!(original.1.payload, retry.1.payload);
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::CaughtUp { .. }
    ));
}

#[tokio::test]
async fn continuation_echo_and_wrong_fixed_boundary_retire_only_that_round() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"A");
    let mut client = peer.client(store, RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::ResumeDurable,
    )
    .await;
    let page = RecoveryReplayPage {
        profile_version: 1,
        subscription_handle: b"H".to_vec(),
        predecessor_checkpoint: b"A".to_vec(),
        result_checkpoint: b"C".to_vec(),
        continuation_marker: b"opaque marker".to_vec(),
        catchup_boundary: b"B".to_vec(),
        batch_payloads: vec![codec::encode(&batch(b"H", b"A", b"C")).unwrap()],
    };
    peer.rpc(client.replay_page(b"H"), wire::REPLAY, |_| bytes(&page))
        .await
        .unwrap();
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::Batch { .. }
    ));
    peer.persist(&mut client, b"H", b"C", b"C state").await;
    let bad = final_page(
        b"H",
        b"C",
        b"different B",
        vec![batch(b"H", b"C", b"different B")],
    );
    assert_eq!(
        peer.rpc(client.replay_page(b"H"), wire::REPLAY, |request| {
            let r: RecoveryReplayRequest = codec::decode(&request.payload).unwrap();
            assert_eq!(r.continuation_marker, b"opaque marker");
            assert_eq!(r.from_checkpoint, b"C");
            bytes(&bad)
        })
        .await
        .err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    assert!(!client.inbox.active(b"H", 7));
}

#[tokio::test]
async fn provider_loss_fences_alias_subscriptions_and_unpersisted_offers_not_other_streams() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    for (h, s) in [
        (b"H".as_slice(), b"S".as_slice()),
        (b"J", b"S"),
        (b"K", b"T"),
    ] {
        peer.subscribe(&mut client, h, b"B", s, SubscribeIntent::InitialLiveOnly)
            .await;
        peer.catchup(&mut client, h, b"B").await;
        notify(&client.inbox, complete(h, b"B"));
        let _ = event(&mut client).await;
    }
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::Batch { .. }
    ));
    notify(&client.inbox, trailer(b"J", Outcome::NextGeneration(8)));
    assert_eq!(
        client
            .persist_and_confirm(b"H", b"must not commit".to_vec())
            .await
            .err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    assert!(store.load(&scope(b"S")).unwrap().is_none());
    assert!(!client.inbox.active(b"H", 7));
    assert!(!client.inbox.active(b"J", 7));
    assert!(client.inbox.active(b"K", 7));
    assert!(peer.writer.try_recv().is_err());
}

#[tokio::test]
async fn commit_unknown_never_confirms_and_next_connection_uses_durable_unacknowledged_record() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.catchup(&mut client, b"H", b"B").await;
    notify(&client.inbox, complete(b"H", b"B"));
    let _ = event(&mut client).await;
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let _ = event(&mut client).await;
    store.unknown.store(true, Ordering::Release);
    assert_eq!(
        client
            .persist_and_confirm(b"H", b"full durable state".to_vec())
            .await
            .err(),
        Some(RecoveryClientError::CommitUnknown)
    );
    assert!(peer.writer.try_recv().is_err());
    assert!(client.inbox.is_closed());
    assert!(client.progress(b"H").unwrap().peer_acknowledged.is_none());
    drop(client);
    store.unknown.store(false, Ordering::Release);
    let mut next = Peer::active().await;
    let mut client = next.client(store, RecoveryLimits::default()).await;
    assert!(client.rounds.is_empty());
    next.rpc(
        client.subscribe(
            b"new alias".to_vec(),
            b"S".to_vec(),
            SubscribeIntent::ResumeDurable,
        ),
        wire::SUBSCRIBE,
        |request| {
            assert_eq!(
                codec::decode::<RecoverySubscribeRequest>(&request.payload)
                    .unwrap()
                    .start_checkpoint,
                b"L"
            );
            bytes(&subscribed(b"fresh H", b"fresh B"))
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn native_store_runs_off_executor_and_loss_during_write_prevents_confirm() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.catchup(&mut client, b"H", b"B").await;
    notify(&client.inbox, complete(b"H", b"B"));
    let _ = event(&mut client).await;
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let _ = event(&mut client).await;
    let inbox = client.inbox();
    let executor_thread = std::thread::current().id();
    *store.hook.lock().unwrap() = Some(Box::new(move || {
        assert_ne!(executor_thread, std::thread::current().id());
        notify(&inbox, trailer(b"H", Outcome::NextGeneration(8)));
        assert!(
            !inbox.active(b"H", 7),
            "ingress fences independently of app IO"
        );
    }));
    assert_eq!(
        client
            .persist_and_confirm(b"H", b"old-G write completed".to_vec())
            .await
            .err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().generation, 7);
    assert_eq!(
        client
            .progress(b"H")
            .unwrap()
            .locally_durable
            .as_ref()
            .unwrap()
            .checkpoint,
        b"L"
    );
    assert!(client.progress(b"H").unwrap().confirm_sent.is_none());
    assert!(peer.writer.try_recv().is_err());
}

async fn snapshot(peer: &mut Peer, client: &mut RecoveryClient<Store>, h: &[u8], s0: &[u8]) {
    peer.rpc(client.snapshot_offer(h), wire::SNAPSHOT_OFFER, |_| {
        bytes(&RecoverySnapshotDescriptor {
            profile_version: 1,
            subscription_handle: h.to_vec(),
            snapshot_handle: b"X".to_vec(),
            boundary_checkpoint: s0.to_vec(),
            total_pages: 1,
            page_bytes_max: 32,
        })
    })
    .await
    .unwrap();
    peer.rpc(
        client.snapshot_fetch(h, 0),
        wire::SNAPSHOT_FETCH,
        |request| {
            let r: RecoverySnapshotFetchRequest = codec::decode(&request.payload).unwrap();
            assert_eq!(r.snapshot_handle, b"X");
            assert_eq!(r.page_index, 0);
            bytes(&RecoverySnapshotChunk {
                profile_version: 1,
                snapshot_handle: b"X".to_vec(),
                page_index: 0,
                boundary_checkpoint: s0.to_vec(),
                page_bytes: b"snapshot bytes".to_vec(),
            })
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn snapshot_same_generation_at_s0_different_from_old_b_requires_installed_gate() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"old B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    snapshot(&mut peer, &mut client, b"H", b"S0").await;
    assert_eq!(client.snapshot_bytes(b"H").unwrap(), b"snapshot bytes");
    notify(&client.inbox, complete(b"H", b"old B"));
    notify(&client.inbox, Notification::Batch(batch(b"H", b"S0", b"L")));
    no_event(&mut client).await;
    let observed = store.clone();
    peer.rpc(
        client.install_and_confirm(b"H", b"transformed full snapshot state".to_vec()),
        wire::SNAPSHOT_CONFIRM,
        |request| {
            let r: RecoverySnapshotConfirmRequest = codec::decode(&request.payload).unwrap();
            assert_eq!(r.generation, 7);
            assert_eq!(r.boundary_checkpoint, b"S0");
            let durable = observed.load(&scope(b"S")).unwrap().unwrap();
            assert_eq!(durable.checkpoint, b"S0");
            assert_eq!(
                durable.application_state,
                b"transformed full snapshot state"
            );
            bytes(&RecoverySnapshotInstalled {
                profile_version: 1,
                subscription_handle: b"H".to_vec(),
                generation: 7,
                boundary_checkpoint: b"S0".to_vec(),
            })
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::Batch { .. }
    ));
    assert_eq!(
        client.catch_up(b"H").await.err(),
        Some(RecoveryClientError::InvalidState),
        "additional catch-up requires fresh H/B"
    );
    peer.persist(&mut client, b"H", b"L", b"snapshot plus live state")
        .await;
    peer.rpc(client.unsubscribe(b"H"), wire::UNSUBSCRIBE, |_| {
        bytes(&RecoveryUnsubscribeResponse {
            profile_version: 1,
            subscription_handle: b"H".to_vec(),
            generation: 7,
        })
    })
    .await
    .unwrap();
    assert!(!client.inbox.active(b"H", 7));
}

#[tokio::test]
async fn snapshot_required_after_staging_retires_offer_even_at_equal_boundary() {
    for s0 in [b"B".as_slice(), b"S0".as_slice()] {
        let mut peer = Peer::active().await;
        let store = Store::default();
        let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
        peer.subscribe(
            &mut client,
            b"H",
            b"B",
            b"S",
            SubscribeIntent::InitialLiveOnly,
        )
        .await;
        snapshot(&mut peer, &mut client, b"H", s0).await;
        assert_eq!(client.snapshot_bytes(b"H").unwrap(), b"snapshot bytes");
        notify(&client.inbox, Notification::Batch(batch(b"H", s0, b"L")));
        assert_eq!(client.inbox.counts().data_messages, 1);
        let mut expiry = trailer(b"H", Outcome::SnapshotRequired(true));
        if let Notification::Trailer(ref mut t) = expiry {
            t.boundary_checkpoint = s0.to_vec();
        }
        notify(&client.inbox, expiry);

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            client.install_and_confirm(b"H", b"must not install expired X".to_vec()),
        )
        .await
        .expect("expiry must reject installation without waiting for a Confirm reply");
        assert_eq!(result.err(), Some(RecoveryClientError::RecoveryNeeded));
        assert!(store.load(&scope(b"S")).unwrap().is_none());
        assert_eq!(store.commits.load(Ordering::Acquire), 0);
        let round = client.rounds.get(b"H".as_slice()).unwrap();
        assert!(round.mode == Mode::Retired);
        assert!(round.stage.is_none());
        assert!(round.pending.is_none());
        assert_eq!(round.progress, RecoveryProgress::default());
        assert!(!client.inbox.active(b"H", 7));
        assert_eq!(client.inbox.counts().data_messages, 0);
        assert_eq!(
            client.snapshot_bytes(b"H").err(),
            Some(RecoveryClientError::RecoveryNeeded)
        );
        assert_eq!(
            client.snapshot_fetch(b"H", 0).await.err(),
            Some(RecoveryClientError::RecoveryNeeded)
        );
        assert_eq!(
            client.snapshot_offer(b"H").await.err(),
            Some(RecoveryClientError::RecoveryNeeded)
        );
        assert!(
            peer.writer.try_recv().is_err(),
            "expired X must emit no SnapshotConfirm or same-H retry"
        );
        assert!(matches!(
            event(&mut client).await,
            RecoveryEvent::RecoveryNeeded {
                generation: 7,
                next_generation: None,
                ..
            }
        ));

        peer.rpc(client.unsubscribe(b"H"), wire::UNSUBSCRIBE, |_| {
            bytes(&RecoveryUnsubscribeResponse {
                profile_version: 1,
                subscription_handle: b"H".to_vec(),
                generation: 7,
            })
        })
        .await
        .unwrap();
        peer.subscribe(
            &mut client,
            b"H2",
            s0,
            b"S",
            SubscribeIntent::SnapshotCurrentGeneration,
        )
        .await;
        assert_eq!(
            client
                .install_and_confirm(b"H2", b"old X is not a new offer".to_vec())
                .await
                .err(),
            Some(RecoveryClientError::InvalidState)
        );
        assert!(
            peer.writer.try_recv().is_err(),
            "equal G/S0 on fresh H does not restore the expired offer"
        );
    }
}

#[tokio::test]
async fn snapshot_required_during_install_write_preserves_durable_state_without_confirm() {
    for s0 in [b"B".as_slice(), b"S0".as_slice()] {
        let mut peer = Peer::active().await;
        let mut store = Store::default();
        seed(&mut store, b"S", 7, b"B");
        let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
        peer.subscribe(
            &mut client,
            b"H",
            b"B",
            b"S",
            SubscribeIntent::ResumeDurable,
        )
        .await;
        snapshot(&mut peer, &mut client, b"H", s0).await;
        let inbox = client.inbox();
        let revision = inbox.revision(b"H");
        let boundary = s0.to_vec();
        let commits_before_install = store.commits.load(Ordering::Acquire);
        *store.hook.lock().unwrap() = Some(Box::new(move || {
            let mut expiry = trailer(b"H", Outcome::SnapshotRequired(true));
            if let Notification::Trailer(ref mut t) = expiry {
                t.boundary_checkpoint = boundary.clone();
            }
            notify(&inbox, expiry);
            assert_ne!(inbox.revision(b"H"), revision);
            assert!(
                inbox.active(b"H", 7),
                "client controls must retire the offered snapshot after the write"
            );
            notify(&inbox, Notification::Batch(batch(b"H", &boundary, b"L")));
        }));

        let application_state = b"full snapshot state committed despite expiry".to_vec();
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            client.install_and_confirm(b"H", application_state.clone()),
        )
        .await
        .expect("successful local commit followed by expiry must not wait for a Confirm reply");
        assert_eq!(result.err(), Some(RecoveryClientError::RecoveryNeeded));
        let durable = DurableRecord {
            generation: 7,
            checkpoint: s0.to_vec(),
            application_state,
        };
        assert_eq!(store.load(&scope(b"S")).unwrap(), Some(durable.clone()));
        let round = client.rounds.get(b"H".as_slice()).unwrap();
        assert!(round.mode == Mode::Retired);
        assert!(round.stage.is_none());
        assert!(round.pending.is_none());
        assert_eq!(
            round.progress.locally_durable,
            Some(ExpectedPosition::from(&durable))
        );
        assert!(round.progress.confirm_sent.is_none());
        assert!(round.progress.peer_acknowledged.is_none());
        assert!(!client.inbox.active(b"H", 7));
        assert_eq!(
            client.inbox.counts().data_messages,
            0,
            "retirement clears live data queued after expiry too"
        );
        assert_eq!(
            client.snapshot_bytes(b"H").err(),
            Some(RecoveryClientError::RecoveryNeeded)
        );
        assert_eq!(
            client
                .install_and_confirm(b"H", b"must not repersist".to_vec())
                .await
                .err(),
            Some(RecoveryClientError::RecoveryNeeded)
        );
        assert_eq!(
            store.commits.load(Ordering::Acquire),
            commits_before_install + 1
        );
        assert!(
            peer.writer.try_recv().is_err(),
            "local durability is not eligibility to confirm expired X"
        );

        peer.rpc(client.unsubscribe(b"H"), wire::UNSUBSCRIBE, |_| {
            bytes(&RecoveryUnsubscribeResponse {
                profile_version: 1,
                subscription_handle: b"H".to_vec(),
                generation: 7,
            })
        })
        .await
        .unwrap();
        let resumed = peer
            .rpc(
                client.subscribe(
                    b"alias".to_vec(),
                    b"S".to_vec(),
                    SubscribeIntent::ResumeDurable,
                ),
                wire::SUBSCRIBE,
                |request| {
                    assert_eq!(
                        codec::decode::<RecoverySubscribeRequest>(&request.payload)
                            .unwrap()
                            .start_checkpoint,
                        s0
                    );
                    bytes(&subscribed(b"H2", s0))
                },
            )
            .await
            .unwrap();
        assert_eq!(resumed.restored, Some(durable.clone()));
        assert_eq!(
            client
                .install_and_confirm(b"H2", b"cannot reuse X at equal S0".to_vec())
                .await
                .err(),
            Some(RecoveryClientError::InvalidState)
        );
        assert_eq!(store.load(&scope(b"S")).unwrap(), Some(durable));
        assert_eq!(
            store.commits.load(Ordering::Acquire),
            commits_before_install + 1,
            "fresh Subscribe must not roll back or repersist the snapshot"
        );
        assert!(peer.writer.try_recv().is_err());
    }
}

#[tokio::test]
async fn snapshot_install_rejects_wrong_generation_response_without_relabeling_durable_state() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    snapshot(&mut peer, &mut client, b"H", b"S0").await;
    assert_eq!(
        peer.rpc(
            client.install_and_confirm(b"H", b"full state".to_vec()),
            wire::SNAPSHOT_CONFIRM,
            |_| bytes(&RecoverySnapshotInstalled {
                profile_version: 1,
                subscription_handle: b"H".to_vec(),
                generation: 8,
                boundary_checkpoint: b"S0".to_vec()
            })
        )
        .await
        .err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().generation, 7);
    assert!(client.progress(b"H").unwrap().peer_acknowledged.is_none());
}

#[tokio::test]
async fn explicit_current_generation_snapshot_does_not_reinterpret_old_durable_checkpoint() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 6, b"old G cursor");
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.rpc(
        client.subscribe(
            b"s".to_vec(),
            b"S".to_vec(),
            SubscribeIntent::SnapshotCurrentGeneration,
        ),
        wire::SUBSCRIBE,
        |request| {
            assert!(codec::decode::<RecoverySubscribeRequest>(&request.payload)
                .unwrap()
                .start_checkpoint
                .is_empty());
            bytes(&subscribed(b"H", b"B"))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        client.catch_up(b"H").await.err(),
        Some(RecoveryClientError::InvalidState)
    );
    snapshot(&mut peer, &mut client, b"H", b"S0").await;
    peer.rpc(
        client.install_and_confirm(b"H", b"replacement snapshot".to_vec()),
        wire::SNAPSHOT_CONFIRM,
        |_| {
            bytes(&RecoverySnapshotInstalled {
                profile_version: 1,
                subscription_handle: b"H".to_vec(),
                generation: 7,
                boundary_checkpoint: b"S0".to_vec(),
            })
        },
    )
    .await
    .unwrap();
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().generation, 7);
}

#[tokio::test]
async fn finite_confirm_retries_are_exact_fresh_ids_and_cache_expiry_preserves_durable_state() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let limits = RecoveryLimits {
        default_deadline: Duration::from_millis(8),
        reply_ttl: Duration::from_secs(1),
        reply_retries: 2,
        ..RecoveryLimits::default()
    };
    let mut client = peer.client(store.clone(), limits).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.catchup(&mut client, b"H", b"B").await;
    notify(&client.inbox, complete(b"H", b"B"));
    let _ = event(&mut client).await;
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let _ = event(&mut client).await;
    let operation = client.persist_and_confirm(b"H", b"full state".to_vec());
    let responses = async {
        let (first_id, first) = peer.request(wire::CONFIRM).await;
        // Drop first result. The client must NOT redo storage/application work.
        let (second_id, second) = peer.request(wire::CONFIRM).await;
        assert_ne!(first_id, second_id);
        assert_eq!(first.payload, second.payload);
        peer.result(second_id, Err(ErrorCode::FailedPrecondition))
            .await;
    };
    let (result, ()) = tokio::join!(operation, responses);
    assert_eq!(result.err(), Some(RecoveryClientError::ReconnectRequired));
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().checkpoint, b"L");
    let progress = client.progress(b"H").unwrap();
    assert!(progress.locally_durable.is_some());
    assert!(progress.confirm_sent.is_some());
    assert!(progress.peer_acknowledged.is_none());
    assert_eq!(
        peer.seen
            .iter()
            .filter(|(_, r)| r.method == wire::CONFIRM)
            .count(),
        2
    );
}

#[tokio::test]
async fn dropped_subscribe_fences_wrapper_and_closes_speculative_inbox() {
    let mut peer = Peer::active().await;
    let mut client = peer
        .client(Store::default(), RecoveryLimits::default())
        .await;
    let mut operation = Box::pin(client.subscribe(
        b"s".to_vec(),
        b"S".to_vec(),
        SubscribeIntent::InitialLiveOnly,
    ));
    let received = async { peer.request(wire::SUBSCRIBE).await };
    let received = tokio::select! {
        biased;
        _ = &mut operation => panic!("peer has not responded"),
        received = received => received,
    };
    assert_eq!(received.1.method, wire::SUBSCRIBE);
    drop(operation);
    assert!(client.inbox.is_closed());
    assert_eq!(
        client.catch_up(b"H").await.err(),
        Some(RecoveryClientError::ReconnectRequired)
    );
    assert!(
        peer.writer.try_recv().is_err(),
        "no automatic Subscribe retry"
    );
}

#[tokio::test]
async fn inbox_close_wakes_event_waiter() {
    let mut peer = Peer::active().await;
    let mut client = peer
        .client(Store::default(), RecoveryLimits::default())
        .await;
    let inbox = client.inbox();
    let close = async {
        tokio::task::yield_now().await;
        inbox.close();
    };
    let (result, ()) = tokio::join!(client.next_event(), close);
    assert_eq!(result.err(), Some(RecoveryClientError::ReconnectRequired));
}

#[test]
fn aggregate_bytes_bound_and_separate_equivalent_completion_slots() {
    let charge = codec::encode(&RecoveryNotification {
        profile_version: 1,
        notification: Some(Notification::Batch(batch(b"H", b"A", b"B"))),
    })
    .unwrap()
    .len()
        + 32;
    let inbox = Arc::new(RecoveryInbox::new(RecoveryLimits {
        queued_bytes_per_connection: charge,
        ..RecoveryLimits::default()
    }));
    inbox.enable().unwrap();
    inbox
        .begin_subscribe()
        .unwrap()
        .register(b"H", 7, b"S")
        .unwrap();
    inbox
        .begin_subscribe()
        .unwrap()
        .register(b"J", 7, b"T")
        .unwrap();
    notify(&inbox, Notification::Batch(batch(b"H", b"A", b"B")));
    assert_eq!(inbox.counts().data_bytes, charge, "exact MAX admitted");
    notify(&inbox, complete(b"H", b"B"));
    let mut equivalent = trailer(b"H", Outcome::CatchupComplete(true));
    if let Notification::Trailer(ref mut t) = equivalent {
        t.boundary_checkpoint = b"B".to_vec();
    }
    notify(&inbox, equivalent);
    assert_eq!(
        inbox.counts().control_messages,
        1,
        "equivalent completion forms are idempotent"
    );
    notify(&inbox, Notification::Batch(batch(b"J", b"A", b"B")));
    assert!(inbox.active(b"H", 7));
    assert!(
        !inbox.active(b"J", 7),
        "only the overflowing target is fenced"
    );
    assert_eq!(inbox.counts().data_bytes, charge);
}

#[tokio::test]
async fn retention_trailer_after_rpc_failure_allows_explicit_snapshot_not_generation_change() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"A");
    let mut client = peer.client(store, RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::ResumeDurable,
    )
    .await;
    let inbox = client.inbox();
    let response = async {
        let (id, _) = peer.request(wire::REPLAY).await;
        peer.result(id, Err(ErrorCode::FailedPrecondition)).await;
        tokio::time::sleep(Duration::from_millis(1)).await;
        notify(&inbox, trailer(b"H", Outcome::SnapshotRequired(true)));
    };
    let (result, ()) = tokio::join!(client.replay_page(b"H"), response);
    assert_eq!(
        result.err(),
        Some(RecoveryClientError::Rpc(ErrorCode::FailedPrecondition))
    );
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::SnapshotRequired { .. }
    ));
    assert!(client.inbox.active(b"H", 7));
    snapshot(&mut peer, &mut client, b"H", b"S0").await;
}

#[tokio::test]
async fn snapshot_confirm_retries_without_reinstalling_or_changing_generation() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let limits = RecoveryLimits {
        default_deadline: Duration::from_millis(10),
        reply_ttl: Duration::from_secs(1),
        reply_retries: 2,
        ..RecoveryLimits::default()
    };
    let mut client = peer.client(store.clone(), limits).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    snapshot(&mut peer, &mut client, b"H", b"S0").await;
    let committed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = committed.clone();
    *store.hook.lock().unwrap() = Some(Box::new(move || {
        count.fetch_add(1, Ordering::AcqRel);
    }));
    let inbox = client.inbox();
    let responses = async {
        let (first_id, first) = peer.request(wire::SNAPSHOT_CONFIRM).await;
        notify(&inbox, complete(b"H", b"B"));
        notify(&inbox, Notification::Batch(batch(b"H", b"S0", b"L")));
        let (retry_id, retry) = peer.request(wire::SNAPSHOT_CONFIRM).await;
        assert_ne!(first_id, retry_id);
        assert_eq!(first.payload, retry.payload);
        assert_eq!(committed.load(Ordering::Acquire), 1);
        peer.result(
            retry_id,
            bytes(&RecoverySnapshotInstalled {
                profile_version: 1,
                subscription_handle: b"H".to_vec(),
                boundary_checkpoint: b"S0".to_vec(),
                generation: 7,
            }),
        )
        .await;
    };
    let (result, ()) = tokio::join!(
        client.install_and_confirm(b"H", b"full snapshot replacement".to_vec()),
        responses
    );
    assert_eq!(result.unwrap().generation, 7);
    assert_eq!(committed.load(Ordering::Acquire), 1);
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::Batch { .. }
    ));
}

#[tokio::test]
async fn duplicate_snapshot_page_at_aggregate_max_counts_once_and_mixed_boundary_retires() {
    let mut peer = Peer::active().await;
    let mut client = peer
        .client(
            Store::default(),
            RecoveryLimits {
                snapshot_pages: 1,
                snapshot_page_bytes: 14,
                ..RecoveryLimits::default()
            },
        )
        .await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.rpc(client.snapshot_offer(b"H"), wire::SNAPSHOT_OFFER, |_| {
        bytes(&RecoverySnapshotDescriptor {
            profile_version: 1,
            subscription_handle: b"H".to_vec(),
            snapshot_handle: b"X".to_vec(),
            boundary_checkpoint: b"S0".to_vec(),
            total_pages: 1,
            page_bytes_max: 14,
        })
    })
    .await
    .unwrap();
    let mut chunk = RecoverySnapshotChunk {
        profile_version: 1,
        snapshot_handle: b"X".to_vec(),
        page_index: 0,
        boundary_checkpoint: b"S0".to_vec(),
        page_bytes: b"snapshot bytes".to_vec(),
    };
    for _ in 0..2 {
        peer.rpc(client.snapshot_fetch(b"H", 0), wire::SNAPSHOT_FETCH, |_| {
            bytes(&chunk)
        })
        .await
        .unwrap();
    }
    assert_eq!(
        client
            .rounds
            .get(b"H".as_slice())
            .unwrap()
            .stage
            .as_ref()
            .unwrap()
            .total_bytes(),
        14
    );
    chunk.boundary_checkpoint = b"other".to_vec();
    assert_eq!(
        peer.rpc(client.snapshot_fetch(b"H", 0), wire::SNAPSHOT_FETCH, |_| {
            bytes(&chunk)
        })
        .await
        .err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    assert!(client.snapshot_bytes(b"H").is_err());
}

#[tokio::test]
async fn stale_resume_generation_never_relabels_old_checkpoint() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 6, b"old C");
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    assert_eq!(
        peer.rpc(
            client.subscribe(
                b"alias".to_vec(),
                b"S".to_vec(),
                SubscribeIntent::ResumeDurable
            ),
            wire::SUBSCRIBE,
            |_| bytes(&subscribed(b"H", b"B"))
        )
        .await
        .err(),
        Some(RecoveryClientError::StaleGeneration)
    );
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().generation, 6);
    assert!(client.inbox.is_closed());
    assert!(peer.writer.try_recv().is_err());
}

#[tokio::test]
async fn fresh_handle_after_gap_uses_latest_durable_c_and_new_b_not_old_round() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store, RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H1",
        b"B1",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.catchup(&mut client, b"H1", b"B1").await;
    notify(&client.inbox, complete(b"H1", b"B1"));
    let _ = event(&mut client).await;
    notify(
        &client.inbox,
        Notification::Batch(batch(b"H1", b"B1", b"C2")),
    );
    let _ = event(&mut client).await;
    peer.persist(&mut client, b"H1", b"C2", b"durable C2".as_slice())
        .await;
    notify(
        &client.inbox,
        Notification::Batch(batch(b"H1", b"gap", b"unknown")),
    );
    assert_eq!(
        client.next_event().await.err(),
        Some(RecoveryClientError::RecoveryNeeded)
    );
    let responses = async {
        let (id, request) = peer.request(wire::UNSUBSCRIBE).await;
        assert_eq!(
            codec::decode::<RecoveryUnsubscribeRequest>(&request.payload)
                .unwrap()
                .subscription_handle,
            b"H1"
        );
        peer.result(
            id,
            bytes(&RecoveryUnsubscribeResponse {
                profile_version: 1,
                subscription_handle: b"H1".to_vec(),
                generation: 7,
            }),
        )
        .await;
        let (id, request) = peer.request(wire::SUBSCRIBE).await;
        assert_eq!(
            codec::decode::<RecoverySubscribeRequest>(&request.payload)
                .unwrap()
                .start_checkpoint,
            b"C2"
        );
        peer.result(id, bytes(&subscribed(b"H2", b"B2"))).await;
    };
    let (result, ()) = tokio::join!(
        client.subscribe(
            b"alias2".to_vec(),
            b"S".to_vec(),
            SubscribeIntent::ResumeDurable
        ),
        responses
    );
    result.unwrap();
    // Consume only the old round's local retirement event.
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::RecoveryNeeded { .. }
    ));
    let page = final_page(b"H2", b"C2", b"B2", vec![batch(b"H2", b"C2", b"B2")]);
    peer.rpc(client.replay_page(b"H2"), wire::REPLAY, |_| bytes(&page))
        .await
        .unwrap();
    notify(&client.inbox, complete(b"H1", b"B2"));
    let _ = event(&mut client).await;
    peer.persist(&mut client, b"H2", b"B2", b"durable B2").await;
    no_event(&mut client).await;
    notify(&client.inbox, complete(b"H2", b"B2"));
    assert!(matches!(
        event(&mut client).await,
        RecoveryEvent::CaughtUp { .. }
    ));
}

#[tokio::test]
async fn cancellation_during_blocking_commit_reconciles_without_late_confirm() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.catchup(&mut client, b"H", b"B").await;
    notify(&client.inbox, complete(b"H", b"B"));
    let _ = event(&mut client).await;
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let _ = event(&mut client).await;
    let (started, waiting) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    *store.hook.lock().unwrap() = Some(Box::new(move || {
        started.send(()).unwrap();
        gate.recv().unwrap();
    }));
    let mut operation =
        Box::pin(client.persist_and_confirm(b"H", b"committed after cancellation".to_vec()));
    tokio::select! {
        biased;
        _ = &mut operation => panic!("worker still gated"),
        result = waiting => result.unwrap(),
    }
    drop(operation);
    assert!(client.inbox.is_closed());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if store.load(&scope(b"S")).unwrap().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        peer.writer.try_recv().is_err(),
        "no detached confirmation worker"
    );
    assert_eq!(
        client.catch_up(b"H").await.err(),
        Some(RecoveryClientError::ReconnectRequired)
    );
}

#[tokio::test]
async fn exhausted_elapsed_budget_retires_without_extra_rpc_or_checkpoint_loss() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"B");
    let limits = RecoveryLimits {
        reply_ttl: Duration::from_millis(5),
        ..RecoveryLimits::default()
    };
    let mut client = peer.client(store.clone(), limits).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::ResumeDurable,
    )
    .await;
    peer.rpc(client.replay_page(b"H"), wire::REPLAY, |_| {
        bytes(&final_page(b"H", b"B", b"B", vec![]))
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(8)).await;
    assert_eq!(
        client.retry_completion(b"H").await.err(),
        Some(RecoveryClientError::ReconnectRequired)
    );
    assert!(peer.writer.try_recv().is_err());
    assert_eq!(store.load(&scope(b"S")).unwrap().unwrap().checkpoint, b"B");
    assert!(!client.inbox.active(b"H", 7));
}

#[tokio::test]
async fn replay_and_catchup_are_mutually_exclusive_and_unoffered_confirm_never_emits() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"A");
    let mut client = peer.client(store, RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::ResumeDurable,
    )
    .await;
    assert_eq!(
        client
            .persist_and_confirm(b"H", b"invented effects".to_vec())
            .await
            .err(),
        Some(RecoveryClientError::InvalidState)
    );
    peer.catchup(&mut client, b"H", b"B").await;
    assert_eq!(
        client.replay_page(b"H").await.err(),
        Some(RecoveryClientError::InvalidState)
    );
    assert_eq!(
        client
            .install_and_confirm(b"H", b"not staged".to_vec())
            .await
            .err(),
        Some(RecoveryClientError::InvalidState)
    );
    assert!(peer.writer.try_recv().is_err());
}

#[tokio::test]
async fn provider_loss_on_alias_interrupts_outstanding_confirm_without_waiting_for_reply() {
    let mut peer = Peer::active().await;
    let mut client = peer
        .client(Store::default(), RecoveryLimits::default())
        .await;
    for h in [b"H".as_slice(), b"J".as_slice()] {
        peer.subscribe(&mut client, h, b"B", b"S", SubscribeIntent::InitialLiveOnly)
            .await;
        peer.catchup(&mut client, h, b"B").await;
        notify(&client.inbox, complete(h, b"B"));
        let _ = event(&mut client).await;
    }
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let _ = event(&mut client).await;
    let inbox = client.inbox();
    let loss = async {
        let _ = peer.request(wire::CONFIRM).await;
        notify(&inbox, trailer(b"J", Outcome::NextGeneration(8)));
        assert!(
            !inbox.active(b"H", 7),
            "scoped ingress fencing does not wait for client polling"
        );
    };
    let (result, ()) = tokio::time::timeout(Duration::from_millis(100), async {
        tokio::join!(
            client.persist_and_confirm(b"H", b"durable L".to_vec()),
            loss
        )
    })
    .await
    .unwrap();
    assert_eq!(result.err(), Some(RecoveryClientError::RecoveryNeeded));
    assert!(client.progress(b"H").unwrap().peer_acknowledged.is_none());
    assert!(
        peer.writer.try_recv().is_err(),
        "no stale confirmation retries"
    );
}

#[tokio::test]
async fn changed_retained_page_cannot_pass_as_a_completion_retry() {
    let mut peer = Peer::active().await;
    let mut store = Store::default();
    seed(&mut store, b"S", 7, b"B");
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::ResumeDurable,
    )
    .await;
    peer.rpc(client.replay_page(b"H"), wire::REPLAY, |_| {
        bytes(&final_page(b"H", b"B", b"B", vec![]))
    })
    .await
    .unwrap();
    let changed = final_page(b"H", b"C", b"B", vec![batch(b"H", b"C", b"B")]);
    assert_eq!(
        peer.rpc(client.retry_completion(b"H"), wire::REPLAY, |_| bytes(
            &changed
        ))
        .await
        .err(),
        Some(RecoveryClientError::InvalidState)
    );
    assert_eq!(
        store.load(&scope(b"S")).unwrap().unwrap().application_state,
        b"full old state"
    );
    assert!(!client.inbox.active(b"H", 7));
}

#[tokio::test]
async fn persistence_worker_panic_is_not_a_silent_drop() {
    let mut peer = Peer::active().await;
    let store = Store::default();
    let mut client = peer.client(store.clone(), RecoveryLimits::default()).await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    peer.catchup(&mut client, b"H", b"B").await;
    notify(&client.inbox, complete(b"H", b"B"));
    let _ = event(&mut client).await;
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"L")));
    let _ = event(&mut client).await;
    let inbox = client.inbox();
    *store.hook.lock().unwrap() = Some(Box::new(|| panic!("test store panic")));
    let task =
        tokio::spawn(async move { client.persist_and_confirm(b"H", b"state".to_vec()).await });
    assert!(task.await.unwrap_err().is_panic());
    assert!(inbox.is_closed());
    assert!(peer.writer.try_recv().is_err());
}

#[tokio::test]
async fn local_overflow_event_carries_ascii_terminal_without_inventing_next_generation() {
    let mut peer = Peer::active().await;
    let mut client = peer
        .client(
            Store::default(),
            RecoveryLimits {
                queued_messages_per_stream: 1,
                ..RecoveryLimits::default()
            },
        )
        .await;
    peer.subscribe(
        &mut client,
        b"H",
        b"B",
        b"S",
        SubscribeIntent::InitialLiveOnly,
    )
    .await;
    notify(&client.inbox, Notification::Batch(batch(b"H", b"B", b"C")));
    notify(&client.inbox, Notification::Batch(batch(b"H", b"C", b"D")));
    let RecoveryEvent::RecoveryNeeded {
        generation,
        next_generation,
        termination: Some(t),
        ..
    } = event(&mut client).await
    else {
        panic!("local terminal event");
    };
    assert_eq!(generation, 7);
    assert_eq!(next_generation, None);
    assert_eq!(t.generation, 7);
    assert_eq!(t.outcome, Some(Outcome::Terminated(true)));
    assert_eq!(t.terminate_reason, b"local-queue-exhausted");
    assert!(
        peer.writer.try_recv().is_err(),
        "never send local trailers as Notifications"
    );
}
