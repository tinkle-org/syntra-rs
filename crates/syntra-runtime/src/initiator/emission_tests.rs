use super::*;
use syntra_core::{proto::rpc_result::Outcome, RpcResult};

const METHOD: &str = "/example.Echo/Echo";

async fn active(config: ConnectionConfig) -> (Initiator, mpsc::Receiver<Vec<u8>>) {
    let (client, writer) = Initiator::new(config);
    *client.conn.shared.state.write().await = ConnectionState::Active;
    *client.conn.shared.version.write().await = Some(1);
    (client, writer)
}

fn assert_clean(client: &Initiator) {
    assert_eq!(client.pending_len(), 0);
    assert!(client.conn.shared.emissions.lock().unwrap().is_empty());
}

fn request(bytes: &[u8]) -> RpcRequest {
    match Frame::decode(bytes).unwrap().body.unwrap() {
        Body::Request(request) => request,
        _ => panic!("expected request"),
    }
}

async fn complete(client: &Initiator, id: u64) {
    client
        .inject_frame(Frame {
            version: 1,
            request_id: id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(b"ok".to_vec())),
            })),
        })
        .await;
}

#[tokio::test(start_paused = true)]
async fn expired_queued_request_is_removed_before_caller_timer_is_polled() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, vec![], 10));
    assert!(futures_util::poll!(&mut call).is_pending());
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(client
        .prepare_outbound(writer.try_recv().unwrap())
        .is_none());
    assert_clean(&client);
    assert!(matches!(call.await, Err(SyntraError::DeadlineExceeded(_))));
}

#[tokio::test(start_paused = true)]
async fn handoff_reduces_and_floors_budget_without_extending_local_deadline() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, b"opaque".to_vec(), 100));
    assert!(futures_util::poll!(&mut call).is_pending());
    tokio::time::advance(Duration::from_micros(40_500)).await;
    let bytes = client.prepare_outbound(writer.try_recv().unwrap()).unwrap();
    let req = request(&bytes);
    assert_eq!(req.timeout_ms, 59);
    assert_eq!(req.payload, b"opaque");
    assert_eq!(req.method, METHOD);
    tokio::time::advance(Duration::from_micros(59_500)).await;
    assert!(matches!(call.await, Err(SyntraError::DeadlineExceeded(_))));
    assert_clean(&client);
    assert!(
        client.prepare_outbound(bytes).is_none(),
        "handoff is one-shot"
    );
}

#[tokio::test(start_paused = true)]
async fn zero_uses_positive_effective_default_and_cap_at_handoff() {
    for (default_ms, cap_ms, expected) in [(80, 100, 60), (200, 100, 80)] {
        let (client, mut writer) = active(ConnectionConfig {
            default_timeout: Duration::from_millis(default_ms),
            max_rpc_timeout: Duration::from_millis(cap_ms),
            ..ConnectionConfig::default()
        })
        .await;
        let mut call = Box::pin(client.call(METHOD, vec![], 0));
        assert!(futures_util::poll!(&mut call).is_pending());
        tokio::time::advance(Duration::from_millis(20)).await;
        let bytes = client.prepare_outbound(writer.try_recv().unwrap()).unwrap();
        assert_eq!(request(&bytes).timeout_ms, expected);
        drop(call);
        assert_clean(&client);
    }
}

#[tokio::test(start_paused = true)]
async fn sub_millisecond_remaining_expires_instead_of_encoding_zero() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, vec![], 10));
    assert!(futures_util::poll!(&mut call).is_pending());
    tokio::time::advance(Duration::from_micros(9_001)).await;
    assert!(client
        .prepare_outbound(writer.try_recv().unwrap())
        .is_none());
    assert!(matches!(call.await, Err(SyntraError::DeadlineExceeded(_))));
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn cancellation_without_repolling_caller_prevents_queued_emission() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let token = crate::CancelToken::new();
    let mut call = Box::pin(client.call_cancellable(METHOD, vec![], 100, &token));
    assert!(futures_util::poll!(&mut call).is_pending());
    token.cancel();
    assert!(client
        .prepare_outbound(writer.try_recv().unwrap())
        .is_none());
    assert_clean(&client);
    assert!(matches!(call.await, Err(SyntraError::Cancelled(_))));
}

#[tokio::test(start_paused = true)]
async fn dropped_future_and_explicit_cancel_prevent_queued_emission() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    for explicit in [false, true] {
        let mut call = Box::pin(client.call(METHOD, vec![], 100));
        assert!(futures_util::poll!(&mut call).is_pending());
        let bytes = writer.try_recv().unwrap();
        if explicit {
            let id = Frame::decode(bytes.as_slice()).unwrap().request_id;
            client.cancel(id).await.unwrap();
            assert!(matches!(call.await, Err(SyntraError::Cancelled(_))));
            let control = writer.try_recv().unwrap();
            assert_eq!(client.prepare_outbound(control.clone()), Some(control));
        } else {
            drop(call);
        }
        assert!(client.prepare_outbound(bytes).is_none());
        assert_clean(&client);
    }
}

#[tokio::test(start_paused = true)]
async fn selected_success_suppresses_queued_duplicates_and_survives_cancel_close() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let token = crate::CancelToken::new();
    let mut call = Box::pin(client.call_cancellable(METHOD, vec![], 100, &token));
    assert!(futures_util::poll!(&mut call).is_pending());
    let bytes = writer.try_recv().unwrap();
    let id = Frame::decode(bytes.as_slice()).unwrap().request_id;
    complete(&client, id).await;
    assert_clean(&client);
    token.cancel();
    client.close().await;
    assert!(client.prepare_outbound(bytes.clone()).is_none());
    assert!(client.prepare_outbound(bytes).is_none());
    assert_eq!(call.await.unwrap(), b"ok");
}

#[tokio::test(start_paused = true)]
async fn handoff_is_one_shot_and_emitted_cancel_remains_advisory() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut call).is_pending());
    let bytes = writer.try_recv().unwrap();
    assert!(
        client.prepare_outbound(bytes.clone()).is_none(),
        "must use original Vec"
    );
    let id = Frame::decode(bytes.as_slice()).unwrap().request_id;
    let prepared = client.prepare_outbound(bytes).unwrap();
    assert!(client.prepare_outbound(prepared.clone()).is_none());
    client.cancel(id).await.unwrap();
    complete(&client, id).await;
    assert_eq!(call.await.unwrap(), b"ok");
    assert_eq!(
        request(&prepared).timeout_ms,
        100,
        "selected bytes stay immutable"
    );
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn admission_and_all_exit_paths_release_emission_registration() {
    let (client, mut writer) = active(ConnectionConfig {
        max_outstanding: 1,
        writer_capacity: 1,
        ..ConnectionConfig::default()
    })
    .await;
    let mut first = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(matches!(
        client.call(METHOD, vec![], 100).await,
        Err(SyntraError::ResourceExhausted(_))
    ));
    assert_eq!(client.conn.shared.emissions.lock().unwrap().len(), 1);
    let stale = writer.try_recv().unwrap();
    drop(first);
    assert_clean(&client);
    // Validation fails after registration (oversized envelope).
    assert!(client
        .call(METHOD, vec![0; syntra_core::MAX_FRAME_BYTES], 100)
        .await
        .is_err());
    assert_clean(&client);
    let mut next = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut next).is_pending());
    assert!(client.prepare_outbound(stale).is_none());
    let bytes = writer.try_recv().unwrap();
    client.on_transport_lost().await;
    assert_clean(&client);
    assert!(client.prepare_outbound(bytes).is_none());
    assert!(matches!(next.await, Err(SyntraError::Unavailable(_))));
}

#[tokio::test(start_paused = true)]
async fn queue_admission_wait_consumes_the_same_budget() {
    let (client, mut writer) = active(ConnectionConfig {
        writer_capacity: 1,
        ..ConnectionConfig::default()
    })
    .await;
    let mut first = Box::pin(client.call(METHOD, vec![], 100));
    let mut next = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(futures_util::poll!(&mut next).is_pending());
    tokio::time::advance(Duration::from_millis(30)).await;
    let first_bytes = writer.try_recv().unwrap();
    assert!(futures_util::poll!(&mut next).is_pending());
    tokio::time::advance(Duration::from_millis(20)).await;
    let next_bytes = client.prepare_outbound(writer.try_recv().unwrap()).unwrap();
    assert_eq!(request(&next_bytes).timeout_ms, 50);
    drop(first);
    drop(next);
    assert!(client.prepare_outbound(first_bytes).is_none());
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn explicit_cancel_interrupts_a_pending_writer_reservation() {
    let (client, mut writer) = active(ConnectionConfig {
        writer_capacity: 1,
        ..ConnectionConfig::default()
    })
    .await;
    let mut first = Box::pin(client.call(METHOD, vec![], 100));
    let mut next = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(futures_util::poll!(&mut next).is_pending());
    client.cancel(2).await.unwrap();
    assert!(matches!(next.await, Err(SyntraError::Cancelled(_))));
    assert_eq!(client.pending_len(), 1);
    assert_eq!(client.conn.shared.emissions.lock().unwrap().len(), 1);
    let bytes = writer.try_recv().unwrap();
    drop(first);
    assert!(client.prepare_outbound(bytes).is_none());
    assert!(writer.try_recv().is_err());
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn caller_timeout_and_send_failure_clean_registration_without_pump_poll() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, vec![], 10));
    assert!(futures_util::poll!(&mut call).is_pending());
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(matches!(call.await, Err(SyntraError::DeadlineExceeded(_))));
    assert_clean(&client);
    assert!(client
        .prepare_outbound(writer.try_recv().unwrap())
        .is_none());
    drop(writer);
    assert!(client.call(METHOD, vec![], 100).await.is_err());
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn default_budget_reserialization_cannot_exceed_envelope_bound() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let oversized = Frame {
        version: 1,
        request_id: 1,
        body: Some(Body::Request(RpcRequest {
            method: METHOD.into(),
            payload: vec![0; syntra_core::MAX_FRAME_BYTES],
            timeout_ms: 0,
        })),
    };
    let overhead = oversized.encoded_len() - syntra_core::MAX_FRAME_BYTES;
    let mut call =
        Box::pin(client.call(METHOD, vec![0; syntra_core::MAX_FRAME_BYTES - overhead], 0));
    assert!(futures_util::poll!(&mut call).is_pending());
    let bytes = writer.try_recv().unwrap();
    assert_eq!(bytes.len(), syntra_core::MAX_FRAME_BYTES);
    assert!(client.prepare_outbound(bytes).is_none());
    assert!(matches!(call.await, Err(SyntraError::ResourceExhausted(_))));
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn handshake_and_control_outputs_pass_through_without_rpc_registration() {
    let (client, mut writer) = Initiator::new(ConnectionConfig::default());
    let mut handshake = Box::pin(client.handshake(vec![]));
    assert!(futures_util::poll!(&mut handshake).is_pending());
    let hello = writer.try_recv().unwrap();
    assert_eq!(client.prepare_outbound(hello.clone()), Some(hello));
    drop(handshake);
    assert_clean(&client);
}
