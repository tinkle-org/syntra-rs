use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use syntra_core::proto::{
    frame::Body, rpc_result::Outcome, Cancel, ClientHello, Notification, RpcError, ServerReady,
};
use syntra_core::{ConnectionState, ErrorCode, Frame, RpcRequest, RpcResult, SyntraError};
use syntra_runtime::{
    AllowAnonymous, AuthError, ConnectionConfig, FnHandler, Handler, HandlerFut, HandlerOutcome,
    Host, Initiator, Principal,
};
use tokio::sync::{mpsc, Notify};

const METHOD: &str = "/example.Echo/Echo";

fn frame(id: u64, body: Body) -> Frame {
    Frame {
        version: 1,
        request_id: id,
        body: Some(body),
    }
}

fn request(id: u64) -> Vec<u8> {
    frame(
        id,
        Body::Request(RpcRequest {
            method: METHOD.into(),
            payload: vec![],
            timeout_ms: 5000,
        }),
    )
    .encode_to_vec()
}

async fn client() -> (Initiator, mpsc::Receiver<Vec<u8>>) {
    let (client, mut writer) = Initiator::new(ConnectionConfig::default());
    let mut handshake = Box::pin(client.handshake(vec![]));
    assert!(futures_util::poll!(&mut handshake).is_pending());
    writer.recv().await.unwrap();
    client
        .ingest(
            &frame(
                0,
                Body::Ready(ServerReady {
                    connection_id: "test-connection".into(),
                }),
            )
            .encode_to_vec(),
        )
        .await;
    handshake.await.unwrap();
    (client, writer)
}

async fn host(
    config: ConnectionConfig,
    handler: Arc<dyn Handler>,
) -> (Arc<Host>, mpsc::Receiver<Vec<u8>>) {
    let (host, mut writer) = Host::new(config, Arc::new(AllowAnonymous), handler);
    host.ingest(
        &frame(
            0,
            Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            }),
        )
        .encode_to_vec(),
    )
    .await;
    writer.recv().await.unwrap();
    (host, writer)
}

fn blocked() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|_, _, _| {
        std::future::pending::<HandlerOutcome>()
    }))
}

fn error_code(bytes: &[u8]) -> (u64, ErrorCode) {
    let frame = Frame::decode(bytes).unwrap();
    let Some(Body::Result(RpcResult {
        outcome: Some(Outcome::Error(error)),
    })) = frame.body
    else {
        panic!("expected terminal error");
    };
    (frame.request_id, ErrorCode::from_i32_lossy(error.code).0)
}

#[tokio::test]
async fn malformed_correlated_outcomes_settle_only_their_rpc_once() {
    for outcome in [
        None,
        Some(Outcome::Error(RpcError {
            code: 0,
            message: "invalid".into(),
        })),
    ] {
        let (client, mut writer) = client().await;
        let mut first = Box::pin(client.call(METHOD, vec![], 5000));
        let mut other = Box::pin(client.call(METHOD, vec![], 5000));
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut other).is_pending());
        let id = Frame::decode(writer.recv().await.unwrap().as_slice())
            .unwrap()
            .request_id;
        let other_id = Frame::decode(writer.recv().await.unwrap().as_slice())
            .unwrap()
            .request_id;
        let bad = frame(id, Body::Result(RpcResult { outcome })).encode_to_vec();
        client.ingest(&bad).await;
        client.ingest(&bad).await;
        assert_eq!(first.await.unwrap_err().code(), ErrorCode::InvalidArgument);
        assert_eq!(client.pending_len(), 1);
        assert!(futures_util::poll!(&mut other).is_pending());
        client
            .ingest(
                &frame(
                    id,
                    Body::Result(RpcResult {
                        outcome: Some(Outcome::Payload(b"late".to_vec())),
                    }),
                )
                .encode_to_vec(),
            )
            .await;
        assert_eq!(client.pending_len(), 1);
        client
            .ingest(
                &frame(
                    other_id,
                    Body::Result(RpcResult {
                        outcome: Some(Outcome::Payload(b"ok".to_vec())),
                    }),
                )
                .encode_to_vec(),
            )
            .await;
        assert_eq!(other.await.unwrap(), b"ok");
        assert_eq!(client.state().await, ConnectionState::Active);
        assert!(writer.try_recv().is_err());
        client.close().await;
    }
}

#[tokio::test]
async fn structurally_invalid_results_never_supply_correlation() {
    for reserved in [false, true] {
        let (client, mut writer) = client().await;
        let mut call = Box::pin(client.call(METHOD, vec![], 5000));
        assert!(futures_util::poll!(&mut call).is_pending());
        let id = Frame::decode(writer.recv().await.unwrap().as_slice())
            .unwrap()
            .request_id;
        let mut bytes = frame(id, Body::Result(RpcResult { outcome: None })).encode_to_vec();
        if reserved {
            bytes.extend_from_slice(&[0x80, 0x01, 0]);
        } else {
            bytes.extend_from_slice(&[0x6a, 0]);
        }
        assert!(syntra_core::validate_wire_structure(&bytes).is_err());
        assert!(Frame::decode(bytes.as_slice()).is_ok());
        client.ingest(&bytes).await;
        assert_eq!(client.pending_len(), 1);
        assert!(futures_util::poll!(&mut call).is_pending());
        client
            .ingest(
                &frame(
                    id,
                    Body::Result(RpcResult {
                        outcome: Some(Outcome::Payload(vec![])),
                    }),
                )
                .encode_to_vec(),
            )
            .await;
        assert_eq!(call.await.unwrap(), Vec::<u8>::new());
        client.close().await;
    }
}

#[tokio::test]
async fn active_handshake_frames_and_version_mismatch_are_immediately_fatal() {
    let mut wrong_version = frame(
        42,
        Body::Result(RpcResult {
            outcome: Some(Outcome::Payload(vec![])),
        }),
    );
    wrong_version.version = 2;
    for invalid in [
        frame(
            0,
            Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            }),
        ),
        frame(
            0,
            Body::Ready(ServerReady {
                connection_id: "unexpected".into(),
            }),
        ),
        wrong_version,
    ] {
        let expected = if invalid.version == 2 {
            ErrorCode::InvalidArgument
        } else {
            ErrorCode::FailedPrecondition
        };
        let bytes = invalid.encode_to_vec();
        let (client, _writer) = client().await;
        client.ingest(&bytes).await;
        assert!(client.is_closed());
        assert_eq!(client.terminal_reason().unwrap().code(), expected);
        client.on_transport_lost().await;
        assert_eq!(client.terminal_reason().unwrap().code(), expected);
        let (host, _writer) = host(ConnectionConfig::default(), blocked()).await;
        host.ingest(&bytes).await;
        assert!(host.is_closed());
        assert_eq!(host.terminal_reason().unwrap().code(), expected);
        assert_eq!(host.sessions().count(), 0);
        host.on_transport_lost().await;
        assert_eq!(host.terminal_reason().unwrap().code(), expected);
    }
}

#[tokio::test]
async fn structural_request_faults_are_not_semantic_rpc_errors() {
    for reserved in [false, true] {
        let (host, mut writer) = host(ConnectionConfig::default(), blocked()).await;
        let mut bad = frame(
            77,
            Body::Request(RpcRequest {
                method: "malformed".into(),
                payload: vec![],
                timeout_ms: 0,
            }),
        )
        .encode_to_vec();
        if reserved {
            bad.extend_from_slice(&[0x88, 0x01, 0]);
        } else {
            bad.extend_from_slice(&[0x62, 0]);
        }
        assert!(Frame::decode(bad.as_slice()).is_ok());
        host.ingest(&bad).await;
        assert!(
            writer.try_recv().is_err(),
            "untrusted id must not receive a result"
        );
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.state().await, ConnectionState::Active);
        host.close().await;
    }
}

#[tokio::test]
async fn initiator_graceful_close_drains_results_and_rejects_new_calls() {
    let (client, mut writer) = client().await;
    let mut call = Box::pin(client.call(METHOD, vec![], 5000));
    assert!(futures_util::poll!(&mut call).is_pending());
    let id = Frame::decode(writer.recv().await.unwrap().as_slice())
        .unwrap()
        .request_id;
    let mut closing = Box::pin(client.close_gracefully(Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut closing).is_pending());
    assert_eq!(client.state().await, ConnectionState::Closing);
    assert!(!client.is_closed());
    assert!(client.call(METHOD, vec![], 100).await.is_err());
    client.cancel(id).await.unwrap();
    assert!(matches!(
        Frame::decode(writer.recv().await.unwrap().as_slice())
            .unwrap()
            .body,
        Some(Body::Cancel(_))
    ));
    client
        .ingest(&frame(id, Body::Cancel(Cancel {})).encode_to_vec())
        .await;
    assert_eq!(client.state().await, ConnectionState::Closing);
    client
        .ingest(
            &frame(
                id,
                Body::Result(RpcResult {
                    outcome: Some(Outcome::Payload(b"drained".to_vec())),
                }),
            )
            .encode_to_vec(),
        )
        .await;
    assert_eq!(call.await.unwrap(), b"drained");
    closing.await;
    assert_eq!(client.state().await, ConnectionState::Closed);
}

#[tokio::test]
async fn host_graceful_close_accepts_cancel_and_drains_one_terminal_result() {
    let (host, mut writer) = host(ConnectionConfig::default(), blocked()).await;
    host.ingest(&request(1)).await;
    let mut closing = Box::pin(host.close_gracefully(Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut closing).is_pending());
    assert_eq!(host.state().await, ConnectionState::Closing);
    host.ingest(&request(2)).await;
    assert_eq!(host.inflight_len(), 1);
    host.ingest(
        &frame(
            99,
            Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(vec![])),
            }),
        )
        .encode_to_vec(),
    )
    .await;
    assert_eq!(host.state().await, ConnectionState::Closing);
    host.ingest(&frame(1, Body::Cancel(Cancel {})).encode_to_vec())
        .await;
    let result = writer.recv().await.unwrap();
    assert_eq!(error_code(&result), (1, ErrorCode::Cancelled));
    closing.await;
    assert!(host.is_closed());
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.sessions().count(), 0);
    assert!(writer.try_recv().is_err());
}

#[tokio::test]
async fn host_graceful_close_waits_for_handler_success_and_writer_drain() {
    let release = Arc::new(Notify::new());
    let handler = Arc::new(FnHandler({
        let release = release.clone();
        move |_, _, _| {
            let release = release.clone();
            async move {
                release.notified().await;
                HandlerOutcome::Payload(b"finished".to_vec())
            }
        }
    }));
    let (host, mut writer) = host(ConnectionConfig::default(), handler).await;
    host.ingest(&request(1)).await;
    let mut closing = Box::pin(host.close_gracefully(Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut closing).is_pending());
    release.notify_one();
    tokio::task::yield_now().await;
    assert!(
        futures_util::poll!(&mut closing).is_pending(),
        "queued results must drain"
    );
    let result = Frame::decode(writer.recv().await.unwrap().as_slice()).unwrap();
    assert!(
        matches!(result.body, Some(Body::Result(RpcResult { outcome: Some(Outcome::Payload(payload)) })) if payload == b"finished")
    );
    closing.await;
    assert!(host.is_closed());
}

#[tokio::test]
async fn graceful_close_is_bounded_with_outstanding_work_and_backpressure() {
    let (client, mut writer) = client().await;
    let mut call = Box::pin(client.call(METHOD, vec![], 5000));
    assert!(futures_util::poll!(&mut call).is_pending());
    writer.recv().await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(200),
        client.close_gracefully(Duration::from_millis(10)),
    )
    .await
    .unwrap();
    assert!(matches!(call.await, Err(SyntraError::Unavailable(_))));
    assert_eq!(client.pending_len(), 0);

    let (host, _writer) = host(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        blocked(),
    )
    .await;
    host.ingest(&request(1)).await;
    tokio::time::timeout(
        Duration::from_millis(200),
        host.close_gracefully(Duration::from_millis(10)),
    )
    .await
    .unwrap();
    assert!(host.is_closed());
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.sessions().count(), 0);
}

#[tokio::test]
async fn transport_loss_interrupts_a_graceful_drain_immediately() {
    let (client, mut writer) = client().await;
    let mut call = Box::pin(client.call(METHOD, vec![], 5000));
    assert!(futures_util::poll!(&mut call).is_pending());
    writer.recv().await.unwrap();
    let mut closing = Box::pin(client.close_gracefully(Duration::from_secs(5)));
    assert!(futures_util::poll!(&mut closing).is_pending());
    client.on_transport_lost().await;
    tokio::time::timeout(Duration::from_millis(100), closing)
        .await
        .unwrap();
    assert_eq!(call.await.unwrap_err().code(), ErrorCode::Unavailable);
}

#[tokio::test]
async fn explicit_withdrawal_settles_all_inflight_and_closes_without_duplicates() {
    let (host, mut writer) = host(ConnectionConfig::default(), blocked()).await;
    host.ingest(&request(1)).await;
    host.ingest(&request(2)).await;
    host.withdraw_principal().await;
    let mut ids = vec![];
    while let Ok(bytes) = writer.try_recv() {
        let (id, code) = error_code(&bytes);
        assert_eq!(code, ErrorCode::Unauthenticated);
        ids.push(id);
    }
    ids.sort();
    assert_eq!(ids, [1, 2]);
    assert!(host.is_closed());
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.sessions().count(), 0);
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
    host.withdraw_principal().await;
    host.ingest(&request(3)).await;
    assert!(writer.try_recv().is_err());
}

#[tokio::test]
async fn authorization_unauthenticated_withdraws_other_calls_and_binding() {
    struct Revoked;
    impl Handler for Revoked {
        fn authorize(&self, _: &Principal, method: &str) -> Result<(), AuthError> {
            if method == METHOD {
                Ok(())
            } else {
                Err(AuthError {
                    code: ErrorCode::Unauthenticated,
                    message: "private revocation details".into(),
                })
            }
        }
        fn handle(&self, _: String, _: Vec<u8>, _: syntra_runtime::CancelToken) -> HandlerFut {
            Box::pin(std::future::pending())
        }
    }
    let (host, mut writer) = host(ConnectionConfig::default(), Arc::new(Revoked)).await;
    host.ingest(&request(1)).await;
    host.ingest(
        &frame(
            2,
            Body::Request(RpcRequest {
                method: "/example.Echo/Revoked".into(),
                payload: vec![],
                timeout_ms: 5000,
            }),
        )
        .encode_to_vec(),
    )
    .await;
    let mut ids = vec![];
    while let Ok(bytes) = writer.try_recv() {
        let (id, code) = error_code(&bytes);
        assert_eq!(code, ErrorCode::Unauthenticated);
        assert!(!String::from_utf8_lossy(&bytes).contains("private revocation"));
        ids.push(id);
    }
    ids.sort();
    assert_eq!(ids, [1, 2]);
    assert_eq!(host.sessions().count(), 0);
    assert!(host.is_closed());
}

#[tokio::test]
async fn withdrawal_preserves_completed_results_and_prevents_late_handler_effects() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let effects = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(FnHandler({
        let effects = effects.clone();
        move |_, _, _| {
            effects.fetch_add(1, Ordering::SeqCst);
            async { HandlerOutcome::Payload(b"done".to_vec()) }
        }
    }));
    let (host, mut writer) = host(ConnectionConfig::default(), handler).await;
    host.ingest(&request(1)).await;
    // Let the first worker queue its terminal result, but leave it in the writer.
    tokio::task::yield_now().await;
    assert_eq!(host.inflight_len(), 0);
    host.ingest(&request(2)).await;
    // Withdrawal fences the admitted second worker before its first poll.
    host.withdraw_principal().await;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let first = Frame::decode(writer.try_recv().unwrap().as_slice()).unwrap();
    assert_eq!(first.request_id, 1);
    assert!(matches!(
        first.body,
        Some(Body::Result(RpcResult {
            outcome: Some(Outcome::Payload(_))
        }))
    ));
    assert_eq!(
        error_code(&writer.try_recv().unwrap()),
        (2, ErrorCode::Unauthenticated)
    );
    assert!(writer.try_recv().is_err());
}

#[tokio::test]
async fn graceful_deadline_bounds_a_full_writer_and_blocked_result_sender() {
    let handler = Arc::new(FnHandler(|_, _, _| async {
        HandlerOutcome::Payload(vec![])
    }));
    let (host, mut writer) = host(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        handler,
    )
    .await;
    host.ingest(&request(1)).await;
    tokio::task::yield_now().await;
    host.ingest(&request(2)).await;
    tokio::task::yield_now().await;
    assert_eq!(host.inflight_len(), 1);
    tokio::time::timeout(
        Duration::from_millis(200),
        host.close_gracefully(Duration::from_millis(10)),
    )
    .await
    .unwrap();
    assert_eq!(host.inflight_len(), 0);
    assert!(writer.try_recv().is_ok());
    assert!(writer.try_recv().is_err());
}

#[tokio::test]
async fn withdrawal_is_bounded_when_terminal_results_cannot_be_queued() {
    let (host, mut writer) = host(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        blocked(),
    )
    .await;
    host.notify(b"queued".to_vec()).await.unwrap();
    host.ingest(&request(1)).await;
    tokio::time::timeout(Duration::from_millis(1500), host.withdraw_principal())
        .await
        .unwrap();
    assert!(host.is_closed());
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.sessions().count(), 0);
    assert!(writer.try_recv().is_ok());
    assert!(writer.try_recv().is_err());
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
}

#[tokio::test]
async fn withdrawal_delivers_unauthenticated_to_live_loopback_waiters() {
    let started = Arc::new(Notify::new());
    let handler = Arc::new(FnHandler({
        let started = started.clone();
        move |_, _, _| {
            let started = started.clone();
            async move {
                started.notify_one();
                std::future::pending::<HandlerOutcome>().await
            }
        }
    }));
    let (client, host) = syntra_runtime::loopback_pair(
        Arc::new(AllowAnonymous),
        handler,
        ConnectionConfig::default(),
    );
    client.handshake(vec![]).await.unwrap();
    let call = tokio::spawn({
        let client = client.clone();
        async move { client.call(METHOD, vec![], 5000).await }
    });
    started.notified().await;
    host.withdraw_principal().await;
    let error = tokio::time::timeout(Duration::from_secs(1), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::Unauthenticated);
    assert_eq!(client.pending_len(), 0);
}

#[tokio::test]
async fn graceful_drain_tolerates_queued_notifications() {
    let (client, mut writer) = client().await;
    let mut call = Box::pin(client.call(METHOD, vec![], 5000));
    assert!(futures_util::poll!(&mut call).is_pending());
    let id = Frame::decode(writer.recv().await.unwrap().as_slice())
        .unwrap()
        .request_id;
    let mut closing = Box::pin(client.close_gracefully(Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut closing).is_pending());
    assert_eq!(client.state().await, ConnectionState::Closing);
    for _ in 0..9 {
        client
            .ingest(
                &frame(
                    0,
                    Body::Notification(Notification {
                        payload: b"queued".to_vec(),
                    }),
                )
                .encode_to_vec(),
            )
            .await;
    }
    assert!(!client.is_closed());
    assert!(futures_util::poll!(&mut call).is_pending());
    client
        .ingest(
            &frame(
                id,
                Body::Result(RpcResult {
                    outcome: Some(Outcome::Payload(b"drained".to_vec())),
                }),
            )
            .encode_to_vec(),
        )
        .await;
    assert_eq!(call.await.unwrap(), b"drained");
    closing.await;
    assert_eq!(client.state().await, ConnectionState::Closed);
}

#[tokio::test]
async fn cancelled_withdrawal_can_be_retried_to_close() {
    let (host, mut writer) = host(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        blocked(),
    )
    .await;
    host.notify(b"queued".to_vec()).await.unwrap();
    host.ingest(&request(1)).await;
    assert_eq!(host.inflight_len(), 1);
    let mut first = Box::pin(host.withdraw_principal());
    assert!(futures_util::poll!(&mut first).is_pending());
    drop(first);
    assert!(!host.is_closed());
    tokio::time::timeout(Duration::from_millis(1500), host.withdraw_principal())
        .await
        .unwrap();
    assert!(host.is_closed());
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.sessions().count(), 0);
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
    assert!(writer.try_recv().is_ok());
}

#[tokio::test]
async fn graceful_close_waits_for_withdrawal_terminal_sends() {
    let (host, mut writer) = host(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        blocked(),
    )
    .await;
    host.notify(b"queued".to_vec()).await.unwrap();
    host.ingest(&request(1)).await;
    let mut withdraw = Box::pin(host.withdraw_principal());
    assert!(futures_util::poll!(&mut withdraw).is_pending());
    let mut closing = Box::pin(host.close_gracefully(Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut closing).is_pending());
    // Free the full writer so the blocked withdrawal terminal can queue.
    let first = writer.try_recv().unwrap();
    assert!(!first.is_empty());
    tokio::time::timeout(Duration::from_millis(500), &mut withdraw)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(500), &mut closing)
        .await
        .unwrap();
    assert!(host.is_closed());
    // The queued notification plus the withdrawal terminal result observe
    // bounded cleanup; the second slot may still hold the terminal.
    let mut saw_unauthenticated = false;
    while let Ok(bytes) = writer.try_recv() {
        if error_code(&bytes).1 == ErrorCode::Unauthenticated {
            saw_unauthenticated = true;
        }
    }
    assert!(saw_unauthenticated);
}
