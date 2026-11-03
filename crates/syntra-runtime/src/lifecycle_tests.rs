//! Supplemental RFC0008 D2/D3 regressions, not physical suspend evidence.
use crate::{
    elapsed::{ElapsedClock, ElapsedSource},
    *,
};
use prost::Message;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_core::{
    proto::{frame::Body, rpc_result::Outcome},
    ErrorCode, Frame, RpcResult,
};

struct Source(AtomicU64);
impl ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}

async fn pair() -> (
    Initiator,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
    Arc<Source>,
    ElapsedClock,
) {
    let source = Arc::new(Source(AtomicU64::new(10_000)));
    let clock = ElapsedClock::with_source(source.clone());
    let (client, mut writer) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let hello = client.handshake(vec![]);
    tokio::pin!(hello);
    assert!(futures_util::poll!(&mut hello).is_pending());
    writer.recv().await.unwrap();
    client
        .ingest(
            &Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Ready(syntra_core::ServerReady {
                    connection_id: "clock-test".into(),
                })),
            }
            .encode_to_vec(),
        )
        .await;
    hello.await.unwrap();
    (client.clone(), writer, source, clock)
}

fn result(id: u64) -> Vec<u8> {
    Frame {
        version: 1,
        request_id: id,
        body: Some(Body::Result(RpcResult {
            outcome: Some(Outcome::Payload(vec![7])),
        })),
    }
    .encode_to_vec()
}

#[tokio::test(start_paused = true)]
async fn suspend_elapsed_expires_queued_emission_without_scheduler_time() {
    let (client, mut writer, source, clock) = pair().await;
    let call = client.call("/test.Echo/Call", vec![], 1000);
    tokio::pin!(call);
    assert!(futures_util::poll!(&mut call).is_pending());
    let bytes = writer.recv().await.unwrap();
    source.0.fetch_add(1001, Ordering::SeqCst);
    clock.wake();
    assert!(client.prepare_outbound(bytes).is_none());
    assert_eq!(call.await.unwrap_err().code(), ErrorCode::DeadlineExceeded);
}

#[tokio::test(start_paused = true)]
async fn buffered_result_loses_to_elapsed_deadline_but_selected_terminal_survives_wake() {
    for selected in [false, true] {
        let (client, mut writer, source, _) = pair().await;
        let call = client.call("/test.Echo/Call", vec![], 1000);
        tokio::pin!(call);
        assert!(futures_util::poll!(&mut call).is_pending());
        let frame = Frame::decode(
            client
                .prepare_outbound(writer.recv().await.unwrap())
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        if selected {
            client.ingest(&result(frame.request_id)).await;
        }
        source.0.fetch_add(1001, Ordering::SeqCst);
        if !selected {
            client.ingest(&result(frame.request_id)).await;
        }
        client.platform_wake().await;
        if selected {
            assert_eq!(call.await.unwrap(), vec![7]);
        } else {
            assert_eq!(call.await.unwrap_err().code(), ErrorCode::DeadlineExceeded);
        }
        assert!(client.is_closed());
    }
}

#[tokio::test(start_paused = true)]
async fn continuity_regression_retires_connection_before_result_or_queued_send() {
    let (client, mut writer, source, clock) = pair().await;
    let call = client.call("/test.Echo/Call", vec![], 1000);
    tokio::pin!(call);
    assert!(futures_util::poll!(&mut call).is_pending());
    let bytes = writer.recv().await.unwrap();
    source.0.store(1, Ordering::SeqCst);
    assert!(!clock.is_continuous());
    client.ingest(&result(1)).await;
    assert!(client.is_closed());
    assert!(client.prepare_outbound(bytes).is_none());
    assert_eq!(call.await.unwrap_err().code(), ErrorCode::Unavailable);
}

#[tokio::test(start_paused = true)]
async fn unknown_continuity_denies_new_rpc_and_retires_host_worker_without_new_input() {
    let (client, mut writer, _, clock) = pair().await;
    clock.invalidate();
    assert_eq!(
        client
            .call("/test.Echo/Call", vec![], 1000)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::Unavailable
    );
    assert!(client.is_closed());
    assert!(writer.try_recv().is_err());

    let source = Arc::new(Source(AtomicU64::new(10_000)));
    let clock = ElapsedClock::with_source(source);
    let (host, mut writer) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, _, _| {
            std::future::pending::<HandlerOutcome>()
        })),
        clock.clone(),
    )
    .unwrap();
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        }
        .encode_to_vec(),
    )
    .await;
    writer.recv().await.unwrap();
    host.ingest(
        &Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Request(syntra_core::RpcRequest {
                method: "/test.Echo/Call".into(),
                payload: vec![],
                timeout_ms: 1000,
            })),
        }
        .encode_to_vec(),
    )
    .await;
    let mut closed = host.subscribe_close();
    clock.invalidate();
    closed.wait_for(|closed| *closed).await.unwrap();
    assert_eq!(host.inflight_len(), 0);
    assert!(host.is_closed());
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn synchronous_suspend_fences_results_and_original_handoff_before_async_wake() {
    let (client, mut writer, _, _) = pair().await;
    let call = client.call("/test.Echo/Call", vec![], 1000);
    tokio::pin!(call);
    assert!(futures_util::poll!(&mut call).is_pending());
    let bytes = writer.recv().await.unwrap();
    client.suspend();
    client.ingest(&result(1)).await;
    assert!(client.prepare_outbound(bytes).is_none());
    assert!(futures_util::poll!(&mut call).is_pending());
    client.platform_wake().await;
    assert_eq!(call.await.unwrap_err().code(), ErrorCode::Unavailable);
}

#[tokio::test(start_paused = true)]
async fn elapsed_handshake_expiry_precedes_buffered_ready_and_host_authentication() {
    let source = Arc::new(Source(AtomicU64::new(10_000)));
    let clock = ElapsedClock::with_source(source.clone());
    let (client, mut writer) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let hello = client.handshake(vec![]);
    tokio::pin!(hello);
    assert!(futures_util::poll!(&mut hello).is_pending());
    let bytes = writer.recv().await.unwrap();
    source.0.fetch_add(20_000, Ordering::SeqCst);
    assert!(client.prepare_outbound(bytes).is_none());
    client
        .ingest(
            &Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Ready(syntra_core::ServerReady {
                    connection_id: "late".into(),
                })),
            }
            .encode_to_vec(),
        )
        .await;
    assert!(client.is_closed());
    assert_eq!(hello.await.unwrap_err().code(), ErrorCode::DeadlineExceeded);

    struct Auth(Arc<AtomicU64>);
    impl Authenticator for Auth {
        fn authenticate(&self, _: &[u8]) -> Result<Principal, AuthError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Principal::anonymous())
        }
    }
    let authenticated = Arc::new(AtomicU64::new(0));
    let (host, _) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(Auth(authenticated.clone())),
        Arc::new(FnHandler(|_, _, _| async {
            HandlerOutcome::Payload(vec![])
        })),
        clock,
    )
    .unwrap();
    source.0.fetch_add(20_000, Ordering::SeqCst);
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        }
        .encode_to_vec(),
    )
    .await;
    assert!(host.is_closed());
    assert_eq!(authenticated.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn host_elapsed_authorization_delay_never_dispatches_expired_effects() {
    struct HandlerClock(Arc<Source>, Arc<AtomicU64>);
    impl Handler for HandlerClock {
        fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
            self.0 .0.fetch_add(1001, Ordering::SeqCst);
            Ok(())
        }
        fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
            self.1.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { HandlerOutcome::Payload(vec![]) })
        }
    }
    let source = Arc::new(Source(AtomicU64::new(10_000)));
    let effects = Arc::new(AtomicU64::new(0));
    let (host, mut writer) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(HandlerClock(source.clone(), effects.clone())),
        ElapsedClock::with_source(source),
    )
    .unwrap();
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        }
        .encode_to_vec(),
    )
    .await;
    writer.recv().await.unwrap();
    host.ingest(
        &Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Request(syntra_core::RpcRequest {
                method: "/test.Echo/Call".into(),
                payload: vec![],
                timeout_ms: 1000,
            })),
        }
        .encode_to_vec(),
    )
    .await;
    let frame = Frame::decode(writer.recv().await.unwrap().as_slice()).unwrap();
    let Some(Body::Result(RpcResult {
        outcome: Some(Outcome::Error(error)),
    })) = frame.body
    else {
        panic!("terminal error required");
    };
    assert_eq!(error.code, ErrorCode::DeadlineExceeded as i32);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    host.close().await;
}
