//! Supplemental local regressions for accepted RFC 0004 D1/D4 and RFC 0008.
//! These are not formal conformance-suite verdicts or real suspend evidence.

use super::*;
use std::sync::Arc;
use syntra_core::{proto::rpc_result::Outcome, RpcResult};
use tokio::sync::Barrier;

const METHOD: &str = "/example.Echo/Echo";

async fn active(config: ConnectionConfig) -> (Initiator, mpsc::Receiver<Vec<u8>>) {
    let (client, writer) = Initiator::try_new(config).expect("valid configuration");
    *client.conn.shared.state.write().await = ConnectionState::Active;
    *client.conn.shared.version.write().await = Some(1);
    (client, writer)
}

fn result_bytes(id: u64, outcome: Outcome) -> Vec<u8> {
    Frame {
        version: 1,
        request_id: id,
        body: Some(Body::Result(RpcResult {
            outcome: Some(outcome),
        })),
    }
    .encode_to_vec()
}

fn payload_result(id: u64, payload: &[u8]) -> Vec<u8> {
    result_bytes(id, Outcome::Payload(payload.to_vec()))
}

fn emitted(client: &Initiator, original: Vec<u8>) -> Frame {
    let bytes = client
        .prepare_outbound(original)
        .expect("live original queue item must reach carrier handoff");
    let frame = Frame::decode(bytes.as_slice()).unwrap();
    assert!(matches!(frame.body, Some(Body::Request(_))));
    frame
}

fn assert_clean(client: &Initiator) {
    assert_eq!(client.pending_len(), 0);
    assert!(client.conn.shared.emissions.lock().unwrap().is_empty());
}

#[test]
fn try_new_rejects_below_floor_empty_queues_and_zero_timers_without_panicking() {
    let invalid = [
        ConnectionConfig {
            max_outstanding: 0,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            max_outstanding: 15,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            writer_capacity: 0,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            notification_capacity: 0,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            default_timeout: Duration::ZERO,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            max_rpc_timeout: Duration::ZERO,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            handshake_timeout: Duration::ZERO,
            ..ConnectionConfig::default()
        },
    ];
    for config in invalid {
        let error = match Initiator::try_new(config.clone()) {
            Err(error) => error,
            Ok(_) => panic!("invalid configuration accepted: {config:?}"),
        };
        assert_eq!(error.code(), ErrorCode::InvalidArgument, "{config:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn sixteen_concurrent_admissions_emit_increasing_ids_and_reverse_complete() {
    let (client, mut writer) = active(ConnectionConfig {
        max_outstanding: 16,
        writer_capacity: 16,
        ..ConnectionConfig::default()
    })
    .await;
    let start = Arc::new(Barrier::new(17));
    let mut callers = Vec::new();
    for label in 0..16u8 {
        let client = client.clone();
        let start = start.clone();
        callers.push(tokio::spawn(async move {
            start.wait().await;
            let payload = vec![label, 0, 0xff];
            let result = client.call(METHOD, payload.clone(), 1000).await;
            (payload, result)
        }));
    }
    start.wait().await;
    let mut requests = Vec::new();
    for _ in 0..16 {
        requests.push(emitted(&client, writer.recv().await.unwrap()));
    }
    assert_eq!(
        client.pending_len(),
        16,
        "all 16 really admitted, none completed"
    );
    let ids: Vec<_> = requests.iter().map(|frame| frame.request_id).collect();
    assert_eq!(ids, (1..=16).collect::<Vec<_>>());
    assert_eq!(
        client.call(METHOD, vec![], 1000).await.unwrap_err().code(),
        ErrorCode::ResourceExhausted
    );
    assert_eq!(
        client.pending_len(),
        16,
        "excess admission leaves originals live"
    );
    assert!(writer.try_recv().is_err(), "overload emits no request");
    for frame in requests.into_iter().rev() {
        let Some(Body::Request(request)) = frame.body else {
            unreachable!();
        };
        client
            .ingest(&payload_result(frame.request_id, &request.payload))
            .await;
    }
    for caller in callers {
        let (expected, result) = caller.await.unwrap();
        assert_eq!(
            result.unwrap(),
            expected,
            "correlation must not assume FIFO"
        );
    }
    assert_clean(&client);

    // The rejected 17th allocation is retired, even after all results arrive.
    let mut follow = Box::pin(client.call(METHOD, vec![], 1000));
    assert!(futures_util::poll!(&mut follow).is_pending());
    let frame = emitted(&client, writer.try_recv().unwrap());
    assert_eq!(frame.request_id, 18);
    client.ingest(&payload_result(18, b"follow")).await;
    assert_eq!(follow.await.unwrap(), b"follow");
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn admission_mutex_orders_allocation_and_fifo_enqueue_despite_reversed_polls() {
    let (client, mut writer) = active(ConnectionConfig {
        max_outstanding: 16,
        writer_capacity: 1,
        ..ConnectionConfig::default()
    })
    .await;
    let admission = client.conn.shared.rpc_admission.lock().await;
    let mut calls: Vec<_> = (0..16u8)
        .map(|label| Box::pin(client.call(METHOD, vec![label], 1000)))
        .collect();
    // Register lock waiters opposite to creation order. No allocation can
    // escape the admission gate; Tokio's mutex retains this waiter order.
    for call in calls.iter_mut().rev() {
        assert!(futures_util::poll!(call.as_mut()).is_pending());
    }
    assert_eq!(client.pending_len(), 0);
    assert!(writer.try_recv().is_err());
    drop(admission);
    let mut requests = Vec::new();
    for next_id in 1..=16 {
        // Poll creation order, not lock registration order. With capacity one,
        // allocation must not run ahead of the holder blocked on FIFO enqueue.
        for _ in 0..16 {
            for call in &mut calls {
                assert!(futures_util::poll!(call.as_mut()).is_pending());
            }
        }
        assert_eq!(client.pending_len(), (next_id + 1).min(16) as usize);
        let frame = emitted(&client, writer.try_recv().expect("one FIFO item"));
        assert_eq!(frame.request_id, next_id);
        let Some(Body::Request(ref request)) = frame.body else {
            unreachable!();
        };
        assert_eq!(request.payload, vec![(16 - next_id) as u8]);
        requests.push(frame);
    }
    for frame in requests.into_iter().rev() {
        let Some(Body::Request(request)) = frame.body else {
            unreachable!();
        };
        client
            .ingest(&payload_result(frame.request_id, &request.payload))
            .await;
    }
    for (label, call) in calls.into_iter().enumerate() {
        assert_eq!(call.await.unwrap(), vec![label as u8]);
    }
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn cancelled_reservation_dropped_and_expired_allocations_are_never_reused() {
    let (client, mut writer) = active(ConnectionConfig {
        writer_capacity: 1,
        ..ConnectionConfig::default()
    })
    .await;
    let mut first = Box::pin(client.call(METHOD, vec![], 1000));
    let mut reserved = Box::pin(client.call(METHOD, vec![], 1000));
    let mut next = Box::pin(client.call(METHOD, vec![], 1000));
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(futures_util::poll!(&mut reserved).is_pending());
    assert!(futures_util::poll!(&mut next).is_pending());
    assert_eq!(
        client.pending_len(),
        2,
        "third caller waits before allocation"
    );
    client.cancel(2).await.unwrap();
    assert_eq!(reserved.await.unwrap_err().code(), ErrorCode::Cancelled);
    let frame = emitted(&client, writer.try_recv().unwrap());
    assert_eq!(frame.request_id, 1);
    assert!(futures_util::poll!(&mut next).is_pending());
    let frame = emitted(&client, writer.try_recv().unwrap());
    assert_eq!(
        frame.request_id, 3,
        "cancelled reservation permanently skipped 2"
    );
    client.ingest(&payload_result(1, b"one")).await;
    client.ingest(&payload_result(3, b"three")).await;
    assert_eq!(first.await.unwrap(), b"one");
    assert_eq!(next.await.unwrap(), b"three");

    let mut dropped = Box::pin(client.call(METHOD, vec![], 1000));
    assert!(futures_util::poll!(&mut dropped).is_pending());
    let stale = writer.try_recv().unwrap();
    assert_eq!(Frame::decode(stale.as_slice()).unwrap().request_id, 4);
    drop(dropped);
    assert!(client.prepare_outbound(stale).is_none());
    let mut expired = Box::pin(client.call(METHOD, vec![], 10));
    assert!(futures_util::poll!(&mut expired).is_pending());
    let stale = writer.try_recv().unwrap();
    assert_eq!(Frame::decode(stale.as_slice()).unwrap().request_id, 5);
    tokio::time::advance(Duration::from_millis(10)).await;
    assert!(client.prepare_outbound(stale).is_none());
    assert_eq!(
        expired.await.unwrap_err().code(),
        ErrorCode::DeadlineExceeded
    );
    assert_clean(&client);

    // Seed IDs are connection-local monotonic history, not recyclable slots.
    // Never reset the allocator after cleanup or seed it to reuse a retired ID.
    let mut fresh = Box::pin(client.call(METHOD, vec![], 1000));
    assert!(futures_util::poll!(&mut fresh).is_pending());
    assert_eq!(emitted(&client, writer.try_recv().unwrap()).request_id, 6);
    for old_id in [1, 2, 3, 4, 5] {
        client.ingest(&payload_result(old_id, b"stale")).await;
        assert_eq!(client.pending_len(), 1);
        assert!(futures_util::poll!(&mut fresh).is_pending());
    }
    client.ingest(&payload_result(6, b"fresh")).await;
    assert_eq!(fresh.await.unwrap(), b"fresh");
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn pump_accepts_only_original_vec_and_only_once() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, b"opaque".to_vec(), 100));
    assert!(futures_util::poll!(&mut call).is_pending());
    let original = writer.try_recv().unwrap();
    let id = Frame::decode(original.as_slice()).unwrap().request_id;
    assert!(client.prepare_outbound(original.clone()).is_none());
    assert!(client
        .prepare_outbound(Frame::decode(original.as_slice()).unwrap().encode_to_vec())
        .is_none());
    assert_eq!(
        client.pending_len(),
        1,
        "invalid ticket must not consume original"
    );
    tokio::time::advance(Duration::from_micros(20_500)).await;
    let prepared = client.prepare_outbound(original).unwrap();
    let frame = Frame::decode(prepared.as_slice()).unwrap();
    let Some(Body::Request(request)) = frame.body else {
        panic!("expected request");
    };
    assert_eq!(request.timeout_ms, 79);
    assert_eq!(request.payload, b"opaque");
    assert!(
        client.prepare_outbound(prepared).is_none(),
        "handoff is one-shot"
    );
    client.ingest(&payload_result(id, b"ok")).await;
    assert_eq!(call.await.unwrap(), b"ok");
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn exact_deadline_beats_result_cancel_loss_and_close_without_caller_repoll() {
    for candidate in ["result", "cancel", "loss", "close"] {
        let (client, mut writer) = active(ConnectionConfig::default()).await;
        let mut call = Box::pin(client.call(METHOD, vec![], 10));
        assert!(futures_util::poll!(&mut call).is_pending());
        let id = emitted(&client, writer.try_recv().unwrap()).request_id;
        tokio::time::advance(Duration::from_millis(10)).await;
        // This future is deliberately not spawned: advance cannot poll its
        // timer/call branch. The incoming candidate must select expiry itself.
        match candidate {
            "result" => client.ingest(&payload_result(id, b"too late")).await,
            "cancel" => client.cancel(id).await.unwrap(),
            "loss" => client.on_transport_lost().await,
            "close" => client.close().await,
            _ => unreachable!(),
        }
        assert_clean(&client);
        assert_eq!(
            call.await.unwrap_err().code(),
            ErrorCode::DeadlineExceeded,
            "pending exact-deadline candidate: {candidate}"
        );
        client.ingest(&payload_result(id, b"later still")).await;
        assert_clean(&client);
    }
}

#[tokio::test(start_paused = true)]
async fn predeadline_selected_result_survives_expiry_cancel_and_teardown() {
    for remote_error in [false, true] {
        for abrupt in [false, true] {
            let (client, mut writer) = active(ConnectionConfig::default()).await;
            let token = crate::CancelToken::new();
            let mut call = Box::pin(client.call_cancellable(METHOD, vec![], 10, &token));
            assert!(futures_util::poll!(&mut call).is_pending());
            let id = emitted(&client, writer.try_recv().unwrap()).request_id;
            tokio::time::advance(Duration::from_millis(9)).await;
            let outcome = if remote_error {
                Outcome::Error(syntra_core::proto::RpcError {
                    code: ErrorCode::NotFound.as_i32(),
                    message: "missing".into(),
                })
            } else {
                Outcome::Payload(b"selected".to_vec())
            };
            client.ingest(&result_bytes(id, outcome)).await;
            assert_clean(&client);
            // Delay callback delivery beyond expiry and every competing signal.
            tokio::time::advance(Duration::from_millis(20)).await;
            token.cancel();
            client.cancel(id).await.unwrap();
            if abrupt {
                client.on_transport_lost().await;
            } else {
                client.close().await;
            }
            let result = call.await;
            if remote_error {
                assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
            } else {
                assert_eq!(result.unwrap(), b"selected");
            }
            assert_clean(&client);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn explicit_cancel_after_emission_is_locally_terminal_before_late_results() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut call).is_pending());
    let prepared = client.prepare_outbound(writer.try_recv().unwrap()).unwrap();
    let id = Frame::decode(prepared.as_slice()).unwrap().request_id;
    client.cancel(id).await.unwrap();
    assert_clean(&client);
    let control = client.prepare_outbound(writer.try_recv().unwrap()).unwrap();
    let control = Frame::decode(control.as_slice()).unwrap();
    assert_eq!(control.request_id, id);
    assert!(matches!(control.body, Some(Body::Cancel(_))));
    client
        .ingest(&payload_result(id, b"remote effects may have happened"))
        .await;
    tokio::time::advance(Duration::from_millis(100)).await;
    client.on_transport_lost().await;
    assert_eq!(call.await.unwrap_err().code(), ErrorCode::Cancelled);
    assert!(matches!(
        Frame::decode(prepared.as_slice()).unwrap().body,
        Some(Body::Request(_))
    ));
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn selected_token_cancellation_is_irreversible_and_late_result_cannot_poison_followup() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let token = crate::CancelToken::new();
    let mut call = Box::pin(client.call_cancellable(METHOD, vec![], 100, &token));
    assert!(futures_util::poll!(&mut call).is_pending());
    let id = emitted(&client, writer.try_recv().unwrap()).request_id;
    token.cancel();
    // Explicitly select the cancellation before a result candidate is offered.
    let std::task::Poll::Ready(result) = futures_util::poll!(&mut call) else {
        panic!("cancellation must settle without remote acknowledgement");
    };
    assert_eq!(result.unwrap_err().code(), ErrorCode::Cancelled);
    drop(call);
    assert_clean(&client);
    let control = Frame::decode(writer.try_recv().unwrap().as_slice()).unwrap();
    assert_eq!(control.request_id, id);
    assert!(matches!(control.body, Some(Body::Cancel(_))));
    let mut follow = Box::pin(client.call(METHOD, vec![], 100));
    assert!(futures_util::poll!(&mut follow).is_pending());
    let next_id = emitted(&client, writer.try_recv().unwrap()).request_id;
    assert!(next_id > id);
    for _ in 0..2 {
        client.ingest(&payload_result(id, b"ignored")).await;
        assert_eq!(client.pending_len(), 1);
        assert!(futures_util::poll!(&mut follow).is_pending());
    }
    client.ingest(&payload_result(next_id, b"follow")).await;
    assert_eq!(follow.await.unwrap(), b"follow");
    assert_clean(&client);
}

#[tokio::test(start_paused = true)]
async fn raw_result_buffered_before_deadline_but_not_selected_expires() {
    let (client, mut writer) = active(ConnectionConfig::default()).await;
    let mut call = Box::pin(client.call(METHOD, vec![], 10));
    assert!(futures_util::poll!(&mut call).is_pending());
    let id = emitted(&client, writer.try_recv().unwrap()).request_id;
    let (raw_tx, mut raw_rx) = mpsc::channel(1);
    tokio::time::advance(Duration::from_millis(9)).await;
    raw_tx.try_send(payload_result(id, b"buffered")).unwrap();
    assert_eq!(
        client.pending_len(),
        1,
        "buffering is not terminal selection"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    // Neither call nor its timer was repolled while raw carrier input waited.
    client.ingest(&raw_rx.try_recv().unwrap()).await;
    assert_clean(&client);
    assert_eq!(call.await.unwrap_err().code(), ErrorCode::DeadlineExceeded);
}

#[tokio::test(start_paused = true)]
async fn exhausted_id_space_closes_promptly_without_lock_upgrade_or_wrap() {
    let (mut client, mut writer) = active(ConnectionConfig::default()).await;
    Arc::get_mut(&mut client.conn.shared).unwrap().ids =
        syntra_core::RequestIdAllocator::starting_at(std::num::NonZeroU64::new(u64::MAX).unwrap());
    let mut last = Box::pin(client.call(METHOD, vec![], 1000));
    assert!(futures_util::poll!(&mut last).is_pending());
    assert_eq!(
        emitted(&client, writer.try_recv().unwrap()).request_id,
        u64::MAX
    );
    let mut exhausted = Box::pin(client.call(METHOD, vec![], 1000));
    let std::task::Poll::Ready(result) = futures_util::poll!(&mut exhausted) else {
        panic!("exhaustion must close immediately, not wait for its own state read lock");
    };
    assert_eq!(result.unwrap_err().code(), ErrorCode::ResourceExhausted);
    assert!(client.is_closed());
    assert_eq!(
        client.terminal_reason().unwrap().code(),
        ErrorCode::ResourceExhausted
    );
    assert_eq!(last.await.unwrap_err().code(), ErrorCode::Unavailable);
    assert!(
        writer.try_recv().is_err(),
        "neither zero nor wrapped ID was enqueued"
    );
    assert_clean(&client);
}
