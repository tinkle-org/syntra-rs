use super::*;
use prost::Message;
use std::{sync::Arc, time::Duration};
use syntra_core::{proto::frame::Body, ClientHello, Frame, RpcRequest};
use tokio::sync::mpsc;

fn host(config: ConnectionConfig) -> (Arc<Host>, mpsc::Receiver<Vec<u8>>) {
    Host::new(
        config,
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(
            |_m, p, _c| async move { HandlerOutcome::Payload(p) },
        )),
    )
}

async fn activate_host(host: &Host, rx: &mut mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        }
        .encode_to_vec(),
    )
    .await;
    rx.recv().await.expect("ready frame")
}

#[tokio::test]
async fn peer_close_fences_host_before_bridge_drain_rendezvous() {
    let config = ConnectionConfig {
        writer_capacity: 1,
        ..ConnectionConfig::default()
    };
    let (host, mut host_rx) = host(config.clone());
    activate_host(&host, &mut host_rx).await;
    let (initiator, _unused) = Initiator::new(config);
    initiator.close().await;

    // A queued malformed request needs a terminal error. More than one
    // writer's capacity forces the inbound drain to wait if its sibling
    // stops consuming but leaves the host writable at the barrier.
    let (tx, rx) = mpsc::channel(8);
    for id in 1..=8 {
        tx.try_send(
            Frame {
                version: 1,
                request_id: id,
                body: Some(Body::Request(RpcRequest {
                    method: String::new(),
                    payload: vec![],
                    timeout_ms: 1000,
                })),
            }
            .encode_to_vec(),
        )
        .unwrap();
    }
    drop(tx);
    let pumps = bridge_pair(&initiator, &host, rx, host_rx);
    let mut closed = host.subscribe_close();
    let observed = tokio::time::timeout(Duration::from_millis(500), async {
        while !*closed.borrow_and_update() {
            closed.changed().await.unwrap();
        }
    })
    .await;
    // Clean up even on red, so failure is an assertion rather than a hang.
    host.close().await;
    for pump in pumps {
        tokio::time::timeout(Duration::from_secs(1), pump.join())
            .await
            .expect("bridge task must exit");
    }
    assert!(
        observed.is_ok(),
        "host remained writable while sibling pump waited at teardown barrier"
    );
    assert!(host.notify(vec![]).await.is_err());
}

#[tokio::test]
async fn host_close_preserves_admitted_terminal_result_and_notifications() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = ConnectionConfig::default();
        let (host, mut host_rx) = host(config.clone());
        let (initiator, mut init_rx) = Initiator::new(config);
        let handshake = initiator.handshake(vec![]);
        tokio::pin!(handshake);
        assert!(futures_util::poll!(&mut handshake).is_pending());
        host.ingest(&init_rx.recv().await.unwrap()).await;
        initiator.ingest(&host_rx.recv().await.unwrap()).await;
        handshake.await.unwrap();

        let call = initiator.call("/example.Echo/Echo", b"terminal".to_vec(), 2000);
        tokio::pin!(call);
        assert!(futures_util::poll!(&mut call).is_pending());
        host.ingest(&init_rx.recv().await.unwrap()).await;
        while host.inflight_len() != 0 {
            tokio::task::yield_now().await;
        }
        host.notify(b"one".to_vec()).await.unwrap();
        host.notify(vec![]).await.unwrap();
        host.close().await;
        let pumps = bridge_pair(&initiator, &host, init_rx, host_rx);
        assert_eq!(call.await.unwrap(), b"terminal");
        for pump in pumps {
            pump.join().await;
        }
        assert!(initiator.is_closed());
        assert_eq!(initiator.next_notification().await, Some(b"one".to_vec()));
        assert_eq!(initiator.next_notification().await, Some(vec![]));
        assert_eq!(initiator.next_notification().await, None);
    })
    .await
    .expect("teardown must drain and terminate");
}

#[tokio::test]
async fn bridge_drain_waits_for_outstanding_writer_permit() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let config = ConnectionConfig::default();
        let (host, mut host_rx) = host(config.clone());
        let (initiator, mut init_rx) = Initiator::new(config);
        let handshake = initiator.handshake(vec![]);
        tokio::pin!(handshake);
        assert!(futures_util::poll!(&mut handshake).is_pending());
        host.ingest(&init_rx.recv().await.unwrap()).await;
        initiator.ingest(&host_rx.recv().await.unwrap()).await;
        handshake.await.unwrap();

        // Model a writer already holding capacity when teardown fences the
        // receiver. A try_recv drain would see Empty and miss this frame.
        let (tx, rx) = mpsc::channel(1);
        let permit = tx.reserve().await.unwrap();
        host.close().await;
        let pumps = bridge_pair(&initiator, &host, init_rx, rx);
        tx.closed().await;
        permit.send(
            Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Notification(syntra_core::proto::Notification {
                    payload: b"reserved".to_vec(),
                })),
            }
            .encode_to_vec(),
        );
        for pump in pumps {
            pump.join().await;
        }
        assert_eq!(
            initiator.next_notification().await,
            Some(b"reserved".to_vec())
        );
        assert_eq!(initiator.next_notification().await, None);
    })
    .await
    .expect("reserved frame must drain before teardown completes");
}

async fn rejected_sends_preserve_inbound(new_send_first: bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (host, mut host_rx) = host(ConnectionConfig::default());
        let (initiator, mut init_rx) = Initiator::new(ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        });
        let handshake = initiator.handshake(vec![]);
        tokio::pin!(handshake);
        assert!(futures_util::poll!(&mut handshake).is_pending());
        host.ingest(&init_rx.recv().await.unwrap()).await;
        initiator.ingest(&host_rx.recv().await.unwrap()).await;
        handshake.await.unwrap();

        let original = initiator.call("/example.Echo/Echo", b"terminal".to_vec(), 2000);
        tokio::pin!(original);
        assert!(futures_util::poll!(&mut original).is_pending());
        host.ingest(&init_rx.recv().await.unwrap()).await;
        while host.inflight_len() != 0 {
            tokio::task::yield_now().await;
        }
        host.notify(b"one".to_vec()).await.unwrap();
        host.notify(vec![]).await.unwrap();

        // Fill the one-frame request queue, then park another call in
        // reserve_writer. Neither request has reached the host.
        let queued = initiator.call("/example.Echo/Echo", b"queued".to_vec(), 2000);
        tokio::pin!(queued);
        assert!(futures_util::poll!(&mut queued).is_pending());
        let blocked = initiator.call("/example.Echo/Echo", b"blocked".to_vec(), 2000);
        tokio::pin!(blocked);
        assert!(futures_util::poll!(&mut blocked).is_pending());
        assert_eq!(initiator.pending_len(), 3);

        host.close().await;
        let (to_host, to_initiator) = bridge_pumps(&initiator, &host, init_rx, host_rx);
        tokio::pin!(to_host);
        // Execute the actual request pump through receiver-close and park
        // it at the barrier. Deliberately do not poll the response pump yet:
        // the successful result and notifications remain admitted but unread.
        assert!(futures_util::poll!(&mut to_host).is_pending());

        let fresh = initiator.call("/example.Echo/Echo", b"new".to_vec(), 2000);
        let (fresh_result, blocked_result) = if new_send_first {
            (fresh.await, blocked.await)
        } else {
            let blocked_result = blocked.await;
            (fresh.await, blocked_result)
        };
        let closed_before_drain = initiator.is_closed();
        let pending_before_drain = initiator.pending_len();

        to_initiator.await;
        to_host.await;
        let original_result = original.await;
        let queued_result = queued.await;
        let first_notification = initiator.next_notification().await;
        let empty_notification = initiator.next_notification().await;
        let end = initiator.next_notification().await;

        assert_eq!(
            original_result.expect("writer rejection must not erase the admitted success"),
            b"terminal"
        );
        assert!(
            !closed_before_drain,
            "send rejection closed the initiator before its inbound drain"
        );
        assert_eq!(
            pending_before_drain, 2,
            "only rejected calls should be removed before drain"
        );
        assert!(matches!(
            fresh_result,
            Err(syntra_core::SyntraError::Closed(_))
        ));
        assert!(matches!(
            blocked_result,
            Err(syntra_core::SyntraError::Closed(_))
        ));
        assert!(matches!(
            queued_result,
            Err(syntra_core::SyntraError::Unavailable(_))
        ));
        assert_eq!(first_notification, Some(b"one".to_vec()));
        assert_eq!(empty_notification, Some(vec![]));
        assert_eq!(end, None);
        assert!(initiator.is_closed());
        assert_eq!(initiator.pending_len(), 0);
    })
    .await
    .expect("rejected sends and both bridge drains must terminate");
}

#[tokio::test]
async fn bridge_rejected_new_send_preserves_admitted_inbound() {
    rejected_sends_preserve_inbound(true).await;
}

#[tokio::test]
async fn bridge_rejected_blocked_send_preserves_admitted_inbound() {
    rejected_sends_preserve_inbound(false).await;
}

#[tokio::test]
async fn unexpected_writer_loss_still_fails_outstanding_calls() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (host, mut host_rx) = host(ConnectionConfig::default());
        let (initiator, mut init_rx) = Initiator::new(ConnectionConfig::default());
        let handshake = initiator.handshake(vec![]);
        tokio::pin!(handshake);
        assert!(futures_util::poll!(&mut handshake).is_pending());
        host.ingest(&init_rx.recv().await.unwrap()).await;
        initiator.ingest(&host_rx.recv().await.unwrap()).await;
        handshake.await.unwrap();

        let outstanding = initiator.call("/example.Echo/Echo", b"outstanding".to_vec(), 2000);
        tokio::pin!(outstanding);
        assert!(futures_util::poll!(&mut outstanding).is_pending());
        assert_eq!(initiator.pending_len(), 1);
        // No intentional fence or draining pump: losing the writer must
        // still signal genuine transport loss to existing RPCs.
        drop(init_rx);
        let fresh = initiator
            .call("/example.Echo/Echo", b"new".to_vec(), 2000)
            .await;
        let outstanding = outstanding.await;
        host.close().await;
        assert!(matches!(fresh, Err(syntra_core::SyntraError::Closed(_))));
        assert!(matches!(
            outstanding,
            Err(syntra_core::SyntraError::Unavailable(_))
        ));
        assert!(initiator.is_closed());
        assert_eq!(initiator.pending_len(), 0);
        assert_eq!(initiator.next_notification().await, None);
    })
    .await
    .expect("unexpected loss must settle calls without hanging");
}
