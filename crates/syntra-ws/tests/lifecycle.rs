#![cfg(not(target_arch = "wasm32"))]

use futures_util::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use syntra_runtime::{AllowAnonymous, ConnectionConfig, FnHandler, HandlerOutcome, Host};
use tokio_tungstenite::tungstenite::{
    handshake::server::{Request, Response},
    protocol::{
        frame::{
            coding::{CloseCode, Data, OpCode},
            Frame,
        },
        CloseFrame,
    },
    Message,
};

// One real socket, one owned peer task. No perpetual accept loop or per-message tasks.
#[allow(clippy::result_large_err)]
async fn peer(
    messages: Vec<Message>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Option<CloseFrame>>,
) {
    peer_with_disconnect(messages, false).await
}

#[allow(clippy::result_large_err)]
async fn peer_with_disconnect(
    messages: Vec<Message>,
    disconnect: bool,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<Option<CloseFrame>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (start, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws =
            tokio_tungstenite::accept_hdr_async(socket, |req: &Request, mut res: Response| {
                assert_eq!(req.headers()["host"], address.to_string());
                res.headers_mut()
                    .insert("sec-websocket-protocol", "syntra.v1".parse().unwrap());
                Ok(res)
            })
            .await
            .unwrap();
        let (host, mut outgoing) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(FnHandler(|_, payload, _| async move {
                HandlerOutcome::Payload(payload)
            })),
        );
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(hello))) => {
                    host.ingest(&hello).await;
                    ws.send(Message::Binary(outgoing.recv().await.unwrap().into()))
                        .await
                        .unwrap();
                    break;
                }
                Some(Ok(Message::Ping(_))) => ws.flush().await.unwrap(),
                other => panic!("expected hello: {other:?}"),
            }
        }
        started.await.unwrap();
        if disconnect {
            drop(ws);
            host.on_transport_lost().await;
            return None;
        }
        for message in messages {
            ws.send(message).await.unwrap();
        }
        let close = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match ws.next().await {
                    Some(Ok(Message::Close(close))) => {
                        let _ = ws.flush().await;
                        break close;
                    }
                    Some(Ok(Message::Ping(_))) => ws.flush().await.unwrap(),
                    other => panic!("expected Close reply, got {other:?}"),
                }
            }
        })
        .await
        .expect("client must flush Close promptly, not at next liveness tick");
        host.on_transport_lost().await;
        close
    });
    (format!("ws://{address}/syntra/v1/ws"), start, task)
}

async fn assert_close(messages: Vec<Message>, code: CloseCode) {
    let (url, start, task) = peer(messages).await;
    let handle = syntra_ws::connect(
        syntra_ws::WsConfig::insecure_dev(url),
        vec![],
        ConnectionConfig::default(),
    )
    .await
    .expect("connect with complete Host authority");
    start.send(()).unwrap();
    assert_eq!(task.await.unwrap().expect("close code").code, code);
    tokio::time::timeout(Duration::from_secs(2), handle.close())
        .await
        .expect("joined teardown");
}

#[tokio::test]
async fn host_authority_and_remote_close_echo() {
    assert_close(
        vec![Message::Close(Some(CloseFrame {
            code: CloseCode::Away,
            reason: "peer leaving".into(),
        }))],
        CloseCode::Away,
    )
    .await;
}

#[tokio::test]
async fn remote_close_without_status_is_flushed() {
    let (url, start, task) = peer(vec![Message::Close(None)]).await;
    let handle = syntra_ws::connect(
        syntra_ws::WsConfig::insecure_dev(url),
        vec![],
        ConnectionConfig::default(),
    )
    .await
    .unwrap();
    start.send(()).unwrap();
    assert!(task.await.unwrap().is_none());
    handle.close().await;
}

#[tokio::test]
async fn dropping_handle_closes_cloned_initiator() {
    let (url, start, task) = peer(vec![]).await;
    let handle = syntra_ws::connect(
        syntra_ws::WsConfig::insecure_dev(url),
        vec![],
        ConnectionConfig::default(),
    )
    .await
    .unwrap();
    let initiator = handle.conn.clone();
    let mut closed = initiator.subscribe_close();
    start.send(()).unwrap();
    drop(handle);
    tokio::time::timeout(Duration::from_secs(1), closed.wait_for(|closed| *closed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.await.unwrap().unwrap().code, CloseCode::Normal);
}

#[tokio::test]
async fn abrupt_read_exit_wakes_idle_pumps_and_fails_pending_calls() {
    let (url, start, task) = peer_with_disconnect(vec![], true).await;
    let handle = syntra_ws::connect(
        syntra_ws::WsConfig::insecure_dev(url),
        vec![],
        ConnectionConfig::default(),
    )
    .await
    .unwrap();
    let caller = handle.conn.clone();
    let call = tokio::spawn(async move { caller.call("/example.Echo/Echo", vec![], 10_000).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while handle.conn.pending_len() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    start.send(()).unwrap();
    task.await.unwrap();
    let error = tokio::time::timeout(Duration::from_secs(1), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(matches!(error, syntra_core::SyntraError::Unavailable(_)));
    tokio::time::timeout(Duration::from_secs(1), handle.close())
        .await
        .expect("all pumps joined promptly");
}

#[tokio::test]
async fn oversize_single_and_fragmented_messages_close_1009() {
    assert_close(
        vec![Message::Binary(
            vec![0; syntra_core::MAX_FRAME_BYTES + 1].into(),
        )],
        CloseCode::Size,
    )
    .await;
    assert_close(
        vec![
            Message::Frame(Frame::message(
                vec![0; 64 * 1024],
                OpCode::Data(Data::Binary),
                false,
            )),
            Message::Frame(Frame::message(
                vec![0; syntra_core::MAX_FRAME_BYTES - 64 * 1024 + 1],
                OpCode::Data(Data::Continue),
                true,
            )),
        ],
        CloseCode::Size,
    )
    .await;
}

#[tokio::test]
async fn empty_and_text_messages_flush_rejection() {
    assert_close(vec![Message::Binary(Vec::new().into())], CloseCode::Invalid).await;
    assert_close(
        vec![Message::Text("invalid".into())],
        CloseCode::Unsupported,
    )
    .await;
}

#[tokio::test]
async fn protocol_closed_by_ingest_stops_idle_writer() {
    use prost::Message as _;
    // The runtime closes after repeated malformed envelopes in ACTIVE.
    let ready = syntra_core::Frame {
        version: 1,
        request_id: 0,
        body: Some(syntra_core::proto::frame::Body::Ready(
            syntra_core::ServerReady {
                connection_id: "second-ready".into(),
            },
        )),
    }
    .encode_to_vec();
    assert_close(vec![Message::Binary(ready.into()); 9], CloseCode::Protocol).await;
}

#[tokio::test]
async fn stalled_upgrade_times_out_and_releases_socket() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/syntra/v1/ws", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        // Without a 101 there must be no binary Syntra hello/credential.
        assert!(bytes.starts_with(b"GET /syntra/v1/ws HTTP/1.1\r\n"));
        assert!(bytes.ends_with(b"\r\n\r\n"));
    });
    let mut cfg = syntra_ws::WsConfig::insecure_dev(url);
    cfg.connect_timeout = Duration::from_millis(20);
    let result = syntra_ws::connect(cfg, vec![], ConnectionConfig::default()).await;
    assert!(
        matches!(result, Err(syntra_ws::TransportError::Connect(message)) if message.contains("timed out"))
    );
    task.await.unwrap();
}
