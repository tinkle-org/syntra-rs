#![cfg(all(feature = "websocket", not(target_arch = "wasm32")))]
use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_core::secure_channel::*;
use syntra_net::{websocket as ws, AuthenticatorFactory, Limits};
use syntra_runtime::{
    AuthError, Authenticator, ConnectionConfig, FnHandler, Handler, HandlerOutcome, Principal,
    RejectAll,
};
use tokio_tungstenite::tungstenite::{
    handshake::server::{Request, Response},
    protocol::frame::{
        coding::{Data, OpCode},
        Frame,
    },
    Message,
};

struct Store;
impl KeyStore for Store {
    fn lookup(&self, c: &Context) -> Result<Secret32, Error> {
        if c.handle == [4; 8] && c.epoch == 9 {
            Ok(Secret32::new([3; 32]))
        } else {
            Err(Error::Authentication)
        }
    }
}
struct BoundAuth(VerifiedIdentity);
impl Authenticator for BoundAuth {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        if !credential.is_empty() {
            return Err(AuthError::unauthenticated());
        }
        match self.0.context().mode {
            Mode::Returning if self.0.context().handle == [4; 8] => Ok(Principal::new("device-4")),
            Mode::Bootstrap => Ok(Principal::anonymous()),
            _ => Err(AuthError::unauthenticated()),
        }
    }
}
fn configs(mode: Mode) -> (ClientConfig, ServerConfig) {
    let (private, public) = generate_server_key().unwrap();
    let returning = mode == Mode::Returning;
    let context = Context {
        mode,
        carrier: Carrier::WebSocket,
        server_key_id: 12,
        scope: b"ws/test".to_vec(),
        handle: if returning { [4; 8] } else { [0; 8] },
        epoch: if returning { 9 } else { 0 },
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: returning.then(|| Secret32::new([3; 32])),
        },
        ServerConfig {
            mode,
            carrier: Carrier::WebSocket,
            server_key_id: 12,
            scope: context.scope,
            private_key: private,
            store: Some(Arc::new(Store)),
        },
    )
}
fn echo() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|_, bytes, _| async move {
        HandlerOutcome::Payload(bytes)
    }))
}

#[tokio::test]
async fn native_ws_live_socket_client_host_both_modes_and_principal_deny() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for deny in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "ws://{}{}",
                listener.local_addr().unwrap(),
                ws::ENDPOINT_PATH
            );
            let (client, server) = configs(mode);
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
                move |id: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                    count.fetch_add(1, Ordering::SeqCst);
                    if deny {
                        Ok(Arc::new(RejectAll))
                    } else {
                        Ok(Arc::new(BoundAuth(id.clone())))
                    }
                },
            );
            let task = tokio::spawn(async move {
                ws::accept(
                    &listener,
                    &server,
                    factory,
                    echo(),
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
            });
            let client = ws::connect(
                &url,
                client,
                vec![],
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await;
            let host = task.await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if deny {
                assert!(client.is_err());
                assert!(host.is_err());
            } else {
                let client = client.unwrap();
                let host = host.unwrap();
                let bytes = vec![5; 200_000];
                assert_eq!(
                    client
                        .conn
                        .call("/test.Service/Echo", bytes.clone(), 5000)
                        .await
                        .unwrap(),
                    bytes
                );
                let retained = client.conn.clone();
                client
                    .close_gracefully(Duration::from_secs(1))
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !retained.is_closed() || !host.is_closed() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                host.close().await;
            }
        }
    }
}

#[tokio::test]
async fn separate_endpoint_and_subprotocol_are_required() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};
    for (path, token, text) in [
        ("/syntra/v1/ws", ws::SUBPROTOCOL, false),
        (ws::ENDPOINT_PATH, "syntra.v1", false),
        (ws::ENDPOINT_PATH, ws::SUBPROTOCOL, true),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}{}", listener.local_addr().unwrap(), path);
        let (_, server) = configs(Mode::Bootstrap);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
            move |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                count.fetch_add(1, Ordering::SeqCst);
                Err(AuthError::denied())
            },
        );
        let task = tokio::spawn(async move {
            ws::accept(
                &listener,
                &server,
                factory,
                echo(),
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await
        });
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("sec-websocket-protocol", HeaderValue::from_static(token));
        let result = tokio_tungstenite::connect_async(request).await;
        if text {
            result
                .unwrap()
                .0
                .send(Message::Text("invalid".into()))
                .await
                .unwrap();
        } else {
            assert!(result.is_err());
        }
        assert!(task.await.unwrap().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn ws_rejects_non_loopback_and_secure_carrier() {
    use syntra_net::Error as TransportError;
    for url in [
        "ws://192.0.2.1/syntra/1.0/ws",
        "ws://example.invalid/syntra/1.0/ws",
        "ws://127.0.0.1.example.invalid/syntra/1.0/ws",
        "ws://[::ffff:192.0.2.1]/syntra/1.0/ws",
    ] {
        let (client, _) = configs(Mode::Bootstrap);
        let result = ws::connect(
            url,
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await;
        assert!(matches!(result, Err(TransportError::Configuration)));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "ws://{}{}",
        listener.local_addr().unwrap(),
        ws::ENDPOINT_PATH
    );
    let (mut client, mut server) = configs(Mode::Bootstrap);
    client.context.carrier = Carrier::SecureWebSocket;
    server.carrier = Carrier::SecureWebSocket;
    assert!(matches!(
        ws::connect(
            &url,
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default()
        )
        .await,
        Err(TransportError::Configuration)
    ));
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            panic!("must not authenticate")
        },
    );
    // Listener mismatch is rejected before waiting for an incoming connection.
    assert!(matches!(
        ws::accept(
            &listener,
            &server,
            factory.clone(),
            echo(),
            ConnectionConfig::default(),
            Limits::default()
        )
        .await,
        Err(TransportError::Configuration)
    ));
    let (raw, _) = tokio::io::duplex(1024);
    assert!(matches!(
        ws::accept_stream(
            raw,
            &server,
            factory,
            echo(),
            ConnectionConfig::default(),
            Limits::default()
        )
        .await,
        Err(TransportError::Configuration)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[allow(clippy::result_large_err)]
async fn protected_peer(
    listener: tokio::net::TcpListener,
    security: ServerConfig,
) -> (
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    Channel,
) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut socket =
        tokio_tungstenite::accept_hdr_async(socket, |request: &Request, mut response: Response| {
            assert_eq!(request.uri().path(), ws::ENDPOINT_PATH);
            assert_eq!(request.headers()["sec-websocket-protocol"], ws::SUBPROTOCOL);
            response
                .headers_mut()
                .insert("sec-websocket-protocol", ws::SUBPROTOCOL.parse().unwrap());
            Ok(response)
        })
        .await
        .unwrap();
    let Some(Ok(Message::Binary(first))) = socket.next().await else {
        panic!("expected M1")
    };
    let (mut channel, second) = respond(&security, &first).unwrap();
    socket.send(Message::Binary(second.into())).await.unwrap();
    let Some(Ok(Message::Binary(hello))) = socket.next().await else {
        panic!("expected protected hello")
    };
    let plaintext = channel.decrypt(&hello).unwrap();
    let frames = FrameDecoder::default().push(&plaintext).unwrap();
    assert_eq!(frames.len(), 1);
    let hello = syntra_core::Frame::decode(frames[0].as_slice()).unwrap();
    assert!(matches!(
        hello.body,
        Some(syntra_core::proto::frame::Body::Hello(_))
    ));
    let ready = syntra_core::Frame {
        version: 1,
        request_id: 0,
        body: Some(syntra_core::proto::frame::Body::Ready(
            syntra_core::ServerReady {
                connection_id: "protected-lifecycle-test".into(),
            },
        )),
    }
    .encode_to_vec();
    let record = channel.encrypt(&frame_plaintext(&ready).unwrap()).unwrap();
    socket.send(Message::Binary(record.into())).await.unwrap();
    (socket, channel)
}

#[tokio::test]
async fn protected_record_bounds_and_active_message_faults_both_modes() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for fault in 0..4 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "ws://{}{}",
                listener.local_addr().unwrap(),
                ws::ENDPOINT_PATH
            );
            let (client, server) = configs(mode);
            let (start, started) = tokio::sync::oneshot::channel();
            let (reject, rejected) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), async move {
                    let (mut socket, mut channel) = protected_peer(listener, server).await;
                    started.await.unwrap();
                    let mut notification = syntra_core::Frame {
                        version: 1,
                        request_id: 0,
                        body: Some(syntra_core::proto::frame::Body::Notification(
                            syntra_core::Notification {
                                payload: vec![0x5a; MAX_PLAINTEXT],
                            },
                        )),
                    };
                    let overhead = frame_plaintext(&notification.encode_to_vec())
                        .unwrap()
                        .len()
                        - MAX_PLAINTEXT;
                    let Some(syntra_core::proto::frame::Body::Notification(body)) =
                        notification.body.as_mut()
                    else {
                        unreachable!()
                    };
                    body.payload.truncate(MAX_PLAINTEXT - overhead);
                    let record = channel
                        .encrypt(&frame_plaintext(&notification.encode_to_vec()).unwrap())
                        .unwrap();
                    assert_eq!(record.len(), MAX_CIPHERTEXT);
                    if fault == 3 {
                        let cut = record.len() / 2;
                        socket
                            .send(Message::Frame(Frame::message(
                                record[..cut].to_vec(),
                                OpCode::Data(Data::Binary),
                                false,
                            )))
                            .await
                            .unwrap();
                        socket.send(Message::Ping(vec![1].into())).await.unwrap();
                        socket
                            .send(Message::Frame(Frame::message(
                                record[cut..].to_vec(),
                                OpCode::Data(Data::Continue),
                                true,
                            )))
                            .await
                            .unwrap();
                    } else {
                        socket.send(Message::Binary(record.into())).await.unwrap();
                    }
                    rejected.await.unwrap();
                    match fault {
                        0 => socket
                            .send(Message::Text("not a protected record".into()))
                            .await
                            .unwrap(),
                        1 => socket
                            .send(Message::Binary(Vec::new().into()))
                            .await
                            .unwrap(),
                        2 => socket
                            .send(Message::Binary(vec![0; MAX_CIPHERTEXT + 1].into()))
                            .await
                            .unwrap(),
                        3 => {
                            socket
                                .send(Message::Frame(Frame::message(
                                    vec![0; 32_768],
                                    OpCode::Data(Data::Binary),
                                    false,
                                )))
                                .await
                                .unwrap();
                            socket
                                .send(Message::Frame(Frame::message(
                                    vec![0; 32_768],
                                    OpCode::Data(Data::Continue),
                                    true,
                                )))
                                .await
                                .unwrap();
                        }
                        _ => unreachable!(),
                    }
                    while let Some(message) = socket.next().await {
                        match message {
                            Ok(Message::Ping(_) | Message::Pong(_)) => {
                                socket.flush().await.unwrap()
                            }
                            Ok(Message::Close(_)) | Err(_) => break,
                            other => panic!("unexpected message after fault: {other:?}"),
                        }
                    }
                })
                .await
                .expect("protected fault peer terminates");
            });
            let handle = ws::connect(
                &url,
                client,
                vec![],
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await
            .unwrap();
            let mut closed = handle.conn.subscribe_close();
            start.send(()).unwrap();
            let payload =
                tokio::time::timeout(Duration::from_secs(2), handle.conn.next_notification())
                    .await
                    .unwrap()
                    .unwrap();
            assert!(!payload.is_empty());
            assert!(payload.iter().all(|byte| *byte == 0x5a));
            reject.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), closed.wait_for(|closed| *closed))
                .await
                .unwrap()
                .unwrap();
            assert!(handle.conn.is_closed());
            handle.close().await;
            peer.await.unwrap();
        }
    }
}

#[tokio::test]
async fn protected_fragment_and_control_trickles_do_not_renew_record_deadline() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}{}",
            listener.local_addr().unwrap(),
            ws::ENDPOINT_PATH
        );
        let (client, server) = configs(mode);
        let (start, started) = tokio::sync::oneshot::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let (mut socket, _) = protected_peer(listener, server).await;
                started.await.unwrap();
                socket.send(Message::Frame(Frame::message(vec![0], OpCode::Data(Data::Binary), false))).await.unwrap();
                tokio::pin!(stopped);
                let mut interval = tokio::time::interval(Duration::from_millis(10));
                let mut sent = 0;
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut stopped => break,
                        _ = interval.tick() => {
                            if socket.send(Message::Ping(vec![1].into())).await.is_err()
                                || socket.send(Message::Pong(vec![2].into())).await.is_err()
                                || socket.send(Message::Frame(Frame::message(vec![0], OpCode::Data(Data::Continue), false))).await.is_err() {
                                break;
                            }
                            sent += 1;
                        }
                    }
                }
                assert!(sent >= 2, "test must exercise an ongoing trickle");
            }).await.expect("trickle peer terminates");
        });
        let limits = Limits {
            record_timeout: Duration::from_millis(300),
            close_timeout: Duration::from_millis(20),
            ..Limits::default()
        };
        let handle = ws::connect(&url, client, vec![], ConnectionConfig::default(), limits)
            .await
            .unwrap();
        let mut closed = handle.conn.subscribe_close();
        let started_at = std::time::Instant::now();
        start.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), closed.wait_for(|closed| *closed))
            .await
            .unwrap()
            .unwrap();
        assert!(
            started_at.elapsed() >= Duration::from_millis(200),
            "valid fragments and controls must not fail before the record deadline"
        );
        let _ = stop.send(());
        handle.close().await;
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn protected_socket_loss_fails_pending_calls_and_handle_drop_closes_clones() {
    use tokio_tungstenite::tungstenite::{error::ProtocolError, Error as WsError};

    for mode in [Mode::Bootstrap, Mode::Returning] {
        for remote_loss in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!(
                "ws://{}{}",
                listener.local_addr().unwrap(),
                ws::ENDPOINT_PATH
            );
            let (client, server) = configs(mode);
            let (request_seen, received_request) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(5), async move {
                    let (mut socket, mut channel) = protected_peer(listener, server).await;
                    let observed = socket.next().await;
                    let Some(Ok(Message::Binary(record))) = observed else {
                        panic!("expected pending protected call, observed {observed:?}")
                    };
                    let plaintext = channel.decrypt(&record).unwrap();
                    let frames = FrameDecoder::default().push(&plaintext).unwrap();
                    assert_eq!(frames.len(), 1);
                    let call = syntra_core::Frame::decode(frames[0].as_slice()).unwrap();
                    assert!(matches!(
                        call.body,
                        Some(syntra_core::proto::frame::Body::Request(_))
                    ));
                    request_seen.send(()).unwrap();
                    if !remote_loss {
                        // Owner drop is abortive: no WS closing handshake is promised.
                        // A Close alone is not enough; poll through to termination.
                        let mut saw_close = false;
                        loop {
                            let observed = socket.next().await;
                            match observed {
                                None
                                | Some(Err(WsError::ConnectionClosed))
                                | Some(Err(WsError::Protocol(
                                    ProtocolError::ResetWithoutClosingHandshake,
                                ))) => break,
                                Some(Err(WsError::Io(ref error)))
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::ConnectionReset
                                            | std::io::ErrorKind::ConnectionAborted
                                            | std::io::ErrorKind::UnexpectedEof
                                            | std::io::ErrorKind::BrokenPipe
                                    ) => break,
                                Some(Ok(Message::Close(_))) if !saw_close => saw_close = true,
                                other => panic!(
                                    "expected peer termination after handle drop, observed {other:?}"
                                ),
                            }
                        }
                    }
                })
                .await
                .expect("protected peer teardown is bounded");
            });
            let handle = ws::connect(
                &url,
                client,
                vec![],
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await
            .unwrap();
            let retained = handle.conn.clone();
            let mut closed = retained.subscribe_close();
            let caller = retained.clone();
            let pending =
                tokio::spawn(
                    async move { caller.call("/test.Service/Echo", vec![], 10_000).await },
                );
            tokio::time::timeout(Duration::from_secs(2), received_request)
                .await
                .expect("peer observes the pending call before loss")
                .unwrap();
            let handle = if remote_loss {
                Some(handle)
            } else {
                assert_eq!(retained.pending_len(), 1);
                drop(handle);
                None
            };
            let error = tokio::time::timeout(Duration::from_secs(2), pending)
                .await
                .expect("transport loss settles the pending call without its RPC timeout")
                .unwrap()
                .unwrap_err();
            assert!(
                matches!(error, syntra_core::SyntraError::Unavailable(_)),
                "unexpected pending-call result: {error:?}"
            );
            if let Some(handle) = handle {
                handle.close().await;
            }
            tokio::time::timeout(Duration::from_secs(2), closed.wait_for(|closed| *closed))
                .await
                .unwrap()
                .unwrap();
            assert!(retained.is_closed());
            assert_eq!(retained.pending_len(), 0);
            let error = tokio::time::timeout(
                Duration::from_secs(2),
                retained.call("/test.Service/Echo", vec![], 10_000),
            )
            .await
            .expect("retained clone rejects new work promptly")
            .unwrap_err();
            assert!(
                matches!(error, syntra_core::SyntraError::Closed(_)),
                "retained clone remained usable: {error:?}"
            );
            peer.await.unwrap();
        }
    }
}
