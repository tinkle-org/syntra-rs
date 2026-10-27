//! WebSocket conformance vectors + live loopback transport tests.
//!
//! - Endpoint/subprotocol rules and the spec close-code table from
//!   `conformance/test-vectors/websocket/` (no sockets needed).
//! - Live `ws://127.0.0.1` loopback (restricted-development only):
//!   Upgrade + subprotocol selection, handshake, echo/get-put RPCs,
//!   unknown-method usability, text/oversize rejection, and subprotocol
//!   mismatch abort. TLS 1.3 enforcement is covered by
//!   `tls13_connector` (fails closed without roots; handshake tests
//!   never touch plaintext for production claims).

#![cfg(not(target_arch = "wasm32"))]

#[path = "../../../tests/interoperability/vectors.rs"]
mod vectors;

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use syntra_core::ErrorCode;
use syntra_runtime::{
    AllowAnonymous, CancelToken, ConnectionConfig, FnHandler, HandlerOutcome, Host,
};

fn test_handler() -> Arc<dyn syntra_runtime::Handler> {
    Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, cancel: CancelToken| async move {
            let _ = cancel;
            match method.as_str() {
                "/example.Echo/Echo" => HandlerOutcome::Payload(payload),
                "/example.KV/Put" => HandlerOutcome::Payload(Vec::new()),
                "/example.KV/Get" => HandlerOutcome::error(ErrorCode::NotFound, "missing"),
                _ => HandlerOutcome::error(ErrorCode::Unimplemented, "unknown method"),
            }
        },
    ))
}

/// Minimal test server: validates the Upgrade, selects `syntra.v1`
/// (unless `no_subproto`), then serves one Host over the socket.
async fn serve(listener: tokio::net::TcpListener, no_subproto: bool) {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    while let Some((stream, _)) = listener.accept().await.ok() {
        let handler = test_handler();
        tokio::spawn(async move {
            let ws = match tokio_tungstenite::accept_hdr_async(
                stream,
                |req: &Request, mut resp: Response| {
                    let offered = req
                        .headers()
                        .get("sec-websocket-protocol")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if !offered.split(',').map(str::trim).any(|p| p == "syntra.v1") {
                        let mut bad = tokio_tungstenite::tungstenite::http::Response::new(None);
                        *bad.status_mut() =
                            tokio_tungstenite::tungstenite::http::StatusCode::BAD_REQUEST;
                        return Err(bad);
                    }
                    if !no_subproto {
                        resp.headers_mut()
                            .insert("sec-websocket-protocol", "syntra.v1".parse().unwrap());
                    }
                    Ok(resp)
                },
            )
            .await
            {
                Ok(ws) => ws,
                Err(_) => return,
            };
            let (mut sink, mut stream) = ws.split();
            let (host, mut wrx) = Host::new(
                ConnectionConfig::default(),
                Arc::new(AllowAnonymous),
                handler,
            );
            // Single-writer pump: binary results from Host plus control
            // replies (Pong) from the read loop.
            use tokio_tungstenite::tungstenite::Message as WsMsg;
            let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<WsMsg>(16);
            let writer = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        b = wrx.recv() => match b {
                            Some(bytes) => {
                                if sink.send(WsMsg::Binary(bytes.into())).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        },
                        c = ctrl_rx.recv() => match c {
                            Some(msg) => {
                                if sink.send(msg).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        },
                    }
                }
            });
            // Control frames are a transport concern: answer Ping, absorb
            // Pong, stop at Close, reject text. Only binary reaches Host.
            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(WsMsg::Binary(data)) => {
                        host.ingest(&data).await;
                        if host.is_closed() {
                            break;
                        }
                    }
                    Ok(WsMsg::Ping(payload)) => {
                        if ctrl_tx.send(WsMsg::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(WsMsg::Pong(_)) | Ok(WsMsg::Frame(_)) => {}
                    Ok(WsMsg::Close(_)) | Ok(WsMsg::Text(_)) | Err(_) => break,
                }
            }
            host.on_transport_lost().await;
            writer.abort();
        });
    }
}

async fn loopback_server(no_subproto: bool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(serve(listener, no_subproto));
    format!("ws://127.0.0.1:{port}/syntra/v1/ws")
}

#[test]
fn endpoint_rules() {
    use syntra_ws::Endpoint;
    assert!(Endpoint::parse("wss://h/syntra/v1/ws", false).is_ok());
    assert!(Endpoint::parse("wss://h/syntra/v1/ws/", false).is_err());
    assert!(Endpoint::parse("ws://h/syntra/v1/ws", false).is_err());
    assert!(Endpoint::parse("ws://127.0.0.1/syntra/v1/ws", true).is_ok());
    assert!(Endpoint::parse("wss://u:p@h/syntra/v1/ws", false).is_err());
    assert!(Endpoint::parse("wss://h/syntra/v1/ws?token=x", false).is_err());
}

#[test]
fn close_code_table_matches_spec() {
    // VEC-WS-007 mapping through the adapter's mapper.
    let cases: &[(ErrorCode, u16)] = &[
        (ErrorCode::Unimplemented, 1002),
        (ErrorCode::FailedPrecondition, 1002),
        (ErrorCode::InvalidArgument, 1002),
        (ErrorCode::Unauthenticated, 1008),
        (ErrorCode::PermissionDenied, 1008),
        (ErrorCode::ResourceExhausted, 1009),
        (ErrorCode::Unavailable, 1001),
        (ErrorCode::Internal, 1011),
    ];
    for (code, wire) in cases {
        let got: u16 = syntra_ws::native::close_code_for_syntra(*code).into();
        assert_eq!(got, *wire, "close mapping for {code:?}");
        assert!(
            !vectors::RESERVED_CLOSE_CODES.contains(&got),
            "reserved code emitted"
        );
    }
    for (code, _label) in vectors::CLOSE_CODE_TABLE {
        assert!(!vectors::RESERVED_CLOSE_CODES.contains(code));
    }
}

#[test]
fn interop_frame_vectors() {
    use syntra_core::{decode_frame, ConnectionState, ValidationContext};
    // One complete binary message decodes directly as one Frame (no TCP
    // length prefix inside WS messages; VEC-WS-003/009).
    let ctx = ValidationContext::pre_handshake(ConnectionState::Connected);
    let good = vectors::hex_to_bytes(vectors::NO_LENGTH_PREFIX_GOOD_HEX);
    assert!(decode_frame(&good, ctx).is_ok());
    // Unknown-field suffix tolerated as the same logical frame.
    let mut with_unknown = good.clone();
    with_unknown.extend_from_slice(&vectors::hex_to_bytes(vectors::UNKNOWN_FIELD_SUFFIX_HEX));
    assert!(decode_frame(&with_unknown, ctx).is_ok());
    // Length prefixes and trailing garbage are malformed, never stripped.
    for hex in [
        vectors::VARINT_PREFIXED_HEX,
        vectors::U32_PREFIXED_HEX,
        vectors::SUFFIXED_HEX,
    ] {
        assert!(
            decode_frame(&vectors::hex_to_bytes(hex), ctx).is_err(),
            "must reject {hex}"
        );
    }
    // Control-frame wire snapshots parse (opcodes 0x9/0xA/0x8).
    let ping = vectors::hex_to_bytes(vectors::PING_WIRE_HEX);
    assert_eq!(ping[0], 0x89);
    let pong = vectors::hex_to_bytes(vectors::PONG_WIRE_HEX);
    assert_eq!(pong[0], 0x8A);
    let close_c = vectors::hex_to_bytes(vectors::CLOSE_CLIENT_WIRE_HEX);
    assert_eq!(close_c[0], 0x88);
    let close_h = vectors::hex_to_bytes(vectors::CLOSE_HOST_WIRE_HEX);
    assert_eq!(close_h[0], 0x88);
    assert_eq!(vectors::MAX_FRAME_BYTES, syntra_core::MAX_FRAME_BYTES);
}

#[tokio::test]
async fn live_echo_over_ws() {
    let url = loopback_server(false).await;
    let cfg = syntra_ws::WsConfig::insecure_dev(url);
    let handle = syntra_ws::connect(cfg, vec![], ConnectionConfig::default())
        .await
        .expect("connect+handshake");
    assert_eq!(handle.version, 1);
    assert!(!handle.connection_id.is_empty());
    for payload in [vec![], b"hello ws".to_vec(), vec![0x00, 0xff, 0x7f]] {
        let out = handle
            .connection()
            .call("/example.Echo/Echo", payload.clone(), 3000)
            .await
            .expect("echo");
        assert_eq!(out, payload);
    }
    // Unknown method: terminal UNIMPLEMENTED, connection usable.
    let err = handle
        .connection()
        .call("/example.Nope/Missing", vec![], 3000)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    let out = handle
        .connection()
        .call("/example.Echo/Echo", b"usable".to_vec(), 3000)
        .await
        .expect("usable");
    assert_eq!(out, b"usable");
    handle.close().await;
}

#[tokio::test]
async fn unfragmented_messages_above_64k_and_near_envelope_limit_are_accepted() {
    let cfg = syntra_ws::WsConfig::insecure_dev(loopback_server(false).await);
    let handle = syntra_ws::connect(cfg, vec![], ConnectionConfig::default())
        .await
        .expect("connect+handshake");
    // Tungstenite sends each Binary as one unfragmented WS frame. Leave
    // room for the Syntra request envelope, not just its opaque payload.
    for len in [64 * 1024 + 1, syntra_core::MAX_FRAME_BYTES - 128] {
        let payload = vec![0x5a; len];
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle
                .connection()
                .call("/example.Echo/Echo", payload.clone(), 3000),
        )
        .await
        .expect("bounded echo")
        .expect("legal unfragmented result");
        assert_eq!(out, payload);
    }
    handle.close().await;
}

#[tokio::test]
async fn healthy_pongs_survive_multiple_ping_intervals() {
    let mut cfg = syntra_ws::WsConfig::insecure_dev(loopback_server(false).await);
    cfg.ping_interval = std::time::Duration::from_millis(100);
    cfg.pong_timeout = std::time::Duration::from_millis(40);
    let handle = syntra_ws::connect(cfg, vec![], ConnectionConfig::default())
        .await
        .expect("connect+handshake");
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    assert!(
        !handle.is_closed(),
        "healthy peer must not time out between Pings"
    );
    let out = handle
        .connection()
        .call("/example.Echo/Echo", b"alive".to_vec(), 1000)
        .await
        .expect("usable after multiple Pongs");
    assert_eq!(out, b"alive");
    handle.close().await;
}

/// One owned peer: flush ready, wait for the client-side test to start,
/// send scripted WS frames, then stay silent without polling (and thus
/// without tungstenite's automatic Pong replies). No per-message tasks.
#[allow(clippy::result_large_err)] // Tungstenite fixes the Upgrade callback's error type.
async fn scripted_peer(
    messages: Vec<tokio_tungstenite::tungstenite::Message>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (start_tx, start_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_hdr_async(
            socket,
            |_req: &Request, mut response: Response| {
                response
                    .headers_mut()
                    .insert("sec-websocket-protocol", "syntra.v1".parse().unwrap());
                Ok(response)
            },
        )
        .await
        .unwrap();
        let (host, mut wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            test_handler(),
        );
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(hello))) => {
                    host.ingest(&hello).await;
                    break;
                }
                Some(Ok(Message::Ping(payload))) => ws.send(Message::Pong(payload)).await.unwrap(),
                other => panic!("expected hello, got {other:?}"),
            }
        }
        ws.send(Message::Binary(wrx.recv().await.unwrap().into()))
            .await
            .unwrap();
        if start_rx.await.is_ok() {
            for message in messages {
                if ws.send(message).await.is_err() {
                    break;
                }
            }
            std::future::pending::<()>().await;
        }
        host.on_transport_lost().await;
    });
    (
        format!("ws://127.0.0.1:{port}/syntra/v1/ws"),
        start_tx,
        task,
    )
}

#[tokio::test]
async fn receive_limit_covers_single_frames_and_fragmented_messages() {
    use prost::Message as _;
    use tokio_tungstenite::tungstenite::{
        protocol::frame::{
            coding::{Data, OpCode},
            Frame,
        },
        Message,
    };
    // At this size, each of the two protobuf length prefixes takes three
    // bytes, so the notification envelope adds exactly ten bytes.
    let payload = vec![0x5a; syntra_core::MAX_FRAME_BYTES - 10];
    let at_limit = syntra_core::Frame {
        version: 1,
        request_id: 0,
        body: Some(syntra_core::proto::frame::Body::Notification(
            syntra_core::Notification {
                payload: payload.clone(),
            },
        )),
    }
    .encode_to_vec();
    assert_eq!(at_limit.len(), syntra_core::MAX_FRAME_BYTES);
    // Each fragment is within the per-frame cap, but their sum is MAX+1.
    for fragmented in [false, true] {
        let oversize = vec![0x5a; syntra_core::MAX_FRAME_BYTES + 1];
        let mut messages = vec![Message::Binary(at_limit.clone().into())];
        if fragmented {
            messages.push(Message::Frame(Frame::message(
                oversize[..64 * 1024].to_vec(),
                OpCode::Data(Data::Binary),
                false,
            )));
            messages.push(Message::Frame(Frame::message(
                oversize[64 * 1024..].to_vec(),
                OpCode::Data(Data::Continue),
                true,
            )));
        } else {
            messages.push(Message::Binary(oversize.into()));
        }
        let (url, start, peer) = scripted_peer(messages).await;
        let handle = syntra_ws::connect(
            syntra_ws::WsConfig::insecure_dev(url),
            vec![],
            ConnectionConfig::default(),
        )
        .await
        .expect("connect+handshake");
        let mut closed = handle.connection().subscribe_close();
        start.send(()).unwrap();
        let received = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            handle.connection().next_notification(),
        )
        .await
        .expect("bounded notification")
        .expect("exact-limit notification accepted");
        assert_eq!(received, payload);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            closed.wait_for(|closed| *closed),
        )
        .await
        .expect("oversize closes connection")
        .unwrap();
        peer.abort();
        assert!(peer.await.unwrap_err().is_cancelled());
        handle.close().await;
    }
}

#[tokio::test]
async fn missing_pongs_still_close_a_silent_peer() {
    let (url, start, peer) = scripted_peer(vec![]).await;
    let mut cfg = syntra_ws::WsConfig::insecure_dev(url);
    cfg.ping_interval = std::time::Duration::from_millis(100);
    cfg.pong_timeout = std::time::Duration::from_millis(40);
    let handle = syntra_ws::connect(cfg, vec![], ConnectionConfig::default())
        .await
        .expect("connect+handshake");
    let mut closed = handle.connection().subscribe_close();
    start.send(()).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        closed.wait_for(|closed| *closed),
    )
    .await
    .expect("silent peer times out")
    .unwrap();
    peer.abort();
    assert!(peer.await.unwrap_err().is_cancelled());
    handle.close().await;
}

#[tokio::test]
async fn subprotocol_mismatch_aborts() {
    let url = loopback_server(true).await;
    let cfg = syntra_ws::WsConfig::insecure_dev(url);
    let err = match syntra_ws::connect(cfg, vec![], ConnectionConfig::default()).await {
        Ok(_) => panic!("expected subprotocol failure"),
        Err(e) => e,
    };
    assert!(matches!(err, syntra_ws::TransportError::Subprotocol(_)));
}

#[tokio::test]
async fn text_message_rejected() {
    use syntra_core::ConnectionState;
    // Dedicated server: completes a real handshake via Host, then sends
    // one text message. The client must reject it (binary-only rule).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        use tokio_tungstenite::tungstenite::Message;
        let (stream, _) = listener.accept().await.unwrap();
        let ws =
            tokio_tungstenite::accept_hdr_async(stream, |_req: &Request, mut resp: Response| {
                resp.headers_mut()
                    .insert("sec-websocket-protocol", "syntra.v1".parse().unwrap());
                Ok(resp)
            })
            .await
            .unwrap();
        let (mut sink, mut stream) = ws.split();
        let (host, mut wrx) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            test_handler(),
        );
        // Drive the handshake, then violate with text. The outbound
        // (ready) frame is flushed inline before the violation so no
        // writer task races the test. Ping/Pong/partial frames are
        // transport business and never end the handshake early.
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    host.ingest(&data).await;
                    if host.state().await == ConnectionState::Active {
                        break;
                    }
                }
                Ok(Message::Ping(payload)) => {
                    sink.send(Message::Pong(payload)).await.unwrap();
                }
                Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => {}
                _ => break,
            }
        }
        assert_eq!(host.state().await, ConnectionState::Active);
        while let Ok(bytes) = wrx.try_recv() {
            sink.send(Message::Binary(bytes.into())).await.unwrap();
        }
        sink.send(Message::Text("nope".into())).await.unwrap();
        // The client must tear the transport down; drain until it does.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while stream.next().await.is_some() {}
        })
        .await;
    });
    let url = format!("ws://127.0.0.1:{port}/syntra/v1/ws");
    let cfg = syntra_ws::WsConfig::insecure_dev(url);
    let handle = syntra_ws::connect(cfg, vec![], ConnectionConfig::default())
        .await
        .expect("connect+handshake");
    // After the text violation the client reports transport loss with
    // unknown outcome (never a synthesized success). In-flight RPCs get
    // UNAVAILABLE; new RPCs on the closed connection get Closed.
    let err = loop {
        if handle.connection().is_closed() {
            // New work on a closed connection is rejected as Closed.
            break handle
                .connection()
                .call("/example.Echo/Echo", vec![], 1000)
                .await
                .unwrap_err();
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(
        matches!(err, syntra_core::SyntraError::Closed(_)),
        "unexpected: {err:?}"
    );
}
