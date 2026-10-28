//! Opt-in real-browser peer; see syntra-web/tests/browser.md.
#![cfg(not(target_arch = "wasm32"))]

use futures_util::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use syntra_runtime::{AllowAnonymous, ConnectionConfig, FnHandler, HandlerOutcome, Host};
use tokio::io::AsyncReadExt;
use tokio_tungstenite::tungstenite::{
    handshake::server::{Request, Response},
    Message,
};

#[allow(clippy::result_large_err)]
async fn fixture(listener: tokio::net::TcpListener, oversize: bool) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_hdr_async(socket, |req: &Request, mut res: Response| {
        assert_eq!(req.uri().path(), "/syntra/v1/ws");
        assert_eq!(req.headers()["sec-websocket-protocol"], "syntra.v1");
        res.headers_mut()
            .insert("sec-websocket-protocol", "syntra.v1".parse().unwrap());
        Ok(res)
    })
    .await
    .unwrap();
    let (host, mut outgoing) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|method: String, payload, _| async move {
            if method == "/example.Echo/Echo" {
                HandlerOutcome::Payload(payload)
            } else {
                HandlerOutcome::error(syntra_core::ErrorCode::Unimplemented, "unknown method")
            }
        })),
    );
    let mut send_oversize = oversize;
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                host.ingest(&bytes).await;
                if host.is_closed() {
                    break;
                }
                ws.send(Message::Binary(outgoing.recv().await.unwrap().into()))
                    .await
                    .unwrap();
                if send_oversize {
                    send_oversize = false;
                    // Give the browser API caller time to begin polling.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    ws.send(Message::Binary(
                        vec![0; syntra_core::MAX_FRAME_BYTES + 1].into(),
                    ))
                    .await
                    .unwrap();
                }
            }
            Some(Ok(Message::Ping(_))) => {
                let _ = ws.flush().await;
            }
            Some(Ok(Message::Close(_))) => {
                let _ = ws.flush().await;
                break;
            }
            Some(Ok(_)) => {}
            _ => break,
        }
    }
    host.on_transport_lost().await;
}

#[tokio::test]
#[ignore = "requires configured trusted WSS proxy and real browser; see syntra-web/tests/browser.md"]
async fn configured_real_browser_fixture() {
    let normal = tokio::net::TcpListener::bind("127.0.0.1:19781")
        .await
        .unwrap();
    let oversize = tokio::net::TcpListener::bind("127.0.0.1:19782")
        .await
        .unwrap();
    let stall = tokio::net::TcpListener::bind("127.0.0.1:19783")
        .await
        .unwrap();
    eprintln!("Browser fixtures ready on loopback ports 19781/19782/19783 (60s budget)");
    // Three bounded, directly owned futures, no detached per-message work.
    tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(fixture(normal, false), fixture(oversize, true), async {
            let (mut socket, _) = stall.accept().await.unwrap();
            let mut bytes = [0u8; 8192];
            // Never send a 101. Browser must cancel its connection attempt
            // at connect_timeout, before any Syntra hello can be sent.
            while socket.read(&mut bytes).await.unwrap_or(0) != 0 {}
        });
    })
    .await
    .expect("browser fixture run exceeded 60 seconds");
}
