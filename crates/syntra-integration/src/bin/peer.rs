//! Minimal SC1 echo peer for container integration tests.
//! Reads provisioning from the environment; never generates production keys.
use std::sync::Arc;
use syntra_core::ErrorCode;
use syntra_runtime::{ConnectionConfig, FnHandler, HandlerOutcome, StaticToken};
use syntra_sc1_transport::{tcp, websocket, HostHandle, Limits};
use syntra_secure_channel::{Carrier, Mode, Secret32, ServerConfig};

fn hex_to_32(s: &str) -> [u8; 32] {
    let s = s.trim();
    assert_eq!(s.len(), 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

fn hex_to_8(s: &str) -> [u8; 8] {
    let s = s.trim();
    assert_eq!(s.len(), 16, "expected 16 hex chars");
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();
    let tcp_addr = std::env::var("SC1_TCP_ADDR").unwrap_or_else(|_| "0.0.0.0:7001".into());
    let ws_addr = std::env::var("SC1_WS_ADDR").unwrap_or_else(|_| "0.0.0.0:7002".into());
    let private_hex = std::env::var("SC1_PRIVATE_HEX").expect("SC1_PRIVATE_HEX");
    let scope = std::env::var("SC1_SCOPE").unwrap_or_else(|_| "integration".into());
    let ak_hex = std::env::var("SC1_AK_HEX").unwrap_or_default();
    let handle_hex = std::env::var("SC1_HANDLE_HEX").unwrap_or_default();
    let epoch: u64 = std::env::var("SC1_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let private_key = Secret32::new(hex_to_32(&private_hex));
    let returning = !ak_hex.is_empty();
    let mode = if returning {
        Mode::Returning
    } else {
        Mode::Bootstrap
    };
    let store: Option<Arc<dyn syntra_secure_channel::KeyStore>> = if returning {
        struct Fixed {
            key: [u8; 32],
            handle: [u8; 8],
            epoch: u64,
        }
        impl syntra_secure_channel::KeyStore for Fixed {
            fn lookup(
                &self,
                ctx: &syntra_secure_channel::Context,
            ) -> Result<Secret32, syntra_secure_channel::Error> {
                if ctx.handle == self.handle && ctx.epoch == self.epoch {
                    Ok(Secret32::new(self.key))
                } else {
                    Err(syntra_secure_channel::Error::Authentication)
                }
            }
        }
        Some(Arc::new(Fixed {
            key: hex_to_32(&ak_hex),
            handle: hex_to_8(&handle_hex),
            epoch,
        }))
    } else {
        None
    };

    let tcp_config = Arc::new(ServerConfig {
        mode,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: scope.as_bytes().to_vec(),
        private_key: Secret32::new(*private_key.expose()),
        store: store.clone(),
    });
    let ws_config = Arc::new(ServerConfig {
        mode,
        carrier: Carrier::WebSocket,
        server_key_id: 1,
        scope: scope.as_bytes().to_vec(),
        private_key: Secret32::new(*private_key.expose()),
        store,
    });

    let handler = Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, _| async move {
            eprintln!("peer tcp handler: {method} {} bytes", payload.len());
            if method == "/test.Denied/Denied" {
                HandlerOutcome::Error {
                    code: ErrorCode::PermissionDenied,
                    message: "denied".into(),
                }
            } else {
                HandlerOutcome::Payload(payload)
            }
        },
    ));
    let factory = {
        let credential = b"test-credential".to_vec();
        Arc::new(
            move |identity: &syntra_secure_channel::VerifiedIdentity|
                  -> Result<Arc<dyn syntra_runtime::Authenticator>, syntra_runtime::AuthError> {
                eprintln!(
                    "peer tcp factory: mode={:?} carrier={:?}",
                    identity.context().mode,
                    identity.context().carrier
                );
                Ok(Arc::new(StaticToken::new(
                    credential.clone(),
                    "test-principal",
                )))
            },
        )
    };

    let tcp_listener = tcp::Listener::bind(tcp_addr.clone(), 64).await?;
    println!("peer tcp ready on {tcp_addr}");
    let ws_listener = tokio::net::TcpListener::bind(ws_addr.clone()).await?;
    println!("peer ws ready on {ws_addr}");

    let tcp_task = tokio::spawn(async move {
        let handles: Arc<tokio::sync::Mutex<Vec<HostHandle>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        loop {
            // Admit the socket first and shake each hand in its own task:
            // a slow client must not block subsequent accepts.
            let stream = match tcp_listener.accept_socket().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("tcp accept failed: {e:?}");
                    continue;
                }
            };
            let (factory, handler, handles, tcp_config) = (
                factory.clone(),
                handler.clone(),
                handles.clone(),
                tcp_config.clone(),
            );
            tokio::spawn(async move {
                match tcp::accept_stream(
                    stream,
                    &tcp_config,
                    factory,
                    handler,
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
                {
                    Ok(h) => {
                        eprintln!("peer tcp accepted");
                        let mut handles = handles.lock().await;
                        handles.push(h);
                        if handles.len() > 4096 {
                            handles.remove(0);
                        }
                    }
                    Err(e) => {
                        eprintln!("tcp handshake failed: {e:?}");
                    }
                }
            });
        }
    });

    let ws_factory = {
        let credential = b"test-credential".to_vec();
        Arc::new(
            move |_: &syntra_secure_channel::VerifiedIdentity|
                  -> Result<Arc<dyn syntra_runtime::Authenticator>, syntra_runtime::AuthError> {
                Ok(Arc::new(StaticToken::new(
                    credential.clone(),
                    "test-principal",
                )))
            },
        )
    };
    let ws_handler = Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, _| async move {
            if method == "/test.Denied/Denied" {
                HandlerOutcome::Error {
                    code: ErrorCode::PermissionDenied,
                    message: "denied".into(),
                }
            } else {
                HandlerOutcome::Payload(payload)
            }
        },
    ));
    let ws_task = tokio::spawn(async move {
        let handles: Arc<tokio::sync::Mutex<Vec<HostHandle>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        loop {
            // Same split as TCP: admit first, shake each hand concurrently
            // so a slow client cannot block subsequent accepts.
            let (socket, _) = match ws_listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("ws accept failed: {e:?}");
                    continue;
                }
            };
            if let Err(e) = socket.set_nodelay(true) {
                eprintln!("ws nodelay failed: {e:?}");
                continue;
            }
            let (ws_factory, ws_handler, handles, ws_config) = (
                ws_factory.clone(),
                ws_handler.clone(),
                handles.clone(),
                ws_config.clone(),
            );
            tokio::spawn(async move {
                let res = websocket::accept_stream(
                    socket,
                    &ws_config,
                    ws_factory,
                    ws_handler,
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await;
                match res {
                    Ok(h) => {
                        eprintln!("peer ws accepted");
                        let mut handles = handles.lock().await;
                        handles.push(h);
                        if handles.len() > 4096 {
                            handles.remove(0);
                        }
                    }
                    Err(e) => {
                        eprintln!("ws handshake failed: {e:?}");
                    }
                }
            });
        }
    });

    let _ = tokio::join!(tcp_task, ws_task);
    Ok(())
}
