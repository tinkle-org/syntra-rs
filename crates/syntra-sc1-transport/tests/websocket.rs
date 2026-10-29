#![cfg(feature = "development-carriers")]
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_runtime::{
    AuthError, Authenticator, ConnectionConfig, FnHandler, Handler, HandlerOutcome, Principal,
    RejectAll,
};
use syntra_sc1_transport::{websocket as sc1, AuthenticatorFactory, Limits};
use syntra_secure_channel::*;

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
                sc1::ENDPOINT_PATH
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
                sc1::accept(
                    &listener,
                    &server,
                    factory,
                    echo(),
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
            });
            let client = sc1::connect(
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
        ("/syntra/v1/ws", sc1::SUBPROTOCOL, false),
        (sc1::ENDPOINT_PATH, "syntra.v1", false),
        (sc1::ENDPOINT_PATH, sc1::SUBPROTOCOL, true),
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
            sc1::accept(
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
async fn development_ws_rejects_non_loopback_and_secure_carrier() {
    use syntra_sc1_transport::Error as TransportError;
    for url in [
        "ws://192.0.2.1/syntra/v1/sc1/ws",
        "ws://example.invalid/syntra/v1/sc1/ws",
        "ws://127.0.0.1.example.invalid/syntra/v1/sc1/ws",
        "ws://[::ffff:192.0.2.1]/syntra/v1/sc1/ws",
    ] {
        let (client, _) = configs(Mode::Bootstrap);
        let result = sc1::connect(
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
        sc1::ENDPOINT_PATH
    );
    let (mut client, mut server) = configs(Mode::Bootstrap);
    client.context.carrier = Carrier::SecureWebSocket;
    server.carrier = Carrier::SecureWebSocket;
    assert!(matches!(
        sc1::connect(
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
        sc1::accept(
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
        sc1::accept_stream(
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
