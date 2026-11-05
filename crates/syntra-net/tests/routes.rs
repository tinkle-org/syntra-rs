//! Local, same-library composition regressions, not independent interoperability.
#![cfg(all(feature = "tcp", not(target_arch = "wasm32")))]

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32, ServerConfig,
};
use syntra_net::{
    routes::{client_routes, Endpoint, Route, RouteConfig, MAX_ROUTES},
    Error, Limits,
};
use syntra_runtime::ConnectionConfig;

fn config(routes: Vec<Route>, allowlist: Vec<Endpoint>) -> RouteConfig {
    RouteConfig {
        routes,
        allowlist,
        runtime: ConnectionConfig::default(),
        limits: Limits::default(),
    }
}

fn local(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}

struct Store;
impl KeyStore for Store {
    fn lookup(&self, context: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        if context.handle == [4; 8] && context.epoch == 9 {
            Ok(Secret32::new([3; 32]))
        } else {
            Err(syntra_core::secure_channel::Error::Authentication)
        }
    }
}

struct Trust {
    server: Arc<ServerConfig>,
    public: [u8; 32],
}
impl Trust {
    fn new(carrier: Carrier, mode: Mode) -> Self {
        let (private_key, public) = generate_server_key().unwrap();
        Self {
            server: Arc::new(ServerConfig {
                mode,
                carrier,
                server_key_id: 1,
                scope: b"route-fixture".to_vec(),
                private_key,
                store: Some(Arc::new(Store)),
            }),
            public,
        }
    }

    fn inputs(
        &self,
        calls: Arc<AtomicUsize>,
    ) -> impl Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static {
        let public = self.public;
        let mode = self.server.mode;
        let carrier = self.server.carrier;
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let returning = mode == Mode::Returning;
            Ok((
                ClientConfig {
                    context: Context {
                        mode,
                        carrier,
                        server_key_id: 1,
                        scope: b"route-fixture".to_vec(),
                        handle: if returning { [4; 8] } else { [0; 8] },
                        epoch: if returning { 9 } else { 0 },
                    },
                    server_public_key: public,
                    authorization_key: returning.then(|| Secret32::new([3; 32])),
                },
                b"explicit-hello-credential".to_vec(),
            ))
        }
    }
}

#[test]
fn entire_configuration_and_allowlist_are_validated_without_inputs_or_runtime() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let reject = |cfg| {
        assert!(matches!(
            client_routes(cfg, || panic!("inputs before validation")),
            Err(Error::Configuration)
        ));
    };
    reject(config(vec![], vec![Endpoint::Tcp(local(1))]));
    reject(config(vec![Route::Tcp(local(1))], vec![]));
    reject(config(
        vec![Route::Tcp(local(1))],
        vec![Endpoint::Tcp(local(2))],
    ));
    for invalid in [
        local(0),
        "0.0.0.0:80".parse().unwrap(),
        "224.0.0.1:80".parse().unwrap(),
        "[::]:80".parse().unwrap(),
    ] {
        // Reject an invalid later route and even an unused invalid allowlist entry.
        reject(config(
            vec![Route::Tcp(local(1)), Route::Tcp(invalid)],
            vec![Endpoint::Tcp(local(1)), Endpoint::Tcp(invalid)],
        ));
        reject(config(
            vec![Route::Tcp(local(1))],
            vec![Endpoint::Tcp(local(1)), Endpoint::Tcp(invalid)],
        ));
    }
    reject(config(
        vec![Route::Tcp(local(1)); MAX_ROUTES + 1],
        vec![Endpoint::Tcp(local(1))],
    ));
    reject(config(
        vec![Route::Tcp(local(1))],
        vec![Endpoint::Tcp(local(1)); MAX_ROUTES + 1],
    ));
    let mut cfg = config(vec![Route::Tcp(local(1))], vec![Endpoint::Tcp(local(1))]);
    cfg.limits.attempt_timeout = Duration::ZERO;
    reject(cfg);
    let calls = Arc::new(AtomicUsize::new(0));
    let connector = client_routes(
        config(vec![Route::Tcp(local(1))], vec![Endpoint::Tcp(local(1))]),
        {
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(Error::Authentication)
            }
        },
    )
    .unwrap();
    drop(connector());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "unpolled futures do not consume inputs"
    );
}

#[tokio::test]
async fn returned_carrier_mismatch_is_rejected_before_socket_accept() {
    let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let trust = Trust::new(Carrier::SecureWebSocket, Mode::Bootstrap);
    let connector = client_routes(
        config(vec![Route::Tcp(address)], vec![Endpoint::Tcp(address)]),
        trust.inputs(calls.clone()),
    )
    .unwrap();
    assert!(matches!(connector().await, Err(Error::Configuration)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn round_robin_is_one_attempt_per_poll_and_preserves_input_errors() {
    let a = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let b = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let endpoints = vec![
        Endpoint::Tcp(a.local_addr().unwrap()),
        Endpoint::Tcp(b.local_addr().unwrap()),
    ];
    let routes = vec![
        Route::Tcp(a.local_addr().unwrap()),
        Route::Tcp(b.local_addr().unwrap()),
    ];
    let trust = Trust::new(Carrier::Tcp, Mode::Returning);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut cfg = config(routes, endpoints);
    cfg.limits.attempt_timeout = Duration::from_millis(60);
    let connector = client_routes(cfg, trust.inputs(calls.clone())).unwrap();
    drop(connector());
    for listener in [&a, &b, &a] {
        let future = connector();
        let peer = async {
            use tokio::io::AsyncReadExt;
            let (mut socket, _) = listener.accept().await.unwrap();
            // Consume M1 then observe EOF when the single attempt expires.
            let length = socket.read_u16().await.unwrap();
            let mut m1 = vec![0; length as usize];
            socket.read_exact(&mut m1).await.unwrap();
            assert_eq!(
                socket.read_u8().await.unwrap_err().kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        };
        let (result, ()) = tokio::join!(future, peer);
        assert!(matches!(result, Err(Error::Timeout)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let connector = client_routes(
        config(
            vec![Route::Tcp(a.local_addr().unwrap())],
            vec![Endpoint::Tcp(a.local_addr().unwrap())],
        ),
        || Err(Error::Authentication),
    )
    .unwrap();
    assert!(matches!(connector().await, Err(Error::Authentication)));
}

#[cfg(any(feature = "websocket", feature = "http"))]
mod web {
    use super::*;
    use syntra_net::tls::{
        BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata, TlsProvider,
        TlsRole,
    };

    pub struct ApplicationTls {
        pub client: Arc<rustls::ClientConfig>,
        pub server: Arc<rustls::ServerConfig>,
        pub calls: AtomicUsize,
    }
    impl ApplicationTls {
        pub fn new() -> Self {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.cert.der().clone()).unwrap();
            let crypto = Arc::new(rustls::crypto::ring::default_provider());
            let mut client = rustls::ClientConfig::builder_with_provider(crypto.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client.enable_early_data = false;
            client.resumption = rustls::client::Resumption::disabled();
            client.alpn_protocols = vec![b"http/1.1".to_vec()];
            let mut server = rustls::ServerConfig::builder_with_provider(crypto)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                        .into(),
                )
                .unwrap();
            server.max_early_data_size = 0;
            server.alpn_protocols = vec![b"http/1.1".to_vec()];
            Self {
                client: Arc::new(client),
                server: Arc::new(server),
                calls: AtomicUsize::new(0),
            }
        }
    }
    // Real TLS 1.3; chain/name/current-validity verification is rustls's ordinary
    // verifier with only this local fixture root. No global trust store changes.
    impl TlsProvider for ApplicationTls {
        fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let name = rustls::pki_types::ServerName::try_from(authority.host().to_owned())
                    .map_err(|_| Error::Configuration)?;
                let stream = tokio_rustls::TlsConnector::from(self.client.clone())
                    .connect(name, stream)
                    .await
                    .map_err(|_| Error::Configuration)?;
                let session = stream.get_ref().1;
                let metadata = TlsMetadata {
                    authority,
                    role: TlsRole::Client,
                    protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                    alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                    early_data: if self.client.enable_early_data || session.is_early_data_accepted()
                    {
                        EarlyData::Enabled
                    } else {
                        EarlyData::Disabled
                    },
                };
                Ok(ProviderTlsStream::new(Box::new(stream), metadata))
            })
        }
        fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
            Box::pin(async move {
                assert_eq!(authority.host(), "localhost");
                let stream = tokio_rustls::TlsAcceptor::from(self.server.clone())
                    .accept(stream)
                    .await
                    .map_err(|_| Error::Configuration)?;
                let session = stream.get_ref().1;
                assert_eq!(session.server_name(), Some("localhost"));
                let metadata = TlsMetadata {
                    authority,
                    role: TlsRole::Server,
                    protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                    alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                    early_data: if self.server.max_early_data_size == 0 {
                        EarlyData::Disabled
                    } else {
                        EarlyData::Enabled
                    },
                };
                Ok(ProviderTlsStream::new(Box::new(stream), metadata))
            })
        }
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn strict_urls_carriers_loopback_and_redacted_debug_before_callbacks() {
        let provider = Arc::new(ApplicationTls::new());
        for url in [
            "https://localhost/syntra/1.0/ws",
            "http://localhost/syntra/1.0/ws",
            "ws://localhost/syntra/1.0/ws",
            "wss://localhost/wrong",
            "wss://user:secret@localhost/syntra/1.0/ws",
            "wss://@localhost/syntra/1.0/ws",
            "wss://localhost/syntra/1.0/ws?",
            "wss://localhost/syntra/1.0/ws#",
            "wss://localhost/else/../syntra/1.0/ws",
            "wss://localhost/%2e/syntra/1.0/ws",
            " wss://localhost/syntra/1.0/ws",
            "wss://localhost/syntra/1.0/ws\n",
            "wss://localhost\\syntra/1.0/ws",
            "wss://localhost/syntra/1.0/%77s",
            "wss://0.0.0.0/syntra/1.0/ws",
            "wss://localhost:0/syntra/1.0/ws",
        ] {
            let route = Route::Wss {
                address: local(1),
                url: url.into(),
                provider: provider.clone(),
            };
            let cfg = config(vec![route.clone()], vec![route.endpoint()]);
            assert!(!format!("{cfg:?}").contains("secret"));
            assert!(
                matches!(
                    client_routes(cfg, || panic!("invalid URL inputs")),
                    Err(Error::Configuration)
                ),
                "{url:?}"
            );
        }
        let ws = Route::Ws {
            address: local(1),
            url: "ws://localhost/syntra/1.0/ws".into(),
        };
        let wss = Route::Wss {
            address: local(1),
            url: "wss://localhost/syntra/1.0/ws".into(),
            provider: provider.clone(),
        };
        let explicit_port = Route::Wss {
            address: local(1),
            url: "wss://localhost:443/syntra/1.0/ws".into(),
            provider: provider.clone(),
        };
        assert!(client_routes(
            config(vec![explicit_port.clone()], vec![explicit_port.endpoint()]),
            || panic!("validation must not invoke inputs")
        )
        .is_ok());
        let oversized = Endpoint::Wss {
            address: local(1),
            url: format!("wss://{}/syntra/1.0/ws", "a".repeat(2048)),
        };
        for cfg in [
            config(
                vec![Route::Tcp(local(1)), ws.clone()],
                vec![Endpoint::Tcp(local(1)), ws.endpoint()],
            ),
            config(
                vec![wss.clone(), ws.clone()],
                vec![wss.endpoint(), ws.endpoint()],
            ),
            config(vec![wss.clone()], vec![wss.endpoint(), ws.endpoint()]),
            config(vec![wss.clone()], vec![wss.endpoint(), oversized]),
            config(
                vec![Route::Ws {
                    address: "192.0.2.1:80".parse().unwrap(),
                    url: "ws://localhost/syntra/1.0/ws".into(),
                }],
                vec![ws.endpoint()],
            ),
            config(
                vec![Route::Ws {
                    address: local(1),
                    url: "ws://not-local.invalid/syntra/1.0/ws".into(),
                }],
                vec![ws.endpoint()],
            ),
        ] {
            assert!(matches!(
                client_routes(cfg, || panic!("mixed carrier inputs")),
                Err(Error::Configuration)
            ));
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);

        // The invalid endpoint must fail on its own merits, not merely because
        // its address/URL differs from a valid allowlist entry.
        for route in [
            Route::Ws {
                address: "192.0.2.1:80".parse().unwrap(),
                url: "ws://localhost/syntra/1.0/ws".into(),
            },
            Route::Ws {
                address: local(1),
                url: "ws://not-local.invalid/syntra/1.0/ws".into(),
            },
        ] {
            assert!(matches!(
                client_routes(config(vec![route.clone()], vec![route.endpoint()]), || {
                    panic!("non-loopback inputs")
                }),
                Err(Error::Configuration)
            ));
        }
    }

    #[cfg(all(feature = "websocket", feature = "proxy"))]
    #[test]
    fn tunnel_authority_must_match_url_and_ws_proxy_is_not_accepted() {
        use syntra_net::proxy::{ProxyConfig, ProxyCredentials, ProxyTarget};
        let provider = Arc::new(ApplicationTls::new());
        let proxy = Arc::new(
            ProxyConfig::socks5(
                local(1),
                Some(
                    ProxyCredentials::new(b"proxy-user".to_vec(), b"proxy-secret".to_vec())
                        .unwrap(),
                ),
            )
            .unwrap(),
        );
        let invalid_tcp_target = Route::TcpProxy {
            proxy: proxy.clone(),
            target: ProxyTarget::ip("0.0.0.0".parse().unwrap(), 80).unwrap(),
        };
        assert!(matches!(
            client_routes(
                config(
                    vec![invalid_tcp_target.clone()],
                    vec![invalid_tcp_target.endpoint()]
                ),
                || panic!("invalid proxy destination inputs")
            ),
            Err(Error::Configuration)
        ));
        for target in [
            ProxyTarget::hostname("other.invalid", 443).unwrap(),
            ProxyTarget::hostname("localhost", 444).unwrap(),
            ProxyTarget::ip(local(443).ip(), 443).unwrap(),
        ] {
            let route = Route::WssProxy {
                proxy: proxy.clone(),
                target,
                url: "wss://localhost/syntra/1.0/ws".into(),
                provider: provider.clone(),
            };
            let cfg = config(vec![route.clone()], vec![route.endpoint()]);
            assert!(!format!("{cfg:?}").contains("proxy-secret"));
            assert!(matches!(
                client_routes(cfg, || panic!("authority mismatch inputs")),
                Err(Error::Configuration)
            ));
        }
        let route = Route::WssProxy {
            proxy,
            target: ProxyTarget::hostname("localhost", 80).unwrap(),
            url: "ws://localhost/syntra/1.0/ws".into(),
            provider,
        };
        assert!(matches!(
            client_routes(
                config(vec![route.clone()], vec![route.endpoint()]),
                || panic!("WS proxy inputs")
            ),
            Err(Error::Configuration)
        ));
    }
}

#[cfg(feature = "managed")]
mod managed {
    use super::*;
    use std::{thread, time::Instant};
    use syntra_core::secure_channel::VerifiedIdentity;
    #[cfg(feature = "websocket")]
    use syntra_net::client::Failure;
    use syntra_net::{
        client::{LifecycleStatus, ReconnectConfig},
        network::{
            Admission, ManagedClient, ManagedServer, Network, NetworkConfig, Operation,
            TcpServerConfig,
        },
        AuthenticatorFactory,
    };
    use syntra_runtime::{
        AuthError, Authenticator, FnHandler, Handler, HandlerOutcome, StaticToken,
    };
    const WAIT: Duration = Duration::from_secs(8);
    pub fn receive<T>(operation: Operation<T>) -> T {
        operation.wait(WAIT).unwrap()
    }
    pub fn until(mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !predicate() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn reconnect() -> ReconnectConfig {
        ReconnectConfig {
            attempt_timeout: Duration::from_secs(3),
            reconnect_budget: Duration::from_secs(20),
            max_attempts: 10,
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(30),
            close_timeout: Duration::from_secs(1),
            start_paused: false,
            initial_network_available: true,
        }
    }
    fn factory() -> Arc<dyn AuthenticatorFactory> {
        Arc::new(
            |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                Ok(Arc::new(StaticToken::new(
                    b"explicit-hello-credential".to_vec(),
                    "local-route-principal",
                )))
            },
        )
    }
    fn echo() -> Arc<dyn Handler> {
        // Explicit test-only allow-all policy, after explicit hello authentication.
        Arc::new(FnHandler(|_, payload, _| async move {
            HandlerOutcome::Payload(payload)
        }))
    }
    fn listen_tcp(network: &Network, trust: &Trust) -> ManagedServer {
        receive(
            network
                .listen_tcp(TcpServerConfig {
                    address: local(0),
                    admission: Admission::new(4).unwrap(),
                    security: trust.server.clone(),
                    authenticator: factory(),
                    handler: echo(),
                    runtime: ConnectionConfig::default(),
                    limits: Limits::default(),
                })
                .unwrap(),
        )
        .unwrap()
    }
    fn connect(
        network: &Network,
        trust: &Trust,
        routes: Vec<Route>,
        calls: Arc<AtomicUsize>,
    ) -> ManagedClient {
        let allowlist = routes.iter().map(Route::endpoint).collect();
        let connector = client_routes(config(routes, allowlist), trust.inputs(calls)).unwrap();
        receive(network.client(reconnect(), connector).unwrap()).unwrap()
    }
    fn rpc(client: &ManagedClient) {
        until(|| matches!(client.status(), LifecycleStatus::CoreReady(_)));
        let payload = vec![0xa7; 150_000];
        let reply = receive(
            client
                .call("/test.Service/Echo".into(), payload.clone(), 3000)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reply.value, payload);
    }
    fn shutdown(network: &mut Network) {
        let report = network.shutdown(WAIT);
        assert!(report.complete, "{report:?}");
        assert_eq!(report.failed_supervisors, 0);
    }

    #[test]
    fn std_managed_tcp_both_modes_failover_fresh_inputs_and_owned_shutdown() {
        assert!(tokio::runtime::Handle::try_current().is_err());
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let mut network = Network::new(NetworkConfig::default()).unwrap();
            let trust = Trust::new(Carrier::Tcp, mode);
            let server = listen_tcp(&network, &trust);
            // A bound but non-listening socket is not available in std; retain a
            // just-released loopback port solely as a local refused-dial fixture.
            let refused = std::net::TcpListener::bind(local(0)).unwrap();
            let address = refused.local_addr().unwrap();
            drop(refused);
            let calls = Arc::new(AtomicUsize::new(0));
            let client = connect(
                &network,
                &trust,
                vec![Route::Tcp(address), Route::Tcp(server.local_addr())],
                calls.clone(),
            );
            rpc(&client);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            client.pause();
            until(|| client.status() == LifecycleStatus::Paused);
            client.resume();
            rpc(&client);
            assert_eq!(calls.load(Ordering::SeqCst), 4);
            shutdown(&mut network);
        }
    }

    #[cfg(feature = "websocket")]
    fn listen_web(
        network: &Network,
        trust: &Trust,
        tls: syntra_net::network::WebSocketTls,
    ) -> ManagedServer {
        let cfg = syntra_net::network::WebSocketServerConfig {
            address: local(0),
            admission: Admission::new(4).unwrap(),
            security: trust.server.clone(),
            authenticator: factory(),
            handler: echo(),
            runtime: ConnectionConfig::default(),
            limits: Limits::default(),
            tls,
        };
        let operation = if trust.server.carrier == Carrier::WebSocket {
            network.listen_ws(cfg)
        } else {
            network.listen_wss(cfg)
        };
        receive(operation.unwrap()).unwrap()
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn std_managed_ws_and_real_provider_wss_rpc_both_modes() {
        use super::web::ApplicationTls;
        use syntra_net::{network::WebSocketTls, tls::TlsAuthority};
        assert!(tokio::runtime::Handle::try_current().is_err());
        for mode in [Mode::Bootstrap, Mode::Returning] {
            for carrier in [Carrier::WebSocket, Carrier::SecureWebSocket] {
                let mut network = Network::new(NetworkConfig::default()).unwrap();
                let trust = Trust::new(carrier, mode);
                let provider = Arc::new(ApplicationTls::new());
                let tls = if carrier == Carrier::WebSocket {
                    WebSocketTls::Loopback
                } else {
                    WebSocketTls::Provider {
                        provider: provider.clone(),
                        authority: TlsAuthority::new("localhost", 443).unwrap(),
                    }
                };
                let server = listen_web(&network, &trust, tls);
                let route = if carrier == Carrier::WebSocket {
                    Route::Ws {
                        address: server.local_addr(),
                        url: format!(
                            "ws://localhost:{}/syntra/1.0/ws",
                            server.local_addr().port()
                        ),
                    }
                } else {
                    Route::Wss {
                        address: server.local_addr(),
                        url: "wss://localhost/syntra/1.0/ws".into(),
                        provider: provider.clone(),
                    }
                };
                let calls = Arc::new(AtomicUsize::new(0));
                let client = connect(&network, &trust, vec![route], calls.clone());
                rpc(&client);
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                assert_eq!(
                    provider.calls.load(Ordering::SeqCst),
                    usize::from(carrier == Carrier::SecureWebSocket)
                );
                shutdown(&mut network);
            }
        }
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn real_tls_wrong_peer_trust_blocks_without_trying_allowlisted_successor() {
        use super::web::ApplicationTls;
        use syntra_net::{network::WebSocketTls, tls::TlsAuthority};
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let trust = Trust::new(Carrier::SecureWebSocket, Mode::Bootstrap);
        let provider = Arc::new(ApplicationTls::new());
        let server = listen_web(
            &network,
            &trust,
            WebSocketTls::Provider {
                provider: provider.clone(),
                authority: TlsAuthority::new("localhost", 443).unwrap(),
            },
        );
        // Independently generated certificate/root: real TLS fails before Upgrade.
        let untrusted = Arc::new(ApplicationTls::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let client = connect(
            &network,
            &trust,
            vec![
                Route::Wss {
                    address: server.local_addr(),
                    url: "wss://localhost/syntra/1.0/ws".into(),
                    provider: untrusted.clone(),
                },
                Route::Wss {
                    address: server.local_addr(),
                    url: "wss://localhost/syntra/1.0/ws".into(),
                    provider: provider.clone(),
                },
            ],
            calls.clone(),
        );
        until(|| {
            matches!(
                client.status(),
                LifecycleStatus::Blocked(Failure::Configuration)
            )
        });
        thread::sleep(Duration::from_millis(100));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(untrusted.calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.status().ready, 0);
        shutdown(&mut network);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn std_managed_socks_and_connect_tcp_rpc_both_modes() {
        use super::proxies::ScriptedProxy;
        use syntra_net::proxy::{ProxyKind, ProxyTarget};
        for mode in [Mode::Bootstrap, Mode::Returning] {
            for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
                let mut network = Network::new(NetworkConfig::default()).unwrap();
                let trust = Trust::new(Carrier::Tcp, mode);
                let server = listen_tcp(&network, &trust);
                let target =
                    ProxyTarget::ip(server.local_addr().ip(), server.local_addr().port()).unwrap();
                let proxy = ScriptedProxy::new(kind, target.clone(), server.local_addr());
                let route = Route::TcpProxy {
                    proxy: proxy.config(),
                    target,
                };
                let client = connect(&network, &trust, vec![route], Arc::new(AtomicUsize::new(0)));
                rpc(&client);
                shutdown(&mut network);
                proxy.join();
            }
        }
    }

    #[cfg(all(feature = "websocket", feature = "proxy"))]
    #[test]
    fn std_managed_socks_and_connect_real_wss_rpc_both_modes() {
        use super::{proxies::ScriptedProxy, web::ApplicationTls};
        use syntra_net::{
            network::WebSocketTls,
            proxy::{ProxyKind, ProxyTarget},
            tls::TlsAuthority,
        };
        assert!(tokio::runtime::Handle::try_current().is_err());
        for mode in [Mode::Bootstrap, Mode::Returning] {
            for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
                let mut network = Network::new(NetworkConfig::default()).unwrap();
                let trust = Trust::new(Carrier::SecureWebSocket, mode);
                let provider = Arc::new(ApplicationTls::new());
                let server = listen_web(
                    &network,
                    &trust,
                    WebSocketTls::Provider {
                        provider: provider.clone(),
                        authority: TlsAuthority::new("localhost", 443).unwrap(),
                    },
                );
                let target = ProxyTarget::hostname("localhost", 443).unwrap();
                let proxy = ScriptedProxy::new(kind, target.clone(), server.local_addr());
                let route = Route::WssProxy {
                    proxy: proxy.config(),
                    target,
                    url: "wss://localhost/syntra/1.0/ws".into(),
                    provider: provider.clone(),
                };
                let client = connect(&network, &trust, vec![route], Arc::new(AtomicUsize::new(0)));
                rpc(&client);
                assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
                shutdown(&mut network);
                proxy.join();
            }
        }
    }
}

#[cfg(all(feature = "managed", feature = "proxy"))]
mod proxies {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        thread,
    };
    use syntra_net::proxy::{ProxyConfig, ProxyCredentials, ProxyKind, ProxyTarget};

    pub struct ScriptedProxy {
        address: SocketAddr,
        kind: ProxyKind,
        owner: thread::JoinHandle<()>,
    }
    impl ScriptedProxy {
        pub fn new(kind: ProxyKind, target: ProxyTarget, destination: SocketAddr) -> Self {
            let listener = TcpListener::bind(local(0)).unwrap();
            let address = listener.local_addr().unwrap();
            let owner = thread::spawn(move || {
                listener.set_nonblocking(true).unwrap();
                let mut accepted = None;
                managed::until(|| match listener.accept() {
                    Ok((stream, _)) => {
                        accepted = Some(stream);
                        true
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                    Err(error) => panic!("{error}"),
                });
                let mut incoming = accepted.unwrap();
                incoming.set_nonblocking(false).unwrap();
                incoming
                    .set_read_timeout(Some(Duration::from_secs(8)))
                    .unwrap();
                incoming
                    .set_write_timeout(Some(Duration::from_secs(8)))
                    .unwrap();
                match kind {
                    ProxyKind::Socks5 => {
                        let mut greeting = [0; 3];
                        incoming.read_exact(&mut greeting).unwrap();
                        assert_eq!(greeting, [5, 1, 2]);
                        incoming.write_all(&[5, 2]).unwrap();
                        let mut auth = [0; 2];
                        incoming.read_exact(&mut auth).unwrap();
                        assert_eq!(auth, [1, 1]);
                        let mut rest = [0; 3];
                        incoming.read_exact(&mut rest).unwrap();
                        assert_eq!(rest, [b'u', 1, b'p']);
                        incoming.write_all(&[1, 0]).unwrap();
                        let mut request = [0; 4];
                        incoming.read_exact(&mut request).unwrap();
                        assert_eq!(&request[..3], &[5, 1, 0]);
                        let host = match request[3] {
                            1 => {
                                let mut bytes = [0; 4];
                                incoming.read_exact(&mut bytes).unwrap();
                                std::net::Ipv4Addr::from(bytes).to_string()
                            }
                            3 => {
                                let mut length = [0];
                                incoming.read_exact(&mut length).unwrap();
                                let mut bytes = vec![0; length[0] as usize];
                                incoming.read_exact(&mut bytes).unwrap();
                                String::from_utf8(bytes).unwrap()
                            }
                            _ => panic!("unexpected fixture target type"),
                        };
                        let mut port = [0; 2];
                        incoming.read_exact(&mut port).unwrap();
                        assert_eq!(
                            format!("{host}:{}", u16::from_be_bytes(port)),
                            target.authority()
                        );
                        incoming.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                    }
                    ProxyKind::HttpConnect => {}
                }
                // Protocol script is below, separated so no tunnel byte is lost.
                if kind == ProxyKind::HttpConnect {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let mut b = [0];
                        incoming.read_exact(&mut b).unwrap();
                        head.push(b[0]);
                        assert!(head.len() <= 16 * 1024);
                    }
                    assert_eq!(head, format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: Basic dTpw\r\n\r\n", target.authority(), target.authority()).as_bytes());
                    incoming.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
                }
                let mut outgoing = TcpStream::connect(destination).unwrap();
                outgoing
                    .set_read_timeout(Some(Duration::from_secs(8)))
                    .unwrap();
                outgoing
                    .set_write_timeout(Some(Duration::from_secs(8)))
                    .unwrap();
                let mut input = incoming.try_clone().unwrap();
                let mut output = outgoing.try_clone().unwrap();
                let forward = thread::spawn(move || {
                    let _ = std::io::copy(&mut input, &mut output);
                    let _ = output.shutdown(Shutdown::Write);
                });
                let _ = std::io::copy(&mut outgoing, &mut incoming);
                let _ = incoming.shutdown(Shutdown::Write);
                forward.join().unwrap();
            });
            Self {
                address,
                kind,
                owner,
            }
        }
        pub fn config(&self) -> Arc<ProxyConfig> {
            let credentials = Some(ProxyCredentials::new(b"u".to_vec(), b"p".to_vec()).unwrap());
            Arc::new(
                match self.kind {
                    ProxyKind::Socks5 => ProxyConfig::socks5(self.address, credentials),
                    ProxyKind::HttpConnect => ProxyConfig::http_connect(self.address, credentials),
                }
                .unwrap(),
            )
        }
        pub fn join(self) {
            self.owner.join().unwrap();
        }
    }
}

#[cfg(all(feature = "websocket", feature = "proxy"))]
#[tokio::test]
async fn original_budget_spans_proxy_tls_upgrade_and_cancellation_closes_socket() {
    use syntra_net::proxy::{ProxyConfig, ProxyTarget};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use web::ApplicationTls;

    // Both branches use real TLS but deliberately withhold the HTTP 101. The
    // proxy and TLS jobs are owned JoinHandles, always observed before returning.
    for cancel in [false, true] {
        let origin = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let address = origin.local_addr().unwrap();
        let proxy = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let provider = Arc::new(ApplicationTls::new());
        let server_tls = provider.server.clone();
        let (upgraded, seen_upgrade) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (stream, _) = origin.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(server_tls)
                .accept(stream)
                .await
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
                assert!(head.len() < 16 * 1024);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(head.starts_with("GET /syntra/1.0/ws HTTP/1.1\r\n"));
            assert!(head
                .to_ascii_lowercase()
                .contains("sec-websocket-protocol: syntra.1.0\r\n"));
            assert!(head.to_ascii_lowercase().contains("host: localhost\r\n"));
            assert!(!head.to_ascii_lowercase().contains("proxy-authorization"));
            let _ = upgraded.send(());
            // TLS truncation without close_notify is an expected abortive close.
            let mut byte = [0];
            let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
                .await
                .unwrap();
            assert!(
                matches!(result, Ok(0) | Err(_)),
                "cancelled Upgrade retained its socket"
            );
        });
        let tunnel = tokio::spawn(async move {
            let (mut incoming, _) = proxy.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(incoming.read_u8().await.unwrap());
            }
            assert_eq!(
                head,
                b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n"
            );
            // Spend most of the setup budget BEFORE TLS/Upgrade begins.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut outgoing = tokio::net::TcpStream::connect(address).await.unwrap();
            incoming
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
        });
        let trust = Trust::new(Carrier::SecureWebSocket, Mode::Returning);
        let route = Route::WssProxy {
            proxy: Arc::new(ProxyConfig::http_connect(proxy_address, None).unwrap()),
            target: ProxyTarget::hostname("localhost", 443).unwrap(),
            url: "wss://localhost/syntra/1.0/ws".into(),
            provider,
        };
        let mut cfg = config(vec![route.clone()], vec![route.endpoint()]);
        cfg.limits.attempt_timeout = if cancel {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(400)
        };
        let connector = client_routes(cfg, trust.inputs(Arc::new(AtomicUsize::new(0)))).unwrap();
        let started = std::time::Instant::now();
        if cancel {
            let mut future = connector();
            tokio::select! {
                result = &mut future => panic!("unexpected completion: {:?}", result.err()),
                result = seen_upgrade => result.unwrap(),
            }
            drop(future);
        } else {
            assert!(matches!(connector().await, Err(Error::Timeout)));
            seen_upgrade.await.unwrap();
            // A budget renewed after CONNECT would take ~600ms, not ~400ms.
            assert!(started.elapsed() < Duration::from_millis(550));
        }
        peer.await.unwrap();
        tunnel.await.unwrap();
    }
}

/// Candidate-only local evidence: actual bindings 4/5 and the same kernel/pump,
/// not registration, normative acceptance or independent interoperability.
#[cfg(feature = "http")]
mod candidate {
    use super::web::ApplicationTls;
    use super::*;
    use syntra_core::secure_channel::VerifiedIdentity;
    use syntra_net::{
        http::{self, Authority},
        AuthenticatorFactory,
    };
    use syntra_runtime::{AuthError, Authenticator, FnHandler, HandlerOutcome, StaticToken};
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn authority() -> Authority {
        Authority::new("localhost:38080").unwrap()
    }

    fn runtime() -> ConnectionConfig {
        ConnectionConfig {
            max_outstanding: 16,
            writer_capacity: 4,
            notification_capacity: 4,
            ..ConnectionConfig::default()
        }
    }

    struct Fixture {
        trust: Trust,
        provider: Arc<ApplicationTls>,
        handle: http::ServerHandle,
        owner: tokio::task::JoinHandle<http::ServerStatus>,
        effects: Arc<AtomicUsize>,
    }

    impl Fixture {
        async fn start(carrier: Carrier, mode: Mode) -> Self {
            let trust = Trust::new(carrier, mode);
            let provider = Arc::new(ApplicationTls::new());
            let effects = Arc::new(AtomicUsize::new(0));
            let count = effects.clone();
            let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
                move |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                    // No HTTP/TLS-to-Noise relabelling and no inferred principal.
                    assert_eq!(identity.context().carrier, carrier);
                    Ok(Arc::new(StaticToken::new(
                        b"explicit-hello-credential".to_vec(),
                        "candidate-route-principal",
                    )))
                },
            );
            let mut settings = http::ServerConfig::new(
                local(0),
                authority(),
                trust.server.clone(),
                factory,
                Arc::new(FnHandler(move |_, payload, _| {
                    count.fetch_add(1, Ordering::SeqCst);
                    async move { HandlerOutcome::Payload(payload) }
                })),
            );
            settings.runtime = runtime();
            if carrier == Carrier::Https {
                settings.tls = Some(provider.clone());
            }
            let (handle, run) = http::bind(settings).await.unwrap();
            Self {
                trust,
                provider,
                handle,
                owner: tokio::spawn(run),
                effects,
            }
        }

        fn direct(&self) -> Route {
            if self.trust.server.carrier == Carrier::Http {
                Route::Http {
                    address: self.handle.local_addr(),
                    authority: authority(),
                }
            } else {
                Route::Https {
                    address: self.handle.local_addr(),
                    authority: authority(),
                    provider: self.provider.clone(),
                }
            }
        }

        async fn stop(self) {
            self.handle.stop();
            let status = tokio::time::timeout(Duration::from_secs(5), self.owner)
                .await
                .unwrap()
                .unwrap();
            assert!(status.stopped, "{status:?}");
            assert_eq!(status.associations, 0);
            assert_eq!(status.failed_tasks, 0);
        }

        async fn rpc(&self, route: Route) {
            let mut cfg = config(vec![route.clone()], vec![route.endpoint()]);
            cfg.runtime = runtime();
            let calls = Arc::new(AtomicUsize::new(0));
            let connector = client_routes(cfg, self.trust.inputs(calls.clone())).unwrap();
            let client = tokio::time::timeout(Duration::from_secs(5), connector())
                .await
                .unwrap()
                .unwrap();
            let payload = vec![0xac; 150_000];
            let reply = client
                .conn
                .call("/test.Service/Echo", payload.clone(), 3000)
                .await
                .unwrap();
            assert_eq!(reply, payload);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(self.effects.load(Ordering::SeqCst), 1);
            client.close().await;
        }
    }

    #[tokio::test]
    async fn direct_http_https_real_encrypted_rpc_both_modes() {
        let _serial = SERIAL.lock().await;
        for carrier in [Carrier::Http, Carrier::Https] {
            for mode in [Mode::Bootstrap, Mode::Returning] {
                let fixture = Fixture::start(carrier, mode).await;
                fixture.rpc(fixture.direct()).await;
                assert_eq!(
                    fixture.provider.calls.load(Ordering::SeqCst),
                    if carrier == Carrier::Https { 2 } else { 0 }
                );
                fixture.stop().await;
            }
        }
    }

    #[test]
    fn http_entire_allowlist_and_candidate_carrier_mismatches_reject_before_inputs() {
        let provider = Arc::new(ApplicationTls::new());
        let plain = Route::Http {
            address: local(1),
            authority: authority(),
        };
        let secure = Route::Https {
            address: local(1),
            authority: authority(),
            provider: provider.clone(),
        };
        for cfg in [
            config(
                vec![plain.clone(), secure.clone()],
                vec![plain.endpoint(), secure.endpoint()],
            ),
            config(
                vec![plain.clone()],
                vec![plain.endpoint(), secure.endpoint()],
            ),
            config(vec![plain.clone()], vec![Endpoint::Tcp(local(1))]),
            config(
                vec![plain.clone()],
                vec![Endpoint::Http {
                    address: local(2),
                    authority: authority(),
                }],
            ),
            config(
                vec![plain.clone()],
                vec![Endpoint::Http {
                    address: local(1),
                    authority: Authority::new("other.invalid:38080").unwrap(),
                }],
            ),
            config(
                vec![plain.clone()],
                vec![
                    plain.endpoint(),
                    Endpoint::Http {
                        address: local(0),
                        authority: authority(),
                    },
                ],
            ),
            config(
                vec![plain.clone()],
                vec![
                    plain.endpoint(),
                    Endpoint::Http {
                        address: local(1),
                        authority: Authority::new("0.0.0.0:80").unwrap(),
                    },
                ],
            ),
        ] {
            assert!(matches!(
                client_routes(cfg, || panic!("candidate configuration inputs")),
                Err(Error::Configuration)
            ));
        }
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn http_carrier_inputs_cannot_be_relabelled_and_emit_no_socket() {
        let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        for wrong in [Carrier::Tcp, Carrier::WebSocket, Carrier::Https] {
            let route = Route::Http {
                address: listener.local_addr().unwrap(),
                authority: authority(),
            };
            let trust = Trust::new(wrong, Mode::Bootstrap);
            let connector = client_routes(
                config(vec![route.clone()], vec![route.endpoint()]),
                trust.inputs(Arc::new(AtomicUsize::new(0))),
            )
            .unwrap();
            assert!(matches!(connector().await, Err(Error::Configuration)));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(feature = "reconnect")]
    fn reconnect() -> syntra_net::ReconnectConfig {
        syntra_net::ReconnectConfig {
            attempt_timeout: Duration::from_secs(3),
            reconnect_budget: Duration::from_secs(15),
            max_attempts: 8,
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(30),
            close_timeout: Duration::from_secs(1),
            start_paused: false,
            initial_network_available: true,
        }
    }

    #[cfg(feature = "reconnect")]
    async fn ready(client: &syntra_net::ReconnectingClient, after: u64) -> u64 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let syntra_net::LifecycleStatus::CoreReady(ready) = client.status() {
                    if ready.generation > after {
                        return ready.generation;
                    }
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap()
    }

    #[cfg(feature = "reconnect")]
    #[tokio::test]
    async fn candidate_generations_never_replay_a_stale_rpc() {
        let _serial = SERIAL.lock().await;
        use syntra_net::{CallError, ReconnectingClient};
        for carrier in [Carrier::Http, Carrier::Https] {
            let fixture = Fixture::start(carrier, Mode::Returning).await;
            let route = fixture.direct();
            let mut cfg = config(vec![route.clone()], vec![route.endpoint()]);
            cfg.runtime = runtime();
            let calls = Arc::new(AtomicUsize::new(0));
            let mut client = ReconnectingClient::new(
                reconnect(),
                client_routes(cfg, fixture.trust.inputs(calls.clone())).unwrap(),
            )
            .unwrap();
            let first = ready(&client, 0).await;
            {
                let stale = client.call("/test.Service/Echo", vec![1], 2000);
                client.pause();
                client.resume();
                let second = ready(&client, first).await;
                assert!(
                    matches!(stale.await, Err(CallError::Unavailable { generation: Some(g) }) if g == first)
                );
                assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
                let reply = client
                    .call("/test.Service/Echo", vec![2], 2000)
                    .await
                    .unwrap();
                assert_eq!(reply.generation, second);
                assert_eq!(reply.value, [2]);
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
            client.close().await.unwrap();
            fixture.stop().await;
        }
    }

    #[cfg(feature = "reconnect")]
    #[tokio::test]
    async fn https_second_lane_trust_failure_is_terminal_and_cannot_select_successor() {
        let _serial = SERIAL.lock().await;
        use syntra_net::tls::{BoxIo, TlsAuthority, TlsFuture, TlsProvider};
        use syntra_net::{Failure, LifecycleStatus, ReconnectingClient};
        struct SplitTrust {
            good: Arc<ApplicationTls>,
            bad: ApplicationTls,
            calls: AtomicUsize,
        }
        impl TlsProvider for SplitTrust {
            fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
                if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.good.connect(stream, authority)
                } else {
                    self.bad.connect(stream, authority)
                }
            }
            fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
                self.good.accept(stream, authority)
            }
        }
        let fixture = Fixture::start(Carrier::Https, Mode::Bootstrap).await;
        let provider = Arc::new(SplitTrust {
            good: fixture.provider.clone(),
            bad: ApplicationTls::new(),
            calls: AtomicUsize::new(0),
        });
        let bad = Route::Https {
            address: fixture.handle.local_addr(),
            authority: authority(),
            provider: provider.clone(),
        };
        let good = fixture.direct();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut client = ReconnectingClient::new(
            reconnect(),
            client_routes(
                config(
                    vec![bad.clone(), good.clone()],
                    vec![bad.endpoint(), good.endpoint()],
                ),
                fixture.trust.inputs(calls.clone()),
            )
            .unwrap(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if client.status() == LifecycleStatus::Blocked(Failure::Configuration) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.provider.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.handle.status().ready, 0);
        client.close().await.unwrap();
        fixture.stop().await;
    }

    #[cfg(feature = "managed")]
    #[test]
    fn std_managed_http_https_failover_both_modes_without_ambient_runtime() {
        use syntra_net::{
            network::{Network, NetworkConfig},
            LifecycleStatus,
        };
        assert!(tokio::runtime::Handle::try_current().is_err());
        let _serial = SERIAL.blocking_lock();
        for carrier in [Carrier::Http, Carrier::Https] {
            for mode in [Mode::Bootstrap, Mode::Returning] {
                let (setup, receiver) = std::sync::mpsc::channel();
                let (stop, stopped) = tokio::sync::oneshot::channel();
                let calls = Arc::new(AtomicUsize::new(0));
                let observed = calls.clone();
                // Only the local fixture server needs this explicitly owned
                // thread/runtime. The client-side caller is an ordinary thread.
                let server = std::thread::spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async {
                            let fixture = Fixture::start(carrier, mode).await;
                            assert!(setup
                                .send((fixture.direct(), fixture.trust.inputs(observed)))
                                .is_ok());
                            stopped.await.unwrap();
                            fixture.stop().await;
                        });
                });
                let (route, inputs) = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
                let refused = std::net::TcpListener::bind(local(0)).unwrap();
                let address = refused.local_addr().unwrap();
                drop(refused);
                let first = match &route {
                    Route::Http { authority, .. } => Route::Http {
                        address,
                        authority: authority.clone(),
                    },
                    Route::Https {
                        authority,
                        provider,
                        ..
                    } => Route::Https {
                        address,
                        authority: authority.clone(),
                        provider: provider.clone(),
                    },
                    _ => unreachable!(),
                };
                let mut cfg = config(
                    vec![first.clone(), route.clone()],
                    vec![first.endpoint(), route.endpoint()],
                );
                cfg.runtime = runtime();
                let mut network = Network::new(NetworkConfig::default()).unwrap();
                let client = managed::receive(
                    network
                        .client(reconnect(), client_routes(cfg, inputs).unwrap())
                        .unwrap(),
                )
                .unwrap();
                managed::until(|| matches!(client.status(), LifecycleStatus::CoreReady(_)));
                let result = managed::receive(
                    client
                        .call("/test.Service/Echo".into(), vec![47], 2000)
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(result.value, [47]);
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                assert!(network.shutdown(Duration::from_secs(5)).complete);
                stop.send(()).unwrap();
                server.join().unwrap();
            }
        }
    }

    #[cfg(feature = "proxy")]
    mod proxied {
        use super::*;
        use syntra_net::{
            http::{codec, OpenEnvelope, OriginPolicy},
            proxy::{ProxyConfig, ProxyCredentials, ProxyTarget},
        };
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

        #[derive(Clone, Copy)]
        enum Kind {
            Socks,
            Connect,
            Forward,
        }

        struct Proxy {
            config: Arc<ProxyConfig>,
            owner: tokio::task::JoinHandle<()>,
            opens: Arc<AtomicUsize>,
        }

        async fn head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            while !bytes.ends_with(b"\r\n\r\n") {
                bytes.push(stream.read_u8().await?);
                assert!(bytes.len() <= codec::MAX_HEADERS);
            }
            Ok(bytes)
        }

        impl Proxy {
            async fn start(fixture: &Fixture, kind: Kind) -> Self {
                let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
                let address = listener.local_addr().unwrap();
                let destination = fixture.handle.local_addr();
                let input = fixture.trust.inputs(Arc::new(AtomicUsize::new(0)))()
                    .unwrap()
                    .0;
                let envelope = OpenEnvelope::new(input.context.encode().unwrap()).unwrap();
                let opens = Arc::new(AtomicUsize::new(0));
                let observed = opens.clone();
                let owner = tokio::spawn(async move {
                    let mut lanes = tokio::task::JoinSet::new();
                    // The client MUST establish exactly two lanes on this route.
                    for _ in 0..2 {
                        let (mut incoming, _) = listener.accept().await.unwrap();
                        let envelope = envelope.clone();
                        let observed = observed.clone();
                        lanes.spawn(async move {
                            match kind {
                                Kind::Socks => {
                                    let mut hello = [0; 3]; incoming.read_exact(&mut hello).await.unwrap();
                                    assert_eq!(hello, [5, 1, 2]);
                                    incoming.write_all(&[5, 2]).await.unwrap();
                                    let mut login = [0; 5]; incoming.read_exact(&mut login).await.unwrap();
                                    assert_eq!(login, [1, 1, b'u', 1, b'p']);
                                    incoming.write_all(&[1, 0]).await.unwrap();
                                    let mut request = [0; 5]; incoming.read_exact(&mut request).await.unwrap();
                                    assert_eq!(request, [5, 1, 0, 3, 9]);
                                    let mut host = [0; 9]; incoming.read_exact(&mut host).await.unwrap();
                                    assert_eq!(&host, b"localhost");
                                    assert_eq!(incoming.read_u16().await.unwrap(), 38080);
                                    incoming.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                                }
                                Kind::Connect => {
                                    assert_eq!(head(&mut incoming).await.unwrap(), b"CONNECT localhost:38080 HTTP/1.1\r\nHost: localhost:38080\r\nProxy-Authorization: Basic dTpw\r\n\r\n");
                                    incoming.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                                }
                                Kind::Forward => {}
                            }
                            let mut outgoing = tokio::net::TcpStream::connect(destination).await.unwrap();
                            if matches!(kind, Kind::Forward) {
                                let (mut input, mut reply) = tokio::io::split(incoming);
                                let (mut response, mut output) = tokio::io::split(outgoing);
                                let forward = async {
                                    loop {
                                        let raw = match head(&mut input).await {
                                            Ok(head) => head,
                                            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                                            Err(error) => panic!("{error}"),
                                        };
                                        let raw = String::from_utf8(raw).unwrap();
                                        let mut lines = raw.split("\r\n");
                                        let first = lines.next().unwrap();
                                        let path = first.strip_prefix("POST http://localhost:38080").unwrap();
                                        assert!(!path.contains("://"));
                                        let mut origin = format!("POST {path}\r\n");
                                        let mut auth = 0;
                                        for line in lines {
                                            if line.is_empty() { continue; }
                                            if line.starts_with("Proxy-Authorization:") {
                                                assert_eq!(line, "Proxy-Authorization: Basic dTpw");
                                                auth += 1;
                                            } else {
                                                origin.push_str(line); origin.push_str("\r\n");
                                            }
                                        }
                                        assert_eq!(auth, 1, "one hop credential per outer request");
                                        origin.push_str("\r\n");
                                        let parsed = codec::parse_request(origin.as_bytes(), &authority(), &OriginPolicy::default(), &envelope).unwrap();
                                        if parsed.operation == codec::Operation::Open { observed.fetch_add(1, Ordering::SeqCst); }
                                        let mut body = vec![0; parsed.body_len];
                                        input.read_exact(&mut body).await.unwrap();
                                        if parsed.operation == codec::Operation::Open { envelope.check_m1(&body).unwrap(); }
                                        // Strict origin codec above rejects hop/origin credentials.
                                        output.write_all(origin.as_bytes()).await.unwrap();
                                        output.write_all(&body).await.unwrap();
                                        output.flush().await.unwrap();
                                    }
                                    let _ = output.shutdown().await;
                                };
                                let back = async {
                                    let _ = tokio::io::copy(&mut response, &mut reply).await;
                                    let _ = reply.shutdown().await;
                                };
                                tokio::join!(forward, back);
                            } else {
                                // Opaque tunnel, not HTTP-origin header rewriting.
                                let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
                            }
                        });
                    }
                    while let Some(result) = lanes.join_next().await {
                        result.unwrap();
                    }
                    assert!(
                        tokio::time::timeout(Duration::from_millis(20), listener.accept())
                            .await
                            .is_err(),
                        "unexpected retry/third lane"
                    );
                });
                let credentials =
                    Some(ProxyCredentials::new(b"u".to_vec(), b"p".to_vec()).unwrap());
                let config = Arc::new(
                    match kind {
                        Kind::Socks => ProxyConfig::socks5(address, credentials),
                        Kind::Connect | Kind::Forward => {
                            ProxyConfig::http_connect(address, credentials)
                        }
                    }
                    .unwrap(),
                );
                Self {
                    config,
                    owner,
                    opens,
                }
            }

            fn route(&self, fixture: &Fixture, kind: Kind) -> Route {
                let target = ProxyTarget::hostname("localhost", 38080).unwrap();
                let proxy = self.config.clone();
                if matches!(kind, Kind::Forward) {
                    Route::HttpForward {
                        proxy,
                        target,
                        authority: authority(),
                    }
                } else if fixture.trust.server.carrier == Carrier::Http {
                    Route::HttpProxy {
                        proxy,
                        target,
                        authority: authority(),
                    }
                } else {
                    Route::HttpsProxy {
                        proxy,
                        target,
                        authority: authority(),
                        provider: fixture.provider.clone(),
                    }
                }
            }
        }

        #[tokio::test]
        async fn socks_connect_and_real_forward_http_https_encrypted_rpc_both_modes() {
            let _serial = SERIAL.lock().await;
            for carrier in [Carrier::Http, Carrier::Https] {
                for mode in [Mode::Bootstrap, Mode::Returning] {
                    for kind in [Kind::Socks, Kind::Connect, Kind::Forward] {
                        if carrier == Carrier::Https && matches!(kind, Kind::Forward) {
                            continue;
                        }
                        let fixture = Fixture::start(carrier, mode).await;
                        let proxy = Proxy::start(&fixture, kind).await;
                        fixture.rpc(proxy.route(&fixture, kind)).await;
                        tokio::time::timeout(Duration::from_secs(5), proxy.owner)
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(
                            proxy.opens.load(Ordering::SeqCst),
                            usize::from(matches!(kind, Kind::Forward))
                        );
                        assert_eq!(
                            fixture.provider.calls.load(Ordering::SeqCst),
                            if carrier == Carrier::Https { 2 } else { 0 }
                        );
                        fixture.stop().await;
                    }
                }
            }
        }

        #[test]
        fn proxy_target_authority_kind_allowlist_and_debug_are_checked_before_inputs() {
            let provider = Arc::new(ApplicationTls::new());
            let secret = || {
                Some(ProxyCredentials::new(b"local-hop".to_vec(), b"do-not-log".to_vec()).unwrap())
            };
            let proxy = Arc::new(ProxyConfig::http_connect(local(1), secret()).unwrap());
            let socks = Arc::new(ProxyConfig::socks5(local(1), secret()).unwrap());
            let wrong = ProxyTarget::hostname("other.invalid", 38080).unwrap();
            let target = ProxyTarget::hostname("localhost", 38080).unwrap();
            for route in [
                Route::HttpProxy {
                    proxy: proxy.clone(),
                    target: wrong.clone(),
                    authority: authority(),
                },
                Route::HttpsProxy {
                    proxy: proxy.clone(),
                    target: wrong.clone(),
                    authority: authority(),
                    provider,
                },
                Route::HttpForward {
                    proxy: proxy.clone(),
                    target: wrong,
                    authority: authority(),
                },
                Route::HttpForward {
                    proxy: socks,
                    target: target.clone(),
                    authority: authority(),
                },
            ] {
                let cfg = config(vec![route.clone()], vec![route.endpoint()]);
                assert!(!format!("{cfg:?}").contains("do-not-log"));
                assert!(matches!(
                    client_routes(cfg, || panic!("proxy policy inputs")),
                    Err(Error::Configuration)
                ));
            }
            let route = Route::HttpForward {
                proxy,
                target: target.clone(),
                authority: authority(),
            };
            for allow in [
                Endpoint::HttpProxy {
                    proxy: local(1),
                    target: target.clone(),
                    authority: authority(),
                },
                Endpoint::HttpForward {
                    proxy: local(2),
                    target: target.clone(),
                    authority: authority(),
                },
                Endpoint::HttpForward {
                    proxy: local(1),
                    target,
                    authority: Authority::new("localhost:38081").unwrap(),
                },
            ] {
                assert!(matches!(
                    client_routes(config(vec![route.clone()], vec![allow]), || panic!(
                        "proxy allowlist inputs"
                    )),
                    Err(Error::Configuration)
                ));
            }
        }

        #[tokio::test]
        async fn paired_tunnels_share_deadline_and_cancel_both_partial_owners() {
            for cancel in [false, true] {
                let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
                let proxy = Arc::new(
                    ProxyConfig::http_connect(listener.local_addr().unwrap(), None).unwrap(),
                );
                let (second, waiting) = tokio::sync::oneshot::channel();
                let server = tokio::spawn(async move {
                    let (mut upload, _) = listener.accept().await.unwrap();
                    head(&mut upload).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    upload.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                    let (mut download, _) = listener.accept().await.unwrap();
                    head(&mut download).await.unwrap();
                    second.send(()).unwrap();
                    let read = async {
                        assert_eq!(upload.read(&mut [0]).await.unwrap(), 0);
                    };
                    let other = async {
                        assert_eq!(download.read(&mut [0]).await.unwrap(), 0);
                    };
                    tokio::time::timeout(Duration::from_secs(2), async {
                        tokio::join!(read, other);
                    })
                    .await
                    .unwrap();
                });
                let trust = Trust::new(Carrier::Https, Mode::Returning);
                let route = Route::HttpsProxy {
                    proxy,
                    target: ProxyTarget::hostname("localhost", 38080).unwrap(),
                    authority: authority(),
                    provider: Arc::new(ApplicationTls::new()),
                };
                let mut cfg = config(vec![route.clone()], vec![route.endpoint()]);
                cfg.limits.attempt_timeout = if cancel {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(400)
                };
                let connector =
                    client_routes(cfg, trust.inputs(Arc::new(AtomicUsize::new(0)))).unwrap();
                let start = std::time::Instant::now();
                if cancel {
                    let mut future = connector();
                    tokio::select! {
                        result = &mut future => panic!("unexpected completion: {:?}", result.err()),
                        result = waiting => result.unwrap(),
                    }
                    drop(future);
                } else {
                    assert!(matches!(connector().await, Err(Error::Timeout)));
                    waiting.await.unwrap();
                    assert!(start.elapsed() < Duration::from_millis(550));
                }
                server.await.unwrap();
            }
        }

        #[tokio::test]
        async fn real_forward_open_shares_setup_budget_and_cancel_closes_both_lanes() {
            for cancel in [false, true] {
                let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
                let proxy = Arc::new(
                    ProxyConfig::http_connect(listener.local_addr().unwrap(), None).unwrap(),
                );
                let (opened, waiting) = tokio::sync::oneshot::channel();
                let peer = tokio::spawn(async move {
                    let (mut upload, _) = listener.accept().await.unwrap();
                    let (mut download, _) = listener.accept().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let raw = head(&mut upload).await.unwrap();
                    let text = std::str::from_utf8(&raw).unwrap();
                    assert!(text.starts_with(
                        "POST http://localhost:38080/syntra/1.0/http/open HTTP/1.1\r\n"
                    ));
                    assert!(text.contains("\r\nHost: localhost:38080\r\n"));
                    assert!(!text.to_ascii_lowercase().contains("authorization:"));
                    let length: usize = text
                        .split("\r\n")
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    assert!(length <= syntra_core::secure_channel::MAX_WRAPPER);
                    let mut m1 = vec![0; length];
                    upload.read_exact(&mut m1).await.unwrap();
                    let (context, _) = Context::parse_first(&m1).unwrap();
                    // Parsed context is test observation, never proof of identity.
                    assert_eq!(context.carrier, Carrier::Http);
                    assert_eq!(context.mode, Mode::Returning);
                    opened.send(()).unwrap();
                    let first = async {
                        assert_eq!(upload.read(&mut [0]).await.unwrap(), 0);
                    };
                    let second = async {
                        assert_eq!(download.read(&mut [0]).await.unwrap(), 0);
                    };
                    tokio::time::timeout(Duration::from_secs(2), async {
                        tokio::join!(first, second);
                    })
                    .await
                    .unwrap();
                });
                let route = Route::HttpForward {
                    proxy,
                    target: ProxyTarget::hostname("localhost", 38080).unwrap(),
                    authority: authority(),
                };
                let mut cfg = config(vec![route.clone()], vec![route.endpoint()]);
                cfg.limits.attempt_timeout = if cancel {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(400)
                };
                let trust = Trust::new(Carrier::Http, Mode::Returning);
                let connector =
                    client_routes(cfg, trust.inputs(Arc::new(AtomicUsize::new(0)))).unwrap();
                let start = std::time::Instant::now();
                if cancel {
                    let mut future = connector();
                    tokio::select! {
                        result = &mut future => panic!("unexpected completion: {:?}", result.err()),
                        result = waiting => result.unwrap(),
                    }
                    drop(future);
                } else {
                    assert!(matches!(connector().await, Err(Error::Timeout)));
                    waiting.await.unwrap();
                    assert!(start.elapsed() < Duration::from_millis(550));
                }
                peer.await.unwrap();
            }
        }
    }
}
