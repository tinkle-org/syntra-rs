//! Local candidate composition evidence, not independent interoperability.
#![cfg(all(feature = "cross-carrier-candidate", not(target_arch = "wasm32")))]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, Mode, Secret32,
};
use syntra_net::{
    routes::{
        client_routes_cross_carrier, CrossCarrierPolicy, Endpoint, Route, RouteConfig, MAX_ROUTES,
    },
    Error, EstablishmentBudget, Limits,
};
use syntra_runtime::ConnectionConfig;

fn local(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}

fn config(routes: Vec<Route>, allowlist: Vec<Endpoint>) -> RouteConfig {
    RouteConfig {
        routes,
        allowlist,
        runtime: ConnectionConfig::default(),
        limits: Limits::default(),
    }
}

fn policy(permitted_carriers: Vec<Carrier>) -> CrossCarrierPolicy {
    CrossCarrierPolicy { permitted_carriers }
}

fn budget() -> EstablishmentBudget {
    EstablishmentBudget::new(
        syntra_runtime::elapsed::ElapsedClock::new(),
        Limits::default().attempt_timeout,
    )
    .unwrap()
}

#[derive(Default)]
struct TestElapsed(std::sync::atomic::AtomicU64);

impl TestElapsed {
    fn set_millis(&self, millis: u64) {
        self.0.store(millis, std::sync::atomic::Ordering::SeqCst);
    }
}

impl syntra_runtime::elapsed::ElapsedSource for TestElapsed {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(
            self.0.load(std::sync::atomic::Ordering::SeqCst),
        ))
    }
}

fn inputs(carrier: Carrier, mode: Mode, public: [u8; 32]) -> (ClientConfig, Vec<u8>) {
    let returning = mode == Mode::Returning;
    (
        ClientConfig {
            context: Context {
                carrier,
                mode,
                server_key_id: 7,
                scope: b"cross-carrier-fixture".to_vec(),
                handle: if returning { [4; 8] } else { [0; 8] },
                epoch: if returning { 9 } else { 0 },
            },
            server_public_key: public,
            authorization_key: returning.then(|| Secret32::new([3; 32])),
        },
        b"explicit-route-credential".to_vec(),
    )
}

#[test]
fn policy_has_no_implicit_permissions_and_rejects_duplicates_and_local_ws() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    for permitted in [
        vec![],
        vec![Carrier::Tcp, Carrier::Tcp],
        vec![Carrier::WebSocket],
        vec![Carrier::Tcp, Carrier::WebSocket],
        vec![Carrier::Tcp; MAX_ROUTES + 1],
    ] {
        assert!(matches!(
            client_routes_cross_carrier(
                config(vec![Route::Tcp(local(1))], vec![Endpoint::Tcp(local(1))]),
                policy(permitted),
                |_| panic!("invalid policy consumed inputs"),
            ),
            Err(Error::Configuration)
        ));
    }
}

#[test]
fn entire_routes_and_unused_allowlist_keep_bounds_and_endpoint_validation() {
    let reject = |cfg| {
        assert!(matches!(
            client_routes_cross_carrier(cfg, policy(vec![Carrier::Tcp]), |_| {
                panic!("invalid configuration consumed inputs")
            }),
            Err(Error::Configuration)
        ));
    };
    reject(config(vec![], vec![Endpoint::Tcp(local(1))]));
    reject(config(vec![Route::Tcp(local(1))], vec![]));
    reject(config(
        vec![Route::Tcp(local(1))],
        vec![Endpoint::Tcp(local(2))],
    ));
    reject(config(
        vec![Route::Tcp(local(1)); MAX_ROUTES + 1],
        vec![Endpoint::Tcp(local(1))],
    ));
    reject(config(
        vec![Route::Tcp(local(1))],
        vec![Endpoint::Tcp(local(1)); MAX_ROUTES + 1],
    ));
    for invalid in [
        local(0),
        "0.0.0.0:80".parse().unwrap(),
        "224.0.0.1:80".parse().unwrap(),
        "[::]:80".parse().unwrap(),
    ] {
        reject(config(
            vec![Route::Tcp(local(1)), Route::Tcp(invalid)],
            vec![Endpoint::Tcp(local(1)), Endpoint::Tcp(invalid)],
        ));
        reject(config(
            vec![Route::Tcp(local(1))],
            vec![Endpoint::Tcp(local(1)), Endpoint::Tcp(invalid)],
        ));
    }
    let mut cfg = config(vec![Route::Tcp(local(1))], vec![Endpoint::Tcp(local(1))]);
    cfg.limits.attempt_timeout = Duration::ZERO;
    reject(cfg);
}

#[tokio::test]
async fn unpolled_is_inert_and_selected_endpoints_are_round_robin_with_unchanged_errors() {
    let a = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let b = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let endpoints = vec![
        Endpoint::Tcp(a.local_addr().unwrap()),
        Endpoint::Tcp(b.local_addr().unwrap()),
    ];
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connector = client_routes_cross_carrier(
        config(
            vec![
                Route::Tcp(a.local_addr().unwrap()),
                Route::Tcp(b.local_addr().unwrap()),
            ],
            endpoints.clone(),
        ),
        policy(vec![Carrier::Tcp]),
        {
            let seen = seen.clone();
            move |endpoint| {
                seen.lock().unwrap().push(endpoint.clone());
                Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "fixture-input",
                )))
            }
        },
    )
    .unwrap();
    drop(connector(budget()));
    assert!(seen.lock().unwrap().is_empty());
    for _ in 0..3 {
        match connector(budget()).await {
            Err(Error::Io(error)) => {
                assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(error.to_string(), "fixture-input");
            }
            _ => panic!("input error changed"),
        }
    }
    assert_eq!(
        *seen.lock().unwrap(),
        vec![
            endpoints[0].clone(),
            endpoints[1].clone(),
            endpoints[0].clone()
        ]
    );
    for listener in [&a, &b] {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn selected_carrier_mismatch_is_not_rewritten_or_dialed() {
    let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let endpoint = Endpoint::Tcp(listener.local_addr().unwrap());
    let (_, public) = generate_server_key().unwrap();
    let connector = client_routes_cross_carrier(
        config(
            vec![Route::Tcp(listener.local_addr().unwrap())],
            vec![endpoint.clone()],
        ),
        policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
        move |selected| {
            assert_eq!(selected, &endpoint);
            Ok(inputs(Carrier::SecureWebSocket, Mode::Returning, public))
        },
    )
    .unwrap();
    assert!(matches!(
        connector(budget()).await,
        Err(Error::Configuration)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn expired_supplied_or_shortened_route_budget_precedes_selection_and_inputs() {
    use syntra_runtime::elapsed::ElapsedClock;
    let a = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let b = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let first = Route::Tcp(a.local_addr().unwrap());
    let second = Route::Tcp(b.local_addr().unwrap());
    for (supplied_seconds, route_seconds) in [(1, 3), (3, 1)] {
        let source = Arc::new(TestElapsed::default());
        let supplied = EstablishmentBudget::new(
            ElapsedClock::with_source(source.clone()),
            Duration::from_secs(supplied_seconds),
        )
        .unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut cfg = config(
            vec![first.clone(), second.clone()],
            vec![first.endpoint(), second.endpoint()],
        );
        cfg.limits.attempt_timeout = Duration::from_secs(route_seconds);
        let connector = client_routes_cross_carrier(cfg, policy(vec![Carrier::Tcp]), {
            let seen = seen.clone();
            move |endpoint| {
                seen.lock().unwrap().push(endpoint.clone());
                Err(Error::Authentication)
            }
        })
        .unwrap();
        let future = connector(supplied);
        source.set_millis(1500);
        assert!(matches!(future.await, Err(Error::Timeout)));
        assert!(seen.lock().unwrap().is_empty());
        assert!(matches!(
            connector(budget()).await,
            Err(Error::Authentication)
        ));
        assert_eq!(*seen.lock().unwrap(), vec![first.endpoint()]);
    }
    for listener in [&a, &b] {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn scope_callback_overrun_of_supplied_or_shortened_deadline_emits_no_socket_io() {
    use syntra_runtime::elapsed::ElapsedClock;
    let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let route = Route::Tcp(listener.local_addr().unwrap());
    let (_, public) = generate_server_key().unwrap();
    for (supplied_seconds, route_seconds) in [(1, 3), (3, 1)] {
        for input_error in [false, true] {
            let source = Arc::new(TestElapsed::default());
            let supplied = EstablishmentBudget::new(
                ElapsedClock::with_source(source.clone()),
                Duration::from_secs(supplied_seconds),
            )
            .unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let mut cfg = config(vec![route.clone()], vec![route.endpoint()]);
            cfg.limits.attempt_timeout = Duration::from_secs(route_seconds);
            let connector = client_routes_cross_carrier(cfg, policy(vec![Carrier::Tcp]), {
                let source = source.clone();
                let seen = seen.clone();
                move |endpoint| {
                    seen.lock().unwrap().push(endpoint.clone());
                    let result = if input_error {
                        Err(Error::Authentication)
                    } else {
                        Ok(inputs(endpoint.carrier(), Mode::Returning, public))
                    };
                    // Simulate synchronous provisioning crossing the original
                    // cutoff within one poll, including an error returned late.
                    source.set_millis(1500);
                    result
                }
            })
            .unwrap();
            // Most of the allowance was spent before route polling. Neither
            // capping nor entering the callback may restart that allowance.
            source.set_millis(750);
            assert!(matches!(connector(supplied).await, Err(Error::Timeout)));
            assert_eq!(*seen.lock().unwrap(), vec![route.endpoint()]);
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
}

#[cfg(any(feature = "websocket", feature = "http"))]
mod tls_fixture {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use syntra_net::tls::{
        BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata, TlsProvider,
        TlsRole,
    };

    pub struct ApplicationTls {
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
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

    // Actual TLS with a local fixture root and ordinary chain/name/time checks.
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
                    early_data: if session.is_early_data_accepted() {
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
                let stream = tokio_rustls::TlsAcceptor::from(self.server.clone())
                    .accept(stream)
                    .await
                    .map_err(|_| Error::Configuration)?;
                let session = stream.get_ref().1;
                let metadata = TlsMetadata {
                    authority,
                    role: TlsRole::Server,
                    protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                    alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                    early_data: EarlyData::Disabled,
                };
                Ok(ProviderTlsStream::new(Box::new(stream), metadata))
            })
        }
    }
}

#[cfg(feature = "websocket")]
#[test]
fn mixed_candidate_validates_unused_permissions_and_old_api_stays_homogeneous() {
    use std::sync::atomic::Ordering;
    use syntra_net::routes::client_routes;
    let provider = Arc::new(tls_fixture::ApplicationTls::new());
    let tcp = Route::Tcp(local(1));
    let wss = Route::Wss {
        address: local(2),
        url: "wss://localhost/syntra/1.0/ws".into(),
        provider: provider.clone(),
    };
    let ws = Route::Ws {
        address: local(3),
        url: "ws://localhost/syntra/1.0/ws".into(),
    };
    for cfg in [
        config(
            vec![tcp.clone(), wss.clone()],
            vec![tcp.endpoint(), wss.endpoint()],
        ),
        config(vec![tcp.clone()], vec![tcp.endpoint(), wss.endpoint()]),
    ] {
        assert!(matches!(
            client_routes_cross_carrier(cfg, policy(vec![Carrier::Tcp]), |_| panic!(
                "denied inputs"
            )),
            Err(Error::Configuration)
        ));
    }
    for cfg in [
        config(
            vec![tcp.clone(), ws.clone()],
            vec![tcp.endpoint(), ws.endpoint()],
        ),
        config(vec![tcp.clone()], vec![tcp.endpoint(), ws.endpoint()]),
    ] {
        assert!(matches!(
            client_routes_cross_carrier(
                cfg,
                policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
                |_| panic!("local downgrade inputs")
            ),
            Err(Error::Configuration)
        ));
    }
    let permitted = policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]);
    let invalid = Route::Wss {
        address: local(2),
        url: "wss://user:secret@localhost/syntra/1.0/ws".into(),
        provider: provider.clone(),
    };
    for cfg in [
        config(
            vec![tcp.clone(), invalid.clone()],
            vec![tcp.endpoint(), invalid.endpoint()],
        ),
        config(vec![tcp.clone()], vec![tcp.endpoint(), invalid.endpoint()]),
        config(vec![tcp.clone(), wss.clone()], vec![tcp.endpoint()]),
    ] {
        assert!(matches!(
            client_routes_cross_carrier(cfg, permitted.clone(), |_| panic!(
                "invalid endpoint inputs"
            )),
            Err(Error::Configuration)
        ));
    }
    for cfg in [
        config(
            vec![tcp.clone(), wss.clone()],
            vec![tcp.endpoint(), wss.endpoint()],
        ),
        config(vec![tcp.clone()], vec![tcp.endpoint(), wss.endpoint()]),
    ] {
        assert!(matches!(
            client_routes(cfg, || panic!("old API mixed inputs")),
            Err(Error::Configuration)
        ));
    }
    assert!(
        client_routes(config(vec![ws.clone()], vec![ws.endpoint()]), || panic!(
            "constructor inputs"
        ))
        .is_ok()
    );
    assert!(client_routes_cross_carrier(
        config(
            vec![tcp.clone(), wss.clone()],
            vec![tcp.endpoint(), wss.endpoint()]
        ),
        permitted,
        |_| panic!("constructor inputs")
    )
    .is_ok());
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn mixed_selection_is_inert_until_polled_and_mismatch_precedes_provider_and_dial() {
    use std::sync::atomic::Ordering;
    let a = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let b = tokio::net::TcpListener::bind(local(0)).await.unwrap();
    let provider = Arc::new(tls_fixture::ApplicationTls::new());
    let first = Route::Tcp(a.local_addr().unwrap());
    let second = Route::Wss {
        address: b.local_addr().unwrap(),
        url: "wss://localhost/syntra/1.0/ws".into(),
        provider: provider.clone(),
    };
    let expected = vec![first.endpoint(), second.endpoint(), first.endpoint()];
    let (_, public) = generate_server_key().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let connector = client_routes_cross_carrier(
        config(
            vec![first.clone(), second.clone()],
            vec![first.endpoint(), second.endpoint()],
        ),
        policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
        {
            let seen = seen.clone();
            move |endpoint| {
                seen.lock().unwrap().push(endpoint.clone());
                if endpoint.carrier() == Carrier::Tcp {
                    Err(Error::Authentication)
                } else {
                    Ok(inputs(Carrier::Tcp, Mode::Returning, public))
                }
            }
        },
    )
    .unwrap();
    drop(connector(budget()));
    assert!(seen.lock().unwrap().is_empty());
    assert!(matches!(
        connector(budget()).await,
        Err(Error::Authentication)
    ));
    drop(connector(budget()));
    assert!(matches!(
        connector(budget()).await,
        Err(Error::Configuration)
    ));
    assert!(matches!(
        connector(budget()).await,
        Err(Error::Authentication)
    ));
    assert_eq!(*seen.lock().unwrap(), expected);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    for listener in [&a, &b] {
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }
}

#[test]
fn input_callback_does_not_hold_route_selection_lock() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use syntra_net::routes::DialFuture;
    let calls = Arc::new(AtomicUsize::new(0));
    let connector = client_routes_cross_carrier(
        config(vec![Route::Tcp(local(1))], vec![Endpoint::Tcp(local(1))]),
        policy(vec![Carrier::Tcp]),
        {
            let calls = calls.clone();
            move |_| {
                // The first callback waits for a second poll to finish selection.
                // A mistakenly retained selection lock would hit this deadline.
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    while calls.load(Ordering::SeqCst) != 2 {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "selection locked during inputs"
                        );
                        std::thread::yield_now();
                    }
                }
                Err(Error::Authentication)
            }
        },
    )
    .unwrap();
    let connector = Arc::new(connector);
    let poll = |future: DialFuture| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(matches!(
            runtime.block_on(future),
            Err(Error::Authentication)
        ));
    };
    let first = std::thread::spawn({
        let connector = connector.clone();
        move || poll(connector(budget()))
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while calls.load(Ordering::SeqCst) == 0 {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    poll(connector(budget()));
    first.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "reconnect")]
mod supervised {
    use super::*;
    use syntra_core::secure_channel::{KeyStore, ServerConfig, VerifiedIdentity};
    use syntra_net::{
        AuthenticatorFactory, Failure, LifecycleStatus, ReconnectConfig, ReconnectingClient,
    };
    use syntra_runtime::{
        AuthError, Authenticator, FnHandler, Handler, HandlerOutcome, StaticToken,
    };

    const WAIT: Duration = Duration::from_secs(5);

    struct Store;
    impl KeyStore for Store {
        fn lookup(
            &self,
            context: &Context,
        ) -> Result<Secret32, syntra_core::secure_channel::Error> {
            if context.handle == [4; 8] && context.epoch == 9 {
                Ok(Secret32::new([3; 32]))
            } else {
                Err(syntra_core::secure_channel::Error::Authentication)
            }
        }
    }

    fn security(carrier: Carrier, mode: Mode) -> (Arc<ServerConfig>, [u8; 32]) {
        let (private_key, public) = generate_server_key().unwrap();
        (
            Arc::new(ServerConfig {
                mode,
                carrier,
                server_key_id: 7,
                scope: b"cross-carrier-fixture".to_vec(),
                private_key,
                store: Some(Arc::new(Store)),
            }),
            public,
        )
    }

    fn factory(carrier: Carrier, mode: Mode) -> Arc<dyn AuthenticatorFactory> {
        Arc::new(
            move |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                assert_eq!(identity.context().carrier, carrier);
                assert_eq!(identity.context().mode, mode);
                Ok(Arc::new(StaticToken::new(
                    b"explicit-route-credential".to_vec(),
                    "route-principal",
                )))
            },
        )
    }

    fn echo() -> Arc<dyn Handler> {
        // Explicit fixture authorization after encrypted hello authentication.
        Arc::new(FnHandler(|_, payload, _| async move {
            HandlerOutcome::Payload(payload)
        }))
    }

    fn reconnect() -> ReconnectConfig {
        ReconnectConfig {
            attempt_timeout: Duration::from_secs(3),
            reconnect_budget: Duration::from_secs(15),
            max_attempts: 4,
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
            close_timeout: Duration::from_secs(1),
            start_paused: false,
            initial_network_available: true,
        }
    }

    async fn until(client: &ReconnectingClient, predicate: impl Fn(&LifecycleStatus) -> bool) {
        tokio::time::timeout(WAIT, async {
            loop {
                if predicate(&client.status()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn terminal_input_failure_leaves_successor_untouched() {
        let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let route = Route::Tcp(listener.local_addr().unwrap());
        #[cfg(feature = "websocket")]
        let provider = Arc::new(tls_fixture::ApplicationTls::new());
        #[cfg(feature = "websocket")]
        let successor = wss(listener.local_addr().unwrap(), provider.clone());
        #[cfg(not(feature = "websocket"))]
        let successor = route.clone();
        let connector = client_routes_cross_carrier(
            config(
                vec![route.clone(), successor.clone()],
                vec![route.endpoint(), successor.endpoint()],
            ),
            policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
            {
                let seen = seen.clone();
                move |endpoint| {
                    seen.lock().unwrap().push(endpoint.clone());
                    Err(Error::Authentication)
                }
            },
        )
        .unwrap();
        let mut client = ReconnectingClient::new_with_budget(reconnect(), connector).unwrap();
        until(&client, |status| {
            *status == LifecycleStatus::Blocked(Failure::Authentication)
        })
        .await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(seen.lock().unwrap().len(), 1);
        #[cfg(feature = "websocket")]
        assert_eq!(provider.calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        client.close().await.unwrap();
    }

    #[cfg(feature = "http")]
    #[tokio::test]
    async fn automatic_tcp_to_real_provider_https_both_authentication_modes() {
        use std::sync::atomic::Ordering;
        use syntra_net::http::{self, Authority};
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let (server, public) = security(Carrier::Https, mode);
            let provider = Arc::new(tls_fixture::ApplicationTls::new());
            let authority = Authority::new("localhost:38080").unwrap();
            let mut settings = http::ServerConfig::new(
                local(0),
                authority.clone(),
                server,
                factory(Carrier::Https, mode),
                echo(),
            );
            settings.tls = Some(provider.clone());
            let (server, run) = http::bind(settings).await.unwrap();
            let owner = tokio::spawn(run);
            let refused = tokio::net::TcpListener::bind(local(0)).await.unwrap();
            let first = Route::Tcp(refused.local_addr().unwrap());
            drop(refused);
            let second = Route::Https {
                address: server.local_addr(),
                authority,
                provider: provider.clone(),
            };
            let expected = vec![first.endpoint(), second.endpoint()];
            let seen = Arc::new(Mutex::new(Vec::new()));
            let connector = client_routes_cross_carrier(
                config(vec![first, second], expected.clone()),
                policy(vec![Carrier::Tcp, Carrier::Https]),
                {
                    let seen = seen.clone();
                    move |endpoint| {
                        seen.lock().unwrap().push(endpoint.clone());
                        Ok(inputs(endpoint.carrier(), mode, public))
                    }
                },
            )
            .unwrap();
            let mut client = ReconnectingClient::new_with_budget(reconnect(), connector).unwrap();
            until(&client, |status| {
                matches!(status, LifecycleStatus::CoreReady(_))
            })
            .await;
            let reply = client
                .call("/test.Service/Echo", vec![0xa7; 4096], 3000)
                .await
                .unwrap();
            assert_eq!(reply.value, vec![0xa7; 4096]);
            assert_eq!(*seen.lock().unwrap(), expected);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
            client.close().await.unwrap();
            server.stop();
            let status = tokio::time::timeout(WAIT, owner).await.unwrap().unwrap();
            assert!(status.stopped, "{status:?}");
            assert_eq!(status.associations, 0);
            assert_eq!(status.failed_tasks, 0);
        }
    }

    #[cfg(feature = "websocket")]
    async fn web_accept(
        listener: tokio::net::TcpListener,
        security: Arc<ServerConfig>,
        provider: Arc<tls_fixture::ApplicationTls>,
    ) -> Result<syntra_net::HostHandle, Error> {
        use syntra_net::{tls, websocket, EstablishmentBudget};
        let budget = EstablishmentBudget::new(
            syntra_runtime::elapsed::ElapsedClock::new(),
            Duration::from_secs(3),
        )?;
        let (stream, _) = listener.accept().await?;
        let authority = tls::TlsAuthority::new("localhost", 443)?;
        let stream =
            tls::accept_stream_with_budget(stream, provider.as_ref(), authority.clone(), budget)
                .await?;
        websocket::accept_verified_tls_stream(
            stream,
            &authority,
            &security,
            factory(security.carrier, security.mode),
            echo(),
            (ConnectionConfig::default(), Limits::default()),
        )
        .await
    }

    #[cfg(feature = "websocket")]
    fn wss(address: SocketAddr, provider: Arc<tls_fixture::ApplicationTls>) -> Route {
        Route::Wss {
            address,
            url: "wss://localhost/syntra/1.0/ws".into(),
            provider,
        }
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn automatic_tcp_to_provider_wss_and_back_both_authentication_modes() {
        use std::sync::atomic::Ordering;
        for mode in [Mode::Bootstrap, Mode::Returning] {
            for live_carrier in [Carrier::Tcp, Carrier::SecureWebSocket] {
                let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
                let address = listener.local_addr().unwrap();
                let refused = tokio::net::TcpListener::bind(local(0)).await.unwrap();
                let refused_address = refused.local_addr().unwrap();
                drop(refused);
                let provider = Arc::new(tls_fixture::ApplicationTls::new());
                let (server, live_public) = security(live_carrier, mode);
                let failed_carrier = if live_carrier == Carrier::Tcp {
                    Carrier::SecureWebSocket
                } else {
                    Carrier::Tcp
                };
                let (_, failed_public) = security(failed_carrier, mode);
                let first = if failed_carrier == Carrier::Tcp {
                    Route::Tcp(refused_address)
                } else {
                    wss(refused_address, provider.clone())
                };
                let second = if live_carrier == Carrier::Tcp {
                    Route::Tcp(address)
                } else {
                    wss(address, provider.clone())
                };
                let expected = vec![first.endpoint(), second.endpoint()];
                let seen = Arc::new(Mutex::new(Vec::new()));
                let connector = client_routes_cross_carrier(
                    config(vec![first, second], expected.clone()),
                    policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
                    {
                        let seen = seen.clone();
                        move |endpoint| {
                            seen.lock().unwrap().push(endpoint.clone());
                            let public = if endpoint.carrier() == live_carrier {
                                live_public
                            } else {
                                failed_public
                            };
                            Ok(inputs(endpoint.carrier(), mode, public))
                        }
                    },
                )
                .unwrap();
                let host = tokio::spawn({
                    let provider = provider.clone();
                    async move {
                        if live_carrier == Carrier::SecureWebSocket {
                            web_accept(listener, server, provider).await
                        } else {
                            let (stream, _) = listener.accept().await.unwrap();
                            syntra_net::tcp::accept_stream(
                                stream,
                                &server,
                                factory(live_carrier, mode),
                                echo(),
                                ConnectionConfig::default(),
                                Limits::default(),
                            )
                            .await
                        }
                    }
                });
                let mut client =
                    ReconnectingClient::new_with_budget(reconnect(), connector).unwrap();
                until(&client, |status| {
                    matches!(status, LifecycleStatus::CoreReady(_))
                })
                .await;
                let host = tokio::time::timeout(WAIT, host)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
                let payload = vec![0xa7; 150_000];
                let reply = client
                    .call("/test.Service/Echo", payload.clone(), 3000)
                    .await
                    .unwrap();
                assert_eq!(reply.value, payload);
                assert_eq!(*seen.lock().unwrap(), expected);
                assert_eq!(
                    provider.calls.load(Ordering::SeqCst),
                    usize::from(live_carrier == Carrier::SecureWebSocket)
                );
                client.close().await.unwrap();
                host.close().await;
            }
        }
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn live_tcp_wss_tcp_generations_use_fresh_endpoint_inputs_both_modes() {
        use std::sync::atomic::Ordering;
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let tcp = tokio::net::TcpListener::bind(local(0)).await.unwrap();
            let web = tokio::net::TcpListener::bind(local(0)).await.unwrap();
            let provider = Arc::new(tls_fixture::ApplicationTls::new());
            let (tcp_security, tcp_public) = security(Carrier::Tcp, mode);
            let (web_security, web_public) = security(Carrier::SecureWebSocket, mode);
            let first = Route::Tcp(tcp.local_addr().unwrap());
            let second = wss(web.local_addr().unwrap(), provider.clone());
            let expected = vec![first.endpoint(), second.endpoint(), first.endpoint()];
            let seen = Arc::new(Mutex::new(Vec::new()));
            let connector = client_routes_cross_carrier(
                config(
                    vec![first.clone(), second.clone()],
                    vec![first.endpoint(), second.endpoint()],
                ),
                policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
                {
                    let seen = seen.clone();
                    move |endpoint| {
                        seen.lock().unwrap().push(endpoint.clone());
                        let public = if endpoint.carrier() == Carrier::Tcp {
                            tcp_public
                        } else {
                            web_public
                        };
                        Ok(inputs(endpoint.carrier(), mode, public))
                    }
                },
            )
            .unwrap();
            let (hosts, mut incoming) = tokio::sync::mpsc::channel(3);
            let tcp_owner = tokio::spawn({
                let hosts = hosts.clone();
                async move {
                    for _ in 0..2 {
                        let (stream, _) = tcp.accept().await.unwrap();
                        let host = syntra_net::tcp::accept_stream(
                            stream,
                            &tcp_security,
                            factory(Carrier::Tcp, mode),
                            echo(),
                            ConnectionConfig::default(),
                            Limits::default(),
                        )
                        .await
                        .unwrap();
                        assert!(hosts.send((Carrier::Tcp, host)).await.is_ok());
                    }
                }
            });
            let web_owner = tokio::spawn({
                let provider = provider.clone();
                async move {
                    let host = web_accept(web, web_security, provider).await.unwrap();
                    assert!(hosts.send((Carrier::SecureWebSocket, host)).await.is_ok());
                }
            });
            let mut client = ReconnectingClient::new_with_budget(reconnect(), connector).unwrap();
            let mut generation = 0;
            for (index, carrier) in [Carrier::Tcp, Carrier::SecureWebSocket, Carrier::Tcp]
                .into_iter()
                .enumerate()
            {
                until(&client, |status| matches!(status, LifecycleStatus::CoreReady(ready) if ready.generation > generation)).await;
                let (accepted_carrier, host) = tokio::time::timeout(WAIT, incoming.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(accepted_carrier, carrier);
                let payload = vec![index as u8; 4096];
                let reply = client
                    .call("/test.Service/Echo", payload.clone(), 3000)
                    .await
                    .unwrap();
                assert!(reply.generation > generation);
                generation = reply.generation;
                assert_eq!(reply.value, payload);
                if index == 2 {
                    client.close().await.unwrap();
                }
                host.close().await;
            }
            tokio::time::timeout(WAIT, tcp_owner)
                .await
                .unwrap()
                .unwrap();
            tokio::time::timeout(WAIT, web_owner)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(*seen.lock().unwrap(), expected);
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn terminal_real_tls_failure_does_not_select_tcp_successor() {
        use std::sync::atomic::Ordering;
        let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let untouched = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let (server, public) = security(Carrier::SecureWebSocket, Mode::Returning);
        let provider = Arc::new(tls_fixture::ApplicationTls::new());
        let untrusted = Arc::new(tls_fixture::ApplicationTls::new());
        let first = wss(listener.local_addr().unwrap(), untrusted.clone());
        let second = Route::Tcp(untouched.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connector = client_routes_cross_carrier(
            config(
                vec![first.clone(), second.clone()],
                vec![first.endpoint(), second.endpoint()],
            ),
            policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
            {
                let seen = seen.clone();
                move |endpoint| {
                    seen.lock().unwrap().push(endpoint.clone());
                    Ok(inputs(endpoint.carrier(), Mode::Returning, public))
                }
            },
        )
        .unwrap();
        let host = tokio::spawn(web_accept(listener, server, provider));
        let mut client = ReconnectingClient::new_with_budget(reconnect(), connector).unwrap();
        until(&client, |status| {
            *status == LifecycleStatus::Blocked(Failure::Configuration)
        })
        .await;
        assert!(tokio::time::timeout(WAIT, host)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(*seen.lock().unwrap(), vec![first.endpoint()]);
        assert_eq!(untrusted.calls.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), untouched.accept())
                .await
                .is_err()
        );
        client.close().await.unwrap();
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn terminal_noise_failure_does_not_select_provider_wss_successor() {
        use std::sync::atomic::Ordering;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let untouched = tokio::net::TcpListener::bind(local(0)).await.unwrap();
        let provider = Arc::new(tls_fixture::ApplicationTls::new());
        let first = Route::Tcp(listener.local_addr().unwrap());
        let second = wss(untouched.local_addr().unwrap(), provider.clone());
        let (_, public) = security(Carrier::Tcp, Mode::Bootstrap);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let connector = client_routes_cross_carrier(
            config(
                vec![first.clone(), second.clone()],
                vec![first.endpoint(), second.endpoint()],
            ),
            policy(vec![Carrier::Tcp, Carrier::SecureWebSocket]),
            {
                let seen = seen.clone();
                move |endpoint| {
                    seen.lock().unwrap().push(endpoint.clone());
                    Ok(inputs(endpoint.carrier(), Mode::Bootstrap, public))
                }
            },
        )
        .unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut m1 = vec![0; length as usize];
            stream.read_exact(&mut m1).await.unwrap();
            stream.write_u16(48).await.unwrap();
            stream.write_all(&[0xa7; 48]).await.unwrap();
        });
        let mut client = ReconnectingClient::new_with_budget(reconnect(), connector).unwrap();
        until(&client, |status| {
            *status == LifecycleStatus::Blocked(Failure::Channel)
        })
        .await;
        peer.await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(*seen.lock().unwrap(), vec![first.endpoint()]);
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), untouched.accept())
                .await
                .is_err()
        );
        client.close().await.unwrap();
    }
}
