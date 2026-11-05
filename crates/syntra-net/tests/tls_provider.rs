//! Application-provider composition with real local TLS, not independent interop
//! or security-review evidence. Certificates never enter the system trust store.
#![cfg(all(feature = "websocket", not(target_arch = "wasm32")))]

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32, ServerConfig,
    VerifiedIdentity,
};
use syntra_net::{
    tls::{
        self, BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata,
        TlsProvider, TlsRole,
    },
    websocket as ws, AuthenticatorFactory, Error, EstablishmentBudget, Limits,
};
use syntra_runtime::{
    elapsed::ElapsedClock, AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler,
    Handler, HandlerOutcome,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

struct Observed<S> {
    inner: S,
    writes: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}
impl<S> Drop for Observed<S> {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Observed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Observed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.writes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy)]
enum MetadataFault {
    None,
    Authority,
    Role,
}

struct ApplicationTls {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    local_authority: TlsAuthority,
    writes: Arc<AtomicUsize>,
    metadata_fault: MetadataFault,
}

impl ApplicationTls {
    fn new(
        authority: TlsAuthority,
        version: &'static rustls::SupportedProtocolVersion,
        alpn: &[u8],
    ) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        Self::with_certificate(authority, version, alpn, cert)
    }

    fn with_certificate(
        authority: TlsAuthority,
        version: &'static rustls::SupportedProtocolVersion,
        alpn: &[u8],
        cert: rcgen::CertifiedKey<rcgen::KeyPair>,
    ) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.enable_early_data = false;
        client.alpn_protocols = if alpn.is_empty() {
            vec![]
        } else {
            vec![alpn.to_vec()]
        };
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        server.max_early_data_size = 0;
        server.alpn_protocols = client.alpn_protocols.clone();
        Self {
            client: Arc::new(client),
            server: Arc::new(server),
            local_authority: authority,
            writes: Arc::new(AtomicUsize::new(0)),
            metadata_fault: MetadataFault::None,
        }
    }

    fn output<S: tls::IoStream>(&self, stream: S, mut metadata: TlsMetadata) -> ProviderTlsStream {
        // Deliberate metadata corruption tests the engine's independent binding
        // checks after a real TLS handshake; it is never a production policy.
        match self.metadata_fault {
            MetadataFault::None => {}
            MetadataFault::Authority => {
                metadata.authority = TlsAuthority::new("wrong.example", 443).unwrap()
            }
            MetadataFault::Role => {
                metadata.role = match metadata.role {
                    TlsRole::Client => TlsRole::Server,
                    TlsRole::Server => TlsRole::Client,
                }
            }
        }
        ProviderTlsStream::new(
            Box::new(Observed {
                inner: stream,
                writes: self.writes.clone(),
                dropped: Arc::new(AtomicBool::new(false)),
            }),
            metadata,
        )
    }
}

// This is trusted application code. rustls's normal verifier checks the chain,
// name and current validity; this fixture's application policy is its local root
// set, with resumption disabled so no earlier policy decision can be reused.
impl TlsProvider for ApplicationTls {
    fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
        Box::pin(async move {
            let mut config = (*self.client).clone();
            config.resumption = rustls::client::Resumption::disabled();
            let name = rustls::pki_types::ServerName::try_from(authority.host().to_owned())
                .map_err(|_| Error::Configuration)?;
            let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, stream)
                .await
                .map_err(|_| Error::Configuration)?;
            let session = stream.get_ref().1;
            let metadata = TlsMetadata {
                authority,
                role: TlsRole::Client,
                protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                early_data: if self.client.enable_early_data || session.is_early_data_accepted() {
                    EarlyData::Enabled
                } else {
                    EarlyData::Disabled
                },
            };
            Ok(self.output(stream, metadata))
        })
    }

    fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
        Box::pin(async move {
            if authority != self.local_authority {
                return Err(Error::Configuration);
            }
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
                early_data: if self.server.max_early_data_size != 0 {
                    EarlyData::Enabled
                } else {
                    EarlyData::Disabled
                },
            };
            Ok(self.output(stream, metadata))
        })
    }
}

fn budget() -> EstablishmentBudget {
    EstablishmentBudget::new(ElapsedClock::default(), Duration::from_secs(5)).unwrap()
}

fn send<T: Send>(value: T) -> T {
    value
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

fn security(mode: Mode) -> (ClientConfig, ServerConfig) {
    let (private_key, server_public_key) = generate_server_key().unwrap();
    let returning = mode == Mode::Returning;
    let context = Context {
        mode,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: b"application-tls-fixture".to_vec(),
        handle: if returning { [4; 8] } else { [0; 8] },
        epoch: if returning { 9 } else { 0 },
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: returning.then(|| Secret32::new([3; 32])),
        },
        ServerConfig {
            mode,
            carrier: Carrier::SecureWebSocket,
            server_key_id: 1,
            scope: context.scope,
            private_key,
            store: Some(Arc::new(Store)),
        },
    )
}

fn echo() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|_, bytes, _| async {
        HandlerOutcome::Payload(bytes)
    }))
}

fn factory(calls: Arc<AtomicUsize>) -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        move |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            calls.fetch_add(1, Ordering::SeqCst);
            // Empty hello credentials remain an explicit application policy, not a
            // TLS or returning-channel principal inferred by the transport.
            Ok(Arc::new(AllowAnonymous))
        },
    )
}

#[tokio::test]
async fn application_provider_both_roles_protected_rpc_both_noise_modes() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let authority = TlsAuthority::new("127.0.0.1", address.port()).unwrap();
        let provider = Arc::new(ApplicationTls::new(
            authority.clone(),
            &rustls::version::TLS13,
            b"http/1.1",
        ));
        let (client, server) = security(mode);
        let calls = Arc::new(AtomicUsize::new(0));
        let host = {
            let provider = provider.clone();
            let authority = authority.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let budget = budget();
                let stream = send(tls::accept_stream_with_budget(
                    stream,
                    provider.as_ref(),
                    authority.clone(),
                    budget,
                ))
                .await
                .unwrap();
                assert_eq!(stream.metadata().role, TlsRole::Server);
                send(ws::accept_verified_tls_stream(
                    stream,
                    &authority,
                    &server,
                    factory(calls),
                    echo(),
                    (ConnectionConfig::default(), Limits::default()),
                ))
                .await
                .unwrap()
            })
        };
        let budget = budget();
        let stream = budget
            .run(tokio::net::TcpStream::connect(address))
            .await
            .unwrap()
            .unwrap();
        let stream = tls::connect_stream_with_budget(stream, provider.as_ref(), authority, budget)
            .await
            .unwrap();
        assert_eq!(stream.metadata().role, TlsRole::Client);
        let client = ws::connect_tls_stream_with_budget(
            stream,
            &format!("wss://{address}{}", ws::ENDPOINT_PATH),
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
        .unwrap();
        let host = host.await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let payload = vec![5; 200_000];
        assert_eq!(
            client
                .conn
                .call("/test.Service/Echo", payload.clone(), 5000)
                .await
                .unwrap(),
            payload
        );
        client
            .close_gracefully(Duration::from_secs(1))
            .await
            .unwrap();
        host.close().await;
    }
}

#[tokio::test]
async fn actual_tls_version_alpn_and_early_data_policy_rejected_for_both_roles() {
    for (version, alpn, early) in [
        (&rustls::version::TLS12, b"http/1.1".as_slice(), false),
        (&rustls::version::TLS13, b"h2".as_slice(), false),
        (&rustls::version::TLS13, b"".as_slice(), false),
        (&rustls::version::TLS13, b"http/1.1".as_slice(), true),
    ] {
        let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
        let mut provider = ApplicationTls::new(authority.clone(), version, alpn);
        if early {
            Arc::get_mut(&mut provider.client)
                .unwrap()
                .enable_early_data = true;
            Arc::get_mut(&mut provider.server)
                .unwrap()
                .max_early_data_size = 1024;
        }
        let (client, server) = tokio::io::duplex(65536);
        let client_budget = budget();
        let server_budget = budget();
        let (client, server) = tokio::join!(
            tls::connect_stream_with_budget(client, &provider, authority.clone(), client_budget),
            tls::accept_stream_with_budget(server, &provider, authority, server_budget),
        );
        assert!(matches!(client, Err(Error::Configuration)));
        assert!(matches!(server, Err(Error::Configuration)));
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn client_chain_name_and_current_certificate_validity_are_enforced() {
    for case in ["chain", "name", "expired"] {
        let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
        let mut provider = if case == "expired" {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
            params.not_before = rcgen::date_time_ymd(2010, 1, 1);
            params.not_after = rcgen::date_time_ymd(2011, 1, 1);
            let cert = params.self_signed(&key).unwrap();
            ApplicationTls::with_certificate(
                authority.clone(),
                &rustls::version::TLS13,
                b"http/1.1",
                rcgen::CertifiedKey {
                    cert,
                    signing_key: key,
                },
            )
        } else {
            ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1")
        };
        if case == "chain" {
            let unrelated =
                ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
            provider.client = unrelated.client;
        }
        let expected = if case == "name" {
            TlsAuthority::new("localhost", 443).unwrap()
        } else {
            authority.clone()
        };
        let (client, server) = tokio::io::duplex(65536);
        let client_budget = budget();
        let server_budget = budget();
        let (client, server) = tokio::join!(
            tls::connect_stream_with_budget(client, &provider, expected, client_budget),
            tls::accept_stream_with_budget(server, &provider, authority, server_budget),
        );
        assert!(matches!(client, Err(Error::Configuration)), "{case}");
        assert!(server.is_err(), "{case}");
    }
}

#[tokio::test]
async fn plaintext_cannot_become_a_verified_tls_proof() {
    for role in [TlsRole::Client, TlsRole::Server] {
        let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
        let provider = ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
        let (stream, mut peer) = tokio::io::duplex(65536);
        let peer = tokio::spawn(async move {
            peer.write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
                .await
                .unwrap();
        });
        let budget = budget();
        let result = match role {
            TlsRole::Client => {
                tls::connect_stream_with_budget(stream, &provider, authority, budget).await
            }
            TlsRole::Server => {
                tls::accept_stream_with_budget(stream, &provider, authority, budget).await
            }
        };
        assert!(matches!(result, Err(Error::Configuration)));
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn verified_result_cannot_change_authority_role_or_binding_before_websocket_io() {
    for case in ["authority", "role", "binding"] {
        let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
        let provider = ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
        let (client, server) = tokio::io::duplex(65536);
        let client_budget = budget();
        let server_budget = budget();
        let (client, server) = tokio::join!(
            tls::connect_stream_with_budget(client, &provider, authority.clone(), client_budget),
            tls::accept_stream_with_budget(server, &provider, authority.clone(), server_budget),
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let (mut security, _) = security(Mode::Bootstrap);
        if case == "binding" {
            security.context.carrier = Carrier::WebSocket;
        }
        let url = if case == "authority" {
            "wss://127.0.0.1:444/syntra/1.0/ws"
        } else if case == "binding" {
            "ws://127.0.0.1/syntra/1.0/ws"
        } else {
            "wss://127.0.0.1/syntra/1.0/ws"
        };
        let stream = if case == "role" { server } else { client };
        let result = ws::connect_tls_stream_with_budget(
            stream,
            url,
            security,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await;
        assert!(matches!(result, Err(Error::Configuration)), "{case}");
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0, "{case}");
    }
}

#[tokio::test]
async fn provider_metadata_cannot_misbind_authority_or_role() {
    for fault in [MetadataFault::Authority, MetadataFault::Role] {
        let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
        let mut provider =
            ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
        provider.metadata_fault = fault;
        let (client, server) = tokio::io::duplex(65536);
        let client_budget = budget();
        let server_budget = budget();
        let (client, server) = tokio::join!(
            tls::connect_stream_with_budget(client, &provider, authority.clone(), client_budget),
            tls::accept_stream_with_budget(server, &provider, authority, server_budget),
        );
        assert!(matches!(client, Err(Error::Configuration)));
        assert!(matches!(server, Err(Error::Configuration)));
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn server_verified_result_checks_role_authority_and_binding_before_http_or_auth() {
    for case in ["authority", "role", "binding"] {
        let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
        let provider = ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
        let (client, server) = tokio::io::duplex(65536);
        let client_budget = budget();
        let server_budget = budget();
        let (client, server) = tokio::join!(
            tls::connect_stream_with_budget(client, &provider, authority.clone(), client_budget),
            tls::accept_stream_with_budget(server, &provider, authority.clone(), server_budget),
        );
        let client = client.unwrap();
        let server = server.unwrap();
        let (_, mut security) = security(Mode::Bootstrap);
        let expected = if case == "authority" {
            TlsAuthority::new("127.0.0.1", 444).unwrap()
        } else {
            authority
        };
        if case == "binding" {
            security.carrier = Carrier::WebSocket;
        }
        let stream = if case == "role" { client } else { server };
        let calls = Arc::new(AtomicUsize::new(0));
        let result = ws::accept_verified_tls_stream(
            stream,
            &expected,
            &security,
            factory(calls.clone()),
            echo(),
            (ConnectionConfig::default(), Limits::default()),
        )
        .await;
        assert!(matches!(result, Err(Error::Configuration)), "{case}");
        assert_eq!(provider.writes.load(Ordering::SeqCst), 0, "{case}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "{case}");
    }
}

struct Source(AtomicU64);
impl syntra_runtime::elapsed::ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}

#[tokio::test(start_paused = true)]
async fn provider_tls_cancel_or_expiry_drops_the_only_underlying_stream_owner() {
    for role in [TlsRole::Client, TlsRole::Server] {
        for cancel in [true, false] {
            let source = Arc::new(Source(AtomicU64::new(0)));
            let clock = ElapsedClock::with_source(source.clone());
            let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
            let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
            let provider =
                ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
            let (stream, _peer) = tokio::io::duplex(65536);
            let dropped = Arc::new(AtomicBool::new(false));
            let stream = Observed {
                inner: stream,
                writes: Arc::new(AtomicUsize::new(0)),
                dropped: dropped.clone(),
            };
            let mut attempt = Box::pin(async {
                match role {
                    TlsRole::Client => {
                        tls::connect_stream_with_budget(stream, &provider, authority, budget).await
                    }
                    TlsRole::Server => {
                        tls::accept_stream_with_budget(stream, &provider, authority, budget).await
                    }
                }
            });
            assert!(futures_util::poll!(&mut attempt).is_pending());
            if cancel {
                drop(attempt);
            } else {
                source.0.store(1000, Ordering::SeqCst);
                clock.wake();
                let scheduled = tokio::time::Instant::now();
                assert!(matches!(attempt.await, Err(Error::Timeout)));
                assert_eq!(scheduled, tokio::time::Instant::now());
            }
            assert!(dropped.load(Ordering::SeqCst));
            assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn completed_tls_does_not_restart_the_attempt_and_deadline_wins_before_upgrade() {
    let source = Arc::new(Source(AtomicU64::new(0)));
    let clock = ElapsedClock::with_source(source.clone());
    let client_budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    let server_budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    let authority = TlsAuthority::new("127.0.0.1", 443).unwrap();
    let provider = ApplicationTls::new(authority.clone(), &rustls::version::TLS13, b"http/1.1");
    let (client, server) = tokio::io::duplex(65536);
    let (client, server) = tokio::join!(
        tls::connect_stream_with_budget(client, &provider, authority.clone(), client_budget),
        tls::accept_stream_with_budget(server, &provider, authority.clone(), server_budget),
    );
    let client = client.unwrap();
    let server = server.unwrap();
    source.0.store(1000, Ordering::SeqCst);
    clock.wake();
    let (client_config, server_config) = security(Mode::Bootstrap);
    // Invalid URL/authority as well as expiry: terminal choice remains deadline-first.
    let result = ws::connect_tls_stream_with_budget(
        client,
        "not a URL",
        client_config,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await;
    assert!(matches!(result, Err(Error::Timeout)));
    let calls = Arc::new(AtomicUsize::new(0));
    let wrong = TlsAuthority::new("wrong.example", 443).unwrap();
    let result = ws::accept_verified_tls_stream(
        server,
        &wrong,
        &server_config,
        factory(calls.clone()),
        echo(),
        (ConnectionConfig::default(), Limits::default()),
    )
    .await;
    assert!(matches!(result, Err(Error::Timeout)));
    assert_eq!(provider.writes.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
