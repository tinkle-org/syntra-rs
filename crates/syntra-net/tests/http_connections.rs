//! Local candidate-only protected round trips. Not RFC acceptance, independent
//! interoperability, formal conformance or a security-review verdict.
#![cfg(all(feature = "http", not(target_arch = "wasm32")))]
use futures_util::{stream::FuturesUnordered, StreamExt};
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use syntra_core::{
    secure_channel::{
        self as kernel, Carrier, ClientConfig, ClientHandshake, Context, KeyStore, Mode, Secret32,
        ServerConfig as Security, VerifiedIdentity,
    },
    ErrorCode,
};
use syntra_net::{
    http::{
        self,
        codec::{self, Operation},
        Authority, OpenEnvelope, ServerConfig, ServerHandle, ServerStatus,
    },
    tls::{
        self, BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata,
        TlsProvider, TlsRole,
    },
    AuthenticatorFactory, Error, EstablishmentBudget, Limits,
};
use syntra_runtime::{
    elapsed::ElapsedClock, AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler,
    Handler, HandlerOutcome, RejectAll,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
// These tests deliberately exercise the process-wide byte/principal quotas.
// Isolate scenarios instead of letting unrelated fixtures consume each other's
// declared capacity when the test harness runs functions concurrently.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(feature = "reconnect")]
#[tokio::test]
async fn reconnect_manager_fences_old_http_and_https_calls_without_replaying_mutations() {
    use syntra_net::{CallError, LifecycleStatus, ReconnectConfig, ReconnectingClient};
    let _serial = SERIAL.lock().await;
    for carrier in [Carrier::Http, Carrier::Https] {
        let fixture = Fixture::start(Mode::Returning, carrier, false, |_| {}).await;
        let address = fixture.handle.local_addr();
        let public = fixture.public;
        let provider = fixture.provider.clone();
        let mut manager = ReconnectingClient::new(
            ReconnectConfig {
                attempt_timeout: Duration::from_secs(5),
                reconnect_budget: Duration::from_secs(20),
                max_attempts: 4,
                base_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(20),
                close_timeout: Duration::from_secs(2),
                start_paused: false,
                initial_network_available: true,
            },
            move || {
                let provider = provider.clone();
                async move {
                    http::connect_with_budget(
                        address,
                        authority(),
                        provider,
                        client(public, Mode::Returning, carrier),
                        vec![],
                        (runtime(), Limits::default()),
                        budget(),
                    )
                    .await
                }
            },
        )
        .unwrap();
        async fn ready(manager: &ReconnectingClient, after: u64) -> u64 {
            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    if let LifecycleStatus::CoreReady(ready) = manager.status() {
                        if ready.generation > after {
                            return ready.generation;
                        }
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap()
        }
        let first = ready(&manager, 0).await;
        {
            let stale = manager.call("/test.Service/Echo", vec![42], 5000);
            manager.pause();
            manager.resume();
            let second = ready(&manager, first).await;
            assert!(
                matches!(stale.await, Err(CallError::Unavailable { generation: Some(generation) }) if generation == first)
            );
            let result = manager
                .call("/test.Service/Echo", vec![43], 5000)
                .await
                .unwrap();
            assert_eq!(result.generation, second);
            assert_eq!(result.value, [43]);
        }
        assert_eq!(fixture.auths.load(Ordering::SeqCst), 2);
        manager.close().await.unwrap();
        fixture.stop().await;
    }
}

fn budget() -> EstablishmentBudget {
    EstablishmentBudget::new(ElapsedClock::new(), Duration::from_secs(15)).unwrap()
}
fn authority() -> Authority {
    Authority::new("127.0.0.1:38080").unwrap()
}
fn runtime() -> ConnectionConfig {
    ConnectionConfig {
        max_outstanding: 16,
        writer_capacity: 16,
        notification_capacity: 16,
        ..ConnectionConfig::default()
    }
}
fn context(mode: Mode, carrier: Carrier) -> Context {
    Context {
        mode,
        carrier,
        server_key_id: 1,
        scope: b"candidate-http-local".to_vec(),
        handle: if mode == Mode::Returning {
            [7; 8]
        } else {
            [0; 8]
        },
        epoch: if mode == Mode::Returning { 2 } else { 0 },
    }
}
struct Store(Arc<AtomicUsize>);
impl KeyStore for Store {
    fn lookup(&self, c: &Context) -> Result<Secret32, kernel::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        if c.handle == [7; 8] && c.epoch == 2 {
            Ok(Secret32::new([8; 32]))
        } else {
            Err(kernel::Error::Authentication)
        }
    }
}
fn client(public: [u8; 32], mode: Mode, carrier: Carrier) -> ClientConfig {
    ClientConfig {
        context: context(mode, carrier),
        server_public_key: public,
        authorization_key: (mode == Mode::Returning).then(|| Secret32::new([8; 32])),
    }
}
fn auth(deny: bool, calls: Arc<AtomicUsize>) -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        move |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            calls.fetch_add(1, Ordering::SeqCst);
            if deny {
                Ok(Arc::new(RejectAll))
            } else {
                Ok(Arc::new(AllowAnonymous))
            }
        },
    )
}
fn echo() -> Arc<dyn Handler> {
    Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, cancel: syntra_runtime::connection::CancelToken| async move {
            if method.ends_with("Wait") {
                cancel.cancelled().await;
            }
            if method.ends_with("Reverse") {
                tokio::time::sleep(Duration::from_millis(u64::from(16 - payload[0]) * 5)).await;
            }
            HandlerOutcome::Payload(payload)
        },
    ))
}
struct Fixture {
    handle: ServerHandle,
    run: tokio::task::JoinHandle<ServerStatus>,
    public: [u8; 32],
    lookups: Arc<AtomicUsize>,
    auths: Arc<AtomicUsize>,
    mode: Mode,
    carrier: Carrier,
    provider: Option<Arc<dyn TlsProvider>>,
}
impl Fixture {
    async fn start(
        mode: Mode,
        carrier: Carrier,
        deny: bool,
        configure: impl FnOnce(&mut ServerConfig),
    ) -> Self {
        let (private_key, public) = kernel::generate_server_key().unwrap();
        let lookups = Arc::new(AtomicUsize::new(0));
        let auths = Arc::new(AtomicUsize::new(0));
        let security = Arc::new(Security {
            mode,
            carrier,
            server_key_id: 1,
            scope: context(mode, carrier).scope,
            private_key,
            store: Some(Arc::new(Store(lookups.clone()))),
        });
        let mut config = ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            authority(),
            security,
            auth(deny, auths.clone()),
            echo(),
        );
        config.runtime = runtime();
        if carrier == Carrier::Https {
            config.tls = Some(Arc::new(LocalTls::new()));
        }
        configure(&mut config);
        let provider = config.tls.clone();
        let (handle, run) = http::bind(config).await.unwrap();
        Self {
            handle,
            run: tokio::spawn(run),
            public,
            lookups,
            auths,
            mode,
            carrier,
            provider,
        }
    }
    fn security(&self) -> ClientConfig {
        client(self.public, self.mode, self.carrier)
    }
    async fn connect(&self) -> Result<syntra_net::ClientHandle, Error> {
        http::connect_with_budget(
            self.handle.local_addr(),
            authority(),
            self.provider.clone(),
            self.security(),
            vec![],
            (runtime(), Limits::default()),
            budget(),
        )
        .await
    }
    async fn ready(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.handle.status().ready != count {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
    async fn stop(self) {
        self.handle.stop();
        let status = tokio::time::timeout(Duration::from_secs(5), self.run)
            .await
            .unwrap()
            .unwrap();
        assert!(status.stopped);
        assert_eq!(status.ready, 0);
        assert_eq!(self.handle.status().associations, 0);
        assert_eq!(self.handle.status().sockets, 0);
        assert_eq!(self.handle.status().reserved_bytes, 0);
    }
}

#[tokio::test]
async fn http_and_https_both_noise_modes_rpc_fragmentation_16_reverse_notifications_and_cancel() {
    let _serial = SERIAL.lock().await;
    for carrier in [Carrier::Http, Carrier::Https] {
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let fixture = Fixture::start(mode, carrier, false, |_| {}).await;
            let client = fixture.connect().await.unwrap();
            fixture.ready(1).await;
            // Repeating an already-running control is not a new generation and
            // must not retire a healthy connection.
            fixture.handle.resume();
            fixture.handle.network_available(true);
            let payload = vec![42; 220_000];
            assert_eq!(
                client
                    .conn
                    .call("/test.Service/Echo", payload.clone(), 5000)
                    .await
                    .unwrap(),
                payload
            );
            let mut calls = FuturesUnordered::new();
            for n in 0..16u8 {
                let conn = client.conn.clone();
                calls.push(async move {
                    (
                        n,
                        conn.call("/test.Service/Reverse", vec![n], 5000)
                            .await
                            .unwrap(),
                    )
                });
            }
            let mut order = Vec::new();
            while let Some((n, result)) = calls.next().await {
                assert_eq!(result, [n]);
                order.push(n);
            }
            assert_ne!(order, (0..16u8).collect::<Vec<_>>());
            fixture.handle.hosts()[0]
                .notify(vec![9; 180_000])
                .await
                .unwrap();
            assert_eq!(
                client.conn.next_notification().await.unwrap(),
                vec![9; 180_000]
            );
            {
                let cancel = syntra_runtime::CancelToken::new();
                let call =
                    client
                        .conn
                        .call_cancellable("/test.Service/Wait", vec![1], 5000, &cancel);
                tokio::pin!(call);
                tokio::select! { result = &mut call => panic!("call finished before cancellation: {result:?}"), _ = tokio::time::sleep(Duration::from_millis(30)) => {} }
                cancel.cancel();
                assert_eq!(call.await.unwrap_err().code(), ErrorCode::Cancelled);
            }
            assert!(client
                .conn
                .call("/test.Service/Echo", vec![2], 5000)
                .await
                .is_ok());
            assert_eq!(fixture.auths.load(Ordering::SeqCst), 1);
            assert_eq!(
                fixture.lookups.load(Ordering::SeqCst),
                usize::from(mode == Mode::Returning)
            );
            client.close().await;
            fixture.stop().await;
        }
    }
}

#[tokio::test]
async fn explicit_hello_denial_and_default_method_denial_remain_host_owned() {
    let _serial = SERIAL.lock().await;
    for carrier in [Carrier::Http, Carrier::Https] {
        let fixture = Fixture::start(Mode::Returning, carrier, true, |_| {}).await;
        assert!(fixture.connect().await.is_err());
        assert_eq!(fixture.auths.load(Ordering::SeqCst), 1);
        fixture.stop().await;
    }
    struct Deny;
    impl Handler for Deny {
        fn handle(
            &self,
            _: String,
            _: Vec<u8>,
            _: syntra_runtime::connection::CancelToken,
        ) -> syntra_runtime::host::HandlerFut {
            panic!("unauthorized handler effect")
        }
    }
    let fixture = Fixture::start(Mode::Bootstrap, Carrier::Http, false, |c| {
        c.handler = Arc::new(Deny)
    })
    .await;
    let client = fixture.connect().await.unwrap();
    assert_eq!(
        client
            .conn
            .call("/test.Service/Echo", vec![], 5000)
            .await
            .unwrap_err()
            .code(),
        ErrorCode::PermissionDenied
    );
    client.close().await;
    fixture.stop().await;
}

async fn head(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < codec::MAX_HEADERS);
        bytes.push(stream.read_u8().await.unwrap());
    }
    bytes
}
async fn open(fixture: &Fixture) -> (TcpStream, http::Route, OpenEnvelope) {
    let config = fixture.security();
    let envelope = OpenEnvelope::new(config.context.encode().unwrap()).unwrap();
    let (noise, m1) = ClientHandshake::start(config).unwrap();
    let mut socket = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    socket
        .write_all(
            &codec::request(Operation::Open, &authority(), None, None, &m1, &envelope).unwrap(),
        )
        .await
        .unwrap();
    socket.write_all(&m1).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), head(&mut socket))
        .await
        .unwrap();
    let parsed = codec::parse_response(&response, Operation::Open).unwrap();
    let mut m2 = [0; 48];
    socket.read_exact(&mut m2).await.unwrap();
    noise.finish(&m2).unwrap();
    (socket, parsed.route.unwrap(), envelope)
}

#[tokio::test]
async fn open_returns_m2_before_d_exists_unknown_h_no_allocation_duplicate_d_retires_only_its_slot()
{
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |_| {}).await;
    let (u1, route1, env) = open(&fixture).await;
    let (u2, route2, _) = open(&fixture).await;
    assert_ne!(route1, route2);
    assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.handle.status().associations, 2);
    let mut unknown = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let arbitrary = http::Route::parse(&"a".repeat(64)).unwrap();
    unknown
        .write_all(
            &codec::request(
                Operation::Poll,
                &authority(),
                Some(&arbitrary),
                Some(0),
                &[],
                &env,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    native_error(&mut unknown, 410).await;
    assert_eq!(fixture.handle.status().associations, 2);
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 2);
    let mut d1 = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let poll = codec::request(
        Operation::Poll,
        &authority(),
        Some(&route1),
        Some(0),
        &[],
        &env,
    )
    .unwrap();
    d1.write_all(&poll).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut duplicate = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    duplicate.write_all(&poll).await.unwrap();
    native_error(&mut duplicate, 410).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.handle.status().associations != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // A completely unrelated U is still alive and owns its original route.
    let mut d2 = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    d2.write_all(
        &codec::request(
            Operation::Poll,
            &authority(),
            Some(&route2),
            Some(0),
            &[],
            &env,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    drop((u1, u2, d1, d2, duplicate, unknown));
    fixture.stop().await;
}

#[tokio::test]
async fn authority_origin_and_malformed_initial_requests_precede_context_lookup() {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |_| {}).await;
    let config = fixture.security();
    let env = OpenEnvelope::new(config.context.encode().unwrap()).unwrap();
    let (_, m1) = ClientHandshake::start(config).unwrap();
    let request = codec::request(Operation::Open, &authority(), None, None, &m1, &env).unwrap();
    let request = String::from_utf8(request).unwrap();
    for (bad, status) in [
        (
            request.replace("127.0.0.1:38080", "other.invalid:38080"),
            404,
        ),
        (request.replace("\r\n\r\n", "\r\nOrigin: null\r\n\r\n"), 403),
        (
            request.replace(
                "Content-Length:",
                "Transfer-Encoding: chunked\r\nContent-Length:",
            ),
            400,
        ),
        (request.replace("POST", "GET"), 405),
    ] {
        let mut stream = TcpStream::connect(fixture.handle.local_addr())
            .await
            .unwrap();
        stream.write_all(bad.as_bytes()).await.unwrap();
        native_error(&mut stream, status).await;
    }
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn missing_d_shared_setup_timeout_pause_fresh_connect_and_principal_quota_cleanup() {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Bootstrap, Carrier::Http, false, |c| {
        c.limits.channel_timeout = Duration::from_millis(180);
        c.admission.principal_associations = 1;
    })
    .await;
    let (mut u, _, _) = open(&fixture).await;
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), u.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let first = fixture.connect().await.unwrap();
    fixture.ready(1).await;
    assert!(fixture.connect().await.is_err());
    fixture.handle.pause();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !first.is_closed() || fixture.handle.status().associations != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.handle.resume();
    let second = fixture.connect().await.unwrap();
    assert_ne!(first.connection_id, second.connection_id);
    second.close().await;
    first.close().await;
    fixture.stop().await;
}

#[tokio::test]
async fn wrong_noise_pin_and_carrier_mismatch_cannot_release_credentials_or_bind_principal() {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |_| {}).await;
    let mut wrong = fixture.security();
    wrong.server_public_key = [1; 32];
    assert!(http::connect_with_budget(
        fixture.handle.local_addr(),
        authority(),
        None,
        wrong,
        b"never-hello".to_vec(),
        (runtime(), Limits::default()),
        budget()
    )
    .await
    .is_err());
    assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
    let u = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let d = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let mut wrong = fixture.security();
    wrong.context.carrier = Carrier::Tcp;
    assert!(matches!(
        http::connect_streams_with_budget(
            u,
            d,
            authority(),
            wrong,
            vec![],
            (runtime(), Limits::default()),
            budget()
        )
        .await,
        Err(Error::Configuration)
    ));
    fixture.stop().await;
}

// Real local TLS 1.3 with an explicit ephemeral root, normal rustls chain/name/
// time validation, no resumption or early data. Not a fake metadata-only proof.
struct LocalTls {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    application_writes: Arc<AtomicUsize>,
    bad_client_role: bool,
}
impl LocalTls {
    fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
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
        server.alpn_protocols = client.alpn_protocols.clone();
        Self {
            client: Arc::new(client),
            server: Arc::new(server),
            application_writes: Arc::new(AtomicUsize::new(0)),
            bad_client_role: false,
        }
    }
}
impl TlsProvider for LocalTls {
    fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
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
                role: if self.bad_client_role {
                    TlsRole::Server
                } else {
                    TlsRole::Client
                },
                protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                early_data: if session.is_early_data_accepted() {
                    EarlyData::Enabled
                } else {
                    EarlyData::Disabled
                },
            };
            Ok(ProviderTlsStream::new(
                Box::new(Counted {
                    stream,
                    writes: self.application_writes.clone(),
                }),
                metadata,
            ))
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
            Ok(ProviderTlsStream::new(
                Box::new(Counted {
                    stream,
                    writes: self.application_writes.clone(),
                }),
                metadata,
            ))
        })
    }
}

struct Counted<S> {
    stream: S,
    writes: Arc<AtomicUsize>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.writes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut this.stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn https_real_certificate_metadata_and_original_pair_budget_precede_m1() {
    let _serial = SERIAL.lock().await;
    for bad_role in [false, true] {
        let mut provider = LocalTls::new();
        provider.bad_client_role = bad_role;
        let provider = Arc::new(provider);
        let observed = provider.application_writes.clone();
        let fixture = Fixture::start(Mode::Returning, Carrier::Https, false, |c| {
            c.tls = Some(provider.clone())
        })
        .await;
        let selected = if bad_role {
            authority()
        } else {
            Authority::new("wrong.invalid:38080").unwrap()
        };
        let result = http::connect_with_budget(
            fixture.handle.local_addr(),
            selected,
            Some(provider),
            fixture.security(),
            b"never-hello".to_vec(),
            (runtime(), Limits::default()),
            budget(),
        )
        .await;
        assert!(matches!(result, Err(Error::Configuration)));
        assert_eq!(observed.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
        fixture.stop().await;
    }
    let provider = Arc::new(LocalTls::new());
    let observed = provider.application_writes.clone();
    let fixture = Fixture::start(Mode::Returning, Carrier::Https, false, |c| {
        c.tls = Some(provider.clone())
    })
    .await;
    let u = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let d = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let expected = authority().tls_authority().unwrap();
    let u = tls::connect_stream_with_budget(u, provider.as_ref(), expected.clone(), budget())
        .await
        .unwrap();
    let d = tls::connect_stream_with_budget(d, provider.as_ref(), expected, budget())
        .await
        .unwrap();
    assert!(matches!(
        http::connect_tls_streams_with_budget(
            u,
            d,
            authority(),
            fixture.security(),
            vec![],
            (runtime(), Limits::default())
        )
        .await,
        Err(Error::Configuration)
    ));
    assert_eq!(observed.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn listener_rate_and_unbound_socket_quotas_precede_lookup_and_stopping_joins_silent_streams()
{
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |c| {
        c.admission.unbound_streams = 2;
        c.admission.sockets = 2 * c.admission.associations + 2;
        c.admission.source_open_burst = 1;
        c.admission.source_opens_per_second = 1;
    })
    .await;
    let (_u, _, _) = open(&fixture).await;
    let config = fixture.security();
    let env = OpenEnvelope::new(config.context.encode().unwrap()).unwrap();
    let (_, m1) = ClientHandshake::start(config).unwrap();
    let mut rejected = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    rejected
        .write_all(&codec::request(Operation::Open, &authority(), None, None, &m1, &env).unwrap())
        .await
        .unwrap();
    // The limiter refuses without reading M1 or looking up an enrollment key.
    native_error(&mut rejected, 429).await;
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 1);
    let _silent1 = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    let _silent2 = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(fixture.handle.status().unbound_streams <= 2);
    fixture.stop().await;
}

#[tokio::test]
async fn dropped_inline_server_owner_is_observable_and_retires_active_client() {
    let _serial = SERIAL.lock().await;
    let (private_key, public) = kernel::generate_server_key().unwrap();
    let security = Arc::new(Security {
        mode: Mode::Bootstrap,
        carrier: Carrier::Http,
        server_key_id: 1,
        scope: context(Mode::Bootstrap, Carrier::Http).scope,
        private_key,
        store: None,
    });
    let mut config = ServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        authority(),
        security,
        auth(false, Arc::new(AtomicUsize::new(0))),
        echo(),
    );
    config.runtime = runtime();
    let (handle, run) = http::bind(config).await.unwrap();
    // Poll both inline, then drop ServerRun itself (not a Tokio JoinHandle, which
    // would detach its caller task). Its retained fallback must own cleanup.
    let client = {
        let connect = http::connect_with_budget(
            handle.local_addr(),
            authority(),
            None,
            client(public, Mode::Bootstrap, Carrier::Http),
            vec![],
            (runtime(), Limits::default()),
            budget(),
        );
        tokio::pin!(connect);
        let mut run = run;
        let client = tokio::select! { result = &mut connect => result.unwrap(), status = &mut run => panic!("unexpected stop: {status:?}") };
        drop(run);
        client
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        while !handle.status().stopped || !client.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(handle.status().associations, 0);
    assert_eq!(handle.status().sockets, 0);
    assert!(http::retired_servers().iter().all(|status| status.stopped));
    client.close().await;
}

fn native_header(status: u16) -> String {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        410 => "Gone",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => panic!("unexpected native status"),
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n{}Cache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
        if status == 405 { "Allow: POST\r\n" } else { "" }
    )
}

async fn native_error<S: AsyncRead + Unpin + ?Sized>(stream: &mut S, status: u16) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut bytes = Vec::with_capacity(128);
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(
                bytes.len() < 128,
                "native error header exceeded its static bound"
            );
            bytes.push(stream.read_u8().await.unwrap());
        }
        // Exact comparison rejects diagnostic/credential reflection, cookies,
        // challenges, redirects, routes, counters, extra headers and any body.
        assert_eq!(bytes, native_header(status).as_bytes());
        no_native_bytes(stream).await;
    })
    .await
    .unwrap();
}

async fn no_native_bytes<S: AsyncRead + Unpin + ?Sized>(stream: &mut S) {
    let mut body = [0];
    match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut body))
        .await
        .unwrap()
    {
        Ok(0) => {}
        // Rejection/abort does not drain an attacker body. TCP may reset with
        // unread input; TLS may close without close_notify. Neither allows even
        // one application byte, a timeout, or an unrelated I/O failure here.
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof
            ) => {}
        result => panic!("connection did not close without application bytes: {result:?}"),
    }
}

fn poll_header(fixture: &Fixture) -> String {
    let envelope = OpenEnvelope::new(fixture.security().context.encode().unwrap()).unwrap();
    let route = http::Route::parse(&"0".repeat(64)).unwrap();
    String::from_utf8(
        codec::request(
            Operation::Poll,
            &authority(),
            Some(&route),
            Some(0),
            &[],
            &envelope,
        )
        .unwrap(),
    )
    .unwrap()
}
async fn native_socket(fixture: &Fixture, tls: Option<&LocalTls>) -> BoxIo {
    let stream = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    if let Some(tls) = tls {
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned()).unwrap();
        Box::new(
            tokio_rustls::TlsConnector::from(tls.client.clone())
                .connect(name, stream)
                .await
                .unwrap(),
        )
    } else {
        Box::new(stream)
    }
}
fn extra_header(base: &str, field: &str) -> String {
    format!("{}{field}\r\n\r\n", &base[..base.len() - 2])
}

#[tokio::test]
async fn native_first_request_status_table_over_real_http_and_verified_https() {
    let _serial = SERIAL.lock().await;
    for carrier in [Carrier::Http, Carrier::Https] {
        let tls = Arc::new(LocalTls::new());
        let fixture = Fixture::start(Mode::Returning, carrier, false, |c| {
            if carrier == Carrier::Https {
                c.tls = Some(tls.clone());
            }
        })
        .await;
        let base = poll_header(&fixture);
        let credential = "fixture-must-not-be-reflected";
        let mut cases = vec![
            (base.replacen("POST ", "GET ", 1), 405),
            ("GET /syntra/1.0/http/poll HTTP/1.1\r\n\r\n".into(), 405),
            (base.replacen("HTTP/1.1", "HTTP/1.0", 1), 505),
            (base.replacen("HTTP/1.1", "HTTP/2.0", 1), 505),
            (base.replacen("HTTP/1.1", "HTTP/x.y", 1), 400),
            (base.replacen("POST ", "POST  ", 1), 400),
            (
                base.replace(Operation::Poll.path(), "/not-a-syntra-path"),
                404,
            ),
            (
                base.replace(Operation::Poll.path(), "/syntra/1.0/http/poll?query"),
                404,
            ),
            (
                base.replace(Operation::Poll.path(), "http://other.invalid/poll"),
                400,
            ),
            (
                base.replace("Host: 127.0.0.1:38080", "Host: other.invalid:80"),
                404,
            ),
            (base.replace("Host: 127.0.0.1:38080\r\n", ""), 400),
            (extra_header(&base, "Host: 127.0.0.1:38080"), 400),
            (extra_header(&base, "Origin: null"), 403),
            (extra_header(&base, "Origin: https://denied.invalid"), 403),
            (
                extra_header(
                    &base,
                    "Origin: https://one.invalid\r\nOrigin: https://two.invalid",
                ),
                403,
            ),
            (extra_header(&base, "Content-Length: 0"), 400),
            (extra_header(&base, "Transfer-Encoding: chunked"), 400),
            (extra_header(&base, "Content-Encoding: gzip"), 400),
            (extra_header(&base, "Connection: close"), 400),
            (extra_header(&base, "Syntra-Unknown: 1"), 400),
            (
                extra_header(&base, "Content-Type: application/octet-stream"),
                400,
            ),
            (
                base.replace("Accept: application/octet-stream", "Accept: text/plain"),
                400,
            ),
            (base.replace("Cache-Control: no-store\r\n", ""), 400),
            (base.replace("Content-Length: 0", "Content-Length: 00"), 400),
            (base.replace("Syntra-Poll: 0", "Syntra-Poll: 00"), 400),
            (
                base.replace("Syntra-Poll: 0", "Syntra-Poll: 18446744073709551616"),
                400,
            ),
            (base.replace(&"0".repeat(64), &"A".repeat(64)), 400),
            (
                base.replace(&format!("Syntra-Route: {}\r\n", "0".repeat(64)), ""),
                400,
            ),
            (base.replace("Content-Length: 0", "Content-Length: 1"), 413),
            (base.clone(), 410),
        ];
        for name in ["Authorization", "Cookie", "Proxy-Authorization"] {
            cases.push((extra_header(&base, &format!("{name}: {credential}")), 400));
        }
        for field in [
            "Expect: 100-continue",
            "Upgrade: websocket",
            "TE: trailers",
            "Trailer: X-End",
            "Set-Cookie: fixture-must-not-be-reflected",
        ] {
            cases.push((extra_header(&base, field), 400));
        }
        let envelope = OpenEnvelope::new(fixture.security().context.encode().unwrap()).unwrap();
        let route = http::Route::parse(&"0".repeat(64)).unwrap();
        let send = String::from_utf8(
            codec::request(
                Operation::Send,
                &authority(),
                Some(&route),
                Some(0),
                &[0; 17],
                &envelope,
            )
            .unwrap(),
        )
        .unwrap();
        cases.push((send.clone(), 400)); // send is not a legal first operation
        cases.push((
            send.replace("Content-Length: 17", "Content-Length: 65536"),
            413,
        ));
        cases.push((
            send.replace("Content-Length: 17", "Content-Length: 18446744073709551616"),
            413,
        ));
        cases.push((
            String::from_utf8(
                codec::request(
                    Operation::Close,
                    &authority(),
                    Some(&route),
                    None,
                    &[],
                    &envelope,
                )
                .unwrap(),
            )
            .unwrap(),
            400,
        ));
        cases.push((format!("POST {} HTTP/1.1\r\nHost: {}\r\nAccept: application/octet-stream\r\nCache-Control: no-store\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", Operation::Open.path(), authority().as_str(), kernel::MAX_WRAPPER + 1), 413));
        for (request, status) in cases {
            let mut stream = native_socket(
                &fixture,
                (carrier == Carrier::Https).then_some(tls.as_ref()),
            )
            .await;
            // Deliberately send headers ONLY, including positive declared body
            // lengths. Every rejection must finish before body/Noise lookup.
            stream.write_all(request.as_bytes()).await.unwrap();
            native_error(&mut *stream, status).await;
        }
        assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
        fixture.stop().await;
    }
}

fn header_size(base: &str, target: usize) -> String {
    let mut text = base[..base.len() - 2].to_owned();
    let mut remaining = target - base.len();
    let mut index = 0;
    while remaining != 0 {
        let mut chunk = remaining.min(codec::MAX_FIELD_LINE);
        if remaining > chunk && remaining - chunk < 16 {
            chunk -= 16;
        }
        let prefix = format!("X-Pad-{index}: ");
        text.push_str(&prefix);
        text.push_str(&"p".repeat(chunk - prefix.len() - 2));
        text.push_str("\r\n");
        remaining -= chunk;
        index += 1;
    }
    text.push_str("\r\n");
    assert_eq!(text.len(), target);
    text
}
#[tokio::test]
async fn native_header_byte_line_and_count_bounds_are_inclusive_and_pre_body() {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |_| {}).await;
    let base = poll_header(&fixture);
    let mut cases = vec![
        (header_size(&base, codec::MAX_HEADERS), 410),
        (header_size(&base, codec::MAX_HEADERS + 1), 431),
    ];
    for (size, status) in [
        (codec::MAX_FIELD_LINE, 410),
        (codec::MAX_FIELD_LINE + 1, 431),
    ] {
        cases.push((
            extra_header(
                &base,
                &format!("X-Pad: {}", "p".repeat(size - "X-Pad: ".len() - 2)),
            ),
            status,
        ));
    }
    let fields = base
        .split("\r\n")
        .skip(1)
        .filter(|line| !line.is_empty())
        .count();
    for (count, status) in [(codec::MAX_FIELDS, 410), (codec::MAX_FIELDS + 1, 431)] {
        let mut request = base.clone();
        for n in fields..count {
            request = extra_header(&request, &format!("X-Field-{n}: p"));
        }
        cases.push((request, status));
    }
    for (size, status) in [
        (codec::MAX_START_LINE, 404),
        (codec::MAX_START_LINE + 1, 431),
    ] {
        let (_, rest) = base.split_once("\r\n").unwrap();
        let request = format!("POST /{} HTTP/1.1\r\n{rest}", "p".repeat(size - 17));
        assert_eq!(request.split_once("\r\n").unwrap().0.len() + 2, size);
        cases.push((request, status));
    }
    for (request, status) in cases {
        let mut stream = native_socket(&fixture, None).await;
        stream.write_all(request.as_bytes()).await.unwrap();
        native_error(&mut *stream, status).await;
    }
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn native_rate_and_capacity_rejections_have_no_body_or_second_crypto_lookup() {
    let _serial = SERIAL.lock().await;
    for condition in [
        "source-rate",
        "listener-rate",
        "associations",
        "handshakes",
        "bytes",
    ] {
        let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |c| match condition {
            "source-rate" => {
                c.admission.source_open_burst = 1;
                c.admission.source_opens_per_second = 1;
            }
            "listener-rate" => {
                c.admission.open_burst = 1;
                c.admission.opens_per_second = 1;
            }
            "associations" => c.admission.associations = 1,
            "handshakes" => c.admission.handshakes = 1,
            "bytes" => c.admission.aggregate_bytes = 150 * 1024 * 1024,
            _ => unreachable!(),
        })
        .await;
        let (u, _, _) = open(&fixture).await;
        let security = fixture.security();
        let envelope = OpenEnvelope::new(security.context.encode().unwrap()).unwrap();
        let (_, m1) = ClientHandshake::start(security).unwrap();
        let request =
            codec::request(Operation::Open, &authority(), None, None, &m1, &envelope).unwrap();
        let mut stream = native_socket(&fixture, None).await;
        stream.write_all(&request).await.unwrap();
        native_error(
            &mut *stream,
            if condition.ends_with("rate") {
                429
            } else {
                503
            },
        )
        .await;
        assert_eq!(fixture.lookups.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
        drop(u);
        fixture.stop().await;
    }
}

#[tokio::test]
async fn native_allowlisted_origin_and_retired_route_are_still_opaque_410s() {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |c| {
        c.origins =
            http::OriginPolicy::allow_exact(vec!["https://allowed.invalid".to_owned()]).unwrap();
        c.limits.channel_timeout = Duration::from_millis(200);
    })
    .await;
    let base = poll_header(&fixture);
    for (origin, status) in [
        ("https://allowed.invalid", 410),
        ("https://other.invalid", 403),
        ("null", 403),
    ] {
        let mut stream = native_socket(&fixture, None).await;
        stream
            .write_all(extra_header(&base, &format!("Origin: {origin}")).as_bytes())
            .await
            .unwrap();
        native_error(&mut *stream, status).await;
    }
    let (u, route, env) = open(&fixture).await;
    drop(u);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.handle.status().associations != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut stream = native_socket(&fixture, None).await;
    stream
        .write_all(
            &codec::request(
                Operation::Poll,
                &authority(),
                Some(&route),
                Some(0),
                &[],
                &env,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    native_error(&mut *stream, 410).await;
    let (mut expired, route, env) = open(&fixture).await;
    no_native_bytes(&mut expired).await; // first-D/hello deadline, no new budget
    let mut stream = native_socket(&fixture, None).await;
    stream
        .write_all(
            &codec::request(
                Operation::Poll,
                &authority(),
                Some(&route),
                Some(0),
                &[],
                &env,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    native_error(&mut *stream, 410).await;
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn native_bad_first_poll_or_substituted_upload_retires_only_the_named_slot() {
    let _serial = SERIAL.lock().await;
    for operation in [Operation::Poll, Operation::Send, Operation::Close] {
        let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |_| {}).await;
        let (u1, route1, env) = open(&fixture).await;
        let (u2, route2, _) = open(&fixture).await;
        let (counter, body) = match operation {
            Operation::Poll => (Some(1), vec![]),
            Operation::Send => (Some(0), vec![0; 17]),
            Operation::Close => (None, vec![]),
            _ => unreachable!(),
        };
        let mut stream = native_socket(&fixture, None).await;
        stream
            .write_all(
                &codec::request(operation, &authority(), Some(&route1), counter, &body, &env)
                    .unwrap(),
            )
            .await
            .unwrap();
        native_error(&mut *stream, 400).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while fixture.handle.status().associations != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // The unaffected slot still accepts its FIRST D. A duplicate ownership
        // claim then gets an empty 410 and retires that slot, without crypto.
        let poll = codec::request(
            Operation::Poll,
            &authority(),
            Some(&route2),
            Some(0),
            &[],
            &env,
        )
        .unwrap();
        let mut d = native_socket(&fixture, None).await;
        d.write_all(&poll).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut duplicate = native_socket(&fixture, None).await;
        duplicate.write_all(&poll).await.unwrap();
        native_error(&mut *duplicate, 410).await;
        assert_eq!(fixture.lookups.load(Ordering::SeqCst), 2);
        assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
        drop((u1, u2, d));
        fixture.stop().await;
    }
}

#[tokio::test]
async fn incomplete_unsafe_and_post_body_context_failures_close_without_native_status() {
    let _serial = SERIAL.lock().await;
    let fixture = Fixture::start(Mode::Returning, Carrier::Http, false, |_| {}).await;
    for bytes in [
        b"POST /syntra/1.0/http/open HTTP/1.1\n\n".as_slice(),
        b"POST /syntra/1.0/http/open HTTP/1.1\r".as_slice(),
    ] {
        let mut stream = TcpStream::connect(fixture.handle.local_addr())
            .await
            .unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.shutdown().await.unwrap();
        no_native_bytes(&mut stream).await;
    }
    let mut security = fixture.security();
    security.context.scope = b"different-scope".to_vec();
    let envelope = OpenEnvelope::new(security.context.encode().unwrap()).unwrap();
    let (_, m1) = ClientHandshake::start(security).unwrap();
    let mut stream = TcpStream::connect(fixture.handle.local_addr())
        .await
        .unwrap();
    stream
        .write_all(
            &codec::request(Operation::Open, &authority(), None, None, &m1, &envelope).unwrap(),
        )
        .await
        .unwrap();
    stream.write_all(&m1).await.unwrap();
    no_native_bytes(&mut stream).await;
    assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

// A test-only lower-bound allocator probe. Only managed runs install it, so the
// independent read-only reviewer harness can keep its own global allocator.
#[cfg(feature = "managed")]
mod allocation_probe {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        sync::atomic::{AtomicUsize, Ordering},
    };
    pub static LIVE: AtomicUsize = AtomicUsize::new(0);
    fn large(size: usize) -> bool {
        (1_000_000..1_050_000).contains(&size)
    }
    struct Probe;
    // SAFETY: Every operation forwards the exact pointer/layout to System. The
    // only extra effect is allocation-free, thread-safe size accounting after
    // successful allocation/reallocation (or before the matching deallocation).
    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: Caller supplies GlobalAlloc's valid layout unchanged.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() && large(layout.size()) {
                LIVE.fetch_add(layout.size(), Ordering::SeqCst);
            }
            pointer
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: Same valid layout and zeroed-allocation contract as System.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() && large(layout.size()) {
                LIVE.fetch_add(layout.size(), Ordering::SeqCst);
            }
            pointer
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if large(layout.size()) {
                LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
            }
            // SAFETY: Caller supplies the original live pointer and its layout.
            unsafe { System.dealloc(pointer, layout) };
        }
        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: System receives the caller's original live allocation and
            // requested new size; failure leaves that allocation and count intact.
            let next = unsafe { System.realloc(pointer, layout, size) };
            if !next.is_null() {
                if large(layout.size()) {
                    LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
                }
                if large(size) {
                    LIVE.fetch_add(size, Ordering::SeqCst);
                }
            }
            next
        }
    }
    #[global_allocator]
    static ALLOCATOR: Probe = Probe;
}

#[cfg(feature = "managed")]
mod review_fixes {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64},
        Mutex,
    };
    use syntra_net::{
        network::{Network, NetworkConfig},
        ConnectionAuthorization,
    };
    use syntra_runtime::{ExecutionBudget, ExecutionLease, Principal};

    async fn settled(mut ready: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !ready() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    struct FixSource(AtomicU64);
    impl syntra_runtime::elapsed::ElapsedSource for FixSource {
        fn elapsed(&self) -> Option<Duration> {
            Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    struct FixFactory {
        clock: ElapsedClock,
        phase: &'static str,
        execution: ExecutionBudget,
        validity_panic: Arc<AtomicBool>,
        lane: Option<Arc<tokio::sync::Semaphore>>,
    }
    struct FixAuth(bool);
    impl Authenticator for FixAuth {
        fn authenticate(&self, _: &[u8]) -> Result<Principal, AuthError> {
            assert!(!self.0, "fixture authentication panic");
            Ok(Principal::new("http-review-fix-principal"))
        }
    }
    struct FixValidity(Arc<AtomicBool>);
    impl ConnectionAuthorization for FixValidity {
        fn check(&self) -> futures_util::future::BoxFuture<'_, Result<(), AuthError>> {
            Box::pin(async {
                assert!(!self.0.load(Ordering::SeqCst), "fixture validity panic");
                Ok(())
            })
        }
        fn interval(&self) -> Duration {
            Duration::from_millis(20)
        }
        fn read_timeout(&self) -> Duration {
            Duration::from_millis(10)
        }
        fn close_timeout(&self) -> Duration {
            Duration::from_secs(2)
        }
    }
    impl AuthenticatorFactory for FixFactory {
        fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
            assert_ne!(self.phase, "prepare", "fixture factory panic");
            Ok(Arc::new(FixAuth(self.phase == "authenticate")))
        }
        fn recovery_service(&self) -> Option<Arc<syntra_runtime::recovery::wire::RecoveryService>> {
            assert_ne!(
                self.phase, "recovery",
                "fixture post-construction factory panic"
            );
            None
        }
        fn elapsed_clock(&self) -> ElapsedClock {
            self.clock.clone()
        }
        fn execution_budget(&self) -> ExecutionBudget {
            self.execution.clone()
        }
        fn blocking_admission(&self) -> Option<Arc<tokio::sync::Semaphore>> {
            self.lane.clone()
        }
        fn connection_authorization(
            &self,
            _: &VerifiedIdentity,
        ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
            Ok((self.phase == "validity").then(|| {
                Arc::new(FixValidity(self.validity_panic.clone()))
                    as Arc<dyn ConnectionAuthorization>
            }))
        }
    }
    fn factory_with_clock(clock: ElapsedClock) -> Arc<FixFactory> {
        Arc::new(FixFactory {
            clock,
            phase: "none",
            execution: ExecutionBudget::new(16),
            validity_panic: Arc::new(AtomicBool::new(false)),
            lane: None,
        })
    }

    struct FixTls {
        tls: LocalTls,
        stall: Arc<AtomicBool>,
        panic_write: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
        wake: Arc<futures_util::task::AtomicWaker>,
        jump: Option<(Arc<FixSource>, u64)>,
        after_cutoff: Arc<AtomicUsize>,
        tls_at: Option<Arc<FixSource>>,
    }
    struct FixIo<S> {
        inner: S,
        stall: Arc<AtomicBool>,
        panic_write: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
        wake: Arc<futures_util::task::AtomicWaker>,
        jump: Option<(Arc<FixSource>, u64)>,
        jumped: bool,
        after_cutoff: Arc<AtomicUsize>,
    }
    impl<S: AsyncRead + Unpin> AsyncRead for FixIo<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.jumped {
                this.after_cutoff.fetch_add(1, Ordering::SeqCst);
            }
            let old = buf.filled().len();
            let result = Pin::new(&mut this.inner).poll_read(cx, buf);
            if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > old && !this.jumped {
                if let Some((source, millis)) = &this.jump {
                    source.0.store(*millis, Ordering::SeqCst);
                    this.jumped = true;
                }
            }
            result
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for FixIo<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.wake.register(cx.waker());
            if bytes.starts_with(b"HTTP/1.1 200") {
                assert!(
                    !this.panic_write.load(Ordering::SeqCst),
                    "fixture protected-response I/O panic"
                );
                if this.stall.load(Ordering::SeqCst) {
                    this.entered.store(true, Ordering::SeqCst);
                    return Poll::Pending;
                }
            }
            Pin::new(&mut this.inner).poll_write(cx, bytes)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }
    impl FixTls {
        fn new(jump: Option<(Arc<FixSource>, u64)>) -> Self {
            Self {
                tls: LocalTls::new(),
                stall: Arc::new(AtomicBool::new(false)),
                panic_write: Arc::new(AtomicBool::new(false)),
                entered: Arc::new(AtomicBool::new(false)),
                wake: Arc::new(futures_util::task::AtomicWaker::new()),
                jump,
                after_cutoff: Arc::new(AtomicUsize::new(0)),
                tls_at: None,
            }
        }
    }
    impl TlsProvider for FixTls {
        fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
            self.tls.connect(stream, authority)
        }
        fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
            Box::pin(async move {
                let stream = tokio_rustls::TlsAcceptor::from(self.tls.server.clone())
                    .accept(stream)
                    .await
                    .map_err(|_| Error::Configuration)?;
                let session = stream.get_ref().1;
                let metadata = TlsMetadata {
                    authority,
                    role: TlsRole::Server,
                    protocol_version: session.protocol_version().map(u16::from).unwrap(),
                    alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                    early_data: EarlyData::Disabled,
                };
                if let Some(source) = &self.tls_at {
                    source.0.fetch_max(4000, Ordering::SeqCst);
                }
                Ok(ProviderTlsStream::new(
                    Box::new(FixIo {
                        inner: stream,
                        stall: self.stall.clone(),
                        panic_write: self.panic_write.clone(),
                        entered: self.entered.clone(),
                        wake: self.wake.clone(),
                        jump: self.jump.clone(),
                        jumped: false,
                        after_cutoff: self.after_cutoff.clone(),
                    }),
                    metadata,
                ))
            })
        }
    }

    #[tokio::test]
    async fn exact_header_cutoff_stops_real_tls_buffered_raw_polls() {
        let _serial = SERIAL.lock().await;
        for millis in [6000, 7000] {
            let source = Arc::new(FixSource(AtomicU64::new(0)));
            let clock = ElapsedClock::with_source(source.clone());
            // Make the accepted-socket origin exactly anchor+1s, ahead of
            // scheduler jitter; anchor+6s is its exact inclusive 5s cutoff.
            source.0.store(1000, Ordering::SeqCst);
            let provider = Arc::new(FixTls::new(Some((source.clone(), millis))));
            let fixture = Fixture::start(Mode::Returning, Carrier::Https, false, |c| {
                c.tls = Some(provider.clone());
                c.authenticator = factory_with_clock(clock);
            })
            .await;
            assert!(fixture.connect().await.is_err());
            assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
            fixture.stop().await;
            assert_eq!(provider.after_cutoff.load(Ordering::SeqCst), 0);
        }
    }

    struct RejectTls {
        tls: LocalTls,
        source: Arc<FixSource>,
        partial: bool,
        stall: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
        wake: Arc<futures_util::task::AtomicWaker>,
    }
    struct RejectIo<S> {
        inner: S,
        source: Arc<FixSource>,
        partial: bool,
        stall: Arc<AtomicBool>,
        entered: Arc<AtomicBool>,
        polls: Arc<AtomicUsize>,
        wake: Arc<futures_util::task::AtomicWaker>,
    }
    impl<S: AsyncRead + Unpin> AsyncRead for RejectIo<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for RejectIo<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            this.wake.register(cx.waker());
            this.entered.store(true, Ordering::SeqCst);
            if this.stall.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            if this.partial {
                let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..1]);
                if matches!(result, Poll::Ready(Ok(1))) {
                    this.source.0.store(6000, Ordering::SeqCst);
                }
                result
            } else {
                Pin::new(&mut this.inner).poll_write(cx, bytes)
            }
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }
    impl TlsProvider for RejectTls {
        fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
            self.tls.connect(stream, authority)
        }
        fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
            Box::pin(async move {
                let stream = tokio_rustls::TlsAcceptor::from(self.tls.server.clone())
                    .accept(stream)
                    .await
                    .map_err(|_| Error::Configuration)?;
                let session = stream.get_ref().1;
                let metadata = TlsMetadata {
                    authority,
                    role: TlsRole::Server,
                    protocol_version: session.protocol_version().map(u16::from).unwrap(),
                    alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                    early_data: EarlyData::Disabled,
                };
                Ok(ProviderTlsStream::new(
                    Box::new(RejectIo {
                        inner: stream,
                        source: self.source.clone(),
                        partial: self.partial,
                        stall: self.stall.clone(),
                        entered: self.entered.clone(),
                        polls: self.polls.clone(),
                        wake: self.wake.clone(),
                    }),
                    metadata,
                ))
            })
        }
    }

    #[tokio::test]
    async fn native_rejection_backpressure_partial_write_and_pause_keep_the_original_phase() {
        let _serial = SERIAL.lock().await;
        for mode in ["deadline", "partial", "pause"] {
            let source = Arc::new(FixSource(AtomicU64::new(0)));
            let clock = ElapsedClock::with_source(source.clone());
            source.0.store(1000, Ordering::SeqCst);
            let provider = Arc::new(RejectTls {
                tls: LocalTls::new(),
                source: source.clone(),
                partial: mode == "partial",
                stall: Arc::new(AtomicBool::new(mode != "partial")),
                entered: Arc::new(AtomicBool::new(false)),
                polls: Arc::new(AtomicUsize::new(0)),
                wake: Arc::new(futures_util::task::AtomicWaker::new()),
            });
            let fixture = Fixture::start(Mode::Returning, Carrier::Https, false, |c| {
                c.tls = Some(provider.clone());
                c.authenticator = factory_with_clock(clock.clone());
            })
            .await;
            let mut stream = native_socket(&fixture, Some(&provider.tls)).await;
            stream
                .write_all(
                    extra_header(&poll_header(&fixture), "Cookie: fixture-not-reflected")
                        .as_bytes(),
                )
                .await
                .unwrap();
            settled(|| provider.entered.load(Ordering::SeqCst)).await;
            let polls = provider.polls.load(Ordering::SeqCst);
            if mode == "pause" {
                fixture.handle.pause();
            } else if mode == "deadline" {
                source.0.store(6000, Ordering::SeqCst);
                clock.wake();
            }
            provider.stall.store(false, Ordering::SeqCst);
            provider.wake.wake();
            let mut emitted = Vec::new();
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let mut byte = [0];
                    match stream.read(&mut byte).await {
                        Ok(0) => break,
                        Ok(1) => {
                            emitted.push(byte[0]);
                            assert!(mode == "partial" && emitted.as_slice() == b"H");
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::UnexpectedEof
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::ConnectionAborted
                            ) =>
                        {
                            break
                        }
                        other => panic!("unexpected rejected-stream read: {other:?}"),
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(
                provider.polls.load(Ordering::SeqCst),
                polls,
                "native output was repolled after its gate closed"
            );
            assert_eq!(polls, 1);
            assert_eq!(fixture.lookups.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.auths.load(Ordering::SeqCst), 0);
            fixture.stop().await;
        }
    }

    #[tokio::test]
    async fn completed_tls_header_phase_does_not_take_time_from_m1s_own_phase() {
        let _serial = SERIAL.lock().await;
        let source = Arc::new(FixSource(AtomicU64::new(0)));
        let mut provider = FixTls::new(None);
        provider.tls_at = Some(source.clone());
        let provider = Arc::new(provider);
        struct AdvanceLookup(Arc<FixSource>);
        impl KeyStore for AdvanceLookup {
            fn lookup(&self, _: &Context) -> Result<Secret32, kernel::Error> {
                self.0 .0.fetch_max(6000, Ordering::SeqCst);
                Ok(Secret32::new([8; 32]))
            }
        }
        let fixture = Fixture::start(Mode::Returning, Carrier::Https, false, |c| {
            c.tls = Some(provider.clone());
            c.authenticator = factory_with_clock(ElapsedClock::with_source(source.clone()));
            let mut security = Security {
                mode: c.security.mode,
                carrier: c.security.carrier,
                server_key_id: c.security.server_key_id,
                scope: c.security.scope.clone(),
                private_key: Secret32::new(*c.security.private_key.expose()),
                store: None,
            };
            security.store = Some(Arc::new(AdvanceLookup(source.clone())));
            c.security = Arc::new(security);
        })
        .await;
        // Raw test peer opens only U. D is intentionally not accepted before M2.
        let socket = TcpStream::connect(fixture.handle.local_addr())
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned()).unwrap();
        let mut socket = tokio_rustls::TlsConnector::from(provider.tls.client.clone())
            .connect(name, socket)
            .await
            .unwrap();
        let security = fixture.security();
        let env = OpenEnvelope::new(security.context.encode().unwrap()).unwrap();
        let (noise, m1) = ClientHandshake::start(security).unwrap();
        socket
            .write_all(
                &codec::request(Operation::Open, &authority(), None, None, &m1, &env).unwrap(),
            )
            .await
            .unwrap();
        socket.write_all(&m1).await.unwrap();
        let mut response = Vec::new();
        while !response.ends_with(b"\r\n\r\n") {
            response.push(socket.read_u8().await.unwrap());
        }
        codec::parse_response(&response, Operation::Open).unwrap();
        let mut m2 = [0; 48];
        socket.read_exact(&mut m2).await.unwrap();
        noise.finish(&m2).unwrap();
        assert_eq!(source.0.load(Ordering::SeqCst), 6000);
        drop(socket);
        fixture.stop().await;
    }

    #[tokio::test]
    async fn allocator_lower_bound_and_runtime_terminal_capacity_are_both_charged() {
        let _serial = SERIAL.lock().await;
        let provider = Arc::new(FixTls::new(None));
        let effects = Arc::new(AtomicUsize::new(0));
        let fixture = Fixture::start(Mode::Returning, Carrier::Https, false, |c| {
            c.tls = Some(provider.clone());
            c.runtime.max_outstanding = 16;
            c.runtime.writer_capacity = 64;
            // The old 128-MiB configuration is now rejected by the independent
            // reservation unit regression. This positive lane funds its real
            // terminal capacity instead of shrinking runtime admission silently.
            c.admission.aggregate_bytes = 256 * 1024 * 1024;
            let effects = effects.clone();
            c.handler = Arc::new(FnHandler(
                move |_: String, _: Vec<u8>, _: syntra_runtime::CancelToken| {
                    effects.fetch_add(1, Ordering::SeqCst);
                    async { HandlerOutcome::Payload(vec![7; 1_000_000]) }
                },
            ));
        })
        .await;
        let client = http::connect_with_budget(
            fixture.handle.local_addr(),
            authority(),
            fixture.provider.clone(),
            fixture.security(),
            vec![],
            (
                ConnectionConfig {
                    max_outstanding: 256,
                    writer_capacity: 256,
                    ..runtime()
                },
                Limits::default(),
            ),
            budget(),
        )
        .await
        .unwrap();
        fixture.ready(1).await;
        let host = fixture.handle.hosts()[0].clone();
        let baseline = allocation_probe::LIVE.load(Ordering::SeqCst);
        provider.stall.store(true, Ordering::SeqCst);
        let mut calls = Vec::new();
        for i in 1..=120 {
            let conn = client.conn.clone();
            calls.push(tokio::spawn(async move {
                conn.call("/test.Service/Large", vec![], 10_000).await
            }));
            settled(|| effects.load(Ordering::SeqCst) >= i && host.inflight_len() == 0).await;
        }
        let live = allocation_probe::LIVE
            .load(Ordering::SeqCst)
            .saturating_sub(baseline);
        let reserved = fixture.handle.status().reserved_bytes;
        eprintln!(
            "large-allocation lower bound={live}, reservation={reserved}, terminal workers={}",
            host.worker_len()
        );
        assert!(
            live > 128 * 1024 * 1024,
            "test must exercise the original undercharge"
        );
        assert!(
            live <= reserved,
            "retained allocations exceeded charged bytes"
        );
        assert!(
            host.worker_len() > 16,
            "selected replies must outlive execution slots in this repro"
        );
        assert!(
            host.worker_len() <= 16 + 64,
            "Host::output capacity contract changed"
        );
        let mut peak = host.worker_len();
        for i in 121..=160 {
            if host.is_closed() {
                break;
            }
            let conn = client.conn.clone();
            calls.push(tokio::spawn(async move {
                conn.call("/test.Service/Large", vec![], 10_000).await
            }));
            settled(|| {
                host.is_closed() || effects.load(Ordering::SeqCst) >= i && host.inflight_len() == 0
            })
            .await;
            peak = peak.max(host.worker_len());
            assert!(
                host.worker_len() <= 16 + 64,
                "independent terminal owners must remain bounded"
            );
        }
        settled(|| host.is_closed()).await;
        assert_eq!(
            peak,
            16 + 64,
            "do not replace the runtime contract with an arbitrary smaller output window"
        );
        provider.stall.store(false, Ordering::SeqCst);
        provider.wake.wake();
        fixture.handle.stop();
        for call in calls {
            assert!(call.await.unwrap().is_err());
        }
        client.close().await;
        fixture.stop().await;
    }

    #[tokio::test]
    async fn default_candidate_reservation_admits_one_usable_connection() {
        let _serial = SERIAL.lock().await;
        let fixture = Fixture::start(Mode::Bootstrap, Carrier::Http, false, |c| {
            let defaults = ServerConfig::new(
                c.address,
                c.authority.clone(),
                c.security.clone(),
                c.authenticator.clone(),
                c.handler.clone(),
            );
            c.runtime = defaults.runtime;
            c.limits = defaults.limits;
        })
        .await;
        let client = fixture.connect().await.unwrap();
        fixture.ready(1).await;
        assert_eq!(
            client
                .conn
                .call("/test.Service/Echo", vec![3], 3000)
                .await
                .unwrap(),
            [3]
        );
        client.close().await;
        fixture.stop().await;
    }

    struct PanicHandler {
        phase: &'static str,
        leases: tokio::sync::mpsc::UnboundedSender<ExecutionLease>,
    }
    impl Handler for PanicHandler {
        fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
            assert_ne!(self.phase, "authorize", "fixture authorization panic");
            Ok(())
        }
        fn handle(
            &self,
            _: String,
            bytes: Vec<u8>,
            _: syntra_runtime::CancelToken,
        ) -> syntra_runtime::host::HandlerFut {
            Box::pin(async { HandlerOutcome::Payload(bytes) })
        }
        fn handle_with_execution(
            &self,
            method: String,
            bytes: Vec<u8>,
            cancel: syntra_runtime::CancelToken,
            lease: ExecutionLease,
        ) -> syntra_runtime::host::HandlerFut {
            if self.phase == "handler" {
                self.leases.send(lease).unwrap();
                panic!("fixture leased handler panic");
            }
            self.handle(method, bytes, cancel)
        }
    }
    fn server_config(
        factory: Arc<dyn AuthenticatorFactory>,
        handler: Arc<dyn Handler>,
        provider: Arc<FixTls>,
    ) -> (ServerConfig, [u8; 32]) {
        let (private_key, public) = kernel::generate_server_key().unwrap();
        let security = Arc::new(Security {
            mode: Mode::Returning,
            carrier: Carrier::Https,
            server_key_id: 1,
            scope: context(Mode::Returning, Carrier::Https).scope,
            private_key,
            store: Some(Arc::new(Store(Arc::new(AtomicUsize::new(0))))),
        });
        let mut config = ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            authority(),
            security,
            factory,
            handler,
        );
        config.runtime = runtime();
        config.tls = Some(provider);
        (config, public)
    }
    async fn shutdown(
        mut network: Network,
        wait: Duration,
    ) -> (Network, syntra_net::network::ShutdownReport) {
        // spawn_blocking still has a current Tokio Handle, and Network correctly
        // refuses to block there. Exercise its ordinary-thread wait contract.
        let (done, receive) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let report = network.shutdown(wait);
            let _ = done.send((network, report));
        });
        let value = receive.await.unwrap();
        thread.join().unwrap();
        value
    }
    fn association_bytes(status: ServerStatus) -> usize {
        status.reserved_bytes
            - status.unbound_streams
                * (codec::MAX_HEADERS + kernel::MAX_WRAPPER).div_ceil(1024)
                * 1024
    }

    #[tokio::test]
    async fn managed_callback_panics_keep_driver_host_and_external_lease_under_the_same_owner() {
        let _serial = SERIAL.lock().await;
        for phase in [
            "authenticate",
            "prepare",
            "recovery",
            "authorize",
            "handler",
            "driver",
            "validity",
        ] {
            let provider = Arc::new(FixTls::new(None));
            let validity_panic = Arc::new(AtomicBool::new(false));
            let execution = ExecutionBudget::new(16);
            let factory = Arc::new(FixFactory {
                clock: ElapsedClock::new(),
                phase,
                execution: execution.clone(),
                validity_panic: validity_panic.clone(),
                lane: None,
            });
            let (leases, mut received) = tokio::sync::mpsc::unbounded_channel();
            let (config, public) = server_config(
                factory,
                Arc::new(PanicHandler { phase, leases }),
                provider.clone(),
            );
            let network = Network::new(NetworkConfig {
                worker_threads: 1,
                ..Default::default()
            })
            .unwrap();
            let server = network
                .listen_https(config)
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            let connected = http::connect_with_budget(
                server.local_addr(),
                authority(),
                Some(provider.clone()),
                client(public, Mode::Returning, Carrier::Https),
                vec![],
                (runtime(), Limits::default()),
                budget(),
            )
            .await;
            let mut external = None;
            if ["authenticate", "prepare", "recovery"].contains(&phase) {
                assert!(connected.is_err());
            } else {
                let client = connected.unwrap();
                settled(|| server.status().ready == 1).await;
                match phase {
                    "driver" => {
                        provider.panic_write.store(true, Ordering::SeqCst);
                        server.hosts()[0].notify(vec![1]).await.unwrap();
                    }
                    "validity" => {
                        validity_panic.store(true, Ordering::SeqCst);
                    }
                    _ => {
                        assert!(client
                            .conn
                            .call("/test.Service/Panic", vec![], 3000)
                            .await
                            .is_err());
                        if phase == "handler" {
                            external = Some(received.recv().await.unwrap());
                        }
                    }
                }
                settled(|| client.is_closed()).await;
                client.close().await;
            }
            if external.is_some() {
                let bytes = association_bytes(server.status());
                let (next, report) = shutdown(network, Duration::from_millis(30)).await;
                assert!(
                    !report.complete && report.pending_operations != 0,
                    "external execution cannot be a successful shutdown"
                );
                assert_eq!(server.status().associations, 1);
                assert_eq!(association_bytes(server.status()), bytes);
                assert_eq!(execution.in_use(), 1);
                assert!(server.status().failed_tasks != 0);
                assert!(
                    http::retired_servers().is_empty(),
                    "managed failure escaped to drop fallback"
                );
                // Drop the managed owner while cleanup is incomplete. Its own
                // process registry, not HTTP's standalone fallback, must retain
                // the runtime/thread running this exact association continuation.
                drop(next);
                assert!(syntra_net::network::retired_networks()
                    .iter()
                    .any(|r| !r.complete && r.pending_operations != 0));
                assert!(!server.status().stopped);
                drop(external.take());
                let mut reported_failure = false;
                settled(|| {
                    reported_failure |= syntra_net::network::retired_networks()
                        .iter()
                        .any(|r| r.complete && r.failed_supervisors != 0);
                    reported_failure && server.status().stopped
                })
                .await;
            } else {
                settled(|| server.status().completed != 0).await;
                let (_network, report) = shutdown(network, Duration::from_secs(5)).await;
                assert!(report.complete);
                assert!(
                    report.failed_supervisors != 0,
                    "panic reported empty success: {phase}"
                );
            }
            assert!(server.status().stopped);
            assert_eq!(server.status().associations, 0);
            assert_eq!(server.status().sockets, 0);
            assert_eq!(server.status().reserved_bytes, 0);
            assert!(server.status().failed_tasks != 0);
            assert!(
                http::retired_servers().is_empty(),
                "managed panic spawned unobserved fallback"
            );
        }
    }

    #[tokio::test]
    async fn cancelled_pre_host_blocking_lookup_keeps_its_join_and_failure_inside_network() {
        let _serial = SERIAL.lock().await;
        let provider = Arc::new(FixTls::new(None));
        let lane = Arc::new(tokio::sync::Semaphore::new(1));
        let factory = Arc::new(FixFactory {
            clock: ElapsedClock::new(),
            phase: "none",
            execution: ExecutionBudget::new(16),
            validity_panic: Arc::new(AtomicBool::new(false)),
            lane: Some(lane.clone()),
        });
        let (mut config, public) = server_config(factory, echo(), provider.clone());
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        struct BlockingPanic {
            entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl KeyStore for BlockingPanic {
            fn lookup(&self, _: &Context) -> Result<Secret32, kernel::Error> {
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release.lock().unwrap().recv().unwrap();
                panic!("fixture blocking lookup panic");
            }
        }
        let mut owned = Security {
            mode: config.security.mode,
            carrier: config.security.carrier,
            server_key_id: config.security.server_key_id,
            scope: config.security.scope.clone(),
            private_key: Secret32::new(*config.security.private_key.expose()),
            store: None,
        };
        owned.store = Some(Arc::new(BlockingPanic {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(release_rx),
        }));
        config.security = Arc::new(owned);
        let network = Network::new(NetworkConfig {
            worker_threads: 1,
            ..Default::default()
        })
        .unwrap();
        let server = network
            .listen_https(config)
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let address = server.local_addr();
        let connect = tokio::spawn(async move {
            http::connect_with_budget(
                address,
                authority(),
                Some(provider),
                client(public, Mode::Returning, Carrier::Https),
                vec![],
                (runtime(), Limits::default()),
                budget(),
            )
            .await
        });
        entered_rx.await.unwrap();
        assert_eq!(lane.available_permits(), 0);
        let bytes = association_bytes(server.status());
        let (network, report) = shutdown(network, Duration::from_millis(30)).await;
        assert!(!report.complete && report.pending_operations != 0);
        assert_eq!(server.status().associations, 1);
        assert_eq!(association_bytes(server.status()), bytes);
        assert_eq!(lane.available_permits(), 0);
        assert!(http::retired_servers().is_empty());
        release.send(()).unwrap();
        assert!(connect.await.unwrap().is_err());
        let (_network, report) = shutdown(network, Duration::from_secs(5)).await;
        assert!(report.complete);
        assert!(report.failed_supervisors != 0);
        assert_eq!(lane.available_permits(), 1);
        assert_eq!(server.status().associations, 0);
        assert_eq!(server.status().reserved_bytes, 0);
        assert!(http::retired_servers().is_empty());
    }
}
