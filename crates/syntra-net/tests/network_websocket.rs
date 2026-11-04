//! Managed carrier round trips use this implementation on both ends, not an
//! independent interoperability peer. TLS roots are confined to this fixture.
#![cfg(all(
    feature = "managed",
    feature = "websocket",
    not(target_arch = "wasm32")
))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    task::{Context as TaskContext, Poll},
    thread,
    time::{Duration, Instant},
};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32, ServerConfig,
    VerifiedIdentity,
};
use syntra_net::{
    client::{LifecycleStatus, ReconnectConfig},
    network::{
        Admission, ManagedClient, ManagedServer, Network, NetworkConfig, Operation,
        TcpServerConfig, WebSocketServerConfig, WebSocketTls,
    },
    tls::{
        self, BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata,
        TlsProvider, TlsRole,
    },
    websocket, AuthenticatorFactory, Error, EstablishmentBudget, Limits,
};
use syntra_runtime::{
    elapsed::{ElapsedClock, ElapsedSource},
    AllowAll, AllowAnonymous, AuthError, Authenticator, ExecutionLease, FnHandler, Handler,
    HandlerFut, HandlerOutcome,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const WAIT: Duration = Duration::from_secs(8);

fn receive<T>(operation: Operation<T>) -> T {
    operation
        .wait(WAIT)
        .unwrap_or_else(|e| panic!("managed operation: {e:?}"))
}
fn until(mut predicate: impl FnMut() -> bool) {
    let end = Instant::now() + WAIT;
    while !predicate() {
        assert!(Instant::now() < end, "condition did not become true");
        thread::sleep(Duration::from_millis(2));
    }
}
fn shutdown(network: &mut Network) {
    let report = network.shutdown(WAIT);
    assert!(report.complete, "{report:?}");
    assert_eq!(report.pending_operations, 0);
    assert_eq!(report.failed_supervisors, 0);
}
fn ready(client: &ManagedClient) -> u64 {
    let mut generation = 0;
    until(|| match client.status() {
        LifecycleStatus::CoreReady(r) => {
            generation = r.generation;
            true
        }
        _ => false,
    });
    generation
}
fn retry_config() -> ReconnectConfig {
    ReconnectConfig {
        attempt_timeout: Duration::from_secs(5),
        reconnect_budget: Duration::from_secs(20),
        max_attempts: 4,
        base_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(20),
        close_timeout: Duration::from_secs(1),
        start_paused: false,
        initial_network_available: true,
    }
}

struct Store;
impl KeyStore for Store {
    fn lookup(&self, context: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        if context.handle == [7; 8] && context.epoch == 2 {
            Ok(Secret32::new([8; 32]))
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
    fn new(carrier: Carrier, mode: Mode) -> Arc<Self> {
        let (private_key, public) = generate_server_key().unwrap();
        Arc::new(Self {
            server: Arc::new(ServerConfig {
                mode,
                carrier,
                server_key_id: 1,
                scope: b"managed-websocket".to_vec(),
                private_key,
                store: Some(Arc::new(Store)),
            }),
            public,
        })
    }
    fn client(&self) -> ClientConfig {
        let returning = self.server.mode == Mode::Returning;
        ClientConfig {
            context: Context {
                mode: self.server.mode,
                carrier: self.server.carrier,
                server_key_id: 1,
                scope: self.server.scope.clone(),
                handle: if returning { [7; 8] } else { [0; 8] },
                epoch: if returning { 2 } else { 0 },
            },
            server_public_key: self.public,
            authorization_key: returning.then(|| Secret32::new([8; 32])),
        }
    }
}
fn echo() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|_, bytes, _| async {
        HandlerOutcome::Payload(bytes)
    }))
}
fn factory() -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            // Explicit fixture application policy, not inferred TLS/channel identity.
            Ok(Arc::new(AllowAnonymous))
        },
    )
}
fn config(trust: &Trust, admission: Arc<Admission>, tls: WebSocketTls) -> WebSocketServerConfig {
    WebSocketServerConfig {
        address: "127.0.0.1:0".parse().unwrap(),
        admission,
        security: trust.server.clone(),
        authenticator: factory(),
        handler: echo(),
        runtime: Default::default(),
        limits: Limits::default(),
        tls,
    }
}
fn listen(network: &Network, config: WebSocketServerConfig, secure: bool) -> ManagedServer {
    receive(
        if secure {
            network.listen_wss(config)
        } else {
            network.listen_ws(config)
        }
        .unwrap(),
    )
    .unwrap()
}
fn tcp_listener(network: &Network, admission: Arc<Admission>) -> ManagedServer {
    let trust = Trust::new(Carrier::Tcp, Mode::Bootstrap);
    receive(
        network
            .listen_tcp(TcpServerConfig {
                address: "127.0.0.1:0".parse().unwrap(),
                admission,
                security: trust.server.clone(),
                authenticator: factory(),
                handler: echo(),
                runtime: Default::default(),
                limits: Limits::default(),
            })
            .unwrap(),
    )
    .unwrap()
}

struct TrackedIo {
    inner: BoxIo,
    live: Arc<AtomicUsize>,
}
impl Drop for TrackedIo {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}
impl AsyncRead for TrackedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for TrackedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Trusted test application provider: real rustls TLS 1.3 with normal root/name/
/// validity verification, explicit ALPN, no early data and no session resumption.
struct ApplicationTls {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    authority: TlsAuthority,
    accepts: AtomicUsize,
    live: Arc<AtomicUsize>,
}
impl ApplicationTls {
    fn new() -> Arc<Self> {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(crypto.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_early_data = false;
        client.resumption = rustls::client::Resumption::disabled();
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
        server.alpn_protocols = client.alpn_protocols.clone();
        server.max_early_data_size = 0;
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Arc::new(Self {
            client: Arc::new(client),
            server: Arc::new(server),
            // Provisioned local authority is independent of the ephemeral test
            // socket binding. It is never taken from HTTP/SNI peer claims.
            authority: TlsAuthority::new("127.0.0.1", 443).unwrap(),
            accepts: AtomicUsize::new(0),
            live: Arc::new(AtomicUsize::new(0)),
        })
    }
    fn mode(self: &Arc<Self>) -> WebSocketTls {
        WebSocketTls::Provider {
            provider: self.clone(),
            authority: self.authority.clone(),
        }
    }
}
impl TlsProvider for ApplicationTls {
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
            if authority != self.authority {
                return Err(Error::Configuration);
            }
            self.accepts.fetch_add(1, Ordering::SeqCst);
            self.live.fetch_add(1, Ordering::SeqCst);
            let stream = TrackedIo {
                inner: stream,
                live: self.live.clone(),
            };
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

fn connect(
    network: &Network,
    address: SocketAddr,
    trust: Arc<Trust>,
    provider: Option<Arc<ApplicationTls>>,
) -> ManagedClient {
    receive(
        network
            .client(retry_config(), move || {
                let trust = trust.clone();
                let provider = provider.clone();
                async move {
                    let budget =
                        EstablishmentBudget::new(ElapsedClock::default(), Duration::from_secs(5))?;
                    let stream = budget
                        .run(tokio::net::TcpStream::connect(address))
                        .await??;
                    establish_client(stream, address, trust, provider, budget).await
                }
            })
            .unwrap(),
    )
    .unwrap()
}
async fn establish_client(
    stream: tokio::net::TcpStream,
    address: SocketAddr,
    trust: Arc<Trust>,
    provider: Option<Arc<ApplicationTls>>,
    budget: EstablishmentBudget,
) -> Result<syntra_net::ClientHandle, Error> {
    stream.set_nodelay(true)?;
    if let Some(provider) = provider {
        let authority = TlsAuthority::new("127.0.0.1", address.port())?;
        let stream =
            tls::connect_stream_with_budget(stream, provider.as_ref(), authority, budget).await?;
        websocket::connect_tls_stream_with_budget(
            stream,
            &format!("wss://{address}/syntra/1.0/ws"),
            trust.client(),
            vec![],
            Default::default(),
            Limits::default(),
        )
        .await
    } else {
        websocket::connect_stream_with_budget(
            stream,
            &format!("ws://{address}/syntra/1.0/ws"),
            trust.client(),
            vec![],
            Default::default(),
            Limits::default(),
            budget,
        )
        .await
    }
}
fn carrier(secure: bool) -> Carrier {
    if secure {
        Carrier::SecureWebSocket
    } else {
        Carrier::WebSocket
    }
}
fn mode(secure: bool, provider: &Arc<ApplicationTls>) -> WebSocketTls {
    if secure {
        provider.mode()
    } else {
        WebSocketTls::Loopback
    }
}
fn peer_closed(socket: &mut TcpStream) {
    socket.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + WAIT;
    let mut byte = [0];
    loop {
        match socket.read(&mut byte) {
            Ok(0) => return,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) =>
            {
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(2));
            }
            result => panic!("socket did not close without data: {result:?}"),
        }
    }
}

#[test]
fn std_owned_ws_and_application_wss_both_modes_rpc_controls_and_ready_shutdown() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    for secure in [false, true] {
        for noise_mode in [Mode::Bootstrap, Mode::Returning] {
            let mut network = Network::new(NetworkConfig::default()).unwrap();
            let trust = Trust::new(carrier(secure), noise_mode);
            let provider = ApplicationTls::new();
            let admission = Admission::new(3).unwrap();
            let server = listen(
                &network,
                config(&trust, admission.clone(), mode(secure, &provider)),
                secure,
            );
            let client = connect(
                &network,
                server.local_addr(),
                trust,
                secure.then(|| provider.clone()),
            );
            let first = ready(&client);
            let payload = vec![5; 150_000];
            let reply = receive(
                client
                    .call("/test.Service/Echo".into(), payload.clone(), 3000)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(reply.value, payload);
            assert_eq!(reply.generation, first);
            network.pause();
            assert!(!client.is_generation_current(first));
            until(|| server.status().admitted == 0);
            network.network_available(false);
            network.resume();
            assert_eq!(client.status(), LifecycleStatus::Offline);
            network.network_available(true);
            assert!(ready(&client) > first);
            shutdown(&mut network);
            assert!(server.status().stopped);
            assert_eq!(admission.available(), 3);
            assert_eq!(provider.live.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn tcp_ws_wss_share_admission_and_do_not_serialize_slow_setup() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let admission = Admission::new(1).unwrap();
    let tcp = tcp_listener(&network, admission.clone());
    let provider = ApplicationTls::new();
    let ws_trust = Trust::new(Carrier::WebSocket, Mode::Bootstrap);
    let wss_trust = Trust::new(Carrier::SecureWebSocket, Mode::Returning);
    let ws = listen(
        &network,
        config(&ws_trust, admission.clone(), WebSocketTls::Loopback),
        false,
    );
    let wss = listen(
        &network,
        config(&wss_trust, admission.clone(), provider.mode()),
        true,
    );
    let tcp_socket = TcpStream::connect(tcp.local_addr()).unwrap();
    until(|| tcp.status().admitted == 1);
    let mut ws_socket = TcpStream::connect(ws.local_addr()).unwrap();
    until(|| ws.status().waiting_admission == 1);
    let mut wss_socket = TcpStream::connect(wss.local_addr()).unwrap();
    until(|| wss.status().waiting_admission == 1);
    assert_eq!(provider.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(admission.available(), 0);
    drop(tcp_socket);
    until(|| ws.status().admitted == 1);
    assert_eq!(wss.status().waiting_admission, 1);
    ws.stop();
    until(|| ws.status().stopped);
    peer_closed(&mut ws_socket);
    until(|| provider.accepts.load(Ordering::SeqCst) == 1);
    network.pause();
    until(|| wss.status().admitted == 0 && provider.live.load(Ordering::SeqCst) == 0);
    peer_closed(&mut wss_socket);
    shutdown(&mut network);
    assert_eq!(admission.available(), 1);
}

#[test]
fn ws_wss_shared_admission_waiter_survives_same_listener_join() {
    for secure in [false, true] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let admission = Admission::new(2).unwrap();
        let tcp = tcp_listener(&network, admission.clone());
        let trust = Trust::new(carrier(secure), Mode::Bootstrap);
        let provider = ApplicationTls::new();
        let server = listen(
            &network,
            config(&trust, admission.clone(), mode(secure, &provider)),
            secure,
        );
        let active = TcpStream::connect(server.local_addr()).unwrap();
        let other = TcpStream::connect(tcp.local_addr()).unwrap();
        until(|| server.status().admitted == 1 && tcp.status().admitted == 1);
        let waiting = TcpStream::connect(server.local_addr()).unwrap();
        until(|| server.status().waiting_admission == 1);
        drop(active); // Both join_next and the retained admission become ready.
        until(|| server.status().completed == 1);
        let socket = Arc::new(Mutex::new(Some(waiting)));
        let address = server.local_addr();
        let client = receive(
            network
                .client(retry_config(), {
                    let provider = provider.clone();
                    move || {
                        let socket = socket.clone();
                        let trust = trust.clone();
                        let provider = provider.clone();
                        async move {
                            // A replacement dial must not conceal cancellation of the
                            // originally queued socket by a same-listener join.
                            let socket =
                                socket.lock().unwrap().take().ok_or(Error::Configuration)?;
                            socket.set_nonblocking(true)?;
                            let stream = tokio::net::TcpStream::from_std(socket)?;
                            let budget = EstablishmentBudget::new(
                                ElapsedClock::default(),
                                Duration::from_secs(5),
                            )?;
                            establish_client(
                                stream,
                                address,
                                trust,
                                secure.then_some(provider),
                                budget,
                            )
                            .await
                        }
                    }
                })
                .unwrap(),
        )
        .unwrap();
        ready(&client);
        assert_eq!(
            receive(
                client
                    .call("/test.Service/Echo".into(), vec![7], 1000)
                    .unwrap()
            )
            .unwrap()
            .value,
            vec![7]
        );
        assert_eq!(server.status().ready, 1);
        drop(other);
        shutdown(&mut network);
        assert_eq!(admission.available(), 2);
        assert_eq!(provider.live.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn slow_ws_upgrade_or_tls_does_not_serialize_other_handshakes() {
    for secure in [false, true] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let admission = Admission::new(2).unwrap();
        let trust = Trust::new(carrier(secure), Mode::Returning);
        let provider = ApplicationTls::new();
        let server = listen(
            &network,
            config(&trust, admission.clone(), mode(secure, &provider)),
            secure,
        );
        let slow = TcpStream::connect(server.local_addr()).unwrap();
        until(|| server.status().admitted == 1);
        let client = connect(
            &network,
            server.local_addr(),
            trust,
            secure.then(|| provider.clone()),
        );
        ready(&client);
        assert_eq!(server.status().admitted, 2);
        assert_eq!(server.status().ready, 1);
        drop(slow);
        shutdown(&mut network);
        assert_eq!(admission.available(), 2);
    }
}

#[test]
fn slow_upgrade_and_tls_are_cancelled_by_pause_offline_and_stop() {
    for secure in [false, true] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let trust = Trust::new(carrier(secure), Mode::Bootstrap);
        let provider = ApplicationTls::new();
        let admission = Admission::new(2).unwrap();
        let server = listen(
            &network,
            config(&trust, admission.clone(), mode(secure, &provider)),
            secure,
        );
        for control in 0..3 {
            let mut socket = TcpStream::connect(server.local_addr()).unwrap();
            if !secure {
                socket
                    .write_all(b"GET /syntra/1.0/ws HTTP/1.1\r\n")
                    .unwrap();
            }
            until(|| server.status().admitted == 1);
            if secure {
                until(|| provider.live.load(Ordering::SeqCst) == 1);
            }
            match control {
                0 => network.pause(),
                1 => network.network_available(false),
                _ => server.stop(),
            }
            until(|| server.status().admitted == 0 && provider.live.load(Ordering::SeqCst) == 0);
            peer_closed(&mut socket);
            assert_eq!(admission.available(), 2);
            if control == 0 {
                network.resume();
            }
            if control == 1 {
                network.network_available(true);
            }
        }
        shutdown(&mut network);
        assert!(server.status().stopped);
    }
}

struct Source(AtomicU64);
impl ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}
struct ClockFactory(ElapsedClock);
impl AuthenticatorFactory for ClockFactory {
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(AllowAnonymous))
    }
    fn elapsed_clock(&self) -> ElapsedClock {
        self.0.clone()
    }
}

#[test]
fn socket_accept_budget_expires_in_admission_before_upgrade_or_tls() {
    for secure in [false, true] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let admission = Admission::new(1).unwrap();
        let tcp = tcp_listener(&network, admission.clone());
        let held = TcpStream::connect(tcp.local_addr()).unwrap();
        until(|| tcp.status().admitted == 1);
        let source = Arc::new(Source(AtomicU64::new(0)));
        let trust = Trust::new(carrier(secure), Mode::Bootstrap);
        let provider = ApplicationTls::new();
        let mut settings = config(&trust, admission.clone(), mode(secure, &provider));
        settings.authenticator = Arc::new(ClockFactory(ElapsedClock::with_source(source.clone())));
        settings.limits.attempt_timeout = Duration::from_secs(1);
        let server = listen(&network, settings, secure);
        let mut socket = TcpStream::connect(server.local_addr()).unwrap();
        until(|| server.status().waiting_admission == 1);
        source.0.store(10_000, Ordering::SeqCst); // Past the original one-second budget.
        drop(held); // Wakes shared admission; it must not grant a fresh second.
        until(|| server.status().rejected == 1);
        assert_eq!(server.status().admitted, 0);
        assert_eq!(provider.accepts.load(Ordering::SeqCst), 0);
        peer_closed(&mut socket);
        shutdown(&mut network);
        assert_eq!(admission.available(), 1);
    }
}

#[test]
fn shared_admission_does_not_reset_the_active_upgrade_or_tls_budget() {
    for secure in [false, true] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let admission = Admission::new(1).unwrap();
        let tcp = tcp_listener(&network, admission.clone());
        let held = TcpStream::connect(tcp.local_addr()).unwrap();
        until(|| tcp.status().admitted == 1);
        let source = Arc::new(Source(AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let trust = Trust::new(carrier(secure), Mode::Bootstrap);
        let provider = ApplicationTls::new();
        let mut settings = config(&trust, admission.clone(), mode(secure, &provider));
        settings.authenticator = Arc::new(ClockFactory(clock.clone()));
        let server = listen(&network, settings, secure);
        let mut socket = TcpStream::connect(server.local_addr()).unwrap();
        until(|| server.status().waiting_admission == 1);
        source.0.store(8000, Ordering::SeqCst);
        drop(held);
        until(|| server.status().admitted == 1);
        if secure {
            until(|| provider.live.load(Ordering::SeqCst) == 1);
        }
        // Past the original 15-second budget, before a new 15-second budget
        // starting at shared-admission grant would expire. No scheduler advance.
        source.0.store(16_000, Ordering::SeqCst);
        clock.wake();
        until(|| server.status().rejected == 1);
        peer_closed(&mut socket);
        assert_eq!(provider.live.load(Ordering::SeqCst), 0);
        shutdown(&mut network);
        assert_eq!(admission.available(), 1);
    }
}

struct ExternalLease(mpsc::Sender<ExecutionLease>);
impl Handler for ExternalLease {
    fn handle(&self, _: String, bytes: Vec<u8>, _: syntra_runtime::CancelToken) -> HandlerFut {
        Box::pin(async { HandlerOutcome::Payload(bytes) })
    }
    fn handle_with_execution(
        &self,
        method: String,
        bytes: Vec<u8>,
        cancel: syntra_runtime::CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        self.0.send(lease).unwrap();
        self.handle(method, bytes, cancel)
    }
}

#[test]
fn incomplete_shutdown_retains_whole_ws_wss_host_and_shared_permit() {
    for secure in [false, true] {
        let mut network = Network::new(NetworkConfig {
            close_grace: Duration::from_millis(20),
            ..Default::default()
        })
        .unwrap();
        let admission = Admission::new(1).unwrap();
        let trust = Trust::new(carrier(secure), Mode::Returning);
        let provider = ApplicationTls::new();
        let (send, receive_lease) = mpsc::channel();
        let mut settings = config(&trust, admission.clone(), mode(secure, &provider));
        settings.handler = Arc::new(AllowAll(ExternalLease(send)));
        let server = listen(&network, settings, secure);
        let client = connect(
            &network,
            server.local_addr(),
            trust,
            secure.then(|| provider.clone()),
        );
        ready(&client);
        assert_eq!(
            receive(
                client
                    .call("/test.Service/Echo".into(), vec![6], 1000)
                    .unwrap()
            )
            .unwrap()
            .value,
            vec![6]
        );
        let lease = receive_lease.recv_timeout(WAIT).unwrap();
        let report = network.shutdown(Duration::from_millis(40));
        assert!(!report.complete, "external execution is still owned");
        assert!(report.pending_operations > 0);
        assert_eq!(server.status().admitted, 1);
        assert_eq!(
            admission.available(),
            0,
            "teardown must retain shared admission"
        );
        drop(lease);
        shutdown(&mut network);
        assert_eq!(server.status().admitted, 0);
        assert_eq!(admission.available(), 1);
        assert_eq!(provider.live.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn native_ws_rejects_nonloopback_bind_and_tls_carrier_mismatches() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let trust = Trust::new(Carrier::WebSocket, Mode::Bootstrap);
    let admission = Admission::new(2).unwrap();
    for address in ["0.0.0.0:0", "[::]:0", "192.0.2.1:0"] {
        let mut settings = config(&trust, admission.clone(), WebSocketTls::Loopback);
        settings.address = address.parse().unwrap();
        assert!(network.listen_ws(settings).is_err());
    }
    let provider = ApplicationTls::new();
    assert!(network
        .listen_ws(config(&trust, admission.clone(), provider.mode()))
        .is_err());
    assert!(network
        .listen_wss(config(&trust, admission.clone(), WebSocketTls::Loopback))
        .is_err());
    assert!(network
        .listen_wss(config(&trust, admission.clone(), provider.mode()))
        .is_err());
    let wss = Trust::new(Carrier::SecureWebSocket, Mode::Bootstrap);
    assert!(network
        .listen_ws(config(&wss, admission, WebSocketTls::Loopback))
        .is_err());
    shutdown(&mut network);
}
