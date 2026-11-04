//! Same-implementation, opt-in HTTP/HTTPS candidate evidence only. Local TLS
//! roots never enter the system trust store; no upstream acceptance is claimed.
#![cfg(all(feature = "managed", feature = "http", not(target_arch = "wasm32")))]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use syntra_core::secure_channel::{
    self as kernel, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32,
    ServerConfig as Security, VerifiedIdentity,
};
use syntra_net::{
    client::{LifecycleStatus, ReconnectConfig},
    http::{self, Authority, ServerConfig, ServerLimits},
    network::{
        retired_networks, ManagedClient, ManagedHttpServer, Network, NetworkConfig, NetworkEvent,
        Operation,
    },
    tls::{
        BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata, TlsProvider,
        TlsRole,
    },
    AuthenticatorFactory, Error, EstablishmentBudget, Limits,
};
use syntra_runtime::{
    elapsed::{ElapsedClock, ElapsedSource},
    AllowAll, AllowAnonymous, AuthError, Authenticator, ConnectionConfig, ExecutionLease,
    FnHandler, Handler, HandlerFut, HandlerOutcome,
};

const WAIT: Duration = Duration::from_secs(10);
// Candidate byte/principal quotas are process-wide, including different listeners.
static SERIAL: Mutex<()> = Mutex::new(());

fn receive<T>(operation: Operation<T>) -> T {
    operation
        .wait(WAIT)
        .unwrap_or_else(|e| panic!("managed operation: {e:?}"))
}
fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not become true");
        thread::sleep(Duration::from_millis(2));
    }
}
fn authority() -> Authority {
    Authority::new("127.0.0.1:38080").unwrap()
}
fn runtime() -> ConnectionConfig {
    ConnectionConfig {
        max_outstanding: 16,
        writer_capacity: 8,
        notification_capacity: 8,
        ..Default::default()
    }
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
fn ready(client: &ManagedClient, after: u64) -> u64 {
    let mut generation = 0;
    until(|| match client.status() {
        LifecycleStatus::CoreReady(r) if r.generation > after => {
            generation = r.generation;
            true
        }
        _ => false,
    });
    generation
}
fn clean(server: &ManagedHttpServer) -> bool {
    let status = server.status();
    status.associations == 0
        && status.ready == 0
        && status.reserved_bytes == 0
        && status.sockets == 0
        && status.unbound_streams == 0
        && server.hosts().is_empty()
}
fn shutdown(network: &mut Network) {
    let report = network.shutdown(WAIT);
    assert!(report.complete, "{report:?}");
    assert_eq!(report.pending_operations, 0);
    assert_eq!(report.failed_supervisors, 0);
    assert!(
        http::retired_servers().is_empty(),
        "managed ServerRun must not use drop fallback"
    );
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

struct Store;
impl KeyStore for Store {
    fn lookup(&self, c: &Context) -> Result<Secret32, kernel::Error> {
        if c.handle == [7; 8] && c.epoch == 2 {
            Ok(Secret32::new([8; 32]))
        } else {
            Err(kernel::Error::Authentication)
        }
    }
}
struct Trust {
    server: Arc<Security>,
    public: [u8; 32],
}
impl Trust {
    fn new(carrier: Carrier, mode: Mode) -> Arc<Self> {
        let (private_key, public) = kernel::generate_server_key().unwrap();
        Arc::new(Self {
            server: Arc::new(Security {
                carrier,
                mode,
                server_key_id: 1,
                scope: b"managed-http-candidate".to_vec(),
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
fn factory() -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            // Explicit fixture application policy, not identity inferred from TLS/AK.
            Ok(Arc::new(AllowAnonymous))
        },
    )
}
fn echo() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|_, bytes, _| async {
        HandlerOutcome::Payload(bytes)
    }))
}
fn config(trust: &Trust, provider: Option<Arc<dyn TlsProvider>>) -> ServerConfig {
    let mut config = ServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        authority(),
        trust.server.clone(),
        factory(),
        echo(),
    );
    config.runtime = runtime();
    config.admission = ServerLimits {
        associations: 2,
        handshakes: 2,
        unbound_streams: 2,
        sockets: 6,
        ..Default::default()
    };
    config.tls = provider;
    config
}
fn listen(network: &Network, config: ServerConfig) -> ManagedHttpServer {
    let secure = config.security.carrier == Carrier::Https;
    receive(
        if secure {
            network.listen_https(config)
        } else {
            network.listen_http(config)
        }
        .unwrap(),
    )
    .unwrap()
}
fn connect(
    network: &Network,
    address: SocketAddr,
    trust: Arc<Trust>,
    provider: Option<Arc<dyn TlsProvider>>,
    retries: ReconnectConfig,
) -> ManagedClient {
    receive(
        network
            .client(retries, move || {
                let trust = trust.clone();
                let provider = provider.clone();
                async move {
                    let budget =
                        EstablishmentBudget::new(ElapsedClock::new(), Duration::from_secs(5))?;
                    http::connect_with_budget(
                        address,
                        authority(),
                        provider,
                        trust.client(),
                        vec![],
                        (runtime(), Limits::default()),
                        budget,
                    )
                    .await
                }
            })
            .unwrap(),
    )
    .unwrap()
}
fn rpc(client: &ManagedClient, bytes: Vec<u8>) -> Vec<u8> {
    receive(
        client
            .call("/test.Service/Echo".into(), bytes, 3000)
            .unwrap(),
    )
    .unwrap()
    .value
}

struct Handshake(Arc<AtomicUsize>);
impl Drop for Handshake {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
// Trusted application fixture: real TLS 1.3, normal chain/name/current-validity
// validation, http/1.1 ALPN, no early data, no resumed trust decisions.
struct LocalTls {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
    accepts: AtomicUsize,
    handshakes: Arc<AtomicUsize>,
}
impl LocalTls {
    fn new() -> Arc<Self> {
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
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
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
        server.max_early_data_size = 0;
        server.alpn_protocols = client.alpn_protocols.clone();
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Arc::new(Self {
            client: Arc::new(client),
            server: Arc::new(server),
            accepts: AtomicUsize::new(0),
            handshakes: Arc::new(AtomicUsize::new(0)),
        })
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
    fn accept(&self, stream: BoxIo, expected: TlsAuthority) -> TlsFuture<'_> {
        Box::pin(async move {
            if expected != authority().tls_authority()? {
                return Err(Error::Configuration);
            }
            self.accepts.fetch_add(1, Ordering::SeqCst);
            self.handshakes.fetch_add(1, Ordering::SeqCst);
            let _handshake = Handshake(self.handshakes.clone());
            let stream = tokio_rustls::TlsAcceptor::from(self.server.clone())
                .accept(stream)
                .await
                .map_err(|_| Error::Configuration)?;
            let session = stream.get_ref().1;
            let metadata = TlsMetadata {
                authority: expected,
                role: TlsRole::Server,
                protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                early_data: EarlyData::Disabled,
            };
            Ok(ProviderTlsStream::new(Box::new(stream), metadata))
        })
    }
}
fn provider(carrier: Carrier, tls: &Arc<LocalTls>) -> Option<Arc<dyn TlsProvider>> {
    (carrier == Carrier::Https).then(|| tls.clone() as Arc<dyn TlsProvider>)
}

#[test]
fn std_owned_http_https_both_modes_rpc_hosts_cleanup_and_single_worker() {
    let _serial = SERIAL.lock().unwrap();
    assert!(tokio::runtime::Handle::try_current().is_err());
    for carrier in [Carrier::Http, Carrier::Https] {
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let mut network = Network::new(NetworkConfig {
                worker_threads: 1,
                ..Default::default()
            })
            .unwrap();
            let trust = Trust::new(carrier, mode);
            let tls = LocalTls::new();
            let workers = Arc::new(Mutex::new(Vec::new()));
            let mut settings = config(&trust, provider(carrier, &tls));
            settings.handler = {
                let workers = workers.clone();
                Arc::new(FnHandler(move |_, bytes, _| {
                    workers
                        .lock()
                        .unwrap()
                        .push(thread::current().name().unwrap_or("").to_owned());
                    async move { HandlerOutcome::Payload(bytes) }
                }))
            };
            let server = listen(&network, settings);
            let client = connect(
                &network,
                server.local_addr(),
                trust,
                provider(carrier, &tls),
                retry_config(),
            );
            ready(&client, 0);
            let payload = vec![42; 150_000];
            assert_eq!(rpc(&client, payload.clone()), payload);
            until(|| server.hosts().len() == 1);
            assert_eq!(server.status().associations, 1);
            assert_eq!(server.status().ready, 1);
            assert!(workers
                .lock()
                .unwrap()
                .iter()
                .all(|name| name == "syntra-net-worker"));
            if carrier == Carrier::Https {
                assert_eq!(tls.accepts.load(Ordering::SeqCst), 2);
            }
            shutdown(&mut network);
            assert!(server.status().stopped);
            assert!(clean(&server));
        }
    }
}

#[test]
fn combined_parent_and_local_controls_retire_associations_without_offline_resume() {
    let _serial = SERIAL.lock().unwrap();
    for carrier in [Carrier::Http, Carrier::Https] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let trust = Trust::new(carrier, Mode::Returning);
        let tls = LocalTls::new();
        let server = listen(&network, config(&trust, provider(carrier, &tls)));
        let client = connect(
            &network,
            server.local_addr(),
            trust,
            provider(carrier, &tls),
            retry_config(),
        );
        let first = ready(&client, 0);
        until(|| server.hosts().len() == 1);
        let old_host = server.hosts().pop().unwrap();
        network.pause();
        assert!(
            server.hosts().is_empty(),
            "parent pause synchronously retires ready association publication"
        );
        assert!(!client.is_generation_current(first));
        network.network_available(false);
        network.resume();
        for _ in 0..32 {
            server.resume();
            server.network_available(true);
            network.resume();
        }
        until(|| server.status().associations == 0 && server.hosts().is_empty());
        assert!(old_host.is_closed());
        let before = tls.accepts.load(Ordering::SeqCst);
        let probe = TcpStream::connect(server.local_addr()).unwrap();
        thread::sleep(Duration::from_millis(30));
        assert_eq!(tls.accepts.load(Ordering::SeqCst), before);
        assert_eq!(server.status().ready, 0);
        drop(probe);
        network.network_available(true);
        let second = ready(&client, first);
        assert!(second > first);
        assert_eq!(rpc(&client, vec![3]), [3]);
        until(|| server.hosts().len() == 1);
        assert!(!Arc::ptr_eq(&old_host, &server.hosts()[0]));
        client.stop();
        until(|| server.status().associations == 0);
        for action in 0..2 {
            if action == 0 {
                server.pause();
            } else {
                server.network_available(false);
            }
            let before = tls.accepts.load(Ordering::SeqCst);
            let mut socket = TcpStream::connect(server.local_addr()).unwrap();
            network.pause();
            network.resume(); // Does not override this server's local mask.
            thread::sleep(Duration::from_millis(20));
            assert_eq!(tls.accepts.load(Ordering::SeqCst), before);
            if action == 0 {
                server.resume();
            } else {
                server.network_available(true);
            }
            until(|| server.status().sockets >= 2);
            if carrier == Carrier::Https {
                until(|| tls.handshakes.load(Ordering::SeqCst) > 0);
            }
            network.pause();
            peer_closed(&mut socket);
            network.resume();
        }
        shutdown(&mut network);
        assert!(clean(&server));
    }
}

#[test]
fn stopping_one_http_server_does_not_stop_the_pool_or_another_listener() {
    let _serial = SERIAL.lock().unwrap();
    let mut network = Network::new(NetworkConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let trust = Trust::new(Carrier::Http, Mode::Bootstrap);
    let first = listen(&network, config(&trust, None));
    let second = listen(&network, config(&trust, None));
    first.stop();
    until(|| first.status().stopped);
    assert!(!network.status().stopping);
    network.pause();
    network.resume();
    first.resume();
    assert!(first.status().stopped);
    assert!(clean(&first));
    let client = connect(&network, second.local_addr(), trust, None, retry_config());
    ready(&client, 0);
    assert_eq!(rpc(&client, vec![4]), [4]);
    shutdown(&mut network);
    assert!(clean(&second));
}

#[test]
fn dropped_managed_handles_or_operation_do_not_orphan_http_owner() {
    let _serial = SERIAL.lock().unwrap();
    for drop_operation in [false, true] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        let trust = Trust::new(Carrier::Http, Mode::Bootstrap);
        let mut events = network.events();
        let operation = network.listen_http(config(&trust, None)).unwrap();
        let mut address = None;
        if drop_operation {
            drop(operation);
        } else {
            address = Some(receive(operation).unwrap().local_addr());
        }
        until(|| {
            while let Ok(event) = events.try_recv() {
                if let NetworkEvent::ListenerStarted(bound) = event {
                    address = Some(bound);
                }
            }
            address.is_some()
        });
        let mut socket = TcpStream::connect(address.unwrap()).unwrap();
        socket
            .write_all(b"POST /syntra/1.0/http/open HTTP/1.1\r\n")
            .unwrap();
        shutdown(&mut network);
        peer_closed(&mut socket);
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
fn initial_network_controls_apply_before_http_run_and_partial_setup_uses_original_clock() {
    let _serial = SERIAL.lock().unwrap();
    for carrier in [Carrier::Http, Carrier::Https] {
        let mut network = Network::new(NetworkConfig::default()).unwrap();
        network.pause();
        network.network_available(false);
        let trust = Trust::new(carrier, Mode::Bootstrap);
        let tls = LocalTls::new();
        let source = Arc::new(Source(AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let mut settings = config(&trust, provider(carrier, &tls));
        settings.authenticator = Arc::new(ClockFactory(clock.clone()));
        let server = listen(&network, settings);
        let mut socket = TcpStream::connect(server.local_addr()).unwrap();
        if carrier == Carrier::Http {
            socket
                .write_all(b"POST /syntra/1.0/http/open HTTP/1.1\r\n")
                .unwrap();
        }
        for _ in 0..32 {
            server.resume();
            network.resume();
        }
        thread::sleep(Duration::from_millis(20));
        assert_eq!(server.status().sockets, 0);
        assert_eq!(tls.accepts.load(Ordering::SeqCst), 0);
        network.network_available(true);
        until(|| server.status().sockets >= 2);
        if carrier == Carrier::Https {
            until(|| tls.handshakes.load(Ordering::SeqCst) == 1);
        }
        source.0.store(16_000, Ordering::SeqCst);
        clock.wake();
        until(|| server.status().rejected > 0);
        peer_closed(&mut socket);
        assert_eq!(server.status().associations, 0);
        shutdown(&mut network);
        assert!(clean(&server));
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
fn incomplete_http_shutdown_and_network_drop_retain_inline_owner_and_external_execution() {
    let _serial = SERIAL.lock().unwrap();
    for carrier in [Carrier::Http, Carrier::Https] {
        for drop_network in [false, true] {
            let mut network = Network::new(NetworkConfig {
                close_grace: Duration::from_millis(20),
                ..Default::default()
            })
            .unwrap();
            let trust = Trust::new(carrier, Mode::Returning);
            let tls = LocalTls::new();
            let (send, receive_lease) = mpsc::channel();
            let mut settings = config(&trust, provider(carrier, &tls));
            settings.handler = Arc::new(AllowAll(ExternalLease(send)));
            settings.limits.close_timeout = Duration::from_millis(20);
            let server = listen(&network, settings);
            let client = connect(
                &network,
                server.local_addr(),
                trust,
                provider(carrier, &tls),
                retry_config(),
            );
            ready(&client, 0);
            assert_eq!(rpc(&client, vec![6]), [6]);
            let lease = receive_lease.recv_timeout(WAIT).unwrap();
            let report = network.shutdown(Duration::from_millis(40));
            assert!(!report.complete);
            assert!(report.pending_operations > 0);
            assert!(!server.status().stopped);
            assert_eq!(server.status().associations, 1);
            assert!(server.status().reserved_bytes > 0);
            assert!(http::retired_servers().is_empty());
            if drop_network {
                drop(network);
                assert!(retired_networks().iter().any(|report| !report.complete));
                drop(lease);
                until(|| server.status().stopped && clean(&server));
                until(|| retired_networks().iter().all(|report| report.complete));
            } else {
                drop(lease);
                shutdown(&mut network);
                assert!(clean(&server));
            }
            assert!(
                http::retired_servers().is_empty(),
                "managed ownership must never enter HTTP drop fallback"
            );
        }
    }
}

#[test]
fn http_association_quota_rejects_second_client_and_releases_after_cleanup() {
    let _serial = SERIAL.lock().unwrap();
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let trust = Trust::new(Carrier::Http, Mode::Bootstrap);
    let mut settings = config(&trust, None);
    settings.admission.associations = 1;
    let server = listen(&network, settings);
    let first = connect(
        &network,
        server.local_addr(),
        trust.clone(),
        None,
        retry_config(),
    );
    ready(&first, 0);
    let mut retries = retry_config();
    retries.max_attempts = 1;
    let second = connect(&network, server.local_addr(), trust, None, retries);
    until(|| server.status().rejected > 0);
    assert_eq!(server.status().associations, 1);
    assert_eq!(rpc(&first, vec![7]), [7]);
    first.stop();
    until(|| server.status().associations == 0);
    second.retry();
    ready(&second, 0);
    assert_eq!(rpc(&second, vec![8]), [8]);
    shutdown(&mut network);
    assert!(clean(&server));
}

#[test]
fn http_binding_tls_mismatches_and_pool_admission_fail_before_binding() {
    let _serial = SERIAL.lock().unwrap();
    fn thread_safe<T: Send + Sync>() {}
    thread_safe::<ManagedHttpServer>();
    let mut network = Network::new(NetworkConfig {
        maximum_operations: 1,
        ..Default::default()
    })
    .unwrap();
    let plain = Trust::new(Carrier::Http, Mode::Bootstrap);
    let secure = Trust::new(Carrier::Https, Mode::Bootstrap);
    let tcp = Trust::new(Carrier::Tcp, Mode::Bootstrap);
    let tls = LocalTls::new();
    assert!(network
        .listen_http(config(&plain, Some(tls.clone())))
        .is_err());
    assert!(network.listen_http(config(&secure, None)).is_err());
    assert!(network.listen_https(config(&secure, None)).is_err());
    assert!(network
        .listen_https(config(&plain, Some(tls.clone())))
        .is_err());
    assert!(network.listen_http(config(&tcp, None)).is_err());
    assert_eq!(network.report().pending_operations, 0);
    let server = listen(&network, config(&plain, None));
    assert!(network.listen_http(config(&plain, None)).is_err());
    server.stop();
    until(|| network.report().pending_operations == 0);
    let replacement = listen(&network, config(&secure, Some(tls)));
    shutdown(&mut network);
    assert!(clean(&replacement));
}
