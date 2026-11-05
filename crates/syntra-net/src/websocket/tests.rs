//! Supplemental outer-budget/ownership regressions, not independent TLS vectors.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(feature = "tls-rustls")]
use syntra_core::secure_channel::VerifiedIdentity;
use syntra_core::secure_channel::{generate_server_key, Context as ChannelContext, Mode};
#[cfg(feature = "tls-rustls")]
use syntra_runtime::{AllowAnonymous, AuthError, Authenticator, FnHandler, HandlerOutcome};
use tokio::io::ReadBuf;

#[test]
fn websocket_error_categories_preserve_protocol_security_and_generic_loss() {
    use tokio_tungstenite::tungstenite::{error::ProtocolError, Error as WsError};
    for error in [
        WsError::Protocol(ProtocolError::NonZeroReservedBits),
        WsError::AttackAttempt,
        WsError::Utf8("untrusted diagnostic".into()),
        WsError::WriteBufferFull(Box::new(Message::Binary(vec![0; 17].into()))),
    ] {
        assert!(matches!(record_error(error), Error::Framing));
    }
    for error in [
        WsError::ConnectionClosed,
        WsError::AlreadyClosed,
        WsError::Protocol(ProtocolError::ResetWithoutClosingHandshake),
    ] {
        assert!(matches!(record_error(error), Error::Closed));
    }
    // The provider's post-establishment stream has no typed trust-error API.
    // Even InvalidData plus suggestive text cannot establish a trust failure.
    for kind in [
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::InvalidData,
    ] {
        assert!(matches!(
            record_error(WsError::Io(std::io::Error::new(
                kind,
                "opaque provider error"
            ))),
            Error::Io(_)
        ));
    }
    #[cfg(feature = "tls-rustls")]
    {
        let error = || WsError::Io(std::io::Error::other(rustls::Error::DecryptError));
        assert!(matches!(record_error(error()), Error::Configuration));
        assert!(matches!(upgrade_error(error()), Error::Configuration));
    }
}

#[tokio::test]
async fn websocket_eof_without_close_is_generic_closed() {
    let (stream, peer) = tokio::io::duplex(128);
    let socket =
        WebSocketStream::from_raw_socket(stream, Role::Client, Some(websocket_config())).await;
    let (_, reader) = socket.split();
    drop(peer);
    assert!(matches!(
        Reader(reader).read_record(MAX_CIPHERTEXT).await,
        Err(Error::Closed)
    ));
}

#[tokio::test]
async fn malformed_websocket_frame_is_not_generic_closed() {
    let (stream, mut peer) = tokio::io::duplex(128);
    let socket =
        WebSocketStream::from_raw_socket(stream, Role::Server, Some(websocket_config())).await;
    let (_, reader) = socket.split();
    let mut reader = Reader(reader);
    // Client frames must be masked. This invalid header is a protocol failure.
    peer.write_all(&[0x82, 17]).await.unwrap();
    peer.write_all(&[0; 17]).await.unwrap();
    drop(peer);
    assert!(matches!(
        reader.read_record(MAX_CIPHERTEXT).await,
        Err(Error::Framing)
    ));
}

struct FailedIo;
fn stream_error() -> std::io::Error {
    #[cfg(feature = "tls-rustls")]
    return std::io::Error::other(rustls::Error::DecryptError);
    #[cfg(not(feature = "tls-rustls"))]
    std::io::Error::new(std::io::ErrorKind::ConnectionReset, "stream lost")
}
impl AsyncRead for FailedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(stream_error()))
    }
}
impl AsyncWrite for FailedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(stream_error()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(stream_error()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(stream_error()))
    }
}

#[tokio::test]
async fn websocket_read_write_and_upgrade_preserve_typed_stream_failures() {
    let socket =
        WebSocketStream::from_raw_socket(FailedIo, Role::Client, Some(websocket_config())).await;
    let (writer, reader) = socket.split();
    let mut reader = Reader(reader);
    let mut writer = Writer(writer);
    let read = reader.read_record(MAX_CIPHERTEXT).await.unwrap_err();
    let write = writer.write_record(&[0; 17]).await.unwrap_err();
    let request =
        client_request(&url::Url::parse("wss://host.invalid/syntra/1.0/ws").unwrap()).unwrap();
    let upgrade = client_upgrade(request, FailedIo).await.err().unwrap();
    for error in [read, write, upgrade] {
        #[cfg(feature = "tls-rustls")]
        assert!(matches!(error, Error::Configuration), "{error:?}");
        #[cfg(not(feature = "tls-rustls"))]
        assert!(matches!(error, Error::Io(_)), "{error:?}");
    }
}

#[test]
fn native_upgrade_rejects_present_origin_before_protected_establishment() {
    let request = || {
        Request::builder()
            .method("GET")
            .uri(ENDPOINT_PATH)
            .header("sec-websocket-protocol", SUBPROTOCOL)
            .body(())
            .unwrap()
    };
    assert!(upgrade(&request(), Response::new(())).is_ok());
    for value in ["null", "https://example.invalid", ""] {
        let mut supplied = request();
        supplied
            .headers_mut()
            .insert("origin", HeaderValue::from_str(value).unwrap());
        assert!(upgrade(&supplied, Response::new(())).is_err());
    }
    let mut duplicate = request();
    duplicate.headers_mut().append(
        "origin",
        HeaderValue::from_static("https://example.invalid"),
    );
    duplicate
        .headers_mut()
        .append("origin", HeaderValue::from_static("null"));
    assert!(upgrade(&duplicate, Response::new(())).is_err());
}

struct Source(AtomicU64);
impl syntra_runtime::elapsed::ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}
fn clock() -> (Arc<Source>, ElapsedClock) {
    let source = Arc::new(Source(AtomicU64::new(0)));
    let clock = ElapsedClock::with_source(source.clone());
    (source, clock)
}
fn security() -> (ClientConfig, ServerConfig) {
    let (private_key, public_key) = generate_server_key().unwrap();
    let scope = b"outer-budget-fixture".to_vec();
    (
        ClientConfig {
            context: ChannelContext {
                mode: Mode::Bootstrap,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 1,
                scope: scope.clone(),
                handle: [0; 8],
                epoch: 0,
            },
            server_public_key: public_key,
            authorization_key: None,
        },
        ServerConfig {
            mode: Mode::Bootstrap,
            carrier: Carrier::SecureWebSocket,
            server_key_id: 1,
            scope,
            private_key,
            store: None,
        },
    )
}
#[cfg(feature = "tls-rustls")]
fn tls() -> (TlsServerSettings, rustls::RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let settings = TlsServerSettings::new(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    (settings, roots)
}

#[cfg(feature = "tls-rustls")]
struct Factory(ElapsedClock, Arc<AtomicUsize>);
#[cfg(feature = "tls-rustls")]
impl AuthenticatorFactory for Factory {
    fn elapsed_clock(&self) -> ElapsedClock {
        self.0.clone()
    }
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(AllowAnonymous))
    }
}
struct Stall(Arc<AtomicBool>);
impl Drop for Stall {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl AsyncRead for Stall {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for Stall {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
#[cfg(feature = "tls-rustls")]
async fn outer_tls_server_wake_expires_before_upgrade_or_authentication() {
    let (source, clock) = clock();
    let (_, config) = security();
    let (tls, _) = tls();
    let dropped = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut accept = Box::pin(accept_tls_stream(
        Stall(dropped.clone()),
        &tls,
        &config,
        Arc::new(Factory(clock.clone(), calls.clone())),
        Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
        ConnectionConfig::default(),
        Limits {
            attempt_timeout: Duration::from_secs(1),
            ..Default::default()
        },
    ));
    assert!(futures_util::poll!(&mut accept).is_pending());
    source.0.store(1000, Ordering::SeqCst);
    clock.wake();
    let scheduled = tokio::time::Instant::now();
    assert!(matches!(accept.await, Err(Error::Timeout)));
    assert_eq!(scheduled, tokio::time::Instant::now());
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct JumpResponse {
    source: Arc<Source>,
    response: Vec<u8>,
    writes: Arc<AtomicUsize>,
}
impl AsyncRead for JumpResponse {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let count = this.response.len().min(buf.remaining());
        buf.put_slice(&this.response[..count]);
        drop(this.response.drain(..count));
        this.source.0.store(1000, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for JumpResponse {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn buffered_upgrade_crossing_cutoff_cannot_start_channel_or_write_again() {
    let (source, clock) = clock();
    let attempt = pump::EstablishmentBudget::new(clock, Duration::from_secs(1)).unwrap();
    let request = format!("wss://127.0.0.1{ENDPOINT_PATH}")
        .into_client_request()
        .unwrap();
    let key = request
        .headers()
        .get("sec-websocket-key")
        .unwrap()
        .to_str()
        .unwrap();
    let response = format!("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n", derive_accept_key(key.as_bytes()));
    let writes = Arc::new(AtomicUsize::new(0));
    let stream = EstablishmentIo {
        inner: JumpResponse {
            source,
            response: response.into_bytes(),
            writes: writes.clone(),
        },
        budget: attempt.io.clone(),
    };
    assert!(matches!(
        attempt.run(client_upgrade(request, stream)).await,
        Err(Error::Timeout)
    ));
    assert_eq!(
        writes.load(Ordering::SeqCst),
        1,
        "only the HTTP request was emitted"
    );
}

#[tokio::test]
#[cfg(feature = "tls-rustls")]
async fn actual_tls_dial_cancel_and_elapsed_expiry_release_the_only_socket_owner() {
    for cancel in [true, false] {
        let (source, clock) = clock();
        let (_, roots) = tls();
        let (config, _) = security();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("wss://{}{ENDPOINT_PATH}", listener.local_addr().unwrap());
        let dial_clock = clock.clone();
        let dial = tokio::spawn(async move {
            connect_with_roots_and_clock(
                &url,
                roots,
                config,
                vec![],
                ConnectionConfig::default(),
                Limits {
                    attempt_timeout: Duration::from_secs(2),
                    ..Default::default()
                },
                dial_clock,
            )
            .await
        });
        let (mut raw, _) = listener.accept().await.unwrap();
        let mut first = [0; 1];
        raw.read_exact(&mut first).await.unwrap(); // actual TLS ClientHello, no HTTP or Noise yet
        if cancel {
            dial.abort();
            match dial.await {
                Err(error) => assert!(error.is_cancelled()),
                Ok(_) => panic!("cancelled dial completed"),
            }
        } else {
            source.0.store(2000, Ordering::SeqCst);
            clock.wake();
            assert!(matches!(dial.await.unwrap(), Err(Error::Timeout)));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut bytes = [0; 4096];
            let mut total = 0;
            loop {
                let count = raw.read(&mut bytes).await.unwrap();
                if count == 0 {
                    break;
                }
                total += count;
                assert!(total < 65536);
            }
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn resolver_pool_exhaustion_is_availability_not_credential_rejection() {
    let jobs = pump::PolicyJobs::new(1).unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let work = jobs
        .spawn(move || {
            blocked.recv().unwrap();
        })
        .unwrap();
    let error = resolve("localhost".into(), 443, &jobs).await.unwrap_err();
    assert!(
        matches!(error, Error::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    release.send(()).unwrap();
    work.await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while jobs.pending() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn timed_out_outer_blocking_work_keeps_its_join_owner() {
    let (source, clock) = clock();
    let jobs = pump::PolicyJobs::new(1).unwrap();
    let attempt = pump::EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let work = jobs
        .spawn(move || {
            blocked.recv().unwrap();
        })
        .unwrap();
    let mut waiting = Box::pin(attempt.run(work));
    assert!(futures_util::poll!(&mut waiting).is_pending());
    source.0.store(1000, Ordering::SeqCst);
    clock.wake();
    assert!(matches!(waiting.await, Err(Error::Timeout)));
    assert_eq!(jobs.pending(), 1);
    assert_eq!(
        jobs.shutdown(&clock, Duration::ZERO).await.unwrap(),
        pump::TransportShutdown::ShutdownIncomplete {
            carrier_tasks: 0,
            policy_jobs: 1
        }
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while jobs.pending() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        jobs.shutdown(&clock, Duration::ZERO).await.unwrap(),
        pump::TransportShutdown::Complete
    );
}

#[tokio::test]
async fn connected_ws_stream_checks_endpoint_and_carrier_before_emission() {
    for secure in [true, false] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let (mut config, _) = security();
        let url = if secure {
            "wss://127.0.0.1/syntra/1.0/ws"
        } else {
            config.context.carrier = Carrier::WebSocket;
            "ws://192.0.2.1/syntra/1.0/ws"
        };
        let attempt =
            pump::EstablishmentBudget::new(pump::default_elapsed_clock(), Duration::from_secs(1))
                .unwrap();
        let result = connect_stream_with_budget(
            stream,
            url,
            config,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
            attempt,
        )
        .await;
        assert!(matches!(result, Err(Error::Configuration)));
        let mut byte = [0; 1];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0, "no HTTP or M1");
    }
}

#[tokio::test]
async fn connected_loopback_ws_stream_preserves_budget_through_protected_rpc() {
    use syntra_runtime::{AllowAnonymous, AuthError, Authenticator, FnHandler, HandlerOutcome};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (mut client, mut server) = security();
    client.context.carrier = Carrier::WebSocket;
    server.carrier = Carrier::WebSocket;
    let host = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let factory = Arc::new(
            |_: &syntra_core::secure_channel::VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                Ok(Arc::new(AllowAnonymous))
            },
        );
        accept_stream(
            stream,
            &server,
            factory,
            Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
        .unwrap()
    });
    let attempt =
        pump::EstablishmentBudget::new(pump::default_elapsed_clock(), Duration::from_secs(5))
            .unwrap();
    let stream = attempt
        .run(tokio::net::TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let client = connect_stream_with_budget(
        stream,
        &format!("ws://{address}{ENDPOINT_PATH}"),
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
        attempt,
    )
    .await
    .unwrap();
    let host = host.await.unwrap();
    assert_eq!(
        client
            .conn
            .call("/test.Service/Echo", vec![9; 1000], 1000)
            .await
            .unwrap(),
        vec![9; 1000]
    );
    client
        .close_gracefully(Duration::from_secs(1))
        .await
        .unwrap();
    host.close().await;
}

#[cfg(feature = "reconnect")]
mod active_loss {
    use super::*;
    use crate::client::{Failure, LifecycleStatus, ReconnectConfig, ReconnectingClient};
    use crate::tls::{BoxIo, EarlyData, ProviderTlsStream, TlsFuture, TlsMetadata, TlsProvider};
    use prost::Message as _;
    use syntra_runtime::{AllowAnonymous, AuthError, Authenticator, FnHandler, HandlerOutcome};

    // Real application-provider TLS, with fixture-only roots and the normal
    // chain/name/current-validity verifier. No production TLS feature is needed.
    struct ApplicationTls {
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    }
    impl ApplicationTls {
        fn new() -> Self {
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
            Self {
                client: Arc::new(client),
                server: Arc::new(server),
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
        fn accept(&self, _: BoxIo, _: TlsAuthority) -> TlsFuture<'_> {
            // The fixture peer below owns server TLS directly.
            Box::pin(async { Err(Error::Configuration) })
        }
    }

    async fn peer_stream(
        listener: &tokio::net::TcpListener,
        tls: Option<&ApplicationTls>,
    ) -> BoxIo {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).unwrap();
        if let Some(tls) = tls {
            Box::new(
                tokio_rustls::TlsAcceptor::from(tls.server.clone())
                    .accept(stream)
                    .await
                    .unwrap(),
            )
        } else {
            Box::new(stream)
        }
    }

    async fn protected_ready(ws: &mut WebSocketStream<BoxIo>, server: &ServerConfig) {
        let Message::Binary(first) = ws.next().await.unwrap().unwrap() else {
            panic!("expected Noise M1");
        };
        let (mut channel, second) = syntra_core::secure_channel::respond(server, &first).unwrap();
        ws.send(Message::Binary(second.into())).await.unwrap();
        let Message::Binary(hello) = ws.next().await.unwrap().unwrap() else {
            panic!("expected protected hello");
        };
        let plaintext = channel.decrypt(&hello).unwrap();
        let frames = syntra_core::secure_channel::FrameDecoder::default()
            .push(&plaintext)
            .unwrap();
        assert_eq!(frames.len(), 1);
        assert!(matches!(
            syntra_core::Frame::decode(frames[0].as_slice())
                .unwrap()
                .body,
            Some(syntra_core::proto::frame::Body::Hello(_))
        ));
        let ready = syntra_core::Frame {
            version: 1,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Ready(
                syntra_core::ServerReady {
                    connection_id: "active-loss-fixture".into(),
                },
            )),
        }
        .encode_to_vec();
        let ready = channel
            .encrypt(&syntra_core::secure_channel::frame_plaintext(&ready).unwrap())
            .unwrap();
        ws.send(Message::Binary(ready.into())).await.unwrap();
    }

    async fn exercise(secure: bool, malformed: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (mut client_config, mut server_config) = security();
        if !secure {
            client_config.context.carrier = Carrier::WebSocket;
            server_config.carrier = Carrier::WebSocket;
        }
        let tls = secure.then(|| Arc::new(ApplicationTls::new()));
        let server_tls = tls.clone();
        let (lose, loss) = tokio::sync::oneshot::channel();
        let (finish, finished) = tokio::sync::oneshot::channel();
        let peer = async move {
            let stream = peer_stream(&listener, server_tls.as_deref()).await;
            let mut ws = tokio_tungstenite::accept_hdr_async_with_config(
                stream,
                upgrade,
                Some(websocket_config()),
            )
            .await
            .unwrap();
            protected_ready(&mut ws, &server_config).await;
            // The test signals only after the ordinary supervisor is CoreReady:
            // this must exercise active loss, not a failed establishment retry.
            loss.await.unwrap();
            if malformed {
                // RSV1 without a negotiated extension is an actual frame error.
                ws.get_mut().write_all(&[0xc2, 0]).await.unwrap();
                ws.get_mut().flush().await.unwrap();
            }
            // End the underlying stream without a WebSocket Close. With TLS this
            // sends close_notify, so tungstenite sees EOF, not a TLS truncation.
            ws.get_mut().shutdown().await.unwrap();
            drop(ws);
            let host = if malformed {
                None
            } else {
                let stream = peer_stream(&listener, server_tls.as_deref()).await;
                let factory = Arc::new(
                    |_: &syntra_core::secure_channel::VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                        Ok(Arc::new(AllowAnonymous))
                    },
                );
                let attempt = pump::EstablishmentBudget::new(
                    pump::default_elapsed_clock(),
                    Duration::from_secs(5),
                )
                .unwrap();
                Some(
                    accept_upgraded(
                        stream,
                        &server_config,
                        factory,
                        Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
                        (ConnectionConfig::default(), Limits::default()),
                        attempt,
                    )
                    .await
                    .unwrap(),
                )
            };
            finished.await.unwrap();
            if let Some(host) = host {
                host.close().await;
            }
        };
        let client = async move {
            let attempts = Arc::new(AtomicUsize::new(0));
            let dials = attempts.clone();
            let mut client = ReconnectingClient::new(
                ReconnectConfig {
                    attempt_timeout: Duration::from_secs(5),
                    reconnect_budget: Duration::from_secs(10),
                    max_attempts: 3,
                    base_backoff: Duration::from_millis(10),
                    max_backoff: Duration::from_millis(10),
                    close_timeout: Duration::from_secs(1),
                    start_paused: false,
                    initial_network_available: true,
                },
                move || {
                    dials.fetch_add(1, Ordering::SeqCst);
                    let tls = tls.clone();
                    // Fresh Noise state on every dial, retaining the provisioned pin.
                    let config = ClientConfig {
                        context: client_config.context.clone(),
                        server_public_key: client_config.server_public_key,
                        authorization_key: None,
                    };
                    async move {
                        let url = format!(
                            "{}://{address}{ENDPOINT_PATH}",
                            if secure { "wss" } else { "ws" }
                        );
                        if let Some(tls) = tls {
                            let attempt = pump::EstablishmentBudget::new(
                                pump::default_elapsed_clock(),
                                Duration::from_secs(5),
                            )?;
                            let stream = attempt
                                .run(tokio::net::TcpStream::connect(address))
                                .await??;
                            let stream = tls::connect_stream_with_budget(
                                stream,
                                tls.as_ref(),
                                TlsAuthority::new("127.0.0.1", address.port())?,
                                attempt,
                            )
                            .await?;
                            connect_tls_stream_with_budget(
                                stream,
                                &url,
                                config,
                                vec![],
                                ConnectionConfig::default(),
                                Limits::default(),
                            )
                            .await
                        } else {
                            connect(
                                &url,
                                config,
                                vec![],
                                ConnectionConfig::default(),
                                Limits::default(),
                            )
                            .await
                        }
                    }
                },
            )
            .unwrap();
            let mut status = client.subscribe_status();
            let first = loop {
                match status.snapshot() {
                    LifecycleStatus::CoreReady(ready) => break ready.generation,
                    LifecycleStatus::Blocked(failure) => {
                        panic!("initial dial blocked: {failure:?}")
                    }
                    _ => {
                        status.changed().await.unwrap();
                    }
                }
            };
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
            lose.send(()).unwrap();
            loop {
                match status.changed().await.unwrap() {
                    LifecycleStatus::Blocked(failure) => {
                        assert!(malformed, "ordinary EOF permanently blocked: {failure:?}");
                        assert_eq!(failure, Failure::Framing);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        assert_eq!(client.status(), LifecycleStatus::Blocked(Failure::Framing));
                        assert_eq!(attempts.load(Ordering::SeqCst), 1);
                        break;
                    }
                    LifecycleStatus::CoreReady(ready) => {
                        assert!(!malformed, "malformed framing must not reconnect");
                        assert!(ready.generation > first);
                        assert_eq!(attempts.load(Ordering::SeqCst), 2);
                        assert!(!client.is_generation_current(first));
                        let reply = client
                            .call("/test.Service/Echo", vec![7; 1000], 1000)
                            .await
                            .unwrap();
                        assert_eq!(reply.generation, ready.generation);
                        assert_eq!(reply.value, vec![7; 1000]);
                        break;
                    }
                    LifecycleStatus::Exhausted { .. } => panic!("unexpected exhaustion"),
                    _ => {}
                }
            }
            client.close().await.unwrap();
            finish.send(()).unwrap();
        };
        tokio::join!(peer, client);
    }

    #[tokio::test]
    async fn protected_ws_active_eof_retries_with_ordinary_supervisor() {
        tokio::time::timeout(Duration::from_secs(10), exercise(false, false))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn protected_provider_wss_active_eof_retries_with_ordinary_supervisor() {
        tokio::time::timeout(Duration::from_secs(10), exercise(true, false))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn protected_ws_malformed_frame_blocks_ordinary_supervisor() {
        tokio::time::timeout(Duration::from_secs(10), exercise(false, true))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn protected_provider_wss_malformed_frame_blocks_ordinary_supervisor() {
        tokio::time::timeout(Duration::from_secs(10), exercise(true, true))
            .await
            .unwrap();
    }
}

#[test]
#[cfg(feature = "tls-rustls")]
fn public_establishment_futures_do_not_embed_the_whole_tls_channel_stack() {
    let (_, clock) = clock();
    let (client, server) = security();
    let (tls, roots) = tls();
    let calls = Arc::new(AtomicUsize::new(0));
    let dial = connect_with_roots_and_clock(
        "wss://127.0.0.1/syntra/1.0/ws",
        roots,
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
        clock.clone(),
    );
    let accept = accept_tls_stream(
        Stall(Arc::new(AtomicBool::new(false))),
        &tls,
        &server,
        Arc::new(Factory(clock, calls)),
        Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
        ConnectionConfig::default(),
        Limits::default(),
    );
    assert!(
        std::mem::size_of_val(&dial) < 65536,
        "dial future must remain caller-stack bounded: {}",
        std::mem::size_of_val(&dial)
    );
    assert!(
        std::mem::size_of_val(&accept) < 65536,
        "accept future must remain caller-stack bounded: {}",
        std::mem::size_of_val(&accept)
    );
}

#[tokio::test]
#[cfg(feature = "tls-rustls")]
async fn joined_connection_close_does_not_wait_for_an_unrelated_process_dns_job() {
    let (client_config, server_config) = security();
    let (settings, roots) = tls();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("wss://{}{ENDPOINT_PATH}", listener.local_addr().unwrap());
    let (release_peer, hold_peer) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(settings.config)
            .accept(stream)
            .await
            .unwrap();
        let mut ws = tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            upgrade,
            Some(websocket_config()),
        )
        .await
        .unwrap();
        let first = match ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            _ => panic!("m1"),
        };
        let (mut channel, second) =
            syntra_core::secure_channel::respond(&server_config, &first).unwrap();
        ws.send(Message::Binary(second.into())).await.unwrap();
        let hello = match ws.next().await.unwrap().unwrap() {
            Message::Binary(b) => b,
            _ => panic!("hello"),
        };
        channel.decrypt(&hello).unwrap();
        use prost::Message as _;
        let ready = syntra_core::Frame {
            version: 1,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Ready(
                syntra_core::ServerReady {
                    connection_id: "test-joined-close".into(),
                },
            )),
        }
        .encode_to_vec();
        let ready = channel
            .encrypt(&syntra_core::secure_channel::frame_plaintext(&ready).unwrap())
            .unwrap();
        ws.send(Message::Binary(ready.into())).await.unwrap();
        // Retain the peer socket independently of Close acknowledgement timing:
        // this regression isolates process-job versus connection ownership.
        hold_peer.await.unwrap();
        drop(ws);
    });
    let client = connect_with_roots(
        &url,
        roots,
        client_config,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    let runtime = client.conn.clone();
    // Deterministically hold a job from ANOTHER attempt beyond this close's
    // budget. Formerly Pump inherited this whole process pool, saw pending=1,
    // and returned Timeout despite already joined carrier/Core ownership.
    let pool = establishment_jobs();
    let (release, blocked) = std::sync::mpsc::channel();
    let unrelated = pool
        .spawn(move || {
            blocked.recv().unwrap();
        })
        .unwrap();
    assert!(pending_establishment_jobs() >= 1);
    let close = client.close_gracefully(Duration::from_secs(1)).await;
    let report = runtime.shutdown_report();
    let still_owned = pending_establishment_jobs();
    release.send(()).unwrap();
    unrelated.await.unwrap();
    close.expect("unrelated process work must not cause carrier close timeout");
    assert_eq!(
        report.phase,
        syntra_runtime::ShutdownPhase::Complete,
        "{report:?}"
    );
    assert_eq!(report.transport_tasks, 0);
    assert!(report.transport_closed);
    assert!(
        still_owned >= 1,
        "other attempt's job remains correctly accounted"
    );
    release_peer.send(()).unwrap();
    server.await.unwrap();
}
