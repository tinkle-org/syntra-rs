//! Supplemental outer-budget/ownership regressions, not independent TLS vectors.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use syntra_core::secure_channel::{
    generate_server_key, Context as ChannelContext, Mode, VerifiedIdentity,
};
use syntra_runtime::{AllowAnonymous, AuthError, Authenticator, FnHandler, HandlerOutcome};
use tokio::io::ReadBuf;

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
fn tls() -> (TlsServerSettings, rustls::RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let settings = TlsServerSettings::new(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
    )
    .unwrap();
    (settings, roots)
}

struct Factory(ElapsedClock, Arc<AtomicUsize>);
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

#[test]
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
