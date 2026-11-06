//! Fatal reader publication versus an already-encrypted partial receipt. Tests
//! drive the actual reader continuation without polling its parent cleanup owner.
use super::*;
use std::{
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use syntra_runtime::{terminal::*, Principal, RequestContext, StaticToken};
use tokio::io::{AsyncWrite, AsyncWriteExt};

struct Owned(Mutex<Option<Transition>>);
impl Authority for Owned {
    fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
        Box::pin(async {
            match self.0.lock().unwrap().as_ref() {
                None => Observation::Active { revision: 1 },
                Some(c) => Observation::OwnedCommitted {
                    reservation: c.reservation.clone(),
                    expected_revision: 1,
                    revision: 2,
                },
            }
        })
    }
    fn commit(&self, c: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            *self.0.lock().unwrap() = Some(c);
        })
    }
}
struct Retire;
impl Handler for Retire {
    fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
        Ok(())
    }
    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        panic!("context hook required")
    }
    fn handle_with_context(
        &self,
        _: String,
        _: Vec<u8>,
        _: CancelToken,
        _: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        Box::pin(async move { context.retire(1).await.unwrap() })
    }
}

/// Record real underlying write attempts and exact bytes, with one partial unit
/// held Pending. Waking it offers an immediate writable carrier on the next poll.
struct CaptureWrite {
    allowance: Arc<Mutex<Option<usize>>>,
    writes: Arc<AtomicUsize>,
    bytes: Arc<Mutex<Vec<u8>>>,
    waker: Arc<AtomicWaker>,
}
impl AsyncWrite for CaptureWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.waker.register(cx.waker());
        self.writes.fetch_add(1, Ordering::SeqCst);
        let mut allowance = self.allowance.lock().unwrap();
        let n = allowance.map_or(bytes.len(), |n| n.min(bytes.len()));
        if n == 0 {
            return Poll::Pending;
        }
        self.bytes.lock().unwrap().extend_from_slice(&bytes[..n]);
        if let Some(allowance) = allowance.as_mut() {
            *allowance -= n;
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct CountRecord {
    inner: crate::tcp::StreamWriter<CaptureWrite>,
    starts: Arc<AtomicUsize>,
}
impl RecordWriter for CountRecord {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        self.inner.write_record(bytes).await
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown().await
    }
}

async fn fatal_reader_defeats_retained_receipt(fault: usize) {
    use syntra_core::{proto::ClientHello, Frame, RpcRequest};
    let clock = ElapsedClock::lifecycle_driven();
    let (host, mut ordinary) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(StaticToken::new(b"fixture".to_vec(), "fixture-principal")),
        Arc::new(Retire),
        clock.clone(),
    )
    .unwrap();
    let coordinator = host
        .install_terminal_tcp(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: Arc::new(Owned(Mutex::new(None))),
            read_timeout: Duration::from_millis(250),
        })
        .unwrap();
    coordinator.refresh().await.unwrap();
    let (mut client_channel, mut host_channel) = channels();
    let hello = Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: b"fixture".to_vec(),
        })),
    }
    .encode_to_vec();
    let authenticated = host_channel
        .decrypt(
            &client_channel
                .encrypt(&frame_plaintext(&hello).unwrap())
                .unwrap(),
        )
        .unwrap();
    host.ingest(&authenticated[4..]).await;
    ordinary.recv().await.unwrap();
    let mut commands = host.take_terminal_commands().unwrap();
    let request = Frame {
        version: 1,
        request_id: 1,
        body: Some(Body::Request(RpcRequest {
            method: "/example.Authority/Retire".into(),
            payload: vec![],
            timeout_ms: 2000,
        })),
    }
    .encode_to_vec();
    let authenticated = host_channel
        .decrypt(
            &client_channel
                .encrypt(&frame_plaintext(&request).unwrap())
                .unwrap(),
        )
        .unwrap();
    host.ingest(&authenticated[4..]).await;
    let Some(DriverCommand::Barrier(ack)) = commands.recv().await else {
        panic!("expected full-frame barrier")
    };
    ack.send(()).unwrap();
    let Some(DriverCommand::Receipt(output)) = commands.recv().await else {
        panic!("expected selected typed receipt")
    };
    let channel = Arc::new(Mutex::new(host_channel));
    let ciphertext = channel
        .lock()
        .unwrap()
        .encrypt(&frame_plaintext(output.bytes()).unwrap())
        .unwrap();
    let original_ciphertext = ciphertext.clone();
    let allowance = Arc::new(Mutex::new(Some(11)));
    let writes = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let waker = Arc::new(AtomicWaker::new());
    let starts = Arc::new(AtomicUsize::new(0));
    let mut writer = CountRecord {
        inner: crate::tcp::StreamWriter(CaptureWrite {
            allowance: allowance.clone(),
            writes: writes.clone(),
            bytes: bytes.clone(),
            waker: waker.clone(),
        }),
        starts: starts.clone(),
    };
    let authorization = Some(Arc::new(FreshAuthorization {
        base: Arc::new(TerminalAuthorization(coordinator.clone())),
        terminal: Some(coordinator.clone()),
        clock: clock.clone(),
        interval: Duration::from_millis(125),
        read: Duration::from_millis(250),
        close: Duration::from_millis(250),
        state: Mutex::new((None, false)),
    }));
    let peer = Peer::Host(host.clone());
    let mut retained_write = Box::pin(authorized_io_inner(
        writer.write_record(&ciphertext),
        &clock,
        Instant::from_std(coordinator.cutoff().unwrap()),
        Some(&peer),
        &authorization,
        Some((&coordinator, &output)),
    ));
    assert!(futures_util::poll!(&mut retained_write).is_pending());
    let before_writes = writes.load(Ordering::SeqCst);
    let before_bytes = bytes.lock().unwrap().clone();
    assert_eq!(
        before_bytes.len(),
        11,
        "partial encrypted record must really have started"
    );

    let (mut remote, input) = tokio::io::duplex(64);
    match fault {
        0 => {
            remote.write_all(&[0, 17]).await.unwrap();
            remote.write_all(&[0; 17]).await.unwrap();
        }
        1 => remote.write_all(&[0, 16]).await.unwrap(),
        _ => {} // EOF is also a terminal carrier failure for this connection.
    }
    drop(remote);
    let terminal = TransportTerminal::default();
    let mut reader = Box::pin(run_reader(
        crate::tcp::StreamReader(input),
        ReaderTask {
            channel,
            receive: ReceiveState::default(),
            end: elapsed_now(&clock) + Duration::from_secs(10),
            limits: Limits::default(),
            peer: peer.clone(),
            authorization: authorization.clone(),
            terminal: terminal.clone(),
        },
    ));
    // Do not yield or join the reader's parent after publication. This also keeps
    // the runtime's separate cleanup continuation unpolled until after handoff.
    let published = futures_util::poll!(&mut reader);
    assert!(matches!(published, Poll::Ready((Direction::Read, Err(_)))));
    assert_eq!(
        terminal.get(),
        Some(match fault {
            0 => TransportFailure::Channel,
            1 => TransportFailure::Framing,
            _ => TransportFailure::Io,
        })
    );
    assert!(
        !host.is_closed(),
        "test must precede parent/runtime cleanup"
    );
    *allowance.lock().unwrap() = None;
    waker.wake();
    assert!(
        matches!(
            futures_util::poll!(&mut retained_write),
            Poll::Ready(Err(_))
        ),
        "retained ciphertext escaped after local fatal reader publication"
    );
    assert!(
        !host.is_closed(),
        "denial must come from publication, not eventual close"
    );
    assert_eq!(
        writes.load(Ordering::SeqCst),
        before_writes,
        "zero additional underlying writes"
    );
    assert_eq!(
        *bytes.lock().unwrap(),
        before_bytes,
        "no appended or replacement bytes"
    );
    assert_eq!(
        starts.load(Ordering::SeqCst),
        1,
        "the ciphertext was never restarted"
    );
    assert_eq!(
        ciphertext, original_ciphertext,
        "no re-encryption or ciphertext replacement"
    );
    assert!(!coordinator.raw_allowed());
    drop(retained_write);
    drop(output);
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn fatal_reader_bad_tag_blocks_retained_receipt_before_parent_cleanup() {
    fatal_reader_defeats_retained_receipt(0).await;
}
#[tokio::test(start_paused = true)]
async fn fatal_reader_invalid_outer_length_blocks_retained_receipt_before_parent_cleanup() {
    fatal_reader_defeats_retained_receipt(1).await;
}
#[tokio::test(start_paused = true)]
async fn fatal_reader_carrier_eof_blocks_retained_receipt_before_parent_cleanup() {
    fatal_reader_defeats_retained_receipt(2).await;
}

struct CountAuthority(AtomicUsize);
impl Authority for CountAuthority {
    fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Observation::Active { revision: 1 } })
    }
    fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
        panic!("cache checks cannot commit")
    }
}
async fn cached_terminal() -> (Arc<Host>, Arc<FreshAuthorization>, Arc<CountAuthority>) {
    let clock = ElapsedClock::lifecycle_driven();
    let (host, _) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
        clock.clone(),
    )
    .unwrap();
    let authority = Arc::new(CountAuthority(AtomicUsize::new(0)));
    let c = host
        .install_terminal_tcp(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
        .unwrap();
    let guard = Arc::new(FreshAuthorization {
        base: Arc::new(TerminalAuthorization(c.clone())),
        terminal: Some(c),
        clock,
        interval: Duration::from_millis(50),
        read: Duration::from_millis(100),
        close: Duration::from_millis(250),
        state: Mutex::new((None, false)),
    });
    guard.check().await.unwrap();
    (host, guard, authority)
}

#[tokio::test(start_paused = true)]
async fn terminal_cached_hot_path_neither_reads_nor_renews_freshness() {
    let (host, guard, authority) = cached_terminal().await;
    for advance in [0, 40, 59] {
        tokio::time::advance(Duration::from_millis(advance)).await;
        for _ in 0..10 {
            guard.check_cached().await.unwrap();
        }
        assert_eq!(authority.0.load(Ordering::SeqCst), 1);
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(guard.check_cached().await.is_err());
    assert!(guard.check().await.is_err(), "expired cache is sticky");
    assert_eq!(authority.0.load(Ordering::SeqCst), 1);
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn terminal_cached_raw_repolls_never_reopen_authority() {
    let (host, guard, authority) = cached_terminal().await;
    let authorization = Some(guard.clone());
    let allowance = Arc::new(Mutex::new(Some(11)));
    let writes = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let waker = Arc::new(AtomicWaker::new());
    let starts = Arc::new(AtomicUsize::new(0));
    let mut writer = CountRecord {
        inner: crate::tcp::StreamWriter(CaptureWrite {
            allowance: allowance.clone(),
            writes: writes.clone(),
            bytes: bytes.clone(),
            waker: waker.clone(),
        }),
        starts: starts.clone(),
    };
    let peer = Peer::Host(host.clone());
    let mut write = Box::pin(write_checked(
        &mut writer,
        &[9; 32],
        &guard.clock,
        elapsed_now(&guard.clock) + Duration::from_secs(1),
        Some(&peer),
        &authorization,
    ));
    assert!(futures_util::poll!(&mut write).is_pending());
    for _ in 0..10 {
        waker.wake();
        assert!(futures_util::poll!(&mut write).is_pending());
    }
    assert_eq!(authority.0.load(Ordering::SeqCst), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let before = writes.load(Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(100)).await;
    *allowance.lock().unwrap() = None;
    waker.wake();
    assert!(matches!(
        futures_util::poll!(&mut write),
        Poll::Ready(Err(_))
    ));
    assert_eq!(writes.load(Ordering::SeqCst), before);
    assert_eq!(bytes.lock().unwrap().len(), 11);
    assert_eq!(authority.0.load(Ordering::SeqCst), 1);
    drop(write);
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn terminal_watchdog_queued_refresh_keeps_the_actual_observation_budget() {
    struct ReadQueue(tokio::sync::Semaphore, AtomicUsize);
    impl Authority for ReadQueue {
        fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                self.0.acquire().await.unwrap().forget();
                Observation::Active { revision: 1 }
            })
        }
        fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
            panic!("watchdog cannot commit")
        }
    }
    let clock = ElapsedClock::lifecycle_driven();
    let (host, _) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
        clock.clone(),
    )
    .unwrap();
    let authority = Arc::new(ReadQueue(
        tokio::sync::Semaphore::new(1),
        AtomicUsize::new(0),
    ));
    let c = host
        .install_terminal_tcp(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
        .unwrap();
    c.refresh().await.unwrap();
    let authorization = Some(Arc::new(FreshAuthorization {
        base: Arc::new(TerminalAuthorization(c.clone())),
        terminal: Some(c.clone()),
        clock: clock.clone(),
        interval: Duration::from_millis(50),
        read: Duration::from_millis(100),
        close: Duration::from_millis(250),
        state: Mutex::new((None, false)),
    }));
    // Queue at t=40 behind reads begun at t=20 and t=60. Acquire at t=90,
    // before the initial t=100 queue bound. Completion at t=145 is permitted
    // by current freshness t=160, beyond an obsolete outer t=140 read budget.
    tokio::time::advance(Duration::from_millis(20)).await;
    let mut first = Box::pin(c.refresh());
    assert!(futures_util::poll!(&mut first).is_pending());
    tokio::time::advance(Duration::from_millis(10)).await;
    let mut second = Box::pin(c.refresh());
    assert!(futures_util::poll!(&mut second).is_pending());
    tokio::time::advance(Duration::from_millis(10)).await;
    let mut watchdog = Box::pin(refresh_authorization(&authorization, &clock));
    assert!(futures_util::poll!(&mut watchdog).is_pending());
    tokio::time::advance(Duration::from_millis(20)).await;
    authority.0.add_permits(1);
    first.await.unwrap(); // Fresh until t=120.
    assert!(futures_util::poll!(&mut second).is_pending());
    tokio::time::advance(Duration::from_millis(30)).await;
    authority.0.add_permits(1);
    second.await.unwrap(); // Fresh until t=160.
    assert!(futures_util::poll!(&mut watchdog).is_pending());
    tokio::time::advance(Duration::from_millis(55)).await;
    authority.0.add_permits(1);
    assert!(watchdog.await.is_ok());
    assert_eq!(authority.1.load(Ordering::SeqCst), 4);
    host.close().await;
}

/// The otherwise idle responder kernel samples this source during encryption.
/// Reset after input preparation; subsequent observations can then distinguish
/// the actual writer's pre-encryption gate from its final handoff gate.
struct EncryptionSample(Arc<AtomicBool>);
impl syntra_core::secure_channel::ElapsedSource for EncryptionSample {
    fn elapsed(&self) -> Option<Duration> {
        self.0.store(true, Ordering::SeqCst);
        Some(Duration::ZERO)
    }
}
struct HandoffAuthority {
    owned: Mutex<Option<Transition>>,
    encrypted: Arc<AtomicBool>,
    final_reads: AtomicUsize,
    deny_final: bool,
}
impl Authority for HandoffAuthority {
    fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
        Box::pin(async {
            if self.encrypted.load(Ordering::SeqCst) {
                self.final_reads.fetch_add(1, Ordering::SeqCst);
                if self.deny_final {
                    return Observation::HardDenied;
                }
            }
            match self.owned.lock().unwrap().as_ref() {
                None => Observation::Active { revision: 1 },
                Some(c) => Observation::OwnedCommitted {
                    reservation: c.reservation.clone(),
                    expected_revision: 1,
                    revision: 2,
                },
            }
        })
    }
    fn commit(&self, c: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
        Box::pin(async move { *self.owned.lock().unwrap() = Some(c) })
    }
}

async fn actual_writer_final_gate(deny_final: bool) {
    use syntra_core::{proto::ClientHello, Frame, RpcRequest};
    let encrypted = Arc::new(AtomicBool::new(false));
    let authority = Arc::new(HandoffAuthority {
        owned: Mutex::new(None),
        encrypted: encrypted.clone(),
        final_reads: AtomicUsize::new(0),
        deny_final,
    });
    let clock = ElapsedClock::lifecycle_driven();
    let (host, mut outbound) = Host::try_new_with_clock(
        ConnectionConfig::default(),
        Arc::new(StaticToken::new(b"fixture".to_vec(), "fixture-principal")),
        Arc::new(Retire),
        clock.clone(),
    )
    .unwrap();
    let coordinator = host
        .install_terminal_tcp(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
        .unwrap();
    coordinator.refresh().await.unwrap();
    let (client_config, server_config) = configs(Mode::Bootstrap);
    let (client_handshake, first) = ClientHandshake::start(client_config).unwrap();
    let (mut channel, second) = syntra_core::secure_channel::respond_with_clock(
        &server_config,
        &first,
        syntra_core::secure_channel::Clock::with_source(Arc::new(EncryptionSample(
            encrypted.clone(),
        ))),
    )
    .unwrap();
    let mut remote = client_handshake.finish(&second).unwrap();
    let hello = Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: b"fixture".to_vec(),
        })),
    }
    .encode_to_vec();
    let hello = channel
        .decrypt(&remote.encrypt(&frame_plaintext(&hello).unwrap()).unwrap())
        .unwrap();
    host.ingest(&hello[4..]).await;
    outbound.recv().await.unwrap(); // Ready is outside the selected receipt.
    let request = Frame {
        version: 1,
        request_id: 1,
        body: Some(Body::Request(RpcRequest {
            method: "/example.Authority/Retire".into(),
            payload: vec![],
            timeout_ms: 2000,
        })),
    }
    .encode_to_vec();
    let request = channel
        .decrypt(&remote.encrypt(&frame_plaintext(&request).unwrap()).unwrap())
        .unwrap();
    encrypted.store(false, Ordering::SeqCst);
    let authorization = Some(Arc::new(FreshAuthorization {
        base: Arc::new(TerminalAuthorization(coordinator.clone())),
        terminal: Some(coordinator),
        clock: clock.clone(),
        interval: Duration::from_millis(50),
        read: Duration::from_millis(100),
        close: Duration::from_millis(250),
        state: Mutex::new((None, false)),
    }));
    let allowance = Arc::new(Mutex::new(Some(11)));
    let writes = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let waker = Arc::new(AtomicWaker::new());
    let starts = Arc::new(AtomicUsize::new(0));
    let writer = CountRecord {
        inner: crate::tcp::StreamWriter(CaptureWrite {
            allowance: allowance.clone(),
            writes: writes.clone(),
            bytes: bytes.clone(),
            waker: waker.clone(),
        }),
        starts: starts.clone(),
    };
    let (_input_owner, input) = tokio::io::duplex(64);
    let pump = spawn_pump(
        crate::tcp::StreamReader(input),
        writer,
        PumpState {
            channel,
            receive: ReceiveState::default(),
            peer: Peer::Host(host.clone()),
            outbound,
            limits: Limits::default(),
            end: elapsed_now(&clock) + Duration::from_secs(10),
            authorization,
            policy_jobs: None,
        },
    )
    .unwrap();
    host.ingest(&request[4..]).await;
    for _ in 0..100 {
        if authority.final_reads.load(Ordering::SeqCst) != 0 || bytes.lock().unwrap().len() == 11 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        encrypted.load(Ordering::SeqCst),
        "actual writer must consume the nonce"
    );
    assert_eq!(
        authority.final_reads.load(Ordering::SeqCst),
        1,
        "one explicit fresh read after encryption"
    );
    if deny_final {
        assert_eq!(
            writes.load(Ordering::SeqCst),
            0,
            "final denial prevents even the first prefix byte"
        );
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    } else {
        for _ in 0..10 {
            waker.wake();
            tokio::task::yield_now().await;
        }
        assert_eq!(
            authority.final_reads.load(Ordering::SeqCst),
            1,
            "partial-write repolls must remain local"
        );
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(bytes.lock().unwrap().len(), 11);
        *allowance.lock().unwrap() = None;
        waker.wake();
        for _ in 0..100 {
            if host.is_closed() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(host.is_closed());
        let wire = bytes.lock().unwrap().clone();
        let length = usize::from(u16::from_be_bytes([wire[0], wire[1]]));
        assert_eq!(wire.len(), length + 2);
        let plaintext = remote.decrypt(&wire[2..]).unwrap();
        let frame = Frame::decode(&plaintext[4..]).unwrap();
        assert_eq!(frame.request_id, 1);
        assert!(matches!(frame.body, Some(Body::Result(_))));
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "no replacement ciphertext"
        );
    }
    pump.close().await;
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn actual_receipt_writer_reads_once_after_encryption_then_repolls_locally() {
    actual_writer_final_gate(false).await;
}

#[tokio::test(start_paused = true)]
async fn actual_receipt_writer_denial_after_encryption_prevents_first_handoff() {
    actual_writer_final_gate(true).await;
}

struct ExpiryFactory {
    clock: ElapsedClock,
    authority: Arc<CountAuthority>,
}
impl AuthenticatorFactory for ExpiryFactory {
    fn elapsed_clock(&self) -> ElapsedClock {
        self.clock.clone()
    }
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(StaticToken::new(
            b"fixture".to_vec(),
            "fixture-principal",
        )))
    }
    fn terminal_receipt(&self, _: &VerifiedIdentity) -> Option<Policy> {
        Some(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: self.authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn ordinary_tcp_result_with_invalid_freshness_aborts_instead_of_quietly_dropping() {
    // Keep the scheduler from auto-advancing while real loopback TCP is pending.
    let awake = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let (source, clock) = elapsed_clock();
    let authority = Arc::new(CountAuthority(AtomicUsize::new(0)));
    let calls = Arc::new(AtomicUsize::new(0));
    let entered = calls.clone();
    let handler = Arc::new(AllowAll(FnHandler(move |_, payload, _| {
        let source = source.clone();
        let entered = entered.clone();
        async move {
            entered.fetch_add(1, Ordering::SeqCst);
            // No timer tick/wake or authority I/O: the ordinary writer must
            // discover lapsed Active authority when the selected result arrives.
            source.0.store(100, Ordering::SeqCst);
            HandlerOutcome::Payload(payload)
        }
    })));
    let (client_config, server_config) = configs(Mode::Bootstrap);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let factory = Arc::new(ExpiryFactory {
        clock,
        authority: authority.clone(),
    });
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        crate::tcp::accept_stream(
            stream,
            &server_config,
            factory,
            handler,
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
        .unwrap()
    });
    let client = crate::tcp::connect(
        address,
        client_config,
        b"fixture".to_vec(),
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    let host = accept.await.unwrap();
    tokio::task::yield_now().await;
    let reads = authority.0.load(Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    let mut call = Box::pin(client.conn.call(
        "/example.Authority/Echo",
        b"ordinary".to_vec(),
        2000,
    ));
    let mut result = None;
    for _ in 0..200 {
        if let Poll::Ready(outcome) = futures_util::poll!(&mut call) {
            result = Some(outcome);
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(result
        .expect("invalid authority must close, not leave a dropped result pending")
        .is_err());
    drop(call);
    assert_eq!(
        tokio::time::Instant::now(),
        start,
        "no RPC timeout or watchdog tick should be needed"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "real ordinary handler ran");
    for _ in 0..100 {
        if host.is_closed() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(host.is_closed());
    assert_eq!(
        host.pump.as_ref().unwrap().terminal.get(),
        Some(TransportFailure::Authentication)
    );
    assert_eq!(
        authority.0.load(Ordering::SeqCst),
        reads,
        "expiry cannot start a late read"
    );
    client.close().await;
    host.close().await;
    awake.abort();
    assert!(awake.await.unwrap_err().is_cancelled());
}
