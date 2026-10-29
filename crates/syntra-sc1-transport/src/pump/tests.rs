use super::*;
use prost::Message;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use syntra_runtime::{AllowAnonymous, FnHandler, HandlerOutcome};
use syntra_secure_channel::{generate_server_key, Carrier, Context, KeyStore, Mode, Secret32};
use tokio::sync::Semaphore;

struct Store;
impl KeyStore for Store {
    fn lookup(&self, _: &Context) -> Result<Secret32, syntra_secure_channel::Error> {
        Ok(Secret32::new([7; 32]))
    }
}

fn configs(mode: Mode) -> (ClientConfig, ServerConfig) {
    let (private_key, server_public_key) = generate_server_key().unwrap();
    let returning = mode == Mode::Returning;
    let context = Context {
        mode,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"test".to_vec(),
        handle: if returning { [9; 8] } else { [0; 8] },
        epoch: if returning { 1 } else { 0 },
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: returning.then(|| Secret32::new([7; 32])),
        },
        ServerConfig {
            mode,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: context.scope,
            private_key,
            store: Some(Arc::new(Store)),
        },
    )
}

fn channels() -> (Channel, Channel) {
    let (client, server) = configs(Mode::Bootstrap);
    let (client, first) = ClientHandshake::start(client).unwrap();
    let (server, second) = respond(&server, &first).unwrap();
    (client.finish(&second).unwrap(), server)
}

struct QueueReader {
    records: mpsc::Receiver<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    later_record_delay: Option<Duration>,
}
impl RecordReader for QueueReader {
    async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let previous = self.reads.fetch_add(1, Ordering::SeqCst);
        if previous > 0 {
            if let Some(delay) = self.later_record_delay {
                tokio::time::sleep(delay).await;
            }
        }
        let record = self.records.recv().await.ok_or(Error::Closed)?;
        if record.len() > maximum {
            return Err(Error::Framing);
        }
        Ok(record)
    }
}

struct Gate {
    armed: AtomicBool,
    records: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
    dropped: AtomicBool,
}
impl Default for Gate {
    fn default() -> Self {
        Self {
            armed: AtomicBool::new(false),
            records: AtomicUsize::new(0),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            dropped: AtomicBool::new(false),
        }
    }
}

struct QueueWriter {
    records: mpsc::Sender<Vec<u8>>,
    gate: Arc<Gate>,
}
impl RecordWriter for QueueWriter {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.gate.armed.load(Ordering::SeqCst)
            && self.gate.records.fetch_add(1, Ordering::SeqCst) == 1
        {
            self.gate.entered.add_permits(1);
            self.gate
                .release
                .acquire()
                .await
                .map_err(|_| Error::Closed)?
                .forget();
        }
        self.records
            .send(bytes.to_vec())
            .await
            .map_err(|_| Error::Closed)
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
impl Drop for QueueWriter {
    fn drop(&mut self) {
        self.gate.dropped.store(true, Ordering::SeqCst);
    }
}

fn reader(records: mpsc::Receiver<Vec<u8>>) -> QueueReader {
    QueueReader {
        records,
        reads: Arc::new(AtomicUsize::new(0)),
        later_record_delay: None,
    }
}

fn anonymous() -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            Ok(Arc::new(AllowAnonymous))
        },
    )
}

#[tokio::test(start_paused = true)]
async fn cancelled_post_sc1_dial_releases_carrier_before_replacement() {
    // Poll establishment ourselves: no owner task gets a chance to clean up
    // between cancellation and starting the next dial.
    for _ in 0..8 {
        let (client, server) = configs(Mode::Returning);
        let (client_tx, mut server_rx) = mpsc::channel(8);
        let (server_tx, client_rx) = mpsc::channel(8);
        let gate = Arc::new(Gate::default());
        let mut dial = Box::pin(connect_records(
            reader(client_rx),
            QueueWriter {
                records: client_tx,
                gate: gate.clone(),
            },
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
        ));
        assert!(futures_util::poll!(&mut dial).is_pending());
        let first = server_rx.try_recv().unwrap();
        let (mut channel, second) = respond(&server, &first).unwrap();
        server_tx.send(second).await.unwrap();
        assert!(futures_util::poll!(&mut dial).is_pending());
        let hello = server_rx.try_recv().unwrap();
        assert!(channel.decrypt(&hello).is_ok());
        assert!(!gate.dropped.load(Ordering::SeqCst));
        drop(dial);
        assert!(gate.dropped.load(Ordering::SeqCst));
        assert!(server_rx.is_closed());
        assert!(server_tx.is_closed());
    }
}

#[tokio::test(start_paused = true)]
async fn core_handshake_loss_and_deadline_remain_retryable() {
    for close in [false, true] {
        let (client, server) = configs(Mode::Bootstrap);
        let (client_tx, mut server_rx) = mpsc::channel(8);
        let (server_tx, client_rx) = mpsc::channel(8);
        let gate = Arc::new(Gate::default());
        let runtime = ConnectionConfig {
            handshake_timeout: Duration::from_millis(5),
            ..ConnectionConfig::default()
        };
        let mut dial = Box::pin(connect_records(
            reader(client_rx),
            QueueWriter {
                records: client_tx,
                gate: gate.clone(),
            },
            client,
            vec![],
            runtime,
            Limits::default(),
        ));
        assert!(futures_util::poll!(&mut dial).is_pending());
        let (_, second) = respond(&server, &server_rx.try_recv().unwrap()).unwrap();
        server_tx.send(second).await.unwrap();
        assert!(futures_util::poll!(&mut dial).is_pending());
        assert!(server_rx.try_recv().is_ok()); // encrypted hello, no ready
        if close {
            drop(server_tx);
            assert!(matches!(dial.await, Err(Error::Closed)));
        } else {
            tokio::time::advance(Duration::from_millis(6)).await;
            assert!(matches!(dial.await, Err(Error::Timeout)));
        }
        assert!(gate.dropped.load(Ordering::SeqCst));
    }
}

fn ready_bytes() -> Vec<u8> {
    syntra_core::Frame {
        version: 1,
        request_id: 0,
        body: Some(syntra_core::proto::frame::Body::Ready(
            syntra_core::ServerReady {
                connection_id: "0123456789abcdef0123456789abcdef".into(),
            },
        )),
    }
    .encode_to_vec()
}

#[tokio::test(start_paused = true)]
async fn ready_with_coalesced_notifications_accounts_for_the_entire_batch() {
    let (client, server) = configs(Mode::Bootstrap);
    let (client_tx, mut server_rx) = mpsc::channel::<Vec<u8>>(8);
    let (server_tx, client_rx) = mpsc::channel(8);
    let server_task = tokio::spawn(async move {
        let (mut channel, second) = respond(&server, &server_rx.recv().await.unwrap()).unwrap();
        server_tx.send(second).await.unwrap();
        channel.decrypt(&server_rx.recv().await.unwrap()).unwrap();
        let mut stream = frame_plaintext(&ready_bytes()).unwrap().to_vec();
        for n in 0..500u32 {
            let frame = syntra_core::Frame {
                version: 1,
                request_id: 0,
                body: Some(syntra_core::proto::frame::Body::Notification(
                    syntra_core::Notification {
                        payload: n.to_be_bytes().to_vec(),
                    },
                )),
            }
            .encode_to_vec();
            stream.extend_from_slice(&frame_plaintext(&frame).unwrap());
        }
        server_tx
            .send(channel.encrypt(&stream).unwrap())
            .await
            .unwrap();
        (server_tx, server_rx)
    });
    let runtime = ConnectionConfig {
        notification_capacity: 1024,
        ..ConnectionConfig::default()
    };
    let client = connect_records(
        reader(client_rx),
        QueueWriter {
            records: client_tx,
            gate: Arc::new(Gate::default()),
        },
        client,
        vec![],
        runtime,
        Limits::default(),
    )
    .await
    .unwrap();
    let _peer = server_task.await.unwrap();
    for n in 0..500u32 {
        assert_eq!(
            client.conn.next_notification().await,
            Some(n.to_be_bytes().to_vec())
        );
    }
    assert_eq!(client.conn.notification_loss(), (0, 0));
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn partial_frame_deadline_survives_ready_and_background_handoff() {
    for ready_first in [false, true] {
        let (client, server) = configs(Mode::Bootstrap);
        let (client_tx, mut server_rx) = mpsc::channel::<Vec<u8>>(8);
        let (server_tx, client_rx) = mpsc::channel(8);
        let server_task = tokio::spawn(async move {
            let (mut channel, second) = respond(&server, &server_rx.recv().await.unwrap()).unwrap();
            server_tx.send(second).await.unwrap();
            channel.decrypt(&server_rx.recv().await.unwrap()).unwrap();
            let mut first = if ready_first {
                frame_plaintext(&ready_bytes()).unwrap().to_vec()
            } else {
                vec![]
            };
            first.push(0); // first byte of a new inner length prefix
            server_tx
                .send(channel.encrypt(&first).unwrap())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            let rest = frame_plaintext(&ready_bytes()).unwrap();
            let _ = server_tx.send(channel.encrypt(&rest[1..]).unwrap()).await;
        });
        let limits = Limits {
            frame_timeout: Duration::from_millis(10),
            record_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let start = Instant::now();
        let result = connect_records(
            reader(client_rx),
            QueueWriter {
                records: client_tx,
                gate: Arc::new(Gate::default()),
            },
            client,
            vec![],
            ConnectionConfig::default(),
            limits,
        )
        .await;
        if ready_first {
            let client = result.unwrap();
            wait_closed(&mut client.conn.subscribe_close()).await;
            client.close().await;
        } else {
            assert!(matches!(result, Err(Error::Timeout)));
        }
        assert!(Instant::now() - start < Duration::from_millis(30));
        server_task.abort();
        let _ = server_task.await;
    }
}

async fn connected(
    handler: Arc<dyn Handler>,
) -> (ClientHandle, HostHandle, Arc<Gate>, mpsc::Sender<Vec<u8>>) {
    let (client, server) = configs(Mode::Bootstrap);
    let (client_tx, server_rx) = mpsc::channel(8);
    let (server_tx, client_rx) = mpsc::channel(8);
    let gate = Arc::new(Gate::default());
    let server_gate = gate.clone();
    let server_task = tokio::spawn(async move {
        accept_records(
            reader(server_rx),
            QueueWriter {
                records: server_tx,
                gate: server_gate,
            },
            &server,
            anonymous(),
            handler,
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
        .unwrap()
    });
    let client = connect_records(
        reader(client_rx),
        QueueWriter {
            records: client_tx.clone(),
            gate: Arc::new(Gate::default()),
        },
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    (client, server_task.await.unwrap(), gate, client_tx)
}

#[tokio::test(start_paused = true)]
async fn confirmation_cannot_outlive_noise_lifetime_in_either_mode() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let (client, server) = configs(mode);
        let (client, first) = ClientHandshake::start(client).unwrap();
        let (to_server, incoming) = mpsc::channel(4);
        let (to_client, mut replies) = mpsc::channel(4);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
            move |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(AllowAnonymous))
            },
        );
        let limits = Limits {
            lifetime: Duration::from_millis(50),
            channel_timeout: Duration::from_secs(1),
            ..Limits::default()
        };
        let task = tokio::spawn(async move {
            accept_records(
                reader(incoming),
                QueueWriter {
                    records: to_client,
                    gate: Arc::new(Gate::default()),
                },
                &server,
                factory,
                Arc::new(FnHandler(|_, bytes, _| async move {
                    HandlerOutcome::Payload(bytes)
                })),
                ConnectionConfig::default(),
                limits,
            )
            .await
        });
        to_server.send(first).await.unwrap();
        let mut client = client.finish(&replies.recv().await.unwrap()).unwrap();
        tokio::time::advance(Duration::from_millis(200)).await;
        let hello = syntra_core::Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        }
        .encode_to_vec();
        let record = client.encrypt(&frame_plaintext(&hello).unwrap()).unwrap();
        let _ = to_server.send(record).await;
        assert!(matches!(task.await.unwrap(), Err(Error::Timeout)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn partial_frame_deadline_includes_every_backpressured_delivery_in_the_batch() {
    for (completed_frames, later_record_delay, expected_reads) in
        [(3, None, 1), (2, Some(Duration::from_millis(20)), 2)]
    {
        let (mut client, server) = channels();
        let mut plaintext = Vec::new();
        for byte in 1..=completed_frames {
            plaintext.extend_from_slice(&frame_plaintext(&[byte]).unwrap());
        }
        plaintext.extend_from_slice(&100u32.to_be_bytes());
        plaintext.push(9);
        let (tx, rx) = mpsc::channel(2);
        tx.send(client.encrypt(&plaintext).unwrap()).await.unwrap();
        tx.send(client.encrypt(&[9; 99]).unwrap()).await.unwrap();
        let mut input = reader(rx);
        input.later_record_delay = later_record_delay;
        let reads = input.reads.clone();
        let delivered = Arc::new(AtomicUsize::new(0));
        let count = delivered.clone();
        let now = Instant::now();
        let limits = Limits {
            frame_timeout: Duration::from_millis(50),
            write_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let result = read_frames(
            input,
            Arc::new(Mutex::new(server)),
            FrameDecoder::default().into(),
            now + Duration::from_secs(2),
            limits,
            move |_| {
                let count = count.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(Instant::now() - now, Duration::from_millis(50));
        assert_eq!(delivered.load(Ordering::SeqCst), 2);
        assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
    }
}

#[tokio::test(start_paused = true)]
async fn delayed_owner_poll_does_not_renew_lifetime() {
    let (client, _) = channels();
    let (_input_tx, input_rx) = mpsc::channel(1);
    let (output_tx, _output_rx) = mpsc::channel(1);
    let (conn, outbound) = Initiator::new(ConnectionConfig::default());
    let now = Instant::now();
    let mut pump = spawn_pump(
        reader(input_rx),
        QueueWriter {
            records: output_tx,
            gate: Arc::new(Gate::default()),
        },
        client,
        FrameDecoder::default().into(),
        Peer::Client(conn.clone()),
        outbound,
        Limits::default(),
        now + Duration::from_millis(50),
    );
    tokio::time::advance(Duration::from_millis(200)).await;
    pump.task.as_mut().unwrap().await.unwrap();
    assert_eq!(Instant::now() - now, Duration::from_millis(200));
    assert!(conn.is_closed());
}

#[tokio::test(start_paused = true)]
async fn close_watch_observes_close_before_and_after_subscription() {
    for close_before_subscribe in [true, false] {
        let (tx, _) = watch::channel(false);
        if close_before_subscribe {
            tx.send_replace(true);
        }
        let mut closed = tx.subscribe();
        if !close_before_subscribe {
            tx.send_replace(true);
        }
        let now = Instant::now();
        timeout(Duration::from_secs(1), wait_closed(&mut closed))
            .await
            .unwrap();
        assert_eq!(Instant::now(), now);
    }
    let (client, _) = channels();
    let (_input_tx, input_rx) = mpsc::channel(1);
    let (output_tx, _output_rx) = mpsc::channel(1);
    let (conn, outbound) = Initiator::new(ConnectionConfig::default());
    let mut pump = spawn_pump(
        reader(input_rx),
        QueueWriter {
            records: output_tx,
            gate: Arc::new(Gate::default()),
        },
        client,
        FrameDecoder::default().into(),
        Peer::Client(conn.clone()),
        outbound,
        Limits::default(),
        Instant::now() + Duration::from_secs(10),
    );
    conn.close().await;
    let now = Instant::now();
    pump.task.as_mut().unwrap().await.unwrap();
    assert_eq!(Instant::now(), now);
}

#[tokio::test(start_paused = true)]
async fn graceful_close_flushes_pump_owned_multirecord_result() {
    let handler = Arc::new(FnHandler(|_, _, _| async move {
        HandlerOutcome::Payload(vec![6; 200_000])
    }));
    let (client, host, gate, _) = connected(handler).await;
    gate.armed.store(true, Ordering::SeqCst);
    let conn = client.conn.clone();
    let request =
        tokio::spawn(async move { conn.call("/test.Service/Large", vec![], 5_000).await });
    gate.entered.acquire().await.unwrap().forget();
    let mut closed = host.host.subscribe_close();
    let closing = tokio::spawn(host.close_gracefully(Duration::from_secs(1)));
    wait_closed(&mut closed).await;
    assert!(!closing.is_finished());
    assert!(!request.is_finished());
    gate.release.add_permits(1);
    assert_eq!(request.await.unwrap().unwrap(), vec![6; 200_000]);
    closing.await.unwrap().unwrap();
    assert!(gate.dropped.load(Ordering::SeqCst));
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn graceful_close_deadline_aborts_a_stalled_carrier() {
    let handler = Arc::new(FnHandler(|_, _, _| async move {
        HandlerOutcome::Payload(vec![6; 200_000])
    }));
    let (client, host, gate, _) = connected(handler).await;
    gate.armed.store(true, Ordering::SeqCst);
    let conn = client.conn.clone();
    let request =
        tokio::spawn(async move { conn.call("/test.Service/Large", vec![], 5_000).await });
    gate.entered.acquire().await.unwrap().forget();
    let mut closed = host.host.subscribe_close();
    let now = Instant::now();
    let closing = tokio::spawn(host.close_gracefully(Duration::from_secs(1)));
    wait_closed(&mut closed).await;
    assert!(!closing.is_finished());
    assert!(matches!(closing.await.unwrap(), Err(Error::Timeout)));
    assert_eq!(Instant::now() - now, Duration::from_secs(1));
    assert!(request.await.unwrap().is_err());
    assert!(gate.dropped.load(Ordering::SeqCst));
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn cancelling_graceful_close_aborts_the_owned_writer() {
    let handler = Arc::new(FnHandler(|_, _, _| async move {
        HandlerOutcome::Payload(vec![6; 200_000])
    }));
    let (client, host, gate, _) = connected(handler).await;
    gate.armed.store(true, Ordering::SeqCst);
    let conn = client.conn.clone();
    let request =
        tokio::spawn(async move { conn.call("/test.Service/Large", vec![], 5_000).await });
    gate.entered.acquire().await.unwrap().forget();
    let mut closed = host.host.subscribe_close();
    let now = Instant::now();
    let closing = tokio::spawn(host.close_gracefully(Duration::from_secs(1)));
    wait_closed(&mut closed).await;
    closing.abort();
    assert!(closing.await.unwrap_err().is_cancelled());
    assert!(request.await.unwrap().is_err());
    assert_eq!(Instant::now(), now);
    assert!(gate.dropped.load(Ordering::SeqCst));
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn security_failures_abort_a_graceful_drain_without_waiting_for_grace() {
    for runtime_protocol_failure in [false, true] {
        let entered = Arc::new(Semaphore::new(0));
        let handler_entered = entered.clone();
        let handler = Arc::new(FnHandler(move |_, _, _| {
            handler_entered.add_permits(1);
            async { std::future::pending::<HandlerOutcome>().await }
        }));
        let (client, host, gate, tamper) = connected(handler).await;
        let conn = client.conn.clone();
        let request =
            tokio::spawn(async move { conn.call("/test.Service/Hold", vec![], 5_000).await });
        entered.acquire().await.unwrap().forget();
        gate.armed.store(true, Ordering::SeqCst);
        host.host.notify(vec![6; 200_000]).await.unwrap();
        gate.entered.acquire().await.unwrap().forget();
        let runtime = host.host.clone();
        let closing = tokio::spawn(host.close_gracefully(Duration::from_secs(1)));
        for _ in 0..100 {
            if runtime.state().await == ConnectionState::Closing {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(runtime.state().await, ConnectionState::Closing);
        let now = Instant::now();
        if runtime_protocol_failure {
            let unexpected_hello = syntra_core::Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Hello(syntra_core::ClientHello {
                    min_version: 1,
                    max_version: 1,
                    credential: vec![],
                })),
            }
            .encode_to_vec();
            runtime.ingest(&unexpected_hello).await;
        } else {
            tamper.send(vec![0; 17]).await.unwrap();
        }
        assert!(closing.await.unwrap().is_err());
        assert_eq!(Instant::now(), now);
        assert!(gate.dropped.load(Ordering::SeqCst));
        assert!(request.await.unwrap().is_err());
        client.close().await;
    }
}
