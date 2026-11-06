use super::*;
use prost::Message;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, Context, KeyStore, Mode, Secret32,
};
use syntra_runtime::{
    AllowAll, AllowAnonymous, CancelToken, ExecutionLease, FnHandler, HandlerFut, HandlerOutcome,
};
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[cfg(feature = "tcp")]
#[path = "terminal_failure_tests.rs"]
mod terminal_failures;

struct Store;
impl KeyStore for Store {
    fn lookup(&self, _: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
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

#[tokio::test(start_paused = true)]
async fn deferred_completion_keeps_cutoff_through_core_ready_and_drop() {
    for accepted in [false, true] {
        let (_, clock) = elapsed_clock();
        let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(2)).unwrap();
        let guard = budget.defer_completion();
        let budget = budget.cap(Duration::from_secs(1)).unwrap();
        budget.io.finish();
        assert!(budget.io.check().is_ok());
        if accepted {
            guard.finish().unwrap();
        }
        drop(guard);
        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(budget.io.check().is_ok(), accepted);
    }
    let (_, clock) = elapsed_clock();
    let budget = EstablishmentBudget::new(clock, Duration::from_secs(2)).unwrap();
    let guard = budget.defer_completion();
    budget.io.finish();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(matches!(guard.finish(), Err(Error::Timeout)));
    assert!(budget.io.check().is_err());

    let (_, clock) = elapsed_clock();
    let budget = EstablishmentBudget::new(clock, Duration::from_secs(15)).unwrap();
    let guard = budget.defer_completion();
    budget
        .io
        .completion
        .restrict(budget.started + Duration::from_secs(5))
        .unwrap();
    budget.io.finish();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert!(
        matches!(guard.finish(), Err(Error::Timeout)),
        "an earlier carrier setup cap still wins"
    );
    assert!(budget.io.check().is_err());
}

#[tokio::test(start_paused = true)]
async fn ordinary_core_ready_still_releases_the_attempt_gate() {
    let (_, clock) = elapsed_clock();
    let budget = EstablishmentBudget::new(clock, Duration::from_secs(2)).unwrap();
    budget.io.finish();
    tokio::time::advance(Duration::from_secs(16)).await;
    assert!(budget.io.check().is_ok());
}

#[tokio::test(start_paused = true)]
async fn absolute_budget_adoption_keeps_cutoff_and_rejects_expiry_and_continuity_loss() {
    let (_, clock) = elapsed_clock();
    let deadline = clock.now() + Duration::from_millis(100);
    tokio::time::advance(Duration::from_millis(40)).await;
    let budget = EstablishmentBudget::until(clock.clone(), deadline).unwrap();
    assert_eq!(budget.deadline(), deadline);
    assert_eq!(budget.io.deadline.into_std(), deadline);
    let entered = AtomicBool::new(false);
    assert!(matches!(
        budget
            .run(async {
                entered.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await
            })
            .await,
        Err(Error::Timeout)
    ));
    assert!(entered.load(Ordering::SeqCst));
    assert_eq!(clock.now(), deadline);
    assert!(matches!(
        EstablishmentBudget::until(clock.clone(), deadline),
        Err(Error::Timeout)
    ));
    clock.invalidate();
    assert!(matches!(
        EstablishmentBudget::until(clock.clone(), deadline + Duration::from_secs(1)),
        Err(Error::Timeout)
    ));
}

#[tokio::test(start_paused = true)]
async fn capped_budget_preserves_origin_clock_and_every_earlier_gate() {
    let (source, clock) = elapsed_clock();
    let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(5)).unwrap();
    let start = budget.started;
    let channel_clock = budget.channel_clock.clone();
    source.0.store(40, Ordering::SeqCst);
    let budget = budget.cap(Duration::from_millis(100)).unwrap();
    assert_eq!(budget.started, start);
    assert_eq!(budget.deadline, start + Duration::from_millis(100));
    assert_eq!(budget.channel_clock.age(), Duration::from_millis(40));
    assert_eq!(budget.channel_clock.age(), channel_clock.age());
    assert!(budget.io.check().is_ok());
    let budget = budget.cap(Duration::from_secs(10)).unwrap();
    assert_eq!(budget.deadline, start + Duration::from_millis(100));
    budget.io.until(start + Duration::from_millis(70)).unwrap();
    let budget = budget.cap(Duration::from_millis(90)).unwrap();
    assert_eq!(budget.deadline, start + Duration::from_millis(90));
    source.0.store(70, Ordering::SeqCst);
    assert!(
        budget.io.check().is_err(),
        "capping must not renew an earlier phase"
    );
    channel_clock.invalidate();
    assert_eq!(
        budget.channel_clock.age(),
        syntra_core::secure_channel::MAX_AGE
    );
    assert!(matches!(
        budget.cap(Duration::from_secs(1)),
        Err(Error::Timeout)
    ));

    let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    let shared_gate = budget.io.clone();
    assert!(matches!(
        budget.cap(Duration::from_millis(100)),
        Err(Error::Configuration)
    ));
    assert!(shared_gate.check().is_ok());
    let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    budget.io.finish();
    assert!(matches!(
        budget.cap(Duration::from_millis(100)),
        Err(Error::Configuration)
    ));
    let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    assert!(matches!(
        budget.cap(Duration::ZERO),
        Err(Error::Configuration)
    ));
    let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(1)).unwrap();
    assert!(budget.cap(Duration::from_millis(1)).is_ok());
    let budget = EstablishmentBudget::new(clock, Duration::from_secs(1)).unwrap();
    source.0.store(72, Ordering::SeqCst);
    assert!(matches!(
        budget.cap(Duration::from_millis(1)),
        Err(Error::Timeout)
    ));
}

#[test]
fn transport_terminal_retains_first_security_failure_over_generic_loss_and_cleanup() {
    for generic in [
        TransportFailure::Io,
        TransportFailure::Timeout,
        TransportFailure::Closed,
    ] {
        for security in [
            TransportFailure::Configuration,
            TransportFailure::Authentication,
            TransportFailure::Channel,
            TransportFailure::Runtime,
            TransportFailure::LocalProtocol(ErrorCode::InvalidArgument),
            TransportFailure::Framing,
        ] {
            let terminal = TransportTerminal::default();
            terminal.record(generic);
            terminal.record(security);
            terminal.record(TransportFailure::Closed);
            terminal.record(TransportFailure::Runtime);
            assert_eq!(terminal.get(), Some(security));
        }
    }
}

struct ReadRacePause {
    entered: oneshot::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

impl ReadRacePause {
    fn new() -> (Self, oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, waiting) = oneshot::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        (
            Self {
                entered,
                resume: resumed,
            },
            waiting,
            resume,
        )
    }

    fn wait(self) {
        let _ = self.entered.send(());
        // Closing the coordinator's sender releases this barrier, including on panic.
        assert!(self.resume.recv().is_err());
    }
}

struct BufferedRaceRead {
    record: Option<Vec<u8>>,
    pause: Option<ReadRacePause>,
}

impl Future for BufferedRaceRead {
    type Output = Result<Vec<u8>, Error>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Ready(Ok(self.record.take().unwrap()))
    }
}

impl Drop for BufferedRaceRead {
    fn drop(&mut self) {
        // authorized_io drops the completed future outside Core's raw-poll gate,
        // before read_frames can decrypt the buffered record.
        if let Some(pause) = self.pause.take() {
            pause.wait();
        }
    }
}

struct RaceReader {
    record: Option<Vec<u8>>,
    before_decrypt: Option<ReadRacePause>,
    after_decrypt: Option<ReadRacePause>,
}

impl RecordReader for RaceReader {
    fn read_record(&mut self, _: usize) -> impl Future<Output = Result<Vec<u8>, Error>> + Send {
        BufferedRaceRead {
            record: self.record.take(),
            pause: self.before_decrypt.take(),
        }
    }
}

impl Drop for RaceReader {
    fn drop(&mut self) {
        // A decrypt failure has returned, but the task has not recorded its category.
        if let Some(pause) = self.after_decrypt.take() {
            pause.wait();
        }
    }
}

struct RaceWriter(Option<oneshot::Sender<()>>);

impl RecordWriter for RaceWriter {
    async fn write_record(&mut self, _: &[u8]) -> Result<(), Error> {
        panic!("race fixture has no outbound frames")
    }

    async fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl Drop for RaceWriter {
    fn drop(&mut self) {
        if let Some(dropped) = self.0.take() {
            let _ = dropped.send(());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_local_teardown_closed_channel_read_is_retryable() {
    let (mut sender, channel) = channels();
    let record = sender.encrypt(&frame_plaintext(&[1]).unwrap()).unwrap();
    let (pause, waiting, resume) = ReadRacePause::new();
    let (writer_dropped, dropped) = oneshot::channel();
    let (output, outbound) = mpsc::channel(1);
    let (conn, _runtime_outbound) = Initiator::new(ConnectionConfig::default());
    let mut pump = spawn_pump(
        RaceReader {
            record: Some(record),
            before_decrypt: Some(pause),
            after_decrypt: None,
        },
        RaceWriter(Some(writer_dropped)),
        PumpState {
            channel,
            receive: ReceiveState::default(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: Instant::now() + Duration::from_secs(10),
            authorization: None,
            policy_jobs: None,
        },
    )
    .unwrap();
    timeout(Duration::from_secs(2), waiting)
        .await
        .unwrap()
        .unwrap();
    conn.suspend();
    assert!(!pump.peer.delivery_open());
    // End the writer independently of the close watch so it closes the shared
    // channel before the owner can cancel it or the buffered read can resume.
    drop(output);
    timeout(Duration::from_secs(2), dropped)
        .await
        .unwrap()
        .unwrap();
    conn.close().await;
    drop(resume);
    assert_eq!(
        pump.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    assert_eq!(pump.terminal.get(), Some(TransportFailure::Closed));
    assert!(!pump.terminal.get().unwrap().terminal());
    assert_eq!(conn.shutdown_report().transport_tasks, 0);
    assert!(conn.shutdown_report().transport_closed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_local_teardown_keeps_decrypt_failures_terminal() {
    for invalid_tag in [true, false] {
        let (mut sender, channel) = channels();
        let mut record = sender.encrypt(&frame_plaintext(&[1]).unwrap()).unwrap();
        if invalid_tag {
            *record.last_mut().unwrap() ^= 1;
        } else {
            record.truncate(16);
        }
        let (pause, waiting, resume) = ReadRacePause::new();
        let (writer_dropped, dropped) = oneshot::channel();
        let (output, outbound) = mpsc::channel(1);
        let (conn, _runtime_outbound) = Initiator::new(ConnectionConfig::default());
        let mut pump = spawn_pump(
            RaceReader {
                record: Some(record),
                before_decrypt: None,
                after_decrypt: Some(pause),
            },
            RaceWriter(Some(writer_dropped)),
            PumpState {
                channel,
                receive: ReceiveState::default(),
                peer: Peer::Client(conn.clone()),
                outbound,
                limits: Limits::default(),
                end: Instant::now() + Duration::from_secs(10),
                authorization: None,
                policy_jobs: None,
            },
        )
        .unwrap();
        timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap()
            .unwrap();
        conn.suspend();
        drop(output);
        timeout(Duration::from_secs(2), dropped)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pump.terminal.get(), Some(TransportFailure::Closed));
        conn.close().await;
        drop(resume);
        assert_eq!(
            pump.shutdown_transport(Duration::from_secs(1))
                .await
                .unwrap(),
            TransportShutdown::Complete
        );
        assert_eq!(pump.terminal.get(), Some(TransportFailure::Channel));
        assert!(pump.terminal.get().unwrap().terminal());
        assert_eq!(conn.shutdown_report().transport_tasks, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pump_closed_channel_without_local_teardown_remains_terminal() {
    let (mut sender, mut channel) = channels();
    let record = sender.encrypt(&frame_plaintext(&[1]).unwrap()).unwrap();
    channel.close();
    let (conn, outbound) = Initiator::new(ConnectionConfig::default());
    let (output, _outgoing) = mpsc::channel(1);
    let mut pump = spawn_pump(
        RaceReader {
            record: Some(record),
            before_decrypt: None,
            after_decrypt: None,
        },
        QueueWriter {
            records: output,
            gate: Arc::new(Gate::default()),
        },
        PumpState {
            channel,
            receive: ReceiveState::default(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: Instant::now() + Duration::from_secs(10),
            authorization: None,
            policy_jobs: None,
        },
    )
    .unwrap();
    timeout(
        Duration::from_secs(2),
        wait_closed(&mut conn.subscribe_close()),
    )
    .await
    .unwrap();
    assert_eq!(
        pump.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    assert_eq!(pump.terminal.get(), Some(TransportFailure::Channel));
    assert_eq!(conn.shutdown_report().transport_tasks, 0);
}

struct CloseOnDropReader(Initiator);
impl RecordReader for CloseOnDropReader {
    async fn read_record(&mut self, _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Framing)
    }
}
impl Drop for CloseOnDropReader {
    fn drop(&mut self) {
        // read_frames drops its reader after raw polling has left the Core gate,
        // but before the task wrapper can retain its result.
        self.0.suspend();
    }
}

#[tokio::test(start_paused = true)]
async fn joined_category_survives_peer_close_winning_the_owner_select() {
    let (channel, _) = channels();
    let (output, _output_rx) = mpsc::channel(1);
    let (conn, outbound) = Initiator::new(ConnectionConfig::default());
    let mut pump = spawn_pump(
        CloseOnDropReader(conn.clone()),
        QueueWriter {
            records: output,
            gate: Arc::new(Gate::default()),
        },
        PumpState {
            channel,
            receive: ReceiveState::default(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: Instant::now() + Duration::from_secs(10),
            authorization: None,
            policy_jobs: None,
        },
    )
    .unwrap();
    let mut closed = conn.subscribe_close();
    wait_closed(&mut closed).await;
    assert_eq!(
        pump.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    assert_eq!(pump.terminal.get(), Some(TransportFailure::Framing));
    assert_eq!(conn.shutdown_report().transport_tasks, 0);
}

struct PanicAuthorization;
impl ConnectionAuthorization for PanicAuthorization {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async { panic!("authorization panic fixture") })
    }
    fn interval(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn read_timeout(&self) -> Duration {
        Duration::from_millis(100)
    }
    fn close_timeout(&self) -> Duration {
        Duration::from_millis(100)
    }
}

#[tokio::test(start_paused = true)]
async fn watchdog_panic_retains_runtime_category_and_joins_carrier_children() {
    let (channel, _) = channels();
    let (_input, input_rx) = mpsc::channel(1);
    let (output, _output_rx) = mpsc::channel(1);
    let (conn, outbound) = Initiator::new(ConnectionConfig::default());
    let mut pump = spawn_pump(
        reader(input_rx),
        QueueWriter {
            records: output,
            gate: Arc::new(Gate::default()),
        },
        PumpState {
            channel,
            receive: ReceiveState::default(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: Instant::now() + Duration::from_secs(10),
            authorization: Some(Arc::new(
                FreshAuthorization::new(Arc::new(PanicAuthorization), conn.elapsed_clock())
                    .unwrap(),
            )),
            policy_jobs: None,
        },
    )
    .unwrap();
    let mut closed = conn.subscribe_close();
    wait_closed(&mut closed).await;
    assert_eq!(pump.terminal.get(), Some(TransportFailure::Runtime));
    assert_eq!(
        pump.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    assert_eq!(conn.shutdown_report().transport_tasks, 0);
    assert!(conn.shutdown_report().transport_closed);
    assert_ne!(conn.shutdown_report().failed_tasks, 0);
}

#[tokio::test(start_paused = true)]
async fn pump_retains_record_and_inner_framing_failures_before_signalling_loss() {
    for case in 0..3 {
        let (mut client_channel, server_channel) = channels();
        let record = match case {
            0 => vec![0; MAX_CIPHERTEXT + 1],
            1 => vec![0; 17],
            _ => client_channel.encrypt(&u32::MAX.to_be_bytes()).unwrap(),
        };
        let (input, input_rx) = mpsc::channel(1);
        let (output, _output_rx) = mpsc::channel(1);
        let (conn, outbound) = Initiator::new(ConnectionConfig::default());
        let mut pump = spawn_pump(
            reader(input_rx),
            QueueWriter {
                records: output,
                gate: Arc::new(Gate::default()),
            },
            PumpState {
                channel: server_channel,
                receive: ReceiveState::default(),
                peer: Peer::Client(conn.clone()),
                outbound,
                limits: Limits::default(),
                end: Instant::now() + Duration::from_secs(10),
                authorization: None,
                policy_jobs: None,
            },
        )
        .unwrap();
        input.send(record).await.unwrap();
        let mut closed = conn.subscribe_close();
        wait_closed(&mut closed).await;
        let expected = if case == 0 {
            TransportFailure::Framing
        } else {
            TransportFailure::Channel
        };
        assert_eq!(pump.terminal.get(), Some(expected));
        assert_eq!(
            pump.shutdown_transport(Duration::from_secs(1))
                .await
                .unwrap(),
            TransportShutdown::Complete
        );
        assert_eq!(pump.terminal.get(), Some(expected));
        assert_eq!(conn.shutdown_report().transport_tasks, 0);
    }
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

#[test]
fn runtime_limits_and_carrier_close_budget_are_validated_separately() {
    let mut runtime = ConnectionConfig::default();
    for capacity in [0, 1, 15, 1025, usize::MAX] {
        runtime.max_outstanding = capacity;
        assert!(matches!(
            Limits::default().validate(&runtime),
            Err(Error::Configuration)
        ));
    }
    for capacity in [16, 1024] {
        runtime.max_outstanding = capacity;
        let mut limits = Limits::default();
        assert_eq!(limits.close_timeout, Duration::from_secs(1));
        limits.close_timeout = Duration::from_secs(86_400);
        assert!(limits.validate(&runtime).is_ok());
        limits.close_timeout += Duration::from_nanos(1);
        assert!(matches!(
            limits.validate(&runtime),
            Err(Error::Configuration)
        ));
        limits.close_timeout = Duration::ZERO;
        assert!(matches!(
            limits.validate(&runtime),
            Err(Error::Configuration)
        ));
    }
}

#[tokio::test(start_paused = true)]
async fn consuming_close_caps_every_accepted_carrier_budget_at_runtime_maximum() {
    for close_timeout in [
        Duration::from_nanos(1),
        syntra_runtime::MAX_CLOSE_GRACE - Duration::from_secs(1),
        syntra_runtime::MAX_CLOSE_GRACE - Duration::from_nanos(1),
        syntra_runtime::MAX_CLOSE_GRACE,
        Duration::from_secs(86_400),
    ] {
        let limits = Limits {
            close_timeout,
            ..Limits::default()
        };
        limits.validate(&ConnectionConfig::default()).unwrap();
        let (channel, _) = channels();
        let (conn, outbound) = Initiator::new(ConnectionConfig::default());
        let (_input, incoming) = mpsc::channel(1);
        let (output, _outgoing) = mpsc::channel(1);
        let gate = Arc::new(Gate::default());
        let pump = spawn_pump(
            reader(incoming),
            QueueWriter {
                records: output,
                gate: gate.clone(),
            },
            PumpState {
                channel,
                receive: ReceiveState::default(),
                peer: Peer::Client(conn.clone()),
                outbound,
                limits,
                end: Instant::now() + Duration::from_secs(86_400),
                authorization: None,
                policy_jobs: None,
            },
        )
        .unwrap();
        assert_eq!(
            pump.grace,
            (close_timeout + Duration::from_secs(1)).min(syntra_runtime::MAX_CLOSE_GRACE)
        );
        validate_close_grace(pump.grace).unwrap();
        pump.close().await;
        assert!(gate.dropped.load(Ordering::SeqCst));
        assert_eq!(conn.shutdown_report().transport_tasks, 0);
        assert_eq!(
            conn.shutdown_report().phase,
            syntra_runtime::ShutdownPhase::Complete
        );
    }
}

#[tokio::test]
async fn invalid_runtime_config_rejects_both_record_entries_before_io() {
    for runtime in [
        ConnectionConfig {
            max_outstanding: 15,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            writer_capacity: 0,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            notification_capacity: 0,
            ..ConnectionConfig::default()
        },
        ConnectionConfig {
            handshake_timeout: Duration::MAX,
            ..ConnectionConfig::default()
        },
    ] {
        let (client, server) = configs(Mode::Bootstrap);
        let (_input, incoming) = mpsc::channel(1);
        let input = reader(incoming);
        let reads = input.reads.clone();
        let (output, mut outgoing) = mpsc::channel(1);
        assert!(matches!(
            connect_records(
                input,
                QueueWriter {
                    records: output,
                    gate: Arc::new(Gate::default())
                },
                client,
                vec![],
                runtime.clone(),
                Limits::default()
            )
            .await,
            Err(Error::Configuration)
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert!(outgoing.try_recv().is_err());

        let (_input, incoming) = mpsc::channel(1);
        let input = reader(incoming);
        let reads = input.reads.clone();
        let (output, mut outgoing) = mpsc::channel(1);
        assert!(matches!(
            accept_records(
                input,
                QueueWriter {
                    records: output,
                    gate: Arc::new(Gate::default())
                },
                &server,
                anonymous(),
                Arc::new(FnHandler(|_, bytes, _| async move {
                    HandlerOutcome::Payload(bytes)
                })),
                runtime,
                Limits::default()
            )
            .await,
            Err(Error::Configuration)
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        assert!(outgoing.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn receipt_timestamps_precede_every_delivery_in_a_reconstructed_batch() {
    for fragmented in [false, true] {
        let (mut client, server) = channels();
        let mut plaintext = frame_plaintext(&[1]).unwrap().to_vec();
        plaintext.extend_from_slice(&frame_plaintext(&[2]).unwrap());
        let (tx, rx) = mpsc::channel(2);
        if fragmented {
            tx.send(client.encrypt(&plaintext[..4]).unwrap())
                .await
                .unwrap();
            tx.send(client.encrypt(&plaintext[4..]).unwrap())
                .await
                .unwrap();
        } else {
            tx.send(client.encrypt(&plaintext).unwrap()).await.unwrap();
        }
        let mut input = reader(rx);
        input.later_record_delay = Some(Duration::from_millis(10));
        let deliveries = Arc::new(Mutex::new(Vec::new()));
        let observed = deliveries.clone();
        let start = Instant::now();
        let result = read_frames(
            input,
            Arc::new(Mutex::new(server)),
            ReceiveState::default(),
            start + Duration::from_secs(1),
            Limits::default(),
            ReadContext {
                clock: ElapsedClock::lifecycle_driven(),
                peer: None,
                authorization: None,
            },
            move |frame, received_at| {
                let observed = observed.clone();
                async move {
                    observed.lock().unwrap().push((
                        frame[0],
                        received_at,
                        Instant::now().into_std(),
                    ));
                    if frame[0] == 2 {
                        return Err(Error::Closed);
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Ok(())
                }
            },
        )
        .await;
        assert!(matches!(result, Err(Error::Closed)));
        let deliveries = deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 2);
        let first_receipt = start.into_std()
            + if fragmented {
                Duration::from_millis(10)
            } else {
                Duration::ZERO
            };
        assert_eq!(deliveries[0], (1, first_receipt, first_receipt));
        assert_eq!(
            deliveries[1],
            (2, first_receipt, first_receipt + Duration::from_millis(20))
        );
    }
}

#[tokio::test(start_paused = true)]
async fn host_peer_uses_receipt_time_not_later_delivery_time() {
    let calls = Arc::new(AtomicUsize::new(0));
    let effects = calls.clone();
    let (host, mut outbound) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(move |_, bytes, _| {
            effects.fetch_add(1, Ordering::SeqCst);
            async move { HandlerOutcome::Payload(bytes) }
        })),
    );
    let peer = Peer::Host(host.clone());
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
    peer.ingest_received_at(&hello, Instant::now().into_std())
        .await;
    assert!(outbound.recv().await.is_some());
    let request = syntra_core::Frame {
        version: 1,
        request_id: 1,
        body: Some(Body::Request(syntra_core::RpcRequest {
            method: "/test.Service/Echo".into(),
            payload: vec![],
            timeout_ms: 10,
        })),
    }
    .encode_to_vec();
    let received_at = Instant::now().into_std();
    tokio::time::advance(Duration::from_millis(20)).await;
    peer.ingest_received_at(&request, received_at).await;
    let frame = syntra_core::Frame::decode(outbound.recv().await.unwrap().as_slice()).unwrap();
    assert_eq!(frame.request_id, 1);
    assert!(
        matches!(frame.body, Some(Body::Result(syntra_core::RpcResult {
        outcome: Some(syntra_core::proto::rpc_result::Outcome::Error(error)),
    })) if error.code == syntra_core::ErrorCode::DeadlineExceeded.as_i32())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn graceful_close_zero_aborts_without_spending_a_drain_budget() {
    let handler = Arc::new(FnHandler(|_, bytes, _| async move {
        HandlerOutcome::Payload(bytes)
    }));
    let (client, host, gate, _) = connected(handler).await;
    let runtime = host.host.clone();
    gate.armed.store(true, Ordering::SeqCst);
    host.host.notify(vec![6; 200_000]).await.unwrap();
    gate.entered.acquire().await.unwrap().forget();
    let now = Instant::now();
    assert!(matches!(
        host.close_gracefully(Duration::ZERO).await,
        Err(Error::Timeout)
    ));
    // A zero budget requests abort but cannot attest a not-yet-joined owner.
    // Core retains it even though the consuming compatibility handle is gone.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert_eq!(Instant::now(), now);
    assert!(runtime.is_closed());
    assert!(gate.dropped.load(Ordering::SeqCst));
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn application_close_grace_accepts_30_seconds_but_not_more() {
    for grace in [
        Duration::from_secs(30),
        Duration::from_secs(30) + Duration::from_nanos(1),
        Duration::MAX,
    ] {
        let handler = Arc::new(FnHandler(|_, bytes, _| async move {
            HandlerOutcome::Payload(bytes)
        }));
        let (client, host, _, _) = connected(handler).await;
        let result = host.close_gracefully(grace).await;
        if grace == Duration::from_secs(30) {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(Error::Configuration)));
        }
        client.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_post_channel_dial_releases_carrier_before_replacement() {
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
    connected_with_factory(anonymous(), handler).await
}

async fn connected_with_factory(
    factory: Arc<dyn AuthenticatorFactory>,
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
            factory,
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

struct BudgetFactory(ExecutionBudget);

impl AuthenticatorFactory for BudgetFactory {
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(AllowAnonymous))
    }

    fn execution_budget(&self) -> ExecutionBudget {
        self.0.clone()
    }
}

struct ExternalLeaseHandler {
    leases: mpsc::Sender<ExecutionLease>,
    calls: Arc<AtomicUsize>,
}

impl Handler for ExternalLeaseHandler {
    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        panic!("execution hook must be used")
    }

    fn handle_with_execution(
        &self,
        _: String,
        payload: Vec<u8>,
        _: CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.leases
            .try_send(lease)
            .unwrap_or_else(|_| panic!("test must retain every external execution lease"));
        // Reporting success does not mean external work has stopped. The test
        // owns the lease until it explicitly releases that work's accounting.
        Box::pin(async move { HandlerOutcome::Payload(payload) })
    }
}

#[tokio::test(start_paused = true)]
async fn replacement_accept_records_keeps_external_execution_charged_to_factory_budget() {
    let budget = ExecutionBudget::new(1);
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(BudgetFactory(budget.clone()));
    let calls = Arc::new(AtomicUsize::new(0));
    let (leases, mut transferred) = mpsc::channel(2);
    let handler: Arc<dyn Handler> = Arc::new(AllowAll(ExternalLeaseHandler {
        leases,
        calls: calls.clone(),
    }));
    // Keep the supported core capacity (default 32), with a separate quota of 1.
    let (first, first_host, _, _) = connected_with_factory(factory.clone(), handler.clone()).await;
    assert_eq!(
        first
            .conn
            .call("/test.Service/Echo", vec![1], 1000)
            .await
            .unwrap(),
        vec![1]
    );
    let external = transferred.recv().await.unwrap();
    assert_eq!(budget.in_use(), 1);
    first_host.close().await;
    first.close().await;
    assert_eq!(
        budget.in_use(),
        1,
        "transport close must not release external work"
    );

    // A new accept/handshake using the same factory must not reset the quota.
    let (replacement, replacement_host, _, _) =
        connected_with_factory(factory.clone(), handler).await;
    let error = replacement
        .conn
        .call("/test.Service/Echo", vec![2], 1000)
        .await
        .unwrap_err();
    assert_eq!(error.code(), syntra_core::ErrorCode::ResourceExhausted);
    assert!(!replacement.is_closed());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(transferred.try_recv().is_err());
    assert_eq!(budget.in_use(), 1);

    drop(external);
    assert_eq!(budget.in_use(), 0);
    assert_eq!(
        replacement
            .conn
            .call("/test.Service/Echo", vec![3], 1000)
            .await
            .unwrap(),
        vec![3]
    );
    let external = transferred.recv().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(budget.in_use(), 1);
    replacement_host.close().await;
    replacement.close().await;
    assert_eq!(budget.in_use(), 1);
    drop(external);
    assert_eq!(budget.in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn default_factory_budget_is_process_shared_across_accepted_connections() {
    struct DefaultFactory;
    impl AuthenticatorFactory for DefaultFactory {
        fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
            Ok(Arc::new(AllowAnonymous))
        }
    }

    assert_eq!(DEFAULT_AGGREGATE_EXECUTION_LIMIT, 1024);
    // Cover both the blanket closure implementation and an ordinary factory
    // using the default hook, with distinct accepted connections.
    let factories: [Arc<dyn AuthenticatorFactory>; 2] = [anonymous(), Arc::new(DefaultFactory)];
    let (leases, mut transferred) = mpsc::channel(2);
    let handler: Arc<dyn Handler> = Arc::new(AllowAll(ExternalLeaseHandler {
        leases,
        calls: Arc::new(AtomicUsize::new(0)),
    }));
    let mut external = Vec::new();
    for factory in &factories {
        let (client, host, _, _) = connected_with_factory(factory.clone(), handler.clone()).await;
        assert_eq!(
            client
                .conn
                .call("/test.Service/Echo", vec![1], 1000)
                .await
                .unwrap(),
            vec![1]
        );
        external.push(transferred.recv().await.unwrap());
        host.close().await;
        client.close().await;
    }
    for factory in &factories {
        // Both retained leases must be visible from every default factory,
        // even after carrier teardown. Other parallel tests may also be charged.
        assert!(factory.execution_budget().in_use() >= external.len());
    }
    drop(external);
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
            ReadContext {
                clock: ElapsedClock::lifecycle_driven(),
                peer: None,
                authorization: None,
            },
            move |_, _| {
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
    let pump = spawn_pump(
        reader(input_rx),
        QueueWriter {
            records: output_tx,
            gate: Arc::new(Gate::default()),
        },
        PumpState {
            channel: client,
            receive: FrameDecoder::default().into(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: now + Duration::from_millis(50),
            authorization: None,
            policy_jobs: None,
        },
    )
    .unwrap();
    tokio::time::advance(Duration::from_millis(200)).await;
    assert!(
        pump.task
            .as_ref()
            .unwrap()
            .join_until(
                &pump.clock,
                (elapsed_now(&pump.clock) + Duration::from_secs(1)).into_std()
            )
            .await
    );
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
    let pump = spawn_pump(
        reader(input_rx),
        QueueWriter {
            records: output_tx,
            gate: Arc::new(Gate::default()),
        },
        PumpState {
            channel: client,
            receive: FrameDecoder::default().into(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: Instant::now() + Duration::from_secs(10),
            authorization: None,
            policy_jobs: None,
        },
    )
    .unwrap();
    conn.close().await;
    let now = Instant::now();
    assert!(
        pump.task
            .as_ref()
            .unwrap()
            .join_until(
                &pump.clock,
                (elapsed_now(&pump.clock) + Duration::from_secs(1)).into_std()
            )
            .await
    );
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

struct CurrentAuthorization;
impl ConnectionAuthorization for CurrentAuthorization {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async { Ok(()) })
    }
    fn interval(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn read_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn close_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}

struct GuardedFactory;
impl AuthenticatorFactory for GuardedFactory {
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(AllowAnonymous))
    }
    fn connection_authorization(
        &self,
        _: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        Ok(Some(Arc::new(CurrentAuthorization)))
    }
}

#[tokio::test(start_paused = true)]
async fn authorization_freshness_also_bounds_a_stalled_server_ready_write() {
    let (client_config, server_config) = configs(Mode::Bootstrap);
    let (to_host, host_records) = mpsc::channel(8);
    let (to_client, client_records) = mpsc::channel(8);
    let gate = Arc::new(Gate::default());
    gate.armed.store(true, Ordering::SeqCst);
    let server_gate = gate.clone();
    let server = tokio::spawn(async move {
        accept_records(
            reader(host_records),
            QueueWriter {
                records: to_client,
                gate: server_gate,
            },
            &server_config,
            Arc::new(GuardedFactory),
            Arc::new(FnHandler(|_, payload, _| async move {
                HandlerOutcome::Payload(payload)
            })),
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
    });
    let client = tokio::spawn(async move {
        connect_records(
            reader(client_records),
            QueueWriter {
                records: to_host,
                gate: Arc::new(Gate::default()),
            },
            client_config,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
    });
    gate.entered.acquire().await.unwrap().forget();
    let start = Instant::now();
    assert!(matches!(server.await.unwrap(), Err(Error::Timeout)));
    assert_eq!(start.elapsed(), Duration::from_secs(1));
    assert!(gate.dropped.load(Ordering::SeqCst));
    assert!(client.await.unwrap().is_err());
}

struct ElapsedSource(std::sync::atomic::AtomicU64);
impl syntra_runtime::elapsed::ElapsedSource for ElapsedSource {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}
fn elapsed_clock() -> (Arc<ElapsedSource>, ElapsedClock) {
    let source = Arc::new(ElapsedSource(std::sync::atomic::AtomicU64::new(0)));
    let clock = ElapsedClock::with_source(source.clone());
    (source, clock)
}

#[tokio::test(start_paused = true)]
async fn noise_client_deadline_precedes_wake_buffered_m2_without_scheduler_advance() {
    let (source, clock) = elapsed_clock();
    let (client, server) = configs(Mode::Returning);
    let (client_tx, mut server_rx) = mpsc::channel(8);
    let (server_tx, client_rx) = mpsc::channel(8);
    let mut dial = Box::pin(connect_records_with_clock(
        reader(client_rx),
        QueueWriter {
            records: client_tx,
            gate: Arc::new(Gate::default()),
        },
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
        clock.clone(),
    ));
    assert!(futures_util::poll!(&mut dial).is_pending());
    let (_, second) = respond(&server, &server_rx.try_recv().unwrap()).unwrap();
    source.0.store(6000, Ordering::SeqCst);
    clock.wake();
    server_tx.send(second).await.unwrap();
    let scheduled = Instant::now();
    assert!(matches!(dial.await, Err(Error::Timeout)));
    assert_eq!(Instant::now(), scheduled);
    assert!(
        server_rx.try_recv().is_err(),
        "expired M2 must not release encrypted hello"
    );
}

struct ClockFactory(ElapsedClock, Arc<AtomicUsize>);
impl AuthenticatorFactory for ClockFactory {
    fn elapsed_clock(&self) -> ElapsedClock {
        self.0.clone()
    }
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(AllowAnonymous))
    }
}

#[tokio::test(start_paused = true)]
async fn noise_host_deadline_precedes_wake_buffered_hello_and_factory_effects() {
    let (source, clock) = elapsed_clock();
    let (client, server) = configs(Mode::Bootstrap);
    let (handshake, first) = ClientHandshake::start(client).unwrap();
    let (input, records) = mpsc::channel(8);
    let (output, mut emitted) = mpsc::channel(8);
    input.send(first).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut accept = Box::pin(accept_records(
        reader(records),
        QueueWriter {
            records: output,
            gate: Arc::new(Gate::default()),
        },
        &server,
        Arc::new(ClockFactory(clock.clone(), calls.clone())),
        Arc::new(FnHandler(
            |_, p, _| async move { HandlerOutcome::Payload(p) },
        )),
        ConnectionConfig::default(),
        Limits::default(),
    ));
    assert!(futures_util::poll!(&mut accept).is_pending());
    let mut client = handshake.finish(&emitted.try_recv().unwrap()).unwrap();
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
    input
        .send(client.encrypt(&frame_plaintext(&hello).unwrap()).unwrap())
        .await
        .unwrap();
    source.0.store(6000, Ordering::SeqCst);
    clock.wake();
    let scheduled = Instant::now();
    assert!(matches!(accept.await, Err(Error::Timeout)));
    assert_eq!(Instant::now(), scheduled);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(emitted.try_recv().is_err());
}

struct JumpReader {
    source: Arc<ElapsedSource>,
    record: Vec<u8>,
}
impl RecordReader for JumpReader {
    async fn read_record(&mut self, _: usize) -> Result<Vec<u8>, Error> {
        self.source.0.store(2000, Ordering::SeqCst);
        Ok(std::mem::take(&mut self.record))
    }
}

#[tokio::test(start_paused = true)]
async fn record_elapsed_gate_rechecks_ready_io_before_decryption_or_delivery() {
    let (source, clock) = elapsed_clock();
    let (mut client, server) = channels();
    let ciphertext = client.encrypt(&frame_plaintext(&[7]).unwrap()).unwrap();
    let channel = Arc::new(Mutex::new(server));
    let delivered = Arc::new(AtomicUsize::new(0));
    let count = delivered.clone();
    let result = read_frames(
        JumpReader {
            source,
            record: ciphertext.clone(),
        },
        channel.clone(),
        ReceiveState::default(),
        elapsed_now(&clock) + Duration::from_secs(1),
        Limits::default(),
        ReadContext {
            clock,
            peer: None,
            authorization: None,
        },
        move |_, _| {
            count.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        },
    )
    .await;
    assert!(matches!(result, Err(Error::Timeout)));
    assert_eq!(delivered.load(Ordering::SeqCst), 0);
    assert!(
        channel.lock().unwrap().decrypt(&ciphertext).is_ok(),
        "expired buffered record consumed no receive nonce"
    );
}

struct LiveGuard {
    valid: AtomicBool,
    checks: AtomicUsize,
}
impl ConnectionAuthorization for LiveGuard {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        let valid = self.valid.load(Ordering::SeqCst);
        Box::pin(async move {
            if valid {
                Ok(())
            } else {
                Err(AuthError::unauthenticated())
            }
        })
    }
    fn interval(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn read_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
    fn close_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}
struct WaitWriter {
    release: Arc<Semaphore>,
    writes: Arc<AtomicUsize>,
}
impl RecordWriter for WaitWriter {
    async fn write_record(&mut self, _: &[u8]) -> Result<(), Error> {
        self.release.acquire().await.unwrap().forget();
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

#[tokio::test(start_paused = true)]
async fn backpressured_ciphertext_is_not_repolled_after_revocation_suspend_or_elapsed_loss() {
    for fault in 0..4 {
        let (source, clock) = elapsed_clock();
        let (conn, _out) =
            Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
        let peer = Peer::Client(conn.clone());
        let release = Arc::new(Semaphore::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let guard = Arc::new(LiveGuard {
            valid: AtomicBool::new(true),
            checks: AtomicUsize::new(0),
        });
        let authorization = Some(Arc::new(
            FreshAuthorization::new(guard.clone(), clock.clone()).unwrap(),
        ));
        let mut writer = WaitWriter {
            release: release.clone(),
            writes: writes.clone(),
        };
        let mut write = Box::pin(write_checked(
            &mut writer,
            &[9; 17],
            &clock,
            elapsed_now(&clock) + Duration::from_secs(1),
            Some(&peer),
            &authorization,
        ));
        assert!(futures_util::poll!(&mut write).is_pending());
        match fault {
            0 => {
                guard.valid.store(false, Ordering::SeqCst);
                assert!(refresh_authorization(&authorization, &clock).await.is_err());
            }
            1 => conn.suspend(),
            2 => {
                source.0.store(2000, Ordering::SeqCst);
                clock.wake();
            }
            _ => clock.invalidate(),
        }
        release.add_permits(1);
        assert!(write.await.is_err());
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        if fault == 0 {
            assert_eq!(guard.checks.load(Ordering::SeqCst), 2);
        }
        conn.on_transport_lost().await;
    }
}

#[tokio::test]
async fn retained_policy_shutdown_never_extends_budget_or_claims_cancelled_work_joined() {
    let pool = PolicyJobs::new(1).unwrap();
    let clock = ElapsedClock::lifecycle_driven();
    let (release, blocked) = std::sync::mpsc::channel();
    let result = pool
        .spawn(move || {
            blocked.recv().unwrap();
            7u8
        })
        .unwrap();
    assert_eq!(pool.pending(), 1);
    assert_eq!(
        pool.shutdown(&clock, Duration::ZERO).await.unwrap(),
        TransportShutdown::ShutdownIncomplete {
            carrier_tasks: 0,
            policy_jobs: 1
        }
    );
    assert!(pool.spawn(|| 8u8).is_err());
    let start = Instant::now();
    assert_eq!(
        pool.shutdown(&clock, Duration::from_secs(30))
            .await
            .unwrap(),
        TransportShutdown::ShutdownIncomplete {
            carrier_tasks: 0,
            policy_jobs: 1
        }
    );
    assert!(start.elapsed() < Duration::from_millis(100));
    release.send(()).unwrap();
    assert_eq!(result.await.unwrap(), 7);
    timeout(Duration::from_secs(1), async {
        while pool.pending() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        pool.shutdown(&clock, Duration::ZERO).await.unwrap(),
        TransportShutdown::Complete
    );
}

#[tokio::test(start_paused = true)]
async fn lapsed_authorization_cannot_renew_from_a_fresh_read_after_wake() {
    let (source, clock) = elapsed_clock();
    let base = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let guard = FreshAuthorization::new(base.clone(), clock.clone()).unwrap();
    guard.check().await.unwrap();
    assert_eq!(base.checks.load(Ordering::SeqCst), 1);
    source.0.store(3000, Ordering::SeqCst);
    clock.wake();
    assert!(guard.check().await.is_err());
    assert_eq!(
        base.checks.load(Ordering::SeqCst),
        1,
        "expired authority was not extended by another lookup"
    );
    assert!(guard.check().await.is_err());
}

#[tokio::test(start_paused = true)]
async fn cached_authorization_reuses_reads_without_extending_until() {
    let (source, clock) = elapsed_clock();
    let base = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let guard = FreshAuthorization::new(base.clone(), clock.clone()).unwrap();
    guard.check_cached().await.unwrap(); // Cold cache must read first.
    let until = guard.state.lock().unwrap().0;
    for millis in [0, 500, 1000, 2000, 2999] {
        source.0.store(millis, Ordering::SeqCst);
        for _ in 0..10 {
            guard.check_cached().await.unwrap();
        }
        assert_eq!(guard.state.lock().unwrap().0, until);
        assert_eq!(base.checks.load(Ordering::SeqCst), 1);
    }
    source.0.store(3000, Ordering::SeqCst);
    assert!(guard.check_cached().await.is_err());
    assert!(guard.check().await.is_err());
    assert_eq!(base.checks.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn cached_authorization_gates_raw_repolls_without_reopening_store() {
    let (_, clock) = elapsed_clock();
    let base = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let authorization = Some(Arc::new(
        FreshAuthorization::new(base.clone(), clock.clone()).unwrap(),
    ));
    let release = Arc::new(Semaphore::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let mut writer = WaitWriter {
        release: release.clone(),
        writes: writes.clone(),
    };
    for _ in 0..10 {
        let mut write = Box::pin(write_checked(
            &mut writer,
            &[9; 17],
            &clock,
            elapsed_now(&clock) + Duration::from_secs(1),
            None,
            &authorization,
        ));
        assert!(futures_util::poll!(&mut write).is_pending());
        release.add_permits(1);
        write.await.unwrap();
    }
    assert_eq!(writes.load(Ordering::SeqCst), 10);
    assert_eq!(base.checks.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn cached_authorization_preserves_withdrawal_and_continuity_failures() {
    for invalidate in [false, true] {
        let (_, clock) = elapsed_clock();
        let base = Arc::new(LiveGuard {
            valid: AtomicBool::new(true),
            checks: AtomicUsize::new(0),
        });
        let guard = FreshAuthorization::new(base.clone(), clock.clone()).unwrap();
        guard.check().await.unwrap();
        if invalidate {
            clock.invalidate();
        } else {
            base.valid.store(false, Ordering::SeqCst);
            assert!(guard.check().await.is_err());
            base.valid.store(true, Ordering::SeqCst);
        }
        assert!(guard.check_cached().await.is_err());
        assert!(guard.check().await.is_err());
        assert_eq!(
            base.checks.load(Ordering::SeqCst),
            if invalidate { 1 } else { 2 }
        );
    }
}

#[tokio::test(start_paused = true)]
async fn cached_authorization_failure_wins_over_parallel_success() {
    struct DelayedGuard(Arc<Semaphore>);
    impl ConnectionAuthorization for DelayedGuard {
        fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
            Box::pin(async move {
                self.0.acquire().await.unwrap().forget();
                Ok(())
            })
        }
        fn interval(&self) -> Duration {
            Duration::from_secs(1)
        }
        fn read_timeout(&self) -> Duration {
            Duration::from_secs(1)
        }
        fn close_timeout(&self) -> Duration {
            Duration::from_secs(1)
        }
    }
    let (_, clock) = elapsed_clock();
    let release = Arc::new(Semaphore::new(1));
    let guard = FreshAuthorization::new(Arc::new(DelayedGuard(release.clone())), clock).unwrap();
    guard.check().await.unwrap();
    let mut first = Box::pin(guard.check());
    assert!(futures_util::poll!(&mut first).is_pending());
    tokio::time::advance(Duration::from_millis(500)).await;
    let mut later = Box::pin(guard.check());
    assert!(futures_util::poll!(&mut later).is_pending());
    tokio::time::advance(Duration::from_millis(500)).await;
    assert!(first.await.is_err());
    release.add_permits(1);
    assert!(
        later.await.is_err(),
        "late success must not resurrect authority"
    );
    assert!(guard.check_cached().await.is_err());
}

struct LiveFactory {
    clock: ElapsedClock,
    guard: Arc<LiveGuard>,
}
impl AuthenticatorFactory for LiveFactory {
    fn elapsed_clock(&self) -> ElapsedClock {
        self.clock.clone()
    }
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(AllowAnonymous))
    }
    fn connection_authorization(
        &self,
        _: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        Ok(Some(self.guard.clone()))
    }
}

#[tokio::test(start_paused = true)]
async fn idle_watchdog_closes_lapsed_authority_without_scheduler_advance() {
    let (source, clock) = elapsed_clock();
    let guard = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let factory = Arc::new(LiveFactory {
        clock: clock.clone(),
        guard: guard.clone(),
    });
    let (client, mut host, _, _) = connected_with_factory(
        factory,
        Arc::new(FnHandler(
            |_, p, _| async move { HandlerOutcome::Payload(p) },
        )),
    )
    .await;
    let checks = guard.checks.load(Ordering::SeqCst);
    source.0.store(4000, Ordering::SeqCst);
    clock.wake();
    let scheduled = Instant::now();
    let mut closed = host.host.subscribe_close();
    wait_closed(&mut closed).await;
    assert_eq!(Instant::now(), scheduled);
    assert_eq!(guard.checks.load(Ordering::SeqCst), checks);
    assert_eq!(
        host.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    assert_eq!(host.host.shutdown_report().transport_tasks, 0);
    assert!(host.host.shutdown_report().transport_closed);
    assert_eq!(
        host.pump.as_ref().unwrap().terminal.get(),
        Some(TransportFailure::Authentication)
    );
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn watchdog_reads_authoritatively_even_while_poll_checks_are_cached() {
    let (_, clock) = elapsed_clock();
    let guard = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let (client, mut host, _, _) = connected_with_factory(
        Arc::new(LiveFactory {
            clock: clock.clone(),
            guard: guard.clone(),
        }),
        Arc::new(FnHandler(
            |_, p, _| async move { HandlerOutcome::Payload(p) },
        )),
    )
    .await;
    // Let the owner's initial watchdog read finish before counting hot-path work.
    tokio::task::yield_now().await;
    let checks = guard.checks.load(Ordering::SeqCst);
    assert_eq!(
        checks, 3,
        "both establishment gates and the watchdog must read"
    );
    for _ in 0..10 {
        assert_eq!(
            client
                .conn
                .call("/test.Service/Echo", vec![7], 1000)
                .await
                .unwrap(),
            vec![7]
        );
    }
    // The response wakes the caller before the writer's post-record yield and
    // deadline check finish. Settle those before advancing the test clock.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(guard.checks.load(Ordering::SeqCst), checks);
    assert!(!host.is_closed());
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..100 {
        if guard.checks.load(Ordering::SeqCst) != checks {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        guard.checks.load(Ordering::SeqCst),
        checks + 1,
        "closed={} reason={:?}",
        host.is_closed(),
        host.host.terminal_reason()
    );
    guard.valid.store(false, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(1)).await;
    let mut closed = host.host.subscribe_close();
    timeout(Duration::from_secs(1), wait_closed(&mut closed))
        .await
        .unwrap();
    assert_eq!(guard.checks.load(Ordering::SeqCst), checks + 2);
    assert_eq!(
        host.pump.as_ref().unwrap().terminal.get(),
        Some(TransportFailure::Authentication)
    );
    assert_eq!(
        host.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn revoked_backpressured_partial_notification_is_aborted_not_delivered() {
    let (source, clock) = elapsed_clock();
    let guard = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let factory = Arc::new(LiveFactory {
        clock: clock.clone(),
        guard: guard.clone(),
    });
    let (client, mut host, gate, _) = connected_with_factory(
        factory,
        Arc::new(FnHandler(
            |_, p, _| async move { HandlerOutcome::Payload(p) },
        )),
    )
    .await;
    gate.armed.store(true, Ordering::SeqCst);
    host.host.notify(vec![8; 200_000]).await.unwrap();
    gate.entered.acquire().await.unwrap().forget();
    guard.valid.store(false, Ordering::SeqCst);
    source.0.store(1000, Ordering::SeqCst);
    clock.wake(); // Watchdog withdrawal must abort even without a carrier wake.
    let mut closed = host.host.subscribe_close();
    wait_closed(&mut closed).await;
    assert_eq!(
        host.shutdown_transport(Duration::from_secs(1))
            .await
            .unwrap(),
        TransportShutdown::Complete
    );
    assert_eq!(client.conn.next_notification().await, None);
    assert_eq!(
        gate.records.load(Ordering::SeqCst),
        2,
        "no following record was retried after withdrawal"
    );
    client.close().await;
}

struct ReadSideEffect {
    release: Arc<Semaphore>,
    flushes: Arc<AtomicUsize>,
}
impl RecordReader for ReadSideEffect {
    async fn read_record(&mut self, _: usize) -> Result<Vec<u8>, Error> {
        self.release.acquire().await.unwrap().forget();
        self.flushes.fetch_add(1, Ordering::SeqCst); // e.g. a queued automatic Pong
        Ok(vec![7])
    }
}

#[tokio::test(start_paused = true)]
async fn suspended_raw_reader_cannot_flush_a_buffered_control_write_on_repoll() {
    let (_, clock) = elapsed_clock();
    let (conn, _out) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let peer = Peer::Client(conn.clone());
    let release = Arc::new(Semaphore::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let mut reader = ReadSideEffect {
        release: release.clone(),
        flushes: flushes.clone(),
    };
    let mut read = Box::pin(read_checked(
        &mut reader,
        MAX_CIPHERTEXT,
        &clock,
        elapsed_now(&clock) + Duration::from_secs(1),
        Some(&peer),
        &None,
    ));
    assert!(futures_util::poll!(&mut read).is_pending());
    conn.suspend();
    release.add_permits(1);
    assert!(matches!(read.await, Err(Error::Closed)));
    assert_eq!(flushes.load(Ordering::SeqCst), 0);
    conn.on_transport_lost().await;
}

#[tokio::test(start_paused = true)]
async fn split_reader_revalidates_queued_output_without_timer_driven_store_polling() {
    let (_, clock) = elapsed_clock();
    let (conn, _out) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let peer = Peer::Client(conn.clone());
    let release = Arc::new(Semaphore::new(0));
    let flushes = Arc::new(AtomicUsize::new(0));
    let guard = Arc::new(LiveGuard {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let authorization = Some(Arc::new(
        FreshAuthorization::new(guard.clone(), clock.clone()).unwrap(),
    ));
    let mut reader = ReadSideEffect {
        release: release.clone(),
        flushes: flushes.clone(),
    };
    let mut read = Box::pin(read_checked(
        &mut reader,
        MAX_CIPHERTEXT,
        &clock,
        elapsed_now(&clock) + Duration::from_secs(1),
        Some(&peer),
        &authorization,
    ));
    assert!(futures_util::poll!(&mut read).is_pending());
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(futures_util::poll!(&mut read).is_pending());
    assert_eq!(guard.checks.load(Ordering::SeqCst), 1);
    guard.valid.store(false, Ordering::SeqCst);
    assert!(refresh_authorization(&authorization, &clock).await.is_err());
    release.add_permits(1);
    assert!(matches!(read.await, Err(Error::Authentication)));
    assert_eq!(guard.checks.load(Ordering::SeqCst), 2);
    assert_eq!(flushes.load(Ordering::SeqCst), 0);
    conn.on_transport_lost().await;
}

#[tokio::test]
async fn cancelled_transport_shutdown_retains_policy_workers_and_actual_carrier_joins() {
    let (client, _) = channels();
    let (source, clock) = elapsed_clock();
    let (_input, records) = mpsc::channel(1);
    let (output, _emitted) = mpsc::channel(1);
    let (conn, outbound) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let pool = PolicyJobs::new(1).unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let response = pool
        .spawn(move || {
            blocked.recv().unwrap();
        })
        .unwrap();
    let mut pump = spawn_pump(
        reader(records),
        QueueWriter {
            records: output,
            gate: Arc::new(Gate::default()),
        },
        PumpState {
            channel: client,
            receive: ReceiveState::default(),
            peer: Peer::Client(conn.clone()),
            outbound,
            limits: Limits::default(),
            end: elapsed_now(&clock) + Duration::from_secs(60),
            authorization: None,
            policy_jobs: Some(pool.clone()),
        },
    )
    .unwrap();
    let mut shutdown = Box::pin(pump.shutdown_transport(Duration::from_secs(1)));
    assert!(futures_util::poll!(&mut shutdown).is_pending());
    drop(shutdown);
    source.0.store(2000, Ordering::SeqCst);
    clock.wake();
    assert!(matches!(
        pump.shutdown_transport(Duration::from_secs(30))
            .await
            .unwrap(),
        TransportShutdown::ShutdownIncomplete { policy_jobs: 1, .. }
    ));
    release.send(()).unwrap();
    response.await.unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if pump.shutdown_transport(Duration::ZERO).await.unwrap() == TransportShutdown::Complete
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(conn.shutdown_report().transport_tasks, 0);
    assert!(conn.shutdown_report().transport_closed);
}

#[tokio::test]
async fn blocking_policy_panics_are_rethrown_to_a_live_waiter() {
    use futures_util::FutureExt;
    let pool = PolicyJobs::new(1).unwrap();
    let job = pool
        .spawn::<()>(|| {
            panic!("synthetic policy failure");
        })
        .unwrap();
    assert!(std::panic::AssertUnwindSafe(job)
        .catch_unwind()
        .await
        .is_err());
    timeout(Duration::from_secs(1), async {
        while pool.pending() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropped_policy_waiter_does_not_silently_dispose_a_worker_panic() {
    let pool = PolicyJobs::new(1).unwrap();
    let job = pool
        .spawn::<()>(|| {
            panic!("synthetic policy failure");
        })
        .unwrap();
    drop(job);
    timeout(Duration::from_secs(1), async {
        loop {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pool.pending())) {
                Err(_) => break,
                Ok(0) => panic!("worker panic was silently disposed"),
                Ok(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_poll_and_suspend_are_serialized_not_a_boolean_check_then_poll() {
    let clock = ElapsedClock::lifecycle_driven();
    let (conn, _out) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let (entered, observed) = oneshot::channel();
    let (release, blocked) = std::sync::mpsc::channel();
    let writes = Arc::new(AtomicUsize::new(0));
    let written = writes.clone();
    let peer = Peer::Client(conn.clone());
    let io = tokio::spawn(async move {
        // Test-only barrier holds a poll open so another OS thread attempts
        // suspend in the check/poll gap. Production raw polls must not block.
        let poll = async move {
            entered.send(()).unwrap();
            blocked.recv().unwrap();
            written.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        authorized_io(
            poll,
            &clock,
            elapsed_now(&clock) + Duration::from_secs(5),
            Some(&peer),
            &None,
        )
        .await
    });
    observed.await.unwrap();
    let (attempted, started) = std::sync::mpsc::channel();
    let (finished, completion) = std::sync::mpsc::channel();
    let suspend = conn.clone();
    let thread = std::thread::spawn(move || {
        attempted.send(()).unwrap();
        suspend.suspend();
        finished.send(()).unwrap();
    });
    started.recv().unwrap();
    let raced = completion.recv_timeout(Duration::from_millis(50)).is_ok();
    release.send(()).unwrap();
    io.await.unwrap().unwrap();
    thread.join().unwrap();
    assert!(
        !raced,
        "suspend completed while a raw carrier poll was still executing"
    );
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    let clock = conn.elapsed_clock();
    assert!(authorized_io(
        async {
            writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        &clock,
        elapsed_now(&clock) + Duration::from_secs(1),
        Some(&Peer::Client(conn.clone())),
        &None
    )
    .await
    .is_err());
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    conn.platform_wake().await;
}

#[tokio::test(start_paused = true)]
async fn join_ready_at_exact_deadline_is_preserved_not_discarded_and_repolled() {
    let (source, clock) = elapsed_clock();
    let deadline = clock.now() + Duration::from_secs(1);
    let mut task = tokio::spawn(async { 37u8 });
    while !task.is_finished() {
        tokio::task::yield_now().await;
    }
    // The selected Ready result crosses the elapsed cutoff in this same poll.
    // A strict post-poll I/O check would consume it, report timeout, and invite
    // an invalid second poll of the borrowed JoinHandle on a shutdown retry.
    let value = clock
        .timeout_until(deadline, async {
            let value = (&mut task).await;
            source.0.store(1000, Ordering::SeqCst);
            clock.wake();
            value
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(clock.now(), deadline);
    assert_eq!(value, 37);
}

#[tokio::test(start_paused = true)]
async fn core_retains_a_cancelled_consuming_close_and_its_actual_joins() {
    let (client, host, gate, _) = connected(Arc::new(FnHandler(|_, p, _| async {
        HandlerOutcome::Payload(p)
    })))
    .await;
    let runtime = host.host.clone();
    gate.armed.store(true, Ordering::SeqCst);
    host.host.notify(vec![8; 200_000]).await.unwrap();
    gate.entered.acquire().await.unwrap().forget();
    let mut close = Box::pin(host.close());
    assert!(futures_util::poll!(&mut close).is_pending());
    drop(close);
    for _ in 0..128 {
        tokio::task::yield_now().await;
    }
    let report = runtime.shutdown_report();
    assert_eq!(
        report.phase,
        syntra_runtime::ShutdownPhase::Complete,
        "{report:?}"
    );
    assert_eq!(report.transport_tasks, 0);
    assert!(report.transport_closed);
    assert!(gate.dropped.load(Ordering::SeqCst));
    client.close().await;
}

#[tokio::test(start_paused = true)]
async fn an_outer_attempt_budget_is_not_restarted_at_noise_entry() {
    let (source, clock) = elapsed_clock();
    let (client, server) = configs(Mode::Bootstrap);
    let attempt = EstablishmentBudget::new(clock.clone(), Duration::from_secs(10)).unwrap();
    source.0.store(9000, Ordering::SeqCst);
    clock.wake(); // carrier/TLS/Upgrade already spent nine seconds
    let (tx, mut peer) = mpsc::channel(8);
    let (back, records) = mpsc::channel(8);
    let mut dial = Box::pin(connect_records_with_budget(
        reader(records),
        QueueWriter {
            records: tx,
            gate: Arc::new(Gate::default()),
        },
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
        attempt,
    ));
    assert!(futures_util::poll!(&mut dial).is_pending());
    let (_, second) = respond(&server, &peer.try_recv().unwrap()).unwrap();
    back.send(second).await.unwrap();
    source.0.store(10000, Ordering::SeqCst);
    clock.wake();
    assert!(matches!(dial.await, Err(Error::Timeout)));
    assert!(
        peer.try_recv().is_err(),
        "expired outer attempt emitted hello under a fresh channel budget"
    );
}

mod establishment_regressions {
    use super::*;
    use std::task::Poll;

    fn hello(min_version: u32, max_version: u32) -> Vec<u8> {
        syntra_core::Frame {
            version: max_version,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::ClientHello {
                min_version,
                max_version,
                credential: vec![],
            })),
        }
        .encode_to_vec()
    }

    fn timed_out<T>(result: Poll<Result<T, Error>>) {
        assert!(matches!(result, Poll::Ready(Err(Error::Timeout))));
    }

    #[tokio::test(start_paused = true)]
    async fn each_transport_timer_enforces_its_own_inclusive_ceiling() {
        for (index, seconds) in [15, 5, 86_400, 86_400, 10, 86_400, 86_400]
            .into_iter()
            .enumerate()
        {
            let maximum = Duration::from_secs(seconds);
            for (value, valid) in [
                (Duration::ZERO, false),
                (Duration::from_nanos(1), true),
                (maximum, true),
                (maximum + Duration::from_nanos(1), false),
            ] {
                let mut limits = Limits::default();
                let timer = match index {
                    0 => &mut limits.attempt_timeout,
                    1 => &mut limits.channel_timeout,
                    2 => &mut limits.record_timeout,
                    3 => &mut limits.frame_timeout,
                    4 => &mut limits.write_timeout,
                    5 => &mut limits.close_timeout,
                    _ => &mut limits.lifetime,
                };
                *timer = value;
                assert_eq!(limits.validate(&ConnectionConfig::default()).is_ok(), valid);
            }
        }
        for (duration, valid) in [
            (Duration::ZERO, false),
            (Duration::from_nanos(1), true),
            (Duration::from_secs(15), true),
            (Duration::from_secs(15) + Duration::from_nanos(1), false),
        ] {
            assert_eq!(
                EstablishmentBudget::new(default_elapsed_clock(), duration).is_ok(),
                valid
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn client_m2_does_not_renew_the_first_hello_output_deadline() {
        let (source, clock) = elapsed_clock();
        let (client, server) = configs(Mode::Returning);
        let (output, mut emitted) = mpsc::channel(8);
        let (input, incoming) = mpsc::channel(8);
        let gate = Arc::new(Gate::default());
        gate.armed.store(true, Ordering::SeqCst);
        let mut dial = Box::pin(connect_records_with_clock(
            reader(incoming),
            QueueWriter {
                records: output,
                gate: gate.clone(),
            },
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
            clock.clone(),
        ));
        assert!(futures_util::poll!(&mut dial).is_pending());
        let (_, second) = respond(&server, &emitted.try_recv().unwrap()).unwrap();
        source.0.store(4900, Ordering::SeqCst);
        input.send(second).await.unwrap();
        assert!(futures_util::poll!(&mut dial).is_pending());
        assert_eq!(gate.entered.available_permits(), 1);
        source.0.store(4999, Ordering::SeqCst);
        assert!(futures_util::poll!(&mut dial).is_pending());
        source.0.store(5000, Ordering::SeqCst);
        clock.wake();
        timed_out(futures_util::poll!(&mut dial));
        assert!(emitted.try_recv().is_err(), "expired hello was not emitted");
        assert!(gate.dropped.load(Ordering::SeqCst));
    }

    struct PreparingFactory {
        clock: ElapsedClock,
        source: Arc<ElapsedSource>,
        calls: Arc<AtomicUsize>,
        complete_at: Option<u64>,
    }
    impl AuthenticatorFactory for PreparingFactory {
        fn elapsed_clock(&self) -> ElapsedClock {
            self.clock.clone()
        }
        fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(at) = self.complete_at {
                self.source.0.store(at, Ordering::SeqCst);
            }
            Ok(Arc::new(AllowAnonymous))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn responder_core_budget_starts_at_m2_output_not_hello_factory_or_ready() {
        // Stall first hello, exhaust the timer in factory preparation, or stall
        // ready output after hello and preparation have consumed most of it.
        for phase in 0..3 {
            let (source, clock) = elapsed_clock();
            let (client, server) = configs(Mode::Bootstrap);
            let (handshake, first) = ClientHandshake::start(client).unwrap();
            let (input, incoming) = mpsc::channel(8);
            let (output, mut emitted) = mpsc::channel(8);
            input.send(first).await.unwrap();
            let gate = Arc::new(Gate::default());
            gate.armed.store(phase == 2, Ordering::SeqCst);
            let calls = Arc::new(AtomicUsize::new(0));
            let mut accept = Box::pin(accept_records(
                reader(incoming),
                QueueWriter {
                    records: output,
                    gate: gate.clone(),
                },
                &server,
                Arc::new(PreparingFactory {
                    clock: clock.clone(),
                    source: source.clone(),
                    calls: calls.clone(),
                    complete_at: match phase {
                        1 => Some(100),
                        2 => Some(80),
                        _ => None,
                    },
                }),
                Arc::new(FnHandler(
                    |_, p, _| async move { HandlerOutcome::Payload(p) },
                )),
                ConnectionConfig {
                    handshake_timeout: Duration::from_millis(100),
                    ..Default::default()
                },
                Limits::default(),
            ));
            assert!(futures_util::poll!(&mut accept).is_pending());
            let mut client = handshake.finish(&emitted.try_recv().unwrap()).unwrap();
            if phase != 0 {
                source.0.store(50, Ordering::SeqCst);
                input
                    .send(
                        client
                            .encrypt(&frame_plaintext(&hello(1, 1)).unwrap())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            }
            if phase == 1 {
                timed_out(futures_util::poll!(&mut accept));
            } else {
                assert!(futures_util::poll!(&mut accept).is_pending());
                if phase == 2 {
                    for _ in 0..64 {
                        if gate.entered.available_permits() != 0 {
                            break;
                        }
                        tokio::task::yield_now().await;
                        assert!(futures_util::poll!(&mut accept).is_pending());
                    }
                    assert_eq!(gate.entered.available_permits(), 1);
                }
                source.0.store(99, Ordering::SeqCst);
                assert!(futures_util::poll!(&mut accept).is_pending());
                source.0.store(100, Ordering::SeqCst);
                clock.wake();
                timed_out(futures_util::poll!(&mut accept));
            }
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(phase != 0));
            assert!(
                emitted.try_recv().is_err(),
                "expired accept emitted no ready/error frame"
            );
            assert!(gate.dropped.load(Ordering::SeqCst));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn channel_age_includes_record_establishment_on_both_sides() {
        // Client: waiting for M2 consumes half the channel lifetime, not zero.
        let (source, clock) = elapsed_clock();
        let (client, server) = configs(Mode::Bootstrap);
        let (output, mut emitted) = mpsc::channel(8);
        let (input, incoming) = mpsc::channel(8);
        let limits = Limits {
            lifetime: Duration::from_millis(100),
            ..Default::default()
        };
        let mut dial = Box::pin(connect_records_with_clock(
            reader(incoming),
            QueueWriter {
                records: output,
                gate: Arc::new(Gate::default()),
            },
            client,
            vec![],
            ConnectionConfig::default(),
            limits.clone(),
            clock.clone(),
        ));
        assert!(futures_util::poll!(&mut dial).is_pending());
        let (mut channel, second) = respond(&server, &emitted.try_recv().unwrap()).unwrap();
        source.0.store(50, Ordering::SeqCst);
        input.send(second).await.unwrap();
        assert!(futures_util::poll!(&mut dial).is_pending());
        channel.decrypt(&emitted.try_recv().unwrap()).unwrap();
        input
            .send(
                channel
                    .encrypt(&frame_plaintext(&ready_bytes()).unwrap())
                    .unwrap(),
            )
            .await
            .unwrap();
        source.0.store(100, Ordering::SeqCst);
        clock.wake();
        timed_out(futures_util::poll!(&mut dial));

        // Responder: waiting for M1 is also part of establishment/channel age.
        let (source, clock) = elapsed_clock();
        let (client, server) = configs(Mode::Returning);
        let (handshake, first) = ClientHandshake::start(client).unwrap();
        let (input, incoming) = mpsc::channel(8);
        let (output, mut emitted) = mpsc::channel(8);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut accept = Box::pin(accept_records(
            reader(incoming),
            QueueWriter {
                records: output,
                gate: Arc::new(Gate::default()),
            },
            &server,
            Arc::new(ClockFactory(clock.clone(), calls.clone())),
            Arc::new(FnHandler(
                |_, p, _| async move { HandlerOutcome::Payload(p) },
            )),
            ConnectionConfig::default(),
            limits,
        ));
        assert!(futures_util::poll!(&mut accept).is_pending());
        source.0.store(50, Ordering::SeqCst);
        input.send(first).await.unwrap();
        assert!(futures_util::poll!(&mut accept).is_pending());
        let mut channel = handshake.finish(&emitted.try_recv().unwrap()).unwrap();
        input
            .send(
                channel
                    .encrypt(&frame_plaintext(&hello(1, 1)).unwrap())
                    .unwrap(),
            )
            .await
            .unwrap();
        source.0.store(100, Ordering::SeqCst);
        clock.wake();
        timed_out(futures_util::poll!(&mut accept));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(emitted.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn local_first_envelope_causes_are_typed_sanitized_and_never_sent_to_the_peer() {
        for mode in [Mode::Bootstrap, Mode::Returning] {
            for (frame, expected, expected_auth_calls) in [
                (hello(2, 2), ErrorCode::Unimplemented, 1),
                (
                    vec![0x08, 0x01, 0x92, 0x01, 0x00],
                    ErrorCode::Unimplemented,
                    0,
                ),
                (vec![0x80], ErrorCode::InvalidArgument, 0),
            ] {
                let (client, server) = configs(mode);
                let (handshake, first) = ClientHandshake::start(client).unwrap();
                let (input, incoming) = mpsc::channel(8);
                let (output, mut emitted) = mpsc::channel(8);
                input.send(first).await.unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let dispatches = Arc::new(AtomicUsize::new(0));
                let effects = dispatches.clone();
                let mut accept = Box::pin(accept_records(
                    reader(incoming),
                    QueueWriter {
                        records: output,
                        gate: Arc::new(Gate::default()),
                    },
                    &server,
                    Arc::new(ClockFactory(default_elapsed_clock(), calls.clone())),
                    Arc::new(FnHandler(move |_, p, _| {
                        effects.fetch_add(1, Ordering::SeqCst);
                        async move { HandlerOutcome::Payload(p) }
                    })),
                    ConnectionConfig::default(),
                    Limits::default(),
                ));
                assert!(futures_util::poll!(&mut accept).is_pending());
                let mut client = handshake.finish(&emitted.try_recv().unwrap()).unwrap();
                input
                    .send(client.encrypt(&frame_plaintext(&frame).unwrap()).unwrap())
                    .await
                    .unwrap();
                let error = match accept.await {
                    Err(error) => error,
                    Ok(_) => panic!("invalid first envelope accepted"),
                };
                assert!(matches!(error, Error::LocalProtocol(code) if code == expected));
                assert!(!format!("{error:?} {error}").contains("private-credential"));
                assert_eq!(calls.load(Ordering::SeqCst), expected_auth_calls);
                assert_eq!(dispatches.load(Ordering::SeqCst), 0);
                assert!(matches!(
                    reader(emitted).read_record(MAX_CIPHERTEXT).await,
                    Err(Error::Closed)
                ));
            }
        }
    }

    #[test]
    fn local_status_mapping_keeps_authentication_distinct_and_discards_diagnostics() {
        for code in [
            ErrorCode::Unimplemented,
            ErrorCode::InvalidArgument,
            ErrorCode::Unauthenticated,
            ErrorCode::PermissionDenied,
        ] {
            let error = runtime_error(SyntraError::Protocol {
                code,
                message: "sensitive dependency diagnostic".into(),
            });
            assert!(matches!(error, Error::LocalProtocol(value) if value == code));
            assert!(!format!("{error:?} {error}").contains("sensitive"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn kernel_clock_bridge_retains_the_outer_origin_and_runtime_continuity() {
        let (source, clock) = elapsed_clock();
        let budget = EstablishmentBudget::new(clock.clone(), Duration::from_secs(15)).unwrap();
        let kernel_clock = budget.channel_clock.clone();
        let (client, server) = configs(Mode::Bootstrap);
        source.0.store(5, Ordering::SeqCst);
        let (handshake, first) =
            ClientHandshake::start_with_clock(client, kernel_clock.clone()).unwrap();
        let (_, second) = respond(&server, &first).unwrap();
        source.0.store(20, Ordering::SeqCst);
        let mut channel = handshake.finish(&second).unwrap();
        assert_eq!(kernel_clock.age(), Duration::from_millis(20));
        clock.invalidate();
        assert!(matches!(
            channel.encrypt(b"data"),
            Err(syntra_core::secure_channel::Error::Limit)
        ));
        assert_eq!(kernel_clock.age(), syntra_core::secure_channel::MAX_AGE);
    }

    struct DelayedFrameWriter(QueueWriter);
    impl RecordWriter for DelayedFrameWriter {
        async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
            if self.0.gate.armed.load(Ordering::SeqCst)
                && self.0.gate.records.load(Ordering::SeqCst) == 0
            {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            self.0.write_record(bytes).await
        }
        async fn shutdown(&mut self) -> Result<(), Error> {
            self.0.shutdown().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn whole_frame_output_expires_at_ten_seconds_not_ten_seconds_per_record() {
        let (client_config, server_config) = configs(Mode::Bootstrap);
        let (to_host, host_records) = mpsc::channel(8);
        let (to_client, client_records) = mpsc::channel(8);
        let gate = Arc::new(Gate::default());
        let (client, host) = tokio::join!(
            connect_records(
                reader(client_records),
                QueueWriter {
                    records: to_host,
                    gate: Arc::new(Gate::default())
                },
                client_config,
                vec![],
                ConnectionConfig::default(),
                Limits::default(),
            ),
            accept_records(
                reader(host_records),
                DelayedFrameWriter(QueueWriter {
                    records: to_client,
                    gate: gate.clone()
                }),
                &server_config,
                anonymous(),
                Arc::new(FnHandler(
                    |_, p, _| async move { HandlerOutcome::Payload(p) }
                )),
                ConnectionConfig::default(),
                Limits::default(),
            )
        );
        let client = client.unwrap();
        let host = host.unwrap();
        let started = Instant::now();
        gate.armed.store(true, Ordering::SeqCst);
        host.host.notify(vec![42; 200_000]).await.unwrap();
        gate.entered.acquire().await.unwrap().forget();
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        tokio::time::advance(Duration::from_millis(7999)).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert!(!host.is_closed());
        assert!(!gate.dropped.load(Ordering::SeqCst));
        tokio::time::advance(Duration::from_millis(1)).await;
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(host.is_closed());
        assert!(gate.dropped.load(Ordering::SeqCst));
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert_eq!(client.conn.next_notification().await, None);
        host.close().await;
        client.close().await;
    }
}
