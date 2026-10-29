//! Carrier-neutral bounded SC1 pump. Socket ownership stays in carrier modules.
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use syntra_core::{
    decode_frame, proto::frame::Body, ConnectionState, SyntraError, ValidationContext,
};
use syntra_runtime::{AuthError, Authenticator, ConnectionConfig, Handler, Host, Initiator};
use syntra_secure_channel::{
    frame_plaintext, respond, Channel, ClientConfig, ClientHandshake, FrameDecoder, ServerConfig,
    VerifiedIdentity, MAX_CIPHERTEXT, MAX_PLAINTEXT, MAX_WRAPPER,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};
use tracing::{debug, warn};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Channel(#[from] syntra_secure_channel::Error),
    #[error("SC1 I/O failed")]
    Io(#[from] std::io::Error),
    #[error("SC1 carrier framing rejected")]
    Framing,
    #[error("SC1 operation timed out")]
    Timeout,
    #[error("SC1 authentication rejected")]
    Authentication,
    #[error("SC1 runtime handshake rejected")]
    Runtime,
    #[error("SC1 configuration rejected")]
    Configuration,
    #[error("SC1 connection closed")]
    Closed,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub attempt_timeout: Duration,
    pub channel_timeout: Duration,
    /// Includes idle time before the next record; bounded silent connections.
    pub record_timeout: Duration,
    pub frame_timeout: Duration,
    pub write_timeout: Duration,
    pub close_timeout: Duration,
    pub lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(15),
            channel_timeout: Duration::from_secs(5),
            record_timeout: Duration::from_secs(30),
            frame_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(1),
            lifetime: Duration::from_secs(86_400),
        }
    }
}
impl Limits {
    pub fn validate(&self, runtime: &ConnectionConfig) -> Result<(), Error> {
        let durations = [
            self.attempt_timeout,
            self.channel_timeout,
            self.record_timeout,
            self.frame_timeout,
            self.write_timeout,
            self.close_timeout,
            self.lifetime,
        ];
        if durations
            .iter()
            .any(|d| d.is_zero() || *d > Duration::from_secs(86_400))
            || runtime.writer_capacity == 0
            || runtime.writer_capacity > 1024
            || runtime.notification_capacity == 0
            || runtime.notification_capacity > 1024
            || runtime.max_outstanding == 0
            || runtime.max_outstanding > 1024
            || [
                runtime.handshake_timeout,
                runtime.default_timeout,
                runtime.max_rpc_timeout,
            ]
            .iter()
            .any(|d| d.is_zero() || *d > Duration::from_secs(86_400))
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Called only after authenticated client data reconstructs a valid first hello.
/// Returning authorization must re-check current enrollment policy here. A factory
/// can capture the private-constructed identity in an Authenticator wrapper.
pub trait AuthenticatorFactory: Send + Sync {
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError>;
}
impl<F> AuthenticatorFactory for F
where
    F: Fn(&VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> + Send + Sync,
{
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        self(identity)
    }
}

pub trait RecordReader: Send + 'static {
    fn read_record(
        &mut self,
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send;
}
pub trait RecordWriter: Send + 'static {
    /// Complete one retained ciphertext, including partial writes, or return a fatal error.
    fn write_record(&mut self, bytes: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
    fn shutdown(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
}

pub struct ClientHandle {
    pub conn: Initiator,
    pub connection_id: String,
    pub version: u32,
    pump: Option<Pump>,
}
impl ClientHandle {
    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }
    pub async fn close(mut self) {
        if let Some(pump) = self.pump.take() {
            pump.close().await;
        }
    }
    /// Stop runtime admission and flush all admitted carrier output within one grace.
    pub async fn close_gracefully(mut self, grace: Duration) -> Result<(), Error> {
        self.pump
            .take()
            .ok_or(Error::Closed)?
            .close_gracefully(grace)
            .await
    }
}

pub struct HostHandle {
    pub host: Arc<Host>,
    pub identity: VerifiedIdentity,
    pump: Option<Pump>,
}
impl HostHandle {
    pub fn is_closed(&self) -> bool {
        self.host.is_closed()
    }
    pub async fn close(mut self) {
        if let Some(pump) = self.pump.take() {
            pump.close().await;
        }
    }
    /// Stop runtime admission and flush terminal results, including a frame already
    /// dequeued by the pump. Failure or grace expiry aborts unfinished output.
    pub async fn close_gracefully(mut self, grace: Duration) -> Result<(), Error> {
        self.pump
            .take()
            .ok_or(Error::Closed)?
            .close_gracefully(grace)
            .await
    }
}

/// Dropping even a partially constructed connect future signals the owner task.
/// The owner stops both children, settles runtime callers, and drops the carrier.
struct GracefulClose {
    deadline: Instant,
    done: oneshot::Sender<Result<(), Error>>,
}

struct Pump {
    stop: Option<oneshot::Sender<()>>,
    graceful: mpsc::Sender<GracefulClose>,
    task: Option<tokio::task::JoinHandle<()>>,
    grace: Duration,
}
impl Pump {
    async fn close_gracefully(self, grace: Duration) -> Result<(), Error> {
        if grace.is_zero() || grace > Duration::from_secs(86_400) {
            return Err(Error::Configuration);
        }
        let deadline = Instant::now() + grace;
        let (done, completed) = oneshot::channel();
        self.graceful
            .try_send(GracefulClose { deadline, done })
            .map_err(|_| Error::Closed)?;
        timeout_at(deadline, completed)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Closed)?
    }
    async fn close(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.task.take() {
            // The stop signal is sent before awaiting; the owner also finishes
            // teardown if this close future is cancelled while waiting.
            if timeout(self.grace, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}
impl Drop for Pump {
    fn drop(&mut self) {
        // Dropping the owning handle aborts the pump and closes the carrier.
        // Fixtures must retain handles for as long as the connection is live.
        debug!("sc1 pump dropped; signalling owner stop");
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

#[derive(Clone)]
enum Peer {
    Client(Initiator),
    Host(Arc<Host>),
}
impl Peer {
    async fn ingest(&self, bytes: &[u8]) {
        match self {
            Self::Client(c) => c.ingest(bytes).await,
            Self::Host(h) => h.ingest(bytes).await,
        }
    }
    async fn lost(&self) {
        match self {
            Self::Client(c) => c.on_transport_lost().await,
            Self::Host(h) => h.on_transport_lost().await,
        }
    }
    fn closed(&self) -> bool {
        match self {
            Self::Client(c) => c.is_closed(),
            Self::Host(h) => h.is_closed(),
        }
    }
    fn subscribe(&self) -> watch::Receiver<bool> {
        match self {
            Self::Client(c) => c.subscribe_close(),
            Self::Host(h) => h.subscribe_close(),
        }
    }
    async fn close_gracefully(&self, grace: Duration) {
        match self {
            Self::Client(c) => c.close_gracefully(grace).await,
            Self::Host(h) => h.close_gracefully(grace).await,
        }
    }
    fn ordinary_close(&self) -> bool {
        let reason = match self {
            Self::Client(c) => c.terminal_reason(),
            Self::Host(h) => h.terminal_reason(),
        };
        matches!(reason, Some(SyntraError::Closed(_)))
    }
}

/// Observe both the sticky initial value and later notifications. Subscribe before
/// inspecting the peer so a close between inspection and the first poll is retained.
async fn wait_closed(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
}

/// Outcome of the first pump task to finish, as observed by the owner.
type TerminalTask = Option<Result<(Direction, Result<(), Error>), tokio::task::JoinError>>;
type PumpTasks = JoinSet<(Direction, Result<(), Error>)>;

#[derive(Default)]
struct ReceiveState {
    decoder: FrameDecoder,
    frame_deadline: Option<Instant>,
}

impl From<FrameDecoder> for ReceiveState {
    fn from(decoder: FrameDecoder) -> Self {
        Self {
            decoder,
            frame_deadline: None,
        }
    }
}

async fn read_frames<R, F, Fut>(
    mut reader: R,
    channel: Arc<Mutex<Channel>>,
    receive: ReceiveState,
    end: Instant,
    limits: Limits,
    mut ingest: F,
) -> Result<(), Error>
where
    R: RecordReader,
    F: FnMut(Zeroizing<Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<(), Error>>,
{
    let ReceiveState {
        mut decoder,
        frame_deadline,
    } = receive;
    let mut frame_deadline = frame_deadline.or_else(|| {
        decoder
            .is_partial()
            .then(|| Instant::now() + limits.frame_timeout)
    });
    loop {
        let deadline = (Instant::now() + limits.record_timeout)
            .min(frame_deadline.unwrap_or(end))
            .min(end);
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let ciphertext = timeout_at(deadline, reader.read_record(MAX_CIPHERTEXT))
            .await
            .map_err(|_| Error::Timeout)??;
        let plaintext = channel
            .lock()
            .map_err(|_| Error::Closed)?
            .decrypt(&ciphertext)?;
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        let frames = decoder.push(&plaintext)?;
        // A new partial frame starts at parsing, before any backpressured delivery.
        // Completion of an earlier frame in this batch permits a new assembly budget.
        if !decoder.is_partial() {
            frame_deadline = None;
        } else if frame_deadline.is_none() || !frames.is_empty() {
            frame_deadline = Some(Instant::now() + limits.frame_timeout);
        }
        let delivery_deadline = (Instant::now() + limits.write_timeout)
            .min(frame_deadline.unwrap_or(end))
            .min(end);
        for frame in frames {
            if Instant::now() >= delivery_deadline {
                return Err(Error::Timeout);
            }
            timeout_at(delivery_deadline, ingest(Zeroizing::new(frame)))
                .await
                .map_err(|_| Error::Timeout)??;
            if Instant::now() >= delivery_deadline {
                return Err(Error::Timeout);
            }
        }
        tokio::task::yield_now().await;
    }
}

async fn drain_gracefully(
    peer: &Peer,
    tasks: &mut PumpTasks,
    reader_abort: &tokio::task::AbortHandle,
    drain: &watch::Sender<Option<Instant>>,
    closed: &mut watch::Receiver<bool>,
    stopped: &mut oneshot::Receiver<()>,
    deadline: Instant,
) -> Result<(), Error> {
    if peer.closed() {
        return Err(Error::Closed);
    }
    let closing = peer.close_gracefully(deadline.saturating_duration_since(Instant::now()));
    tokio::pin!(closing);
    let mut runtime_done = false;
    let mut close_observed = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut *stopped => return Err(Error::Closed),
            _ = tokio::time::sleep_until(deadline) => return Err(Error::Timeout),
            _ = wait_closed(closed), if !close_observed => {
                if !peer.ordinary_close() { return Err(Error::Closed); }
                close_observed = true;
                reader_abort.abort();
            }
            result = tasks.join_next() => match result {
                Some(Ok((Direction::Write, result))) => return result,
                Some(Ok((Direction::Read, Err(Error::Closed)))) if peer.closed() && peer.ordinary_close() => {},
                Some(Ok((Direction::Read, result))) => return result.and(Err(Error::Closed)),
                Some(Err(error)) if error.is_cancelled() && close_observed => {},
                _ => return Err(Error::Closed),
            },
            _ = &mut closing, if !runtime_done => {
                if !peer.ordinary_close() { return Err(Error::Closed); }
                runtime_done = true;
                close_observed = true;
                reader_abort.abort();
                drain.send(Some(deadline)).map_err(|_| Error::Closed)?;
            }
        }
    }
}

fn spawn_pump<R: RecordReader, W: RecordWriter>(
    reader: R,
    mut writer: W,
    channel: Channel,
    receive: ReceiveState,
    peer: Peer,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    limits: Limits,
    end: Instant,
) -> Pump {
    let (stop, mut stopped) = oneshot::channel();
    let (graceful, mut graceful_rx) = mpsc::channel::<GracefulClose>(1);
    let (drain, mut draining) = watch::channel::<Option<Instant>>(None);
    let mut closed = peer.subscribe();
    let channel = Arc::new(Mutex::new(channel));
    let grace = limits.close_timeout + Duration::from_secs(1);
    let task = tokio::spawn(async move {
        if *closed.borrow() || peer.closed() {
            peer.lost().await;
            return;
        }
        let mut tasks = JoinSet::new();
        let read_channel = channel.clone();
        let read_peer = peer.clone();
        let read_limits = limits.clone();
        let reader_abort = tasks.spawn(async move {
            let result = read_frames(
                reader,
                read_channel,
                receive,
                end,
                read_limits,
                move |frame| {
                    let peer = read_peer.clone();
                    async move {
                        peer.ingest(&frame).await;
                        if peer.closed() {
                            Err(Error::Closed)
                        } else {
                            Ok(())
                        }
                    }
                },
            )
            .await;
            (Direction::Read, result)
        });
        let write_channel = channel.clone();
        let write_peer = peer.clone();
        tasks.spawn(async move {
            let result = async {
                let mut drain_deadline = None;
                loop {
                    if let Some(deadline) = *draining.borrow_and_update() {
                        drain_deadline = Some(deadline);
                        outbound.close();
                    }
                    let frame = tokio::select! {
                        biased;
                        _ = draining.changed(), if drain_deadline.is_none() => continue,
                        frame = outbound.recv() => match frame { Some(frame) => frame, None => break },
                    };
                    // Gate exactly once before framing/encryption. A selected
                    // frame's record sequence must finish in order or abort;
                    // never re-gate/rewrite after a nonce has been consumed.
                    let frame = match &write_peer {
                        Peer::Client(client) => match client.prepare_outbound(frame) {
                            Some(frame) => frame,
                            None => continue,
                        },
                        Peer::Host(_) => frame,
                    };
                    let frame = Zeroizing::new(frame);
                    let deadline = (Instant::now() + limits.write_timeout).min(end).min(drain_deadline.unwrap_or(end));
                    let plaintext = frame_plaintext(&frame)?;
                    // One frame's complete record sequence is owned until completion or abort.
                    timeout_at(deadline, async {
                        for chunk in plaintext.chunks(MAX_PLAINTEXT) {
                            if Instant::now() >= deadline { return Err(Error::Timeout); }
                            let ciphertext = write_channel.lock().map_err(|_| Error::Closed)?.encrypt(chunk)?;
                            writer.write_record(&ciphertext).await?;
                            if Instant::now() >= deadline { return Err(Error::Timeout); }
                            tokio::task::yield_now().await;
                        }
                        Ok::<(), Error>(())
                    }).await.map_err(|_| Error::Timeout)??;
                }
                Ok::<(), Error>(())
            }.await;
            if let Ok(mut channel) = write_channel.lock() { channel.close(); }
            if result.is_ok() {
                let deadline = (Instant::now() + limits.close_timeout).min(end);
                let shutdown = timeout_at(deadline, writer.shutdown()).await.map_err(|_| Error::Timeout).and_then(|result| result);
                return (Direction::Write, shutdown);
            }
            (Direction::Write, result)
        });
        let mut graceful_done = None;
        let mut terminal_task: TerminalTask = None;
        tokio::select! {
            biased;
            _ = &mut stopped => debug!("sc1 pump owner stopped by close signal"),
            _ = wait_closed(&mut closed) => debug!("sc1 pump owner stopped by peer closed"),
            _ = tokio::time::sleep_until(end) => debug!("sc1 pump owner stopped by lifetime end"),
            result = tasks.join_next() => {
                terminal_task = result;
            }
            request = graceful_rx.recv() => if let Some(request) = request {
                let result = drain_gracefully(&peer, &mut tasks, &reader_abort, &drain,
                    &mut closed, &mut stopped, request.deadline.min(end)).await;
                graceful_done = Some((request.done, result));
            },
        }
        if terminal_task.is_none() {
            debug!(
                graceful = graceful_done.is_some(),
                "sc1 pump owner exited without terminal task"
            );
        }
        if let Some(Ok((direction, result))) = terminal_task {
            match result {
                Ok(()) => debug!(?direction, "sc1 pump task ended with clean shutdown"),
                Err(ref error) => warn!(?direction, error = ?error, "sc1 pump task ended"),
            }
        }
        // No cipher state survives either direction's failure or cancelled output.
        if let Ok(mut channel) = channel.lock() {
            channel.close();
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        peer.lost().await;
        if let Some((done, result)) = graceful_done {
            let _ = done.send(result);
        }
    });
    Pump {
        stop: Some(stop),
        graceful,
        task: Some(task),
        grace,
    }
}

pub async fn connect_records<R: RecordReader, W: RecordWriter>(
    mut reader: R,
    mut writer: W,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let attempt = Instant::now() + limits.attempt_timeout;
    let channel_deadline = attempt.min(Instant::now() + limits.channel_timeout);
    let (channel, end) = timeout_at(channel_deadline, async {
        let (handshake, first) = ClientHandshake::start(security)?;
        writer.write_record(&first).await?;
        let second = reader.read_record(48).await?;
        let channel = handshake.finish(&second)?;
        Ok::<_, Error>((channel, Instant::now() + limits.lifetime))
    })
    .await
    .map_err(|_| Error::Timeout)??;
    if Instant::now() >= channel_deadline {
        return Err(Error::Timeout);
    }
    let core_deadline = attempt
        .min(end)
        .min(Instant::now() + runtime.handshake_timeout);
    let (conn, mut outbound) = Initiator::new(runtime);
    let mut channel = channel;
    let mut receive = ReceiveState::default();
    // Establishment I/O stays in the caller's future. In particular, do not
    // spawn an owner before ready: cancelling a partial dial must synchronously
    // release both carrier halves before a lifecycle replacement can begin.
    let id = timeout_at(core_deadline, async {
        let handshake = conn.handshake(credential);
        tokio::pin!(handshake);
        let mut hello_sent = false;
        loop {
            let deadline = core_deadline
                .min(Instant::now() + limits.record_timeout)
                .min(receive.frame_deadline.unwrap_or(core_deadline));
            tokio::select! {
                biased;
                result = &mut handshake => break result.map_err(runtime_error),
                hello = outbound.recv(), if !hello_sent => {
                    let hello = Zeroizing::new(hello.ok_or(Error::Closed)?);
                    let plaintext = frame_plaintext(&hello)?;
                    let write_deadline = core_deadline.min(Instant::now() + limits.write_timeout);
                    for chunk in plaintext.chunks(MAX_PLAINTEXT) {
                        let encrypted = channel.encrypt(chunk)?;
                        timeout_at(write_deadline, writer.write_record(&encrypted))
                            .await.map_err(|_| Error::Timeout)??;
                    }
                    hello_sent = true;
                }
                record = timeout_at(deadline, reader.read_record(MAX_CIPHERTEXT)), if hello_sent => {
                    let record = record.map_err(|_| Error::Timeout)??;
                    if Instant::now() >= deadline { return Err(Error::Timeout); }
                    let plaintext = channel.decrypt(&record)?;
                    let frames = receive.decoder.push(&plaintext)?;
                    if !receive.decoder.is_partial() {
                        receive.frame_deadline = None;
                    } else if receive.frame_deadline.is_none() || !frames.is_empty() {
                        receive.frame_deadline = Some(Instant::now() + limits.frame_timeout);
                    }
                    // This body is outside the select futures: ready cannot
                    // cancel delivery midway through a decoded batch. Yielding
                    // in ingest preserves the iterator until its whole batch
                    // has been accounted for (unless establishment itself fails).
                    for frame in frames {
                        conn.ingest(&Zeroizing::new(frame)).await;
                    }
                }
            }
        }
    }).await.map_err(|_| Error::Timeout)??;
    if Instant::now() >= core_deadline {
        return Err(Error::Timeout);
    }
    let version = conn.negotiated_version().await.ok_or(Error::Runtime)?;
    let pump = spawn_pump(
        reader,
        writer,
        channel,
        receive,
        Peer::Client(conn.clone()),
        outbound,
        limits,
        end,
    );
    Ok(ClientHandle {
        conn,
        connection_id: id,
        version,
        pump: Some(pump),
    })
}

fn runtime_error(error: SyntraError) -> Error {
    match error.code() {
        syntra_core::ErrorCode::DeadlineExceeded => Error::Timeout,
        syntra_core::ErrorCode::Unavailable => Error::Closed,
        syntra_core::ErrorCode::Unauthenticated | syntra_core::ErrorCode::PermissionDenied => {
            Error::Authentication
        }
        _ => Error::Runtime,
    }
}

pub async fn accept_records<R: RecordReader, W: RecordWriter>(
    mut reader: R,
    mut writer: W,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error> {
    limits.validate(&runtime)?;
    let attempt = Instant::now() + limits.attempt_timeout;
    let channel_deadline = attempt.min(Instant::now() + limits.channel_timeout);
    let (channel, mut decoder, first_frame, end) = timeout_at(channel_deadline, async {
        let first = reader.read_record(MAX_WRAPPER).await?;
        let (mut channel, second) = respond(security, &first)?;
        let end = Instant::now() + limits.lifetime;
        let confirmation_deadline = channel_deadline.min(end);
        timeout_at(confirmation_deadline, writer.write_record(&second))
            .await
            .map_err(|_| Error::Timeout)??;
        let mut decoder = FrameDecoder::default();
        // Absolute confirmation deadline includes every partial record and frame.
        loop {
            if Instant::now() >= confirmation_deadline {
                return Err(Error::Timeout);
            }
            let record = timeout_at(confirmation_deadline, reader.read_record(MAX_CIPHERTEXT))
                .await
                .map_err(|_| Error::Timeout)??;
            let plaintext = channel.decrypt(&record)?;
            let mut frames = decoder.push(&plaintext)?;
            if !frames.is_empty() {
                // The first envelope must be hello, with no pipelined application data.
                if frames.len() != 1 || decoder.is_partial() {
                    return Err(Error::Framing);
                }
                break Ok::<_, Error>((channel, decoder, frames.remove(0), end));
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| Error::Timeout)??;
    if Instant::now() >= channel_deadline.min(end) {
        return Err(Error::Timeout);
    }
    let first_frame = Zeroizing::new(first_frame);
    let first = decode_frame(
        &first_frame,
        ValidationContext::pre_handshake(ConnectionState::Connected),
    )
    .map_err(|_| Error::Framing)?;
    if !matches!(first.body, Some(Body::Hello(_))) {
        return Err(Error::Framing);
    }
    let identity = channel.verified_identity().ok_or(Error::Authentication)?;
    if Instant::now() >= attempt.min(end) {
        return Err(Error::Timeout);
    }
    let auth = factory
        .create(&identity)
        .map_err(|_| Error::Authentication)?;
    if Instant::now() >= attempt.min(end) {
        return Err(Error::Timeout);
    }
    let (host, mut outbound) = Host::new(runtime, auth, handler);
    timeout_at(attempt.min(end), host.ingest(&first_frame))
        .await
        .map_err(|_| Error::Timeout)?;
    if host.is_closed() {
        return Err(Error::Authentication);
    }
    // Flush ready before transferring the carrier to background tasks. A
    // cancelled accept owns/drops its partial carrier just like a cancelled dial.
    let ready = timeout_at(attempt.min(end), outbound.recv())
        .await
        .map_err(|_| Error::Timeout)?
        .ok_or(Error::Closed)?;
    let plaintext = frame_plaintext(&Zeroizing::new(ready))?;
    let mut channel = channel;
    let deadline = attempt.min(end).min(Instant::now() + limits.write_timeout);
    for chunk in plaintext.chunks(MAX_PLAINTEXT) {
        let encrypted = channel.encrypt(chunk)?;
        timeout_at(deadline, writer.write_record(&encrypted))
            .await
            .map_err(|_| Error::Timeout)??;
    }
    if Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    let pump = spawn_pump(
        reader,
        writer,
        channel,
        std::mem::take(&mut decoder).into(),
        Peer::Host(host.clone()),
        outbound,
        limits,
        end,
    );
    Ok(HostHandle {
        host,
        identity,
        pump: Some(pump),
    })
}

#[cfg(test)]
mod tests;
