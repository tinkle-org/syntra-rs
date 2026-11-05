use super::{
    codec::{self, Head, Operation},
    Authority, OpenEnvelope, OriginPolicy, Route,
};
use crate::{Error, EstablishmentBudget, RecordReader, RecordWriter};
use std::{
    future::{poll_fn, Future},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::Poll,
    time::Duration,
};
use syntra_runtime::elapsed::ElapsedClock;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf},
    sync::{mpsc, oneshot, watch},
    time::Instant,
};

const EXCHANGE: Duration = Duration::from_secs(5);
const POLL: Duration = Duration::from_secs(30);
const HOLD: Duration = Duration::from_secs(25);
const GAP: Duration = Duration::from_secs(5);
const RECORD: Duration = Duration::from_secs(60);
const OUTPUT: Duration = Duration::from_secs(10);

struct State {
    clock: ElapsedClock,
    setup: Instant,
    lifetime: Instant,
    establishing: AtomicBool,
    closed: watch::Sender<bool>,
    gate: Mutex<()>,
    establishment: Mutex<Option<EstablishmentBudget>>,
    completion: Arc<crate::pump::EstablishmentCompletion>,
    // A protected registry may attach admission ownership. Every driver, record
    // half and selected response future shares it through actual I/O teardown,
    // even if its outer supervisor unwinds or its waiter is cancelled.
    retained: Mutex<Option<Arc<dyn Send + Sync>>>,
}

impl State {
    fn new(budget: EstablishmentBudget) -> Arc<Self> {
        let now = Instant::from_std(budget.clock.now());
        // Starting the candidate's channel budget at pair construction is
        // conservative: it never grants a second allowance to the D stream.
        let setup = budget
            .deadline
            .min(now.checked_add(EXCHANGE).unwrap_or(budget.deadline));
        let completion = budget.io.completion.clone();
        let registered = completion.restrict(setup);
        let state = Arc::new(Self {
            clock: budget.clock.clone(),
            setup,
            // The original attempt can already be up to fifteen seconds old.
            lifetime: budget
                .deadline
                .checked_add(Duration::from_secs(86_400 - 15))
                .unwrap_or(budget.deadline),
            establishing: AtomicBool::new(true),
            closed: watch::channel(false).0,
            gate: Mutex::new(()),
            establishment: Mutex::new(Some(budget)),
            completion,
            retained: Mutex::new(None),
        });
        if registered.is_err() {
            state.retire();
        }
        state
    }

    fn now(&self) -> Instant {
        Instant::from_std(self.clock.now())
    }
    fn cap(&self, at: Instant) -> Instant {
        let at = at.min(self.lifetime);
        if self.establishing.load(Ordering::Acquire) || self.completion.pending() {
            at.min(self.setup)
                .min(self.completion.deadline().unwrap_or_else(|_| self.now()))
        } else {
            at
        }
    }
    fn after(&self, duration: Duration) -> Instant {
        self.now()
            .checked_add(duration)
            .unwrap_or(self.lifetime)
            .min(self.lifetime)
    }
    fn retire(&self) {
        let _gate = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        self.closed.send_replace(true);
    }
    fn check(&self, at: Instant) -> Result<(), Error> {
        if !self.clock.is_continuous() || self.now() >= self.cap(at) {
            return Err(Error::Timeout);
        }
        if *self.closed.borrow() {
            return Err(Error::Closed);
        }
        Ok(())
    }

    async fn run<T>(
        &self,
        at: Instant,
        future: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        let mut guard = Guard {
            state: self,
            done: false,
        };
        self.check(at)?;
        let mut closed = self.closed.subscribe();
        if *closed.borrow_and_update() {
            return Err(Error::Closed);
        }
        tokio::pin!(future);
        loop {
            let cap = self.cap(at);
            let result = tokio::select! {
                biased;
                _ = closed.changed() => Err(Error::Closed),
                _ = self.clock.sleep_until(cap.into_std()) => {
                    // Releasing setup removes only that phase cap. Keep the
                    // *same pinned I/O future* and original exchange deadline;
                    // no selected bytes or HTTP operation are ever restarted.
                    if self.clock.is_continuous() && self.cap(at) > cap && self.now() < self.cap(at) {
                        continue;
                    }
                    Err(Error::Timeout)
                },
                value = &mut future => value,
            };
            if !self.clock.is_continuous() || self.now() >= self.cap(at) {
                return Err(Error::Timeout);
            }
            // Preserve an inner operation's precise local failure even though
            // its guard has already retired the shared association.
            let value = result?;
            self.check(at)?;
            guard.done = true;
            return Ok(value);
        }
    }
}

struct Guard<'a> {
    state: &'a State,
    done: bool,
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.state.retire();
        }
    }
}

/// Shared abort control. Aborting is sticky and wakes inline I/O in both halves.
/// Retain the server driver future through completion; this control spawns and
/// joins nothing. No handle can replace a stream or revive a retired pair.
#[derive(Clone)]
pub struct Control(Arc<State>);
impl Control {
    pub(super) fn retain(&self, owner: Arc<dyn Send + Sync>) -> Result<(), Error> {
        let _gate = self.0.gate.lock().map_err(|_| Error::Closed)?;
        self.0.check(self.0.setup)?;
        let mut retained = self.0.retained.lock().map_err(|_| Error::Closed)?;
        if retained.is_some() {
            return Err(Error::Configuration);
        }
        *retained = Some(owner);
        Ok(())
    }
    pub fn abort(&self) {
        self.0.retire();
    }
    pub fn is_retired(&self) -> bool {
        *self.0.closed.borrow()
    }

    /// Move the original single-owner attempt budget to a future protected
    /// driver, without restarting its clock or channel-age origin. At most one
    /// caller can take it. This does not finish setup, validate Noise or indicate
    /// readiness; the high-level candidate connection APIs own those steps.
    pub fn take_establishment_budget(&self) -> Result<EstablishmentBudget, Error> {
        self.0.check(self.0.setup)?;
        self.0
            .establishment
            .lock()
            .map_err(|_| Error::Closed)?
            .take()
            .ok_or(Error::Configuration)
    }

    /// End the raw adapter's setup deadline *only after* an external protected
    /// driver has validated Noise, hello/ready and current host policy. This is
    /// scheduling input, not readiness or TLS evidence. Until called, the shared
    /// original attempt/channel deadline bounds every operation on both streams.
    /// A required-recovery owner keeps that cap active until its acceptance; this
    /// call cannot release the owner's deferred phase or rebase any deadline.
    pub fn finish_setup(&self) -> Result<(), Error> {
        if let Err(error) = self.0.check(self.0.setup) {
            self.0.retire();
            return Err(error);
        }
        self.0.establishing.store(false, Ordering::Release);
        Ok(())
    }
}

struct Wire<S> {
    read: ReadHalf<S>,
    write: WriteHalf<S>,
}
impl<S: AsyncRead + AsyncWrite> Wire<S> {
    fn new(stream: S) -> Self {
        let (read, write) = io::split(stream);
        Self { read, write }
    }
}

// Every individual poll is deadline/retirement gated, including synchronous
// Ready loops. No read-ahead: header/body parsing cannot lose the next unit.
async fn read_some<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &State,
    at: Instant,
    bytes: &mut [u8],
) -> Result<usize, Error> {
    poll_fn(|cx| {
        let _gate = state.gate.lock().map_err(|_| Error::Closed)?;
        state.check(at)?;
        let mut buf = ReadBuf::new(bytes);
        match Pin::new(&mut *r).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                state.check(at)?;
                Poll::Ready(Ok(buf.filled().len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(e))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn read_exact<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &State,
    at: Instant,
    mut bytes: &mut [u8],
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let n = read_some(r, state, at, bytes).await?;
        if n == 0 {
            return Err(Error::Closed);
        }
        bytes = &mut bytes[n..];
    }
    Ok(())
}

async fn write<W: AsyncWrite + Unpin>(
    w: &mut W,
    state: &State,
    at: Instant,
    header: &[u8],
    body: &[u8],
) -> Result<(), Error> {
    write_bytes(w, state, at, header, body).await?;
    flush(w, state, at).await
}

async fn write_bytes<W: AsyncWrite + Unpin>(
    w: &mut W,
    state: &State,
    at: Instant,
    header: &[u8],
    body: &[u8],
) -> Result<(), Error> {
    for mut bytes in [header, body] {
        while !bytes.is_empty() {
            let n = poll_fn(|cx| {
                let _gate = state.gate.lock().map_err(|_| Error::Closed)?;
                state.check(at)?;
                let result = Pin::new(&mut *w).poll_write(cx, bytes).map_err(Error::Io);
                state.check(at)?;
                result
            })
            .await?;
            if n == 0 {
                return Err(Error::Closed);
            }
            bytes = &bytes[n..];
        }
    }
    Ok(())
}

async fn flush<W: AsyncWrite + Unpin>(w: &mut W, state: &State, at: Instant) -> Result<(), Error> {
    poll_fn(|cx| {
        let _gate = state.gate.lock().map_err(|_| Error::Closed)?;
        state.check(at)?;
        let result = Pin::new(&mut *w).poll_flush(cx).map_err(Error::Io);
        state.check(at)?;
        result
    })
    .await
}

async fn header<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &State,
    idle: Instant,
    exchange: Duration,
) -> Result<(Vec<u8>, Instant), Error> {
    let mut first = [0];
    state
        .run(idle, read_exact(r, state, idle, &mut first))
        .await?;
    let deadline = state.after(exchange);
    let assembly = state.after(EXCHANGE).min(deadline);
    let mut bytes = Vec::with_capacity(codec::MAX_HEADERS);
    bytes.push(first[0]);
    let mut line_start = 0;
    let mut fields = 0;
    state
        .run(assembly, async {
            loop {
                if bytes.len() == codec::MAX_HEADERS {
                    return Err(Error::Framing);
                }
                let mut b = [0];
                read_exact(r, state, assembly, &mut b).await?;
                bytes.push(b[0]);
                let limit = if line_start == 0 {
                    codec::MAX_START_LINE
                } else {
                    codec::MAX_FIELD_LINE
                };
                if bytes.len() - line_start > limit {
                    return Err(Error::Framing);
                }
                if bytes.ends_with(b"\r\n") {
                    if bytes.len() - line_start == 2 {
                        return Ok((bytes, deadline));
                    }
                    if line_start != 0 {
                        fields += 1;
                    }
                    if fields > codec::MAX_FIELDS {
                        return Err(Error::Framing);
                    }
                    line_start = bytes.len();
                } else if (b[0] == b'\n') || (bytes.len() >= 2 && bytes[bytes.len() - 2] == b'\r') {
                    return Err(Error::Framing);
                }
            }
        })
        .await
}

async fn body<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &State,
    at: Instant,
    len: usize,
    maximum: usize,
) -> Result<Vec<u8>, Error> {
    if len > maximum.min(codec::MAX_RECORD) {
        return Err(Error::Framing);
    }
    let mut bytes = vec![0; len];
    read_exact(r, state, at, &mut bytes).await?;
    Ok(bytes)
}

// A peer cannot legally send a second response before our next request. Reject
// immediately available surplus/EOF rather than silently accepting a 204 body.
// Later surplus is rejected as the next malformed header, without resync.
async fn response_end<R: AsyncRead + Unpin>(
    r: &mut R,
    state: &State,
    at: Instant,
    persistent: bool,
) -> Result<(), Error> {
    poll_fn(|cx| {
        let _gate = state.gate.lock().map_err(|_| Error::Closed)?;
        state.check(at)?;
        let mut scratch = [0];
        let mut buf = ReadBuf::new(&mut scratch);
        match Pin::new(&mut *r).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Io(e))),
            Poll::Ready(Ok(())) if buf.filled().is_empty() && !persistent => Poll::Ready(Ok(())),
            Poll::Ready(Ok(())) => Poll::Ready(Err(if buf.filled().is_empty() {
                Error::Closed
            } else {
                Error::Framing
            })),
        }
    })
    .await
}

// A second request (or EOF) before all response bytes are written is terminal.
// Once those bytes are written, the peer can lawfully send its next request even
// if local flush is still pending. Never consume that request as lookahead.
async fn no_pipeline<R: AsyncRead + Unpin, T>(
    r: &mut R,
    state: &State,
    at: Instant,
    future: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let mut scratch = [0];
    tokio::select! {
        biased;
        result = read_some(r, state, at, &mut scratch) => { result?; Err(Error::Framing) },
        result = future => result,
    }
}

async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    state: &State,
    at: Instant,
    op: Operation,
    route: Option<&Route>,
    counter: Option<u64>,
    bytes: &[u8],
) -> Result<(), Error> {
    let h = codec::response(op, route, counter, bytes)?;
    no_pipeline(
        &mut wire.read,
        state,
        at,
        write_bytes(&mut wire.write, state, at, &h, bytes),
    )
    .await?;
    // Leave any next request in the stream until this bounded flush completes;
    // no new allocation, exchange, or deadline is started here.
    flush(&mut wire.write, state, at).await
}

fn next(counter: u64) -> Result<u64, Error> {
    counter.checked_add(1).ok_or(Error::Framing)
}

struct Opened {
    route: Route,
    m2: Vec<u8>,
}

pub struct ClientReader<D> {
    wire: Wire<D>,
    state: Arc<State>,
    authority: Authority,
    envelope: OpenEnvelope,
    opened: mpsc::Receiver<Opened>,
    route: Option<Route>,
    counter: u64,
    due: Instant,
}
pub struct ClientWriter<U> {
    wire: Wire<U>,
    state: Arc<State>,
    authority: Authority,
    envelope: OpenEnvelope,
    opened: mpsc::Sender<Opened>,
    route: Option<Route>,
    counter: u64,
}

/// Construct raw client record halves over an exclusively owned stream pair.
/// First write is M1, first read is M2. Subsequent reads issue sequential polls;
/// callers must keep a read pending (also while writing) to meet the poll gap.
/// No bytes are emitted by construction. Both streams must already satisfy the
/// caller's same-endpoint/route policy. This API makes no HTTPS security claim.
pub fn client_pair<U, D>(
    upload: U,
    download: D,
    authority: Authority,
    envelope: OpenEnvelope,
    budget: EstablishmentBudget,
) -> (ClientReader<D>, ClientWriter<U>, Control)
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = State::new(budget);
    let (tx, rx) = mpsc::channel(1);
    (
        ClientReader {
            wire: Wire::new(download),
            state: state.clone(),
            authority: authority.clone(),
            envelope: envelope.clone(),
            opened: rx,
            route: None,
            counter: 0,
            due: state.setup,
        },
        ClientWriter {
            wire: Wire::new(upload),
            state: state.clone(),
            authority,
            envelope,
            opened: tx,
            route: None,
            counter: 0,
        },
        Control(state),
    )
}

impl<D: AsyncRead + AsyncWrite + Unpin + Send + 'static> RecordReader for ClientReader<D> {
    fn read_record(
        &mut self,
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send {
        // Bound composed pump future/stack size independently of HTTP's nested
        // exchange timers. This future still retains the same I/O across Pending.
        let future: futures_util::future::BoxFuture<'_, Result<Vec<u8>, Error>> =
            Box::pin(async move {
                let state = self.state.clone();
                let at = state.after(RECORD);
                state
                    .run(at, async {
                        if self.route.is_none() {
                            let opened = self.opened.recv().await.ok_or(Error::Closed)?;
                            if opened.m2.len() > maximum {
                                return Err(Error::Framing);
                            }
                            self.route = Some(opened.route);
                            self.due = state.after(GAP);
                            return Ok(opened.m2);
                        }
                        loop {
                            state.check(self.due)?;
                            let exchange = state.after(POLL).min(at);
                            let h = codec::request(
                                Operation::Poll,
                                &self.authority,
                                self.route.as_ref(),
                                Some(self.counter),
                                &[],
                                &self.envelope,
                            )?;
                            // The response-header assembly timer starts at its first byte,
                            // not when a long poll is sent. The whole exchange remains capped.
                            let result = state
                                .run(exchange, async {
                                    write(&mut self.wire.write, &state, exchange, &h, &[]).await?;
                                    let (h, _) =
                                        header(&mut self.wire.read, &state, exchange, EXCHANGE)
                                            .await?;
                                    let head = codec::parse_response(&h, Operation::Poll)?;
                                    if head.counter != Some(self.counter) {
                                        return Err(Error::Framing);
                                    }
                                    let bytes = body(
                                        &mut self.wire.read,
                                        &state,
                                        exchange,
                                        head.body_len,
                                        maximum,
                                    )
                                    .await?;
                                    response_end(&mut self.wire.read, &state, exchange, true)
                                        .await?;
                                    Ok((head, bytes))
                                })
                                .await?;
                            self.counter = next(self.counter)?;
                            self.due = state.after(GAP);
                            if result.0.status == Some(200) {
                                return Ok(result.1);
                            }
                            state.check(at)?; // Empty polls never renew the next-record wait.
                        }
                    })
                    .await
            });
        future
    }
}

impl<U: AsyncRead + AsyncWrite + Unpin + Send + 'static> RecordWriter for ClientWriter<U> {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let future: futures_util::future::BoxFuture<'_, Result<(), Error>> = Box::pin(async move {
            let state = self.state.clone();
            let at = state.after(EXCHANGE);
            state
                .run(at, async {
                    let op = if self.route.is_none() {
                        Operation::Open
                    } else {
                        Operation::Send
                    };
                    let n = if op == Operation::Send {
                        Some(self.counter)
                    } else {
                        None
                    };
                    let h = codec::request(
                        op,
                        &self.authority,
                        self.route.as_ref(),
                        n,
                        bytes,
                        &self.envelope,
                    )?;
                    write(&mut self.wire.write, &state, at, &h, bytes).await?;
                    let (h, _) = header(&mut self.wire.read, &state, at, EXCHANGE).await?;
                    let head = codec::parse_response(&h, op)?;
                    let response = body(&mut self.wire.read, &state, at, head.body_len, 48).await?;
                    response_end(&mut self.wire.read, &state, at, true).await?;
                    if op == Operation::Open {
                        let route = head.route.ok_or(Error::Framing)?;
                        self.route = Some(route.clone());
                        self.opened
                            .try_send(Opened {
                                route,
                                m2: response,
                            })
                            .map_err(|_| Error::Closed)?;
                    } else {
                        if head.counter != n {
                            return Err(Error::Framing);
                        }
                        self.counter = next(self.counter)?;
                    }
                    Ok(())
                })
                .await
        });
        future.await
    }

    async fn shutdown(&mut self) -> Result<(), Error> {
        let state = self.state.clone();
        let at = state.after(Duration::from_secs(2));
        let result = state
            .run(at, async {
                let route = self.route.as_ref().ok_or(Error::Closed)?;
                let h = codec::request(
                    Operation::Close,
                    &self.authority,
                    Some(route),
                    None,
                    &[],
                    &self.envelope,
                )?;
                write(&mut self.wire.write, &state, at, &h, &[]).await?;
                let (h, _) = header(&mut self.wire.read, &state, at, EXCHANGE).await?;
                codec::parse_response(&h, Operation::Close)?;
                // A host may close immediately after a lawful close response; unlike
                // send/poll, persistence is no longer required at this terminal step.
                response_end(&mut self.wire.read, &state, at, false).await?;
                Ok(())
            })
            .await;
        state.retire();
        result
    }
}

pub struct ServerReader {
    state: Arc<State>,
    input: mpsc::Receiver<Vec<u8>>,
}
pub struct ServerWriter {
    state: Arc<State>,
    output: mpsc::Sender<Output>,
}
struct Output {
    bytes: Vec<u8>,
    deadline: Instant,
    work: oneshot::Sender<futures_util::future::BoxFuture<'static, Result<(), Error>>>,
}

// Poll protected response I/O in the writer's original future, not in the
// independently scheduled HTTP reader/driver. The pump wraps that future in its
// authorization/lifecycle gate on *every* poll. Cancelling it disposes the owned
// wire; neither the driver nor a later poll can redeliver selected ciphertext.
async fn emit<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut wire: Wire<S>,
    state: Arc<State>,
    at: Instant,
    op: Operation,
    route: Option<Route>,
    counter: Option<u64>,
    output: Output,
) -> Result<Wire<S>, Error> {
    let (returned, receive) = oneshot::channel();
    let work = Box::pin(async move {
        let result = respond(
            &mut wire,
            &state,
            at,
            op,
            route.as_ref(),
            counter,
            &output.bytes,
        )
        .await;
        if result.is_ok() {
            returned.send(wire).map_err(|_| Error::Closed)?;
        }
        result
    });
    output.work.send(work).map_err(|_| Error::Closed)?;
    receive.await.map_err(|_| Error::Closed)
}

/// Inline owner of both server streams. This is a pre-associated pair, not an
/// accept registry/listener. `run` must be driven concurrently with the two raw
/// record halves. Dropping it invalidates the pair and drops both owned streams.
pub struct ServerDriver<U, D> {
    upload: Option<Wire<U>>,
    download: Option<Wire<D>>,
    state: Arc<State>,
    authority: Authority,
    envelope: OpenEnvelope,
    origins: OriginPolicy,
    route: Route,
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Output>,
}

/// Construct a single pre-reserved server pair. `route` must be provisioned by
/// the application's bounded unique-selector registry/CSPRNG. This function
/// performs no entropy generation, registry lookup, socket acceptance or crypto.
pub fn server_pair<U, D>(
    upload: U,
    download: D,
    authority: Authority,
    envelope: OpenEnvelope,
    origins: OriginPolicy,
    route: Route,
    budget: EstablishmentBudget,
) -> (ServerReader, ServerWriter, ServerDriver<U, D>, Control)
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let state = State::new(budget);
    let (input, rx) = mpsc::channel(1);
    let (tx, output) = mpsc::channel(1);
    (
        ServerReader {
            state: state.clone(),
            input: rx,
        },
        ServerWriter {
            state: state.clone(),
            output: tx,
        },
        ServerDriver {
            upload: Some(Wire::new(upload)),
            download: Some(Wire::new(download)),
            state: state.clone(),
            authority,
            envelope,
            origins,
            route,
            input,
            output,
        },
        Control(state),
    )
}

impl RecordReader for ServerReader {
    async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let state = self.state.clone();
        state
            .run(state.after(RECORD), async {
                let bytes = self.input.recv().await.ok_or(Error::Closed)?;
                if bytes.len() > maximum {
                    return Err(Error::Framing);
                }
                Ok(bytes)
            })
            .await
    }
}
impl RecordWriter for ServerWriter {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let state = self.state.clone();
        let deadline = state.after(OUTPUT);
        state
            .run(deadline, async {
                if bytes.is_empty() || bytes.len() > codec::MAX_RECORD {
                    return Err(Error::Framing);
                }
                let (work, receive) = oneshot::channel();
                self.output
                    .try_send(Output {
                        bytes: bytes.to_vec(),
                        deadline,
                        work,
                    })
                    .map_err(|_| Error::Closed)?;
                receive.await.map_err(|_| Error::Closed)?.await
            })
            .await
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        self.state.retire();
        Ok(())
    }
}

impl<
        U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    > ServerDriver<U, D>
{
    /// Run until close, failure or abort; no internal task is spawned or detached.
    /// A clean client close returns `Ok(())`; unknown outcomes are fatal errors.
    pub async fn run(mut self) -> Result<(), Error> {
        let state = self.state.clone();
        let _guard = Guard {
            state: &state,
            done: false,
        };
        let at = state.after(EXCHANGE);
        let mut upload = self.upload.take().ok_or(Error::Closed)?;
        upload = state
            .run(at, async {
                let (h, _) = header(&mut upload.read, &state, at, EXCHANGE).await?;
                let head =
                    codec::parse_request(&h, &self.authority, &self.origins, &self.envelope)?;
                if head.operation != Operation::Open {
                    return Err(Error::Framing);
                }
                let m1 = body(
                    &mut upload.read,
                    &state,
                    at,
                    head.body_len,
                    self.envelope.m1_len(),
                )
                .await?;
                self.envelope.check_m1(&m1)?;
                // Capacity admission, not decryption, precedes the response. M1 is
                // available to the consumer while the driver waits for exactly M2.
                {
                    let _gate = state.gate.lock().map_err(|_| Error::Closed)?;
                    state.check(at)?;
                    self.input.try_send(m1).map_err(|_| Error::Closed)?;
                }
                let output = no_pipeline(&mut upload.read, &state, at, async {
                    self.output.recv().await.ok_or(Error::Closed)
                })
                .await?;
                let at = at.min(output.deadline);
                upload = emit(
                    upload,
                    state.clone(),
                    at,
                    Operation::Open,
                    Some(self.route.clone()),
                    None,
                    output,
                )
                .await?;
                Ok(upload)
            })
            .await?;
        let at = {
            let upload = uploads(
                &mut upload,
                &state,
                &self.authority,
                &self.envelope,
                &self.origins,
                &self.route,
                &self.input,
            );
            let poll = polls(
                self.download.take().ok_or(Error::Closed)?,
                &state,
                &self.authority,
                &self.envelope,
                &self.origins,
                &self.route,
                &mut self.output,
            );
            tokio::pin!(upload, poll);
            tokio::select! {
                biased;
                result = &mut upload => result?,
                result = &mut poll => { result?; return Err(Error::Closed); },
            }
        };
        // A valid close has already retired ordinary activity. Drop the poll
        // future before emitting the final 204: its retirement observation must
        // not cancel a backpressured close response. Retain the original close
        // deadline and both streams inline until completion, failure or drop.
        let closing = State {
            clock: state.clock.clone(),
            setup: at.min(state.setup),
            lifetime: at,
            establishing: AtomicBool::new(false),
            closed: watch::channel(false).0,
            gate: Mutex::new(()),
            establishment: Mutex::new(None),
            completion: state.completion.clone(),
            retained: Mutex::new(None),
        };
        closing
            .run(
                at,
                respond(&mut upload, &closing, at, Operation::Close, None, None, &[]),
            )
            .await
    }
}

async fn request_head<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    state: &State,
    idle: Instant,
    exchange: Duration,
    authority: &Authority,
    envelope: &OpenEnvelope,
    origins: &OriginPolicy,
) -> Result<(Head, Instant), Error> {
    let (h, at) = header(&mut wire.read, state, idle, exchange).await?;
    Ok((codec::parse_request(&h, authority, origins, envelope)?, at))
}

async fn uploads<S: AsyncRead + AsyncWrite + Unpin>(
    wire: &mut Wire<S>,
    state: &State,
    authority: &Authority,
    envelope: &OpenEnvelope,
    origins: &OriginPolicy,
    route: &Route,
    input: &mpsc::Sender<Vec<u8>>,
) -> Result<Instant, Error> {
    let mut counter = 0;
    loop {
        let idle = state.lifetime;
        let (head, at) = state
            .run(
                idle,
                request_head(wire, state, idle, EXCHANGE, authority, envelope, origins),
            )
            .await?;
        if head.route.as_ref() != Some(route) {
            return Err(Error::Framing);
        }
        if head.operation == Operation::Close {
            // Transfer only a validated close and its existing deadline to the
            // owner. Retirement stops both ordinary directions before the final
            // response; no future here can be raced away during that response.
            let at = state.cap(at);
            state.retire();
            return Ok(at);
        }
        state
            .run(at, async {
                match head.operation {
                    Operation::Send => {
                        if head.counter != Some(counter) {
                            return Err(Error::Framing);
                        }
                        let next = next(counter)?;
                        // Refuse full capacity before body allocation, never wait
                        // on higher-runtime consumption or acknowledge a full slot.
                        let permit = input.try_reserve().map_err(|_| Error::Closed)?;
                        let bytes = state
                            .run(
                                at,
                                body(&mut wire.read, state, at, head.body_len, codec::MAX_RECORD),
                            )
                            .await?;
                        {
                            let _gate = state.gate.lock().map_err(|_| Error::Closed)?;
                            state.check(at)?;
                            permit.send(bytes);
                        }
                        state
                            .run(
                                at,
                                respond(wire, state, at, Operation::Send, None, Some(counter), &[]),
                            )
                            .await?;
                        counter = next;
                        Ok(())
                    }
                    _ => Err(Error::Framing),
                }
            })
            .await?;
    }
}

async fn polls<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut wire: Wire<S>,
    state: &Arc<State>,
    authority: &Authority,
    envelope: &OpenEnvelope,
    origins: &OriginPolicy,
    route: &Route,
    output: &mut mpsc::Receiver<Output>,
) -> Result<(), Error> {
    let mut counter = 0;
    loop {
        let idle = state.after(GAP);
        // The first-header gap and complete exchange use separate absolute
        // deadlines. The exchange cannot be extended by hold expiry or trickle.
        wire = state
            .run(state.after(POLL), async {
                let (head, at) =
                    request_head(&mut wire, state, idle, POLL, authority, envelope, origins)
                        .await?;
                if head.operation != Operation::Poll
                    || head.route.as_ref() != Some(route)
                    || head.counter != Some(counter)
                {
                    return Err(Error::Framing);
                }
                let next = next(counter)?;
                let hold = state
                    .after(HOLD)
                    .min(at.checked_sub(Duration::from_secs(1)).unwrap_or(at));
                let selected = state
                    .run(
                        at,
                        no_pipeline(&mut wire.read, state, at, async {
                            tokio::select! {
                                biased;
                                _ = state.clock.sleep_until(hold.into_std()) => Ok(None),
                                output = output.recv() => Ok(Some(output.ok_or(Error::Closed)?)),
                            }
                        }),
                    )
                    .await?;
                if let Some(selected) = selected {
                    wire = state
                        .run(
                            at.min(selected.deadline),
                            emit(
                                wire,
                                state.clone(),
                                at.min(selected.deadline),
                                Operation::Poll,
                                None,
                                Some(counter),
                                selected,
                            ),
                        )
                        .await?;
                } else {
                    state
                        .run(
                            at,
                            respond(
                                &mut wire,
                                state,
                                at,
                                Operation::Poll,
                                None,
                                Some(counter),
                                &[],
                            ),
                        )
                        .await?;
                }
                counter = next;
                Ok(wire)
            })
            .await?;
    }
}

impl<D> Drop for ClientReader<D> {
    fn drop(&mut self) {
        self.state.retire();
    }
}
impl<U> Drop for ClientWriter<U> {
    fn drop(&mut self) {
        self.state.retire();
    }
}
impl Drop for ServerReader {
    fn drop(&mut self) {
        self.state.retire();
    }
}
impl Drop for ServerWriter {
    fn drop(&mut self) {
        self.state.retire();
    }
}
impl<U, D> Drop for ServerDriver<U, D> {
    fn drop(&mut self) {
        self.state.retire();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn counters_never_wrap_or_resynchronize() {
        assert_eq!(super::next(0).unwrap(), 1);
        assert_eq!(super::next(u64::MAX - 1).unwrap(), u64::MAX);
        assert!(super::next(u64::MAX).is_err());
    }
}
