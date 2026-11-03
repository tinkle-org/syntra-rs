//! Local-task browser owner. JS objects are deliberately !Send/!Sync. No lock
//! spans an await; RefCell guards protect only synchronous queue/cipher steps.

use super::{time::ConnectionClock, Error, Limits, SUBPROTOCOL};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::Future,
    rc::Rc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use syntra_core::secure_channel::{
    frame_plaintext, Channel, ClientConfig, ClientHandshake, FrameDecoder, MAX_CIPHERTEXT,
    MAX_PLAINTEXT,
};
use syntra_runtime::{ConnectionConfig, Initiator};
use tokio::sync::{mpsc, oneshot, Notify};
use wasm_bindgen::{closure::Closure, JsCast};
use web_sys::{Event, MessageEvent, WebSocket};

static OWNERS: AtomicUsize = AtomicUsize::new(0);
struct OwnerAdmission;
impl OwnerAdmission {
    fn acquire() -> Result<Self, Error> {
        OWNERS
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 32).then_some(n + 1)
            })
            .map_err(|_| Error::Limit)?;
        Ok(Self)
    }
}
impl Drop for OwnerAdmission {
    fn drop(&mut self) {
        OWNERS.fetch_sub(1, Ordering::Relaxed);
    }
}

struct Inbox {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    opened: bool,
    error: Option<Error>,
    maximum: usize,
    channel: Option<std::rc::Weak<RefCell<Channel>>>,
    time: ConnectionClock,
}

impl Inbox {
    fn fail(&mut self, error: Error) {
        self.error.get_or_insert(error);
        self.queue.clear();
        self.bytes = 0;
        if let Some(channel) = self.channel.as_ref().and_then(std::rc::Weak::upgrade) {
            channel.borrow_mut().close();
        }
        self.time.invalidate();
    }
}

/// Owns every callback. Never forget a Closure: detach before dropping it.
struct Socket {
    ws: WebSocket,
    inbox: Rc<RefCell<Inbox>>,
    wake: Rc<Notify>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _open: Closure<dyn FnMut(Event)>,
    _failure: Closure<dyn FnMut(Event)>,
    lifecycle: Closure<dyn FnMut(Event)>,
    window: web_sys::Window,
    document: web_sys::Document,
    time: ConnectionClock,
    last_tick: Cell<Duration>,
    /// Current absolute setup cutoff; removed only after CoreReady is admitted.
    phase_deadline: Cell<Option<Duration>>,
    end: Duration,
    limits: Limits,
}

impl Socket {
    fn new(url: &str, limits: Limits, time: ConnectionClock) -> Result<Self, Error> {
        time.check(limits.attempt.min(limits.lifetime))?;
        let window = web_sys::window().ok_or(Error::Unsupported)?;
        let document = window.document().ok_or(Error::Unsupported)?;
        if document.hidden() {
            return Err(Error::Unsupported);
        }
        let ws = WebSocket::new_with_str(url, SUBPROTOCOL).map_err(|_| Error::Closed)?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
        let inbox = Rc::new(RefCell::new(Inbox {
            queue: VecDeque::new(),
            bytes: 0,
            opened: false,
            error: None,
            maximum: 48,
            channel: None,
            time: time.clone(),
        }));
        let wake = Rc::new(Notify::new());
        let state = Rc::downgrade(&inbox);
        let signal = wake.clone();
        let socket = ws.clone();
        let bound = limits.clone();
        let message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let Some(state) = state.upgrade() else {
                return;
            };
            let mut state = state.borrow_mut();
            if state.error.is_some() {
                return;
            }
            let data = event.data();
            let error = if let Some(buffer) = data.dyn_ref::<js_sys::ArrayBuffer>() {
                let n = buffer.byte_length() as usize;
                if n == 0 || n > state.maximum {
                    Some(Error::Framing)
                } else if state.queue.len() >= bound.receive_messages
                    || state.bytes + n > bound.receive_bytes
                {
                    Some(Error::Limit)
                } else {
                    // Check assembled size and admission BEFORE copying into Rust.
                    state
                        .queue
                        .push_back(js_sys::Uint8Array::new(buffer).to_vec());
                    state.bytes += n;
                    None
                }
            } else {
                Some(Error::Framing)
            };
            if let Some(error) = error {
                state.fail(error);
                let _ = socket.close();
            }
            signal.notify_one();
        });
        let state = Rc::downgrade(&inbox);
        let signal = wake.clone();
        let open = Closure::<dyn FnMut(Event)>::new(move |_| {
            if let Some(state) = state.upgrade() {
                state.borrow_mut().opened = true;
            }
            signal.notify_one();
        });
        let state = Rc::downgrade(&inbox);
        let signal = wake.clone();
        let failure = Closure::<dyn FnMut(Event)>::new(move |_| {
            if let Some(state) = state.upgrade() {
                let mut state = state.borrow_mut();
                state.fail(Error::Closed);
            }
            signal.notify_one();
        });
        let state = Rc::downgrade(&inbox);
        let signal = wake.clone();
        let socket = ws.clone();
        let doc = document.clone();
        let lifecycle = Closure::<dyn FnMut(Event)>::new(move |event: Event| {
            if event.type_() == "pagehide" || doc.hidden() {
                if let Some(state) = state.upgrade() {
                    let mut state = state.borrow_mut();
                    state.fail(Error::Closed);
                }
                let _ = socket.close();
                signal.notify_one();
            }
        });
        ws.set_onmessage(Some(message.as_ref().unchecked_ref()));
        ws.set_onopen(Some(open.as_ref().unchecked_ref()));
        ws.set_onerror(Some(failure.as_ref().unchecked_ref()));
        ws.set_onclose(Some(failure.as_ref().unchecked_ref()));
        let result = Self {
            ws,
            inbox,
            wake,
            _message: message,
            _open: open,
            _failure: failure,
            lifecycle,
            window,
            document,
            time,
            last_tick: Cell::new(Duration::ZERO),
            phase_deadline: Cell::new(Some(limits.attempt.min(limits.lifetime))),
            end: limits.lifetime,
            limits,
        };
        result
            .document
            .add_event_listener_with_callback(
                "visibilitychange",
                result.lifecycle.as_ref().unchecked_ref(),
            )
            .map_err(|_| Error::Unsupported)?;
        result
            .window
            .add_event_listener_with_callback("pagehide", result.lifecycle.as_ref().unchecked_ref())
            .map_err(|_| Error::Unsupported)?;
        Ok(result)
    }

    fn check(&self) -> Result<(), Error> {
        let time = self.time.now();
        // Kernel age uses the greater elapsed/wall observation and retires on
        // regression or disagreement. The owner additionally fences >2s gaps
        // between observations before buffered work can run after a freeze.
        let previous = self.last_tick.replace(time);
        if time < previous
            || time.saturating_sub(previous) > Duration::from_secs(2)
            || self
                .time
                .check(self.phase_deadline.get().unwrap_or(self.end).min(self.end))
                .is_err()
            || self.document.hidden()
        {
            self.time.invalidate();
            return Err(Error::Timeout);
        }
        self.inbox.borrow().error.map_or(Ok(()), Err)
    }

    fn shutdown(&self) {
        self.ws.set_onmessage(None);
        self.ws.set_onopen(None);
        self.ws.set_onerror(None);
        self.ws.set_onclose(None);
        let _ = self.document.remove_event_listener_with_callback(
            "visibilitychange",
            self.lifecycle.as_ref().unchecked_ref(),
        );
        let _ = self.window.remove_event_listener_with_callback(
            "pagehide",
            self.lifecycle.as_ref().unchecked_ref(),
        );
        let mut state = self.inbox.borrow_mut();
        state.fail(Error::Closed);
        let _ = self.ws.close();
        self.wake.notify_one();
    }

    async fn opened(&self) -> Result<(), Error> {
        loop {
            self.check()?;
            if self.inbox.borrow().opened {
                return if self.ws.protocol() == SUBPROTOCOL && self.ws.extensions().is_empty() {
                    Ok(())
                } else {
                    Err(Error::Framing)
                };
            }
            self.wake.notified().await;
        }
    }

    async fn receive(&self) -> Result<Vec<u8>, Error> {
        loop {
            self.check()?;
            {
                let mut state = self.inbox.borrow_mut();
                if let Some(bytes) = state.queue.pop_front() {
                    state.bytes -= bytes.len();
                    return Ok(bytes);
                }
            }
            self.wake.notified().await;
        }
    }

    async fn capacity(&self, bytes: usize, deadline: Duration) -> Result<(), Error> {
        self.time
            .run(deadline, async {
                loop {
                    self.check()?;
                    if self.ws.ready_state() != WebSocket::OPEN {
                        return Err(Error::Closed);
                    }
                    if u64::from(self.ws.buffered_amount()) + bytes as u64
                        <= u64::from(self.limits.buffered_bytes)
                    {
                        return Ok(());
                    }
                    syntra_runtime::sleep_for(Duration::from_millis(5)).await;
                }
            })
            .await
    }

    fn send(&self, bytes: &[u8], deadline: Duration) -> Result<(), Error> {
        self.check()?;
        self.time.check(deadline)?;
        if self.ws.ready_state() != WebSocket::OPEN {
            return Err(Error::Closed);
        }
        if u64::from(self.ws.buffered_amount()) + bytes.len() as u64
            > u64::from(self.limits.buffered_bytes)
        {
            return Err(Error::Limit);
        }
        self.time.check(deadline)?;
        self.ws
            .send_with_u8_array(bytes)
            .map_err(|_| Error::Closed)?;
        self.time.check(deadline)
    }

    async fn establishing<T>(
        &self,
        deadline: Duration,
        future: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        self.time
            .run(deadline, async {
                // Keep observing during a legitimately slow Upgrade/M2, not just
                // after ready. A blocked JS turn still retires before buffered work.
                tokio::select! {
                    biased;
                    result = self.monitor() => { result?; Err(Error::Closed) },
                    result = future => result,
                }
            })
            .await
    }

    async fn monitor(&self) -> Result<(), Error> {
        loop {
            self.check()?;
            syntra_runtime::sleep_for(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A non-Send browser client with retained owner completion. Dropping it closes
/// the carrier synchronously and wakes the owner; no callbacks survive teardown.
pub struct BrowserClient {
    pub initiator: Initiator,
    socket: Rc<Socket>,
    done: Option<oneshot::Receiver<()>>,
}

impl BrowserClient {
    pub fn check_live(&self) -> Result<(), Error> {
        let result = self.socket.check();
        if result.is_err() {
            self.socket.shutdown();
        }
        result
    }

    /// Abortive bounded close. No claim that browser close_notify was delivered.
    pub async fn close(mut self) -> Result<(), Error> {
        // Retiring the live clock must not prevent awaiting owned teardown. This
        // independent dual-clock budget starts before shutdown and authorizes
        // only joining; it never reaches any handshake or traffic cipher state.
        let cleanup = ConnectionClock::new();
        self.socket.shutdown();
        cleanup
            .run(self.socket.limits.close, async {
                self.initiator.on_transport_lost().await;
                if let Some(done) = self.done.take() {
                    done.await.map_err(|_| Error::ShutdownIncomplete)?;
                }
                Ok(())
            })
            .await
            .map_err(|_| Error::ShutdownIncomplete)
    }
}

impl Drop for BrowserClient {
    fn drop(&mut self) {
        self.socket.shutdown();
    }
}

async fn write_frames(
    socket: &Socket,
    channel: &RefCell<Channel>,
    initiator: &Initiator,
    mut outbound: mpsc::Receiver<Vec<u8>>,
) -> Result<(), Error> {
    while let Some(bytes) = outbound.recv().await {
        let deadline = socket
            .time
            .after(socket.limits.write)
            .min(socket.end)
            .min(socket.phase_deadline.get().unwrap_or(socket.end));
        // Await capacity before committing runtime emission. Each later segment
        // retains the same frame and deadline; cancellation aborts the channel.
        socket
            .capacity((bytes.len() + 4).min(MAX_PLAINTEXT) + 16, deadline)
            .await?;
        let Some(bytes) = initiator.prepare_outbound(bytes) else {
            continue;
        };
        let plaintext = frame_plaintext(&bytes)?;
        for chunk in plaintext.chunks(MAX_PLAINTEXT) {
            socket.capacity(chunk.len() + 16, deadline).await?;
            socket.time.check(deadline)?;
            let ciphertext = channel.borrow_mut().encrypt(chunk)?;
            // Synchronous browser handoff: one binary message, no u16 prefix.
            // Never re-encrypt or retry a consumed nonce after send failure.
            socket.send(&ciphertext, deadline)?;
        }
        // bufferedAmount is local handoff progress, never peer receipt.
        socket
            .time
            .run(deadline, async {
                while socket.ws.buffered_amount() != 0 {
                    socket.check()?;
                    syntra_runtime::sleep_for(Duration::from_millis(5)).await;
                }
                Ok(())
            })
            .await?;
    }
    Err(Error::Closed)
}

async fn read_frames(
    socket: &Socket,
    channel: &RefCell<Channel>,
    initiator: &Initiator,
) -> Result<(), Error> {
    let mut decoder = FrameDecoder::default();
    let mut assembly = socket.end;
    loop {
        // The next-record budget includes idle wait, not only partial frames.
        let deadline = socket
            .time
            .after(socket.limits.record)
            .min(assembly)
            .min(socket.end);
        let ciphertext = socket.time.run(deadline, socket.receive()).await?;
        socket.check()?;
        let plaintext = channel.borrow_mut().decrypt(&ciphertext)?;
        socket.time.check(deadline)?;
        let frames = decoder.push(&plaintext)?;
        socket.time.check(deadline)?;
        if !decoder.is_partial() {
            assembly = socket.end;
        } else if assembly == socket.end || !frames.is_empty() {
            assembly = socket.time.after(socket.limits.frame).min(socket.end);
        }
        for frame in frames {
            socket.check()?;
            socket
                .time
                .run(
                    socket
                        .time
                        .after(socket.limits.write)
                        .min(assembly)
                        .min(socket.end),
                    async {
                        initiator.ingest(&frame).await;
                        Ok(())
                    },
                )
                .await?;
            if initiator.is_closed() {
                return Err(Error::Closed);
            }
        }
    }
}

/// WSS → exact selection → pinned Noise → encrypted hello → CoreReady.
/// Never retries or changes authentication modes. Not Send by design.
pub async fn connect(
    url: &str,
    config: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<BrowserClient, Error> {
    // Capture kernel dual-clock age before admission, validation and any outer
    // WebSocket work. No phase creates a new cryptographic lifetime origin.
    let time = ConnectionClock::new();
    let admission = OwnerAdmission::acquire()?;
    let mut credential = zeroize::Zeroizing::new(credential);
    super::validate(url, &config)?;
    limits.validate(&runtime)?;
    if credential.len() > syntra_core::MAX_CREDENTIAL_BYTES {
        return Err(Error::Limit);
    }
    let attempt = limits.attempt.min(limits.lifetime);
    let socket = Rc::new(Socket::new(url, limits, time.clone())?);
    socket.establishing(attempt, socket.opened()).await?;
    let establishment = time.after(socket.limits.establishment).min(attempt);
    socket.phase_deadline.set(Some(establishment));
    let (handshake, first) = ClientHandshake::start_with_clock(config, time.kernel.clone())?;
    socket.send(&first, establishment)?;
    let second = socket.establishing(establishment, socket.receive()).await?;
    let channel = Rc::new(RefCell::new(handshake.finish(&second)?));
    time.check(establishment)?;
    socket.inbox.borrow_mut().channel = Some(Rc::downgrade(&channel));
    socket.inbox.borrow_mut().maximum = MAX_CIPHERTEXT;
    let (initiator, outbound) = Initiator::try_new_with_clock(runtime, time.runtime.clone())
        .map_err(|_| Error::Configuration)?;
    let (complete, done) = oneshot::channel();
    let client = BrowserClient {
        initiator: initiator.clone(),
        socket: socket.clone(),
        done: Some(done),
    };
    let peer = initiator.clone();
    // One local owner polls both directions. Crypto mutation is synchronous;
    // there is exactly one writer and a single close/callback cleanup path.
    wasm_bindgen_futures::spawn_local(async move {
        // Account for work until the owner really finishes, even when a close
        // caller times out or drops its future. Do not report a free slot early.
        let _admission = admission;
        let mut closed = peer.subscribe_close();
        if peer.is_closed() {
            socket.shutdown();
        }
        tokio::select! {
            biased;
            _ = socket.monitor() => {},
            _ = async { if !*closed.borrow_and_update() { let _ = closed.changed().await; } } => {},
            _ = read_frames(&socket, &channel, &peer) => {},
            _ = write_frames(&socket, &channel, &peer, outbound) => {},
        }
        channel.borrow_mut().close();
        socket.shutdown();
        peer.on_transport_lost().await;
        let _ = complete.send(());
    });
    // Client's Drop owns cancellation even if the partially established future
    // is dropped here. Keep establishment/attempt absolute across CoreReady.
    time.run(establishment, async {
        initiator
            .handshake(std::mem::take(&mut *credential))
            .await
            .map_err(|_| Error::Authentication)?;
        client.check_live()?;
        Ok(())
    })
    .await?;
    client.socket.phase_deadline.set(None);
    Ok(client)
}
