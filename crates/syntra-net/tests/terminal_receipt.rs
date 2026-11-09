//! Encrypted native TCP receipt tests. Fixture authority is not durable storage.
#![cfg(all(feature = "tcp", not(target_arch = "wasm32")))]
use futures_util::future::BoxFuture;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use syntra_core::secure_channel::*;
use syntra_net::{
    pump::{AuthenticatorFactory, Limits},
    tcp,
};
use syntra_runtime::elapsed::{ElapsedClock, ElapsedDeadline};
use syntra_runtime::{terminal::*, *};
use tokio::sync::Notify;

const METHOD: &str = "/example.Authority/Retire";

/// Bounded wall-time diagnostics, separate from any explicitly driven test clock.
/// Observation events describe fixture state, not an SDK authorization verdict.
struct EventTrace {
    started: std::time::Instant,
    events: Mutex<Vec<(Duration, &'static str, usize)>>,
}
impl EventTrace {
    /// Start bounded diagnostics in a separate real-time domain.
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }
    /// Retain at most 256 observations, including actual raw-byte handoffs.
    fn record(&self, event: &'static str, count: usize) {
        let mut events = self.events.lock().unwrap();
        if events.len() < 256 {
            events.push((self.started.elapsed(), event, count));
        }
    }
}
/// Linearizable in-memory authority with explicit commit-return and denial controls.
struct AuthorityFixture {
    state: Mutex<(u64, Option<Transition>, bool)>,
    commits: AtomicUsize,
    reads: AtomicUsize,
    mode: AtomicUsize,
    committed: Notify,
    reserved: Notify,
    release: Notify,
    trace: Arc<EventTrace>,
    read_budgets: Mutex<Vec<Duration>>,
    commit_budgets: Mutex<Vec<Duration>>,
}
impl AuthorityFixture {
    /// Select one evidence/failure mode for a new active binding.
    fn new(mode: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new((1, None, false)),
            commits: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            mode: AtomicUsize::new(mode),
            committed: Notify::new(),
            reserved: Notify::new(),
            release: Notify::new(),
            trace: Arc::new(EventTrace::new()),
            read_budgets: Mutex::new(vec![]),
            commit_budgets: Mutex::new(vec![]),
        })
    }
}
impl Authority for AuthorityFixture {
    /// Record the actual read bound while preserving legacy fixture behavior.
    fn observe_with_budget(
        &self,
        transition: Option<Transition>,
        budget: ElapsedDeadline,
    ) -> BoxFuture<'_, Observation> {
        self.read_budgets
            .lock()
            .unwrap()
            .push(budget.remaining().unwrap());
        self.observe(transition)
    }
    /// Record the non-renewed cutoff passed across the native TCP boundary.
    fn commit_with_budget(
        &self,
        transition: Transition,
        lease: ExecutionLease,
        budget: ElapsedDeadline,
    ) -> BoxFuture<'_, ()> {
        self.commit_budgets
            .lock()
            .unwrap()
            .push(budget.remaining().unwrap());
        self.commit(transition, lease)
    }
    /// Count and report the fixture's current active, owned, or failure evidence.
    fn observe(&self, transition: Option<Transition>) -> BoxFuture<'_, Observation> {
        Box::pin(async move {
            let s = self.state.lock().unwrap();
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.trace.record(
                if s.1.is_some() {
                    "observe.owner-record"
                } else if transition.is_some() {
                    "observe.reserved"
                } else {
                    "observe.active"
                },
                0,
            );
            if transition.is_some() && s.1.is_none() {
                self.reserved.notify_one();
            }
            if s.2 {
                return Observation::HardDenied;
            }
            if let Some(c) = &s.1 {
                return match self.mode.load(Ordering::SeqCst) {
                    2 => Observation::Unknown,
                    3 => Observation::Active { revision: 1 },
                    4 => Observation::OwnedCommitted {
                        reservation: c.reservation.clone(),
                        expected_revision: 0,
                        revision: 2,
                    },
                    _ => Observation::OwnedCommitted {
                        reservation: c.reservation.clone(),
                        expected_revision: 1,
                        revision: s.0,
                    },
                };
            }
            Observation::Active { revision: s.0 }
        })
    }
    /// Conditionally record ownership and optionally hold the callback open.
    fn commit(&self, c: Transition, _lease: ExecutionLease) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.trace.record("commit", 0);
            self.commits.fetch_add(1, Ordering::SeqCst);
            {
                let mut s = self.state.lock().unwrap();
                if s.0 != c.expected_revision || s.1.is_some() || s.2 {
                    return;
                }
                s.0 += 1;
                s.1 = Some(c);
                if self.mode.load(Ordering::SeqCst) == 1 {
                    s.2 = true;
                }
            }
            self.committed.notify_one();
            if self.mode.load(Ordering::SeqCst) == 5 {
                self.release.notified().await;
            }
        })
    }
}
/// Supply typed policy and optionally the test's driven elapsed domain.
struct Factory {
    authority: Arc<AuthorityFixture>,
    payload: Vec<u8>,
    enabled: bool,
    clock: Option<ElapsedClock>,
}
impl AuthenticatorFactory for Factory {
    /// Use the explicitly driven clock when supplied, otherwise native elapsed time.
    fn elapsed_clock(&self) -> ElapsedClock {
        self.clock.clone().unwrap_or_default()
    }
    /// Refuse withdrawn bindings and authenticate the fixed fixture principal.
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        if self.authority.state.lock().unwrap().1.is_some() {
            return Err(AuthError::unauthenticated());
        }
        Ok(Arc::new(StaticToken::new(
            b"fixture".to_vec(),
            "fixture-principal",
        )))
    }
    /// Opt into the fixed receipt with the minimum supported authority read bound.
    fn terminal_receipt(&self, _: &VerifiedIdentity) -> Option<Policy> {
        self.enabled.then(|| Policy {
            method: METHOD.into(),
            payload: self.payload.clone(),
            authority: self.authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
    }
}
/// Retire only the configured method; sibling methods exercise ordinary output.
struct Retire;
impl Handler for Retire {
    /// Echo payloads on the legacy hook; retirement requires the request context.
    fn handle(&self, _: String, p: Vec<u8>, _: CancelToken) -> HandlerFut {
        Box::pin(async move { HandlerOutcome::Payload(p) })
    }
    /// Retire the configured method or return an ordinary echo.
    fn handle_with_context(
        &self,
        method: String,
        p: Vec<u8>,
        _: CancelToken,
        _: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        Box::pin(async move {
            if method != METHOD {
                return HandlerOutcome::Payload(p);
            }
            context.retire(1).await.unwrap_or_else(|_| {
                HandlerOutcome::error(
                    syntra_core::ErrorCode::Unavailable,
                    "retirement unavailable",
                )
            })
        })
    }
}

/// Hold an admitted sibling until the test releases its ordinary result.
#[derive(Clone, Default)]
struct HeldSibling {
    started: Arc<Notify>,
    release: Arc<Notify>,
}
impl Handler for HeldSibling {
    /// Preserve the legacy echo hook; retirement still needs the request context.
    fn handle(&self, method: String, p: Vec<u8>, cancel: CancelToken) -> HandlerFut {
        Retire.handle(method, p, cancel)
    }
    /// Witness sibling entry before reservation and control completion without time.
    fn handle_with_context(
        &self,
        method: String,
        p: Vec<u8>,
        cancel: CancelToken,
        lease: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        if method != "/example.Authority/Slow" {
            return Retire.handle_with_context(method, p, cancel, lease, context);
        }
        let started = self.started.clone();
        let release = self.release.clone();
        Box::pin(async move {
            started.notify_one();
            release.notified().await;
            HandlerOutcome::Payload(p)
        })
    }
}
/// Build fresh encrypted TCP provisioning; application credentials bind the principal.
fn configs() -> (ClientConfig, ServerConfig) {
    let (private_key, public) = generate_server_key().unwrap();
    let context = Context {
        mode: Mode::Bootstrap,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"terminal-fixture".to_vec(),
        handle: [0; 8],
        epoch: 0,
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: None,
        },
        ServerConfig {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: context.scope,
            private_key,
            store: None,
        },
    )
}
/// Establish real TCP peers with native elapsed clocks and a 100 ms read bound.
async fn pair(
    authority: Arc<AuthorityFixture>,
    payload: Vec<u8>,
    enabled: bool,
) -> (tcp::ClientHandle, tcp::HostHandle) {
    pair_with_handler(authority, payload, enabled, Arc::new(AllowAll(Retire))).await
}

/// Establish TCP with an explicitly selected application handler and policy.
async fn pair_with_handler(
    authority: Arc<AuthorityFixture>,
    payload: Vec<u8>,
    enabled: bool,
    handler: Arc<dyn Handler>,
) -> (tcp::ClientHandle, tcp::HostHandle) {
    let (client, server) = configs();
    let listener = tcp::Listener::bind("127.0.0.1:0", 2).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        listener
            .accept(
                &server,
                Arc::new(Factory {
                    authority,
                    payload,
                    enabled,
                    clock: None,
                }),
                handler,
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await
    });
    let client = tcp::connect(
        address,
        client,
        b"fixture".to_vec(),
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    (client, accept.await.unwrap().unwrap())
}

/// Add only a local request cap, forwarding the existing context-aware handler.
struct CappedRetire(Duration);
impl Handler for CappedRetire {
    /// Cap only retirement, preserving ordinary request deadlines for sibling methods.
    fn request_budget(&self, _: &Principal, method: &str, _: &[u8]) -> Option<Duration> {
        (method == METHOD).then_some(self.0)
    }
    /// Preserve the legacy echo hook; retirement still requires context-aware dispatch.
    fn handle(&self, method: String, payload: Vec<u8>, cancel: CancelToken) -> HandlerFut {
        Retire.handle(method, payload, cancel)
    }
    /// Verify the retirement cap reaches dispatch before forwarding its context and lease.
    fn handle_with_context(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: CancelToken,
        lease: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        if method == METHOD {
            assert!(context.budget().remaining().unwrap() <= self.0);
        }
        Retire.handle_with_context(method, payload, cancel, lease, context)
    }
}

/// Real TCP uses the SDK-local cap for terminal authority without changing wire timeouts.
#[tokio::test]
async fn encrypted_tcp_local_budget_reaches_terminal_authority() {
    let authority = AuthorityFixture::new(0);
    let (client, host) = pair_with_handler(
        authority.clone(),
        b"retired".to_vec(),
        true,
        Arc::new(AllowAll(CappedRetire(Duration::from_secs(3)))),
    )
    .await;
    assert_eq!(
        client.conn.call(METHOD, vec![], 30_000).await.unwrap(),
        b"retired"
    );
    closed(&host).await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
    let budgets = authority.commit_budgets.lock().unwrap().clone();
    assert_eq!(budgets.len(), 1);
    assert!(!budgets[0].is_zero());
    assert!(budgets[0] <= Duration::from_millis(2750));
    assert!(authority
        .read_budgets
        .lock()
        .unwrap()
        .iter()
        .all(|b| *b <= Duration::from_millis(100)));
    client.close().await;
    host.close().await;
}

/// Zero local cap expires before retirement, leaving unrelated RPCs usable.
#[tokio::test]
async fn encrypted_tcp_zero_local_budget_never_commits() {
    let authority = AuthorityFixture::new(0);
    let (client, host) = pair_with_handler(
        authority.clone(),
        b"retired".to_vec(),
        true,
        Arc::new(AllowAll(CappedRetire(Duration::ZERO))),
    )
    .await;
    assert_eq!(
        client
            .conn
            .call(METHOD, vec![], 30_000)
            .await
            .unwrap_err()
            .code(),
        syntra_core::ErrorCode::DeadlineExceeded
    );
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    assert_eq!(
        client
            .conn
            .call("/example.Authority/Echo", vec![], 1000)
            .await
            .unwrap(),
        b""
    );
    client.close().await;
    host.close().await;
}
/// Bound the wait for observable host retirement separately from joined cleanup.
async fn closed(host: &tcp::HostHandle) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !host.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
/// One owned commit emits exact bytes and makes this connection unusable afterward.
#[tokio::test]
async fn encrypted_tcp_exact_receipt_and_retirement() {
    let authority = AuthorityFixture::new(0);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    assert_eq!(
        client.conn.call(METHOD, vec![], 2000).await.unwrap(),
        b"retired"
    );
    closed(&host).await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
    assert!(client.conn.call(METHOD, vec![], 1000).await.is_err());
    client.close().await;
    host.close().await;
}
/// Default-disabled retirement leaves ordinary RPCs available and commits nothing.
#[tokio::test]
async fn disabled_never_mutates_and_connection_remains_ordinary() {
    let authority = AuthorityFixture::new(0);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), false).await;
    assert!(client.conn.call(METHOD, vec![], 1000).await.is_err());
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    assert_eq!(
        client
            .conn
            .call("/example.Authority/Echo", b"ordinary".to_vec(), 1000)
            .await
            .unwrap(),
        b"ordinary"
    );
    client.close().await;
    host.close().await;
}
/// Denial, uncertainty, stale-active evidence, and mismatched ownership suppress success.
#[tokio::test]
async fn authoritative_external_unknown_stale_wrong_owner_never_emit_success() {
    for mode in 1..=4 {
        let authority = AuthorityFixture::new(mode);
        let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
        assert!(
            client.conn.call(METHOD, vec![], 1000).await.is_err(),
            "mode {mode}"
        );
        closed(&host).await;
        assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
        client.close().await;
        host.close().await;
    }
}
/// Owned evidence bridges callback delay without restoring ordinary output permission.
#[tokio::test]
async fn commit_before_callback_return_is_observed_but_not_sent_early() {
    let authority = AuthorityFixture::new(5);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    let conn = client.conn.clone();
    let call = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.committed.notified().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!host.is_closed(), "own commit is not a generic revocation");
    assert!(!call.is_finished(), "callback completion still required");
    assert!(host.host.notify(b"protected".to_vec()).await.is_err());
    authority.release.notify_one();
    assert_eq!(call.await.unwrap().unwrap(), b"retired");
    closed(&host).await;
    client.close().await;
    host.close().await;
}
/// Deadline closes reporting while the retained commit task still holds its lease.
#[tokio::test]
async fn surviving_authority_work_keeps_execution_charge_after_deadline() {
    let authority = AuthorityFixture::new(5);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    let conn = client.conn.clone();
    let call = tokio::spawn(async move { conn.call(METHOD, vec![], 400).await });
    authority.committed.notified().await;
    assert!(call.await.unwrap().is_err());
    closed(&host).await;
    assert_eq!(
        host.host.execution_len(),
        1,
        "SDK must own still-running authority work"
    );
    authority.release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        while host.host.execution_len() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client.close().await;
    host.close().await;
}

/// The size ceiling counts the complete serialized result frame, not just its payload.
#[tokio::test]
async fn complete_frame_limit_is_1024_not_payload_limit() {
    use prost::Message;
    use syntra_core::{
        proto::{frame::Body, rpc_result::Outcome},
        Frame, RpcResult,
    };
    let size = |n| {
        Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(vec![0; n])),
            })),
        }
        .encoded_len()
    };
    let n = (0..1024).find(|n| size(*n) == 1024).unwrap();
    for (payload, success) in [(vec![0; n], true), (vec![0; n + 1], false)] {
        let authority = AuthorityFixture::new(0);
        let (client, host) = pair(authority.clone(), payload.clone(), true).await;
        let result = client.conn.call(METHOD, vec![], 1000).await;
        if success {
            assert_eq!(result.unwrap(), payload);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(
            authority.commits.load(Ordering::SeqCst),
            usize::from(success)
        );
        client.close().await;
        host.close().await;
    }
}

/// Wire cancellation before selection aborts despite a visible durable owner.
#[tokio::test]
async fn cancellation_before_selection_aborts_even_when_commit_is_visible() {
    let authority = AuthorityFixture::new(5);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    let conn = client.conn.clone();
    let call = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.committed.notified().await;
    call.abort(); // dropped Initiator call sends the existing correlated cancel
    closed(&host).await;
    authority.release.notify_one();
    assert!(client.conn.next_notification().await.is_none());
    client.close().await;
    host.close().await;
}

/// A superseding denial during the commit-return gap wins over owned evidence.
#[tokio::test]
async fn superseding_denial_in_commit_return_gap_wins() {
    let authority = AuthorityFixture::new(5);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    let conn = client.conn.clone();
    let call = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.committed.notified().await;
    authority.state.lock().unwrap().2 = true;
    closed(&host).await;
    authority.release.notify_one();
    assert!(call.await.unwrap().is_err());
    client.close().await;
    host.close().await;
}

/// Controlled real stream; only raw host writes pause, so inbound cancellation
/// and the typed authority watchdog remain live during partial output.
struct Controlled<S> {
    stream: S,
    gate: Arc<Gate>,
}
#[derive(Default)]
/// Bound raw write progress without suspending the reader or authority watchdog.
struct Gate {
    state: Mutex<Option<usize>>,
    waker: futures_util::task::AtomicWaker,
    blocked: Notify,
    trace: Mutex<Option<Arc<EventTrace>>>,
}
impl Gate {
    /// Forward optional diagnostics without influencing protocol time.
    fn record(&self, event: &'static str, count: usize) {
        if let Some(trace) = self.trace.lock().unwrap().as_ref() {
            trace.record(event, count);
        }
    }
    /// Permit exactly this many raw bytes before returning Pending.
    fn pause_after(&self, n: usize) {
        self.record("gate.arm", n);
        *self.state.lock().unwrap() = Some(n);
    }
    /// Restore raw writability and wake the same retained I/O future.
    fn release(&self) {
        self.record("gate.release", 0);
        *self.state.lock().unwrap() = None;
        self.waker.wake();
    }
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Controlled<S> {
    /// Forward inbound reads independently of the controlled write gate.
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Controlled<S> {
    /// Hand off at most the remaining allowance and record actual byte progress.
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.gate.waker.register(cx.waker());
        let mut state = this.gate.state.lock().unwrap();
        let n = state.map_or(bytes.len(), |n| n.min(bytes.len()));
        if n == 0 {
            this.gate.record("write.blocked", 0);
            this.gate.blocked.notify_one();
            return std::task::Poll::Pending;
        }
        let result = std::pin::Pin::new(&mut this.stream).poll_write(cx, &bytes[..n]);
        if let std::task::Poll::Ready(Ok(written)) = result {
            this.gate.record("write.bytes", written);
            if let Some(n) = state.as_mut() {
                *n -= written;
            }
        }
        result
    }
    /// Forward flushes without changing the raw-byte allowance.
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    /// Forward shutdown to the underlying stream.
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
/// Use a controlled real TCP writer with the normal native elapsed source.
async fn controlled_pair(
    authority: Arc<AuthorityFixture>,
    gate: Arc<Gate>,
) -> (tcp::ClientHandle, tcp::HostHandle) {
    controlled_pair_with_clock(authority, gate, None).await
}

/// Supply one explicit elapsed domain to both real TCP peers only when a test
/// drives its clock. Ordinary tests keep their native suspend-inclusive clocks.
async fn controlled_pair_with_clock(
    authority: Arc<AuthorityFixture>,
    gate: Arc<Gate>,
    clock: Option<ElapsedClock>,
) -> (tcp::ClientHandle, tcp::HostHandle) {
    controlled_pair_with_handler_and_clock(authority, gate, clock, Arc::new(AllowAll(Retire))).await
}

/// Keep the same TCP/clock setup while selecting a synchronized application handler.
async fn controlled_pair_with_handler_and_clock(
    authority: Arc<AuthorityFixture>,
    gate: Arc<Gate>,
    clock: Option<ElapsedClock>,
    handler: Arc<dyn Handler>,
) -> (tcp::ClientHandle, tcp::HostHandle) {
    *gate.trace.lock().unwrap() = Some(authority.trace.clone());
    let (client, server) = configs();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let host_clock = clock.clone();
    let accept = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tcp::accept_stream(
            Controlled { stream, gate },
            &server,
            Arc::new(Factory {
                authority,
                payload: b"retired".to_vec(),
                enabled: true,
                clock: host_clock,
            }),
            handler,
            ConnectionConfig {
                writer_capacity: 1,
                ..Default::default()
            },
            Limits::default(),
        )
        .await
    });
    let client = if let Some(clock) = clock {
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.set_nodelay(true).unwrap();
        let limits = Limits::default();
        let budget =
            syntra_net::pump::EstablishmentBudget::new(clock, limits.attempt_timeout).unwrap();
        tcp::connect_stream_with_budget(
            stream,
            client,
            b"fixture".to_vec(),
            ConnectionConfig::default(),
            limits,
            budget,
        )
        .await
        .unwrap()
    } else {
        tcp::connect(
            address,
            client,
            b"fixture".to_vec(),
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
        .unwrap()
    };
    (client, accept.await.unwrap().unwrap())
}

/// Paused Tokio clocks normally auto-advance when real sockets are pending. Keep
/// one ready task until joined so only explicit advance() changes test time.
struct ManualTime {
    clock: ElapsedClock,
    awake: Option<tokio::task::JoinHandle<()>>,
}
impl ManualTime {
    /// Prevent idle Tokio auto-advance while the test drives real sockets.
    fn new() -> Self {
        Self {
            clock: ElapsedClock::lifecycle_driven(),
            awake: Some(tokio::spawn(async {
                loop {
                    tokio::task::yield_now().await;
                }
            })),
        }
    }
    /// Cancel and join the ready task before leaving the test runtime.
    async fn finish(mut self) {
        let awake = self.awake.take().unwrap();
        awake.abort();
        assert!(awake.await.unwrap_err().is_cancelled());
    }
}
impl Drop for ManualTime {
    /// Stop the ready task if the test exits before explicit joined cleanup.
    fn drop(&mut self) {
        if let Some(awake) = &self.awake {
            awake.abort();
        }
    }
}

/// Bound fixture progress in wall time even when ManualTime prevents timer advance.
async fn wait_for_fixture_state(ready: impl Fn() -> bool, message: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !ready() {
        assert!(std::time::Instant::now() < deadline, "{message}");
        tokio::task::yield_now().await;
    }
}

/// Prompt authority survives six idle refreshes with a simulated 15 ms wakeup
/// delay at the minimum policy bound, but a full missed freshness window still fences.
#[tokio::test(start_paused = true)]
async fn idle_minimum_bound_refreshes_with_timer_margin_then_expires_exactly() {
    let time = ManualTime::new();
    let authority = AuthorityFixture::new(0);
    let (client, host) = controlled_pair_with_clock(
        authority.clone(),
        Arc::new(Gate::default()),
        Some(time.clock.clone()),
    )
    .await;
    let coordinator = host.host.terminal_coordinator().unwrap();
    assert_eq!(coordinator.read_timeout(), Duration::from_millis(100));
    // Settle the owner's initial watchdog read at t=0.
    tokio::task::yield_now().await;
    for _ in 0..6 {
        let before = authority.reads.load(Ordering::SeqCst);
        tokio::time::advance(Duration::from_millis(65)).await;
        let wall_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while authority.reads.load(Ordering::SeqCst) == before && !host.is_closed() {
            assert!(
                std::time::Instant::now() < wall_deadline,
                "watchdog did not refresh"
            );
            tokio::task::yield_now().await;
        }
        assert!(!host.is_closed());
        assert!(coordinator.raw_allowed());
        assert!(authority.reads.load(Ordering::SeqCst) > before);
    }
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(
        !coordinator.raw_allowed(),
        "exact freshness tie fails closed"
    );
    assert!(
        coordinator.refresh().await.is_err(),
        "prompt late evidence cannot revive authority"
    );
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    client.close().await;
    host.close().await;
    time.finish().await;
}

/// Real idle TCP stays open and completes retirement with native elapsed time.
/// The driven-clock test above checks minimum-bound refresh counts and expiry.
#[tokio::test]
async fn real_idle_minimum_bound_refreshes_before_retirement() {
    let authority = AuthorityFixture::new(0);
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    assert!(!host.is_closed());
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    assert_eq!(
        client.conn.call(METHOD, vec![], 2000).await.unwrap(),
        b"retired"
    );
    closed(&host).await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
    client.close().await;
    host.close().await;
}

/// A full multi-record ordinary frame finishes before commit; queued output is dropped.
#[tokio::test(start_paused = true)]
async fn partial_ordinary_frame_finishes_before_commit_and_queued_notifications_drop() {
    let time = ManualTime::new();
    let authority = AuthorityFixture::new(0);
    let gate = Arc::new(Gate::default());
    let (client, host) =
        controlled_pair_with_clock(authority.clone(), gate.clone(), Some(time.clock.clone())).await;
    let started = time.clock.now();
    gate.pause_after(11);
    let conn = client.conn.clone();
    let ordinary = tokio::spawn(async move {
        conn.call("/example.Authority/Echo", vec![42; 200_000], 2000)
            .await
    });
    gate.blocked.notified().await;
    host.host.notify(b"must-not-escape".to_vec()).await.unwrap();
    let conn = client.conn.clone();
    let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.reserved.notified().await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    assert_eq!(
        time.clock.now(),
        started,
        "CPU load/socket waits cannot spend the success case's elapsed budget"
    );
    gate.release();
    let result = ordinary.await.unwrap().unwrap_or_else(|error| {
        panic!(
            "ordinary result {error:?}; commits={}; events={:?}",
            authority.commits.load(Ordering::SeqCst),
            authority.trace.events.lock().unwrap()
        )
    });
    assert_eq!(result, vec![42; 200_000]);
    assert_eq!(receipt.await.unwrap().unwrap(), b"retired");
    assert!(client.conn.next_notification().await.is_none());
    // Prove the barrier waited for every record, not just the initially blocked
    // record. Count actual underlying TCP bytes handed off before commit entry.
    let plaintext = 4 + prost::Message::encoded_len(&syntra_core::Frame {
        version: client.version,
        request_id: 1,
        body: Some(syntra_core::proto::frame::Body::Result(
            syntra_core::RpcResult {
                outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(result)),
            },
        )),
    });
    let expected_wire_bytes =
        plaintext + plaintext.div_ceil(MAX_PLAINTEXT) * (2 + MAX_CIPHERTEXT - MAX_PLAINTEXT);
    {
        let events = authority.trace.events.lock().unwrap();
        let arm = events
            .iter()
            .position(|(_, event, _)| *event == "gate.arm")
            .unwrap();
        let commit = events
            .iter()
            .position(|(_, event, _)| *event == "commit")
            .unwrap();
        let written_before_commit: usize = events[arm..commit]
            .iter()
            .filter(|(_, event, _)| *event == "write.bytes")
            .map(|(_, _, bytes)| bytes)
            .sum();
        assert_eq!(
            written_before_commit, expected_wire_bytes,
            "all ordinary record prefixes/ciphertext must finish before authority mutation"
        );
    }
    closed(&host).await;
    client.close().await;
    host.close().await;
    time.finish().await;
}

/// Exact whole-frame write expiry aborts without commit even with fresh authority.
#[tokio::test(start_paused = true)]
async fn partial_ordinary_frame_exact_write_cutoff_aborts_before_commit_with_fresh_authority() {
    let time = ManualTime::new();
    let authority = AuthorityFixture::new(0);
    let gate = Arc::new(Gate::default());
    let (client, host) =
        controlled_pair_with_clock(authority.clone(), gate.clone(), Some(time.clock.clone())).await;
    gate.pause_after(11);
    let conn = client.conn.clone();
    let ordinary = tokio::spawn(async move {
        conn.call("/example.Authority/Echo", vec![42; 200_000], 2000)
            .await
    });
    gate.blocked.notified().await;
    host.host.notify(b"must-not-escape".to_vec()).await.unwrap();
    let conn = client.conn.clone();
    let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.reserved.notified().await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    assert!(host.host.terminal_coordinator().unwrap().raw_allowed());
    let started = time.clock.now();
    // The ordinary frame's inherited authorization interval is 100ms / 2.
    // At this exact 50ms tie, typed authority is still fresh (100ms), and the
    // receipt's 2s request deadline/teardown tail has not expired.
    tokio::time::advance(Duration::from_millis(50)).await;
    gate.release();
    assert!(ordinary.await.unwrap().is_err());
    assert!(receipt.await.unwrap().is_err());
    assert_eq!(
        time.clock.now().duration_since(started),
        Duration::from_millis(50)
    );
    assert_eq!(
        authority.commits.load(Ordering::SeqCst),
        0,
        "a partial expired ordinary frame must never acknowledge the commit barrier"
    );
    assert!(authority.state.lock().unwrap().1.is_none());
    assert!(client.conn.next_notification().await.is_none());
    assert!(host.is_closed());
    client.close().await;
    host.close().await;
    time.finish().await;
}

/// Stalled ordinary ciphertext cannot be spliced with a terminal result or trigger commit.
#[tokio::test]
async fn stalled_partial_frame_aborts_without_mutation_or_receipt_splice() {
    let authority = AuthorityFixture::new(0);
    let gate = Arc::new(Gate::default());
    let (client, host) = controlled_pair(authority.clone(), gate.clone()).await;
    gate.pause_after(11);
    let conn = client.conn.clone();
    let ordinary = tokio::spawn(async move {
        conn.call("/example.Authority/Echo", vec![42; 200_000], 2000)
            .await
    });
    gate.blocked.notified().await;
    assert!(client.conn.call(METHOD, vec![], 400).await.is_err());
    closed(&host).await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    gate.release();
    assert!(ordinary.await.unwrap().is_err());
    client.close().await;
    host.close().await;
}

/// External denial blocks the remainder of a partially handed-off receipt.
#[tokio::test]
async fn partial_receipt_is_not_reencrypted_and_external_denial_aborts_remainder() {
    let authority = AuthorityFixture::new(0);
    let gate = Arc::new(Gate::default());
    let (client, host) = controlled_pair(authority.clone(), gate.clone()).await;
    gate.pause_after(11);
    let conn = client.conn.clone();
    let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 1000).await });
    gate.blocked.notified().await;
    assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
    authority.state.lock().unwrap().2 = true;
    closed(&host).await;
    gate.release();
    assert!(receipt.await.unwrap().is_err());
    client.close().await;
    host.close().await;
}

/// Temporary backpressure resumes the same ciphertext sequence exactly once.
#[tokio::test]
async fn partial_receipt_completes_same_encrypted_stream_after_backpressure() {
    let authority = AuthorityFixture::new(0);
    let gate = Arc::new(Gate::default());
    let (client, host) = controlled_pair(authority.clone(), gate.clone()).await;
    gate.pause_after(11);
    let conn = client.conn.clone();
    let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 1000).await });
    gate.blocked.notified().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    gate.release();
    assert_eq!(receipt.await.unwrap().unwrap(), b"retired");
    closed(&host).await;
    client.close().await;
    host.close().await;
}

/// Custom record adapters refuse terminal policy before any handler effects.
#[tokio::test]
async fn custom_record_driver_refuses_policy_before_handler_effects() {
    let authority = AuthorityFixture::new(0);
    let (client_config, server) = configs();
    let (left, right) = tokio::io::duplex(4096);
    let (read, write) = tokio::io::split(right);
    let a = authority.clone();
    let accept = tokio::spawn(async move {
        syntra_net::pump::accept_records(
            tcp::StreamReader(read),
            tcp::StreamWriter(write),
            &server,
            Arc::new(Factory {
                authority: a,
                payload: b"retired".to_vec(),
                enabled: true,
                clock: None,
            }),
            Arc::new(AllowAll(Retire)),
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
    });
    assert!(tcp::connect_stream(
        left,
        client_config,
        b"fixture".to_vec(),
        ConnectionConfig::default(),
        Limits::default()
    )
    .await
    .is_err());
    assert!(matches!(
        accept.await.unwrap(),
        Err(syntra_net::pump::Error::Configuration)
    ));
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
}

/// Handle loss and write stall both retire without reconnecting or replaying mutation.
#[tokio::test]
async fn dropped_handle_and_stalled_receipt_retire_without_replay() {
    for drop_handle in [false, true] {
        let authority = AuthorityFixture::new(0);
        let gate = Arc::new(Gate::default());
        let (client, host) = controlled_pair(authority.clone(), gate.clone()).await;
        let retained = host.host.clone();
        gate.pause_after(11);
        let conn = client.conn.clone();
        let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 400).await });
        gate.blocked.notified().await;
        if drop_handle {
            drop(host);
        } else {
            closed(&host).await;
            host.close().await;
        }
        assert!(receipt.await.unwrap().is_err());
        assert!(retained.is_closed());
        assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
        gate.release();
        assert!(client.conn.call(METHOD, vec![], 1000).await.is_err());
        client.close().await;
    }
}

/// Completed sibling work cannot escape the fence while own commit waits to return.
#[tokio::test(start_paused = true)]
async fn sibling_completion_during_owned_commit_gap_has_no_delivery_permission() {
    let time = ManualTime::new();
    let authority = AuthorityFixture::new(5);
    let sibling_control = HeldSibling::default();
    let (client, host) = controlled_pair_with_handler_and_clock(
        authority.clone(),
        Arc::new(Gate::default()),
        Some(time.clock.clone()),
        Arc::new(AllowAll(sibling_control.clone())),
    )
    .await;
    let started = time.clock.now();
    let conn = client.conn.clone();
    let sibling = tokio::spawn(async move {
        conn.call("/example.Authority/Slow", b"protected".to_vec(), 2000)
            .await
    });
    sibling_control.started.notified().await;
    let conn = client.conn.clone();
    let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.committed.notified().await;
    let coordinator = host.host.terminal_coordinator().unwrap();
    coordinator.refresh().await.unwrap();
    assert!(!coordinator.ordinary_allowed());
    assert_eq!(host.host.worker_len(), 2);
    sibling_control.release.notify_one();
    wait_for_fixture_state(
        || host.host.worker_len() == 1,
        "sibling must finish host selection and fenced emission",
    )
    .await;
    assert_eq!(host.host.inflight_len(), 1);
    assert!(!host.is_closed());
    assert!(coordinator.raw_allowed());
    assert!(!receipt.is_finished(), "callback completion still required");
    assert!(
        !sibling.is_finished(),
        "fenced sibling success must never escape"
    );
    assert_eq!(
        time.clock.now(),
        started,
        "fixture waits cannot spend freshness"
    );
    authority.release.notify_one();
    assert_eq!(receipt.await.unwrap().unwrap(), b"retired");
    assert!(sibling.await.unwrap().is_err());
    assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
    client.close().await;
    host.close().await;
    time.finish().await;
}

/// Exact freshness expiry during owned commit is sticky despite late callback return.
#[tokio::test(start_paused = true)]
async fn owned_commit_gap_exact_freshness_expiry_cannot_be_revived() {
    let time = ManualTime::new();
    let authority = AuthorityFixture::new(5);
    let (client, host) = controlled_pair_with_clock(
        authority.clone(),
        Arc::new(Gate::default()),
        Some(time.clock.clone()),
    )
    .await;
    let conn = client.conn.clone();
    let receipt = tokio::spawn(async move { conn.call(METHOD, vec![], 2000).await });
    authority.committed.notified().await;
    let coordinator = host.host.terminal_coordinator().unwrap();
    coordinator.refresh().await.unwrap();
    assert!(coordinator.raw_allowed());
    assert!(!coordinator.ordinary_allowed());
    assert!(!receipt.is_finished());
    let reads = authority.reads.load(Ordering::SeqCst);
    let started = time.clock.now();
    tokio::time::advance(coordinator.read_timeout()).await;
    assert_eq!(time.clock.now() - started, Duration::from_millis(100));
    assert!(
        !coordinator.raw_allowed(),
        "exact freshness tie fails closed"
    );
    assert!(coordinator.refresh().await.is_err());
    assert_eq!(authority.reads.load(Ordering::SeqCst), reads);
    wait_for_fixture_state(|| host.is_closed(), "expired owned gap must close").await;
    assert_eq!(
        receipt.await.unwrap().unwrap_err().code(),
        syntra_core::ErrorCode::Unavailable
    );
    assert_eq!(host.host.execution_len(), 1, "commit work remains owned");
    authority.release.notify_one();
    wait_for_fixture_state(
        || host.host.execution_len() == 0,
        "released authority work must finish",
    )
    .await;
    assert!(
        coordinator.refresh().await.is_err(),
        "late return cannot revive proof"
    );
    assert!(!coordinator.raw_allowed());
    assert!(host.is_closed());
    assert_eq!(authority.commits.load(Ordering::SeqCst), 1);
    client.close().await;
    host.close().await;
    time.finish().await;
}

/// A changed active revision prevents conditional mutation after reservation.
#[tokio::test]
async fn expected_revision_mismatch_aborts_before_conditional_mutation() {
    let authority = AuthorityFixture::new(0);
    authority.state.lock().unwrap().0 = 2;
    let (client, host) = pair(authority.clone(), b"retired".to_vec(), true).await;
    assert!(client.conn.call(METHOD, vec![], 1000).await.is_err());
    assert_eq!(authority.commits.load(Ordering::SeqCst), 0);
    closed(&host).await;
    client.close().await;
    host.close().await;
}

/// Returning admission reads authority; only verified refusal records denial evidence.
struct ReturningFixture {
    authority: Arc<AuthorityFixture>,
    handlers: AtomicUsize,
    denials: AtomicUsize,
}
impl ReturningFixture {
    /// Start with one active binding and no operation or refusal observations.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            authority: AuthorityFixture::new(0),
            handlers: AtomicUsize::new(0),
            denials: AtomicUsize::new(0),
        })
    }

    /// Reuse the receipt suite's authentication and typed authority policy.
    fn factory(&self) -> Arc<Factory> {
        Arc::new(Factory {
            authority: self.authority.clone(),
            payload: b"retired".to_vec(),
            enabled: true,
            clock: None,
        })
    }
}
impl KeyStore for ReturningFixture {
    /// Look up only the exact active handle/epoch, without recording evidence.
    fn lookup(&self, context: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        if context.handle != [7; 8]
            || context.epoch != 2
            || self.authority.state.lock().unwrap().1.is_some()
        {
            return Err(syntra_core::secure_channel::Error::Authentication);
        }
        Ok(Secret32::new([8; 32]))
    }
}

/// Count actual handler admission while retaining the existing retirement behavior.
struct ReturningRetire(Arc<ReturningFixture>);
impl Handler for ReturningRetire {
    /// Forward the legacy handler without manufacturing a request context.
    fn handle(&self, method: String, payload: Vec<u8>, cancel: CancelToken) -> HandlerFut {
        Retire.handle(method, payload, cancel)
    }

    /// Count context-aware dispatch before delegating to the suite's handler.
    fn handle_with_context(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: CancelToken,
        lease: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        self.0.handlers.fetch_add(1, Ordering::SeqCst);
        Retire.handle_with_context(method, payload, cancel, lease, context)
    }
}

/// Fix one public test binding independently of each freshly generated server key.
fn returning_context() -> Context {
    Context {
        mode: Mode::Returning,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"terminal-fixture".to_vec(),
        handle: [7; 8],
        epoch: 2,
    }
}

/// Reuse native key generation with a Returning key store and matching client key.
fn returning_configs(fixture: Arc<ReturningFixture>) -> (ClientConfig, ServerConfig) {
    let (mut client, mut server) = configs();
    client.context = returning_context();
    client.authorization_key = Some(Secret32::new([8; 32]));
    server.mode = Mode::Returning;
    server.store = Some(fixture);
    (client, server)
}

/// Inspect and replay the bounded first message through native acceptance; count
/// only an exact withdrawn-binding refusal after one handler and one commit.
async fn returning_probe(
    listener: &tcp::Listener,
    server: &ServerConfig,
    fixture: Arc<ReturningFixture>,
    requested: Context,
    key: [u8; 32],
    public: [u8; 32],
) -> bool {
    use syntra_net::pump::RecordReader;
    use tokio::io::AsyncReadExt;

    let accept = async {
        let stream = listener.accept_socket().await.unwrap();
        let (read, write) = tokio::io::split(stream);
        let mut reader = tcp::StreamReader(read);
        let first = reader.read_record(MAX_WRAPPER).await.unwrap();
        let (actual, _) = Context::parse_first(&first).unwrap();
        let mut prefix = (first.len() as u16).to_be_bytes().to_vec();
        prefix.extend_from_slice(&first);
        let stream = tokio::io::join(std::io::Cursor::new(prefix).chain(reader.0), write);
        let result = tcp::accept_stream(
            stream,
            server,
            fixture.factory(),
            Arc::new(AllowAll(ReturningRetire(fixture.clone()))),
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await;
        match result {
            Err(syntra_net::Error::Channel(syntra_core::secure_channel::Error::Authentication)) => {
            }
            Ok(host) => {
                host.close().await;
                panic!("refused Returning attempt unexpectedly established");
            }
            Err(error) => panic!("expected native authentication refusal, got {error:?}"),
        }
        actual
    };
    let connect = tcp::connect(
        listener.local_addr().unwrap(),
        ClientConfig {
            context: requested,
            server_public_key: public,
            authorization_key: Some(Secret32::new(key)),
        },
        b"fixture".to_vec(),
        ConnectionConfig::default(),
        Limits::default(),
    );
    let (actual, connected) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(accept, connect)
    })
    .await
    .unwrap();
    assert!(connected.is_err(), "refused attempt must never establish");
    let withdrawn = actual == returning_context()
        && fixture.authority.state.lock().unwrap().1.is_some()
        && fixture.authority.commits.load(Ordering::SeqCst) == 1
        && fixture.handlers.load(Ordering::SeqCst) == 1;
    if withdrawn {
        fixture.denials.fetch_add(1, Ordering::SeqCst);
    }
    withdrawn
}

/// Wrong-key native authentication refusal does not prove an active binding withdrew.
#[tokio::test]
async fn wrong_key_failure_is_not_withdrawn_binding_evidence() {
    let fixture = ReturningFixture::new();
    let (client, server) = returning_configs(fixture.clone());
    let listener = tcp::Listener::bind("127.0.0.1:0", 2).await.unwrap();
    assert!(
        !returning_probe(
            &listener,
            &server,
            fixture.clone(),
            returning_context(),
            [9; 32],
            client.server_public_key,
        )
        .await
    );
    assert_eq!(fixture.denials.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.handlers.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.authority.commits.load(Ordering::SeqCst), 0);
    assert!(fixture.authority.state.lock().unwrap().1.is_none());
    assert_eq!(
        *fixture.lookup(&returning_context()).unwrap().expose(),
        [8; 32]
    );
}

/// Lookup validates handle/epoch without effects; only a real exact-binding
/// refusal after retirement counts, and no refused attempt reaches the handler.
#[tokio::test]
async fn lookup_is_pure_and_validates_the_requested_binding() {
    let fixture = ReturningFixture::new();
    assert_eq!(
        *fixture.lookup(&returning_context()).unwrap().expose(),
        [8; 32]
    );
    let mut wrong_handle = returning_context();
    wrong_handle.handle = [9; 8];
    let mut wrong_epoch = returning_context();
    wrong_epoch.epoch += 1;
    for requested in [&wrong_handle, &wrong_epoch] {
        assert!(fixture.lookup(requested).is_err());
    }
    let (client, server) = returning_configs(fixture.clone());
    let public = client.server_public_key;
    let listener = tcp::Listener::bind("127.0.0.1:0", 2).await.unwrap();
    let (accepted, connected) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(
            listener.accept(
                &server,
                fixture.factory(),
                Arc::new(AllowAll(ReturningRetire(fixture.clone()))),
                ConnectionConfig::default(),
                Limits::default(),
            ),
            tcp::connect(
                listener.local_addr().unwrap(),
                client,
                b"fixture".to_vec(),
                ConnectionConfig::default(),
                Limits::default(),
            )
        )
    })
    .await
    .unwrap();
    let (host, client) = (accepted.unwrap(), connected.unwrap());
    assert_eq!(
        client.conn.call(METHOD, vec![], 2000).await.unwrap(),
        b"retired"
    );
    for requested in [&returning_context(), &wrong_handle, &wrong_epoch] {
        assert!(fixture.lookup(requested).is_err());
    }
    assert_eq!(
        fixture.denials.load(Ordering::SeqCst),
        0,
        "lookup records no evidence"
    );
    client.close().await;
    host.close().await;
    for requested in [wrong_handle, wrong_epoch] {
        assert!(
            !returning_probe(
                &listener,
                &server,
                fixture.clone(),
                requested,
                [8; 32],
                public
            )
            .await
        );
        assert_eq!(fixture.denials.load(Ordering::SeqCst), 0);
    }
    assert!(
        returning_probe(
            &listener,
            &server,
            fixture.clone(),
            returning_context(),
            [8; 32],
            public
        )
        .await
    );
    assert_eq!(fixture.denials.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.handlers.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.authority.commits.load(Ordering::SeqCst), 1);
}
