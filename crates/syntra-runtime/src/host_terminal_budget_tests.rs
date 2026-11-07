//! Cooperative authority budgets and retained work after request-wide expiry.
use super::*;
use std::sync::atomic::AtomicUsize;

const METHOD: &str = "/example.Authority/Retire";

/// Observe every passed deadline and optionally delay the actual mutation.
struct BudgetAuthority {
    reads: Mutex<Vec<ElapsedDeadline>>,
    commits: Mutex<Vec<ElapsedDeadline>>,
    owner: Mutex<Option<Transition>>,
    hold: bool,
    entered: Notify,
    release: Notify,
    effects: AtomicUsize,
}
impl Authority for BudgetAuthority {
    fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
        panic!("budget-aware observation must be used")
    }
    fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
        panic!("budget-aware commit must be used")
    }
    fn observe_with_budget(
        &self,
        _: Option<Transition>,
        budget: ElapsedDeadline,
    ) -> BoxFuture<'_, Observation> {
        assert!(budget.remaining().unwrap() <= Duration::from_millis(100));
        self.reads.lock().unwrap().push(budget);
        Box::pin(async {
            match self.owner.lock().unwrap().as_ref() {
                Some(c) => Observation::OwnedCommitted {
                    reservation: c.reservation.clone(),
                    expected_revision: c.expected_revision,
                    revision: c.expected_revision + 1,
                },
                None => Observation::Active { revision: 7 },
            }
        })
    }
    fn commit_with_budget(
        &self,
        transition: Transition,
        _lease: ExecutionLease,
        budget: ElapsedDeadline,
    ) -> BoxFuture<'_, ()> {
        assert_eq!(budget.remaining(), Ok(Duration::from_millis(720)));
        self.commits.lock().unwrap().push(budget);
        self.entered.notify_one();
        Box::pin(async move {
            if self.hold {
                self.release.notified().await;
            }
            // Deliberately uncooperative fixture: a deadline cannot roll this back.
            *self.owner.lock().unwrap() = Some(transition);
            self.effects.fetch_add(1, Ordering::SeqCst);
        })
    }
}

/// Select one second from original receipt and retire through the actual context.
struct BudgetRetire;
impl Handler for BudgetRetire {
    fn request_budget(&self, _: &Principal, _: &str, _: &[u8]) -> Option<Duration> {
        Some(Duration::from_secs(1))
    }
    fn authorize_with_budget(
        &self,
        _: &Principal,
        _: &str,
        budget: ElapsedDeadline,
    ) -> Result<(), AuthError> {
        assert_eq!(budget.remaining(), Ok(Duration::from_millis(960)));
        Ok(())
    }
    fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
        panic!("context required")
    }
    fn handle_with_context(
        &self,
        _: String,
        _: Vec<u8>,
        _: crate::CancelToken,
        _: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        assert_eq!(context.budget().remaining(), Ok(Duration::from_millis(960)));
        Box::pin(async move {
            context.retire(7).await.unwrap_or_else(|_| {
                HandlerOutcome::error(ErrorCode::Unavailable, "retirement unavailable")
            })
        })
    }
}

async fn fixture(
    hold: bool,
) -> (
    Arc<Host>,
    Arc<Coordinator>,
    Arc<BudgetAuthority>,
    mpsc::Receiver<DriverCommand>,
    Instant,
) {
    let (host, mut ordinary) = Host::new(
        ConnectionConfig::default(),
        Arc::new(crate::StaticToken::new(
            b"fixture".to_vec(),
            "fixture-principal",
        )),
        Arc::new(BudgetRetire),
    );
    let authority = Arc::new(BudgetAuthority {
        reads: Mutex::new(vec![]),
        commits: Mutex::new(vec![]),
        owner: Mutex::new(None),
        hold,
        entered: Notify::new(),
        release: Notify::new(),
        effects: AtomicUsize::new(0),
    });
    let c = host
        .install_terminal_tcp(Policy {
            method: METHOD.into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
        .unwrap();
    c.refresh().await.unwrap();
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::proto::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: b"fixture".to_vec(),
            })),
        }
        .encode_to_vec(),
    )
    .await;
    ordinary.recv().await.unwrap();
    let origin = host.elapsed_clock().now();
    tokio::time::advance(Duration::from_millis(40)).await;
    host.ingest_received_at(
        &Frame {
            version: 1,
            request_id: 123,
            body: Some(Body::Request(RpcRequest {
                method: METHOD.into(),
                payload: vec![],
                timeout_ms: 10_000,
            })),
        }
        .encode_to_vec(),
        origin,
    )
    .await;
    let mut commands = host.take_terminal_commands().unwrap();
    match tokio::time::timeout(Duration::from_secs(2), commands.recv())
        .await
        .expect("retirement must reach the barrier")
        .unwrap()
    {
        DriverCommand::Barrier(ack) => ack.send(()).unwrap(),
        _ => panic!("barrier must precede commit"),
    }
    tokio::time::timeout(Duration::from_secs(2), authority.entered.notified())
        .await
        .expect("retirement must enter authority commit");
    assert_eq!(c.deadline(), Some(origin + Duration::from_secs(1)));
    assert_eq!(c.cutoff(), Some(origin + Duration::from_millis(760)));
    (host, c, authority, commands, origin)
}

/// Authority callbacks receive the derived cutoff/read bounds on the same clock.
#[tokio::test(start_paused = true)]
async fn request_wide_budget_reaches_terminal_observe_commit_and_receipt() {
    let (host, c, authority, mut commands, _) = fixture(false).await;
    let Some(DriverCommand::Receipt(output)) = commands.recv().await else {
        panic!("exact successful receipt expected")
    };
    c.consume(&output).unwrap();
    assert_eq!(authority.effects.load(Ordering::SeqCst), 1);
    assert_eq!(authority.commits.lock().unwrap().len(), 1);
    assert_eq!(authority.reads.lock().unwrap().len(), 4);
    c.written();
    drop(output);
    host.close().await;
}

/// Expiry fences output but keeps actual mutation charged until it really ends.
#[tokio::test(start_paused = true)]
async fn request_wide_expiry_retains_late_commit_charge_without_receipt() {
    let (host, c, authority, mut commands, _) = fixture(true).await;
    assert_eq!(host.execution_len(), 1);
    tokio::time::advance(Duration::from_millis(720)).await;
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(!c.raw_allowed());
    assert_eq!(
        host.execution_len(),
        1,
        "timeout cannot release retained authority work"
    );
    assert!(authority.commits.lock().unwrap()[0].check().is_err());
    assert_eq!(authority.effects.load(Ordering::SeqCst), 0);
    authority.release.notify_one();
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        authority.effects.load(Ordering::SeqCst),
        1,
        "late commit remains possible"
    );
    assert_eq!(host.execution_len(), 0);
    assert!(
        commands.try_recv().is_err(),
        "no receipt for a late durable effect"
    );
    assert_eq!(c.refresh().await, Err(Refused::Unavailable));
    host.close().await;
}

/// A fresh read near the operation cutoff gets only its remaining slice.
#[tokio::test(start_paused = true)]
async fn request_wide_observation_budget_is_clamped_to_remaining_cutoff() {
    let (host, c, authority, mut commands, _) = fixture(true).await;
    for _ in 0..8 {
        tokio::time::advance(Duration::from_millis(80)).await;
        c.refresh().await.unwrap();
    }
    tokio::time::advance(Duration::from_millis(60)).await;
    c.refresh().await.unwrap();
    assert_eq!(
        authority.reads.lock().unwrap().last().unwrap().remaining(),
        Ok(Duration::from_millis(20))
    );
    c.abort();
    authority.release.notify_one();
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert_eq!(host.execution_len(), 0);
    assert!(commands.try_recv().is_err());
    host.close().await;
}

/// An in-progress hard-denial callback must serialize before terminal reservation.
#[tokio::test(start_paused = true)]
async fn racing_authorization_hard_denial_cannot_be_swallowed_by_terminal_reservation() {
    /// Hold authorization on a separate thread, as in the existing slow-policy
    /// regression `expiry_during_synchronous_authorization_prevents_handler_effects`.
    /// Only this test barrier deliberately violates the nonblocking contract.
    struct SlowDenial {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        context: Mutex<Option<oneshot::Sender<RequestContext>>>,
        result: Mutex<Option<oneshot::Receiver<HandlerOutcome>>>,
    }
    impl Handler for SlowDenial {
        fn request_budget(&self, _: &Principal, _: &str, _: &[u8]) -> Option<Duration> {
            Some(Duration::from_secs(3))
        }
        fn authorize(&self, _: &Principal, method: &str) -> Result<(), AuthError> {
            if method == METHOD {
                return Ok(());
            }
            self.started
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            self.release.lock().unwrap().recv().unwrap();
            Err(AuthError::unauthenticated())
        }
        fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            panic!("context hook required")
        }
        fn handle_with_context(
            &self,
            method: String,
            _: Vec<u8>,
            _: crate::CancelToken,
            _: ExecutionLease,
            context: RequestContext,
        ) -> HandlerFut {
            assert_eq!(method, METHOD, "denied handler must never run");
            assert!(self
                .context
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(context)
                .is_ok());
            let result = self.result.lock().unwrap().take().unwrap();
            Box::pin(async move { result.await.unwrap() })
        }
    }
    /// Expose any improperly admitted transition as exact owned evidence.
    struct Owned(Mutex<Option<Transition>>);
    impl Authority for Owned {
        fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
            Box::pin(async {
                match self.0.lock().unwrap().as_ref() {
                    None => Observation::Active { revision: 7 },
                    Some(c) => Observation::OwnedCommitted {
                        reservation: c.reservation.clone(),
                        expected_revision: 7,
                        revision: 8,
                    },
                }
            })
        }
        fn commit(&self, claim: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
            Box::pin(async move { *self.0.lock().unwrap() = Some(claim) })
        }
    }
    let (started, observed) = oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let (capture, captured) = oneshot::channel();
    let (returned, result) = oneshot::channel();
    let (host, mut ordinary) = Host::new(
        ConnectionConfig::default(),
        Arc::new(crate::StaticToken::new(
            b"fixture".to_vec(),
            "fixture-principal",
        )),
        Arc::new(SlowDenial {
            started: Mutex::new(Some(started)),
            release: Mutex::new(released),
            context: Mutex::new(Some(capture)),
            result: Mutex::new(Some(result)),
        }),
    );
    let authority = Arc::new(Owned(Mutex::new(None)));
    let coordinator = host
        .install_terminal_tcp(Policy {
            method: METHOD.into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(100),
        })
        .unwrap();
    coordinator.refresh().await.unwrap();
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(syntra_core::proto::ClientHello {
                min_version: 1,
                max_version: 1,
                credential: b"fixture".to_vec(),
            })),
        }
        .encode_to_vec(),
    )
    .await;
    ordinary.recv().await.unwrap();
    let request = |id, method: &str| {
        Frame {
            version: 1,
            request_id: id,
            body: Some(Body::Request(RpcRequest {
                method: method.into(),
                payload: vec![],
                timeout_ms: 10_000,
            })),
        }
        .encode_to_vec()
    };
    host.ingest(&request(1, METHOD)).await;
    let context = captured.await.unwrap();
    let admission_host = host.clone();
    let runtime = tokio::runtime::Handle::current();
    let bytes = request(2, "/example.Authority/Check");
    let admission =
        tokio::task::spawn_blocking(move || runtime.block_on(admission_host.ingest(&bytes)));
    observed.await.unwrap();
    let mut retiring = Box::pin(async move {
        let outcome = context.retire(7).await;
        drop(context);
        outcome
    });
    assert!(futures_util::poll!(&mut retiring).is_pending());
    let crossed_authorization = coordinator.fenced();
    // Release before any assertion that could strand the blocking test callback.
    release.send(()).unwrap();
    let finish = async {
        let outcome = retiring.await;
        let succeeded = outcome.is_ok();
        let _ = returned.send(outcome.unwrap_or_else(|_| {
            HandlerOutcome::error(ErrorCode::Unavailable, "retirement unavailable")
        }));
        succeeded
    };
    let settled = async { tokio::join!(finish, admission) };
    tokio::pin!(settled);
    let mut commands = host.take_terminal_commands().unwrap();
    let mut receipts = 0;
    let succeeded = loop {
        tokio::select! {
            result = &mut settled => {
                result.1.unwrap();
                break result.0;
            }
            Some(command) = commands.recv() => match command {
                DriverCommand::Barrier(ack) => { let _ = ack.send(()); }
                DriverCommand::Receipt(_) => receipts += 1,
            }
        }
    };
    for _ in 0..1000 {
        if host.worker_len() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    while let Ok(command) = commands.try_recv() {
        if matches!(command, DriverCommand::Receipt(_)) {
            receipts += 1;
        }
    }
    let withdrawn = host.conn.shared.principal_withdrawn.load(Ordering::Acquire);
    let committed = authority.0.lock().unwrap().is_some();
    host.close().await;
    assert_eq!(
        (crossed_authorization, withdrawn, committed, succeeded, receipts),
        (false, true, false, false, 0),
        "reservation must wait for authorization; hard denial must withdraw without commit or receipt"
    );
}
