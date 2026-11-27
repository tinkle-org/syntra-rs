//! Cooperative authority budgets and retained work after request-wide expiry.
use super::*;
use std::sync::atomic::AtomicUsize;

const METHOD: &str = "/example.Authority/Retire";

/// Bound an async wait even while blocking work inhibits Tokio's paused clock.
async fn wall_clock_timeout<F: std::future::Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, &'static str> {
    let (stop, stopped) = std::sync::mpsc::channel::<()>();
    let (expired, expiry) = oneshot::channel();
    std::thread::Builder::new()
        .name("terminal-budget-watchdog".into())
        .spawn(move || {
            if matches!(
                stopped.recv_timeout(duration),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                let _ = expired.send(());
            }
        })
        .expect("wall-clock watchdog must start");
    let result = tokio::select! {
        biased;
        _ = expiry => Err("wall-clock watchdog expired or disconnected"),
        output = future => Ok(output),
    };
    // Also disarm on cancellation/unwind: the sender is local to this future.
    drop(stop);
    result
}

/// Preserve test panics without an unbounded runtime drop on blocking admission.
fn run_paused_test(shutdown_timeout: Duration, test: impl std::future::Future<Output = ()>) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("paused test runtime must start");
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(test)));
    // A started spawn_blocking task cannot be aborted. Bound the wait even if
    // releasing the fixture's channels during unwind cannot make it finish.
    runtime.shutdown_timeout(shutdown_timeout);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// Check admission unlocked without mistaking a transient output reader for it.
async fn assert_lifecycle_unlocked(state: &tokio::sync::RwLock<ConnectionState>) {
    // Retirement has settled, but the denied request's output worker may still
    // hold a read guard or have been granted one from the fair lock's queue.
    wall_clock_timeout(Duration::from_secs(2), async {
        drop(state.write().await);
    })
    .await
    .expect("the pause must not retain the lifecycle read guard");
}

/// A concurrent output reader is transient contention, not a retained admission guard.
#[tokio::test(start_paused = true)]
async fn lifecycle_unlock_probe_waits_for_transient_reader() {
    let state = tokio::sync::RwLock::new(ConnectionState::Active);
    let reader = state.read().await;
    let mut probe = Box::pin(assert_lifecycle_unlocked(&state));
    assert!(futures_util::poll!(&mut probe).is_pending());
    drop(reader);
    probe.await;
    assert!(
        state.try_write().is_ok(),
        "the probe must release its guard"
    );
}

/// Prove wall-clock expiry and bounded panic teardown with blocking work still held.
#[test]
fn wall_clock_watchdog_bounds_paused_wait_and_blocking_teardown() {
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (finished, completion) = std::sync::mpsc::channel();
    let shutdown_started = Mutex::new(None);
    let outcome = std::panic::catch_unwind(|| {
        run_paused_test(Duration::from_millis(50), async {
            let (entered, entry) = oneshot::channel();
            let blocking = tokio::task::spawn_blocking(move || {
                let _ = entered.send(());
                let _ = released.recv();
                let _ = finished.send(());
            });
            wall_clock_timeout(Duration::from_secs(2), entry)
                .await
                .expect("blocking probe must start")
                .unwrap();
            assert_eq!(
                wall_clock_timeout(Duration::from_secs(2), async { 7 }).await,
                Ok(7)
            );
            let frozen_at = tokio::time::Instant::now();
            let mut virtual_timeout = Box::pin(tokio::time::timeout(
                Duration::from_millis(10),
                std::future::pending::<()>(),
            ));
            assert!(
                wall_clock_timeout(Duration::from_millis(50), &mut virtual_timeout)
                    .await
                    .is_err()
            );
            assert_eq!(tokio::time::Instant::now(), frozen_at);
            assert!(futures_util::poll!(&mut virtual_timeout).is_pending());
            assert!(!blocking.is_finished());
            *shutdown_started.lock().unwrap() = Some(std::time::Instant::now());
            panic!("watchdog teardown probe");
        });
    });
    let elapsed = shutdown_started
        .lock()
        .unwrap()
        .map(|start| start.elapsed());
    let still_blocked = matches!(
        completion.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    // Release before assertions so even a failed teardown probe owns its cleanup.
    drop(release);
    completion
        .recv_timeout(Duration::from_secs(2))
        .expect("blocking probe must finish after release");
    assert_eq!(
        outcome.unwrap_err().downcast_ref::<&str>(),
        Some(&"watchdog teardown probe")
    );
    assert!(
        still_blocked,
        "shutdown must return with blocking work held"
    );
    assert!(
        elapsed.expect("probe must reach shutdown") < Duration::from_secs(2),
        "teardown took {elapsed:?}"
    );
}

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
    /// Reject a legacy read that would bypass the coordinator's deadline handoff.
    fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
        panic!("budget-aware observation must be used")
    }
    /// Reject a legacy mutation that would bypass the operation cutoff.
    fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
        panic!("budget-aware commit must be used")
    }
    /// Capture the bounded read deadline and report active or exact owned evidence.
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
    /// Check the inherited cutoff, then optionally hold mutation past its expiry.
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
    /// Apply a one-second cap to the request's original receipt time.
    fn request_budget(&self, _: &Principal, _: &str, _: &[u8]) -> Option<Duration> {
        Some(Duration::from_secs(1))
    }
    /// Verify admission has already spent the fixture's forty milliseconds.
    fn authorize_with_budget(
        &self,
        _: &Principal,
        _: &str,
        budget: ElapsedDeadline,
    ) -> Result<(), AuthError> {
        assert_eq!(budget.remaining(), Ok(Duration::from_millis(960)));
        Ok(())
    }
    /// Reject dispatch without the terminal request context.
    fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
        panic!("context required")
    }
    /// Check the same remaining budget at dispatch and request conditional retirement.
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

/// Admit an aged request, acknowledge its write barrier, and wait for commit entry.
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

/// Hard denial must fence reservation before unlocking, not in later withdrawal.
#[test]
fn racing_authorization_hard_denial_cannot_be_swallowed_by_terminal_reservation() {
    run_paused_test(Duration::from_secs(2), async {
        // Backstop the other scenario awaits too, including admission join/close.
        wall_clock_timeout(Duration::from_secs(10), hard_denial_reservation_race())
            .await
            .expect("authorization race scenario must finish");
    });
}

/// Exercise the actual admission and reservation interleaving on a paused runtime.
async fn hard_denial_reservation_race() {
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
        /// Keep the race within a request-wide cap without resetting it at reservation.
        fn request_budget(&self, _: &Principal, _: &str, _: &[u8]) -> Option<Duration> {
            Some(Duration::from_secs(3))
        }
        /// Allow retirement but hold a sibling's hard denial until the test releases it.
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
            // The sender lives only in the test: unwinding drops it and releases
            // this callback too, so a failed assertion cannot strand blocking work.
            let _ = self.release.lock().unwrap().recv();
            Err(AuthError::unauthenticated())
        }
        /// Reject legacy dispatch that cannot expose the retirement capability.
        fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            panic!("context hook required")
        }
        /// Expose only the admitted retirement context and await its controlled result.
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
        /// Report exact owner evidence if a transition crossed the authorization fence.
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
        /// Retain any admitted transition so the test detects an improper mutation.
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
    let (resume, resumed) = oneshot::channel();
    let pause = Arc::new(WithdrawalPause {
        id: 2,
        unlocked: Notify::new(),
        release: Mutex::new(Some(resumed)),
    });
    *host.withdrawal_pause.lock().unwrap() = Some(pause.clone());
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
    let waited_for_authorization = futures_util::poll!(&mut retiring).is_pending();
    let crossed_authorization = coordinator.fenced();
    // Release before any assertion that could strand the blocking test callback.
    release.send(()).unwrap();
    wall_clock_timeout(Duration::from_secs(2), pause.unlocked.notified())
        .await
        .expect("admission must reach the post-unlock pause");
    let withdrawal_deferred = !host.conn.shared.principal_withdrawn.load(Ordering::Acquire);
    // Drive reservation and the real authority/barrier path while admission is
    // held specifically in the post-unlock/pre-withdraw gap, not by scheduler luck.
    let mut commands = host.take_terminal_commands().unwrap();
    let mut receipts = 0;
    let outcome = loop {
        tokio::select! {
            outcome = &mut retiring => break outcome,
            Some(command) = commands.recv() => match command {
                DriverCommand::Barrier(ack) => { let _ = ack.send(()); }
                DriverCommand::Receipt(_) => receipts += 1,
            }
        }
    };
    assert_lifecycle_unlocked(&host.conn.shared.state).await;
    let succeeded = outcome.is_ok();
    let _ = returned.send(outcome.unwrap_or_else(|_| {
        HandlerOutcome::error(ErrorCode::Unavailable, "retirement unavailable")
    }));
    // Observe worker completion (including receipt selection/emission), rather
    // than giving it an arbitrary number of yields to produce an illegal receipt.
    wall_clock_timeout(Duration::from_secs(2), async {
        loop {
            let changed = host.progress.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if host.worker_len() == 0 {
                break;
            }
            changed.await;
        }
    })
    .await
    .expect("request workers must finish after retirement settles");
    while let Ok(command) = commands.try_recv() {
        if matches!(command, DriverCommand::Receipt(_)) {
            receipts += 1;
        }
    }
    let committed = authority.0.lock().unwrap().is_some();
    let _ = resume.send(());
    admission.await.unwrap();
    let withdrawn = host.conn.shared.principal_withdrawn.load(Ordering::Acquire);
    host.close().await;
    assert!(
        waited_for_authorization,
        "reservation must await authorization"
    );
    assert!(
        withdrawal_deferred,
        "withdrawal must remain paused during retirement"
    );
    assert_eq!(
        (crossed_authorization, withdrawn, committed, succeeded, receipts),
        (false, true, false, false, 0),
        "reservation must wait for authorization; hard denial must withdraw without commit or receipt"
    );
}
