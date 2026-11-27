#![cfg(not(target_arch = "wasm32"))]
//! Executable D5 lifecycle fixtures. These exercise runtime owners, not devices.
use prost::Message;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_core::{proto::frame::Body, ClientHello, Frame, RpcRequest};
use syntra_runtime::{
    elapsed::{ElapsedClock, ElapsedSource},
    *,
};

struct Source(AtomicU64);
impl ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}
fn clock() -> (Arc<Source>, ElapsedClock) {
    let source = Arc::new(Source(AtomicU64::new(1000)));
    (source.clone(), ElapsedClock::with_source(source))
}
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}
fn hello() -> Vec<u8> {
    Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![],
        })),
    }
    .encode_to_vec()
}
fn request(id: u64) -> Vec<u8> {
    Frame {
        version: 1,
        request_id: id,
        body: Some(Body::Request(RpcRequest {
            method: "/fixture.App/Mutate".into(),
            payload: vec![1],
            timeout_ms: 10_000,
        })),
    }
    .encode_to_vec()
}
struct External(tokio::sync::mpsc::UnboundedSender<ExecutionLease>);
impl Handler for External {
    fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
        Ok(())
    }
    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        unreachable!("lease hook")
    }
    fn handle_with_execution(
        &self,
        _: String,
        _: Vec<u8>,
        _: CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        self.0
            .send(lease)
            .unwrap_or_else(|_| panic!("fixture owns lease receiver"));
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn host_shutdown_retains_execution_and_foreign_join_after_cancellation_and_deadline() {
    let (source, clock) = clock();
    let budget = ExecutionBudget::new(1);
    let (leases, mut transferred) = tokio::sync::mpsc::unbounded_channel();
    let (host, mut writer) = Host::try_new_with_execution_budget_and_clock(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(External(leases)),
        budget.clone(),
        clock.clone(),
    )
    .unwrap();
    host.register_transport_tasks(1).unwrap();
    host.ingest_received_at(&hello(), clock.now()).await;
    writer.recv().await.unwrap();
    host.ingest_received_at(&request(1), clock.now()).await;
    let external = transferred.recv().await.unwrap();
    let mut waiter = Box::pin(host.shutdown(Duration::from_millis(100)));
    assert!(futures_util::poll!(&mut waiter).is_pending());
    drop(waiter);
    let deadline = host.shutdown_budget().unwrap().deadline;
    assert!(host.register_transport_tasks(1).is_err());
    source.0.fetch_add(101, Ordering::SeqCst);
    clock.wake();
    settle().await;
    host.acknowledge_transport_closed();
    let report = host.shutdown(Duration::from_secs(30)).await.unwrap();
    assert_eq!(host.shutdown_budget().unwrap().deadline, deadline);
    assert_eq!(report.phase, ShutdownPhase::ShutdownIncomplete);
    assert_eq!(report.pending_calls, 0);
    assert_eq!(report.live_executions, 1);
    assert_eq!(report.transport_tasks, 1);
    assert!(report.owned_tasks >= 1);
    assert_eq!(
        budget.in_use(),
        1,
        "reporting timeout cannot release execution"
    );
    drop(external);
    settle().await;
    assert_eq!(budget.in_use(), 0);
    assert_eq!(
        host.shutdown_report().phase,
        ShutdownPhase::ShutdownIncomplete,
        "foreign task still unjoined"
    );
    host.acknowledge_transport_task_joined().unwrap();
    settle().await;
    let report = host.shutdown_report();
    assert_eq!(report.phase, ShutdownPhase::Complete, "{report:?}");
    assert_eq!(report.owned_tasks, 0);
}

#[tokio::test(start_paused = true)]
async fn initiator_shutdown_requires_carrier_attestation_and_actual_owned_join() {
    let (source, clock) = clock();
    let (client, _writer) =
        Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
    let release = Arc::new(tokio::sync::Notify::new());
    let work = release.clone();
    let task = client.own_native_task(tokio::spawn(async move {
        work.notified().await;
    }));
    client.begin_shutdown(Duration::from_millis(100)).unwrap();
    assert!(client
        .call("/fixture.App/Mutate", vec![], 1000)
        .await
        .is_err());
    source.0.fetch_add(101, Ordering::SeqCst);
    clock.wake();
    settle().await;
    let report = client.shutdown_report();
    assert_eq!(report.phase, ShutdownPhase::ShutdownIncomplete);
    assert!(!report.transport_closed);
    assert!(report.owned_tasks >= 1);
    client.acknowledge_transport_closed();
    assert_ne!(client.shutdown_report().phase, ShutdownPhase::Complete);
    release.notify_one();
    settle().await;
    assert!(task.is_finished());
    assert_eq!(client.shutdown_report().phase, ShutdownPhase::Complete);
}

#[tokio::test]
async fn owned_task_failure_is_joined_and_reported_not_silent_success() {
    let (client, _writer) = Initiator::new(ConnectionConfig::default());
    client.own_native_task(tokio::spawn(async {
        panic!("test-only owned task failure");
    }));
    client.acknowledge_transport_closed();
    let report = client.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(report.phase, ShutdownPhase::Complete);
    assert_eq!(
        report.failed_tasks, 1,
        "termination is distinct from successful execution"
    );
}

#[tokio::test]
async fn actual_loopback_pumps_are_retained_and_joined_by_runtime_shutdown() {
    let (client, host) = loopback_pair(
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, p, _| async { HandlerOutcome::Payload(p) })),
        ConnectionConfig::default(),
    );
    client.handshake(vec![]).await.unwrap();
    assert_eq!(
        client
            .call("/fixture.App/Echo", vec![7], 1000)
            .await
            .unwrap(),
        vec![7]
    );
    let report = client.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(report.phase, ShutdownPhase::Complete, "{report:?}");
    let report = host.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(report.phase, ShutdownPhase::Complete, "{report:?}");
}

#[tokio::test(start_paused = true)]
async fn deadline_object_rechecks_the_source_after_a_ready_authorization_poll() {
    use syntra_runtime::elapsed::ElapsedFailure;
    let (source, clock) = clock();
    let deadline = clock.deadline_after(Duration::from_millis(50)).unwrap();
    let checked = deadline
        .run(async {
            source.0.fetch_add(50, Ordering::SeqCst);
            true
        })
        .await;
    assert_eq!(
        checked,
        Err(ElapsedFailure::Deadline),
        "a late ready result cannot renew authority"
    );
    clock.invalidate();
    assert_eq!(deadline.check(), Err(ElapsedFailure::ContinuityLost));
}

#[tokio::test(start_paused = true)]
async fn elapsed_join_wait_never_discards_an_already_consumed_join_result() {
    use std::{future::Future, pin::Pin};
    let (source, clock) = clock();
    let mut task = tokio::spawn(async {});
    settle().await;
    let result = clock
        .timeout_until(
            clock.now() + Duration::from_millis(50),
            std::future::poll_fn(|cx| {
                let result = Pin::new(&mut task).poll(cx);
                if result.is_ready() {
                    source.0.fetch_add(51, Ordering::SeqCst);
                }
                result
            }),
        )
        .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "never turn a consumed JoinHandle into a retryable timeout"
    );
}

#[tokio::test]
async fn handler_initiated_shutdown_owner_survives_its_waiter_being_cancelled() {
    let reference = Arc::new(std::sync::Mutex::new(std::sync::Weak::<Host>::new()));
    let bound = reference.clone();
    let handler = FnHandler(move |_, _, _| {
        let host = bound.lock().unwrap().upgrade().unwrap();
        async move {
            host.shutdown(Duration::from_millis(30)).await.unwrap();
            HandlerOutcome::Payload(vec![1])
        }
    });
    let (client, host) = loopback_pair(
        Arc::new(AllowAnonymous),
        Arc::new(handler),
        ConnectionConfig::default(),
    );
    *reference.lock().unwrap() = Arc::downgrade(&host);
    client.handshake(vec![]).await.unwrap();
    assert!(client
        .call("/fixture.App/Stop", vec![], 1000)
        .await
        .is_err());
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if host.shutdown_report().phase == ShutdownPhase::Complete {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(host.execution_len(), 0);
}

#[tokio::test]
async fn suspend_linearizes_with_an_in_progress_raw_carrier_poll() {
    let (client, _writer) = Initiator::new(ConnectionConfig::default());
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let (started, start) = std::sync::mpsc::channel();
    let (suspended, stopped) = std::sync::mpsc::channel();
    let poll_client = client.clone();
    let poller = std::thread::spawn(move || {
        // Intentionally parked only to expose the gate's concurrency boundary.
        // Production raw poll callbacks must be nonblocking/non-reentrant.
        assert_eq!(
            poll_client.with_carrier_io(|| {
                entered.send(()).unwrap();
                wait.recv().unwrap();
                7
            }),
            Some(7)
        );
    });
    observed.recv_timeout(Duration::from_secs(1)).unwrap();
    let control_client = client.clone();
    let controller = std::thread::spawn(move || {
        started.send(()).unwrap();
        control_client.suspend();
        suspended.send(()).unwrap();
    });
    start.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        stopped.recv_timeout(Duration::from_millis(20)).is_err(),
        "suspend cannot return before the active raw poll leaves"
    );
    release.send(()).unwrap();
    poller.join().unwrap();
    stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    controller.join().unwrap();
    assert!(client
        .with_carrier_io(|| panic!("no new raw poll after suspend"))
        .is_none());
}
