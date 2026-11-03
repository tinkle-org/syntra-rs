//! Host-only RFC 0004 D2/D4 and RFC 0008 D2/D5 regressions. These exercise
//! serialized wire frames locally; they are not an independent interop verdict.

use super::*;
use crate::session::AllowAnonymous;
use std::sync::atomic::{AtomicUsize, Ordering};
use syntra_core::proto::{rpc_result::Outcome, Cancel, ClientHello};

fn request(id: u64, method: &str, timeout_ms: u32) -> Vec<u8> {
    Frame {
        version: 1,
        request_id: id,
        body: Some(Body::Request(RpcRequest {
            method: method.into(),
            payload: vec![],
            timeout_ms,
        })),
    }
    .encode_to_vec()
}

fn call(id: u64) -> Vec<u8> {
    request(id, "/example.Echo/Echo", 1000)
}

fn cancel(id: u64) -> Vec<u8> {
    Frame {
        version: 1,
        request_id: id,
        body: Some(Body::Cancel(Cancel {})),
    }
    .encode_to_vec()
}

async fn activate(host: &Host, writer: &mut mpsc::Receiver<Vec<u8>>) {
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![],
            })),
        }
        .encode_to_vec(),
    )
    .await;
    assert!(matches!(
        Frame::decode(writer.recv().await.unwrap().as_slice())
            .unwrap()
            .body,
        Some(Body::Ready(_))
    ));
}

async fn result(writer: &mut mpsc::Receiver<Vec<u8>>, id: u64) -> Outcome {
    let frame = Frame::decode(writer.recv().await.unwrap().as_slice()).unwrap();
    assert_eq!(frame.request_id, id);
    let Some(Body::Result(RpcResult {
        outcome: Some(outcome),
    })) = frame.body
    else {
        panic!("expected result");
    };
    outcome
}

fn error(outcome: Outcome, code: ErrorCode) {
    assert!(matches!(outcome, Outcome::Error(e) if e.code == code.as_i32()));
}

async fn spin_until(mut condition: impl FnMut() -> bool) {
    // Never let paused time auto-advance while waiting for a scheduler barrier.
    for _ in 0..1000 {
        if condition() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(condition(), "worker did not reach barrier");
}

fn echo(effects: Arc<AtomicUsize>) -> Arc<dyn Handler> {
    Arc::new(FnHandler(move |_, _, _| {
        effects.fetch_add(1, Ordering::SeqCst);
        async { HandlerOutcome::Payload(b"ok".to_vec()) }
    }))
}

#[tokio::test(start_paused = true)]
async fn increasing_gaps_and_completed_reuse_close_without_a_second_result() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        echo(effects.clone()),
    );
    activate(&host, &mut writer).await;
    for id in [7, 10, u64::MAX] {
        host.ingest(&call(id)).await;
        assert_eq!(
            result(&mut writer, id).await,
            Outcome::Payload(b"ok".to_vec())
        );
    }
    host.ingest(&cancel(7)).await; // references do not advance H
    host.ingest(&call(u64::MAX)).await;
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::FailedPrecondition
    );
    assert!(host.is_closed());
    assert!(writer.try_recv().is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 3);
    assert_eq!(*host.highwater.lock().unwrap(), u64::MAX);
}

#[tokio::test(start_paused = true)]
async fn skipped_below_highwater_and_outstanding_duplicate_are_connection_violations() {
    for offending in [7, 9, 10] {
        let effects = Arc::new(AtomicUsize::new(0));
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(FnHandler({
                let effects = effects.clone();
                move |_, _, _| {
                    effects.fetch_add(1, Ordering::SeqCst);
                    std::future::pending::<HandlerOutcome>()
                }
            })),
        );
        activate(&host, &mut writer).await;
        host.ingest(&call(10)).await;
        spin_until(|| effects.load(Ordering::SeqCst) == 1).await;
        host.ingest(&call(offending)).await;
        assert!(host.is_closed());
        assert_eq!(
            host.terminal_reason().unwrap().code(),
            ErrorCode::FailedPrecondition
        );
        assert!(writer.try_recv().is_err(), "no ambiguous violation result");
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn malformed_method_and_authorization_rejections_consume_highwater() {
    struct Denied;
    impl Handler for Denied {
        fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            panic!("denied work dispatched")
        }
    }
    for (method, code) in [
        ("bad-method", ErrorCode::InvalidArgument),
        ("/example.Echo/Echo", ErrorCode::PermissionDenied),
    ] {
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(Denied),
        );
        activate(&host, &mut writer).await;
        host.ingest(&request(7, method, 1000)).await;
        error(result(&mut writer, 7).await, code);
        assert_eq!(*host.highwater.lock().unwrap(), 7);
        host.ingest(&call(7)).await;
        assert!(host.is_closed());
        assert!(writer.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn structural_and_nonzero_id_checks_precede_highwater() {
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        echo(Arc::new(AtomicUsize::new(0))),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(0)).await;
    let mut malformed = call(100);
    malformed.extend([0x62, 0]); // repeated body, not a trustworthy request
    host.ingest(&malformed).await;
    assert_eq!(*host.highwater.lock().unwrap(), 0);
    host.ingest(&call(7)).await;
    assert!(matches!(result(&mut writer, 7).await, Outcome::Payload(_)));
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn fifo_gate_and_receipt_timestamp_include_admission_delay() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        echo(effects.clone()),
    );
    activate(&host, &mut writer).await;
    let gate = host.admission.lock().await;
    let received = now();
    let first_bytes = call(7);
    let second_bytes = call(10);
    let mut first = Box::pin(host.ingest_received_at(&first_bytes, received));
    let mut second = Box::pin(host.ingest_received_at(&second_bytes, received));
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(futures_util::poll!(&mut second).is_pending());
    tokio::time::advance(Duration::from_secs(1)).await;
    drop(gate);
    // Poll the second waiter first: FIFO acquisition must still admit 7 first.
    assert!(futures_util::poll!(&mut second).is_pending());
    first.await;
    second.await;
    let mut ids = Vec::new();
    for _ in 0..2 {
        let frame = Frame::decode(writer.recv().await.unwrap().as_slice()).unwrap();
        ids.push(frame.request_id);
        let Some(Body::Result(RpcResult {
            outcome: Some(outcome),
        })) = frame.body
        else {
            panic!("result")
        };
        error(outcome, ErrorCode::DeadlineExceeded);
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![7, 10]);
    assert!(!host.is_closed());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn selected_output_backpressure_neither_blocks_admission_nor_changes_terminal() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        echo(effects.clone()),
    );
    activate(&host, &mut writer).await;
    host.conn.shared.writer.try_send(vec![0]).unwrap();
    host.ingest(&call(7)).await;
    spin_until(|| host.inflight_len() == 0).await;
    assert_eq!(host.output.in_use(), 1);
    host.ingest(&cancel(7)).await;
    host.ingest(&request(8, "malformed", 1000)).await;
    host.ingest(&call(10)).await;
    spin_until(|| effects.load(Ordering::SeqCst) == 2 && host.inflight_len() == 0).await;
    assert_eq!(*host.highwater.lock().unwrap(), 10);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(writer.recv().await.unwrap(), vec![0]);
    assert_eq!(
        result(&mut writer, 7).await,
        Outcome::Payload(b"ok".to_vec())
    );
    // Results need not follow request order; only admission has that requirement.
    let mut outcomes = HashMap::new();
    for _ in 0..2 {
        let frame = Frame::decode(writer.recv().await.unwrap().as_slice()).unwrap();
        let Some(Body::Result(result)) = frame.body else {
            panic!("result")
        };
        outcomes.insert(frame.request_id, result.outcome.unwrap());
    }
    error(outcomes.remove(&8).unwrap(), ErrorCode::InvalidArgument);
    assert_eq!(
        outcomes.remove(&10).unwrap(),
        Outcome::Payload(b"ok".to_vec())
    );
    assert!(writer.try_recv().is_err());
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn exact_deadline_beats_ready_completion_and_incoming_cancel() {
    for incoming_cancel in [false, true] {
        let (complete, completed) = oneshot::channel();
        let completed = Mutex::new(Some(completed));
        let (started, mut starts) = mpsc::channel(1);
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(FnHandler(move |_, _, _| {
                let completed = completed.lock().unwrap().take().unwrap();
                started.try_send(()).unwrap();
                async move { completed.await.unwrap() }
            })),
        );
        activate(&host, &mut writer).await;
        host.ingest(&call(7)).await;
        starts.recv().await.unwrap();
        complete.send(HandlerOutcome::Payload(vec![])).unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        if incoming_cancel {
            host.ingest(&cancel(7)).await;
        }
        error(result(&mut writer, 7).await, ErrorCode::DeadlineExceeded);
        assert!(writer.try_recv().is_err());
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn first_predeadline_cancel_wins_even_when_completion_is_ready() {
    let (complete, completed) = oneshot::channel();
    let completed = Mutex::new(Some(completed));
    let (started, mut starts) = mpsc::channel(1);
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(move |_, _, _| {
            let completed = completed.lock().unwrap().take().unwrap();
            started.try_send(()).unwrap();
            async move { completed.await.unwrap() }
        })),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    starts.recv().await.unwrap();
    complete.send(HandlerOutcome::Payload(vec![])).unwrap();
    host.ingest(&cancel(7)).await; // no yield: cancellation observes the gate first
    error(result(&mut writer, 7).await, ErrorCode::Cancelled);
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(writer.try_recv().is_err());
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn loss_withdrawal_and_close_candidates_check_deadline_and_cannot_replace_selection() {
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::Unauthenticated,
        ErrorCode::Cancelled,
    ] {
        let mut calls = Calls::default();
        let (selected, result) = oneshot::channel();
        calls.pending.insert(
            7,
            PendingCall {
                deadline: now(),
                cancel: crate::CancelToken::new(),
                selected,
            },
        );
        calls.select(7, HandlerOutcome::error(code, "candidate"));
        calls.select(7, HandlerOutcome::Payload(vec![]));
        assert!(matches!(
            result.await.unwrap(),
            HandlerOutcome::Error {
                code: ErrorCode::DeadlineExceeded,
                ..
            }
        ));
    }
}

// Models work which definitely survives dropping HandlerFut. Tests explicitly
// own and release the transferred lease, rather than claiming a dropped future
// proves that an external task was stopped.
struct External {
    leases: mpsc::UnboundedSender<ExecutionLease>,
}

impl Handler for External {
    fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
        Ok(())
    }
    fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
        panic!("execution hook must be used")
    }
    fn handle_with_execution(
        &self,
        _: String,
        _: Vec<u8>,
        _: crate::CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        self.leases
            .send(lease)
            .unwrap_or_else(|_| panic!("test lease receiver closed"));
        Box::pin(std::future::pending())
    }
}

#[tokio::test(start_paused = true)]
async fn abandoned_execution_remains_charged_after_timeout_cancel_and_close_across_replacements() {
    for reason in [
        ErrorCode::DeadlineExceeded,
        ErrorCode::Cancelled,
        ErrorCode::Unavailable,
    ] {
        let budget = ExecutionBudget::new(1);
        let config = ConnectionConfig {
            max_outstanding: 16,
            ..ConnectionConfig::default()
        };
        let (leases, mut transferred) = mpsc::unbounded_channel();
        let handler: Arc<dyn Handler> = Arc::new(AllowAll(External { leases }));
        let (host, mut writer) = Host::new_with_execution_budget(
            config.clone(),
            Arc::new(AllowAnonymous),
            handler.clone(),
            budget.clone(),
        );
        activate(&host, &mut writer).await;
        host.ingest(&call(7)).await;
        let external = transferred.recv().await.unwrap();
        match reason {
            ErrorCode::DeadlineExceeded => tokio::time::advance(Duration::from_secs(1)).await,
            ErrorCode::Cancelled => host.ingest(&cancel(7)).await,
            _ => host.on_transport_lost().await,
        }
        if reason != ErrorCode::Unavailable {
            error(result(&mut writer, 7).await, reason);
            spin_until(|| host.output.in_use() == 0).await;
            // Correlation ended; shared execution capacity did not. The core
            // capacity remains the supported 16-way production minimum.
            host.ingest(&call(10)).await;
            error(result(&mut writer, 10).await, ErrorCode::ResourceExhausted);
            assert_eq!(*host.highwater.lock().unwrap(), 10);
            host.close().await;
        }
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.execution_len(), 1);
        assert_eq!(budget.in_use(), 1);
        assert_eq!(host.worker_len(), 1);
        let (replacement, mut replacement_writer) = Host::new_with_execution_budget(
            config,
            Arc::new(AllowAnonymous),
            handler,
            budget.clone(),
        );
        activate(&replacement, &mut replacement_writer).await;
        replacement.ingest(&call(1)).await;
        error(
            result(&mut replacement_writer, 1).await,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(
            replacement.execution_len(),
            0,
            "failed shared admission rolls local charge back"
        );
        drop(external);
        spin_until(|| budget.in_use() == 0 && host.worker_len() == 0).await;
        replacement.ingest(&call(2)).await;
        let external = transferred.recv().await.unwrap();
        assert_eq!(budget.in_use(), 1);
        replacement.ingest(&cancel(2)).await;
        error(
            result(&mut replacement_writer, 2).await,
            ErrorCode::Cancelled,
        );
        drop(external);
        spin_until(|| budget.in_use() == 0).await;
        replacement.close().await;
        assert!(transferred.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn direct_error_variants_are_sanitized_and_bounded() {
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, _, _| async {
            HandlerOutcome::Error {
                code: ErrorCode::Unspecified,
                message: "é".repeat(syntra_core::MAX_DIAGNOSTIC_BYTES),
            }
        })),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    let Outcome::Error(e) = result(&mut writer, 7).await else {
        panic!("error")
    };
    assert_eq!(e.code, ErrorCode::Unknown.as_i32());
    assert!(e.message.len() <= syntra_core::MAX_DIAGNOSTIC_BYTES);
    assert!(std::str::from_utf8(e.message.as_bytes()).is_ok());
    let Outcome::Error(e) = outcome_error(ErrorCode::Unspecified, &"x".repeat(10_000)) else {
        panic!("error")
    };
    assert_eq!(e.code, ErrorCode::Unknown.as_i32());
    assert!(e.message.len() <= syntra_core::MAX_DIAGNOSTIC_BYTES);
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn expiry_during_synchronous_authorization_prevents_handler_effects() {
    struct SlowPolicy {
        started: Mutex<Option<oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        effects: AtomicUsize,
        revoked: bool,
    }
    impl Handler for SlowPolicy {
        fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
            self.started
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
            self.release.lock().unwrap().recv().unwrap();
            if self.revoked {
                Err(AuthError {
                    code: ErrorCode::Unauthenticated,
                    message: "private reason".into(),
                })
            } else {
                Ok(())
            }
        }
        fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            self.effects.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { HandlerOutcome::Payload(vec![]) })
        }
    }
    for revoked in [false, true] {
        let (started, observed) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let policy = Arc::new(SlowPolicy {
            started: Mutex::new(Some(started)),
            release: Mutex::new(released),
            effects: AtomicUsize::new(0),
            revoked,
        });
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            policy.clone(),
        );
        activate(&host, &mut writer).await;
        let worker_host = host.clone();
        let runtime = tokio::runtime::Handle::current();
        // Deliberately violate authorize's nonblocking contract without blocking
        // the test runtime. This is a test barrier, not production dispatch policy.
        let admission =
            tokio::task::spawn_blocking(move || runtime.block_on(worker_host.ingest(&call(7))));
        observed.await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        release.send(()).unwrap();
        admission.await.unwrap();
        error(result(&mut writer, 7).await, ErrorCode::DeadlineExceeded);
        assert_eq!(policy.effects.load(Ordering::SeqCst), 0);
        assert_eq!(host.execution_len(), 0);
        assert_eq!(
            host.is_closed(),
            revoked,
            "deadline does not undo withdrawal"
        );
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn admitted_handlers_execute_concurrently_and_results_can_finish_out_of_order() {
    let (release, released) = oneshot::channel();
    let released = Mutex::new(Some(released));
    let (started, mut starts) = mpsc::channel(2);
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(move |_, _, _| {
            let released = released.lock().unwrap().take();
            started.try_send(()).unwrap();
            async move {
                if let Some(released) = released {
                    released.await.unwrap();
                }
                HandlerOutcome::Payload(vec![])
            }
        })),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    starts.recv().await.unwrap();
    host.ingest(&call(10)).await;
    starts.recv().await.unwrap();
    assert!(matches!(result(&mut writer, 10).await, Outcome::Payload(_)));
    assert_eq!(host.inflight_len(), 1);
    release.send(()).unwrap();
    assert!(matches!(result(&mut writer, 7).await, Outcome::Payload(_)));
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn withdrawal_preserves_success_selected_before_writer_capacity() {
    let (host, mut writer) = Host::new(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        echo(Arc::new(AtomicUsize::new(0))),
    );
    activate(&host, &mut writer).await;
    host.conn.shared.writer.try_send(vec![0]).unwrap();
    host.ingest(&call(7)).await;
    spin_until(|| host.inflight_len() == 0).await;
    let mut withdrawal = Box::pin(host.withdraw_principal());
    assert!(futures_util::poll!(&mut withdrawal).is_pending());
    assert_eq!(writer.recv().await.unwrap(), vec![0]);
    assert_eq!(
        result(&mut writer, 7).await,
        Outcome::Payload(b"ok".to_vec())
    );
    withdrawal.await;
    assert!(host.is_closed());
    assert!(writer.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn overload_consumes_id_while_full_output_is_bounded_without_waiting() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new_with_execution_budget(
        ConnectionConfig {
            max_outstanding: 16,
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler({
            let effects = effects.clone();
            move |_, _, _| {
                effects.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<HandlerOutcome>()
            }
        })),
        ExecutionBudget::new(1),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    spin_until(|| effects.load(Ordering::SeqCst) == 1).await;
    host.ingest(&call(10)).await;
    error(result(&mut writer, 10).await, ErrorCode::ResourceExhausted);
    assert_eq!(*host.highwater.lock().unwrap(), 10);
    host.ingest(&call(10)).await;
    assert!(host.is_closed());
    assert!(writer.try_recv().is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 1);

    let (host, mut writer) = Host::new(
        ConnectionConfig {
            max_outstanding: 16,
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        echo(Arc::new(AtomicUsize::new(0))),
    );
    activate(&host, &mut writer).await;
    host.conn.shared.writer.try_send(vec![0]).unwrap();
    for id in 1..=17 {
        host.ingest(&request(id, "malformed", 1000)).await;
    }
    assert_eq!(host.output.in_use(), 17);
    host.ingest(&call(18)).await; // bounded rejection output exhausted: close, no wait
    assert!(host.is_closed());
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::ResourceExhausted
    );
    assert_eq!(writer.try_recv().unwrap(), vec![0]);
    assert!(writer.try_recv().is_err());
}

#[test]
fn execution_lease_and_budget_have_deliberate_send_sync_bounds() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<ExecutionLease>();
    assert_send_sync::<ExecutionBudget>();
}

#[tokio::test(start_paused = true)]
async fn panicking_hook_closes_without_losing_external_execution_ownership() {
    struct Panicking(mpsc::UnboundedSender<ExecutionLease>);
    impl Handler for Panicking {
        fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
            Ok(())
        }
        fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            unreachable!()
        }
        fn handle_with_execution(
            &self,
            _: String,
            _: Vec<u8>,
            _: crate::CancelToken,
            lease: ExecutionLease,
        ) -> HandlerFut {
            self.0
                .send(lease)
                .unwrap_or_else(|_| panic!("test receiver closed"));
            panic!("modeled application hook panic");
        }
    }
    let (leases, mut transferred) = mpsc::unbounded_channel();
    let budget = ExecutionBudget::new(1);
    let (host, mut writer) = Host::new_with_execution_budget(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(Panicking(leases)),
        budget.clone(),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    let external = transferred.recv().await.unwrap();
    spin_until(|| host.is_closed()).await;
    assert_eq!(host.terminal_reason().unwrap().code(), ErrorCode::Internal);
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.sessions.count(), 0);
    assert_eq!(host.worker_len(), 1);
    assert_eq!(budget.in_use(), 1);
    assert!(writer.try_recv().is_err());
    drop(external);
    spin_until(|| budget.in_use() == 0 && host.worker_len() == 0).await;
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn oversize_success_is_an_error_candidate_before_selection() {
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, _, _| async {
            HandlerOutcome::Payload(vec![0; syntra_core::MAX_FRAME_BYTES])
        })),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    error(result(&mut writer, 7).await, ErrorCode::ResourceExhausted);
    host.ingest(&cancel(7)).await;
    assert!(writer.try_recv().is_err());
    host.close().await;
}

#[tokio::test(start_paused = true)]
async fn cooperative_handler_token_cancellation_uses_the_same_terminal_gate() {
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_, _, cancel: crate::CancelToken| async move {
            cancel.cancel();
            std::future::pending::<HandlerOutcome>().await
        })),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    error(result(&mut writer, 7).await, ErrorCode::Cancelled);
    assert!(writer.try_recv().is_err());
    host.close().await;
}

#[test]
fn checked_constructors_reject_invalid_limits_without_an_executor_or_panicking() {
    let mut invalid = Vec::new();
    for max_outstanding in [0, 15, 1025, usize::MAX] {
        invalid.push(ConnectionConfig {
            max_outstanding,
            ..ConnectionConfig::default()
        });
    }
    for capacity in [0, 1025, usize::MAX] {
        invalid.push(ConnectionConfig {
            writer_capacity: capacity,
            ..ConnectionConfig::default()
        });
        invalid.push(ConnectionConfig {
            notification_capacity: capacity,
            ..ConnectionConfig::default()
        });
    }
    for timeout in [Duration::ZERO, Duration::from_secs(86_401), Duration::MAX] {
        invalid.push(ConnectionConfig {
            default_timeout: timeout,
            ..ConnectionConfig::default()
        });
        invalid.push(ConnectionConfig {
            max_rpc_timeout: timeout,
            ..ConnectionConfig::default()
        });
        invalid.push(ConnectionConfig {
            handshake_timeout: timeout,
            ..ConnectionConfig::default()
        });
    }
    let effects = Arc::new(AtomicUsize::new(0));
    let handler = echo(effects.clone());
    let budget = ExecutionBudget::new(1);
    // This deliberately has no Tokio runtime: even a valid channel followed by
    // an accidental spawn-before-validation would panic instead of returning Err.
    for config in invalid {
        for constructor in 0..3 {
            let built = match constructor {
                0 => Host::try_new(config.clone(), Arc::new(AllowAnonymous), handler.clone()),
                1 => Host::try_new_with_versions(
                    config.clone(),
                    Arc::new(AllowAnonymous),
                    handler.clone(),
                    vec![1],
                ),
                _ => Host::try_new_with_execution_budget(
                    config.clone(),
                    Arc::new(AllowAnonymous),
                    handler.clone(),
                    budget.clone(),
                ),
            };
            assert_eq!(
                built.err().expect("invalid configuration accepted").code(),
                ErrorCode::InvalidArgument
            );
        }
    }
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(budget.in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn checked_constructors_accept_production_boundaries() {
    for max_outstanding in [16, 1024] {
        let config = ConnectionConfig {
            max_outstanding,
            writer_capacity: 1,
            notification_capacity: 1024,
            default_timeout: Duration::from_secs(86_400),
            max_rpc_timeout: Duration::from_secs(86_400),
            handshake_timeout: Duration::from_secs(86_400),
        };
        for constructor in 0..3 {
            let handler = echo(Arc::new(AtomicUsize::new(0)));
            let (host, mut writer) = match constructor {
                0 => Host::try_new(config.clone(), Arc::new(AllowAnonymous), handler),
                1 => Host::try_new_with_versions(
                    config.clone(),
                    Arc::new(AllowAnonymous),
                    handler,
                    vec![1],
                ),
                _ => Host::try_new_with_execution_budget(
                    config.clone(),
                    Arc::new(AllowAnonymous),
                    handler,
                    ExecutionBudget::new(1),
                ),
            }
            .unwrap();
            assert_eq!(host.state().await, ConnectionState::Connected);
            activate(&host, &mut writer).await;
            host.close().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn invalid_close_grace_is_fallible_or_recorded_before_immediate_close() {
    for grace in [
        Duration::from_secs(30) + Duration::from_nanos(1),
        Duration::MAX,
    ] {
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo(Arc::new(AtomicUsize::new(0))),
        );
        activate(&host, &mut writer).await;
        let before = now();
        let failure = host.try_close_gracefully(grace).await.unwrap_err();
        assert_eq!(failure.code(), ErrorCode::InvalidArgument);
        assert_eq!(host.state().await, ConnectionState::Active);
        assert!(host.terminal_reason().is_none());
        assert_eq!(host.sessions.count(), 1);
        host.close_gracefully(grace).await;
        assert!(host.is_closed());
        assert_eq!(
            host.terminal_reason().unwrap().code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(host.sessions.count(), 0);
        assert_eq!(now(), before);
        assert!(writer.try_recv().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn zero_close_grace_skips_backpressured_drain_and_maximum_grace_is_valid() {
    for checked in [false, true] {
        let (host, mut writer) = Host::new(
            ConnectionConfig {
                writer_capacity: 1,
                ..ConnectionConfig::default()
            },
            Arc::new(AllowAnonymous),
            Arc::new(FnHandler(|_, _, _| {
                std::future::pending::<HandlerOutcome>()
            })),
        );
        activate(&host, &mut writer).await;
        host.conn.shared.writer.try_send(vec![0]).unwrap();
        host.ingest(&call(1)).await;
        let before = now();
        if checked {
            host.try_close_gracefully(Duration::ZERO).await.unwrap();
        } else {
            host.close_gracefully(Duration::ZERO).await;
        }
        assert!(host.is_closed());
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.execution_len(), 0);
        assert_eq!(now(), before, "zero grace must not wait for writer drain");
        assert_eq!(writer.try_recv().unwrap(), vec![0]);
        assert!(writer.try_recv().is_err());
    }
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        echo(Arc::new(AtomicUsize::new(0))),
    );
    activate(&host, &mut writer).await;
    host.try_close_gracefully(Duration::from_secs(30))
        .await
        .unwrap();
    assert!(host.is_closed());
}

#[tokio::test(start_paused = true)]
async fn authorization_codes_are_generic_and_never_replace_or_union_the_bound_principal() {
    struct Policy {
        code: ErrorCode,
        principals: Mutex<Vec<Principal>>,
        effects: AtomicUsize,
    }
    impl Handler for Policy {
        fn authorize(&self, principal: &Principal, method: &str) -> Result<(), AuthError> {
            self.principals.lock().unwrap().push(principal.clone());
            if method == "/example.Auth/Change" {
                Err(AuthError {
                    code: self.code,
                    message: "private alternate principal".into(),
                })
            } else {
                Ok(())
            }
        }
        fn handle(&self, _: String, payload: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            self.effects.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { HandlerOutcome::Payload(payload) })
        }
    }
    for (code, expected, message) in [
        (
            ErrorCode::FailedPrecondition,
            ErrorCode::FailedPrecondition,
            "principal change not permitted",
        ),
        (
            ErrorCode::Unauthenticated,
            ErrorCode::Unauthenticated,
            "credential not accepted",
        ),
        (
            ErrorCode::PermissionDenied,
            ErrorCode::PermissionDenied,
            "access denied",
        ),
        (
            ErrorCode::Internal,
            ErrorCode::PermissionDenied,
            "access denied",
        ),
        (
            ErrorCode::Unspecified,
            ErrorCode::PermissionDenied,
            "access denied",
        ),
    ] {
        let policy = Arc::new(Policy {
            code,
            principals: Mutex::new(Vec::new()),
            effects: AtomicUsize::new(0),
        });
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            policy.clone(),
        );
        activate(&host, &mut writer).await;
        let id = host.bound_id.lock().unwrap().clone().unwrap();
        let original = host.sessions.get(&id).unwrap().principal;
        host.ingest(&request(7, "/example.Auth/Change", 1000)).await;
        let Outcome::Error(failure) = result(&mut writer, 7).await else {
            panic!("authorization error")
        };
        assert_eq!(failure.code, expected.as_i32());
        assert_eq!(failure.message, message);
        assert_eq!(policy.effects.load(Ordering::SeqCst), 0);
        if code == ErrorCode::Unauthenticated {
            assert!(host.is_closed());
            assert!(host.sessions.get(&id).is_none());
        } else {
            assert_eq!(host.state().await, ConnectionState::Active);
            assert_eq!(host.sessions.get(&id).unwrap().principal, original);
            assert_eq!(host.bound_id.lock().unwrap().as_deref(), Some(id.as_str()));
            host.ingest(&call(8)).await;
            assert!(matches!(result(&mut writer, 8).await, Outcome::Payload(_)));
            assert_eq!(policy.effects.load(Ordering::SeqCst), 1);
        }
        assert!(policy
            .principals
            .lock()
            .unwrap()
            .iter()
            .all(|p| p == &original));
        assert!(writer.try_recv().is_err());
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn pending_capacity_is_sixteen_independently_of_rejection_output() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new(
        ConnectionConfig {
            max_outstanding: 16,
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler({
            let effects = effects.clone();
            move |_, _, _| {
                effects.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<HandlerOutcome>()
            }
        })),
    );
    activate(&host, &mut writer).await;
    for id in 1..=16 {
        host.ingest(&call(id)).await;
    }
    spin_until(|| effects.load(Ordering::SeqCst) == 16).await;
    for id in 17..=19 {
        host.ingest(&call(id)).await;
        error(result(&mut writer, id).await, ErrorCode::ResourceExhausted);
        assert_eq!(host.inflight_len(), 16);
        assert_eq!(host.execution_len(), 16);
        assert_eq!(effects.load(Ordering::SeqCst), 16);
        assert!(!host.is_closed());
    }
    host.ingest(&cancel(1)).await;
    error(result(&mut writer, 1).await, ErrorCode::Cancelled);
    spin_until(|| host.execution_len() == 15).await;
    host.ingest(&call(20)).await;
    spin_until(|| effects.load(Ordering::SeqCst) == 17).await;
    assert_eq!(host.inflight_len(), 16);
    assert_eq!(host.execution_len(), 16);
    host.close().await;
    assert!(writer.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn future_receipt_timestamp_is_local_input_error_not_an_extended_or_overflowed_deadline() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        echo(effects.clone()),
    );
    activate(&host, &mut writer).await;
    let mut future = now();
    // Approach the platform Instant boundary without ever using panicking add.
    // Adding another normal RPC timeout at this boundary need not be representable.
    for bit in (0..64).rev() {
        if let Some(later) = future.checked_add(Duration::from_secs(1u64 << bit)) {
            future = later;
        }
    }
    assert!(future > now());
    host.ingest_received_at(&call(1), future).await;
    assert!(host.is_closed());
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(*host.highwater.lock().unwrap(), 0);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert!(writer.try_recv().is_err());
}

fn withdrawal_finished(host: &Host) -> bool {
    host.withdrawal
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|owner| *owner.done.borrow())
}

#[tokio::test(start_paused = true)]
async fn handler_initiated_withdrawal_returns_and_independent_owner_closes_once() {
    for park_after_withdrawal in [false, true] {
        let target = Arc::new(Mutex::new(std::sync::Weak::<Host>::new()));
        let (returned, mut returns) = mpsc::channel(1);
        let handler = Arc::new(FnHandler({
            let target = target.clone();
            move |_, _, _| {
                let host = target.lock().unwrap().upgrade().unwrap();
                let returned = returned.clone();
                async move {
                    host.withdraw_principal().await;
                    // Prove that withdrawal returns to its initiating handler.
                    returned.try_send(()).unwrap();
                    if park_after_withdrawal {
                        // The worker must drop this future, without dropping the
                        // independently owned close continuation along with it.
                        return std::future::pending::<HandlerOutcome>().await;
                    }
                    HandlerOutcome::Payload(b"must not replace withdrawal".to_vec())
                }
            }
        }));
        let (host, mut writer) = Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            handler,
        );
        *target.lock().unwrap() = Arc::downgrade(&host);
        activate(&host, &mut writer).await;
        let started = now();
        host.ingest(&request(7, "/example.Auth/Withdraw", 5000))
            .await;
        tokio::time::timeout(SHUTDOWN_GRACE, returns.recv())
            .await
            .expect("handler must not wait for its own terminal output")
            .expect("handler must return from withdrawal");
        error(result(&mut writer, 7).await, ErrorCode::Unauthenticated);
        spin_until(|| host.is_closed() && withdrawal_finished(&host) && host.worker_len() == 0)
            .await;
        assert!(now().saturating_duration_since(started) <= SHUTDOWN_GRACE);
        assert_eq!(host.state().await, ConnectionState::Closed);
        assert_eq!(
            host.terminal_reason().unwrap().code(),
            ErrorCode::Unauthenticated
        );
        assert_eq!(host.sessions.count(), 0);
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.execution_len(), 0);
        assert!(
            writer.try_recv().is_err(),
            "no replacement or duplicate result"
        );
        assert!(returns.try_recv().is_err());
        let weak = Arc::downgrade(&host);
        drop(host);
        assert!(
            weak.upgrade().is_none(),
            "withdrawal owner must not retain Host"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_public_withdrawal_still_closes_without_retry_and_preserves_selection() {
    for selected_success in [false, true] {
        let handler: Arc<dyn Handler> = if selected_success {
            echo(Arc::new(AtomicUsize::new(0)))
        } else {
            Arc::new(FnHandler(|_, _, _| {
                std::future::pending::<HandlerOutcome>()
            }))
        };
        let (host, mut writer) = Host::new(
            ConnectionConfig {
                writer_capacity: 1,
                ..ConnectionConfig::default()
            },
            Arc::new(AllowAnonymous),
            handler,
        );
        activate(&host, &mut writer).await;
        host.conn.shared.writer.try_send(vec![0]).unwrap();
        host.ingest(&request(7, "/example.Echo/Echo", 5000)).await;
        if selected_success {
            spin_until(|| host.inflight_len() == 0).await;
        }
        let started = now();
        let mut withdrawal = Box::pin(host.withdraw_principal());
        assert!(futures_util::poll!(&mut withdrawal).is_pending());
        assert_eq!(host.state().await, ConnectionState::Closing);
        assert!(!withdrawal_finished(&host));
        drop(withdrawal); // No retry: the retained owner must finish alone.

        assert_eq!(writer.recv().await.unwrap(), vec![0]);
        let outcome = result(&mut writer, 7).await;
        if selected_success {
            assert_eq!(outcome, Outcome::Payload(b"ok".to_vec()));
        } else {
            error(outcome, ErrorCode::Unauthenticated);
        }
        spin_until(|| host.is_closed() && withdrawal_finished(&host) && host.worker_len() == 0)
            .await;
        assert!(now().saturating_duration_since(started) <= SHUTDOWN_GRACE);
        assert_eq!(
            host.terminal_reason().unwrap().code(),
            ErrorCode::Unauthenticated
        );
        assert_eq!(host.sessions.count(), 0);
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.execution_len(), 0);
        assert!(writer.try_recv().is_err(), "one selected result only");
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_withdrawal_has_one_absolute_budget_and_retains_external_execution() {
    let budget = ExecutionBudget::new(1);
    let (leases, mut transferred) = mpsc::unbounded_channel();
    let handler: Arc<dyn Handler> = Arc::new(External { leases });
    let (host, mut writer) = Host::new_with_execution_budget(
        ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        handler.clone(),
        budget.clone(),
    );
    activate(&host, &mut writer).await;
    host.ingest(&request(7, "/example.External/Work", 5000))
        .await;
    let external = transferred.recv().await.unwrap();
    host.conn.shared.writer.try_send(vec![0]).unwrap();
    let started = now();
    let mut first = Box::pin(host.withdraw_principal());
    assert!(futures_util::poll!(&mut first).is_pending());
    let first_done = host
        .withdrawal
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .done
        .clone();
    drop(first);
    tokio::time::advance(SHUTDOWN_GRACE / 2).await;
    assert!(!host.is_closed(), "output is still backpressured");
    let mut second = Box::pin(host.withdraw_principal());
    assert!(futures_util::poll!(&mut second).is_pending());
    assert!(host
        .withdrawal
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .done
        .same_channel(&first_done));
    drop(second); // Repeated/cancelled callers must not reset the deadline.
    tokio::time::advance(SHUTDOWN_GRACE / 2).await;
    spin_until(|| host.is_closed() && withdrawal_finished(&host) && host.output.in_use() == 0)
        .await;
    assert_eq!(now().saturating_duration_since(started), SHUTDOWN_GRACE);
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
    assert_eq!(host.sessions.count(), 0);
    assert_eq!(host.inflight_len(), 0);
    assert_eq!(host.execution_len(), 1);
    assert_eq!(host.worker_len(), 1, "external owner remains retained");
    assert_eq!(budget.in_use(), 1);
    assert_eq!(writer.try_recv().unwrap(), vec![0]);
    assert!(
        writer.try_recv().is_err(),
        "cutoff must not emit another terminal"
    );

    let (replacement, mut replacement_writer) = Host::new_with_execution_budget(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        handler,
        budget.clone(),
    );
    activate(&replacement, &mut replacement_writer).await;
    replacement.ingest(&call(1)).await;
    error(
        result(&mut replacement_writer, 1).await,
        ErrorCode::ResourceExhausted,
    );
    assert!(
        transferred.try_recv().is_err(),
        "surviving work still consumes shared capacity"
    );
    drop(external);
    spin_until(|| budget.in_use() == 0 && host.worker_len() == 0).await;
    replacement.close().await;
}
