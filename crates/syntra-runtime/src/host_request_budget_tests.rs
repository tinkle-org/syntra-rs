//! Request-wide local caps through the real bounded host admission path.
use super::*;
use crate::elapsed::{ElapsedClock, ElapsedDeadline, ElapsedSource};
use std::sync::atomic::AtomicU64;

/// Advance trusted elapsed time without sleeping or blocking a callback.
#[derive(Default)]
struct Source(AtomicU64);
impl ElapsedSource for Source {
    /// Read the test-controlled monotonic millisecond counter.
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}

/// Capture the same shrinking budget at each application boundary.
struct BudgetPolicy {
    cap: Option<Duration>,
    source: Arc<Source>,
    selector_ms: u64,
    auth_ms: u64,
    finish_ms: AtomicU64,
    selections: AtomicUsize,
    authorized: Mutex<Vec<ElapsedDeadline>>,
    contexts: Mutex<Vec<ElapsedDeadline>>,
    effects: AtomicUsize,
    host: Mutex<Weak<Host>>,
}
impl Handler for BudgetPolicy {
    /// Verify lock-free classification, charge selector time, and return the local cap.
    fn request_budget(&self, _: &Principal, method: &str, payload: &[u8]) -> Option<Duration> {
        assert_eq!(method, "/example.Echo/Echo");
        assert!(payload.is_empty());
        let host = self.host.lock().unwrap().upgrade().unwrap();
        assert!(
            host.conn.shared.state.try_write().is_ok(),
            "classifier holds lifecycle lock"
        );
        assert!(host.calls.try_lock().is_ok());
        assert!(host.highwater.try_lock().is_ok());
        self.selections.fetch_add(1, Ordering::SeqCst);
        self.source.0.fetch_add(self.selector_ms, Ordering::SeqCst);
        self.cap
    }
    /// Retain the admitted deadline and charge simulated authorization time to it.
    fn authorize_with_budget(
        &self,
        _: &Principal,
        _: &str,
        budget: ElapsedDeadline,
    ) -> Result<(), AuthError> {
        self.authorized.lock().unwrap().push(budget);
        self.source.0.fetch_add(self.auth_ms, Ordering::SeqCst);
        Ok(())
    }
    /// Reject legacy dispatch so the test cannot miss request-context propagation.
    fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
        panic!("context-aware dispatch required")
    }
    /// Record dispatch and advance elapsed time before returning a ready payload.
    fn handle_with_context(
        &self,
        _: String,
        _: Vec<u8>,
        _: crate::CancelToken,
        _: ExecutionLease,
        context: terminal::RequestContext,
    ) -> HandlerFut {
        self.contexts.lock().unwrap().push(context.budget());
        self.effects.fetch_add(1, Ordering::SeqCst);
        let source = self.source.clone();
        let finish_ms = self.finish_ms.load(Ordering::SeqCst);
        Box::pin(async move {
            source.0.fetch_add(finish_ms, Ordering::SeqCst);
            HandlerOutcome::Payload(b"ok".to_vec())
        })
    }
}

/// Activate a host with independent default/deployment limits and a driven policy clock.
async fn fixture(
    cap: Option<Duration>,
    selector_ms: u64,
    auth_ms: u64,
) -> (Arc<Host>, mpsc::Receiver<Vec<u8>>, Arc<BudgetPolicy>) {
    let policy = Arc::new(BudgetPolicy {
        cap,
        source: Arc::new(Source::default()),
        selector_ms,
        auth_ms,
        finish_ms: AtomicU64::new(0),
        selections: AtomicUsize::new(0),
        authorized: Mutex::new(vec![]),
        contexts: Mutex::new(vec![]),
        effects: AtomicUsize::new(0),
        host: Mutex::new(Weak::new()),
    });
    let (host, mut writer) = Host::try_new_with_clock(
        ConnectionConfig {
            default_timeout: Duration::from_millis(200),
            max_rpc_timeout: Duration::from_millis(300),
            ..ConnectionConfig::default()
        },
        Arc::new(AllowAnonymous),
        policy.clone(),
        ElapsedClock::with_source(policy.source.clone()),
    )
    .unwrap();
    *policy.host.lock().unwrap() = Arc::downgrade(&host);
    activate(&host, &mut writer).await;
    (host, writer, policy)
}

/// No cap, long caps and unrepresentable caps never extend wire/default/deployment time.
#[tokio::test(start_paused = true)]
async fn optional_long_and_huge_caps_preserve_existing_deadlines() {
    for cap in [None, Some(Duration::from_secs(1)), Some(Duration::MAX)] {
        for (wire_ms, expected_ms) in [(100, 100), (0, 200), (1000, 300)] {
            let (host, mut writer, policy) = fixture(cap, 0, 0).await;
            host.ingest(&request(7, "/example.Echo/Echo", wire_ms))
                .await;
            assert_eq!(
                result(&mut writer, 7).await,
                Outcome::Payload(b"ok".to_vec())
            );
            assert_eq!(
                policy.authorized.lock().unwrap()[0].remaining(),
                Ok(Duration::from_millis(expected_ms))
            );
            assert_eq!(
                policy.contexts.lock().unwrap()[0].remaining(),
                Ok(Duration::from_millis(expected_ms))
            );
            host.close().await;
        }
    }
}

/// The local cap is based on original receipt, never selector/auth entry or dispatch.
#[tokio::test(start_paused = true)]
async fn original_receipt_includes_queue_selector_and_authorization_time() {
    let (host, mut writer, policy) = fixture(Some(Duration::from_millis(100)), 20, 30).await;
    let received = host.elapsed_clock().now();
    let gate = host.admission.lock().await;
    let bytes = call(7);
    let mut input = Box::pin(host.ingest_received_at(&bytes, received));
    assert!(futures_util::poll!(&mut input).is_pending());
    policy.source.0.store(40, Ordering::SeqCst);
    drop(gate);
    input.await;
    assert_eq!(
        result(&mut writer, 7).await,
        Outcome::Payload(b"ok".to_vec())
    );
    let auth = policy.authorized.lock().unwrap()[0].clone();
    let context = policy.contexts.lock().unwrap()[0].clone();
    assert_eq!(auth.remaining(), Ok(Duration::from_millis(10)));
    assert_eq!(context.remaining(), auth.remaining());
    policy.source.0.store(100, Ordering::SeqCst);
    assert!(auth.check().is_err());
    assert!(
        context.check().is_err(),
        "retained readonly budget must expire too"
    );
    host.close().await;
}

/// Zero is immediate expiry; selector/auth time cannot buy another dispatch window.
#[tokio::test(start_paused = true)]
async fn zero_and_expiry_during_policy_prevent_handler_effects() {
    for (cap_ms, selector_ms, auth_ms, auth_calls) in
        [(0, 0, 0, 0), (100, 100, 0, 0), (100, 20, 80, 1)]
    {
        let (host, mut writer, policy) =
            fixture(Some(Duration::from_millis(cap_ms)), selector_ms, auth_ms).await;
        host.ingest(&call(7)).await;
        error(result(&mut writer, 7).await, ErrorCode::DeadlineExceeded);
        assert_eq!(policy.effects.load(Ordering::SeqCst), 0);
        assert_eq!(policy.authorized.lock().unwrap().len(), auth_calls);
        assert_eq!(host.execution_len(), 0);
        assert_eq!(*host.highwater.lock().unwrap(), 7);
        host.close().await;
    }
}

/// Pending selection and the last dispatch gate both use the selected local D.
#[tokio::test(start_paused = true)]
async fn local_deadline_wins_at_dispatch_and_at_ready_completion() {
    for before_dispatch in [true, false] {
        let (host, mut writer, policy) = fixture(Some(Duration::from_millis(100)), 0, 0).await;
        if !before_dispatch {
            policy.finish_ms.store(100, Ordering::SeqCst);
        }
        host.ingest(&call(7)).await;
        if before_dispatch {
            policy.source.0.store(100, Ordering::SeqCst);
        }
        error(result(&mut writer, 7).await, ErrorCode::DeadlineExceeded);
        assert_eq!(
            policy.effects.load(Ordering::SeqCst),
            usize::from(!before_dispatch)
        );
        assert_eq!(host.inflight_len(), 0);
        assert!(writer.try_recv().is_err());
        host.close().await;
    }
}

/// A local cap exhausted entirely in admission cannot run initial authorization.
#[tokio::test(start_paused = true)]
async fn queue_expiry_is_not_restarted_at_budget_selection() {
    let (host, mut writer, policy) = fixture(Some(Duration::from_millis(100)), 0, 0).await;
    let received = host.elapsed_clock().now();
    let gate = host.admission.lock().await;
    let bytes = call(7);
    let mut input = Box::pin(host.ingest_received_at(&bytes, received));
    assert!(futures_util::poll!(&mut input).is_pending());
    policy.source.0.store(100, Ordering::SeqCst);
    drop(gate);
    input.await;
    error(result(&mut writer, 7).await, ErrorCode::DeadlineExceeded);
    assert_eq!(policy.selections.load(Ordering::SeqCst), 1);
    assert!(policy.authorized.lock().unwrap().is_empty());
    assert_eq!(policy.effects.load(Ordering::SeqCst), 0);
    host.close().await;
}

/// AllowAll forwards caps/context while keeping its intentional authorization bypass.
#[tokio::test(start_paused = true)]
async fn allow_all_preserves_scoped_caps_and_unrelated_methods() {
    struct Scoped;
    impl Handler for Scoped {
        /// Expire only Echo, leaving other methods subject to their ordinary deadline.
        fn request_budget(&self, _: &Principal, method: &str, _: &[u8]) -> Option<Duration> {
            (method == "/example.Echo/Echo").then_some(Duration::ZERO)
        }
        /// Fail if AllowAll delegates authorization instead of preserving its bypass.
        fn authorize_with_budget(
            &self,
            _: &Principal,
            _: &str,
            _: ElapsedDeadline,
        ) -> Result<(), AuthError> {
            panic!("AllowAll must retain its explicit authorization bypass")
        }
        /// Fail if AllowAll drops the request context during dispatch.
        fn handle(&self, _: String, _: Vec<u8>, _: crate::CancelToken) -> HandlerFut {
            panic!("AllowAll must forward context")
        }
        /// Verify the unrelated method retains its full wire budget through AllowAll.
        fn handle_with_context(
            &self,
            _: String,
            _: Vec<u8>,
            _: crate::CancelToken,
            _: ExecutionLease,
            context: terminal::RequestContext,
        ) -> HandlerFut {
            assert_eq!(context.budget().remaining(), Ok(Duration::from_secs(1)));
            Box::pin(async { HandlerOutcome::Payload(b"ordinary".to_vec()) })
        }
    }
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        Arc::new(AllowAll(Scoped)),
    );
    activate(&host, &mut writer).await;
    host.ingest(&call(7)).await;
    error(result(&mut writer, 7).await, ErrorCode::DeadlineExceeded);
    host.ingest(&request(8, "/example.Echo/Other", 1000)).await;
    assert_eq!(
        result(&mut writer, 8).await,
        Outcome::Payload(b"ordinary".to_vec())
    );
    host.close().await;
}

/// Validation and reserved profile routing precede any application classifier.
#[tokio::test(start_paused = true)]
async fn invalid_envelopes_methods_and_recovery_never_reach_classifier() {
    let (host, mut writer, policy) = fixture(Some(Duration::ZERO), 0, 0).await;
    host.ingest(&request(7, "invalid", 1000)).await;
    error(result(&mut writer, 7).await, ErrorCode::InvalidArgument);
    let mut malformed = call(8);
    malformed.extend([0x62, 0]);
    host.ingest(&malformed).await;
    assert_eq!(policy.selections.load(Ordering::SeqCst), 0);
    host.ingest(&request(9, "/syntra.v1.UpdateRecovery/Unknown", 1000))
        .await;
    error(result(&mut writer, 9).await, ErrorCode::Unimplemented);
    assert_eq!(policy.selections.load(Ordering::SeqCst), 0);
    host.ingest(
        &Frame {
            version: 1,
            request_id: 10,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![0; syntra_core::MAX_FRAME_BYTES],
                timeout_ms: 1000,
            })),
        }
        .encode_to_vec(),
    )
    .await;
    assert!(host.is_closed());
    assert_eq!(policy.selections.load(Ordering::SeqCst), 0);
    host.close().await;
}
