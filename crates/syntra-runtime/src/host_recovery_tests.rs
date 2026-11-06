//! Host attachment tests use actual bounded core frames, not an application
//! handler pretending to implement the recovery profile. No external bridge.

use super::*;
use crate::recovery::wire::{
    AuthorizationHook, PageBudget, ProviderPage, ProviderSnapshot, ProviderStream, RecoveryLimits,
    RecoverySource,
};
use crate::session::StaticToken;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use syntra_core::proto::*;
use syntra_core::ErrorCode;

#[derive(Default)]
struct Source {
    seen: Mutex<Vec<Principal>>,
    denied: Mutex<Option<ProviderError>>,
    denied_selector: Mutex<Option<Vec<u8>>>,
    delay: Mutex<Duration>,
    emit_calls: AtomicUsize,
    generations: Mutex<HashMap<Vec<u8>, u64>>,
    generation_error: Mutex<Option<ProviderError>>,
    validate_issued_error: Mutex<Option<ProviderError>>,
}

impl RecoverySource for Source {
    fn authorize(
        &self,
        p: &Principal,
        selector: &[u8],
        hook: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        if matches!(hook, AuthorizationHook::Emit) {
            self.emit_calls.fetch_add(1, Ordering::SeqCst);
        }
        self.seen.lock().unwrap().push(p.clone());
        let delay = *self.delay.lock().unwrap();
        // Deliberate provider-contract violation to prove late denial still
        // withdraws the root principal even when the RPC deadline wins.
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if self
            .denied_selector
            .lock()
            .unwrap()
            .as_deref()
            .is_some_and(|s| s != selector)
        {
            return Ok(());
        }
        self.denied.lock().unwrap().map_or(Ok(()), Err)
    }
    fn capture(&self, p: &Principal, selector: &[u8]) -> Result<ProviderStream, ProviderError> {
        ProviderStream::new(
            selector.to_vec(),
            self.current_generation(p, selector)?,
            b"c0".to_vec(),
        )
    }
    fn current_generation(&self, _: &Principal, identity: &[u8]) -> Result<u64, ProviderError> {
        if let Some(error) = *self.generation_error.lock().unwrap() {
            return Err(error);
        }
        Ok(*self.generations.lock().unwrap().get(identity).unwrap_or(&1))
    }
    fn validate_issued(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &[u8],
    ) -> Result<(), ProviderError> {
        self.validate_issued_error
            .lock()
            .unwrap()
            .map_or(Ok(()), Err)
    }
    fn replay(
        &self,
        _: &Principal,
        s: &ProviderStream,
        _: &[u8],
        _: &[u8],
        _: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        ProviderPage::new(vec![], s.boundary().to_vec(), vec![])
    }
    fn snapshot(
        &self,
        _: &Principal,
        _: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        Err(ProviderError::Unimplemented)
    }
    fn snapshot_page(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &ProviderSnapshot,
        _: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unimplemented)
    }
}

#[derive(Default)]
struct Application {
    authorizations: AtomicUsize,
    executions: AtomicUsize,
}
impl Handler for Application {
    fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::denied())
    }
    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        self.executions.fetch_add(1, Ordering::SeqCst);
        panic!("built-in profile must not reach application handler")
    }
}

fn service(source: Arc<Source>) -> Arc<RecoveryService> {
    RecoveryService::new(source, RecoveryLimits::default()).unwrap()
}

async fn activate(host: &Host, writer: &mut mpsc::Receiver<Vec<u8>>) {
    host.ingest(
        &Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: b"credential".to_vec(),
            })),
        }
        .encode_to_vec(),
    )
    .await;
    let frame = receive(writer).await;
    assert!(matches!(frame.body, Some(Body::Ready(_))));
    assert_eq!(host.state().await, ConnectionState::Active);
}

fn new_host(config: ConnectionConfig) -> (Arc<Host>, mpsc::Receiver<Vec<u8>>, Arc<Application>) {
    let app = Arc::new(Application::default());
    let (host, writer) = Host::new(
        config,
        Arc::new(StaticToken::new(b"credential".to_vec(), "actual-principal")),
        app.clone(),
    );
    (host, writer, app)
}

async fn receive(writer: &mut mpsc::Receiver<Vec<u8>>) -> Frame {
    let bytes = tokio::time::timeout(Duration::from_secs(2), writer.recv())
        .await
        .unwrap()
        .unwrap();
    Frame::decode(bytes.as_slice()).unwrap()
}

async fn send(host: &Host, id: u64, method: &str, payload: Vec<u8>, timeout_ms: u32) {
    host.ingest(
        &Frame {
            version: 1,
            request_id: id,
            body: Some(Body::Request(RpcRequest {
                method: method.into(),
                payload,
                timeout_ms,
            })),
        }
        .encode_to_vec(),
    )
    .await;
}

fn result(frame: Frame, id: u64) -> Result<Vec<u8>, ErrorCode> {
    assert_eq!(frame.request_id, id);
    match frame.body {
        Some(Body::Result(RpcResult {
            outcome: Some(rpc_result::Outcome::Payload(p)),
        })) => Ok(p),
        Some(Body::Result(RpcResult {
            outcome: Some(rpc_result::Outcome::Error(e)),
        })) => Err(ErrorCode::from_i32_lossy(e.code).0),
        _ => panic!("expected terminal RPC result"),
    }
}

async fn negotiate(host: &Host, writer: &mut mpsc::Receiver<Vec<u8>>) {
    send(
        host,
        1,
        wire::NEGOTIATE,
        RecoveryNegotiateRequest {
            profile_version: 1,
            capability: wire::CAPABILITY.into(),
            min_version: 1,
            max_version: 1,
        }
        .encode_to_vec(),
        0,
    )
    .await;
    let payload = result(receive(writer).await, 1).unwrap();
    assert_eq!(
        RecoveryNegotiateResponse::decode(payload.as_slice())
            .unwrap()
            .selected_version,
        1
    );
}

fn subscribe_payload(selector: &[u8]) -> Vec<u8> {
    RecoverySubscribeRequest {
        profile_version: 1,
        stream_selector: selector.to_vec(),
        start_checkpoint: vec![],
    }
    .encode_to_vec()
}

async fn subscribe(
    host: &Host,
    writer: &mut mpsc::Receiver<Vec<u8>>,
    id: u64,
    selector: &[u8],
) -> Vec<u8> {
    send(host, id, wire::SUBSCRIBE, subscribe_payload(selector), 0).await;
    let payload = result(receive(writer).await, id).unwrap();
    RecoverySubscribeResponse::decode(payload.as_slice())
        .unwrap()
        .subscription_handle
}

fn bound_session(host: &Host) -> Arc<RecoveryHostSession> {
    host.recovery
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .binding
        .as_ref()
        .unwrap()
        .session
        .clone()
}

async fn closed(host: &Host) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !host.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

/// The actual recovery attachment closes before the conditional terminal transition.
#[tokio::test]
async fn terminal_reservation_retires_actual_recovery_attachment_before_transition() {
    use crate::terminal::{
        Authority, DriverCommand, Observation, Policy, RequestContext, Transition,
    };
    use futures_util::future::BoxFuture;
    /// In-memory owner evidence for retirement of an actual recovery attachment.
    struct Owned(Mutex<Option<Transition>>);
    impl Authority for Owned {
        /// Report active authority or the owner recorded by the transition callback.
        fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
            Box::pin(async {
                match self.0.lock().unwrap().as_ref() {
                    None => Observation::Active { revision: 1 },
                    Some(c) => Observation::OwnedCommitted {
                        reservation: c.reservation.clone(),
                        expected_revision: 1,
                        revision: 2,
                    },
                }
            })
        }
        /// Record ownership after the test has checked the recovery-close barrier.
        fn commit(&self, c: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                *self.0.lock().unwrap() = Some(c);
            })
        }
    }
    /// Require context-aware retirement for the recovery-attachment fixture.
    struct Retire;
    impl Handler for Retire {
        /// Admit fixture requests to the retirement hook.
        fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
            Ok(())
        }
        /// Fail if dispatch bypasses the request context.
        fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
            panic!("context hook required")
        }
        /// Retire at the fixture's active revision and return its fixed outcome.
        fn handle_with_context(
            &self,
            _: String,
            _: Vec<u8>,
            _: CancelToken,
            _: ExecutionLease,
            c: RequestContext,
        ) -> HandlerFut {
            Box::pin(async move { c.retire(1).await.unwrap() })
        }
    }
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(StaticToken::new(b"credential".to_vec(), "actual-principal")),
        Arc::new(Retire),
    );
    let authority = Arc::new(Owned(Mutex::new(None)));
    let coordinator = host
        .install_terminal_tcp(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(250),
        })
        .unwrap();
    coordinator.refresh().await.unwrap();
    host.configure_recovery(service(Arc::new(Source::default())))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    subscribe(&host, &mut writer, 2, b"stream").await;
    let recovery = bound_session(&host);
    let mut commands = host.take_terminal_commands().unwrap();
    send(&host, 3, "/example.Authority/Retire", vec![], 2000).await;
    let Some(DriverCommand::Barrier(ack)) = commands.recv().await else {
        panic!("expected barrier")
    };
    assert!(
        recovery.is_closed(),
        "actual recovery producer closes before mutation"
    );
    assert!(authority.0.lock().unwrap().is_none());
    assert!(host.notify(b"protected".to_vec()).await.is_err());
    assert!(
        writer.try_recv().is_err(),
        "no ordinary recovery/result output"
    );
    ack.send(()).unwrap(); // Runtime-only fixture; native barriers tested separately.
    let Some(DriverCommand::Receipt(output)) = commands.recv().await else {
        panic!("expected exact typed result")
    };
    assert_eq!(
        result(Frame::decode(output.bytes()).unwrap(), 3).unwrap(),
        b"retired"
    );
    coordinator.refresh().await.unwrap();
    assert!(coordinator
        .with_receipt_io(&output, &mut true, || ())
        .is_some());
    coordinator.written();
    closed(&host).await;
    assert!(writer.try_recv().is_err());
    host.close().await;
}

/// Exercise real application/recovery workers with a preemption at the shared
/// last-check/hook gap, and real RequestContext reservation on the other task.
async fn reservation_dispatch_linearization(profile: bool) {
    use crate::terminal::{
        Authority, DriverCommand, Observation, Policy, RequestContext, Transition,
    };
    use futures_util::future::BoxFuture;
    /// In-memory authority used to observe mutation ordering across dispatch.
    struct Owned(Mutex<Option<Transition>>);
    impl Authority for Owned {
        /// Report active authority until the exact operation owner is recorded.
        fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
            Box::pin(async {
                match self.0.lock().unwrap().as_ref() {
                    None => Observation::Active { revision: 1 },
                    Some(c) => Observation::OwnedCommitted {
                        reservation: c.reservation.clone(),
                        expected_revision: 1,
                        revision: 2,
                    },
                }
            })
        }
        /// Record the owner so the test can detect mutation before dispatch completes.
        fn commit(&self, c: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                *self.0.lock().unwrap() = Some(c);
            })
        }
    }
    /// Capture a retirement context and count ordinary synchronous hook construction.
    struct Capture {
        context: Mutex<Option<oneshot::Sender<RequestContext>>>,
        effects: Arc<AtomicUsize>,
    }
    impl Handler for Capture {
        /// Admit fixture requests for the dispatch-ordering test.
        fn authorize(&self, _: &Principal, _: &str) -> Result<(), AuthError> {
            Ok(())
        }
        /// Fail if dispatch omits the context-aware hook.
        fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
            panic!("context hook required")
        }
        /// Export the retirement context or synchronously count an ordinary dispatch.
        fn handle_with_context(
            &self,
            method: String,
            _: Vec<u8>,
            _: CancelToken,
            _: ExecutionLease,
            context: RequestContext,
        ) -> HandlerFut {
            if method == "/example.Authority/Retire" {
                assert!(self
                    .context
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(context)
                    .is_ok());
                return Box::pin(std::future::pending());
            }
            self.effects.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { HandlerOutcome::Payload(b"ordinary".to_vec()) })
        }
    }
    let (capture, captured) = oneshot::channel();
    let effects = Arc::new(AtomicUsize::new(0));
    let (host, mut writer) = Host::new(
        ConnectionConfig::default(),
        Arc::new(StaticToken::new(b"credential".to_vec(), "actual-principal")),
        Arc::new(Capture {
            context: Mutex::new(Some(capture)),
            effects: effects.clone(),
        }),
    );
    let authority = Arc::new(Owned(Mutex::new(None)));
    let coordinator = host
        .install_terminal_tcp(Policy {
            method: "/example.Authority/Retire".into(),
            payload: b"retired".to_vec(),
            authority: authority.clone(),
            read_timeout: Duration::from_millis(250),
        })
        .unwrap();
    coordinator.refresh().await.unwrap();
    let source = Arc::new(Source::default());
    host.configure_recovery(service(source.clone()))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    send(&host, 2, "/example.Authority/Retire", vec![], 2000).await;
    let context = captured.await.unwrap();
    let pause = Arc::new(DispatchPause {
        id: 3,
        checked: Notify::new(),
        release: Notify::new(),
    });
    *host.dispatch_pause.lock().unwrap() = Some(pause.clone());
    let before = source.seen.lock().unwrap().len();
    let method = if profile {
        wire::SUBSCRIBE
    } else {
        "/example.Authority/Ordinary"
    };
    let payload = if profile {
        subscribe_payload(b"stream")
    } else {
        vec![]
    };
    send(&host, 3, method, payload, 2000).await;
    pause.checked.notified().await;
    let mut retiring = Box::pin(context.retire(1));
    assert!(futures_util::poll!(&mut retiring).is_pending());
    assert!(
        !coordinator.fenced(),
        "reservation crossed the checked-but-not-dispatched worker"
    );
    assert!(
        authority.0.lock().unwrap().is_none(),
        "no transition before the synchronous hook finishes"
    );
    pause.release.notify_one();
    let mut commands = host.take_terminal_commands().unwrap();
    let driver = async {
        let Some(DriverCommand::Barrier(ack)) = commands.recv().await else {
            panic!("expected barrier")
        };
        if profile {
            assert!(
                source.seen.lock().unwrap().len() > before,
                "prepared recovery dispatch must run before fencing"
            );
        } else {
            assert_eq!(
                effects.load(Ordering::SeqCst),
                1,
                "synchronous application construction must finish before fencing"
            );
        }
        ack.send(()).unwrap();
    };
    let (outcome, ()) = tokio::join!(retiring, driver);
    host.calls.lock().unwrap().select(2, outcome.unwrap());
    let Some(DriverCommand::Receipt(output)) = commands.recv().await else {
        panic!("expected receipt")
    };
    assert!(coordinator
        .with_receipt_io(&output, &mut true, || ())
        .is_some());
    coordinator.written();
    drop(output);
    drop(context);
    closed(&host).await;
    host.close().await;
}

/// Reservation cannot cross the worker's final check/application-hook construction gap.
#[tokio::test]
async fn terminal_fence_waits_for_application_hook_construction() {
    reservation_dispatch_linearization(false).await;
}

/// Reservation waits for an already-checked prepared recovery dispatch to complete.
#[tokio::test]
async fn terminal_fence_waits_for_prepared_recovery_dispatch() {
    reservation_dispatch_linearization(true).await;
}

#[tokio::test]
async fn mandatory_only_refuses_the_entire_profile_prefix_without_app_policy() {
    let (host, mut writer, app) = new_host(ConnectionConfig::default());
    activate(&host, &mut writer).await;
    for (index, method) in wire::METHODS
        .iter()
        .chain(["/syntra.v1.UpdateRecovery/Future"].iter())
        .enumerate()
    {
        let id = index as u64 + 1;
        send(&host, id, method, vec![], 0).await;
        assert_eq!(
            result(receive(&mut writer).await, id),
            Err(ErrorCode::Unimplemented)
        );
    }
    assert_eq!(app.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(app.executions.load(Ordering::SeqCst), 0);
    assert!(host.recovery.lock().unwrap().is_none());
    host.close().await;
}

#[tokio::test]
async fn configuration_is_connected_only_single_and_lazy_unknown_has_no_effects() {
    let source = Arc::new(Source::default());
    let service = service(source.clone());
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service.clone()).await.unwrap();
    assert_eq!(
        host.configure_recovery(service.clone())
            .await
            .unwrap_err()
            .code(),
        ErrorCode::FailedPrecondition
    );
    assert!(host
        .recovery
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .binding
        .is_none());
    activate(&host, &mut writer).await;
    assert_eq!(
        host.configure_recovery(service).await.unwrap_err().code(),
        ErrorCode::FailedPrecondition
    );
    send(&host, 1, "/syntra.v1.UpdateRecovery/Future", vec![], 0).await;
    assert_eq!(
        result(receive(&mut writer).await, 1),
        Err(ErrorCode::Unimplemented)
    );
    assert!(host
        .recovery
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .binding
        .is_none());
    assert!(source.seen.lock().unwrap().is_empty());
    host.close().await;
}

#[tokio::test]
async fn profile_binds_actual_core_principal_and_application_stays_fail_closed() {
    let source = Arc::new(Source::default());
    let (host, mut writer, app) = new_host(ConnectionConfig::default());
    host.configure_recovery(service(source.clone()))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    let binding = bound_session(&host);
    subscribe(&host, &mut writer, 2, b"stream").await;
    assert!(Arc::ptr_eq(&binding, &bound_session(&host)));
    assert_eq!(binding.principal(), &Principal::new("actual-principal"));
    assert!(source
        .seen
        .lock()
        .unwrap()
        .iter()
        .all(|p| p == binding.principal()));
    assert_eq!(app.authorizations.load(Ordering::SeqCst), 0);
    send(&host, 3, "/example.App/Protected", vec![], 0).await;
    assert_eq!(
        result(receive(&mut writer).await, 3),
        Err(ErrorCode::PermissionDenied)
    );
    assert_eq!(app.authorizations.load(Ordering::SeqCst), 1);
    host.close().await;
    assert!(binding.is_closed());
    assert_eq!(binding.queue_counts(), Err(ProviderError::Unavailable));
}

#[tokio::test]
async fn profile_default_is_source_deadline_clamped_to_core_and_explicit_is_unchanged() {
    let (host, _, _) = new_host(ConnectionConfig {
        default_timeout: Duration::from_millis(10),
        max_rpc_timeout: Duration::from_secs(3),
        ..ConnectionConfig::default()
    });
    let mut req = RpcRequest {
        method: wire::NEGOTIATE.into(),
        ..Default::default()
    };
    assert_eq!(host.request_timeout(&req), Duration::from_secs(3));
    let limits = RecoveryLimits {
        default_deadline: Duration::from_secs(2),
        ..Default::default()
    };
    host.configure_recovery(RecoveryService::new(Arc::new(Source::default()), limits).unwrap())
        .await
        .unwrap();
    assert_eq!(host.request_timeout(&req), Duration::from_secs(2));
    req.timeout_ms = 1;
    assert_eq!(host.request_timeout(&req), Duration::from_millis(1));
    req.timeout_ms = 0;
    req.method = "/example.App/Protected".into();
    assert_eq!(host.request_timeout(&req), Duration::from_millis(10));
    host.close().await;
}

#[tokio::test]
async fn expired_receipt_consumes_id_before_profile_admission_without_binding() {
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service(Arc::new(Source::default())))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    let bytes = Frame {
        version: 1,
        request_id: 7,
        body: Some(Body::Request(RpcRequest {
            method: wire::NEGOTIATE.into(),
            payload: vec![],
            timeout_ms: 1,
        })),
    }
    .encode_to_vec();
    host.ingest_received_at(&bytes, now() - Duration::from_millis(20))
        .await;
    assert_eq!(
        result(receive(&mut writer).await, 7),
        Err(ErrorCode::DeadlineExceeded)
    );
    assert!(host
        .recovery
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .binding
        .is_none());
    host.ingest(&bytes).await;
    assert!(host.is_closed());
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::FailedPrecondition
    );
}

#[tokio::test]
async fn independent_profile_quota_does_not_lower_the_core_floor() {
    let limits = RecoveryLimits {
        pending_rpcs_per_connection: 1,
        ..Default::default()
    };
    let service = RecoveryService::new(Arc::new(Source::default()), limits).unwrap();
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service).await.unwrap();
    activate(&host, &mut writer).await;
    let first = host
        .prepare_recovery(&Principal::new("actual-principal"))
        .unwrap();
    send(&host, 1, wire::NEGOTIATE, vec![], 0).await;
    assert_eq!(
        result(receive(&mut writer).await, 1),
        Err(ErrorCode::ResourceExhausted)
    );
    assert!(host.conn.shared.config.max_outstanding >= 16);
    drop(first);
    send(
        &host,
        2,
        wire::NEGOTIATE,
        RecoveryNegotiateRequest {
            profile_version: 1,
            capability: wire::CAPABILITY.into(),
            min_version: 1,
            max_version: 1,
        }
        .encode_to_vec(),
        0,
    )
    .await;
    result(receive(&mut writer).await, 2).unwrap();
    host.close().await;
}

#[tokio::test]
async fn notification_worker_emits_without_application_consumer_or_rpc_completion() {
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service(Arc::new(Source::default())))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    let handle = subscribe(&host, &mut writer, 2, b"stream").await;
    send(
        &host,
        3,
        wire::CATCH_UP,
        RecoveryCatchUpRequest {
            profile_version: 1,
            subscription_handle: handle.clone(),
        }
        .encode_to_vec(),
        0,
    )
    .await;
    let mut results = 0;
    let mut notifications = 0;
    for _ in 0..2 {
        let frame = receive(&mut writer).await;
        if frame.request_id == 3 {
            result(frame, 3).unwrap();
            results += 1;
        } else {
            assert_eq!(frame.request_id, 0);
            let Some(Body::Notification(n)) = frame.body else {
                panic!("notification expected")
            };
            assert!(RecoveryNotification::decode(n.payload.as_slice())
                .unwrap()
                .notification
                .is_some());
            notifications += 1;
        }
    }
    assert_eq!((results, notifications), (1, 1));
    host.close().await;
}

#[tokio::test]
async fn rpc_unauthenticated_withdraws_core_not_just_stream() {
    let source = Arc::new(Source::default());
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service(source.clone()))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    *source.denied.lock().unwrap() = Some(ProviderError::Unauthenticated);
    send(&host, 2, wire::SUBSCRIBE, subscribe_payload(b"stream"), 0).await;
    assert_eq!(
        result(receive(&mut writer).await, 2),
        Err(ErrorCode::Unauthenticated)
    );
    closed(&host).await;
    assert_eq!(host.sessions.count(), 0);
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
    assert!(bound_session(&host).is_closed());
}

#[tokio::test]
async fn late_rpc_unauthenticated_still_withdraws_when_deadline_wins() {
    let source = Arc::new(Source::default());
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service(source.clone()))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    *source.denied.lock().unwrap() = Some(ProviderError::Unauthenticated);
    *source.delay.lock().unwrap() = Duration::from_millis(20);
    send(&host, 2, wire::SUBSCRIBE, subscribe_payload(b"stream"), 5).await;
    assert_eq!(
        result(receive(&mut writer).await, 2),
        Err(ErrorCode::DeadlineExceeded)
    );
    closed(&host).await;
    assert_eq!(host.sessions.count(), 0);
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
}

fn live_batch() -> wire::StoredBatch {
    wire::StoredBatch {
        generation: 1,
        predecessor: b"c0".to_vec(),
        result: b"c1".to_vec(),
        payload: b"event".to_vec(),
    }
}

#[tokio::test]
async fn notification_unauthenticated_withdraws_before_a_pending_terminal_trailer() {
    let source = Arc::new(Source::default());
    let service = service(source.clone());
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service.clone()).await.unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    subscribe(&host, &mut writer, 2, b"stream").await;
    *source.denied.lock().unwrap() = Some(ProviderError::Unauthenticated);
    assert_eq!(
        service.publish(&Principal::new("actual-principal"), b"stream", live_batch()),
        Err(ProviderError::Unauthenticated)
    );
    closed(&host).await;
    assert_eq!(host.sessions.count(), 0);
    assert_eq!(
        host.terminal_reason().unwrap().code(),
        ErrorCode::Unauthenticated
    );
    assert!(
        writer.try_recv().is_err(),
        "revocation trailer must not escape root fencing"
    );
}

#[tokio::test]
async fn notification_permission_denial_retires_only_the_target_stream() {
    let source = Arc::new(Source::default());
    let service = service(source.clone());
    let (host, mut writer, _) = new_host(ConnectionConfig::default());
    host.configure_recovery(service.clone()).await.unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    let denied_handle = subscribe(&host, &mut writer, 2, b"denied").await;
    subscribe(&host, &mut writer, 3, b"allowed").await;
    *source.denied_selector.lock().unwrap() = Some(b"denied".to_vec());
    *source.denied.lock().unwrap() = Some(ProviderError::PermissionDenied);
    assert_eq!(
        service.publish(&Principal::new("actual-principal"), b"denied", live_batch()),
        Err(ProviderError::PermissionDenied)
    );
    let frame = receive(&mut writer).await;
    assert_eq!(frame.request_id, 0);
    let Some(Body::Notification(n)) = frame.body else {
        panic!("expected targeted terminal")
    };
    let n = RecoveryNotification::decode(n.payload.as_slice()).unwrap();
    let Some(recovery_notification::Notification::Trailer(t)) = n.notification else {
        panic!("expected terminal trailer")
    };
    assert_eq!(t.subscription_handle, denied_handle);
    assert_eq!(host.state().await, ConnectionState::Active);
    assert_eq!(
        bound_session(&host).queue_counts().unwrap().subscriptions,
        1
    );
    host.close().await;
}

#[tokio::test]
async fn close_wakes_a_backpressured_notification_worker() {
    let (host, mut writer, _) = new_host(ConnectionConfig {
        writer_capacity: 1,
        ..ConnectionConfig::default()
    });
    host.configure_recovery(service(Arc::new(Source::default())))
        .await
        .unwrap();
    activate(&host, &mut writer).await;
    negotiate(&host, &mut writer).await;
    let handle = subscribe(&host, &mut writer, 2, b"stream").await;
    send(
        &host,
        3,
        wire::CATCH_UP,
        RecoveryCatchUpRequest {
            profile_version: 1,
            subscription_handle: handle,
        }
        .encode_to_vec(),
        0,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while host.conn.shared.writer.capacity() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_millis(200), host.close())
        .await
        .unwrap();
    assert!(bound_session(&host).is_closed());
    assert_eq!(host.worker_len(), 0);
}

#[tokio::test]
async fn drop_and_transport_loss_close_idle_scoped_session_and_release_quota() {
    for transport_loss in [false, true] {
        let service = RecoveryService::new(
            Arc::new(Source::default()),
            RecoveryLimits {
                max_connections: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let (host, mut writer, _) = new_host(ConnectionConfig::default());
        host.configure_recovery(service.clone()).await.unwrap();
        activate(&host, &mut writer).await;
        negotiate(&host, &mut writer).await;
        let session = bound_session(&host);
        let weak = Arc::downgrade(&host);
        if transport_loss {
            host.on_transport_lost().await;
        }
        drop(host);
        assert!(weak.upgrade().is_none(), "idle worker must not retain Host");
        assert!(session.is_closed());
        assert_eq!(session.queue_counts(), Err(ProviderError::Unavailable));
        let replacement = service
            .open_connection(Principal::new("actual-principal"))
            .unwrap();
        assert!(!replacement.is_closed());
        replacement.close();
    }
}

fn recovery_event(frame: Frame) -> recovery_notification::Notification {
    assert_eq!(frame.version, 1);
    assert_eq!(
        frame.request_id, 0,
        "notifications must not complete an RPC"
    );
    let Some(Body::Notification(n)) = frame.body else {
        panic!("expected recovery notification");
    };
    wire::codec::decode::<RecoveryNotification>(&n.payload)
        .unwrap()
        .notification
        .unwrap()
}

async fn complete_worker_baseline(
    host: &Host,
    writer: &mut mpsc::Receiver<Vec<u8>>,
    id: u64,
    handle: &[u8],
) {
    send(
        host,
        id,
        wire::CATCH_UP,
        RecoveryCatchUpRequest {
            profile_version: 1,
            subscription_handle: handle.to_vec(),
        }
        .encode_to_vec(),
        0,
    )
    .await;
    let mut accepted = false;
    let mut completed = false;
    // Acceptance and completion may arrive in either order. Both must be
    // consumed before filling the writer; neither is the later live batch.
    for _ in 0..2 {
        let frame = receive(writer).await;
        if frame.request_id == id {
            assert!(!accepted);
            let payload = result(frame, id).unwrap();
            let reply: RecoveryCatchUpAccepted = wire::codec::decode(&payload).unwrap();
            assert_eq!(reply.subscription_handle, handle);
            assert_eq!(reply.generation, 1);
            assert_eq!(reply.catchup_boundary, b"c0");
            accepted = true;
        } else {
            assert!(!completed);
            let recovery_notification::Notification::Trailer(t) = recovery_event(frame) else {
                panic!("expected typed baseline completion");
            };
            assert_eq!(t.subscription_handle, handle);
            assert_eq!(t.generation, 1);
            assert_eq!(t.boundary_checkpoint, b"c0");
            assert_eq!(
                t.outcome,
                Some(recovery_batch_trailer::Outcome::CatchupComplete(true))
            );
            completed = true;
        }
    }
    assert!(accepted && completed);
    assert!(writer.try_recv().is_err());
}

struct WorkerBarrier {
    source: Arc<Source>,
    service: Arc<RecoveryService>,
    host: Arc<Host>,
    writer: mpsc::Receiver<Vec<u8>>,
    affected: Vec<u8>,
    healthy: Vec<u8>,
}

impl WorkerBarrier {
    async fn new() -> Self {
        let source = Arc::new(Source::default());
        let service = service(source.clone());
        let (host, mut writer, _) = new_host(ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        });
        host.configure_recovery(service.clone()).await.unwrap();
        activate(&host, &mut writer).await;
        negotiate(&host, &mut writer).await;
        let affected = subscribe(&host, &mut writer, 2, b"affected").await;
        complete_worker_baseline(&host, &mut writer, 3, &affected).await;
        let healthy = subscribe(&host, &mut writer, 4, b"healthy").await;
        complete_worker_baseline(&host, &mut writer, 5, &healthy).await;
        Self {
            source,
            service,
            host,
            writer,
            affected,
            healthy,
        }
    }

    fn marker() -> Vec<u8> {
        Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Notification(Notification {
                payload: b"fixture writer-capacity barrier".to_vec(),
            })),
        }
        .encode_to_vec()
    }

    async fn hold_popped_batch(&self) {
        let session = bound_session(&self.host);
        let before = session.queue_counts().unwrap();
        assert_eq!((before.data_messages, before.control_messages), (0, 0));
        self.host
            .conn
            .shared
            .writer
            .try_send(Self::marker())
            .unwrap();
        assert_eq!(self.host.conn.shared.writer.capacity(), 0);
        self.service
            .publish(
                &Principal::new("actual-principal"),
                b"affected",
                live_batch(),
            )
            .unwrap();
        // These tests use the current-thread executor. No await since publish:
        // the real worker has not yet had a chance to pop the new live unit.
        assert_eq!(session.queue_counts().unwrap().data_messages, 1);
        let after_publish = self.source.emit_calls.load(Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let counts = session.queue_counts().unwrap();
                if self.source.emit_calls.load(Ordering::SeqCst) > after_publish
                    && counts.data_messages == 0
                    && counts.offered_checkpoints == before.offered_checkpoints + 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("real notification worker must pop and offer the live batch");
        assert_eq!(self.host.conn.shared.writer.capacity(), 0);
        assert_eq!(self.writer.len(), 1, "only the marker can be queued");
        assert_eq!(self.host.state().await, ConnectionState::Active);
    }

    fn release_writer(&mut self) {
        // Synchronous release: the source mutation must already be committed
        // before the worker can resume reserve_writer and its last state await.
        assert_eq!(self.writer.try_recv().unwrap(), Self::marker());
    }

    async fn targeted_terminal(&mut self) -> RecoveryBatchTrailer {
        let recovery_notification::Notification::Trailer(t) =
            recovery_event(receive(&mut self.writer).await)
        else {
            panic!("stale popped batch escaped instead of targeted terminal");
        };
        assert_eq!(t.subscription_handle, self.affected);
        assert_eq!(t.generation, 1, "terminal must identify the OLD generation");
        assert_eq!(t.boundary_checkpoint, b"c0");
        t
    }

    async fn healthy_continues(&mut self) {
        assert_eq!(self.host.state().await, ConnectionState::Active);
        assert_eq!(self.host.sessions.count(), 1);
        assert_eq!(
            bound_session(&self.host)
                .queue_counts()
                .unwrap()
                .subscriptions,
            1
        );
        self.service
            .publish(
                &Principal::new("actual-principal"),
                b"healthy",
                live_batch(),
            )
            .unwrap();
        let recovery_notification::Notification::Batch(b) =
            recovery_event(receive(&mut self.writer).await)
        else {
            panic!("healthy stream must continue delivering");
        };
        assert_eq!(b.subscription_handle, self.healthy);
        assert_eq!(b.generation, 1);
        assert_eq!(b.predecessor_checkpoint, b"c0");
        assert_eq!(b.result_checkpoint, b"c1");
        assert_eq!(b.batch_payload, b"event");
        assert!(
            self.writer.try_recv().is_err(),
            "no stale affected batch may follow"
        );
        self.host.close().await;
    }
}

#[tokio::test]
async fn worker_barrier_permission_revoked_after_pop_discards_batch_only_for_target() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = WorkerBarrier::new().await;
        fixture.hold_popped_batch().await;
        *fixture.source.denied_selector.lock().unwrap() = Some(b"affected".to_vec());
        *fixture.source.denied.lock().unwrap() = Some(ProviderError::PermissionDenied);
        fixture.release_writer();
        assert_eq!(
            fixture.targeted_terminal().await.outcome,
            Some(recovery_batch_trailer::Outcome::Terminated(true))
        );
        fixture.healthy_continues().await;
    })
    .await
    .expect("permission revalidation must settle without a stalled worker");
}

#[tokio::test]
async fn worker_barrier_principal_revoked_after_pop_discards_batch_and_withdraws_core() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = WorkerBarrier::new().await;
        fixture.hold_popped_batch().await;
        let session = bound_session(&fixture.host);
        *fixture.source.denied_selector.lock().unwrap() = Some(b"affected".to_vec());
        *fixture.source.denied.lock().unwrap() = Some(ProviderError::Unauthenticated);
        fixture.release_writer();
        closed(&fixture.host).await;
        assert_eq!(fixture.host.state().await, ConnectionState::Closed);
        assert_eq!(fixture.host.sessions.count(), 0);
        assert_eq!(
            fixture.host.terminal_reason().unwrap().code(),
            ErrorCode::Unauthenticated
        );
        assert_eq!(
            session.terminal_error(),
            Some(ProviderError::Unauthenticated)
        );
        assert!(session.is_closed());
        assert!(
            fixture.writer.try_recv().is_err(),
            "no stale batch or trailer after root revocation"
        );
    })
    .await
    .expect("principal revocation must close Core, not just the subscription");
}

#[tokio::test]
async fn worker_barrier_generation_advanced_after_pop_discards_old_batch_only_for_target() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = WorkerBarrier::new().await;
        fixture.hold_popped_batch().await;
        // Do NOT call service.provider_loss: only the final egress recheck can
        // discover this source change and retain the targeted loss control.
        fixture
            .source
            .generations
            .lock()
            .unwrap()
            .insert(b"affected".to_vec(), 2);
        fixture.release_writer();
        assert_eq!(
            fixture.targeted_terminal().await.outcome,
            Some(recovery_batch_trailer::Outcome::NextGeneration(2))
        );
        fixture.healthy_continues().await;
    })
    .await
    .expect("generation loss must retire old output without stalling other streams");
}

#[tokio::test]
async fn worker_barrier_internal_notification_production_error_closes_core() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut fixture = WorkerBarrier::new().await;
        let session = bound_session(&fixture.host);
        fixture
            .service
            .publish(
                &Principal::new("actual-principal"),
                b"affected",
                live_batch(),
            )
            .unwrap();
        let after_publish = fixture.source.emit_calls.load(Ordering::SeqCst);
        // No await since publication: fault the generation read in the actual
        // next_notification production step, not publication or egress recheck.
        *fixture.source.generation_error.lock().unwrap() = Some(ProviderError::Internal);
        closed(&fixture.host).await;
        assert!(fixture.source.emit_calls.load(Ordering::SeqCst) > after_publish);
        assert_eq!(session.terminal_error(), Some(ProviderError::Internal));
        assert!(session.is_closed());
        assert_eq!(fixture.host.state().await, ConnectionState::Closed);
        assert_eq!(fixture.host.sessions.count(), 0);
        assert_eq!(
            fixture.host.terminal_reason().unwrap().code(),
            ErrorCode::Internal
        );
        assert!(
            fixture.writer.try_recv().is_err(),
            "failed production must not leak a batch"
        );
    })
    .await
    .expect("notification production failure must close Core instead of leaving an idle worker");
}

#[tokio::test]
async fn publish_validate_issued_unauthenticated_wakes_idle_worker_and_withdraws_pending_core_rpc()
{
    struct PendingApplication(Mutex<Option<oneshot::Sender<()>>>);

    impl Handler for PendingApplication {
        fn authorize(&self, principal: &Principal, method: &str) -> Result<(), AuthError> {
            assert_eq!(principal, &Principal::new("actual-principal"));
            assert_eq!(method, "/example.App/Pending");
            Ok(())
        }

        fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
            let started = self.0.lock().unwrap().take().expect("one application RPC");
            Box::pin(async move {
                started.send(()).expect("test must observe execution start");
                std::future::pending::<HandlerOutcome>().await
            })
        }
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        let source = Arc::new(Source::default());
        let service = service(source.clone());
        let (started, running) = oneshot::channel();
        let (host, mut writer) = Host::new(
            ConnectionConfig {
                writer_capacity: 1,
                ..ConnectionConfig::default()
            },
            Arc::new(StaticToken::new(b"credential".to_vec(), "actual-principal")),
            Arc::new(PendingApplication(Mutex::new(Some(started)))),
        );
        host.configure_recovery(service.clone()).await.unwrap();
        activate(&host, &mut writer).await;
        negotiate(&host, &mut writer).await;
        let handle = subscribe(&host, &mut writer, 2, b"stream").await;
        complete_worker_baseline(&host, &mut writer, 3, &handle).await;
        let session = bound_session(&host);
        assert_eq!(session.principal(), &Principal::new("actual-principal"));

        // Start real Core execution, not just correlation admission. Its future
        // never resolves on its own, and its deadline exceeds this whole test.
        send(&host, 4, "/example.App/Pending", vec![], 30_000).await;
        tokio::time::timeout(Duration::from_secs(1), running)
            .await
            .expect("application worker must start")
            .unwrap();
        assert_eq!(host.inflight_len(), 1);
        assert_eq!(host.state().await, ConnectionState::Active);
        let counts = session.queue_counts().unwrap();
        assert_eq!(counts.subscriptions, 1);
        assert_eq!((counts.data_messages, counts.control_messages), (0, 0));
        assert!(writer.try_recv().is_err());
        assert_eq!(host.conn.shared.writer.capacity(), 1);

        // Emit authorization and G remain valid. Only issued-binding validation
        // denies the principal, before publication can queue any notification.
        assert!(source.denied.lock().unwrap().is_none());
        assert!(source.generation_error.lock().unwrap().is_none());
        assert_eq!(
            source.current_generation(session.principal(), b"stream"),
            Ok(1)
        );
        let emits_before_publish = source.emit_calls.load(Ordering::SeqCst);
        *source.validate_issued_error.lock().unwrap() = Some(ProviderError::Unauthenticated);
        assert_eq!(
            service.publish(session.principal(), b"stream", live_batch()),
            Err(ProviderError::Unauthenticated)
        );
        assert!(source.emit_calls.load(Ordering::SeqCst) > emits_before_publish);

        // No second publish, control record, RPC, manual pop, or explicit close
        // wakes the idle notification worker. Observing publish's Err alone is
        // insufficient: it must cause real root withdrawal on this connection.
        let did_close = tokio::time::timeout(Duration::from_secs(2), async {
            while !host.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            did_close.is_ok(),
            "publish returned Unauthenticated without root withdrawal: state={:?}, recovery_error={:?}, sessions={}, pending={}",
            host.state().await,
            session.terminal_error(),
            host.sessions.count(),
            host.inflight_len(),
        );
        assert_eq!(host.state().await, ConnectionState::Closed);
        assert_eq!(
            host.terminal_reason().unwrap().code(),
            ErrorCode::Unauthenticated
        );
        assert_eq!(host.sessions.count(), 0);
        assert!(host.bound_id.lock().unwrap().is_none());
        assert_eq!(
            session.terminal_error(),
            Some(ProviderError::Unauthenticated)
        );
        assert!(session.is_closed());

        tokio::time::timeout(Duration::from_secs(1), async {
            while host.worker_len() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("withdrawal must settle and drop the pending application future");
        assert_eq!(host.inflight_len(), 0);
        assert_eq!(host.execution_len(), 0);
        // Writer capacity was available: the pending RPC must receive exactly
        // one UNAUTHENTICATED result, not success, a generic error, or a batch.
        let frame = receive(&mut writer).await;
        assert_eq!(frame.version, 1);
        assert_eq!(result(frame, 4), Err(ErrorCode::Unauthenticated));
        assert!(
            writer.try_recv().is_err(),
            "no duplicate result or stale protected batch"
        );
    })
    .await
    .expect("validate_issued revocation must wake the idle worker and close Core");
}
