//! Server-owned quotas on two independently authenticated connections.

use futures_util::future::BoxFuture;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use syntra_core::{secure_channel::VerifiedIdentity, ErrorCode, SyntraError};
use syntra_integration::{Loopback, CREDENTIAL};
use syntra_net::{AuthenticatorFactory, ConnectionAuthorization};
use syntra_runtime::{
    AdmissionRefusal, AllowAll, AuthError, Authenticator, CancelToken, ExecutionBudget,
    ExecutionLease, Handler, HandlerFut, HandlerOutcome, OperationAuthority, OperationClass,
    OperationGrant, OperationLimits, Principal, QuotaOwnership, StaticToken,
};
use tokio::sync::{mpsc, Notify, Semaphore};

const HOLD: &str = "/test.Media/Hold";
const READ: &str = "/test.Media/Read";
const PING: &str = "/test.UI/Ping";
const LARGE: &str = "/test.Media/Large";
const COMMIT: &str = "/test.Media/Commit";
const CAP: usize = 1024;
const TICKETS: usize = 8;

async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), f)
        .await
        .expect("test timed out")
}

#[derive(Default)]
struct Access {
    revoked: bool,
    commits: usize,
}

struct Authority {
    access: Mutex<Access>,
    tickets: Arc<Semaphore>,
}

impl OperationAuthority for Authority {
    fn try_admit(
        &self,
        principal: &Principal,
        method: &str,
        _: usize,
    ) -> Result<OperationGrant, AdmissionRefusal> {
        if principal.subject != "account" {
            return Err(AdmissionRefusal::Unavailable);
        }
        if self.access.lock().unwrap().revoked {
            return Err(AdmissionRefusal::Revoked);
        }
        let class = match method {
            HOLD | READ | LARGE | COMMIT => OperationClass::Media,
            PING => OperationClass::Interactive,
            _ => return Err(AdmissionRefusal::Unavailable),
        };
        let ticket = self
            .tickets
            .clone()
            .try_acquire_owned()
            .map_err(|_| AdmissionRefusal::Exhausted)?;
        Ok(OperationGrant {
            class,
            response_frame_bytes: CAP,
            ownership: QuotaOwnership::External(Box::new(ticket)),
        })
    }
}

impl ConnectionAuthorization for Authority {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async {
            if self.access.lock().unwrap().revoked {
                Err(AuthError::unauthenticated())
            } else {
                Ok(())
            }
        })
    }
    fn interval(&self) -> Duration {
        Duration::from_millis(200)
    }
    fn read_timeout(&self) -> Duration {
        Duration::from_millis(100)
    }
    fn close_timeout(&self) -> Duration {
        Duration::from_secs(1)
    }
}

#[derive(Clone)]
struct Factory {
    budget: ExecutionBudget,
    authority: Arc<Authority>,
    subject: &'static str,
    guard: bool,
}

impl AuthenticatorFactory for Factory {
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(StaticToken::new(
            CREDENTIAL.to_vec(),
            self.subject,
        )))
    }
    fn execution_budget(&self) -> ExecutionBudget {
        self.budget.clone()
    }
    fn connection_authorization(
        &self,
        _: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        Ok(if self.guard {
            Some(self.authority.clone())
        } else {
            None
        })
    }
}

struct Service {
    authority: Arc<Authority>,
    entered: AtomicUsize,
    held: mpsc::UnboundedSender<ExecutionLease>,
    resume: Arc<Notify>,
}

impl Handler for Service {
    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        unreachable!()
    }
    fn handle_with_execution(
        &self,
        method: String,
        payload: Vec<u8>,
        _: CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        self.entered.fetch_add(1, Ordering::SeqCst);
        assert_eq!(lease.response_frame_bytes(), CAP);
        match method.as_str() {
            HOLD => {
                self.held.send(lease).unwrap();
                Box::pin(std::future::pending())
            }
            COMMIT => {
                self.held.send(lease).unwrap();
                let resume = self.resume.clone();
                let authority = self.authority.clone();
                Box::pin(async move {
                    resume.notified().await;
                    // Application transaction: admission is not commit authority.
                    let mut state = authority.access.lock().unwrap();
                    if state.revoked {
                        return HandlerOutcome::error(ErrorCode::PermissionDenied, "access denied");
                    }
                    state.commits += 1;
                    HandlerOutcome::Payload(payload)
                })
            }
            LARGE => Box::pin(std::future::ready(HandlerOutcome::Payload(vec![1; CAP]))),
            READ | PING => Box::pin(std::future::ready(HandlerOutcome::Payload(payload))),
            _ => panic!("admission failure dispatched to handler"),
        }
    }
}

fn setup(
    limits: OperationLimits,
) -> (
    Factory,
    Arc<AllowAll<Service>>,
    mpsc::UnboundedReceiver<ExecutionLease>,
) {
    let authority = Arc::new(Authority {
        access: Mutex::default(),
        tickets: Arc::new(Semaphore::new(TICKETS)),
    });
    let aggregate = ExecutionBudget::new(2);
    let factory = Factory {
        budget: aggregate.clone(),
        authority: authority.clone(),
        subject: "account",
        guard: false,
    };
    aggregate
        .configure_operations(limits, authority.clone())
        .unwrap();
    let (held, rx) = mpsc::unbounded_channel();
    let service = Arc::new(AllowAll(Service {
        authority,
        held,
        entered: AtomicUsize::new(0),
        resume: Arc::new(Notify::new()),
    }));
    (factory, service, rx)
}

fn limits() -> OperationLimits {
    OperationLimits {
        interactive_executions: 1,
        bytes: 10 * CAP,
        interactive_bytes: CAP,
    }
}

fn remote_error(result: Result<Vec<u8>, SyntraError>, expected: ErrorCode) {
    assert!(
        matches!(result, Err(SyntraError::Rpc { code, .. }) if code == expected),
        "expected {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn media_saturation_and_cancellation_keep_the_interactive_slot_and_external_charge() {
    bounded(async {
        let (factory, service, mut rx) = setup(limits());
        let mut fixture = Loopback::bind().await.unwrap();
        let (a, ah) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        let (b, bh) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        let cancel = CancelToken::new();
        let (cancelled, lease) = tokio::join!(
            a.conn.call_cancellable(HOLD, vec![0; 7], 5000, &cancel),
            async {
                let lease = rx.recv().await.unwrap();
                remote_error(
                    b.conn.call(READ, b"interactive".to_vec(), 5000).await,
                    ErrorCode::ResourceExhausted,
                );
                assert_eq!(service.0.entered.load(Ordering::SeqCst), 1);
                assert_eq!(b.conn.call(PING, vec![42], 5000).await.unwrap(), [42]);
                cancel.cancel();
                lease
            }
        );
        assert_eq!(cancelled.unwrap_err().code(), ErrorCode::Cancelled);
        while ah.host.inflight_len() != 0 {
            tokio::task::yield_now().await;
        }
        remote_error(
            b.conn.call(READ, vec![], 5000).await,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(factory.budget.in_use(), 1);
        assert_eq!(factory.budget.bytes_in_use(), CAP + 7);
        // A replacement cannot obtain a fresh byte pool by reinstalling policy.
        assert_eq!(
            factory
                .budget
                .configure_operations(limits(), factory.authority.clone())
                .unwrap_err()
                .code(),
            ErrorCode::FailedPrecondition
        );
        assert_eq!(factory.authority.tickets.available_permits(), TICKETS - 1);
        drop(lease);
        while ah.host.worker_len() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(b.conn.call(READ, vec![9], 5000).await.unwrap(), [9]);
        assert_eq!(factory.authority.tickets.available_permits(), TICKETS);
        tokio::join!(a.close(), ah.close(), b.close(), bh.close());
    })
    .await;
}

#[tokio::test]
async fn independent_pools_require_positive_provider_capacity() {
    bounded(async {
        let (factory, service, mut rx) = setup(limits());
        // Model a second process with a distinct local pool. Only the provider
        // knows about outstanding tickets held by the other owner(s).
        let second = Factory {
            budget: ExecutionBudget::new(2),
            ..factory.clone()
        };
        second
            .budget
            .configure_operations(limits(), factory.authority.clone())
            .unwrap();
        let other_work = factory
            .authority
            .tickets
            .try_acquire_many((TICKETS - 1) as u32)
            .unwrap();
        let mut fixture = Loopback::bind().await.unwrap();
        let (a, ah) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        let (b, bh) = fixture
            .open(Arc::new(second.clone()), service.clone())
            .await
            .unwrap();
        let cancel = CancelToken::new();
        let (result, lease) = tokio::join!(
            a.conn.call_cancellable(HOLD, vec![], 5000, &cancel),
            async {
                let lease = rx.recv().await.unwrap();
                cancel.cancel();
                lease
            }
        );
        assert_eq!(result.unwrap_err().code(), ErrorCode::Cancelled);
        remote_error(
            b.conn.call(READ, vec![], 5000).await,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(second.budget.in_use(), 0);
        assert_eq!(second.budget.bytes_in_use(), 0);
        assert_eq!(service.0.entered.load(Ordering::SeqCst), 1);
        drop(lease);
        while ah.host.worker_len() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(b.conn.call(READ, vec![9], 5000).await.unwrap(), [9]);
        drop(other_work);
        tokio::join!(a.close(), ah.close(), b.close(), bh.close());
    })
    .await;
}

#[tokio::test]
async fn unavailable_scope_and_oversized_requests_fail_before_effects_and_results_are_capped() {
    bounded(async {
        let (factory, service, _) = setup(OperationLimits {
            bytes: 2 * CAP,
            ..limits()
        });
        let mut fixture = Loopback::bind().await.unwrap();
        let (a, ah) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        let (b, bh) = fixture
            .open(
                Arc::new(Factory {
                    subject: "not-owned",
                    ..factory.clone()
                }),
                service.clone(),
            )
            .await
            .unwrap();
        remote_error(
            b.conn.call(PING, b"account".to_vec(), 5000).await,
            ErrorCode::Unavailable,
        );
        remote_error(
            a.conn.call(READ, vec![1], 5000).await,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(service.0.entered.load(Ordering::SeqCst), 0);
        assert_eq!(factory.budget.in_use(), 0);
        assert_eq!(factory.budget.bytes_in_use(), 0);
        assert_eq!(factory.authority.tickets.available_permits(), TICKETS);
        remote_error(
            a.conn.call(LARGE, vec![], 5000).await,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(a.conn.call(PING, vec![11], 5000).await.unwrap(), [11]);
        factory.authority.access.lock().unwrap().revoked = true;
        let failure = a.conn.call(PING, vec![12], 5000).await.unwrap_err();
        assert!(matches!(
            failure.code(),
            ErrorCode::Unauthenticated | ErrorCode::Unavailable
        ));
        a.conn.subscribe_close().wait_for(|v| *v).await.unwrap();
        assert_eq!(
            ah.host.terminal_reason().unwrap().code(),
            ErrorCode::Unauthenticated
        );
        assert_eq!(service.0.entered.load(Ordering::SeqCst), 2);
        tokio::join!(a.close(), ah.close(), b.close(), bh.close());
    })
    .await;
}

#[tokio::test]
async fn output_blocked_on_the_writer_keeps_its_bytes_and_leaves_interactive_headroom() {
    use syntra_core::{
        encode_frame, proto::frame::Body, ClientHello, ConnectionState, Frame, RpcRequest,
        ValidationContext,
    };
    use syntra_runtime::{ConnectionConfig, Host};
    bounded(async {
        let (factory, service, _) = setup(OperationLimits {
            bytes: 2 * CAP + 6,
            ..limits()
        });
        let mut fixture = Loopback::bind().await.unwrap();
        let (client, peer) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        // Keep ready in this raw core host's only writer slot. The selected
        // response cannot be handed off even after the execution lease drops.
        let (blocked, mut writer) = Host::new_with_execution_budget(
            ConnectionConfig {
                writer_capacity: 1,
                ..Default::default()
            },
            Arc::new(StaticToken::new(CREDENTIAL.to_vec(), "account")),
            service.clone(),
            factory.budget.clone(),
        );
        let hello = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: CREDENTIAL.to_vec(),
            })),
        };
        blocked
            .ingest(
                &encode_frame(
                    &hello,
                    ValidationContext::pre_handshake(ConnectionState::Connected),
                )
                .unwrap(),
            )
            .await;
        let request = Frame {
            version: 1,
            request_id: 1,
            body: Some(Body::Request(RpcRequest {
                method: READ.into(),
                payload: vec![3; 6],
                timeout_ms: 5000,
            })),
        };
        blocked
            .ingest(&encode_frame(&request, ValidationContext::active(1)).unwrap())
            .await;
        while service.0.entered.load(Ordering::SeqCst) == 0 || factory.budget.in_use() != 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!(factory.budget.bytes_in_use(), CAP + 6);
        remote_error(
            client.conn.call(READ, vec![], 5000).await,
            ErrorCode::ResourceExhausted,
        );
        // Even interactive traffic cannot exceed the total byte ceiling.
        remote_error(
            client.conn.call(PING, vec![1], 5000).await,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(client.conn.call(PING, vec![], 5000).await.unwrap(), []);
        writer.recv().await.unwrap(); // ready
        writer.recv().await.unwrap(); // result
        assert_eq!(factory.budget.bytes_in_use(), 0);
        assert_eq!(factory.authority.tickets.available_permits(), TICKETS);
        assert_eq!(client.conn.call(READ, vec![9], 5000).await.unwrap(), [9]);
        tokio::join!(blocked.close(), client.close(), peer.close());
    })
    .await;
}

#[tokio::test]
async fn commit_rechecks_revocation_and_watchdogs_close_both_bindings_without_another_rpc() {
    bounded(async {
        let (mut factory, service, mut rx) = setup(limits());
        let mut fixture = Loopback::bind().await.unwrap();
        // Keep watchdog publication under test independent from the application's
        // transactional refusal: either may win the wire race on the active peer.
        factory.guard = true;
        let (a, ah) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        let (idle, ih) = fixture
            .open(Arc::new(factory.clone()), service.clone())
            .await
            .unwrap();
        let (result, lease) = tokio::join!(a.conn.call(COMMIT, vec![99], 5000), async {
            let lease = rx.recv().await.unwrap();
            factory.authority.access.lock().unwrap().revoked = true;
            service.0.resume.notify_one();
            lease
        });
        assert!(matches!(
            result.unwrap_err().code(),
            ErrorCode::PermissionDenied | ErrorCode::Unavailable | ErrorCode::Unauthenticated
        ));
        assert_eq!(factory.authority.access.lock().unwrap().commits, 0);
        for peer in [&a, &idle] {
            peer.conn.subscribe_close().wait_for(|v| *v).await.unwrap();
        }
        assert_eq!(factory.budget.in_use(), 1);
        drop(lease);
        tokio::join!(a.close(), ah.close(), idle.close(), ih.close());
    })
    .await;
}
