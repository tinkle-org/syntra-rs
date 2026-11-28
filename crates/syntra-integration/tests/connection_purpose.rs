//! Interactive and bulk are local uses of independently authenticated connections.

use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use syntra_core::{secure_channel::VerifiedIdentity, ErrorCode, SyntraError};
use syntra_integration::{Loopback, CREDENTIAL};
use syntra_net::{ClientHandle, HostHandle};
use syntra_runtime::{
    AuthError, Authenticator, CancelToken, Handler, HandlerFut, HandlerOutcome, Principal,
    StaticToken,
};
use tokio::sync::{Notify, Semaphore};

const READ: &str = "/test.Objects/Read";
const WRITE: &str = "/test.Objects/Write";
const OWN: u8 = 1;
const OTHER: u8 = 2;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("loopback test timed out")
}

struct Account {
    token: StaticToken,
    readable_object: u8,
    slots: Semaphore,
    state: Mutex<Access>,
}

#[derive(Default)]
struct Access {
    revoked: bool,
    effects: usize,
}

#[derive(Default)]
struct Gate {
    admitted: Notify,
    release: Notify,
}

#[derive(Default)]
struct Service {
    caller: OnceLock<(Principal, Arc<Account>)>,
    gate: Option<Arc<Gate>>,
}

struct Login {
    account: Arc<Account>,
    service: Arc<Service>,
}

impl Authenticator for Login {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        let principal = self.account.token.authenticate(credential)?;
        if self.account.state.lock().unwrap().revoked {
            return Err(AuthError::unauthenticated());
        }
        self.service
            .caller
            .set((principal.clone(), self.account.clone()))
            .map_err(|_| AuthError::unauthenticated())?;
        Ok(principal)
    }
}

impl Handler for Service {
    fn authorize(&self, principal: &Principal, method: &str) -> Result<(), AuthError> {
        let (bound, account) = self.caller.get().ok_or_else(AuthError::unauthenticated)?;
        if bound != principal || account.state.lock().unwrap().revoked {
            Err(AuthError::unauthenticated())
        } else if method != READ {
            Err(AuthError::denied())
        } else {
            Ok(())
        }
    }

    fn handle(&self, _: String, payload: Vec<u8>, _: CancelToken) -> HandlerFut {
        let (_, account) = self.caller.get().expect("dispatch without authentication");
        let account = account.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            // The peer selects an object and opaque tag, never an account or quota key.
            if payload.first() != Some(&account.readable_object) {
                return HandlerOutcome::error(ErrorCode::PermissionDenied, "access denied");
            }
            let Ok(_permit) = account.slots.try_acquire() else {
                return HandlerOutcome::error(ErrorCode::ResourceExhausted, "caller quota");
            };
            if let Some(gate) = gate {
                gate.admitted.notify_one();
                gate.release.notified().await;
            }
            // Fixture equivalent of a storage transaction fenced against revocation.
            let mut state = account.state.lock().unwrap();
            if state.revoked {
                return HandlerOutcome::error(ErrorCode::PermissionDenied, "access denied");
            }
            state.effects += 1;
            HandlerOutcome::Payload(payload)
        })
    }
}

struct Peer {
    client: ClientHandle,
    host: HostHandle,
}

impl Peer {
    async fn open(fixture: &mut Loopback, account: &Arc<Account>, gate: Option<Arc<Gate>>) -> Self {
        let service = Arc::new(Service {
            gate,
            ..Default::default()
        });
        let login: Arc<dyn Authenticator> = Arc::new(Login {
            account: account.clone(),
            service: service.clone(),
        });
        let factory = Arc::new(move |_: &VerifiedIdentity| Ok(login.clone()));
        let (client, host) = fixture.open(factory, service).await.unwrap();
        Self { client, host }
    }

    async fn call(&self, method: &str, object: u8, tag: u8) -> Result<Vec<u8>, SyntraError> {
        self.client
            .conn
            .call(method, vec![object, tag], 5_000)
            .await
    }

    async fn close(self) {
        tokio::join!(self.client.close(), self.host.close());
    }
}

async fn peers(slots: usize, bulk_gate: Option<Arc<Gate>>) -> (Peer, Peer, Arc<Account>) {
    let mut fixture = Loopback::bind().await.unwrap();
    let account = Arc::new(Account {
        token: StaticToken::new(CREDENTIAL.to_vec(), "reader"),
        readable_object: OWN,
        slots: Semaphore::new(slots),
        state: Mutex::default(),
    });
    let interactive = Peer::open(&mut fixture, &account, None).await;
    let bulk = Peer::open(&mut fixture, &account, bulk_gate).await;
    assert_ne!(interactive.client.connection_id, bulk.client.connection_id);
    (interactive, bulk, account)
}

fn assert_rpc_error(result: Result<Vec<u8>, SyntraError>, expected: ErrorCode) {
    assert!(
        matches!(&result, Err(SyntraError::Rpc { code, .. }) if *code == expected),
        "expected remote {expected:?}, got {result:?}"
    );
}

#[tokio::test]
async fn both_connections_enforce_the_same_method_and_object_access() {
    bounded(async {
        let (interactive, bulk, account) = peers(1, None).await;
        for peer in [&interactive, &bulk] {
            assert_eq!(peer.call(READ, OWN, 7).await.unwrap(), [OWN, 7]);
            assert_rpc_error(peer.call(WRITE, OWN, 7).await, ErrorCode::PermissionDenied);
            assert_rpc_error(peer.call(READ, OTHER, 7).await, ErrorCode::PermissionDenied);
        }
        assert_eq!(account.state.lock().unwrap().effects, 2);
        tokio::join!(interactive.close(), bulk.close());
    })
    .await;
}

#[tokio::test]
async fn caller_quota_is_shared_and_reusable_after_bulk_completes() {
    bounded(async {
        let gate = Arc::new(Gate::default());
        let (interactive, bulk, account) = peers(1, Some(gate.clone())).await;
        let (held, denied) = tokio::join!(bulk.call(READ, OWN, 11), async {
            gate.admitted.notified().await;
            let result = interactive.call(READ, OWN, 22).await;
            gate.release.notify_one();
            result
        });
        assert_rpc_error(denied, ErrorCode::ResourceExhausted);
        assert_eq!(held.unwrap(), [OWN, 11]);
        assert_eq!(interactive.call(READ, OWN, 22).await.unwrap(), [OWN, 22]);
        assert_eq!(account.state.lock().unwrap().effects, 2);
        tokio::join!(interactive.close(), bulk.close());
    })
    .await;
}

#[tokio::test]
async fn overlapping_results_stay_correlated_and_bulk_close_leaves_interactive_live() {
    bounded(async {
        let gate = Arc::new(Gate::default());
        let (interactive, bulk, _) = peers(2, Some(gate.clone())).await;
        let (slow, fast) = tokio::join!(bulk.call(READ, OWN, 31), async {
            gate.admitted.notified().await;
            let result = interactive.call(READ, OWN, 32).await;
            gate.release.notify_one();
            result
        });
        assert_eq!(fast.unwrap(), [OWN, 32]);
        assert_eq!(slow.unwrap(), [OWN, 31]);
        bulk.close().await;
        assert_eq!(interactive.call(READ, OWN, 33).await.unwrap(), [OWN, 33]);
        interactive.close().await;
    })
    .await;
}

#[tokio::test]
async fn revoking_one_account_withdraws_both_live_bindings_on_their_next_call() {
    bounded(async {
        let (interactive, bulk, account) = peers(1, None).await;
        for peer in [&interactive, &bulk] {
            assert_eq!(peer.call(READ, OWN, 9).await.unwrap(), [OWN, 9]);
        }
        account.state.lock().unwrap().revoked = true;
        for peer in [&interactive, &bulk] {
            let err = peer.call(READ, OWN, 9).await.unwrap_err();
            // Withdrawal can close the transport before its terminal error is delivered.
            assert!(
                matches!(
                    err.code(),
                    ErrorCode::Unauthenticated | ErrorCode::Unavailable
                ),
                "{err:?}"
            );
            let mut closed = peer.client.conn.subscribe_close();
            closed.wait_for(|value| *value).await.unwrap();
            assert_eq!(
                peer.host.host.terminal_reason().unwrap().code(),
                ErrorCode::Unauthenticated
            );
        }
        assert_eq!(account.state.lock().unwrap().effects, 2);
        tokio::join!(interactive.close(), bulk.close());
    })
    .await;
}

#[tokio::test]
async fn withdrawal_before_commit_blocks_an_already_admitted_effect() {
    bounded(async {
        let gate = Arc::new(Gate::default());
        let (interactive, bulk, account) = peers(1, Some(gate.clone())).await;
        let (result, ()) = tokio::join!(bulk.call(READ, OWN, 55), async {
            gate.admitted.notified().await;
            account.state.lock().unwrap().revoked = true;
            gate.release.notify_one();
        });
        assert_rpc_error(result, ErrorCode::PermissionDenied);
        assert_eq!(account.state.lock().unwrap().effects, 0);
        tokio::join!(interactive.close(), bulk.close());
    })
    .await;
}
