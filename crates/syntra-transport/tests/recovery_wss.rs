//! Local direct TLS 1.3/WSS recovery probes using real core endpoints.
#![cfg(all(
    feature = "websocket",
    feature = "reconnect",
    not(target_arch = "wasm32")
))]
//! Generated test PKI is never installed in system roots. Memory persistence
//! verifies atomic full-state records, NOT filesystem/process-crash durability.
//! No real-device, independent interoperability, or CONF verdict is claimed.

use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Duration,
};

use prost::Message;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32, ServerConfig,
    VerifiedIdentity,
};
use syntra_core::{proto::*, ConnectionState, ErrorCode};
use syntra_runtime::{
    recovery::{
        persistence::{
            DurableRecord, ExpectedPosition, MemoryRecoveryStore, PersistenceError,
            PersistenceScope, RecoveryPersistence, StoreLimits,
        },
        wire::{self, *},
        wire_client::{
            Negotiation, RecoveryClient, RecoveryClientError, RecoveryEvent, SubscribeIntent,
        },
    },
    AuthError, Authenticator, ConnectionConfig, ExecutionBudget, FnHandler, HandlerOutcome,
    Principal,
};
use syntra_transport::{
    websocket as ws, AuthenticatorFactory, ClientHandle, Error, HostHandle, Limits,
    RecoveryAuthenticatorFactory,
};
use tokio::net::TcpListener;

const CREDENTIAL: &[u8] = b"local-recovery-wss-credential";
const STREAM: &[u8] = b"local-stable-stream";
const SELECTOR: &[u8] = b"local-stream-alias";
const GENERATION: u64 = 7;
// Only the source interprets ordering. Payloads are opaque, not RecoveryBatch encodings.
const CP: [&[u8]; 5] = [b"\xfe\0", b"\0\xff", b"\x80", b"\x03\0", b"\xff\x01"];
const PAYLOAD: &[u8] = b"\xff\0opaque application delta";
const STATE: &[u8] = b"full application state\0rows plus indexes";
const SNAPSHOT: &[u8] = b"full immutable snapshot\0rows plus indexes";
const ECHO: &str = "/local.Echo/Echo";

fn principal(mode: Mode) -> Principal {
    Principal::new(match mode {
        Mode::Bootstrap => "core-authenticated-bootstrap",
        Mode::Returning => "core-authenticated-returning",
    })
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("local WSS probe exceeded its deadline")
}

struct Certificate {
    der: CertificateDer<'static>,
    key: Vec<u8>,
}
impl Certificate {
    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        roots
    }
    fn settings(&self) -> ws::TlsServerSettings {
        // The production settings constructor admits TLS 1.3 only, no early data.
        ws::TlsServerSettings::new(
            vec![self.der.clone()],
            PrivatePkcs8KeyDer::from(self.key.clone()).into(),
        )
        .unwrap()
    }
}
fn certificate() -> &'static Certificate {
    static CERT: OnceLock<Certificate> = OnceLock::new();
    CERT.get_or_init(|| {
        let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        Certificate {
            der: generated.cert.der().clone(),
            key: generated.key_pair.serialize_der(),
        }
    })
}

struct Keys;
impl KeyStore for Keys {
    fn lookup(&self, context: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        if context.handle == [4; 8] && context.epoch == 9 {
            Ok(Secret32::new([3; 32]))
        } else {
            Err(syntra_core::secure_channel::Error::Authentication)
        }
    }
}
struct Security {
    mode: Mode,
    server: ServerConfig,
    pin: [u8; 32],
}
impl Security {
    fn new(mode: Mode) -> Self {
        let (private_key, pin) = generate_server_key().unwrap();
        Self {
            mode,
            pin,
            server: ServerConfig {
                mode,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 12,
                scope: b"wss/local-recovery".to_vec(),
                private_key,
                store: Some(Arc::new(Keys)),
            },
        }
    }
    fn client(&self) -> ClientConfig {
        let returning = self.mode == Mode::Returning;
        ClientConfig {
            context: Context {
                mode: self.mode,
                carrier: Carrier::SecureWebSocket,
                server_key_id: self.server.server_key_id,
                scope: self.server.scope.clone(),
                handle: if returning { [4; 8] } else { [0; 8] },
                epoch: if returning { 9 } else { 0 },
            },
            server_public_key: self.pin,
            authorization_key: returning.then(|| Secret32::new([3; 32])),
        }
    }
}
struct BoundAuth(VerifiedIdentity);
impl Authenticator for BoundAuth {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        if credential != CREDENTIAL || self.0.context().carrier != Carrier::SecureWebSocket {
            return Err(AuthError::unauthenticated());
        }
        Ok(principal(self.0.context().mode))
    }
}
fn base_factory(creates: Arc<AtomicUsize>) -> impl AuthenticatorFactory {
    move |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
        creates.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::new(BoundAuth(identity.clone())))
    }
}

async fn connect(
    security: &Security,
    factory: Arc<dyn AuthenticatorFactory>,
    credential: &[u8],
) -> (Result<ClientHandle, Error>, Result<HostHandle, Error>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "wss://{}{}",
        listener.local_addr().unwrap(),
        ws::ENDPOINT_PATH
    );
    let limits = Limits {
        attempt_timeout: Duration::from_secs(5),
        channel_timeout: Duration::from_secs(3),
        ..Limits::default()
    };
    let accept = async {
        let (stream, _) = listener.accept().await.unwrap();
        ws::accept_tls_stream(
            stream,
            &certificate().settings(),
            &security.server,
            factory,
            Arc::new(FnHandler(|_, payload, _| async move {
                HandlerOutcome::Payload(payload)
            })),
            ConnectionConfig::default(),
            limits.clone(),
        )
        .await
    };
    // Every invocation performs fresh TLS + Noise M1/M2 and encrypted hello/ready.
    // No plaintext development carrier, hand-fed core frames, or bridge task.
    bounded(async {
        tokio::join!(
            ws::connect_with_roots(
                &url,
                certificate().roots(),
                security.client(),
                credential.to_vec(),
                ConnectionConfig::default(),
                limits.clone(),
            ),
            accept
        )
    })
    .await
}

/// One P/S/G, five immutable issued bindings and one immutable one-page snapshot.
/// Tests serialize capture/publication; no unbounded storage, polling, or I/O.
struct Source {
    mode: Mode,
    head: AtomicUsize,
    hooks: Mutex<Vec<AuthorizationHook>>,
    replay_calls: AtomicUsize,
}
impl Source {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            head: AtomicUsize::new(0),
            hooks: Mutex::new(Vec::new()),
            replay_calls: AtomicUsize::new(0),
        })
    }
    fn check(&self, p: &Principal, identity: &[u8]) -> Result<(), ProviderError> {
        if p.subject != principal(self.mode).subject || ![STREAM, SELECTOR].contains(&identity) {
            return Err(ProviderError::PermissionDenied);
        }
        Ok(())
    }
    fn batch(from: usize, to: usize) -> StoredBatch {
        StoredBatch {
            generation: GENERATION,
            predecessor: CP[from].to_vec(),
            result: CP[to].to_vec(),
            payload: PAYLOAD.to_vec(),
        }
    }
    fn append(&self, service: &RecoveryService) {
        let from = self.head.load(Ordering::SeqCst);
        assert!(from + 1 < CP.len(), "bounded fixture history exhausted");
        self.head.store(from + 1, Ordering::SeqCst);
        service
            .publish(&principal(self.mode), STREAM, Self::batch(from, from + 1))
            .unwrap();
    }
}
impl RecoverySource for Source {
    fn authorize(
        &self,
        p: &Principal,
        selector: &[u8],
        hook: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        self.check(p, selector)?;
        // Short, synchronous bookkeeping only; never held across await/callback.
        let mut hooks = self.hooks.lock().unwrap();
        assert!(hooks.len() < 128, "bounded hook trace exhausted");
        hooks.push(hook);
        Ok(())
    }
    fn capture(&self, p: &Principal, selector: &[u8]) -> Result<ProviderStream, ProviderError> {
        self.check(p, selector)?;
        ProviderStream::new(
            STREAM.to_vec(),
            GENERATION,
            CP[self.head.load(Ordering::SeqCst)].to_vec(),
        )
    }
    fn current_generation(&self, p: &Principal, identity: &[u8]) -> Result<u64, ProviderError> {
        self.check(p, identity)?;
        Ok(GENERATION)
    }
    fn validate_issued(
        &self,
        p: &Principal,
        stream: &ProviderStream,
        checkpoint: &[u8],
    ) -> Result<(), ProviderError> {
        self.check(p, stream.identity())?;
        if stream.generation() != GENERATION
            || !CP[..=self.head.load(Ordering::SeqCst)].contains(&checkpoint)
        {
            return Err(ProviderError::FailedPrecondition);
        }
        Ok(())
    }
    fn replay(
        &self,
        p: &Principal,
        stream: &ProviderStream,
        from: &[u8],
        marker: &[u8],
        budget: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        self.validate_issued(p, stream, from)?;
        self.replay_calls.fetch_add(1, Ordering::SeqCst);
        let start = CP
            .iter()
            .position(|cp| *cp == from)
            .ok_or(ProviderError::FailedPrecondition)?;
        let end = CP
            .iter()
            .position(|cp| *cp == stream.boundary())
            .ok_or(ProviderError::Internal)?;
        if start > end || !marker.is_empty() && marker != from {
            return Err(ProviderError::FailedPrecondition);
        }
        let stop = (start + budget.max_batches.min(2)).min(end);
        // Tiny entries, conservative serialized RecoveryBatch overhead allowance.
        if budget.max_entry_bytes < 256 || (stop - start) * 256 > budget.max_entry_total_bytes {
            return Err(ProviderError::ResourceExhausted);
        }
        ProviderPage::new(
            (start..stop).map(|n| Self::batch(n, n + 1)).collect(),
            CP[stop].to_vec(),
            if stop == end {
                vec![]
            } else {
                CP[stop].to_vec()
            },
        )
    }
    fn snapshot(
        &self,
        p: &Principal,
        stream: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        self.validate_issued(p, stream, CP[3])?;
        ProviderSnapshot::new(b"immutable-local-snapshot".to_vec(), CP[3].to_vec(), 1, 128)
    }
    fn snapshot_page(
        &self,
        p: &Principal,
        stream: &ProviderStream,
        snapshot: &ProviderSnapshot,
        index: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        self.validate_issued(p, stream, snapshot.boundary())?;
        if snapshot.key() != b"immutable-local-snapshot"
            || snapshot.boundary() != CP[3]
            || index != 0
        {
            return Err(ProviderError::FailedPrecondition);
        }
        Ok(SNAPSHOT.to_vec())
    }
}

// Observable, bounded process-local store. std Mutex is sufficient: only short
// memory operations, no await or filesystem I/O while holding it.
#[derive(Clone)]
struct Store(Arc<Mutex<MemoryRecoveryStore>>);
impl Store {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(
            MemoryRecoveryStore::with_limits(StoreLimits {
                max_records: 1,
                max_state_bytes: 1024,
                max_total_bytes: 4096,
            })
            .unwrap(),
        )))
    }
}
impl RecoveryPersistence for Store {
    fn load(&self, scope: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError> {
        self.0.lock().unwrap().load(scope)
    }
    fn commit(
        &mut self,
        scope: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        record: DurableRecord,
    ) -> Result<(), PersistenceError> {
        self.0.lock().unwrap().commit(scope, expected, record)
    }
}
fn scope(mode: Mode) -> PersistenceScope {
    PersistenceScope::new(principal(mode).subject.into_bytes(), STREAM.to_vec()).unwrap()
}
fn client(handle: &ClientHandle, mode: Mode, store: Store) -> RecoveryClient<Store> {
    RecoveryClient::new(
        handle.conn.clone(),
        principal(mode).subject.into_bytes(),
        store,
        RecoveryLimits::default(),
    )
    .unwrap()
}
async fn negotiate(client: &mut RecoveryClient<Store>) {
    let Negotiation::Confirmed(response) = bounded(client.negotiate()).await.unwrap() else {
        panic!("server-owned service was not installed before hello")
    };
    assert_eq!(response.selected_version, 1);
}
async fn subscribe(
    client: &mut RecoveryClient<Store>,
    intent: SubscribeIntent,
) -> RecoverySubscribeResponse {
    bounded(client.subscribe(SELECTOR.to_vec(), STREAM.to_vec(), intent))
        .await
        .unwrap()
        .response
}
async fn confirm_live(
    client: &mut RecoveryClient<Store>,
    handle: &[u8],
    from: usize,
    to: usize,
    state: &[u8],
) {
    let RecoveryEvent::Batch { batch } = bounded(client.next_event()).await.unwrap() else {
        panic!("expected live batch on real WSS")
    };
    assert_eq!(batch.subscription_handle, handle);
    assert_eq!(batch.generation, GENERATION);
    assert_eq!(batch.predecessor_checkpoint, CP[from]);
    assert_eq!(batch.result_checkpoint, CP[to]);
    assert_eq!(batch.batch_payload, PAYLOAD);
    let response = bounded(client.persist_and_confirm(handle, state.to_vec()))
        .await
        .unwrap();
    assert_eq!(response.confirmed_checkpoint, CP[to]);
    let progress = client.progress(handle).unwrap();
    assert_eq!(progress.locally_durable, progress.peer_acknowledged);
    assert_eq!(progress.confirm_sent, progress.peer_acknowledged);
}

#[tokio::test]
async fn direct_wss_recovery_both_noise_modes_and_explicit_reconnect() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let source = Source::new(mode);
        let service = RecoveryService::new(source.clone(), RecoveryLimits::default()).unwrap();
        let creates = Arc::new(AtomicUsize::new(0));
        // Exercises new() with the existing blanket closure implementation.
        let factory: Arc<dyn AuthenticatorFactory> = Arc::new(RecoveryAuthenticatorFactory::new(
            base_factory(creates.clone()),
            service.clone(),
        ));
        let security = Security::new(mode);
        let store = Store::new();
        let (handle, host) = connect(&security, factory.clone(), CREDENTIAL).await;
        let handle = handle.unwrap();
        let host = host.unwrap();
        assert_eq!(handle.conn.state().await, ConnectionState::Active);
        assert_eq!(host.identity.context().mode, mode);
        assert_eq!(host.identity.context().carrier, Carrier::SecureWebSocket);
        assert_eq!(
            host.host
                .configure_recovery(service.clone())
                .await
                .unwrap_err()
                .code(),
            ErrorCode::FailedPrecondition
        );
        let first_connection = handle.connection_id.clone();
        let mut recovery = client(&handle, mode, store.clone());
        assert!(matches!(
            RecoveryClient::new(
                handle.conn.clone(),
                principal(mode).subject.into_bytes(),
                Store::new(),
                RecoveryLimits::default()
            ),
            Err(RecoveryClientError::InvalidState)
        ));
        // Installing the service does not negotiate it, even on an ACTIVE host.
        let request = RecoverySubscribeRequest {
            profile_version: 1,
            stream_selector: SELECTOR.to_vec(),
            start_checkpoint: vec![],
        };
        assert_eq!(
            bounded(
                handle
                    .conn
                    .call(wire::SUBSCRIBE, request.encode_to_vec(), 2000)
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::Unimplemented
        );
        negotiate(&mut recovery).await;
        let first = subscribe(&mut recovery, SubscribeIntent::InitialLiveOnly).await;
        assert_eq!(first.catchup_boundary, CP[0]);
        assert!(recovery
            .progress(&first.subscription_handle)
            .unwrap()
            .locally_durable
            .is_none());
        assert_eq!(
            bounded(recovery.catch_up(&first.subscription_handle))
                .await
                .unwrap()
                .catchup_boundary,
            CP[0]
        );
        assert!(
            matches!(bounded(recovery.next_event()).await.unwrap(), RecoveryEvent::InitialLiveBaseline { handle, boundary } if handle == first.subscription_handle && boundary == CP[0])
        );
        assert!(store.load(&scope(mode)).unwrap().is_none());
        assert_eq!(source.replay_calls.load(Ordering::SeqCst), 0);
        assert!(!source
            .hooks
            .lock()
            .unwrap()
            .contains(&AuthorizationHook::Confirm));
        source.append(&service);
        confirm_live(&mut recovery, &first.subscription_handle, 0, 1, STATE).await;
        assert_eq!(
            store.load(&scope(mode)).unwrap().unwrap(),
            DurableRecord {
                generation: GENERATION,
                checkpoint: CP[1].to_vec(),
                application_state: STATE.to_vec()
            }
        );
        bounded(handle.close()).await;
        bounded(host.close()).await;
        assert_eq!(
            recovery.catch_up(&first.subscription_handle).await.err(),
            Some(RecoveryClientError::ReconnectRequired)
        );

        // Explicit fresh connection/wrapper/Negotiate: no lifecycle auto-renegotiation.
        let (handle, host) = connect(&security, factory, CREDENTIAL).await;
        let handle = handle.unwrap();
        let host = host.unwrap();
        assert_ne!(handle.connection_id, first_connection);
        assert_eq!(creates.load(Ordering::SeqCst), 2);
        let mut fresh = client(&handle, mode, store.clone());
        assert_eq!(
            fresh.catch_up(&first.subscription_handle).await.err(),
            Some(RecoveryClientError::Unconfirmed)
        );
        assert_eq!(
            bounded(
                handle
                    .conn
                    .call(wire::SUBSCRIBE, request.encode_to_vec(), 2000)
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::Unimplemented
        );
        negotiate(&mut fresh).await;
        let stale_confirm = RecoveryConfirmRequest {
            profile_version: 1,
            subscription_handle: first.subscription_handle.clone(),
            generation: GENERATION,
            checkpoint: CP[1].to_vec(),
        };
        assert_eq!(
            bounded(
                handle
                    .conn
                    .call(wire::CONFIRM, stale_confirm.encode_to_vec(), 2000)
            )
            .await
            .unwrap_err()
            .code(),
            ErrorCode::FailedPrecondition
        );
        let restored = bounded(fresh.subscribe(
            SELECTOR.to_vec(),
            STREAM.to_vec(),
            SubscribeIntent::ResumeDurable,
        ))
        .await
        .unwrap();
        assert_eq!(restored.restored.unwrap().application_state, STATE);
        let resumed = restored.response;
        assert_ne!(resumed.subscription_handle, first.subscription_handle);
        assert_eq!(resumed.catchup_boundary, CP[1]);
        let page = bounded(fresh.replay_page(&resumed.subscription_handle))
            .await
            .unwrap();
        assert!(page.batch_payloads.is_empty());
        assert!(
            matches!(bounded(fresh.next_event()).await.unwrap(), RecoveryEvent::CaughtUp { handle } if handle == resumed.subscription_handle)
        );
        // A stale application callback on the replacement host still crosses the
        // real encrypted socket. Old H cannot mutate a newly subscribed round.
        let stale = RecoveryNotification {
            profile_version: 1,
            notification: Some(recovery_notification::Notification::Batch(RecoveryBatch {
                profile_version: 1,
                subscription_handle: first.subscription_handle.clone(),
                generation: GENERATION,
                predecessor_checkpoint: CP[1].to_vec(),
                result_checkpoint: CP[2].to_vec(),
                batch_payload: b"stale callback".to_vec(),
            })),
        };
        host.host.notify(stale.encode_to_vec()).await.unwrap();
        // Same host writer FIFO: Echo result is a barrier after stale notification.
        assert_eq!(
            bounded(handle.conn.call(ECHO, b"barrier".to_vec(), 2000))
                .await
                .unwrap(),
            b"barrier"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), fresh.next_event())
                .await
                .is_err()
        );
        assert_eq!(store.load(&scope(mode)).unwrap().unwrap().checkpoint, CP[1]);
        assert_eq!(
            fresh
                .progress(&resumed.subscription_handle)
                .unwrap()
                .locally_durable
                .as_ref()
                .unwrap()
                .checkpoint,
            CP[1]
        );
        source.append(&service);
        confirm_live(&mut fresh, &resumed.subscription_handle, 1, 2, STATE).await;
        bounded(fresh.unsubscribe(&resumed.subscription_handle))
            .await
            .unwrap();
        // Unsubscribe retires H locally and exposes its terminal event before
        // the next round's data; it is not a failure of the snapshot round.
        assert!(
            matches!(bounded(fresh.next_event()).await.unwrap(), RecoveryEvent::RecoveryNeeded { handle, termination: None, .. } if handle == resumed.subscription_handle)
        );

        let snapshot = subscribe(&mut fresh, SubscribeIntent::SnapshotCurrentGeneration).await;
        assert_eq!(snapshot.catchup_boundary, CP[2]);
        source.append(&service);
        let descriptor = bounded(fresh.snapshot_offer(&snapshot.subscription_handle))
            .await
            .unwrap();
        assert_eq!(descriptor.boundary_checkpoint, CP[3]);
        assert_ne!(descriptor.boundary_checkpoint, snapshot.catchup_boundary);
        assert_eq!(
            bounded(fresh.snapshot_fetch(&snapshot.subscription_handle, 0))
                .await
                .unwrap()
                .page_bytes,
            SNAPSHOT
        );
        assert_eq!(
            fresh.snapshot_bytes(&snapshot.subscription_handle).unwrap(),
            SNAPSHOT
        );
        assert_eq!(
            store.load(&scope(mode)).unwrap().unwrap().checkpoint,
            CP[2],
            "offer/fetch must not persist"
        );
        let installed =
            bounded(fresh.install_and_confirm(&snapshot.subscription_handle, SNAPSHOT.to_vec()))
                .await
                .unwrap();
        assert_eq!(installed.boundary_checkpoint, CP[3]);
        assert_eq!(
            store.load(&scope(mode)).unwrap().unwrap(),
            DurableRecord {
                generation: GENERATION,
                checkpoint: CP[3].to_vec(),
                application_state: SNAPSHOT.to_vec()
            }
        );
        source.append(&service);
        confirm_live(&mut fresh, &snapshot.subscription_handle, 3, 4, STATE).await;
        for hook in [
            AuthorizationHook::Subscribe,
            AuthorizationHook::Replay,
            AuthorizationHook::CatchUp,
            AuthorizationHook::Confirm,
            AuthorizationHook::Emit,
            AuthorizationHook::SnapshotOffer,
            AuthorizationHook::SnapshotFetch,
            AuthorizationHook::SnapshotConfirm,
            AuthorizationHook::Unsubscribe,
        ] {
            assert!(
                source.hooks.lock().unwrap().contains(&hook),
                "missing provider hook {hook:?}"
            );
        }
        bounded(handle.close_gracefully(Duration::from_secs(1)))
            .await
            .unwrap();
        bounded(host.close()).await;
    }
}

#[tokio::test]
async fn default_factory_stays_mandatory_only_and_core_auth_rejection_is_generic() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let creates = Arc::new(AtomicUsize::new(0));
        let base = base_factory(creates.clone());
        assert!(base.recovery_service().is_none());
        let security = Security::new(mode);
        let (handle, host) = connect(&security, Arc::new(base), CREDENTIAL).await;
        let handle = handle.unwrap();
        let host = host.unwrap();
        let mut recovery = client(&handle, mode, Store::new());
        assert!(matches!(
            bounded(recovery.negotiate()).await.unwrap(),
            Negotiation::RecoveryUnavailable
        ));
        assert_eq!(
            bounded(handle.conn.call(ECHO, b"baseline".to_vec(), 2000))
                .await
                .unwrap(),
            b"baseline"
        );
        bounded(handle.close()).await;
        bounded(host.close()).await;

        let source = Source::new(mode);
        let service = RecoveryService::new(source.clone(), RecoveryLimits::default()).unwrap();
        let factory = RecoveryAuthenticatorFactory::new(base_factory(creates.clone()), service);
        let (handle, host) = connect(&security, Arc::new(factory), b"wrong-local-credential").await;
        assert!(handle.is_err());
        let error = host.err().expect("core auth must reject before ready");
        assert!(matches!(
            error,
            Error::LocalProtocol(ErrorCode::Unauthenticated)
        ));
        assert_eq!(
            error.to_string(),
            "Syntra local protocol failure (Unauthenticated)"
        );
        assert_eq!(creates.load(Ordering::SeqCst), 2);
        assert!(source.hooks.lock().unwrap().is_empty());
    }
}

struct BudgetFactory {
    budget: ExecutionBudget,
    calls: Arc<AtomicUsize>,
}
impl AuthenticatorFactory for BudgetFactory {
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(BoundAuth(identity.clone())))
    }
    fn execution_budget(&self) -> ExecutionBudget {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.budget.clone()
    }
}

#[tokio::test]
async fn recovery_wrapper_preserves_base_execution_budget_across_connections() {
    let mode = Mode::Returning;
    let source = Source::new(mode);
    let service = RecoveryService::new(source, RecoveryLimits::default()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    // Zero shared execution capacity must not become the default 1024 on wrapping.
    // Handshake is independent of RPC execution admission and still succeeds.
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(RecoveryAuthenticatorFactory::new(
        BudgetFactory {
            budget: ExecutionBudget::new(0),
            calls: calls.clone(),
        },
        service.clone(),
    ));
    assert!(Arc::ptr_eq(&factory.recovery_service().unwrap(), &service));
    let security = Security::new(mode);
    for _ in 0..2 {
        let (handle, host) = connect(&security, factory.clone(), CREDENTIAL).await;
        let handle = handle.unwrap();
        let host = host.unwrap();
        assert_eq!(
            bounded(handle.conn.call(ECHO, vec![], 2000))
                .await
                .unwrap_err()
                .code(),
            ErrorCode::ResourceExhausted
        );
        let mut recovery = client(&handle, mode, Store::new());
        assert_eq!(
            bounded(recovery.negotiate()).await.err(),
            Some(RecoveryClientError::Rpc(ErrorCode::ResourceExhausted))
        );
        bounded(handle.close()).await;
        bounded(host.close()).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}
