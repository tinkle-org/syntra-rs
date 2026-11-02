//! Public, bounded local fixtures; not a production DurableSource or CONF runner.
use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use prost::Message;
use syntra_core::proto::{frame::Body, recovery_notification::Notification, *};
use syntra_core::{ConnectionState, ErrorCode};
use syntra_runtime::recovery::persistence::*;
use syntra_runtime::recovery::wire::*;
use syntra_runtime::recovery::wire_client::*;
use syntra_runtime::{ConnectionConfig, FnHandler, HandlerOutcome, Host, Initiator, StaticToken};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinSet as TaskJoinSet;

pub const P: &str = "public-fixture-principal";
pub const OTHER_P: &str = "public-fixture-other-principal";
pub const A: &[u8] = b"public-stream-a";
pub const ALIAS: &[u8] = b"public-alias-a";
pub const B: &[u8] = b"public-stream-b";
pub const ECHO: &str = "/example.Echo/Echo";
// Only Source interprets these as positions. Lexicographic/numeric order is useless.
pub const CP: [&[u8]; 8] = [
    b"\xfe\0",
    b"\0\x99\xff",
    b"\x80",
    b"\x03\0",
    b"\xff\x01",
    b"\x02\xee\0",
    b"\x91\x04",
    b"\x01\0\xff\0",
];
pub const STATE: &[u8] = b"public full application state\0including rows and indexes";

pub fn checkpoint(stream: &[u8], index: usize) -> Vec<u8> {
    if stream == B {
        [b"\x00\xfeB".as_slice(), CP[index]].concat()
    } else {
        CP[index].to_vec()
    }
}

pub async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), f)
        .await
        .expect("local acceptance probe exceeded outer budget")
}

pub async fn pending<T>(f: impl Future<Output = T>) {
    tokio::pin!(f);
    std::future::poll_fn(|cx| {
        assert!(
            f.as_mut().poll(cx).is_pending(),
            "unexpected event before gate"
        );
        Poll::Ready(())
    })
    .await;
}

pub fn scope(stream: &[u8]) -> PersistenceScope {
    PersistenceScope::new(P.as_bytes().to_vec(), stream.to_vec()).unwrap()
}
pub fn record(index: usize) -> DurableRecord {
    DurableRecord {
        generation: 7,
        checkpoint: CP[index].to_vec(),
        application_state: STATE.to_vec(),
    }
}
pub fn memory(index: usize) -> MemoryRecoveryStore {
    let mut store = MemoryRecoveryStore::new();
    store.commit(&scope(A), None, record(index)).unwrap();
    store
}

/// Bounded immutable history and issued bindings are reconstructible from these
/// fixture inputs after service restart, independently of reply caches/Confirm.
pub struct Source {
    pub head: [AtomicUsize; 2],
    pub generation: [AtomicU64; 2],
    pub replay_calls: AtomicUsize,
    pub retention_miss: AtomicBool,
    pub snapshot_at: AtomicUsize,
    pub denied: Mutex<Option<(Vec<u8>, ProviderError)>>,
}
impl Source {
    pub fn new(head: usize) -> Arc<Self> {
        assert!(head < CP.len());
        Arc::new(Self {
            head: [AtomicUsize::new(head), AtomicUsize::new(head)],
            generation: [AtomicU64::new(7), AtomicU64::new(7)],
            replay_calls: AtomicUsize::new(0),
            retention_miss: AtomicBool::new(false),
            snapshot_at: AtomicUsize::new(head),
            denied: Mutex::new(None),
        })
    }
    fn stream(s: &[u8]) -> Result<usize, ProviderError> {
        if s == A || s == ALIAS {
            Ok(0)
        } else if s == B {
            Ok(1)
        } else {
            Err(ProviderError::PermissionDenied)
        }
    }
    fn principal(p: &Principal) -> Result<(), ProviderError> {
        if p.subject == P || p.subject == OTHER_P {
            Ok(())
        } else {
            Err(ProviderError::PermissionDenied)
        }
    }
    pub fn batch(&self, stream: &[u8], from: usize, to: usize) -> StoredBatch {
        assert!(from < CP.len() && to < CP.len());
        StoredBatch {
            generation: self.generation[Self::stream(stream).unwrap()].load(Ordering::SeqCst),
            predecessor: checkpoint(stream, from),
            result: checkpoint(stream, to),
            payload: vec![b'F', to as u8],
        }
    }
    pub fn append(&self, service: &RecoveryService, stream: &[u8]) {
        let i = Self::stream(stream).unwrap();
        let from = self.head[i].load(Ordering::SeqCst);
        assert!(from + 1 < CP.len(), "bounded fixture history exhausted");
        self.head[i].store(from + 1, Ordering::SeqCst);
        service
            .publish(
                &Principal::new(P),
                if i == 0 { A } else { B },
                self.batch(stream, from, from + 1),
            )
            .unwrap();
    }
    pub fn service(self: &Arc<Self>, limits: RecoveryLimits) -> Arc<RecoveryService> {
        RecoveryService::new(self.clone(), limits).unwrap()
    }
}
impl RecoverySource for Source {
    fn authorize(
        &self,
        p: &Principal,
        selector: &[u8],
        _: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        Self::principal(p)?;
        Self::stream(selector)?;
        if let Some((s, e)) = &*self.denied.lock().unwrap() {
            if s == selector {
                return Err(*e);
            }
        }
        Ok(())
    }
    fn capture(&self, p: &Principal, selector: &[u8]) -> Result<ProviderStream, ProviderError> {
        Self::principal(p)?;
        let i = Self::stream(selector)?;
        ProviderStream::new(
            if i == 0 { A } else { B }.to_vec(),
            self.current_generation(p, selector)?,
            checkpoint(selector, self.head[i].load(Ordering::SeqCst)),
        )
    }
    fn current_generation(&self, p: &Principal, identity: &[u8]) -> Result<u64, ProviderError> {
        Self::principal(p)?;
        let i = Self::stream(identity)?;
        Ok(if p.subject == OTHER_P {
            7
        } else {
            self.generation[i].load(Ordering::SeqCst)
        })
    }
    fn validate_issued(
        &self,
        p: &Principal,
        s: &ProviderStream,
        cp: &[u8],
    ) -> Result<(), ProviderError> {
        let i = Self::stream(s.identity())?;
        if self.current_generation(p, s.identity())? != s.generation()
            || !(0..=self.head[i].load(Ordering::SeqCst)).any(|n| checkpoint(s.identity(), n) == cp)
        {
            return Err(ProviderError::FailedPrecondition);
        }
        Ok(())
    }
    fn replay(
        &self,
        p: &Principal,
        s: &ProviderStream,
        from: &[u8],
        marker: &[u8],
        budget: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        Self::principal(p)?;
        self.replay_calls.fetch_add(1, Ordering::SeqCst);
        if self.retention_miss.load(Ordering::SeqCst) {
            return Err(ProviderError::ProviderRetentionMiss);
        }
        self.validate_issued(p, s, from)?;
        let start = (0..CP.len())
            .position(|n| checkpoint(s.identity(), n) == from)
            .ok_or(ProviderError::FailedPrecondition)?;
        let end = (0..CP.len())
            .position(|n| checkpoint(s.identity(), n) == s.boundary())
            .ok_or(ProviderError::Internal)?;
        if start > end || (!marker.is_empty() && marker != from) {
            return Err(ProviderError::FailedPrecondition);
        }
        let stop = (start + budget.max_batches.min(2)).min(end);
        let batches = (start..stop)
            .map(|n| {
                let mut b = self.batch(s.identity(), n, n + 1);
                b.generation = s.generation();
                b
            })
            .collect::<Vec<_>>();
        // The fixture has tiny entries; enforce a conservative envelope allowance.
        if batches.len() * 128 > budget.max_entry_total_bytes || budget.max_entry_bytes < 128 {
            return Err(ProviderError::ResourceExhausted);
        }
        ProviderPage::new(
            batches,
            checkpoint(s.identity(), stop),
            if stop == end {
                vec![]
            } else {
                checkpoint(s.identity(), stop)
            },
        )
    }
    fn snapshot(
        &self,
        p: &Principal,
        s: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        Self::principal(p)?;
        let n = self.snapshot_at.load(Ordering::SeqCst);
        self.validate_issued(p, s, &checkpoint(s.identity(), n))?;
        ProviderSnapshot::new(
            b"public-immutable-snapshot".to_vec(),
            checkpoint(s.identity(), n),
            2,
            128,
        )
    }
    fn snapshot_page(
        &self,
        p: &Principal,
        s: &ProviderStream,
        snap: &ProviderSnapshot,
        index: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        Self::principal(p)?;
        self.validate_issued(p, s, snap.boundary())?;
        if snap.key() != b"public-immutable-snapshot" || index >= 2 {
            return Err(ProviderError::FailedPrecondition);
        }
        Ok(if index == 0 {
            b"public snapshot rows\0".to_vec()
        } else {
            b"public snapshot indexes".to_vec()
        })
    }
}

/// Captures only ACTIVE public fixture traffic; never Hello credentials or Ready IDs.
#[derive(Clone)]
pub struct RawFrame {
    pub to_host: bool,
    pub frame: Frame,
    pub bytes: Vec<u8>,
    pub delivered: bool,
}
#[derive(Default)]
pub struct Trace {
    pub frames: Mutex<Vec<RawFrame>>,
    changed: Notify,
}
impl Trace {
    fn push(&self, to_host: bool, bytes: &[u8], delivered: bool) {
        let frame = Frame::decode(bytes).unwrap();
        if !matches!(
            frame.body,
            Some(Body::Request(_) | Body::Result(_) | Body::Notification(_))
        ) {
            return;
        }
        let mut frames = self.frames.lock().unwrap();
        assert!(frames.len() < 512, "bounded public trace exhausted");
        frames.push(RawFrame {
            to_host,
            frame,
            bytes: bytes.to_vec(),
            delivered,
        });
        drop(frames);
        self.changed.notify_waiters();
    }
    pub fn requests(&self, method: &str) -> Vec<(u64, Vec<u8>)> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| match &r.frame.body {
                Some(Body::Request(q)) if r.to_host && q.method == method => {
                    Some((r.frame.request_id, q.payload.clone()))
                }
                _ => None,
            })
            .collect()
    }
    pub fn responses(&self, method: &str) -> Vec<Result<Vec<u8>, ErrorCode>> {
        let ids = self
            .requests(method)
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| {
                if r.to_host || !ids.contains(&r.frame.request_id) {
                    return None;
                }
                match &r.frame.body {
                    Some(Body::Result(RpcResult {
                        outcome: Some(rpc_result::Outcome::Payload(p)),
                    })) => Some(Ok(p.clone())),
                    Some(Body::Result(RpcResult {
                        outcome: Some(rpc_result::Outcome::Error(e)),
                    })) => Some(Err(ErrorCode::from_i32_lossy(e.code).0)),
                    _ => None,
                }
            })
            .collect()
    }
    pub fn notifications(&self, delivered_only: bool) -> Vec<Notification> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter_map(|r| match &r.frame.body {
                Some(Body::Notification(n)) if !delivered_only || r.delivered => {
                    assert_eq!(r.frame.request_id, 0);
                    RecoveryNotification::decode(n.payload.as_slice())
                        .unwrap()
                        .notification
                }
                _ => None,
            })
            .collect()
    }
    pub async fn wait_notifications(&self, count: usize, delivered: bool) {
        self.wait_matching(count, delivered, |_| true).await;
    }
    pub async fn wait_matching(
        &self,
        count: usize,
        delivered: bool,
        matches: impl Fn(&Notification) -> bool,
    ) {
        bounded(async {
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self
                    .notifications(delivered)
                    .iter()
                    .filter(|n| matches(n))
                    .count()
                    >= count
                {
                    return;
                }
                notified.await;
            }
        })
        .await;
    }
    pub fn assert_ids(&self) {
        let frames = self.frames.lock().unwrap();
        let ids = frames
            .iter()
            .filter_map(|r| {
                if r.to_host && matches!(r.frame.body, Some(Body::Request(_))) {
                    Some(r.frame.request_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert!(ids.iter().all(|id| *id > 0));
        assert!(
            ids.windows(2).all(|w| w[0] < w[1]),
            "fresh increasing Core IDs required"
        );
        for r in frames.iter() {
            assert_eq!(Frame::decode(r.bytes.as_slice()).unwrap(), r.frame);
        }
    }
}
#[derive(Default)]
pub struct Faults {
    pub hold_completion: AtomicBool,
    pub drop_results: Mutex<Option<&'static str>>,
}
pub struct Bridge {
    pub init: Initiator,
    pub host: Arc<Host>,
    pub trace: Arc<Trace>,
    pub faults: Arc<Faults>,
    release: mpsc::Sender<oneshot::Sender<()>>,
    tasks: TaskJoinSet<()>,
}
impl Bridge {
    pub async fn new(service: Option<Arc<RecoveryService>>) -> Self {
        Self::new_as(service, P).await
    }
    pub async fn new_as(service: Option<Arc<RecoveryService>>, principal: &str) -> Self {
        let config = ConnectionConfig {
            notification_capacity: 1,
            ..ConnectionConfig::default()
        };
        let (init, mut init_rx) = Initiator::try_new(config.clone()).unwrap();
        let (host, mut host_rx) = Host::try_new(
            config,
            Arc::new(StaticToken::new(
                b"public-fixture-credential".to_vec(),
                principal,
            )),
            Arc::new(FnHandler(|m: String, p: Vec<u8>, _| async move {
                if m == ECHO {
                    HandlerOutcome::Payload(p)
                } else {
                    HandlerOutcome::error(ErrorCode::Unimplemented, "public fixture")
                }
            })),
        )
        .unwrap();
        assert_eq!(host.state().await, ConnectionState::Connected);
        if let Some(service) = service {
            host.configure_recovery(service).await.unwrap();
        }
        let trace = Arc::new(Trace::default());
        let faults = Arc::new(Faults::default());
        let methods = Arc::new(Mutex::new(BTreeMap::<u64, String>::new()));
        let mut tasks = TaskJoinSet::new();
        let (i, h, t, m) = (init.clone(), host.clone(), trace.clone(), methods.clone());
        tasks.spawn(async move {
            let (mut ic, mut hc) = (i.subscribe_close(), h.subscribe_close());
            loop {
                if i.is_closed() || h.is_closed() { break; }
                tokio::select! { biased;
                    _ = ic.changed() => break,
                    _ = hc.changed() => break,
                    bytes = init_rx.recv() => match bytes {
                        Some(original) => if let Some(bytes) = i.prepare_outbound(original) {
                            let received = tokio::time::Instant::now().into_std();
                            if let Some(Body::Request(q)) = Frame::decode(bytes.as_slice()).unwrap().body {
                                m.lock().unwrap().insert(Frame::decode(bytes.as_slice()).unwrap().request_id, q.method);
                            }
                            t.push(true, &bytes, true);
                            h.ingest_received_at(&bytes, received).await;
                        },
                        None => break,
                    }
                }
            }
            init_rx.close();
            h.on_transport_lost().await;
        });
        let (release, mut releases) = mpsc::channel::<oneshot::Sender<()>>(1);
        let (i, h, t, f) = (init.clone(), host.clone(), trace.clone(), faults.clone());
        tasks.spawn(async move {
            let (mut ic, mut hc) = (i.subscribe_close(), h.subscribe_close());
            let mut held: Vec<Vec<u8>> = Vec::new();
            loop {
                if i.is_closed() || h.is_closed() { break; }
                tokio::select! { biased;
                    _ = ic.changed() => break,
                    _ = hc.changed() => break,
                    Some(done) = releases.recv() => {
                        for bytes in held.drain(..) { i.ingest(&bytes).await; t.push(false, &bytes, true); }
                        let _ = done.send(());
                    },
                    bytes = host_rx.recv() => match bytes {
                        Some(bytes) => {
                            let frame = Frame::decode(bytes.as_slice()).unwrap();
                            let completion = match &frame.body { Some(Body::Notification(n)) => match RecoveryNotification::decode(n.payload.as_slice()).unwrap().notification {
                                Some(Notification::ReplayComplete(_)) => true,
                                Some(Notification::Trailer(t)) => t.outcome == Some(recovery_batch_trailer::Outcome::CatchupComplete(true)),
                                _ => false,
                            }, _ => false };
                            let drop_result = matches!(frame.body, Some(Body::Result(_))) && f.drop_results.lock().unwrap().is_some_and(|method| methods.lock().unwrap().get(&frame.request_id).is_some_and(|m| m == method));
                            if completion && f.hold_completion.load(Ordering::SeqCst) {
                                t.push(false, &bytes, false); assert!(held.len() < 32); held.push(bytes);
                            } else if drop_result { t.push(false, &bytes, false); }
                            else { i.ingest(&bytes).await; t.push(false, &bytes, true); }
                        },
                        None => break,
                    }
                }
            }
            host_rx.close();
            i.on_transport_lost().await;
        });
        let bridge = Self {
            init,
            host,
            trace,
            faults,
            release,
            tasks,
        };
        bounded(bridge.init.handshake(b"public-fixture-credential".to_vec()))
            .await
            .unwrap();
        bridge
    }
    pub fn client<S: RecoveryPersistence + 'static>(
        &self,
        store: S,
        limits: RecoveryLimits,
    ) -> RecoveryClient<S> {
        RecoveryClient::new(self.init.clone(), P.as_bytes().to_vec(), store, limits).unwrap()
    }
    pub async fn release_completions(&self) {
        bounded(async {
            self.faults.hold_completion.store(false, Ordering::SeqCst);
            let (tx, rx) = oneshot::channel();
            self.release.send(tx).await.unwrap();
            rx.await.unwrap();
        })
        .await;
    }
    pub async fn echo(&self) {
        assert_eq!(
            bounded(self.init.call(ECHO, b"public core control".to_vec(), 2000))
                .await
                .unwrap(),
            b"public core control"
        );
    }
    pub async fn raw<M: Message>(&self, method: &str, request: M) -> Result<Vec<u8>, ErrorCode> {
        bounded(self.init.call(method, request.encode_to_vec(), 2000))
            .await
            .map_err(|e| e.code())
    }
    pub async fn finish(mut self) {
        self.trace.assert_ids();
        bounded(async {
            self.host.close().await;
            self.init.close().await;
            while let Some(result) = self.tasks.join_next().await {
                result.unwrap();
            }
        })
        .await;
        assert!(self.host.is_closed() && self.init.is_closed());
    }
}
pub async fn negotiate<S: RecoveryPersistence + 'static>(
    c: &mut RecoveryClient<S>,
) -> RecoveryNegotiateResponse {
    match bounded(c.negotiate()).await.unwrap() {
        Negotiation::Confirmed(n) => n,
        _ => panic!("fixture supports profile"),
    }
}
pub async fn subscribe<S: RecoveryPersistence + 'static>(
    c: &mut RecoveryClient<S>,
    stream: &[u8],
    intent: SubscribeIntent,
) -> RecoverySubscribeResponse {
    bounded(c.subscribe(
        stream.to_vec(),
        if stream == ALIAS { A } else { stream }.to_vec(),
        intent,
    ))
    .await
    .unwrap()
    .response
}
pub async fn batch<S: RecoveryPersistence + 'static>(c: &mut RecoveryClient<S>) -> RecoveryBatch {
    match bounded(c.next_event()).await.unwrap() {
        RecoveryEvent::Batch { batch } => batch,
        _ => panic!("expected batch offer"),
    }
}

static DIR_SERIAL: AtomicUsize = AtomicUsize::new(0);
pub struct Disk(pub PathBuf);
impl Disk {
    pub fn new() -> Self {
        Self(std::env::temp_dir().canonicalize().unwrap().join(format!(
            "syntra-wire-public-{}-{}",
            std::process::id(),
            DIR_SERIAL.fetch_add(1, Ordering::SeqCst)
        )))
    }
    pub async fn open(&self) -> FileRecoveryStore {
        let path = self.0.clone();
        bounded(tokio::task::spawn_blocking(move || {
            FileRecoveryStore::open(path, StoreLimits::default()).unwrap()
        }))
        .await
        .unwrap()
    }
    pub async fn seeded(&self, index: usize) -> FileRecoveryStore {
        let mut store = self.open().await;
        bounded(tokio::task::spawn_blocking(move || {
            store.commit(&scope(A), None, record(index)).unwrap();
            store
        }))
        .await
        .unwrap()
    }
}
impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
