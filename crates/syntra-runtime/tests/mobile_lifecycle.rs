#![cfg(not(target_arch = "wasm32"))]
//! Local executable app/lifecycle harness, NOT mobile OS/device evidence. Each
//! replacement is a fresh Core namespace; the fixture explicitly fences receipts.
use prost::Message;
use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_core::{ErrorCode, Frame};
use syntra_runtime::{
    elapsed::{ElapsedClock, ElapsedSource},
    *,
};
use tokio::sync::mpsc;

struct Source(AtomicU64);
impl ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}
struct Receipt {
    generation: u64,
    bytes: Vec<u8>,
}
struct MobileFixture {
    generation: u64,
    client: Initiator,
    host: Arc<Host>,
    to_host: mpsc::Receiver<Vec<u8>>,
    to_app: mpsc::Receiver<Vec<u8>>,
}
impl MobileFixture {
    async fn connect(generation: u64, source: Arc<Source>, mutations: Arc<AtomicUsize>) -> Self {
        let clock = ElapsedClock::with_source(source);
        let (client, to_host) =
            Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
        let handler = FnHandler(move |method: String, payload, _| {
            let mutations = mutations.clone();
            async move {
                if method == "/fixture.App/Mutate" {
                    mutations.fetch_add(1, Ordering::SeqCst);
                }
                HandlerOutcome::Payload(payload)
            }
        });
        let (host, to_app) = Host::try_new_with_clock(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            Arc::new(handler),
            clock,
        )
        .unwrap();
        let mut this = Self {
            generation,
            client,
            host,
            to_host,
            to_app,
        };
        let conn = this.client.clone();
        let handshake = tokio::spawn(async move { conn.handshake(vec![]).await });
        let ready = this.handoff().await;
        assert!(this.deliver(ready).await);
        handshake.await.unwrap().unwrap();
        this
    }
    async fn handoff(&mut self) -> Receipt {
        let original = self.to_host.recv().await.unwrap();
        let bytes = self
            .client
            .prepare_outbound(original)
            .expect("one-shot original Vec handoff");
        let received_at = self.host.elapsed_clock().now();
        self.host.ingest_received_at(&bytes, received_at).await;
        Receipt {
            generation: self.generation,
            bytes: self.to_app.recv().await.unwrap(),
        }
    }
    async fn deliver(&self, receipt: Receipt) -> bool {
        if receipt.generation != self.generation || self.client.is_closed() {
            return false;
        }
        self.client.ingest(&receipt.bytes).await;
        true
    }
    fn call(
        &self,
        method: &'static str,
        payload: Vec<u8>,
    ) -> tokio::task::JoinHandle<Result<Vec<u8>, syntra_core::SyntraError>> {
        let conn = self.client.clone();
        tokio::spawn(async move { conn.call(method, payload, 1000).await })
    }
    fn suspend(&self) {
        self.client.suspend();
        self.host.suspend();
    }
    async fn wake(&self) {
        self.client.platform_wake().await;
        self.host.platform_wake().await;
    }
    async fn shutdown(mut self) {
        self.to_host.close();
        self.to_app.close();
        while self.to_host.try_recv().is_ok() {}
        while self.to_app.try_recv().is_ok() {}
        // Fixture owns both queues: no partial unit or callback remains.
        self.client.acknowledge_transport_closed();
        self.host.acknowledge_transport_closed();
        let (client, host) = tokio::join!(
            self.client.shutdown(Duration::from_secs(1)),
            self.host.shutdown(Duration::from_secs(1))
        );
        client.unwrap();
        host.unwrap();
        // Unknown continuity may make the bounded wait return incomplete before
        // ready cleanup tasks run. Poll actual joins; never reset that budget.
        for _ in 0..128 {
            if self.client.shutdown_report().phase == ShutdownPhase::Complete
                && self.host.shutdown_report().phase == ShutdownPhase::Complete
            {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "fixture retained work: {:?} {:?}",
            self.client.shutdown_report(),
            self.host.shutdown_report()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn app_mutation_suspend_wake_replacement_late_receipt_and_shutdown_script() {
    let source = Arc::new(Source(AtomicU64::new(10_000)));
    let effects = Arc::new(AtomicUsize::new(0));
    let mut old = MobileFixture::connect(1, source.clone(), effects.clone()).await;
    let mutation = old.call("/fixture.App/Mutate", vec![1]);
    let buffered = old.handoff().await; // host effect happened; result not selected
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let old_id = Frame::decode(buffered.bytes.as_slice()).unwrap().request_id;
    old.suspend();
    source.0.fetch_add(2000, Ordering::SeqCst);
    old.wake().await;
    assert_eq!(
        mutation.await.unwrap().unwrap_err().code(),
        ErrorCode::DeadlineExceeded
    );
    let mut replacement = MobileFixture::connect(2, source, effects.clone()).await;
    let echo = replacement.call("/fixture.App/Echo", vec![2]);
    let fresh = replacement.handoff().await;
    assert_eq!(
        Frame::decode(fresh.bytes.as_slice()).unwrap().request_id,
        old_id,
        "IDs can restart only in a fresh namespace"
    );
    assert!(!replacement.deliver(buffered).await);
    assert!(
        !echo.is_finished(),
        "old generation must not complete a replacement call"
    );
    assert!(replacement.deliver(fresh).await);
    assert_eq!(echo.await.unwrap().unwrap(), vec![2]);
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "no mutation replay on replacement"
    );
    old.shutdown().await;
    replacement.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn app_unknown_elapsed_continuity_fences_queued_mutation_before_handoff() {
    let source = Arc::new(Source(AtomicU64::new(10_000)));
    let effects = Arc::new(AtomicUsize::new(0));
    let mut fixture = MobileFixture::connect(1, source, effects.clone()).await;
    let call = fixture.call("/fixture.App/Mutate", vec![1]);
    let original = fixture.to_host.recv().await.unwrap();
    fixture.suspend();
    fixture.client.elapsed_clock().invalidate();
    assert!(fixture.client.prepare_outbound(original).is_none());
    fixture.wake().await;
    assert_eq!(
        call.await.unwrap().unwrap_err().code(),
        ErrorCode::Unavailable
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    fixture.shutdown().await;
}
