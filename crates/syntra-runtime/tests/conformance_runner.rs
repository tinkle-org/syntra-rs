//! Shared conformance runner — async Rust leg (pairing `rust-async`).
//!
//! Exercises selected loopback/manual byte-pump cases described in
//! `conformance/runner/scenarios.yaml`. Recovery tests run separately;
//! this file does not certify every scenario or the full manifest matrix.
//!
//! Fault injection is deterministic: a seeded counter decides drop/duplicate/
//! truncate faults, so the same seed replays the same pattern.

use std::sync::Arc;
use std::time::Duration;

use syntra_core::{decode_frame, ErrorCode, ValidationContext};
use syntra_runtime::{
    loopback_pair, AllowAnonymous, CancelToken, ConnectionConfig, FnHandler, HandlerOutcome,
};

fn echo_handler() -> Arc<dyn syntra_runtime::Handler> {
    Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, _cancel: CancelToken| async move {
            match method.as_str() {
                "/example.Echo/Echo" => HandlerOutcome::Payload(payload),
                "/example.KV/Get" => HandlerOutcome::error(ErrorCode::NotFound, "missing"),
                "/example.Slow/Wait" => {
                    syntra_runtime::sleep_for(Duration::from_millis(300)).await;
                    HandlerOutcome::Payload(b"slow-ok".to_vec())
                }
                "/example.Huge/Reply" => HandlerOutcome::Payload(vec![0xAB; 2 * 1024 * 1024]),
                _ => HandlerOutcome::error(ErrorCode::Unimplemented, "unknown method"),
            }
        },
    ))
}

/// Deterministic fault injector: wraps raw transport bytes with seeded
/// drop/duplicate/truncation. The same seed replays the same pattern.
struct FaultInjector {
    seed: u64,
    counter: u64,
}

impl FaultInjector {
    fn new(seed: u64) -> Self {
        Self { seed, counter: 0 }
    }
    fn next(&mut self) -> u64 {
        // xorshift64* — deterministic, no external RNG.
        let mut x = self
            .seed
            .wrapping_add(self.counter.wrapping_mul(0x9E3779B97F4A7C15));
        self.counter += 1;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn should_drop(&mut self) -> bool {
        self.next() % 64 == 0
    }
    fn should_duplicate(&mut self) -> bool {
        self.next() % 128 == 0
    }
    fn should_truncate(&mut self) -> bool {
        self.next() % 96 == 0
    }
    /// Apply seeded faults to one transport unit. Returns the byte vectors
    /// the transport would deliver: empty on drop, two copies on duplicate,
    /// a single truncated copy on truncation, otherwise the input unchanged.
    fn transport_wrap(&mut self, bytes: Vec<u8>) -> Vec<Vec<u8>> {
        if self.should_drop() {
            return Vec::new();
        }
        if self.should_truncate() {
            let mut t = bytes;
            let n = t.len().saturating_sub(1).max(1);
            t.truncate(n);
            return vec![t];
        }
        if self.should_duplicate() {
            return vec![bytes.clone(), bytes];
        }
        vec![bytes]
    }
    /// Apply seeded faults to one host->initiator unit (response path).
    /// Same drop/duplicate/truncate semantics as [`transport_wrap`]; a
    /// separate injector instance per direction keeps each seeded stream
    /// deterministic and undisturbed by the other direction's draws.
    fn response_wrap(&mut self, bytes: Vec<u8>) -> Vec<Vec<u8>> {
        self.transport_wrap(bytes)
    }
}

fn hello_bytes() -> Vec<u8> {
    use prost::Message;
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::{ClientHello, Frame};
    Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: vec![].into(),
        })),
    }
    .encode_to_vec()
}

/// Assert a decoded Result carries the expected request id and payload.
/// This assertion alone says nothing about caller settlement or replay.
fn assert_terminal_payload(frame_bytes: &[u8], expected: &[u8], request_id: u64) {
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::rpc_result::Outcome;
    let ctx = ValidationContext::active(1);
    let f = decode_frame(frame_bytes, ctx).expect("terminal must decode");
    assert_eq!(f.request_id, request_id, "terminal carries the delivery id");
    match f.body {
        Some(Body::Result(r)) => match r.outcome {
            Some(Outcome::Payload(p)) => {
                assert_eq!(&p[..], expected, "opaque payload preserved")
            }
            other => panic!("expected payload terminal, got {other:?}"),
        },
        other => panic!("expected result terminal, got {other:?}"),
    }
}

/// Pump real Host responses into an Initiator with a registered pending call.
/// Loss/corruption is recovered by redelivery of the held response, not by
/// claiming reliable-session replay or re-executing an application handler.
async fn exercise_response_fault(fi: &mut FaultInjector) -> &'static str {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (initiator, mut requests) = syntra_runtime::Initiator::new(ConnectionConfig::default());
        let (host, mut responses) = syntra_runtime::Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        let mut handshake = Box::pin(initiator.handshake(vec![]));
        assert!(futures_util::poll!(&mut handshake).is_pending());
        host.ingest(&requests.recv().await.expect("hello")).await;
        initiator
            .ingest(&responses.recv().await.expect("ready"))
            .await;
        handshake.await.expect("handshake");

        let payload = b"response-fault".to_vec();
        let mut call = Box::pin(initiator.call("/example.Echo/Echo", payload.clone(), 4000));
        assert!(futures_util::poll!(&mut call).is_pending());
        let request = requests.recv().await.expect("pending request");
        let id = decode_frame(&request, ValidationContext::active(1))
            .unwrap()
            .request_id;
        host.ingest(&request).await;
        let response = responses.recv().await.expect("host result");
        assert_terminal_payload(&response, &payload, id);
        let copies = fi.response_wrap(response.clone());
        let kind = if copies.is_empty() {
            "drop"
        } else if copies.len() == 2 {
            "duplicate"
        } else if copies[0] != response {
            "truncate"
        } else {
            "clean"
        };
        assert_eq!(initiator.pending_len(), 1);
        for copy in &copies {
            initiator.ingest(copy).await;
        }
        if kind == "drop" || kind == "truncate" {
            assert_eq!(initiator.pending_len(), 1, "fault cannot settle the caller");
            assert!(futures_util::poll!(&mut call).is_pending());
            initiator.ingest(&response).await;
        }
        assert_eq!(
            initiator.pending_len(),
            0,
            "delivered response settles pending state"
        );
        assert_eq!(call.await.expect("one terminal caller outcome"), payload);
        assert_eq!(initiator.pending_len(), 0);

        // A late duplicate must not settle another pending call or poison it.
        let mut follow = Box::pin(initiator.call("/example.Echo/Echo", b"follow".to_vec(), 4000));
        assert!(futures_util::poll!(&mut follow).is_pending());
        let next = requests.recv().await.expect("follow-up request");
        initiator.ingest(&response).await;
        assert_eq!(initiator.pending_len(), 1);
        assert!(futures_util::poll!(&mut follow).is_pending());
        host.ingest(&next).await;
        initiator
            .ingest(&responses.recv().await.expect("follow-up result"))
            .await;
        assert_eq!(follow.await.unwrap(), b"follow");
        assert_eq!(initiator.pending_len(), 0);
        assert!(
            responses.try_recv().is_err(),
            "no extra host terminal queued"
        );
        initiator.close().await;
        host.close().await;
        kind
    })
    .await
    .expect("response fault case bounded")
}

async fn expect_ready(wrx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>, what: &str) {
    tokio::time::timeout(Duration::from_secs(2), wrx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}"))
        .expect("open");
}

/// Build a handshaked Host while faulting the hello through `fi`.
/// Drop: no ready arrives; the same Host recovers via hello retry.
/// Truncate/duplicate: handshake validation terminally rejects the faulted
/// hello (never a bogus ready); a fresh Host plus a clean hello recovers.
async fn establish_host(
    fi: &mut FaultInjector,
    handler: Arc<dyn syntra_runtime::Handler>,
    hello_faults: &mut u32,
) -> (
    Arc<syntra_runtime::Host>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let clean = hello_bytes();
    let (host, mut wrx) = syntra_runtime::Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        handler.clone(),
    );
    let sends = fi.transport_wrap(clean.clone());
    if sends.len() == 1 && sends[0] == clean {
        host.ingest(&sends[0]).await;
        expect_ready(&mut wrx, "ready").await;
        return (host, wrx);
    }
    *hello_faults += 1;
    if sends.is_empty() {
        // Dropped hello: nothing may arrive; retry on the SAME host.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wrx.recv())
                .await
                .is_err(),
            "dropped hello must not produce a ready"
        );
        host.ingest(&clean).await;
        expect_ready(&mut wrx, "hello retry after drop recovers").await;
        return (host, wrx);
    }
    if sends.len() == 2 {
        // Duplicated hello: the first copy handshakes (exactly one ready);
        // the second copy is rejected as an unexpected hello — never a
        // second ready — and the handshake is torn down.
        host.ingest(&sends[0]).await;
        expect_ready(&mut wrx, "first hello copy handshakes").await;
        host.ingest(&sends[1]).await;
        match tokio::time::timeout(Duration::from_millis(50), wrx.recv()).await {
            Ok(Some(_)) => panic!("duplicated hello must not produce a second ready"),
            Ok(None) | Err(_) => {}
        }
    } else {
        // Truncated hello: handshake validation fails it; no ready and no
        // usable session — rejected terminally by design.
        host.ingest(&sends[0]).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wrx.recv())
                .await
                .is_err(),
            "truncated hello must not produce a ready"
        );
    }
    let (host, mut wrx) = syntra_runtime::Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        handler,
    );
    host.ingest(&clean).await;
    expect_ready(&mut wrx, "clean handshake after faulted hello recovers").await;
    (host, wrx)
}

#[tokio::test]
async fn sc_echo() {
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        echo_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    for payload in [vec![], b"hello".to_vec(), vec![7u8; 64 * 1024]] {
        let out = initiator
            .call("/example.Echo/Echo", payload.clone(), 2000)
            .await
            .expect("echo");
        assert_eq!(
            out, payload,
            "opaque bytes must be preserved bit-identically"
        );
    }
}

#[tokio::test]
async fn sc_concurrent_16_correlated() {
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        echo_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let c = initiator.clone();
        handles.push(tokio::spawn(async move {
            let p = vec![i; 32];
            let out = c
                .call("/example.Echo/Echo", p.clone(), 5000)
                .await
                .expect("ok");
            assert_eq!(out, p);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn sc_cancelled_call_and_followup() {
    let started = Arc::new(tokio::sync::Notify::new());
    let entered = started.clone();
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(
            move |_m: String, p: Vec<u8>, cancel: CancelToken| {
                let entered = entered.clone();
                async move {
                    // Only the first payload waits for cancel; follow-ups echo.
                    if p == b"x" {
                        entered.notify_one();
                        cancel.cancelled().await;
                        HandlerOutcome::Payload(b"late".to_vec())
                    } else {
                        HandlerOutcome::Payload(p)
                    }
                }
            },
        )),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let token = CancelToken::new();
    let call = {
        let c = initiator.clone();
        let t = token.clone();
        tokio::spawn(async move {
            c.call_cancellable("/example.Echo/Echo", b"x".to_vec(), 5000, &t)
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("handler entered");
    token.cancel();
    let err = tokio::time::timeout(Duration::from_secs(2), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
    // Caller cancellation and follow-up usability; wire count is not observed.
    let out = initiator
        .call("/example.Echo/Echo", b"after".to_vec(), 1000)
        .await
        .expect("usable");
    assert_eq!(out, b"after");
}

#[tokio::test]
async fn sc_caller_deadline_unknown_outcome() {
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        echo_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let err = initiator
        .call("/example.Slow/Wait", b"x".to_vec(), 50)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    assert!(err.is_unknown_outcome());
}

#[tokio::test]
async fn sc_oversize_handler_result_bounded() {
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        echo_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let err = initiator
        .call("/example.Huge/Reply", b"x".to_vec(), 2000)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::ResourceExhausted);
    // Connection stays usable after bounded failure.
    let out = initiator
        .call("/example.Echo/Echo", b"ok".to_vec(), 1000)
        .await
        .expect("usable");
    assert_eq!(out, b"ok");
}

#[tokio::test]
async fn sc_duplicate_outstanding_rejected() {
    use prost::Message;
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::{Frame, RpcRequest};
    let release = Arc::new(tokio::sync::Notify::new());
    let started = Arc::new(tokio::sync::Notify::new());
    let dispatches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rh = release.clone();
    let entered = started.clone();
    let count = dispatches.clone();
    let blocking = Arc::new(FnHandler(
        move |_m: String, _p: Vec<u8>, _c: CancelToken| {
            let rh = rh.clone();
            let entered = entered.clone();
            let count = count.clone();
            async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                entered.notify_one();
                rh.notified().await;
                HandlerOutcome::Payload(b"first".to_vec())
            }
        },
    ));
    let (host, mut wrx) = syntra_runtime::Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        blocking,
    );
    {
        use syntra_core::proto::ClientHello;
        let raw = Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Hello(ClientHello {
                min_version: 1,
                max_version: 1,
                credential: vec![].into(),
            })),
        }
        .encode_to_vec();
        host.ingest(&raw).await;
    }
    expect_ready(&mut wrx, "ready").await;
    let req = |id: u64| {
        Frame {
            version: 1,
            request_id: id,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![].into(),
                timeout_ms: 5000,
            })),
        }
        .encode_to_vec()
    };
    host.ingest(&req(7)).await;
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("original handler started");
    host.ingest(&req(7)).await;
    let dup = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
        .await
        .expect("duplicate rejected")
        .expect("open");
    let ctx = ValidationContext::active(1);
    let f = decode_frame(&dup, ctx).expect("valid");
    assert_eq!(f.request_id, 7);
    match f.body {
        Some(Body::Result(r)) => match r.outcome {
            Some(syntra_core::proto::rpc_result::Outcome::Error(e)) => {
                assert_eq!(e.code, ErrorCode::FailedPrecondition.as_i32())
            }
            other => panic!("expected error, got {other:?}"),
        },
        other => panic!("expected result, got {other:?}"),
    }
    release.notify_one();
    let first = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
        .await
        .expect("first")
        .expect("open");
    assert_terminal_payload(&first, b"first", 7);
    assert_eq!(dispatches.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(wrx.try_recv().is_err(), "no extra host terminal queued");
    host.close().await;
}

#[tokio::test]
async fn sc_close_after_completed_echo() {
    let (initiator, host) = loopback_pair(
        Arc::new(AllowAnonymous),
        echo_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let out = initiator
        .call("/example.Echo/Echo", b"before-close".to_vec(), 1000)
        .await
        .expect("ok");
    assert_eq!(out, b"before-close");
    // Only close after an already-completed echo is exercised here.
    host.close().await;
    assert_eq!(host.sessions().count(), 0);
}

#[tokio::test]
async fn sc_fault_injection_deterministic() {
    // Separate request, response and hello streams. Request retries here
    // are ordinary RPC retries, not durable delivery reconciliation.
    use prost::Message;
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::{Frame, RpcRequest};
    let mut fi = FaultInjector::new(0x5EED1234);
    let mut resp_fi = FaultInjector::new(0xBE5E11);
    let mut hello_fi = FaultInjector::new(0xCAFE01);
    let mut drops = 0u32;
    let mut dups = 0u32;
    let mut truncs = 0u32;
    let mut resp_drops = 0u32;
    let mut resp_dups = 0u32;
    let mut resp_truncs = 0u32;
    let mut hello_faults = 0u32;
    for i in 0..128u8 {
        let payload = vec![i; 16];
        let req_id = 1000u64 + i as u64;
        let raw = Frame {
            version: 1,
            request_id: req_id,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: payload.clone().into(),
                timeout_ms: 5000,
            })),
        }
        .encode_to_vec();
        let sends = fi.transport_wrap(raw.clone());
        if sends.is_empty() {
            drops += 1;
            // Raw request dropped before host ingest; retry the intact bytes.
            let (host, mut wrx) =
                establish_host(&mut hello_fi, echo_handler(), &mut hello_faults).await;
            host.ingest(&raw).await;
            let resp = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
                .await
                .expect("retry after dropped request recovers")
                .expect("open");
            assert_terminal_payload(&resp, &payload, req_id);
            host.close().await;
            continue;
        }
        let is_truncated = sends.len() == 1 && sends[0] != raw;
        if is_truncated {
            truncs += 1;
            let (host, mut wrx) =
                establish_host(&mut hello_fi, echo_handler(), &mut hello_faults).await;
            host.ingest(&sends[0]).await;
            host.ingest(&raw).await;
            let resp = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
                .await
                .expect("truncated must not break connection")
                .expect("open");
            let ctx = ValidationContext::active(1);
            let f = decode_frame(&resp, ctx).expect("valid");
            match f.body {
                Some(Body::Result(r)) => {
                    use syntra_core::proto::rpc_result::Outcome;
                    match r.outcome {
                        Some(Outcome::Payload(p)) => {
                            assert_eq!(p, payload, "opaque payload preserved")
                        }
                        other => panic!("expected payload, got {other:?}"),
                    }
                }
                other => panic!("expected result, got {other:?}"),
            }
            host.close().await;
            continue;
        }
        if sends.len() == 2 {
            dups += 1;
            let release = Arc::new(tokio::sync::Notify::new());
            let rh = release.clone();
            let ph = payload.clone();
            let blocking = Arc::new(FnHandler(
                move |_m: String, _p: Vec<u8>, _c: CancelToken| {
                    let rh2 = rh.clone();
                    let p = ph.clone();
                    async move {
                        rh2.notified().await;
                        HandlerOutcome::Payload(p)
                    }
                },
            ));
            let (host, mut wrx) = establish_host(&mut hello_fi, blocking, &mut hello_faults).await;
            host.ingest(&sends[0]).await;
            host.ingest(&sends[1]).await;
            let dup_resp = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
                .await
                .expect("duplicate rejected")
                .expect("open");
            let ctx = ValidationContext::active(1);
            let f = decode_frame(&dup_resp, ctx).expect("valid");
            match f.body {
                Some(Body::Result(r)) => match r.outcome {
                    Some(syntra_core::proto::rpc_result::Outcome::Error(e)) => {
                        assert_eq!(e.code, ErrorCode::FailedPrecondition.as_i32());
                    }
                    other => panic!("expected duplicate error, got {other:?}"),
                },
                other => panic!("expected result, got {other:?}"),
            }
            release.notify_one();
            let first = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
                .await
                .expect("first")
                .expect("open");
            let f1 = decode_frame(&first, ctx).expect("valid");
            match f1.body {
                Some(Body::Result(r)) => match r.outcome {
                    Some(syntra_core::proto::rpc_result::Outcome::Payload(p)) => {
                        assert_eq!(p, payload, "opaque payload preserved")
                    }
                    other => panic!("expected payload, got {other:?}"),
                },
                other => panic!("expected result, got {other:?}"),
            }
            host.close().await;
            continue;
        }
        let (host, mut wrx) =
            establish_host(&mut hello_fi, echo_handler(), &mut hello_faults).await;
        host.ingest(&sends[0]).await;
        let resp = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
            .await
            .expect("echo under faults")
            .expect("open");
        assert_terminal_payload(&resp, &payload, req_id);
        match exercise_response_fault(&mut resp_fi).await {
            "drop" => resp_drops += 1,
            "duplicate" => resp_dups += 1,
            "truncate" => resp_truncs += 1,
            "clean" => {}
            other => panic!("unknown response fault {other}"),
        }
        host.close().await;
    }
    assert!(
        drops > 0 && drops < 8,
        "seeded drop rate exercised: {drops}"
    );
    assert!(dups > 0, "seeded duplicate branch exercised: {dups}");
    assert!(truncs > 0, "seeded truncation branch exercised: {truncs}");
    eprintln!("fault coverage: req drops={drops} dups={dups} truncs={truncs} | resp drops={resp_drops} dups={resp_dups} truncs={resp_truncs} | hello faults={hello_faults}");
    assert!(
        resp_drops + resp_dups + resp_truncs + hello_faults > 0,
        "response/hello fault branches must be exercised"
    );
}

#[tokio::test]
async fn sc_response_faults_recover() {
    // Find a deterministic PRNG position for EACH fault, then execute the
    // real pending-caller case at that position. Coverage is not probabilistic.
    for wanted in ["drop", "truncate", "duplicate"] {
        let mut finder = FaultInjector::new(0xBE5E11);
        let counter = (0..100_000)
            .find(|_| {
                let copies = finder.response_wrap(vec![1, 2, 3]);
                match wanted {
                    "drop" => copies.is_empty(),
                    "truncate" => copies == vec![vec![1, 2]],
                    "duplicate" => copies.len() == 2,
                    _ => unreachable!(),
                }
            })
            .expect("seed must cover each fault");
        // Each wrap consumes a variable number of PRNG draws; replay wraps,
        // rather than assuming the wrap index equals the PRNG counter.
        let mut fi = FaultInjector::new(0xBE5E11);
        for _ in 0..counter {
            fi.response_wrap(vec![1, 2, 3]);
        }
        assert_eq!(exercise_response_fault(&mut fi).await, wanted);
        eprintln!("response fault exercised with pending caller: {wanted}");
    }
}

#[tokio::test]
async fn sc_hello_faults_recover() {
    // Hello-path faults, deterministically: a dropped hello yields no
    // ready and the same Host recovers via retry; a duplicated hello
    // yields exactly one ready — the second copy is rejected and never
    // produces a second ready.
    {
        let (host, mut wrx) = syntra_runtime::Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), wrx.recv())
                .await
                .is_err(),
            "no hello, no ready"
        );
        host.ingest(&hello_bytes()).await;
        expect_ready(&mut wrx, "hello retry after drop recovers").await;
    }
    {
        let (host, mut wrx) = syntra_runtime::Host::new(
            ConnectionConfig::default(),
            Arc::new(AllowAnonymous),
            echo_handler(),
        );
        host.ingest(&hello_bytes()).await;
        expect_ready(&mut wrx, "first hello handshakes").await;
        host.ingest(&hello_bytes()).await;
        match tokio::time::timeout(Duration::from_millis(50), wrx.recv()).await {
            Ok(Some(_)) => panic!("duplicated hello must not produce a second ready"),
            Ok(None) | Err(_) => {}
        }
    }
}

#[tokio::test]
async fn sc_wire_vectors_decode() {
    use syntra_core::proto::frame::Body;
    for id in ["GOLD-PROT-HELLO-01", "GOLD-PROT-REQ-01"] {
        let hex = corpus_hex(id);
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&hex[n..n + 2], 16).unwrap())
            .collect();
        let ctx = if id == "GOLD-PROT-HELLO-01" {
            ValidationContext::pre_handshake(syntra_core::ConnectionState::Connected)
        } else {
            ValidationContext::active(1)
        };
        let f = decode_frame(&bytes, ctx).expect("shared corpus decodes");
        assert_eq!(f.version, 1);
        match f.body {
            Some(Body::Hello(h)) => {
                assert_eq!((f.request_id, h.min_version, h.max_version), (0, 1, 1));
                assert_eq!(&h.credential[..], b"opaque-test-credential-A");
                println!("CORPUS {{\"id\":{id:?},\"frame_hex\":{hex:?},\"semantic_fields\":{{\"version\":{},\"request_id\":{},\"body\":\"hello\",\"min_version\":{},\"max_version\":{},\"credential\":{:?}}}}}",
                    f.version, f.request_id, h.min_version, h.max_version, std::str::from_utf8(&h.credential).unwrap());
            }
            Some(Body::Request(r)) => {
                assert_eq!(f.request_id, 7);
                assert_eq!(r.method, "/example.Echo/Echo");
                assert_eq!(&r.payload[..], b"hello");
                assert_eq!(r.timeout_ms, 500);
                println!("CORPUS {{\"id\":{id:?},\"frame_hex\":{hex:?},\"semantic_fields\":{{\"version\":{},\"request_id\":{},\"body\":\"request\",\"method\":{:?},\"payload\":{:?},\"timeout_ms\":{}}}}}",
                    f.version, f.request_id, r.method, std::str::from_utf8(&r.payload).unwrap(), r.timeout_ms);
            }
            other => panic!("unexpected corpus body {other:?}"),
        }
    }
}

fn corpus_hex(id: &str) -> String {
    let text = include_str!("../../../conformance/test-vectors/protobuf/vectors.yaml");
    let marker = format!("  - id: {id}");
    let mut selected = false;
    let mut found = Vec::new();
    for line in text.lines() {
        if line.starts_with("  - id: ") {
            selected = line == marker;
        }
        if selected {
            if let Some(value) = line.strip_prefix("    frame_hex: ") {
                found.push(value.trim_matches('"').to_string());
            }
        }
    }
    assert_eq!(found.len(), 1, "one shared corpus hex for {id}");
    found.remove(0)
}
