//! Rust side of the C contract. Invoked by build_contract.py, which links the
//! consumer against the feature-selected cdylib. No test host in the library.
#![cfg(all(feature = "managed-media", not(target_family = "wasm")))]
use std::{
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use syntra_core::{
    secure_channel::{
        generate_server_key, Carrier, Context, Error, KeyStore, Mode, Secret32, ServerConfig,
        VerifiedIdentity,
    },
    ErrorCode,
};
use syntra_net::{
    media::{MediaHandler, SqliteMediaHost},
    tcp, AuthenticatorFactory, Limits,
};
use syntra_runtime::{
    AuthError, Authenticator, CancelToken, ExecutionLease, Handler, HandlerFut, HandlerOutcome,
    Principal, RequestContext,
};
use tokio::{net::TcpListener, task::JoinSet};
#[path = "managed_fixture/history.rs"]
mod history;
use history::History;
use std::sync::atomic::Ordering::SeqCst;
use syntra_net::{media::Method, RecoveryAuthenticatorFactory};
use syntra_runtime::recovery::wire::RecoveryService;

const SCOPE: &[u8] = b"ffi-loopback";
const ECHO: &str = "/fixture.Echo/Echo";

struct TestEnrollment;
impl KeyStore for TestEnrollment {
    fn lookup(&self, c: &Context) -> Result<Secret32, Error> {
        if c.mode == Mode::Returning
            && c.carrier == Carrier::Tcp
            && c.server_key_id == 23
            && c.scope == SCOPE
            && c.epoch == 17
            && c.handle == [4; 8]
        {
            Ok(Secret32::new([3; 32])) // public test vector
        } else {
            Err(Error::Authentication)
        }
    }
}

struct Echo(Arc<MediaHandler>, Arc<History>, Arc<RecoveryService>);
struct Held<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.store(false, SeqCst);
    }
}
impl Handler for Echo {
    fn authorize(&self, p: &Principal, method: &str) -> Result<(), AuthError> {
        if p.subject == "ffi-caller" && method == ECHO
            || p.subject == "update-caller"
                && matches!(
                    method,
                    ECHO | "/fixture.Echo/Held" | "/fixture.Echo/RawWait"
                )
        {
            Ok(())
        } else {
            self.0.authorize(p, method)
        }
    }
    fn handle_with_context(
        &self,
        method: String,
        data: Vec<u8>,
        cancel: CancelToken,
        lease: ExecutionLease,
        ctx: RequestContext,
    ) -> HandlerFut {
        if method == ECHO {
            self.handle(method, data, cancel)
        } else if method == "/fixture.Echo/Held" {
            let h = &self.1;
            assert!(
                h.holding_reply.load(SeqCst)
                    && h.first.load(SeqCst) == 1
                    && h.last.load(SeqCst) == 0
            );
            h.raw_release.notify_one();
            Box::pin(async move { HandlerOutcome::Payload(data) })
        } else if method == "/fixture.Echo/RawWait" {
            let h = self.1.clone();
            Box::pin(async move {
                h.raw_release.notified().await;
                HandlerOutcome::Payload(data)
            })
        } else if data.starts_with(&[7; 16])
            && (method == Method::Put.path() || method == Method::Finalize.path())
        {
            let h = self.1.clone();
            let svc = self.2.clone();
            let put = method == Method::Put.path();
            let pos = put.then(|| u64::from_be_bytes(data[80..88].try_into().unwrap()));
            let work = self
                .0
                .handle_with_context(method, data, cancel.clone(), lease, ctx);
            Box::pin(async move {
                let outcome = work.await;
                assert!(matches!(outcome, HandlerOutcome::Payload(_)));
                match pos {
                    Some(0) => {
                        assert_eq!(h.first.fetch_add(1, SeqCst), 0, "first chunk resent");
                        h.holding_reply.store(true, SeqCst);
                        let _held = Held(&h.holding_reply);
                        h.published.store(true, SeqCst);
                        svc.publish(&Principal::new("update-caller"), b"feed", history::delta())
                            .unwrap();
                        // The real SQLite Put committed, but its reply cannot reach C.
                        cancel.cancelled().await;
                    }
                    Some(262144) => {
                        assert_eq!(h.last.fetch_add(1, SeqCst), 0);
                    }
                    None => {
                        assert_eq!(h.finalizes.fetch_add(1, SeqCst), 0);
                    }
                    _ => panic!("unexpected chunk offset"),
                }
                outcome
            })
        } else {
            self.0.handle_with_context(method, data, cancel, lease, ctx)
        }
    }
    fn handle(&self, method: String, data: Vec<u8>, _: CancelToken) -> HandlerFut {
        Box::pin(async move {
            if method == ECHO {
                HandlerOutcome::Payload(data)
            } else {
                HandlerOutcome::error(ErrorCode::Unimplemented, "unknown method")
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run via tests/build_contract.py with linked C consumer"]
async fn protected_c_consumer() {
    let (private_key, pin) = generate_server_key().unwrap();
    let security = Arc::new(ServerConfig {
        mode: Mode::Returning,
        carrier: Carrier::Tcp,
        server_key_id: 23,
        scope: SCOPE.to_vec(),
        private_key,
        store: Some(Arc::new(TestEnrollment)),
    });
    let history = Arc::new(History::default());
    let service = RecoveryService::new(history.clone(), Default::default()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exe =
        std::path::PathBuf::from(std::env::var_os("SYNTRA_MANAGED_C").expect("missing C consumer"));
    let dir = exe.parent().unwrap(); // private temporary build_contract directory
    let storage = SqliteMediaHost::open(
        dir.join("host.sqlite"),
        "ffi-test",
        Arc::new(|_, p, _, key| {
            if key.version == 1
                && (p.subject == "ffi-caller" && key.object == [1; 16]
                    || p.subject == "update-caller" && key.object == [7; 16])
            {
                Ok(())
            } else {
                Err(AuthError::denied())
            }
        }),
    )
    .unwrap();
    let launch = |stage: &str| {
        eprintln!("protected C consumer: {stage}");
        let mut child = Command::new(&exe)
            .current_dir(dir)
            .arg(listener.local_addr().unwrap().to_string())
            .arg(stage)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&pin).unwrap();
        child
    };
    let mut stages = ["partial", "resume", "smoke"].into_iter();
    let mut child = launch(stages.next().unwrap());
    let mut hosts = JoinSet::new();
    let mut count = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            if status.success() {
                if let Some(stage) = stages.next() {
                    child = launch(stage);
                    continue;
                }
            }
            break status;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("C consumer timed out");
        }
        if let Ok(Ok((stream, _))) =
            tokio::time::timeout(Duration::from_millis(10), listener.accept()).await
        {
            count += 1;
            let security = security.clone();
            let plain = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (login, notify) = (history.clone(), plain.clone());
            let factory: Arc<dyn AuthenticatorFactory> =
                Arc::new(RecoveryAuthenticatorFactory::new(
                    move |i: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                        if i.context().mode != Mode::Returning {
                            return Err(AuthError::unauthenticated());
                        }
                        Ok(Arc::new(history::Login(login.clone(), notify.clone())))
                    },
                    service.clone(),
                ));
            let handler = Arc::new(Echo(storage.handler(), history.clone(), service.clone()));
            hosts.spawn(async move {
                if let Ok(host) = tcp::accept_stream(
                    stream,
                    &security,
                    factory,
                    handler,
                    Default::default(),
                    Limits::default(),
                )
                .await
                {
                    if plain.load(SeqCst) {
                        let _ = host.host.notify(b"lane-ready".to_vec()).await;
                    }
                    while !host.is_closed() {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    host.close().await;
                }
            });
        }
    };
    assert!(status.success(), "C consumer: {status}");
    assert!(count >= 2, "expected separate protected lanes");
    assert_eq!(
        (
            history.first.load(SeqCst),
            history.last.load(SeqCst),
            history.finalizes.load(SeqCst)
        ),
        (1, 1, 1)
    );
    assert!(history.rotated.load(SeqCst) >= 2);
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(done) = hosts.join_next().await {
            done.unwrap();
        }
    })
    .await
    .unwrap();
}
