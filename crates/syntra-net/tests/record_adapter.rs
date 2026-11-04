//! An external embedding consumer: only public record I/O, with no carrier feature.
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, Mode, ServerConfig, VerifiedIdentity,
};
use syntra_net::{
    pump, AuthenticatorFactory, Error, EstablishmentBudget, Limits, RecordReader, RecordWriter,
};
use syntra_runtime::{
    AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler, HandlerOutcome,
};
use tokio::sync::mpsc;

struct Reader(mpsc::Receiver<Vec<u8>>);
struct Writer(mpsc::Sender<Vec<u8>>);
impl RecordReader for Reader {
    async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let record = self.0.recv().await.ok_or(Error::Closed)?;
        if record.len() > maximum {
            return Err(Error::Framing);
        }
        Ok(record)
    }
}
impl RecordWriter for Writer {
    async fn write_record(&mut self, record: &[u8]) -> Result<(), Error> {
        self.0
            .send(record.to_vec())
            .await
            .map_err(|_| Error::Closed)
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }
}
fn security() -> (ClientConfig, ServerConfig) {
    let (private_key, public_key) = generate_server_key().unwrap();
    let context = Context {
        mode: Mode::Bootstrap,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"embedded-record-service".to_vec(),
        handle: [0; 8],
        epoch: 0,
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public_key,
            authorization_key: None,
        },
        ServerConfig {
            mode: context.mode,
            carrier: context.carrier,
            server_key_id: context.server_key_id,
            scope: context.scope,
            private_key,
            store: None,
        },
    )
}

#[tokio::test]
async fn external_record_adapter_authenticates_and_runs_rpc_without_native_carriers() {
    let (client, server) = security();
    let (to_host, host_records) = mpsc::channel(2);
    let (to_client, client_records) = mpsc::channel(2);
    let authenticated = Arc::new(AtomicUsize::new(0));
    let count = authenticated.clone();
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
        move |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            assert_eq!(identity.context().scope, b"embedded-record-service");
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(AllowAnonymous))
        },
    );
    let (client, host) = tokio::join!(
        pump::connect_records(
            Reader(client_records),
            Writer(to_host),
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default()
        ),
        pump::accept_records(
            Reader(host_records),
            Writer(to_client),
            &server,
            factory,
            Arc::new(FnHandler(|_, payload, _| async move {
                HandlerOutcome::Payload(payload)
            })),
            ConnectionConfig::default(),
            Limits::default()
        )
    );
    let mut client = client.unwrap();
    let mut host = host.unwrap();
    assert_eq!(authenticated.load(Ordering::SeqCst), 1);
    let original = vec![37; 200_000];
    assert_eq!(
        client
            .conn
            .call("/test.Service/Echo", original.clone(), 5000)
            .await
            .unwrap(),
        original
    );
    client
        .shutdown_transport(Duration::from_secs(1))
        .await
        .unwrap();
    host.shutdown_transport(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn external_dialer_passes_its_expired_budget_without_emitting_a_record() {
    let (client, _) = security();
    let clock = syntra_runtime::elapsed::ElapsedClock::lifecycle_driven();
    let budget = EstablishmentBudget::new(clock.clone(), Duration::from_millis(1)).unwrap();
    let deadline = budget.deadline();
    clock.sleep_until(deadline).await;
    let (_peer, received) = mpsc::channel(1);
    let (sent, mut peer) = mpsc::channel(1);
    assert!(matches!(
        pump::connect_records_with_budget(
            Reader(received),
            Writer(sent),
            client,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
            budget
        )
        .await,
        Err(Error::Timeout)
    ));
    assert!(peer.recv().await.is_none());
}

struct ReturningStore;
impl syntra_core::secure_channel::KeyStore for ReturningStore {
    fn lookup(
        &self,
        context: &Context,
    ) -> Result<syntra_core::secure_channel::Secret32, syntra_core::secure_channel::Error> {
        if context.mode != Mode::Returning
            || context.carrier != Carrier::Tcp
            || context.handle != [7; 8]
            || context.epoch != 1
            || context.scope != b"embedded-record-service"
        {
            return Err(syntra_core::secure_channel::Error::Authentication);
        }
        Ok(syntra_core::secure_channel::Secret32::new([9; 32]))
    }
}

struct PolicyAuth {
    code: syntra_core::ErrorCode,
    calls: Arc<AtomicUsize>,
}
impl Authenticator for PolicyAuth {
    fn authenticate(&self, _: &[u8]) -> Result<syntra_runtime::Principal, AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(AuthError {
            code: self.code,
            message: "private-policy-diagnostic".into(),
        })
    }
}

struct PolicyFactory {
    code: syntra_core::ErrorCode,
    reject_in_prepare: bool,
    preparations: Arc<AtomicUsize>,
    authentications: Arc<AtomicUsize>,
}
impl AuthenticatorFactory for PolicyFactory {
    fn create(&self, _: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(Arc::new(PolicyAuth {
            code: self.code,
            calls: self.authentications.clone(),
        }))
    }
    fn prepare<'a>(
        &'a self,
        identity: &'a VerifiedIdentity,
    ) -> futures_util::future::BoxFuture<'a, Result<Arc<dyn Authenticator>, AuthError>> {
        Box::pin(async move {
            self.preparations.fetch_add(1, Ordering::SeqCst);
            if self.reject_in_prepare {
                return Err(AuthError {
                    code: self.code,
                    message: "private-policy-diagnostic".into(),
                });
            }
            self.create(identity)
        })
    }
}

struct CountedWriter {
    inner: Writer,
    records: Arc<AtomicUsize>,
}
impl RecordWriter for CountedWriter {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.inner.write_record(bytes).await?;
        self.records.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        self.inner.shutdown().await
    }
}

#[tokio::test]
async fn local_application_auth_codes_are_distinct_while_remote_failure_is_only_close() {
    use syntra_core::ErrorCode;
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for code in [ErrorCode::Unauthenticated, ErrorCode::PermissionDenied] {
            for reject_in_prepare in [true, false] {
                let (mut client, mut server) = security();
                client.context.mode = mode;
                server.mode = mode;
                if mode == Mode::Returning {
                    client.context.handle = [7; 8];
                    client.context.epoch = 1;
                    client.authorization_key =
                        Some(syntra_core::secure_channel::Secret32::new([9; 32]));
                    server.store = Some(Arc::new(ReturningStore));
                }
                let (to_host, host_records) = mpsc::channel(2);
                let (to_client, client_records) = mpsc::channel(2);
                let preparations = Arc::new(AtomicUsize::new(0));
                let authentications = Arc::new(AtomicUsize::new(0));
                let dispatched = Arc::new(AtomicUsize::new(0));
                let records = Arc::new(AtomicUsize::new(0));
                let effects = dispatched.clone();
                let (remote, local) = tokio::time::timeout(Duration::from_secs(5), async {
                    tokio::join!(
                        pump::connect_records(
                            Reader(client_records),
                            Writer(to_host),
                            client,
                            b"private-application-credential".to_vec(),
                            ConnectionConfig::default(),
                            Limits::default(),
                        ),
                        pump::accept_records(
                            Reader(host_records),
                            CountedWriter {
                                inner: Writer(to_client),
                                records: records.clone()
                            },
                            &server,
                            Arc::new(PolicyFactory {
                                code,
                                reject_in_prepare,
                                preparations: preparations.clone(),
                                authentications: authentications.clone()
                            }),
                            Arc::new(FnHandler(move |_, payload, _| {
                                effects.fetch_add(1, Ordering::SeqCst);
                                async move { HandlerOutcome::Payload(payload) }
                            })),
                            ConnectionConfig::default(),
                            Limits::default(),
                        )
                    )
                })
                .await
                .expect("policy failure closes both endpoints promptly");
                let local = match local {
                    Err(error) => error,
                    Ok(_) => panic!("policy rejection accepted"),
                };
                assert!(matches!(local, Error::LocalProtocol(value) if value == code));
                assert!(matches!(remote, Err(Error::Closed)));
                let diagnostic = format!("{local:?} {local}");
                assert!(!diagnostic.contains("private-policy-diagnostic"));
                assert!(!diagnostic.contains("private-application-credential"));
                assert_eq!(preparations.load(Ordering::SeqCst), 1);
                assert_eq!(
                    authentications.load(Ordering::SeqCst),
                    usize::from(!reject_in_prepare)
                );
                assert_eq!(dispatched.load(Ordering::SeqCst), 0);
                assert_eq!(
                    records.load(Ordering::SeqCst),
                    1,
                    "only Noise M2, no ready or error frame"
                );
            }
        }
    }
}
