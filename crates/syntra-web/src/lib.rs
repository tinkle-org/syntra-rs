//! `syntra-web`: protected browser client for Syntra 1.0.
//!
//! JS-facing API (via `wasm-bindgen`; every `async fn` becomes a `Promise`):
//! `connect` / [`call`] / [`poll_notify`] / [`close`], with clients held
//! in a registry by numeric id so calls, notifications, and close work
//! across invocations (not a one-shot stub).
//!
//! The default `browser-connection` feature provides the only connect API:
//! browser WSS, exact `syntra.1.0` selection, provisioned Noise pin, protected
//! establishment and encrypted ClientHello. No plaintext or loopback fallback.
//! Native connection attempts are explicitly unsupported.
//!
//! Browser I/O is a platform binding of the same Syntra encryption and message
//! layers used by native drivers, not a separate protocol or plaintext mode.
//!
//! Notifications: [`poll_notify`] resolves with the next opaque payload,
//! `undefined` on timeout, and rejects when the connection is closed.

#[cfg(target_arch = "wasm32")]
use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
use std::sync::atomic::AtomicU32;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[cfg(any(test, all(target_arch = "wasm32", feature = "browser-connection")))]
use syntra_runtime::ConnectionConfig;
use syntra_runtime::Initiator;
#[cfg(all(test, not(target_arch = "wasm32")))]
use syntra_runtime::{AllowAnonymous, CancelToken, FnHandler, HandlerOutcome};
use wasm_bindgen::prelude::*;

#[cfg(feature = "browser-connection")]
pub mod connection;
#[cfg(all(target_arch = "wasm32", feature = "browser-test-fixture"))]
mod connection_fixture;

fn err(value: impl ToString) -> JsValue {
    JsValue::from_str(&value.to_string())
}

struct WebClient {
    initiator: Initiator,
    #[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
    connection: connection::BrowserClient,
    #[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
    _admission: Admission,
    polls: Arc<AtomicUsize>,
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    // Browser handles are !Send by design. Never hold a borrow across an await.
    static CLIENTS: RefCell<HashMap<u32, WebClient>> = RefCell::new(HashMap::new());
}

fn registry<T>(f: impl FnOnce(&mut HashMap<u32, WebClient>) -> T) -> T {
    #[cfg(target_arch = "wasm32")]
    {
        CLIENTS.with_borrow_mut(f)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        static CLIENTS: std::sync::OnceLock<std::sync::Mutex<HashMap<u32, WebClient>>> =
            std::sync::OnceLock::new();
        f(&mut CLIENTS.get_or_init(Default::default).lock().unwrap())
    }
}

#[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
static ADMITTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
struct Admission;
#[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
impl Admission {
    fn acquire() -> Result<Self, JsValue> {
        ADMITTED
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < 32).then_some(n + 1)
            })
            .map_err(|_| err("client admission bound reached"))?;
        Ok(Self)
    }
}
#[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
impl Drop for Admission {
    fn drop(&mut self) {
        ADMITTED.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
fn next_id() -> Result<u32, JsValue> {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| err("client id space exhausted"))
}

/// Unit-test handler only; never reachable from the public connect API.
#[cfg(all(test, not(target_arch = "wasm32")))]
fn fixture_handler() -> Arc<dyn syntra_runtime::Handler> {
    Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, cancel: CancelToken| async move {
            let _ = cancel;
            match method.as_str() {
                // Neutral fixtures (conformance/test-vectors, no app model).
                "/example.Echo/Echo" => HandlerOutcome::Payload(payload),
                "/example.KV/Get" => {
                    HandlerOutcome::error(syntra_core::ErrorCode::NotFound, "missing")
                }
                "/example.KV/Put" => HandlerOutcome::Payload(Vec::new()),
                _ => HandlerOutcome::error(syntra_core::ErrorCode::Unimplemented, "unknown method"),
            }
        },
    ))
}

fn with_client<T>(id: u32, f: impl FnOnce(&WebClient) -> T) -> Result<T, JsValue> {
    registry(|reg| match reg.get(&id) {
        Some(c) => {
            #[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
            c.connection.check_live().map_err(err)?;
            Ok(f(c))
        }
        None => Err(err("unknown client id")),
    })
}

/// Explicit authentication mode/pin/context, consumed by connect. No endpoint
/// can teach a new pin. Returning parameters never fall back to bootstrap.
#[wasm_bindgen]
#[cfg(feature = "browser-connection")]
pub struct ConnectionOptions {
    config: syntra_core::secure_channel::ClientConfig,
}

#[wasm_bindgen]
#[cfg(feature = "browser-connection")]
impl ConnectionOptions {
    #[wasm_bindgen(constructor)]
    pub fn bootstrap(
        server_public_key: Vec<u8>,
        server_key_id: u32,
        scope: String,
    ) -> Result<ConnectionOptions, JsValue> {
        Ok(Self {
            config: syntra_core::secure_channel::ClientConfig {
                context: syntra_core::secure_channel::Context {
                    mode: syntra_core::secure_channel::Mode::Bootstrap,
                    carrier: syntra_core::secure_channel::Carrier::SecureWebSocket,
                    server_key_id,
                    scope: scope.into_bytes(),
                    handle: [0; 8],
                    epoch: 0,
                },
                server_public_key: server_public_key
                    .try_into()
                    .map_err(|_| err(connection::Error::Configuration))?,
                authorization_key: None,
            },
        })
    }

    /// AK input is copied by wasm-bindgen. The caller must clear its own JS
    /// buffer; zeroizing Rust's copy cannot erase JS/engine/internal copies.
    pub fn returning(
        mut self,
        mut authorization_key: Vec<u8>,
        handle: Vec<u8>,
        epoch: u64,
    ) -> Result<ConnectionOptions, JsValue> {
        use zeroize::Zeroize;
        let key: Result<[u8; 32], _> = authorization_key.as_slice().try_into();
        authorization_key.zeroize();
        self.config.authorization_key = Some(syntra_core::secure_channel::Secret32::new(
            key.map_err(|_| err(connection::Error::Configuration))?,
        ));
        self.config.context.mode = syntra_core::secure_channel::Mode::Returning;
        self.config.context.handle = handle
            .try_into()
            .map_err(|_| err(connection::Error::Configuration))?;
        self.config.context.epoch = epoch;
        Ok(self)
    }
}

/// Establish a pinned, protected Syntra 1.0 connection. Credentials travel only
/// in the encrypted ClientHello. Native builds reject; they never use a fixture.
#[wasm_bindgen]
#[cfg(feature = "browser-connection")]
pub async fn connect(
    url: String,
    credential: Vec<u8>,
    options: ConnectionOptions,
) -> Result<u32, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        let admission = Admission::acquire()?;
        let id = next_id()?;
        let handle = connection::connect(
            &url,
            options.config,
            credential,
            ConnectionConfig {
                writer_capacity: 16,
                notification_capacity: 32,
                ..ConnectionConfig::default()
            },
            connection::Limits::default(),
        )
        .await
        .map_err(err)?;
        registry(|clients| {
            clients.insert(
                id,
                WebClient {
                    initiator: handle.initiator.clone(),
                    connection: handle,
                    _admission: admission,
                    polls: Arc::new(AtomicUsize::new(0)),
                },
            )
        });
        Ok(id)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native fixtures must be selected explicitly outside this production API.
        let _ = (url, credential, options.config);
        Err(err(native_connection_error()))
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "browser-connection"))]
fn native_connection_error() -> connection::Error {
    connection::Error::Unsupported
}

#[wasm_bindgen]
pub fn connection_support() -> String {
    #[cfg(feature = "browser-connection")]
    {
        connection::SUPPORT.into()
    }
    #[cfg(not(feature = "browser-connection"))]
    {
        "UNSUPPORTED: browser-connection was not compiled; no connect API or plaintext fallback is provided.".into()
    }
}

/// Rust-only attachment to the existing negotiated recovery state machine.
/// A store must return durable success before Confirm, not IDB write submission.
/// No default browser store or JS durability promise is provided. Mixed generic
/// notifications require explicit demultiplexing before using this attachment.
pub fn attach_recovery<
    S: syntra_runtime::recovery::persistence::RecoveryPersistence + Send + Sync + 'static,
>(
    client_id: u32,
    principal_scope: Vec<u8>,
    store: S,
    limits: syntra_runtime::recovery::wire::RecoveryLimits,
) -> Result<syntra_runtime::recovery::wire_client::RecoveryClient<S>, JsValue> {
    let initiator = with_client(client_id, |c| c.initiator.clone())?;
    syntra_runtime::recovery::wire_client::RecoveryClient::new(
        initiator,
        principal_scope,
        store,
        limits,
    )
    .map_err(err)
}

/// Invoke `method` with opaque `payload`; resolves with the opaque
/// response payload (JS `Uint8Array`). Failures reject with the typed
/// Syntra error text.
#[wasm_bindgen]
pub async fn call(
    client_id: u32,
    method: String,
    payload: Vec<u8>,
    timeout_ms: u32,
) -> Result<Vec<u8>, JsValue> {
    let initiator = with_client(client_id, |c| c.initiator.clone())?;
    initiator
        .call(&method, payload, timeout_ms)
        .await
        .map_err(err)
}

/// Wait up to `timeout_ms` for the next host notification. Resolves
/// with the opaque payload, `undefined` (None) on timeout; rejects when
/// the connection is closed and drained.
#[wasm_bindgen]
pub async fn poll_notify(client_id: u32, timeout_ms: u32) -> Result<Option<Vec<u8>>, JsValue> {
    let (initiator, polls) = with_client(client_id, |c| (c.initiator.clone(), c.polls.clone()))?;
    polls
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            (n < 32).then_some(n + 1)
        })
        .map_err(|_| err("notification poll admission bound reached"))?;
    struct PollAdmission(Arc<AtomicUsize>);
    impl Drop for PollAdmission {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _admission = PollAdmission(polls);
    poll_notification(&initiator, timeout_ms).await.map_err(err)
}

// Keep errors typed until the JS boundary, so native unit tests need no JsValue.
async fn poll_notification(
    initiator: &Initiator,
    timeout_ms: u32,
) -> Result<Option<Vec<u8>>, syntra_core::SyntraError> {
    let clock = initiator.elapsed_clock();
    let deadline = clock.now() + std::time::Duration::from_millis(u64::from(timeout_ms));
    let next = tokio::select! {
        biased;
        _ = clock.sleep_until(deadline) => None,
        next = initiator.next_notification() => Some(next),
    };
    if !clock.is_continuous() {
        return Err(syntra_core::SyntraError::Closed(
            "elapsed continuity lost".into(),
        ));
    }
    // A selected receive has already consumed its payload; never discard it.
    if !matches!(next, Some(Some(_))) && clock.now() >= deadline {
        return Ok(None);
    }
    match next {
        Some(Some(bytes)) => Ok(Some(bytes)),
        Some(None) => Err(syntra_core::SyntraError::Closed("connection closed".into())),
        None => Ok(None),
    }
}

/// Retire a client and await bounded owner completion. Unknown ids resolve false;
/// incomplete shutdown rejects. Browser wire-close delivery remains unobservable.
#[wasm_bindgen]
pub async fn close(client_id: u32) -> Result<bool, JsValue> {
    let client = registry(|clients| clients.remove(&client_id));
    match client {
        Some(c) => {
            #[cfg(all(target_arch = "wasm32", feature = "browser-connection"))]
            c.connection.close().await.map_err(err)?;
            #[cfg(not(all(target_arch = "wasm32", feature = "browser-connection")))]
            c.initiator.close().await;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Number of registered clients (observability for tests/embeds).
#[wasm_bindgen]
pub fn client_count() -> u32 {
    registry(|clients| clients.len() as u32)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[cfg(feature = "browser-connection")]
    #[test]
    fn native_connection_is_explicitly_unsupported() {
        assert_eq!(native_connection_error(), connection::Error::Unsupported);
        assert_eq!(
            native_connection_error().code(),
            syntra_core::ErrorCode::Unimplemented
        );
    }

    #[tokio::test]
    async fn recovery_attachment_requires_explicit_negotiation() {
        use syntra_runtime::recovery::{
            persistence::MemoryRecoveryStore, wire::RecoveryLimits, wire_client::Negotiation,
        };
        let (initiator, _host) = syntra_runtime::loopback_pair(
            Arc::new(AllowAnonymous),
            fixture_handler(),
            ConnectionConfig::default(),
        );
        initiator.handshake(vec![]).await.unwrap();
        // Internal unit-test insertion only. No production native fixture API.
        const ID: u32 = 1;
        registry(|clients| {
            clients.insert(
                ID,
                WebClient {
                    initiator,
                    polls: Arc::new(AtomicUsize::new(0)),
                },
            )
        });
        let mut recovery = attach_recovery(
            ID,
            b"principal-scope".to_vec(),
            MemoryRecoveryStore::default(),
            RecoveryLimits::default(),
        )
        .unwrap();
        assert!(matches!(
            recovery.negotiate().await.unwrap(),
            Negotiation::RecoveryUnavailable
        ));
        assert!(close(ID).await.unwrap());
    }

    #[tokio::test]
    async fn open_notification_poll_times_out_without_native_fixture_connect() {
        let (initiator, _host) = syntra_runtime::loopback_pair(
            Arc::new(AllowAnonymous),
            fixture_handler(),
            ConnectionConfig::default(),
        );
        initiator.handshake(vec![]).await.unwrap();
        assert_eq!(poll_notification(&initiator, 5).await.unwrap(), None);
        initiator.close().await;
    }

    #[tokio::test]
    async fn poll_deadline_wins_already_buffered_notification() {
        let (initiator, _host) = syntra_runtime::loopback_pair(
            Arc::new(AllowAnonymous),
            fixture_handler(),
            ConnectionConfig::default(),
        );
        initiator.handshake(vec![]).await.unwrap();
        let bytes = syntra_core::encode_frame(
            &syntra_core::Frame {
                version: 1,
                request_id: 0,
                body: Some(syntra_core::proto::frame::Body::Notification(
                    syntra_core::Notification { payload: vec![1] },
                )),
            },
            syntra_core::ValidationContext::active(1),
        )
        .unwrap();
        initiator.ingest(&bytes).await;
        assert_eq!(poll_notification(&initiator, 0).await.unwrap(), None);
        assert_eq!(
            poll_notification(&initiator, 100).await.unwrap(),
            Some(vec![1])
        );
        initiator.close().await;
    }

    #[tokio::test]
    async fn poll_preserves_payload_taken_as_deadline_passes() {
        use std::time::Duration;
        use syntra_runtime::elapsed::{ElapsedClock, ElapsedSource};

        struct DequeueClock {
            armed: AtomicBool,
            samples: AtomicUsize,
        }
        impl ElapsedSource for DequeueClock {
            fn elapsed(&self) -> Option<Duration> {
                // Before dequeue: deadline creation, timer now/continuity, and
                // receiver entry. Advance at the receiver's post-dequeue check.
                let expired = self.armed.load(Ordering::Relaxed)
                    && self.samples.fetch_add(1, Ordering::Relaxed) >= 4;
                Some(Duration::from_secs(if expired { 20 } else { 0 }))
            }
        }

        for payload in [vec![1, 2, 3], vec![]] {
            let source = Arc::new(DequeueClock {
                armed: AtomicBool::new(false),
                samples: AtomicUsize::new(0),
            });
            let clock = ElapsedClock::with_source(source.clone());
            let (initiator, mut outbound) =
                Initiator::try_new_with_clock(ConnectionConfig::default(), clock.clone()).unwrap();
            let ready = syntra_core::encode_frame(
                &syntra_core::Frame {
                    version: 1,
                    request_id: 0,
                    body: Some(syntra_core::proto::frame::Body::Ready(
                        syntra_core::ServerReady {
                            connection_id: "poll-regression".into(),
                        },
                    )),
                },
                syntra_core::ValidationContext::pre_handshake(
                    syntra_core::ConnectionState::Authenticating,
                ),
            )
            .unwrap();
            let (handshake, ()) = tokio::join!(initiator.handshake(vec![]), async {
                let hello = outbound.recv().await.unwrap();
                assert!(initiator.prepare_outbound(hello).is_some());
                initiator.ingest(&ready).await;
            });
            handshake.unwrap();
            let notification = syntra_core::encode_frame(
                &syntra_core::Frame {
                    version: 1,
                    request_id: 0,
                    body: Some(syntra_core::proto::frame::Body::Notification(
                        syntra_core::Notification {
                            payload: payload.clone(),
                        },
                    )),
                },
                syntra_core::ValidationContext::active(1),
            )
            .unwrap();
            initiator.ingest(&notification).await;

            let deadline = clock.now() + Duration::from_secs(10);
            source.armed.store(true, Ordering::Relaxed);
            assert_eq!(
                poll_notification(&initiator, 10_000).await.unwrap(),
                Some(payload)
            );
            assert!(clock.now() >= deadline);
            // Exactly one payload was consumed; no duplicate remains to drain.
            initiator.close().await;
            assert_eq!(initiator.next_notification().await, None);
        }
    }

    #[tokio::test]
    async fn close_drains_admitted_notifications_before_rejecting() {
        let (initiator, _host) = syntra_runtime::loopback_pair(
            Arc::new(AllowAnonymous),
            fixture_handler(),
            ConnectionConfig::default(),
        );
        initiator.handshake(vec![]).await.unwrap();
        let notification = syntra_core::Frame {
            version: 1,
            request_id: 0,
            body: Some(syntra_core::proto::frame::Body::Notification(
                syntra_core::Notification {
                    payload: b"admitted".to_vec(),
                },
            )),
        };
        let bytes =
            syntra_core::encode_frame(&notification, syntra_core::ValidationContext::active(1))
                .unwrap();
        initiator.ingest(&bytes).await;
        initiator.close().await;
        assert_eq!(
            poll_notification(&initiator, 100).await.unwrap(),
            Some(b"admitted".to_vec())
        );
        assert!(matches!(
            poll_notification(&initiator, 100).await,
            Err(syntra_core::SyntraError::Closed(_))
        ));
    }

    #[tokio::test]
    async fn closed_notification_poll_is_not_a_timeout() {
        let (initiator, _writer) = Initiator::new(ConnectionConfig::default());
        initiator.close().await;
        assert!(matches!(
            poll_notification(&initiator, 10).await,
            Err(syntra_core::SyntraError::Closed(_))
        ));
    }

    #[tokio::test]
    async fn close_during_notification_poll_rejects_promptly() {
        let (initiator, _writer) = Initiator::new(ConnectionConfig::default());
        let (result, ()) = tokio::join!(
            tokio::time::timeout(
                std::time::Duration::from_millis(200),
                poll_notification(&initiator, 10_000)
            ),
            async {
                tokio::task::yield_now().await;
                initiator.on_transport_lost().await;
            }
        );
        assert!(matches!(
            result.expect("close must wake poll"),
            Err(syntra_core::SyntraError::Closed(_))
        ));
    }
}
