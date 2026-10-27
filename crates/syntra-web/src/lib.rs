//! `syntra-web`: browser client for Syntra v1.
//!
//! JS-facing API (via `wasm-bindgen`; every `async fn` becomes a `Promise`):
//! [`connect`] / [`call`] / [`poll_notify`] / [`close`], with clients held
//! in a registry by numeric id so calls, notifications, and close work
//! across invocations (not a one-shot stub).
//!
//! - On `wasm32-unknown-unknown`, `connect` dials `url` over the browser
//!   `WebSocket` (`syntra-ws::wasm`: binary-only, `syntra.v1`
//!   subprotocol, credential only in `ClientHello.credential`).
//! - On native targets `connect` wires an in-memory loopback pair with
//!   neutral echo/get-put fixtures. That path exists for host-side tests
//!   and development only; browsers always use the WebSocket path.
//!
//! Notifications: [`poll_notify`] resolves with the next opaque payload,
//! `undefined` on timeout, and rejects when the connection is closed.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc, Mutex, OnceLock,
};

#[cfg(not(target_arch = "wasm32"))]
use syntra_runtime::{AllowAnonymous, CancelToken, FnHandler, HandlerOutcome};
use syntra_runtime::{ConnectionConfig, Host, Initiator};
use wasm_bindgen::prelude::*;

fn err(value: impl ToString) -> JsValue {
    JsValue::from_str(&value.to_string())
}

struct WebClient {
    initiator: Initiator,
    shutdown: Arc<AtomicBool>,
    /// Native loopback only: keeps the host side (and its pumps) alive.
    _host: Option<Arc<Host>>,
}

fn clients() -> &'static Mutex<HashMap<u32, WebClient>> {
    static REG: OnceLock<Mutex<HashMap<u32, WebClient>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_id() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Native test/dev loopback handler (neutral fixtures, no app model).
/// Browsers never use this path (see `transport_connect`).
#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(target_arch = "wasm32")]
async fn transport_connect(
    url: String,
    credential: Vec<u8>,
    cfg: ConnectionConfig,
) -> Result<(Initiator, Option<Arc<Host>>), String> {
    let ws_cfg = syntra_ws::WsConfig::secure(url);
    let handle = syntra_ws::connect(ws_cfg, credential, cfg)
        .await
        .map_err(|e| e.to_string())?;
    let (initiator, shutdown) = handle.into_parts();
    let _ = shutdown;
    Ok((initiator, None))
}

#[cfg(not(target_arch = "wasm32"))]
async fn transport_connect(
    _url: String,
    credential: Vec<u8>,
    cfg: ConnectionConfig,
) -> Result<(Initiator, Option<Arc<Host>>), String> {
    // Native test/dev path: in-memory loopback with neutral fixtures.
    // Browsers never take this path (see the wasm32 branch above).
    let _ = _url;
    let (initiator, host) =
        syntra_runtime::loopback_pair(Arc::new(AllowAnonymous), fixture_handler(), cfg);
    initiator
        .handshake(credential)
        .await
        .map_err(|e| e.to_string())?;
    Ok((initiator, Some(host)))
}

/// Open a client: connect, run the Syntra handshake, and register the
/// connection. Resolves with the numeric client id for [`call`],
/// [`poll_notify`], and [`close`].
///
/// `credential` is presented only as `ClientHello.credential`, never in
/// the URL.
#[wasm_bindgen]
pub async fn connect(url: String, credential: Vec<u8>) -> Result<u32, JsValue> {
    let cfg = ConnectionConfig::default();
    let (initiator, host) = transport_connect(url, credential, cfg).await.map_err(err)?;
    let id = next_id();
    clients().lock().unwrap().insert(
        id,
        WebClient {
            initiator,
            shutdown: Arc::new(AtomicBool::new(false)),
            _host: host,
        },
    );
    Ok(id)
}

fn with_client<T>(id: u32, f: impl FnOnce(&WebClient) -> T) -> Result<T, JsValue> {
    let reg = clients().lock().unwrap();
    match reg.get(&id) {
        Some(c) => Ok(f(c)),
        None => Err(err("unknown client id")),
    }
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
    let initiator = with_client(client_id, |c| c.initiator.clone())?;
    poll_notification(&initiator, timeout_ms).await.map_err(err)
}

// Keep the result typed until the JS boundary (also testable natively,
// where constructing a JsValue error is unsupported by wasm-bindgen).
async fn poll_notification(
    initiator: &Initiator,
    timeout_ms: u32,
) -> Result<Option<Vec<u8>>, syntra_core::SyntraError> {
    // Executor-agnostic race: runtime sleep is JS timers on wasm.
    tokio::select! {
        biased;
        n = initiator.next_notification() => match n {
            Some(payload) => Ok(Some(payload)),
            None => Err(syntra_core::SyntraError::Closed("connection closed and notifications drained".into())),
        },
        _ = syntra_runtime::sleep_for(std::time::Duration::from_millis(timeout_ms as u64)) => Ok(None),
    }
}

/// Graceful close + registry release. Resolves false for unknown ids.
#[wasm_bindgen]
pub async fn close(client_id: u32) -> bool {
    let client = clients().lock().unwrap().remove(&client_id);
    match client {
        Some(c) => {
            c.shutdown.store(true, Ordering::Relaxed);
            c.initiator.close().await;
            true
        }
        None => false,
    }
}

/// Number of registered clients (observability for tests/embeds).
#[wasm_bindgen]
pub fn client_count() -> u32 {
    clients().lock().unwrap().len() as u32
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

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
            poll_notification(&initiator, 0).await.unwrap(),
            Some(b"admitted".to_vec())
        );
        assert!(matches!(
            poll_notification(&initiator, 0).await,
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
