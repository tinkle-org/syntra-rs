//! `syntra-runtime`: connection runtime over transport-agnostic bytes.
//!
//! - [`Initiator`] — client engine: handshake, RPC calls, cancellation,
//!   notifications.
//! - [`Host`] — server engine: handshake acceptance, request dispatch,
//!   cancellation, connection-bound sessions.
//! - [`SessionManager`] / [`Principal`] / [`Authenticator`] — generic
//!   auth hooks. No user, account, or chat types exist here.
//!
//! Sessions are connection-bound only (SNTR-SESS-003): the session
//! lifetime equals the connection lifetime, and resumption across
//! connections is unavailable in v1 (SNTR-SESS-006; open blocker 2 —
//! recorded, not invented).
//!
//! Open questions this crate does NOT invent bindings for (see
//! upstream [session open questions]): typed pre-`ACTIVE` error carrier (B1),
//! pre-`ACTIVE` notification conflict (B2), stale `request_id` reuse
//! (B3), payload-vs-envelope size (B8), cancel/deadline/`UNAVAILABLE`
//! races (B10). Enforced choices are documented on the items.
//!
//! [session open questions]: https://github.com/tinkle-org/syntra/blob/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/SESSION-OPEN-QUESTIONS.md

pub mod connection;
mod emission;
pub mod host;
pub mod initiator;
pub mod policy;
pub mod recovery;
pub mod reliable;
pub mod session;

pub use connection::{CancelToken, Connection, ConnectionConfig};
pub use host::{AllowAll, FnHandler, Handler, HandlerFut, HandlerOutcome, Host};
pub use initiator::Initiator;
pub use policy::{
    AdmittedRequest, AuthDecision, AuthzDecision, CompletionDisposition, CompletionToken,
    HostResult, PolicyDeadlines,
};
pub use recovery::{RecoveryAction, RecoveryInput, StreamCheckpoint, StreamRecovery};
pub use reliable::{now_ms, ReliableSessionManager, StoredOutcome};
pub use session::{
    AllowAnonymous, AuthError, Authenticator, Principal, RejectAll, Session, SessionManager,
    StaticToken,
};

/// Sleep without depending on a timer driver: native tokio timers on
/// native targets, JS `setTimeout` on wasm32. Powers deadline paths that
/// must also run in browsers.
pub async fn sleep_for(d: std::time::Duration) {
    connection::sleep(d).await;
}

/// In-memory connected pair for tests, embeds, and FFI loopback.
///
/// Wires an [`Initiator`] to a [`Host`] with bounded channels and
/// background pumps (host<->initiator), exactly like a transport adapter
/// would, minus the sockets. Returns the initiator and the shared host.
/// Remote teardown propagates like a real transport: when either side
/// closes, both pumps end and the surviving peer observes transport loss
/// (`UNAVAILABLE` to in-flight waiters, handshake waiters fail) —
/// idempotent with local close, so graceful shutdown stays clean.
pub fn loopback_pair(
    auth: std::sync::Arc<dyn Authenticator>,
    handler: std::sync::Arc<dyn Handler>,
    config: ConnectionConfig,
) -> (Initiator, std::sync::Arc<Host>) {
    let (initiator, init_rx) = Initiator::new(config.clone());
    let (host, host_rx) = Host::new(config, auth, handler);
    bridge_pair(&initiator, &host, init_rx, host_rx);
    (initiator, host)
}

fn bridge_pair(
    initiator: &Initiator,
    host: &std::sync::Arc<Host>,
    init_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    host_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> [crate::connection::TaskHandle; 2] {
    let (to_host, to_initiator) = bridge_pumps(initiator, host, init_rx, host_rx);
    [
        crate::connection::spawn_task(to_host),
        crate::connection::spawn_task(to_initiator),
    ]
}

fn bridge_pumps(
    initiator: &Initiator,
    host: &std::sync::Arc<Host>,
    mut init_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut host_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> (
    impl std::future::Future<Output = ()>,
    impl std::future::Future<Output = ()>,
) {
    // Fence each writer before draining it. A receiver close preserves
    // admitted frames (including outstanding permits), but rejects new sends
    // so the sibling drain cannot refill a queue nobody will consume.
    // Host loss must be visible before the rendezvous: its inbound drain may
    // otherwise block trying to reply to the closed initiator. Only initiator
    // loss waits for BOTH drains, preserving already-admitted terminal results.
    let teardown = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let pump_host = host.clone();
    let pump_init = initiator.clone();
    let mut init_closed_a = pump_init.subscribe_close();
    let mut host_closed_a = pump_host.subscribe_close();
    let teardown_a = teardown.clone();
    let to_host = async move {
        loop {
            if pump_host.is_closed() || pump_init.is_closed() {
                break;
            }
            tokio::select! {
                biased;
                _ = init_closed_a.changed() => break,
                _ = host_closed_a.changed() => break,
                msg = init_rx.recv() => {
                    match msg {
                        Some(bytes) => {
                            if let Some(bytes) = pump_init.prepare_outbound(bytes) {
                                pump_host.ingest(&bytes).await;
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        // Receiver-close also wakes capacity-blocked sends with an error.
        // Mark it intentional before doing so: rejected sends must not
        // close the initiator while the sibling still holds inbound frames.
        pump_init.fence_writer().await;
        init_rx.close();
        while let Some(bytes) = init_rx.recv().await {
            if let Some(bytes) = pump_init.prepare_outbound(bytes) {
                pump_host.ingest(&bytes).await;
            }
        }
        pump_host.on_transport_lost().await;
        if teardown_a.wait().await.is_leader() {
            pump_init.on_transport_lost().await;
        }
    };
    let pump_host = host.clone();
    let pump_init = initiator.clone();
    let mut init_closed_b = pump_init.subscribe_close();
    let mut host_closed_b = pump_host.subscribe_close();
    let teardown_b = teardown.clone();
    let to_initiator = async move {
        loop {
            if pump_host.is_closed() || pump_init.is_closed() {
                break;
            }
            tokio::select! {
                biased;
                _ = init_closed_b.changed() => break,
                _ = host_closed_b.changed() => break,
                msg = host_rx.recv() => {
                    match msg {
                        Some(bytes) => pump_init.ingest(&bytes).await,
                        None => break,
                    }
                }
            }
        }
        host_rx.close();
        while let Some(bytes) = host_rx.recv().await {
            pump_init.ingest(&bytes).await;
        }
        pump_host.on_transport_lost().await;
        if teardown_b.wait().await.is_leader() {
            pump_init.on_transport_lost().await;
        }
    };

    (to_host, to_initiator)
}

#[cfg(test)]
mod transport_teardown_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_echo_round_trip() {
        let auth = std::sync::Arc::new(AllowAnonymous);
        let handler =
            std::sync::Arc::new(FnHandler(
                |_m, p, _c| async move { HandlerOutcome::Payload(p) },
            ));
        let (initiator, _host) = loopback_pair(auth, handler, ConnectionConfig::default());
        let id = initiator.handshake(vec![]).await.expect("handshake");
        assert!(!id.is_empty());
        let out = initiator
            .call("/example.Echo/Echo", b"hello".to_vec(), 2000)
            .await
            .expect("echo");
        assert_eq!(out, b"hello");
    }
}
