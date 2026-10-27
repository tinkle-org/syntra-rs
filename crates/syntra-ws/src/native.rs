//! Native WSS/WS adapter (`tokio-tungstenite` + `rustls`).
//!
//! Security properties (WSS section 1M, transport-security):
//! - TLS 1.3 only via a pinned `rustls` client config; <1.3 fails closed.
//! - Full chain + hostname + expiry validation before any Syntra byte.
//! - No `wss://` -> `ws://` downgrade retry (FORBIDDEN).
//! - SNI sent consistently with the intended hostname.
//! - No credentials in Upgrade target/headers/query; the only Syntra
//!   credential carrier is `ClientHello.credential` after 101.
//! - `Origin` is never authentication (WS section 1H).
//!
//! Framing: one binary message = one `Frame` (no length prefix).
//! Text (0x1) -> close 1003. Empty binary -> `INVALID_ARGUMENT` + close.
//! Assembled message > MAX_FRAME_BYTES is rejected during assembly
//! (tungstenite size cap) and re-checked on receipt -> close 1009.
//! Control frames (Ping/Pong/Close) never reach the Syntra core:
//! Ping is answered, Pong feeds liveness, Close tears down.
//!
//! Backpressure/liveness (WS sections 1I/1L): outbound queue bounded by
//! `writer_capacity`; a write stalled past `write_grace` closes a slow
//! receiver (typically 1001); Ping/Pong liveness closes silent peers
//! (typically 1001). In-flight RPCs get `UNAVAILABLE` on teardown.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame, Message};

use syntra_core::{ErrorCode, SyntraError};
use syntra_runtime::{ConnectionConfig, Initiator};

use crate::config::{Endpoint, WsConfig};
use crate::error::TransportError;
use crate::{ENDPOINT_PATH, SUBPROTOCOL};

/// Live transport handle: protocol engine + shutdown.
pub struct WsHandle {
    /// Generic Syntra initiator (handshake, RPCs, notifications).
    pub conn: Initiator,
    /// Server's `connection_id` from `ServerReady` (diagnostic only,
    /// never an authenticator or resume token).
    pub connection_id: String,
    /// Selected Syntra version (`Frame.version` post-handshake).
    pub version: u32,
    shutdown_tx: Option<mpsc::Sender<CloseCode>>,
    closed: Arc<AtomicBool>,
    tasks: Option<PumpTasks>,
    shutdown_grace: Duration,
}

// Task ownership also covers cancellation of connect while handshaking.
struct PumpTasks(Vec<tokio::task::JoinHandle<()>>);

impl PumpTasks {
    async fn join(&mut self, grace: Duration) {
        for task in &mut self.0 {
            if tokio::time::timeout(grace, &mut *task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

impl Drop for PumpTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

enum ReadExit {
    Close(CloseCode),
    FlushRemoteClose,
    Lost,
}

impl WsHandle {
    /// Graceful close: stop new RPCs, allow close grace, WS Close 1000,
    /// then teardown (WSS section 1J / WS section 1J).
    pub async fn close(mut self) {
        self.conn.close().await;
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(CloseCode::Normal).await;
        }
        if let Some(mut tasks) = self.tasks.take() {
            tasks.join(self.shutdown_grace).await;
        }
        self.closed.store(true, Ordering::Relaxed);
    }

    pub fn connection(&self) -> &Initiator {
        &self.conn
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

impl Drop for WsHandle {
    fn drop(&mut self) {
        // A dropped handle must not leave cloned Initiators active after
        // their pumps have disappeared. This is one bounded teardown per
        // connection, never per-message work; it owns and joins the pumps.
        if let Some(mut tasks) = self.tasks.take() {
            self.closed.store(true, Ordering::Relaxed);
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.try_send(CloseCode::Normal);
            }
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let conn = self.conn.clone();
                let grace = self.shutdown_grace;
                runtime.spawn(async move {
                    conn.on_transport_lost().await;
                    tasks.join(grace).await;
                });
            }
            // If the executor is already gone, PumpTasks::drop aborts.
        }
    }
}

/// Map a Syntra condition to the WS close code to send (WS section 1J
/// table, normative). Codes 1005/1006/1015 are NEVER sent (local-only).
pub fn close_code_for_syntra(code: ErrorCode) -> CloseCode {
    match code {
        ErrorCode::Unauthenticated | ErrorCode::PermissionDenied => CloseCode::Policy,
        ErrorCode::Unimplemented
        | ErrorCode::FailedPrecondition
        | ErrorCode::InvalidArgument
        | ErrorCode::OutOfRange
        | ErrorCode::Aborted
        | ErrorCode::DataLoss => CloseCode::Protocol,
        ErrorCode::ResourceExhausted => CloseCode::Size,
        ErrorCode::DeadlineExceeded | ErrorCode::Unavailable | ErrorCode::Cancelled => {
            CloseCode::Away
        }
        ErrorCode::Internal
        | ErrorCode::Unknown
        | ErrorCode::Unspecified
        | ErrorCode::NotFound
        | ErrorCode::AlreadyExists => CloseCode::Error,
    }
}

/// Build the TLS-1.3-only connector (WSS section 1M). Any peer offering
/// only <1.3 fails negotiation with no Syntra byte sent and no plaintext
/// fallback. No custom TLS/handshake implementation: version floor plus
/// rustls secure defaults.
#[cfg(not(target_arch = "wasm32"))]
fn tls13_connector() -> Result<tokio_tungstenite::Connector, TransportError> {
    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() {
        tracing::warn!(errors = ?loaded.errors, "some system root certificates failed to load");
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(loaded.certs);
    if roots.is_empty() {
        return Err(TransportError::Tls(
            "no trust anchors available; failing closed".to_string(),
        ));
    }
    let config = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
}

/// Connect, validate the Upgrade, run the Syntra handshake, and spawn
/// background pump tasks.
///
/// `credential` is secret bytes presented only as
/// `ClientHello.credential`. This function never logs it and the caller
/// should zeroize/drop it after the handshake where possible.
pub async fn connect(
    cfg: WsConfig,
    credential: Vec<u8>,
    conn_cfg: ConnectionConfig,
) -> Result<WsHandle, TransportError> {
    let endpoint = Endpoint::parse(&cfg.url, cfg.allow_insecure)?;
    if cfg.ping_interval.is_zero() {
        return Err(TransportError::InvalidUrl(
            "ping interval must be nonzero".into(),
        ));
    }
    if !endpoint.is_secure {
        tracing::warn!("insecure WS enabled: restricted-development only, never public traffic");
    }

    // Build the WS request with the Syntra subprotocol offered first.
    // No Authorization/Cookie/credential headers are ever set: browsers
    // forbid them and native code carries credentials only in
    // ClientHello.credential after 101.
    let host_header = cfg
        .sni_override
        .clone()
        .unwrap_or_else(|| endpoint.authority());
    let request = {
        use tokio_tungstenite::tungstenite::http::Request;
        Request::builder()
            .uri(cfg.url.as_str())
            .header("Host", host_header)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Protocol", SUBPROTOCOL)
            .body(())
            .map_err(|e| TransportError::InvalidUrl(format!("bad ws request: {e}")))?
    };

    let mut ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
    // Enforce the 1 MiB bound DURING assembly: tungstenite aborts
    // oversized messages before we allocate them.
    ws_config.max_message_size = Some(syntra_core::MAX_FRAME_BYTES);
    ws_config.max_frame_size = Some(syntra_core::MAX_FRAME_BYTES);
    let connector = if endpoint.is_secure {
        Some(tls13_connector()?)
    } else {
        None
    };
    let _ = ENDPOINT_PATH; // path validated by Endpoint::parse above.
    let connect_fut = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(ws_config),
        false,
        connector,
    );
    let (ws_stream, response) = tokio::time::timeout(cfg.connect_timeout, connect_fut)
        .await
        .map_err(|_| TransportError::Connect("ws connect timed out".to_string()))?
        .map_err(|e| map_tungstenite_error(&e))?;

    // Validate 101 + selected subprotocol (WS section 1C).
    let selected = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if selected != SUBPROTOCOL {
        return Err(TransportError::Subprotocol(format!(
            "expected {SUBPROTOCOL}, got '{selected}'"
        )));
    }

    // Engine: the runtime owns handshake/RPC correlation; pumps move bytes.
    let (conn, mut wrx) = Initiator::new(conn_cfg.clone());
    let (close_tx, mut close_rx) = mpsc::channel::<CloseCode>(4);
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Message>(16);
    // Unlike an atomic flag, this wakes an idle writer on EVERY read exit.
    // Separate from the bounded control queue, so Close cannot be starved.
    let (read_done_tx, mut read_done_rx) = oneshot::channel();
    let closed = Arc::new(AtomicBool::new(false));
    let last_pong = Arc::new(AtomicU64::new(now_millis()));

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Write pump: the ONLY writer to the socket. One runtime Vec<u8> =
    // one binary message (never length-prefixed). Control flow arrives
    // on ctrl_rx (Ping from liveness, Pong replies from the read pump)
    // and close codes on close_rx.
    //
    // Slow receiver: a write stalled past write_grace closes (1001)
    // instead of queueing unboundedly (WS section 1L).
    let write_conn = conn.clone();
    let write_closed = closed.clone();
    let write_grace = cfg.write_grace;
    let close_grace = cfg.close_grace;
    let mut tasks = PumpTasks(Vec::with_capacity(3));
    let writer_task = tokio::spawn(async move {
        let mut read_to_drain = None;
        loop {
            tokio::select! {
                biased;
                code = close_rx.recv() => {
                    let code = code.unwrap_or(CloseCode::Normal);
                    bounded_close(&mut ws_write, code, "closing", close_grace).await;
                    break;
                }
                exit = &mut read_done_rx => {
                    let action = match exit {
                        Ok((action, read)) => {
                            read_to_drain = Some(read);
                            action
                        }
                        Err(_) => ReadExit::Lost,
                    };
                    match action {
                        ReadExit::Close(code) => bounded_close(&mut ws_write, code, "inbound rejected", close_grace).await,
                        ReadExit::FlushRemoteClose => {
                            // tungstenite queues the peer's exact Close response
                            // during read; sending a new Close is not equivalent.
                            let _ = tokio::time::timeout(close_grace, ws_write.flush()).await;
                        }
                        ReadExit::Lost => {}
                    }
                    break;
                }
                // Control traffic must not starve behind a full RPC queue.
                ctrl = ctrl_rx.recv() => {
                    match ctrl {
                        Some(msg) => {
                            let send = ws_write.send(msg);
                            match tokio::time::timeout(write_grace, send).await {
                                Ok(Ok(())) => {}
                                _ => {
                                    tracing::warn!("control write stalled; closing");
                                    bounded_close(&mut ws_write, CloseCode::Away, "slow receiver", close_grace).await;
                                    break;
                                }
                            }
                        }
                        None => break,
                    }
                }
                msg = wrx.recv() => {
                    match msg {
                        Some(bytes) => {
                            if bytes.len() > syntra_core::MAX_FRAME_BYTES {
                                tracing::warn!("outgoing frame exceeds bound; dropping");
                                continue;
                            }
                            let send = ws_write.send(Message::Binary(bytes.into()));
                            match tokio::time::timeout(write_grace, send).await {
                                Ok(Ok(())) => {}
                                _ => {
                                    tracing::warn!("slow receiver; closing");
                                    bounded_close(&mut ws_write, CloseCode::Away, "slow receiver", close_grace).await;
                                    break;
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }
        write_closed.store(true, Ordering::Relaxed);
        write_conn.on_transport_lost().await;
        // Wake/join the reader logically and recover the whole socket before
        // release. Draining a bounded amount of raw transport bytes avoids
        // resetting TCP with unread oversized input before the peer can see
        // our Close. Do not ask the failed WS parser to assemble that input.
        if read_to_drain.is_none() {
            if let Ok(Ok((_, read))) = tokio::time::timeout(close_grace, &mut read_done_rx).await {
                read_to_drain = Some(read);
            }
        }
        if let Some(read) = read_to_drain {
            if let Ok(mut socket) = ws_write.reunite(read) {
                let _ = tokio::time::timeout(close_grace, async {
                    let mut buffer = [0u8; 8192];
                    let mut remaining = syntra_core::MAX_FRAME_BYTES * 2;
                    while remaining > 0 {
                        let limit = remaining.min(buffer.len());
                        match socket.get_mut().read(&mut buffer[..limit]).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => remaining -= n,
                        }
                    }
                })
                .await;
            }
        }
    });
    tasks.0.push(writer_task);

    // Liveness: Ping at ping_interval; allow a full interval plus the
    // Pong latency bound since the previous Pong before closing (1001).
    // Unsolicited Pong is accepted and ignored beyond liveness.
    let live_conn = conn.clone();
    let live_closed = closed.clone();
    let live_pong = last_pong.clone();
    let live_ctrl = ctrl_tx.clone();
    let live_close = close_tx.clone();
    let ping_interval = cfg.ping_interval;
    let pong_timeout = cfg.pong_timeout;
    let mut live_stop = conn.subscribe_close();
    let liveness_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(ping_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = live_stop.changed() => break,
                _ = interval.tick() => {}
            }
            if live_closed.load(Ordering::Relaxed) {
                break;
            }
            let silent = now_millis().saturating_sub(live_pong.load(Ordering::Relaxed));
            if u128::from(silent) > ping_interval.saturating_add(pong_timeout).as_millis() {
                tracing::warn!("liveness timeout; closing");
                // Queue Away before waking the reader: the writer prefers
                // close_rx (biased select), so this preserves 1001 instead
                // of the reader's Normal (1000) exit racing ahead.
                let _ = live_close.try_send(CloseCode::Away);
                live_conn.on_transport_lost().await;
                break;
            }
            if live_ctrl
                .try_send(Message::Ping(b"syntra-ping".to_vec().into()))
                .is_err()
            {
                let _ = live_close.try_send(CloseCode::Away);
                break;
            }
        }
    });
    tasks.0.push(liveness_task);

    // Read pump: binary -> ingest; text -> close 1003; empty -> reject;
    // oversize -> close 1009; Ping answered, Pong feeds liveness;
    // control frames never reach the core.
    let read_conn = conn.clone();
    let read_closed = closed.clone();
    let read_pong = last_pong.clone();
    let read_ctrl = ctrl_tx.clone();
    let mut read_stop = conn.subscribe_close();
    let reader_task = tokio::spawn(async move {
        let exit = loop {
            let msg = tokio::select! {
                biased;
                _ = read_stop.changed() => break ReadExit::Close(CloseCode::Normal),
                msg = ws_read.next() => match msg {
                    Some(msg) => msg,
                    None => break ReadExit::Lost,
                }
            };
            match msg {
                Ok(Message::Binary(data)) => {
                    if data.is_empty() {
                        tracing::warn!("empty binary message rejected");
                        break ReadExit::Close(CloseCode::Invalid);
                    }
                    if data.len() > syntra_core::MAX_FRAME_BYTES {
                        tracing::warn!("assembled message exceeds bound");
                        break ReadExit::Close(CloseCode::Size);
                    }
                    read_conn.ingest(&data).await;
                    if read_conn.is_closed() {
                        break ReadExit::Close(CloseCode::Protocol);
                    }
                }
                Ok(Message::Text(_)) => {
                    tracing::warn!("text message rejected (binary required)");
                    break ReadExit::Close(CloseCode::Unsupported);
                }
                Ok(Message::Ping(payload)) => {
                    // Answered at the WS layer; never reaches the core.
                    if read_ctrl.try_send(Message::Pong(payload)).is_err() {
                        break ReadExit::Close(CloseCode::Away);
                    }
                }
                Ok(Message::Pong(_)) => {
                    read_pong.store(now_millis(), Ordering::Relaxed);
                }
                Ok(Message::Close(_)) => break ReadExit::FlushRemoteClose,
                Ok(Message::Frame(_)) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "ws read error");
                    break match e {
                        tungstenite::Error::Capacity(_) => ReadExit::Close(CloseCode::Size),
                        tungstenite::Error::Protocol(_) => ReadExit::Close(CloseCode::Protocol),
                        _ => ReadExit::Lost,
                    };
                }
            }
        };
        let _ = read_done_tx.send((exit, ws_read));
        read_closed.store(true, Ordering::Relaxed);
        read_conn.on_transport_lost().await;
    });
    tasks.0.push(reader_task);

    // Syntra handshake: exactly one hello first, then await ready.
    // No Syntra byte was sent before TLS + 101 (WSS section 1F).
    // No Authorization/credential headers were sent: the only credential
    // carrier is ClientHello.credential below.
    match conn.handshake(credential).await {
        Ok(connection_id) => {
            let version = conn.negotiated_version().await.unwrap_or(1);
            Ok(WsHandle {
                conn,
                connection_id,
                version,
                shutdown_tx: Some(close_tx),
                closed,
                tasks: Some(tasks),
                shutdown_grace: cfg
                    .write_grace
                    .saturating_add(cfg.close_grace.saturating_mul(3)),
            })
        }
        Err(e) => {
            // Spec-mapped close before teardown; never downgrade/retry.
            let _ = close_tx.send(handshake_close_code(&e)).await;
            // Let the write pump flush the close, then stop the pumps.
            tasks
                .join(
                    cfg.write_grace
                        .saturating_add(cfg.close_grace.saturating_mul(3)),
                )
                .await;
            conn.on_transport_lost().await;
            Err(TransportError::Connect(format!(
                "syntra handshake failed: {e}"
            )))
        }
    }
}

fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn send_close<S>(ws: &mut S, code: CloseCode, reason: &str)
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Debug,
{
    let frame = CloseFrame {
        code,
        reason: reason.into(),
    };
    if let Err(e) = ws.send(Message::Close(Some(frame))).await {
        tracing::debug!(error = ?e, "close send failed");
    }
}

async fn bounded_close<S>(ws: &mut S, code: CloseCode, reason: &str, grace: Duration)
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Debug,
{
    let _ = tokio::time::timeout(grace, send_close(ws, code, reason)).await;
}

fn map_tungstenite_error(e: &tungstenite::Error) -> TransportError {
    use tungstenite::Error as E;
    match e {
        E::ConnectionClosed | E::AlreadyClosed => {
            TransportError::Closed("connection closed".to_string())
        }
        E::Capacity(_) => TransportError::TooBig,
        E::Protocol(p) => {
            // Subprotocol negotiation failures are Syntra handshake
            // failures (missing/wrong token), not generic protocol noise.
            use tungstenite::error::ProtocolError as P;
            match p {
                P::SecWebSocketSubProtocolError(_) => TransportError::Subprotocol(e.to_string()),
                _ => TransportError::Protocol(e.to_string()),
            }
        }
        E::Tls(_) => TransportError::Tls(e.to_string()),
        E::Io(io) => TransportError::Io(io.to_string()),
        _ => TransportError::Connect(e.to_string()),
    }
}

/// Map a handshake failure to its spec close code for adapters that
/// terminate the WS connection on handshake failure.
pub fn handshake_close_code(e: &SyntraError) -> CloseCode {
    close_code_for_syntra(e.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprotocol_and_path_constants() {
        assert_eq!(SUBPROTOCOL, "syntra.v1");
        assert_eq!(ENDPOINT_PATH, "/syntra/v1/ws");
    }

    #[test]
    fn close_code_mapping_never_reserved() {
        // WS section 1J: 1005/1006/1015 must never appear on the wire.
        // close_code_for_syntra only returns real codes; assert the
        // mapping table covers every Syntra code deterministically.
        use syntra_core::ErrorCode as C;
        let codes = [
            C::Unspecified,
            C::Cancelled,
            C::Unknown,
            C::InvalidArgument,
            C::DeadlineExceeded,
            C::NotFound,
            C::AlreadyExists,
            C::PermissionDenied,
            C::ResourceExhausted,
            C::FailedPrecondition,
            C::Aborted,
            C::OutOfRange,
            C::Unimplemented,
            C::Internal,
            C::Unavailable,
            C::DataLoss,
            C::Unauthenticated,
        ];
        for c in codes {
            let wire: u16 = close_code_for_syntra(c).into();
            assert!(
                ![1005, 1006, 1015].contains(&wire),
                "reserved code for {c:?}"
            );
        }
        // Spot-check the normative rows (fixtures VEC-WS-007).
        assert_eq!(u16::from(close_code_for_syntra(C::Unimplemented)), 1002);
        assert_eq!(
            u16::from(close_code_for_syntra(C::FailedPrecondition)),
            1002
        );
        assert_eq!(u16::from(close_code_for_syntra(C::InvalidArgument)), 1002);
        assert_eq!(u16::from(close_code_for_syntra(C::Unauthenticated)), 1008);
        assert_eq!(u16::from(close_code_for_syntra(C::PermissionDenied)), 1008);
        assert_eq!(u16::from(close_code_for_syntra(C::ResourceExhausted)), 1009);
        assert_eq!(u16::from(close_code_for_syntra(C::Unavailable)), 1001);
        assert_eq!(u16::from(close_code_for_syntra(C::Internal)), 1011);
    }

    #[test]
    fn tls13_connector_builds() {
        // Fails closed (no roots) rather than succeeding insecurely.
        let _ = tls13_connector();
    }
}
