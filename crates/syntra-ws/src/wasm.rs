//! Browser/WASM adapter (wasm32 only).
//!
//! Uses `ws_stream_wasm` (browser `WebSocket`) with the same
//! one-binary-message-one-`Frame` rule as native. No `Authorization`
//! header is ever set: browsers forbid arbitrary WS headers, and
//! authentication uses the approved Syntra handshake
//! (`ClientHello.credential` -> `ServerReady`), never HTTP-layer
//! credentials.
//!
//! Mapping: binary-only (opcode 0x2); text is
//! rejected; empty binary is rejected (`INVALID_ARGUMENT`); assembled
//! messages exceeding 1 MiB are rejected AFTER browser reassembly; control handling stays in the
//! browser stack and never reaches the Syntra core; Ping/Pong liveness
//! is the browser's (documented), with handshake/RPC timers enforced by
//! the runtime on top.
//!
//! Browser limitations: the WebSocket API exposes only assembled messages
//! and does not permit application close codes 1003/1009 (only 1000 or
//! 3000..=4999). On text/empty/oversize input we discard without ingesting
//! and initiate a browser-managed Close with no supplied code. We do not
//! promise a 1009 wire close or bounded receive assembly here. Additionally,
//! ws_stream_wasm queues complete messages internally without a configurable
//! byte cap. This adapter is NOT full SNTR-WS-035/WSS-030 resource-bound
//! conformance; use native transport for that claim. TLS policy and network
//! buffering are controlled by the browser, not by this adapter.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use futures_util::{SinkExt, StreamExt};
use syntra_runtime::{ConnectionConfig, Initiator};

use crate::config::WsConfig;
use crate::error::TransportError;
use crate::{ENDPOINT_PATH, SUBPROTOCOL};

/// Live browser transport handle.
pub struct WsHandle {
    pub conn: Initiator,
    pub connection_id: String,
    pub version: u32,
    shutdown: Arc<AtomicBool>,
}

impl WsHandle {
    /// Graceful close: stop new RPCs, then release the socket.
    /// The connection's close broadcast wakes both pumps, including while
    /// idle; the writer closes the browser sink before releasing it.
    pub async fn close(self) {
        self.conn.close().await;
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub fn connection(&self) -> &Initiator {
        &self.conn
    }

    /// Split into the protocol engine and its shutdown flag for embeds
    /// (e.g. client registries) that manage lifetime by id.
    /// Call `Initiator::close()` to wake idle pumps; setting the flag alone
    /// does not send a wakeup. Both pumps share the initiator's close signal.
    pub fn into_parts(self) -> (Initiator, Arc<AtomicBool>) {
        (self.conn, self.shutdown)
    }
}

/// Connect over the browser `WebSocket`, run the Syntra handshake, and
/// spawn `wasm-bindgen-futures` pump tasks.
///
/// `cfg.url` must use `wss://` (or an explicitly allowed `ws://` dev
/// URL); the path must be `/syntra/v1/ws`. The subprotocol `syntra.v1`
/// is offered. `credential` travels only in `ClientHello.credential`.
pub async fn connect(
    cfg: WsConfig,
    credential: Vec<u8>,
    conn_cfg: ConnectionConfig,
) -> Result<WsHandle, TransportError> {
    let endpoint = crate::config::Endpoint::parse(&cfg.url, cfg.allow_insecure)?;
    if !endpoint.is_secure {
        tracing::warn!("insecure WS enabled: restricted-development only, never public traffic");
    }
    let _ = ENDPOINT_PATH;

    // Browser WebSocket: protocols are the ONLY handshake parameter we
    // set. No Authorization/Cookie/credential headers exist here by
    // construction (the platform forbids them), which enforces the
    // credential-placement rule at the API level.
    let (meta, ws_stream) = crate::config::connect_with_timeout(
        async {
            ws_stream_wasm::WsMeta::connect(&cfg.url, vec![SUBPROTOCOL])
                .await
                .map_err(|e| TransportError::Connect(format!("ws connect failed: {e}")))
        },
        cfg.connect_timeout,
    )
    .await?;

    // The server must have selected our subprotocol (WS section 1C).
    // ws_stream_wasm surfaces the URL/protocol via WsMeta.
    if meta.protocol() != SUBPROTOCOL {
        return Err(TransportError::Subprotocol(format!(
            "expected {SUBPROTOCOL}, got '{}'",
            meta.protocol()
        )));
    }

    let (conn, mut wrx) = Initiator::new(conn_cfg);
    let shutdown = Arc::new(AtomicBool::new(false));

    let (mut sink, mut stream) = ws_stream.split();

    // Write pump: one Vec<u8> = one binary message.
    let write_conn = conn.clone();
    let write_shutdown = shutdown.clone();
    let mut write_close = conn.subscribe_close();
    let close_grace = cfg.close_grace;
    wasm_bindgen_futures::spawn_local(async move {
        loop {
            if write_conn.is_closed() || write_shutdown.load(Ordering::Relaxed) {
                break;
            }
            let next = tokio::select! {
                biased;
                _ = write_close.changed() => break,
                next = wrx.recv() => next,
            };
            match next {
                Some(bytes) => {
                    if bytes.len() > syntra_core::MAX_FRAME_BYTES {
                        tracing::warn!("outgoing frame exceeds bound; dropping");
                        continue;
                    }
                    if sink
                        .send(ws_stream_wasm::WsMessage::Binary(bytes))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                None => break,
            }
        }
        write_shutdown.store(true, Ordering::Relaxed);
        // Closing the sink initiates WebSocket.close; do not retain the
        // split socket forever if the browser never delivers its close event.
        tokio::select! {
            biased;
            _ = sink.close() => {},
            _ = syntra_runtime::sleep_for(close_grace) => {},
        }
        drop(sink);
        write_conn.on_transport_lost().await;
    });

    // Read pump: binary -> ingest; text/empty/oversize rejected.
    // (Pong/ping/close stay inside the browser stack.)
    let read_conn = conn.clone();
    let read_shutdown = shutdown.clone();
    let mut read_close = conn.subscribe_close();
    wasm_bindgen_futures::spawn_local(async move {
        // `WsStream` yields `WsMessage` directly (errors surface as
        // `Close` events on the socket, which end the stream).
        loop {
            if read_conn.is_closed() || read_shutdown.load(Ordering::Relaxed) {
                break;
            }
            let msg = tokio::select! {
                biased;
                _ = read_close.changed() => break,
                msg = stream.next() => match msg {
                    Some(msg) => msg,
                    None => break,
                },
            };
            match msg {
                ws_stream_wasm::WsMessage::Binary(data) => {
                    if data.is_empty() {
                        tracing::warn!("empty binary message rejected");
                        break;
                    }
                    if data.len() > syntra_core::MAX_FRAME_BYTES {
                        tracing::warn!("assembled message exceeds bound");
                        break;
                    }
                    read_conn.ingest(&data).await;
                    if read_conn.is_closed() {
                        break;
                    }
                }
                ws_stream_wasm::WsMessage::Text(_) => {
                    tracing::warn!("text message rejected (binary required)");
                    break;
                }
            }
        }
        read_shutdown.store(true, Ordering::Relaxed);
        read_conn.on_transport_lost().await;
    });

    // Syntra handshake over the established socket (WS section 1F).
    match conn.handshake(credential).await {
        Ok(connection_id) => {
            let version = conn.negotiated_version().await.unwrap_or(1);
            Ok(WsHandle {
                conn,
                connection_id,
                version,
                shutdown,
            })
        }
        Err(e) => {
            shutdown.store(true, Ordering::Relaxed);
            conn.on_transport_lost().await;
            Err(TransportError::Connect(format!(
                "syntra handshake failed: {e}"
            )))
        }
    }
}
