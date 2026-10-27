//! Initiator (client) engine: handshake, RPC calls, cancellation,
//! notifications over a transport-agnostic byte channel.
//!
//! A transport adapter (WS/WSS loopback, TCP, HTTP) constructs an
//! `Initiator` with a `writer` channel (one serialized `Frame` per item),
//! drives inbound bytes via [`Initiator::ingest`], and forwards
//! [`Initiator::next_notification`] to the application.
//!
//! Spec mapping:
//! - exactly one `hello` first, as the first Syntra envelope
//!   (SNTR-HS-020/040); a second `hello` is never sent;
//! - `ready` version is range-checked against the proposed range
//!   (SNTR-HS-010); mismatch fails the handshake and closes the core;
//! - handshake timeout explicitly closes the core with
//!   `DEADLINE_EXCEEDED` (SNTR-HS-002/011);
//! - pre-`ACTIVE` `result`/`cancel`/`notification`/`hello` (and stray
//!   `ready` outside the handshake window) are handshake failures
//!   (`FAILED_PRECONDITION`, `UNIMPLEMENTED` for unknown variants) with
//!   connection closure (handshake.md section 1B; open carrier B1: the
//!   typed code is surfaced locally, no zero-`request_id` `result` and
//!   no second `hello` is emitted). Pre-`ACTIVE` notification handling
//!   follows handshake.md (fail/close); the events-draft
//!   ignore-with-diagnostic default is the recorded conflict B2 —
//!   handshake.md governs here because state-machine safety dominates;
//! - per-RPC deadlines start BEFORE queue admission; local validation
//!   failures clean the pending entry; dropped futures abandon the
//!   waiter (host still owns the RPC until `cancel` or its own
//!   deadline); completion wins every race (`biased` select with the
//!   result branch first; a timer that fires first still re-checks for
//!   an arrived result before reporting expiry).

use std::time::{Duration, Instant};

use prost::Message;
use tokio::sync::oneshot::error::RecvError;
use tokio::sync::{mpsc, oneshot};

use syntra_core::{
    proto::frame::Body, validate_frame, Cancel, ClientHello, ConnectionState, ErrorCode, Frame,
    PendingOutcome, RpcRequest, StateEvent, SyntraError, ValidationContext,
};

use crate::connection::{
    sleep_until, Connection, ConnectionConfig, HandshakeDone, PendingGuard, Role, Shared,
};

/// Transport-independent Syntra initiator.
#[derive(Clone)]
pub struct Initiator {
    conn: Connection,
}

impl Initiator {
    /// Create an initiator in `CONNECTED` with the given writer. Returns
    /// the initiator plus the receiver the transport pump must drain
    /// (one serialized `Frame` per item).
    pub fn new(config: ConnectionConfig) -> (Self, mpsc::Receiver<Vec<u8>>) {
        Self::new_with_proposal(config, syntra_core::MIN_VERSION, syntra_core::MAX_VERSION)
    }

    pub fn new_with_proposal(
        config: ConnectionConfig,
        min_version: u32,
        max_version: u32,
    ) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (wtx, wrx) = mpsc::channel(config.writer_capacity);
        let (shared, notif_rx) =
            Shared::new(Role::Initiator, wtx, config, min_version, max_version);
        (
            Self {
                conn: Connection::wrap(shared, notif_rx),
            },
            wrx,
        )
    }

    /// Current state (for diagnostics; not a wire value).
    pub async fn state(&self) -> ConnectionState {
        self.conn.state().await
    }

    pub async fn negotiated_version(&self) -> Option<u32> {
        self.conn.negotiated_version().await
    }

    pub fn pending_len(&self) -> usize {
        self.conn.pending_len()
    }

    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Subscribe to the close broadcast (transport-pump use).
    pub fn subscribe_close(&self) -> tokio::sync::watch::Receiver<bool> {
        self.conn.subscribe_close()
    }

    pub(crate) async fn fence_writer(&self) {
        self.conn.fence_writer().await;
    }

    // -- Handshake -------------------------------------------------------

    /// Send `hello` and await `ready` (or a terminal handshake error).
    ///
    /// `credential` is secret bytes presented only in
    /// `ClientHello.credential`. This function never logs it and the
    /// caller should drop it after the handshake where possible.
    pub async fn handshake(&self, credential: Vec<u8>) -> Result<String, SyntraError> {
        let deadline = Instant::now() + self.conn.shared.config.handshake_timeout;
        let (min_version, max_version) = {
            let shared = &self.conn.shared;
            (shared.proposed_min, shared.proposed_max)
        };
        syntra_core::validate_hello_range(min_version, max_version)?;
        if credential.len() > syntra_core::MAX_CREDENTIAL_BYTES {
            return Err(SyntraError::ResourceExhausted(
                "credential exceeds bound".to_string(),
            ));
        }

        let hello = ClientHello {
            min_version,
            max_version,
            credential,
        };
        let frame = Frame {
            version: max_version,
            request_id: 0,
            body: Some(Body::Hello(hello)),
        };
        validate_frame(
            &frame,
            ValidationContext::pre_handshake(ConnectionState::Connected),
        )?;

        let (tx, rx) = oneshot::channel();
        {
            // Claim the handshake and install its waiter atomically. The
            // lock order is state -> handshake_tx, also used by on_ready.
            let mut state = self.conn.shared.state.write().await;
            if *state != ConnectionState::Connected || self.conn.is_closed() {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "handshake already started".to_string(),
                });
            }
            let mut waiter = self.conn.shared.handshake_tx.lock().await;
            *state = state.transition(StateEvent::HelloSent)?;
            *waiter = Some(tx);
        }

        let bytes = frame.encode_to_vec();
        let sent = tokio::select! {
            biased;
            _ = sleep_until(deadline) => Err(SyntraError::DeadlineExceeded("handshake timed out".to_string())),
            sent = self.conn.send_bytes(bytes) => sent,
        };
        if let Err(e) = sent {
            self.conn
                .fail_handshake_and_close(e.code(), "handshake send failed".to_string())
                .await;
            return Err(e);
        }

        // Await ready with the handshake deadline; expiry explicitly
        // closes the core (SNTR-HS-011).
        let res = tokio::select! {
            biased;
            res = rx => res
                .map_err(|_| SyntraError::Closed("handshake waiter dropped".to_string()))?,
            _ = sleep_until(deadline) => {
                self.conn
                    .fail_handshake_and_close(
                        ErrorCode::DeadlineExceeded,
                        "handshake timed out".to_string(),
                    )
                    .await;
                return Err(SyntraError::DeadlineExceeded(
                    "handshake timed out".to_string(),
                ));
            }
        };
        match res {
            Ok(done) => Ok(done.connection_id),
            Err(e) => Err(e),
        }
    }

    // -- Inbound ---------------------------------------------------------

    /// Ingest one transport unit (exactly one serialized `Frame`).
    /// Called by the transport adapter's read loop.
    pub async fn ingest(&self, bytes: &[u8]) {
        let ctx = self.conn.ctx().await;
        let frame = match syntra_core::decode_frame(bytes, ctx) {
            Ok(f) => f,
            Err(e) => {
                self.on_decode_error(e).await;
                return;
            }
        };
        self.dispatch(frame).await;
    }

    async fn on_decode_error(&self, e: SyntraError) {
        // Framing-layer failures before ACTIVE are terminal for the
        // connection; in ACTIVE the affected unit fails locally (the
        // connection closes only if exhausted/misbehaving per policy,
        // SNTR-ASEC-020/SNTR-REL-007).
        tracing::debug!(error = ?e, "inbound frame rejected");
        if !self.conn.state().await.is_active() {
            let (code, message) = match e {
                SyntraError::Protocol { code, message } => (code, message),
                other => (other.code(), other.to_string()),
            };
            self.conn.fail_handshake_and_close(code, message).await;
            return;
        }
        let fatal = matches!(
            e,
            SyntraError::ResourceExhausted(_) | SyntraError::Protocol { .. }
        ) && matches!(e.code(), ErrorCode::ResourceExhausted);
        if fatal {
            self.conn.close().await;
            return;
        }
        let n = self
            .conn
            .shared
            .misbehavior
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n >= 8 {
            tracing::warn!("too many malformed frames; closing");
            self.conn.close().await;
        }
    }

    async fn dispatch(&self, frame: Frame) {
        let kind = match &frame.body {
            Some(Body::Hello(_)) => "hello",
            Some(Body::Ready(_)) => "ready",
            Some(Body::Request(_)) => "request",
            Some(Body::Result(_)) => "result",
            Some(Body::Cancel(_)) => "cancel",
            Some(Body::Notification(_)) => "notification",
            None => return,
        };
        match kind {
            "ready" => self.on_ready(frame).await,
            "result" => self.on_result(frame).await,
            "notification" => self.on_notification(frame).await,
            // The initiator never expects hello/request/cancel inbound.
            // Before ACTIVE this fails the handshake (SNTR-HS-012); in
            // ACTIVE an unexpected hello is fatal, while request/cancel
            // are ignored with a diagnostic (no handler exists here).
            _ => {
                let st = self.conn.state().await;
                tracing::debug!(?kind, state = ?st, "unexpected inbound frame");
                if !st.is_active() {
                    self.conn
                        .fail_handshake_and_close(
                            ErrorCode::FailedPrecondition,
                            "unexpected message during handshake".to_string(),
                        )
                        .await;
                } else if kind == "hello" {
                    self.conn
                        .transition(StateEvent::ProtocolViolationFatal)
                        .await
                        .ok();
                    self.conn.close().await;
                }
            }
        }
    }

    async fn on_ready(&self, frame: Frame) {
        let st = self.conn.state().await;
        if st != ConnectionState::Negotiating && st != ConnectionState::Authenticating {
            // Stray ready (e.g. in ACTIVE or before hello was sent):
            // protocol violation (SNTR-HS-012).
            self.conn
                .fail_handshake_and_close(
                    ErrorCode::FailedPrecondition,
                    "unexpected ready".to_string(),
                )
                .await;
            if st.is_active() {
                let _ = self
                    .conn
                    .transition(StateEvent::ProtocolViolationFatal)
                    .await;
                self.conn.close().await;
            }
            return;
        }
        let ready = match frame.body {
            Some(Body::Ready(r)) => r,
            _ => return,
        };
        // Selected version is Frame.version AND must lie within the
        // proposed range (SNTR-HS-010 version-range check on ready).
        let (min_version, max_version) = {
            let shared = &self.conn.shared;
            (shared.proposed_min, shared.proposed_max)
        };
        if let Err(e) =
            syntra_core::handshake::check_ready_version(frame.version, min_version, max_version)
        {
            let (code, message) = match e {
                SyntraError::Handshake { code, message } => (code, message),
                SyntraError::Protocol { code, message } => (code, message),
                other => (other.code(), other.to_string()),
            };
            self.conn.fail_handshake_and_close(code, message).await;
            return;
        }
        if let Err(e) = syntra_core::validate_connection_id(&ready.connection_id) {
            let message = match e {
                SyntraError::Protocol { message, .. } => message,
                other => other.to_string(),
            };
            self.conn
                .fail_handshake_and_close(ErrorCode::InvalidArgument, message)
                .await;
            return;
        }
        let mut state = self.conn.shared.state.write().await;
        if self.conn.is_closed() {
            return;
        }
        // Re-check after all validation awaits: close may have won.
        let authenticating = if *state == ConnectionState::Negotiating {
            state.transition(StateEvent::VersionAccepted)
        } else if *state == ConnectionState::Authenticating {
            Ok(*state)
        } else {
            return;
        };
        let Ok(active) = authenticating.and_then(|s| s.transition(StateEvent::ReadyReceived))
        else {
            return;
        };
        *self.conn.shared.version.write().await = Some(frame.version);
        *state = active;
        self.conn
            .complete_handshake(HandshakeDone {
                connection_id: ready.connection_id,
            })
            .await;
    }

    async fn on_result(&self, frame: Frame) {
        let result = match frame.body {
            Some(Body::Result(r)) => r,
            _ => return,
        };
        if !self.conn.state().await.is_active() {
            // Pre-ACTIVE results are handshake failures, never RPC
            // completions (SNTR-HS-012; carrier B1: surface locally,
            // close, emit nothing).
            self.conn
                .fail_handshake_and_close(
                    ErrorCode::FailedPrecondition,
                    "result before ACTIVE".to_string(),
                )
                .await;
            return;
        }
        // Missing outcome was already rejected by validation; unknown ids
        // are ignored with a diagnostic (no error storm).
        self.conn.shared.pending.complete(frame.request_id, result);
    }

    async fn on_notification(&self, frame: Frame) {
        let notif = match frame.body {
            Some(Body::Notification(n)) => n,
            _ => return,
        };
        let state = self.conn.shared.state.read().await;
        if !state.is_active() {
            drop(state);
            // Pre-ACTIVE notifications fail the handshake per
            // handshake.md section 1B (recorded conflict B2).
            self.conn
                .fail_handshake_and_close(
                    ErrorCode::FailedPrecondition,
                    "notification before ACTIVE".to_string(),
                )
                .await;
            return;
        }
        // Notifications never complete an RPC. Bounded notification
        // queue stays non-blocking: overflow drops with loss accounting,
        // never unbounded queueing.
        let dropped_len = notif.payload.len() as u64;
        if self
            .conn
            .shared
            .notif_tx
            .try_send(notif.payload.into())
            .is_err()
        {
            // Cumulative loss accounting stays the signal; the latest
            // totals are published for every loss waiter, and the drop
            // diagnostic is throttled so a burst cannot amplify into logs.
            let (dropped, dropped_bytes) = self
                .conn
                .shared
                .record_notification_loss(dropped_len);
            if loss_warn_on_drop(dropped) {
                tracing::warn!(
                    dropped,
                    dropped_bytes,
                    "notification queue full; dropping notification"
                );
            } else {
                tracing::debug!(
                    dropped,
                    dropped_bytes,
                    "notification queue full; dropping notification"
                );
            }
        }
    }

    // -- RPC -------------------------------------------------------------

    fn budget(&self, timeout_ms: u32) -> Duration {
        let budget = if timeout_ms == 0 {
            self.conn.shared.config.default_timeout
        } else {
            Duration::from_millis(timeout_ms as u64)
        };
        budget.min(self.conn.shared.config.max_rpc_timeout)
    }

    async fn alloc_id(&self) -> Result<u64, SyntraError> {
        for _ in 0..4096 {
            let id = self.conn.shared.ids.next_candidate();
            if id != 0 && !self.conn.shared.pending.is_pending(id) {
                return Ok(id);
            }
        }
        Err(SyntraError::ResourceExhausted(
            "request-id space exhausted".to_string(),
        ))
    }

    /// Invoke a method: payload is opaque application bytes;
    /// correlation/deadline/cancel are ours.
    ///
    /// - The deadline starts BEFORE queue admission.
    /// - Validates method shape before sending (`INVALID_ARGUMENT`).
    /// - Allocates a nonzero id unique among outstanding RPCs.
    /// - Enforces bounded outstanding (`RESOURCE_EXHAUSTED`).
    /// - Sends one `request`; awaits exactly one terminal `result`.
    /// - Interleaved notifications do not complete the RPC.
    /// - Local timeout abandons the waiter but does not cancel the host
    ///   without an explicit [`Initiator::cancel`].
    /// - A result that arrived by the deadline wins over the timer.
    pub async fn call(
        &self,
        method: &str,
        payload: Vec<u8>,
        timeout_ms: u32,
    ) -> Result<Vec<u8>, SyntraError> {
        // Share admission/deadline/cleanup logic with the cancellable path.
        self.call_cancellable(method, payload, timeout_ms, &crate::CancelToken::new())
            .await
    }

    /// Cancellable RPC: same as [`Initiator::call`] but aborts early when
    /// `cancel` fires. On cancellation this sends best-effort `Cancel{}`
    /// for an admitted request, abandons the waiter, and returns
    /// `CANCELLED`. The host still ends the RPC with exactly one
    /// terminal `result` (completion wins races); the late result is
    /// ignored as unknown. (`SNTR-RPC-005/021`.)
    ///
    /// Tie-breaks (recorded, open B10): completion beats both
    /// cancellation and deadline; cancellation beats deadline.
    pub async fn call_cancellable(
        &self,
        method: &str,
        payload: Vec<u8>,
        timeout_ms: u32,
        cancel: &crate::connection::CancelToken,
    ) -> Result<Vec<u8>, SyntraError> {
        self.call_cancellable_impl(method, payload, timeout_ms, cancel, None)
            .await
            .1
    }

    /// Same as [`Initiator::call_cancellable`] but also returns the
    /// allocated `request_id` (0 when allocation never happened), so
    /// embeds can correlate explicit `cancel(id)` with the in-flight call.
    pub async fn call_cancellable_tracked(
        &self,
        method: &str,
        payload: Vec<u8>,
        timeout_ms: u32,
        cancel: &crate::connection::CancelToken,
    ) -> (u64, Result<Vec<u8>, SyntraError>) {
        let mut id = 0u64;
        let res = self
            .call_cancellable_impl(method, payload, timeout_ms, cancel, Some(&mut id))
            .await;
        (id, res.1)
    }

    async fn call_cancellable_impl(
        &self,
        method: &str,
        payload: Vec<u8>,
        timeout_ms: u32,
        cancel: &crate::connection::CancelToken,
        mut id_out: Option<&mut u64>,
    ) -> (u64, Result<Vec<u8>, SyntraError>) {
        let fail = |e: SyntraError| (0u64, Err(e));
        let deadline = Instant::now() + self.budget(timeout_ms);
        let admission = async {
            // Hold the read lock only through pending insertion, so close
            // cannot drain the table just before a late insertion.
            let state = self.conn.shared.state.read().await;
            if self.conn.is_closed() || self.conn.writer_is_fenced() {
                return Err(SyntraError::Closed("connection closed".to_string()));
            }
            if *state != ConnectionState::Active {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "RPC requires ACTIVE connection".to_string(),
                });
            }
            syntra_core::validate_method(method)?;
            let version = self
                .conn
                .negotiated_version()
                .await
                .ok_or(SyntraError::Protocol {
                    code: ErrorCode::FailedPrecondition,
                    message: "no negotiated version".to_string(),
                })?;
            let id = self.alloc_id().await?;
            if let Some(slot) = id_out.as_deref_mut() {
                *slot = id;
            }
            let rx = self.conn.shared.pending.insert(id, method.to_string())?;
            let guard = PendingGuard::new(&self.conn.shared.pending, id);
            drop(state);
            let frame = Frame {
                version,
                request_id: id,
                body: Some(Body::Request(RpcRequest {
                    method: method.to_string(),
                    payload,
                    timeout_ms,
                })),
            };
            validate_frame(&frame, ValidationContext::active(version))?;
            let bytes = frame.encode_to_vec();
            if bytes.len() > syntra_core::MAX_FRAME_BYTES {
                return Err(SyntraError::ResourceExhausted(
                    "request exceeds maximum envelope size".to_string(),
                ));
            }
            let permit = self.conn.reserve_writer().await?;
            let state = self.conn.shared.state.read().await;
            if self.conn.is_closed()
                || self.conn.writer_is_fenced()
                || *state != ConnectionState::Active
            {
                return Err(SyntraError::Closed("connection closed".to_string()));
            }
            // select! checked before polling admission. Re-check at the
            // actual enqueue point as encoding/lock acquisition may have
            // consumed the remaining budget during that poll.
            if cancel.is_cancelled() {
                return Err(SyntraError::Cancelled(format!("{method} cancelled")));
            }
            if Instant::now() >= deadline {
                return Err(SyntraError::DeadlineExceeded(format!("{method} timed out")));
            }
            permit.send(bytes);
            drop(state);
            Ok((id, rx, guard))
        };
        // Before admission there can be no successful remote completion.
        // Cancellation/expiry win over newly available capacity; dropping
        // the send future cannot enqueue the request later. No Cancel is
        // sent for work that never left the initiator.
        let admitted = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(SyntraError::Cancelled(format!("{method} cancelled"))),
            _ = sleep_until(deadline) => Err(SyntraError::DeadlineExceeded(format!("{method} timed out"))),
            admitted = admission => admitted,
        };
        let (id, mut rx, _guard) = match admitted {
            Ok(admitted) => admitted,
            Err(e) => return fail(e),
        };
        // Completion wins every race (biased, result branch first).
        enum Outcome {
            Done(Result<PendingOutcome, RecvError>),
            Cancelled,
            TimedOut,
        }
        let outcome = tokio::select! {
            biased;
            res = &mut rx => Outcome::Done(res),
            _ = cancel.cancelled() => match rx.try_recv() {
                Ok(res) => Outcome::Done(Ok(res)),
                _ => Outcome::Cancelled,
            },
            _ = sleep_until(deadline) => match rx.try_recv() {
                Ok(res) => Outcome::Done(Ok(res)),
                _ if cancel.is_cancelled() => Outcome::Cancelled,
                _ => Outcome::TimedOut,
            },
        };
        match outcome {
            Outcome::Done(res) => {
                let outcome = match res {
                    Ok(o) => o,
                    Err(_) => {
                        return (
                            id,
                            Err(SyntraError::Closed("rpc waiter dropped".to_string())),
                        )
                    }
                };
                (id, map_outcome(method, outcome))
            }
            Outcome::TimedOut => (
                id,
                Err(SyntraError::DeadlineExceeded(format!("{method} timed out"))),
            ),
            Outcome::Cancelled => {
                let _ = self.cancel(id).await;
                (
                    id,
                    Err(SyntraError::Cancelled(format!("{method} cancelled"))),
                )
            }
        }
    }

    /// Best-effort cancellation (`SNTR-RPC-005`). Advisory only; the RPC
    /// still ends with exactly one terminal `result` (success wins races).
    /// Unknown/completed ids are ignored to tolerate races.
    pub async fn cancel(&self, request_id: u64) -> Result<(), SyntraError> {
        if request_id == 0 {
            return Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "cancel requires nonzero request_id".to_string(),
            });
        }
        let version = match self.conn.negotiated_version().await {
            Some(v) => v,
            None => return Ok(()), // no ACTIVE connection; nothing to cancel
        };
        let frame = Frame {
            version,
            request_id,
            body: Some(Body::Cancel(Cancel {})),
        };
        // Send best-effort; ignore transport errors for unknown ids.
        let bytes = frame.encode_to_vec();
        let _state = self.conn.shared.state.read().await;
        if self.conn.is_closed() || self.conn.writer_is_fenced() {
            return Ok(());
        }
        let _ = self.conn.shared.writer.try_send(bytes);
        Ok(())
    }

    /// Take the next notification payload (opaque application bytes).
    /// Returns None when the connection is closed and drained.
    pub async fn next_notification(&self) -> Option<Vec<u8>> {
        self.conn.next_notification().await
    }

    /// Notification queue overflow observability for this Initiator.
    /// Returns `(dropped_count, dropped_bytes)` for notifications
    /// discarded when the bounded notification queue was full.
    /// Bounds are unchanged; the queue stays non-blocking and drops.
    pub fn notification_loss(&self) -> (u64, u64) {
        self.conn.notification_loss()
    }

    /// Take the next notification plus current loss totals
    /// `(payload, (dropped_count, dropped_bytes))`.
    ///
    /// Recovery embedding must map a loss increment to
    /// `GapDetected`/`RecoveryNeeded` through the Syntra recovery
    /// coordinator and must not treat idle `None` as caught-up:
    /// `None` without a loss increment reports an idle or closed
    /// Connection drain, never committed progress through the
    /// recovery coordinator.
    ///
    /// Wakes on a queued notification, on a loss-counter change, or on
    /// close, so a loss without further notifications still returns
    /// promptly with the updated totals. Every waiter observes the same
    /// carried totals; a waiter subscribed before the publish cannot
    /// miss it.
    pub async fn next_notification_with_loss(&self) -> (Option<Vec<u8>>, (u64, u64)) {
        let mut loss_rx = self.conn.shared.notification_loss_tx.subscribe();
        // Baseline from the subscription itself: a loss published between
        // subscribe and loop entry must not be folded into the baseline.
        let mut baseline = *loss_rx.borrow_and_update();
        let mut closed_rx = self.conn.subscribe_close();
        loop {
            tokio::select! {
                biased;
                next = self.conn.next_notification() => {
                    return (next, self.notification_loss());
                }
                res = loss_rx.changed() => {
                    if res.is_err() {
                        return (None, self.notification_loss());
                    }
                    // Mark the new version seen; the cumulative counters
                    // are the signal, the watch only carries them.
                    let cur = *loss_rx.borrow_and_update();
                    if cur != baseline {
                        baseline = cur;
                        return (None, cur);
                    }
                    // Version moved without counter movement; keep waiting.
                }
                _ = closed_rx.changed() => {
                    return (None, self.notification_loss());
                }
            }
        }
    }

    /// Graceful close from ACTIVE: stop new RPCs, drain already-queued
    /// inbound results via the pump, then teardown (SNTR-HS-006/013).
    pub async fn close(&self) {
        use syntra_core::StateEvent;
        let _ = self.conn.transition(StateEvent::GracefulClose).await;
        self.conn.close().await;
    }

    /// Report abrupt transport loss: `UNAVAILABLE` to all in-flight RPCs
    /// with unknown outcome (SNTR-REL-009), handshake waiter fails,
    /// state moves to CLOSED.
    pub async fn on_transport_lost(&self) {
        self.conn.on_transport_lost().await;
    }

    /// Test hook: inject a decoded inbound frame without bytes.
    #[cfg(test)]
    pub async fn inject_frame(&self, frame: Frame) {
        self.dispatch(frame).await;
    }
}

/// Syntra notification-loss diagnostic cadence: the first drop and every
/// 64th drop warn; the rest stay at debug so a burst cannot amplify
/// into logs. Cumulative counters remain the signal.
const NOTIFICATION_LOSS_WARN_INTERVAL: u64 = 64;

/// Whether the drop diagnostic for a cumulative `dropped` count warns.
fn loss_warn_on_drop(dropped: u64) -> bool {
    dropped == 1 || dropped % NOTIFICATION_LOSS_WARN_INTERVAL == 0
}

fn map_outcome(method: &str, outcome: PendingOutcome) -> Result<Vec<u8>, SyntraError> {
    match outcome {
        PendingOutcome::TransportLost => Err(SyntraError::Unavailable(format!(
            "{method} lost: transport closed (outcome unknown)"
        ))),
        PendingOutcome::Result(res) => match res.outcome {
            Some(syntra_core::proto::rpc_result::Outcome::Payload(b)) => Ok(b.to_vec()),
            Some(syntra_core::proto::rpc_result::Outcome::Error(e)) => {
                let (code, raw) = ErrorCode::from_i32_lossy(e.code);
                Err(SyntraError::Rpc {
                    code,
                    raw_code: raw,
                    message: e.message,
                })
            }
            None => Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "result outcome missing".to_string(),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syntra_core::proto::rpc_result::Outcome;
    use syntra_core::proto::{RpcError as ProtoError, RpcResult};

    #[tokio::test]
    async fn concurrent_handshake_does_not_replace_original_waiter() {
        let (c, mut writer) = Initiator::new(ConnectionConfig::default());
        let gate = c.conn.shared.handshake_tx.lock().await;
        let mut first = Box::pin(c.handshake(vec![]));
        let mut second = Box::pin(c.handshake(vec![]));
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());
        drop(gate);
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(second.await.is_err());
        // The first send may have queued a state read behind the second
        // handshake's exclusive claim; resume it before delivering ready.
        assert!(futures_util::poll!(&mut first).is_pending());
        c.inject_frame(ready_frame(1)).await;
        assert_eq!(first.await.unwrap(), "conn-test-1");
        assert!(writer.try_recv().is_ok());
        assert!(writer.try_recv().is_err(), "only one hello");
    }

    #[tokio::test]
    async fn handshake_send_failure_closes_connection() {
        let (c, writer) = Initiator::new(ConnectionConfig::default());
        drop(writer);
        assert!(c.handshake(vec![]).await.is_err());
        assert!(c.is_closed());
        assert_eq!(c.state().await, ConnectionState::Closed);
        assert!(*c.subscribe_close().borrow());
    }

    async fn saturated_conn() -> (Initiator, mpsc::Receiver<Vec<u8>>) {
        let (c, writer) = Initiator::new(ConnectionConfig {
            writer_capacity: 1,
            ..ConnectionConfig::default()
        });
        *c.conn.shared.state.write().await = ConnectionState::Active;
        *c.conn.shared.version.write().await = Some(1);
        c.conn.shared.writer.try_send(vec![0]).unwrap();
        (c, writer)
    }

    #[tokio::test]
    async fn both_rpc_paths_deadline_bounds_queue_admission() {
        for cancellable in [false, true] {
            let (c, mut writer) = saturated_conn().await;
            let token = crate::CancelToken::new();
            let result = tokio::time::timeout(Duration::from_secs(1), async {
                if cancellable {
                    c.call_cancellable("/example.Echo/Echo", vec![], 10, &token)
                        .await
                } else {
                    c.call("/example.Echo/Echo", vec![], 10).await
                }
            })
            .await
            .expect("queueing must respect the RPC deadline");
            assert!(matches!(result, Err(SyntraError::DeadlineExceeded(_))));
            assert_eq!(c.pending_len(), 0);
            assert_eq!(writer.try_recv().unwrap(), vec![0]);
            assert!(
                writer.try_recv().is_err(),
                "expired request must not be queued later"
            );
        }
    }

    #[tokio::test]
    async fn cancellation_during_queue_admission_never_sends_request_or_cancel() {
        let (c, mut writer) = saturated_conn().await;
        let token = crate::CancelToken::new();
        let mut call = Box::pin(c.call_cancellable("/example.Echo/Echo", vec![], 5000, &token));
        assert!(futures_util::poll!(&mut call).is_pending());
        token.cancel();
        let result = tokio::time::timeout(Duration::from_secs(1), call)
            .await
            .expect("cancel must interrupt queue admission");
        assert!(matches!(result, Err(SyntraError::Cancelled(_))));
        assert_eq!(c.pending_len(), 0);
        assert_eq!(writer.try_recv().unwrap(), vec![0]);
        assert!(writer.try_recv().is_err());
    }

    #[tokio::test]
    async fn pre_cancelled_call_does_not_allocate_or_send() {
        let (c, mut writer) = test_conn().await;
        let token = crate::CancelToken::new();
        token.cancel();
        let (id, result) = c
            .call_cancellable_tracked("/example.Echo/Echo", vec![], 1000, &token)
            .await;
        assert_eq!(id, 0);
        assert!(matches!(result, Err(SyntraError::Cancelled(_))));
        assert!(writer.try_recv().is_err());
        assert_eq!(c.pending_len(), 0);
    }

    #[tokio::test]
    async fn expired_admission_loses_to_new_capacity_in_both_rpc_paths() {
        for cancellable in [false, true] {
            let (c, mut writer) = saturated_conn().await;
            let token = crate::CancelToken::new();
            let mut call = Box::pin(async {
                if cancellable {
                    c.call_cancellable("/example.Echo/Echo", vec![], 10, &token)
                        .await
                } else {
                    c.call("/example.Echo/Echo", vec![], 10).await
                }
            });
            assert!(futures_util::poll!(&mut call).is_pending());
            tokio::time::sleep(Duration::from_millis(20)).await;
            writer.try_recv().unwrap();
            assert!(matches!(call.await, Err(SyntraError::DeadlineExceeded(_))));
            assert!(writer.try_recv().is_err());
            assert_eq!(c.pending_len(), 0);
        }
    }

    #[tokio::test]
    async fn close_and_dropped_futures_clean_queued_calls() {
        for cancellable in [false, true] {
            let (c, _writer) = saturated_conn().await;
            let token = crate::CancelToken::new();
            let mut call = Box::pin(async {
                if cancellable {
                    c.call_cancellable("/example.Echo/Echo", vec![], 5000, &token)
                        .await
                } else {
                    c.call("/example.Echo/Echo", vec![], 5000).await
                }
            });
            assert!(futures_util::poll!(&mut call).is_pending());
            assert_eq!(c.pending_len(), 1);
            drop(call);
            assert_eq!(c.pending_len(), 0);
            let mut call = Box::pin(c.call("/example.Echo/Echo", vec![], 5000));
            assert!(futures_util::poll!(&mut call).is_pending());
            c.close().await;
            assert!(tokio::time::timeout(Duration::from_secs(1), call)
                .await
                .unwrap()
                .is_err());
            assert_eq!(c.pending_len(), 0);
        }
    }

    #[tokio::test]
    async fn queued_handshake_is_bounded_by_its_deadline() {
        let (c, mut writer) = Initiator::new(ConnectionConfig {
            writer_capacity: 1,
            handshake_timeout: Duration::from_millis(10),
            ..ConnectionConfig::default()
        });
        c.conn.shared.writer.try_send(vec![0]).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), c.handshake(vec![]))
            .await
            .unwrap();
        assert!(matches!(result, Err(SyntraError::DeadlineExceeded(_))));
        assert!(c.is_closed());
        assert_eq!(writer.try_recv().unwrap(), vec![0]);
        assert!(writer.try_recv().is_err());
    }

    async fn test_conn() -> (Initiator, mpsc::Receiver<Vec<u8>>) {
        let (c, wrx) = Initiator::new(ConnectionConfig::default());
        // Force ACTIVE for RPC tests.
        *c.conn.shared.state.write().await = ConnectionState::Active;
        *c.conn.shared.version.write().await = Some(1);
        (c, wrx)
    }

    fn ready_frame(version: u32) -> Frame {
        Frame {
            version,
            request_id: 0,
            body: Some(Body::Ready(syntra_core::proto::ServerReady {
                connection_id: "conn-test-1".to_string(),
            })),
        }
    }

    #[tokio::test]
    async fn out_of_order_results_correlate_by_id() {
        let (c, mut wrx) = test_conn().await;
        let c_call1 = c.clone();
        let c_call2 = c.clone();
        let h1 = tokio::spawn(async move {
            c_call1
                .call("/example.Echo/Echo", b"A".to_vec(), 5000)
                .await
        });
        let h2 = tokio::spawn(async move {
            c_call2
                .call("/example.Echo/Echo", b"B".to_vec(), 5000)
                .await
        });
        // Collect the two request ids.
        let b1 = wrx.recv().await.unwrap();
        let b2 = wrx.recv().await.unwrap();
        let f1 = Frame::decode(&*b1).unwrap();
        let f2 = Frame::decode(&*b2).unwrap();
        assert_ne!(f1.request_id, f2.request_id);
        // Complete second first (out-of-order legal; FIFO must not be assumed).
        c.inject_frame(Frame {
            version: 1,
            request_id: f2.request_id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(b"B".to_vec())),
            })),
        })
        .await;
        c.inject_frame(Frame {
            version: 1,
            request_id: f1.request_id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(b"A".to_vec())),
            })),
        })
        .await;
        assert_eq!(h1.await.unwrap().unwrap(), b"A");
        assert_eq!(h2.await.unwrap().unwrap(), b"B");
    }

    #[tokio::test]
    async fn unknown_id_result_ignored() {
        let (c, _wrx) = test_conn().await;
        c.inject_frame(Frame {
            version: 1,
            request_id: 9999,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(vec![].into())),
            })),
        })
        .await;
        // No panic, no error storm.
        assert_eq!(c.conn.shared.pending.len(), 0);
    }

    #[tokio::test]
    async fn transport_loss_maps_to_unavailable() {
        let (c, mut wrx) = test_conn().await;
        let h = tokio::spawn({
            let c = c.clone();
            async move { c.call("/example.Echo/Echo", b"x".to_vec(), 5000).await }
        });
        let _ = wrx.recv().await.unwrap();
        c.on_transport_lost().await;
        let err = h.await.unwrap().unwrap_err();
        assert!(err.is_unknown_outcome());
        assert!(matches!(err, SyntraError::Unavailable(_)));
    }

    #[tokio::test]
    async fn error_code_mapped() {
        let (c, mut wrx) = test_conn().await;
        let h = tokio::spawn({
            let c = c.clone();
            async move { c.call("/example.KV/Get", b"k".to_vec(), 5000).await }
        });
        let b = wrx.recv().await.unwrap();
        let f = Frame::decode(&*b).unwrap();
        c.inject_frame(Frame {
            version: 1,
            request_id: f.request_id,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Error(ProtoError {
                    code: 5, // NOT_FOUND
                    message: "missing".into(),
                })),
            })),
        })
        .await;
        let err = h.await.unwrap().unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn ready_version_range_checked() {
        let (c, mut wrx) = Initiator::new(ConnectionConfig::default());
        let h = tokio::spawn({
            let c = c.clone();
            async move { c.handshake(vec![]).await }
        });
        let _hello = wrx.recv().await.unwrap();
        // Ready with a version outside the proposed range fails.
        c.inject_frame(ready_frame(99)).await;
        let err = h.await.unwrap().unwrap_err();
        assert!(matches!(err, SyntraError::Handshake { .. }));
        assert!(c.is_closed());
    }

    #[tokio::test]
    async fn handshake_timeout_closes_core() {
        let mut cfg = ConnectionConfig::default();
        cfg.handshake_timeout = Duration::from_millis(50);
        let (c, mut wrx) = Initiator::new(cfg);
        let h = tokio::spawn({
            let c = c.clone();
            async move { c.handshake(vec![]).await }
        });
        let _hello = wrx.recv().await.unwrap();
        let err = h.await.unwrap().unwrap_err();
        assert!(matches!(err, SyntraError::DeadlineExceeded(_)));
        assert!(c.is_closed());
        assert_eq!(c.state().await, ConnectionState::Closed);
    }

    #[tokio::test]
    async fn pre_active_result_fails_handshake() {
        let (c, mut wrx) = Initiator::new(ConnectionConfig::default());
        let h = tokio::spawn({
            let c = c.clone();
            async move { c.handshake(vec![]).await }
        });
        let _hello = wrx.recv().await.unwrap();
        c.inject_frame(Frame {
            version: 1,
            request_id: 7,
            body: Some(Body::Result(RpcResult {
                outcome: Some(Outcome::Payload(vec![].into())),
            })),
        })
        .await;
        let err = h.await.unwrap().unwrap_err();
        assert!(matches!(err, SyntraError::Handshake { .. }));
        assert!(c.is_closed());
    }

    #[tokio::test]
    async fn notification_overflow_reports_loss() {
        // Bounded notification queue of capacity 1 admits one
        // Initiator notification and drops the next with loss accounting.
        let (c, _wrx) = Initiator::new(ConnectionConfig {
            notification_capacity: 1,
            ..ConnectionConfig::default()
        });
        *c.conn.shared.state.write().await = ConnectionState::Active;
        *c.conn.shared.version.write().await = Some(1);
        for payload in [b"one".to_vec(), b"two".to_vec()] {
            let frame = Frame {
                version: 1,
                request_id: 0,
                body: Some(Body::Notification(syntra_core::proto::Notification {
                    payload,
                })),
            };
            c.ingest(&frame.encode_to_vec()).await;
        }
        let (dropped, dropped_bytes) = c.notification_loss();
        assert_eq!(dropped, 1);
        assert_eq!(dropped_bytes, 3);
        assert_eq!(c.conn.notification_loss(), (1, 3));
        // The carried loss totals publish on the same drop for loss
        // waiters, including late subscribers.
        assert_eq!(*c.conn.shared.notification_loss_tx.borrow(), (1, 3));
    }

    fn notification_frame(payload: &[u8]) -> Frame {
        Frame {
            version: 1,
            request_id: 0,
            body: Some(Body::Notification(syntra_core::proto::Notification {
                payload: payload.to_vec(),
            })),
        }
    }

    #[test]
    fn notification_loss_warn_throttles_under_burst() {
        // First drop plus every 64th warns; the rest stay at debug so a
        // burst cannot amplify into logs.
        assert!(loss_warn_on_drop(1));
        assert!(!loss_warn_on_drop(2));
        assert!(!loss_warn_on_drop(63));
        assert!(loss_warn_on_drop(64));
        assert!(!loss_warn_on_drop(65));
        assert!(loss_warn_on_drop(128));
    }

    #[tokio::test]
    async fn notification_loss_counters_accumulate_under_burst() {
        // A burst over the bounded Syntra notification queue stays
        // non-blocking: every overflow drops with cumulative loss
        // accounting, and the carried totals track the counters.
        let (c, _wrx) = Initiator::new(ConnectionConfig {
            notification_capacity: 1,
            ..ConnectionConfig::default()
        });
        *c.conn.shared.state.write().await = ConnectionState::Active;
        *c.conn.shared.version.write().await = Some(1);
        c.inject_frame(notification_frame(b"one")).await;
        for _ in 0..200 {
            c.inject_frame(notification_frame(b"x")).await;
        }
        assert_eq!(c.notification_loss(), (200, 200));
        assert_eq!(*c.conn.shared.notification_loss_tx.borrow(), (200, 200));
    }

    #[tokio::test]
    async fn concurrent_loss_waiters_all_wake_on_single_drop() {
        // Bounded Syntra notification queue of capacity 1 shared by cloned
        // Initiators (one Shared): one queued notification plus one drop
        // must wake every concurrent loss waiter with the loss totals.
        let (c, _wrx) = Initiator::new(ConnectionConfig {
            notification_capacity: 1,
            ..ConnectionConfig::default()
        });
        *c.conn.shared.state.write().await = ConnectionState::Active;
        *c.conn.shared.version.write().await = Some(1);
        c.inject_frame(notification_frame(b"one")).await;
        assert_eq!(c.notification_loss(), (0, 0));
        // Hold the receiver so parked waiters cannot consume the queued
        // notification before the drop is published.
        let _hold = c.conn.hold_notification_receiver_for_test().await;
        let mut waiters: Vec<_> = (0..4)
            .map(|_| {
                let waiter = c.clone();
                Box::pin(async move { waiter.next_notification_with_loss().await })
            })
            .collect();
        for waiter in &mut waiters {
            assert!(futures_util::poll!(waiter.as_mut()).is_pending());
        }
        // One more notification overflows the full queue: exactly one loss.
        c.inject_frame(notification_frame(b"two")).await;
        assert_eq!(c.notification_loss(), (1, 3));
        drop(_hold);
        let results = tokio::time::timeout(
            Duration::from_secs(2),
            futures_util::future::join_all(waiters),
        )
        .await
        .expect("one loss must wake every concurrent waiter");
        for (_payload, totals) in results {
            // The receiver holder may take the queued notification while
            // the rest wake on the loss signal; every waiter observes the
            // same cumulative loss totals.
            assert_eq!(totals, (1, 3));
        }
    }
}
