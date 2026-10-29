//! Synchronous queued-to-emitting handoff for initiator RPCs.

use std::{collections::HashMap, sync::Arc};

use prost::Message;
use syntra_core::{proto::frame::Body, Frame, PendingOutcome, RpcResult, SyntraError};
use tokio::sync::oneshot;
use web_time::Instant;

use crate::connection::{CancelToken, Shared};

// Use Tokio's elapsed clock on native so RPC timers and handoff checks use
// the same source, including under deterministic paused-time tests.
pub(crate) fn now() -> Instant {
    #[cfg(not(target_arch = "wasm32"))]
    return tokio::time::Instant::now().into_std();
    #[cfg(target_arch = "wasm32")]
    return Instant::now();
}

pub(crate) async fn sleep_until(deadline: Instant) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
    #[cfg(target_arch = "wasm32")]
    crate::connection::sleep_until(deadline).await;
}

pub(crate) struct EmissionState {
    deadline: Instant,
    cancel: CancelToken,
}

pub(crate) struct QueuedRpc {
    state: Arc<EmissionState>,
    // The original Vec allocation is an opaque, connection-local queue ticket.
    // It stays alive in the byte channel (or pump) until prepare_outbound takes
    // ownership. No dereference is performed. A stale live allocation cannot
    // alias a newer queue item even if its wire request ID has been reused.
    phase: EmissionPhase,
    failed: oneshot::Sender<SyntraError>,
}

enum EmissionPhase {
    Waiting,
    Queued(usize),
    Emitting,
}

pub(crate) type Emissions = HashMap<u64, QueuedRpc>;

/// Owns both pending and emission registration. Identity checks prevent an old
/// waiter dropping after result delivery from abandoning a newer use of its ID.
pub(crate) struct PendingGuard<'a> {
    shared: &'a Shared,
    id: u64,
    state: Arc<EmissionState>,
}

impl PendingGuard<'_> {
    pub(crate) fn enqueue(&self, bytes: Vec<u8>, send: impl FnOnce(Vec<u8>)) {
        let mut entries = self.shared.emissions.lock().unwrap();
        if let Some(entry) = entries.get_mut(&self.id) {
            if Arc::ptr_eq(&entry.state, &self.state) {
                entry.phase = EmissionPhase::Queued(bytes.as_ptr() as usize);
                send(bytes);
            }
        }
    }

    /// Select a local terminal outcome atomically against handoff/results.
    /// False means another terminal outcome has already selected its channel.
    pub(crate) fn terminate(&self) -> bool {
        self.terminate_with(|| {})
    }

    pub(crate) fn terminate_with(&self, selected: impl FnOnce()) -> bool {
        let mut entries = self.shared.emissions.lock().unwrap();
        if !entries
            .get(&self.id)
            .is_some_and(|entry| Arc::ptr_eq(&entry.state, &self.state))
        {
            return false;
        }
        selected();
        entries.remove(&self.id);
        self.shared.pending.abandon(self.id);
        true
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.terminate();
    }
}

impl Shared {
    pub(crate) fn admit_rpc(
        &self,
        id: u64,
        method: &str,
        deadline: Instant,
        cancel: &CancelToken,
    ) -> Result<
        (
            oneshot::Receiver<PendingOutcome>,
            oneshot::Receiver<SyntraError>,
            PendingGuard<'_>,
        ),
        SyntraError,
    > {
        let mut entries = self.emissions.lock().unwrap();
        let rx = self.pending.insert(id, method.to_string())?;
        let state = Arc::new(EmissionState {
            deadline,
            cancel: cancel.clone(),
        });
        let (failed, failure) = oneshot::channel();
        entries.insert(
            id,
            QueuedRpc {
                state: state.clone(),
                phase: EmissionPhase::Waiting,
                failed,
            },
        );
        Ok((
            rx,
            failure,
            PendingGuard {
                shared: self,
                id,
                state,
            },
        ))
    }

    pub(crate) fn complete_rpc(&self, id: u64, result: RpcResult) {
        let mut entries = self.emissions.lock().unwrap();
        self.pending.complete(id, result);
        entries.remove(&id);
    }

    // Explicit cancellation before handoff ends locally. The caller still
    // emits its best-effort control frame; emitting RPCs remain advisory.
    pub(crate) fn cancel_queued_rpc(&self, id: u64) -> bool {
        let mut entries = self.emissions.lock().unwrap();
        if entries
            .get(&id)
            .is_some_and(|entry| !matches!(entry.phase, EmissionPhase::Emitting))
        {
            let entry = entries.remove(&id).unwrap();
            let _ = entry
                .failed
                .send(SyntraError::Cancelled("queued RPC cancelled".into()));
            self.pending.abandon(id);
            return true;
        }
        false
    }

    pub(crate) fn prepare_outbound(&self, bytes: Vec<u8>) -> Option<Vec<u8>> {
        let mut frame = Frame::decode(bytes.as_slice()).ok()?;
        let Some(Body::Request(request)) = &mut frame.body else {
            // Handshake and control units are not RPC queue entries.
            return Some(bytes);
        };
        let mut entries = self.emissions.lock().unwrap();
        let entry = entries.get_mut(&frame.request_id)?;
        if !matches!(entry.phase, EmissionPhase::Queued(address) if address == bytes.as_ptr() as usize)
        {
            return None;
        }
        // Lock order: emissions -> cancellation. CancelToken::cancel takes
        // only cancellation, so a completed cancel cannot race a stale check.
        let _cancel = entry.state.cancel.lock();
        let remaining = entry
            .state
            .deadline
            .saturating_duration_since(now())
            .as_millis();
        let failure = if entry.state.cancel.is_cancelled() {
            Some(SyntraError::Cancelled("queued RPC cancelled".into()))
        } else if remaining == 0 {
            Some(SyntraError::DeadlineExceeded("queued RPC expired".into()))
        } else {
            None
        };
        if let Some(failure) = failure {
            drop(_cancel);
            let entry = entries.remove(&frame.request_id).unwrap();
            let _ = entry.failed.send(failure);
            self.pending.abandon(frame.request_id);
            return None;
        }
        request.timeout_ms = remaining.min(u32::MAX as u128) as u32;
        let prepared = frame.encode_to_vec();
        if prepared.len() > syntra_core::MAX_FRAME_BYTES {
            drop(_cancel);
            let entry = entries.remove(&frame.request_id).unwrap();
            let _ = entry.failed.send(SyntraError::ResourceExhausted(
                "request exceeds maximum envelope size at handoff".into(),
            ));
            self.pending.abandon(frame.request_id);
            return None;
        }
        // This is the linearization point, still under both gates. Bytes are
        // immutable to the runtime after handoff, including after cancellation.
        entry.phase = EmissionPhase::Emitting;
        Some(prepared)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::connection::{ConnectionConfig, Role};
    use syntra_core::{proto::rpc_result::Outcome, RpcRequest};
    use tokio::sync::mpsc;
    use web_time::Duration;

    #[tokio::test(start_paused = true)]
    async fn stale_queue_item_and_old_guard_cannot_affect_reused_pending_id() {
        let (writer, mut queue) = mpsc::channel(2);
        let (shared, _) = Shared::new(Role::Initiator, writer, ConnectionConfig::default(), 1, 1);
        let token = CancelToken::new();
        let bytes = || {
            Frame {
                version: 1,
                request_id: 7,
                body: Some(Body::Request(RpcRequest {
                    method: "/example.Echo/Echo".into(),
                    payload: vec![],
                    timeout_ms: 1000,
                })),
            }
            .encode_to_vec()
        };
        let (old_result, _, old_guard) = shared
            .admit_rpc(7, "old", now() + Duration::from_secs(1), &token)
            .unwrap();
        old_guard.enqueue(bytes(), |b| {
            shared.writer.try_send(b).unwrap();
        });
        let stale = queue.try_recv().unwrap();
        shared.complete_rpc(
            7,
            RpcResult {
                outcome: Some(Outcome::Payload(vec![])),
            },
        );
        assert!(old_result.await.is_ok());
        let (_, _, new_guard) = shared
            .admit_rpc(7, "new", now() + Duration::from_secs(1), &token)
            .unwrap();
        new_guard.enqueue(bytes(), |b| {
            shared.writer.try_send(b).unwrap();
        });
        drop(old_guard);
        assert_eq!(shared.pending.len(), 1);
        assert_eq!(shared.emissions.lock().unwrap().len(), 1);
        assert!(shared.prepare_outbound(stale).is_none());
        assert!(shared.prepare_outbound(queue.try_recv().unwrap()).is_some());
        drop(new_guard);
        assert_eq!(shared.pending.len(), 0);
        assert!(shared.emissions.lock().unwrap().is_empty());
    }
}
