//! Connection-owned ingress, before the core's lossy notification queue.
//!
//! Only bounded bookkeeping runs under this synchronous mutex. No application
//! callback, I/O, or await is permitted here. The parent authenticates and
//! validates the core envelope first; this is not a capability sniffer. Once
//! enabled, every payload routed here must be a RecoveryNotification. Other
//! application notifications require an explicit demultiplexer above core.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use prost::Message;
use syntra_core::proto::{recovery_batch_trailer::Outcome, recovery_notification::Notification};
use syntra_core::proto::{RecoveryBatch, RecoveryBatchTrailer, RecoveryNotification};
use tokio::sync::Notify;

use super::super::wire::{codec, ProviderError, RecoveryLimits};

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct InboxCounts {
    pub data_bytes: usize,
    pub data_messages: usize,
    pub control_messages: usize,
    pub handles: usize,
}

struct Queued {
    batch: RecoveryBatch,
    bytes: usize,
}

struct Slot {
    generation: u64,
    revision: u64,
    stable_stream: Vec<u8>,
    registered: bool,
    fenced: bool,
    data: VecDeque<Queued>,
    replay: VecDeque<Queued>,
    bytes: usize,
    leased: usize,
    completion: Option<Notification>,
    terminal: Option<Notification>,
}

impl Slot {
    fn new(generation: u64, registered: bool) -> Self {
        Self {
            generation,
            revision: 0,
            stable_stream: Vec::new(),
            registered,
            fenced: false,
            data: VecDeque::new(),
            replay: VecDeque::new(),
            bytes: 0,
            leased: 0,
            completion: None,
            terminal: None,
        }
    }

    fn clear_data(&mut self) {
        self.data.clear();
        self.replay.clear();
        self.bytes = 0;
        self.leased = 0;
        self.completion = None;
    }

    fn overflow(&mut self, handle: &[u8]) {
        self.clear_data();
        self.fenced = true;
        self.terminal = Some(Notification::Trailer(RecoveryBatchTrailer {
            profile_version: 1,
            subscription_handle: handle.to_vec(),
            generation: self.generation,
            boundary_checkpoint: Vec::new(),
            outcome: Some(Outcome::Terminated(true)),
            terminate_reason: b"local-queue-exhausted".to_vec(),
        }));
    }
}

#[derive(Default)]
struct State {
    enabled: bool,
    closed: bool,
    serial: u64,
    pending: Option<u64>,
    // Retired registered slots remain as small tombstones: H is never reused.
    slots: BTreeMap<Vec<u8>, Slot>,
}

/// A fresh inbox must be attached to exactly one authenticated Initiator.
/// `close` is required at connection teardown, including handshake failure.
pub struct RecoveryInbox {
    limits: RecoveryLimits,
    state: Mutex<State>,
    pub(super) changed: Notify,
}

impl RecoveryInbox {
    pub(super) fn new(limits: RecoveryLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
            changed: Notify::new(),
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        let s = self.state.lock().expect("recovery inbox poisoned");
        s.enabled && !s.closed
    }

    /// Called only after explicit, validated version-1 negotiation succeeds.
    pub(crate) fn enable(&self) -> Result<(), ProviderError> {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        if s.closed {
            return Err(ProviderError::Unavailable);
        }
        s.enabled = true;
        Ok(())
    }

    pub(crate) fn close(&self) {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        s.closed = true;
        s.enabled = false;
        s.pending = None;
        s.slots.clear();
        drop(s);
        self.changed.notify_waiters();
    }

    pub fn counts(&self) -> InboxCounts {
        counts(&self.state.lock().expect("recovery inbox poisoned"))
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().expect("recovery inbox poisoned").closed
    }

    /// Non-async ingress. Invalid payloads fail closed; unknown H is inert
    /// except during the one exact Subscribe registration window.
    pub(crate) fn push(&self, payload: &[u8]) -> Result<(), ProviderError> {
        if !self.is_enabled() {
            return Err(ProviderError::FailedPrecondition);
        }
        let n: RecoveryNotification = codec::decode(payload)?;
        let n = n.notification.ok_or(ProviderError::FailedPrecondition)?;
        let (h, generation) = identity(&n);
        let h = h.to_vec();
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        if s.closed {
            return Err(ProviderError::Unavailable);
        }
        if !s.slots.contains_key(&h) {
            if s.pending.is_none() {
                return Ok(());
            }
            // Unknown candidates are counted against the same connection cap.
            if s.slots.len() >= self.limits.handles_per_connection {
                return Err(ProviderError::ResourceExhausted);
            }
            s.slots.insert(h.clone(), Slot::new(generation, false));
        }
        let total = counts(&s).data_bytes;
        let slot = s.slots.get_mut(&h).expect("inserted");
        if slot.fenced {
            return Ok(());
        }
        if slot.generation != generation {
            return Err(ProviderError::FailedPrecondition);
        }
        let loss = match &n {
            Notification::Trailer(t) if slot.registered => match t.outcome {
                Some(Outcome::NextGeneration(next)) => Some((slot.stable_stream.clone(), next)),
                _ => None,
            },
            _ => None,
        };
        match n {
            Notification::Batch(batch) => {
                // Include a conservative core Notification/Frame overhead;
                // unknown fields are charged at their original encoded size.
                let bytes = payload.len().saturating_add(32);
                if slot.bytes.saturating_add(bytes) > self.limits.queued_bytes_per_stream
                    || total.saturating_add(bytes) > self.limits.queued_bytes_per_connection
                    || slot.data.len() + slot.replay.len() + usize::from(slot.leased != 0)
                        >= self.limits.queued_messages_per_stream
                {
                    slot.overflow(&h);
                } else {
                    slot.bytes += bytes;
                    slot.data.push_back(Queued { batch, bytes });
                }
            }
            Notification::ReplayComplete(_) => {
                if slot
                    .completion
                    .as_ref()
                    .is_some_and(|old| completion_boundary(old) != completion_boundary(&n))
                {
                    slot.overflow(&h);
                } else {
                    slot.completion = Some(n);
                }
            }
            Notification::Trailer(ref trailer) => match trailer.outcome {
                Some(Outcome::CatchupComplete(true)) => {
                    if slot
                        .completion
                        .as_ref()
                        .is_some_and(|old| completion_boundary(old) != completion_boundary(&n))
                    {
                        slot.overflow(&h);
                    } else {
                        slot.completion = Some(n);
                    }
                }
                _ => {
                    slot.clear_data();
                    slot.revision = slot.revision.saturating_add(1);
                    slot.fenced = !matches!(trailer.outcome, Some(Outcome::SnapshotRequired(true)));
                    slot.terminal = Some(n);
                }
            },
        }
        if let Some((stable_stream, next)) = loss {
            // Application-declared aliases share S in this connection's P.
            // Fan out a provider-declared scoped loss locally, so a blocked
            // store or RPC on another H cannot delay fencing its next retry.
            // These local controls are never emitted as wire Notifications.
            for (handle, slot) in &mut s.slots {
                if slot.registered
                    && !slot.fenced
                    && slot.stable_stream == stable_stream
                    && slot.generation < next
                {
                    slot.clear_data();
                    slot.revision = slot.revision.saturating_add(1);
                    slot.fenced = true;
                    slot.terminal = Some(Notification::Trailer(RecoveryBatchTrailer {
                        profile_version: 1,
                        subscription_handle: handle.clone(),
                        generation: slot.generation,
                        boundary_checkpoint: Vec::new(),
                        outcome: Some(Outcome::NextGeneration(next)),
                        terminate_reason: Vec::new(),
                    }));
                }
            }
        }
        drop(s);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(super) fn begin_subscribe(self: &Arc<Self>) -> Result<SubscribeToken, ProviderError> {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        if !s.enabled || s.closed || s.pending.is_some() {
            return Err(ProviderError::FailedPrecondition);
        }
        s.serial = s
            .serial
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted)?;
        let serial = s.serial;
        s.pending = Some(serial);
        Ok(SubscribeToken {
            inbox: self.clone(),
            serial,
        })
    }

    pub(super) fn retire(&self, handle: &[u8]) {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        if let Some(slot) = s.slots.get_mut(handle) {
            slot.clear_data();
            slot.terminal = None;
            slot.fenced = true;
        }
        drop(s);
        self.changed.notify_waiters();
    }

    pub(super) fn active(&self, handle: &[u8], generation: u64) -> bool {
        let s = self.state.lock().expect("recovery inbox poisoned");
        !s.closed
            && s.slots
                .get(handle)
                .is_some_and(|v| v.registered && !v.fenced && v.generation == generation)
    }

    pub(super) fn revision(&self, handle: &[u8]) -> Option<u64> {
        self.state
            .lock()
            .expect("recovery inbox poisoned")
            .slots
            .get(handle)
            .map(|s| s.revision)
    }

    pub(super) fn take_control(&self, handle: &[u8]) -> Option<Notification> {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        let slot = s.slots.get_mut(handle)?;
        slot.terminal.take().or_else(|| slot.completion.take())
    }

    pub(super) fn clear_data(&self, handle: &[u8]) {
        if let Some(slot) = self
            .state
            .lock()
            .expect("recovery inbox poisoned")
            .slots
            .get_mut(handle)
        {
            slot.clear_data();
        }
    }

    /// Atomically admit an entire correlated page. Live and replay bytes share
    /// the same quotas, even while the application has not persisted an offer.
    pub(super) fn replay_page(
        &self,
        handle: &[u8],
        batches: Vec<RecoveryBatch>,
    ) -> Result<(), ProviderError> {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        let total = counts(&s).data_bytes;
        let slot = s
            .slots
            .get_mut(handle)
            .ok_or(ProviderError::FailedPrecondition)?;
        if slot.fenced || !slot.registered || !slot.replay.is_empty() {
            return Err(ProviderError::FailedPrecondition);
        }
        let bytes = batches.iter().map(|b| b.encoded_len() + 40).sum::<usize>();
        if slot.bytes.saturating_add(bytes) > self.limits.queued_bytes_per_stream
            || total.saturating_add(bytes) > self.limits.queued_bytes_per_connection
            || slot.data.len() + batches.len() + usize::from(slot.leased != 0)
                > self.limits.queued_messages_per_stream
        {
            slot.overflow(handle);
            drop(s);
            self.changed.notify_waiters();
            return Err(ProviderError::ResourceExhausted);
        }
        if batches
            .iter()
            .any(|b| b.subscription_handle != handle || b.generation != slot.generation)
        {
            return Err(ProviderError::FailedPrecondition);
        }
        slot.bytes += bytes;
        slot.replay.extend(batches.into_iter().map(|batch| Queued {
            bytes: batch.encoded_len() + 40,
            batch,
        }));
        drop(s);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(super) fn replay_empty(&self, handle: &[u8]) -> bool {
        self.state
            .lock()
            .expect("recovery inbox poisoned")
            .slots
            .get(handle)
            .is_none_or(|s| s.replay.is_empty())
    }

    pub(super) fn take_batch(
        &self,
        handle: &[u8],
        replay: bool,
        allow: impl Fn(&RecoveryBatch) -> bool,
    ) -> Option<RecoveryBatch> {
        let mut s = self.state.lock().expect("recovery inbox poisoned");
        let slot = s.slots.get_mut(handle)?;
        if slot.fenced || slot.leased != 0 {
            return None;
        }
        let queue = if replay {
            &mut slot.replay
        } else {
            &mut slot.data
        };
        let index = queue.iter().position(|q| allow(&q.batch))?;
        let q = queue.remove(index)?;
        slot.leased = q.bytes;
        Some(q.batch)
    }

    pub(super) fn release_offer(&self, handle: &[u8]) {
        if let Some(slot) = self
            .state
            .lock()
            .expect("recovery inbox poisoned")
            .slots
            .get_mut(handle)
        {
            slot.bytes -= slot.leased;
            slot.leased = 0;
        }
        self.changed.notify_waiters();
    }
}

/// Not cloneable. Dropping a failed/cancelled Subscribe clears only its own
/// unknown-H window; another Subscribe can never inherit speculative output.
pub(super) struct SubscribeToken {
    inbox: Arc<RecoveryInbox>,
    serial: u64,
}

impl SubscribeToken {
    pub(super) fn register(
        self,
        handle: &[u8],
        generation: u64,
        stable_stream: &[u8],
    ) -> Result<(), ProviderError> {
        let mut s = self.inbox.state.lock().expect("recovery inbox poisoned");
        if s.closed || s.pending != Some(self.serial) {
            return Err(ProviderError::FailedPrecondition);
        }
        if s.slots
            .get(handle)
            .is_some_and(|v| v.registered || v.generation != generation)
        {
            return Err(ProviderError::FailedPrecondition);
        }
        let candidate = s.slots.remove(handle);
        s.slots.retain(|_, v| v.registered);
        if s.slots.len() >= self.inbox.limits.handles_per_connection {
            return Err(ProviderError::ResourceExhausted);
        }
        let mut slot = candidate.unwrap_or_else(|| Slot::new(generation, true));
        slot.registered = true;
        slot.stable_stream = stable_stream.to_vec();
        s.slots.insert(handle.to_vec(), slot);
        s.pending = None;
        Ok(())
    }
}

impl Drop for SubscribeToken {
    fn drop(&mut self) {
        let mut s = self.inbox.state.lock().expect("recovery inbox poisoned");
        if s.pending == Some(self.serial) {
            s.pending = None;
            s.slots.retain(|_, v| v.registered);
        }
    }
}

fn identity(n: &Notification) -> (&[u8], u64) {
    match n {
        Notification::Batch(b) => (&b.subscription_handle, b.generation),
        Notification::ReplayComplete(c) => (&c.subscription_handle, c.generation),
        Notification::Trailer(t) => (&t.subscription_handle, t.generation),
    }
}

fn completion_boundary(n: &Notification) -> &[u8] {
    match n {
        Notification::ReplayComplete(c) => &c.live_boundary_checkpoint,
        Notification::Trailer(t) => &t.boundary_checkpoint,
        Notification::Batch(_) => unreachable!("not a completion"),
    }
}

fn counts(s: &State) -> InboxCounts {
    let mut c = InboxCounts {
        handles: s.slots.len(),
        ..InboxCounts::default()
    };
    for slot in s.slots.values() {
        c.data_bytes += slot.bytes;
        c.data_messages += slot.data.len() + slot.replay.len() + usize::from(slot.leased != 0);
        c.control_messages +=
            usize::from(slot.completion.is_some()) + usize::from(slot.terminal.is_some());
    }
    c
}
