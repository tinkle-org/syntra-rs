//! Bounded Bebop recovery codec. Wire structure is checked on borrowed bytes
//! before generated decoding and conversion into the owned runtime values.

use super::{ProviderError, CAPABILITY};
use syntra_core::wire::*;
#[path = "wire_bindings.rs"]
mod bindings;
pub(crate) use bindings::batch_size;

/// Leaves room for the enclosing result or notification frame.
pub const MAX_PAYLOAD_BYTES: usize = syntra_core::MAX_FRAME_BYTES - 128;

pub trait ProfileMessage: Default + bindings::Binding {
    fn validate(&self) -> Result<(), ProviderError>;
}

pub fn decode<M: ProfileMessage>(bytes: &[u8]) -> Result<M, ProviderError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(ProviderError::ResourceExhausted);
    }
    let value = M::read(bytes)?;
    value.validate()?;
    Ok(value)
}

pub fn encode<M: ProfileMessage>(message: &M) -> Result<Vec<u8>, ProviderError> {
    message.validate()?;
    message.write()
}

#[cfg(test)]
pub(crate) trait FixtureRecord: ProfileMessage {
    // Bypass semantic validation only, for fixtures sent by a faulty peer.
    fn fixture_bytes(&self) -> Vec<u8> {
        self.write().unwrap()
    }
}
#[cfg(test)]
impl<M: ProfileMessage> FixtureRecord for M {}

fn require(ok: bool) -> Result<(), ProviderError> {
    if ok {
        Ok(())
    } else {
        Err(ProviderError::FailedPrecondition)
    }
}
fn opaque(bytes: &[u8], max: usize, nonempty: bool) -> bool {
    bytes.len() <= max && (!nonempty || !bytes.is_empty())
}
fn handle(bytes: &[u8]) -> bool {
    opaque(bytes, 256, true)
}
fn cp(bytes: &[u8]) -> bool {
    opaque(bytes, 4096, true)
}

macro_rules! profile {
    ($ty:ty, $s:ident, $check:expr) => {
        impl ProfileMessage for $ty {
            fn validate(&$s) -> Result<(), ProviderError> {
                require($s.profile_version == 1)?;
                $check
            }
        }
    };
}

profile!(
    Negotiate,
    self,
    require(
        self.min_version != 0
            && self.max_version >= self.min_version
            && self.capability == CAPABILITY
    )
);
profile!(
    Negotiated,
    self,
    require(
        self.selected_version == 1
            && (1..=64).contains(&self.max_subscriptions_per_connection)
            && (1..=16).contains(&self.max_pending_rpcs_per_connection)
            && (1..=262_144).contains(&self.max_page_bytes)
            && (1..=256).contains(&self.max_snapshot_pages)
    )
);
profile!(
    Subscribe,
    self,
    require(
        opaque(&self.stream_selector, 1024, true) && opaque(&self.start_checkpoint, 4096, false)
    )
);
profile!(
    SubscriptionAccepted,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.catchup_boundary)
    )
);
profile!(
    Replay,
    self,
    require(
        handle(&self.subscription_handle)
            && cp(&self.from_checkpoint)
            && (1..=64).contains(&self.max_batches)
            && (1..=262_144).contains(&self.max_bytes)
            && opaque(&self.continuation_marker, 4096, false)
    )
);
profile!(RecoveryReplayPage, self, {
    require(
        handle(&self.subscription_handle)
            && cp(&self.predecessor_checkpoint)
            && cp(&self.result_checkpoint)
            && cp(&self.catchup_boundary)
            && opaque(&self.continuation_marker, 4096, false)
            && self.batch_payloads.len() <= 64,
    )?;
    let mut total = 0usize;
    let mut cursor = self.predecessor_checkpoint.clone();
    let mut generation = None;
    for entry in &self.batch_payloads {
        total = total
            .checked_add(entry.len())
            .ok_or(ProviderError::ResourceExhausted)?;
        require(entry.len() <= 262_144 && total <= 262_144)?;
        let b: RecoveryBatch = decode(entry)?;
        require(
            b.subscription_handle == self.subscription_handle
                && b.predecessor_checkpoint == cursor
                && generation.is_none_or(|g| g == b.generation),
        )?;
        generation = Some(b.generation);
        cursor = b.result_checkpoint;
    }
    require(
        cursor == self.result_checkpoint
            && (self.continuation_marker.is_empty()
                == (self.result_checkpoint == self.catchup_boundary)),
    )
});
profile!(
    RecoveryReplayComplete,
    self,
    require(
        handle(&self.subscription_handle)
            && self.generation != 0
            && cp(&self.live_boundary_checkpoint)
    )
);
profile!(CatchUp, self, require(handle(&self.subscription_handle)));
profile!(
    RecoveryCatchUpAccepted,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.catchup_boundary)
    )
);
profile!(
    OfferSnapshot,
    self,
    require(handle(&self.subscription_handle) && self.generation != 0)
);
profile!(
    RecoverySnapshotDescriptor,
    self,
    require(
        handle(&self.subscription_handle)
            && handle(&self.snapshot_handle)
            && cp(&self.boundary_checkpoint)
            && (1..=256).contains(&self.total_pages)
            && (1..=262_144).contains(&self.page_bytes_max)
    )
);
profile!(
    FetchSnapshot,
    self,
    require(handle(&self.snapshot_handle) && self.page_index < 256)
);
profile!(
    RecoverySnapshotChunk,
    self,
    require(
        handle(&self.snapshot_handle)
            && self.page_index < 256
            && cp(&self.boundary_checkpoint)
            && opaque(&self.page_bytes, 262_144, true)
    )
);
profile!(
    Confirm,
    self,
    require(handle(&self.subscription_handle) && self.generation != 0 && cp(&self.checkpoint))
);
profile!(
    Confirmed,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.confirmed_checkpoint)
    )
);
profile!(
    ConfirmSnapshot,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.boundary_checkpoint)
    )
);
profile!(
    RecoverySnapshotInstalled,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.boundary_checkpoint)
    )
);
profile!(
    Unsubscribe,
    self,
    require(handle(&self.subscription_handle))
);
profile!(
    Unsubscribed,
    self,
    require(handle(&self.subscription_handle) && self.generation != 0)
);
profile!(
    RecoveryBatch,
    self,
    require(
        handle(&self.subscription_handle)
            && self.generation != 0
            && opaque(&self.predecessor_checkpoint, 4096, false)
            && cp(&self.result_checkpoint)
            && batch_size(self) <= 262_144
    )
);
profile!(RecoveryBatchTrailer, self, {
    use recovery_batch_trailer::Outcome;
    require(
        handle(&self.subscription_handle)
            && self.generation != 0
            && opaque(&self.boundary_checkpoint, 4096, false),
    )?;
    require(match &self.outcome {
        Some(Outcome::NextGeneration(g)) => {
            *g > self.generation && self.terminate_reason.is_empty()
        }
        Some(Outcome::Terminated) => {
            opaque(&self.terminate_reason, 256, true) && self.terminate_reason.is_ascii()
        }
        Some(Outcome::CatchupComplete) => {
            cp(&self.boundary_checkpoint) && self.terminate_reason.is_empty()
        }
        Some(Outcome::SnapshotRequired) => self.terminate_reason.is_empty(),
        None => false,
    })
});
profile!(RecoveryNotification, self, {
    match &self.notification {
        Some(recovery_notification::Notification::Batch(b)) => b.validate(),
        Some(recovery_notification::Notification::ReplayComplete(c)) => c.validate(),
        Some(recovery_notification::Notification::Trailer(t)) => t.validate(),
        None => Err(ProviderError::FailedPrecondition),
    }
});
