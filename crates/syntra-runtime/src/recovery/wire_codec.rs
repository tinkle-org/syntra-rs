//! Bounded profile protobuf codec. Preflight scans borrowed bytes before prost
//! allocates any fields, including nested notifications and replay entries.
//! Unknown well-formed fields are ignored. Ordinary protobuf last-value/merge
//! semantics apply; core Frame's raw outcome policy is NOT a profile rule.

use super::{ProviderError, CAPABILITY};
use prost::Message;
use syntra_core::proto::*;

/// Leaves room for the existing Frame/RpcResult or Notification envelope,
/// including worst-case integer varints. This is NOT a new wire allocation.
pub const MAX_PAYLOAD_BYTES: usize = syntra_core::MAX_FRAME_BYTES - 128;

#[derive(Clone, Copy)]
#[doc(hidden)]
pub enum Kind {
    Negotiate,
    Negotiated,
    Subscribe,
    Subscribed,
    Replay,
    Page,
    Complete,
    CatchUp,
    Accepted,
    Offer,
    Descriptor,
    Fetch,
    Chunk,
    Confirm,
    Confirmed,
    SnapshotConfirm,
    Installed,
    Unsubscribe,
    Unsubscribed,
    Batch,
    Trailer,
    Notification,
}

mod sealed {
    pub trait Sealed {}
}
pub trait ProfileMessage: Message + Default + sealed::Sealed {
    #[doc(hidden)]
    const KIND: Kind;
    fn validate(&self) -> Result<(), ProviderError>;
}

pub fn decode<M: ProfileMessage>(bytes: &[u8]) -> Result<M, ProviderError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err(ProviderError::ResourceExhausted);
    }
    scan(bytes, Some(M::KIND), 0)?;
    let value = M::decode(bytes).map_err(|_| ProviderError::FailedPrecondition)?;
    value.validate()?;
    Ok(value)
}

pub fn encode<M: ProfileMessage>(message: &M) -> Result<Vec<u8>, ProviderError> {
    message.validate()?;
    if message.encoded_len() > MAX_PAYLOAD_BYTES {
        return Err(ProviderError::ResourceExhausted);
    }
    Ok(message.encode_to_vec())
}

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
    ($ty:ty, $kind:ident, $s:ident, $check:expr) => {
        impl sealed::Sealed for $ty {}
        impl ProfileMessage for $ty {
            const KIND: Kind = Kind::$kind;
            fn validate(&$s) -> Result<(), ProviderError> {
                require($s.profile_version == 1)?;
                $check
            }
        }
    };
}

profile!(
    RecoveryNegotiateRequest,
    Negotiate,
    self,
    require(
        self.min_version != 0
            && self.max_version >= self.min_version
            && self.capability == CAPABILITY
    )
);
profile!(
    RecoveryNegotiateResponse,
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
    RecoverySubscribeRequest,
    Subscribe,
    self,
    require(
        opaque(&self.stream_selector, 1024, true) && opaque(&self.start_checkpoint, 4096, false)
    )
);
profile!(
    RecoverySubscribeResponse,
    Subscribed,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.catchup_boundary)
    )
);
profile!(
    RecoveryReplayRequest,
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
profile!(RecoveryReplayPage, Page, self, {
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
    Complete,
    self,
    require(
        handle(&self.subscription_handle)
            && self.generation != 0
            && cp(&self.live_boundary_checkpoint)
    )
);
profile!(
    RecoveryCatchUpRequest,
    CatchUp,
    self,
    require(handle(&self.subscription_handle))
);
profile!(
    RecoveryCatchUpAccepted,
    Accepted,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.catchup_boundary)
    )
);
profile!(
    RecoverySnapshotOfferRequest,
    Offer,
    self,
    require(handle(&self.subscription_handle) && self.generation != 0)
);
profile!(
    RecoverySnapshotDescriptor,
    Descriptor,
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
    RecoverySnapshotFetchRequest,
    Fetch,
    self,
    require(handle(&self.snapshot_handle) && self.page_index < 256)
);
profile!(
    RecoverySnapshotChunk,
    Chunk,
    self,
    require(
        handle(&self.snapshot_handle)
            && self.page_index < 256
            && cp(&self.boundary_checkpoint)
            && opaque(&self.page_bytes, 262_144, true)
    )
);
profile!(
    RecoveryConfirmRequest,
    Confirm,
    self,
    require(handle(&self.subscription_handle) && self.generation != 0 && cp(&self.checkpoint))
);
profile!(
    RecoveryConfirmResponse,
    Confirmed,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.confirmed_checkpoint)
    )
);
profile!(
    RecoverySnapshotConfirmRequest,
    SnapshotConfirm,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.boundary_checkpoint)
    )
);
profile!(
    RecoverySnapshotInstalled,
    Installed,
    self,
    require(
        handle(&self.subscription_handle) && self.generation != 0 && cp(&self.boundary_checkpoint)
    )
);
profile!(
    RecoveryUnsubscribeRequest,
    Unsubscribe,
    self,
    require(handle(&self.subscription_handle))
);
profile!(
    RecoveryUnsubscribeResponse,
    Unsubscribed,
    self,
    require(handle(&self.subscription_handle) && self.generation != 0)
);
profile!(
    RecoveryBatch,
    Batch,
    self,
    require(
        handle(&self.subscription_handle)
            && self.generation != 0
            && opaque(&self.predecessor_checkpoint, 4096, false)
            && cp(&self.result_checkpoint)
            && self.encoded_len() <= 262_144
    )
);
profile!(RecoveryBatchTrailer, Trailer, self, {
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
        Some(Outcome::Terminated(true)) => {
            opaque(&self.terminate_reason, 256, true) && self.terminate_reason.is_ascii()
        }
        Some(Outcome::CatchupComplete(true)) => {
            cp(&self.boundary_checkpoint) && self.terminate_reason.is_empty()
        }
        Some(Outcome::SnapshotRequired(true)) => self.terminate_reason.is_empty(),
        _ => false,
    })
});
profile!(RecoveryNotification, Notification, self, {
    match &self.notification {
        Some(recovery_notification::Notification::Batch(b)) => b.validate(),
        Some(recovery_notification::Notification::ReplayComplete(c)) => c.validate(),
        Some(recovery_notification::Notification::Trailer(t)) => t.validate(),
        None => Err(ProviderError::FailedPrecondition),
    }
});

#[derive(Clone, Copy)]
enum Field {
    U32,
    U64,
    Bytes(usize),
    Text(usize),
    Nested(Kind),
    Entry,
}
fn field(k: Kind, n: u32) -> Option<Field> {
    use Field::*;
    use Kind::*;
    if n == 1 {
        return Some(U32);
    }
    Some(match (k, n) {
        (Negotiate, 2 | 3)
        | (Negotiated, 2..=6)
        | (Replay, 4 | 5)
        | (Descriptor, 5 | 6)
        | (Fetch | Chunk, 3) => U32,
        (
            Subscribed | Unsubscribed | Complete | Accepted | Offer | Confirm | SnapshotConfirm
            | Batch | Trailer,
            3,
        )
        | (Confirmed | Installed, 4)
        | (Trailer, 5..=8) => U64,
        (Negotiate, 4) => Text(256),
        (Subscribe, 2) => Bytes(1024),
        (Subscribe, 3)
        | (Replay, 3 | 6)
        | (Page, 3..=6)
        | (Subscribed | Complete | Accepted, 4)
        | (Descriptor, 4)
        | (Chunk, 5)
        | (Confirm | SnapshotConfirm, 4)
        | (Confirmed | Installed, 3)
        | (Batch, 4 | 5)
        | (Trailer, 4) => Bytes(4096),
        (Page, 7) => Entry,
        (Chunk, 4) | (Batch, 6) => Bytes(262_144),
        (Notification, 2) => Nested(Batch),
        (Notification, 3) => Nested(Complete),
        (Notification, 4) => Nested(Trailer),
        (
            Subscribed | Replay | Page | Complete | CatchUp | Accepted | Offer | Descriptor | Fetch
            | Chunk | Confirm | Confirmed | SnapshotConfirm | Installed | Unsubscribe
            | Unsubscribed | Batch | Trailer,
            2,
        )
        | (Descriptor, 3)
        | (Trailer, 9) => Bytes(256),
        _ => return None,
    })
}

fn varint(bytes: &[u8], pos: &mut usize) -> Result<u64, ProviderError> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let b = *bytes.get(*pos).ok_or(ProviderError::FailedPrecondition)?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return Err(ProviderError::FailedPrecondition);
        }
        value |= u64::from(b & 127) << shift;
        if b < 128 {
            return Ok(value);
        }
    }
    Err(ProviderError::FailedPrecondition)
}

fn scan(bytes: &[u8], kind: Option<Kind>, depth: usize) -> Result<(), ProviderError> {
    if depth > 32 {
        return Err(ProviderError::ResourceExhausted);
    }
    if matches!(kind, Some(Kind::Batch)) && bytes.len() > 262_144 {
        return Err(ProviderError::ResourceExhausted);
    }
    let mut p = 0;
    let mut entries = 0;
    let mut entry_bytes = 0usize;
    while p < bytes.len() {
        let key = varint(bytes, &mut p)?;
        let n = u32::try_from(key >> 3).map_err(|_| ProviderError::FailedPrecondition)?;
        require(n != 0 && n <= 0x1fff_ffff)?;
        let wire = key & 7;
        let f = kind.and_then(|k| field(k, n));
        match wire {
            0 => {
                require(f.is_none() || matches!(f, Some(Field::U32 | Field::U64)))?;
                let v = varint(bytes, &mut p)?;
                if matches!(f, Some(Field::U32)) {
                    require(v <= u64::from(u32::MAX))?;
                }
            }
            1 | 5 => {
                require(f.is_none())?;
                p = p
                    .checked_add(if wire == 1 { 8 } else { 4 })
                    .ok_or(ProviderError::FailedPrecondition)?;
                require(p <= bytes.len())?;
            }
            2 => {
                require(!matches!(f, Some(Field::U32 | Field::U64)))?;
                let len = usize::try_from(varint(bytes, &mut p)?)
                    .map_err(|_| ProviderError::FailedPrecondition)?;
                let end = p
                    .checked_add(len)
                    .ok_or(ProviderError::FailedPrecondition)?;
                let data = bytes.get(p..end).ok_or(ProviderError::FailedPrecondition)?;
                match f {
                    Some(Field::Bytes(max) | Field::Text(max)) => {
                        require(len <= max)?;
                        if matches!(f, Some(Field::Text(_))) {
                            require(data.is_ascii())?;
                        }
                    }
                    Some(Field::Nested(k)) => scan(data, Some(k), depth + 1)?,
                    Some(Field::Entry) => {
                        entries += 1;
                        entry_bytes = entry_bytes
                            .checked_add(len)
                            .ok_or(ProviderError::ResourceExhausted)?;
                        require(entries <= 64 && len <= 262_144 && entry_bytes <= 262_144)?;
                        scan(data, Some(Kind::Batch), depth + 1)?;
                    }
                    _ => {}
                }
                p = end;
            }
            3 => {
                require(f.is_none())?;
                skip_group(bytes, &mut p, n, depth + 1)?;
            }
            _ => return Err(ProviderError::FailedPrecondition),
        }
    }
    Ok(())
}

fn skip_group(bytes: &[u8], p: &mut usize, tag: u32, depth: usize) -> Result<(), ProviderError> {
    if depth > 32 {
        return Err(ProviderError::ResourceExhausted);
    }
    loop {
        let key = varint(bytes, p)?;
        let n = u32::try_from(key >> 3).map_err(|_| ProviderError::FailedPrecondition)?;
        require(n != 0 && n <= 0x1fff_ffff)?;
        match key & 7 {
            0 => {
                varint(bytes, p)?;
            }
            1 => *p = p.checked_add(8).ok_or(ProviderError::FailedPrecondition)?,
            2 => {
                let len = usize::try_from(varint(bytes, p)?)
                    .map_err(|_| ProviderError::FailedPrecondition)?;
                *p = p
                    .checked_add(len)
                    .ok_or(ProviderError::FailedPrecondition)?;
            }
            3 => skip_group(bytes, p, n, depth + 1)?,
            4 => return require(n == tag),
            5 => *p = p.checked_add(4).ok_or(ProviderError::FailedPrecondition)?,
            _ => return Err(ProviderError::FailedPrecondition),
        }
        require(*p <= bytes.len())?;
    }
}
