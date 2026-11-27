//! Adapter between the owned runtime values and the borrowed generated records.

use super::*;
use bebop::{Record, SubRecord};
use syntra_core::generated as raw;

type Result<T> = std::result::Result<T, ProviderError>;
const INVALID: ProviderError = ProviderError::FailedPrecondition;
const ENTRY_BYTES: usize = 262_144;
const ENTRIES: usize = 64;

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    let (field, rest) = input.split_at_checked(n).ok_or(INVALID)?;
    *input = rest;
    Ok(field)
}

fn len(input: &mut &[u8]) -> Result<usize> {
    Ok(u32::from_le_bytes(take(input, 4)?.try_into().unwrap()) as usize)
}

fn blob<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8]> {
    let n = len(input)?;
    require(n <= max)?;
    take(input, n)
}

// Bebop excludes the discriminator from a union's length. Check the arm's
// exact extent before calling generated code (including on 32-bit targets).
fn arm<'a>(input: &mut &'a [u8]) -> Result<(u8, &'a [u8])> {
    let n = len(input)?;
    let tag = take(input, 1)?[0];
    Ok((tag, take(input, n)?))
}

fn entries(mut packed: &[u8], mut visit: impl FnMut(&[u8])) -> Result<()> {
    let mut total = 0;
    let mut count = 0;
    while !packed.is_empty() {
        let entry = blob(&mut packed, ENTRY_BYTES)?;
        total += entry.len();
        count += 1;
        require(count <= ENTRIES && total <= ENTRY_BYTES)?;
        RecoveryBatch::preflight(entry)?;
        visit(entry);
    }
    Ok(())
}

pub trait Binding: Sized {
    fn preflight(bytes: &[u8]) -> Result<()>;
    fn read(bytes: &[u8]) -> Result<Self>;
    fn write(&self) -> Result<Vec<u8>>;
}

fn read<'a, R: Record<'a>>(bytes: &'a [u8]) -> Result<R> {
    let (used, value) = R::_deserialize_chained(bytes).map_err(|_| INVALID)?;
    require(used == bytes.len())?;
    Ok(value)
}

fn write<'a, R: Record<'a>>(value: R) -> Result<Vec<u8>> {
    let n = value.serialized_size();
    if n > MAX_PAYLOAD_BYTES {
        return Err(ProviderError::ResourceExhausted);
    }
    let mut out = Vec::with_capacity(n);
    value.serialize(&mut out).map_err(|_| INVALID)?;
    Ok(out)
}

macro_rules! scan_field {
    ($s:ident, u32) => {
        take(&mut $s, 4)?;
    };
    ($s:ident, u64) => {
        take(&mut $s, 8)?;
    };
    ($s:ident, text) => {
        blob(&mut $s, 256)?;
    };
    ($s:ident, $max:literal) => {
        blob(&mut $s, $max)?;
    };
    ($s:ident, outcome) => {{
        let (tag, data) = arm(&mut $s)?;
        require(match tag {
            5 => data.len() == 8,
            6..=8 => data.is_empty(),
            _ => false,
        })?;
    }};
    ($s:ident, event) => {{
        let (tag, data) = arm(&mut $s)?;
        match tag {
            2 => RecoveryBatch::preflight(data)?,
            3 => RecoveryReplayComplete::preflight(data)?,
            4 => RecoveryBatchTrailer::preflight(data)?,
            _ => return Err(INVALID),
        };
    }};
}

macro_rules! borrow_field {
    ($v:expr, u32) => {
        $v
    };
    ($v:expr, u64) => {
        $v
    };
    ($v:expr, text) => {
        $v.as_str()
    };
    ($v:expr, $max:literal) => {
        bebop::SliceWrapper::from_cooked(&$v)
    };
    ($v:expr, outcome) => {
        match $v.ok_or(INVALID)? {
            recovery_batch_trailer::Outcome::NextGeneration(value) => {
                raw::TrailerOutcome::NextGeneration { value }
            }
            recovery_batch_trailer::Outcome::Terminated => raw::TrailerOutcome::Terminated {},
            recovery_batch_trailer::Outcome::CatchupComplete => {
                raw::TrailerOutcome::CatchupComplete {}
            }
            recovery_batch_trailer::Outcome::SnapshotRequired => {
                raw::TrailerOutcome::SnapshotRequired {}
            }
        }
    };
    ($v:expr, event) => {
        match $v.as_ref().ok_or(INVALID)? {
            recovery_notification::Notification::Batch(b) => {
                raw::RecoveryEvent::Batch { value: batch(b)? }
            }
            recovery_notification::Notification::ReplayComplete(c) => {
                raw::RecoveryEvent::ReplayComplete {
                    value: complete(c)?,
                }
            }
            recovery_notification::Notification::Trailer(t) => {
                raw::RecoveryEvent::Trailer { value: trailer(t)? }
            }
        }
    };
}
macro_rules! own_field {
    ($v:expr, u32) => {
        $v
    };
    ($v:expr, u64) => {
        $v
    };
    ($v:expr, text) => {
        $v.to_owned()
    };
    ($v:expr, $max:literal) => {
        $v.to_vec()
    };
    ($v:expr, outcome) => {
        Some(match $v {
            raw::TrailerOutcome::NextGeneration { value } => {
                recovery_batch_trailer::Outcome::NextGeneration(value)
            }
            raw::TrailerOutcome::Terminated {} => recovery_batch_trailer::Outcome::Terminated,
            raw::TrailerOutcome::CatchupComplete {} => {
                recovery_batch_trailer::Outcome::CatchupComplete
            }
            raw::TrailerOutcome::SnapshotRequired {} => {
                recovery_batch_trailer::Outcome::SnapshotRequired
            }
            raw::TrailerOutcome::Unknown => return Err(INVALID),
        })
    };
    ($v:expr, event) => {
        Some(match $v {
            raw::RecoveryEvent::Batch { value } => {
                recovery_notification::Notification::Batch(value.try_into_owned()?)
            }
            raw::RecoveryEvent::ReplayComplete { value } => {
                recovery_notification::Notification::ReplayComplete(value.try_into_owned()?)
            }
            raw::RecoveryEvent::Trailer { value } => {
                recovery_notification::Notification::Trailer(value.try_into_owned()?)
            }
            raw::RecoveryEvent::Unknown => return Err(INVALID),
        })
    };
}

trait IntoOwned<T> {
    fn try_into_owned(self) -> Result<T>;
}

// Field order is recovery.bop's positional order. One declaration supplies
// both conversion directions and the allocation-free length preflight.
macro_rules! binding {
    ($view:ident, $name:ident $(<$life:lifetime>)? $(; max_size = $limit:expr)?, $($field:ident: $kind:tt),*) => {
        fn $view(value: &$name) -> Result<raw::$name $(<$life>)?> {
            Ok(raw::$name {profile_version: value.profile_version, $($field: borrow_field!(value.$field, $kind)),*})
        }
        impl IntoOwned<$name> for raw::$name $(<$life>)? {
            fn try_into_owned(self) -> Result<$name> {
                Ok($name {profile_version: self.profile_version, $($field: own_field!(self.$field, $kind)),*})
            }
        }
        impl Binding for $name {
            fn preflight(mut bytes: &[u8]) -> Result<()> {
                $(if bytes.len() > $limit { return Err(ProviderError::ResourceExhausted); })?
                take(&mut bytes, 4)?;
                $(scan_field!(bytes, $kind);)*
                require(bytes.is_empty())
            }
            fn read(bytes: &[u8]) -> Result<Self> {
                Self::preflight(bytes)?;
                read::<raw::$name>(bytes)?.try_into_owned()
            }
            fn write(&self) -> Result<Vec<u8>> {write($view(self)?)}
        }
    }
}
binding!(negotiate, Negotiate<'_>, min_version:u32,max_version:u32,capability:text);
binding!(negotiated, Negotiated, selected_version:u32,max_subscriptions_per_connection:u32,max_pending_rpcs_per_connection:u32,max_page_bytes:u32,max_snapshot_pages:u32);
binding!(subscribe, Subscribe<'_>, stream_selector:1024,start_checkpoint:4096);
binding!(subscribed, SubscriptionAccepted<'_>, subscription_handle:256,generation:u64,catchup_boundary:4096);
binding!(unsubscribe, Unsubscribe<'_>, subscription_handle:256);
binding!(unsubscribed, Unsubscribed<'_>, subscription_handle:256,generation:u64);
binding!(replay, Replay<'_>, subscription_handle:256,from_checkpoint:4096,max_batches:u32,max_bytes:u32,continuation_marker:4096);
binding!(complete, RecoveryReplayComplete<'_>, subscription_handle:256,generation:u64,live_boundary_checkpoint:4096);
binding!(catch_up, CatchUp<'_>, subscription_handle:256);
binding!(accepted, RecoveryCatchUpAccepted<'_>,subscription_handle:256,generation:u64,catchup_boundary:4096);
binding!(offer, OfferSnapshot<'_>, subscription_handle:256,generation:u64);
binding!(descriptor, RecoverySnapshotDescriptor<'_>,subscription_handle:256,snapshot_handle:256,boundary_checkpoint:4096,total_pages:u32,page_bytes_max:u32);
binding!(fetch, FetchSnapshot<'_>,snapshot_handle:256,page_index:u32);
binding!(chunk, RecoverySnapshotChunk<'_>,snapshot_handle:256,page_index:u32,page_bytes:262144,boundary_checkpoint:4096);
binding!(confirm, Confirm<'_>,subscription_handle:256,generation:u64,checkpoint:4096);
binding!(confirmed, Confirmed<'_>,subscription_handle:256,confirmed_checkpoint:4096,generation:u64);
binding!(confirm_snapshot, ConfirmSnapshot<'_>,subscription_handle:256,generation:u64,boundary_checkpoint:4096);
binding!(installed, RecoverySnapshotInstalled<'_>,subscription_handle:256,boundary_checkpoint:4096,generation:u64);
binding!(batch, RecoveryBatch<'_>; max_size = ENTRY_BYTES,subscription_handle:256,generation:u64,predecessor_checkpoint:4096,result_checkpoint:4096,batch_payload:262144);
binding!(trailer, RecoveryBatchTrailer<'_>,subscription_handle:256,generation:u64,boundary_checkpoint:4096,outcome:outcome,terminate_reason:256);
binding!(notification, RecoveryNotification<'_>,notification:event);

pub(crate) fn batch_size(value: &RecoveryBatch) -> usize {
    batch(value).expect("batch has no union").serialized_size()
}

impl Binding for RecoveryReplayPage {
    fn preflight(mut bytes: &[u8]) -> Result<()> {
        take(&mut bytes, 4)?;
        for max in [256, 4096, 4096, 4096, 4096] {
            blob(&mut bytes, max)?;
        }
        entries(blob(&mut bytes, ENTRY_BYTES + 4 * ENTRIES)?, |_| {})?;
        require(bytes.is_empty())
    }
    fn read(bytes: &[u8]) -> Result<Self> {
        Self::preflight(bytes)?;
        let page: raw::RecoveryReplayPage = read(bytes)?;
        let mut batches = Vec::new();
        entries(&page.batch_payloads, |entry| batches.push(entry.to_vec()))?;
        Ok(Self {
            profile_version: page.profile_version,
            subscription_handle: page.subscription_handle.to_vec(),
            predecessor_checkpoint: page.predecessor_checkpoint.to_vec(),
            result_checkpoint: page.result_checkpoint.to_vec(),
            continuation_marker: page.continuation_marker.to_vec(),
            catchup_boundary: page.catchup_boundary.to_vec(),
            batch_payloads: batches,
        })
    }
    fn write(&self) -> Result<Vec<u8>> {
        let mut packed = Vec::new();
        for entry in &self.batch_payloads {
            bebop::write_len(&mut packed, entry.len()).map_err(|_| INVALID)?;
            packed.extend_from_slice(entry);
        }
        write(raw::RecoveryReplayPage {
            profile_version: self.profile_version,
            subscription_handle: bebop::SliceWrapper::from_cooked(&self.subscription_handle),
            predecessor_checkpoint: bebop::SliceWrapper::from_cooked(&self.predecessor_checkpoint),
            result_checkpoint: bebop::SliceWrapper::from_cooked(&self.result_checkpoint),
            continuation_marker: bebop::SliceWrapper::from_cooked(&self.continuation_marker),
            catchup_boundary: bebop::SliceWrapper::from_cooked(&self.catchup_boundary),
            batch_payloads: bebop::SliceWrapper::from_cooked(&packed),
        })
    }
}
