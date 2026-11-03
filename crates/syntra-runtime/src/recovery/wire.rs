//! Accepted RFC 0006 §11 wire adapter (syntra@8ede3810b29fbba4d0e6ae6751a0025ceedda140).
//!
//! Host configuration attaches this binding to admitted Core RPCs and a managed
//! notification worker. Business semantics and durable provider history remain
//! application-owned. Session close discards connection-local confirmation and
//! routing; Core validates its envelope, binds the principal and bounds output.
//!
//! Provider callbacks are synchronous, fast and bounded. They cannot be forcibly
//! interrupted: deadlines are checked before/after callbacks, before exposing
//! results. They must not perform blocking I/O. Durable issued bindings belong
//! to the source, not this volatile session or its checked handle counters.

#[path = "wire_codec.rs"]
pub mod codec;
#[path = "wire_host.rs"]
mod host;
#[path = "wire_provider.rs"]
mod provider;

pub use super::driver::StoredBatch;
pub use crate::session::Principal;
pub use host::{QueueCounts, RecoveryHostSession, RecoveryService};
pub use provider::{
    AuthorizationHook, PageBudget, ProviderLoss, ProviderPage, ProviderSnapshot, ProviderStream,
    RecoverySource,
};

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;

use std::time::Duration;
use syntra_core::ErrorCode;

pub const CAPABILITY: &str = "syntra.update-recovery/1";
pub const PROFILE_VERSION: u32 = 1;
pub const NEGOTIATE: &str = "/syntra.v1.UpdateRecovery/Negotiate";
pub const SUBSCRIBE: &str = "/syntra.v1.UpdateRecovery/Subscribe";
pub const REPLAY: &str = "/syntra.v1.UpdateRecovery/Replay";
pub const CATCH_UP: &str = "/syntra.v1.UpdateRecovery/CatchUp";
pub const CONFIRM: &str = "/syntra.v1.UpdateRecovery/Confirm";
pub const SNAPSHOT_CONFIRM: &str = "/syntra.v1.UpdateRecovery/SnapshotConfirm";
pub const SNAPSHOT_OFFER: &str = "/syntra.v1.UpdateRecovery/SnapshotOffer";
pub const SNAPSHOT_FETCH: &str = "/syntra.v1.UpdateRecovery/SnapshotFetch";
pub const UNSUBSCRIBE: &str = "/syntra.v1.UpdateRecovery/Unsubscribe";
pub const METHODS: [&str; 9] = [
    NEGOTIATE,
    SUBSCRIBE,
    REPLAY,
    CATCH_UP,
    CONFIRM,
    SNAPSHOT_CONFIRM,
    SNAPSHOT_OFFER,
    SNAPSHOT_FETCH,
    UNSUBSCRIBE,
];

/// Typed, non-sensitive errors; the parent maps `code()` into RpcError.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    #[error("unknown recovery operation")]
    Unimplemented,
    #[error("invalid RPC method")]
    InvalidArgument,
    #[error("recovery precondition failed")]
    FailedPrecondition,
    #[error("recovery authorization denied")]
    PermissionDenied,
    #[error("recovery principal unavailable")]
    Unauthenticated,
    #[error("recovery resource bound reached")]
    ResourceExhausted,
    #[error("provider replay retention unavailable")]
    ProviderRetentionMiss,
    #[error("recovery deadline expired")]
    DeadlineExceeded,
    #[error("recovery connection closed")]
    Unavailable,
    #[error("invalid recovery provider result")]
    Internal,
}

impl ProviderError {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::Unimplemented => ErrorCode::Unimplemented,
            Self::InvalidArgument => ErrorCode::InvalidArgument,
            Self::FailedPrecondition | Self::ProviderRetentionMiss => ErrorCode::FailedPrecondition,
            Self::PermissionDenied => ErrorCode::PermissionDenied,
            Self::Unauthenticated => ErrorCode::Unauthenticated,
            Self::ResourceExhausted => ErrorCode::ResourceExhausted,
            Self::DeadlineExceeded => ErrorCode::DeadlineExceeded,
            Self::Unavailable => ErrorCode::Unavailable,
            Self::Internal => ErrorCode::Internal,
        }
    }
}

/// Deployment bounds. Public configuration is validated by `validate` and `new`.
/// Numeric profile ceilings can be narrowed, never widened. The pending RPC
/// default is 16. A stricter profile quota does not change Core's separate
/// supported-capacity floor of 16.
/// Additional local caps bound connections, retired-handle slots, reply caches,
/// and tiny notifications (a byte bound alone is not a count bound).
/// The offered-checkpoint ledger independently uses the per-stream byte/count
/// caps. Reserved controls are separately bounded by admitted slots and the
/// 4096-byte boundary / 256-byte reason caps, so a full data queue cannot hide
/// a terminal signal. Transient page assembly is one bounded page per operation.
#[derive(Debug, Clone)]
pub struct RecoveryLimits {
    pub subscriptions_per_connection: usize,
    pub subscriptions_per_principal: usize,
    pub pending_rpcs_per_connection: usize,
    pub queued_bytes_per_stream: usize,
    pub queued_bytes_per_connection: usize,
    pub queued_messages_per_stream: usize,
    pub replay_batches: usize,
    pub replay_bytes: usize,
    pub snapshot_page_bytes: usize,
    pub snapshot_pages: u32,
    pub default_deadline: Duration,
    pub max_connections: usize,
    pub max_connections_per_principal: usize,
    /// Active plus retired slots; exhaustion requires a fresh connection.
    pub handles_per_connection: usize,
    /// Shared per-connection retention, including replay/acceptance/descriptor.
    pub retained_reply_bytes: usize,
    pub retained_replies: usize,
    pub reply_ttl: Duration,
    /// Bounded exact retry budget per retained reply.
    pub reply_retries: u32,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            subscriptions_per_connection: 64,
            subscriptions_per_principal: 256,
            pending_rpcs_per_connection: 16,
            queued_bytes_per_stream: 262_144,
            queued_bytes_per_connection: 1_048_576,
            queued_messages_per_stream: 256,
            replay_batches: 64,
            replay_bytes: 262_144,
            snapshot_page_bytes: 262_144,
            snapshot_pages: 256,
            default_deadline: Duration::from_secs(5),
            max_connections: 1024,
            max_connections_per_principal: 16,
            handles_per_connection: 1024,
            retained_reply_bytes: 1_048_576,
            retained_replies: 256,
            reply_ttl: Duration::from_secs(30),
            reply_retries: 8,
        }
    }
}

impl RecoveryLimits {
    pub fn validate(&self) -> Result<(), ProviderError> {
        let bounds = [
            (self.subscriptions_per_connection, 64),
            (self.subscriptions_per_principal, 256),
            (self.queued_bytes_per_stream, 262_144),
            (self.queued_bytes_per_connection, 1_048_576),
            (self.queued_messages_per_stream, 4096),
            (self.replay_batches, 64),
            (self.replay_bytes, 262_144),
            (self.snapshot_page_bytes, 262_144),
            (self.snapshot_pages as usize, 256),
            (self.max_connections, 65_536),
            (self.max_connections_per_principal, 1024),
            (self.handles_per_connection, 65_536),
            (self.retained_reply_bytes, 16 * 1_048_576),
            (self.retained_replies, 4096),
            (self.reply_retries as usize, 1024),
        ];
        if bounds.iter().any(|&(v, max)| v == 0 || v > max)
            || !(1..=16).contains(&self.pending_rpcs_per_connection)
            || self.handles_per_connection < self.subscriptions_per_connection
            || self.default_deadline.is_zero()
            || self.default_deadline > Duration::from_secs(5)
            || self.reply_ttl.is_zero()
            || self.reply_ttl > Duration::from_secs(3600)
        {
            return Err(ProviderError::FailedPrecondition);
        }
        Ok(())
    }
}
