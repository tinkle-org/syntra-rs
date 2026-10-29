//! Reliable-session core contract: validation-only, transport-independent.
//!
//! OPTIONAL `syntra.reliable-session/1` (sessions.md §1H, reliability.md §1C,
//! rpc.md §§1J–1L, handshake.md §2B, capabilities.md SNTR-CAP-008). No network,
//! no payload interpretation beyond equality, no custom crypto, no
//! exactly-once business claims. Wire impact: none (reserved preserved).
//! Compiles for `wasm32-unknown-unknown` (std only, no Tokio).

use crate::error::{ErrorCode, SyntraError};

pub const RELIABLE_SESSION_CAPABILITY: &str = "syntra.reliable-session/1";
pub const SESSION_ID_LEN: usize = 16;
pub const DELIVERY_ID_LEN: usize = 16;
pub const RESUME_CREDENTIAL_LEN: usize = 32;
pub const MAX_RESUME_CREDENTIAL_LEN: usize = 256;
pub const MAX_RELIABLE_PRINCIPAL_LEN: usize = 512;
pub const DEFAULT_MAX_SESSIONS: usize = 1024;
pub const DEFAULT_MAX_RETAINED_RESULTS: usize = 128;
pub const DEFAULT_MAX_RETAINED_BYTES: usize = 1 << 20;
pub const DEFAULT_MAX_TOMBSTONES: usize = 128;
pub const DEFAULT_MAX_RESUME_CREDENTIALS: usize = 1024;
pub const DEFAULT_MAX_CONTROL_QUEUE: usize = 64;
pub const DEFAULT_MAX_CONTROL_BYTES: usize = 64 << 10;
pub const DEFAULT_RESULT_RETENTION_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_TOMBSTONE_RETENTION_MS: u64 = 5 * 60 * 1000;
pub const DEFAULT_RESUME_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;
pub const MIN_IDLE_TIMEOUT_MS: u32 = 2_000;
pub const MAX_IDLE_TIMEOUT_MS: u32 = 300_000;
pub const MIN_KEEPALIVE_MS: u32 = 1_000;
pub const MAX_KEEPALIVE_MS: u32 = 60_000;
pub const DEFAULT_IDLE_TIMEOUT_MS: u32 = 30_000;
pub const DEFAULT_KEEPALIVE_MS: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryId(pub [u8; DELIVERY_ID_LEN]);
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ResumeCredential(pub Vec<u8>);

impl std::fmt::Debug for ResumeCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ResumeCredential")
            .field(&"[REDACTED]")
            .finish()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttachmentEpoch(pub u64);

fn invalid(msg: &str) -> SyntraError {
    SyntraError::Protocol {
        code: ErrorCode::InvalidArgument,
        message: msg.to_string(),
    }
}
fn precondition(msg: &str) -> SyntraError {
    SyntraError::Protocol {
        code: ErrorCode::FailedPrecondition,
        message: msg.to_string(),
    }
}
pub fn validate_session_id(id: &[u8]) -> Result<SessionId, SyntraError> {
    if id.len() != SESSION_ID_LEN {
        return Err(invalid("session id must be 16 bytes"));
    }
    let mut buf = [0u8; SESSION_ID_LEN];
    buf.copy_from_slice(id);
    if buf == [0u8; SESSION_ID_LEN] {
        return Err(invalid("session id must not be all zero"));
    }
    Ok(SessionId(buf))
}
pub fn validate_delivery_id(id: &[u8]) -> Result<DeliveryId, SyntraError> {
    if id.len() != DELIVERY_ID_LEN {
        return Err(invalid("delivery id must be 16 bytes"));
    }
    let mut buf = [0u8; DELIVERY_ID_LEN];
    buf.copy_from_slice(id);
    if buf == [0u8; DELIVERY_ID_LEN] {
        return Err(invalid("delivery id must not be all zero"));
    }
    Ok(DeliveryId(buf))
}
pub fn validate_resume_credential(cred: &[u8]) -> Result<ResumeCredential, SyntraError> {
    if cred.is_empty() || cred.len() > MAX_RESUME_CREDENTIAL_LEN {
        return Err(invalid("resume credential length out of bounds"));
    }
    if cred.len() != RESUME_CREDENTIAL_LEN && cred.len() < 16 {
        return Err(invalid("resume credential too short"));
    }
    if cred.iter().all(|&b| b == 0) {
        return Err(invalid("resume credential must not be all zero"));
    }
    Ok(ResumeCredential(cred.to_vec()))
}
pub fn validate_epoch(epoch: u64) -> Result<AttachmentEpoch, SyntraError> {
    if epoch == 0 {
        return Err(invalid("attachment epoch must be nonzero"));
    }
    Ok(AttachmentEpoch(epoch))
}
pub fn check_epoch_advance(current: u64, proposed: u64) -> Result<(), SyntraError> {
    if proposed == 0 {
        return Err(invalid("attachment epoch must be nonzero"));
    }
    if proposed <= current {
        return Err(precondition("stale attachment epoch; fenced"));
    }
    Ok(())
}
pub fn next_epoch(current: u64) -> Result<u64, SyntraError> {
    current.checked_add(1).ok_or_else(|| SyntraError::Protocol {
        code: ErrorCode::FailedPrecondition,
        message: "attachment epoch exhausted; retire the session".to_string(),
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseProposal {
    pub idle_timeout_ms: u32,
    pub keepalive_interval_ms: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedLease {
    pub idle_timeout_ms: u32,
    pub keepalive_interval_ms: u32,
}
pub fn negotiate_lease(p: LeaseProposal) -> Result<ConfirmedLease, SyntraError> {
    let mut idle = if p.idle_timeout_ms == 0 {
        DEFAULT_IDLE_TIMEOUT_MS
    } else {
        p.idle_timeout_ms
    };
    let mut keepalive = if p.keepalive_interval_ms == 0 {
        DEFAULT_KEEPALIVE_MS
    } else {
        p.keepalive_interval_ms
    };
    if p.idle_timeout_ms != 0 && p.idle_timeout_ms < MIN_IDLE_TIMEOUT_MS {
        return Err(SyntraError::Protocol {
            code: ErrorCode::OutOfRange,
            message: "idle timeout out of range".to_string(),
        });
    }
    if p.keepalive_interval_ms != 0 && p.keepalive_interval_ms < MIN_KEEPALIVE_MS {
        return Err(SyntraError::Protocol {
            code: ErrorCode::OutOfRange,
            message: "keepalive interval out of range".to_string(),
        });
    }
    if idle > MAX_IDLE_TIMEOUT_MS {
        idle = MAX_IDLE_TIMEOUT_MS;
    }
    if keepalive > MAX_KEEPALIVE_MS {
        keepalive = MAX_KEEPALIVE_MS;
    }
    let max_keep = (idle / 2).max(MIN_KEEPALIVE_MS);
    if keepalive >= idle {
        keepalive = max_keep.min(idle.saturating_sub(1).max(1));
    } else if keepalive > max_keep {
        keepalive = max_keep;
    }
    if keepalive == 0 || idle == 0 || keepalive >= idle {
        return Err(invalid("keepalive must be less than idle timeout"));
    }
    Ok(ConfirmedLease {
        idle_timeout_ms: idle,
        keepalive_interval_ms: keepalive,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionSignal {
    Draining,
    GoingAway,
    Overloaded,
    Fenced,
    Expired,
    Revoked,
    IdleTimeout,
}
impl SessionSignal {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::Draining | Self::GoingAway | Self::IdleTimeout => ErrorCode::Unavailable,
            Self::Overloaded => ErrorCode::ResourceExhausted,
            Self::Fenced => ErrorCode::FailedPrecondition,
            Self::Expired | Self::Revoked => ErrorCode::Unauthenticated,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Draining => "draining",
            Self::GoingAway => "going-away",
            Self::Overloaded => "overloaded",
            Self::Fenced => "fenced",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::IdleTimeout => "idle-timeout",
        }
    }
    pub fn parse(name: &str) -> Result<Self, SyntraError> {
        match name {
            "draining" => Ok(Self::Draining),
            "going-away" => Ok(Self::GoingAway),
            "overloaded" => Ok(Self::Overloaded),
            "fenced" => Ok(Self::Fenced),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            "idle-timeout" => Ok(Self::IdleTimeout),
            _ => Err(invalid("unknown session signal")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileOutcome {
    Retained,
    Forgotten,
    Unknown,
    Pending,
}
pub fn check_duplicate_content(
    expected_method: &str,
    expected_payload: &[u8],
    actual_method: &str,
    actual_payload: &[u8],
) -> Result<(), SyntraError> {
    if expected_method != actual_method || expected_payload != actual_payload {
        return Err(precondition(
            "delivery id reused with different content; rejected",
        ));
    }
    Ok(())
}
pub fn validate_delivery_for_session(id: &DeliveryId) -> Result<(), SyntraError> {
    if id.0 == [0u8; DELIVERY_ID_LEN] {
        return Err(invalid("delivery id must not be all zero"));
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlBounds {
    pub max_sessions: usize,
    pub max_retained_results: usize,
    pub max_retained_bytes: usize,
    pub max_tombstones: usize,
    pub max_resume_credentials: usize,
    pub max_control_queue: usize,
    pub max_control_bytes: usize,
    pub result_retention_ms: u64,
    pub tombstone_retention_ms: u64,
    pub resume_lifetime_ms: u64,
}
impl Default for ControlBounds {
    fn default() -> Self {
        Self {
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_retained_results: DEFAULT_MAX_RETAINED_RESULTS,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_tombstones: DEFAULT_MAX_TOMBSTONES,
            max_resume_credentials: DEFAULT_MAX_RESUME_CREDENTIALS,
            max_control_queue: DEFAULT_MAX_CONTROL_QUEUE,
            max_control_bytes: DEFAULT_MAX_CONTROL_BYTES,
            result_retention_ms: DEFAULT_RESULT_RETENTION_MS,
            tombstone_retention_ms: DEFAULT_TOMBSTONE_RETENTION_MS,
            resume_lifetime_ms: DEFAULT_RESUME_LIFETIME_MS,
        }
    }
}
impl ControlBounds {
    pub fn validate(self) -> Result<(), SyntraError> {
        if self.max_sessions == 0
            || self.max_retained_results == 0
            || self.max_tombstones == 0
            || self.max_resume_credentials == 0
            || self.max_control_queue == 0
        {
            return Err(invalid("control bounds must be nonzero"));
        }
        if self.max_control_bytes == 0 || self.max_retained_bytes == 0 {
            return Err(invalid("control byte bounds must be nonzero"));
        }
        if self.result_retention_ms == 0
            || self.tombstone_retention_ms == 0
            || self.resume_lifetime_ms == 0
        {
            return Err(invalid("retention lifetimes must be nonzero"));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_credential_debug_is_redacted() {
        let credential = ResumeCredential(b"unique-sensitive-credential".to_vec());
        assert_eq!(
            format!("{credential:?}"),
            "ResumeCredential(\"[REDACTED]\")"
        );
    }
    #[test]
    fn session_id_shape() {
        assert!(validate_session_id(&vec![7u8; 16]).is_ok());
        assert!(validate_session_id(&[0u8; 16]).is_err());
        assert!(validate_session_id(&[1u8; 15]).is_err());
    }
    #[test]
    fn delivery_id_shape() {
        let id = validate_delivery_id(&vec![9u8; 16]).unwrap();
        assert!(validate_delivery_for_session(&id).is_ok());
        assert!(validate_delivery_id(&[0u8; 16]).is_err());
    }
    #[test]
    fn resume_bounds() {
        assert!(validate_resume_credential(&vec![7u8; 32]).is_ok());
        assert!(validate_resume_credential(&[]).is_err());
        assert!(validate_resume_credential(&vec![0u8; 32]).is_err());
    }
    #[test]
    fn epoch_fencing() {
        assert!(validate_epoch(1).is_ok());
        assert!(validate_epoch(0).is_err());
        assert!(check_epoch_advance(3, 4).is_ok());
        assert!(check_epoch_advance(3, 3).is_err());
        assert_eq!(next_epoch(41).unwrap(), 42);
        assert!(next_epoch(u64::MAX).is_err());
    }
    #[test]
    fn lease_rules() {
        let c = negotiate_lease(LeaseProposal {
            idle_timeout_ms: 0,
            keepalive_interval_ms: 0,
        })
        .unwrap();
        assert!(c.keepalive_interval_ms < c.idle_timeout_ms);
        assert!(negotiate_lease(LeaseProposal {
            idle_timeout_ms: 1,
            keepalive_interval_ms: 1000
        })
        .is_err());
        // Over-maximum proposals clamp to the documented maxima.
        let c = negotiate_lease(LeaseProposal {
            idle_timeout_ms: 400_000,
            keepalive_interval_ms: 0,
        })
        .unwrap();
        assert_eq!(c.idle_timeout_ms, MAX_IDLE_TIMEOUT_MS);
        assert!(c.keepalive_interval_ms < c.idle_timeout_ms);
        let c = negotiate_lease(LeaseProposal {
            idle_timeout_ms: 400_000,
            keepalive_interval_ms: 120_000,
        })
        .unwrap();
        assert_eq!(c.idle_timeout_ms, MAX_IDLE_TIMEOUT_MS);
        assert_eq!(c.keepalive_interval_ms, MAX_KEEPALIVE_MS);
        assert!(c.keepalive_interval_ms < c.idle_timeout_ms);
    }
    #[test]
    fn signals_map() {
        assert_eq!(
            SessionSignal::Overloaded.code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(SessionSignal::Fenced.code(), ErrorCode::FailedPrecondition);
        assert!(SessionSignal::parse("nope").is_err());
    }
    #[test]
    fn duplicate_content() {
        assert!(check_duplicate_content("/a/B/C", b"one", "/a/B/C", b"one").is_ok());
        assert!(check_duplicate_content("/a/B/C", b"one", "/a/B/C", b"two").is_err());
    }
}
