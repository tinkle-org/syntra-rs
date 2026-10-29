//! Host-owned policy bridge for foreign-language embedding.
//!
//! The core validates shape, selects versions, correlates RPCs, enforces
//! deadlines, and observes cancellation. The embedding application resolves
//! authentication, authorization, dispatch, and completion asynchronously.
//!
//! This module defines the completion-token contract used by the production
//! native ABI. Tokens are distinct from wire `request_id` values so late,
//! duplicate, cancelled, and post-close completions resolve deterministically.

use std::time::Duration;

use syntra_core::ErrorCode;

/// Authentication outcome resolved by the host application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// Bind this principal and emit `ServerReady`.
    Allow { principal: String },
    /// Reject the handshake without an oracle.
    Deny { code: ErrorCode },
}

/// Per-request authorization outcome resolved by the host application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny { code: ErrorCode },
}

/// Opaque completion token issued when a request is admitted for dispatch.
///
/// The token identifies the admitted dispatch slot. The wire `request_id`
/// identifies correlation on the transport. Separating them keeps
/// late completions, retries with reused ids, and post-close arrivals
/// unambiguous.
///
/// Token-issuing authority: the embedding application (host-owned dispatch
/// layer) issues the token when it admits a request for dispatch. Tokens
/// MUST be unique per admitted slot and MUST NOT be reused for a distinct
/// admission while the original slot is outstanding.
///
/// Completion-resolution rules (embedding MUST enforce):
/// - Resolve completions by token equality only; do NOT route completions
///   by wire `request_id` after admission.
/// - A result for an unknown or already-completed token is dropped
///   ([`CompletionDisposition::Unknown`]).
/// - A result arriving after the slot deadline is dropped without
///   transmission ([`CompletionDisposition::Expired`]).
/// - A result arriving after handle close is dropped
///   ([`CompletionDisposition::Closed`]).
/// - Wire `request_id` reuse with a different token MUST NOT complete the
///   newer call; only the matching token completes its own slot.
///
/// Integration note: the production C ABI (`syntra-ffi::production`)
/// correlates dispatch/completion by wire `request_id` only
/// (`host_take_pending` / `host_answer`). `CompletionToken` is the
/// embedding-layer contract for disambiguating late/duplicate completions
/// when `request_id` values are reused; it is intentionally not plumbed
/// through the stable C ABI in v1. Threading tokens through the ABI would
/// change `host_take_pending` / `host_answer` signatures (an ABI break)
/// and is out of scope for this change, which is limited to this module.
/// Until such wiring lands, embeddings must keep a `(request_id -> token)`
/// side table and resolve completions by token per the rules above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompletionToken(u64);

impl CompletionToken {
    /// Issues a token value. Call only from the token-issuing authority
    /// (embedding dispatch layer) when admitting a request.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the opaque token value for transport to the completion path.
    /// The value carries no wire meaning; it only identifies the slot.
    pub fn value(self) -> u64 {
        self.0
    }
}

/// A request admitted for application dispatch.
#[derive(Debug, Clone)]
pub struct AdmittedRequest {
    pub token: CompletionToken,
    pub request_id: u64,
    pub method: String,
    pub payload: Vec<u8>,
    pub deadline: Duration,
}

/// Result supplied by the application for an admitted request.
///
/// Invariant: exactly one of `payload` / `error` is present. Construct only
/// via [`HostResult::ok`] / [`HostResult::err`]; field access goes through
/// [`HostResult::token`], [`HostResult::payload`], and [`HostResult::error`]
/// so the invariant cannot be broken by direct construction.
#[derive(Debug, Clone)]
pub struct HostResult {
    token: CompletionToken,
    payload: Option<Vec<u8>>,
    error: Option<(ErrorCode, String)>,
}

impl HostResult {
    pub fn ok(token: CompletionToken, payload: Vec<u8>) -> Self {
        Self {
            token,
            payload: Some(payload),
            error: None,
        }
    }

    pub fn err(token: CompletionToken, code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            token,
            payload: None,
            error: Some((code, message.into())),
        }
    }

    /// Token of the admitted slot this result completes.
    pub fn token(&self) -> CompletionToken {
        self.token
    }

    /// Success payload, when [`HostResult::ok`] constructed this result.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Typed error, when [`HostResult::err`] constructed this result.
    pub fn error(&self) -> Option<&(ErrorCode, String)> {
        self.error.as_ref()
    }
}

/// Resolution of a supplied result against core state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionDisposition {
    /// Result accepted; the terminal frame may be transmitted.
    Accepted,
    /// RPC already expired; the result must not be transmitted.
    Expired,
    /// Unknown or already-completed token; the result is dropped.
    Unknown,
    /// Handle closed; the result is dropped.
    Closed,
}

/// Policy deadlines owned by the deployment.
#[derive(Debug, Clone)]
pub struct PolicyDeadlines {
    /// Maximum time to resolve authentication for one handshake.
    pub auth_timeout: Duration,
    /// Maximum time to resolve authorization for one request.
    pub authz_timeout: Duration,
}

impl Default for PolicyDeadlines {
    fn default() -> Self {
        Self {
            auth_timeout: Duration::from_secs(5),
            authz_timeout: Duration::from_secs(5),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Reference slot table implementing the documented completion-resolution
    /// rules: resolve by token equality only; unknown or already-completed
    /// tokens are dropped (`Unknown`); results past the slot deadline are
    /// dropped (`Expired`); results after handle close are dropped (`Closed`).
    /// Embeddings implement these rules against their own state; this table
    /// exists so the rules themselves are exercised, not just the token
    /// accessors.
    struct ReferenceSlots {
        outstanding: HashMap<CompletionToken, Duration>,
        closed: bool,
    }

    impl ReferenceSlots {
        fn new() -> Self {
            Self {
                outstanding: HashMap::new(),
                closed: false,
            }
        }

        fn admit(&mut self, req: &AdmittedRequest) {
            self.outstanding.insert(req.token, req.deadline);
        }

        fn resolve(&mut self, result: &HostResult, now: Duration) -> CompletionDisposition {
            if self.closed {
                return CompletionDisposition::Closed;
            }
            match self.outstanding.remove(&result.token()) {
                None => CompletionDisposition::Unknown,
                Some(deadline) if now > deadline => CompletionDisposition::Expired,
                Some(_) => CompletionDisposition::Accepted,
            }
        }

        fn close(&mut self) {
            self.closed = true;
        }
    }

    fn admitted(token: u64, request_id: u64, deadline_secs: u64) -> AdmittedRequest {
        AdmittedRequest {
            token: CompletionToken::new(token),
            request_id,
            method: "/example.Echo/Echo".to_string(),
            payload: b"payload".to_vec(),
            deadline: Duration::from_secs(deadline_secs),
        }
    }

    #[test]
    fn completion_resolution_follows_token_rules() {
        let mut slots = ReferenceSlots::new();
        let first = admitted(7, 42, 5);
        slots.admit(&first);

        // Matching token before the deadline completes its own slot.
        let ok = HostResult::ok(first.token, b"ok".to_vec());
        assert_eq!(
            slots.resolve(&ok, Duration::from_secs(1)),
            CompletionDisposition::Accepted
        );
        // The slot is consumed: a duplicate completion is unknown.
        assert_eq!(
            slots.resolve(&ok, Duration::from_secs(1)),
            CompletionDisposition::Unknown
        );
        // A token that was never admitted is unknown.
        let stranger = HostResult::ok(CompletionToken::new(99), b"ok".to_vec());
        assert_eq!(
            slots.resolve(&stranger, Duration::from_secs(1)),
            CompletionDisposition::Unknown
        );

        // Past the slot deadline the result expires without transmission.
        let second = admitted(8, 43, 5);
        slots.admit(&second);
        let late = HostResult::ok(second.token, b"ok".to_vec());
        assert_eq!(
            slots.resolve(&late, Duration::from_secs(6)),
            CompletionDisposition::Expired
        );

        // After handle close every result is dropped, even a fresh one.
        let third = admitted(9, 44, 60);
        slots.admit(&third);
        slots.close();
        let after_close = HostResult::ok(third.token, b"ok".to_vec());
        assert_eq!(
            slots.resolve(&after_close, Duration::from_secs(1)),
            CompletionDisposition::Closed
        );
    }

    #[test]
    fn late_result_for_old_token_cannot_complete_reused_wire_id() {
        let mut slots = ReferenceSlots::new();
        // Same wire `request_id` reused for a second admission.
        let first = admitted(7, 42, 5);
        let second = admitted(8, 42, 5);
        slots.admit(&first);
        let first_result = HostResult::ok(first.token, b"first".to_vec());
        assert_eq!(
            slots.resolve(&first_result, Duration::from_secs(1)),
            CompletionDisposition::Accepted
        );
        slots.admit(&second);
        // The late duplicate for the old token resolves Unknown: it must
        // not complete the second slot, which only token 8 can complete.
        assert_eq!(
            slots.resolve(&first_result, Duration::from_secs(2)),
            CompletionDisposition::Unknown
        );
        let second_result = HostResult::ok(second.token, b"second".to_vec());
        assert_eq!(
            slots.resolve(&second_result, Duration::from_secs(2)),
            CompletionDisposition::Accepted
        );
    }

    #[test]
    fn completion_tokens_distinguish_wire_ids() {
        // Same wire `request_id` reused for two admissions must still resolve
        // by token: distinct tokens identify distinct slots.
        let first = AdmittedRequest {
            token: CompletionToken::new(7),
            request_id: 42,
            method: "/example.Echo/Echo".to_string(),
            payload: b"first".to_vec(),
            deadline: Duration::from_secs(5),
        };
        let second = AdmittedRequest {
            token: CompletionToken::new(8),
            request_id: 42,
            method: "/example.Echo/Echo".to_string(),
            payload: b"second".to_vec(),
            deadline: Duration::from_secs(5),
        };
        assert_ne!(first.token, second.token);
        assert_eq!(first.request_id, second.request_id);

        // Late result for the first slot must not complete the second slot:
        // resolution is by token equality.
        let late = HostResult::ok(first.token, b"ok".to_vec());
        assert_eq!(late.token(), first.token);
        assert_ne!(late.token(), second.token);
        assert_eq!(late.payload(), Some(b"ok".as_slice()));
        assert!(late.error().is_none());

        let err = HostResult::err(second.token, ErrorCode::PermissionDenied, "denied");
        assert_eq!(err.token(), second.token);
        assert!(err.payload().is_none());
        let (code, msg) = err.error().expect("typed error");
        assert_eq!(*code, ErrorCode::PermissionDenied);
        assert_eq!(msg, "denied");
    }

    #[test]
    fn admitted_request_preserves_distinct_token_and_wire_id() {
        let req = AdmittedRequest {
            token: CompletionToken::new(7),
            request_id: 42,
            method: "/example.Echo/Echo".to_string(),
            payload: b"hello".to_vec(),
            deadline: Duration::from_secs(5),
        };
        assert_eq!(req.token.value(), 7);
        assert_eq!(req.request_id, 42);
        assert_ne!(req.token.value(), req.request_id);
    }

    #[test]
    fn deny_decisions_carry_typed_codes() {
        let d = AuthzDecision::Deny {
            code: ErrorCode::PermissionDenied,
        };
        assert!(matches!(d, AuthzDecision::Deny { .. }));
    }
}
