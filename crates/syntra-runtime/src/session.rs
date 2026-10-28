//! Connection-bound sessions (SNTR-SESS-001/003).
//!
//! Default v1 rule: the session lifetime EQUALS the connection lifetime.
//! A session is established implicitly when a connection reaches ACTIVE
//! (principal bound); it ends when the connection closes. No state
//! survives except application-defined durable state outside Syntra.
//!
//! What this module does NOT do (open blockers, recorded not invented):
//! - resumption across connections (blocker 2): `resume()` always fails
//!   with `UNAUTHENTICATED` documenting SNTR-SESS-006; any resumption
//!   needs an approved RFC capability, which does not exist in v1;
//! - `connection_id` is a per-connection diagnostic, never an
//!   authenticator, resume token, or session handle (SNTR-SESS-002).
//!   `SessionManager` keys sessions by it only to scope them to the
//!   connection, and rejects it wherever a credential is expected.
//!
//! Authentication hooks are generic: a `Principal` is an opaque subject
//! string bound at `ServerReady`. No user/account/chat types exist here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use syntra_core::{ErrorCode, SyntraError};

/// Opaque authenticated principal bound for one connection
/// (SNTR-AUTH-007). The `subject` is deployment-defined (e.g. a service
/// identity or token fingerprint); the core never interprets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub subject: String,
}

impl Principal {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
        }
    }

    /// Anonymous principal for hosts that allow unauthenticated attempts
    /// with least privilege (handshake.md section 2A.6).
    pub fn anonymous() -> Self {
        Self {
            subject: "anonymous".to_string(),
        }
    }
}

/// Generic authentication failure. Messages MUST stay generic (no reason
/// oracle distinguishing valid/invalid principals beyond the code).
#[derive(Debug, Clone)]
pub struct AuthError {
    pub code: ErrorCode,
    pub message: String,
}

impl AuthError {
    /// Credential missing, invalid, expired, or revoked.
    pub fn unauthenticated() -> Self {
        Self {
            code: ErrorCode::Unauthenticated,
            message: "credential not accepted".to_string(),
        }
    }

    /// Valid credential, insufficient access.
    pub fn denied() -> Self {
        Self {
            code: ErrorCode::PermissionDenied,
            message: "access denied".to_string(),
        }
    }
}

/// Generic credential validator. Implementations check the opaque
/// `ClientHello.credential` bytes and bind a `Principal`; they MUST NOT
/// log the credential and MUST NOT encode principal/session information
/// into the `connection_id` (that is generated separately).
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError>;
}

/// Allows only empty credentials, binding an anonymous principal with
/// least privilege. All other attempts fail closed.
#[derive(Debug, Default)]
pub struct AllowAnonymous;

impl Authenticator for AllowAnonymous {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        if credential.is_empty() {
            Ok(Principal::anonymous())
        } else {
            Err(AuthError::unauthenticated())
        }
    }
}

/// Rejects every attempt. Useful for tests and locked-down deployments.
#[derive(Debug, Default)]
pub struct RejectAll;

impl Authenticator for RejectAll {
    fn authenticate(&self, _credential: &[u8]) -> Result<Principal, AuthError> {
        Err(AuthError::unauthenticated())
    }
}

/// Accepts exactly one static bearer token (constant-time compare),
/// binding the configured subject. The token bytes live only in this
/// struct; callers MUST zeroize/drop them when rotated.
pub struct StaticToken {
    token: Vec<u8>,
    subject: String,
}

impl std::fmt::Debug for StaticToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticToken")
            .field("token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl StaticToken {
    pub fn new(token: Vec<u8>, subject: impl Into<String>) -> Self {
        Self {
            token,
            subject: subject.into(),
        }
    }
}

impl Authenticator for StaticToken {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        // Empty credentials are anonymous attempts, never bearer tokens.
        // Keep the infallible constructor compatible, but fail closed for
        // an empty/misconfigured token on every authentication attempt.
        if self.token.is_empty() || credential.len() != self.token.len() {
            return Err(AuthError::unauthenticated());
        }
        let mut diff = 0u8;
        for (a, b) in credential.iter().zip(self.token.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(Principal::new(self.subject.clone()))
        } else {
            Err(AuthError::unauthenticated())
        }
    }
}

/// One connection-bound session: exactly one `Principal` for exactly one
/// connection (SNTR-SESS-007). Dies with the connection (SNTR-SESS-003).
#[derive(Debug, Clone)]
pub struct Session {
    /// Per-connection diagnostic id (SNTR-SESS-002). Never authority.
    pub connection_id: String,
    pub principal: Principal,
    pub version: u32,
    pub established_at: Instant,
}

/// Owns the connection-bound sessions of one host. Sessions are keyed by
/// `connection_id` and discarded on close; there is deliberately no
/// lookup-by-token and no resume path (SNTR-SESS-006).
#[derive(Debug, Default, Clone)]
pub struct SessionManager {
    inner: Arc<Mutex<HashMap<String, Session>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn bind(&self, session: Session) {
        self.inner
            .lock()
            .unwrap()
            .insert(session.connection_id.clone(), session);
    }

    pub fn unbind(&self, connection_id: &str) {
        self.inner.lock().unwrap().remove(connection_id);
    }

    pub fn get(&self, connection_id: &str) -> Option<Session> {
        self.inner.lock().unwrap().get(connection_id).cloned()
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Resumption is not available in default v1 (SNTR-SESS-006; open
    /// blocker 2). Always fails; a future RFC capability would define
    /// the token format, lifetime, rotation, replay window, restored
    /// state, and revocation transport. Callers MUST start a fresh
    /// handshake with a fresh credential instead.
    pub fn resume(&self, _token: &[u8]) -> Result<Session, SyntraError> {
        Err(SyntraError::Handshake {
            code: ErrorCode::Unauthenticated,
            message: "session resumption requires a negotiated RFC capability (none in v1)"
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_token_debug_redacts_credentials() {
        let auth = StaticToken::new(b"unique-secret".to_vec(), "svc-a");
        let debug = format!("{auth:?}");
        assert!(!debug.contains("unique-secret"));
        assert!(
            !debug.contains("117, 110, 105"),
            "byte arrays are secrets too"
        );
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn empty_static_token_fails_closed() {
        let auth = StaticToken::new(vec![], "svc-a");
        assert!(auth.authenticate(b"").is_err());
        assert!(auth.authenticate(b"nonempty").is_err());
    }

    #[test]
    fn anonymous_policy() {
        let a = AllowAnonymous;
        assert!(a.authenticate(b"").is_ok());
        assert!(a.authenticate(b"x").is_err());
    }

    #[test]
    fn static_token_round_trip() {
        let a = StaticToken::new(b"secret".to_vec(), "svc-a");
        assert_eq!(
            a.authenticate(b"secret").unwrap().subject,
            "svc-a".to_string()
        );
        assert!(a.authenticate(b"wrong!").is_err());
        assert!(a.authenticate(b"short").is_err());
    }

    #[test]
    fn resumption_unavailable() {
        let m = SessionManager::new();
        assert!(m.resume(b"anything").is_err());
    }
}
