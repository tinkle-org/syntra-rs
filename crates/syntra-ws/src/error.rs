//! Transport-level errors (mapped to Syntra codes by the connection).

use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum TransportError {
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("insecure transport denied: {0}")]
    InsecureDenied(String),
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("upgrade rejected: {0}")]
    UpgradeRejected(String),
    #[error("subprotocol mismatch: {0}")]
    Subprotocol(String),
    #[error("tls verification failed: {0}")]
    Tls(String),
    #[error("message too big")]
    TooBig,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("closed: {0}")]
    Closed(String),
    #[error("io: {0}")]
    Io(String),
}

impl TransportError {
    /// Best-effort mapping to a Syntra error for uniform reporting.
    pub fn to_syntra_error(&self) -> syntra_core::SyntraError {
        use syntra_core::{ErrorCode, SyntraError};
        match self {
            Self::InvalidUrl(m) | Self::Protocol(m) => SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: m.clone(),
            },
            Self::InsecureDenied(m) => SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: m.clone(),
            },
            Self::Subprotocol(m) => SyntraError::Handshake {
                code: ErrorCode::FailedPrecondition,
                message: m.clone(),
            },
            // TLS endpoint validation precedes Syntra authentication. A TLS
            // failure is not rejection of ClientHello.credential.
            Self::Tls(m) => SyntraError::Unavailable(format!("tls failure: {m}")),
            Self::TooBig => SyntraError::ResourceExhausted("message too big".to_string()),
            Self::UpgradeRejected(m) | Self::Connect(m) => SyntraError::Unavailable(m.clone()),
            Self::Closed(m) => SyntraError::Closed(m.clone()),
            Self::Io(m) => SyntraError::Transport(m.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn tls_failure_is_unavailable_not_syntra_authentication() {
        let error = super::TransportError::Tls("certificate rejected".into()).to_syntra_error();
        assert_eq!(error.code(), syntra_core::ErrorCode::Unavailable);
        assert!(!matches!(error, syntra_core::SyntraError::Handshake { .. }));
    }
}
