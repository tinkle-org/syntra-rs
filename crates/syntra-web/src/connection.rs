//! Protected Syntra 1.0 browser connections, not a native TLS conformance claim.

use std::time::Duration;
use syntra_core::secure_channel::{Carrier, ClientConfig};
use syntra_core::ErrorCode;
use syntra_runtime::ConnectionConfig;

#[cfg(any(test, target_arch = "wasm32"))]
#[path = "connection_time.rs"]
mod time;

#[cfg(target_arch = "wasm32")]
#[path = "connection_browser.rs"]
mod browser;
#[cfg(target_arch = "wasm32")]
pub use browser::{connect, BrowserClient};

pub const ENDPOINT: &str = "/syntra/1.0/ws";
pub const SUBPROTOCOL: &str = "syntra.1.0";

/// Sanitized errors: never include URLs, credentials, JS exception text or keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid browser connection configuration")]
    Configuration,
    #[error("browser connection is unsupported on this platform or in this lifecycle state")]
    Unsupported,
    #[error("browser connection authentication failed")]
    Authentication,
    #[error("browser connection framing rejected")]
    Framing,
    #[error("browser connection resource bound reached")]
    Limit,
    #[error("browser connection operation timed out")]
    Timeout,
    #[error("browser connection closed; unfinished outcomes may be unknown")]
    Closed,
    #[error("browser connection owner shutdown incomplete")]
    ShutdownIncomplete,
}

impl Error {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::Configuration | Self::Framing => ErrorCode::InvalidArgument,
            Self::Unsupported => ErrorCode::Unimplemented,
            Self::Authentication => ErrorCode::Unauthenticated,
            Self::Limit => ErrorCode::ResourceExhausted,
            Self::Timeout => ErrorCode::DeadlineExceeded,
            Self::Closed | Self::ShutdownIncomplete => ErrorCode::Unavailable,
        }
    }
}

impl From<syntra_core::secure_channel::Error> for Error {
    fn from(error: syntra_core::secure_channel::Error) -> Self {
        use syntra_core::secure_channel::Error as E;
        match error {
            E::Invalid => Self::Framing,
            E::Limit => Self::Limit,
            E::Closed => Self::Closed,
            E::Authentication | E::Entropy => Self::Authentication,
        }
    }
}

/// Finite application-owned budgets. Browser/network allocations before the
/// message event, TLS policy, cookies, control frames and compression are not
/// controllable here. The host must enforce TLS 1.3, no cookies and no compression.
#[derive(Clone, Debug)]
pub struct Limits {
    /// Total setup through CoreReady, at most 15 seconds.
    pub attempt: Duration,
    /// Noise and first encrypted hello/confirmation share at most 5 seconds.
    pub establishment: Duration,
    /// Next complete record, including idle wait; at most 24 hours.
    pub record: Duration,
    /// Assembly from first incomplete authenticated plaintext; at most 24 hours.
    pub frame: Duration,
    /// One entire frame's output across all records, at most 10 seconds.
    pub write: Duration,
    /// Owner teardown/join budget after retirement; at most 24 hours.
    pub close: Duration,
    /// Age from before outer WebSocket setup, including idle and suspension.
    pub lifetime: Duration,
    pub receive_messages: usize,
    pub receive_bytes: usize,
    pub buffered_bytes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            attempt: Duration::from_secs(15),
            establishment: Duration::from_secs(5),
            record: Duration::from_secs(30),
            frame: Duration::from_secs(30),
            write: Duration::from_secs(10),
            close: Duration::from_secs(1),
            lifetime: Duration::from_secs(86_400),
            receive_messages: 32,
            receive_bytes: 256 * 1024,
            buffered_bytes: 128 * 1024,
        }
    }
}

impl Limits {
    pub fn validate(&self, runtime: &ConnectionConfig) -> Result<(), Error> {
        runtime.validate().map_err(|_| Error::Configuration)?;
        if [
            self.attempt,
            self.establishment,
            self.record,
            self.frame,
            self.write,
            self.close,
            self.lifetime,
        ]
        .iter()
        .any(|d| d.is_zero() || *d > Duration::from_secs(86_400))
            || self.attempt > Duration::from_secs(15)
            || self.establishment > Duration::from_secs(5)
            || self.write > Duration::from_secs(10)
            || !(1..=1024).contains(&self.receive_messages)
            || !(65_535..=8 * 1024 * 1024).contains(&self.receive_bytes)
            || !(65_535..=8 * 1024 * 1024).contains(&self.buffered_bytes)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Exact protocol selection, checked before constructing a WebSocket. The pin and
/// context come from independent trusted provisioning, never from the peer.
pub fn validate(url: &str, config: &ClientConfig) -> Result<(), Error> {
    let endpoint = url::Url::parse(url).map_err(|_| Error::Configuration)?;
    if endpoint.scheme() != "wss"
        || endpoint.host_str().is_none()
        || endpoint.path() != ENDPOINT
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        // URL parsing normalizes dot segments; do not accept aliases as input.
        || url.split_once("://").is_none_or(|(_, rest)| {
            rest.find('/').is_none_or(|start| &rest[start..] != ENDPOINT)
        })
        || config.context.carrier != Carrier::SecureWebSocket
        || config.server_public_key == [0; 32]
    {
        return Err(Error::Configuration);
    }
    config.context.encode().map_err(|_| Error::Configuration)?;
    match (config.context.mode, config.authorization_key.as_ref()) {
        (syntra_core::secure_channel::Mode::Bootstrap, None) => Ok(()),
        (syntra_core::secure_channel::Mode::Returning, Some(key)) if key.expose() != &[0; 32] => {
            Ok(())
        }
        _ => Err(Error::Configuration),
    }
}

/// Machine-readable support disclosure for JS embeds. No native policy is
/// silently accepted then ignored; there is no custom-root/TLS-option API.
pub const SUPPORT: &str = concat!(
    "Syntra 1.0; NK and NKpsk0 authentication; syntra.1.0 context; provisioned Noise pin; ",
    "encrypted hello; ordered records; bounded post-assembly queues; ",
    "explicit Rust recovery attachment; no automatic replay. ",
    "UNSUPPORTED: native TLS version/root/revocation/ALPN controls, Upgrade header ",
    "inspection, disabling implicit cookies/compression offers (negotiated extensions are rejected), pre-reassembly/network ",
    "buffer limits, Ping/Pong probes, authenticated close, background operation, ",
    "browser durable recovery store, guaranteed JS/engine secret erasure. ",
    "Browser validates TLS and Upgrade; deployment must enforce TLS 1.3+, direct ",
    "host termination, cookie rejection, compression disabled and Origin policy. ",
    "Monotonic deadlines; dual-clock kernel age; hidden/pagehide and unknown elapsed continuity retire the connection. ",
    "Browser clocks are not a trusted suspend-inclusive hardware source. ",
    "Not a full Syntra 1.0 or native WSS conformance claim."
);

#[cfg(test)]
mod tests {
    use super::*;
    use syntra_core::secure_channel::{Context, Mode, Secret32};

    fn config() -> ClientConfig {
        ClientConfig {
            context: Context {
                mode: Mode::Bootstrap,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 0,
                scope: b"scope".to_vec(),
                handle: [0; 8],
                epoch: 0,
            },
            server_public_key: [5; 32],
            authorization_key: None,
        }
    }

    #[test]
    fn selection_rejects_noncanonical_endpoints_and_credential_urls() {
        let good = "wss://example.test/syntra/1.0/ws";
        assert!(validate(good, &config()).is_ok());
        let bad_endpoints = [
            "ws://example.test/syntra/1.0/ws",
            "wss://example.test/invalid/connection",
            "wss://example.test/invalid/nested/connection",
            "wss://user@example.test/syntra/1.0/ws",
            "wss://example.test/syntra/1.0/ws?",
            "wss://example.test/syntra/1.0/ws#",
            "wss://example.test/a/../syntra/1.0/ws",
        ];
        let mut returning = config();
        returning.context.mode = Mode::Returning;
        assert!(validate(good, &returning).is_err());
        returning.context.handle = [1; 8];
        returning.context.epoch = 1;
        returning.authorization_key = Some(Secret32::new([0; 32]));
        assert!(validate(good, &returning).is_err());
        returning.authorization_key = Some(Secret32::new([1; 32]));
        assert!(validate(good, &returning).is_ok());
        for config in [config(), returning] {
            for bad in bad_endpoints {
                assert_eq!(validate(bad, &config), Err(Error::Configuration));
            }
        }
        let mut unpinned = config();
        unpinned.server_public_key = [0; 32];
        assert_eq!(validate(good, &unpinned), Err(Error::Configuration));
    }

    #[test]
    fn each_timer_enforces_its_inclusive_hard_maximum() {
        for (index, seconds) in [15, 5, 86_400, 86_400, 10, 86_400, 86_400]
            .into_iter()
            .enumerate()
        {
            let maximum = Duration::from_secs(seconds);
            for (value, valid) in [
                (Duration::ZERO, false),
                (Duration::from_nanos(1), true),
                (maximum, true),
                (maximum + Duration::from_nanos(1), false),
            ] {
                let mut limits = Limits::default();
                *match index {
                    0 => &mut limits.attempt,
                    1 => &mut limits.establishment,
                    2 => &mut limits.record,
                    3 => &mut limits.frame,
                    4 => &mut limits.write,
                    5 => &mut limits.close,
                    _ => &mut limits.lifetime,
                } = value;
                assert_eq!(
                    limits.validate(&ConnectionConfig::default()).is_ok(),
                    valid,
                    "timer {index}, value {value:?}"
                );
            }
        }
    }

    #[test]
    fn budgets_and_queues_are_finite() {
        let mut limits = Limits::default();
        assert!(limits.validate(&ConnectionConfig::default()).is_ok());
        limits.frame = Duration::ZERO;
        assert_eq!(
            limits.validate(&ConnectionConfig::default()),
            Err(Error::Configuration)
        );
        limits.frame = Duration::from_secs(30);
        limits.receive_messages = 1025;
        assert!(limits.validate(&ConnectionConfig::default()).is_err());
    }
}
