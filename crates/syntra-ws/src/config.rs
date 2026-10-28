//! Endpoint + TLS policy configuration.

use std::time::Duration;

/// WebSocket endpoint configuration.
#[derive(Debug, Clone)]
pub struct WsConfig {
    /// Full URL, e.g. `wss://gateway.example.com/syntra/v1/ws`.
    /// The path MUST be `/syntra/v1/ws` (case-sensitive, no trailing slash
    /// variant unless the deployment documents aliasing).
    /// Query strings (including empty ones) are not supported; credentials
    /// belong only in `ClientHello.credential`, never in the Upgrade target.
    pub url: String,
    /// When false (default), only `wss://` is accepted. Set true only for
    /// loopback endpoints (`ws://127.0.0.1/...`); production
    /// builds MUST NOT enable it.
    pub allow_insecure: bool,
    /// Expected host for TLS hostname verification is derived from the URL;
    /// this override exists only for tests with custom resolvers and
    /// changes only the `Host` authority the native client sends (include
    /// the port when needed). It does NOT override SNI or TLS verification.
    pub sni_override: Option<String>,
    /// TCP + TLS + WS Upgrade timeout.
    pub connect_timeout: Duration,
    /// Close grace period for in-flight results (SNTR-HS-006/013).
    pub close_grace: Duration,
    /// Ping interval for transport liveness (WS section 1I).
    pub ping_interval: Duration,
    /// Pong latency allowance after each Ping interval: silence longer than
    /// `ping_interval + pong_timeout` closes the connection (typically code
    /// 1001) with `UNAVAILABLE` to in-flight RPCs.
    pub pong_timeout: Duration,
    /// Bound for one outbound write: exceeding it closes a slow receiver
    /// (typically 1001) instead of queueing unboundedly (WS section 1L).
    pub write_grace: Duration,
}

impl WsConfig {
    pub fn secure(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            allow_insecure: false,
            sni_override: None,
            connect_timeout: Duration::from_secs(10),
            close_grace: Duration::from_secs(2),
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            write_grace: Duration::from_secs(5),
        }
    }

    /// Development-only plaintext endpoint. Emits an insecure-mode warning
    /// at connect time and refuses non-loopback hosts, even with
    /// `allow_insecure` set (defense against accidental public plaintext).
    pub fn insecure_dev(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            allow_insecure: true,
            sni_override: None,
            connect_timeout: Duration::from_secs(10),
            close_grace: Duration::from_secs(2),
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            write_grace: Duration::from_secs(5),
        }
    }
}

/// Parsed + validated endpoint.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub is_secure: bool,
}

impl Endpoint {
    /// HTTP Host authority, preserving IPv6 brackets and non-default ports.
    pub fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    pub fn parse(
        url_str: &str,
        allow_insecure: bool,
    ) -> Result<Self, crate::error::TransportError> {
        let url = url::Url::parse(url_str)
            .map_err(|e| crate::error::TransportError::InvalidUrl(format!("invalid url: {e}")))?;
        // Credentials MUST NOT travel in URL/query (SNTR-ASEC-003, SNTR-TSEC-021).
        if !url.username().is_empty() || url.password().is_some() {
            return Err(crate::error::TransportError::InvalidUrl(
                "credentials must not appear in the URL".to_string(),
            ));
        }
        if url.query().is_some() {
            return Err(crate::error::TransportError::InvalidUrl(
                "query strings are not supported".to_string(),
            ));
        }
        let scheme = url.scheme().to_string();
        let is_secure = match scheme.as_str() {
            "wss" => true,
            "ws" => {
                if !allow_insecure {
                    return Err(crate::error::TransportError::InsecureDenied(
                        "ws:// requires explicit insecure-dev opt-in".to_string(),
                    ));
                }
                false
            }
            _ => {
                return Err(crate::error::TransportError::InvalidUrl(format!(
                    "scheme must be ws or wss, got {scheme}"
                )))
            }
        };
        let path = url.path().to_string();
        if path != crate::ENDPOINT_PATH {
            return Err(crate::error::TransportError::InvalidUrl(format!(
                "path must be {}, got {path}",
                crate::ENDPOINT_PATH
            )));
        }
        let host = url.host_str().unwrap_or("").to_string();
        if host.is_empty() {
            return Err(crate::error::TransportError::InvalidUrl(
                "missing host".to_string(),
            ));
        }
        // A development opt-in never authorizes credentials over public
        // plaintext. Inspect the parsed host, not a spoofable string prefix.
        if !is_secure && !url.host().is_some_and(is_loopback) {
            return Err(crate::error::TransportError::InsecureDenied(
                "plaintext WS is restricted to loopback hosts".to_string(),
            ));
        }
        Ok(Self {
            scheme,
            host,
            port: url.port(),
            path,
            is_secure,
        })
    }
}

fn is_loopback(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(name) => name == "localhost",
        url::Host::Ipv4(ip) => std::net::IpAddr::V4(ip).is_loopback(),
        url::Host::Ipv6(ip) => std::net::IpAddr::V6(ip).is_loopback(),
    }
}

/// Browser establishment has its own budget, before the Syntra handshake
/// timer exists. Dropping ws_stream_wasm's connect future cancels the socket
/// attempt and unregisters its callbacks (the library's cancellation guard).
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) async fn connect_with_timeout<T>(
    connect: impl std::future::Future<Output = Result<T, crate::TransportError>>,
    timeout: Duration,
) -> Result<T, crate::TransportError> {
    tokio::select! {
        biased;
        result = connect => result,
        _ = syntra_runtime::sleep_for(timeout) => Err(crate::TransportError::Connect("ws connect timed out".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_deadline_cancels_pending_establishment() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = Dropped(dropped.clone());
        let attempt = async move {
            let _guard = guard;
            std::future::pending::<Result<(), crate::TransportError>>().await
        };
        let result = connect_with_timeout(attempt, Duration::from_millis(10)).await;
        assert!(matches!(result, Err(crate::TransportError::Connect(_))));
        assert!(
            dropped.load(Ordering::SeqCst),
            "attempt must be dropped, not detached"
        );
    }

    #[tokio::test]
    async fn completed_establishment_wins_deadline_tie() {
        assert!(connect_with_timeout(async { Ok(()) }, Duration::ZERO)
            .await
            .is_ok());
    }

    #[test]
    fn rejects_credentials_in_url() {
        assert!(Endpoint::parse("wss://user:pass@h/syntra/v1/ws", false).is_err());
        assert!(Endpoint::parse("wss://h/syntra/v1/ws?token=abc", false).is_err());
    }

    #[test]
    fn rejects_every_query_including_encoded_keys_and_empty_queries() {
        for query in [
            "?%74oken=x",
            "?key=x",
            "?x=secret-value",
            "?",
            "?harmless=1",
        ] {
            assert!(
                matches!(
                    Endpoint::parse(&format!("wss://h/syntra/v1/ws{query}"), false),
                    Err(crate::TransportError::InvalidUrl(_))
                ),
                "query must be rejected: {query}"
            );
        }
    }

    #[test]
    fn enforces_path_and_scheme() {
        assert!(Endpoint::parse("wss://h/syntra/v1/ws", false).is_ok());
        assert!(Endpoint::parse("wss://h/syntra/v1/ws/", false).is_err());
        assert!(Endpoint::parse("ws://h/syntra/v1/ws", false).is_err());
        assert!(Endpoint::parse("ws://127.0.0.1/syntra/v1/ws", true).is_ok());
        assert!(Endpoint::parse("https://h/syntra/v1/ws", false).is_err());
    }

    #[test]
    fn authority_preserves_non_default_ports_and_ipv6_brackets() {
        for (url, authority) in [
            ("wss://example.com:8443/syntra/v1/ws", "example.com:8443"),
            ("ws://[::1]:8080/syntra/v1/ws", "[::1]:8080"),
            ("wss://[::1]/syntra/v1/ws", "[::1]"),
            ("wss://example.com:443/syntra/v1/ws", "example.com"),
        ] {
            assert_eq!(Endpoint::parse(url, true).unwrap().authority(), authority);
        }
    }

    #[test]
    fn plaintext_requires_loopback_even_with_dev_opt_in() {
        for host in [
            "example.com",
            "127.evil.example",
            "127.0.0.1.example.com",
            "localhost.example.com",
            "192.168.1.2",
            "0.0.0.0",
            "[::]",
            "[2001:db8::1]",
            "[::ffff:127.0.0.1]",
        ] {
            let cfg = WsConfig::insecure_dev(format!("ws://{host}/syntra/v1/ws"));
            assert!(
                matches!(
                    Endpoint::parse(&cfg.url, cfg.allow_insecure),
                    Err(crate::error::TransportError::InsecureDenied(_))
                ),
                "plaintext must be denied for {host}"
            );
            assert!(Endpoint::parse(&format!("wss://{host}/syntra/v1/ws"), false).is_ok());
        }
    }

    #[test]
    fn plaintext_accepts_only_parsed_loopback_addresses_and_localhost() {
        for host in [
            "localhost",
            "LOCALHOST",
            "127.0.0.1",
            "127.23.45.67",
            "[::1]",
            "[0:0:0:0:0:0:0:1]",
        ] {
            let url = format!("ws://{host}/syntra/v1/ws");
            assert!(Endpoint::parse(&url, true).is_ok(), "loopback: {host}");
            assert!(matches!(
                Endpoint::parse(&url, false),
                Err(crate::error::TransportError::InsecureDenied(_))
            ));
            assert!(Endpoint::parse(&format!("ws://u:p@{host}/syntra/v1/ws"), true).is_err());
            assert!(Endpoint::parse(&format!("{url}?token=abc"), true).is_err());
        }
    }
}
