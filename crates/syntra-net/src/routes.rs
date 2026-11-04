//! Explicit, bounded client route composition. No discovery, redirects, DNS,
//! carrier downgrade, authentication fallback, or internal retry loop.
//!
//! Pass [`client_routes`]'s connector directly to `Network::client` or
//! `ReconnectingClient::new`. Only those owners decide whether an error permits
//! another attempt. Each polled attempt selects one route round-robin, obtains
//! fresh inputs, and continues one absolute budget through socket/proxy, TLS,
//! WebSocket Upgrade, Noise and protected message readiness. Setup stays inline;
//! cancelling the future drops its partial connection, without detached tasks.
//!
//! `cross-carrier-candidate` adds an explicit permitted-carrier policy and a
//! budget-aware connector for `Network::client_with_budget` or
//! `ReconnectingClient::new_with_budget`. The homogeneous constructor retains its
//! same-carrier checks even when the candidate is compiled. Neither constructor
//! owns retries or replays requests into a replacement connection.
//!
//! `http` additionally exposes the unaccepted HTTP/HTTPS candidate, using actual
//! candidate bindings 4/5, never relabelling TCP/WS or inferring Noise trust from
//! an HTTP authority. Both lanes use one endpoint, policy and original budget.

use crate::{pump, tcp, ClientHandle, Error, EstablishmentBudget, Limits};
use std::{fmt, future::Future, net::SocketAddr, pin::Pin, sync::Arc, sync::Mutex};
use syntra_core::secure_channel::{Carrier, ClientConfig};
use syntra_runtime::ConnectionConfig;

#[cfg(feature = "http")]
use crate::http::{self, Authority};
#[cfg(feature = "proxy")]
use crate::proxy::{self, ProxyConfig, ProxyTarget};
#[cfg(any(feature = "websocket", feature = "http"))]
use crate::tls;
#[cfg(feature = "websocket")]
use crate::websocket;
#[cfg(all(feature = "http", feature = "proxy"))]
mod forward;

/// Independently bounds both the active route list and its entire allowlist.
pub const MAX_ROUTES: usize = 256;

/// Secret-free allowlist identity. Proxy identities include BOTH the explicitly
/// dialed proxy socket and the destination requested from it. WSS URL authority
/// is independent of the provisioned direct socket, but must equal a tunnel's
/// target. Allowlisting one authority never allows another URL or carrier.
///
/// Debug is deliberately redacted even before validation: an invalid URL might
/// contain userinfo. HTTP/HTTPS variants require the isolated `http` candidate
/// feature; proxied plaintext WS is never accepted.
#[derive(Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp(SocketAddr),
    #[cfg(feature = "proxy")]
    TcpProxy {
        proxy: SocketAddr,
        target: ProxyTarget,
    },
    #[cfg(feature = "websocket")]
    Ws {
        address: SocketAddr,
        url: String,
    },
    #[cfg(feature = "websocket")]
    Wss {
        address: SocketAddr,
        url: String,
    },
    #[cfg(all(feature = "websocket", feature = "proxy"))]
    WssProxy {
        proxy: SocketAddr,
        target: ProxyTarget,
        url: String,
    },
    #[cfg(feature = "http")]
    Http {
        address: SocketAddr,
        authority: Authority,
    },
    #[cfg(feature = "http")]
    Https {
        address: SocketAddr,
        authority: Authority,
    },
    #[cfg(all(feature = "http", feature = "proxy"))]
    HttpProxy {
        proxy: SocketAddr,
        target: ProxyTarget,
        authority: Authority,
    },
    #[cfg(all(feature = "http", feature = "proxy"))]
    HttpsProxy {
        proxy: SocketAddr,
        target: ProxyTarget,
        authority: Authority,
    },
    #[cfg(all(feature = "http", feature = "proxy"))]
    HttpForward {
        proxy: SocketAddr,
        target: ProxyTarget,
        authority: Authority,
    },
}

impl Endpoint {
    pub fn carrier(&self) -> Carrier {
        match self {
            Self::Tcp(_) => Carrier::Tcp,
            #[cfg(feature = "proxy")]
            Self::TcpProxy { .. } => Carrier::Tcp,
            #[cfg(feature = "websocket")]
            Self::Ws { .. } => Carrier::WebSocket,
            #[cfg(feature = "websocket")]
            Self::Wss { .. } => Carrier::SecureWebSocket,
            #[cfg(all(feature = "websocket", feature = "proxy"))]
            Self::WssProxy { .. } => Carrier::SecureWebSocket,
            #[cfg(feature = "http")]
            Self::Http { .. } => Carrier::Http,
            #[cfg(feature = "http")]
            Self::Https { .. } => Carrier::Https,
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpProxy { .. } | Self::HttpForward { .. } => Carrier::Http,
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpsProxy { .. } => Carrier::Https,
        }
    }

    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Tcp(address) => valid_socket(*address),
            #[cfg(feature = "proxy")]
            Self::TcpProxy { proxy, target } => {
                valid_socket(*proxy)?;
                // ProxyTarget is syntactically validated, but its IP form also
                // needs the same destination policy as a direct socket.
                if let Ok(address) = target.authority().parse() {
                    valid_socket(address)?;
                }
                Ok(())
            }
            #[cfg(feature = "websocket")]
            Self::Ws { address, url } => {
                valid_socket(*address)?;
                let parsed = valid_url(url, Carrier::WebSocket)?;
                let local = match parsed.host() {
                    Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                    Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                    Some(url::Host::Domain(name)) => name == "localhost",
                    None => false,
                };
                if !address.ip().is_loopback() || !local {
                    return Err(Error::Configuration);
                }
                Ok(())
            }
            #[cfg(feature = "websocket")]
            Self::Wss { address, url } => {
                valid_socket(*address)?;
                valid_url(url, Carrier::SecureWebSocket)?;
                Ok(())
            }
            #[cfg(all(feature = "websocket", feature = "proxy"))]
            Self::WssProxy { proxy, target, url } => {
                valid_socket(*proxy)?;
                let parsed = valid_url(url, Carrier::SecureWebSocket)?;
                let authority = tls::TlsAuthority::from_url(&parsed)?;
                let expected = match authority.host().parse() {
                    Ok(ip) => ProxyTarget::ip(ip, authority.port())?,
                    Err(_) => ProxyTarget::hostname(authority.host(), authority.port())?,
                };
                if *target != expected {
                    return Err(Error::Configuration);
                }
                Ok(())
            }
            #[cfg(feature = "http")]
            Self::Http { address, authority } | Self::Https { address, authority } => {
                valid_socket(*address)?;
                valid_http_authority(authority)
            }
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpProxy {
                proxy,
                target,
                authority,
            }
            | Self::HttpsProxy {
                proxy,
                target,
                authority,
            }
            | Self::HttpForward {
                proxy,
                target,
                authority,
            } => {
                valid_socket(*proxy)?;
                valid_http_authority(authority)?;
                if target.authority() != authority.as_str() {
                    return Err(Error::Configuration);
                }
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("carrier", &self.carrier())
            .finish_non_exhaustive()
    }
}

/// Connection path plus application-owned proxy secrets/TLS policy. Arc shares
/// immutable configuration, not live TLS/Noise state or cloned credentials.
#[derive(Clone)]
pub enum Route {
    Tcp(SocketAddr),
    #[cfg(feature = "proxy")]
    TcpProxy {
        proxy: Arc<ProxyConfig>,
        target: ProxyTarget,
    },
    #[cfg(feature = "websocket")]
    Ws {
        address: SocketAddr,
        url: String,
    },
    #[cfg(feature = "websocket")]
    Wss {
        address: SocketAddr,
        url: String,
        provider: Arc<dyn tls::TlsProvider>,
    },
    #[cfg(all(feature = "websocket", feature = "proxy"))]
    WssProxy {
        proxy: Arc<ProxyConfig>,
        target: ProxyTarget,
        url: String,
        provider: Arc<dyn tls::TlsProvider>,
    },
    /// Unaccepted candidate HTTP: two plain outer streams, integral Noise.
    #[cfg(feature = "http")]
    Http {
        address: SocketAddr,
        authority: Authority,
    },
    /// Unaccepted candidate HTTPS: two independently verified TLS streams.
    #[cfg(feature = "http")]
    Https {
        address: SocketAddr,
        authority: Authority,
        provider: Arc<dyn tls::TlsProvider>,
    },
    #[cfg(all(feature = "http", feature = "proxy"))]
    HttpProxy {
        proxy: Arc<ProxyConfig>,
        target: ProxyTarget,
        authority: Authority,
    },
    #[cfg(all(feature = "http", feature = "proxy"))]
    HttpsProxy {
        proxy: Arc<ProxyConfig>,
        target: ProxyTarget,
        authority: Authority,
        provider: Arc<dyn tls::TlsProvider>,
    },
    /// Explicit plain HTTP forward proxy, NOT CONNECT or a direct fallback.
    /// Only this route emits absolute-form requests and proxy-hop authentication.
    /// Use a `ProxyConfig::http_connect` configuration for its validated HTTP
    /// credentials/address; this variant sends no CONNECT request at all.
    #[cfg(all(feature = "http", feature = "proxy"))]
    HttpForward {
        proxy: Arc<ProxyConfig>,
        target: ProxyTarget,
        authority: Authority,
    },
}

impl Route {
    fn carrier(&self) -> Carrier {
        match self {
            Self::Tcp(_) => Carrier::Tcp,
            #[cfg(feature = "proxy")]
            Self::TcpProxy { .. } => Carrier::Tcp,
            #[cfg(feature = "websocket")]
            Self::Ws { .. } => Carrier::WebSocket,
            #[cfg(feature = "websocket")]
            Self::Wss { .. } => Carrier::SecureWebSocket,
            #[cfg(all(feature = "websocket", feature = "proxy"))]
            Self::WssProxy { .. } => Carrier::SecureWebSocket,
            #[cfg(feature = "http")]
            Self::Http { .. } => Carrier::Http,
            #[cfg(feature = "http")]
            Self::Https { .. } => Carrier::Https,
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpProxy { .. } | Self::HttpForward { .. } => Carrier::Http,
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpsProxy { .. } => Carrier::Https,
        }
    }

    fn checked_endpoint(&self) -> Result<Endpoint, Error> {
        #[cfg(all(feature = "http", feature = "proxy"))]
        if let Self::HttpForward { proxy, .. } = self {
            if proxy.kind() != proxy::ProxyKind::HttpConnect {
                return Err(Error::Configuration);
            }
        }
        // Bound caller-owned strings before making the allowlist snapshot copy.
        #[cfg(feature = "websocket")]
        match self {
            Self::Ws { url, .. } | Self::Wss { url, .. } if url.len() > 2048 => {
                return Err(Error::Configuration);
            }
            #[cfg(feature = "proxy")]
            Self::WssProxy { url, .. } if url.len() > 2048 => {
                return Err(Error::Configuration);
            }
            _ => {}
        }
        let endpoint = self.endpoint();
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Build the secret-free identity to compare with a separately provisioned
    /// allowlist. This does not validate or authorize the route by itself.
    pub fn endpoint(&self) -> Endpoint {
        match self {
            Self::Tcp(address) => Endpoint::Tcp(*address),
            #[cfg(feature = "proxy")]
            Self::TcpProxy { proxy, target } => Endpoint::TcpProxy {
                proxy: proxy.endpoint(),
                target: target.clone(),
            },
            #[cfg(feature = "websocket")]
            Self::Ws { address, url } => Endpoint::Ws {
                address: *address,
                url: url.clone(),
            },
            #[cfg(feature = "websocket")]
            Self::Wss { address, url, .. } => Endpoint::Wss {
                address: *address,
                url: url.clone(),
            },
            #[cfg(all(feature = "websocket", feature = "proxy"))]
            Self::WssProxy {
                proxy, target, url, ..
            } => Endpoint::WssProxy {
                proxy: proxy.endpoint(),
                target: target.clone(),
                url: url.clone(),
            },
            #[cfg(feature = "http")]
            Self::Http { address, authority } => Endpoint::Http {
                address: *address,
                authority: authority.clone(),
            },
            #[cfg(feature = "http")]
            Self::Https {
                address, authority, ..
            } => Endpoint::Https {
                address: *address,
                authority: authority.clone(),
            },
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpProxy {
                proxy,
                target,
                authority,
            } => Endpoint::HttpProxy {
                proxy: proxy.endpoint(),
                target: target.clone(),
                authority: authority.clone(),
            },
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpsProxy {
                proxy,
                target,
                authority,
                ..
            } => Endpoint::HttpsProxy {
                proxy: proxy.endpoint(),
                target: target.clone(),
                authority: authority.clone(),
            },
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpForward {
                proxy,
                target,
                authority,
            } => Endpoint::HttpForward {
                proxy: proxy.endpoint(),
                target: target.clone(),
                authority: authority.clone(),
            },
        }
    }

    async fn connect(
        self,
        security: ClientConfig,
        credential: Vec<u8>,
        runtime: ConnectionConfig,
        limits: Limits,
        budget: EstablishmentBudget,
    ) -> Result<ClientHandle, Error> {
        match self {
            Self::Tcp(address) => {
                let stream = dial(address, &budget).await?;
                tcp::connect_stream_with_budget(
                    stream, security, credential, runtime, limits, budget,
                )
                .await
            }
            #[cfg(feature = "proxy")]
            Self::TcpProxy { proxy, target } => {
                let stream = proxy::connect_tunnel_with_budget(&proxy, &target, &budget).await?;
                tcp::connect_stream_with_budget(
                    stream, security, credential, runtime, limits, budget,
                )
                .await
            }
            #[cfg(feature = "websocket")]
            Self::Ws { address, url } => {
                let stream = dial(address, &budget).await?;
                websocket::connect_stream_with_budget(
                    stream, &url, security, credential, runtime, limits, budget,
                )
                .await
            }
            #[cfg(feature = "websocket")]
            Self::Wss {
                address,
                url,
                provider,
            } => {
                let stream = dial(address, &budget).await?;
                connect_wss(
                    stream,
                    &url,
                    provider.as_ref(),
                    security,
                    credential,
                    (runtime, limits),
                    budget,
                )
                .await
            }
            #[cfg(all(feature = "websocket", feature = "proxy"))]
            Self::WssProxy {
                proxy,
                target,
                url,
                provider,
            } => {
                let stream = proxy::connect_tunnel_with_budget(&proxy, &target, &budget).await?;
                connect_wss(
                    stream,
                    &url,
                    provider.as_ref(),
                    security,
                    credential,
                    (runtime, limits),
                    budget,
                )
                .await
            }
            #[cfg(feature = "http")]
            Self::Http { address, authority } => {
                http::connect_with_budget(
                    address,
                    authority,
                    None,
                    security,
                    credential,
                    (runtime, limits),
                    budget,
                )
                .await
            }
            #[cfg(feature = "http")]
            Self::Https {
                address,
                authority,
                provider,
            } => {
                http::connect_with_budget(
                    address,
                    authority,
                    Some(provider),
                    security,
                    credential,
                    (runtime, limits),
                    budget,
                )
                .await
            }
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpProxy {
                proxy,
                target,
                authority,
            } => {
                let upload = proxy::connect_tunnel_with_budget(&proxy, &target, &budget).await?;
                let download = proxy::connect_tunnel_with_budget(&proxy, &target, &budget).await?;
                http::connect_streams_with_budget(
                    upload,
                    download,
                    authority,
                    security,
                    credential,
                    (runtime, limits),
                    budget,
                )
                .await
            }
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpsProxy {
                proxy,
                target,
                authority,
                provider,
            } => {
                let upload = proxy::connect_tunnel_with_budget(&proxy, &target, &budget).await?;
                let download = proxy::connect_tunnel_with_budget(&proxy, &target, &budget).await?;
                let pair = http::verify_tls_streams_with_budget(
                    upload,
                    download,
                    provider.as_ref(),
                    authority,
                    budget,
                )
                .await?;
                http::connect_tls_pair_with_budget(pair, security, credential, (runtime, limits))
                    .await
            }
            #[cfg(all(feature = "http", feature = "proxy"))]
            Self::HttpForward {
                proxy, authority, ..
            } => {
                let upload = dial(proxy.endpoint(), &budget).await?;
                let download = dial(proxy.endpoint(), &budget).await?;
                let envelope = http::OpenEnvelope::new(security.context.encode()?)?;
                let upload = forward::ForwardIo::new(
                    upload,
                    proxy.clone(),
                    authority.clone(),
                    envelope.clone(),
                    true,
                    &budget,
                );
                let download = forward::ForwardIo::new(
                    download,
                    proxy,
                    authority.clone(),
                    envelope,
                    false,
                    &budget,
                );
                http::connect_streams_with_budget(
                    upload,
                    download,
                    authority,
                    security,
                    credential,
                    (runtime, limits),
                    budget,
                )
                .await
            }
        }
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route")
            .field("carrier", &self.carrier())
            .finish_non_exhaustive()
    }
}

/// Immutable after construction of the connector. All routes AND all allowlist
/// entries are checked before the inputs callback or any dial/provider invocation.
/// Lists must each have 1..=MAX_ROUTES entries. [`client_routes`] requires one
/// identical carrier even when the cross-carrier candidate feature is enabled.
#[derive(Debug)]
pub struct RouteConfig {
    pub routes: Vec<Route>,
    pub allowlist: Vec<Endpoint>,
    pub runtime: ConnectionConfig,
    pub limits: Limits,
}

/// Owned Send setup future; accepted by managed and lower-level reconnect owners.
pub type DialFuture = Pin<Box<dyn Future<Output = Result<ClientHandle, Error>> + Send>>;

/// Validate a route policy now, without requiring a running Tokio runtime, and
/// return a connector with no caller-side carrier loop. Each invocation yields
/// one attempt; merely creating/dropping an unpolled future does not dial, consume
/// inputs, or advance the cursor. Concurrent polls serialize selection only.
///
/// `inputs` must be nonblocking and return fresh security settings and explicit
/// encrypted-hello credentials every time. Never reuse ephemeral/cipher state or
/// silently change Returning to Bootstrap. The provisioned pin/scope remain the
/// application's trust policy, never learned from these endpoints. A returned
/// carrier mismatch is rejected before socket I/O. Errors are not reclassified.
pub fn client_routes<F>(
    config: RouteConfig,
    inputs: F,
) -> Result<impl Fn() -> DialFuture + Send + Sync + 'static, Error>
where
    F: Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static,
{
    config.limits.validate(&config.runtime)?;
    if config.routes.is_empty()
        || config.routes.len() > MAX_ROUTES
        || config.allowlist.is_empty()
        || config.allowlist.len() > MAX_ROUTES
    {
        return Err(Error::Configuration);
    }
    let carrier = config.routes[0].carrier();
    for endpoint in &config.allowlist {
        endpoint.validate()?;
        if endpoint.carrier() != carrier {
            return Err(Error::Configuration);
        }
    }
    for route in &config.routes {
        let endpoint = route.checked_endpoint()?;
        if endpoint.carrier() != carrier || !config.allowlist.contains(&endpoint) {
            return Err(Error::Configuration);
        }
    }
    let config = Arc::new(config);
    let inputs = Arc::new(inputs);
    let cursor = Arc::new(Mutex::new(0usize));
    Ok(move || {
        let config = config.clone();
        let inputs = inputs.clone();
        let cursor = cursor.clone();
        Box::pin(async move {
            let budget = EstablishmentBudget::new(
                pump::default_elapsed_clock(),
                config.limits.attempt_timeout,
            )?;
            let route = {
                let mut index = cursor.lock().map_err(|_| Error::Configuration)?;
                let route = config.routes[*index].clone();
                *index = (*index + 1) % config.routes.len();
                route
            };
            let (security, credential) = budget.run(async { inputs() }).await??;
            if security.context.carrier != carrier {
                return Err(Error::Configuration);
            }
            route
                .connect(
                    security,
                    credential,
                    config.runtime.clone(),
                    config.limits.clone(),
                    budget,
                )
                .await
        }) as DialFuture
    })
}

/// Explicit permissions for the opt-in cross-carrier candidate. There are no
/// default permissions. Loopback-only WebSocket is never a candidate
/// permission; use the homogeneous [`client_routes`] API for that local fixture.
/// Permitting a carrier does not enable its implementation's Cargo feature.
#[cfg(feature = "cross-carrier-candidate")]
#[derive(Clone, Debug)]
pub struct CrossCarrierPolicy {
    pub permitted_carriers: Vec<Carrier>,
}

#[cfg(feature = "cross-carrier-candidate")]
impl CrossCarrierPolicy {
    fn validate(&self) -> Result<(), Error> {
        let known = [
            Carrier::Tcp,
            Carrier::WebSocket,
            Carrier::SecureWebSocket,
            #[cfg(feature = "http")]
            Carrier::Http,
            #[cfg(feature = "http")]
            Carrier::Https,
        ];
        if self.permitted_carriers.is_empty() || self.permitted_carriers.len() > known.len() {
            return Err(Error::Configuration);
        }
        for (index, carrier) in self.permitted_carriers.iter().enumerate() {
            if *carrier == Carrier::WebSocket
                || !known.contains(carrier)
                || self.permitted_carriers[..index].contains(carrier)
            {
                return Err(Error::Configuration);
            }
        }
        Ok(())
    }
}

/// Build an explicitly permitted, sequential cross-carrier candidate connector.
/// Every route and every allowlist identity (including unused entries) must be
/// valid and permitted before any inputs callback, provider or dial can run.
///
/// Pass this connector directly to `ReconnectingClient::new_with_budget` or
/// `Network::client_with_budget`, with the corresponding owner feature enabled.
/// The supplied budget retains its original start and clock; route limits can
/// only shorten its deadline. Capping happens when polled, before selection or
/// application inputs, so time already spent by the owner cannot be regained here.
///
/// Each unexpired polled future selects exactly one route round-robin. An unpolled
/// future is inert. Selection alone holds the cursor lock; application inputs run
/// outside it and receive the selected endpoint, not an inferred security context.
/// Return fresh inputs with that endpoint's carrier and provisioned pin/scope,
/// preserving the intended authentication mode. A carrier mismatch fails before
/// dialing; security settings are never rewritten. Inputs must be nonblocking.
///
/// Errors pass through unchanged. There is no internal retry, discovery or
/// authentication fallback: the owning supervisor alone decides whether another
/// attempt is permitted, including backoff and terminal failure handling.
#[cfg(feature = "cross-carrier-candidate")]
pub fn client_routes_cross_carrier<F>(
    config: RouteConfig,
    policy: CrossCarrierPolicy,
    inputs: F,
) -> Result<impl Fn(EstablishmentBudget) -> DialFuture + Send + Sync + 'static, Error>
where
    F: Fn(&Endpoint) -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static,
{
    policy.validate()?;
    config.limits.validate(&config.runtime)?;
    if config.routes.is_empty()
        || config.routes.len() > MAX_ROUTES
        || config.allowlist.is_empty()
        || config.allowlist.len() > MAX_ROUTES
    {
        return Err(Error::Configuration);
    }
    for endpoint in &config.allowlist {
        endpoint.validate()?;
        if !policy.permitted_carriers.contains(&endpoint.carrier()) {
            return Err(Error::Configuration);
        }
    }
    for route in &config.routes {
        let endpoint = route.checked_endpoint()?;
        if !policy.permitted_carriers.contains(&endpoint.carrier())
            || !config.allowlist.contains(&endpoint)
        {
            return Err(Error::Configuration);
        }
    }
    let config = Arc::new(config);
    let inputs = Arc::new(inputs);
    let cursor = Arc::new(Mutex::new(0usize));
    Ok(move |budget: EstablishmentBudget| {
        let config = config.clone();
        let inputs = inputs.clone();
        let cursor = cursor.clone();
        Box::pin(async move {
            let budget = budget.cap(config.limits.attempt_timeout)?;
            let route = {
                let mut index = cursor.lock().map_err(|_| Error::Configuration)?;
                let route = config.routes[*index].clone();
                *index = (*index + 1) % config.routes.len();
                route
            };
            let endpoint = route.endpoint();
            let (security, credential) = budget.run(async { inputs(&endpoint) }).await??;
            if security.context.carrier != endpoint.carrier() {
                return Err(Error::Configuration);
            }
            route
                .connect(
                    security,
                    credential,
                    config.runtime.clone(),
                    config.limits.clone(),
                    budget,
                )
                .await
        }) as DialFuture
    })
}

fn valid_socket(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        return Err(Error::Configuration);
    }
    Ok(())
}

#[cfg(feature = "http")]
fn valid_http_authority(authority: &Authority) -> Result<(), Error> {
    let expected = authority.tls_authority()?;
    if let Ok(ip) = expected.host().parse::<std::net::IpAddr>() {
        let socket = SocketAddr::new(ip, expected.port());
        valid_socket(socket)?;
        if socket.to_string() != authority.as_str() {
            return Err(Error::Configuration);
        }
    } else if format!("{}:{}", expected.host(), expected.port()) != authority.as_str() {
        return Err(Error::Configuration);
    }
    Ok(())
}

async fn dial(
    address: SocketAddr,
    budget: &EstablishmentBudget,
) -> Result<tokio::net::TcpStream, Error> {
    budget
        .run(async {
            let stream = tokio::net::TcpStream::connect(address).await?;
            stream.set_nodelay(true)?;
            Ok::<_, Error>(stream)
        })
        .await?
}

#[cfg(feature = "websocket")]
fn valid_url(raw: &str, carrier: Carrier) -> Result<url::Url, Error> {
    if raw.len() > 2048 || !raw.is_ascii() {
        return Err(Error::Configuration);
    }
    let scheme = if carrier == Carrier::WebSocket {
        "ws"
    } else {
        "wss"
    };
    let (raw_scheme, rest) = raw.split_once("://").ok_or(Error::Configuration)?;
    let (authority, path) = rest.split_once('/').ok_or(Error::Configuration)?;
    // Check the original path, before the URL parser can remove dot segments,
    // backslashes or whitespace. Explicit default ports are valid; host/port
    // normalization is used consistently for TLS and tunnel target comparison.
    if raw_scheme != scheme
        || path != &websocket::ENDPOINT_PATH[1..]
        || authority.is_empty()
        || authority
            .bytes()
            .any(|b| b <= b' ' || b >= 0x7f || b"@\\%?#".contains(&b))
    {
        return Err(Error::Configuration);
    }
    let parsed = url::Url::parse(raw).map_err(|_| Error::Configuration)?;
    if parsed.scheme() != scheme
        || parsed.path() != websocket::ENDPOINT_PATH
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::Configuration);
    }
    let authority = tls::TlsAuthority::from_url(&parsed)?;
    if let Ok(ip) = authority.host().parse::<std::net::IpAddr>() {
        valid_socket(SocketAddr::new(ip, authority.port()))?;
    }
    Ok(parsed)
}

#[cfg(feature = "websocket")]
async fn connect_wss(
    stream: tokio::net::TcpStream,
    url: &str,
    provider: &dyn tls::TlsProvider,
    security: ClientConfig,
    credential: Vec<u8>,
    config: (ConnectionConfig, Limits),
    budget: EstablishmentBudget,
) -> Result<ClientHandle, Error> {
    let parsed = valid_url(url, Carrier::SecureWebSocket)?;
    let authority = tls::TlsAuthority::from_url(&parsed)?;
    let stream = tls::connect_stream_with_budget(stream, provider, authority, budget).await?;
    websocket::connect_tls_stream_with_budget(stream, url, security, credential, config.0, config.1)
        .await
}
