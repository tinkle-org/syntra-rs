//! Explicit native proxies over the existing encrypted TCP binding.
//!
//! SOCKS5 CONNECT (RFC 1928, optional RFC 1929) and HTTP/1 CONNECT are
//! supported. There is no direct fallback, retry, redirect, UDP, or new Syntra
//! carrier. Proxy credentials are independent of encrypted hello credentials.
//! These proxy protocols send credentials in cleartext to the proxy: provision a
//! trusted proxy/network. Neither a successful tunnel nor an externally supplied
//! stream attests TLS verification or authenticates the Syntra server.
//!
//! The proxy endpoint is an explicit socket address. Resolve it separately under
//! deployment-owned bounded DNS policy if necessary. Destination hostnames are
//! never resolved here; SOCKS uses ATYP=DOMAINNAME and CONNECT uses authority-form.
//! All establishment stays inline, is Send, and aborts by dropping the owned
//! stream on cancellation/error. No partially negotiated stream is reusable.
//!
//! Errors follow the native driver conventions: invalid local inputs are
//! `Configuration`, malformed replies are `Framing`, rejected authentication is
//! `Authentication`, and tunnel refusal is `Io(ConnectionRefused)`. Peer diagnostic
//! text is never retained in an error. Informational HTTP responses are rejected,
//! not followed to another status line. Limits are 16 KiB/64 headers/4 KiB per line.

use crate::{pump, stream::EstablishmentIo, tcp};
use std::{fmt, net::IpAddr, net::SocketAddr};
use syntra_core::secure_channel::{Carrier, ClientConfig};
use syntra_runtime::ConnectionConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub use pump::{ClientHandle, Error, EstablishmentBudget, Limits};

/// Maximum CONNECT response head, including status line and final CRLF.
pub const MAX_CONNECT_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_CONNECT_HEADERS: usize = 64;
const MAX_HTTP_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetHost {
    Ip(IpAddr),
    Hostname(String),
}

/// Validated destination, with an explicit distinction between IP and remote DNS.
/// No URL, userinfo, scope ID, implicit port, IDNA conversion or normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    host: TargetHost,
    port: u16,
}

impl ProxyTarget {
    pub fn ip(address: IpAddr, port: u16) -> Result<Self, Error> {
        if port == 0 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            host: TargetHost::Ip(address),
            port,
        })
    }

    /// ASCII DNS labels (1..=63 bytes), at most 253 bytes including an optional
    /// trailing dot. IP literals and ambiguous numeric-only names are rejected;
    /// use `ip` for an IP, and pre-encode international names as DNS A-labels.
    pub fn hostname(host: impl Into<String>, port: u16) -> Result<Self, Error> {
        let host = host.into();
        let labels = host.strip_suffix('.').unwrap_or(&host);
        if port == 0
            || host.len() > 253
            || labels.is_empty()
            || !host.is_ascii()
            || host.parse::<IpAddr>().is_ok()
            || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || labels.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            host: TargetHost::Hostname(host),
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// HTTP authority-form, including brackets around an IPv6 literal.
    pub fn authority(&self) -> String {
        match &self.host {
            TargetHost::Ip(address) => SocketAddr::new(*address, self.port).to_string(),
            TargetHost::Hostname(host) => format!("{host}:{}", self.port),
        }
    }
}

/// Non-cloneable proxy-only secret octets. Debug never includes either field.
/// Owned inputs and encoded authentication/request scratch are zeroized on drop,
/// including rejection/cancellation. Caller copies, OS buffers and allocator
/// history are outside that guarantee.
pub struct ProxyCredentials {
    username: Zeroizing<Vec<u8>>,
    password: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyCredentials([REDACTED])")
    }
}

impl ProxyCredentials {
    /// RFC 1929 permits arbitrary octets, with each field 1..=255 bytes.
    /// HTTP Basic additionally requires printable ASCII and no ':' in username;
    /// that restriction is checked by `ProxyConfig::http_connect`.
    pub fn new(username: Vec<u8>, password: Vec<u8>) -> Result<Self, Error> {
        let credentials = Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
        };
        if !(1..=255).contains(&credentials.username.len())
            || !(1..=255).contains(&credentials.password.len())
        {
            return Err(Error::Configuration);
        }
        Ok(credentials)
    }

    fn valid_http(&self) -> bool {
        !self.username.contains(&b':')
            && self
                .username
                .iter()
                .chain(self.password.iter())
                .all(|b| (0x20..=0x7e).contains(b))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Socks5,
    HttpConnect,
}

/// Immutable validated configuration; credentials cannot be extracted or cloned.
#[derive(Debug)]
pub struct ProxyConfig {
    endpoint: SocketAddr,
    kind: ProxyKind,
    credentials: Option<ProxyCredentials>,
}

impl ProxyConfig {
    pub fn socks5(
        endpoint: SocketAddr,
        credentials: Option<ProxyCredentials>,
    ) -> Result<Self, Error> {
        Self::new(endpoint, ProxyKind::Socks5, credentials)
    }

    /// Preemptive Basic authentication to this proxy only. A 407 fails; no
    /// challenge negotiation, second request or credential-bearing redirect.
    pub fn http_connect(
        endpoint: SocketAddr,
        credentials: Option<ProxyCredentials>,
    ) -> Result<Self, Error> {
        Self::new(endpoint, ProxyKind::HttpConnect, credentials)
    }

    fn new(
        endpoint: SocketAddr,
        kind: ProxyKind,
        credentials: Option<ProxyCredentials>,
    ) -> Result<Self, Error> {
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
            || (kind == ProxyKind::HttpConnect
                && credentials.as_ref().is_some_and(|c| !c.valid_http()))
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            endpoint,
            kind,
            credentials,
        })
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn kind(&self) -> ProxyKind {
        self.kind
    }

    /// Only the explicit candidate HTTP forward route may use this hop header.
    /// Never call for tunneled/origin requests. The caller supplies a fresh,
    /// zeroizing, fully reserved header buffer so secret bytes cannot reallocate.
    #[cfg(feature = "http")]
    pub(crate) fn append_forward_authorization(
        &self,
        head: &mut Zeroizing<Vec<u8>>,
    ) -> Result<(), Error> {
        if self.kind != ProxyKind::HttpConnect || head.capacity() < MAX_CONNECT_HEADER_BYTES {
            return Err(Error::Configuration);
        }
        if let Some(credentials) = &self.credentials {
            let value = basic_value(credentials);
            let prefix = b"Proxy-Authorization: Basic ";
            if head.len() + prefix.len() + value.len() + 2 > MAX_CONNECT_HEADER_BYTES {
                return Err(Error::Framing);
            }
            head.extend_from_slice(prefix);
            head.extend_from_slice(&value);
            head.extend_from_slice(b"\r\n");
        }
        Ok(())
    }
}

/// Dial the proxy, negotiate a tunnel, authenticate the provisioned Syntra pin
/// and scope, then complete protected hello/ready under one absolute budget.
pub async fn connect_tcp_proxy(
    proxy: &ProxyConfig,
    target: &ProxyTarget,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let budget = EstablishmentBudget::new(pump::default_elapsed_clock(), limits.attempt_timeout)?;
    connect_tcp_proxy_with_budget(proxy, target, security, credential, runtime, limits, budget)
        .await
}

/// Continue an external owner's budget; do not mint a new one on handoff.
pub async fn connect_tcp_proxy_with_budget(
    proxy: &ProxyConfig,
    target: &ProxyTarget,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
    budget: EstablishmentBudget,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    if security.context.carrier != Carrier::Tcp {
        return Err(Error::Framing);
    }
    let stream = connect_tunnel_with_budget(proxy, target, &budget).await?;
    tcp::connect_stream_with_budget(stream, security, credential, runtime, limits, budget).await
}

/// Open a raw tunnel, not a Syntra connection. The caller MUST continue setup
/// with this same budget (e.g. `tcp::connect_stream_with_budget`). No TLS trust
/// or channel principal is inferred from proxy success. One dial, no fallback.
pub async fn connect_tunnel_with_budget(
    proxy: &ProxyConfig,
    target: &ProxyTarget,
    budget: &EstablishmentBudget,
) -> Result<tokio::net::TcpStream, Error> {
    let stream = budget
        .run(async {
            let stream = tokio::net::TcpStream::connect(proxy.endpoint).await?;
            stream.set_nodelay(true)?;
            Ok::<_, Error>(stream)
        })
        .await??;
    tunnel_stream_with_budget(stream, proxy, target, budget).await
}

/// Own and negotiate an already-connected proxy stream. `proxy.endpoint` is
/// informational here; the caller supplies the correct peer and any TLS policy.
/// Every raw poll is budget-gated, even if one operation performs many polls.
/// Failure/cancellation drops the stream rather than returning partial state.
pub async fn tunnel_stream_with_budget<S>(
    stream: S,
    proxy: &ProxyConfig,
    target: &ProxyTarget,
    budget: &EstablishmentBudget,
) -> Result<S, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = EstablishmentIo {
        inner: stream,
        budget: budget.io.clone(),
    };
    budget
        .run(async {
            match proxy.kind {
                ProxyKind::Socks5 => socks5(&mut stream, target, proxy.credentials.as_ref()).await,
                ProxyKind::HttpConnect => {
                    http_connect(&mut stream, target, proxy.credentials.as_ref()).await
                }
            }
        })
        .await??;
    Ok(stream.inner)
}

async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &ProxyTarget,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), Error> {
    // Offer exactly one method: configured authentication can never downgrade.
    let method = if credentials.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    stream.flush().await?;
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != 5 {
        return Err(Error::Framing);
    }
    if selection[1] != method {
        return Err(Error::Authentication);
    }
    if let Some(credentials) = credentials {
        let mut auth = Zeroizing::new(Vec::with_capacity(
            3 + credentials.username.len() + credentials.password.len(),
        ));
        auth.extend_from_slice(&[1, credentials.username.len() as u8]);
        auth.extend_from_slice(&credentials.username);
        auth.push(credentials.password.len() as u8);
        auth.extend_from_slice(&credentials.password);
        stream.write_all(&auth).await?;
        stream.flush().await?;
        let mut response = [0; 2];
        stream.read_exact(&mut response).await?;
        if response[0] != 1 {
            return Err(Error::Framing);
        }
        if response[1] != 0 {
            return Err(Error::Authentication);
        }
    }
    let mut request = Vec::with_capacity(262);
    request.extend_from_slice(&[5, 1, 0]);
    match &target.host {
        TargetHost::Ip(IpAddr::V4(address)) => {
            request.push(1);
            request.extend_from_slice(&address.octets());
        }
        TargetHost::Ip(IpAddr::V6(address)) => {
            request.push(4);
            request.extend_from_slice(&address.octets());
        }
        TargetHost::Hostname(host) => {
            request.extend_from_slice(&[3, host.len() as u8]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut response = [0; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[2] != 0 {
        return Err(Error::Framing);
    }
    if response[1] != 0 {
        return Err(match response[1] {
            2 => Error::Authentication, // Explicit ruleset denial, not unavailability.
            7 | 8 => Error::Configuration, // Unsupported command/address type.
            1 | 3..=6 => refused(),
            _ => Error::Framing,
        });
    }
    let address_len = match response[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                return Err(Error::Framing);
            }
            len
        }
        _ => return Err(Error::Framing),
    };
    // Consume the entire bounded BND.ADDR and BND.PORT, but no tunnel bytes.
    let mut bound = [0; 257];
    stream.read_exact(&mut bound[..address_len + 2]).await?;
    Ok(())
}

fn refused() -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "proxy tunnel refused",
    ))
}

fn basic_value(credentials: &ProxyCredentials) -> Zeroizing<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut plain = Zeroizing::new(Vec::with_capacity(
        credentials.username.len() + 1 + credentials.password.len(),
    ));
    plain.extend_from_slice(&credentials.username);
    plain.push(b':');
    plain.extend_from_slice(&credentials.password);
    let mut encoded = Zeroizing::new(Vec::with_capacity(plain.len().div_ceil(3) * 4));
    for chunk in plain.chunks(3) {
        let a = chunk[0] as usize;
        let b = chunk.get(1).copied().unwrap_or(0) as usize;
        let c = chunk.get(2).copied().unwrap_or(0) as usize;
        encoded.push(ALPHABET[a >> 2]);
        encoded.push(ALPHABET[((a & 3) << 4) | (b >> 4)]);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[((b & 15) << 2) | (c >> 6)]
        } else {
            b'='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[c & 63]
        } else {
            b'='
        });
    }
    encoded
}

async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    target: &ProxyTarget,
    credentials: Option<&ProxyCredentials>,
) -> Result<(), Error> {
    let authority = target.authority();
    // Reserve the full bounded request before copying secrets, avoiding a secret
    // allocation being reallocated without erasure. No user-supplied headers.
    let mut request = Zeroizing::new(Vec::with_capacity(MAX_CONNECT_HEADER_BYTES));
    request.extend_from_slice(b"CONNECT ");
    request.extend_from_slice(authority.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(authority.as_bytes());
    request.extend_from_slice(b"\r\n");
    if let Some(credentials) = credentials {
        request.extend_from_slice(b"Proxy-Authorization: Basic ");
        request.extend_from_slice(&basic_value(credentials));
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    stream.write_all(&request).await?;
    stream.flush().await?;
    // Never buffer past CRLFCRLF: the very next byte belongs to the tunnel,
    // regardless of a Content-Length or Transfer-Encoding on a 2xx response.
    // Zeroize peer headers too: a malicious proxy may reflect credentials.
    let mut head = Zeroizing::new(Vec::with_capacity(MAX_CONNECT_HEADER_BYTES));
    loop {
        if head.len() == MAX_CONNECT_HEADER_BYTES {
            return Err(Error::Framing);
        }
        head.push(stream.read_u8().await?);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    parse_connect_response(&head)
}

fn http_value_byte(b: u8) -> bool {
    b == b'\t' || b >= 0x20 && b != 0x7f
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn parse_connect_response(head: &[u8]) -> Result<(), Error> {
    let mut lines = head.split(|b| *b == b'\n');
    let status = lines.next().ok_or(Error::Framing)?;
    let status = status.strip_suffix(b"\r").ok_or(Error::Framing)?;
    if status.len() < 13
        || status.len() > MAX_HTTP_LINE_BYTES
        || !matches!(&status[..9], b"HTTP/1.1 " | b"HTTP/1.0 ")
        || !status[9..12].iter().all(u8::is_ascii_digit)
        || status[12] != b' '
        || !status[13..].iter().copied().all(http_value_byte)
    {
        return Err(Error::Framing);
    }
    let code = (status[9] - b'0') as u16 * 100
        + (status[10] - b'0') as u16 * 10
        + (status[11] - b'0') as u16;
    let mut count = 0;
    for line in lines.by_ref() {
        let line = line.strip_suffix(b"\r").ok_or(Error::Framing)?;
        if line.is_empty() {
            break;
        }
        count += 1;
        if count > MAX_CONNECT_HEADERS || line.len() > MAX_HTTP_LINE_BYTES {
            return Err(Error::Framing);
        }
        let colon = line.iter().position(|b| *b == b':').ok_or(Error::Framing)?;
        let name = &line[..colon];
        if name.is_empty()
            || !name.iter().copied().all(token_byte)
            || name.eq_ignore_ascii_case(b"status")
            || !line[colon + 1..].iter().copied().all(http_value_byte)
        {
            // Reject obs-fold, whitespace before ':', pseudo/status fields and
            // additional status lines instead of selecting one interpretation.
            return Err(Error::Framing);
        }
    }
    if lines.next() != Some(b"".as_slice()) || lines.next().is_some() {
        return Err(Error::Framing);
    }
    match code {
        // RFC 9110 §9.3.6: ANY 2xx switches immediately to tunnel mode. Ignore
        // Content-Length/Transfer-Encoding rather than consuming an HTTP body.
        200..=299 => Ok(()),
        401 | 403 | 407 => Err(Error::Authentication),
        100..=599 => Err(refused()),
        _ => Err(Error::Framing),
    }
}

/// Routing metadata for a FUTURE HTTP forward binding, not a Syntra carrier or
/// an HTTP client. It deliberately has no reference to `ProxyConfig`/credentials.
/// Use absolute-form on a forward proxy connection and `host_header` as Host.
/// Do not forward Proxy-Authorization to an origin or reuse it inside a tunnel;
/// an eventual HTTP owner must separate proxy/origin headers and forbid redirects
/// carrying credentials. HTTPS requires a tunnel plus independently verified TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpForwardTarget {
    absolute_uri: String,
    host_header: String,
}

impl HttpForwardTarget {
    /// Accept RFC 3986 origin-form path/query only, bounded to 8192 ASCII bytes.
    /// Percent encoding is validated, never decoded. No userinfo or fragment.
    pub fn new(target: &ProxyTarget, path_and_query: &str) -> Result<Self, Error> {
        if !path_and_query.starts_with('/')
            || path_and_query.len() > 8192
            || !valid_path_and_query(path_and_query.as_bytes())
        {
            return Err(Error::Configuration);
        }
        let host_header = target.authority();
        Ok(Self {
            absolute_uri: format!("http://{host_header}{path_and_query}"),
            host_header,
        })
    }

    pub fn absolute_uri(&self) -> &str {
        &self.absolute_uri
    }

    pub fn host_header(&self) -> &str {
        &self.host_header
    }
}

fn valid_path_and_query(mut bytes: &[u8]) -> bool {
    while let Some((&byte, rest)) = bytes.split_first() {
        if byte == b'%' {
            if rest.len() < 2 || !rest[..2].iter().all(u8::is_ascii_hexdigit) {
                return false;
            }
            bytes = &rest[2..];
        } else if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&byte) {
            bytes = rest;
        } else {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests;
