//! Experimental canonical SC1 over native WebSocket. One binary
//! message per channel record; encrypted inner framing is shared with TCP.
//! Browser SC1 is not implemented.
//!
//! WSS requires verified TLS 1.3 and the SecureWebSocket SC1 carrier binding.
//! Plaintext WS is a loopback-only dial option under `development-carriers`.
//! Experimental and unpublished: no accepted upstream profile or audit claim.
use crate::pump::{self, RecordReader, RecordWriter};
pub use crate::{AuthenticatorFactory, ClientHandle, Error, HostHandle, Limits};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::sync::Arc;
use syntra_runtime::{ConnectionConfig, Handler};
use syntra_secure_channel::{Carrier, ClientConfig, ServerConfig, MAX_CIPHERTEXT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    tungstenite::{
        client::IntoClientRequest,
        handshake::{
            client::generate_request,
            derive_accept_key,
            server::{ErrorResponse, Request, Response},
        },
        http::{HeaderValue, StatusCode},
        protocol::{Message, Role, WebSocketConfig},
    },
    WebSocketStream,
};

pub const SUBPROTOCOL: &str = "syntra.sc1.v1";
pub const ENDPOINT_PATH: &str = "/syntra/v1/sc1/ws";

const MAX_UPGRADE_HEADERS: usize = 16 * 1024;
const MAX_UPGRADE_FIELDS: usize = 64;

// Compatibility with tungstenite 0.26.2: its response verifier compares the
// whole Connection value instead of its tokens and leaves extension validation
// as TODO. Validate the original bytes here, then retain tungstenite's framing.
// https://docs.rs/tungstenite/0.26.2/src/tungstenite/handshake/client.rs.html
// https://docs.rs/httparse/1.10.1/httparse/struct.Response.html
fn validate_upgrade_response(bytes: &[u8], accept_key: &[u8]) -> Result<Option<usize>, Error> {
    let mut fields = [httparse::EMPTY_HEADER; MAX_UPGRADE_FIELDS];
    let mut response = httparse::Response::new(&mut fields);
    let size = match response.parse(bytes).map_err(|_| Error::Configuration)? {
        httparse::Status::Partial if bytes.len() < MAX_UPGRADE_HEADERS => return Ok(None),
        httparse::Status::Partial => return Err(Error::Configuration),
        httparse::Status::Complete(size) => size,
    };
    // Count only HTTP bytes, not a WebSocket frame coalesced with the response.
    // httparse also accepts bare LF; this binding requires HTTP CRLF lines.
    if size > MAX_UPGRADE_HEADERS
        || response.version != Some(1)
        || response.code != Some(101)
        || !bytes[..size].ends_with(b"\r\n\r\n")
        || bytes[..size].iter().enumerate().any(|(i, &byte)| {
            (byte == b'\n' && (i == 0 || bytes[i - 1] != b'\r'))
                || (byte == b'\r' && bytes.get(i + 1) != Some(&b'\n'))
        })
    {
        return Err(Error::Configuration);
    }
    let single = |name: &str| -> Result<&[u8], Error> {
        let mut values = response
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name));
        let value = values.next().ok_or(Error::Configuration)?.value;
        if values.next().is_some() {
            return Err(Error::Configuration);
        }
        Ok(value)
    };
    let mut connection_upgrade = false;
    for header in response.headers.iter() {
        if header.name.eq_ignore_ascii_case("sec-websocket-extensions") {
            return Err(Error::Configuration);
        }
        if header.name.eq_ignore_ascii_case("connection") {
            for token in header.value.split(|&byte| byte == b',') {
                let token = token.trim_ascii();
                if token.is_empty()
                    || !token.iter().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)
                    })
                {
                    return Err(Error::Configuration);
                }
                connection_upgrade |= token.eq_ignore_ascii_case(b"upgrade");
            }
        }
    }
    if !connection_upgrade
        || !single("upgrade")?.eq_ignore_ascii_case(b"websocket")
        || single("sec-websocket-accept")? != accept_key
        || single("sec-websocket-protocol")? != SUBPROTOCOL.as_bytes()
    {
        return Err(Error::Configuration);
    }
    Ok(Some(size))
}

// The caller's absolute attempt deadline covers request writes and all reads.
// No redirects or response bodies are followed; no SC1 bytes are sent here.
async fn client_upgrade<S>(request: Request, mut stream: S) -> Result<WebSocketStream<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (request, key) = generate_request(request).map_err(upgrade_error)?;
    let accept_key = derive_accept_key(key.as_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;
    let mut received = Vec::with_capacity(4096);
    let mut chunk = [0; 2048];
    loop {
        if let Some(size) = validate_upgrade_response(&received, accept_key.as_bytes())? {
            let tail = received.split_off(size);
            return Ok(WebSocketStream::from_partially_read(
                stream,
                tail,
                Role::Client,
                Some(websocket_config()),
            )
            .await);
        }
        let n = stream.read(&mut chunk).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Configuration
            } else {
                Error::Io(error)
            }
        })?;
        if n == 0 {
            return Err(Error::Configuration);
        }
        received.extend_from_slice(&chunk[..n]);
    }
}

fn websocket_config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.read_buffer_size = 16_384;
    config.write_buffer_size = 16_384;
    config.max_write_buffer_size = 131_072;
    config.max_message_size = Some(MAX_CIPHERTEXT);
    config.max_frame_size = Some(MAX_CIPHERTEXT);
    config
}

struct Reader<S>(SplitStream<WebSocketStream<S>>);
struct Writer<S>(SplitSink<WebSocketStream<S>, Message>);
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> RecordReader for Reader<S> {
    async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        // Tungstenite handles Ping/Pong and fragment reassembly below this layer.
        // An unlimited control-frame stream is still bounded by the caller's absolute deadline.
        loop {
            match self.0.next().await {
                Some(Ok(Message::Binary(bytes)))
                    if (17..=maximum.min(MAX_CIPHERTEXT)).contains(&bytes.len()) =>
                {
                    return Ok(bytes.to_vec())
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {
                    tokio::task::yield_now().await;
                }
                Some(Ok(Message::Close(_))) | None => return Err(Error::Closed),
                Some(Err(tokio_tungstenite::tungstenite::Error::Io(error))) => {
                    return Err(Error::Io(error));
                }
                Some(Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)) => {
                    return Err(Error::Closed);
                }
                _ => return Err(Error::Framing),
            }
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> RecordWriter for Writer<S> {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !(17..=MAX_CIPHERTEXT).contains(&bytes.len()) {
            return Err(Error::Framing);
        }
        self.0
            .send(Message::Binary(bytes.to_vec().into()))
            .await
            .map_err(|_| Error::Closed)
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        self.0
            .send(Message::Close(None))
            .await
            .map_err(|_| Error::Closed)
    }
}

/// Dial WSS using native trust roots, hostname validation and TLS 1.3, then SC1
/// using the provisioned Noise server pin. No redirects, downgrade or fallback.
/// Development WS requires `development-carriers` and a parsed loopback host.
///
/// TLS/endpoint validation failures return `Error::Configuration`; socket
/// failures return `Io`/`Closed`, deadlines `Timeout`, and SC1 errors `Channel`
/// or `Authentication`. Never retry `Configuration` using a weaker carrier.
pub async fn connect(
    url: &str,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    connect_inner(url, None, security, credential, runtime, limits).await
}

/// As `connect`, but WSS trusts only the supplied roots. The connector is built
/// internally: callers cannot override certificate or hostname verification,
/// protocol versions, or enable early application data.
pub async fn connect_with_roots(
    url: &str,
    roots: rustls::RootCertStore,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    connect_inner(url, Some(roots), security, credential, runtime, limits).await
}

fn endpoint(url: &str, carrier: Carrier) -> Result<url::Url, Error> {
    let parsed = url::Url::parse(url).map_err(|_| Error::Configuration)?;
    match parsed.scheme() {
        "wss" if carrier == Carrier::SecureWebSocket => {}
        "ws" if carrier == Carrier::WebSocket && cfg!(feature = "development-carriers") => {
            let loopback = match parsed.host() {
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                Some(url::Host::Domain(name)) => name == "localhost",
                None => false,
            };
            if !loopback {
                return Err(Error::Configuration);
            }
        }
        _ => return Err(Error::Configuration),
    }
    if parsed.host().is_none()
        || parsed.path() != ENDPOINT_PATH
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::Configuration);
    }
    Ok(parsed)
}

// A rustls protocol/certificate error is not a transient socket failure. Keep
// this distinction without expanding the carrier-neutral error enum.
fn tls_error(error: std::io::Error) -> Error {
    if error
        .get_ref()
        .is_some_and(|cause| cause.is::<rustls::Error>())
        || matches!(
            error.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
        )
    {
        Error::Configuration
    } else {
        Error::Io(error)
    }
}

fn upgrade_error(error: tokio_tungstenite::tungstenite::Error) -> Error {
    use tokio_tungstenite::tungstenite::Error as WsError;
    match error {
        WsError::Io(error) => Error::Io(error),
        WsError::ConnectionClosed | WsError::AlreadyClosed => Error::Closed,
        _ => Error::Configuration,
    }
}

async fn connect_inner(
    url: &str,
    roots: Option<rustls::RootCertStore>,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let deadline = tokio::time::Instant::now() + limits.attempt_timeout;
    let parsed = endpoint(url, security.context.carrier)?;
    let host = match parsed.host().ok_or(Error::Configuration)? {
        url::Host::Domain(name) => name.to_owned(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    let port = parsed.port_or_known_default().ok_or(Error::Configuration)?;
    let mut request = parsed
        .as_str()
        .into_client_request()
        .map_err(|_| Error::Configuration)?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let connector = if parsed.scheme() == "wss" {
        let roots = roots.unwrap_or_else(|| {
            let loaded = rustls_native_certs::load_native_certs();
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(loaded.certs);
            roots
        });
        if roots.is_empty() {
            return Err(Error::Configuration);
        }
        // Pin the ring provider explicitly instead of relying on the
        // process-default provider, and keep TLS 1.3-only. A provider that
        // cannot offer TLS 1.3 is a configuration error, not a panic.
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| Error::Configuration)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.enable_early_data = false;
        Some(tokio_rustls::TlsConnector::from(Arc::new(config)))
    } else {
        None
    };
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    tokio::time::timeout_at(deadline, async {
        let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
        stream.set_nodelay(true)?;
        let stream = if let Some(connector) = connector {
            let name = ServerName::try_from(host).map_err(|_| Error::Configuration)?;
            let stream = connector.connect(name, stream).await.map_err(tls_error)?;
            if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
                return Err(Error::Configuration);
            }
            tokio_tungstenite::MaybeTlsStream::Rustls(stream)
        } else {
            // Also check the resolved address: localhost must not be re-bound
            // to a non-loopback peer through host resolver configuration.
            if !stream.peer_addr()?.ip().is_loopback() {
                return Err(Error::Configuration);
            }
            tokio_tungstenite::MaybeTlsStream::Plain(stream)
        };
        let socket = client_upgrade(request, stream).await?;
        let (writer, reader) = socket.split();
        pump::connect_records(
            Reader(reader),
            Writer(writer),
            security,
            credential,
            runtime,
            limits.clone(),
        )
        .await
    })
    .await
    .map_err(|_| Error::Timeout)?
}

fn upgrade(request: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    let valid = request.uri().path() == ENDPOINT_PATH
        && request.uri().query().is_none()
        && request
            .headers()
            .get_all("sec-websocket-protocol")
            .iter()
            .count()
            == 1
        && request
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            == Some(SUBPROTOCOL)
        && !request.headers().contains_key("authorization")
        && !request.headers().contains_key("cookie");
    if !valid {
        let mut error = ErrorResponse::new(Some("SC1 endpoint rejected".into()));
        *error.status_mut() = StatusCode::BAD_REQUEST;
        return Err(error);
    }
    response.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    Ok(response)
}

/// Restricted-development raw stream fixture. This API never asserts WSS,
/// including for caller-terminated TLS or streams carrying forwarded headers.
/// Caller bounds aggregate admission and confines raw fixtures to development.
#[cfg(feature = "development-carriers")]
pub async fn accept_stream<S>(
    stream: S,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    limits.validate(&runtime)?;
    if security.carrier != Carrier::WebSocket {
        return Err(Error::Configuration);
    }
    tokio::time::timeout(
        limits.attempt_timeout,
        accept_upgraded(stream, security, factory, handler, runtime, limits.clone()),
    )
    .await
    .map_err(|_| Error::Timeout)?
}

/// Immutable TLS 1.3-only server settings built from a certificate chain and
/// matching private key. No arbitrary rustls config or verifier is accepted.
#[derive(Clone)]
pub struct TlsServerSettings {
    config: Arc<rustls::ServerConfig>,
}

impl TlsServerSettings {
    pub fn new(
        certificates: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, Error> {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| Error::Configuration)?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| Error::Configuration)?;
        config.max_early_data_size = 0;
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

/// Own TLS on a raw accepted byte stream, check negotiated TLS 1.3, then
/// Upgrade and run SC1. The SC1 config must bind SecureWebSocket. TLS, Upgrade,
/// and SC1 share one absolute attempt deadline. Client identity comes from SC1,
/// not client certificates or proxy/forwarded headers. Caller caps admission.
pub async fn accept_tls_stream<S>(
    stream: S,
    tls: &TlsServerSettings,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    limits.validate(&runtime)?;
    if security.carrier != Carrier::SecureWebSocket {
        return Err(Error::Configuration);
    }
    tokio::time::timeout(limits.attempt_timeout, async {
        let stream = tokio_rustls::TlsAcceptor::from(tls.config.clone())
            .accept(stream)
            .await
            .map_err(tls_error)?;
        if stream.get_ref().1.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
            return Err(Error::Configuration);
        }
        accept_upgraded(stream, security, factory, handler, runtime, limits.clone()).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}

async fn accept_upgraded<S>(
    stream: S,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let socket =
        tokio_tungstenite::accept_hdr_async_with_config(stream, upgrade, Some(websocket_config()))
            .await
            .map_err(upgrade_error)?;
    let (writer, reader) = socket.split();
    pump::accept_records(
        Reader(reader),
        Writer(writer),
        security,
        factory,
        handler,
        runtime,
        limits.clone(),
    )
    .await
}

/// Accept one connection from a caller-owned listener. Callers must cap simultaneous
/// calls and live handles (e.g. an owned semaphore permit held with each handle).
#[cfg(feature = "development-carriers")]
pub async fn accept(
    listener: &tokio::net::TcpListener,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error> {
    limits.validate(&runtime)?;
    if security.carrier != Carrier::WebSocket {
        return Err(Error::Configuration);
    }
    let (stream, peer) = listener.accept().await?;
    if !peer.ip().is_loopback() {
        return Err(Error::Configuration);
    }
    stream.set_nodelay(true)?;
    accept_stream(stream, security, factory, handler, runtime, limits).await
}
