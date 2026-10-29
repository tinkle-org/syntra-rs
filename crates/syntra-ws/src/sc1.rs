//! Native SC1 local revision 1. One binary message per channel record; encrypted
//! inner framing is shared with TCP. Browser SC1 is not implemented.
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use std::sync::Arc;
use syntra_runtime::{ConnectionConfig, Handler};
use syntra_secure_channel::{Carrier, ClientConfig, ServerConfig, MAX_CIPHERTEXT};
use syntra_tcp::pump::{self, RecordReader, RecordWriter};
pub use syntra_tcp::{AuthenticatorFactory, ClientHandle, Error, HostHandle, Limits};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{ErrorResponse, Request, Response},
        http::{HeaderValue, StatusCode},
        protocol::{Message, WebSocketConfig},
    },
    WebSocketStream,
};

pub const SUBPROTOCOL: &str = "syntra.sc1.local1.ws";
pub const ENDPOINT_PATH: &str = "/syntra/local/sc1/1/ws";

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

/// Dial ws/wss using a provisioned Noise server pin. No fallback or redirected retries.
/// WSS additionally uses TLS 1.3 with platform trust roots and hostname validation.
pub async fn connect(
    url: &str,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let deadline = tokio::time::Instant::now() + limits.attempt_timeout;
    if security.context.carrier != Carrier::WebSocket {
        return Err(Error::Configuration);
    }
    let parsed = url::Url::parse(url).map_err(|_| Error::Configuration)?;
    if !matches!(parsed.scheme(), "ws" | "wss")
        || parsed.path() != ENDPOINT_PATH
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(Error::Configuration);
    }
    let mut request = url
        .into_client_request()
        .map_err(|_| Error::Configuration)?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );
    let connector = if parsed.scheme() == "wss" {
        let loaded = rustls_native_certs::load_native_certs();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(loaded.certs);
        if roots.is_empty() {
            return Err(Error::Configuration);
        }
        let config =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        Some(tokio_tungstenite::Connector::Rustls(Arc::new(config)))
    } else {
        None
    };
    if tokio::time::Instant::now() >= deadline {
        return Err(Error::Timeout);
    }
    tokio::time::timeout_at(deadline, async {
        let (socket, response) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(websocket_config()),
            false,
            connector,
        )
        .await
        .map_err(|_| Error::Closed)?;
        if response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            != Some(SUBPROTOCOL)
        {
            return Err(Error::Framing);
        }
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

/// Upgrade an accepted native byte stream (TCP or caller-terminated TLS), then
/// authenticate SC1 and accept a Syntra host. Caller bounds aggregate admission.
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
    tokio::time::timeout(limits.attempt_timeout, async {
        let socket = tokio_tungstenite::accept_hdr_async_with_config(
            stream,
            upgrade,
            Some(websocket_config()),
        )
        .await
        .map_err(|_| Error::Framing)?;
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
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// Accept one connection from a caller-owned listener. Callers must cap simultaneous
/// calls and live handles (e.g. an owned semaphore permit held with each handle).
pub async fn accept(
    listener: &tokio::net::TcpListener,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<HostHandle, Error> {
    let (stream, _) = listener.accept().await?;
    stream.set_nodelay(true)?;
    accept_stream(stream, security, factory, handler, runtime, limits).await
}
