//! Native local SC1 TCP adapter. Generic accepted streams need no socket feature.
#![forbid(unsafe_code)]

pub mod pump;

pub use pump::{AuthenticatorFactory, ClientHandle, Error, HostHandle, Limits};
use std::{sync::Arc, time::Duration};
use syntra_runtime::{ConnectionConfig, Handler};
use syntra_secure_channel::{Carrier, ClientConfig, ServerConfig, MAX_CIPHERTEXT};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const BINDING: &str = "syntra.sc1.local1.tcp";

pub struct StreamReader<R>(pub R);
pub struct StreamWriter<W>(pub W);

impl<R: AsyncRead + Unpin + Send + 'static> pump::RecordReader for StreamReader<R> {
    async fn read_record(&mut self, maximum: usize) -> Result<Vec<u8>, Error> {
        let len = self.0.read_u16().await? as usize;
        if !(17..=maximum.min(MAX_CIPHERTEXT)).contains(&len) {
            return Err(Error::Framing);
        }
        let mut bytes = vec![0; len];
        self.0.read_exact(&mut bytes).await?;
        Ok(bytes)
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> pump::RecordWriter for StreamWriter<W> {
    async fn write_record(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if !(17..=MAX_CIPHERTEXT).contains(&bytes.len()) {
            return Err(Error::Framing);
        }
        self.0
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await?;
        self.0.write_all(bytes).await?;
        self.0.flush().await?;
        Ok(())
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        self.0.shutdown().await.map_err(Into::into)
    }
}

/// Own a connected ordered stream, authenticate the server, then run Syntra hello/ready.
pub async fn connect_stream<S>(
    stream: S,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if security.context.carrier != Carrier::Tcp {
        return Err(Error::Framing);
    }
    let (read, write) = tokio::io::split(stream);
    pump::connect_records(
        StreamReader(read),
        StreamWriter(write),
        security,
        credential,
        runtime,
        limits,
    )
    .await
}

/// Own an accepted stream. The factory sees only freshly confirmed channel context.
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
    if security.carrier != Carrier::Tcp {
        return Err(Error::Framing);
    }
    let (read, write) = tokio::io::split(stream);
    pump::accept_records(
        StreamReader(read),
        StreamWriter(write),
        security,
        factory,
        handler,
        runtime,
        limits,
    )
    .await
}

#[cfg(feature = "sockets")]
pub async fn connect(
    address: impl tokio::net::ToSocketAddrs,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let deadline = tokio::time::Instant::now() + limits.attempt_timeout;
    tokio::time::timeout_at(deadline, async {
        let socket = tokio::net::TcpStream::connect(address).await?;
        socket.set_nodelay(true)?;
        connect_stream(socket, security, credential, runtime, limits).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}

/// Listener admission bounds cover concurrent SC1 attempts and live handles.
/// Socket admission is separate from the handshake: `accept_socket` returns
/// before any handshake bytes are read, so callers must drive each
/// connection's `accept_stream` handshake in its own task. Driving `accept`
/// (or `accept_socket` + `accept_stream`) sequentially lets one slow client
/// block subsequent accepts.
#[cfg(feature = "sockets")]
pub struct Listener {
    socket: tokio::net::TcpListener,
    admission: Arc<tokio::sync::Semaphore>,
}

#[cfg(feature = "sockets")]
impl Listener {
    pub async fn bind(
        address: impl tokio::net::ToSocketAddrs,
        maximum_connections: usize,
    ) -> Result<Self, Error> {
        if maximum_connections == 0 || maximum_connections > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(Error::Configuration);
        }
        Ok(Self {
            socket: tokio::net::TcpListener::bind(address).await?,
            admission: Arc::new(tokio::sync::Semaphore::new(maximum_connections)),
        })
    }
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, Error> {
        Ok(self.socket.local_addr()?)
    }
    /// Accept one socket, holding one admission permit until the returned
    /// stream is dropped. Returns before any handshake bytes are read, so a
    /// slow client cannot block subsequent accepts as long as the caller
    /// keeps accepting and drives each `accept_stream` handshake
    /// concurrently. Dropping the stream without completing the handshake
    /// releases the permit; completing it carries the permit into the
    /// connection lifetime via the returned handle.
    pub async fn accept_socket(&self) -> Result<AdmittedStream, Error> {
        let permit = self
            .admission
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Closed)?;
        let (socket, _) = self.socket.accept().await?;
        socket.set_nodelay(true)?;
        Ok(AdmittedStream {
            socket,
            _permit: permit,
        })
    }
    /// Accept one connection and run the SC1 handshake inline. Convenience
    /// wrapper around `accept_socket` + `accept_stream`: drive the returned
    /// future concurrently (spawn one task per call) so a slow handshake
    /// cannot block subsequent accepts.
    pub async fn accept(
        &self,
        security: &ServerConfig,
        factory: Arc<dyn AuthenticatorFactory>,
        handler: Arc<dyn Handler>,
        runtime: ConnectionConfig,
        limits: Limits,
    ) -> Result<HostHandle, Error> {
        let stream = self.accept_socket().await?;
        accept_stream(stream, security, factory, handler, runtime, limits).await
    }
}

/// A socket accepted by `Listener::accept_socket`. The admission permit is
/// held until this stream is dropped, covering the handshake and the whole
/// connection lifetime. Cannot be constructed outside this crate, so the
/// permit cannot be forged or detached from its socket.
#[cfg(feature = "sockets")]
pub struct AdmittedStream {
    socket: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
#[cfg(feature = "sockets")]
impl AsyncRead for AdmittedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
#[cfg(feature = "sockets")]
impl AsyncWrite for AdmittedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.socket).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_shutdown(cx)
    }
}

// The constants stay available to applications compiling with sockets disabled.
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
