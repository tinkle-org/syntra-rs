//! Encrypted Syntra 1.0 TCP binding. Never selected as a fallback from WSS.
use crate::pump;
use crate::stream::EstablishmentIo;

pub use pump::{AuthenticatorFactory, ClientHandle, Error, HostHandle, Limits};
use std::{sync::Arc, time::Duration};
use syntra_core::secure_channel::{Carrier, ClientConfig, ServerConfig, MAX_CIPHERTEXT};
use syntra_runtime::{ConnectionConfig, Handler};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const BINDING: &str = "syntra.1.0";

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
    limits.validate(&runtime)?;
    let budget =
        pump::EstablishmentBudget::new(pump::default_elapsed_clock(), limits.attempt_timeout)?;
    connect_stream_with_budget(stream, security, credential, runtime, limits, budget).await
}

/// Continue the caller's original dial budget without resetting its deadline.
pub async fn connect_stream_with_budget<S>(
    stream: S,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
    budget: pump::EstablishmentBudget,
) -> Result<ClientHandle, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    limits.validate(&runtime)?;
    if security.context.carrier != Carrier::Tcp {
        return Err(Error::Framing);
    }
    let stream = EstablishmentIo {
        inner: stream,
        budget: budget.io.clone(),
    };
    let (read, write) = tokio::io::split(stream);
    pump::connect_records_with_budget(
        StreamReader(read),
        StreamWriter(write),
        security,
        credential,
        runtime,
        limits,
        budget,
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
    limits.validate(&runtime)?;
    let budget = pump::EstablishmentBudget::new(factory.elapsed_clock(), limits.attempt_timeout)?;
    accept_stream_with_budget(
        stream,
        security,
        factory,
        handler,
        (runtime, limits),
        budget,
    )
    .await
}

/// Continue admission under the same elapsed source and deadline as the dialer.
pub async fn accept_stream_with_budget<S>(
    stream: S,
    security: &ServerConfig,
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
    config: (ConnectionConfig, Limits),
    budget: pump::EstablishmentBudget,
) -> Result<HostHandle, Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (runtime, limits) = config;
    limits.validate(&runtime)?;
    if security.carrier != Carrier::Tcp {
        return Err(Error::Framing);
    }
    let stream = EstablishmentIo {
        inner: stream,
        budget: budget.io.clone(),
    };
    let (read, write) = tokio::io::split(stream);
    pump::accept_tcp_records_with_budget(
        StreamReader(read),
        StreamWriter(write),
        security,
        factory,
        handler,
        (runtime, limits),
        budget,
    )
    .await
}

pub async fn connect(
    address: impl tokio::net::ToSocketAddrs,
    security: ClientConfig,
    credential: Vec<u8>,
    runtime: ConnectionConfig,
    limits: Limits,
) -> Result<ClientHandle, Error> {
    limits.validate(&runtime)?;
    let budget =
        pump::EstablishmentBudget::new(pump::default_elapsed_clock(), limits.attempt_timeout)?;
    let socket = budget
        .run(async {
            let socket = tokio::net::TcpStream::connect(address).await?;
            socket.set_nodelay(true)?;
            Ok::<_, Error>(socket)
        })
        .await??;
    connect_stream_with_budget(socket, security, credential, runtime, limits, budget).await
}

/// Listener admission bounds cover concurrent Syntra attempts and live handles.
/// Socket admission is separate from the handshake: `accept_socket` returns
/// before any handshake bytes are read, so callers must drive each
/// connection's `accept_stream` handshake in its own task. Driving `accept`
/// (or `accept_socket` + `accept_stream`) sequentially lets one slow client
/// block subsequent accepts.
pub struct Listener {
    socket: tokio::net::TcpListener,
    admission: Arc<tokio::sync::Semaphore>,
}

/// Internal stage boundary; public accept APIs still return the original error.
#[derive(Debug)]
pub(crate) enum AcceptError {
    Retryable(std::io::Error),
    Terminal(Error),
}

impl AcceptError {
    pub(crate) fn socket_accept(error: std::io::Error) -> Self {
        use std::io::ErrorKind;
        // Unknown errors fail closed. Some retryable accept errors lack a stable
        // ErrorKind, so recognize native resource limits and pending network errors.
        let mut resource = false;
        #[cfg(unix)]
        {
            // ENOMEM, ENFILE, EMFILE.
            resource |= matches!(error.raw_os_error(), Some(12 | 23 | 24));
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // ENONET, EPROTO, ENOPROTOOPT, EOPNOTSUPP, ENOBUFS, EHOSTDOWN.
            resource |= matches!(error.raw_os_error(), Some(64 | 71 | 92 | 95 | 105 | 112));
        }
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "dragonfly"
        ))]
        {
            // ENOBUFS.
            resource |= error.raw_os_error() == Some(55);
        }
        #[cfg(windows)]
        {
            // WSAEMFILE, WSAENOBUFS.
            resource |= matches!(error.raw_os_error(), Some(10024 | 10055));
        }
        if resource
            || matches!(
                error.kind(),
                ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionRefused
                    | ErrorKind::Interrupted
                    | ErrorKind::WouldBlock
                    | ErrorKind::TimedOut
                    | ErrorKind::OutOfMemory
                    | ErrorKind::NetworkDown
                    | ErrorKind::NetworkUnreachable
                    | ErrorKind::HostUnreachable
            )
        {
            Self::Retryable(error)
        } else {
            Self::Terminal(Error::Io(error))
        }
    }

    fn into_error(self) -> Error {
        match self {
            Self::Retryable(error) => Error::Io(error),
            Self::Terminal(error) => error,
        }
    }
}

impl From<Error> for AcceptError {
    fn from(error: Error) -> Self {
        Self::Terminal(error)
    }
}

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
        self.accept_socket_classified()
            .await
            .map_err(AcceptError::into_error)
    }

    pub(crate) async fn accept_socket_classified(&self) -> Result<AdmittedStream, AcceptError> {
        self.accept_socket_with(self.socket.accept(), |socket| socket.set_nodelay(true))
            .await
    }

    pub(crate) async fn accept_socket_with(
        &self,
        raw_socket: impl std::future::Future<
                Output = std::io::Result<(tokio::net::TcpStream, std::net::SocketAddr)>,
            > + Send,
        configure: impl FnOnce(&tokio::net::TcpStream) -> std::io::Result<()> + Send,
    ) -> Result<AdmittedStream, AcceptError> {
        let permit = self
            .admission
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Closed)?;
        let (socket, _) = raw_socket.await.map_err(AcceptError::socket_accept)?;
        configure(&socket).map_err(AcceptError::Retryable)?;
        Ok(AdmittedStream {
            socket,
            _permit: permit,
        })
    }
    /// Accept one connection and run the Syntra handshake inline. Convenience
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
        limits.validate(&runtime)?;
        let stream = self.accept_socket().await?;
        accept_stream(stream, security, factory, handler, runtime, limits).await
    }
}

/// A socket accepted by `Listener::accept_socket`. The admission permit is
/// held until this stream is dropped, covering the handshake and the whole
/// connection lifetime. Cannot be constructed outside this crate, so the
/// permit cannot be forged or detached from its socket.
pub struct AdmittedStream {
    socket: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl AsyncRead for AdmittedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.socket).poll_read(cx, buf)
    }
}
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

pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        sync::atomic::{AtomicU64, AtomicUsize, Ordering},
        task::{Context, Poll},
    };
    use syntra_core::secure_channel::{generate_server_key, Context as ChannelContext, Mode};
    use syntra_runtime::elapsed::{ElapsedClock, ElapsedSource};

    #[test]
    fn accept_error_classification_preserves_stage_and_public_io_error() {
        use std::io::ErrorKind;
        for kind in [
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionReset,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
            ErrorKind::OutOfMemory,
            ErrorKind::NetworkDown,
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
        ] {
            let error = AcceptError::socket_accept(kind.into());
            assert!(matches!(error, AcceptError::Retryable(_)), "{kind:?}");
            assert!(matches!(error.into_error(), Error::Io(e) if e.kind() == kind));
            assert!(matches!(
                AcceptError::from(Error::Io(kind.into())),
                AcceptError::Terminal(_)
            ));
        }
        for kind in [
            ErrorKind::InvalidInput,
            ErrorKind::PermissionDenied,
            ErrorKind::Unsupported,
            ErrorKind::NotConnected,
            ErrorKind::Other,
        ] {
            assert!(
                matches!(
                    AcceptError::socket_accept(kind.into()),
                    AcceptError::Terminal(_)
                ),
                "{kind:?}"
            );
        }
        #[cfg(unix)]
        for code in [12, 23, 24] {
            assert!(matches!(
                AcceptError::socket_accept(std::io::Error::from_raw_os_error(code)),
                AcceptError::Retryable(_)
            ));
        }
        #[cfg(unix)]
        // EBADF is a broken listener, not temporary descriptor exhaustion.
        assert!(matches!(
            AcceptError::socket_accept(std::io::Error::from_raw_os_error(9)),
            AcceptError::Terminal(_)
        ));
        #[cfg(any(target_os = "linux", target_os = "android"))]
        for code in [64, 71, 92, 95, 105, 112] {
            let error = AcceptError::socket_accept(std::io::Error::from_raw_os_error(code));
            assert!(matches!(error, AcceptError::Retryable(_)), "errno {code}");
            assert!(matches!(error.into_error(), Error::Io(e) if e.raw_os_error() == Some(code)));
        }
        #[cfg(windows)]
        for code in [10024, 10055] {
            assert!(matches!(
                AcceptError::socket_accept(std::io::Error::from_raw_os_error(code)),
                AcceptError::Retryable(_)
            ));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_accept_setup_failure_and_cancellation_release_local_admission() {
        use futures_util::FutureExt;
        let listener = Listener::bind("127.0.0.1:0", 1).await.unwrap();
        let mut peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let result = listener
            .accept_socket_with(listener.socket.accept(), |_| {
                Err(std::io::ErrorKind::Other.into())
            })
            .await;
        assert!(matches!(result, Err(AcceptError::Retryable(_))));
        assert_eq!(listener.admission.available_permits(), 1);
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let mut accepting = Box::pin(listener.accept_socket());
        assert!(accepting.as_mut().now_or_never().is_none());
        assert_eq!(listener.admission.available_permits(), 0);
        drop(accepting);
        assert_eq!(listener.admission.available_permits(), 1);
        listener.admission.close();
        assert!(matches!(
            listener.accept_socket().now_or_never(),
            Some(Err(Error::Closed))
        ));
        assert_eq!(listener.admission.available_permits(), 1);
    }

    struct Source(AtomicU64);
    impl ElapsedSource for Source {
        fn elapsed(&self) -> Option<Duration> {
            Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    struct JumpWrite {
        source: Arc<Source>,
        writes: Arc<AtomicUsize>,
    }
    impl AsyncRead for JumpWrite {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }
    impl AsyncWrite for JumpWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.source.0.store(1000, Ordering::SeqCst);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    fn security() -> ClientConfig {
        let (_, public) = generate_server_key().unwrap();
        ClientConfig {
            context: ChannelContext {
                mode: Mode::Bootstrap,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: b"tcp-budget".to_vec(),
                handle: [0; 8],
                epoch: 0,
            },
            server_public_key: public,
            authorization_key: None,
        }
    }
    #[tokio::test(start_paused = true)]
    async fn tcp_gates_each_raw_poll_even_within_one_record_write() {
        let source = Arc::new(Source(AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let budget = pump::EstablishmentBudget::new(clock, Duration::from_secs(1)).unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let stream = JumpWrite {
            source,
            writes: writes.clone(),
        };
        let result = connect_stream_with_budget(
            stream,
            security(),
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
            budget,
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(
            writes.load(Ordering::SeqCst),
            1,
            "a length-prefix poll crossing the cutoff must not write its payload"
        );
    }
    #[tokio::test(start_paused = true)]
    async fn tcp_channel_cutoff_gates_raw_polls_before_the_longer_total_budget() {
        let source = Arc::new(Source(AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let budget = pump::EstablishmentBudget::new(clock, Duration::from_secs(15)).unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let result = connect_stream_with_budget(
            JumpWrite {
                source,
                writes: writes.clone(),
            },
            security(),
            vec![],
            ConnectionConfig::default(),
            Limits {
                channel_timeout: Duration::from_secs(1),
                ..Default::default()
            },
            budget,
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn tcp_does_not_reset_an_external_dialers_elapsed_budget() {
        let source = Arc::new(Source(AtomicU64::new(0)));
        let clock = ElapsedClock::with_source(source.clone());
        let budget = pump::EstablishmentBudget::new(clock, Duration::from_secs(1)).unwrap();
        source.0.store(1000, Ordering::SeqCst);
        let writes = Arc::new(AtomicUsize::new(0));
        let result = connect_stream_with_budget(
            JumpWrite {
                source,
                writes: writes.clone(),
            },
            security(),
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
            budget,
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}
