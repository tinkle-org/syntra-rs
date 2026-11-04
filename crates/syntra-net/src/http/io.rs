use super::panic::Failure;
use crate::{tls::BoxIo, EstablishmentBudget};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{oneshot, OwnedSemaphorePermit},
};

/// Catch dependency I/O panics *inside* the raw poll, before unwinding through
/// Core's serialized emission gate (whose mutex must not be poisoned). Failure
/// is sticky across both streams. The owned stream is retained until cleanup;
/// a panicked TLS/adapter state is never polled again or substituted/retried.
pub(super) struct Contained<S> {
    pub inner: S,
    pub failure: Arc<Failure>,
}
impl<S> Contained<S> {
    fn poll<T>(&mut self, work: impl FnOnce(&mut S) -> Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if !self.failure.failed() {
            if let Some(result) = self.failure.catch(|| work(&mut self.inner)) {
                return result;
            }
        }
        Poll::Ready(Err(io::Error::other("Syntra HTTP I/O failed")))
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Contained<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll(|inner| Pin::new(inner).poll_read(cx, buf))
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Contained<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll(|inner| Pin::new(inner).poll_write(cx, bytes))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll(|inner| Pin::new(inner).poll_flush(cx))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll(|inner| Pin::new(inner).poll_shutdown(cx))
    }
}

/// Admission ownership follows the actual socket, including TLS buffering and
/// partial I/O. Dropping a logical handle cannot release a live socket's permit.
pub(super) struct Admitted<S> {
    pub inner: S,
    pub _permit: OwnedSemaphorePermit,
    pub _global_permit: OwnedSemaphorePermit,
}
impl<S: AsyncRead + Unpin> AsyncRead for Admitted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Admitted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Replay only the bounded bytes consumed by initial dispatch. There is no
/// scanning, retransmission, stream substitution or attacker-sized read-ahead.
pub(super) struct ReplayStream {
    pub inner: BoxIo,
    pub prefix: std::io::Cursor<Vec<u8>>,
}
impl ReplayStream {
    pub fn new(inner: BoxIo, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix: std::io::Cursor::new(prefix),
        }
    }
}
impl AsyncRead for ReplayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let at = this.prefix.position() as usize;
        let bytes = this.prefix.get_ref();
        if at < bytes.len() && buf.remaining() != 0 {
            let count = (bytes.len() - at).min(buf.remaining());
            buf.put_slice(&bytes[at..at + count]);
            this.prefix.set_position((at + count) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for ReplayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

pub(super) struct Attached {
    pub stream: ReplayStream,
    pub budget: EstablishmentBudget,
}

/// U/Noise starts before D exists. Only the registry can fulfill this one-shot,
/// after validating the first poll and atomically consuming D ownership.
pub(super) struct DeferredDownload {
    pub receiver: oneshot::Receiver<Attached>,
    pub stream: Option<ReplayStream>,
    pub budget: Arc<Mutex<Option<EstablishmentBudget>>>,
}
impl DeferredDownload {
    fn poll_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut ReplayStream>> {
        if self.stream.is_none() {
            let attached = ready!(Pin::new(&mut self.receiver).poll(cx))
                .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))?;
            *self
                .budget
                .lock()
                .map_err(|_| io::Error::from(io::ErrorKind::ConnectionAborted))? =
                Some(attached.budget);
            self.stream = Some(attached.stream);
        }
        Poll::Ready(
            self.stream
                .as_mut()
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionAborted)),
        )
    }
}
impl AsyncRead for DeferredDownload {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(ready!(self.get_mut().poll_stream(cx))?).poll_read(cx, buf)
    }
}
impl AsyncWrite for DeferredDownload {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(ready!(self.get_mut().poll_stream(cx))?).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(ready!(self.get_mut().poll_stream(cx))?).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(ready!(self.get_mut().poll_stream(cx))?).poll_shutdown(cx)
    }
}
