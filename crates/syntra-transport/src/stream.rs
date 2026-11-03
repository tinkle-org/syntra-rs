//! Per-poll establishment gate shared by native stream bindings.
use crate::pump::AttemptIoBudget;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Once CoreReady is committed, the pump's serialized Core gate owns lifecycle
/// admission; this wrapper never reenters Core under that gate.
pub(crate) struct EstablishmentIo<S> {
    pub(crate) inner: S,
    pub(crate) budget: Arc<AttemptIoBudget>,
}
impl<S: AsyncRead + Unpin> AsyncRead for EstablishmentIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.budget.check()?;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                this.budget.check()?;
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for EstablishmentIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.budget.check()?;
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.budget.check()?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.budget.check()?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}
