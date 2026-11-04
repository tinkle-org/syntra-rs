//! One-hop request-header adaptation for the explicit plain HTTP candidate route.
//! This is not a general HTTP proxy client. The candidate codec validates each
//! complete origin header before any of it is emitted. Bodies are never buffered,
//! inspected, rewritten, re-encrypted or replayed. No response is intercepted.
use crate::{
    http::{codec, Authority, OpenEnvelope, OriginPolicy, Route},
    proxy::ProxyConfig,
    stream::EstablishmentIo,
    Error, EstablishmentBudget,
};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::{Zeroize, Zeroizing};

/// Each lane owns one actual connection to the explicitly configured forward
/// proxy. No TLS stream or origin socket can enter this private adapter via the
/// route factory. Credential scope is the proxy hop; a proxy must strip it before
/// forwarding. There is no ambient proxy selection or CONNECT fallback here.
/// Each lane reserves two 16 KiB zeroizing header buffers, but no body buffer.
pub(super) struct ForwardIo<S> {
    inner: EstablishmentIo<S>,
    proxy: Arc<ProxyConfig>,
    authority: Authority,
    envelope: OpenEnvelope,
    upload: bool,
    opened: bool,
    closed: bool,
    route: Option<Route>,
    counter: u64,
    head: Zeroizing<Vec<u8>>,
    wire: Zeroizing<Vec<u8>>,
    offset: usize,
    remaining: usize,
    failed: bool,
}

impl<S> ForwardIo<S> {
    pub(super) fn new(
        inner: S,
        proxy: Arc<ProxyConfig>,
        authority: Authority,
        envelope: OpenEnvelope,
        upload: bool,
        budget: &EstablishmentBudget,
    ) -> Self {
        Self {
            inner: EstablishmentIo {
                inner,
                budget: budget.io.clone(),
            },
            proxy,
            authority,
            envelope,
            upload,
            opened: false,
            closed: false,
            route: None,
            counter: 0,
            head: Zeroizing::new(Vec::with_capacity(codec::MAX_HEADERS)),
            wire: Zeroizing::new(Vec::with_capacity(codec::MAX_HEADERS)),
            offset: 0,
            remaining: 0,
            failed: false,
        }
    }

    fn fail(&mut self, kind: io::ErrorKind) -> io::Error {
        self.failed = true;
        self.head.zeroize();
        self.wire.zeroize();
        io::Error::new(kind, "Syntra HTTP forward stream retired")
    }

    fn rewrite(&mut self) -> Result<(), Error> {
        use codec::Operation;
        let parsed = codec::parse_request(
            &self.head,
            &self.authority,
            &OriginPolicy::default(),
            &self.envelope,
        )?;
        // Enforce lane, initial Open, association syntax/continuity and exact
        // counters in addition to the codec's fixed paths, Host and body bounds.
        match (self.upload, self.opened, parsed.operation) {
            (true, false, Operation::Open) => self.opened = true,
            (true, true, Operation::Send) | (false, _, Operation::Poll) => {
                if parsed.counter != Some(self.counter) {
                    return Err(Error::Framing);
                }
                self.counter = self.counter.checked_add(1).ok_or(Error::Framing)?;
            }
            (true, true, Operation::Close) => self.closed = true,
            _ => return Err(Error::Framing),
        }
        if let Some(route) = parsed.route {
            if self
                .route
                .as_ref()
                .is_some_and(|expected| expected != &route)
            {
                return Err(Error::Framing);
            }
            self.route = Some(route);
        }
        let line_end = self
            .head
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(Error::Framing)?
            + 2;
        // Reserve one header field for hop authentication even when absent.
        let fields = self.head.windows(2).filter(|w| *w == b"\r\n").count() - 2;
        let start = format!(
            "POST http://{}{} HTTP/1.1\r\n",
            self.authority.as_str(),
            parsed.operation.path()
        );
        let rest = &self.head[line_end..self.head.len() - 2];
        if fields >= codec::MAX_FIELDS
            || start.len() > codec::MAX_START_LINE
            || start.len() + rest.len() + 2 > codec::MAX_HEADERS
        {
            return Err(Error::Framing);
        }
        self.wire.extend_from_slice(start.as_bytes());
        self.wire.extend_from_slice(rest);
        self.proxy.append_forward_authorization(&mut self.wire)?;
        if self.wire.len() + 2 > codec::MAX_HEADERS {
            return Err(Error::Framing);
        }
        self.wire.extend_from_slice(b"\r\n");
        self.head.zeroize();
        self.remaining = parsed.body_len;
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> ForwardIo<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.wire.is_empty() {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_write(cx, &self.wire[self.offset..]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.fail(error.kind());
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(0)) => Poll::Ready(Err(self.fail(io::ErrorKind::WriteZero))),
            Poll::Ready(Ok(n)) => {
                self.offset += n;
                if self.offset == self.wire.len() {
                    self.wire.zeroize();
                    self.offset = 0;
                }
                // Exactly one raw write per outer poll, including Ready loops.
                // The HTTP/pump's lifecycle/deadline gate runs before the next
                // repoll; the selected immutable header and cursor are retained.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ForwardIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ForwardIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.drain(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if this.remaining != 0 {
            let end = bytes.len().min(this.remaining);
            return match Pin::new(&mut this.inner).poll_write(cx, &bytes[..end]) {
                Poll::Ready(Ok(0)) => Poll::Ready(Err(this.fail(io::ErrorKind::WriteZero))),
                Poll::Ready(Ok(n)) => {
                    this.remaining -= n;
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(error)) => {
                    this.fail(error.kind());
                    Poll::Ready(Err(error))
                }
                Poll::Pending => Poll::Pending,
            };
        }
        if this.closed {
            return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
        }
        for (index, byte) in bytes.iter().enumerate() {
            if this.head.len() == codec::MAX_HEADERS {
                return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
            }
            this.head.push(*byte);
            if this.head.ends_with(b"\r\n\r\n") {
                if this.rewrite().is_err() {
                    return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
                }
                // Acknowledge origin header bytes, never the larger wire count.
                // A following body write or flush drains the immutable header.
                return Poll::Ready(Ok(index + 1));
            }
        }
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || !this.head.is_empty() || this.remaining != 0 {
            return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
        }
        match this.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed || !this.head.is_empty() || !this.wire.is_empty() || this.remaining != 0 {
            return Poll::Ready(Err(this.fail(io::ErrorKind::InvalidData)));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyCredentials;
    use std::time::Duration;
    use syntra_runtime::elapsed::ElapsedClock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn adapter<S>(stream: S, upload: bool) -> ForwardIo<S> {
        let proxy = Arc::new(
            ProxyConfig::http_connect(
                "127.0.0.1:1".parse().unwrap(),
                Some(ProxyCredentials::new(b"u".to_vec(), b"p".to_vec()).unwrap()),
            )
            .unwrap(),
        );
        ForwardIo::new(
            stream,
            proxy,
            Authority::new("localhost:38080").unwrap(),
            OpenEnvelope::new(vec![1; 35]).unwrap(),
            upload,
            &EstablishmentBudget::new(ElapsedClock::lifecycle_driven(), Duration::from_secs(5))
                .unwrap(),
        )
    }

    fn message() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut body = vec![1; 83];
        body[40..44].copy_from_slice(b"\r\n\r\n");
        let header = codec::request(
            codec::Operation::Open,
            &Authority::new("localhost:38080").unwrap(),
            None,
            None,
            &body,
            &OpenEnvelope::new(vec![1; 35]).unwrap(),
        )
        .unwrap();
        let text = std::str::from_utf8(&header).unwrap();
        let expected = text.replacen("POST /", "POST http://localhost:38080/", 1);
        let expected = expected.strip_suffix("\r\n").unwrap();
        let mut expected =
            format!("{expected}Proxy-Authorization: Basic dTpw\r\n\r\n").into_bytes();
        expected.extend_from_slice(&body);
        (header, body, expected)
    }

    #[tokio::test]
    async fn every_header_split_tiny_partial_writes_preserve_byte_counts_and_body() {
        let (header, body, expected) = message();
        for split in 0..=header.len() {
            let (stream, mut peer) = tokio::io::duplex(3);
            let mut writer = adapter(stream, true);
            let write = async {
                writer.write_all(&header[..split]).await.unwrap();
                writer.write_all(&header[split..]).await.unwrap();
                let ptr = body.as_ptr();
                writer.write_all(&body).await.unwrap();
                assert_eq!(ptr, body.as_ptr());
                writer.flush().await.unwrap();
                drop(writer);
            };
            let read = async {
                let mut actual = Vec::new();
                peer.read_to_end(&mut actual).await.unwrap();
                assert_eq!(actual, expected, "split {split}");
            };
            tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(write, read);
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_authority_path_fields_lane_and_header_bound_emit_nothing() {
        let (header, _, _) = message();
        let text = std::str::from_utf8(&header).unwrap();
        for bad in [
            text.replace("Host: localhost:38080", "Host: other.invalid:38080")
                .into_bytes(),
            text.replace("/http/open", "/http/open?route=x")
                .into_bytes(),
            text.replace("/http/open", "/http/unknown").into_bytes(),
            text.replace(
                "\r\n\r\n",
                "\r\nProxy-Authorization: Basic injected\r\n\r\n",
            )
            .into_bytes(),
            text.replace("\r\n\r\n", "\r\nAuthorization: injected\r\n\r\n")
                .into_bytes(),
            text.replace("\r\n\r\n", "\r\nCookie: injected\r\n\r\n")
                .into_bytes(),
            text.replace("\r\n\r\n", "\r\nHost: localhost:38080\r\n\r\n")
                .into_bytes(),
            vec![b'x'; codec::MAX_HEADERS + 1],
        ] {
            let (stream, mut peer) = tokio::io::duplex(1);
            let mut writer = adapter(stream, true);
            assert!(writer.write_all(&bad).await.is_err());
            assert!(writer.flush().await.is_err());
            drop(writer);
            assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        }
        let (stream, mut peer) = tokio::io::duplex(1);
        let mut download = adapter(stream, false);
        assert!(
            download.write_all(&header).await.is_err(),
            "Open on download lane"
        );
        drop(download);
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn cancelling_owner_during_stalled_rewritten_header_never_duplicates_output() {
        let (header, body, expected) = message();
        let mut input = header;
        input.extend_from_slice(&body);
        let (stream, mut peer) = tokio::io::duplex(4);
        let mut writer = adapter(stream, true);
        let mut pending = Box::pin(writer.write_all(&input));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), pending.as_mut())
                .await
                .is_err()
        );
        drop(pending);
        // Production cancellation retires the enclosing HTTP pair and disposes
        // this owner. This private writer is never retried as a standalone unit.
        drop(writer);
        let mut actual = Vec::new();
        peer.read_to_end(&mut actual).await.unwrap();
        assert_eq!(actual, expected[..4]);
    }
}
