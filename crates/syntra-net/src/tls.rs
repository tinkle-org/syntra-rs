//! Trusted application TLS termination for native WSS stream composition.
//!
//! This in-process provider boundary is an implementation-branch proposal, not
//! adoption of Draft RFC0013 or a completed public approval/security review.
//! The provider is part of the application's trusted computing base. Metadata
//! checks bind its result to one role, authority and attempt; they cannot prove
//! that an arbitrary provider performed TLS. An arbitrary boolean, a forwarded
//! header, a proxy's claims, or a plaintext stream is not security attestation.

use crate::{stream::EstablishmentIo, Error, EstablishmentBudget};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Owned connected I/O. Providers must retain this exact stream, including its
/// per-poll deadline gate, rather than dial another connection or detach tasks.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> IoStream for S {}
pub type BoxIo = Box<dyn IoStream>;

// Keep the record adapter's stream type concrete across its async trait methods.
// Only this module can expose the provider-owned dynamic I/O to those adapters.
pub(crate) struct ProviderIo(BoxIo);
impl AsyncRead for ProviderIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
    }
}
impl AsyncWrite for ProviderIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

/// Canonical URL host and effective port, without credentials or HTTP claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsAuthority {
    host: String,
    port: u16,
}

impl TlsAuthority {
    pub fn new(host: &str, port: u16) -> Result<Self, Error> {
        if port == 0 {
            return Err(Error::Configuration);
        }
        let host = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => url::Host::Ipv4(ip),
            Ok(std::net::IpAddr::V6(ip)) => url::Host::Ipv6(ip),
            Err(_) => url::Host::parse(host).map_err(|_| Error::Configuration)?,
        };
        if matches!(&host, url::Host::Domain(name) if name.is_empty()) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            host: match host {
                url::Host::Domain(name) => name,
                url::Host::Ipv4(ip) => ip.to_string(),
                url::Host::Ipv6(ip) => ip.to_string(),
            },
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    #[cfg(feature = "websocket")]
    pub(crate) fn from_url(url: &url::Url) -> Result<Self, Error> {
        let host = match url.host().ok_or(Error::Configuration)? {
            url::Host::Domain(name) => name.to_owned(),
            url::Host::Ipv4(ip) => ip.to_string(),
            url::Host::Ipv6(ip) => format!("[{ip}]"),
        };
        Self::new(
            &host,
            url.port_or_known_default().ok_or(Error::Configuration)?,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsRole {
    Client,
    Server,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EarlyData {
    Disabled,
    Enabled,
}

/// Connection-scoped observations from the provider's completed TLS session.
/// Chain/name/current-policy validation is a provider obligation, not a boolean
/// accepted here. Report the actual negotiated version/ALPN and early-data policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsMetadata {
    pub authority: TlsAuthority,
    pub role: TlsRole,
    /// TLS wire version; TLS 1.3 is 0x0304.
    pub protocol_version: u16,
    pub alpn: Option<Vec<u8>>,
    /// Must be disabled, not merely offered but unused on this connection.
    pub early_data: EarlyData,
}

/// Unchecked provider output. Only the engine can turn it into a
/// [`VerifiedTlsStream`], after checking its metadata under the original budget.
pub struct ProviderTlsStream {
    stream: BoxIo,
    metadata: TlsMetadata,
}

impl ProviderTlsStream {
    /// For trusted providers only, after successful authenticated TLS completion.
    /// This constructor alone does not create a verified WSS stream.
    pub fn new(stream: BoxIo, metadata: TlsMetadata) -> Self {
        Self { stream, metadata }
    }
}

pub type TlsFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderTlsStream, Error>> + Send + 'a>>;

/// Trusted application TLS implementation, not a certificate-verification hook.
///
/// Both methods must complete TLS 1.3 on the supplied connection, disable early
/// data/0-RTT even on resumed sessions, and negotiate exactly `http/1.1` ALPN. Client
/// establishment must validate the server chain, authority hostname, certificate
/// time validity and current application trust/revocation policy, also on resumed
/// sessions. Server establishment must use current policy and credentials for the
/// supplied local authority. SNI/forwarded headers alone do not establish it.
///
/// Read version/ALPN/role metadata from that completed connection, not from peer
/// assertions or cached results for another connection. Never return plaintext,
/// bypass the supplied I/O gate, emit HTTP/Syntra data before completion, or spawn
/// detached I/O. Dropping the future must release partial TLS state and its sole
/// stream owner. TLS does not authenticate a Syntra application principal.
/// Certificate/protocol/policy rejection returns `Error::Configuration`, not a
/// retryable socket failure; I/O uses `Error::Io`/`Closed`. Never retry a trust
/// failure by weakening TLS policy or selecting a plaintext carrier.
///
/// A dishonest implementation can fabricate both stream and metadata. The safe
/// Rust type enforces ownership, not trust in arbitrary code or an external TLS
/// terminator; choosing/reviewing this provider is the application's obligation.
pub trait TlsProvider: Send + Sync {
    fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_>;
    fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_>;
}

/// Single-owner TLS result. No public constructor, raw inner access, Clone, or
/// AsyncRead/AsyncWrite implementation permits relabelling it as another proof.
pub struct VerifiedTlsStream {
    stream: ProviderIo,
    metadata: TlsMetadata,
    budget: EstablishmentBudget,
}

impl VerifiedTlsStream {
    pub fn metadata(&self) -> &TlsMetadata {
        &self.metadata
    }

    pub(crate) fn into_parts(self) -> (ProviderIo, TlsMetadata, EstablishmentBudget) {
        (self.stream, self.metadata, self.budget)
    }
}

pub(crate) fn validate(
    metadata: &TlsMetadata,
    authority: &TlsAuthority,
    role: TlsRole,
) -> Result<(), Error> {
    if metadata.authority != *authority
        || metadata.role != role
        || metadata.protocol_version != 0x0304
        || metadata.alpn.as_deref() != Some(b"http/1.1".as_slice())
        || metadata.early_data != EarlyData::Disabled
    {
        return Err(Error::Configuration);
    }
    Ok(())
}

/// Complete client TLS on an engine-dialed connected stream. Create the budget
/// before dialing and bound that dial with `budget.run`. The result owns that
/// budget through `websocket::connect_tls_stream_with_budget`; it cannot be
/// replaced or reused for another connection.
///
/// ```compile_fail,E0382
/// use syntra_net::{tls, EstablishmentBudget};
/// fn reuse(a: tokio::io::DuplexStream, b: tokio::io::DuplexStream,
///          provider: &dyn tls::TlsProvider, authority: tls::TlsAuthority,
///          budget: EstablishmentBudget) {
///     let first = tls::connect_stream_with_budget(a, provider, authority.clone(), budget);
///     let second = tls::connect_stream_with_budget(b, provider, authority, budget);
/// }
/// ```
pub async fn connect_stream_with_budget<S: IoStream>(
    stream: S,
    provider: &dyn TlsProvider,
    authority: TlsAuthority,
    budget: EstablishmentBudget,
) -> Result<VerifiedTlsStream, Error> {
    establish(stream, provider, authority, TlsRole::Client, budget).await
}

/// Complete server TLS on an engine-accepted connected stream. Retain aggregate
/// admission ownership through TLS, WebSocket, Syntra readiness and teardown.
/// The result carries the same budget into `websocket::accept_verified_tls_stream`.
pub async fn accept_stream_with_budget<S: IoStream>(
    stream: S,
    provider: &dyn TlsProvider,
    authority: TlsAuthority,
    budget: EstablishmentBudget,
) -> Result<VerifiedTlsStream, Error> {
    establish(stream, provider, authority, TlsRole::Server, budget).await
}

async fn establish<S: IoStream>(
    stream: S,
    provider: &dyn TlsProvider,
    authority: TlsAuthority,
    role: TlsRole,
    budget: EstablishmentBudget,
) -> Result<VerifiedTlsStream, Error> {
    let stream: BoxIo = Box::new(EstablishmentIo {
        inner: stream,
        budget: budget.io.clone(),
    });
    let result = budget
        .run(Box::pin(async move {
            let result = match role {
                TlsRole::Client => provider.connect(stream, authority.clone()).await?,
                TlsRole::Server => provider.accept(stream, authority.clone()).await?,
            };
            validate(&result.metadata, &authority, role)?;
            Ok::<_, Error>(result)
        }))
        .await??;
    Ok(VerifiedTlsStream {
        // Gate buffered TLS plaintext as well as underlying encrypted I/O.
        stream: ProviderIo(Box::new(EstablishmentIo {
            inner: result.stream,
            budget: budget.io.clone(),
        })),
        metadata: result.metadata,
        budget,
    })
}
