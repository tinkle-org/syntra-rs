//! Candidate-only protected connection composition. No carrier inference,
//! downgrade, automatic retry, redirects or application-operation replay.
use super::{client_pair, Authority, OpenEnvelope};
use crate::{pump, tls, ClientHandle, Error, EstablishmentBudget, Limits};
use std::{net::SocketAddr, sync::Arc};
use syntra_core::secure_channel::{Carrier, ClientConfig};
use syntra_runtime::ConnectionConfig;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

impl Authority {
    pub fn tls_authority(&self) -> Result<tls::TlsAuthority, Error> {
        let (host, port) = self.as_str().rsplit_once(':').ok_or(Error::Configuration)?;
        let host = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        tls::TlsAuthority::new(host, port.parse().map_err(|_| Error::Configuration)?)
    }
}

/// Single-owner HTTPS pair. The only public constructor performs real TLS via
/// the configured trusted provider on *both* streams under one original budget.
/// No raw I/O access, cloning or boolean proof permits relabelling the result.
pub struct VerifiedTlsPair {
    upload: tls::VerifiedTlsStream,
    download: tls::VerifiedTlsStream,
    authority: Authority,
}

pub async fn verify_tls_streams_with_budget<U: tls::IoStream, D: tls::IoStream>(
    upload: U,
    download: D,
    provider: &dyn tls::TlsProvider,
    authority: Authority,
    budget: EstablishmentBudget,
) -> Result<VerifiedTlsPair, Error> {
    let expected = authority.tls_authority()?;
    let upload =
        tls::connect_stream_with_budget(upload, provider, expected.clone(), budget.clone()).await?;
    let download = tls::connect_stream_with_budget(download, provider, expected, budget).await?;
    Ok(VerifiedTlsPair {
        upload,
        download,
        authority,
    })
}

pub async fn connect_tls_pair_with_budget(
    pair: VerifiedTlsPair,
    security: ClientConfig,
    credential: Vec<u8>,
    config: (ConnectionConfig, Limits),
) -> Result<ClientHandle, Error> {
    connect_tls_streams_with_budget(
        pair.upload,
        pair.download,
        pair.authority,
        security,
        credential,
        config,
    )
    .await
}

/// Compose two exclusively owned persistent streams into an actual candidate
/// HTTP connection. The explicit `Carrier::Http` selection permits plaintext
/// outer I/O only; integral Noise and the provisioned pin/scope remain mandatory.
/// Both streams must be distinct connections to the provisioned same endpoint,
/// route and policy generation. Generic I/O cannot verify those socket facts.
pub async fn connect_streams_with_budget<U, D>(
    upload: U,
    download: D,
    authority: Authority,
    security: ClientConfig,
    credential: Vec<u8>,
    config: (ConnectionConfig, Limits),
    budget: EstablishmentBudget,
) -> Result<ClientHandle, Error>
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if security.context.carrier != Carrier::Http {
        return Err(Error::Configuration);
    }
    connect_pair(
        upload, download, authority, security, credential, config, budget,
    )
    .await
}

/// HTTPS can only consume two engine-verified TLS streams, each verified for the
/// same authority/client role under the *same original* attempt budget. Matching
/// deadlines alone are not budget identity. No raw stream/boolean escape hatch.
pub async fn connect_tls_streams_with_budget(
    upload: tls::VerifiedTlsStream,
    download: tls::VerifiedTlsStream,
    authority: Authority,
    security: ClientConfig,
    credential: Vec<u8>,
    config: (ConnectionConfig, Limits),
) -> Result<ClientHandle, Error> {
    if security.context.carrier != Carrier::Https {
        return Err(Error::Configuration);
    }
    let expected = authority.tls_authority()?;
    let (upload, um, budget) = upload.into_parts();
    let (download, dm, other) = download.into_parts();
    tls::validate(&um, &expected, tls::TlsRole::Client)?;
    tls::validate(&dm, &expected, tls::TlsRole::Client)?;
    if !Arc::ptr_eq(&budget.io, &other.io) {
        return Err(Error::Configuration);
    }
    connect_pair(
        upload, download, authority, security, credential, config, budget,
    )
    .await
}

async fn connect_pair<U, D>(
    upload: U,
    download: D,
    authority: Authority,
    security: ClientConfig,
    credential: Vec<u8>,
    config: (ConnectionConfig, Limits),
    budget: EstablishmentBudget,
) -> Result<ClientHandle, Error>
where
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (runtime, limits) = config;
    limits.validate(&runtime)?;
    let envelope = OpenEnvelope::new(security.context.encode()?)?;
    let (reader, writer, control) = client_pair(upload, download, authority, envelope, budget);
    let budget = control.take_establishment_budget()?;
    let handle = Box::pin(pump::connect_records_with_budget(
        reader, writer, security, credential, runtime, limits, budget,
    ))
    .await?;
    // Mark Core setup complete. The pair shares the pump's deferred owner phase,
    // so required recovery still bounds both streams until owner acceptance.
    if let Err(error) = control.finish_setup() {
        handle.close().await;
        return Err(error);
    }
    Ok(handle)
}

/// Direct explicit destination; no DNS, proxy discovery, fallback or retry loop.
/// The caller must authorize this socket address separately from the authority
/// and provisioned Noise scope/pin. Create `budget` before selecting/dialing it.
pub async fn connect_with_budget(
    destination: SocketAddr,
    authority: Authority,
    provider: Option<Arc<dyn tls::TlsProvider>>,
    security: ClientConfig,
    credential: Vec<u8>,
    config: (ConnectionConfig, Limits),
    budget: EstablishmentBudget,
) -> Result<ClientHandle, Error> {
    config.1.validate(&config.0)?;
    let secure = match (security.context.carrier, provider.as_ref()) {
        (Carrier::Http, None) => false,
        (Carrier::Https, Some(_)) => true,
        _ => return Err(Error::Configuration),
    };
    let upload = budget.run(TcpStream::connect(destination)).await??;
    upload.set_nodelay(true)?;
    let download = budget.run(TcpStream::connect(destination)).await??;
    download.set_nodelay(true)?;
    if secure {
        let provider = provider.ok_or(Error::Configuration)?;
        let pair =
            verify_tls_streams_with_budget(upload, download, provider.as_ref(), authority, budget)
                .await?;
        connect_tls_pair_with_budget(pair, security, credential, config).await
    } else {
        connect_streams_with_budget(
            upload, download, authority, security, credential, config, budget,
        )
        .await
    }
}
