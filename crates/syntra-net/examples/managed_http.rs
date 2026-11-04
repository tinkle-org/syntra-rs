//! Run with `cargo run -p syntra-net --no-default-features --features managed,http --example managed_http`.
//! Add `-- --https` for HTTPS with an in-process, locally trusted TLS provider.
//! Draft RFC0013 candidate pending adoption, not production-approved support or
//! conformance evidence. Both modes perform an encrypted bootstrap echo; returning
//! mode is exercised separately by the connection/managed networking test suites.
//!
//! The configured canonical authority is mapped explicitly to an ephemeral loopback
//! socket. Its port is a logical service port, NOT the physical listener port.
//! No DNS discovery, remote trust learning, or bind/drop/rebind port reservation.

use std::{
    error::Error as StdError,
    io,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use syntra_core::{
    secure_channel::{
        generate_server_key, Carrier, ClientConfig, Context, Mode, ServerConfig, VerifiedIdentity,
    },
    ErrorCode,
};
use syntra_net::{
    client::{CallError, LifecycleStatus, ReconnectConfig},
    http::{self, Authority, ServerLimits},
    network::{ManagedClient, Network, NetworkConfig},
    routes::{client_routes, Endpoint, Route, RouteConfig},
    tls::{
        BoxIo, EarlyData, ProviderTlsStream, TlsAuthority, TlsFuture, TlsMetadata, TlsProvider,
        TlsRole,
    },
    AuthenticatorFactory, Error, Limits,
};
use syntra_runtime::{
    AuthError, Authenticator, CancelToken, Handler, HandlerFut, HandlerOutcome, Principal,
    StaticToken,
};

type DemoResult = Result<(), Box<dyn StdError>>;
const WAIT: Duration = Duration::from_secs(10);
const ATTEMPT: Duration = Duration::from_secs(5);
const HOSTNAME: &str = "localhost";
const SCOPE: &[u8] = b"managed-http-candidate-demo";
const ECHO: &str = "/demo.Echo/Echo";
const SUBJECT: &str = "local-demo-client";
// Public placeholder for this in-process demo, not a deployment credential.
const CREDENTIAL: &[u8] = b"demo-only-placeholder-token";

/// Example-local trust: normal rustls chain/hostname/current-time verification
/// against this run's sole locally generated root, never a root learned from a
/// TLS peer. No OS trust changes, certificate bypass, resumption or early data.
/// Trust and credentials live only for this run; deployment revocation and
/// credential rotation policies are not implemented by this local demo.
struct LocalTls {
    authority: TlsAuthority,
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
}

impl LocalTls {
    fn new(authority: TlsAuthority) -> Result<Self, Box<dyn StdError>> {
        let cert = rcgen::generate_simple_self_signed(vec![HOSTNAME.into()])?;
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        // Trusted local provisioning before either TLS stream is dialed.
        roots.add(cert.cert.der().clone())?;
        let mut client = rustls::ClientConfig::builder_with_provider(crypto.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        client.enable_early_data = false;
        client.resumption = rustls::client::Resumption::disabled();
        let mut server = rustls::ServerConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )?;
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        server.max_early_data_size = 0;
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        Ok(Self {
            authority,
            client: Arc::new(client),
            server: Arc::new(server),
        })
    }
}

fn tls_error(error: io::Error) -> Error {
    if error
        .get_ref()
        .is_some_and(|cause| cause.is::<rustls::Error>())
        || matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput
        )
    {
        Error::Configuration
    } else {
        Error::Io(error)
    }
}

impl TlsProvider for LocalTls {
    fn connect(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
        Box::pin(async move {
            if authority != self.authority {
                return Err(Error::Configuration);
            }
            let name = rustls::pki_types::ServerName::try_from(authority.host().to_owned())
                .map_err(|_| Error::Configuration)?;
            // Keep the supplied deadline-gated stream: no redial or detached I/O.
            let stream = tokio_rustls::TlsConnector::from(self.client.clone())
                .connect(name, stream)
                .await
                .map_err(tls_error)?;
            let session = stream.get_ref().1;
            let metadata = TlsMetadata {
                authority,
                role: TlsRole::Client,
                protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                early_data: if self.client.enable_early_data || session.is_early_data_accepted() {
                    EarlyData::Enabled
                } else {
                    EarlyData::Disabled
                },
            };
            Ok(ProviderTlsStream::new(Box::new(stream), metadata))
        })
    }

    fn accept(&self, stream: BoxIo, authority: TlsAuthority) -> TlsFuture<'_> {
        Box::pin(async move {
            // Listener-provisioned authority, not a peer SNI/HTTP trust claim.
            if authority != self.authority {
                return Err(Error::Configuration);
            }
            let stream = tokio_rustls::TlsAcceptor::from(self.server.clone())
                .accept(stream)
                .await
                .map_err(tls_error)?;
            let session = stream.get_ref().1;
            let metadata = TlsMetadata {
                authority,
                role: TlsRole::Server,
                protocol_version: session.protocol_version().map(u16::from).unwrap_or(0),
                alpn: session.alpn_protocol().map(<[u8]>::to_vec),
                early_data: if self.server.max_early_data_size == 0 {
                    EarlyData::Disabled
                } else {
                    EarlyData::Enabled
                },
            };
            Ok(ProviderTlsStream::new(Box::new(stream), metadata))
        })
    }
}

struct Echo;
impl Handler for Echo {
    fn authorize(&self, principal: &Principal, method: &str) -> Result<(), AuthError> {
        if principal.subject == SUBJECT && method == ECHO {
            Ok(())
        } else {
            Err(AuthError::denied())
        }
    }

    fn handle(&self, method: String, payload: Vec<u8>, _cancel: CancelToken) -> HandlerFut {
        // Immediate side-effect-free work; no external tasks or execution leases.
        Box::pin(async move {
            if method == ECHO {
                HandlerOutcome::Payload(payload)
            } else {
                HandlerOutcome::error(ErrorCode::Unimplemented, "unknown method")
            }
        })
    }
}

fn wait_ready(client: &ManagedClient) -> Result<u64, io::Error> {
    let deadline = Instant::now() + WAIT;
    loop {
        let status = client.status();
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("readiness wait expired: {status:?}"),
            ));
        }
        match status {
            LifecycleStatus::CoreReady(ready) => {
                println!("CoreReady: generation {}", ready.generation);
                return Ok(ready.generation);
            }
            LifecycleStatus::Starting
            | LifecycleStatus::Connecting { .. }
            | LifecycleStatus::Backoff { .. } => thread::sleep(Duration::from_millis(5)),
            other => return Err(io::Error::other(format!("not ready: {other:?}"))),
        }
    }
}

fn run(network: &Network) -> DemoResult {
    let mut args = std::env::args_os().skip(1);
    let https = match (args.next(), args.next()) {
        (None, None) => false,
        (Some(arg), None) if arg == "--https" => true,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: managed_http [--https]",
            )
            .into())
        }
    };
    let carrier = if https { Carrier::Https } else { Carrier::Http };
    let authority = Authority::new(if https {
        "localhost:38443"
    } else {
        "localhost:38080"
    })?;
    let provider: Option<Arc<dyn TlsProvider>> = if https {
        Some(Arc::new(LocalTls::new(authority.tls_authority()?)?))
    } else {
        None
    };
    // Independently provision the fresh local Noise pin and exact scope before
    // any dial. Neither HTTP authority nor TLS replaces this trust input.
    let (private_key, public_pin) = generate_server_key()?;
    let security = Arc::new(ServerConfig {
        mode: Mode::Bootstrap,
        carrier,
        server_key_id: 1,
        scope: SCOPE.to_vec(),
        private_key,
        store: None,
    });
    let authenticator: Arc<dyn AuthenticatorFactory> = Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            // Confirmed bootstrap participation is not an application principal.
            // Require the explicit credential in the encrypted ClientHello.
            Ok(Arc::new(StaticToken::new(CREDENTIAL.to_vec(), SUBJECT)))
        },
    );
    let mut config = http::ServerConfig::new(
        "127.0.0.1:0".parse()?,
        authority.clone(),
        security,
        authenticator,
        Arc::new(Echo),
    );
    config.runtime.max_outstanding = 16;
    config.runtime.writer_capacity = 8;
    config.runtime.notification_capacity = 8;
    config.limits = Limits {
        attempt_timeout: ATTEMPT,
        ..Limits::default()
    };
    config.admission = ServerLimits {
        associations: 2,
        handshakes: 2,
        unbound_streams: 2,
        sockets: 6,
        ..ServerLimits::default()
    };
    config.tls = provider.clone();
    let runtime = config.runtime.clone();
    let limits = config.limits.clone();
    let server = if https {
        network.listen_https(config)
    } else {
        network.listen_http(config)
    }?
    .wait(WAIT)??;
    let address = server.local_addr();
    println!("Candidate {carrier:?} (pending adoption): canonical authority {} -> mapped socket {address}", authority.as_str());
    // Bind once on port 0. The local provisioning owner maps the configured
    // authority to that actual socket for BOTH streams, without changing Host or
    // TLS identity to the ephemeral port. No connection is made to the logical port.
    let (route, endpoint) = match provider {
        Some(provider) => (
            Route::Https {
                address,
                authority: authority.clone(),
                provider,
            },
            Endpoint::Https { address, authority },
        ),
        None => (
            Route::Http {
                address,
                authority: authority.clone(),
            },
            Endpoint::Http { address, authority },
        ),
    };
    // One attempt budget spans both sockets, optional TLS, HTTP setup, Noise and
    // protected hello/ready. routes adds no separate retry loop or weaker fallback.
    let connector = client_routes(
        RouteConfig {
            routes: vec![route],
            allowlist: vec![endpoint],
            runtime,
            limits,
        },
        move || {
            Ok((
                ClientConfig {
                    context: Context {
                        mode: Mode::Bootstrap,
                        carrier,
                        server_key_id: 1,
                        scope: SCOPE.to_vec(),
                        handle: [0; 8],
                        epoch: 0,
                    },
                    server_public_key: public_pin,
                    authorization_key: None,
                },
                CREDENTIAL.to_vec(),
            ))
        },
    )?;
    let client = network
        .client(
            ReconnectConfig {
                attempt_timeout: ATTEMPT,
                reconnect_budget: Duration::from_secs(8),
                max_attempts: 2,
                base_backoff: Duration::from_millis(50),
                max_backoff: Duration::from_millis(100),
                close_timeout: Duration::from_secs(1),
                start_paused: false,
                initial_network_available: true,
            },
            connector,
        )?
        .wait(WAIT)??;
    // Manager creation/listener binding do not establish readiness. This bounded
    // std-thread wait observes core readiness, not negotiated recovery readiness.
    let generation = wait_ready(&client)?;
    let payload = b"local echo bytes".to_vec();
    let operation = client.call(ECHO.into(), payload.clone(), 3000)?;
    let reply = match operation.wait(WAIT) {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => {
            match &error {
                CallError::Unavailable { generation: None } => {
                    eprintln!("RPC unavailable before generation admission; not retried");
                }
                _ => eprintln!("RPC errored: {error}; remote outcome may be unknown; not retried"),
            }
            return Err(error.into());
        }
        Err(error) => {
            eprintln!("RPC wait failed: {error}; outcome unknown; not retried");
            return Err(error.into());
        }
    };
    if reply.generation != generation || reply.value != payload {
        return Err(io::Error::other("unexpected echo result or generation").into());
    }
    println!(
        "Encrypted echo OK: {} bytes in generation {}",
        reply.value.len(),
        reply.generation
    );
    println!("Server status: {:?}", server.status());
    Ok(())
}

fn main() -> DemoResult {
    // Ordinary std caller, no caller Tokio runtime. Every fallible post-creation
    // step returns here, including argument/listen/readiness/RPC errors.
    let mut network = Network::new(NetworkConfig::default())?;
    let result = run(&network);
    let report = network.shutdown(WAIT);
    println!("Network shutdown: {report:?}");
    if let Err(error) = &result {
        eprintln!("Demo failed: {error}");
    }
    if !report.complete || report.pending_operations != 0 || report.failed_supervisors != 0 {
        // Do not silently claim cleanup: unfinished work remains owned and Drop
        // transfers it to the observable process registry, not detached success.
        drop(network);
        eprintln!(
            "Retired network owners: {:?}",
            syntra_net::network::retired_networks()
        );
        return Err(io::Error::other(format!("network shutdown not clean: {report:?}")).into());
    }
    let retired = http::retired_servers();
    if !retired.is_empty() {
        return Err(io::Error::other(format!(
            "unexpected retained HTTP server owners: {retired:?}"
        ))
        .into());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_demo_principal_can_echo() {
        assert!(Echo.authorize(&Principal::new(SUBJECT), ECHO).is_ok());
        assert!(Echo.authorize(&Principal::anonymous(), ECHO).is_err());
        assert!(Echo
            .authorize(&Principal::new("other-client"), ECHO)
            .is_err());
        assert!(Echo
            .authorize(&Principal::new(SUBJECT), "/demo.Echo/Other")
            .is_err());
    }

    #[test]
    fn hello_requires_the_explicit_demo_credential() {
        let auth = StaticToken::new(CREDENTIAL.to_vec(), SUBJECT);
        assert_eq!(auth.authenticate(CREDENTIAL).unwrap().subject, SUBJECT);
        assert!(auth.authenticate(b"").is_err());
        assert!(auth.authenticate(b"incorrect-placeholder").is_err());
    }
}
