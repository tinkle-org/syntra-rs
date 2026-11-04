//! Run with `cargo run -p syntra-net --no-default-features --features managed,websocket --example managed_wss`.
//! Local WSS echo using an application-owned TLS provider and Network-owned runtime.
//! Opt into the unadopted cross-carrier candidate by also enabling
//! `cross-carrier-candidate` and passing `-- --failover`: a deliberately stalled
//! local TCP endpoint times out before a fresh, real provider-WSS establishment.

#[cfg(feature = "cross-carrier-candidate")]
use std::{net::TcpListener, sync::Mutex};
#[cfg(feature = "cross-carrier-candidate")]
use syntra_net::routes::{client_routes_cross_carrier, CrossCarrierPolicy};

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
    network::{
        Admission, ManagedClient, Network, NetworkConfig, WebSocketServerConfig, WebSocketTls,
    },
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
const SCOPE: &[u8] = b"managed-wss-demo";
const ECHO: &str = "/demo.Echo/Echo";
const SUBJECT: &str = "local-demo-client";
// Public placeholder for this in-process demo, not a deployment credential.
const CREDENTIAL: &[u8] = b"demo-only-placeholder-token";

/// Example-local policy: one freshly generated certificate is the only root,
/// normal rustls chain/hostname/time verification, no resumption or early data.
/// Trust lives only for this run; no OS roots, remote pin learning or TLS bypass.
struct LocalTls {
    client: Arc<rustls::ClientConfig>,
    server: Arc<rustls::ServerConfig>,
}

impl LocalTls {
    fn new() -> Result<Self, Box<dyn StdError>> {
        let cert = rcgen::generate_simple_self_signed(vec![HOSTNAME.into()])?;
        let crypto = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        // Provision the locally generated root directly, never from a TLS peer.
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
            if authority.host() != HOSTNAME {
                return Err(Error::Configuration);
            }
            let name = rustls::pki_types::ServerName::try_from(authority.host().to_owned())
                .map_err(|_| Error::Configuration)?;
            // Use the supplied, deadline-gated stream; no second dial or spawned I/O.
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
            // Only the provisioned local hostname has credentials in this provider.
            // This authority comes from listener configuration, not peer SNI/HTTP.
            if authority.host() != HOSTNAME {
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

fn client_inputs(carrier: Carrier, public_pin: [u8; 32]) -> (ClientConfig, Vec<u8>) {
    (
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
    )
}

fn run(network: &Network, failover: bool) -> DemoResult {
    // Both independent trust inputs are provisioned locally before any dial.
    let provider = Arc::new(LocalTls::new()?);
    let (private_key, public_pin) = generate_server_key()?;
    #[cfg(feature = "cross-carrier-candidate")]
    let tcp_fixture = if failover {
        // Hold this loopback port for the whole run, without accepting or spawning
        // another worker. TCP may connect, but no responder supplies Noise M2:
        // the bounded attempt times out. This is an availability fixture, not an
        // authentication denial or a race to connect to an unused port.
        let listener = TcpListener::bind("127.0.0.1:0")?;
        // Provision an independent valid TCP pin before dialing, even though this
        // fixture never completes Noise. Never reuse/infer the WSS pin on failure.
        let (_, tcp_pin) = generate_server_key()?;
        Some((listener, tcp_pin))
    } else {
        None
    };
    let attempt_timeout = if failover {
        Duration::from_secs(1)
    } else {
        ATTEMPT
    };
    let security = Arc::new(ServerConfig {
        mode: Mode::Bootstrap,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: SCOPE.to_vec(),
        private_key,
        store: None,
    });
    let authenticator: Arc<dyn AuthenticatorFactory> = Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            // TLS and bootstrap Noise do not supply an application principal.
            Ok(Arc::new(StaticToken::new(CREDENTIAL.to_vec(), SUBJECT)))
        },
    );
    let limits = Limits {
        attempt_timeout,
        ..Limits::default()
    };
    let server = network
        .listen_wss(WebSocketServerConfig {
            address: "127.0.0.1:0".parse()?,
            admission: Admission::new(4)?,
            security,
            authenticator,
            handler: Arc::new(Echo),
            runtime: Default::default(),
            limits: limits.clone(),
            tls: WebSocketTls::Provider {
                provider: provider.clone(),
                // Provisioned local TLS service identity; the demo socket below
                // uses an ephemeral port independently of this logical authority.
                authority: TlsAuthority::new(HOSTNAME, 443)?,
            },
        })?
        .wait(WAIT)??;
    let address = server.local_addr();
    let url = format!("wss://{HOSTNAME}:{}/syntra/1.0/ws", address.port());
    println!("WSS listener: {address}; verified hostname: {HOSTNAME}");
    let routes = RouteConfig {
        routes: vec![Route::Wss {
            address,
            url: url.clone(),
            provider,
        }],
        allowlist: vec![Endpoint::Wss { address, url }],
        runtime: Default::default(),
        limits,
    };
    let reconnect = ReconnectConfig {
        attempt_timeout,
        reconnect_budget: Duration::from_secs(8),
        max_attempts: 2,
        base_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(100),
        close_timeout: Duration::from_secs(1),
        start_paused: false,
        initial_network_available: true,
    };
    #[cfg(feature = "cross-carrier-candidate")]
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let operation = if failover {
        #[cfg(feature = "cross-carrier-candidate")]
        {
            let (listener, tcp_pin) = tcp_fixture.as_ref().ok_or(Error::Configuration)?;
            let tcp_address = listener.local_addr()?;
            let tcp_pin = *tcp_pin;
            let mut routes = routes;
            routes.routes.insert(0, Route::Tcp(tcp_address));
            routes.allowlist.insert(0, Endpoint::Tcp(tcp_address));
            let attempts = attempts.clone();
            let connector = client_routes_cross_carrier(
                routes,
                // Explicitly permit absence of outer TLS for TCP; Noise is still
                // mandatory. TLS-mandatory deployments must not permit TCP.
                CrossCarrierPolicy {
                    permitted_carriers: vec![Carrier::Tcp, Carrier::SecureWebSocket],
                },
                move |endpoint| {
                    let (carrier, pin) = match endpoint {
                        Endpoint::Tcp(selected) if *selected == tcp_address => {
                            (Carrier::Tcp, tcp_pin)
                        }
                        Endpoint::Wss {
                            address: selected, ..
                        } if *selected == address => (Carrier::SecureWebSocket, public_pin),
                        _ => return Err(Error::Configuration),
                    };
                    attempts
                        .lock()
                        .map_err(|_| Error::Configuration)?
                        .push(carrier);
                    // Log only the carrier, never credentials or security inputs.
                    println!("Candidate attempt carrier: {carrier:?}");
                    Ok(client_inputs(carrier, pin))
                },
            )?;
            // One supervisor owns both attempts and the total outage budget. Its
            // original budget reaches socket, TLS, upgrade, Noise and ready; no
            // application retry loop or independently restarted setup budget.
            network.client_with_budget(reconnect, connector)?
        }
        #[cfg(not(feature = "cross-carrier-candidate"))]
        {
            return Err(io::Error::other("--failover requires cross-carrier-candidate").into());
        }
    } else {
        // Preserve the ordinary same-carrier WSS connector and its original
        // five-second attempt. The listener starts its budget before admission.
        let connector = client_routes(routes, move || {
            Ok(client_inputs(Carrier::SecureWebSocket, public_pin))
        })?;
        network.client(reconnect, connector)?
    };
    let client = operation.wait(WAIT)??;
    let generation = wait_ready(&client)?;
    #[cfg(feature = "cross-carrier-candidate")]
    if failover {
        let attempts = attempts.lock().map_err(|_| Error::Configuration)?;
        if attempts.as_slice() != [Carrier::Tcp, Carrier::SecureWebSocket] {
            return Err(io::Error::other("expected exactly TCP then WSS inputs").into());
        }
        // The TCP fixture cannot reach ready. CoreReady after exactly these two
        // callbacks, followed by the echo below, proves fresh provider-WSS use.
        println!("Candidate fallback ready: WSS after TCP timeout (not recovery readiness)");
    }
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
        "Echo OK: {} bytes in generation {}",
        reply.value.len(),
        reply.generation
    );
    println!("Server status: {:?}", server.status());
    Ok(())
}

fn parse_failover(args: impl IntoIterator<Item = String>) -> Result<bool, io::Error> {
    let mut failover = false;
    for arg in args {
        if arg != "--failover" || failover {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "usage: managed_wss [--failover]",
            ));
        }
        failover = true;
    }
    Ok(failover)
}

fn demo(failover: bool) -> DemoResult {
    if failover && !cfg!(feature = "cross-carrier-candidate") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--failover requires --features managed,websocket,cross-carrier-candidate",
        )
        .into());
    }
    // All post-creation errors return here before leaving the runtime owner.
    let mut network = Network::new(NetworkConfig::default())?;
    let result = run(&network, failover);
    let report = network.shutdown(WAIT);
    println!("Network shutdown: {report:?}");
    if let Err(error) = &result {
        eprintln!("Demo failed: {error}");
    }
    if !report.complete || report.pending_operations != 0 || report.failed_supervisors != 0 {
        // Dropping an incomplete owner transfers it to retired_networks; this
        // report explicitly does not attest that unfinished work has stopped.
        return Err(io::Error::other(format!("network shutdown not clean: {report:?}")).into());
    }
    result
}

fn main() -> DemoResult {
    demo(parse_failover(std::env::args().skip(1))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_is_explicit() {
        assert!(!parse_failover(Vec::new()).unwrap());
        assert!(parse_failover(vec!["--failover".into()]).unwrap());
        assert!(parse_failover(vec!["--other".into()]).is_err());
        assert!(parse_failover(vec!["--failover".into(), "--failover".into()]).is_err());
    }

    #[test]
    fn single_wss_echo_and_owned_shutdown() {
        demo(false).unwrap();
    }

    #[cfg(feature = "cross-carrier-candidate")]
    #[test]
    fn tcp_timeout_then_provider_wss_echo_and_owned_shutdown() {
        // Assert observable route order/readiness/echo and clean ownership, not
        // scheduler-dependent elapsed timing. No environment-global mode switch.
        demo(true).unwrap();
    }

    #[cfg(not(feature = "cross-carrier-candidate"))]
    #[test]
    fn failover_without_feature_is_a_configuration_error() {
        let error = demo(true).unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(error.to_string().contains("cross-carrier-candidate"));
    }

    #[test]
    fn only_the_demo_principal_can_echo() {
        assert!(Echo.authorize(&Principal::new(SUBJECT), ECHO).is_ok());
        assert!(Echo.authorize(&Principal::anonymous(), ECHO).is_err());
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
