//! Run with `cargo run -p syntra-net --no-default-features --features managed --example managed_tcp`.
//! An encrypted TCP echo round trip driven entirely by the Network-owned runtime.

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
    network::{Admission, ManagedClient, Network, NetworkConfig, TcpServerConfig},
    routes::{client_routes, Endpoint, Route, RouteConfig},
    AuthenticatorFactory, Limits,
};
use syntra_runtime::{
    AuthError, Authenticator, CancelToken, Handler, HandlerFut, HandlerOutcome, Principal,
    StaticToken,
};

type DemoResult = Result<(), Box<dyn StdError>>;
const WAIT: Duration = Duration::from_secs(10);
const ATTEMPT: Duration = Duration::from_secs(5);
const SCOPE: &[u8] = b"managed-tcp-demo";
const ECHO: &str = "/demo.Echo/Echo";
const SUBJECT: &str = "local-demo-client";
// Public placeholder for this in-process demo, not a deployment credential.
const CREDENTIAL: &[u8] = b"demo-only-placeholder-token";

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
        // Immediate, side-effect-free work; no external tasks or execution leases.
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
    // Trusted local provisioning: distribute the fresh public pin and exact scope
    // before any dial. Never learn or replace this pin from a remote endpoint.
    let (private_key, public_pin) = generate_server_key()?;
    let security = Arc::new(ServerConfig {
        mode: Mode::Bootstrap,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: SCOPE.to_vec(),
        private_key,
        store: None,
    });
    let authenticator: Arc<dyn AuthenticatorFactory> = Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            // A confirmed bootstrap channel is not an application principal.
            // Authenticate the explicit encrypted ClientHello credential instead.
            Ok(Arc::new(StaticToken::new(CREDENTIAL.to_vec(), SUBJECT)))
        },
    );
    let limits = Limits {
        attempt_timeout: ATTEMPT,
        ..Limits::default()
    };
    let server = network
        .listen_tcp(TcpServerConfig {
            address: "127.0.0.1:0".parse()?,
            admission: Admission::new(4)?,
            security,
            authenticator,
            handler: Arc::new(Echo),
            runtime: Default::default(),
            limits: limits.clone(),
        })?
        .wait(WAIT)??;
    let address = server.local_addr();
    println!("TCP listener: {address}");
    let connector = client_routes(
        RouteConfig {
            routes: vec![Route::Tcp(address)],
            // This demo's provisioning owner permits only its own bound socket.
            allowlist: vec![Endpoint::Tcp(address)],
            runtime: Default::default(),
            limits,
        },
        move || {
            Ok((
                ClientConfig {
                    context: Context {
                        mode: Mode::Bootstrap,
                        carrier: Carrier::Tcp,
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
    // Creation returns a manager, not readiness. Poll owned status snapshots from
    // an ordinary thread with one bounded std::time::Instant wait.
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
        "Echo OK: {} bytes in generation {}",
        reply.value.len(),
        reply.generation
    );
    println!("Server status: {:?}", server.status());
    Ok(())
}

fn main() -> DemoResult {
    // No caller Tokio runtime. Every fallible step after creation is inside run,
    // so even a failed listen/dial/readiness/RPC wait reaches explicit shutdown.
    let mut network = Network::new(NetworkConfig::default())?;
    let result = run(&network);
    let report = network.shutdown(WAIT);
    println!("Network shutdown: {report:?}");
    if let Err(error) = &result {
        eprintln!("Demo failed: {error}");
    }
    if !report.complete || report.pending_operations != 0 || report.failed_supervisors != 0 {
        // Incomplete work stays owned; dropping Network transfers it to the
        // observable retired_networks registry rather than attesting completion.
        return Err(io::Error::other(format!("network shutdown not clean: {report:?}")).into());
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
