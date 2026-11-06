//! Local cross-language fixture. Public test-only keys; never deploy this binary.
//! See TERMINAL_RECEIPT_DESIGN.md for CLI and provisioning bytes.
#[cfg(feature = "tcp")]
mod fixture {
    use futures_util::future::BoxFuture;
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };
    use syntra_core::secure_channel::*;
    use syntra_core::{ErrorCode, SyntraError};
    use syntra_net::{pump::AuthenticatorFactory, tcp};
    use syntra_runtime::{terminal::*, *};

    const METHOD: &str = "/example.Authority/Retire";
    const PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    /// Fixture state is linearizable in memory, deliberately not durable storage.
    #[derive(Default)]
    struct State {
        transition: Option<Transition>,
        commits: usize,
        handlers: usize,
        denials: usize,
        committing: bool,
        gap_seen: bool,
    }
    struct Store {
        state: Mutex<State>,
        scenario: String,
        gap_observed: tokio::sync::Notify,
    }
    impl KeyStore for Store {
        fn lookup(
            &self,
            context: &Context,
        ) -> Result<Secret32, syntra_core::secure_channel::Error> {
            let mut state = self.state.lock().unwrap();
            if state.transition.is_some() {
                state.denials += 1;
                println!("{{\"event\":\"fresh_denied\",\"before_handler\":true}}");
                return Err(syntra_core::secure_channel::Error::Authentication);
            }
            if context.handle != [7; 8] || context.epoch != 2 {
                return Err(syntra_core::secure_channel::Error::Authentication);
            }
            Ok(Secret32::new([8; 32]))
        }
    }
    impl Authority for Store {
        fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
            Box::pin(async {
                let mut state = self.state.lock().unwrap();
                if self.scenario == "gap"
                    && state.transition.is_some()
                    && state.committing
                    && !state.gap_seen
                {
                    state.gap_seen = true;
                    println!("{{\"event\":\"gap_observed\",\"before_callback_return\":true}}");
                    self.gap_observed.notify_one();
                }
                match state.transition.as_ref() {
                    None => Observation::Active { revision: 1 },
                    Some(_) if self.scenario == "deny" => {
                        println!("{{\"event\":\"authority_outcome\",\"state\":\"HardDenied\"}}");
                        Observation::HardDenied
                    }
                    Some(_) if self.scenario == "unknown" => {
                        println!("{{\"event\":\"authority_outcome\",\"state\":\"Unknown\"}}");
                        Observation::Unknown
                    }
                    Some(c) => Observation::OwnedCommitted {
                        reservation: c.reservation.clone(),
                        expected_revision: 1,
                        revision: 2,
                    },
                }
            })
        }
        fn commit(&self, claim: Transition, _lease: ExecutionLease) -> BoxFuture<'_, ()> {
            Box::pin(async move {
                {
                    let mut state = self.state.lock().unwrap();
                    if state.transition.is_some() || claim.expected_revision != 1 {
                        return;
                    }
                    state.transition = Some(claim);
                    state.commits += 1;
                    state.committing = true;
                    println!("{{\"event\":\"transition\",\"recorded\":true}}");
                }
                if self.scenario == "gap" {
                    self.gap_observed.notified().await;
                }
                self.state.lock().unwrap().committing = false;
                println!("{{\"event\":\"commit_return\"}}");
            })
        }
    }
    struct Factory(Arc<Store>);
    impl AuthenticatorFactory for Factory {
        fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
            if identity.context().mode != Mode::Returning
                || self.0.state.lock().unwrap().transition.is_some()
            {
                return Err(AuthError::unauthenticated());
            }
            Ok(Arc::new(StaticToken::new(
                b"terminal-fixture".to_vec(),
                "fixture-principal",
            )))
        }
        fn terminal_receipt(&self, _: &VerifiedIdentity) -> Option<Policy> {
            Some(Policy {
                method: METHOD.into(),
                payload: b"retired".to_vec(),
                authority: self.0.clone(),
                read_timeout: Duration::from_millis(100),
            })
        }
    }
    struct Retire(Arc<Store>);
    impl Handler for Retire {
        fn authorize(&self, _: &Principal, method: &str) -> Result<(), AuthError> {
            if method == METHOD {
                Ok(())
            } else {
                Err(AuthError::denied())
            }
        }
        fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
            Box::pin(async {
                HandlerOutcome::error(syntra_core::ErrorCode::Unimplemented, "unsupported method")
            })
        }
        fn handle_with_context(
            &self,
            _: String,
            payload: Vec<u8>,
            _: CancelToken,
            _: ExecutionLease,
            context: RequestContext,
        ) -> HandlerFut {
            self.0.state.lock().unwrap().handlers += 1;
            Box::pin(async move {
                if !payload.is_empty() {
                    return HandlerOutcome::error(
                        syntra_core::ErrorCode::InvalidArgument,
                        "expected empty request",
                    );
                }
                context.retire(1).await.unwrap_or_else(|_| {
                    HandlerOutcome::error(
                        syntra_core::ErrorCode::Unavailable,
                        "retirement unavailable",
                    )
                })
            })
        }
    }
    fn key(hex: &str) -> [u8; 32] {
        std::array::from_fn(|i| {
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixed public test key")
        })
    }
    fn context() -> Context {
        Context {
            mode: Mode::Returning,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"terminal-fixture".to_vec(),
            handle: [7; 8],
            epoch: 2,
        }
    }
    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() < 3
            || args.len() > 4
            || !matches!(args[1].as_str(), "server" | "client" | "probe")
        {
            return Err(
                "usage: terminal_receipt server|client|probe 127.0.0.1:PORT [owned|deny|unknown|gap]"
                    .into(),
            );
        }
        let address: std::net::SocketAddr = args[2].parse()?;
        if !address.ip().is_loopback() {
            return Err("fixture requires loopback".into());
        }
        let scenario = args.get(3).map_or("owned", String::as_str);
        if !matches!(scenario, "owned" | "deny" | "unknown" | "gap") {
            return Err("unknown fixture scenario".into());
        }
        if args[1] == "client" || args[1] == "probe" {
            let connected = tcp::connect(
                address,
                ClientConfig {
                    context: context(),
                    server_public_key: key(PUBLIC),
                    authorization_key: Some(Secret32::new([8; 32])),
                },
                b"terminal-fixture".to_vec(),
                ConnectionConfig::default(),
                tcp::Limits::default(),
            )
            .await;
            // Probe sends no RPC, and is accepted only with server-side denial evidence.
            if args[1] == "probe" {
                match connected {
                    Err(
                        syntra_net::Error::Io(_)
                        | syntra_net::Error::Closed
                        | syntra_net::Error::Authentication
                        | syntra_net::Error::Channel(
                            syntra_core::secure_channel::Error::Authentication,
                        ),
                    ) => {
                        println!(
                            "{{\"event\":\"probe\",\"establishment_denied\":true,\"calls\":0}}"
                        );
                        return Ok(());
                    }
                    Ok(client) => {
                        client.close().await;
                        return Err("fresh Returning unexpectedly established".into());
                    }
                    Err(_) => return Err("unexpected probe establishment failure".into()),
                }
            }
            let client = connected?;
            println!("{{\"event\":\"established\"}}");
            let result = client.conn.call(METHOD, vec![], 3000).await;
            match (scenario, result) {
                ("owned" | "gap", Ok(payload)) if payload == b"retired" => {
                    println!("{{\"event\":\"result\",\"outcome\":\"observed\",\"payload\":\"retired\",\"receipts\":1}}")
                }
                ("deny" | "unknown", Err(SyntraError::Unavailable(_))) => println!("{{\"event\":\"result\",\"outcome\":\"unknown\",\"code\":\"Unavailable\",\"receipts\":0}}"),
                ("deny", Err(SyntraError::Rpc { code: ErrorCode::Unauthenticated, .. })) => println!("{{\"event\":\"result\",\"outcome\":\"unknown\",\"code\":\"Unauthenticated\",\"receipts\":0}}"),
                _ => return Err("unexpected fixture result".into()),
            }
            client.close().await;
            return Ok(());
        }
        let store = Arc::new(Store {
            state: Mutex::new(State::default()),
            scenario: scenario.into(),
            gap_observed: tokio::sync::Notify::new(),
        });
        let security = ServerConfig {
            mode: Mode::Returning,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: context().scope,
            private_key: Secret32::new(key(PRIVATE)),
            store: Some(store.clone()),
        };
        let listener = tcp::Listener::bind(address, 2).await?;
        println!(
            "{{\"event\":\"listening\",\"address\":\"{}\"}}",
            listener.local_addr()?
        );
        let host = listener
            .accept(
                &security,
                Arc::new(Factory(store.clone())),
                Arc::new(Retire(store.clone())),
                ConnectionConfig::default(),
                tcp::Limits::default(),
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(6), async {
            while !host.is_closed() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        host.close().await;
        {
            let state = store.state.lock().unwrap();
            if state.transition.is_none() || state.commits != 1 || state.handlers != 1 {
                return Err("fixture transition/count assertion failed".into());
            }
        }
        println!("{{\"event\":\"connection_closed\",\"connection\":1}}");
        // Required, independent fresh Returning handshake. No mutation retry.
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            listener.accept(
                &security,
                Arc::new(Factory(store.clone())),
                Arc::new(Retire(store.clone())),
                ConnectionConfig::default(),
                tcp::Limits::default(),
            ),
        )
        .await?;
        if !matches!(
            result,
            Err(syntra_net::Error::Channel(
                syntra_core::secure_channel::Error::Authentication
            ))
        ) {
            return Err("expected actual withdrawn-binding authentication denial".into());
        }
        let state = store.state.lock().unwrap();
        if state.transition.is_none()
            || state.commits != 1
            || state.handlers != 1
            || state.denials != 1
        {
            return Err("fixture final state/count assertion failed".into());
        }
        println!("{{\"event\":\"connection_closed\",\"connection\":2}}");
        println!(
            "{{\"event\":\"summary\",\"commits\":1,\"handlers\":1,\"denials\":1,\"closed\":2}}"
        );
        Ok(())
    }
}

#[cfg(feature = "tcp")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(25), fixture::run()).await?
}

#[cfg(not(feature = "tcp"))]
fn main() {
    eprintln!("enable syntra-net/tcp for this local fixture");
}
