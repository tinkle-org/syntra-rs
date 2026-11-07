//! Local cross-language fixture. Public test-only keys; never deploy this binary.
//! See TERMINAL_RECEIPT_DESIGN.md for CLI and provisioning bytes.
#[cfg(feature = "tcp")]
mod fixture {
    use futures_util::future::BoxFuture;
    use std::{
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use syntra_core::secure_channel::*;
    use syntra_core::{ErrorCode, SyntraError};
    use syntra_net::{
        pump::{AuthenticatorFactory, RecordReader},
        tcp,
    };
    use syntra_runtime::elapsed::ElapsedDeadline;
    use syntra_runtime::{terminal::*, *};
    use tokio::io::AsyncReadExt;

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
        /// Local measurement origin only; never exported as an absolute timestamp.
        budget_started: Option<Instant>,
    }
    /// Read-only key lookup plus separately recorded authority/fixture evidence.
    struct Store {
        state: Mutex<State>,
        scenario: String,
        gap_observed: tokio::sync::Notify,
    }
    /// Opt in only the three neutral application request-budget scenarios.
    fn budget_case(scenario: &str) -> bool {
        scenario.starts_with("budget-")
    }
    /// Keep healthy caps generous enough for independent read freshness renewal.
    fn host_cap(scenario: &str) -> Duration {
        Duration::from_millis(if scenario == "budget-late" { 600 } else { 1500 })
    }
    impl Store {
        /// Print clock-relative metrics without provisioning or authority identifiers.
        fn observe_budget(&self, phase: &str, budget: &ElapsedDeadline) {
            if !budget_case(&self.scenario) {
                return;
            }
            let Some(started) = self.state.lock().unwrap().budget_started else {
                return;
            };
            let remaining = budget.remaining();
            println!(
                "{{\"event\":\"budget\",\"phase\":\"{}\",\"live\":{},\"sdk_budget_present\":true,\"remaining_ms\":{},\"elapsed_ms\":{}}}",
                phase,
                remaining.is_ok(),
                remaining.unwrap_or_default().as_secs_f64() * 1000.0,
                started.elapsed().as_secs_f64() * 1000.0,
            );
        }
    }
    impl KeyStore for Store {
        /// Validate the exact requested handle/epoch and read its active key, without evidence effects.
        fn lookup(
            &self,
            context: &Context,
        ) -> Result<Secret32, syntra_core::secure_channel::Error> {
            if context.handle != [7; 8] || context.epoch != 2 {
                return Err(syntra_core::secure_channel::Error::Authentication);
            }
            if self.state.lock().unwrap().transition.is_some() {
                return Err(syntra_core::secure_channel::Error::Authentication);
            }
            Ok(Secret32::new([8; 32]))
        }
    }
    impl Authority for Store {
        /// Report the runtime's bounded authoritative read budget after reservation.
        fn observe_with_budget(
            &self,
            transition: Option<Transition>,
            budget: ElapsedDeadline,
        ) -> BoxFuture<'_, Observation> {
            if transition.is_some() {
                self.observe_budget("observe", &budget);
            }
            self.observe(transition)
        }

        /// Retain actual work and its execution lease beyond cutoff only in the
        /// explicitly labelled uncooperative test adapter, never in authorization.
        fn commit_with_budget(
            &self,
            claim: Transition,
            lease: ExecutionLease,
            budget: ElapsedDeadline,
        ) -> BoxFuture<'_, ()> {
            self.observe_budget("commit", &budget);
            Box::pin(async move {
                if self.scenario == "budget-late" {
                    // TEST-ONLY CONTRACT VIOLATION: external work ignores expiry.
                    // The retained SDK task/lease must join and cannot regain a receipt.
                    // Open a deterministic event range for reads after actual
                    // commit admission but before delayed mutation completion.
                    println!("{{\"event\":\"commit_pending\"}}");
                    budget.expired().await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    println!("{{\"event\":\"late_commit\",\"expired\":{},\"retained_work\":true,\"contract_violation\":true}}", budget.check().is_err());
                }
                self.commit(claim, lease).await;
            })
        }

        /// Report current typed authority, including recorded-owner visibility during callback delay.
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
        /// Atomically record the in-memory withdrawal/owner before any optional gap await.
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
    /// Bind authentication and terminal policy to the fixture's verified connection.
    struct Factory(Arc<Store>);
    impl AuthenticatorFactory for Factory {
        /// Authenticate the fixed principal only for a still-active Returning binding.
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
        /// Bind the fixed non-sensitive receipt to this fixture's in-memory authority.
        fn terminal_receipt(&self, _: &VerifiedIdentity) -> Option<Policy> {
            Some(Policy {
                method: METHOD.into(),
                payload: b"retired".to_vec(),
                authority: self.0.clone(),
                read_timeout: Duration::from_millis(100),
            })
        }
    }
    /// Count actual handler admission; only the authority callback mutates binding state.
    struct Retire(Arc<Store>);
    impl Handler for Retire {
        /// Select only by authenticated principal, exact method and opaque input.
        fn request_budget(
            &self,
            principal: &Principal,
            method: &str,
            payload: &[u8],
        ) -> Option<Duration> {
            if !budget_case(&self.0.scenario) {
                return None;
            }
            self.0.state.lock().unwrap().budget_started = Some(Instant::now());
            let cap = host_cap(&self.0.scenario);
            println!(
                "{{\"event\":\"budget_selected\",\"cap_ms\":{},\"input_valid\":{}}}",
                cap.as_millis(),
                principal.subject == "fixture-principal" && method == METHOD && payload.is_empty()
            );
            Some(cap)
        }
        /// Observe the selected budget without blocking the synchronous authorizer.
        fn authorize_with_budget(
            &self,
            principal: &Principal,
            method: &str,
            budget: ElapsedDeadline,
        ) -> Result<(), AuthError> {
            self.0.observe_budget("authorize", &budget);
            self.authorize(principal, method)
        }
        /// Authorize only the fixture's exact retirement method.
        fn authorize(&self, _: &Principal, method: &str) -> Result<(), AuthError> {
            if method == METHOD {
                Ok(())
            } else {
                Err(AuthError::denied())
            }
        }
        /// Refuse the legacy hook, which cannot supply a retirement context.
        fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
            Box::pin(async {
                HandlerOutcome::error(syntra_core::ErrorCode::Unimplemented, "unsupported method")
            })
        }
        /// Validate the request, await the authority-owned mutation, and return without further effects.
        fn handle_with_context(
            &self,
            _: String,
            payload: Vec<u8>,
            _: CancelToken,
            _: ExecutionLease,
            context: RequestContext,
        ) -> HandlerFut {
            self.0.state.lock().unwrap().handlers += 1;
            let store = self.0.clone();
            Box::pin(async move {
                if !payload.is_empty() {
                    return HandlerOutcome::error(
                        syntra_core::ErrorCode::InvalidArgument,
                        "expected empty request",
                    );
                }
                if budget_case(&store.scenario) {
                    // Cooperative async work spends, rather than refreshes, D.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    store.observe_budget("handler", &context.budget());
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
    /// Decode fixed public test provisioning bytes.
    fn key(hex: &str) -> [u8; 32] {
        std::array::from_fn(|i| {
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("fixed public test key")
        })
    }
    /// Exact public binding that the independent fresh Returning probe must request.
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
    /// Inspect the actual bounded first message outside KeyStore, then replay it
    /// unchanged through native accept (and its normal respond_with_clock path).
    /// Only an exact withdrawn-binding authentication refusal counts as evidence;
    /// an arbitrary bad handle/epoch or wrong-key failure on an active binding does not.
    async fn accept_probe(
        listener: &tcp::Listener,
        security: &ServerConfig,
        store: Arc<Store>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let stream = listener.accept_socket().await?;
        let (read, write) = tokio::io::split(stream);
        let mut reader = tcp::StreamReader(read);
        let first = reader.read_record(MAX_WRAPPER).await?;
        let (requested, _) = Context::parse_first(&first)?;
        let mut prefix = (first.len() as u16).to_be_bytes().to_vec();
        prefix.extend_from_slice(&first);
        let stream = tokio::io::join(std::io::Cursor::new(prefix).chain(reader.0), write);
        let result = tcp::accept_stream(
            stream,
            security,
            Arc::new(Factory(store.clone())),
            Arc::new(Retire(store.clone())),
            ConnectionConfig::default(),
            tcp::Limits::default(),
        )
        .await;
        if !matches!(
            result,
            Err(syntra_net::Error::Channel(
                syntra_core::secure_channel::Error::Authentication
            ))
        ) || requested != context()
        {
            if let Ok(host) = result {
                host.close().await;
            }
            return Err("expected actual withdrawn-binding authentication denial".into());
        }
        let mut state = store.state.lock().unwrap();
        if state.transition.is_none() || state.handlers != 1 || state.commits != 1 {
            return Err("fresh denial lacked the intended committed withdrawal".into());
        }
        state.denials += 1;
        println!("{{\"event\":\"fresh_denied\",\"before_handler\":true}}");
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        /// Attempt a real first message and return only the server's evidence verdict.
        async fn probe(
            listener: &tcp::Listener,
            store: Arc<Store>,
            requested: Context,
            ak: [u8; 32],
        ) -> bool {
            let security = ServerConfig {
                mode: Mode::Returning,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: context().scope,
                private_key: Secret32::new(key(PRIVATE)),
                store: Some(store.clone()),
            };
            let client = tcp::connect(
                listener.local_addr().unwrap(),
                ClientConfig {
                    context: requested,
                    server_public_key: key(PUBLIC),
                    authorization_key: Some(Secret32::new(ak)),
                },
                b"terminal-fixture".to_vec(),
                ConnectionConfig::default(),
                tcp::Limits::default(),
            );
            let (evidence, connected) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(accept_probe(listener, &security, store), client)
            })
            .await
            .unwrap();
            assert!(connected.is_err(), "probe must never establish");
            evidence.is_ok()
        }

        /// A bad AK on an active binding is not proof of a committed withdrawal.
        #[tokio::test]
        async fn wrong_key_failure_is_not_withdrawn_binding_evidence() {
            let store = Arc::new(Store {
                state: Mutex::new(State::default()),
                scenario: "owned".into(),
                gap_observed: tokio::sync::Notify::new(),
            });
            let listener = tcp::Listener::bind("127.0.0.1:0", 2).await.unwrap();
            assert!(!probe(&listener, store.clone(), context(), [9; 32]).await);
            assert_eq!(store.state.lock().unwrap().denials, 0);
        }

        /// Rejected lookups are read-only, even after withdrawal and for wrong bindings.
        #[tokio::test]
        async fn lookup_is_pure_and_validates_the_requested_binding() {
            let store = Arc::new(Store {
                state: Mutex::new(State::default()),
                scenario: "owned".into(),
                gap_observed: tokio::sync::Notify::new(),
            });
            assert_eq!(*store.lookup(&context()).unwrap().expose(), [8; 32]);
            let mut wrong_handle = context();
            wrong_handle.handle = [9; 8];
            let mut wrong_epoch = context();
            wrong_epoch.epoch += 1;
            for requested in [&wrong_handle, &wrong_epoch] {
                assert!(store.lookup(requested).is_err());
            }
            let listener = tcp::Listener::bind("127.0.0.1:0", 2).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server_store = store.clone();
            let accept = tokio::spawn(async move {
                let host = listener
                    .accept(
                        &ServerConfig {
                            mode: Mode::Returning,
                            carrier: Carrier::Tcp,
                            server_key_id: 1,
                            scope: context().scope,
                            private_key: Secret32::new(key(PRIVATE)),
                            store: Some(server_store.clone()),
                        },
                        Arc::new(Factory(server_store.clone())),
                        Arc::new(Retire(server_store)),
                        ConnectionConfig::default(),
                        tcp::Limits::default(),
                    )
                    .await
                    .unwrap();
                (host, listener)
            });
            let client = tcp::connect(
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
            .await
            .unwrap();
            let (host, listener) = accept.await.unwrap();
            assert_eq!(
                client.conn.call(METHOD, vec![], 2000).await.unwrap(),
                b"retired"
            );
            for requested in [&context(), &wrong_handle, &wrong_epoch] {
                assert!(store.lookup(requested).is_err());
            }
            assert_eq!(
                store.state.lock().unwrap().denials,
                0,
                "lookup must not record evidence"
            );
            client.close().await;
            host.close().await;
            for requested in [wrong_handle, wrong_epoch] {
                assert!(!probe(&listener, store.clone(), requested, [8; 32]).await);
                assert_eq!(store.state.lock().unwrap().denials, 0);
            }
            assert!(probe(&listener, store.clone(), context(), [8; 32]).await);
            let state = store.state.lock().unwrap();
            assert_eq!(state.denials, 1);
            assert_eq!((state.commits, state.handlers), (1, 1));
        }
    }
    /// Run one bounded loopback fixture role, preserving the JSON evidence contract.
    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = std::env::args().collect();
        if args.len() < 3
            || args.len() > 4
            || !matches!(args[1].as_str(), "server" | "client" | "probe")
        {
            return Err(
                "usage: terminal_receipt server|client|probe 127.0.0.1:PORT [owned|deny|unknown|gap|budget-cap|budget-short|budget-late]"
                    .into(),
            );
        }
        let address: std::net::SocketAddr = args[2].parse()?;
        if !address.ip().is_loopback() {
            return Err("fixture requires loopback".into());
        }
        let scenario = args.get(3).map_or("owned", String::as_str);
        if !matches!(
            scenario,
            "owned" | "deny" | "unknown" | "gap" | "budget-cap" | "budget-short" | "budget-late"
        ) {
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
            let peer_budget = match scenario {
                "budget-short" => 1000,
                "budget-cap" | "budget-late" => 120000,
                _ => 3000,
            };
            if budget_case(scenario) {
                println!(
                    "{{\"event\":\"peer_budget\",\"timeout_ms\":{}}}",
                    peer_budget
                );
            }
            let result = client.conn.call(METHOD, vec![], peer_budget).await;
            match (scenario, result) {
                ("owned" | "gap" | "budget-cap" | "budget-short", Ok(payload)) if payload == b"retired" => {
                    println!("{{\"event\":\"result\",\"outcome\":\"observed\",\"payload\":\"retired\",\"receipts\":1}}")
                }
                ("deny" | "unknown" | "budget-late", Err(SyntraError::Unavailable(_))) => println!("{{\"event\":\"result\",\"outcome\":\"unknown\",\"code\":\"Unavailable\",\"receipts\":0}}"),
                ("budget-late", Err(SyntraError::Rpc { code: ErrorCode::DeadlineExceeded, .. })) => println!("{{\"event\":\"result\",\"outcome\":\"unknown\",\"code\":\"DeadlineExceeded\",\"receipts\":0}}"),
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
            accept_probe(&listener, &security, store.clone()),
        )
        .await?;
        result?;
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
/// Bound the complete fixture run independently of individual connection deadlines.
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(std::time::Duration::from_secs(25), fixture::run()).await?
}

#[cfg(not(feature = "tcp"))]
/// Explain the explicitly required carrier feature for this fixture.
fn main() {
    eprintln!("enable syntra-net/tcp for this local fixture");
}
