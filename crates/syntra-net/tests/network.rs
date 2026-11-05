#![cfg(all(feature = "managed", not(target_arch = "wasm32")))]

use std::{
    net::{SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, Mode, ServerConfig, VerifiedIdentity,
};
use syntra_net::{
    client::{CallError, Failure, LifecycleStatus, ReconnectConfig},
    network::{
        retired_networks, tcp_routes, Admission, ManagedClient, ManagedServer, Network,
        NetworkConfig, NetworkEvent, Operation, TcpServerConfig,
    },
    AuthenticatorFactory, Error, Limits,
};
use syntra_runtime::{
    AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler, Handler, HandlerOutcome,
};

const WAIT: Duration = Duration::from_secs(8);

fn receive<T>(operation: Operation<T>) -> T {
    operation
        .wait(WAIT)
        .unwrap_or_else(|e| panic!("managed operation: {e:?}"))
}
fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not become true");
        thread::sleep(Duration::from_millis(2));
    }
}
fn reconnect() -> ReconnectConfig {
    ReconnectConfig {
        attempt_timeout: Duration::from_secs(3),
        reconnect_budget: Duration::from_secs(20),
        max_attempts: 20,
        base_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        close_timeout: Duration::from_secs(1),
        start_paused: false,
        initial_network_available: true,
    }
}
struct Trust {
    server: Arc<ServerConfig>,
    public: [u8; 32],
}
impl Trust {
    fn new() -> Self {
        let (private_key, public) = generate_server_key().unwrap();
        Self {
            server: Arc::new(ServerConfig {
                mode: Mode::Bootstrap,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: b"managed/local".to_vec(),
                private_key,
                store: None,
            }),
            public,
        }
    }
    fn inputs(
        &self,
    ) -> impl Fn() -> Result<(ClientConfig, Vec<u8>), Error> + Send + Sync + 'static {
        let public = self.public;
        move || {
            Ok((
                ClientConfig {
                    context: Context {
                        mode: Mode::Bootstrap,
                        carrier: Carrier::Tcp,
                        server_key_id: 1,
                        scope: b"managed/local".to_vec(),
                        handle: [0; 8],
                        epoch: 0,
                    },
                    server_public_key: public,
                    authorization_key: None,
                },
                vec![],
            ))
        }
    }
}
fn echo(count: Arc<AtomicUsize>) -> Arc<dyn Handler> {
    Arc::new(FnHandler(move |_, payload, _| {
        count.fetch_add(1, Ordering::SeqCst);
        async move { HandlerOutcome::Payload(payload) }
    }))
}
fn listen(
    network: &Network,
    trust: &Trust,
    admission: Arc<Admission>,
    count: Arc<AtomicUsize>,
) -> ManagedServer {
    listen_handler(network, trust, admission, echo(count))
}
fn listen_handler(
    network: &Network,
    trust: &Trust,
    admission: Arc<Admission>,
    handler: Arc<dyn Handler>,
) -> ManagedServer {
    let factory: Arc<dyn AuthenticatorFactory> = Arc::new(
        |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            Ok(Arc::new(AllowAnonymous))
        },
    );
    receive(
        network
            .listen_tcp(TcpServerConfig {
                address: "127.0.0.1:0".parse().unwrap(),
                admission,
                security: trust.server.clone(),
                authenticator: factory,
                handler,
                runtime: ConnectionConfig::default(),
                limits: Limits::default(),
            })
            .unwrap(),
    )
    .unwrap()
}
fn connect(network: &Network, trust: &Trust, routes: Vec<SocketAddr>) -> ManagedClient {
    let connector = tcp_routes(
        routes.clone(),
        routes,
        trust.inputs(),
        ConnectionConfig::default(),
        Limits::default(),
    )
    .unwrap();
    receive(network.client(reconnect(), connector).unwrap()).unwrap()
}
fn generation(client: &ManagedClient) -> u64 {
    let mut found = 0;
    until(|| match client.status() {
        LifecycleStatus::CoreReady(ready) => {
            found = ready.generation;
            true
        }
        _ => false,
    });
    found
}
fn stopped(network: &mut Network) {
    let report = network.shutdown(WAIT);
    assert!(report.complete, "{report:?}");
    assert_eq!(report.pending_operations, 0);
    assert_eq!(report.failed_supervisors, 0);
}

#[test]
fn std_owned_pool_tcp_rpc_pause_resume_and_generation_fences() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let mut events = network.events();
    let trust = Trust::new();
    let effects = Arc::new(AtomicUsize::new(0));
    let server = listen(
        &network,
        &trust,
        Admission::new(4).unwrap(),
        effects.clone(),
    );
    let client = connect(&network, &trust, vec![server.local_addr()]);
    let first = generation(&client);
    let payload = vec![42; 150_000];
    let response = receive(
        client
            .call("/test.Service/Echo".into(), payload.clone(), 3000)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(response.generation, first);
    assert_eq!(response.value, payload);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert!(server.status().ready > 0);

    network.pause();
    assert!(!client.is_generation_current(first));
    assert_eq!(client.status(), LifecycleStatus::Paused);
    client.retry(); // A per-client control cannot bypass the network pause.
    assert_eq!(client.status(), LifecycleStatus::Paused);
    let unavailable = client
        .call("/test.Service/Echo".into(), vec![7], 1000)
        .unwrap();
    network.resume();
    let second = generation(&client);
    assert!(second > first);
    assert!(matches!(
        receive(unavailable),
        Err(CallError::Unavailable { .. })
    ));
    assert_eq!(
        effects.load(Ordering::SeqCst),
        1,
        "paused RPC was not replayed"
    );
    let cloned = client.clone();
    thread::spawn(move || {
        let response = receive(
            cloned
                .call("/test.Service/Echo".into(), vec![8], 1000)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.value, vec![8]);
    })
    .join()
    .unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    network.network_available(false);
    assert!(!client.is_generation_current(second));
    until(|| client.status() == LifecycleStatus::Offline);
    network.network_available(true);
    assert!(generation(&client) > second);
    server.stop();
    until(|| server.status().stopped);
    network.resume();
    assert!(server.status().stopped, "listener stop is terminal");
    stopped(&mut network);
    let mut observed_ready = false;
    while let Ok(event) = events.try_recv() {
        observed_ready |= matches!(event, NetworkEvent::ConnectionReady(_));
    }
    assert!(observed_ready);
}

#[test]
fn concurrent_handshakes_admission_held_until_teardown() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let trust = Trust::new();
    let admission = Admission::new(2).unwrap();
    let server = listen(
        &network,
        &trust,
        admission.clone(),
        Arc::new(AtomicUsize::new(0)),
    );
    let slow = TcpStream::connect(server.local_addr()).unwrap();
    until(|| server.status().admitted == 1);
    let client = connect(&network, &trust, vec![server.local_addr()]);
    generation(&client); // A stalled handshake did not serialize the second one.
    assert_eq!(server.status().admitted, 2);
    assert_eq!(admission.available(), 0);
    let queued = connect(&network, &trust, vec![server.local_addr()]);
    thread::sleep(Duration::from_millis(40));
    assert!(!matches!(queued.status(), LifecycleStatus::CoreReady(_)));
    assert_eq!(server.status().admitted, 2);
    drop(slow);
    generation(&queued);
    assert!(server.status().admitted <= 2);
    stopped(&mut network);
    assert_eq!(admission.available(), 2);
    assert_eq!(server.status().admitted, 0);
    assert_eq!(server.status().ready, 0);
}

#[test]
fn shared_admission_does_not_let_idle_listeners_hoard_capacity() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let trust = Trust::new();
    let admission = Admission::new(1).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let first = listen(&network, &trust, admission.clone(), count.clone());
    let second = listen(&network, &trust, admission.clone(), count);
    assert_eq!(admission.available(), 1);
    let active = connect(&network, &trust, vec![second.local_addr()]);
    generation(&active);
    let waiting = connect(&network, &trust, vec![first.local_addr()]);
    until(|| first.status().waiting_admission == 1);
    assert_eq!(first.status().admitted, 0);
    assert_eq!(second.status().admitted, 1);
    active.stop();
    generation(&waiting);
    assert_eq!(first.status().admitted, 1);
    stopped(&mut network);
    assert_eq!(admission.available(), 1);
    assert_eq!(first.status().waiting_admission, 0);
}

#[test]
fn shared_admission_waiter_survives_a_same_listener_connection_join() {
    let mut network = Network::new(NetworkConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let trust = Trust::new();
    let admission = Admission::new(2).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let first = listen(&network, &trust, admission.clone(), count.clone());
    let second = listen(&network, &trust, admission.clone(), count.clone());
    let active = TcpStream::connect(first.local_addr()).unwrap();
    let other = TcpStream::connect(second.local_addr()).unwrap();
    until(|| first.status().admitted == 1 && second.status().admitted == 1);
    let waiting = TcpStream::connect(first.local_addr()).unwrap();
    until(|| first.status().waiting_admission == 1);
    assert_eq!(admission.available(), 0);

    // Completing this task both frees shared capacity and makes join_next ready.
    // A biased join must not cancel the already accepted, waiting socket.
    drop(active);
    until(|| first.status().completed == 1);
    let external = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    external.block_on(async {
        waiting.set_nonblocking(true).unwrap();
        let stream = tokio::net::TcpStream::from_std(waiting).unwrap();
        let (security, credential) = trust.inputs()().unwrap();
        let client = tokio::time::timeout(
            WAIT,
            syntra_net::tcp::connect_stream(
                stream,
                security,
                credential,
                ConnectionConfig::default(),
                Limits::default(),
            ),
        )
        .await
        .expect("the retained waiter must receive admission")
        .expect("joining another connection must not close the waiting socket");
        assert_eq!(
            client
                .conn
                .call("/test.Service/Echo", vec![5], 1000)
                .await
                .unwrap(),
            vec![5]
        );
        assert_eq!(first.status().ready, 1);
        client.close().await;
    });
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(other);
    stopped(&mut network);
    assert_eq!(admission.available(), 2);
    assert_eq!(first.status().waiting_admission, 0);
}

#[test]
fn listener_lifecycle_controls_drop_a_retained_admission_waiter() {
    use std::io::Read;

    let mut network = Network::new(NetworkConfig {
        worker_threads: 2,
        ..Default::default()
    })
    .unwrap();
    let trust = Trust::new();
    let admission = Admission::new(1).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let first = listen(&network, &trust, admission.clone(), count.clone());
    let second = listen(&network, &trust, admission.clone(), count);
    for stop in [false, true] {
        let active = TcpStream::connect(second.local_addr()).unwrap();
        until(|| second.status().admitted == 1);
        let mut waiting = TcpStream::connect(first.local_addr()).unwrap();
        waiting.set_read_timeout(Some(WAIT)).unwrap();
        until(|| first.status().waiting_admission == 1);
        if stop {
            first.stop();
        } else {
            network.pause();
        }
        let mut byte = [0];
        assert_eq!(
            waiting.read(&mut byte).unwrap(),
            0,
            "discard cancelled admission"
        );
        until(|| first.status().waiting_admission == 0);
        drop(active);
        until(|| second.status().admitted == 0);
        if stop {
            until(|| first.status().stopped);
        } else {
            assert_eq!(admission.available(), 1);
            network.resume();
        }
    }
    stopped(&mut network);
    assert_eq!(admission.available(), 1);
}

#[test]
fn operation_can_be_awaited_from_an_unrelated_executor() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let external = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    external.block_on(async {
        let mut config = reconnect();
        config.start_paused = true;
        let client = network
            .client(config, || async { Err(Error::Closed) })
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(client.status(), LifecycleStatus::Paused);
        assert!(matches!(
            client
                .call("/test.Service/Echo".into(), vec![], 1000)
                .unwrap()
                .await
                .unwrap(),
            Err(CallError::Unavailable { generation: None })
        ));
    });
    stopped(&mut network);
}

#[test]
fn inflight_rpc_is_fenced_without_replay_to_a_successor() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let trust = Trust::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn Handler> = {
        let calls = calls.clone();
        Arc::new(FnHandler(move |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<HandlerOutcome>()
        }))
    };
    let server = listen_handler(&network, &trust, Admission::new(2).unwrap(), handler);
    let client = connect(&network, &trust, vec![server.local_addr()]);
    let first = generation(&client);
    let operation = client
        .call("/test.Service/Echo".into(), vec![4], 3000)
        .unwrap();
    until(|| calls.load(Ordering::SeqCst) == 1);
    network.pause();
    assert!(matches!(
        receive(operation),
        Err(CallError::Unavailable { generation: Some(generation) }) if generation == first
    ));
    network.resume();
    assert!(generation(&client) > first);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stopped(&mut network);
}

#[test]
fn explicit_allowlisted_failover_and_authentication_is_terminal() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    let trust = Trust::new();
    let server = listen(
        &network,
        &trust,
        Admission::new(4).unwrap(),
        Arc::new(AtomicUsize::new(0)),
    );
    // Reserve then close a local port to get a concrete unreachable first route.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unreachable = closed.local_addr().unwrap();
    drop(closed);
    assert!(tcp_routes(
        vec![unreachable],
        vec![server.local_addr()],
        trust.inputs(),
        ConnectionConfig::default(),
        Limits::default()
    )
    .is_err());
    let client = connect(&network, &trust, vec![unreachable, server.local_addr()]);
    generation(&client);
    assert_eq!(
        receive(
            client
                .call("/test.Service/Echo".into(), vec![9], 1000)
                .unwrap()
        )
        .unwrap()
        .value,
        vec![9]
    );

    let wrong = Trust::new();
    let wrong_effects = Arc::new(AtomicUsize::new(0));
    let wrong_server = listen(
        &network,
        &wrong,
        Admission::new(2).unwrap(),
        wrong_effects.clone(),
    );
    // A wrong NK key can close the socket before an authenticated error exists.
    // That I/O failure may advance routes, but cannot change the provisioned pin.
    let verified = connect(
        &network,
        &trust,
        vec![wrong_server.local_addr(), server.local_addr()],
    );
    generation(&verified);
    assert_eq!(wrong_effects.load(Ordering::SeqCst), 0);
    let attempts = Arc::new(AtomicUsize::new(0));
    let blocked = receive(
        network
            .client(reconnect(), {
                let attempts = attempts.clone();
                move || {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async { Err(Error::Authentication) }
                }
            })
            .unwrap(),
    )
    .unwrap();
    until(|| {
        matches!(
            blocked.status(),
            LifecycleStatus::Blocked(Failure::Authentication)
        )
    });
    thread::sleep(Duration::from_millis(100));
    assert!(
        matches!(blocked.status(), LifecycleStatus::Blocked(_)),
        "authentication failure must not advance to a different route"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    stopped(&mut network);
}

#[test]
fn timeout_retains_runtime_and_blocking_jobs_until_observed_completion() {
    let mut network = Network::new(NetworkConfig {
        worker_threads: 1,
        max_blocking_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let running = Arc::new(AtomicBool::new(false));
    let connector = {
        let gate = gate.clone();
        let running = running.clone();
        move || {
            let gate = gate.clone();
            let running = running.clone();
            async move {
                let work = tokio::task::spawn_blocking(move || {
                    running.store(true, Ordering::SeqCst);
                    let (value, changed) = &*gate;
                    let mut released = value.lock().unwrap();
                    while !*released {
                        released = changed.wait(released).unwrap();
                    }
                    running.store(false, Ordering::SeqCst);
                });
                // Runtime destruction must still own this job after cancellation
                // of the connector await. It cannot be aborted by Tokio.
                let _ = work.await;
                Err(Error::Closed)
            }
        }
    };
    receive(network.client(reconnect(), connector).unwrap()).unwrap();
    until(|| running.load(Ordering::SeqCst));
    let started = Instant::now();
    let report = network.shutdown(Duration::from_millis(20));
    assert!(!report.complete);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(running.load(Ordering::SeqCst));
    *gate.0.lock().unwrap() = true;
    gate.1.notify_all();
    stopped(&mut network);
    assert!(!running.load(Ordering::SeqCst));
}

#[test]
fn drop_from_owned_worker_and_external_async_context_never_self_joins() {
    let slot = Arc::new(Mutex::new(None::<Network>));
    let dropped = Arc::new(AtomicBool::new(false));
    let network = Network::new(NetworkConfig {
        worker_threads: 1,
        ..Default::default()
    })
    .unwrap();
    let connector = {
        let slot = slot.clone();
        let dropped = dropped.clone();
        move || {
            let slot = slot.clone();
            let dropped = dropped.clone();
            async move {
                loop {
                    let owner = slot.lock().unwrap().take();
                    if let Some(mut network) = owner {
                        assert!(!network.shutdown(Duration::from_secs(10)).complete);
                        drop(network);
                        dropped.store(true, Ordering::SeqCst);
                        return Err(Error::Closed);
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
        }
    };
    let client = receive(network.client(reconnect(), connector).unwrap()).unwrap();
    *slot.lock().unwrap() = Some(network);
    until(|| dropped.load(Ordering::SeqCst));
    until(|| client.status() == LifecycleStatus::Stopped);
    until(|| retired_networks().iter().all(|report| report.complete));

    let external = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    external.block_on(async {
        let network = Network::new(NetworkConfig::default()).unwrap();
        drop(network);
    });
    until(|| retired_networks().iter().all(|report| report.complete));
}

#[test]
fn invalid_configuration_and_bounded_service_admission() {
    fn thread_safe<T: Send + Sync>() {}
    thread_safe::<Network>();
    thread_safe::<ManagedClient>();
    thread_safe::<ManagedServer>();
    thread_safe::<Operation<Vec<u8>>>();
    assert!(Network::new(NetworkConfig {
        worker_threads: 0,
        ..Default::default()
    })
    .is_err());
    let mut network = Network::new(NetworkConfig {
        maximum_operations: 1,
        ..Default::default()
    })
    .unwrap();
    let mut config = reconnect();
    config.start_paused = true;
    let client = receive(
        network
            .client(config.clone(), || async { Err(Error::Closed) })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(client.status(), LifecycleStatus::Paused);
    assert!(network
        .client(config, || async { Err(Error::Closed) })
        .is_err());
    assert_eq!(client.status(), LifecycleStatus::Paused);
    stopped(&mut network);
}

#[test]
fn clients_created_while_network_paused_cannot_start_a_dial() {
    let mut network = Network::new(NetworkConfig::default()).unwrap();
    network.pause();
    let attempts = Arc::new(AtomicUsize::new(0));
    let client = receive(
        network
            .client(reconnect(), {
                let attempts = attempts.clone();
                move || {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    async { Err(Error::Authentication) }
                }
            })
            .unwrap(),
    )
    .unwrap();
    assert!(network.status().paused);
    assert_eq!(client.status(), LifecycleStatus::Paused);
    thread::sleep(Duration::from_millis(20));
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    network.resume();
    until(|| attempts.load(Ordering::SeqCst) == 1);
    stopped(&mut network);
}
