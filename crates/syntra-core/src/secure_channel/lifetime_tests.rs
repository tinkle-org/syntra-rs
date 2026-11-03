use super::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct ManualSource(Mutex<Option<Duration>>);
impl ManualSource {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(Some(Duration::from_secs(100)))))
    }
    fn set(&self, value: Option<Duration>) {
        *self.0.lock().unwrap() = value;
    }
    fn advance_to(&self, age: Duration) {
        self.set(Some(Duration::from_secs(100) + age));
    }
}
impl ElapsedSource for ManualSource {
    fn elapsed(&self) -> Option<Duration> {
        *self.0.lock().unwrap()
    }
}

struct Store;
impl KeyStore for Store {
    fn lookup(&self, _: &Context) -> Result<Secret32, Error> {
        Ok(Secret32::new([9; 32]))
    }
}

fn configs(mode: Mode) -> (ClientConfig, ServerConfig) {
    let (private_key, server_public_key) = generate_server_key().unwrap();
    let context = Context {
        mode,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: b"lifetime-test".to_vec(),
        handle: if mode == Mode::Returning {
            [7; 8]
        } else {
            [0; 8]
        },
        epoch: u64::from(mode == Mode::Returning),
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key,
            authorization_key: (mode == Mode::Returning).then(|| Secret32::new([9; 32])),
        },
        ServerConfig {
            mode,
            carrier: context.carrier,
            server_key_id: context.server_key_id,
            scope: context.scope,
            private_key,
            store: Some(Arc::new(Store)),
        },
    )
}

fn pair(mode: Mode, clock: Clock) -> (Channel, Channel) {
    let (client, server) = configs(mode);
    let (client, first) = ClientHandshake::start_with_clock(client, clock.clone()).unwrap();
    let (mut server, second) = respond_with_clock(&server, &first, clock).unwrap();
    let mut client = client.finish(&second).unwrap();
    server
        .decrypt(&client.encrypt(b"confirm client").unwrap())
        .unwrap();
    client
        .decrypt(&server.encrypt(b"confirm server").unwrap())
        .unwrap();
    (client, server)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn establishment_and_idle_consume_both_roles_lifetime_without_reset_at_split() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let source = ManualSource::new();
        let clock = Clock::with_source(source.clone());
        let (config, server_config) = configs(mode);
        // Time before kernel entry can include socket/TLS/upgrade establishment.
        source.advance_to(Duration::from_secs(7));
        let (client, first) = ClientHandshake::start_with_clock(config, clock.clone()).unwrap();
        source.advance_to(MAX_AGE - Duration::from_secs(1));
        let (mut server, second) = respond_with_clock(&server_config, &first, clock).unwrap();
        let mut client = client.finish(&second).unwrap();
        assert_eq!(client.age(), MAX_AGE - Duration::from_secs(1));
        assert_eq!(server.age(), MAX_AGE - Duration::from_secs(1));
        let record = client.encrypt(b"last second").unwrap();
        server.decrypt(&record).unwrap();
        assert!(server.verified_identity().is_some());
        // No traffic or timer callback occurs during the last idle second.
        source.advance_to(MAX_AGE);
        assert!(server.verified_identity().is_none());
        assert!(matches!(client.encrypt(b"expired"), Err(Error::Limit)));
        assert!(matches!(server.decrypt(&record), Err(Error::Limit)));
        assert!(matches!(client.encrypt(b"no revival"), Err(Error::Closed)));
        assert!(matches!(server.decrypt(&record), Err(Error::Closed)));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn expired_establishment_never_returns_a_first_flight_or_channel() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        let source = ManualSource::new();
        let clock = Clock::with_source(source.clone());
        let (config, server_config) = configs(mode);
        let (client, first) = ClientHandshake::start_with_clock(config, clock.clone()).unwrap();
        let (_, second) = respond(&server_config, &first).unwrap();
        source.advance_to(MAX_AGE);
        assert!(matches!(client.finish(&second), Err(Error::Limit)));
        assert!(matches!(
            respond_with_clock(&server_config, &first, clock.clone()),
            Err(Error::Limit)
        ));
        let (config, _) = configs(mode);
        assert!(matches!(
            ClientHandshake::start_with_clock(config, clock),
            Err(Error::Limit)
        ));
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn responder_lookup_time_is_charged_before_m2_is_returned() {
    struct DelayedStore {
        source: Arc<ManualSource>,
        age: Duration,
    }
    impl KeyStore for DelayedStore {
        fn lookup(&self, _: &Context) -> Result<Secret32, Error> {
            self.source.advance_to(self.age);
            Ok(Secret32::new([9; 32]))
        }
    }
    for age in [MAX_AGE - Duration::from_secs(1), MAX_AGE] {
        let source = ManualSource::new();
        let clock = Clock::with_source(source.clone());
        let (config, mut server) = configs(Mode::Returning);
        let (_, first) = ClientHandshake::start(config).unwrap();
        server.store = Some(Arc::new(DelayedStore { source, age }));
        let result = respond_with_clock(&server, &first, clock);
        if age < MAX_AGE {
            assert_eq!(result.unwrap().0.age(), age);
        } else {
            assert!(matches!(result, Err(Error::Limit)));
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn clock_unknown_regression_and_invalidation_are_sticky() {
    for unavailable in [true, false] {
        let source = ManualSource::new();
        if unavailable {
            source.set(None);
        }
        let clock = Clock::with_source(source.clone());
        if !unavailable {
            source.advance_to(Duration::from_secs(10));
            assert_eq!(clock.age(), Duration::from_secs(10));
            // Still above origin, but below the previous observation.
            source.advance_to(Duration::from_secs(9));
        }
        assert_eq!(clock.age(), MAX_AGE);
        source.advance_to(Duration::from_secs(20));
        assert_eq!(clock.clone().age(), MAX_AGE);
    }
    let source = ManualSource::new();
    let clock = Clock::with_source(source.clone());
    source.set(None);
    assert_eq!(clock.age(), MAX_AGE);
    source.advance_to(Duration::from_secs(1));
    assert_eq!(clock.age(), MAX_AGE);
    let clock = Clock::with_source(source);
    clock.clone().invalidate();
    assert_eq!(clock.age(), MAX_AGE);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn suspend_or_unknown_time_retires_standalone_kernel_in_both_directions() {
    for failure in [
        None,
        Some(Duration::from_secs(99)),
        Some(Duration::from_secs(100) + MAX_AGE),
    ] {
        for mode in [Mode::Bootstrap, Mode::Returning] {
            let source = ManualSource::new();
            let clock = Clock::with_source(source.clone());
            let (mut client, mut server) = pair(mode, clock);
            let incoming = client.encrypt(b"buffered before suspend").unwrap();
            // A trusted source advances across suspend even without a scheduler
            // tick, a timer firing, or a wall-clock observation.
            source.set(failure);
            assert!(server.verified_identity().is_none());
            assert!(matches!(
                client.encrypt(b"after suspend"),
                Err(Error::Limit)
            ));
            assert!(matches!(server.decrypt(&incoming), Err(Error::Limit)));
            source.advance_to(Duration::from_secs(1));
            assert!(matches!(client.encrypt(b"no revival"), Err(Error::Closed)));
            assert!(matches!(server.decrypt(&incoming), Err(Error::Closed)));
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn final_allowed_record_succeeds_then_either_counter_gates_both_directions() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for responder in [false, true] {
            for send_limit in [false, true] {
                for next_send in [false, true] {
                    let (client, server) = pair(mode, Clock::new());
                    let (mut target, mut peer) = if responder {
                        (server, client)
                    } else {
                        (client, server)
                    };
                    let incoming = peer.encrypt(b"incoming").unwrap();
                    if send_limit {
                        target.sent = MAX_RECORDS - 1;
                        let final_record = target.encrypt(b"final outgoing").unwrap();
                        assert_eq!(&**peer.decrypt(&final_record).unwrap(), b"final outgoing");
                        assert_eq!(target.sent, MAX_RECORDS);
                    } else {
                        target.received = MAX_RECORDS - 1;
                        assert_eq!(&**target.decrypt(&incoming).unwrap(), b"incoming");
                        assert_eq!(target.received, MAX_RECORDS);
                    }
                    assert!(target.verified_identity().is_none());
                    if next_send {
                        assert!(matches!(target.encrypt(b"over budget"), Err(Error::Limit)));
                    } else {
                        assert!(matches!(target.decrypt(&incoming), Err(Error::Limit)));
                    }
                    assert!(matches!(target.encrypt(b"closed"), Err(Error::Closed)));
                    assert!(matches!(target.decrypt(&incoming), Err(Error::Closed)));
                }
            }
        }
    }
}
