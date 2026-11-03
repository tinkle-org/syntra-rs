use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Synthetic, test-only envelope vault. Deliberately NOT an at-rest encryption
// implementation and never exposed outside this cfg(test) module.
#[derive(Default)]
struct Vault(Mutex<Vec<(Binding, [u8; 32])>>);
impl KeyProtection for Vault {
    fn protect(&self, binding: &Binding, key: &Secret32) -> Result<Vec<u8>, Error> {
        self.0
            .lock()
            .unwrap()
            .push((binding.clone(), *key.expose()));
        Ok(binding.handle.to_vec())
    }
    fn unprotect(&self, binding: &Binding, envelope: &[u8]) -> Result<Secret32, Error> {
        if envelope != binding.handle {
            return Err(Error::Denied);
        }
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|(b, _)| b == binding)
            .map(|(_, key)| Secret32::new(*key))
            .ok_or(Error::Denied)
    }
    fn destroy(&self, binding: &Binding) -> Result<(), Error> {
        self.0.lock().unwrap().retain(|(b, _)| b != binding);
        Ok(())
    }
    fn reconcile_orphans(
        &self,
        store_id: &str,
        known: &[Binding],
        limit: usize,
    ) -> Result<usize, Error> {
        let mut removed = 0;
        self.0.lock().unwrap().retain(|(binding, _)| {
            if binding.store_id == store_id && !known.contains(binding) && removed < limit {
                removed += 1;
                false
            } else {
                true
            }
        });
        Ok(removed)
    }
}

#[derive(Default)]
struct Authority;
impl EnrollmentAuthority for Authority {
    fn approve(&self, request: &Request, evidence: &[u8]) -> Result<(), Error> {
        let expected = if request.issuance == Issuance::Recovery {
            b"independent-recovery".as_slice()
        } else {
            b"approved".as_slice()
        };
        if evidence == expected {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    fn approve_revocation(&self, _: &str, evidence: &[u8]) -> Result<(), Error> {
        if evidence == b"revoke" {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
    fn verify_durable_ack(&self, binding: &Binding, receipt: &[u8]) -> Result<(), Error> {
        if receipt == binding.handle {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
}

#[derive(Default)]
struct AnchorStore {
    head: Mutex<Option<Anchor>>,
    unavailable: AtomicBool,
    fail_before: AtomicBool,
    lose_response: AtomicBool,
    delay_ms: AtomicU64,
    delay_next_cas: AtomicBool,
    delayed_cas: Mutex<Option<(Option<Anchor>, Anchor)>>,
    unsettled: AtomicBool,
    commit_during_settlement: AtomicBool,
    fenced: Mutex<Vec<Anchor>>,
}
impl AnchorStore {
    fn apply_delayed(&self) -> bool {
        let Some((expected, next)) = self.delayed_cas.lock().unwrap().take() else {
            return false;
        };
        if self.fenced.lock().unwrap().contains(&next) {
            return false;
        }
        let mut head = self.head.lock().unwrap();
        assert_eq!(*head, expected);
        *head = Some(next);
        true
    }
}
impl RollbackAuthority for AnchorStore {
    fn current(&self) -> Result<Option<Anchor>, Error> {
        let delay = self.delay_ms.load(Ordering::SeqCst);
        if delay != 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        Ok(*self.head.lock().unwrap())
    }
    fn compare_and_swap(&self, expected: Option<Anchor>, next: Anchor) -> Result<(), Error> {
        if self.unavailable.load(Ordering::SeqCst) || self.fail_before.swap(false, Ordering::SeqCst)
        {
            return Err(Error::Unavailable);
        }
        if self.fenced.lock().unwrap().contains(&next) {
            return Err(Error::Denied);
        }
        if self.delay_next_cas.swap(false, Ordering::SeqCst) {
            *self.delayed_cas.lock().unwrap() = Some((expected, next));
            return Err(Error::CommitUnknown);
        }
        let mut head = self.head.lock().unwrap();
        if *head != expected {
            return Err(Error::Integrity);
        }
        *head = Some(next);
        if self.lose_response.swap(false, Ordering::SeqCst) {
            return Err(Error::CommitUnknown);
        }
        Ok(())
    }
    fn settle(&self, expected: Option<Anchor>, next: Anchor) -> Result<Settlement, Error> {
        if self.unavailable.load(Ordering::SeqCst) || self.unsettled.load(Ordering::SeqCst) {
            return Err(Error::Unavailable);
        }
        if self.commit_during_settlement.swap(false, Ordering::SeqCst) {
            assert!(self.apply_delayed());
        }
        let head = *self.head.lock().unwrap();
        if head == Some(next) {
            return Ok(Settlement::Committed);
        }
        if head != expected {
            return Err(Error::Integrity);
        }
        // This mock implements a definitive abort/fence, not a second snapshot
        // read. The delayed worker is still queued, but can no longer apply.
        self.fenced.lock().unwrap().push(next);
        Ok(Settlement::Aborted)
    }
}

struct Clock(AtomicU64);
impl TrustedClock for Clock {
    fn now(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Delivery(Mutex<Option<[u8; 32]>>);
impl EncryptedDelivery for Delivery {
    fn deliver(&self, _: &Binding, key: &Secret32) -> Result<(), Error> {
        *self.0.lock().unwrap() = Some(*key.expose());
        Ok(())
    }
}

fn policy() -> Policy {
    Policy {
        permitted_bindings: vec![EnrollmentBinding::SecureWebSocket],
        activation_seconds: 20,
        overlap_seconds: 10,
        max_validity_seconds: 1000,
        freshness_seconds: 10,
        read_seconds: 1,
        close_seconds: 1,
        max_records: 64,
        audit_entries: 4,
        cleanup_batch: 4,
        max_pins: 4,
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: std::path::PathBuf,
    lock: std::path::PathBuf,
    anchor: Arc<AnchorStore>,
    vault: Arc<Vault>,
    clock: Arc<Clock>,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "syntra-enrollment-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        Self {
            lock: path.with_extension("lock"),
            path,
            anchor: Default::default(),
            vault: Default::default(),
            clock: Arc::new(Clock(AtomicU64::new(100))),
        }
    }
    fn open(&self) -> SqliteEnrollmentStore {
        self.open_with_policy(policy())
    }
    fn open_with_policy(&self, policy: Policy) -> SqliteEnrollmentStore {
        SqliteEnrollmentStore::open(
            &self.path,
            &self.lock,
            "test-store".into(),
            policy,
            self.deployment(),
        )
        .unwrap()
    }
    fn deployment(&self) -> Deployment {
        Deployment {
            protector: self.vault.clone(),
            rollback: self.anchor.clone(),
            authority: Arc::new(Authority),
            clock: self.clock.clone(),
        }
    }
    fn time(&self, now: u64) {
        self.clock.0.store(now, Ordering::SeqCst);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only remove the exact synthetic files this fixture created. No directory
        // cleanup, and never any production/test sibling paths.
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(&self.lock);
    }
}

fn request(attempt: &str, issuance: Issuance) -> Request {
    Request {
        attempt: attempt.into(),
        logical_id: "device-1".into(),
        principal: "principal-A".into(),
        device: "device-ref".into(),
        scope: "service.example:443/app".into(),
        expires_at: 500,
        issuance,
    }
}
fn context(binding: &Binding) -> Context {
    Context {
        mode: Mode::Returning,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: binding.scope.as_bytes().to_vec(),
        handle: binding.handle,
        epoch: binding.epoch,
    }
}
fn provision(store: &SqliteEnrollmentStore, attempt: &str, issuance: Issuance) -> Binding {
    let evidence = if issuance == Issuance::Recovery {
        b"independent-recovery".as_slice()
    } else {
        b"approved".as_slice()
    };
    let binding = store.stage(request(attempt, issuance), evidence).unwrap();
    store.deliver(attempt, &Delivery(Mutex::new(None))).unwrap();
    store.activate(attempt, &binding.handle).unwrap()
}

#[test]
fn denied_authority_has_no_record_or_secret_and_stage_never_authorizes() {
    let f = Fixture::new();
    let store = f.open();
    assert_eq!(
        store.stage(request("first", Issuance::Initial), b"candidate-ak"),
        Err(Error::Denied)
    );
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 0);
    assert!(f.vault.0.lock().unwrap().is_empty());
    let binding = store
        .stage(request("first", Issuance::Initial), b"approved")
        .unwrap();
    assert!(store.lookup(&context(&binding)).is_err());
    assert_eq!(store.activate("first", &binding.handle), Err(Error::Denied));
    let delivery = Delivery(Mutex::new(None));
    store.deliver("first", &delivery).unwrap();
    assert!(store.lookup(&context(&binding)).is_err());
    assert_eq!(
        store.activate("first", b"not-persisted"),
        Err(Error::Denied)
    );
    store.activate("first", &binding.handle).unwrap();
    assert_eq!(
        store.lookup(&context(&binding)).unwrap().expose(),
        delivery.0.lock().unwrap().as_ref().unwrap()
    );
    assert_eq!(
        store
            .stage(request("first", Issuance::Initial), b"approved")
            .unwrap(),
        binding
    );
    assert_eq!(store.activate("first", &binding.handle).unwrap(), binding);
    assert_eq!(f.vault.0.lock().unwrap().len(), 1);
}

#[test]
fn immutable_principal_scope_attempt_and_carrier_binding() {
    let f = Fixture::new();
    let store = f.open();
    let binding = provision(&store, "initial", Issuance::Initial);
    assert_eq!(
        store.validate(&context(&binding), Some("principal-B")),
        Err(Error::Denied)
    );
    let mut bad = context(&binding);
    bad.scope.push(b'x');
    assert!(store.lookup(&bad).is_err());
    bad = context(&binding);
    bad.carrier = Carrier::WebSocket;
    assert!(store.lookup(&bad).is_err());
    bad.carrier = Carrier::Tcp;
    assert!(store.lookup(&bad).is_err());
    for field in [0, 1, 2] {
        let mut req = request("rotation", Issuance::Rotation);
        match field {
            0 => req.principal = "principal-B".into(),
            1 => req.scope = "elsewhere".into(),
            _ => req.device = "another".into(),
        }
        assert_eq!(store.stage(req, b"approved"), Err(Error::Denied));
    }
    let mut changed = request("initial", Issuance::Initial);
    changed.expires_at += 1;
    assert_eq!(store.stage(changed, b"approved"), Err(Error::Denied));
}

#[test]
fn rotation_is_fresh_bounded_and_lost_ack_cannot_extend_cutoff() {
    let f = Fixture::new();
    let store = f.open();
    let old = provision(&store, "initial", Issuance::Initial);
    let new = store
        .stage(request("rotation", Issuance::Rotation), b"approved")
        .unwrap();
    assert_ne!(new.handle, old.handle);
    assert!(new.epoch > old.epoch);
    store
        .deliver("rotation", &Delivery(Mutex::new(None)))
        .unwrap();
    assert!(store.lookup(&context(&new)).is_err());
    f.time(105);
    store
        .stage(request("rotation", Issuance::Rotation), b"approved")
        .unwrap();
    store.activate("rotation", &new.handle).unwrap();
    assert!(store.lookup(&context(&old)).is_ok());
    assert_ne!(
        store.lookup(&context(&old)).unwrap().expose(),
        store.lookup(&context(&new)).unwrap().expose()
    );
    f.time(110);
    assert!(store.lookup(&context(&old)).is_err());
    assert!(store.lookup(&context(&new)).is_ok());
    let third = store
        .stage(request("lost-ack", Issuance::Rotation), b"approved")
        .unwrap();
    store
        .deliver("lost-ack", &Delivery(Mutex::new(None)))
        .unwrap();
    f.time(120);
    assert!(store.lookup(&context(&new)).is_err());
    assert!(store.lookup(&context(&third)).is_err());
    assert_eq!(
        store.activate("lost-ack", &third.handle),
        Err(Error::Denied)
    );
    assert!(store
        .stage(request("lost-ack", Issuance::Rotation), b"approved")
        .is_ok());
    // Even an identical retry has not extended the predecessor cutoff.
    assert!(store.lookup(&context(&new)).is_err());
}

#[test]
fn expiry_timeout_and_recovery_require_independent_authority() {
    let f = Fixture::new();
    let store = f.open();
    let binding = store
        .stage(request("expired", Issuance::Initial), b"approved")
        .unwrap();
    f.time(120);
    assert_eq!(
        store.deliver("expired", &Delivery(Mutex::new(None))),
        Err(Error::Denied)
    );
    assert_eq!(
        store.stage(request("expired", Issuance::Initial), b"approved"),
        Err(Error::Denied)
    );
    assert_eq!(store.cleanup().unwrap(), 1);
    assert!(f.vault.unprotect(&binding, &binding.handle).is_err());
    assert_eq!(
        store.stage(request("recovery", Issuance::Recovery), b"approved"),
        Err(Error::Denied)
    );
    let fresh = provision(&store, "recovery", Issuance::Recovery);
    assert_ne!(fresh.handle, binding.handle);
    assert_eq!(store.revoke("device-1", b"revoked-ak"), Err(Error::Denied));
    store.revoke("device-1", b"revoke").unwrap();
    assert!(store.lookup(&context(&fresh)).is_err());
    assert_eq!(
        store.stage(request("self-restore", Issuance::Rotation), b"approved"),
        Err(Error::Denied)
    );
    let replacement = provision(&store, "independent", Issuance::Recovery);
    f.time(500);
    assert!(store.lookup(&context(&replacement)).is_err());
}

#[test]
fn crash_boundaries_reconcile_lost_anchor_response_and_abort_uncommitted_intent() {
    let f = Fixture::new();
    let store = f.open();
    f.anchor.fail_before.store(true, Ordering::SeqCst);
    assert_eq!(
        store.stage(request("first", Issuance::Initial), b"approved"),
        Err(Error::CommitUnknown)
    );
    drop(store);
    let store = f.open();
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 0);
    f.anchor.lose_response.store(true, Ordering::SeqCst);
    assert_eq!(
        store.stage(request("first", Issuance::Initial), b"approved"),
        Err(Error::CommitUnknown)
    );
    drop(store);
    let store = f.open();
    let binding = store
        .stage(request("first", Issuance::Initial), b"approved")
        .unwrap();
    store.deliver("first", &Delivery(Mutex::new(None))).unwrap();
    f.anchor.lose_response.store(true, Ordering::SeqCst);
    assert_eq!(
        store.activate("first", &binding.handle),
        Err(Error::CommitUnknown)
    );
    drop(store);
    let store = f.open();
    assert_eq!(store.activate("first", &binding.handle).unwrap(), binding);
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 1);
}

#[test]
fn every_provisioning_commit_boundary_reconciles_before_and_after_external_cas() {
    for boundary in 0..3 {
        for after_cas in [false, true] {
            let f = Fixture::new();
            let store = f.open();
            let mut binding = None;
            if boundary > 0 {
                binding = Some(
                    store
                        .stage(request("attempt", Issuance::Initial), b"approved")
                        .unwrap(),
                );
            }
            if boundary > 1 {
                store
                    .deliver("attempt", &Delivery(Mutex::new(None)))
                    .unwrap();
            }
            if after_cas {
                f.anchor.lose_response.store(true, Ordering::SeqCst);
            } else {
                f.anchor.fail_before.store(true, Ordering::SeqCst);
            }
            let outcome = match boundary {
                0 => store
                    .stage(request("attempt", Issuance::Initial), b"approved")
                    .map(|_| ()),
                1 => store.deliver("attempt", &Delivery(Mutex::new(None))),
                _ => store
                    .activate("attempt", &binding.as_ref().unwrap().handle)
                    .map(|_| ()),
            };
            assert_eq!(outcome, Err(Error::CommitUnknown));
            drop(store);
            let store = f.open();
            let reconciled = store
                .stage(request("attempt", Issuance::Initial), b"approved")
                .unwrap();
            if let Some(binding) = binding {
                assert_eq!(binding, reconciled);
            }
            let active = store.validate(&context(&reconciled), None).is_ok();
            assert_eq!(active, boundary == 2 && after_cas);
            if !active {
                store
                    .deliver("attempt", &Delivery(Mutex::new(None)))
                    .unwrap();
            }
            store.activate("attempt", &reconciled.handle).unwrap();
            store.cleanup().unwrap(); // also disposes orphan wrapping objects
            assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 1);
            assert_eq!(f.vault.0.lock().unwrap().len(), 1);
        }
    }
}

#[test]
fn delayed_cas_after_failed_reconciliation_retains_its_only_durable_image() {
    let f = Fixture::new();
    let store = f.open();
    f.anchor.delay_next_cas.store(true, Ordering::SeqCst);
    assert_eq!(
        store.stage(request("late", Issuance::Initial), b"approved"),
        Err(Error::CommitUnknown)
    );
    // A current() read sees the old anchor, but cannot settle a still-running
    // remote operation. Returning unavailable must NOT delete SQLite slot 1.
    f.anchor.unsettled.store(true, Ordering::SeqCst);
    assert_eq!(store.inspect(|_, _| Ok(())), Err(Error::Unavailable));
    assert!(
        SqliteEnrollmentStore::image(&store.database.lock().unwrap().connection, 1)
            .unwrap()
            .is_some()
    );
    // Remote CAS applies AFTER that reconciliation read, before a later retry.
    assert!(f.anchor.apply_delayed());
    drop(store);
    f.anchor.unsettled.store(false, Ordering::SeqCst);
    let store = f.open();
    let binding = store
        .stage(request("late", Issuance::Initial), b"approved")
        .unwrap();
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 1);
    assert!(store.lookup(&context(&binding)).is_err());
    store.deliver("late", &Delivery(Mutex::new(None))).unwrap();
    store.activate("late", &binding.handle).unwrap();
    assert!(store.lookup(&context(&binding)).is_ok());
}

#[test]
fn definitive_settlement_fences_a_worker_that_runs_after_intent_cleanup() {
    let f = Fixture::new();
    let store = f.open();
    f.anchor.delay_next_cas.store(true, Ordering::SeqCst);
    assert_eq!(
        store.stage(request("aborted", Issuance::Initial), b"approved"),
        Err(Error::CommitUnknown)
    );
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 0);
    assert!(
        !f.anchor.apply_delayed(),
        "settlement must fence the late worker, not merely read old state"
    );
    // Repeated identical no-op writes at the same time still have fresh CAS
    // identities, so a previous abort cannot strand a later legitimate write.
    f.anchor.fail_before.store(true, Ordering::SeqCst);
    assert_eq!(store.cleanup(), Err(Error::CommitUnknown));
    store.inspect(|_, _| Ok(())).unwrap();
    store.cleanup().unwrap();
    let binding = provision(&store, "fresh", Issuance::Initial);
    assert!(store.lookup(&context(&binding)).is_ok());
}

#[test]
fn settlement_observes_a_cas_committing_after_the_initial_old_head_read() {
    let f = Fixture::new();
    let store = f.open();
    f.anchor.delay_next_cas.store(true, Ordering::SeqCst);
    assert_eq!(
        store.stage(request("racing", Issuance::Initial), b"approved"),
        Err(Error::CommitUnknown)
    );
    f.anchor
        .commit_during_settlement
        .store(true, Ordering::SeqCst);
    let binding = store
        .stage(request("racing", Issuance::Initial), b"approved")
        .unwrap();
    store
        .deliver("racing", &Delivery(Mutex::new(None)))
        .unwrap();
    store.activate("racing", &binding.handle).unwrap();
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 1);
    assert!(store.lookup(&context(&binding)).is_ok());
}

#[test]
fn enrollment_policy_requires_an_explicit_nonduplicate_binding_set() {
    for bindings in [vec![], vec![EnrollmentBinding::Tcp, EnrollmentBinding::Tcp]] {
        let mut policy = policy();
        policy.permitted_bindings = bindings;
        assert_eq!(policy.validate(), Err(Error::Configuration));
    }
}

#[tokio::test]
async fn configured_tcp_enrollment_preserves_store_scope_principal_and_revocation_checks() {
    use crate::pump::AuthenticatorFactory;
    use syntra_core::secure_channel::{
        generate_server_key, respond, ClientConfig, ClientHandshake, ServerConfig, VerifiedIdentity,
    };
    use syntra_runtime::{AuthError, ExecutionBudget, Principal};

    struct Identity(&'static str);
    impl ApplicationIdentity for Identity {
        fn authenticate(&self, _: &VerifiedIdentity, _: &[u8]) -> Result<Principal, AuthError> {
            Ok(Principal::new(self.0))
        }
    }
    let fixture = Fixture::new();
    let mut policy = policy();
    policy.permitted_bindings = vec![EnrollmentBinding::Tcp];
    let store = Arc::new(fixture.open_with_policy(policy));
    let binding = provision(&store, "tcp", Issuance::Initial);
    let mut context = context(&binding);
    assert!(store.lookup(&context).is_err()); // WSS was not configured.
    context.carrier = Carrier::Tcp;
    assert!(store.lookup(&context).is_ok());
    let mut wrong_scope = context.clone();
    wrong_scope.scope.push(b'x');
    assert!(store.lookup(&wrong_scope).is_err());
    assert_eq!(
        store.validate(&context, Some("principal-B")),
        Err(Error::Denied)
    );

    let (private_key, public_key) = generate_server_key().unwrap();
    let mut server = ServerConfig {
        mode: Mode::Returning,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: context.scope.clone(),
        private_key,
        store: Some(store.clone()),
    };
    let factory = EnrollmentAuthenticatorFactory::new(
        store.clone(),
        Arc::new(Identity("principal-A")),
        ExecutionBudget::new(16),
        2,
    )
    .unwrap();
    factory.validate_server_config(&server).unwrap();
    let other_fixture = Fixture::new();
    server.store = Some(Arc::new(other_fixture.open()));
    assert!(factory.validate_server_config(&server).is_err());
    server.store = Some(store.clone());
    let (handshake, first) = ClientHandshake::start(ClientConfig {
        context: context.clone(),
        server_public_key: public_key,
        authorization_key: Some(store.lookup(&context).unwrap()),
    })
    .unwrap();
    let (mut channel, second) = respond(&server, &first).unwrap();
    let mut client = handshake.finish(&second).unwrap();
    channel
        .decrypt(&client.encrypt(b"fresh confirmation").unwrap())
        .unwrap();
    let identity = channel.verified_identity().unwrap();
    let auth = factory.prepare(&identity).await.unwrap();
    assert_eq!(
        auth.authenticate(b"verified-app-credential")
            .unwrap()
            .subject,
        "principal-A"
    );
    let mismatch = EnrollmentAuthenticatorFactory::new(
        store.clone(),
        Arc::new(Identity("principal-B")),
        ExecutionBudget::new(16),
        2,
    )
    .unwrap();
    assert!(mismatch
        .prepare(&identity)
        .await
        .unwrap()
        .authenticate(b"verified-app-credential")
        .is_err());
    let guard = factory
        .connection_authorization(&identity)
        .unwrap()
        .unwrap();
    guard.check().await.unwrap();
    store.revoke("device-1", b"revoke").unwrap();
    assert!(guard.check().await.is_err());
    assert!(store.lookup(&context).is_err());
}

#[test]
fn reopening_with_changed_binding_policy_cannot_reauthorize_or_rewrite_the_store() {
    let fixture = Fixture::new();
    let store = fixture.open();
    let binding = provision(&store, "initial", Issuance::Initial);
    let original = {
        let db = store.database.lock().unwrap();
        SqliteEnrollmentStore::image(&db.connection, 0)
            .unwrap()
            .unwrap()
    };
    drop(store);
    for bindings in [
        vec![EnrollmentBinding::Tcp],
        vec![EnrollmentBinding::SecureWebSocket, EnrollmentBinding::Tcp],
    ] {
        let mut changed = policy();
        changed.permitted_bindings = bindings;
        assert!(matches!(
            SqliteEnrollmentStore::open(
                &fixture.path,
                &fixture.lock,
                "test-store".into(),
                changed,
                fixture.deployment(),
            ),
            Err(Error::Integrity)
        ));
        assert_eq!(fixture.anchor.current().unwrap(), Some(original.0));
        let store = fixture.open();
        let image = {
            let db = store.database.lock().unwrap();
            SqliteEnrollmentStore::image(&db.connection, 0)
                .unwrap()
                .unwrap()
        };
        assert_eq!(image, original);
        let mut context = context(&binding);
        assert!(store.lookup(&context).is_ok());
        context.carrier = Carrier::Tcp;
        assert!(store.lookup(&context).is_err());
    }
}

#[test]
fn binding_policy_is_checked_against_both_full_image_anchor_and_configured_policy() {
    for missing in [false, true] {
        let fixture = Fixture::new();
        let store = fixture.open();
        let binding = provision(&store, "initial", Issuance::Initial);
        let altered = {
            let mut db = store.database.lock().unwrap();
            let (head, image) = SqliteEnrollmentStore::image(&db.connection, 0)
                .unwrap()
                .unwrap();
            let mut image: serde_json::Value = serde_json::from_slice(&image).unwrap();
            let policy = image["policy"].as_object_mut().unwrap();
            if missing {
                policy.remove("permitted_bindings");
            } else {
                policy.insert("permitted_bindings".into(), serde_json::json!(["Tcp"]));
            }
            let image = serde_json::to_vec(&image).unwrap();
            SqliteEnrollmentStore::write_image(&mut db.connection, 0, head.revision, &image)
                .unwrap();
            SqliteEnrollmentStore::anchor(head.revision, &image)
        };
        // An altered field changes the full-image digest.
        assert_eq!(
            store.validate(&context(&binding), None),
            Err(Error::Integrity)
        );
        // Even an independently anchored image cannot supply missing bindings or
        // replace this deployment's configured policy during a live store read.
        *fixture.anchor.head.lock().unwrap() = Some(altered);
        assert_eq!(
            store.validate(&context(&binding), None),
            Err(Error::Integrity)
        );
        assert!(store.lookup(&context(&binding)).is_err());
    }
}

struct DeniedIdentity;
impl ApplicationIdentity for DeniedIdentity {
    fn authenticate(
        &self,
        _: &syntra_core::secure_channel::VerifiedIdentity,
        _: &[u8],
    ) -> Result<syntra_runtime::Principal, syntra_runtime::AuthError> {
        Err(syntra_runtime::AuthError {
            code: syntra_core::ErrorCode::PermissionDenied,
            message: "synthetic-sensitive-application-reason".into(),
        })
    }
}

#[tokio::test]
async fn permission_denied_identity_keeps_status_but_sanitizes_message() {
    use crate::pump::AuthenticatorFactory;
    use syntra_core::secure_channel::{
        generate_server_key, respond, ClientConfig, ClientHandshake, ServerConfig,
    };
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let (private_key, public_key) = generate_server_key().unwrap();
    let (handshake, first) = ClientHandshake::start(ClientConfig {
        context: context(&binding),
        server_public_key: public_key,
        authorization_key: Some(store.lookup(&context(&binding)).unwrap()),
    })
    .unwrap();
    let (mut server, second) = respond(
        &ServerConfig {
            mode: Mode::Returning,
            carrier: Carrier::SecureWebSocket,
            server_key_id: 1,
            scope: binding.scope.as_bytes().to_vec(),
            private_key,
            store: Some(store.clone()),
        },
        &first,
    )
    .unwrap();
    let mut client = handshake.finish(&second).unwrap();
    server
        .decrypt(&client.encrypt(b"fresh confirmation").unwrap())
        .unwrap();
    let identity = server.verified_identity().unwrap();
    let factory = EnrollmentAuthenticatorFactory::new(
        store,
        Arc::new(DeniedIdentity),
        syntra_runtime::ExecutionBudget::new(16),
        4,
    )
    .unwrap();
    let auth = factory.prepare(&identity).await.unwrap();
    let error = auth.authenticate(b"opaque-credential").unwrap_err();
    assert_eq!(error.code, syntra_core::ErrorCode::PermissionDenied);
    assert_eq!(error.message, syntra_runtime::AuthError::denied().message);
    assert!(!format!("{error:?}").contains("synthetic-sensitive"));
}

#[test]
fn restoring_pre_revocation_database_and_store_outage_fail_closed() {
    let f = Fixture::new();
    let store = f.open();
    let binding = provision(&store, "initial", Issuance::Initial);
    let old = std::fs::read(&f.path).unwrap();
    f.anchor.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        store.validate(&context(&binding), None),
        Err(Error::Unavailable)
    );
    assert!(store.lookup(&context(&binding)).is_err());
    f.anchor.unavailable.store(false, Ordering::SeqCst);
    store.revoke("device-1", b"revoke").unwrap();
    drop(store);
    std::fs::write(&f.path, old).unwrap();
    assert!(matches!(
        SqliteEnrollmentStore::open(
            &f.path,
            &f.lock,
            "test-store".into(),
            policy(),
            f.deployment()
        ),
        Err(Error::Integrity)
    ));
}

#[test]
fn owner_lock_concurrency_and_bounded_audit_cleanup() {
    let f = Fixture::new();
    let store = Arc::new(f.open());
    assert!(SqliteEnrollmentStore::open(
        &f.path,
        &f.lock,
        "test-store".into(),
        policy(),
        f.deployment()
    )
    .is_err());
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            std::thread::spawn(move || {
                store
                    .stage(request("same", Issuance::Initial), b"approved")
                    .unwrap()
            })
        })
        .collect();
    let bindings: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(bindings.iter().all(|b| b == &bindings[0]));
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 1);
    assert!(store.inspect(|s, _| Ok(s.audit.len())).unwrap() <= 4);
    f.time(120);
    assert_eq!(store.cleanup().unwrap(), 1);
    assert_eq!(store.cleanup().unwrap(), 0);
}

struct Pins;
impl PinUpdateAuthority for Pins {
    fn verify(&self, _: &str, _: &PinUpdate, evidence: &[u8]) -> Result<(), Error> {
        if evidence == b"independent-config" {
            Ok(())
        } else {
            Err(Error::Denied)
        }
    }
}

#[test]
fn pins_first_update_accepts_already_active_pin() {
    let f = Fixture::new();
    let store = f.open();
    store
        .update_pins(
            PinUpdate {
                generation: 1,
                pins: vec![Pin {
                    key_id: 1,
                    public_key: [1; 32],
                    activates_at: 90,
                    retires_at: 120,
                }],
            },
            b"independent-config",
            &Pins,
        )
        .unwrap();
    assert_eq!(store.server_pin(1).unwrap(), [1; 32]);
}

#[test]
fn pins_expired_adopted_pin_allows_already_active_replacement() {
    for now in [120, 121] {
        let f = Fixture::new();
        let store = f.open();
        let first = Pin {
            key_id: 1,
            public_key: [1; 32],
            activates_at: 100,
            retires_at: 120,
        };
        store
            .update_pins(
                PinUpdate {
                    generation: 1,
                    pins: vec![first.clone()],
                },
                b"independent-config",
                &Pins,
            )
            .unwrap();
        f.time(now);
        assert_eq!(store.server_pin(1), Err(Error::Denied));
        store
            .update_pins(
                PinUpdate {
                    generation: 2,
                    pins: vec![
                        first,
                        Pin {
                            key_id: 2,
                            public_key: [2; 32],
                            activates_at: 110,
                            retires_at: 130,
                        },
                    ],
                },
                b"independent-config",
                &Pins,
            )
            .unwrap();
        assert_eq!(store.server_pin(1), Err(Error::Denied));
        assert_eq!(store.server_pin(2).unwrap(), [2; 32]);
    }
}

#[test]
fn pins_active_adopted_pin_rejects_backdated_new_pin() {
    let f = Fixture::new();
    let store = f.open();
    let first = Pin {
        key_id: 1,
        public_key: [1; 32],
        activates_at: 100,
        retires_at: 120,
    };
    store
        .update_pins(
            PinUpdate {
                generation: 1,
                pins: vec![first.clone()],
            },
            b"independent-config",
            &Pins,
        )
        .unwrap();
    f.time(110);
    assert_eq!(
        store.update_pins(
            PinUpdate {
                generation: 2,
                pins: vec![
                    first,
                    Pin {
                        key_id: 2,
                        public_key: [2; 32],
                        activates_at: 109,
                        retires_at: 130,
                    },
                ],
            },
            b"independent-config",
            &Pins,
        ),
        Err(Error::Denied)
    );
    assert_eq!(store.server_pin(1).unwrap(), [1; 32]);
    assert_eq!(store.server_pin(2), Err(Error::Denied));
}

#[test]
fn pins_require_independent_distribution_and_cannot_replay_or_revive() {
    let f = Fixture::new();
    let store = f.open();
    let first = Pin {
        key_id: 1,
        public_key: [1; 32],
        activates_at: 100,
        retires_at: 120,
    };
    let update = PinUpdate {
        generation: 1,
        pins: vec![first.clone()],
    };
    assert_eq!(
        store.update_pins(update.clone(), b"peer-taught", &Pins),
        Err(Error::Denied)
    );
    store
        .update_pins(update.clone(), b"independent-config", &Pins)
        .unwrap();
    assert_eq!(store.server_pin(1).unwrap(), [1; 32]);
    assert_eq!(
        store.update_pins(update, b"independent-config", &Pins),
        Err(Error::Denied)
    );
    let second = Pin {
        key_id: 2,
        public_key: [2; 32],
        activates_at: 110,
        retires_at: 130,
    };
    store
        .update_pins(
            PinUpdate {
                generation: 2,
                pins: vec![first.clone(), second.clone()],
            },
            b"independent-config",
            &Pins,
        )
        .unwrap();
    assert_eq!(store.server_pin(2), Err(Error::Denied));
    f.time(120);
    assert_eq!(store.server_pin(1), Err(Error::Denied));
    assert_eq!(store.server_pin(2).unwrap(), [2; 32]);
    let mut revived = first;
    revived.retires_at = 140;
    assert_eq!(
        store.update_pins(
            PinUpdate {
                generation: 3,
                pins: vec![revived, second]
            },
            b"independent-config",
            &Pins
        ),
        Err(Error::Denied)
    );
}

#[test]
fn policy_time_rewind_and_debug_do_not_grant_or_expose_material() {
    let mut invalid = policy();
    invalid.freshness_seconds = 300;
    assert_eq!(invalid.validate(), Err(Error::Configuration));
    invalid = policy();
    invalid.overlap_seconds = 0;
    assert_eq!(invalid.validate(), Err(Error::Configuration));
    invalid = policy();
    invalid.freshness_seconds = 5;
    invalid.read_seconds = 3;
    assert_eq!(invalid.validate(), Err(Error::Configuration));
    let f = Fixture::new();
    let store = f.open();
    let binding = provision(&store, "initial", Issuance::Initial);
    let marker = *store.lookup(&context(&binding)).unwrap().expose();
    let db = std::fs::read(&f.path).unwrap();
    assert!(!db.windows(32).any(|w| w == marker));
    assert!(!format!("{binding:?}").contains("principal-A"));
    f.time(99);
    assert_eq!(
        store.validate(&context(&binding), None),
        Err(Error::Integrity)
    );
}

struct Identity {
    principal: &'static str,
    revoke_on_auth: Option<Arc<SqliteEnrollmentStore>>,
}
impl ApplicationIdentity for Identity {
    fn authenticate(
        &self,
        _: &syntra_core::secure_channel::VerifiedIdentity,
        credential: &[u8],
    ) -> Result<syntra_runtime::Principal, syntra_runtime::AuthError> {
        if credential != b"independently-verified" {
            return Err(syntra_runtime::AuthError::unauthenticated());
        }
        if let Some(store) = &self.revoke_on_auth {
            store.revoke("device-1", b"revoke").unwrap();
        }
        Ok(syntra_runtime::Principal::new(self.principal))
    }
}

// Actual host-terminated TLS 1.3/WSS, using local synthetic certificates and the
// real SQLite admission store/factory. This is not independent interoperability
// and does not label any registered CONF case PASS.
#[cfg(feature = "websocket")]
async fn wss_pair(
    store: Arc<SqliteEnrollmentStore>,
    binding: &Binding,
    key: Secret32,
    application: Arc<dyn ApplicationIdentity>,
    effects: Arc<AtomicU64>,
) -> (
    Result<crate::ClientHandle, crate::Error>,
    Result<crate::HostHandle, crate::Error>,
) {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use syntra_core::secure_channel::{generate_server_key, ClientConfig, ServerConfig};
    use syntra_runtime::{ConnectionConfig, ExecutionBudget, FnHandler, HandlerOutcome};
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let der = cert.cert.der().clone();
    let settings = crate::websocket::TlsServerSettings::new(
        vec![der.clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "wss://{}{}",
        listener.local_addr().unwrap(),
        crate::websocket::ENDPOINT_PATH
    );
    let (private_key, public_key) = generate_server_key().unwrap();
    let server = ServerConfig {
        mode: Mode::Returning,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: binding.scope.as_bytes().to_vec(),
        private_key,
        store: Some(store.clone()),
    };
    let factory = Arc::new(
        EnrollmentAuthenticatorFactory::new(store, application, ExecutionBudget::new(32), 8)
            .unwrap(),
    );
    let handler = Arc::new(FnHandler(move |_, payload, _| {
        effects.fetch_add(1, Ordering::SeqCst);
        async move { HandlerOutcome::Payload(payload) }
    }));
    let limits = crate::Limits {
        attempt_timeout: Duration::from_secs(3),
        channel_timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let host_limits = limits.clone();
    let host = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        crate::websocket::accept_tls_stream(
            stream,
            &settings,
            &server,
            factory,
            handler,
            ConnectionConfig::default(),
            host_limits,
        )
        .await
    });
    let client = crate::websocket::connect_with_roots(
        &url,
        roots,
        ClientConfig {
            context: context(binding),
            server_public_key: public_key,
            authorization_key: Some(key),
        },
        b"independently-verified".to_vec(),
        ConnectionConfig::default(),
        limits,
    )
    .await;
    (client, host.await.unwrap())
}

#[tokio::test]
#[cfg(feature = "websocket")]
async fn wss_same_principal_and_current_enrollment_are_required_before_ready() {
    for revoke_on_auth in [false, true] {
        let f = Fixture::new();
        let store = Arc::new(f.open());
        let binding = provision(&store, "initial", Issuance::Initial);
        let key = store.lookup(&context(&binding)).unwrap();
        let effects = Arc::new(AtomicU64::new(0));
        let (client, host) = wss_pair(
            store.clone(),
            &binding,
            key,
            Arc::new(Identity {
                principal: if revoke_on_auth {
                    "principal-A"
                } else {
                    "principal-B"
                },
                revoke_on_auth: revoke_on_auth.then(|| store.clone()),
            }),
            effects.clone(),
        )
        .await;
        assert!(client.is_err());
        assert!(host.is_err());
        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
#[cfg(feature = "websocket")]
async fn wss_revocation_cuts_off_protected_dispatch_delivery_and_reconnect() {
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let key = store.lookup(&context(&binding)).unwrap();
    let reconnect_key = Secret32::new(*key.expose());
    let effects = Arc::new(AtomicU64::new(0));
    let (client, host) = wss_pair(
        store.clone(),
        &binding,
        key,
        Arc::new(Identity {
            principal: "principal-A",
            revoke_on_auth: None,
        }),
        effects.clone(),
    )
    .await;
    let client = client.unwrap();
    let host = host.unwrap();
    assert_eq!(
        client
            .conn
            .call("/test.Service/Echo", vec![1], 1000)
            .await
            .unwrap(),
        vec![1]
    );
    let committed = tokio::time::Instant::now();
    store.revoke("device-1", b"revoke").unwrap();
    // Cached gates may use the last successful read only within the declared
    // freshness window. The watchdog must withdraw it even on an idle carrier.
    tokio::time::timeout(Duration::from_secs(10), async {
        while !host.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(committed.elapsed() < Duration::from_secs(10));
    let _ = host.host.notify(vec![2]).await;
    assert!(client
        .conn
        .call("/test.Service/Echo", vec![3], 1000)
        .await
        .is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_ne!(
        tokio::time::timeout(Duration::from_secs(1), client.conn.next_notification()).await,
        Ok(Some(vec![2]))
    );
    client.close().await;
    host.close().await;
    let (client, host) = wss_pair(
        store,
        &binding,
        reconnect_key,
        Arc::new(Identity {
            principal: "principal-A",
            revoke_on_auth: None,
        }),
        effects,
    )
    .await;
    assert!(client.is_err());
    assert!(host.is_err());
}

#[tokio::test]
#[cfg(feature = "websocket")]
async fn wss_idle_channel_closes_within_declared_freshness_after_store_outage() {
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let key = store.lookup(&context(&binding)).unwrap();
    let (client, host) = wss_pair(
        store,
        &binding,
        key,
        Arc::new(Identity {
            principal: "principal-A",
            revoke_on_auth: None,
        }),
        Arc::new(AtomicU64::new(0)),
    )
    .await;
    let client = client.unwrap();
    let host = host.unwrap();
    f.anchor.unavailable.store(true, Ordering::SeqCst);
    let failed = tokio::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !host.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(failed.elapsed() < Duration::from_secs(10));
    client.close().await;
    host.close().await;
}

#[test]
fn entropy_failure_degenerate_keys_handle_and_key_collisions_do_not_stage() {
    let f = Fixture::new();
    let store = f.open();
    assert_eq!(
        store.stage_with(request("entropy", Issuance::Initial), b"approved", |_| Err(
            syntra_core::secure_channel::Error::Entropy
        )),
        Err(Error::Unavailable)
    );
    assert_eq!(
        store.stage_with(request("zero", Issuance::Initial), b"approved", |epoch| Ok(
            Enrollment {
                key: Secret32::new([0; 32]),
                handle: [1; 8],
                epoch
            }
        )),
        Err(Error::Denied)
    );
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 0);
    let original = provision(&store, "initial", Issuance::Initial);
    let original_key = *store.lookup(&context(&original)).unwrap().expose();
    assert_eq!(
        store.stage_with(
            request("handle-collision", Issuance::Rotation),
            b"approved",
            |epoch| Ok(Enrollment {
                key: Secret32::generate().unwrap(),
                handle: original.handle,
                epoch
            })
        ),
        Err(Error::Denied)
    );
    assert_eq!(
        store.stage_with(
            request("key-collision", Issuance::Rotation),
            b"approved",
            |epoch| Ok(Enrollment {
                key: Secret32::new(original_key),
                handle: [23; 8],
                epoch
            })
        ),
        Err(Error::Denied)
    );
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 1);
    assert!(store.lookup(&context(&original)).is_ok());
}

#[test]
fn epoch_exhaustion_and_fast_rotations_never_rewind_or_union_old_generations() {
    let f = Fixture::new();
    let store = f.open();
    let first = provision(&store, "initial", Issuance::Initial);
    let second = provision(&store, "second", Issuance::Rotation);
    let third = provision(&store, "third", Issuance::Rotation);
    assert!(store.lookup(&context(&first)).is_err());
    assert!(store.lookup(&context(&second)).is_ok());
    assert!(store.lookup(&context(&third)).is_ok());
    store
        .change(|s, _| {
            s.records.last_mut().unwrap().binding.epoch = u64::MAX;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        store.stage(request("overflow", Issuance::Rotation), b"approved"),
        Err(Error::Exhausted)
    );
    assert_eq!(store.inspect(|s, _| Ok(s.records.len())).unwrap(), 3);
}

#[test]
fn timed_out_initial_attempt_releases_material_for_fresh_authorized_attempt() {
    let f = Fixture::new();
    let store = f.open();
    let timed_out = store
        .stage(request("abandoned", Issuance::Initial), b"approved")
        .unwrap();
    f.time(120);
    store.cleanup().unwrap();
    let fresh = provision(&store, "new-attempt", Issuance::Initial);
    assert_ne!(fresh.handle, timed_out.handle);
    assert!(fresh.epoch > timed_out.epoch);
    assert_eq!(
        store.stage(request("abandoned", Issuance::Initial), b"approved"),
        Err(Error::Denied)
    );
    assert!(store.lookup(&context(&timed_out)).is_err());
    assert_eq!(
        store.stage(
            request("cannot-bypass-recovery", Issuance::Initial),
            b"approved"
        ),
        Err(Error::Denied)
    );
}

#[tokio::test]
async fn timed_out_store_read_retains_worker_capacity_until_actual_completion() {
    use crate::pump::AuthenticatorFactory;
    use syntra_core::secure_channel::{
        generate_server_key, respond, ClientConfig, ClientHandshake, ServerConfig,
    };
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let (private_key, public_key) = generate_server_key().unwrap();
    let (handshake, first) = ClientHandshake::start(ClientConfig {
        context: context(&binding),
        server_public_key: public_key,
        authorization_key: Some(store.lookup(&context(&binding)).unwrap()),
    })
    .unwrap();
    let server = ServerConfig {
        mode: Mode::Returning,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: binding.scope.as_bytes().to_vec(),
        private_key,
        store: Some(store.clone()),
    };
    let (mut server, second) = respond(&server, &first).unwrap();
    let mut client = handshake.finish(&second).unwrap();
    server
        .decrypt(&client.encrypt(b"fresh confirmation").unwrap())
        .unwrap();
    let identity = server.verified_identity().unwrap();
    let factory = EnrollmentAuthenticatorFactory::new(
        store,
        Arc::new(Identity {
            principal: "principal-A",
            revoke_on_auth: None,
        }),
        syntra_runtime::ExecutionBudget::new(16),
        1,
    )
    .unwrap();
    let guard = factory
        .connection_authorization(&identity)
        .unwrap()
        .unwrap();
    f.anchor.delay_ms.store(1500, Ordering::SeqCst);
    let start = tokio::time::Instant::now();
    assert!(guard.check().await.is_err());
    assert!(start.elapsed() < Duration::from_millis(1400));
    assert_eq!(factory.in_flight_checks(), 1);
    // A second check waits for admission within its own single read budget,
    // rather than permanently failing on the first worker's retained slot.
    f.anchor.delay_ms.store(0, Ordering::SeqCst);
    assert!(guard.check().await.is_ok());
    tokio::time::timeout(Duration::from_secs(2), async {
        while factory.in_flight_checks() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(guard.check().await.is_ok());
}

fn authorization_guard(
    store: Arc<SqliteEnrollmentStore>,
    binding: &Binding,
    clock: syntra_runtime::elapsed::ElapsedClock,
) -> (
    EnrollmentAuthenticatorFactory,
    Arc<dyn crate::pump::ConnectionAuthorization>,
) {
    use crate::pump::AuthenticatorFactory;
    use syntra_core::secure_channel::{
        generate_server_key, respond, ClientConfig, ClientHandshake,
    };
    let (private_key, server_public_key) = generate_server_key().unwrap();
    let (handshake, first) = ClientHandshake::start(ClientConfig {
        context: context(binding),
        server_public_key,
        authorization_key: Some(store.lookup(&context(binding)).unwrap()),
    })
    .unwrap();
    let (mut channel, second) = respond(
        &syntra_core::secure_channel::ServerConfig {
            mode: Mode::Returning,
            carrier: Carrier::SecureWebSocket,
            server_key_id: 1,
            scope: binding.scope.as_bytes().to_vec(),
            private_key,
            store: Some(store.clone()),
        },
        &first,
    )
    .unwrap();
    let mut client = handshake.finish(&second).unwrap();
    channel
        .decrypt(&client.encrypt(b"confirmation").unwrap())
        .unwrap();
    let factory = EnrollmentAuthenticatorFactory::with_clock(
        store,
        Arc::new(Identity {
            principal: "principal-A",
            revoke_on_auth: None,
        }),
        syntra_runtime::ExecutionBudget::new(16),
        1,
        clock,
    )
    .unwrap();
    let guard = factory
        .connection_authorization(&channel.verified_identity().unwrap())
        .unwrap()
        .unwrap();
    (factory, guard)
}

#[tokio::test(start_paused = true)]
async fn authorization_retries_pool_admission_not_revocation_or_store_failure() {
    use crate::pump::AuthenticatorFactory;
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let clock = syntra_runtime::elapsed::ElapsedClock::lifecycle_driven();
    let (factory, guard) = authorization_guard(store.clone(), &binding, clock);
    let pool = factory.policy_jobs().unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let busy = pool.spawn(move || blocked.recv().unwrap()).unwrap();
    let mut check = Box::pin(guard.check());
    assert!(futures_util::poll!(&mut check).is_pending());
    assert_eq!(
        pool.pending(),
        1,
        "admission wait must not queue blocking work"
    );
    release.send(()).unwrap();
    busy.await.unwrap();
    while pool.pending() != 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(10)).await;
    check.await.unwrap();

    for revoked in [false, true] {
        if revoked {
            f.anchor.unavailable.store(false, Ordering::SeqCst);
            store.revoke("device-1", b"revoke").unwrap();
        } else {
            f.anchor.unavailable.store(true, Ordering::SeqCst);
        }
        while pool.pending() != 0 {
            tokio::task::yield_now().await;
        }
        let start = tokio::time::Instant::now();
        assert!(guard.check().await.is_err());
        assert_eq!(
            start.elapsed(),
            Duration::ZERO,
            "an admitted failure is not retried"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn authorization_pool_admission_timeout_and_shutdown_fail_closed_without_new_jobs() {
    use crate::pump::AuthenticatorFactory;
    for stopped in [false, true] {
        let f = Fixture::new();
        let store = Arc::new(f.open());
        let binding = provision(&store, "initial", Issuance::Initial);
        let clock = syntra_runtime::elapsed::ElapsedClock::lifecycle_driven();
        let (factory, guard) = authorization_guard(store, &binding, clock.clone());
        let pool = factory.policy_jobs().unwrap();
        let (release, blocked) = std::sync::mpsc::channel();
        let busy = if stopped {
            pool.shutdown(&clock, Duration::ZERO).await.unwrap();
            None
        } else {
            Some(pool.spawn(move || blocked.recv().unwrap()).unwrap())
        };
        let mut check = Box::pin(guard.check());
        assert!(futures_util::poll!(&mut check).is_pending());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(check.await.is_err());
        assert_eq!(pool.pending(), usize::from(!stopped));
        if let Some(busy) = busy {
            release.send(()).unwrap();
            busy.await.unwrap();
        }
        while pool.pending() != 0 {
            tokio::task::yield_now().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_authorization_admission_wait_never_starts_a_late_read() {
    use crate::pump::AuthenticatorFactory;
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let clock = syntra_runtime::elapsed::ElapsedClock::lifecycle_driven();
    let (factory, guard) = authorization_guard(store, &binding, clock);
    let pool = factory.policy_jobs().unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let busy = pool.spawn(move || blocked.recv().unwrap()).unwrap();
    let mut check = Box::pin(guard.check());
    assert!(futures_util::poll!(&mut check).is_pending());
    drop(check);
    release.send(()).unwrap();
    busy.await.unwrap();
    while pool.pending() != 0 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(pool.pending(), 0);
}

#[tokio::test(start_paused = true)]
async fn authorization_admission_and_validation_share_one_read_deadline() {
    use crate::pump::AuthenticatorFactory;
    let f = Fixture::new();
    let store = Arc::new(f.open());
    let binding = provision(&store, "initial", Issuance::Initial);
    let clock = syntra_runtime::elapsed::ElapsedClock::lifecycle_driven();
    let (factory, guard) = authorization_guard(store.clone(), &binding, clock);
    let pool = factory.policy_jobs().unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let busy = pool.spawn(move || blocked.recv().unwrap()).unwrap();
    let mut check = Box::pin(guard.check());
    assert!(futures_util::poll!(&mut check).is_pending());
    tokio::time::advance(Duration::from_millis(900)).await;
    release.send(()).unwrap();
    busy.await.unwrap();
    while pool.pending() != 0 {
        tokio::task::yield_now().await;
    }
    // Test-only lock barrier holds the newly admitted synchronous read open.
    // Poll manually so no executor task carries this std MutexGuard over await.
    {
        let _db = store.database.lock().unwrap();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(check.as_mut(), &mut cx).is_pending());
        assert_eq!(pool.pending(), 1);
    }
    // Even a now-ready validation cannot win at the original inclusive deadline.
    tokio::time::advance(Duration::from_millis(100)).await;
    assert!(check.await.is_err());
    while pool.pending() != 0 {
        tokio::task::yield_now().await;
    }
}

#[test]
fn factory_rejects_splicing_a_different_noise_admission_store() {
    use crate::pump::AuthenticatorFactory;
    use syntra_core::secure_channel::{generate_server_key, ServerConfig};
    let f = Fixture::new();
    let other = Fixture::new();
    let store = Arc::new(f.open());
    let factory = EnrollmentAuthenticatorFactory::new(
        store.clone(),
        Arc::new(Identity {
            principal: "principal-A",
            revoke_on_auth: None,
        }),
        syntra_runtime::ExecutionBudget::new(16),
        4,
    )
    .unwrap();
    let (private_key, _) = generate_server_key().unwrap();
    let mut security = ServerConfig {
        mode: Mode::Returning,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 1,
        scope: b"scope".to_vec(),
        private_key,
        store: None,
    };
    assert!(factory.validate_server_config(&security).is_err());
    security.store = Some(Arc::new(other.open()));
    assert!(factory.validate_server_config(&security).is_err());
    security.store = Some(store);
    assert!(factory.validate_server_config(&security).is_ok());
}
