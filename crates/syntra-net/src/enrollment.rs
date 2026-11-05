//! Optional native enrollment backend with explicit deployment trust boundaries.
//!
//! All methods are synchronous control-plane operations: run them on a bounded
//! blocking executor, never while holding an application lock. SQLite uses FULL
//! synchronous DELETE journaling and a process-lifetime exclusive owner lock. A
//! prepared image is durable before the external rollback anchor advances; a
//! second SQLite transaction promotes it. Restart reconciles a lost CAS/commit
//! response. A restored image without the anchored intent fails closed, never
//! resets the external anchor. The bounded image contains *only protected* AKs.
//!
//! The deployment MUST provision the database directory/owner lock with private
//! access controls, prevent path replacement/symlinks, and protect journal, temp,
//! backup and restore paths. It MUST supply independent enrollment/recovery,
//! durable-device-ack verification, authenticated time, key wrapping/erasure and
//! an external linearizable rollback authority. No plaintext protector, local
//! rollback authority, enrollment RPC or deployment credentials are supplied.
//! Erasure is retried by bounded cleanup; file unlink/SQLite secure_delete does
//! not erase backups or storage media. Key protection must make old ciphertext
//! irrecoverable across the deployment's complete backup boundary.

use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syntra_core::secure_channel::{Carrier, Context, Enrollment, KeyStore, Mode, Secret32};

mod authorization;
mod pins;
pub use authorization::{ApplicationIdentity, EnrollmentAuthenticatorFactory};
pub use pins::{Pin, PinUpdate, PinUpdateAuthority};

/// Deliberately generic: dependency errors and credentials never enter diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("authorization not established")]
    Denied,
    #[error("authorization dependency unavailable")]
    Unavailable,
    #[error("authorization state cannot be verified")]
    Integrity,
    #[error("authorization transaction outcome unknown; reconcile before retry")]
    CommitUnknown,
    #[error("authorization capacity or identifier exhausted")]
    Exhausted,
    #[error("authorization configuration rejected")]
    Configuration,
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}

/// Required finite deployment policy, with no implicit production defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Explicit bindings allowed to use this store's returning credentials.
    /// A deployment must opt into TCP; a credential never becomes portable merely
    /// because a caller changes its channel context. Scope and principal still
    /// have to match the anchored enrollment record.
    /// The full policy is part of the anchored store image. Reopening with a
    /// different binding set fails closed; missing persisted bindings are not
    /// assigned a default or migrated implicitly.
    pub permitted_bindings: Vec<EnrollmentBinding>,
    pub activation_seconds: u32,
    pub overlap_seconds: u32,
    pub max_validity_seconds: u32,
    pub freshness_seconds: u32,
    pub read_seconds: u32,
    pub close_seconds: u32,
    /// Includes tombstones: exhaustion requires an independently reviewed migration,
    /// not deletion of anti-replay history or reuse of an old logical enrollment.
    pub max_records: u32,
    pub audit_entries: u32,
    pub cleanup_batch: u32,
    pub max_pins: u32,
}

impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.permitted_bindings.is_empty()
            || self.permitted_bindings.len() > 2
            || self.permitted_bindings.iter().enumerate().any(|(i, binding)| self.permitted_bindings[..i].contains(binding))
            || self.activation_seconds == 0
            || self.overlap_seconds == 0
            || self.max_validity_seconds == 0
            || self.freshness_seconds == 0
            || self.read_seconds == 0
            || self.close_seconds == 0
            || u64::from(self.freshness_seconds)
                <= u64::from(self.read_seconds) + u64::from(self.close_seconds)
            // A completed read must fit before the next poll's start; otherwise
            // repeated slow reads could silently consume two read budgets and
            // exceed the declared last-validity freshness window.
            || u64::from(self.freshness_seconds)
                < 2 * u64::from(self.read_seconds) + u64::from(self.close_seconds)
            || u64::from(self.freshness_seconds)
                + u64::from(self.read_seconds)
                + u64::from(self.close_seconds)
                > 300
            || !(1..=4096).contains(&self.max_records)
            || self.audit_entries > 4096
            || !(1..=self.max_records).contains(&self.cleanup_batch)
            || !(1..=32).contains(&self.max_pins)
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }

    pub fn read_timeout(&self) -> Duration {
        Duration::from_secs(u64::from(self.read_seconds))
    }

    fn permits(&self, carrier: Carrier) -> bool {
        self.permitted_bindings.iter().any(|binding| {
            matches!(
                (binding, carrier),
                (EnrollmentBinding::Tcp, Carrier::Tcp)
                    | (EnrollmentBinding::SecureWebSocket, Carrier::SecureWebSocket)
            )
        })
    }
}

/// Returning enrollment supports only explicitly configured authenticated bindings.
/// WS is intentionally not an enrollment binding, even on loopback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentBinding {
    Tcp,
    SecureWebSocket,
}

/// Seconds in a deployment-authenticated, suspend-inclusive, non-rewinding time
/// domain. Reboot/continuity uncertainty MUST return an error, not a cached time.
pub trait TrustedClock: Send + Sync {
    fn now(&self) -> Result<u64, Error>;
}

/// An anchor belongs to exactly one provisioned store namespace. It is NOT a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub revision: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settlement {
    /// The attempted transition is durably committed, never merely queued.
    Committed,
    /// No outstanding worker can now or later apply this exact transition.
    Aborted,
}

/// Must live outside SQLite's rollback/backup domain. Reads are linearizable,
/// independently authenticated and bounded. CAS is durable, immutable and never
/// rewinds; an uncertain CAS MUST return CommitUnknown. No implementation here
/// pretends that a second local file is rollback-resistant. The deployment
/// explicitly provisions an empty namespace (`None`) once; a missing previously
/// provisioned namespace must be an error, not None.
pub trait RollbackAuthority: Send + Sync {
    fn current(&self) -> Result<Option<Anchor>, Error>;
    fn compare_and_swap(&self, expected: Option<Anchor>, next: Anchor) -> Result<(), Error>;
    /// Authoritatively settle AND fence this exact CAS, including a worker whose
    /// response was lost or which has not yet applied remotely. Aborted is a
    /// durable promise that no delayed CAS(expected,next) can ever commit later;
    /// current()==expected alone cannot establish that promise. Committed means
    /// the operation actually committed. For an unknown/restored intent, this
    /// operation MUST NOT submit/replay a CAS: prove its fate or return an error.
    /// Unavailable/uncertain settlement leaves the SQLite intent intact and the
    /// store fail-closed. There is deliberately no permissive default method.
    fn settle(&self, expected: Option<Anchor>, next: Anchor) -> Result<Settlement, Error>;
}

/// Immutable authenticated key-wrapping context. Protector implementations must
/// authenticate every field (including store_id) as associated data. Ciphertexts
/// are bounded, non-plaintext envelopes; per-tuple erasure must survive restoring
/// old SQLite files and backups. Methods must be bounded and never log inputs.
pub trait KeyProtection: Send + Sync {
    fn protect(&self, binding: &Binding, key: &Secret32) -> Result<Vec<u8>, Error>;
    fn unprotect(&self, binding: &Binding, envelope: &[u8]) -> Result<Secret32, Error>;
    /// Idempotent cryptographic disposal, including envelopes in older backups.
    fn destroy(&self, binding: &Binding) -> Result<(), Error>;
    /// Remove at most `limit` tentative wrapping objects absent from the current
    /// anchored image. Required for crashes/failures between protect and stage
    /// commit. The namespace is deployment-provisioned; this method must never
    /// affect another store. Called under the exclusive lifecycle owner lock.
    fn reconcile_orphans(
        &self,
        store_id: &str,
        known: &[Binding],
        limit: usize,
    ) -> Result<usize, Error>;
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub store_id: String,
    pub logical_id: String,
    pub principal: String,
    pub device: String,
    /// Exact Syntra endpoint/audience/service scope bytes, never normalized.
    pub scope: String,
    pub handle: [u8; 8],
    pub epoch: u64,
}

// Stable handles/principals must not accidentally become log or metric labels.
impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Binding([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Issuance {
    Initial,
    Rotation,
    /// Always independently authenticated, and revokes all older tuples at stage.
    Recovery,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub attempt: String,
    pub logical_id: String,
    pub principal: String,
    pub device: String,
    pub scope: String,
    pub expires_at: u64,
    pub issuance: Issuance,
}

/// Deployment must independently authenticate the enroller and approve the exact
/// request. Evidence is opaque, bounded, never persisted or echoed. In Recovery,
/// compromised AK/device state MUST NOT be evidence; in Rotation, validate the
/// current tuple as well as the designated enrollment authority. No boolean
/// "authenticated" supplied by a remote caller is accepted by the reference.
/// The deployment must reject anonymous enrollment and rate-limit issuance and
/// collision retries here; the store's finite capacity is not an issuance rate.
pub trait EnrollmentAuthority: Send + Sync {
    fn approve(&self, request: &Request, evidence: &[u8]) -> Result<(), Error>;
    fn approve_revocation(&self, logical_id: &str, evidence: &[u8]) -> Result<(), Error>;
    /// Verify end-to-end recipient binding AND a receipt produced only after the
    /// designated device secure storage durably installed this exact tuple.
    fn verify_durable_ack(&self, binding: &Binding, receipt: &[u8]) -> Result<(), Error>;
}

/// The only delivery surface. Implementations must protect AK end-to-end to the
/// independently authenticated intended device (never merely an unverified
/// transport). Returning success attests encrypted delivery, NOT installation.
pub trait EncryptedDelivery: Send + Sync {
    fn deliver(&self, binding: &Binding, key: &Secret32) -> Result<(), Error>;
}

/// Explicit deployment trust boundaries; there are no fallback implementations.
pub struct Deployment {
    pub protector: Arc<dyn KeyProtection>,
    pub rollback: Arc<dyn RollbackAuthority>,
    pub authority: Arc<dyn EnrollmentAuthority>,
    pub clock: Arc<dyn TrustedClock>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Status {
    Staged,
    Delivered,
    Active,
    Terminal,
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    request: Request,
    binding: Binding,
    envelope: Vec<u8>,
    // Domain-separated one-way duplicate detection, never used as a PSK.
    key_digest: [u8; 32],
    status: Status,
    activated: bool,
    activation_deadline: u64,
    cutoff: Option<u64>,
    predecessor: Option<u64>,
    destroyed: bool,
}

impl Record {
    fn valid(&self, now: u64) -> bool {
        self.status == Status::Active
            && now < self.request.expires_at
            && self.cutoff.is_none_or(|cutoff| now < cutoff)
    }

    fn timed_out(&self, now: u64) -> bool {
        self.status == Status::Terminal
            || now >= self.request.expires_at
            || self.cutoff.is_some_and(|cutoff| now >= cutoff)
            || (matches!(self.status, Status::Staged | Status::Delivered)
                && now >= self.activation_deadline)
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct State {
    version: u32,
    /// Public, fresh per-transition nonce. Prevents a later legitimate write of
    /// identical state from reusing a definitively aborted CAS identity.
    operation_nonce: [u8; 32],
    store_id: String,
    policy: Policy,
    last_time: u64,
    records: Vec<Record>,
    /// Bounded, secret-free event codes only. No attempt, handle or principal.
    audit: Vec<u8>,
    pins: pins::PinState,
}

impl State {
    fn audit(&mut self, event: u8) {
        if self.policy.audit_entries == 0 {
            return;
        }
        if self.audit.len() >= self.policy.audit_entries as usize {
            self.audit.remove(0);
        }
        self.audit.push(event);
    }
}

struct Database {
    connection: Connection,
    // Held until the SQLite connection is dropped. Exactly one process owner;
    // DB transactions alone cannot fence external CAS + two SQLite commits.
    _owner: File,
}

pub struct SqliteEnrollmentStore {
    // std Mutex is deliberate: all operations are synchronous, no guard crosses
    // await. Async adapters use a bounded spawn_blocking lane, not tokio Mutex
    // around synchronous SQLite/KMS/authority I/O.
    database: Mutex<Database>,
    store_id: String,
    policy: Policy,
    protector: Arc<dyn KeyProtection>,
    rollback: Arc<dyn RollbackAuthority>,
    authority: Arc<dyn EnrollmentAuthority>,
    clock: Arc<dyn TrustedClock>,
    time_highwater: AtomicU64,
}

const MAX_IMAGE: usize = 16 * 1024 * 1024;
const MAX_ENVELOPE: usize = 2048;
const MAX_EVIDENCE: usize = 16 * 1024;

fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

impl SqliteEnrollmentStore {
    /// Open/create a deployment-protected regular database path. `owner_path`
    /// must be the SAME protected lock path for every process opening this DB.
    /// This call does not implicitly provision the external namespace.
    pub fn open(
        path: &Path,
        owner_path: &Path,
        store_id: String,
        policy: Policy,
        deployment: Deployment,
    ) -> Result<Self, Error> {
        policy.validate()?;
        if !text(&store_id, 255) || path == owner_path {
            return Err(Error::Configuration);
        }
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(owner_path)
            .map_err(|_| Error::Unavailable)?;
        owner.try_lock_exclusive().map_err(|_| Error::Unavailable)?;
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::ZERO)?;
        connection.execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             PRAGMA temp_store=MEMORY;
             PRAGMA secure_delete=ON;
             PRAGMA trusted_schema=OFF;
             CREATE TABLE IF NOT EXISTS lifecycle (
                 slot INTEGER PRIMARY KEY CHECK(slot IN (0,1)),
                 revision BLOB NOT NULL CHECK(length(revision)=8),
                 image BLOB NOT NULL CHECK(length(image)<=16777216)
             );",
        )?;
        let store = Self {
            database: Mutex::new(Database {
                connection,
                _owner: owner,
            }),
            store_id,
            policy,
            protector: deployment.protector,
            rollback: deployment.rollback,
            authority: deployment.authority,
            clock: deployment.clock,
            time_highwater: AtomicU64::new(0),
        };
        // Verify immediately; no API accepts a partially initialized store.
        store.inspect(|_, _| Ok(()))?;
        Ok(store)
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    fn now(&self, floor: u64) -> Result<u64, Error> {
        let now = self.clock.now()?;
        if now < floor || now < self.time_highwater.fetch_max(now, Ordering::SeqCst) {
            return Err(Error::Integrity);
        }
        Ok(now)
    }

    fn anchor(revision: u64, image: &[u8]) -> Anchor {
        let mut hash = Sha256::new();
        hash.update(b"syntra/rfc0010/sqlite-image/v1\0");
        hash.update(revision.to_be_bytes());
        hash.update(image);
        Anchor {
            revision,
            digest: hash.finalize().into(),
        }
    }

    fn image(connection: &Connection, slot: u8) -> Result<Option<(Anchor, Vec<u8>)>, Error> {
        let row: Option<(Vec<u8>, usize)> = connection
            .query_row(
                "SELECT revision,length(image) FROM lifecycle WHERE slot=?",
                [slot],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((revision, length)) = row else {
            return Ok(None);
        };
        if length > MAX_IMAGE {
            return Err(Error::Integrity);
        }
        let revision = u64::from_be_bytes(revision.try_into().map_err(|_| Error::Integrity)?);
        let bytes: Vec<u8> =
            connection.query_row("SELECT image FROM lifecycle WHERE slot=?", [slot], |r| {
                r.get(0)
            })?;
        Ok(Some((Self::anchor(revision, &bytes), bytes)))
    }

    fn write_image(
        connection: &mut Connection,
        slot: u8,
        revision: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR REPLACE INTO lifecycle(slot,revision,image) VALUES(?,?,?)",
            params![slot, revision.to_be_bytes().as_slice(), bytes],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn promote(connection: &mut Connection) -> Result<(), Error> {
        (|| -> rusqlite::Result<()> {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("DELETE FROM lifecycle WHERE slot=0", [])?;
            tx.execute("UPDATE lifecycle SET slot=0 WHERE slot=1", [])?;
            tx.commit()
        })()
        .map_err(|_| Error::CommitUnknown)
    }

    fn load(&self, connection: &mut Connection) -> Result<(Anchor, State, u64), Error> {
        let current = Self::image(connection, 0)?;
        let pending = Self::image(connection, 1)?;
        let external = self.rollback.current()?;
        let (head, image) = if let Some(pending) = pending {
            if Some(pending.0) == external {
                Self::promote(connection)?;
                pending
            } else {
                let expected = current.as_ref().map(|value| value.0);
                if external != expected {
                    return Err(Error::Integrity);
                }
                // A linearizable read may still precede a remotely delayed CAS.
                // Never delete its only durable image until settlement fences it.
                match self.rollback.settle(expected, pending.0)? {
                    Settlement::Committed => {
                        if self.rollback.current()? != Some(pending.0) {
                            return Err(Error::Integrity);
                        }
                        Self::promote(connection)?;
                        pending
                    }
                    Settlement::Aborted => {
                        if self.rollback.current()? != expected {
                            return Err(Error::Integrity);
                        }
                        connection.execute("DELETE FROM lifecycle WHERE slot=1", [])?;
                        match current {
                            Some(current) => current,
                            None => self.initialize(connection)?,
                        }
                    }
                }
            }
        } else if let Some(current) = current {
            if Some(current.0) != external {
                return Err(Error::Integrity);
            }
            current
        } else if external.is_none() {
            self.initialize(connection)?
        } else {
            return Err(Error::Integrity);
        };
        let state: State = serde_json::from_slice(&image).map_err(|_| Error::Integrity)?;
        if state.version != 2 || state.store_id != self.store_id || state.policy != self.policy {
            return Err(Error::Integrity);
        }
        let now = self.now(state.last_time)?;
        Ok((head, state, now))
    }

    fn initialize(&self, connection: &mut Connection) -> Result<(Anchor, Vec<u8>), Error> {
        let state = State {
            version: 2,
            operation_nonce: Self::operation_nonce()?,
            store_id: self.store_id.clone(),
            policy: self.policy.clone(),
            last_time: self.now(0)?,
            records: Vec::new(),
            audit: Vec::new(),
            pins: Default::default(),
        };
        let image = serde_json::to_vec(&state).map_err(|_| Error::Integrity)?;
        let head = Self::anchor(1, &image);
        Self::write_image(connection, 1, head.revision, &image)?;
        self.rollback
            .compare_and_swap(None, head)
            .map_err(|_| Error::CommitUnknown)?;
        Self::promote(connection)?;
        Ok((head, image))
    }

    fn operation_nonce() -> Result<[u8; 32], Error> {
        // Random public transaction identity, never an AK or a wrapping key.
        Secret32::generate()
            .map(|nonce| *nonce.expose())
            .map_err(|_| Error::Unavailable)
    }

    fn inspect<T>(&self, f: impl FnOnce(&State, u64) -> Result<T, Error>) -> Result<T, Error> {
        let mut db = self.database.lock().map_err(|_| Error::Unavailable)?;
        let (_, state, now) = self.load(&mut db.connection)?;
        f(&state, now)
    }

    fn change<T>(&self, f: impl FnOnce(&mut State, u64) -> Result<T, Error>) -> Result<T, Error> {
        let mut db = self.database.lock().map_err(|_| Error::Unavailable)?;
        let (head, mut state, now) = self.load(&mut db.connection)?;
        state.operation_nonce = Self::operation_nonce()?;
        let result = f(&mut state, now)?;
        state.last_time = self.now(now)?;
        let image = serde_json::to_vec(&state).map_err(|_| Error::Integrity)?;
        if image.len() > MAX_IMAGE {
            return Err(Error::Exhausted);
        }
        let next = Self::anchor(
            head.revision.checked_add(1).ok_or(Error::Exhausted)?,
            &image,
        );
        Self::write_image(&mut db.connection, 1, next.revision, &image)?;
        self.rollback
            .compare_and_swap(Some(head), next)
            .map_err(|_| Error::CommitUnknown)?;
        Self::promote(&mut db.connection)?;
        Ok(result)
    }

    /// Authority is checked before entropy generation or recording. Attempts are
    /// stable, exact-match idempotency keys; terminal keys are never recycled.
    pub fn stage(&self, request: Request, evidence: &[u8]) -> Result<Binding, Error> {
        self.stage_with(request, evidence, Enrollment::generate)
    }

    // Private fault seam; no deterministic RNG/provider is a production API.
    fn stage_with(
        &self,
        request: Request,
        evidence: &[u8],
        generate: impl FnOnce(u64) -> Result<Enrollment, syntra_core::secure_channel::Error>,
    ) -> Result<Binding, Error> {
        if evidence.len() > MAX_EVIDENCE
            || !text(&request.attempt, 255)
            || !text(&request.logical_id, 255)
            || !text(&request.principal, 255)
            || request.principal == "anonymous"
            || !text(&request.device, 255)
            || !text(&request.scope, 255)
        {
            return Err(Error::Denied);
        }
        self.authority
            .approve(&request, evidence)
            .map_err(|_| Error::Denied)?;
        self.change(|state, now| {
            if let Some(old) = state
                .records
                .iter()
                .find(|r| r.request.attempt == request.attempt)
            {
                return if old.request == request && !old.timed_out(now) {
                    Ok(old.binding.clone())
                } else {
                    Err(Error::Denied)
                };
            }
            if request.expires_at <= now
                || request.expires_at - now > u64::from(state.policy.max_validity_seconds)
                || state.records.len() >= state.policy.max_records as usize
            {
                return Err(Error::Exhausted);
            }
            let previous: Vec<_> = state
                .records
                .iter()
                .filter(|r| r.binding.logical_id == request.logical_id)
                .collect();
            if previous.iter().any(|r| {
                r.binding.principal != request.principal
                    || r.binding.device != request.device
                    || r.binding.scope != request.scope
            }) {
                return Err(Error::Denied);
            }
            if previous.iter().any(|r| {
                matches!(r.status, Status::Staged | Status::Delivered) && !r.timed_out(now)
            }) {
                return Err(Error::Denied);
            }
            let highest = previous.iter().map(|r| r.binding.epoch).max().unwrap_or(0);
            let current = previous
                .iter()
                .filter(|r| r.valid(now))
                .max_by_key(|r| r.binding.epoch);
            let predecessor = current.map(|r| r.binding.epoch);
            match request.issuance {
                Issuance::Initial if previous.iter().any(|r| r.activated) => {
                    return Err(Error::Denied)
                }
                Issuance::Rotation if current.is_none_or(|r| !r.valid(now)) => {
                    return Err(Error::Denied)
                }
                Issuance::Recovery if highest == 0 => return Err(Error::Denied),
                _ => {}
            }
            let epoch = highest.checked_add(1).ok_or(Error::Exhausted)?;
            // One collision rejects the attempt. This is a documented bounded
            // conflict procedure, never an unbounded redraw or overwrite.
            let issued = generate(epoch).map_err(|_| Error::Unavailable)?;
            let mut hash = Sha256::new();
            hash.update(b"syntra/rfc0010/ak-uniqueness/v1\0");
            hash.update(issued.key.expose());
            let key_digest: [u8; 32] = hash.finalize().into();
            if issued
                .key
                .expose()
                .iter()
                .all(|b| *b == issued.key.expose()[0])
                || issued.handle == [0; 8]
                || state
                    .records
                    .iter()
                    .any(|r| r.binding.handle == issued.handle)
                || state.records.iter().any(|r| r.key_digest == key_digest)
            {
                return Err(Error::Denied);
            }
            let binding = Binding {
                store_id: self.store_id.clone(),
                logical_id: request.logical_id.clone(),
                principal: request.principal.clone(),
                device: request.device.clone(),
                scope: request.scope.clone(),
                handle: issued.handle,
                epoch,
            };
            let envelope = self.protector.protect(&binding, &issued.key)?;
            if envelope.is_empty()
                || envelope.len() > MAX_ENVELOPE
                || envelope.windows(32).any(|part| part == issued.key.expose())
            {
                return Err(Error::Integrity);
            }
            let activation_deadline = now
                .checked_add(u64::from(state.policy.activation_seconds))
                .ok_or(Error::Exhausted)?;
            if self.now(now)? >= activation_deadline.min(request.expires_at) {
                return Err(Error::Denied);
            }
            // A lost ack must not keep the old key alive indefinitely. The hard
            // cutoff begins at intent, is persisted, and is never extended by a
            // retry, redelivery, late acknowledgement or host restart.
            if request.issuance == Issuance::Rotation {
                let cutoff = now
                    .checked_add(u64::from(state.policy.overlap_seconds))
                    .ok_or(Error::Exhausted)?;
                for r in &mut state.records {
                    if r.binding.logical_id == request.logical_id
                        && Some(r.binding.epoch) == predecessor
                    {
                        r.cutoff = Some(r.cutoff.unwrap_or(cutoff).min(cutoff));
                    }
                }
            }
            if request.issuance == Issuance::Recovery {
                for r in &mut state.records {
                    if r.binding.logical_id == request.logical_id {
                        r.status = Status::Terminal;
                    }
                }
            }
            state.records.push(Record {
                request,
                binding: binding.clone(),
                envelope,
                key_digest,
                status: Status::Staged,
                activated: false,
                activation_deadline,
                cutoff: None,
                predecessor,
                destroyed: false,
            });
            state.audit(1);
            Ok(binding)
        })
    }

    pub fn deliver(&self, attempt: &str, delivery: &dyn EncryptedDelivery) -> Result<(), Error> {
        self.change(|state, now| {
            let record = state
                .records
                .iter_mut()
                .find(|r| r.request.attempt == attempt)
                .ok_or(Error::Denied)?;
            if record.timed_out(now) || !matches!(record.status, Status::Staged | Status::Delivered)
            {
                return Err(Error::Denied);
            }
            let key = self
                .protector
                .unprotect(&record.binding, &record.envelope)?;
            delivery.deliver(&record.binding, &key)?;
            if record.timed_out(self.now(now)?) {
                return Err(Error::Denied);
            }
            record.status = Status::Delivered;
            state.audit(2);
            Ok(())
        })
    }

    /// Durable device receipt is required; there is no public `acknowledged: bool`.
    /// Lost commit outcomes reconcile the existing tuple, never issue a new AK.
    pub fn activate(&self, attempt: &str, receipt: &[u8]) -> Result<Binding, Error> {
        if receipt.len() > MAX_EVIDENCE {
            return Err(Error::Denied);
        }
        self.change(|state, now| {
            let index = state
                .records
                .iter()
                .position(|r| r.request.attempt == attempt)
                .ok_or(Error::Denied)?;
            let record = &state.records[index];
            self.authority
                .verify_durable_ack(&record.binding, receipt)
                .map_err(|_| Error::Denied)?;
            let now = self.now(now)?;
            if record.valid(now) {
                return Ok(record.binding.clone());
            }
            if record.timed_out(now) || record.status != Status::Delivered {
                return Err(Error::Denied);
            }
            let binding = record.binding.clone();
            let issuance = record.request.issuance;
            if issuance == Issuance::Rotation {
                // Only the immediately superseded tuple may overlap. Earlier
                // generations are terminal even if rotations happen rapidly.
                let previous = record.predecessor.ok_or(Error::Denied)?;
                let old = state
                    .records
                    .iter()
                    .find(|r| {
                        r.binding.logical_id == binding.logical_id && r.binding.epoch == previous
                    })
                    .ok_or(Error::Denied)?;
                if !old.valid(now) {
                    return Err(Error::Denied);
                }
                for r in &mut state.records {
                    if r.binding.logical_id == binding.logical_id
                        && r.binding.epoch < binding.epoch
                        && r.binding.epoch != previous
                    {
                        r.status = Status::Terminal;
                    }
                }
            }
            state.records[index].status = Status::Active;
            state.records[index].activated = true;
            state.audit(3);
            Ok(binding)
        })
    }

    pub fn revoke(&self, logical_id: &str, evidence: &[u8]) -> Result<(), Error> {
        if !text(logical_id, 255) || evidence.len() > MAX_EVIDENCE {
            return Err(Error::Denied);
        }
        self.authority
            .approve_revocation(logical_id, evidence)
            .map_err(|_| Error::Denied)?;
        self.change(|state, _| {
            let mut found = false;
            for record in &mut state.records {
                if record.binding.logical_id == logical_id {
                    record.status = Status::Terminal;
                    found = true;
                }
            }
            if !found {
                return Err(Error::Denied);
            }
            state.audit(4);
            Ok(())
        })?;
        self.cleanup().map(|_| ())
    }

    /// Bounded erasure work; tombstones retain tuple and attempt anti-replay
    /// identity but release ciphertext. Repeat after protector outages/restarts.
    /// Schedule this within the deployment's declared secret-disposal budget.
    pub fn cleanup(&self) -> Result<usize, Error> {
        self.change(|state, now| {
            let mut count = 0;
            for record in &mut state.records {
                if count >= state.policy.cleanup_batch {
                    break;
                }
                if record.timed_out(now) && !record.destroyed {
                    record.status = Status::Terminal;
                    self.protector.destroy(&record.binding)?;
                    record.envelope.clear();
                    record.destroyed = true;
                    count += 1;
                }
            }
            let known: Vec<_> = state.records.iter().map(|r| r.binding.clone()).collect();
            let remaining = (state.policy.cleanup_batch - count) as usize;
            let orphans = self
                .protector
                .reconcile_orphans(&self.store_id, &known, remaining)?;
            if orphans > remaining {
                return Err(Error::Integrity);
            }
            count += orphans as u32;
            Ok(count as usize)
        })
    }

    pub fn validate(&self, context: &Context, principal: Option<&str>) -> Result<Binding, Error> {
        self.inspect(|state, now| {
            let record = Self::find(state, context, now)?;
            if principal.is_some_and(|p| p != record.binding.principal) {
                return Err(Error::Denied);
            }
            Ok(record.binding.clone())
        })
    }

    fn find<'a>(state: &'a State, context: &Context, now: u64) -> Result<&'a Record, Error> {
        if context.mode != Mode::Returning || !state.policy.permits(context.carrier) {
            return Err(Error::Denied);
        }
        state
            .records
            .iter()
            .find(|record| {
                record.binding.handle == context.handle
                    && record.binding.epoch == context.epoch
                    && record.binding.scope.as_bytes() == context.scope
                    && record.valid(now)
            })
            .ok_or(Error::Denied)
    }
}

impl KeyStore for SqliteEnrollmentStore {
    /// Shared channel KeyStore is synchronous. Embedders must bound the authority/KMS
    /// calls and account for its admission latency; this is not async cancellation.
    fn lookup(&self, context: &Context) -> Result<Secret32, syntra_core::secure_channel::Error> {
        self.inspect(|state, now| {
            let record = Self::find(state, context, now)?;
            let key = self
                .protector
                .unprotect(&record.binding, &record.envelope)?;
            if !record.valid(self.now(now)?) {
                return Err(Error::Denied);
            }
            if key.expose() == &[0; 32] {
                return Err(Error::Denied);
            }
            Ok(key)
        })
        .map_err(|_| syntra_core::secure_channel::Error::Authentication)
    }
}

#[cfg(test)]
mod tests;
