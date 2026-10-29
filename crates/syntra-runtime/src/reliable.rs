//! Reliable-session runtime managers: bounded, sync, transport-agnostic.

use crate::connection::fill_random;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use syntra_core::error::{ErrorCode, SyntraError};
use syntra_core::reliable::{
    check_duplicate_content, check_epoch_advance, negotiate_lease, next_epoch,
    validate_delivery_id, validate_epoch, validate_resume_credential, validate_session_id,
    ConfirmedLease, ControlBounds, DeliveryId, LeaseProposal, ReconcileOutcome, SessionId,
    SessionSignal,
};

fn resource(msg: &str) -> SyntraError {
    SyntraError::ResourceExhausted(msg.to_string())
}
fn unauthenticated(msg: &str) -> SyntraError {
    SyntraError::Handshake {
        code: ErrorCode::Unauthenticated,
        message: msg.to_string(),
    }
}
fn failed_precondition(msg: &str) -> SyntraError {
    SyntraError::Protocol {
        code: ErrorCode::FailedPrecondition,
        message: msg.to_string(),
    }
}
fn internal(msg: &str) -> SyntraError {
    SyntraError::Protocol {
        code: ErrorCode::Internal,
        message: msg.to_string(),
    }
}

/// Bounded content identity for terminal markers.
///
/// Tombstone and forgotten markers suppress resends while live. To reject
/// same-delivery-ID reuse with different method/payload (FAILED_PRECONDITION)
/// without retaining unbounded request bytes, each marker stores a fixed-size
/// digest (method/payload lengths plus SHA-256) instead of full
/// content. Digests are constant size and bounded by the existing count caps
/// (`max_tombstones` for tombstones, `max_retained_results` for forgotten
/// markers); they consume no `max_retained_bytes` charge, so `forget` still
/// frees request bytes and tombstoning still releases pending charge.
/// Lengths are checked explicitly and included in the digest input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentDigest {
    method_len: usize,
    payload_len: usize,
    hash: [u8; 32],
}
fn digest_content(method: &str, payload: &[u8]) -> ContentDigest {
    let mut h = Sha256::new();
    h.update((method.len() as u64).to_le_bytes());
    h.update(method.as_bytes());
    h.update((payload.len() as u64).to_le_bytes());
    h.update(payload);
    ContentDigest {
        method_len: method.len(),
        payload_len: payload.len(),
        hash: h.finalize().into(),
    }
}
fn check_digest(expected: &ContentDigest, method: &str, payload: &[u8]) -> Result<(), SyntraError> {
    if expected.method_len != method.len() || expected.payload_len != payload.len() {
        return Err(failed_precondition(
            "delivery id reused with different content; rejected",
        ));
    }
    if expected.hash != digest_content(method, payload).hash {
        return Err(failed_precondition(
            "delivery id reused with different content; rejected",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredOutcome {
    Payload(Vec<u8>),
    Error { code: ErrorCode, message: String },
}
impl StoredOutcome {
    fn byte_len(&self) -> usize {
        match self {
            Self::Payload(b) => b.len(),
            Self::Error { message, .. } => message.len(),
        }
    }
}
#[derive(Debug, Clone)]
struct RetainedEntry {
    method: String,
    payload: Vec<u8>,
    outcome: StoredOutcome,
    retained_at_ms: u64,
}
impl RetainedEntry {
    fn byte_len(&self) -> usize {
        self.method.len() + self.payload.len() + self.outcome.byte_len()
    }
}
#[derive(Debug, Clone)]
struct PendingEntry {
    method: String,
    payload: Vec<u8>,
}
impl PendingEntry {
    fn byte_len(&self) -> usize {
        self.method.len() + self.payload.len()
    }
}
/// A live Forgotten marker means retention expired or explicit forget, and
/// while live it suppresses resends (stays Forgotten, not new work); only
/// after expiry may the same delivery ID be reused as new work (Pending) with
/// any content. Content handling is consistent: while live, resends validate
/// against the stored digest (mismatches rejected); after expiry, any content
/// is accepted as new work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ForgottenEntry {
    forgot_at_ms: u64,
    content: Option<ContentDigest>,
}
#[derive(Debug, Default)]
struct OutcomeStore {
    entries: HashMap<DeliveryId, RetainedEntry>,
    // Aggregate owned content: pending requests plus retained requests/results.
    // Forgotten/tombstone digests are fixed-size and bounded by count caps,
    // so they consume no byte-cap charge; forget still frees request bytes.
    bytes: usize,
    forgotten: HashMap<DeliveryId, ForgottenEntry>,
    pending: HashMap<DeliveryId, PendingEntry>,
}
impl OutcomeStore {
    fn replacement_bytes(
        &self,
        bounds: &ControlBounds,
        did: &DeliveryId,
        n: usize,
    ) -> Result<usize, SyntraError> {
        let retained = self.entries.get(did);
        let pending = self.pending.get(did);
        let count = self.entries.len() + self.pending.len()
            - usize::from(retained.is_some())
            - usize::from(pending.is_some());
        if count >= bounds.max_retained_results {
            return Err(resource("retained and pending result budget exhausted"));
        }
        let replaced =
            retained.map_or(0, RetainedEntry::byte_len) + pending.map_or(0, PendingEntry::byte_len);
        self.bytes
            .checked_sub(replaced)
            .and_then(|bytes| bytes.checked_add(n))
            .filter(|&bytes| bytes <= bounds.max_retained_bytes)
            .ok_or_else(|| resource("retained and pending result bytes exhausted"))
    }
    fn release_pending(&mut self, did: &DeliveryId) {
        if let Some(pending) = self.pending.remove(did) {
            self.bytes -= pending.byte_len();
        }
    }
    fn insert(
        &mut self,
        bounds: &ControlBounds,
        now_ms: u64,
        did: DeliveryId,
        method: String,
        payload: Vec<u8>,
        outcome: StoredOutcome,
    ) -> Result<ReconcileOutcome, SyntraError> {
        if let Some(pending) = self.pending.get(&did) {
            check_duplicate_content(&pending.method, &pending.payload, &method, &payload)?;
        }
        if let Some(existing) = self.entries.get(&did) {
            if now_ms.saturating_sub(existing.retained_at_ms) <= bounds.result_retention_ms {
                check_duplicate_content(&existing.method, &existing.payload, &method, &payload)?;
                return Ok(ReconcileOutcome::Retained);
            }
        }
        let n = method
            .len()
            .checked_add(payload.len())
            .and_then(|n| n.checked_add(outcome.byte_len()))
            .ok_or_else(|| resource("retained result size overflow"))?;
        let bytes = self.replacement_bytes(bounds, &did, n)?;
        // Commit only after content validation and replacement admission succeed.
        self.pending.remove(&did);
        self.forgotten.remove(&did);
        self.entries.insert(
            did,
            RetainedEntry {
                method,
                payload,
                outcome,
                retained_at_ms: now_ms,
            },
        );
        self.bytes = bytes;
        Ok(ReconcileOutcome::Retained)
    }
    fn note_dispatch(
        &mut self,
        bounds: &ControlBounds,
        now_ms: u64,
        did: DeliveryId,
        method: String,
        payload: Vec<u8>,
    ) -> Result<(), SyntraError> {
        if let Some(pending) = self.pending.get(&did) {
            return check_duplicate_content(&pending.method, &pending.payload, &method, &payload);
        }
        if let Some(existing) = self.entries.get(&did) {
            if now_ms.saturating_sub(existing.retained_at_ms) <= bounds.result_retention_ms {
                return check_duplicate_content(
                    &existing.method,
                    &existing.payload,
                    &method,
                    &payload,
                );
            }
        }
        if let Some(entry) = self.forgotten.get(&did) {
            if now_ms.saturating_sub(entry.forgot_at_ms) <= bounds.result_retention_ms {
                if let Some(expected) = &entry.content {
                    return check_digest(expected, &method, &payload);
                }
                // Content-less marker (explicit forget on Unknown): first live
                // resend defines the digest so later mismatches reject.
                let digest = digest_content(&method, &payload);
                if let Some(slot) = self.forgotten.get_mut(&did) {
                    slot.content = Some(digest);
                }
                return Ok(());
            }
        }
        let n = method
            .len()
            .checked_add(payload.len())
            .ok_or_else(|| resource("pending dispatch size overflow"))?;
        let bytes = self.replacement_bytes(bounds, &did, n)?;
        // Stale terminal markers must not hide a newly admitted Pending entry.
        self.entries.remove(&did);
        self.forgotten.remove(&did);
        self.pending.insert(did, PendingEntry { method, payload });
        self.bytes = bytes;
        Ok(())
    }
    fn get(&self, now_ms: u64, retention_ms: u64, did: &DeliveryId) -> ReconcileOutcome {
        match self.entries.get(did) {
            Some(e) if now_ms.saturating_sub(e.retained_at_ms) > retention_ms => {
                ReconcileOutcome::Forgotten
            }
            Some(_) => ReconcileOutcome::Retained,
            None => match self.forgotten.get(did) {
                Some(entry) if now_ms.saturating_sub(entry.forgot_at_ms) > retention_ms => {
                    ReconcileOutcome::Unknown
                }
                Some(_) => ReconcileOutcome::Forgotten,
                None => match self.pending.get(did) {
                    Some(_) => ReconcileOutcome::Pending,
                    None => ReconcileOutcome::Unknown,
                },
            },
        }
    }
    fn outcome_of(&self, did: &DeliveryId) -> Option<StoredOutcome> {
        self.entries.get(did).map(|e| e.outcome.clone())
    }
    fn forget(&mut self, bounds: &ControlBounds, now_ms: u64, did: &DeliveryId) -> bool {
        if let Some(e) = self.entries.remove(did) {
            self.bytes -= e.byte_len();
            let digest = digest_content(&e.method, &e.payload);
            if !self.forgotten.contains_key(did)
                && self.forgotten.len() >= bounds.max_retained_results
            {
                if let Some(oldest) = self
                    .forgotten
                    .iter()
                    .min_by_key(|(_, v)| v.forgot_at_ms)
                    .map(|(k, _)| *k)
                {
                    self.forgotten.remove(&oldest);
                }
            }
            self.forgotten.insert(
                *did,
                ForgottenEntry {
                    forgot_at_ms: now_ms,
                    content: Some(digest),
                },
            );
            true
        } else if !self.forgotten.contains_key(did) {
            if self.forgotten.len() >= bounds.max_retained_results {
                if let Some(oldest) = self
                    .forgotten
                    .iter()
                    .min_by_key(|(_, v)| v.forgot_at_ms)
                    .map(|(k, _)| *k)
                {
                    self.forgotten.remove(&oldest);
                }
            }
            // No prior retained content to carry: content-less marker. The
            // first live resend defines the digest (see note_dispatch).
            self.forgotten.insert(
                *did,
                ForgottenEntry {
                    forgot_at_ms: now_ms,
                    content: None,
                },
            );
            true
        } else {
            false
        }
    }
    fn reap_expired(&mut self, bounds: &ControlBounds, now_ms: u64, retention_ms: u64) -> usize {
        let expired: Vec<DeliveryId> = self
            .entries
            .iter()
            .filter(|(_, e)| now_ms.saturating_sub(e.retained_at_ms) > retention_ms)
            .map(|(k, _)| *k)
            .collect();
        let n = expired.len();
        for k in expired {
            self.forget(bounds, now_ms, &k);
        }
        // Time passing cannot prove a handler stopped executing. Pending owns
        // its content and budget until a successful result/tombstone mutation.
        let expired_forgotten: Vec<DeliveryId> = self
            .forgotten
            .iter()
            .filter(|(_, v)| now_ms.saturating_sub(v.forgot_at_ms) > retention_ms)
            .map(|(k, _)| *k)
            .collect();
        for k in expired_forgotten {
            self.forgotten.remove(&k);
        }
        n
    }
}
/// A live tombstone suppresses resends (stays Retained with the terminal
/// error, not new work); only after expiry may the same delivery ID be reused
/// as new work (Pending) with any content. While live, resends validate
/// against the stored digest (mismatches rejected with FAILED_PRECONDITION).
#[derive(Debug, Clone)]
struct TombstoneEntry {
    code: ErrorCode,
    retained_at_ms: u64,
    content: Option<ContentDigest>,
}
#[derive(Debug, Default)]
struct TombstoneStore {
    entries: HashMap<DeliveryId, TombstoneEntry>,
}
impl TombstoneStore {
    fn record(
        &mut self,
        bounds: &ControlBounds,
        now_ms: u64,
        did: DeliveryId,
        code: ErrorCode,
        content: Option<ContentDigest>,
    ) -> Result<(), SyntraError> {
        // Spec (reliability): tombstones exist only for terminal
        // DEADLINE_EXCEEDED and CANCELLED. UNAVAILABLE means unknown
        // outcome and must stay reconcilable-as-Unknown, never tombstoned.
        if !matches!(code, ErrorCode::DeadlineExceeded | ErrorCode::Cancelled) {
            return Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "tombstones only for deadline/cancel".to_string(),
            });
        }
        // First-write-wins: racing deadline/cancel reports are deterministic.
        if let Some(existing) = self.entries.get_mut(&did) {
            if existing.code != code {
                return Err(failed_precondition(
                    "tombstone already recorded with different terminal code",
                ));
            }
            match (&existing.content, &content) {
                (Some(e), Some(n)) if e != n => {
                    return Err(failed_precondition(
                        "delivery id reused with different content; rejected",
                    ));
                }
                (None, Some(n)) => {
                    existing.content = Some(*n);
                }
                _ => {}
            }
            return Ok(());
        }
        if self.entries.len() >= bounds.max_tombstones {
            return Err(resource("tombstone budget exhausted"));
        }
        self.entries.insert(
            did,
            TombstoneEntry {
                code,
                retained_at_ms: now_ms,
                content,
            },
        );
        Ok(())
    }
    fn get(&self, now_ms: u64, retention_ms: u64, did: &DeliveryId) -> Option<ErrorCode> {
        self.entries.get(did).and_then(|e| {
            if now_ms.saturating_sub(e.retained_at_ms) > retention_ms {
                None
            } else {
                Some(e.code)
            }
        })
    }
    fn reap_expired(&mut self, now_ms: u64, retention_ms: u64) -> usize {
        let expired: Vec<DeliveryId> = self
            .entries
            .iter()
            .filter(|(_, e)| now_ms.saturating_sub(e.retained_at_ms) > retention_ms)
            .map(|(k, _)| *k)
            .collect();
        let n = expired.len();
        for k in expired {
            self.entries.remove(&k);
        }
        n
    }
}
#[derive(Debug, Clone)]
struct ResumeEntry {
    session_id: SessionId,
    principal: String,
    version: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
}
#[derive(Debug)]
struct SessionState {
    principal: String,
    version: u32,
    epoch: u64,
    last_activity_ms: u64,
    lease: ConfirmedLease,
    active_connection: Option<String>,
    ever_attached: bool,
    outcomes: OutcomeStore,
    tombstones: TombstoneStore,
}
#[derive(Debug, Default)]
struct ControlQueue {
    queue: VecDeque<(SessionId, SessionSignal)>,
    bytes: usize,
}
impl ControlQueue {
    fn push(
        &mut self,
        bounds: &ControlBounds,
        id: SessionId,
        sig: SessionSignal,
    ) -> Result<(), SyntraError> {
        if self.queue.len() >= bounds.max_control_queue {
            return Err(resource("control queue full; back off"));
        }
        if self.bytes.saturating_add(32) > bounds.max_control_bytes {
            return Err(resource("control queue bytes exhausted"));
        }
        self.queue.push_back((id, sig));
        self.bytes = self.bytes.saturating_add(32);
        Ok(())
    }
    fn drain(&mut self, limit: usize) -> Vec<(SessionId, SessionSignal)> {
        let n = limit.min(self.queue.len());
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            if let Some((id, sig)) = self.queue.pop_front() {
                self.bytes = self.bytes.saturating_sub(32);
                out.push((id, sig));
            }
        }
        out
    }
    fn len(&self) -> usize {
        self.queue.len()
    }
}
#[derive(Default)]
struct ManagerInner {
    sessions: HashMap<SessionId, SessionState>,
    resume_index: HashMap<Vec<u8>, ResumeEntry>,
    revoked: HashMap<Vec<u8>, u64>,
    signals: ControlQueue,
    draining: bool,
}
pub struct ReliableSessionManager {
    inner: std::sync::Mutex<ManagerInner>,
    bounds: ControlBounds,
}
impl std::fmt::Debug for ReliableSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReliableSessionManager")
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}
impl ReliableSessionManager {
    pub fn new(bounds: ControlBounds) -> Result<Self, SyntraError> {
        bounds.validate()?;
        Ok(Self {
            inner: std::sync::Mutex::new(ManagerInner::default()),
            bounds,
        })
    }
    pub fn bounds(&self) -> ControlBounds {
        self.bounds
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, ManagerInner>, SyntraError> {
        self.inner
            .lock()
            .map_err(|_| internal("manager lock poisoned"))
    }
    pub fn create_session(
        &self,
        now_ms: u64,
        principal: String,
        version: u32,
        proposal: LeaseProposal,
    ) -> Result<(SessionId, u64, Vec<u8>, ConfirmedLease), SyntraError> {
        if principal.is_empty()
            || principal.len() > syntra_core::reliable::MAX_RELIABLE_PRINCIPAL_LEN
        {
            return Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "principal length out of bounds".to_string(),
            });
        }
        if version == 0 {
            return Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "version must be nonzero".to_string(),
            });
        }
        let lease = negotiate_lease(proposal)?;
        let mut inner = self.lock()?;
        if inner.draining {
            return Err(SyntraError::Unavailable(
                "draining; no new sessions".to_string(),
            ));
        }
        if inner.sessions.len() >= self.bounds.max_sessions {
            return Err(resource("too many reliable sessions"));
        }
        if inner.resume_index.len() >= self.bounds.max_resume_credentials {
            return Err(resource("too many resume credentials"));
        }
        let sid = generate_session_id()?;
        if inner.sessions.contains_key(&sid) {
            return Err(internal("session id collision"));
        }
        let cred = generate_resume_credential()?;
        if inner.resume_index.contains_key(&cred) {
            return Err(internal("resume credential collision"));
        }
        let exp = now_ms.saturating_add(self.bounds.resume_lifetime_ms);
        inner.sessions.insert(
            sid,
            SessionState {
                principal: principal.clone(),
                version,
                epoch: 1,
                last_activity_ms: now_ms,
                lease,
                active_connection: None,
                ever_attached: false,
                outcomes: OutcomeStore::default(),
                tombstones: TombstoneStore::default(),
            },
        );
        inner.resume_index.insert(
            cred.clone(),
            ResumeEntry {
                session_id: sid,
                principal,
                version,
                issued_at_ms: now_ms,
                expires_at_ms: exp,
            },
        );
        Ok((sid, 1, cred, lease))
    }
    pub fn attach(
        &self,
        now_ms: u64,
        session_id: &[u8],
        resume_credential: &[u8],
        connection_id: String,
        principal: &str,
        version: u32,
        proposal: LeaseProposal,
    ) -> Result<(u64, ConfirmedLease, Option<String>, Option<Vec<u8>>), SyntraError> {
        let sid = validate_session_id(session_id)?;
        if connection_id.is_empty() || connection_id.len() > 256 {
            return Err(SyntraError::Protocol {
                code: ErrorCode::InvalidArgument,
                message: "connection_id length out of bounds".to_string(),
            });
        }
        let lease = negotiate_lease(proposal)?;
        let fresh_pre = if resume_credential.is_empty() {
            None
        } else {
            Some(generate_resume_credential()?)
        };
        let mut inner = self.lock()?;
        if inner.draining {
            return Err(SyntraError::Unavailable(
                "draining; no new attachments".to_string(),
            ));
        }
        let (bp, bv, cur) = {
            let s = inner
                .sessions
                .get(&sid)
                .ok_or_else(|| SyntraError::Handshake {
                    code: ErrorCode::Unauthenticated,
                    message: "unknown session".to_string(),
                })?;
            (s.principal.clone(), s.version, s.epoch)
        };
        if bp != principal {
            return Err(unauthenticated("principal mismatch for session"));
        }
        if bv != version {
            return Err(failed_precondition("version mismatch for session"));
        }
        if let Some(fresh) = fresh_pre {
            let cred = validate_resume_credential(resume_credential)?;
            if inner.revoked.contains_key(&cred.0) {
                return Err(unauthenticated("resume credential revoked"));
            }
            let (rp, rv, rs, rexp) = {
                let e = inner
                    .resume_index
                    .get(&cred.0)
                    .ok_or_else(|| SyntraError::Handshake {
                        code: ErrorCode::Unauthenticated,
                        message: "unknown resume credential".to_string(),
                    })?;
                (
                    e.principal.clone(),
                    e.version,
                    e.session_id,
                    e.expires_at_ms,
                )
            };
            if rs != sid {
                return Err(unauthenticated("resume credential audience mismatch"));
            }
            if rp != principal || rv != version {
                return Err(unauthenticated("resume credential binding mismatch"));
            }
            if now_ms > rexp {
                return Err(unauthenticated("resume credential expired"));
            }
            let proposed = next_epoch(cur)?;
            check_epoch_advance(cur, proposed)?;
            if inner.resume_index.contains_key(&fresh) || inner.revoked.contains_key(&fresh) {
                return Err(internal("resume credential collision"));
            }
            let total = inner.resume_index.len().saturating_add(inner.revoked.len());
            if total.saturating_add(1) > self.bounds.max_resume_credentials.saturating_mul(2) {
                return Err(resource("too many resume credentials"));
            }
            let st = inner
                .sessions
                .get(&sid)
                .ok_or_else(|| SyntraError::Handshake {
                    code: ErrorCode::Unauthenticated,
                    message: "unknown session".to_string(),
                })?;
            if st.epoch != cur {
                return Err(failed_precondition("concurrent attach raced epoch"));
            }
            // Pre-reserve Fenced-signal capacity BEFORE committing the
            // epoch/connection rotation: ControlQueue::push is fallible
            // (bounded), and a post-mutation push failure must not leave a
            // committed rotation without its fence signal (or swallow the
            // error). Under the manager lock no concurrent mutation can
            // invalidate this check, so the push below must succeed.
            if st.active_connection.is_some()
                && (inner.signals.len() >= self.bounds.max_control_queue
                    || inner.signals.bytes.saturating_add(32) > self.bounds.max_control_bytes)
            {
                return Err(resource("control queue full; back off"));
            }
            let st = inner
                .sessions
                .get_mut(&sid)
                .ok_or_else(|| SyntraError::Handshake {
                    code: ErrorCode::Unauthenticated,
                    message: "unknown session".to_string(),
                })?;
            if st.epoch != cur {
                return Err(failed_precondition("concurrent attach raced epoch"));
            }
            let fenced = st.active_connection.clone();
            st.epoch = proposed;
            st.active_connection = Some(connection_id);
            st.ever_attached = true;
            st.last_activity_ms = now_ms;
            st.lease = lease;
            inner.resume_index.remove(&cred.0);
            let rev_exp = now_ms.saturating_add(self.bounds.resume_lifetime_ms);
            inner.revoked.insert(cred.0.clone(), rev_exp);
            let exp = now_ms.saturating_add(self.bounds.resume_lifetime_ms);
            inner.resume_index.insert(
                fresh.clone(),
                ResumeEntry {
                    session_id: sid,
                    principal: bp,
                    version: bv,
                    issued_at_ms: now_ms,
                    expires_at_ms: exp,
                },
            );
            if fenced.is_some() {
                // Pre-reserved above: this push must succeed; propagate
                // instead of swallowing so a bound change is never silent.
                inner
                    .signals
                    .push(&self.bounds, sid, SessionSignal::Fenced)?;
            }
            Ok((proposed, lease, fenced, Some(fresh)))
        } else {
            validate_epoch(cur)?;
            let st = inner
                .sessions
                .get_mut(&sid)
                .ok_or_else(|| SyntraError::Handshake {
                    code: ErrorCode::Unauthenticated,
                    message: "unknown session".to_string(),
                })?;
            if st.active_connection.is_some() {
                return Err(failed_precondition(
                    "session already attached; present resume credential",
                ));
            }
            if st.ever_attached {
                return Err(unauthenticated(
                    "credential-less re-attach forbidden; present resume credential",
                ));
            }
            st.active_connection = Some(connection_id);
            st.ever_attached = true;
            st.last_activity_ms = now_ms;
            st.lease = lease;
            let epoch = st.epoch;
            Ok((epoch, lease, None, None))
        }
    }
    pub fn detach(&self, session_id: &[u8], connection_id: &str) -> Result<(), SyntraError> {
        let sid = validate_session_id(session_id)?;
        let mut inner = self.lock()?;
        if let Some(st) = inner.sessions.get_mut(&sid) {
            if st.active_connection.as_deref() == Some(connection_id) {
                st.active_connection = None;
            }
        }
        Ok(())
    }
    pub fn record_result(
        &self,
        now_ms: u64,
        session_id: &[u8],
        expected_epoch: u64,
        delivery_id: &[u8],
        method: String,
        payload: Vec<u8>,
        outcome: StoredOutcome,
    ) -> Result<ReconcileOutcome, SyntraError> {
        let sid = validate_session_id(session_id)?;
        let did = validate_delivery_id(delivery_id)?;
        if payload.len() > syntra_core::MAX_FRAME_BYTES {
            return Err(resource("payload exceeds envelope bound"));
        }
        let mut inner = self.lock()?;
        let st = inner
            .sessions
            .get_mut(&sid)
            .ok_or_else(|| failed_precondition("unknown session for result"))?;
        // Fencing: a connection fenced by a newer attach (epoch advanced)
        // must not complete work. Callers pass the epoch they attached at;
        // anything stale is rejected before any outcome mutation.
        if st.epoch != expected_epoch {
            return Err(failed_precondition(
                "stale attachment epoch; fenced connection cannot complete",
            ));
        }
        if st
            .tombstones
            .get(now_ms, self.bounds.tombstone_retention_ms, &did)
            .is_some()
        {
            return Err(failed_precondition(
                "delivery id is tombstoned; terminal state preserved",
            ));
        }
        st.last_activity_ms = now_ms;
        st.outcomes
            .insert(&self.bounds, now_ms, did, method, payload, outcome)
    }
    pub fn reconcile(
        &self,
        now_ms: u64,
        session_id: &[u8],
        delivery_id: &[u8],
    ) -> Result<(ReconcileOutcome, Option<StoredOutcome>), SyntraError> {
        let sid = validate_session_id(session_id)?;
        let did = validate_delivery_id(delivery_id)?;
        let inner = self.lock()?;
        let st = inner
            .sessions
            .get(&sid)
            .ok_or_else(|| failed_precondition("unknown session for reconcile"))?;
        let o = st
            .outcomes
            .get(now_ms, self.bounds.result_retention_ms, &did);
        // Tombstones are terminal too: an outcome with no retained result
        // but a live tombstone reconciles to the tombstoned error instead
        // of Unknown, so a retry after deadline/cancel observes the
        // terminal code rather than re-dispatching forever.
        let (o, stored) = match o {
            ReconcileOutcome::Retained => (o, st.outcomes.outcome_of(&did)),
            ReconcileOutcome::Unknown => {
                match st
                    .tombstones
                    .get(now_ms, self.bounds.tombstone_retention_ms, &did)
                {
                    Some(code) => (
                        ReconcileOutcome::Retained,
                        Some(StoredOutcome::Error {
                            code,
                            message: "terminal outcome retained as tombstone".to_string(),
                        }),
                    ),
                    None => (ReconcileOutcome::Unknown, None),
                }
            }
            ReconcileOutcome::Forgotten => (o, None),
            ReconcileOutcome::Pending => (o, None),
        };
        Ok((o, stored))
    }
    pub fn forget(
        &self,
        now_ms: u64,
        session_id: &[u8],
        expected_epoch: u64,
        delivery_id: &[u8],
    ) -> Result<bool, SyntraError> {
        let sid = validate_session_id(session_id)?;
        let did = validate_delivery_id(delivery_id)?;
        let mut inner = self.lock()?;
        let st = inner
            .sessions
            .get_mut(&sid)
            .ok_or_else(|| failed_precondition("unknown session for forget"))?;
        if st.epoch != expected_epoch {
            return Err(failed_precondition(
                "stale attachment epoch; fenced connection cannot forget",
            ));
        }
        if st.outcomes.pending.contains_key(&did) {
            return Err(failed_precondition(
                "cannot forget a pending dispatch before a terminal outcome",
            ));
        }
        Ok(st.outcomes.forget(&self.bounds, now_ms, &did))
    }
    /// Admit request content before handler dispatch; identical resends are idempotent.
    /// Pending content shares the retained count/byte caps and never expires by
    /// time alone. The owner must record a terminal result or deadline/cancel
    /// tombstone once work is terminal; `forget` cannot clear executing work.
    ///
    /// Suppression semantics: a live retained outcome, live tombstone, or live
    /// forgotten marker suppresses resends (stays in that terminal state, not
    /// new work) and validates content — mismatched method/payload is rejected
    /// with FAILED_PRECONDITION. Only after expiry may the same delivery ID be
    /// reused as new work (Pending) with any content. Tombstone and forgotten
    /// markers store bounded digests (not full content) so validation holds
    /// while live without charging `max_retained_bytes`.
    pub fn note_dispatch(
        &self,
        now_ms: u64,
        session_id: &[u8],
        expected_epoch: u64,
        delivery_id: &[u8],
        method: String,
        payload: Vec<u8>,
    ) -> Result<(), SyntraError> {
        let sid = validate_session_id(session_id)?;
        let did = validate_delivery_id(delivery_id)?;
        if payload.len() > syntra_core::MAX_FRAME_BYTES {
            return Err(resource("payload exceeds envelope bound"));
        }
        let mut inner = self.lock()?;
        let st = inner
            .sessions
            .get_mut(&sid)
            .ok_or_else(|| failed_precondition("unknown session for dispatch"))?;
        if st.epoch != expected_epoch {
            return Err(failed_precondition(
                "stale attachment epoch; fenced connection cannot dispatch",
            ));
        }
        // Live tombstone suppresses but must still validate content. Validate
        // all live markers first (reject on any mismatch) before filling any
        // content-less marker, so a rejected resend never pollutes an empty
        // marker with mismatched content.
        let tomb_live = st
            .tombstones
            .get(now_ms, self.bounds.tombstone_retention_ms, &did)
            .is_some();
        if tomb_live {
            if let Some(entry) = st.tombstones.entries.get(&did) {
                if let Some(expected) = &entry.content {
                    check_digest(expected, &method, &payload)?;
                }
            }
            // Validate live outcome markers without admitting new work.
            if let Some(pending) = st.outcomes.pending.get(&did) {
                check_duplicate_content(&pending.method, &pending.payload, &method, &payload)?;
            }
            if let Some(existing) = st.outcomes.entries.get(&did) {
                if now_ms.saturating_sub(existing.retained_at_ms) <= self.bounds.result_retention_ms
                {
                    check_duplicate_content(
                        &existing.method,
                        &existing.payload,
                        &method,
                        &payload,
                    )?;
                }
            }
            if let Some(forgotten) = st.outcomes.forgotten.get(&did) {
                if now_ms.saturating_sub(forgotten.forgot_at_ms) <= self.bounds.result_retention_ms
                {
                    if let Some(expected) = &forgotten.content {
                        check_digest(expected, &method, &payload)?;
                    }
                }
            }
            // All live markers match (or are content-less): fill empties so
            // later mismatches reject, then suppress (no new pending).
            let digest = digest_content(&method, &payload);
            if let Some(slot) = st.tombstones.entries.get_mut(&did) {
                if slot.content.is_none() {
                    slot.content = Some(digest);
                }
            }
            if let Some(slot) = st.outcomes.forgotten.get_mut(&did) {
                if now_ms.saturating_sub(slot.forgot_at_ms) <= self.bounds.result_retention_ms
                    && slot.content.is_none()
                {
                    slot.content = Some(digest);
                }
            }
            st.last_activity_ms = now_ms;
            return Ok(());
        }
        st.outcomes
            .note_dispatch(&self.bounds, now_ms, did, method, payload)?;
        st.tombstones.entries.remove(&did);
        st.last_activity_ms = now_ms;
        Ok(())
    }
    /// Record a terminal deadline/cancel tombstone.
    ///
    /// Outcomes and tombstones stay exclusive: tombstoning a delivery with a
    /// live retained result is rejected with FAILED_PRECONDITION (the retained
    /// outcome is preserved). Expired retained handling is expire-then-tombstone:
    /// an expired retained entry is removed (bytes freed, digest carried into
    /// the new tombstone) and the tombstone is recorded, consistent with
    /// `note_dispatch` replacing expired retained without a reaper. A live
    /// forgotten marker may coexist (reconcile still reports Forgotten until it
    /// expires, then the tombstone surfaces); pending content is carried into
    /// the tombstone digest and the pending charge is released.
    pub fn record_tombstone(
        &self,
        now_ms: u64,
        session_id: &[u8],
        expected_epoch: u64,
        delivery_id: &[u8],
        code: ErrorCode,
    ) -> Result<(), SyntraError> {
        let sid = validate_session_id(session_id)?;
        let did = validate_delivery_id(delivery_id)?;
        let mut inner = self.lock()?;
        let st = inner
            .sessions
            .get_mut(&sid)
            .ok_or_else(|| failed_precondition("unknown session for tombstone"))?;
        if st.epoch != expected_epoch {
            return Err(failed_precondition(
                "stale attachment epoch; fenced connection cannot tombstone",
            ));
        }
        // P2: outcomes and tombstones stay exclusive while retained is live.
        let mut expired_digest: Option<ContentDigest> = None;
        if let Some(existing) = st.outcomes.entries.get(&did) {
            if now_ms.saturating_sub(existing.retained_at_ms) <= self.bounds.result_retention_ms {
                return Err(failed_precondition(
                    "tombstone conflicts with live retained outcome",
                ));
            }
            // Expired: capture digest for carry-over, then remove below.
            expired_digest = Some(digest_content(&existing.method, &existing.payload));
        }
        // Capture content for future resend validation: prefer pending
        // (executing work), else the expired retained just observed, else copy
        // a live forgotten digest for consistency, else content-less (the first
        // live resend after tombstoning will define it).
        let content: Option<ContentDigest> = if let Some(pending) = st.outcomes.pending.get(&did) {
            Some(digest_content(&pending.method, &pending.payload))
        } else if expired_digest.is_some() {
            expired_digest
        } else if let Some(forgotten) = st.outcomes.forgotten.get(&did) {
            if now_ms.saturating_sub(forgotten.forgot_at_ms) <= self.bounds.result_retention_ms {
                forgotten.content
            } else {
                None
            }
        } else {
            None
        };
        // Expire-then-tombstone: record the tombstone first so a failed
        // record preserves the expired terminal state; only free the entry's
        // bytes after the tombstone is durably recorded.
        st.tombstones
            .record(&self.bounds, now_ms, did, code, content)?;
        if expired_digest.is_some() {
            if let Some(removed) = st.outcomes.entries.remove(&did) {
                st.outcomes.bytes = st.outcomes.bytes.saturating_sub(removed.byte_len());
            }
        }
        st.outcomes.release_pending(&did);
        Ok(())
    }
    pub fn tombstone_of(
        &self,
        now_ms: u64,
        session_id: &[u8],
        delivery_id: &[u8],
    ) -> Result<Option<ErrorCode>, SyntraError> {
        let sid = validate_session_id(session_id)?;
        let did = validate_delivery_id(delivery_id)?;
        let inner = self.lock()?;
        let st = inner
            .sessions
            .get(&sid)
            .ok_or_else(|| failed_precondition("unknown session for tombstone lookup"))?;
        Ok(st
            .tombstones
            .get(now_ms, self.bounds.tombstone_retention_ms, &did))
    }
    pub fn revoke(&self, now_ms: u64, credential: &[u8]) -> Result<bool, SyntraError> {
        let cred = validate_resume_credential(credential)?;
        let mut inner = self.lock()?;
        if !inner.revoked.contains_key(&cred.0) {
            let total = inner.resume_index.len().saturating_add(inner.revoked.len());
            if total >= self.bounds.max_resume_credentials.saturating_mul(2) {
                return Err(resource("revocation set exhausted; retire sessions"));
            }
        }
        let removed = inner.resume_index.remove(&cred.0).is_some();
        if !inner.revoked.contains_key(&cred.0) {
            let exp = now_ms.saturating_add(self.bounds.resume_lifetime_ms);
            inner.revoked.insert(cred.0, exp);
        }
        Ok(removed)
    }
    pub fn poll_idle(&self, now_ms: u64) -> Result<Vec<(SessionId, SessionSignal)>, SyntraError> {
        let mut inner = self.lock()?;
        // Cap the batch at the remaining control-queue capacity (both count
        // and bytes, 32 per signal) so every collected signal can be pushed
        // without error.
        let remaining_slots = self
            .bounds
            .max_control_queue
            .saturating_sub(inner.signals.len());
        let remaining_bytes = self
            .bounds
            .max_control_bytes
            .saturating_sub(inner.signals.bytes);
        let remaining_by_bytes = remaining_bytes / 32;
        let capacity = remaining_slots.min(remaining_by_bytes);
        let mut idle: Vec<(SessionId, SessionSignal)> = Vec::new();
        for (id, st) in inner.sessions.iter() {
            if idle.len() >= capacity {
                break;
            }
            if st.active_connection.is_some()
                && now_ms.saturating_sub(st.last_activity_ms) > u64::from(st.lease.idle_timeout_ms)
            {
                idle.push((*id, SessionSignal::IdleTimeout));
            }
        }
        for (id, sig) in &idle {
            inner.signals.push(&self.bounds, *id, *sig)?;
        }
        for (id, _) in &idle {
            if let Some(st) = inner.sessions.get_mut(id) {
                st.active_connection.take();
            }
        }
        Ok(idle)
    }
    pub fn signal(&self, session_id: &[u8], signal: SessionSignal) -> Result<(), SyntraError> {
        let sid = validate_session_id(session_id)?;
        let mut inner = self.lock()?;
        if !inner.sessions.contains_key(&sid) {
            return Err(failed_precondition("unknown session for signal"));
        }
        inner.signals.push(&self.bounds, sid, signal)
    }
    pub fn drain_signals(&self, limit: usize) -> Vec<(SessionId, SessionSignal)> {
        let capped = limit.min(self.bounds.max_control_queue).max(1);
        match self.lock() {
            Ok(mut inner) => inner.signals.drain(capped),
            Err(_) => Vec::new(),
        }
    }
    pub fn session_count(&self) -> usize {
        self.lock().map(|g| g.sessions.len()).unwrap_or(0)
    }
    pub fn signal_len(&self) -> usize {
        self.lock().map(|g| g.signals.len()).unwrap_or(0)
    }
    pub fn reap_expired(&self, now_ms: u64) -> (usize, usize, usize, usize) {
        let Ok(mut inner) = self.lock() else {
            return (0, 0, 0, 0);
        };
        let mut o = 0;
        let mut t = 0;
        for st in inner.sessions.values_mut() {
            o += st
                .outcomes
                .reap_expired(&self.bounds, now_ms, self.bounds.result_retention_ms);
            t += st
                .tombstones
                .reap_expired(now_ms, self.bounds.tombstone_retention_ms);
        }
        let before = inner.resume_index.len();
        inner.resume_index.retain(|_, e| now_ms <= e.expires_at_ms);
        let resume_reaped = before.saturating_sub(inner.resume_index.len());
        let before_rev = inner.revoked.len();
        inner.revoked.retain(|_, exp| now_ms <= *exp);
        let revoked_reaped = before_rev.saturating_sub(inner.revoked.len());
        (o, t, resume_reaped, revoked_reaped)
    }
    pub fn drain_for_shutdown(&self) -> Vec<(SessionId, SessionSignal)> {
        let Ok(mut inner) = self.lock() else {
            return Vec::new();
        };
        inner.draining = true;
        let mut ids: Vec<SessionId> = Vec::new();
        for (id, st) in inner.sessions.iter_mut() {
            if st.active_connection.take().is_some() {
                ids.push(*id);
            }
        }
        let mut out = inner.signals.drain(self.bounds.max_control_queue);
        out.extend(ids.into_iter().map(|id| (id, SessionSignal::GoingAway)));
        out
    }
    pub fn epoch_of(&self, session_id: &[u8]) -> Result<u64, SyntraError> {
        let sid = validate_session_id(session_id)?;
        let inner = self.lock()?;
        inner
            .sessions
            .get(&sid)
            .map(|s| s.epoch)
            .ok_or_else(|| failed_precondition("unknown session"))
    }
}
fn generate_session_id() -> Result<SessionId, SyntraError> {
    let mut buf = [0u8; syntra_core::reliable::SESSION_ID_LEN];
    fill_random(&mut buf).map_err(|e| internal(&format!("session id RNG failed: {e}")))?;
    if buf == [0u8; syntra_core::reliable::SESSION_ID_LEN] {
        return Err(internal("session id RNG returned zero"));
    }
    Ok(SessionId(buf))
}
fn generate_resume_credential() -> Result<Vec<u8>, SyntraError> {
    let mut buf = vec![0u8; syntra_core::reliable::RESUME_CREDENTIAL_LEN];
    fill_random(&mut buf).map_err(|e| internal(&format!("resume RNG failed: {e}")))?;
    if buf.iter().all(|&b| b == 0) {
        return Err(internal("resume RNG returned zero"));
    }
    Ok(buf)
}
pub fn now_ms() -> u64 {
    use web_time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}
#[cfg(test)]
mod tests {
    use super::*;
    use syntra_core::reliable::LeaseProposal;
    fn bounds() -> ControlBounds {
        ControlBounds {
            max_sessions: 4,
            max_retained_results: 4,
            max_retained_bytes: 4096,
            max_tombstones: 4,
            max_resume_credentials: 8,
            max_control_queue: 8,
            max_control_bytes: 1024,
            result_retention_ms: 60_000,
            tombstone_retention_ms: 60_000,
            resume_lifetime_ms: 60_000,
        }
    }
    fn proposal() -> LeaseProposal {
        LeaseProposal {
            idle_timeout_ms: 10_000,
            keepalive_interval_ms: 2_000,
        }
    }
    fn manager() -> ReliableSessionManager {
        ReliableSessionManager::new(bounds()).expect("bounds")
    }
    #[test]
    fn manager_debug_does_not_dump_credentials_or_application_content() {
        let m = manager();
        let (sid, _, cred, _) = m
            .create_session(1_000, "private-principal".into(), 1, proposal())
            .unwrap();
        m.attach(
            1_001,
            &sid.0,
            &[],
            "private-connection".into(),
            "private-principal",
            1,
            proposal(),
        )
        .unwrap();
        m.note_dispatch(
            1_002,
            &sid.0,
            1,
            &[7u8; 16],
            "/private.Service/Method".into(),
            b"private-payload".to_vec(),
        )
        .unwrap();
        let debug = format!("{m:?}");
        assert!(!debug.contains(&format!("{cred:?}")));
        assert!(!debug.contains("private-"));
        m.revoke(1_003, &cred).unwrap();
        assert!(!format!("{m:?}").contains(&format!("{cred:?}")));
    }
    #[test]
    fn create_and_attach() {
        let m = manager();
        let (sid, epoch, cred, lease) = m
            .create_session(1_000, "svc-a".to_string(), 1, proposal())
            .expect("create");
        assert_eq!(epoch, 1);
        assert_eq!(cred.len(), 32);
        assert!(lease.keepalive_interval_ms < lease.idle_timeout_ms);
        let (e, _, f, r) = m
            .attach(
                1_001,
                &sid.0,
                &[],
                "conn-1".to_string(),
                "svc-a",
                1,
                proposal(),
            )
            .expect("attach");
        assert_eq!(e, 1);
        assert!(f.is_none());
        assert!(r.is_none());
    }
    #[test]
    fn resume_fences() {
        let m = manager();
        let (sid, _, cred, _) = m
            .create_session(1_000, "svc-a".to_string(), 1, proposal())
            .expect("create");
        m.attach(
            1_001,
            &sid.0,
            &[],
            "conn-1".to_string(),
            "svc-a",
            1,
            proposal(),
        )
        .expect("first");
        let (e2, _, fenced, rotated) = m
            .attach(
                1_002,
                &sid.0,
                &cred,
                "conn-2".to_string(),
                "svc-a",
                1,
                proposal(),
            )
            .expect("resume");
        assert_eq!(e2, 2);
        assert_eq!(fenced.as_deref(), Some("conn-1"));
        let rotated = rotated.expect("resume must rotate credential");
        assert_eq!(rotated.len(), 32);
        assert_ne!(rotated, cred);
        assert!(m
            .attach(
                1_003,
                &sid.0,
                &cred,
                "conn-3".to_string(),
                "svc-a",
                1,
                proposal()
            )
            .is_err());
    }
    #[test]
    fn reconcile_flow() {
        let m = manager();
        let (sid, _, _, _) = m
            .create_session(1_000, "svc-a".to_string(), 1, proposal())
            .expect("create");
        m.attach(
            1_001,
            &sid.0,
            &[],
            "conn-1".to_string(),
            "svc-a",
            1,
            proposal(),
        )
        .expect("attach");
        let did = [7u8; 16];
        let (o, _) = m.reconcile(1_002, &sid.0, &did).expect("r");
        assert_eq!(o, ReconcileOutcome::Unknown);
        m.record_result(
            1_003,
            &sid.0,
            1,
            &did,
            "/example.Echo/Echo".to_string(),
            b"h".to_vec(),
            StoredOutcome::Payload(b"h".to_vec()),
        )
        .expect("rec");
        let (o2, _) = m.reconcile(1_004, &sid.0, &did).expect("r2");
        assert_eq!(o2, ReconcileOutcome::Retained);
        assert!(m
            .record_result(
                1_005,
                &sid.0,
                1,
                &did,
                "/example.Echo/Echo".to_string(),
                b"x".to_vec(),
                StoredOutcome::Payload(b"x".to_vec())
            )
            .is_err());
        let (o3, _) = m.reconcile(61_003 + 1_003, &sid.0, &did).expect("r3");
        assert_eq!(o3, ReconcileOutcome::Forgotten);
    }
    #[test]
    fn tombstone_flow() {
        let m = manager();
        let (sid, _, _, _) = m
            .create_session(1_000, "svc-a".to_string(), 1, proposal())
            .expect("create");
        m.attach(
            1_001,
            &sid.0,
            &[],
            "conn-1".to_string(),
            "svc-a",
            1,
            proposal(),
        )
        .expect("attach");
        m.record_tombstone(1_002, &sid.0, 1, &[11u8; 16], ErrorCode::DeadlineExceeded)
            .expect("t");
        assert_eq!(
            m.tombstone_of(1_003, &sid.0, &[11u8; 16]).expect("l"),
            Some(ErrorCode::DeadlineExceeded)
        );
        // UNAVAILABLE is unknown-outcome, never tombstoned.
        assert!(m
            .record_tombstone(1_004, &sid.0, 1, &[12u8; 16], ErrorCode::Unavailable)
            .is_err());
        // A live tombstone reconciles to the terminal error, not Unknown.
        let (o, stored) = m
            .reconcile(1_005, &sid.0, &[11u8; 16])
            .expect("reconcile tombstone");
        assert_eq!(o, ReconcileOutcome::Retained);
        match stored {
            Some(StoredOutcome::Error { code, .. }) => {
                assert_eq!(code, ErrorCode::DeadlineExceeded)
            }
            other => panic!("expected tombstoned error, got {other:?}"),
        }
    }
    #[test]
    fn fenced_connection_cannot_complete() {
        let m = manager();
        let (sid, _, cred, _) = m
            .create_session(1_000, "svc-a".to_string(), 1, proposal())
            .expect("create");
        m.attach(
            1_001,
            &sid.0,
            &[],
            "conn-1".to_string(),
            "svc-a",
            1,
            proposal(),
        )
        .expect("first");
        // Advance the epoch: conn-1 is now fenced.
        let (e2, _, _, rotated) = m
            .attach(
                1_002,
                &sid.0,
                &cred,
                "conn-2".to_string(),
                "svc-a",
                1,
                proposal(),
            )
            .expect("resume");
        assert_eq!(e2, 2);
        let _ = rotated;
        let did = [9u8; 16];
        // Stale epoch (conn-1) cannot record, forget, or tombstone.
        assert!(m
            .record_result(
                1_003,
                &sid.0,
                1,
                &did,
                "/a/B/C".to_string(),
                b"p".to_vec(),
                StoredOutcome::Payload(b"p".to_vec())
            )
            .is_err());
        assert!(m.forget(1_003, &sid.0, 1, &did).is_err());
        assert!(m
            .record_tombstone(1_003, &sid.0, 1, &did, ErrorCode::Cancelled)
            .is_err());
        // Current epoch (conn-2) works.
        m.record_result(
            1_004,
            &sid.0,
            2,
            &did,
            "/a/B/C".to_string(),
            b"p".to_vec(),
            StoredOutcome::Payload(b"p".to_vec()),
        )
        .expect("current epoch records");
        assert!(m
            .forget(1_005, &sid.0, 2, &did)
            .expect("current epoch forgets"));
    }
    #[test]
    fn idle_and_drain_bounded() {
        let m = manager();
        let (sid, _, _, _) = m
            .create_session(1_000, "svc-a".to_string(), 1, proposal())
            .expect("create");
        m.attach(
            1_001,
            &sid.0,
            &[],
            "conn-1".to_string(),
            "svc-a",
            1,
            proposal(),
        )
        .expect("attach");
        let s = m.poll_idle(12_001).expect("poll");
        assert_eq!(s.len(), 1);
        assert!(m.drain_signals(64).len() <= 8);
        let _ = m.drain_for_shutdown();
        assert!(m
            .create_session(99_999, "svc-b".to_string(), 1, proposal())
            .is_err());
    }
}
