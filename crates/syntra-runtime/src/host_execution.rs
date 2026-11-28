//! Host execution accounting, independent of correlation and result delivery.

use super::{Principal, SyntraError};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::watch;

/// Only the server assigns a class, from the authorized method and bound principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    Interactive,
    Media,
}

/// One pool shared by every host in this authority's scope, including reconnects.
#[derive(Debug, Clone, Copy)]
pub struct OperationLimits {
    /// Reserved within the existing aggregate and each connection's (possibly
    /// smaller) execution cap. A reserve >= the connection cap excludes media.
    pub interactive_executions: usize,
    /// Logical request payload bytes plus reserved encoded result bytes; not RSS.
    pub bytes: usize,
    pub interactive_bytes: usize,
}

/// A positive server decision. `response_frame_bytes` is a hard bound on the
/// encoded result, in 1024..=MAX_FRAME_BYTES. The minimum leaves room for core
/// failures and every prevalidated terminal receipt (including after commit).
pub struct OperationGrant {
    pub class: OperationClass,
    pub response_frame_bytes: usize,
    pub ownership: QuotaOwnership,
}

/// Evidence supplied by the deployment, never inferred from a connection ID.
pub enum QuotaOwnership {
    /// The provider confirms this process is the sole quota owner for the scope.
    ExclusiveProcess,
    /// A provider-owned quota reservation valid until dropped. Drop must be
    /// nonblocking and non-reentrant, including on failed local admission.
    External(Box<dyn Send + Sync>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionRefusal {
    Exhausted,
    /// No positive ownership or quota evidence. Never fall back to local admission.
    Unavailable,
    /// The bound principal is no longer valid. Initiates host withdrawal.
    Revoked,
}

/// A deployment must either route the principal exclusively to the owner of
/// this pool (including during failover), or supply authoritative, non-overlapping
/// external quota tickets. Independent processes' local counters do not compose.
/// Return `Unavailable` on missing/stale ownership or provider failure. Choose
/// class by principal and method only; the payload length is for charging.
/// Called under ordered admission and the lifecycle read guard: use a prompt
/// nonblocking decision, e.g. predelegated capacity, never remote I/O here.
/// This is admission only: use the connection authority watchdog for idle and
/// carrier checks, and check revocation atomically with application mutations.
pub trait OperationAuthority: Send + Sync {
    fn try_admit(
        &self,
        principal: &Principal,
        method: &str,
        request_payload_bytes: usize,
    ) -> Result<OperationGrant, AdmissionRefusal>;
}

struct OperationPolicy {
    limits: OperationLimits,
    bytes: Arc<Pool>,
    authority: Arc<dyn OperationAuthority>,
}

/// A host- or principal-scoped execution ceiling. Reuse the same budget for
/// replacement connections; creating a fresh budget on reconnect defeats the
/// aggregate bound. This is accounting, not an application task supervisor.
#[derive(Clone)]
pub struct ExecutionBudget {
    slots: Arc<Pool>,
    // Some(policy) on explicit configuration; None seals legacy behavior at
    // first shared admission. A sibling clone can never install a fresh pool.
    policy: Arc<OnceLock<Option<OperationPolicy>>>,
}

struct Pool {
    limit: usize,
    used: Mutex<Usage>,
}

#[derive(Default)]
struct Usage {
    total: usize,
    media: usize,
}

impl Pool {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: Mutex::default(),
        })
    }

    fn used(&self) -> usize {
        self.used.lock().unwrap_or_else(|e| e.into_inner()).total
    }

    fn take(self: &Arc<Self>, units: usize, media: bool, reserve: usize) -> Option<Units> {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        let media_available = self
            .limit
            .saturating_sub(reserve)
            .saturating_sub(used.media);
        if units > self.limit - used.total || (media && units > media_available) {
            return None;
        }
        used.total += units;
        if media {
            used.media += units;
        }
        Some(Units {
            pool: self.clone(),
            units,
            media,
        })
    }
}

struct Units {
    pool: Arc<Pool>,
    units: usize,
    media: bool,
}

impl Drop for Units {
    fn drop(&mut self) {
        let mut used = self.pool.used.lock().unwrap_or_else(|e| e.into_inner());
        used.total -= self.units;
        if self.media {
            used.media -= self.units;
        }
    }
}

impl ExecutionBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            slots: Pool::new(limit),
            policy: Arc::default(),
        }
    }

    /// Install once, before the first shared execution, on the existing factory
    /// budget. All clones use the same policy and counters, even earlier clones.
    /// Return clones from `execution_budget`, including for replacements. A new
    /// independently constructed budget is a different authority scope.
    pub fn configure_operations(
        &self,
        limits: OperationLimits,
        authority: Arc<dyn OperationAuthority>,
    ) -> Result<(), SyntraError> {
        if limits.interactive_executions > self.slots.limit
            || limits.interactive_bytes > limits.bytes
        {
            return Err(SyntraError::Protocol {
                code: syntra_core::ErrorCode::InvalidArgument,
                message: "interactive reserve exceeds aggregate budget".into(),
            });
        }
        self.policy
            .set(Some(OperationPolicy {
                limits,
                bytes: Pool::new(limits.bytes),
                authority,
            }))
            .map_err(|_| SyntraError::Protocol {
                code: syntra_core::ErrorCode::FailedPrecondition,
                message: "execution policy already configured or in use".into(),
            })
    }

    pub fn in_use(&self) -> usize {
        self.slots.used()
    }

    /// Reserved through both execution (including external copies) and core
    /// output. The managed writer retains the charge through the complete frame
    /// write or abort. With a raw `Receiver<Vec<u8>>`, ordinary output accounting
    /// ends at channel handoff; terminal receipts carry their own charge.
    pub fn bytes_in_use(&self) -> usize {
        self.policy
            .get()
            .and_then(Option::as_ref)
            .map_or(0, |p| p.bytes.used())
    }

    pub(super) fn try_acquire(&self) -> Option<BudgetPermit> {
        Some(BudgetPermit {
            _slot: self.slots.take(1, false, 0)?,
            operation: None,
        })
    }
}

pub(super) struct BudgetPermit {
    _slot: Units,
    operation: Option<Arc<OperationCharge>>,
}

/// Private native driver boundary: one serialized ordinary frame and its optional
/// operation charge, in a single bounded queue item. No charge for control frames.
#[doc(hidden)]
pub struct ManagedOutput {
    bytes: Vec<u8>,
    _operation: Option<Arc<OperationCharge>>,
}

impl ManagedOutput {
    /// Move the buffer to the writer. Retain this owner across authorization,
    /// every record's last write poll, and any intermediate backpressure.
    pub fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl From<Vec<u8>> for ManagedOutput {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            _operation: None,
        }
    }
}

impl BudgetPermit {
    pub(super) fn managed_output(&mut self, bytes: Vec<u8>) -> ManagedOutput {
        ManagedOutput {
            bytes,
            _operation: self.operation.take(),
        }
    }
}

struct OperationCharge {
    grant: OperationGrant,
    _bytes: Units,
}

/// Transfer/clone this lease into external work *before* spawning it. The last
/// copy must live until that work actually stops, not just until its caller
/// times out. Dropping a HandlerFut alone proves nothing about external effects.
/// The host also keeps a copy while its handler future is live.
#[derive(Clone)]
#[must_use = "retain the lease until execution actually stops"]
pub struct ExecutionLease {
    charge: Arc<ExecutionCharge>,
}

struct ExecutionCharge {
    // Field drop order releases accounting before notifying the observer.
    _local: Units,
    _shared: Option<Units>,
    operation: Option<Arc<OperationCharge>>,
    _done: watch::Sender<()>,
}

pub(super) type Execution = (ExecutionLease, watch::Receiver<()>);

impl ExecutionLease {
    pub(super) fn acquire(
        local: &ExecutionBudget,
        shared: Option<&ExecutionBudget>,
        principal: &Principal,
        method: &str,
        payload_bytes: usize,
    ) -> Result<Execution, AdmissionRefusal> {
        let mut media = false;
        let mut reserve = 0;
        let operation =
            if let Some(policy) = shared.and_then(|s| s.policy.get_or_init(|| None).as_ref()) {
                let grant = policy
                    .authority
                    .try_admit(principal, method, payload_bytes)?;
                if !(super::terminal::MAX_RECEIPT_FRAME_BYTES..=syntra_core::MAX_FRAME_BYTES)
                    .contains(&grant.response_frame_bytes)
                {
                    return Err(AdmissionRefusal::Unavailable);
                }
                media = grant.class == OperationClass::Media;
                reserve = policy.limits.interactive_executions;
                let bytes = payload_bytes
                    .checked_add(grant.response_frame_bytes)
                    .ok_or(AdmissionRefusal::Exhausted)?;
                let bytes = policy
                    .bytes
                    .take(bytes, media, policy.limits.interactive_bytes)
                    .ok_or(AdmissionRefusal::Exhausted)?;
                Some(Arc::new(OperationCharge {
                    grant,
                    _bytes: bytes,
                }))
            } else {
                None
            };
        let slot = |b: &ExecutionBudget| {
            b.slots
                .take(1, media, reserve)
                .ok_or(AdmissionRefusal::Exhausted)
        };
        let local = slot(local)?;
        let shared = shared.map(slot).transpose()?;
        let (done, observer) = watch::channel(());
        Ok((
            Self {
                charge: Arc::new(ExecutionCharge {
                    _local: local,
                    _shared: shared,
                    operation,
                    _done: done,
                }),
            },
            observer,
        ))
    }

    /// The handler should bound production before allocating. The host checks
    /// the encoded frame again before selecting the handler's result.
    pub fn response_frame_bytes(&self) -> usize {
        self.charge
            .operation
            .as_ref()
            .map_or(syntra_core::MAX_FRAME_BYTES, |o| {
                o.grant.response_frame_bytes
            })
    }

    pub(super) fn retain_output(&self, output: &mut BudgetPermit) {
        output.operation = self.charge.operation.clone();
    }
}
