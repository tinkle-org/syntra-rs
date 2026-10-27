//! RPC mechanics: method identifiers, request-ids, pending correlation.
//!
//! `SNTR-RPC-001/002/008`, clarified in rpc.md sections 1B/1C:
//! - method = canonical `/package.Service/Method` (printable-ASCII path
//!   rule); malformed methods yield terminal `INVALID_ARGUMENT` for the
//!   affected RPC — the connection stays usable, no socket is closed;
//! - `request_id` is the `uint64` correlation field of the enclosing
//!   `Frame` (not a field of `RpcRequest`), initiator-chosen, nonzero,
//!   unique among *outstanding* RPCs on that connection only;
//! - duplicate *outstanding* ids reject the new attempt with
//!   `FAILED_PRECONDITION` while the original continues untouched;
//! - reuse after a terminal `result` is permitted by the core model;
//!   whether a stale replay is also rejected is the open conflict B3 —
//!   this crate enforces duplicate-*outstanding* only and documents it.
//!
//! `request_id` MUST NOT be used for cross-connection deduplication;
//! durable continuity uses the application operation key in the payload
//! (SNTR-RPC-007/010).

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use tokio::sync::oneshot;

use crate::error::{ErrorCode, SyntraError};
use crate::proto::RpcResult;

/// Validate an `RpcRequest.method` before sending or dispatching.
///
/// Wire syntax is canonical `/package.Service/Method`: leading slash,
/// exactly two slashes, non-empty segments, ASCII printable excluding
/// spaces/control (bytes `0x21..=0x7E`), byte-exact case-sensitive match,
/// no normalization. Returns `INVALID_ARGUMENT` on violation; callers
/// map this to a terminal per-RPC error, never to connection teardown.
pub fn validate_method(method: &str) -> Result<(), SyntraError> {
    if method.is_empty() || method.len() > 512 {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "method must be 1..512 bytes".to_string(),
        });
    }
    if !method.starts_with('/') {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "method must start with '/'".to_string(),
        });
    }
    if method.matches('/').count() != 2 {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "method must be /package.Service/Method".to_string(),
        });
    }
    let mut parts = method.split('/');
    let _leading = parts.next(); // "" before the leading slash
    let pkg_svc = parts.next().unwrap_or("");
    let meth = parts.next().unwrap_or("");
    // Exactly two slashes means no fourth segment; check explicitly.
    if parts.next().is_some() {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "method must contain exactly two '/'".to_string(),
        });
    }
    if pkg_svc.is_empty() || meth.is_empty() {
        return Err(SyntraError::Protocol {
            code: ErrorCode::InvalidArgument,
            message: "method segments must be non-empty".to_string(),
        });
    }
    for seg in [pkg_svc, meth] {
        for b in seg.bytes() {
            // Printable ASCII excluding space (0x20), controls, and DEL.
            // '/' (0x2F) cannot appear: the two-slash count forbids it.
            if !(0x21..=0x7E).contains(&b) {
                return Err(SyntraError::Protocol {
                    code: ErrorCode::InvalidArgument,
                    message: "method must be ASCII printable excluding spaces/control".to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Allocates nonzero ids unique among outstanding RPCs.
///
/// The allocator hands out monotonically increasing ids (wrapping).
/// Callers MUST check the pending table and skip ids still in use
/// (see `PendingTable::is_pending`), because reuse-after-completion is
/// permitted but duplicate-*outstanding* is rejected with
/// `FAILED_PRECONDITION`.
#[derive(Debug, Default)]
pub struct RequestIdAllocator {
    next: AtomicU64,
}

impl RequestIdAllocator {
    pub fn new() -> Self {
        // Start at 1; 0 is never valid for RPC.
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Return the next candidate id (nonzero). The caller must verify
    /// it is not currently outstanding and retry on collision (wraparound).
    pub fn next_candidate(&self) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        // fetch_add returns the previous value; skip 0 on wrap.
        if id == 0 {
            self.next.fetch_add(1, Ordering::Relaxed)
        } else {
            id
        }
    }

    /// Reset the id space. Called only when the connection dies;
    /// the id space dies with the connection.
    pub fn reset(&self) {
        self.next.store(1, Ordering::Relaxed);
    }
}

/// Outcome delivered to one waiter.
#[derive(Debug)]
pub enum PendingOutcome {
    Result(RpcResult),
    TransportLost,
}

/// One outstanding RPC.
#[derive(Debug)]
struct Slot {
    tx: oneshot::Sender<PendingOutcome>,
    method: String,
}

/// Bounded correlation table: each RPC uses a nonzero initiator-chosen
/// `request_id` unique among concurrent RPCs. Exactly one terminal
/// `RpcResult` with the same id completes the RPC. `cancel` for
/// unknown/completed ids is ignored; duplicate outstanding ids are
/// rejected with `FAILED_PRECONDITION` while the original waiter keeps
/// running; `result` for an unknown id is ignored with a diagnostic
/// (no error storm).
#[derive(Debug, Default)]
pub struct PendingTable {
    inner: Mutex<HashMap<u64, Slot>>,
    max_outstanding: usize,
}

impl PendingTable {
    pub fn new(max_outstanding: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_outstanding,
        }
    }

    /// Register a new RPC. Rejects duplicate outstanding ids
    /// (`FAILED_PRECONDITION`, original untouched) and excess
    /// concurrency (`RESOURCE_EXHAUSTED`).
    pub fn insert(
        &self,
        id: u64,
        method: String,
    ) -> Result<oneshot::Receiver<PendingOutcome>, SyntraError> {
        let mut g = self.inner.lock().unwrap();
        if g.contains_key(&id) {
            return Err(SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: "duplicate outstanding request_id".to_string(),
            });
        }
        if g.len() >= self.max_outstanding {
            return Err(SyntraError::ResourceExhausted(
                "too many outstanding RPCs".to_string(),
            ));
        }
        let (tx, rx) = oneshot::channel();
        g.insert(id, Slot { tx, method });
        Ok(rx)
    }

    pub fn is_pending(&self, id: u64) -> bool {
        self.inner.lock().unwrap().contains_key(&id)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    /// Complete one RPC with its terminal `result`. Unknown ids are
    /// ignored with a diagnostic (no error storm). Returns true if a
    /// waiter existed.
    pub fn complete(&self, id: u64, result: RpcResult) -> bool {
        let slot = self.inner.lock().unwrap().remove(&id);
        match slot {
            Some(s) => {
                let _ = s.tx.send(PendingOutcome::Result(result));
                true
            }
            None => {
                tracing::debug!(request_id = id, "result for unknown request_id; ignoring");
                false
            }
        }
    }

    /// Remove one waiter without completing (deadline/cancel-abandon).
    /// A late `result` afterwards is ignored as unknown (completion wins
    /// races; abandonment does not cancel the host without `cancel`).
    pub fn abandon(&self, id: u64) {
        self.inner.lock().unwrap().remove(&id);
    }

    /// Drain all waiters on transport loss/close. Each gets
    /// `TransportLost`, which the connection maps to `UNAVAILABLE`
    /// with unknown outcome (SNTR-REL-009).
    pub fn drain_transport_lost(&self) {
        let slots: Vec<Slot> = {
            let mut g = self.inner.lock().unwrap();
            g.drain().map(|(_, s)| s).collect()
        };
        for s in slots {
            let _ = s.tx.send(PendingOutcome::TransportLost);
        }
    }

    #[allow(dead_code)]
    pub fn method_of(&self, id: u64) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .get(&id)
            .map(|s| s.method.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical() {
        assert!(validate_method("/example.Echo/Echo").is_ok());
        assert!(validate_method("/example.KV/Get").is_ok());
        assert!(validate_method("/example.Events/Subscribe").is_ok());
    }

    #[test]
    fn rejects_shorthand_and_malformed() {
        assert!(validate_method("example.echo").is_err());
        assert!(validate_method("/only-one").is_err());
        assert!(validate_method("/a/b/c").is_err());
        assert!(validate_method("//Method").is_err());
        assert!(validate_method("/pkg./").is_err());
        assert!(validate_method("/pkg.Svc/With Space").is_err());
        assert!(validate_method("").is_err());
        assert!(validate_method("/pkg.Svc/With\x7fDel").is_err());
        assert!(validate_method("/pkg.Svc/With\tTab").is_err());
    }

    #[test]
    fn rejects_duplicate_outstanding_keeps_original() {
        let t = PendingTable::new(16);
        let rx = t.insert(7, "/a/B/C".into()).unwrap();
        assert!(t.insert(7, "/a/B/C".into()).is_err());
        // Original entry is untouched: completing it still works.
        assert!(t.is_pending(7));
        drop(rx);
    }

    #[test]
    fn enforces_bound() {
        let t = PendingTable::new(1);
        let _rx = t.insert(1, "/a/B/C".into()).unwrap();
        assert!(matches!(
            t.insert(2, "/a/B/C".into()),
            Err(SyntraError::ResourceExhausted(_))
        ));
    }

    #[test]
    fn never_zero() {
        let a = RequestIdAllocator::new();
        for _ in 0..10_000 {
            assert_ne!(a.next_candidate(), 0);
        }
    }
}
