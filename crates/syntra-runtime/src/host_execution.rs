//! Host execution accounting, independent of correlation and result delivery.

use std::sync::{Arc, Mutex};

use tokio::sync::watch;

/// A host- or principal-scoped execution ceiling. Reuse the same budget for
/// replacement connections; creating a fresh budget on reconnect defeats the
/// aggregate bound. This is accounting, not an application task supervisor.
#[derive(Clone)]
pub struct ExecutionBudget {
    inner: Arc<Mutex<BudgetState>>,
}

struct BudgetState {
    limit: usize,
    used: usize,
}

impl ExecutionBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BudgetState { limit, used: 0 })),
        }
    }

    pub fn in_use(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).used
    }

    pub(super) fn try_acquire(&self) -> Option<BudgetPermit> {
        // No await or user code under this lock; a std mutex keeps accounting
        // synchronous on native and wasm, including RAII release on drop.
        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if state.used >= state.limit {
            return None;
        }
        state.used += 1;
        Some(BudgetPermit(self.clone()))
    }
}

pub(super) struct BudgetPermit(ExecutionBudget);

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        self.0.inner.lock().unwrap_or_else(|e| e.into_inner()).used -= 1;
    }
}

/// Transfer/clone this lease into external work *before* spawning it. The last
/// copy must live until that work actually stops, not just until its caller
/// times out. Dropping a HandlerFut alone proves nothing about external effects.
/// The host also keeps a copy while its handler future is live.
#[derive(Clone)]
#[must_use = "retain the lease until execution actually stops"]
pub struct ExecutionLease {
    _charge: Arc<ExecutionCharge>,
}

struct ExecutionCharge {
    // Field drop order releases accounting before notifying the observer.
    _local: BudgetPermit,
    _shared: Option<BudgetPermit>,
    _done: watch::Sender<()>,
}

impl ExecutionLease {
    pub(super) fn acquire(
        local: &ExecutionBudget,
        shared: Option<&ExecutionBudget>,
    ) -> Option<(Self, watch::Receiver<()>)> {
        let local = local.try_acquire()?;
        let shared = match shared {
            Some(budget) => Some(budget.try_acquire()?),
            None => None,
        };
        let (done, observer) = watch::channel(());
        Some((
            Self {
                _charge: Arc::new(ExecutionCharge {
                    _local: local,
                    _shared: shared,
                    _done: done,
                }),
            },
            observer,
        ))
    }
}
