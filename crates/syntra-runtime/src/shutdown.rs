//! Retained RFC0008 D5 ownership. A Core close is not a carrier/task join.
use crate::{
    connection::{Connection, TaskHandle},
    elapsed::ElapsedClock,
};
use std::{
    sync::{atomic::Ordering, Mutex},
    time::Duration,
};
use syntra_core::SyntraError;
use web_time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    Running,
    Pending,
    ShutdownIncomplete,
    /// Quiescent and joined, not a claim that tasks succeeded. Inspect failed_tasks.
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    pub phase: ShutdownPhase,
    pub pending_calls: usize,
    pub owned_tasks: usize,
    pub live_executions: usize,
    pub transport_closed: bool,
    pub transport_tasks: usize,
    /// Queued frames plus outstanding reserved writer slots. A held permit is
    /// still owned output capacity even before its Vec has been enqueued.
    pub queued_frames: usize,
    /// Joined task panics/failures, distinct from whether work has terminated.
    pub failed_tasks: usize,
}

/// One immutable budget in the connection's elapsed domain. Repeated shutdown
/// requests do not extend it. Positive totals reserve positive teardown time.
#[derive(Clone)]
pub struct ShutdownBudget {
    pub clock: ElapsedClock,
    pub deadline: Instant,
    pub drain_cutoff: Instant,
}
impl ShutdownBudget {
    pub fn new(clock: ElapsedClock, total: Duration) -> Result<Self, SyntraError> {
        crate::validate_close_grace(total)?;
        let deadline = clock.now() + total;
        let reserve = (total / 4)
            .max(Duration::from_nanos(1))
            .min(Duration::from_secs(1))
            .min(total);
        Ok(Self {
            clock,
            deadline,
            drain_cutoff: deadline - reserve,
        })
    }
}

#[derive(Default)]
pub(crate) struct TaskGroup(Mutex<Vec<TaskHandle>>, std::sync::atomic::AtomicUsize);
impl TaskGroup {
    pub(crate) fn register(&self, task: TaskHandle) {
        let mut tasks = self.0.lock().unwrap();
        tasks.retain(|t| {
            let done = t.reap();
            if done && t.failed() {
                self.1.fetch_add(1, Ordering::Relaxed);
            }
            !done
        });
        tasks.push(task);
    }
    pub(crate) fn pending(&self) -> usize {
        let mut tasks = self.0.lock().unwrap();
        tasks.retain(|t| {
            let done = t.reap();
            if done && t.failed() {
                self.1.fetch_add(1, Ordering::Relaxed);
            }
            !done
        });
        tasks.len()
    }
    pub(crate) async fn join_until(&self, clock: &ElapsedClock, deadline: Instant) {
        let join = std::future::poll_fn(|cx| {
            let mut tasks = self.0.lock().unwrap();
            tasks.retain(|t| {
                let done = t.poll_join(cx).is_ready();
                if done && t.failed() {
                    self.1.fetch_add(1, Ordering::Relaxed);
                }
                !done
            });
            if tasks.is_empty() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        });
        let _ = clock.timeout_until(deadline, join).await;
    }
}

pub(crate) struct ShutdownState {
    pub budget: ShutdownBudget,
    pub owner: TaskHandle,
}

/// Shared join ownership: dropping/cancelling the adapter's waiter cannot detach
/// its task from the connection's retained registry.
#[derive(Clone)]
pub struct OwnedTask(pub(crate) TaskHandle);
impl OwnedTask {
    pub fn abort(&self) {
        self.0.abort();
    }
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }
    pub async fn join_until(&self, clock: &ElapsedClock, deadline: Instant) -> bool {
        if self.0.reap() {
            return true;
        }
        clock
            .timeout_until(deadline, std::future::poll_fn(|cx| self.0.poll_join(cx)))
            .await
            .is_ok()
    }
}

impl Connection {
    pub fn shutdown_budget(&self) -> Option<ShutdownBudget> {
        self.shared
            .shutdown
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.budget.clone())
    }
    #[cfg(not(target_arch = "wasm32"))]
    /// Adopt one of an adapter's bounded set of native I/O tasks. Never use this
    /// as an unbounded per-request spawn API; handlers use execution leases.
    /// Adoption after shutdown requests abort and still retain the task's join.
    pub fn own_native_task(&self, handle: tokio::task::JoinHandle<()>) -> OwnedTask {
        let _shutdown = self.shared.shutdown.lock().unwrap();
        let task = TaskHandle::from_native(handle);
        if self.shared.shutdown_requested.load(Ordering::Acquire) {
            task.abort();
        }
        self.shared.tasks.register(task.clone());
        OwnedTask(task)
    }
    pub(crate) fn start_shutdown(
        &self,
        total: Duration,
        start: impl FnOnce(ShutdownBudget) -> TaskHandle,
    ) -> Result<(), SyntraError> {
        crate::validate_close_grace(total)?;
        let mut state = self.shared.shutdown.lock().unwrap();
        if state.is_none() {
            let budget = ShutdownBudget::new(self.shared.clock.clone(), total)?;
            self.shared
                .shutdown_requested
                .store(true, Ordering::Release);
            let owner = start(budget.clone());
            *state = Some(ShutdownState { budget, owner });
        }
        Ok(())
    }

    /// Local carrier-owner attestation: the carrier is gone, all partial units
    /// were finished or abandoned with it, and no old I/O callback can use it.
    /// This never follows from a remote message or from Core CLOSED alone.
    pub fn acknowledge_transport_closed(&self) {
        let _handoff = self.shared.emissions.lock().unwrap();
        self.shared.transport_closed.store(true, Ordering::Release);
    }

    /// Declare externally owned I/O tasks before starting them. Decrement only
    /// after actual join, not abort-request or dropping a foreign future.
    pub fn register_transport_tasks(&self, count: usize) -> Result<(), SyntraError> {
        let _shutdown = self.shared.shutdown.lock().unwrap();
        if count == 0 || count > 1024 || self.shared.shutdown_requested.load(Ordering::Acquire) {
            return Err(SyntraError::ResourceExhausted(
                "invalid transport ownership registration".into(),
            ));
        }
        self.shared
            .transport_tasks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(count).filter(|n| *n <= 1024)
            })
            .map_err(|_| {
                SyntraError::ResourceExhausted("transport task ownership exhausted".into())
            })?;
        Ok(())
    }
    pub fn acknowledge_transport_task_joined(&self) -> Result<(), SyntraError> {
        self.shared
            .transport_tasks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .map_err(|_| SyntraError::Closed("no transport task to join".into()))?;
        Ok(())
    }

    pub(crate) fn shutdown_report_for(
        &self,
        pending_calls: usize,
        live_executions: usize,
    ) -> ShutdownReport {
        let mut owned_tasks = self.shared.tasks.pending();
        let state = self.shared.shutdown.lock().unwrap();
        let transport_closed = self.shared.transport_closed.load(Ordering::Acquire);
        let transport_tasks = self.shared.transport_tasks.load(Ordering::Acquire);
        let queued_frames = self.shared.writer.max_capacity() - self.shared.writer.capacity();
        let phase = if let Some(state) = state.as_ref() {
            if !state.owner.reap() {
                owned_tasks += 1;
            }
            if self.is_closed()
                && pending_calls == 0
                && owned_tasks == 0
                && live_executions == 0
                && transport_closed
                && transport_tasks == 0
                && queued_frames == 0
            {
                ShutdownPhase::Complete
            } else if !state.budget.clock.is_continuous()
                || state.budget.clock.now() >= state.budget.deadline
            {
                ShutdownPhase::ShutdownIncomplete
            } else {
                ShutdownPhase::Pending
            }
        } else {
            ShutdownPhase::Running
        };
        let failed_tasks = self.shared.tasks.1.load(Ordering::Relaxed)
            + usize::from(state.as_ref().is_some_and(|s| s.owner.failed()));
        ShutdownReport {
            phase,
            pending_calls,
            owned_tasks,
            live_executions,
            transport_closed,
            transport_tasks,
            queued_frames,
            failed_tasks,
        }
    }

    pub(crate) async fn await_shutdown_owner(&self) {
        let state = self
            .shared
            .shutdown
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| (s.owner.clone(), s.budget.clone()));
        if let Some((owner, budget)) = state {
            let _ = budget
                .clock
                .timeout_until(
                    budget.deadline,
                    std::future::poll_fn(|cx| owner.poll_join(cx)),
                )
                .await;
        }
    }
}
