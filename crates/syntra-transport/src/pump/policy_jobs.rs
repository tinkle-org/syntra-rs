//! Bounded, retained owners for synchronous deployment policy work.
use super::*;
use futures_util::FutureExt;
use std::sync::atomic::{AtomicBool, Ordering};

type Panic = Box<dyn std::any::Any + Send + 'static>;
type Failure = Arc<Mutex<Option<Panic>>>;

struct OwnedJob {
    task: tokio::task::JoinHandle<()>,
    failure: Failure,
}

/// Cancellation-safe waiter. A worker panic is rethrown here, or by the retained
/// owner if this waiter was dropped; it is never an authentication rejection.
pub struct PolicyJob<T> {
    result: oneshot::Receiver<T>,
    failure: Failure,
}

impl<T> Future for PolicyJob<T> {
    type Output = Result<T, oneshot::error::RecvError>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let result = std::pin::Pin::new(&mut self.result).poll(cx);
        if matches!(result, std::task::Poll::Ready(Err(_))) {
            let failure = self
                .failure
                .lock()
                .expect("policy panic owner poisoned")
                .take();
            if let Some(failure) = failure {
                std::panic::resume_unwind(failure);
            }
        }
        result
    }
}

/// A factory-scoped pool, including work whose caller/accept future was dropped.
/// Holding a permit is not evidence of task join; actual JoinHandles are retained
/// and reaped. A panic is resumed, never converted into a successful disposal.
pub struct PolicyJobs {
    slots: Arc<tokio::sync::Semaphore>,
    maximum: usize,
    stopped: AtomicBool,
    tasks: Mutex<Vec<OwnedJob>>,
    shutdown_budget: Mutex<Option<(ElapsedClock, Instant)>>,
}

impl PolicyJobs {
    pub fn new(maximum: usize) -> Result<Arc<Self>, Error> {
        if !(1..=1024).contains(&maximum) {
            return Err(Error::Configuration);
        }
        Ok(Arc::new(Self {
            slots: Arc::new(tokio::sync::Semaphore::new(maximum)),
            maximum,
            stopped: AtomicBool::new(false),
            tasks: Mutex::new(Vec::new()),
            shutdown_budget: Mutex::new(None),
        }))
    }

    // Return failures so callers can release the owner lock before unwinding.
    fn reap(tasks: &mut Vec<OwnedJob>) -> Option<Panic> {
        let mut index = 0;
        while index < tasks.len() {
            if !tasks[index].task.is_finished() {
                index += 1;
                continue;
            }
            let job = tasks.swap_remove(index);
            let failure = job
                .failure
                .lock()
                .expect("policy panic owner poisoned")
                .take();
            if let Some(failure) = failure {
                return Some(failure);
            }
            let task = job.task;
            match task
                .now_or_never()
                .expect("finished policy task is joinable")
            {
                Ok(()) => {}
                Err(error) if error.is_panic() => return Some(error.into_panic()),
                Err(_) => {
                    return Some(Box::new(
                        "owned blocking policy task was unexpectedly cancelled",
                    ));
                }
            }
        }
        None
    }

    /// No unbounded executor queue, and no abort of started blocking work.
    pub fn spawn<T: Send + 'static>(
        self: &Arc<Self>,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<PolicyJob<T>, Error> {
        let mut tasks = self.tasks.lock().map_err(|_| Error::Closed)?;
        if let Some(failure) = Self::reap(&mut tasks) {
            drop(tasks);
            std::panic::resume_unwind(failure);
        }
        if self.stopped.load(Ordering::Acquire) || tasks.len() >= self.maximum {
            return Err(Error::Authentication);
        }
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Authentication)?;
        let (done, result) = oneshot::channel();
        let failure = Arc::new(Mutex::new(None));
        let worker_failure = failure.clone();
        // Keep the owner alive even when the last caller disappears. Its own
        // handle remains accounted until the work exits, not until timeout.
        let owner = self.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _owner = owner;
            let _permit = permit;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) {
                Ok(value) => {
                    let _ = done.send(value);
                } // Cancellation cannot cancel work.
                Err(panic) => {
                    *worker_failure.lock().expect("policy panic owner poisoned") = Some(panic);
                }
            }
        });
        tasks.push(OwnedJob {
            task,
            failure: failure.clone(),
        });
        Ok(PolicyJob { result, failure })
    }

    pub fn pending(&self) -> usize {
        let mut tasks = self.tasks.lock().expect("policy owner lock poisoned");
        if let Some(failure) = Self::reap(&mut tasks) {
            drop(tasks);
            std::panic::resume_unwind(failure);
        }
        tasks.len()
    }

    /// Factory-wide shutdown: explicitly refuse future admissions and policy
    /// jobs, retaining handles for later attempts if this deadline is exhausted.
    /// Callers must quiesce every connection using this factory first.
    pub async fn shutdown(
        &self,
        clock: &ElapsedClock,
        grace: Duration,
    ) -> Result<TransportShutdown, Error> {
        validate_close_grace(grace).map_err(|_| Error::Configuration)?;
        self.stopped.store(true, Ordering::Release);
        let (clock, deadline) = self
            .shutdown_budget
            .lock()
            .map_err(|_| Error::Closed)?
            .get_or_insert_with(|| (clock.clone(), elapsed_now(clock) + grace))
            .clone();
        loop {
            let pending = self.pending();
            if pending == 0 {
                return Ok(TransportShutdown::Complete);
            }
            if !clock.is_continuous() || elapsed_now(&clock) >= deadline {
                return Ok(TransportShutdown::ShutdownIncomplete {
                    carrier_tasks: 0,
                    policy_jobs: pending,
                });
            }
            clock
                .sleep_until(
                    (elapsed_now(&clock) + Duration::from_millis(10))
                        .min(deadline)
                        .into_std(),
                )
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_finished(pool: &PolicyJobs) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool
                .tasks
                .lock()
                .unwrap()
                .iter()
                .any(|job| !job.task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("policy workers must finish");
    }

    #[tokio::test]
    async fn retained_panics_leave_owner_usable_for_every_reaping_caller() {
        for caller in 0..3 {
            let pool = PolicyJobs::new(1).unwrap();
            drop(
                pool.spawn::<()>(|| panic!("retained policy panic"))
                    .unwrap(),
            );
            wait_finished(&pool).await;
            let failure = if caller == 2 {
                std::panic::AssertUnwindSafe(
                    pool.shutdown(&ElapsedClock::lifecycle_driven(), Duration::ZERO),
                )
                .catch_unwind()
                .await
                .expect_err("shutdown must propagate the worker panic")
            } else {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if caller == 0 {
                        pool.pending();
                    } else {
                        let _job = pool.spawn(|| panic!("must not start another worker"));
                    }
                }))
                .expect_err("reaping must propagate the worker panic")
            };
            assert_eq!(
                failure.downcast_ref::<&str>(),
                Some(&"retained policy panic")
            );
            assert!(
                pool.tasks.try_lock().is_ok(),
                "panic must not poison the owner"
            );
            assert_eq!(pool.pending(), 0);
            if caller != 2 {
                assert_eq!(pool.spawn(|| 42).unwrap().await.unwrap(), 42);
                wait_finished(&pool).await;
                assert_eq!(pool.pending(), 0);
            }
            assert_eq!(
                pool.shutdown(&ElapsedClock::lifecycle_driven(), Duration::ZERO)
                    .await
                    .unwrap(),
                TransportShutdown::Complete
            );
        }
    }

    #[tokio::test]
    async fn join_panics_and_unexpected_cancellations_leave_owner_unpoisoned() {
        for cancelled in [false, true] {
            let pool = PolicyJobs::new(1).unwrap();
            let task = if cancelled {
                let task = tokio::spawn(std::future::pending::<()>());
                task.abort();
                task
            } else {
                tokio::spawn(async { panic!("uncaught policy panic") })
            };
            pool.tasks.lock().unwrap().push(OwnedJob {
                task,
                failure: Arc::new(Mutex::new(None)),
            });
            wait_finished(&pool).await;
            let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pool.pending()))
                .expect_err("join failure must not be silently disposed");
            let expected = if cancelled {
                "owned blocking policy task was unexpectedly cancelled"
            } else {
                "uncaught policy panic"
            };
            assert_eq!(failure.downcast_ref::<&str>(), Some(&expected));
            assert!(pool.tasks.try_lock().is_ok());
            assert_eq!(pool.pending(), 0);
        }
    }
}
