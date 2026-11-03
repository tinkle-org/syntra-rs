//! Process-local suspend-inclusive budgets (RFC 0008 D2). Never persist these
//! timestamps. Timer scheduling is only a wakeup hint; gates read the clock again.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use web_time::Instant;

/// A trusted local source, not peer time or an adjustable wall clock. Values must
/// increase across suspend in one process. `None` or regression loses continuity.
/// Sampling must be prompt, nonblocking and non-reentrant: gates call it under
/// short protocol locks. Never perform network, storage or runtime callbacks here.
pub trait ElapsedSource: Send + Sync {
    fn elapsed(&self) -> Option<Duration>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElapsedFailure {
    Deadline,
    ContinuityLost,
}

/// A deadline carrying its own source. Use this across adapter/authorization
/// boundaries instead of comparing unrelated Tokio/std/projected Instants.
#[derive(Clone)]
pub struct ElapsedDeadline {
    clock: ElapsedClock,
    at: Instant,
}
impl ElapsedDeadline {
    pub fn check(&self) -> Result<(), ElapsedFailure> {
        if !self.clock.is_continuous() {
            return Err(ElapsedFailure::ContinuityLost);
        }
        if self.clock.now() >= self.at {
            Err(ElapsedFailure::Deadline)
        } else {
            Ok(())
        }
    }
    pub fn remaining(&self) -> Result<Duration, ElapsedFailure> {
        self.check()?;
        let now = self.clock.now();
        if now >= self.at {
            Err(ElapsedFailure::Deadline)
        } else {
            Ok(self.at - now)
        }
    }
    pub async fn expired(&self) {
        self.clock.sleep_until(self.at).await;
    }
    pub async fn run<T>(
        &self,
        future: impl std::future::Future<Output = T>,
    ) -> Result<T, ElapsedFailure> {
        let value = self.clock.timeout_until(self.at, future).await?;
        // Only unselected I/O/policy units use this stricter post-poll check.
        // Do not discard an already consumed JoinHandle outcome this way.
        self.check()?;
        Ok(value)
    }
}

#[derive(Clone)]
pub struct ElapsedClock(Arc<Inner>);

struct Inner {
    source: Option<Arc<dyn ElapsedSource>>,
    origin: Option<Duration>,
    anchor: Instant,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
}

struct State {
    previous: Duration,
    last: Instant,
    continuous: bool,
}

impl Default for ElapsedClock {
    fn default() -> Self {
        Self::new()
    }
}

impl ElapsedClock {
    pub fn deadline_after(&self, budget: Duration) -> Result<ElapsedDeadline, ElapsedFailure> {
        if !self.is_continuous() {
            return Err(ElapsedFailure::ContinuityLost);
        }
        let at = self
            .now()
            .checked_add(budget)
            .ok_or(ElapsedFailure::ContinuityLost)?;
        Ok(ElapsedDeadline {
            clock: self.clone(),
            at,
        })
    }
    /// Scheduler-only adapter for platforms without a continuous source and for
    /// deterministic executor tests. MUST fence/retire live connections on wake;
    /// this constructor does not claim suspend-inclusive timing by itself.
    pub fn lifecycle_driven() -> Self {
        Self::build(None)
    }

    /// Native Linux/Android use BOOTTIME; Apple uses mach continuous time.
    /// Other targets require lifecycle hints: wake must retire their connection.
    pub fn new() -> Self {
        #[cfg(all(
            not(test),
            any(target_os = "linux", target_os = "android", target_vendor = "apple")
        ))]
        return Self::with_source(Arc::new(PlatformSource));
        #[cfg(any(
            test,
            not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
        ))]
        Self::build(None)
    }

    pub fn with_source(source: Arc<dyn ElapsedSource>) -> Self {
        Self::build(Some(source))
    }

    fn build(source: Option<Arc<dyn ElapsedSource>>) -> Self {
        let anchor = scheduler_now();
        let origin = source.as_ref().and_then(|s| s.elapsed());
        let continuous = source.is_none() || origin.is_some();
        Self(Arc::new(Inner {
            source,
            origin,
            anchor,
            state: Mutex::new(State {
                previous: Duration::ZERO,
                last: anchor,
                continuous,
            }),
            changed: tokio::sync::Notify::new(),
        }))
    }

    /// Project elapsed duration into this clock's local Instant domain. Uses the
    /// greater scheduler/source duration so virtual Tokio tests remain usable.
    /// Failure is sticky and must be checked by the owner before protected work.
    pub fn now(&self) -> Instant {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        let scheduled = scheduler_now().saturating_duration_since(self.0.anchor);
        let elapsed = if let Some(source) = &self.0.source {
            match source
                .elapsed()
                .zip(self.0.origin)
                .and_then(|(n, o)| n.checked_sub(o))
            {
                Some(value) if value >= state.previous => {
                    state.previous = value;
                    scheduled.max(value)
                }
                _ => {
                    state.continuous = false;
                    scheduled
                }
            }
        } else {
            scheduled
        };
        match self.0.anchor.checked_add(elapsed) {
            Some(now) => state.last = state.last.max(now),
            None => state.continuous = false,
        }
        state.last
    }

    pub fn is_continuous(&self) -> bool {
        self.now();
        self.0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .continuous
    }

    /// Explicit unknown wake/process continuity. Does not reset deadlines or keys.
    pub fn invalidate(&self) {
        self.0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .continuous = false;
        self.0.changed.notify_waiters();
    }

    /// Wake sleeping gates after a trusted source advances. Call before allowing
    /// buffered callbacks or sends. Unknown continuity requires `invalidate`.
    pub fn wake(&self) {
        self.now();
        self.0.changed.notify_waiters();
    }

    pub async fn sleep_until(&self, deadline: Instant) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let now = self.now();
            if now >= deadline || !self.is_continuous() {
                return;
            }
            // Native timer clocks need not include suspend. Recheck on a bounded
            // slice even without a platform hint; no per-call polling task.
            tokio::select! {
                _ = changed => {},
                _ = crate::connection::sleep((deadline - now).min(Duration::from_millis(100))) => {},
            }
        }
    }

    /// Absolute elapsed wait. The timer/continuity gate runs before polling the
    /// future. A completed future's output is retained (important for joins).
    /// For unselected I/O or policy, `ElapsedDeadline::run` also rechecks after
    /// the poll. Dropping partial output on timeout always requires carrier abort.
    pub async fn timeout_until<T>(
        &self,
        deadline: Instant,
        future: impl std::future::Future<Output = T>,
    ) -> Result<T, ElapsedFailure> {
        tokio::select! {
            biased;
            _ = self.sleep_until(deadline) => Err(if self.is_continuous() { ElapsedFailure::Deadline } else { ElapsedFailure::ContinuityLost }),
            value = future => Ok(value),
        }
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
mod tests {
    use super::*;
    #[test]
    fn native_kernel_source_is_available_and_monotonic() {
        let first = PlatformSource.elapsed().expect("native continuous clock");
        let second = PlatformSource.elapsed().expect("native continuous clock");
        assert!(second >= first);
        assert!(ElapsedClock::with_source(Arc::new(PlatformSource)).is_continuous());
    }
}

pub(crate) fn scheduler_now() -> Instant {
    #[cfg(not(target_arch = "wasm32"))]
    return tokio::time::Instant::now().into_std();
    #[cfg(target_arch = "wasm32")]
    Instant::now()
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
struct PlatformSource;

#[cfg(any(target_os = "linux", target_os = "android"))]
impl ElapsedSource for PlatformSource {
    fn elapsed(&self) -> Option<Duration> {
        let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: clock_gettime initializes the owned timespec on success.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } != 0 {
            return None;
        }
        let value = unsafe { value.assume_init() };
        if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
            return None;
        }
        Some(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
    }
}

#[cfg(target_vendor = "apple")]
#[allow(deprecated)] // Bindings remain ABI-stable; avoid a second platform dependency.
impl ElapsedSource for PlatformSource {
    fn elapsed(&self) -> Option<Duration> {
        // mach_continuous_time includes sleep, unlike mach_absolute_time. It is
        // available on supported macOS 10.12+/iOS 10+ deployment targets.
        unsafe extern "C" {
            fn mach_continuous_time() -> u64;
        }
        let mut info = std::mem::MaybeUninit::<libc::mach_timebase_info_data_t>::uninit();
        // SAFETY: owned output pointer; these kernel APIs take no other memory.
        if unsafe { libc::mach_timebase_info(info.as_mut_ptr()) } != 0 {
            return None;
        }
        let info = unsafe { info.assume_init() };
        if info.denom == 0 {
            return None;
        }
        let nanos = u128::from(unsafe { mach_continuous_time() }) * u128::from(info.numer)
            / u128::from(info.denom);
        Some(Duration::new(
            u64::try_from(nanos / 1_000_000_000).ok()?,
            (nanos % 1_000_000_000) as u32,
        ))
    }
}
