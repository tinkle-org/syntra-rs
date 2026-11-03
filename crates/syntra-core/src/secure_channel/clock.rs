use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Trusted local elapsed time, including idle and system suspension. Values must
/// share one origin and never regress. `None` means continuity is unknown.
/// Sampling must be prompt, nonblocking and non-reentrant: the kernel samples
/// under a short lock. Never use peer time, adjustable wall time alone, or an
/// Instant that stops during suspend. A runtime adapter can implement this trait
/// without introducing a dependency from the kernel to that runtime.
pub trait ElapsedSource: Send + Sync {
    fn elapsed(&self) -> Option<Duration>;
}

/// A connection's establishment origin and sticky continuity/age gate. Clones
/// share the same origin and retirement state, never cryptographic state.
/// Create before carrier establishment when that time must share the budget,
/// then pass into `ClientHandshake::start_with_clock` or `respond_with_clock`.
#[derive(Clone)]
pub struct Clock(Arc<Inner>);

struct Inner {
    source: Arc<dyn ElapsedSource>,
    origin: Option<Duration>,
    previous: Mutex<Option<Duration>>,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    /// Linux/Android use BOOTTIME, Apple uses mach continuous time, and WASM
    /// preserves the browser dual-clock checks. Other native targets fail closed
    /// unless the owner supplies a trusted suspend-inclusive source.
    pub fn new() -> Self {
        #[cfg(target_arch = "wasm32")]
        return Self::with_source(Arc::new(super::browser_elapsed::Clock::new()));
        #[cfg(not(target_arch = "wasm32"))]
        Self::with_source(Arc::new(NativeSource))
    }

    pub fn with_source(source: Arc<dyn ElapsedSource>) -> Self {
        let origin = source.elapsed();
        Self(Arc::new(Inner {
            source,
            origin,
            previous: Mutex::new(origin),
        }))
    }

    /// Returns MAX_AGE after expiry, missing time, regression, invalidation or
    /// lock poisoning. Retirement is sticky even if later samples look valid.
    pub fn age(&self) -> Duration {
        let Ok(mut previous) = self.0.previous.lock() else {
            return super::MAX_AGE;
        };
        if let (Some(last), Some(origin)) = (*previous, self.0.origin) {
            if let Some(now) = self.0.source.elapsed() {
                if now >= last {
                    if let Some(age) = now.checked_sub(origin).filter(|age| *age < super::MAX_AGE) {
                        *previous = Some(now);
                        return age;
                    }
                }
            }
        }
        *previous = None;
        super::MAX_AGE
    }

    /// Retire on lifecycle loss or unknown continuity before buffered work runs.
    /// This never resets the origin, budget, keys or nonces.
    pub fn invalidate(&self) {
        if let Ok(mut previous) = self.0.previous.lock() {
            *previous = None;
        }
    }

    pub(super) fn check(&self) -> Result<(), super::Error> {
        if self.age() >= super::MAX_AGE {
            Err(super::Error::Limit)
        } else {
            Ok(())
        }
    }
}

#[cfg(target_arch = "wasm32")]
impl ElapsedSource for super::browser_elapsed::Clock {
    fn elapsed(&self) -> Option<Duration> {
        let age = self.age();
        (age < super::MAX_AGE).then_some(age)
    }
}

#[cfg(not(target_arch = "wasm32"))]
struct NativeSource;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
impl ElapsedSource for NativeSource {
    fn elapsed(&self) -> Option<Duration> {
        None
    }
}

// The only unsafe boundary is the owned-output platform clock FFI. No protocol
// buffer, key or cipher state enters this module.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
#[allow(unsafe_code)]
mod native {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    impl ElapsedSource for NativeSource {
        fn elapsed(&self) -> Option<Duration> {
            let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
            // SAFETY: the pointer is owned and valid; success initializes it.
            if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } != 0 {
                return None;
            }
            // SAFETY: clock_gettime succeeded above.
            let value = unsafe { value.assume_init() };
            if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
                return None;
            }
            Some(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
        }
    }

    #[cfg(target_vendor = "apple")]
    #[allow(deprecated)]
    impl ElapsedSource for NativeSource {
        fn elapsed(&self) -> Option<Duration> {
            // Available on supported macOS 10.12+/iOS 10+ deployment targets.
            unsafe extern "C" {
                fn mach_continuous_time() -> u64;
            }
            let mut info = std::mem::MaybeUninit::<libc::mach_timebase_info_data_t>::uninit();
            // SAFETY: the kernel initializes the owned output on success.
            if unsafe { libc::mach_timebase_info(info.as_mut_ptr()) } != 0 {
                return None;
            }
            // SAFETY: mach_timebase_info succeeded above.
            let info = unsafe { info.assume_init() };
            if info.denom == 0 || info.numer == 0 {
                return None;
            }
            // SAFETY: no arguments or borrowed memory; this includes sleep.
            let ticks = unsafe { mach_continuous_time() };
            let nanos = u128::from(ticks) * u128::from(info.numer) / u128::from(info.denom);
            Some(Duration::new(
                u64::try_from(nanos / 1_000_000_000).ok()?,
                (nanos % 1_000_000_000) as u32,
            ))
        }
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "android", target_vendor = "apple")
))]
#[test]
fn native_source_is_available_and_monotonic() {
    let first = NativeSource
        .elapsed()
        .expect("suspend-inclusive kernel clock");
    let second = NativeSource
        .elapsed()
        .expect("suspend-inclusive kernel clock");
    assert!(second >= first);
    assert!(Clock::new().age() < super::MAX_AGE);
}
