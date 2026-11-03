//! One pre-carrier age origin for browser driver, kernel and runtime gates.

use super::Error;
use std::{future::Future, sync::Arc, time::Duration};
use syntra_core::secure_channel::{Clock, MAX_AGE};
use syntra_runtime::elapsed::{ElapsedClock, ElapsedSource};

struct KernelElapsed(Clock);

impl ElapsedSource for KernelElapsed {
    fn elapsed(&self) -> Option<Duration> {
        let age = self.0.age();
        (age < MAX_AGE).then_some(age)
    }
}

#[derive(Clone)]
pub(super) struct ConnectionClock {
    pub kernel: Clock,
    pub runtime: ElapsedClock,
}

impl ConnectionClock {
    pub fn new() -> Self {
        Self::with_kernel(Clock::new())
    }

    fn with_kernel(kernel: Clock) -> Self {
        // Kernel's WASM source observes both elapsed and wall time. Reusing its
        // sticky gate avoids a second origin or an independently resumed budget.
        let runtime = ElapsedClock::with_source(Arc::new(KernelElapsed(kernel.clone())));
        Self { kernel, runtime }
    }

    pub fn now(&self) -> Duration {
        self.kernel.age()
    }

    pub fn after(&self, budget: Duration) -> Duration {
        self.now().saturating_add(budget)
    }

    pub fn invalidate(&self) {
        self.kernel.invalidate();
        self.runtime.invalidate();
    }

    pub fn check(&self, deadline: Duration) -> Result<(), Error> {
        let age = self.now();
        if age >= deadline || age >= MAX_AGE || !self.runtime.is_continuous() {
            Err(Error::Timeout)
        } else {
            Ok(())
        }
    }

    async fn until(&self, deadline: Duration) {
        loop {
            if self.check(deadline).is_err() {
                return;
            }
            // A timer is only a scheduling hint. Re-sample the shared dual clock
            // after every wake, even if Performance stopped during suspension.
            let remaining = deadline.saturating_sub(self.now());
            syntra_runtime::sleep_for(remaining.min(Duration::from_millis(100))).await;
        }
    }

    pub async fn run<T>(
        &self,
        deadline: Duration,
        future: impl Future<Output = Result<T, Error>>,
    ) -> Result<T, Error> {
        self.check(deadline)?;
        let result = tokio::select! {
            biased;
            _ = self.until(deadline) => Err(Error::Timeout),
            result = future => result,
        };
        // Synchronous crypto/JS callbacks can cross the boundary in one poll.
        // Any discarded partial I/O is followed by the socket owner's abort.
        self.check(deadline)?;
        result
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Source(AtomicU64);
    impl syntra_core::secure_channel::ElapsedSource for Source {
        fn elapsed(&self) -> Option<Duration> {
            Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }

    fn clock() -> (Arc<Source>, ConnectionClock) {
        let source = Arc::new(Source::default());
        let clock = ConnectionClock::with_kernel(Clock::with_source(source.clone()));
        (source, clock)
    }

    #[test]
    fn default_clock_matches_platform_support() {
        assert_eq!(
            ConnectionClock::new()
                .check(Duration::from_secs(15))
                .is_ok(),
            cfg!(any(
                target_os = "linux",
                target_os = "android",
                target_vendor = "apple"
            )),
        );
    }

    #[tokio::test]
    async fn late_m2_does_not_renew_hello_or_output_budget() {
        let (source, clock) = clock();
        let channel_deadline = clock.after(Duration::from_secs(5));
        source.0.store(4900, Ordering::SeqCst);
        let output_deadline = clock.after(Duration::from_secs(10)).min(channel_deadline);
        assert_eq!(output_deadline, Duration::from_secs(5));
        clock.run(output_deadline, async { Ok(()) }).await.unwrap();
        let result = clock
            .run(output_deadline, async {
                source.0.store(5000, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert_eq!(result, Err(Error::Timeout));
        // Expiry wins even if the queued output future is already ready.
        assert_eq!(
            clock.run(output_deadline, async { Ok(()) }).await,
            Err(Error::Timeout)
        );
    }

    #[tokio::test]
    async fn stalled_establishment_expires_without_polling_work() {
        let (source, clock) = clock();
        let deadline = Duration::from_secs(15);
        source.0.store(15_000, Ordering::SeqCst);
        let result = clock
            .run(deadline, async {
                panic!("expired setup must not be polled")
            })
            .await;
        assert_eq!(result, Err::<(), _>(Error::Timeout));
    }

    #[test]
    fn setup_idle_and_invalidation_share_kernel_and_runtime_age() {
        use syntra_core::secure_channel::{
            generate_server_key, respond_with_clock, Carrier, ClientConfig, ClientHandshake,
            Context, Mode, ServerConfig,
        };
        let (source, clock) = clock();
        let (private_key, server_public_key) = generate_server_key().unwrap();
        source.0.store(1400, Ordering::SeqCst);
        let (handshake, first) = ClientHandshake::start_with_clock(
            ClientConfig {
                context: Context {
                    mode: Mode::Bootstrap,
                    carrier: Carrier::SecureWebSocket,
                    server_key_id: 0,
                    scope: b"browser-fixture".to_vec(),
                    handle: [0; 8],
                    epoch: 0,
                },
                server_public_key,
                authorization_key: None,
            },
            clock.kernel.clone(),
        )
        .unwrap();
        let (_server, second) = respond_with_clock(
            &ServerConfig {
                mode: Mode::Bootstrap,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 0,
                scope: b"browser-fixture".to_vec(),
                private_key,
                store: None,
            },
            &first,
            clock.kernel.clone(),
        )
        .unwrap();
        let channel = handshake.finish(&second).unwrap();
        assert_eq!(channel.age(), Duration::from_millis(1400));
        source.0.store(3000, Ordering::SeqCst);
        assert_eq!(clock.check(Duration::from_secs(3)), Err(Error::Timeout));
        assert_eq!(channel.age(), Duration::from_secs(3));
        clock.invalidate();
        assert_eq!(channel.age(), MAX_AGE);
        assert!(!clock.runtime.is_continuous());
    }

    #[test]
    fn regression_retires_both_gates_without_recovery() {
        let (source, clock) = clock();
        source.0.store(1000, Ordering::SeqCst);
        assert!(clock.check(Duration::from_secs(15)).is_ok());
        source.0.store(999, Ordering::SeqCst);
        assert_eq!(clock.check(Duration::from_secs(15)), Err(Error::Timeout));
        source.0.store(1001, Ordering::SeqCst);
        assert_eq!(clock.now(), MAX_AGE);
        assert!(!clock.runtime.is_continuous());
    }
}
