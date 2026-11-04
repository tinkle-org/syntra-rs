use super::*;
use crate::pump::{AuthenticatorFactory, ConnectionAuthorization, PolicyJobs, TransportShutdown};
use futures_util::future::BoxFuture;
use syntra_core::secure_channel::{ServerConfig, VerifiedIdentity};
use syntra_runtime::{elapsed::ElapsedClock, AuthError, Authenticator, ExecutionBudget, Principal};

/// Deployment identity verification; must independently verify the opaque hello
/// credential, including explicit policy for credential-less returning devices.
/// The claimed enrollment principal is NOT supplied as authentication evidence.
/// This Core authentication hook must be prompt/nonblocking. Deployments needing
/// remote identity I/O must establish a bounded verified credential ahead of it;
/// an executor-blocking callback cannot be made cancellable by a timer wrapper.
pub trait ApplicationIdentity: Send + Sync {
    fn authenticate(
        &self,
        identity: &VerifiedIdentity,
        credential: &[u8],
    ) -> Result<Principal, AuthError>;
}

/// Returning-device factory. Bootstrap enrollment remains on an independently
/// configured authority path; installing this factory never grants bootstrap RPCs.
pub struct EnrollmentAuthenticatorFactory {
    store: Arc<SqliteEnrollmentStore>,
    application: Arc<dyn ApplicationIdentity>,
    budget: ExecutionBudget,
    jobs: Arc<PolicyJobs>,
    clock: ElapsedClock,
}

impl EnrollmentAuthenticatorFactory {
    pub fn new(
        store: Arc<SqliteEnrollmentStore>,
        application: Arc<dyn ApplicationIdentity>,
        budget: ExecutionBudget,
        concurrent_checks: usize,
    ) -> Result<Self, Error> {
        Self::with_clock(
            store,
            application,
            budget,
            concurrent_checks,
            ElapsedClock::new(),
        )
    }

    pub fn with_clock(
        store: Arc<SqliteEnrollmentStore>,
        application: Arc<dyn ApplicationIdentity>,
        budget: ExecutionBudget,
        concurrent_checks: usize,
        clock: ElapsedClock,
    ) -> Result<Self, Error> {
        if !(1..=1024).contains(&concurrent_checks) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            store,
            application,
            budget,
            jobs: PolicyJobs::new(concurrent_checks).map_err(|_| Error::Configuration)?,
            clock,
        })
    }

    /// Includes timed-out/cancelled blocking handshakes and checks until they
    /// actually exit. A deployment shutdown must not claim these workers joined
    /// merely because the carrier closed or an authorization timeout fired.
    pub fn in_flight_checks(&self) -> usize {
        self.jobs.pending()
    }

    /// Explicitly stops the entire factory pool, not just one connection. Pending
    /// blocking operations remain owned and reported after timeout/cancellation.
    pub async fn shutdown_policy_jobs(
        &self,
        grace: Duration,
    ) -> Result<TransportShutdown, crate::Error> {
        self.jobs.shutdown(&self.clock, grace).await
    }
}

struct BoundAuthenticator {
    identity: VerifiedIdentity,
    application: Arc<dyn ApplicationIdentity>,
    // Trusted enrollment binding validated asynchronously by the pump before
    // hello ingestion. It is never derived from ClientHello identity candidates.
    binding: Binding,
}

impl Authenticator for BoundAuthenticator {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        let principal = self
            .application
            .authenticate(&self.identity, credential)
            .map_err(|error| {
                if error.code == syntra_core::ErrorCode::PermissionDenied {
                    AuthError::denied()
                } else {
                    AuthError::unauthenticated()
                }
            })?;
        if principal.subject.is_empty() || principal.subject != self.binding.principal {
            return Err(AuthError::unauthenticated());
        }
        Ok(principal)
    }
}

struct Guard {
    store: Arc<SqliteEnrollmentStore>,
    context: Context,
    jobs: Arc<PolicyJobs>,
    clock: ElapsedClock,
}

impl ConnectionAuthorization for Guard {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async move {
            if !self.clock.is_continuous() {
                return Err(AuthError::unauthenticated());
            }
            // Retry admission only, within ONE read budget including the actual
            // read. No blocking task is queued until admitted. PolicyJobs reports
            // saturation and a stopped pool identically; both remain fail-closed
            // at the deadline. Never retry an admitted validation failure.
            let deadline = self.clock.now() + self.store.policy.read_timeout();
            let task = loop {
                if !self.clock.is_continuous() || self.clock.now() >= deadline {
                    return Err(AuthError::unauthenticated());
                }
                let store = self.store.clone();
                let context = self.context.clone();
                match self
                    .jobs
                    .spawn(move || store.validate(&context, None).map(|_| ()))
                {
                    Ok(task) => break task,
                    Err(crate::Error::Authentication) => {
                        self.clock
                            .sleep_until(
                                (self.clock.now() + Duration::from_millis(10)).min(deadline),
                            )
                            .await;
                    }
                    Err(_) => return Err(AuthError::unauthenticated()),
                }
            };
            // A timed-out task retains its permit and owner until it really exits;
            // dropping this waiter never cancels synchronous SQLite/KMS work.
            let result = self.clock.timeout_until(deadline, task).await;
            match result {
                Ok(Ok(Ok(()))) if self.clock.is_continuous() && self.clock.now() < deadline => {
                    Ok(())
                }
                _ => Err(AuthError::unauthenticated()),
            }
        })
    }

    fn interval(&self) -> Duration {
        // Reserve read and teardown time INSIDE the declared freshness bound.
        Duration::from_secs(u64::from(
            self.store.policy.freshness_seconds
                - self.store.policy.read_seconds
                - self.store.policy.close_seconds,
        ))
    }

    fn read_timeout(&self) -> Duration {
        self.store.policy.read_timeout()
    }
    fn close_timeout(&self) -> Duration {
        Duration::from_secs(u64::from(self.store.policy.close_seconds))
    }
}

impl AuthenticatorFactory for EnrollmentAuthenticatorFactory {
    fn elapsed_clock(&self) -> ElapsedClock {
        self.clock.clone()
    }
    fn policy_jobs(&self) -> Option<Arc<PolicyJobs>> {
        Some(self.jobs.clone())
    }
    fn validate_server_config(&self, security: &ServerConfig) -> Result<(), AuthError> {
        let expected: Arc<dyn KeyStore> = self.store.clone();
        if security.mode != Mode::Returning
            || !self.store.policy.permits(security.carrier)
            || security
                .store
                .as_ref()
                .is_none_or(|store| !Arc::ptr_eq(store, &expected))
        {
            return Err(AuthError::unauthenticated());
        }
        Ok(())
    }

    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        // Do not accidentally perform SQLite/KMS I/O on an executor through the
        // synchronous factory entry point. The pump uses prepare().
        let _ = identity;
        Err(AuthError::unauthenticated())
    }

    fn prepare<'a>(
        &'a self,
        identity: &'a VerifiedIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn Authenticator>, AuthError>> {
        Box::pin(async move {
            if !self.clock.is_continuous() {
                return Err(AuthError::unauthenticated());
            }
            let store = self.store.clone();
            let context = identity.context().clone();
            let deadline = self.clock.now() + self.store.policy.read_timeout();
            let task = self
                .jobs
                .spawn(move || store.validate(&context, None))
                .map_err(|_| AuthError::unauthenticated())?;
            let result = self.clock.timeout_until(deadline, task).await;
            let binding = match result {
                Ok(Ok(Ok(binding)))
                    if self.clock.is_continuous() && self.clock.now() < deadline =>
                {
                    binding
                }
                _ => return Err(AuthError::unauthenticated()),
            };
            Ok(Arc::new(BoundAuthenticator {
                identity: identity.clone(),
                application: self.application.clone(),
                binding,
            }) as Arc<dyn Authenticator>)
        })
    }

    fn connection_authorization(
        &self,
        identity: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        if identity.context().mode != Mode::Returning
            || !self.store.policy.permits(identity.context().carrier)
        {
            return Err(AuthError::unauthenticated());
        }
        Ok(Some(Arc::new(Guard {
            store: self.store.clone(),
            context: identity.context().clone(),
            jobs: self.jobs.clone(),
            clock: self.clock.clone(),
        })))
    }

    fn execution_budget(&self) -> ExecutionBudget {
        self.budget.clone()
    }
}
