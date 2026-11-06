use super::panic::Failure;
use crate::{AuthenticatorFactory, ConnectionAuthorization, PolicyJobs};
use futures_util::future::BoxFuture;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use syntra_core::secure_channel::{ServerConfig, VerifiedIdentity};
use syntra_runtime::{
    elapsed::ElapsedClock, recovery::wire::RecoveryService, AuthError, Authenticator,
    ExecutionBudget, Principal,
};

pub(super) type Principals = Arc<Mutex<BTreeMap<String, usize>>>;
pub(super) struct Lease {
    subject: String,
    principals: Principals,
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut principals = self.principals.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = principals.get_mut(&self.subject) {
            *count -= 1;
            if *count == 0 {
                principals.remove(&self.subject);
            }
        }
    }
}

pub(super) struct LimitedFactory {
    pub base: Arc<dyn AuthenticatorFactory>,
    pub principals: Principals,
    pub maximum: usize,
    pub lease: Arc<Mutex<Option<Lease>>>,
    pub failure: Arc<Failure>,
}
struct LimitedAuth {
    base: Arc<dyn Authenticator>,
    principals: Principals,
    maximum: usize,
    lease: Arc<Mutex<Option<Lease>>>,
}
impl Authenticator for LimitedAuth {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        // Always authenticate explicit hello credentials first, including empty
        // credentials. The route, Noise handle and TLS identity never stand in.
        let principal = self.base.authenticate(credential)?;
        if principal.subject.len() > 1024 {
            return Err(AuthError::denied());
        }
        let mut lease = self.lease.lock().map_err(|_| AuthError::denied())?;
        if lease.is_some() {
            return Err(AuthError::denied());
        }
        let mut principals = self.principals.lock().map_err(|_| AuthError::denied())?;
        let count = principals.get(&principal.subject).copied().unwrap_or(0);
        if count >= self.maximum {
            return Err(AuthError::denied());
        }
        principals.insert(principal.subject.clone(), count + 1);
        *lease = Some(Lease {
            subject: principal.subject.clone(),
            principals: self.principals.clone(),
        });
        Ok(principal)
    }
}
impl LimitedFactory {
    fn wrap(&self, base: Arc<dyn Authenticator>) -> Arc<dyn Authenticator> {
        Arc::new(LimitedAuth {
            base,
            principals: self.principals.clone(),
            maximum: self.maximum,
            lease: self.lease.clone(),
        })
    }
}
impl AuthenticatorFactory for LimitedFactory {
    fn terminal_receipt(
        &self,
        identity: &VerifiedIdentity,
    ) -> Option<syntra_runtime::terminal::Policy> {
        // Preserve the opt-in so the unsupported HTTP driver rejects it before
        // handler effects, instead of silently dropping host configuration.
        self.base.terminal_receipt(identity)
    }
    fn create(&self, identity: &VerifiedIdentity) -> Result<Arc<dyn Authenticator>, AuthError> {
        Ok(self.wrap(self.base.create(identity)?))
    }
    fn prepare<'a>(
        &'a self,
        identity: &'a VerifiedIdentity,
    ) -> BoxFuture<'a, Result<Arc<dyn Authenticator>, AuthError>> {
        Box::pin(async move { Ok(self.wrap(self.base.prepare(identity).await?)) })
    }
    fn elapsed_clock(&self) -> ElapsedClock {
        self.base.elapsed_clock()
    }
    fn policy_jobs(&self) -> Option<Arc<PolicyJobs>> {
        self.base.policy_jobs()
    }
    fn validate_server_config(&self, security: &ServerConfig) -> Result<(), AuthError> {
        self.base.validate_server_config(security)
    }
    fn connection_authorization(
        &self,
        identity: &VerifiedIdentity,
    ) -> Result<Option<Arc<dyn ConnectionAuthorization>>, AuthError> {
        Ok(self.base.connection_authorization(identity)?.map(|base| {
            Arc::new(ContainedAuthorization {
                base,
                failure: self.failure.clone(),
            }) as Arc<dyn ConnectionAuthorization>
        }))
    }
    fn blocking_admission(&self) -> Option<Arc<tokio::sync::Semaphore>> {
        self.base.blocking_admission()
    }
    fn execution_budget(&self) -> ExecutionBudget {
        self.base.execution_budget()
    }
    fn recovery_service(&self) -> Option<Arc<RecoveryService>> {
        self.base.recovery_service()
    }
}

struct ContainedAuthorization {
    base: Arc<dyn ConnectionAuthorization>,
    failure: Arc<Failure>,
}
impl ConnectionAuthorization for ContainedAuthorization {
    fn check(&self) -> BoxFuture<'_, Result<(), AuthError>> {
        Box::pin(async move {
            self.failure
                .catch_async(async { self.base.check().await })
                .await
                .unwrap_or_else(|| Err(AuthError::unauthenticated()))
        })
    }
    fn interval(&self) -> std::time::Duration {
        self.base.interval()
    }
    fn read_timeout(&self) -> std::time::Duration {
        self.base.read_timeout()
    }
    fn close_timeout(&self) -> std::time::Duration {
        self.base.close_timeout()
    }
}

pub(super) struct Bucket {
    tokens: f64,
    at: std::time::Instant,
}
impl Bucket {
    pub fn new(burst: u32, at: std::time::Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            at,
        }
    }
    pub fn expired(&self, now: std::time::Instant, rate: u32, burst: u32) -> bool {
        // Deleting a bucket is equivalent to replacing it with a full burst.
        // Only do so when its real refill has already reached that burst. Clock
        // regression is not elapsed time and must never make room for a source.
        now.checked_duration_since(self.at).is_some_and(|elapsed| {
            self.tokens + elapsed.as_secs_f64() * f64::from(rate) >= f64::from(burst)
        })
    }
    pub fn take(&mut self, now: std::time::Instant, rate: u32, burst: u32) -> bool {
        let Some(elapsed) = now.checked_duration_since(self.at) else {
            return false;
        };
        self.tokens = (self.tokens + elapsed.as_secs_f64() * f64::from(rate)).min(f64::from(burst));
        self.at = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn slow_source_eviction_requires_a_full_refill_not_two_seconds() {
        let at = std::time::Instant::now();
        let mut bucket = Bucket::new(8, at);
        for _ in 0..8 {
            assert!(bucket.take(at, 1, 8));
        }
        let later = at + Duration::from_millis(2100);
        assert!(!bucket.expired(later, 1, 8));
        assert!(bucket.take(later, 1, 8));
        assert!(bucket.take(later, 1, 8));
        assert!(!bucket.take(later, 1, 8));
        assert!(!bucket.expired(at, 1, 8));
        assert!(bucket.expired(later + Duration::from_secs(8), 1, 8));
    }
}
