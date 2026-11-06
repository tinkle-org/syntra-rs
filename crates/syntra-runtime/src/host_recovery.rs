//! Optional recovery profile attachment. One immutable binding and one retained
//! notification worker per connection; no provider callback runs under our mutex.

use super::*;
use crate::connection::CancelToken;
pub(super) use crate::recovery::wire::ProviderError;
use crate::recovery::wire::{self, RecoveryHostSession, RecoveryService};
use std::sync::atomic::Ordering;

pub(super) fn is_profile(method: &str) -> bool {
    method.starts_with("/syntra.v1.UpdateRecovery/")
}

pub(super) fn known_method(method: &str) -> bool {
    wire::METHODS.contains(&method)
}

pub(super) fn outcome(error: ProviderError) -> HandlerOutcome {
    // ProviderError contains only typed, non-sensitive diagnostics.
    HandlerOutcome::error(error.code(), error.to_string())
}

pub(super) struct Attachment {
    service: Arc<RecoveryService>,
    pending: ExecutionBudget,
    binding: Option<Binding>,
}

struct Binding {
    session: Arc<RecoveryHostSession>,
    stop: CancelToken,
    revoked: CancelToken,
    worker: Option<TaskHandle>,
}

impl Binding {
    fn close(&self) {
        self.session.close();
        self.stop.cancel();
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        // The worker owns session/signal clones, NOT this owner or an Arc<Host>.
        // Closing wakes an idle worker even when the last Host is simply dropped.
        self.close();
    }
}

pub(super) struct Call {
    session: Arc<RecoveryHostSession>,
    revoked: CancelToken,
    _pending: execution::BudgetPermit,
}

impl Call {
    pub(super) fn handle(
        &self,
        method: &str,
        payload: &[u8],
        remaining: Duration,
        conn: &Connection,
    ) -> HandlerOutcome {
        let result = self
            .session
            .handle_with_deadline(method, payload, remaining);
        if result == Err(ProviderError::Unauthenticated)
            || self.session.terminal_error() == Some(ProviderError::Unauthenticated)
        {
            // Synchronous handoff BEFORE the RPC select can choose its deadline.
            // The managed worker calls the core's persistent withdrawal owner.
            revoke(conn, &self.revoked);
        }
        result.map_or_else(outcome, HandlerOutcome::Payload)
    }
}

impl Host {
    /// Opt into the recovery profile before receiving hello. Configuration is
    /// immutable: a second registration or any non-CONNECTED state is rejected.
    /// Session creation is lazy, using only the actual handshake-bound principal.
    pub async fn configure_recovery(
        &self,
        service: Arc<RecoveryService>,
    ) -> Result<(), SyntraError> {
        // Same FIFO gate as ingest: a hello cannot race this registration.
        let _ordered = self.admission.lock().await;
        let state = self.conn.shared.state.read().await;
        let mut recovery = self.recovery.lock().unwrap_or_else(|e| e.into_inner());
        if *state != ConnectionState::Connected || self.conn.is_closed() || recovery.is_some() {
            return Err(SyntraError::Protocol {
                code: ErrorCode::FailedPrecondition,
                message: "recovery configuration requires unconfigured CONNECTED host".into(),
            });
        }
        *recovery = Some(Attachment {
            pending: ExecutionBudget::new(service.limits().pending_rpcs_per_connection),
            service,
            binding: None,
        });
        Ok(())
    }

    pub(super) fn recovery_configured(&self) -> bool {
        self.recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    pub(super) fn request_timeout(&self, req: &RpcRequest) -> Duration {
        if req.timeout_ms != 0 || !is_profile(&req.method) {
            return self.effective_timeout(req.timeout_ms);
        }
        self.recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map_or(Duration::from_secs(5), |a| {
                a.service.limits().default_deadline
            })
            .min(self.conn.shared.config.max_rpc_timeout)
    }

    pub(super) fn prepare_recovery(&self, principal: &Principal) -> Result<Call, ProviderError> {
        // Only short setup/accounting, never provider calls or writer awaits.
        // open_connection allocates a registry entry without invoking the source.
        let mut recovery = self.recovery.lock().unwrap_or_else(|e| e.into_inner());
        let attachment = recovery.as_mut().ok_or(ProviderError::Unimplemented)?;
        let pending = attachment
            .pending
            .try_acquire()
            .ok_or(ProviderError::ResourceExhausted)?;
        if attachment.binding.is_none() {
            let session = attachment.service.open_connection(principal.clone())?;
            let stop = CancelToken::new();
            let revoked = CancelToken::new();
            let worker = notification_worker(
                self.weak_self.clone(),
                self.conn.clone(),
                session.clone(),
                stop.clone(),
                revoked.clone(),
            );
            self.conn.shared.tasks.register(worker.clone());
            attachment.binding = Some(Binding {
                session,
                stop,
                revoked,
                worker: Some(worker),
            });
        }
        let binding = attachment.binding.as_ref().expect("initialized binding");
        if binding.session.principal() != principal {
            return Err(ProviderError::Unauthenticated);
        }
        Ok(Call {
            session: binding.session.clone(),
            revoked: binding.revoked.clone(),
            _pending: pending,
        })
    }

    pub(super) fn close_recovery(&self) {
        if let Some(binding) = self
            .recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(|a| a.binding.as_ref())
        {
            binding.close();
        }
    }

    pub(super) async fn stop_recovery_until(&self, deadline: Instant) {
        let worker = self
            .recovery
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .and_then(|a| a.binding.as_mut())
            .and_then(|b| b.worker.take());
        if let Some(worker) = worker {
            let _ = self
                .conn
                .shared
                .clock
                .timeout_until(deadline, worker.join())
                .await;
        }
    }
}

fn revoke(conn: &Connection, revoked: &CancelToken) {
    conn.shared
        .principal_withdrawn
        .store(true, Ordering::Release);
    revoked.cancel();
}

async fn withdraw(host: &Weak<Host>) {
    if let Some(host) = host.upgrade() {
        host.withdraw_principal().await;
    }
}

// Session cleanup is also guaranteed if a provider panics. The panic remains a
// task failure after core cleanup; it is never converted into a silent EOF.
struct CloseSession(Arc<RecoveryHostSession>);
impl Drop for CloseSession {
    fn drop(&mut self) {
        self.0.close();
    }
}

fn notification_worker(
    host: Weak<Host>,
    conn: Connection,
    session: Arc<RecoveryHostSession>,
    stop: CancelToken,
    revoked: CancelToken,
) -> TaskHandle {
    spawn_task(async move {
        let _cleanup = CloseSession(session.clone());
        let work = notifications(&host, &conn, &session, &stop, &revoked);
        match std::panic::AssertUnwindSafe(work).catch_unwind().await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(host) = host.upgrade() {
                    host.fail_protocol_and_close(error).await;
                }
            }
            Err(panic) => {
                session.close();
                if let Some(host) = host.upgrade() {
                    host.fail_protocol_and_close(SyntraError::Protocol {
                        code: ErrorCode::Internal,
                        message: "recovery notification worker panicked".into(),
                    })
                    .await;
                }
                std::panic::resume_unwind(panic);
            }
        }
    })
}

async fn notifications(
    host: &Weak<Host>,
    conn: &Connection,
    session: &RecoveryHostSession,
    stop: &CancelToken,
    revoked: &CancelToken,
) -> Result<(), SyntraError> {
    let mut closed = conn.subscribe_close();
    loop {
        if conn.is_closed() {
            return Ok(());
        }
        let payload = tokio::select! {
            biased;
            _ = revoked.cancelled() => { withdraw(host).await; return Ok(()); },
            _ = stop.cancelled() => return Ok(()),
            _ = closed.changed() => return Ok(()),
            payload = session.next_notification() => payload,
        };
        // A terminal trailer may be pending while the source has revoked the
        // principal. Inspect the sticky typed error before ANY protected output.
        if session.terminal_error() == Some(ProviderError::Unauthenticated) {
            revoke(conn, revoked);
            withdraw(host).await;
            return Ok(());
        }
        if revoked.is_cancelled() {
            withdraw(host).await;
            return Ok(());
        }
        let Some(payload) = payload else {
            if let Some(error) = session.terminal_error() {
                return Err(SyntraError::Protocol {
                    code: error.code(),
                    message: "recovery notification production failed".into(),
                });
            }
            return Ok(());
        };
        let ctx = conn.ctx().await;
        if ctx.state != ConnectionState::Active || session.is_closed() {
            return Ok(());
        }
        let frame = Frame {
            version: ctx.negotiated_version.unwrap_or(0),
            request_id: 0,
            body: Some(Body::Notification(syntra_core::proto::Notification {
                payload,
            })),
        };
        validate_frame(&frame, ctx)?;
        // Exactly one bounded frame outside the session queues. No profile lock
        // or provider operation spans this wait; core control/results stay free.
        let deadline = now()
            + conn
                .shared
                .config
                .max_rpc_timeout
                .min(Duration::from_secs(5));
        let permit = tokio::select! {
            biased;
            _ = sleep_until(deadline) => {
                if session.terminal_error() == Some(ProviderError::Unauthenticated) || revoked.is_cancelled() {
                    revoke(conn, revoked);
                    withdraw(host).await;
                    return Ok(());
                }
                return Err(SyntraError::Unavailable("recovery writer stalled".into()));
            },
            _ = revoked.cancelled() => { withdraw(host).await; return Ok(()); },
            _ = stop.cancelled() => return Ok(()),
            _ = closed.changed() => return Ok(()),
            permit = conn.reserve_writer() => permit?,
        };
        loop {
            let state = conn.shared.state.read().await;
            if session.terminal_error() == Some(ProviderError::Unauthenticated)
                || revoked.is_cancelled()
            {
                drop(state);
                revoke(conn, revoked);
                withdraw(host).await;
                return Ok(());
            }
            if *state != ConnectionState::Active
                || conn.is_closed()
                || conn.writer_is_fenced()
                || conn.terminal_fenced()
                || conn.shared.principal_withdrawn.load(Ordering::Acquire)
                || session.is_closed()
            {
                return Ok(());
            }
            // Writer backpressure can outlive an authorization or generation
            // decision made at pop. Recheck after the LAST await, not before it.
            let payload = match &frame.body {
                Some(Body::Notification(n)) => &n.payload,
                _ => unreachable!(),
            };
            match session.revalidate_notification(payload) {
                Ok(()) => {
                    if now() >= deadline {
                        return Err(SyntraError::Unavailable("recovery writer stalled".into()));
                    }
                    permit.send(frame.encode_to_vec());
                    break;
                }
                Err(ProviderError::Unauthenticated) => {
                    drop(state);
                    revoke(conn, revoked);
                    withdraw(host).await;
                    return Ok(());
                }
                Err(ProviderError::PermissionDenied | ProviderError::FailedPrecondition) => {
                    // Only this already-popped payload is stale. The service
                    // has retained any required targeted control separately.
                    break;
                }
                Err(ProviderError::ResourceExhausted) => {
                    drop(state);
                    tokio::select! {
                        biased;
                        _ = sleep_until(deadline) => return Err(SyntraError::Unavailable("recovery writer stalled".into())),
                        _ = revoked.cancelled() => { withdraw(host).await; return Ok(()); },
                        _ = stop.cancelled() => return Ok(()),
                        _ = closed.changed() => return Ok(()),
                        _ = sleep_until((now() + Duration::from_millis(1)).min(deadline)) => {},
                    }
                }
                Err(error) => {
                    return Err(SyntraError::Protocol {
                        code: error.code(),
                        message: "recovery notification validation failed".into(),
                    })
                }
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "host_recovery_tests.rs"]
mod tests;
