use super::{store::Store, *};
use rusqlite::Transaction;
use std::{
    path::Path,
    sync::{Arc, OnceLock},
};
use syntra_runtime::{
    AuthError, CancelToken, ExecutionLease, Handler, HandlerFut, HandlerOutcome, Principal,
    RequestContext,
};

/// Application-owned ACL and revocation fence. Read authoritative ACLs from
/// this transaction, with revocations committed to the same database. A check
/// against an independent mutable store/cache does NOT fence its revocations.
/// Called on a blocking worker before any object lookup, read or effect. Do
/// not commit the transaction or perform non-transactional side effects here.
/// Finalize calls this policy in both a read-only verification snapshot and
/// the conditional publish transaction. The policy must be read-only.
pub type ObjectPolicy = dyn Fn(&Transaction<'_>, &Principal, Method, ObjectVersion) -> std::result::Result<(), AuthError>
    + Send
    + Sync;

pub struct SqliteMediaHost {
    db: Store,
    policy: Arc<ObjectPolicy>,
}

impl SqliteMediaHost {
    /// One private SQLite file per authority scope. The application manages
    /// its ACL tables, disk quotas and tombstone retention. No allow-all default.
    pub fn open(
        path: impl AsRef<Path>,
        scope: &str,
        policy: Arc<ObjectPolicy>,
    ) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            db: Store::open(path.as_ref(), "host", scope)?,
            policy,
        }))
    }

    /// Allocate per connection. Runtime authorization supplies the principal;
    /// reusing a handler with another subject fails closed, never rebinds it.
    pub fn handler(self: &Arc<Self>) -> Arc<MediaHandler> {
        Arc::new(MediaHandler {
            host: self.clone(),
            caller: OnceLock::new(),
        })
    }

    pub(super) fn dispatch(
        &self,
        caller: &Principal,
        method: Method,
        payload: &[u8],
        response_frame_bytes: usize,
        check: impl Fn() -> Result<()>,
    ) -> Result<Vec<u8>> {
        check()?;
        let mut src = payload;
        let key = ObjectVersion::parse(&mut src)?;
        let authorize = |tx: &Transaction<'_>| {
            check()?;
            (self.policy)(tx, caller, method, key).map_err(|e| {
                MediaError::Refused(if e.code == ErrorCode::Unauthenticated {
                    e.code
                } else {
                    ErrorCode::PermissionDenied
                })
            })
        };
        if method == Method::Finalize {
            let mut src = payload;
            let spec = Manifest::parse(&mut src)?;
            end(src)?;
            let verified = self.db.snapshot(|tx| {
                authorize(tx)?;
                store::verify(tx, spec, &caller.subject, false, &check)
            })?;
            return self.db.transaction(|tx| {
                authorize(tx)?;
                let state = store::publish(tx, spec, &caller.subject, verified)?;
                check()?;
                Ok(state.bytes())
            });
        }
        self.db.transaction(|tx| {
            authorize(tx)?;
            let reply = if method == Method::Describe {
                end(src)?;
                store::describe(tx, key)?.bytes()
            } else {
                let mut src = payload;
                let spec = Manifest::parse(&mut src)?;
                let owner = &caller.subject;
                match method {
                    Method::Put => {
                        let (pos, data) = block(spec, src)?;
                        store::put(tx, spec, owner, pos, data)?.bytes()
                    }
                    Method::Read => {
                        let pos = number(&mut src)?;
                        end(src)?;
                        let n = if pos == spec.length {
                            0
                        } else {
                            spec.chunk_len(pos)?
                        };
                        if n + BLOCK_HEADER + 64 > response_frame_bytes {
                            return Err(MediaError::Refused(ErrorCode::ResourceExhausted));
                        }
                        store::read(tx, spec, pos)?
                    }
                    method => {
                        end(src)?;
                        match method {
                            Method::Begin => store::begin(tx, spec, owner)?,
                            Method::Abort => store::abort(tx, spec, owner)?,
                            Method::Query => store::state(tx, spec, owner)?,
                            _ => unreachable!(),
                        }
                        .bytes()
                    }
                }
            };
            check()?;
            Ok(reply)
        })
    }
}

pub struct MediaHandler {
    host: Arc<SqliteMediaHost>,
    caller: OnceLock<Principal>,
}

fn failure(e: MediaError) -> HandlerOutcome {
    let code = match e {
        MediaError::Invalid => ErrorCode::InvalidArgument,
        MediaError::Conflict => ErrorCode::AlreadyExists,
        MediaError::Corrupt => ErrorCode::DataLoss,
        MediaError::Refused(code) => code,
        _ => ErrorCode::Internal,
    };
    HandlerOutcome::error(code, "media operation refused")
}

impl Handler for MediaHandler {
    fn authorize(&self, principal: &Principal, method: &str) -> std::result::Result<(), AuthError> {
        if principal.subject.is_empty() || *principal == Principal::anonymous() {
            return Err(AuthError::unauthenticated());
        }
        if Method::from_path(method).is_none() {
            return Err(AuthError::denied());
        }
        if self.caller.get_or_init(|| principal.clone()) != principal {
            return Err(AuthError::denied());
        }
        Ok(())
    }

    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        Box::pin(async {
            HandlerOutcome::error(
                ErrorCode::PermissionDenied,
                "media requires admitted context",
            )
        })
    }

    fn handle_with_context(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: CancelToken,
        lease: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        let host = self.host.clone();
        let caller = self.caller.get().cloned();
        Box::pin(async move {
            let (Some(principal), Some(method)) = (caller, Method::from_path(&method)) else {
                return HandlerOutcome::error(ErrorCode::PermissionDenied, "access denied");
            };
            let budget = context.budget();
            let result = tokio::task::spawn_blocking(move || {
                let response_frame_bytes = lease.response_frame_bytes();
                let _lease = lease;
                host.dispatch(&principal, method, &payload, response_frame_bytes, || {
                    if budget.check().is_err() {
                        return Err(MediaError::Refused(ErrorCode::DeadlineExceeded));
                    }
                    if cancel.is_cancelled() {
                        return Err(MediaError::Refused(ErrorCode::Cancelled));
                    }
                    Ok(())
                })
            })
            .await
            .unwrap_or(Err(MediaError::Worker));
            match result {
                Ok(bytes) => HandlerOutcome::Payload(bytes),
                Err(e) => failure(e),
            }
        })
    }
}
