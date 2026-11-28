use super::*;
use crate::production::{
    recovery::{self, ForeignPersistence, STATE_MAX},
    syntra_record_t, syntra_storage_request_t,
};
use std::{future::Future, pin::Pin};
use syntra_core::proto::RecoveryBatch;
use syntra_net::lanes::{UpdateApplication, UpdateStatus, UpdateStream};
use syntra_runtime::recovery::{
    persistence::{DurableRecord, PersistenceScope},
    wire_client::RecoveryClientError,
};

type Restore = unsafe extern "C" fn(usize, u64, *const syntra_record_t) -> i32;
type Apply = unsafe extern "C" fn(
    usize,
    u64,
    u64,
    syntra_view_t,
    syntra_view_t,
    syntra_view_t,
    *mut u8,
    usize,
    *mut usize,
) -> i32;
#[repr(C)]
pub struct syntra_updates_t {
    principal_scope: syntra_view_t,
    stable_stream: syntra_view_t,
    selector: syntra_view_t,
    context: usize,
    restore: Option<Restore>,
    apply: Option<Apply>,
}
pub(super) struct Config {
    pub(super) storage: Arc<Storage>,
    scope: PersistenceScope,
    selector: Vec<u8>,
    app: Callbacks,
}
pub(super) struct Callbacks {
    context: usize,
    restore: Restore,
    apply: Apply,
}
impl Config {
    pub(super) unsafe fn copy(c: &syntra_updates_t) -> AbiResult<Self> {
        let (p, s, selector) = unsafe {
            (
                c.principal_scope.copy(1024)?,
                c.stable_stream.copy(1024)?,
                c.selector.copy(1024)?,
            )
        };
        if selector.is_empty() {
            return Err(INVALID);
        }
        Ok(Self {
            storage: Storage::new(Default::default()),
            scope: PersistenceScope::new(p, s).map_err(|_| INVALID)?,
            selector,
            app: Callbacks {
                context: c.context,
                restore: c.restore.ok_or(INVALID)?,
                apply: c.apply.ok_or(INVALID)?,
            },
        })
    }
    pub(super) fn into_stream(self) -> (UpdateStream<ForeignPersistence>, Arc<Callbacks>) {
        (
            UpdateStream {
                principal_scope: self.scope.principal_scope().to_vec(),
                stable_stream: self.scope.stable_stream().to_vec(),
                selector: self.selector,
                store: Arc::new(Mutex::new(ForeignPersistence(self.storage))),
                limits: recovery::limits(),
            },
            Arc::new(self.app),
        )
    }
}

type Work<'a, T> = Pin<Box<dyn Future<Output = Result<T, RecoveryClientError>> + Send + 'a>>;
fn view(buf: &[u8]) -> syntra_view_t {
    syntra_view_t {
        data: buf.as_ptr(),
        len: buf.len(),
    }
}
impl UpdateApplication for Callbacks {
    fn restore(&self, g: u64, r: DurableRecord) -> Work<'_, ()> {
        Box::pin(async move {
            let record = syntra_record_t {
                generation: r.generation,
                checkpoint: r.checkpoint.as_ptr(),
                checkpoint_len: r.checkpoint.len(),
                application_state: r.application_state.as_ptr(),
                application_state_len: r.application_state.len(),
            };
            // SAFETY: all borrowed fields outlive this synchronous callback. C retains
            // neither inputs nor outputs; context/functions remain live through shutdown.
            if unsafe { (self.restore)(self.context, g, &record) } != 0 {
                return Err(RecoveryClientError::InvalidState);
            }
            Ok(())
        })
    }
    fn apply(&self, g: u64, b: RecoveryBatch) -> Work<'_, Vec<u8>> {
        Box::pin(async move {
            let mut state = vec![0; STATE_MAX];
            let mut used = 0;
            // SAFETY: input and initialized bounded output have independent storage;
            // C writes at most capacity, and no returned pointer is ever dereferenced.
            let rc = unsafe {
                (self.apply)(
                    self.context,
                    g,
                    b.generation,
                    view(&b.predecessor_checkpoint),
                    view(&b.result_checkpoint),
                    view(&b.batch_payload),
                    state.as_mut_ptr(),
                    state.len(),
                    &mut used,
                )
            };
            if rc != 0 || used > state.len() {
                return Err(RecoveryClientError::InvalidState);
            }
            state.truncate(used);
            Ok(state)
        })
    }
}

#[no_mangle]
pub unsafe extern "C" fn syntra_managed_open_updates(
    abi: u32,
    c: *const syntra_managed_config_t,
    u: *const syntra_updates_t,
    out: *mut *mut syntra_managed_t,
    id: *mut u64,
) -> i32 {
    boundary(|| unsafe { open(abi, c, Some(u), out, id) })
}
#[repr(C)]
#[derive(Default)]
pub struct syntra_update_status_t {
    state: u32,
    grpc_code: i32,
    generation: u64,
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_update_status(
    p: *mut syntra_managed_t,
    id: u64,
    out: *mut syntra_update_status_t,
) -> i32 {
    boundary(|| unsafe {
        write(out, Default::default())?;
        let s = state(p, id)?;
        let status = match &s.client {
            Some(c) => c.as_ref().map_err(|e| *e)?.update_status(),
            None if s.storage.is_some() => UpdateStatus::Waiting,
            None => UpdateStatus::Disabled,
        };
        let (state, generation, grpc_code) = match status {
            UpdateStatus::Disabled => (0, 0, 0),
            UpdateStatus::Waiting => (1, 0, 0),
            UpdateStatus::Restoring(g) => (2, g, 0),
            UpdateStatus::Restored(g) => (3, g, 0),
            UpdateStatus::Failed(g, e) => (4, g, e.code().as_i32()),
        };
        write(
            out,
            syntra_update_status_t {
                state,
                grpc_code,
                generation,
            },
        )?;
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_storage_take(
    p: *mut syntra_managed_t,
    id: u64,
    out: *mut syntra_storage_request_t,
) -> i32 {
    boundary(|| unsafe {
        write(out, Default::default())?;
        let s = state(p, id)?;
        recovery::take_storage(s.storage.as_ref().ok_or(INVALID)?, out)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_storage_complete(
    p: *mut syntra_managed_t,
    id: u64,
    token: u64,
    status: u32,
    r: *const syntra_record_t,
) -> i32 {
    boundary(|| unsafe {
        let s = state(p, id)?;
        recovery::complete_storage(s.storage.as_ref().ok_or(INVALID)?, token, status, r)
    })
}
