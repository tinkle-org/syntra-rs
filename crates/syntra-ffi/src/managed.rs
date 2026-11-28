//! Protected native client. The C owner never exposes a stream, a cipher, or a
//! runtime pointer. See syntra_managed.h for the shared unsafe entry contract.
use super::recovery::Storage;
use super::{
    boundary, buffer, bytes, fresh, syntra_bytes_t, write, AbiResult, BUSY, CLOSED, EMPTY,
    INCOMPLETE, INTERNAL, INVALID, LIMIT, MISMATCH, OK, STALE, SYNTRA_ABI_VERSION,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    ptr,
    sync::{Arc, Mutex},
    time::Duration,
};
use syntra_core::{
    secure_channel::{Carrier, ClientConfig, Context, Mode, Secret32},
    MAX_CREDENTIAL_BYTES, MAX_FRAME_BYTES,
};
use syntra_net::{
    lanes::NotificationOperation,
    lanes::{Lane, LaneClient, LaneConfig, LaneError, MediaOperation},
    network::CallOperation,
    CallError, GenerationValue, LifecycleStatus, Notification,
};
use zeroize::Zeroizing;
#[path = "managed_updates.rs"]
mod updates;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct syntra_view_t {
    data: *const u8,
    len: usize,
}

impl syntra_view_t {
    unsafe fn copy(self, max: usize) -> AbiResult<Vec<u8>> {
        // SAFETY: the header requires an immutable live region for this call.
        unsafe { bytes(self.data, self.len, max) }
    }
    unsafe fn array<const N: usize>(&self) -> AbiResult<&[u8; N]> {
        if self.len != N || self.data.is_null() {
            return Err(INVALID);
        }
        // SAFETY: exact size checked; alignment is 1. The caller keeps the
        // underlying immutable C region live for this borrow.
        Ok(unsafe { &*self.data.cast::<[u8; N]>() })
    }
}

#[repr(C)]
pub struct syntra_managed_config_t {
    address: syntra_view_t,
    scope: syntra_view_t,
    server_pin: syntra_view_t,
    credential: syntra_view_t,
    mode: u32,
    server_key_id: u32,
    epoch: u64,
    handle: syntra_view_t,
    authorization_key: syntra_view_t,
}

struct Provision {
    address: SocketAddr,
    context: Context,
    pin: [u8; 32],
    key: Secret32,
    credential: Zeroizing<Vec<u8>>,
}
impl Provision {
    unsafe fn copy(c: &syntra_managed_config_t) -> AbiResult<Self> {
        // SAFETY: fields remain valid until open returns. Nothing foreign is retained.
        unsafe {
            let address = String::from_utf8(c.address.copy(64)?)
                .map_err(|_| INVALID)?
                .parse::<SocketAddr>()
                .map_err(|_| INVALID)?;
            if address.port() == 0
                || address.ip().is_unspecified()
                || address.ip().is_multicast()
                || c.mode != 2
            {
                return Err(INVALID);
            }
            let key = Secret32::from_borrowed(c.authorization_key.array()?);
            if key.expose().iter().fold(0u8, |a, b| a | b) == 0 {
                return Err(INVALID);
            }
            let context = Context {
                mode: Mode::Returning,
                handle: *c.handle.array()?,
                epoch: c.epoch,
                carrier: Carrier::Tcp,
                server_key_id: c.server_key_id,
                scope: c.scope.copy(255)?,
            };
            context.encode().map_err(|_| INVALID)?;
            let pin = *c.server_pin.array()?;
            if pin == [0; 32] {
                return Err(INVALID);
            }
            Ok(Self {
                address,
                context,
                pin,
                key,
                credential: Zeroizing::new(c.credential.copy(MAX_CREDENTIAL_BYTES)?),
            })
        }
    }
    fn inputs(&self) -> (ClientConfig, Zeroizing<Vec<u8>>) {
        (
            ClientConfig {
                context: self.context.clone(),
                server_public_key: self.pin,
                authorization_key: Some(Secret32::from_borrowed(self.key.expose())),
            },
            self.credential.clone(),
        )
    }
}

#[repr(C)]
#[derive(Default)]
pub struct syntra_lane_status_t {
    state: u32,
    attempt: u32,
    generation: u64,
}
impl From<LifecycleStatus> for syntra_lane_status_t {
    fn from(s: LifecycleStatus) -> Self {
        use LifecycleStatus::*;
        let (state, attempt, generation) = match s {
            Starting => (0, 0, 0),
            Connecting { attempt } => (1, attempt, 0),
            CoreReady(r) | RecoveryNegotiated(r) => (2, 0, r.generation),
            Backoff { attempts, .. } => (3, attempts, 0),
            Paused => (4, 0, 0),
            Offline => (5, 0, 0),
            Blocked(_) => (6, 0, 0),
            Exhausted { attempts, .. } => (7, attempts, 0),
            Stopping => (8, 0, 0),
            Stopped => (9, 0, 0),
            ShutdownIncomplete => (10, 0, 0),
            Retired(_) => (11, 0, 0),
        };
        Self {
            state,
            attempt,
            generation,
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct syntra_managed_result_t {
    grpc_code: i32,
    has_data: u32,
    generation: u64,
    dropped_count: u64,
    dropped_bytes: u64,
    data: syntra_bytes_t,
}

#[derive(Default)]
struct Reply {
    code: i32,
    generation: u64,
    data: Option<Vec<u8>>,
    lost: u64,
    lost_bytes: u64,
}

fn managed_error_code(error: &syntra_core::SyntraError) -> i32 {
    match error {
        syntra_core::SyntraError::Rpc {
            raw_code: Some(raw),
            ..
        } => *raw,
        _ => error.code().as_i32(),
    }
}

impl From<CallError> for Reply {
    fn from(e: CallError) -> Self {
        let (code, generation) = match e {
            CallError::Unavailable { generation } => (14, generation.unwrap_or(0)),
            CallError::Rpc { generation, source } => (managed_error_code(&source), generation),
        };
        Self {
            code,
            generation,
            ..Self::default()
        }
    }
}
impl From<GenerationValue<Vec<u8>>> for Reply {
    fn from(v: GenerationValue<Vec<u8>>) -> Self {
        Self {
            generation: v.generation,
            data: Some(v.value),
            ..Self::default()
        }
    }
}
impl From<GenerationValue<Notification>> for Reply {
    fn from(v: GenerationValue<Notification>) -> Self {
        Self {
            generation: v.generation,
            data: v.value.payload,
            lost: v.value.dropped_count,
            lost_bytes: v.value.dropped_bytes,
            ..Self::default()
        }
    }
}
impl Reply {
    fn export(self) -> AbiResult<syntra_managed_result_t> {
        let mut out = syntra_managed_result_t {
            grpc_code: self.code,
            generation: self.generation,
            has_data: self.data.is_some().into(),
            dropped_count: self.lost,
            dropped_bytes: self.lost_bytes,
            ..Default::default()
        };
        if let Some(data) = self.data {
            if data.len() > MAX_FRAME_BYTES {
                return Err(INTERNAL);
            }
            // SAFETY: disjoint, live fields; boxed slice is released by syntra_free.
            unsafe {
                buffer(data, &mut out.data.data, &mut out.data.len)?;
            }
        }
        Ok(out)
    }
}

fn lane(n: u32) -> AbiResult<Lane> {
    match n {
        1 => Ok(Lane::Interactive),
        2 => Ok(Lane::Media),
        _ => Err(INVALID),
    }
}
fn admission(e: LaneError) -> i32 {
    match e {
        LaneError::NotReady => EMPTY,
        LaneError::Busy | LaneError::Network(syntra_net::Error::Configuration) => BUSY,
        LaneError::Invalid => INVALID,
        LaneError::Network(syntra_net::Error::Closed) => CLOSED,
        LaneError::Call(_) => STALE,
        _ => INTERNAL,
    }
}

enum Job {
    Call(CallOperation, bool),
    Media(MediaOperation, bool),
    Notification(NotificationOperation),
    Transfer(transfer::Worker),
}
impl Job {
    fn take(&mut self) -> Option<AbiResult<Reply>> {
        Some(match self {
            Self::Call(op, cancel) => op
                .try_take()?
                .map(|r| r.map(Reply::from).unwrap_or_else(Reply::from))
                .map(|r| r.local_cancel(*cancel))
                .map_err(|_| INTERNAL),
            Self::Notification(op) => op
                .try_take()?
                .map(|r| r.map(Reply::from).unwrap_or_else(Reply::from))
                .map_err(|_| INTERNAL),
            Self::Media(op, cancel) => op
                .try_take()?
                .map(|r| match r {
                    Ok(r) => Reply {
                        generation: r.generation(),
                        data: Some(r.into_bytes()),
                        ..Default::default()
                    },
                    Err(LaneError::Call(e)) => e.into(),
                    Err(LaneError::ResponseTooLarge { generation }) => Reply {
                        generation,
                        code: 8,
                        ..Default::default()
                    },
                    Err(LaneError::Expired) => Reply {
                        code: 4,
                        ..Default::default()
                    },
                    Err(_) => Reply {
                        code: 14,
                        ..Default::default()
                    },
                })
                .map(|r| r.local_cancel(*cancel))
                .map_err(|_| INTERNAL),
            Self::Transfer(w) => return w.take(),
        })
    }
}

impl Reply {
    fn local_cancel(self, cancelled: bool) -> Self {
        if cancelled {
            Self {
                code: 1,
                generation: self.generation,
                ..Self::default()
            }
        } else {
            self
        }
    }
}

#[derive(Default)]
struct State {
    client: Option<AbiResult<Arc<LaneClient>>>,
    stopping: bool,
    worker_failed: bool,
    terminal: Option<i32>,
    init: Option<std::thread::JoinHandle<()>>,
    jobs: HashMap<u64, Job>,
    storage: Option<Arc<Storage>>,
}
impl State {
    fn active(&self) -> AbiResult<&Arc<LaneClient>> {
        if self.stopping {
            return Err(CLOSED);
        }
        self.client.as_ref().ok_or(EMPTY)?.as_ref().map_err(|e| *e)
    }
    fn slot(&self) -> AbiResult<u64> {
        if self.stopping {
            return Err(CLOSED);
        }
        if self.jobs.len() >= LIMIT {
            return Err(BUSY);
        }
        fresh()
    }
    fn bulk_slot(&self) -> AbiResult<u64> {
        let token = self.slot()?;
        if self
            .jobs
            .values()
            .filter(|j| matches!(j, Job::Media(..) | Job::Transfer(_)))
            .count()
            >= 6
        {
            return Err(BUSY);
        }
        Ok(token)
    }
}

#[allow(non_camel_case_types)]
pub struct syntra_managed_t {
    id: u64,
    state: Arc<Mutex<State>>,
}

// SAFETY: every exported function below uses the common live, aligned,
// nonaliasing pointer contract in syntra_managed.h, including exclusive destroy.
unsafe fn state<'a>(
    p: *mut syntra_managed_t,
    id: u64,
) -> AbiResult<std::sync::MutexGuard<'a, State>> {
    let h = unsafe { p.as_ref() }.ok_or(INVALID)?;
    if h.id != id {
        return Err(STALE);
    }
    h.state.lock().map_err(|_| INTERNAL)
}

#[no_mangle]
pub unsafe extern "C" fn syntra_managed_open(
    abi: u32,
    c: *const syntra_managed_config_t,
    out: *mut *mut syntra_managed_t,
    id: *mut u64,
) -> i32 {
    boundary(|| unsafe { open(abi, c, None, out, id) })
}

unsafe fn open(
    abi: u32,
    c: *const syntra_managed_config_t,
    updates: Option<*const updates::syntra_updates_t>,
    out: *mut *mut syntra_managed_t,
    id: *mut u64,
) -> AbiResult<i32> {
    unsafe {
        write(out, ptr::null_mut())?;
        write(id, 0)?;
        if abi != SYNTRA_ABI_VERSION {
            return Err(MISMATCH);
        }
        let provision = Provision::copy(c.as_ref().ok_or(INVALID)?)?;
        let updates = updates
            .map(|p| updates::Config::copy(p.as_ref().ok_or(INVALID)?))
            .transpose()?;
        let h = Box::new(syntra_managed_t {
            id: fresh()?,
            state: Arc::new(Mutex::new(State {
                storage: updates.as_ref().map(|u| u.storage.clone()),
                ..Default::default()
            })),
        });
        let shared = h.state.clone();
        let init = std::thread::Builder::new()
            .name("syntra-managed-open".into())
            .spawn(move || {
                let client = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let address = provision.address;
                    let inputs = move || Ok(provision.inputs());
                    match updates {
                        None => LaneClient::tcp_zeroizing(address, LaneConfig::default(), inputs),
                        Some(u) => {
                            let (stream, app) = u.into_stream();
                            LaneClient::tcp_with_updates_zeroizing(
                                address,
                                LaneConfig::default(),
                                inputs,
                                stream,
                                app,
                            )
                        }
                    }
                }))
                .map_err(|_| INTERNAL)
                .and_then(|r| r.map(Arc::new).map_err(admission));
                let mut s = shared.lock().unwrap_or_else(|e| e.into_inner());
                if s.stopping {
                    if let Ok(c) = &client {
                        c.stop();
                    }
                }
                s.client = Some(client);
            })
            .map_err(|_| INTERNAL)?;
        h.state.lock().map_err(|_| INTERNAL)?.init = Some(init);
        write(id, h.id)?;
        write(out, Box::into_raw(h))?;
        Ok(OK)
    }
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_status(
    p: *mut syntra_managed_t,
    id: u64,
    n: u32,
    out: *mut syntra_lane_status_t,
) -> i32 {
    boundary(|| unsafe {
        write(out, Default::default())?;
        let lane = lane(n)?;
        let s = state(p, id)?;
        if let Some(client) = &s.client {
            write(out, client.as_ref().map_err(|e| *e)?.status(lane).into())?;
        }
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_call(
    p: *mut syntra_managed_t,
    id: u64,
    n: u32,
    method: syntra_view_t,
    payload: syntra_view_t,
    timeout_ms: u32,
    out: *mut u64,
) -> i32 {
    boundary(|| unsafe {
        write(out, 0)?;
        let lane = lane(n)?;
        let mut s = state(p, id)?;
        let token = if lane == Lane::Media {
            s.bulk_slot()?
        } else {
            s.slot()?
        };
        let c = s.active()?;
        let method = String::from_utf8(method.copy(512)?).map_err(|_| INVALID)?;
        syntra_core::validate_method(&method).map_err(|_| INVALID)?;
        if payload.len > MAX_FRAME_BYTES || (payload.len > 0 && payload.data.is_null()) {
            return Err(INVALID);
        }
        let job = match lane {
            Lane::Interactive => Job::Call(
                c.call_interactive(method, payload.copy(MAX_FRAME_BYTES)?, timeout_ms)
                    .map_err(|e| admission(e.into()))?,
                false,
            ),
            Lane::Media => {
                let reservation = c
                    .try_reserve_media(payload.len, MAX_FRAME_BYTES)
                    .map_err(admission)?;
                Job::Media(
                    reservation
                        .call(&method, payload.copy(MAX_FRAME_BYTES)?, timeout_ms)
                        .map_err(admission)?,
                    false,
                )
            }
        };
        s.jobs.insert(token, job);
        write(out, token)?;
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_next_notification(
    p: *mut syntra_managed_t,
    id: u64,
    n: u32,
    out: *mut u64,
) -> i32 {
    boundary(|| unsafe {
        write(out, 0)?;
        if lane(n)? != Lane::Interactive {
            return Err(INVALID);
        }
        let mut s = state(p, id)?;
        let token = s.slot()?;
        if s.jobs.values().any(|j| matches!(j, Job::Notification(_))) {
            return Err(BUSY);
        }
        let job = s.active()?.next_notification().map_err(admission)?;
        s.jobs.insert(token, Job::Notification(job));
        write(out, token)?;
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_poll(
    p: *mut syntra_managed_t,
    id: u64,
    token: u64,
    out: *mut syntra_managed_result_t,
) -> i32 {
    boundary(|| unsafe {
        write(out, Default::default())?;
        let mut s = state(p, id)?;
        let reply = s.jobs.get_mut(&token).ok_or(STALE)?.take().ok_or(EMPTY)?;
        s.worker_failed |= reply.is_err();
        s.jobs.remove(&token);
        write(out, reply?.export()?)?;
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_control(
    p: *mut syntra_managed_t,
    id: u64,
    action: u32,
) -> i32 {
    boundary(|| unsafe {
        let s = state(p, id)?;
        let c = s.active()?;
        match action {
            1 => c.pause(),
            2 => c.resume(),
            3 => c.network_available(false),
            4 => c.network_available(true),
            5 => c.platform_wake(),
            6 => c.retry(),
            _ => return Err(INVALID),
        };
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_shutdown(p: *mut syntra_managed_t, id: u64) -> i32 {
    boundary(|| unsafe {
        let mut s = state(p, id)?;
        s.stopping = true;
        if let Some(storage) = &s.storage {
            storage.retire()?;
        }
        for job in s.jobs.values() {
            if let Job::Transfer(w) = job {
                w.cancel();
            }
        }
        if let Some(Ok(c)) = &s.client {
            c.stop();
        }
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_shutdown_poll(p: *mut syntra_managed_t, id: u64) -> i32 {
    boundary(|| unsafe {
        let mut s = state(p, id)?;
        if let Some(code) = s.terminal {
            return Ok(code);
        }
        if !s.stopping || s.init.as_ref().is_some_and(|t| !t.is_finished()) {
            return Ok(INCOMPLETE);
        }
        if let Some(storage) = &s.storage {
            if storage.pending()? {
                return Ok(INCOMPLETE);
            }
        }
        let mut failed = s.init.take().is_some_and(|t| t.join().is_err());
        for job in s.jobs.values_mut() {
            if let Job::Transfer(worker) = job {
                match worker.joined() {
                    None => return Ok(INCOMPLETE),
                    Some(Err(_)) => failed = true,
                    Some(Ok(_)) => (),
                }
            }
        }
        s.worker_failed |= failed;
        let code = match &s.client {
            Some(Ok(c)) => {
                let r = c.shutdown(Duration::ZERO);
                if !r.complete {
                    return Ok(INCOMPLETE);
                }
                if r.failed_supervisors != 0 || r.pending_operations != 0 || s.worker_failed {
                    INTERNAL
                } else {
                    OK
                }
            }
            _ => INTERNAL,
        };
        s.terminal = Some(code);
        Ok(code)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_destroy(p: *mut syntra_managed_t, id: u64) -> i32 {
    boundary(|| unsafe {
        if state(p, id)?.terminal.is_none() {
            return Ok(INCOMPLETE);
        }
        drop(Box::from_raw(p));
        Ok(OK)
    })
}

#[path = "managed_transfer.rs"]
mod transfer;
