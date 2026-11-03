//! Syntra 1.0 production ABI 1 over the shared runtime.
//! Low-level plaintext Core frames; the application driver owns protected I/O.
//! See syntra_production.h for the memory, callback and carrier contracts.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle as Thread;
use std::time::{Duration, Instant};

use syntra_core::{ErrorCode, SyntraError, MAX_CREDENTIAL_BYTES, MAX_FRAME_BYTES};
use syntra_runtime::elapsed::{ElapsedClock, ElapsedSource};
use syntra_runtime::{
    AuthError, Authenticator, CancelToken, ConnectionConfig, ExecutionBudget, ExecutionLease,
    Handler, HandlerFut, HandlerOutcome, Host, Initiator, Principal,
};
use tokio::runtime::{Builder, Handle};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

const OK: i32 = 0;
const EMPTY: i32 = 1;
const INCOMPLETE: i32 = 2;
const INVALID: i32 = -1;
const CLOSED: i32 = -2;
const MISMATCH: i32 = -3;
const INTERNAL: i32 = -6;
const STALE: i32 = -7;
const BUSY: i32 = -8;
const LIMIT: usize = 32;

/// Sole production ABI; independent of Core wire/profile versions.
pub const SYNTRA_ABI_VERSION: u32 = 1;
/// Plaintext Core frame adapter, not a secure carrier.
pub const SYNTRA_CAP_CORE: u64 = 1;
/// Reserved cryptographic record protection; unset by this plaintext adapter.
pub const SYNTRA_CAP_RECORD_PROTECTION: u64 = 2;
/// Typed recovery client and foreign persistence receipts, not a provider.
pub const SYNTRA_CAP_RECOVERY_CLIENT: u64 = 4;
/// Shared-runtime suspend/wake lifecycle and elapsed clock integration.
pub const SYNTRA_CAP_LIFECYCLE: u64 = 8;

type AbiResult<T> = Result<T, i32>;
type Output = Result<Vec<u8>, SyntraError>;
type Work = JoinHandle<(u64, Output)>;

// IDs fence replacement handles as well as per-handle slots. Exhaustion is
// permanent; no wrapping, random collision assumption or pointer identity.
static NEXT: AtomicU64 = AtomicU64::new(1);
fn fresh() -> AbiResult<u64> {
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| INTERNAL)
}

/// Synchronous policy hooks, copied at open. Context is an opaque caller word.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct syntra_policy_t {
    pub context: usize,
    pub authenticate:
        Option<unsafe extern "C" fn(usize, *const u8, usize, *mut u8, usize, *mut usize) -> i32>,
    pub authorize: Option<unsafe extern "C" fn(usize, *const u8, usize, *const u8, usize) -> i32>,
}

/// Trusted local elapsed nanoseconds, sampled promptly on arbitrary threads.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct syntra_clock_t {
    pub context: usize,
    pub sample: Option<unsafe extern "C" fn(usize, *mut u64) -> i32>,
}

struct ClockSource(syntra_clock_t);
impl ElapsedSource for ClockSource {
    fn elapsed(&self) -> Option<Duration> {
        let mut nanos = 0;
        let sample = self.0.sample?;
        // SAFETY: caller retains callback/context through owner destruction.
        // The callback may only write this live scalar, and cannot reenter FFI.
        (unsafe { sample(self.0.context, &mut nanos) } == 0).then_some(Duration::from_nanos(nanos))
    }
}

struct Policy(syntra_policy_t);
impl Authenticator for Policy {
    fn authenticate(&self, credential: &[u8]) -> Result<Principal, AuthError> {
        let mut principal = [0u8; 1024];
        let mut len = 0;
        let callback = self.0.authenticate.ok_or_else(AuthError::unauthenticated)?;
        // SAFETY: callbacks/context remain live until successful destroy. The
        // header prohibits retention/reentry and bounds writes to this stack
        // buffer. All borrowed slices live through this synchronous invocation.
        let code = unsafe {
            callback(
                self.0.context,
                credential.as_ptr(),
                credential.len(),
                principal.as_mut_ptr(),
                principal.len(),
                &mut len,
            )
        };
        if code != 0 || !(1..=principal.len()).contains(&len) {
            return Err(if code == 7 {
                AuthError::denied()
            } else {
                AuthError::unauthenticated()
            });
        }
        let subject =
            std::str::from_utf8(&principal[..len]).map_err(|_| AuthError::unauthenticated())?;
        Ok(Principal::new(subject))
    }
}

struct Dispatch {
    method: Option<String>,
    payload: Vec<u8>,
    cancel: CancelToken,
    reply: oneshot::Sender<HandlerOutcome>,
    // Foreign execution can outlive cancellation/drop of HandlerFut. This
    // lease is released only on completion acknowledgement, or before delivery.
    _lease: ExecutionLease,
}
#[derive(Default)]
struct Dispatches(HashMap<u64, Dispatch>);
impl Dispatches {
    fn reap_undelivered(&mut self) {
        self.0
            .retain(|_, d| d.method.is_none() || !d.reply.is_closed());
    }
}
struct ForeignHandler {
    policy: Policy,
    dispatches: Arc<Mutex<Dispatches>>,
}
impl Handler for ForeignHandler {
    fn authorize(&self, principal: &Principal, method: &str) -> Result<(), AuthError> {
        let callback = self.policy.0.authorize.ok_or_else(AuthError::denied)?;
        // SAFETY: same lifetime/reentry contract as authenticate; these slices
        // are immutable and borrowed only for this synchronous invocation.
        let code = unsafe {
            callback(
                self.policy.0.context,
                principal.subject.as_ptr(),
                principal.subject.len(),
                method.as_ptr(),
                method.len(),
            )
        };
        match code {
            0 => Ok(()),
            16 => Err(AuthError::unauthenticated()),
            _ => Err(AuthError::denied()),
        }
    }

    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        // Host always invokes handle_with_execution. Fail closed if that ever
        // changes; never dispatch foreign work without an execution lease.
        Box::pin(async { HandlerOutcome::error(ErrorCode::Internal, "execution lease required") })
    }

    fn handle_with_execution(
        &self,
        method: String,
        payload: Vec<u8>,
        cancel: CancelToken,
        lease: ExecutionLease,
    ) -> HandlerFut {
        let (tx, rx) = oneshot::channel();
        let admitted = (|| {
            let mut slots = self.dispatches.lock().map_err(|_| INTERNAL)?;
            slots.reap_undelivered();
            if slots.0.len() == LIMIT {
                return Err(BUSY);
            }
            slots.0.insert(
                fresh()?,
                Dispatch {
                    method: Some(method),
                    payload,
                    cancel,
                    reply: tx,
                    _lease: lease,
                },
            );
            Ok(())
        })();
        Box::pin(async move {
            if admitted.is_err() {
                return HandlerOutcome::error(ErrorCode::ResourceExhausted, "dispatch unavailable");
            }
            rx.await.unwrap_or_else(|_| {
                HandlerOutcome::error(ErrorCode::Internal, "completion owner lost")
            })
        })
    }
}

#[derive(Clone)]
enum Endpoint {
    Client(Initiator),
    Host(Arc<Host>),
}
impl Endpoint {
    fn clock(&self) -> ElapsedClock {
        match self {
            Self::Client(c) => c.elapsed_clock(),
            Self::Host(h) => h.elapsed_clock(),
        }
    }
    fn suspend(&self) {
        match self {
            Self::Client(c) => c.suspend(),
            Self::Host(h) => h.suspend(),
        }
    }
    async fn platform_wake(&self) {
        match self {
            Self::Client(c) => c.platform_wake().await,
            Self::Host(h) => h.platform_wake().await,
        }
    }
    fn closed(&self) -> bool {
        match self {
            Self::Client(c) => c.is_closed(),
            Self::Host(h) => h.is_closed(),
        }
    }
    fn reason(&self) -> i32 {
        match self {
            Self::Client(c) => c.terminal_reason(),
            Self::Host(h) => h.terminal_reason(),
        }
        .map_or(0, |e| e.code().as_i32())
    }
    fn begin_shutdown(&self, total: Duration) -> AbiResult<syntra_runtime::ShutdownBudget> {
        match self {
            Self::Client(c) => c.begin_shutdown(total),
            Self::Host(h) => h.begin_shutdown(total),
        }
        .map_err(|_| INVALID)?;
        match self {
            Self::Client(c) => c.shutdown_budget(),
            Self::Host(h) => h.shutdown_budget(),
        }
        .ok_or(INTERNAL)
    }
    fn shutdown_report(&self) -> syntra_runtime::ShutdownReport {
        match self {
            Self::Client(c) => c.shutdown_report(),
            Self::Host(h) => h.shutdown_report(),
        }
    }
    fn register_reader(&self) -> AbiResult<()> {
        match self {
            Self::Client(c) => c.register_transport_tasks(1),
            Self::Host(h) => h.register_transport_tasks(1),
        }
        .map_err(|_| INTERNAL)
    }
    fn reader_joined(&self) -> AbiResult<()> {
        match self {
            Self::Client(c) => c.acknowledge_transport_task_joined(),
            Self::Host(h) => h.acknowledge_transport_task_joined(),
        }
        .map_err(|_| INTERNAL)
    }
    fn carrier_closed(&self) {
        match self {
            Self::Client(c) => c.acknowledge_transport_closed(),
            Self::Host(h) => h.acknowledge_transport_closed(),
        }
    }
    async fn transport_lost(&self) {
        match self {
            Self::Client(c) => c.on_transport_lost().await,
            Self::Host(h) => h.on_transport_lost().await,
        }
    }
}

struct Job {
    work: Option<Work>,
    result: Option<AbiResult<(u64, Output)>>,
    cancel: Option<CancelToken>,
    recovery: bool,
}
impl Job {
    fn observe(&mut self) -> bool {
        if let Some(work) = self.work.as_mut() {
            if work.is_finished() {
                if let Poll::Ready(result) =
                    Pin::new(work).poll(&mut Context::from_waker(Waker::noop()))
                {
                    self.result = Some(result.map_err(|_| INTERNAL));
                    self.work = None;
                }
            }
        }
        self.result.is_some()
    }
}
struct Shutdown {
    deadline: Instant,
    drain_cutoff: Instant,
    work: Option<JoinHandle<()>>,
    carrier_closed: bool,
}
struct State {
    writer: mpsc::Receiver<Vec<u8>>,
    receipts: VecDeque<(u64, Instant)>,
    emitting: Option<u64>,
    jobs: HashMap<u64, Job>,
    shutdown: Option<Shutdown>,
    withdrawal: Option<JoinHandle<()>>,
    transport_loss: Option<JoinHandle<()>>,
    wake: Option<JoinHandle<()>>,
    retired: bool,
    notification_pending: Option<u64>,
    failed: bool,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<Thread<()>>,
}

/// Opaque native owner. No address is used as a generation or completion ID.
#[repr(C)]
pub struct syntra_t {
    generation: u64,
    runtime: Handle,
    endpoint: Endpoint,
    inbound: mpsc::Sender<(Vec<u8>, Instant)>,
    reader: Mutex<Option<JoinHandle<()>>>,
    dispatches: Arc<Mutex<Dispatches>>,
    handshake_started: AtomicBool,
    recovery: Mutex<Option<Arc<recovery::Recovery>>>,
    // std Mutex: synchronous ownership transitions only, never held across
    // await or foreign policy callbacks. Runtime tasks use separate channels.
    state: Mutex<State>,
}

fn config() -> ConnectionConfig {
    ConnectionConfig {
        writer_capacity: LIMIT,
        notification_capacity: LIMIT,
        ..ConnectionConfig::default()
    }
}

fn open(policy: Option<syntra_policy_t>) -> AbiResult<Box<syntra_t>> {
    open_with_clock(policy, None)
}

fn open_with_clock(
    policy: Option<syntra_policy_t>,
    clock: Option<ElapsedClock>,
) -> AbiResult<Box<syntra_t>> {
    let generation = fresh()?;
    let dispatches = Arc::new(Mutex::new(Dispatches::default()));
    let slots = dispatches.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (stop, stopped) = oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("syntra-ffi".into())
        .spawn(move || {
            // A dedicated current-thread executor keeps timers/tasks running while
            // foreign code is idle, without blocking a caller-owned Tokio worker.
            let runtime = match Builder::new_current_thread().enable_time().build() {
                Ok(r) => r,
                Err(_) => {
                    let _ = ready_tx.send(Err(INTERNAL));
                    return;
                }
            };
            runtime.block_on(async move {
                let built = (|| {
                    let (endpoint, writer) = if let Some(callbacks) = policy {
                        static BUDGET: OnceLock<ExecutionBudget> = OnceLock::new();
                        let (h, rx) = Host::try_new_with_execution_budget_and_clock(
                            config(),
                            Arc::new(Policy(callbacks)),
                            Arc::new(ForeignHandler {
                                policy: Policy(callbacks),
                                dispatches: slots,
                            }),
                            BUDGET.get_or_init(|| ExecutionBudget::new(1024)).clone(),
                            clock.unwrap_or_default(),
                        )
                        .map_err(|_| INVALID)?;
                        (Endpoint::Host(h), rx)
                    } else {
                        let (c, rx) =
                            Initiator::try_new_with_clock(config(), clock.unwrap_or_default())
                                .map_err(|_| INVALID)?;
                        (Endpoint::Client(c), rx)
                    };
                    endpoint.register_reader()?;
                    let (inbound, mut rx) = mpsc::channel::<(Vec<u8>, Instant)>(LIMIT);
                    let peer = endpoint.clone();
                    let reader = tokio::spawn(async move {
                        while let Some((bytes, received)) = rx.recv().await {
                            match &peer {
                                Endpoint::Client(c) => c.ingest(&bytes).await,
                                Endpoint::Host(h) => h.ingest_received_at(&bytes, received).await,
                            }
                        }
                    });
                    Ok((Handle::current(), endpoint, writer, inbound, reader))
                })();
                if ready_tx.send(built).is_ok() {
                    let _ = stopped.await;
                }
            });
            // No FFI spawn_blocking jobs or foreign callbacks are started during
            // teardown. Dropping this runtime cancels remaining cooperative tasks;
            // the native thread is subsequently joined before destroy succeeds.
            drop(runtime);
        })
        .map_err(|_| INTERNAL)?;
    let (runtime, endpoint, writer, inbound, reader) = match ready_rx.recv() {
        Ok(Ok(built)) => built,
        _ => {
            // An initialization error may leave the runtime awaiting shutdown.
            drop(stop);
            let _ = thread.join();
            return Err(INTERNAL);
        }
    };
    Ok(Box::new(syntra_t {
        generation,
        runtime,
        endpoint,
        inbound,
        reader: Mutex::new(Some(reader)),
        dispatches,
        handshake_started: AtomicBool::new(false),
        recovery: Mutex::new(None),
        state: Mutex::new(State {
            writer,
            receipts: VecDeque::new(),
            emitting: None,
            jobs: HashMap::new(),
            shutdown: None,
            withdrawal: None,
            transport_loss: None,
            wake: None,
            retired: false,
            notification_pending: None,
            failed: false,
            stop: Some(stop),
            thread: Some(thread),
        }),
    }))
}

impl syntra_t {
    fn submit(
        &self,
        f: impl Future<Output = (u64, Output)> + Send + 'static,
        cancel: Option<CancelToken>,
    ) -> AbiResult<u64> {
        let mut state = self.state.lock().map_err(|_| INTERNAL)?;
        if state.failed {
            return Err(INTERNAL);
        }
        if state.retired
            || state.shutdown.is_some()
            || state.withdrawal.is_some()
            || self.endpoint.closed()
        {
            return Err(CLOSED);
        }
        if state.jobs.len() >= LIMIT {
            return Err(BUSY);
        }
        let token = fresh()?;
        state.jobs.insert(
            token,
            Job {
                work: Some(self.runtime.spawn(f)),
                result: None,
                cancel,
                recovery: false,
            },
        );
        Ok(token)
    }
}

fn boundary(f: impl FnOnce() -> AbiResult<i32>) -> i32 {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or(Err(INTERNAL))
        .unwrap_or_else(|code| code)
}

// Raw-pointer access is confined to these helpers and the consuming destroy.
// SAFETY contracts are imposed by the header, not inferred from null checks.
unsafe fn owner<'a>(p: *mut syntra_t, generation: u64) -> AbiResult<&'a syntra_t> {
    // SAFETY: caller holds a live owner, no concurrent destroy, properly aligned.
    let owner = unsafe { p.as_ref() }.ok_or(INVALID)?;
    if owner.generation != generation {
        return Err(STALE);
    }
    Ok(owner)
}
unsafe fn write<T>(p: *mut T, value: T) -> AbiResult<()> {
    if p.is_null() {
        return Err(INVALID);
    }
    // SAFETY: required writable/aligned nonaliasing output lives for this call.
    unsafe {
        p.write(value);
    }
    Ok(())
}
unsafe fn bytes(p: *const u8, len: usize, max: usize) -> AbiResult<Vec<u8>> {
    if len > max || (p.is_null() && len != 0) {
        return Err(INVALID);
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: bounded input region is live/immutable for the call; copied before
    // returning or scheduling work, with no retained foreign pointer.
    Ok(unsafe { std::slice::from_raw_parts(p, len) }.to_vec())
}
unsafe fn buffer(data: Vec<u8>, out: *mut *mut u8, len: *mut usize) -> AbiResult<()> {
    let data = data.into_boxed_slice();
    let n = data.len();
    let p = if n == 0 {
        ptr::null_mut()
    } else {
        Box::into_raw(data).cast::<u8>()
    };
    // SAFETY: outputs were checked before ownership/state mutation at entry.
    unsafe {
        write(out, p)?;
        write(len, n)
    }
}

/// Native ABI version, independent of negotiated Core wire versions.
#[no_mangle]
pub extern "C" fn syntra_abi_version() -> u32 {
    SYNTRA_ABI_VERSION
}
/// Local implementation availability: Core, typed recovery client and lifecycle.
/// Not peer negotiation or security status; record protection remains unset.
#[no_mangle]
pub extern "C" fn syntra_capabilities() -> u64 {
    SYNTRA_CAP_CORE | SYNTRA_CAP_RECOVERY_CLIENT | SYNTRA_CAP_LIFECYCLE
}

// Each exported unsafe entry uses the common header's pointer contract.
// Keeping it in one native header avoids divergent per-language contracts.
#[allow(clippy::missing_safety_doc)]
mod exports {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn syntra_client_open(
        abi: u32,
        out: *mut *mut syntra_t,
        generation: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: header requires independent writable outputs.
            unsafe {
                write(out, ptr::null_mut())?;
                write(generation, 0)?;
            }
            if abi != SYNTRA_ABI_VERSION {
                return Err(MISMATCH);
            }
            let h = open(None)?;
            // SAFETY: outputs validated before constructing the owner.
            unsafe {
                write(generation, h.generation)?;
                write(out, Box::into_raw(h))?;
            }
            Ok(OK)
        })
    }
    #[no_mangle]
    pub unsafe extern "C" fn syntra_host_open(
        abi: u32,
        policy: syntra_policy_t,
        out: *mut *mut syntra_t,
        generation: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: header requires independent writable outputs.
            unsafe {
                write(out, ptr::null_mut())?;
                write(generation, 0)?;
            }
            if abi != SYNTRA_ABI_VERSION {
                return Err(MISMATCH);
            }
            if policy.authenticate.is_none() || policy.authorize.is_none() {
                return Err(INVALID);
            }
            let h = open(Some(policy))?;
            // SAFETY: outputs validated before constructing the owner.
            unsafe {
                write(generation, h.generation)?;
                write(out, Box::into_raw(h))?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_client_open_clock(
        abi: u32,
        clock: syntra_clock_t,
        out: *mut *mut syntra_t,
        generation: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: independent required outputs checked before construction.
            unsafe {
                write(out, ptr::null_mut())?;
                write(generation, 0)?;
            }
            if abi != SYNTRA_ABI_VERSION {
                return Err(MISMATCH);
            }
            if clock.sample.is_none() {
                return Err(INVALID);
            }
            let clock = ElapsedClock::with_source(Arc::new(ClockSource(clock)));
            if !clock.is_continuous() {
                return Err(INVALID);
            }
            let h = open_with_clock(None, Some(clock))?;
            // SAFETY: outputs checked above; callbacks remain caller-owned.
            unsafe {
                write(generation, h.generation)?;
                write(out, Box::into_raw(h))?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_host_open_clock(
        abi: u32,
        policy: syntra_policy_t,
        clock: syntra_clock_t,
        out: *mut *mut syntra_t,
        generation: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: required independent outputs; context/hook lifetimes are
            // the same as host_open and client_open_clock, not retained borrows.
            unsafe {
                write(out, ptr::null_mut())?;
                write(generation, 0)?;
            }
            if abi != SYNTRA_ABI_VERSION {
                return Err(MISMATCH);
            }
            if clock.sample.is_none() || policy.authenticate.is_none() || policy.authorize.is_none()
            {
                return Err(INVALID);
            }
            let clock = ElapsedClock::with_source(Arc::new(ClockSource(clock)));
            if !clock.is_continuous() {
                return Err(INVALID);
            }
            let h = open_with_clock(Some(policy), Some(clock))?;
            // SAFETY: outputs checked above before starting native ownership.
            unsafe {
                write(generation, h.generation)?;
                write(out, Box::into_raw(h))?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_suspend(p: *mut syntra_t, g: u64) -> i32 {
        boundary(|| {
            // SAFETY: live owner, no concurrent destruction per native contract.
            let h = unsafe { owner(p, g)? };
            let mut state = h.state.lock().map_err(|_| INTERNAL)?;
            h.endpoint.suspend();
            state.retired = true;
            state.receipts.clear();
            h.retire_recovery()?;
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_platform_wake(
        p: *mut syntra_t,
        g: u64,
        continuity_known: i32,
    ) -> i32 {
        boundary(|| {
            if !matches!(continuity_known, 0 | 1) {
                return Err(INVALID);
            }
            // SAFETY: live owner; wake never revives this connection/generation.
            let h = unsafe { owner(p, g)? };
            let mut state = h.state.lock().map_err(|_| INTERNAL)?;
            h.endpoint.suspend();
            state.retired = true;
            state.receipts.clear();
            h.retire_recovery()?;
            if continuity_known == 0 {
                h.endpoint.clock().invalidate();
            }
            if state.wake.is_none() && state.thread.is_some() {
                let endpoint = h.endpoint.clone();
                state.wake = Some(
                    h.runtime
                        .spawn(async move { endpoint.platform_wake().await }),
                );
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_handshake(
        p: *mut syntra_t,
        g: u64,
        credential: *const u8,
        len: usize,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: common header pointer contract; inputs copied for tasks.
            let (h, credential) = unsafe {
                write(token, 0)?;
                (owner(p, g)?, bytes(credential, len, MAX_CREDENTIAL_BYTES)?)
            };
            let Endpoint::Client(c) = &h.endpoint else {
                return Err(INVALID);
            };
            if h.handshake_started.swap(true, Ordering::AcqRel) {
                return Err(INVALID);
            }
            let c = c.clone();
            let id = h
                .submit(
                    async move { (0, c.handshake(credential).await.map(String::into_bytes)) },
                    None,
                )
                .inspect_err(|_| {
                    h.handshake_started.store(false, Ordering::Release);
                })?;
            // SAFETY: output validated before submit.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_call(
        p: *mut syntra_t,
        g: u64,
        method: *const u8,
        method_len: usize,
        payload: *const u8,
        len: usize,
        timeout_ms: u32,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: common header pointer contract; no pointers enter tasks.
            let h = unsafe {
                write(token, 0)?;
                owner(p, g)?
            };
            let clock = h.endpoint.clock();
            let started = clock.now();
            // SAFETY: bounded borrowed slices are copied before any await; the
            // clock sample precedes copy/validation and queue admission costs.
            let (method, payload) = unsafe {
                (
                    bytes(method, method_len, 512)?,
                    bytes(payload, len, MAX_FRAME_BYTES)?,
                )
            };
            let method = String::from_utf8(method).map_err(|_| INVALID)?;
            syntra_core::validate_method(&method).map_err(|_| INVALID)?;
            let Endpoint::Client(c) = &h.endpoint else {
                return Err(INVALID);
            };
            let c = c.clone();
            let cancel = CancelToken::new();
            let cc = cancel.clone();
            let budget = if timeout_ms == 0 {
                30_000
            } else {
                timeout_ms.min(120_000)
            };
            let deadline = started + Duration::from_millis(u64::from(budget));
            let id = h.submit(
                async move {
                    let remaining =
                        deadline.saturating_duration_since(clock.now()).as_millis() as u32;
                    if remaining == 0 {
                        // A positive sub-ms budget cannot be emitted as zero
                        // (which means default) or rounded up. Wait without an
                        // RPC slot; don't select an early deadline ahead of an
                        // eligible cancellation before the actual cutoff.
                        let error = tokio::select! {
                            biased;
                            _ = clock.sleep_until(deadline) => {
                                if clock.now() >= deadline {
                                    SyntraError::DeadlineExceeded("call expired before admission".into())
                                } else {
                                    SyntraError::Unavailable("elapsed continuity lost".into())
                                }
                            }
                            _ = cc.cancelled() => {
                                if clock.now() >= deadline {
                                    SyntraError::DeadlineExceeded("call expired before admission".into())
                                } else {
                                    SyntraError::Cancelled("call cancelled before admission".into())
                                }
                            }
                        };
                        return (0, Err(error));
                    }
                    c.call_cancellable_tracked(&method, payload, remaining, &cc)
                        .await
                },
                Some(cancel),
            )?;
            // SAFETY: output validated before submit.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_cancel(p: *mut syntra_t, g: u64, token: u64) -> i32 {
        boundary(|| {
            // SAFETY: live owner as specified by header.
            let h = unsafe { owner(p, g)? };
            let s = h.state.lock().map_err(|_| INTERNAL)?;
            s.jobs
                .get(&token)
                .ok_or(STALE)?
                .cancel
                .as_ref()
                .ok_or(INVALID)?
                .cancel();
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_poll(
        p: *mut syntra_t,
        g: u64,
        token: u64,
        code: *mut i32,
        request_id: *mut u64,
        out: *mut *mut u8,
        len: *mut usize,
    ) -> i32 {
        boundary(|| {
            // SAFETY: initialize required outputs before consuming any result.
            let h = unsafe {
                write(code, 0)?;
                write(request_id, 0)?;
                write(out, ptr::null_mut())?;
                write(len, 0)?;
                owner(p, g)?
            };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            let job = s.jobs.get_mut(&token).ok_or(STALE)?;
            if job.recovery {
                return Err(INVALID);
            }
            if !job.observe() {
                return Ok(EMPTY);
            }
            let result = job.result.take().ok_or(INTERNAL)?;
            s.jobs.remove(&token);
            if s.notification_pending == Some(token) {
                s.notification_pending = None;
            }
            let (id, result) = result.map_err(|_| {
                s.failed = true;
                INTERNAL
            })?;
            // SAFETY: output regions validated at entry, owned allocation is
            // transferred once and freed only by syntra_free.
            unsafe {
                write(request_id, id)?;
                match result {
                    Ok(data) => buffer(data, out, len)?,
                    Err(e) => write(code, e.code().as_i32())?,
                }
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_receipt(p: *mut syntra_t, g: u64, token: *mut u64) -> i32 {
        boundary(|| {
            // SAFETY: header pointer contract.
            let h = unsafe {
                write(token, 0)?;
                owner(p, g)?
            };
            let received = h.endpoint.clock().now();
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if s.retired || s.shutdown.is_some() || h.endpoint.closed() {
                return Err(CLOSED);
            }
            if s.receipts.len() >= LIMIT {
                return Err(BUSY);
            }
            let id = fresh()?;
            s.receipts.push_back((id, received));
            // SAFETY: output checked before receipt registration.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_ingest(
        p: *mut syntra_t,
        g: u64,
        receipt: u64,
        data: *const u8,
        len: usize,
    ) -> i32 {
        boundary(|| {
            // SAFETY: input copied before the foreign borrow ends.
            let (h, data) = unsafe { (owner(p, g)?, bytes(data, len, MAX_FRAME_BYTES)?) };
            if data.is_empty() {
                return Err(INVALID);
            }
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if s.retired || s.shutdown.is_some() || h.endpoint.closed() {
                return Err(CLOSED);
            }
            let &(id, received) = s.receipts.front().ok_or(STALE)?;
            if id != receipt {
                return Err(STALE);
            }
            h.inbound.try_send((data, received)).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => BUSY,
                mpsc::error::TrySendError::Closed(_) => INTERNAL,
            })?;
            s.receipts.pop_front();
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_emit(
        p: *mut syntra_t,
        g: u64,
        token: *mut u64,
        out: *mut *mut u8,
        len: *mut usize,
    ) -> i32 {
        boundary(|| {
            // SAFETY: all outputs initialized before dequeuing/preparing a unit.
            let h = unsafe {
                write(token, 0)?;
                write(out, ptr::null_mut())?;
                write(len, 0)?;
                owner(p, g)?
            };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if !h.endpoint.clock().is_continuous() {
                s.retired = true;
                h.endpoint.suspend();
                h.retire_recovery()?;
            }
            if s.retired {
                return Err(CLOSED);
            }
            if s.emitting.is_some() {
                return Err(BUSY);
            }
            if s.shutdown
                .as_ref()
                .is_some_and(|v| h.endpoint.clock().now() >= v.drain_cutoff || v.carrier_closed)
            {
                return Err(CLOSED);
            }
            let id = fresh()?;
            while let Ok(original) = s.writer.try_recv() {
                // Preserve the original Vec allocation until the runtime's
                // one-shot handoff; never decode/rebuild queued RPCs here.
                let unit = match &h.endpoint {
                    Endpoint::Client(c) => c.prepare_outbound(original),
                    Endpoint::Host(_) => Some(original),
                };
                if let Some(unit) = unit {
                    s.emitting = Some(id);
                    // SAFETY: validated independent outputs; one owned buffer.
                    unsafe {
                        write(token, id)?;
                        buffer(unit, out, len)?;
                    }
                    return Ok(OK);
                }
            }
            Ok(EMPTY)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_emitted(p: *mut syntra_t, g: u64, token: u64) -> i32 {
        boundary(|| {
            // SAFETY: live owner; caller attests whole immutable unit finished.
            let h = unsafe { owner(p, g)? };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if s.emitting != Some(token) {
                return Err(STALE);
            }
            s.emitting = None;
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_take_dispatch(
        p: *mut syntra_t,
        g: u64,
        token: *mut u64,
        method: *mut *mut u8,
        method_len: *mut usize,
        payload: *mut *mut u8,
        payload_len: *mut usize,
    ) -> i32 {
        boundary(|| {
            // SAFETY: initialize all outputs before transferring dispatch.
            let h = unsafe {
                write(token, 0)?;
                write(method, ptr::null_mut())?;
                write(method_len, 0)?;
                write(payload, ptr::null_mut())?;
                write(payload_len, 0)?;
                owner(p, g)?
            };
            let _admission = h.state.lock().map_err(|_| INTERNAL)?;
            if _admission.retired {
                return Err(CLOSED);
            }
            let mut slots = h.dispatches.lock().map_err(|_| INTERNAL)?;
            slots.reap_undelivered();
            let Some((&id, d)) = slots.0.iter_mut().find(|(_, d)| d.method.is_some()) else {
                return Ok(EMPTY);
            };
            let name = d.method.take().ok_or(INTERNAL)?;
            // SAFETY: required outputs checked before taking the slot. Lease
            // stays charged until complete, even after cancellation/expiry.
            unsafe {
                write(token, id)?;
                buffer(name.into_bytes(), method, method_len)?;
                buffer(std::mem::take(&mut d.payload), payload, payload_len)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_dispatch_cancelled(
        p: *mut syntra_t,
        g: u64,
        token: u64,
        cancelled: *mut i32,
    ) -> i32 {
        boundary(|| {
            // SAFETY: common header contract.
            let h = unsafe {
                write(cancelled, 0)?;
                owner(p, g)?
            };
            let slots = h.dispatches.lock().map_err(|_| INTERNAL)?;
            let d = slots.0.get(&token).ok_or(STALE)?;
            // SAFETY: output checked before lookup.
            unsafe {
                write(
                    cancelled,
                    i32::from(d.cancel.is_cancelled() || d.reply.is_closed()),
                )?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_complete(
        p: *mut syntra_t,
        g: u64,
        token: u64,
        code: i32,
        data: *const u8,
        len: usize,
    ) -> i32 {
        boundary(|| {
            if !(0..=16).contains(&code) || (code != 0 && len != 0) {
                return Err(INVALID);
            }
            // SAFETY: copied input and live owner per header.
            let (h, data) = unsafe { (owner(p, g)?, bytes(data, len, MAX_FRAME_BYTES - 128)?) };
            let mut slots = h.dispatches.lock().map_err(|_| INTERNAL)?;
            if slots.0.get(&token).is_none_or(|d| d.method.is_some()) {
                return Err(STALE);
            }
            let d = slots.0.remove(&token).ok_or(STALE)?;
            let outcome = if code == 0 {
                HandlerOutcome::Payload(data)
            } else {
                HandlerOutcome::error(
                    ErrorCode::from_i32_lossy(code).0,
                    "application request failed",
                )
            };
            // Sending is merely a candidate. The shared Host deadline gate,
            // not this adapter, selects the terminal outcome. Dropping d's
            // lease acknowledges external work really stopped.
            Ok(if d.reply.send(outcome).is_ok() {
                OK
            } else {
                STALE
            })
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_notify(
        p: *mut syntra_t,
        g: u64,
        data: *const u8,
        len: usize,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: required output and copied input.
            let (h, data) = unsafe {
                write(token, 0)?;
                (owner(p, g)?, bytes(data, len, MAX_FRAME_BYTES - 128)?)
            };
            let Endpoint::Host(host) = &h.endpoint else {
                return Err(INVALID);
            };
            let host = host.clone();
            let id = h.submit(
                async move { (0, host.notify(data).await.map(|()| vec![])) },
                None,
            )?;
            // SAFETY: output checked before submit.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_next_notification(
        p: *mut syntra_t,
        g: u64,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: common header contract.
            let h = unsafe {
                write(token, 0)?;
                owner(p, g)?
            };
            let Endpoint::Client(c) = &h.endpoint else {
                return Err(INVALID);
            };
            let c = c.clone();
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if h.recovery.lock().map_err(|_| INTERNAL)?.is_some() {
                return Err(INVALID); // profile inbox has exclusive routing
            }
            if s.retired || s.shutdown.is_some() || s.notification_pending.is_some() {
                return Err(BUSY);
            }
            // One notification waiter per handle; its job slot must be polled
            // before issuing another. Bound it with ordinary result slots.
            if s.jobs.len() >= LIMIT {
                return Err(BUSY);
            }
            let id = fresh()?;
            let work = h.runtime.spawn(async move {
                (
                    0,
                    c.next_notification()
                        .await
                        .ok_or_else(|| SyntraError::Closed("notification stream closed".into())),
                )
            });
            s.jobs.insert(
                id,
                Job {
                    work: Some(work),
                    result: None,
                    cancel: None,
                    recovery: false,
                },
            );
            s.notification_pending = Some(id);
            // SAFETY: output checked before insertion.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_withdraw(p: *mut syntra_t, g: u64) -> i32 {
        boundary(|| {
            // SAFETY: common header contract.
            let h = unsafe { owner(p, g)? };
            let Endpoint::Host(host) = &h.endpoint else {
                return Err(INVALID);
            };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if s.shutdown.is_some() {
                return Err(CLOSED);
            }
            if s.withdrawal.is_none() {
                let host = host.clone();
                s.withdrawal = Some(
                    h.runtime
                        .spawn(async move { host.withdraw_principal().await }),
                );
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_shutdown(p: *mut syntra_t, g: u64, total_ms: u32) -> i32 {
        boundary(|| {
            if !(2..=30_000).contains(&total_ms) {
                return Err(INVALID);
            }
            // SAFETY: common header contract.
            let h = unsafe { owner(p, g)? };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            if s.shutdown.is_none() {
                h.retire_recovery()?;
                let total = Duration::from_millis(u64::from(total_ms));
                // start_shutdown installs its retained owner synchronously and
                // shares ONE elapsed budget with drain and task cleanup.
                let _entered = h.runtime.enter();
                let budget = h.endpoint.begin_shutdown(total)?;
                s.shutdown = Some(Shutdown {
                    deadline: budget.deadline,
                    drain_cutoff: budget.drain_cutoff,
                    work: None,
                    carrier_closed: false,
                });
                s.receipts.clear();
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_transport_closed(p: *mut syntra_t, g: u64) -> i32 {
        boundary(|| {
            // SAFETY: caller attests carrier is closed and no partial writes
            // or callbacks can subsequently use this generation's bytes.
            let h = unsafe { owner(p, g)? };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            h.retire_recovery()?;
            if s.shutdown.is_none() {
                let _entered = h.runtime.enter();
                let budget = h.endpoint.begin_shutdown(Duration::ZERO)?;
                let endpoint = h.endpoint.clone();
                let work = h
                    .runtime
                    .spawn(async move { endpoint.transport_lost().await });
                s.shutdown = Some(Shutdown {
                    deadline: budget.deadline,
                    drain_cutoff: budget.drain_cutoff,
                    work: Some(work),
                    carrier_closed: true,
                });
            } else if !s.shutdown.as_ref().ok_or(INTERNAL)?.carrier_closed {
                let endpoint = h.endpoint.clone();
                s.transport_loss = Some(
                    h.runtime
                        .spawn(async move { endpoint.transport_lost().await }),
                );
            }
            s.shutdown.as_mut().ok_or(INTERNAL)?.carrier_closed = true;
            h.endpoint.carrier_closed();
            // Carrier abort retires these plaintext units, NOT an emission
            // handoff. Release channel capacity so shared shutdown accounting
            // does not mistake discarded output for a still-owned wire write.
            s.writer.close();
            while s.writer.try_recv().is_ok() {}
            s.emitting = None;
            s.receipts.clear();
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_status(
        p: *mut syntra_t,
        g: u64,
        closed: *mut i32,
        reason: *mut i32,
        external_work: *mut usize,
        lost_count: *mut u64,
        lost_bytes: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: all required independent writable scalars initialized.
            let h = unsafe {
                write(closed, 0)?;
                write(reason, 0)?;
                write(external_work, 0)?;
                write(lost_count, 0)?;
                write(lost_bytes, 0)?;
                owner(p, g)?
            };
            {
                // Match shutdown's state -> reader lock order.
                let mut s = h.state.lock().map_err(|_| INTERNAL)?;
                if s.failed
                    || (s.shutdown.is_none()
                        && h.reader
                            .lock()
                            .map_err(|_| INTERNAL)?
                            .as_ref()
                            .is_some_and(|r| r.is_finished()))
                {
                    s.failed = true;
                    return Err(INTERNAL);
                }
            }
            let mut slots = h.dispatches.lock().map_err(|_| INTERNAL)?;
            slots.reap_undelivered();
            let loss = match &h.endpoint {
                Endpoint::Client(c) => c.notification_loss(),
                Endpoint::Host(_) => (0, 0),
            };
            // SAFETY: outputs checked before observation; no foreign borrows
            // are retained by runtime tasks or returned as borrowed pointers.
            unsafe {
                write(closed, i32::from(h.endpoint.closed()))?;
                write(reason, h.endpoint.reason())?;
                write(external_work, slots.0.len() + h.recovery_work_count()?)?;
                write(lost_count, loss.0)?;
                write(lost_bytes, loss.1)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_shutdown_poll(p: *mut syntra_t, g: u64) -> i32 {
        boundary(|| {
            // SAFETY: common live-owner contract, never consumes the pointer.
            let h = unsafe { owner(p, g)? };
            let mut s = h.state.lock().map_err(|_| INTERNAL)?;
            let shutdown = s.shutdown.as_mut().ok_or(INVALID)?;
            let expired = h.endpoint.clock().now() >= shutdown.deadline;
            if !shutdown.carrier_closed || s.emitting.is_some() {
                return Ok(if expired { INCOMPLETE } else { EMPTY });
            }
            let mut slots = h.dispatches.lock().map_err(|_| INTERNAL)?;
            slots.reap_undelivered();
            if !slots.0.is_empty() {
                return Ok(if expired { INCOMPLETE } else { EMPTY });
            }
            if h.recovery_pending()? {
                return Ok(if expired { INCOMPLETE } else { EMPTY });
            }
            // Outstanding writer permits can finish after Receiver::close.
            // Reap their retired units on every poll until all producers join.
            while s.writer.try_recv().is_ok() {}
            if s.shutdown
                .as_ref()
                .ok_or(INTERNAL)?
                .work
                .as_ref()
                .is_some_and(|j| !j.is_finished())
                || s.jobs.values_mut().any(|j| !j.observe())
                || s.withdrawal.as_ref().is_some_and(|j| !j.is_finished())
                || s.transport_loss.as_ref().is_some_and(|j| !j.is_finished())
                || s.wake.as_ref().is_some_and(|j| !j.is_finished())
            {
                return Ok(if expired { INCOMPLETE } else { EMPTY });
            }
            if let Endpoint::Host(host) = &h.endpoint {
                if host.execution_len() != 0 || host.worker_len() != 0 {
                    return Ok(if expired { INCOMPLETE } else { EMPTY });
                }
            }
            // JoinError is visible, never a successful silent task drop.
            if let Some(mut work) = s.shutdown.as_mut().ok_or(INTERNAL)?.work.take() {
                if let Poll::Ready(Err(_)) =
                    Pin::new(&mut work).poll(&mut Context::from_waker(Waker::noop()))
                {
                    s.failed = true;
                }
            }
            if let Some(mut work) = s.withdrawal.take() {
                if let Poll::Ready(Err(_)) =
                    Pin::new(&mut work).poll(&mut Context::from_waker(Waker::noop()))
                {
                    s.failed = true;
                }
            }
            if let Some(mut work) = s.transport_loss.take() {
                if let Poll::Ready(Err(_)) =
                    Pin::new(&mut work).poll(&mut Context::from_waker(Waker::noop()))
                {
                    s.failed = true;
                }
            }
            if let Some(mut work) = s.wake.take() {
                if let Poll::Ready(Err(_)) =
                    Pin::new(&mut work).poll(&mut Context::from_waker(Waker::noop()))
                {
                    s.failed = true;
                }
            }
            if s.jobs
                .values()
                .any(|j| j.result.as_ref().is_some_and(Result::is_err))
            {
                s.failed = true;
            }
            let mut reader = h.reader.lock().map_err(|_| INTERNAL)?;
            if let Some(work) = reader.as_mut() {
                if !work.is_finished() {
                    work.abort();
                    return Ok(if expired { INCOMPLETE } else { EMPTY });
                }
            }
            if let Some(mut work) = reader.take() {
                if let Poll::Ready(Err(error)) =
                    Pin::new(&mut work).poll(&mut Context::from_waker(Waker::noop()))
                {
                    if !error.is_cancelled() {
                        s.failed = true;
                    }
                }
                h.endpoint.reader_joined()?;
            }
            let report = h.endpoint.shutdown_report();
            if report.failed_tasks != 0 {
                s.failed = true;
            }
            if report.phase != syntra_runtime::ShutdownPhase::Complete {
                return Ok(if expired { INCOMPLETE } else { EMPTY });
            }
            if let Some(stop) = s.stop.take() {
                let _ = stop.send(());
            }
            if s.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                return Ok(if expired { INCOMPLETE } else { EMPTY });
            }
            if let Some(thread) = s.thread.take() {
                if thread.join().is_err() {
                    s.failed = true;
                }
            }
            Ok(if s.failed { INTERNAL } else { OK })
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_destroy(p: *mut syntra_t, g: u64) -> i32 {
        boundary(|| {
            // SAFETY: exclusive destruction, no concurrent or future calls.
            let h = unsafe { owner(p, g)? };
            let s = h.state.lock().map_err(|_| INTERNAL)?;
            if s.thread.is_some() {
                return Err(BUSY);
            }
            drop(s);
            // SAFETY: exactly the Box returned by open, consumed once only
            // after the native thread joined and external leases were released.
            drop(unsafe { Box::from_raw(p) });
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_free(p: *mut u8, len: usize) {
        if !p.is_null() {
            // SAFETY: caller returns the original owned slice exactly once,
            // with its original length, and has ceased all accesses to it.
            drop(unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(p, len)) });
        }
    }
}
pub use exports::*;

#[path = "recovery.rs"]
mod recovery;
pub use recovery::*;

#[cfg(test)]
#[path = "production_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "recovery_tests.rs"]
mod recovery_tests;
