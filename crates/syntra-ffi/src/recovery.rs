//! Typed recovery client and polled durable-storage bridge. No provider engine,
//! checkpoint arithmetic, profile fallback, or in-memory durability substitute.
use super::*;
use syntra_runtime::recovery::persistence::{
    DurableRecord, ExpectedPosition, PersistenceError, PersistenceScope, RecoveryPersistence,
    StoreLimits,
};
use syntra_runtime::recovery::wire::RecoveryLimits;
use syntra_runtime::recovery::wire_client::{
    Negotiation, RecoveryClient, RecoveryClientError, RecoveryEvent, SubscribeIntent,
};

const STATE_MAX: usize = 1_048_576;
const STORAGE_SLOTS: usize = 1;

#[repr(C)]
#[derive(Default)]
pub struct syntra_bytes_t {
    pub data: *mut u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Default)]
pub struct syntra_recovery_result_t {
    pub kind: u32,
    pub grpc_code: i32,
    pub event: u32,
    pub flags: u32,
    pub stream: u64,
    pub generation: u64,
    pub next_generation: u64,
    pub index: u32,
    pub total_pages: u32,
    pub page_bytes_max: u32,
    pub restored_generation: u64,
    pub data: syntra_bytes_t,
    pub checkpoint: syntra_bytes_t,
    pub predecessor: syntra_bytes_t,
    pub restored_checkpoint: syntra_bytes_t,
    pub restored_state: syntra_bytes_t,
}

#[repr(C)]
#[derive(Default)]
pub struct syntra_storage_request_t {
    pub token: u64,
    pub kind: u32,
    pub expected_present: u32,
    pub expected_generation: u64,
    pub generation: u64,
    pub principal_scope: syntra_bytes_t,
    pub stable_stream: syntra_bytes_t,
    pub expected_checkpoint: syntra_bytes_t,
    pub checkpoint: syntra_bytes_t,
    pub application_state: syntra_bytes_t,
}

#[repr(C)]
pub struct syntra_record_t {
    pub generation: u64,
    pub checkpoint: *const u8,
    pub checkpoint_len: usize,
    pub application_state: *const u8,
    pub application_state_len: usize,
}

fn store_limits() -> StoreLimits {
    StoreLimits {
        max_records: 4,
        max_state_bytes: STATE_MAX,
        max_total_bytes: 8 * STATE_MAX,
    }
}
fn limits() -> RecoveryLimits {
    RecoveryLimits {
        subscriptions_per_connection: 4,
        handles_per_connection: 32,
        snapshot_pages: 4,
        ..RecoveryLimits::default()
    }
}

enum StorageInput {
    Load(PersistenceScope),
    Commit(PersistenceScope, Option<ExpectedPosition>, DurableRecord),
}
struct StorageSlot {
    input: Option<StorageInput>,
    deadline: Instant,
    commit: bool,
    delivered: bool,
    reply: Option<std::sync::mpsc::SyncSender<Result<Option<DurableRecord>, PersistenceError>>>,
}
#[derive(Default)]
struct StorageState {
    retired: bool,
    slots: HashMap<u64, StorageSlot>,
}
impl StorageState {
    fn retire(&mut self) {
        self.retired = true;
        self.slots.retain(|_, slot| {
            if let Some(reply) = slot.reply.take() {
                let error = if slot.commit && slot.delivered {
                    PersistenceError::CommitUnknown
                } else {
                    PersistenceError::Unavailable
                };
                let _ = reply.send(Err(error));
            }
            slot.delivered // retained foreign work must acknowledge actual stop
        });
    }
}
#[cfg(test)]
pub(super) struct StorageWaitPause {
    pub(super) armed: AtomicBool,
    pub(super) reached: std::sync::Barrier,
    pub(super) release: std::sync::Barrier,
}
struct Storage {
    clock: ElapsedClock,
    state: Mutex<StorageState>,
    #[cfg(test)]
    wait_pause: Mutex<Option<Arc<StorageWaitPause>>>,
}
impl Storage {
    fn retire(&self) -> AbiResult<()> {
        let mut state = self.state.lock().map_err(|_| INTERNAL)?;
        state.retire();
        Ok(())
    }
    fn expire_pending(&self, token: u64) -> AbiResult<()> {
        let mut state = self.state.lock().map_err(|_| INTERNAL)?;
        // Absence means a receipt already selected a terminal under this same
        // lock. Worker scheduling after its deadline cannot replace that result
        // or poison the store after a timely receipt removed its slot.
        if state.slots.get(&token).is_some_and(|slot| {
            slot.reply.is_some()
                && (!self.clock.is_continuous() || self.clock.now() >= slot.deadline)
        }) {
            state.retire();
        }
        Ok(())
    }
    fn request(&self, input: StorageInput) -> Result<Option<DurableRecord>, PersistenceError> {
        let commit = matches!(input, StorageInput::Commit(..));
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let token = fresh().map_err(|_| PersistenceError::OverLimit)?;
        let deadline = self.clock.now() + Duration::from_secs(5);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| PersistenceError::Unavailable)?;
            if state.retired || state.slots.len() >= STORAGE_SLOTS {
                return Err(PersistenceError::Unavailable);
            }
            state.slots.insert(
                token,
                StorageSlot {
                    input: Some(input),
                    deadline,
                    commit,
                    delivered: false,
                    reply: Some(tx),
                },
            );
        }
        // RecoveryClient calls this synchronous trait on spawn_blocking. Never
        // block its Tokio owner. Timeout/retirement fences the client, but a
        // delivered foreign write remains accounted until its explicit receipt.
        loop {
            self.expire_pending(token).map_err(|_| {
                if commit {
                    PersistenceError::CommitUnknown
                } else {
                    PersistenceError::Unavailable
                }
            })?;
            #[cfg(test)]
            {
                let pause = self.wait_pause.lock().unwrap().clone();
                if let Some(pause) = pause {
                    if pause.armed.swap(false, Ordering::AcqRel) {
                        // Test scheduler rendezvous ONLY: no storage/clock lock
                        // spans it. C advances time/completes the real receipt
                        // before this worker may inspect its receive channel.
                        pause.reached.wait();
                        pause.release.wait();
                    }
                }
            }
            match rx.recv_timeout(Duration::from_millis(10)) {
                // Selection happened under StorageState's lock, not at receive
                // time. Rechecking now would destroy timely selected success.
                Ok(result) => return result,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(if commit {
                        PersistenceError::CommitUnknown
                    } else {
                        PersistenceError::Unavailable
                    });
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}
struct ForeignPersistence(Arc<Storage>);
impl RecoveryPersistence for ForeignPersistence {
    fn load(&self, scope: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError> {
        self.0.request(StorageInput::Load(scope.clone()))
    }
    fn commit(
        &mut self,
        scope: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        record: DurableRecord,
    ) -> Result<(), PersistenceError> {
        record.validate(&store_limits())?;
        self.0
            .request(StorageInput::Commit(
                scope.clone(),
                expected.cloned(),
                record,
            ))
            .map(|_| ())
    }
}

#[derive(Default)]
struct Value {
    event: u32,
    flags: u32,
    stream: u64,
    generation: u64,
    next_generation: u64,
    index: u32,
    total_pages: u32,
    page_bytes_max: u32,
    restored_generation: u64,
    data: Vec<u8>,
    checkpoint: Vec<u8>,
    predecessor: Vec<u8>,
    restored_checkpoint: Vec<u8>,
    restored_state: Vec<u8>,
}
#[derive(Default)]
struct Control {
    retired: bool,
    busy: Option<(u64, u32)>,
    streams: HashMap<u64, Vec<u8>>,
    result: Option<Value>,
}
pub(super) struct Recovery {
    // The shared client's &mut operations intentionally span RPC/persistence
    // awaits. Only this lock is async; short ownership tables use std Mutex and
    // never hold their guards across await or foreign storage execution.
    engine: tokio::sync::Mutex<RecoveryClient<ForeignPersistence>>,
    control: Mutex<Control>,
    storage: Arc<Storage>,
}
impl Recovery {
    fn retire(&self) -> AbiResult<()> {
        let mut control = self.control.lock().map_err(|_| INTERNAL)?;
        control.retired = true;
        control.streams.clear();
        control.result = None;
        self.storage.retire()
    }
}
impl syntra_t {
    pub(super) fn retire_recovery(&self) -> AbiResult<()> {
        if let Some(recovery) = self.recovery.lock().map_err(|_| INTERNAL)?.as_ref() {
            recovery.retire()?;
        }
        Ok(())
    }
    pub(super) fn recovery_pending(&self) -> AbiResult<bool> {
        Ok(self.recovery_work_count()? != 0)
    }
    pub(super) fn recovery_work_count(&self) -> AbiResult<usize> {
        let recovery = self.recovery.lock().map_err(|_| INTERNAL)?;
        Ok(match recovery.as_ref() {
            Some(r) => r.storage.state.lock().map_err(|_| INTERNAL)?.slots.len(),
            None => 0,
        })
    }
    fn recovery(&self) -> AbiResult<Arc<Recovery>> {
        self.recovery
            .lock()
            .map_err(|_| INTERNAL)?
            .clone()
            .ok_or(INVALID)
    }
    #[cfg(test)]
    pub(super) fn pause_storage_wait(&self, pause: Arc<StorageWaitPause>) {
        let r = self.recovery().unwrap();
        *r.storage.wait_pause.lock().unwrap() = Some(pause);
    }
    #[cfg(test)]
    pub(super) fn storage_deadline(&self) -> Instant {
        let r = self.recovery().unwrap();
        let storage = r.storage.state.lock().unwrap();
        storage.slots.values().next().unwrap().deadline
    }
}

enum Command {
    Negotiate,
    Subscribe(Vec<u8>, Vec<u8>, SubscribeIntent),
    Replay,
    CatchUp,
    Retry,
    Event,
    Persist(Vec<u8>),
    SnapshotOffer,
    SnapshotFetch(u32),
    SnapshotBytes,
    Install(Vec<u8>),
    Unsubscribe,
}

fn failure(e: RecoveryClientError) -> SyntraError {
    SyntraError::Protocol {
        code: e.code(),
        message: "recovery operation failed".into(),
    }
}
async fn execute(
    r: &Recovery,
    command: Command,
    stream: u64,
) -> Result<Value, RecoveryClientError> {
    let handle = if stream == 0 {
        vec![]
    } else {
        r.control
            .lock()
            .map_err(|_| RecoveryClientError::InvalidState)?
            .streams
            .get(&stream)
            .cloned()
            .ok_or(RecoveryClientError::InvalidState)?
    };
    let mut engine = r.engine.lock().await;
    let mut value = Value {
        stream,
        ..Value::default()
    };
    match command {
        Command::Negotiate => match engine.negotiate().await? {
            Negotiation::Confirmed(response) => {
                value.flags = 1;
                value.total_pages = response.max_snapshot_pages;
                value.page_bytes_max = response.max_page_bytes;
            }
            Negotiation::RecoveryUnavailable => {
                return Err(RecoveryClientError::RecoveryUnavailable)
            }
        },
        Command::Subscribe(selector, stable, intent) => {
            let sub = engine.subscribe(selector, stable, intent).await?;
            let mut control = r
                .control
                .lock()
                .map_err(|_| RecoveryClientError::InvalidState)?;
            if control.retired {
                return Err(RecoveryClientError::ReconnectRequired);
            }
            // Runtime limits count ACTIVE subscriptions. This local table also
            // retains retired tokens; bound it by the lifetime H allocation cap
            // instead of refusing new rounds after provider loss/retention.
            if control.streams.len() >= 32 {
                return Err(RecoveryClientError::ResourceExhausted);
            }
            value.stream = fresh().map_err(|_| RecoveryClientError::ResourceExhausted)?;
            value.generation = sub.response.generation;
            value.checkpoint = sub.response.catchup_boundary;
            if let Some(record) = sub.restored {
                record
                    .validate(&store_limits())
                    .map_err(RecoveryClientError::Persistence)?;
                value.flags = 1;
                value.restored_generation = record.generation;
                value.restored_checkpoint = record.checkpoint;
                value.restored_state = record.application_state;
            }
            control
                .streams
                .insert(value.stream, sub.response.subscription_handle);
        }
        Command::Replay => {
            let page = engine.replay_page(&handle).await?;
            value.flags = u32::from(page.continuation_marker.is_empty());
            value.index = page.batch_payloads.len() as u32;
            value.checkpoint = page.result_checkpoint;
            value.predecessor = page.predecessor_checkpoint;
        }
        Command::CatchUp => {
            engine.catch_up(&handle).await?;
        }
        Command::Retry => {
            engine.retry_completion(&handle).await?;
        }
        Command::Event => {
            let (wire_handle, event) = match engine.next_event().await? {
                RecoveryEvent::Batch { batch } => {
                    value.generation = batch.generation;
                    value.data = batch.batch_payload;
                    value.checkpoint = batch.result_checkpoint;
                    value.predecessor = batch.predecessor_checkpoint;
                    (batch.subscription_handle, 1)
                }
                RecoveryEvent::CaughtUp { handle } => (handle, 2),
                RecoveryEvent::InitialLiveBaseline { handle, boundary } => {
                    value.checkpoint = boundary;
                    (handle, 3)
                }
                RecoveryEvent::SnapshotRequired { handle } => (handle, 4),
                RecoveryEvent::RecoveryNeeded {
                    handle,
                    generation,
                    next_generation,
                    ..
                } => {
                    value.generation = generation;
                    value.next_generation = next_generation.unwrap_or(0);
                    (handle, 5)
                }
            };
            value.event = event;
            value.stream = r
                .control
                .lock()
                .map_err(|_| RecoveryClientError::InvalidState)?
                .streams
                .iter()
                .find(|(_, h)| **h == wire_handle)
                .map(|(&t, _)| t)
                .ok_or(RecoveryClientError::InvalidState)?;
        }
        Command::Persist(state) => {
            let response = engine.persist_and_confirm(&handle, state).await?;
            value.generation = response.generation;
            value.checkpoint = response.confirmed_checkpoint;
        }
        Command::SnapshotOffer => {
            let d = engine.snapshot_offer(&handle).await?;
            value.total_pages = d.total_pages;
            value.page_bytes_max = d.page_bytes_max;
            value.checkpoint = d.boundary_checkpoint;
        }
        Command::SnapshotFetch(index) => {
            let page = engine.snapshot_fetch(&handle, index).await?;
            value.index = page.page_index;
            value.data = page.page_bytes;
            value.checkpoint = page.boundary_checkpoint;
        }
        Command::SnapshotBytes => {
            value.data = engine.snapshot_bytes(&handle)?;
        }
        Command::Install(state) => {
            let response = engine.install_and_confirm(&handle, state).await?;
            value.generation = response.generation;
            value.checkpoint = response.boundary_checkpoint;
        }
        Command::Unsubscribe => {
            engine.unsubscribe(&handle).await?;
            r.control
                .lock()
                .map_err(|_| RecoveryClientError::InvalidState)?
                .streams
                .remove(&stream);
        }
    }
    Ok(value)
}

fn submit(h: &syntra_t, kind: u32, stream: u64, command: Command, wait_ms: u32) -> AbiResult<u64> {
    if !(1..=30_000).contains(&wait_ms) {
        return Err(INVALID);
    }
    let r = h.recovery()?;
    let mut state = h.state.lock().map_err(|_| INTERNAL)?;
    if state.failed {
        return Err(INTERNAL);
    }
    if state.retired || state.shutdown.is_some() || h.endpoint.closed() {
        return Err(CLOSED);
    }
    if state.jobs.len() >= LIMIT {
        return Err(BUSY);
    }
    let mut control = r.control.lock().map_err(|_| INTERNAL)?;
    if control.retired {
        return Err(CLOSED);
    }
    if control.busy.is_some() {
        return Err(BUSY);
    }
    if stream != 0 && !control.streams.contains_key(&stream) {
        return Err(STALE);
    }
    let token = fresh()?;
    let cancel = CancelToken::new();
    let cc = cancel.clone();
    let rr = r.clone();
    let clock = h.endpoint.clock();
    let deadline = clock.now() + Duration::from_millis(u64::from(wait_ms));
    let work = h.runtime.spawn(async move {
        let (result, interrupted) = tokio::select! {
            biased;
            _ = clock.sleep_until(deadline) => (Err(if clock.is_continuous() {
                SyntraError::DeadlineExceeded("recovery wait expired".into())
            } else {
                SyntraError::Unavailable("elapsed continuity lost".into())
            }), true),
            _ = cc.cancelled() => (Err(SyntraError::Cancelled("recovery operation cancelled".into())), true),
            value = execute(&rr, command, stream) => (value.map_err(failure), false),
        };
        let result = match result {
            Ok(value) => {
                match rr.control.lock() {
                    Ok(mut c) if !c.retired => { c.result = Some(value); Ok(vec![]) }
                    _ => Err(SyntraError::Unavailable("recovery owner retired".into())),
                }
            }
            Err(e) => {
                // next_event is a cancellation-safe waiter; other cancelled
                // stateful operations require a fresh connection, not retries.
                // Shared RecoveryClient alone decides retention-miss, per-H
                // termination and persistence failures. Never replace its
                // recoverable SnapshotRequired path with an adapter-wide reset.
                if interrupted && kind != 6 {
                    let _ = rr.retire();
                }
                Err(e)
            }
        };
        (0, result)
    });
    control.busy = Some((token, kind));
    state.jobs.insert(
        token,
        Job {
            work: Some(work),
            result: None,
            cancel: Some(cancel),
            recovery: true,
        },
    );
    Ok(token)
}

fn owned(data: Vec<u8>) -> syntra_bytes_t {
    let data = data.into_boxed_slice();
    let len = data.len();
    let data = if len == 0 {
        ptr::null_mut()
    } else {
        Box::into_raw(data).cast::<u8>()
    };
    syntra_bytes_t { data, len }
}

#[allow(clippy::missing_safety_doc)]
mod exports {
    use super::*;

    #[no_mangle]
    pub unsafe extern "C" fn syntra_recovery_attach(
        p: *mut syntra_t,
        g: u64,
        principal: *const u8,
        len: usize,
    ) -> i32 {
        boundary(|| {
            // SAFETY: live owner and bounded copied scope under header contract.
            let h = unsafe { owner(p, g)? };
            // SAFETY: bounded immutable scope input is live for this call only.
            let principal = unsafe { bytes(principal, len, 1024)? };
            let state = h.state.lock().map_err(|_| INTERNAL)?;
            if state.retired
                || state.shutdown.is_some()
                || h.handshake_started.load(Ordering::Acquire)
            {
                return Err(CLOSED);
            }
            let Endpoint::Client(client) = &h.endpoint else {
                return Err(INVALID);
            };
            let mut slot = h.recovery.lock().map_err(|_| INTERNAL)?;
            if slot.is_some() {
                return Err(INVALID);
            }
            let storage = Arc::new(Storage {
                clock: client.elapsed_clock(),
                state: Mutex::new(StorageState::default()),
                #[cfg(test)]
                wait_pause: Mutex::new(None),
            });
            let engine = RecoveryClient::new(
                client.clone(),
                principal,
                ForeignPersistence(storage.clone()),
                limits(),
            )
            .map_err(|_| INVALID)?;
            *slot = Some(Arc::new(Recovery {
                engine: tokio::sync::Mutex::new(engine),
                control: Mutex::new(Control::default()),
                storage,
            }));
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_recovery_negotiate(
        p: *mut syntra_t,
        g: u64,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: required writable scalar initialized before submission.
            let h = unsafe {
                write(token, 0)?;
                owner(p, g)?
            };
            let id = submit(h, 1, 0, Command::Negotiate, 5000)?;
            // SAFETY: output checked before submission; no state change on NULL.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_recovery_subscribe(
        p: *mut syntra_t,
        g: u64,
        selector: *const u8,
        selector_len: usize,
        stable: *const u8,
        stable_len: usize,
        intent: u32,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: all foreign slices copied before returning/scheduling.
            let (h, selector, stable) = unsafe {
                write(token, 0)?;
                (
                    owner(p, g)?,
                    bytes(selector, selector_len, 1024)?,
                    bytes(stable, stable_len, 1024)?,
                )
            };
            let intent = match intent {
                1 => SubscribeIntent::InitialLiveOnly,
                2 => SubscribeIntent::ResumeDurable,
                3 => SubscribeIntent::SnapshotCurrentGeneration,
                _ => return Err(INVALID),
            };
            let id = submit(
                h,
                2,
                0,
                Command::Subscribe(selector, stable, intent),
                30_000,
            )?;
            // SAFETY: output checked before submission, only the token escapes.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_recovery_step(
        p: *mut syntra_t,
        g: u64,
        kind: u32,
        stream: u64,
        index: u32,
        data: *const u8,
        len: usize,
        wait_ms: u32,
        token: *mut u64,
    ) -> i32 {
        boundary(|| {
            // SAFETY: outputs checked before any command acquires ownership.
            let h = unsafe {
                write(token, 0)?;
                owner(p, g)?
            };
            if !matches!(kind, 7 | 11) && len != 0 {
                return Err(INVALID);
            }
            // SAFETY: input state is copied/bounded before an async operation.
            let data = unsafe { bytes(data, len, STATE_MAX)? };
            let command = match kind {
                3 => Command::Replay,
                4 => Command::CatchUp,
                5 => Command::Retry,
                6 => Command::Event,
                7 => Command::Persist(data),
                8 => Command::SnapshotOffer,
                9 => Command::SnapshotFetch(index),
                10 => Command::SnapshotBytes,
                11 => Command::Install(data),
                12 => Command::Unsubscribe,
                _ => return Err(INVALID),
            };
            if (kind == 6 && stream != 0) || (kind != 6 && stream == 0) {
                return Err(INVALID);
            }
            let id = submit(h, kind, stream, command, wait_ms)?;
            // SAFETY: output initialized before scheduling the command.
            unsafe {
                write(token, id)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_recovery_poll(
        p: *mut syntra_t,
        g: u64,
        token: u64,
        out: *mut syntra_recovery_result_t,
    ) -> i32 {
        boundary(|| {
            // SAFETY: one required, independent writable aggregate output.
            let h = unsafe {
                write(out, syntra_recovery_result_t::default())?;
                owner(p, g)?
            };
            let r = h.recovery()?;
            let mut state = h.state.lock().map_err(|_| INTERNAL)?;
            let mut control = r.control.lock().map_err(|_| INTERNAL)?;
            let (id, kind) = control.busy.ok_or(STALE)?;
            if id != token {
                return Err(STALE);
            }
            let job = state.jobs.get_mut(&token).ok_or(STALE)?;
            if !job.observe() {
                return Ok(EMPTY);
            }
            let result = job.result.take().ok_or(INTERNAL)?;
            state.jobs.remove(&token);
            control.busy = None;
            let (_, result) = result.map_err(|_| {
                state.failed = true;
                INTERNAL
            })?;
            let mut value = control.result.take().unwrap_or_default();
            let code = if state.retired || control.retired && result.is_ok() {
                value = Value::default();
                ErrorCode::Unavailable.as_i32()
            } else {
                result.err().map_or(0, |e| e.code().as_i32())
            };
            let output = syntra_recovery_result_t {
                kind,
                grpc_code: code,
                event: value.event,
                flags: value.flags,
                stream: value.stream,
                generation: value.generation,
                next_generation: value.next_generation,
                index: value.index,
                total_pages: value.total_pages,
                page_bytes_max: value.page_bytes_max,
                restored_generation: value.restored_generation,
                data: owned(value.data),
                checkpoint: owned(value.checkpoint),
                predecessor: owned(value.predecessor),
                restored_checkpoint: owned(value.restored_checkpoint),
                restored_state: owned(value.restored_state),
            };
            // SAFETY: aggregate output checked before consuming the job/result.
            unsafe {
                write(out, output)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_storage_take(
        p: *mut syntra_t,
        g: u64,
        out: *mut syntra_storage_request_t,
    ) -> i32 {
        boundary(|| {
            // SAFETY: required writable aggregate, checked before delivery.
            let h = unsafe {
                write(out, syntra_storage_request_t::default())?;
                owner(p, g)?
            };
            let r = h.recovery()?;
            let _state = h.state.lock().map_err(|_| INTERNAL)?;
            let mut storage = r.storage.state.lock().map_err(|_| INTERNAL)?;
            if _state.retired || storage.retired {
                return Err(CLOSED);
            }
            let Some((&token, slot)) = storage.slots.iter_mut().find(|(_, s)| !s.delivered) else {
                return Ok(EMPTY);
            };
            let mut output = syntra_storage_request_t {
                token,
                ..Default::default()
            };
            let scope = match slot.input.take().ok_or(INTERNAL)? {
                StorageInput::Load(scope) => {
                    output.kind = 1;
                    scope
                }
                StorageInput::Commit(scope, expected, record) => {
                    output.kind = 2;
                    if let Some(expected) = expected {
                        output.expected_present = 1;
                        output.expected_generation = expected.generation;
                        output.expected_checkpoint = owned(expected.checkpoint);
                    }
                    output.generation = record.generation;
                    output.checkpoint = owned(record.checkpoint);
                    output.application_state = owned(record.application_state);
                    scope
                }
            };
            output.principal_scope = owned(scope.principal_scope().to_vec());
            output.stable_stream = owned(scope.stable_stream().to_vec());
            slot.delivered = true;
            // SAFETY: output checked before marking storage delivery; only
            // owned slices cross the ABI, not references into the slot table.
            unsafe {
                write(out, output)?;
            }
            Ok(OK)
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_storage_complete(
        p: *mut syntra_t,
        g: u64,
        token: u64,
        status: u32,
        record: *const syntra_record_t,
    ) -> i32 {
        boundary(|| {
            // SAFETY: live owner; optional immutable record copied and bounded.
            let h = unsafe { owner(p, g)? };
            let r = h.recovery()?;
            let result = match status {
                0 | 2 => {
                    if !record.is_null() {
                        return Err(INVALID);
                    }
                    Ok(None)
                }
                1 => {
                    // SAFETY: FOUND requires a live aligned immutable record;
                    // both slices are copied/bounded, never kept by reference.
                    let value = unsafe {
                        let record = record.as_ref().ok_or(INVALID)?;
                        DurableRecord {
                            generation: record.generation,
                            checkpoint: bytes(record.checkpoint, record.checkpoint_len, 4096)?,
                            application_state: bytes(
                                record.application_state,
                                record.application_state_len,
                                STATE_MAX,
                            )?,
                        }
                    };
                    value.validate(&store_limits()).map_err(|_| INVALID)?;
                    Ok(Some(value))
                }
                3..=7 => {
                    if !record.is_null() {
                        return Err(INVALID);
                    }
                    Err(match status {
                        3 => PersistenceError::Unavailable,
                        4 => PersistenceError::Corrupt,
                        5 => PersistenceError::Conflict,
                        6 => PersistenceError::CommitUnknown,
                        _ => PersistenceError::OverLimit,
                    })
                }
                _ => return Err(INVALID),
            };
            let mut storage = r.storage.state.lock().map_err(|_| INTERNAL)?;
            let slot = storage.slots.get(&token).ok_or(STALE)?;
            if !slot.delivered {
                return Err(STALE);
            }
            if status <= 2 && ((slot.commit && status != 2) || (!slot.commit && status == 2)) {
                return Err(INVALID);
            }
            // This lock is the receipt's terminal gate, shared with timer,
            // cancellation and wake retirement. Expiry wins exact ties. A late
            // DURABLE acknowledgement releases foreign ownership but publishes
            // only CommitUnknown (or Unavailable for load), never success that
            // could authorize Confirm. Actual durable state remains untouched.
            if storage.retired
                || !r.storage.clock.is_continuous()
                || r.storage.clock.now() >= slot.deadline
            {
                storage.retire();
                storage.slots.remove(&token);
                return Ok(STALE);
            }
            let slot = storage.slots.remove(&token).ok_or(STALE)?;
            Ok(match slot.reply {
                Some(reply) => {
                    if reply.send(result).is_ok() {
                        OK
                    } else {
                        STALE
                    }
                }
                None => STALE,
            })
        })
    }

    #[no_mangle]
    pub unsafe extern "C" fn syntra_recovery_result_free(out: *mut syntra_recovery_result_t) {
        if out.is_null() {
            return;
        }
        // SAFETY: exclusive aggregate originally returned by recovery_poll;
        // each buffer is returned exactly once, then the aggregate is cleared.
        let value = unsafe { ptr::replace(out, syntra_recovery_result_t::default()) };
        for b in [
            value.data,
            value.checkpoint,
            value.predecessor,
            value.restored_checkpoint,
            value.restored_state,
        ] {
            // SAFETY: original slice and length, no subsequent access.
            unsafe {
                syntra_free(b.data, b.len);
            }
        }
    }
    #[no_mangle]
    pub unsafe extern "C" fn syntra_storage_request_free(out: *mut syntra_storage_request_t) {
        if out.is_null() {
            return;
        }
        // SAFETY: exclusive aggregate originally returned by storage_take;
        // freeing request bytes does NOT acknowledge external storage work.
        let value = unsafe { ptr::replace(out, syntra_storage_request_t::default()) };
        for b in [
            value.principal_scope,
            value.stable_stream,
            value.expected_checkpoint,
            value.checkpoint,
            value.application_state,
        ] {
            // SAFETY: original slice and length, no subsequent access.
            unsafe {
                syntra_free(b.data, b.len);
            }
        }
    }
}
pub use exports::*;

#[cfg(test)]
mod tests {
    use super::*;

    struct StepSource(AtomicU64);
    impl ElapsedSource for StepSource {
        fn elapsed(&self) -> Option<Duration> {
            Some(Duration::from_nanos(self.0.load(Ordering::SeqCst)))
        }
    }

    #[test]
    fn storage_elapsed_expiry_retains_only_delivered_foreign_work() {
        for delivered in [false, true] {
            let source = Arc::new(StepSource(AtomicU64::new(0)));
            let storage = Arc::new(Storage {
                clock: ElapsedClock::with_source(source.clone()),
                state: Mutex::new(StorageState::default()),
                wait_pause: Mutex::new(None),
            });
            let worker_storage = storage.clone();
            let worker = std::thread::spawn(move || {
                worker_storage.request(StorageInput::Commit(
                    PersistenceScope::new(b"P".to_vec(), b"S".to_vec()).unwrap(),
                    None,
                    DurableRecord {
                        generation: 7,
                        checkpoint: b"opaque".to_vec(),
                        application_state: b"complete state".to_vec(),
                    },
                ))
            });
            super::super::tests::until(|| {
                let mut state = storage.state.lock().unwrap();
                let slot = state.slots.values_mut().next()?;
                slot.delivered = delivered;
                Some(())
            });
            source.0.store(6_000_000_000, Ordering::SeqCst);
            super::super::tests::until(|| worker.is_finished().then_some(()));
            assert_eq!(
                worker.join().unwrap().unwrap_err(),
                if delivered {
                    PersistenceError::CommitUnknown
                } else {
                    PersistenceError::Unavailable
                }
            );
            let state = storage.state.lock().unwrap();
            assert!(state.retired);
            assert_eq!(state.slots.len(), usize::from(delivered));
        }
    }
}
