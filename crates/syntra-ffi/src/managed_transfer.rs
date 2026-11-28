//! Only paths and a pinned manifest cross the boundary. MediaClient owns chunk
//! geometry, verification and durable resume. Never materialize a whole object.
use super::*;
use std::{
    io::{self, Write},
    thread::JoinHandle,
};
use syntra_net::{
    lanes::{MediaReservation, MediaResponse},
    media::{
        self, DownloadStore, Manifest, MediaClient, MediaError, MediaRpc, Method, ObjectVersion,
    },
};
use tokio::sync::watch;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct syntra_manifest_t {
    object: [u8; 16],
    transfer_id: [u8; 16],
    sha256: [u8; 32],
    version: u64,
    length: u64,
}
impl syntra_manifest_t {
    fn checked(self) -> AbiResult<Manifest> {
        if self.version == 0 || self.length > media::MAX_OBJECT_BYTES {
            return Err(INVALID);
        }
        Ok(Manifest {
            key: ObjectVersion {
                object: self.object,
                version: self.version,
            },
            transfer_id: self.transfer_id,
            length: self.length,
            sha256: self.sha256,
        })
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct syntra_sink_t {
    context: usize,
    chunk: Option<unsafe extern "C" fn(usize, *const u8, usize) -> i32>,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct syntra_progress_t {
    completed_rpcs: u64,
    request_bytes: u64,
    response_bytes: u64,
    object_bytes: u64,
}

struct Counted {
    lanes: Arc<LaneClient>,
    progress: Arc<Mutex<syntra_progress_t>>,
}
impl MediaRpc for Counted {
    type Reservation = MediaReservation;
    type Reply = MediaResponse;
    fn generation(permit: &MediaReservation) -> u64 {
        permit.generation()
    }
    fn reserve(&self, request: usize, reply: usize) -> media::Result<MediaReservation> {
        // Admission uses try_lock: the idle observer alone can return Busy. This
        // is a dedicated transfer thread; no payload has been allocated or sent.
        // Bound the wait and never retry a submitted call or a generation error.
        for _ in 0..8 {
            match self.lanes.try_reserve_media(request, reply) {
                Err(LaneError::Busy) => std::thread::sleep(Duration::from_millis(1)),
                r => return r.map_err(|e| MediaError::Call(Box::new(e))),
            }
        }
        self.lanes.reserve(request, reply)
    }
    async fn call(
        &self,
        p: MediaReservation,
        m: Method,
        data: Vec<u8>,
    ) -> media::Result<MediaResponse> {
        let request = data.len();
        let response = self.lanes.call(p, m, data).await?;
        let mut progress = self.progress.lock().map_err(|_| MediaError::Worker)?;
        progress.completed_rpcs += 1;
        progress.request_bytes += request as u64;
        progress.response_bytes += response.bytes().len() as u64;
        Ok(response)
    }
}

struct Sink(syntra_sink_t, watch::Receiver<bool>);
impl Write for Sink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if *self.1.borrow() {
            return Err(io::Error::other("cancelled"));
        }
        let chunk = self
            .0
            .chunk
            .ok_or_else(|| io::Error::other("missing sink"))?;
        // SAFETY: context/function live until terminal poll or joined shutdown;
        // data is immutable and live throughout this synchronous callback only.
        if unsafe { chunk(self.0.context, data.as_ptr(), data.len()) } != 0 {
            return Err(io::Error::other("sink stopped"));
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum Direction {
    Upload,
    Download { scope: String, sink: syntra_sink_t },
}

fn code(e: MediaError) -> i32 {
    match e {
        MediaError::Invalid => 3,
        MediaError::Conflict => 6,
        MediaError::Corrupt => 15,
        MediaError::Refused(c) => c.as_i32(),
        MediaError::Call(e) => match e.downcast_ref::<LaneError>() {
            Some(LaneError::Call(CallError::Rpc { source, .. })) => source.code().as_i32(),
            Some(LaneError::Busy | LaneError::ResponseTooLarge { .. }) => 8,
            Some(LaneError::Expired) => 4,
            _ => 14,
        },
        MediaError::Io(_) | MediaError::Storage(_) | MediaError::Worker => 13,
    }
}

pub(super) struct Worker {
    task: Option<JoinHandle<i32>>,
    result: Option<AbiResult<i32>>,
    stop: watch::Sender<bool>,
    progress: Arc<Mutex<syntra_progress_t>>,
}
impl Worker {
    fn start(
        lanes: Arc<LaneClient>,
        spec: Manifest,
        path: String,
        direction: Direction,
    ) -> AbiResult<Self> {
        // Cold demand is a synchronous PENDING with no file I/O or callback.
        drop(lanes.try_reserve_media(0, 0).map_err(admission)?);
        let progress = Arc::new(Mutex::new(syntra_progress_t {
            object_bytes: spec.length,
            ..Default::default()
        }));
        let client = MediaClient::new(Counted {
            lanes,
            progress: progress.clone(),
        });
        let (stop, mut cancelled) = watch::channel(false);
        let task = std::thread::Builder::new()
            .name("syntra-ffi-transfer".into())
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .max_blocking_threads(1)
                    .enable_all()
                    .build()
                else {
                    return 13;
                };
                let sink_cancel = cancelled.clone();
                let work = async move {
                    match direction {
                        Direction::Upload => client.upload(spec, path).await,
                        Direction::Download { scope, sink } => {
                            let db = DownloadStore::open(path, &scope)?;
                            client.download(spec, &db).await?;
                            if sink.chunk.is_some() {
                                db.copy_verified(spec, Sink(sink, sink_cancel))?;
                            }
                            Ok(())
                        }
                    }
                };
                // Runtime drop joins any storage workers even if work is cancelled.
                rt.block_on(async {
                    tokio::select! {
                        biased;
                        _ = cancelled.changed() => 1,
                        result = work => match result {
                            Ok(()) => 0,
                            Err(_) if *cancelled.borrow() => 1,
                            Err(e) => code(e),
                        },
                    }
                })
            })
            .map_err(|_| INTERNAL)?;
        Ok(Self {
            task: Some(task),
            result: None,
            stop,
            progress,
        })
    }
    pub(super) fn cancel(&self) {
        self.stop.send_replace(true);
    }
    pub(super) fn joined(&mut self) -> Option<AbiResult<i32>> {
        if let Some(t) = &self.task {
            if !t.is_finished() {
                return None;
            }
            self.result = Some(self.task.take()?.join().map_err(|_| INTERNAL));
        }
        self.result
    }
    pub(super) fn take(&mut self) -> Option<AbiResult<Reply>> {
        Some(self.joined()?.map(|code| Reply {
            code,
            ..Default::default()
        }))
    }
}

unsafe fn text(view: syntra_view_t, max: usize) -> AbiResult<String> {
    let text = String::from_utf8(unsafe { view.copy(max)? }).map_err(|_| INVALID)?;
    if text.is_empty() || text.contains('\0') {
        Err(INVALID)
    } else {
        Ok(text)
    }
}
unsafe fn start(
    p: *mut syntra_managed_t,
    id: u64,
    spec: *const syntra_manifest_t,
    path: syntra_view_t,
    download: Option<(syntra_view_t, syntra_sink_t)>,
    out: *mut u64,
) -> AbiResult<i32> {
    unsafe {
        write(out, 0)?;
        let mut s = state(p, id)?;
        let token = s.bulk_slot()?;
        if s.jobs
            .values()
            .filter(|j| matches!(j, Job::Transfer(_)))
            .count()
            >= 2
        {
            return Err(BUSY);
        }
        let spec = spec.as_ref().ok_or(INVALID)?.checked()?;
        let path = text(path, 4096)?;
        let dir = match download {
            None => Direction::Upload,
            Some((scope, sink)) => Direction::Download {
                scope: text(scope, 1024)?,
                sink,
            },
        };
        let worker = Worker::start(s.active()?.clone(), spec, path, dir)?;
        s.jobs.insert(token, Job::Transfer(worker));
        write(out, token)?;
        Ok(OK)
    }
}

#[no_mangle]
pub unsafe extern "C" fn syntra_managed_upload(
    p: *mut syntra_managed_t,
    id: u64,
    spec: *const syntra_manifest_t,
    path: syntra_view_t,
    out: *mut u64,
) -> i32 {
    boundary(|| unsafe { start(p, id, spec, path, None, out) })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_download(
    p: *mut syntra_managed_t,
    id: u64,
    spec: *const syntra_manifest_t,
    path: syntra_view_t,
    scope: syntra_view_t,
    sink: syntra_sink_t,
    out: *mut u64,
) -> i32 {
    boundary(|| unsafe { start(p, id, spec, path, Some((scope, sink)), out) })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_progress(
    p: *mut syntra_managed_t,
    id: u64,
    token: u64,
    out: *mut syntra_progress_t,
) -> i32 {
    boundary(|| unsafe {
        write(out, Default::default())?;
        let s = state(p, id)?;
        let Some(Job::Transfer(w)) = s.jobs.get(&token) else {
            return Err(STALE);
        };
        write(out, *w.progress.lock().map_err(|_| INTERNAL)?)?;
        Ok(OK)
    })
}
#[no_mangle]
pub unsafe extern "C" fn syntra_managed_cancel(
    p: *mut syntra_managed_t,
    id: u64,
    token: u64,
) -> i32 {
    boundary(|| unsafe {
        let mut s = state(p, id)?;
        match s.jobs.get_mut(&token) {
            Some(Job::Transfer(w)) => w.cancel(),
            Some(Job::Media(_, cancelled) | Job::Call(_, cancelled)) => *cancelled = true,
            _ => return Err(STALE),
        }
        Ok(OK)
    })
}
