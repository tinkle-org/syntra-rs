use super::{store::Store, *};
use std::{
    fs::File,
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

/// Reserve before allocation or file I/O. `call` submits once, consuming the
/// reservation; its reply owns the charge until dropped (including storage on
/// a blocking worker). A failed call is never retried by the engine.
/// One adapter instance must represent one fixed authority/account and one
/// media lane, with non-reused generations. `call` must dispatch only on the
/// reservation's generation (also when the call is queued before polling).
pub trait MediaRpc: Sync {
    type Reservation: Send + 'static;
    type Reply: AsRef<[u8]> + Send + 'static;
    fn generation(permit: &Self::Reservation) -> u64;
    fn reserve(&self, request_bytes: usize, max_response_bytes: usize)
        -> Result<Self::Reservation>;
    fn call(
        &self,
        permit: Self::Reservation,
        method: Method,
        payload: Vec<u8>,
    ) -> impl Future<Output = Result<Self::Reply>> + Send;
}

impl AsRef<[u8]> for crate::lanes::MediaResponse {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl MediaRpc for Arc<crate::lanes::LaneClient> {
    type Reservation = crate::lanes::MediaReservation;
    type Reply = crate::lanes::MediaResponse;
    fn generation(permit: &Self::Reservation) -> u64 {
        permit.generation()
    }
    fn reserve(&self, request: usize, reply: usize) -> Result<Self::Reservation> {
        self.try_reserve_media(request, reply).map_err(call_error)
    }
    async fn call(
        &self,
        permit: Self::Reservation,
        method: Method,
        payload: Vec<u8>,
    ) -> Result<Self::Reply> {
        permit
            .call(method.path(), payload, 0)
            .map_err(call_error)?
            .await
            .map_err(call_error)?
            .map_err(call_error)
    }
}

fn call_error(e: impl std::error::Error + Send + Sync + 'static) -> MediaError {
    MediaError::Call(Box::new(e))
}

async fn io<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| MediaError::Worker)?
}

/// A private SQLite destination, not just a cursor sidecar. Chunk data and its
/// verified checkpoint advance atomically. `scope` must stably identify the
/// remote authority AND authenticated account. Use separate private files for
/// separate scopes; the reference does not encrypt data at rest.
#[derive(Clone)]
pub struct DownloadStore(Arc<Store>);

impl DownloadStore {
    pub fn open(path: impl AsRef<Path>, scope: &str) -> Result<Self> {
        Ok(Self(Arc::new(Store::open(
            path.as_ref(),
            "download",
            scope,
        )?)))
    }

    /// Blocking export. Verify the entire committed object before handing any
    /// bytes to the writer, then stream from the same snapshot. If the writer
    /// itself fails its output may be partial; the SQLite destination is intact.
    pub fn copy_verified(&self, spec: Manifest, mut out: impl Write) -> Result<()> {
        spec.validate()?;
        self.0.snapshot(|tx| {
            if store::state(tx, spec, LOCAL)? != UploadState::Committed {
                return Err(MediaError::Refused(ErrorCode::FailedPrecondition));
            }
            store::scan(tx, spec, spec.length, |_| Ok(()))?;
            store::scan(tx, spec, spec.length, |bytes| Ok(out.write_all(bytes)?))
        })
    }

    /// Blocking, explicit recovery from a damaged local copy. Never deletes
    /// another manifest's bytes or changes remote state.
    pub fn discard(&self, spec: Manifest) -> Result<()> {
        self.0.transaction(|tx| {
            if store::state(tx, spec, LOCAL)? != UploadState::Absent {
                tx.execute("DELETE FROM media_v1_chunk WHERE id=?1", [spec.transfer_id])?;
                tx.execute(
                    "DELETE FROM media_v1_transfer WHERE id=?1",
                    [spec.transfer_id],
                )?;
            }
            Ok(())
        })
    }
}

// The entire download DB is bound to a single private scope at open.
const LOCAL: &str = "destination";

pub struct MediaClient<R>(pub(super) R);

#[derive(Default)]
struct Attempt(Option<u64>);

impl Attempt {
    fn reserve<R: MediaRpc>(
        &mut self,
        rpc: &R,
        req: usize,
        reply: usize,
    ) -> Result<R::Reservation> {
        let permit = rpc.reserve(req, reply)?;
        let generation = R::generation(&permit);
        if *self.0.get_or_insert(generation) != generation {
            return Err(MediaError::Refused(ErrorCode::Unavailable));
        }
        Ok(permit)
    }
}

impl<R: MediaRpc> MediaClient<R> {
    pub fn new(rpc: R) -> Self {
        Self(rpc)
    }

    async fn control(
        &self,
        attempt: &mut Attempt,
        spec: Manifest,
        method: Method,
    ) -> Result<UploadState> {
        spec.validate()?;
        let p = attempt.reserve(&self.0, MANIFEST_BYTES, STATE_BYTES)?;
        let reply = self.0.call(p, method, spec.bytes()).await?;
        UploadState::parse(reply.as_ref(), spec)
    }

    pub async fn query(&self, spec: Manifest) -> Result<UploadState> {
        self.control(&mut Attempt::default(), spec, Method::Query)
            .await
    }

    pub async fn abort(&self, spec: Manifest) -> Result<()> {
        if self
            .control(&mut Attempt::default(), spec, Method::Abort)
            .await?
            != UploadState::Aborted
        {
            return Err(MediaError::Invalid);
        }
        Ok(())
    }

    pub async fn describe(&self, key: ObjectVersion) -> Result<Manifest> {
        self.describe_on(&mut Attempt::default(), key).await
    }

    async fn describe_on(&self, attempt: &mut Attempt, key: ObjectVersion) -> Result<Manifest> {
        let p = attempt.reserve(&self.0, 24, MANIFEST_BYTES)?;
        let reply = self.0.call(p, Method::Describe, key.bytes()).await?;
        let mut src = reply.as_ref();
        let spec = Manifest::parse(&mut src)?;
        end(src)?;
        if spec.key != key {
            return Err(MediaError::Conflict);
        }
        Ok(spec)
    }

    /// Start or resume from the host's authoritative offset. Re-enter with
    /// the same manifest after interruption. A committed result is returned
    /// without opening the source, including after a lost finalize reply.
    pub async fn upload(&self, spec: Manifest, path: impl AsRef<Path>) -> Result<()> {
        let mut attempt = Attempt::default();
        let mut state = self.control(&mut attempt, spec, Method::Query).await?;
        if state == UploadState::Absent {
            state = self.control(&mut attempt, spec, Method::Begin).await?;
        }
        let mut pos = match state {
            UploadState::Uploading(n) => n,
            UploadState::Committed => return Ok(()),
            UploadState::Aborted => return Err(MediaError::Refused(ErrorCode::Aborted)),
            UploadState::Absent => return Err(MediaError::Invalid),
        };
        let path = path.as_ref();
        if spec.length == 0 {
            let path = path.to_owned();
            io(move || {
                let meta = std::fs::metadata(path)?;
                if !meta.is_file() || meta.len() != 0 {
                    return Err(MediaError::Conflict);
                }
                Ok(())
            })
            .await?;
        }
        while pos < spec.length {
            let n = spec.chunk_len(pos)?;
            let size = MANIFEST_BYTES + BLOCK_HEADER + n;
            let permit = attempt.reserve(&self.0, size, STATE_BYTES)?;
            let path = path.to_owned();
            let (permit, req) = io(move || {
                let mut file = File::open(path)?;
                let meta = file.metadata()?;
                if !meta.is_file() || meta.len() != spec.length {
                    return Err(MediaError::Conflict);
                }
                file.seek(SeekFrom::Start(pos))?;
                let mut buf = Vec::with_capacity(size);
                buf.extend(spec.bytes());
                buf.extend(pos.to_be_bytes());
                buf.resize(size, 0);
                let (header, data) = buf.split_at_mut(size - n);
                file.read_exact(data)?;
                header[MANIFEST_BYTES + 8..].copy_from_slice(&digest(data));
                Ok((permit, buf))
            })
            .await?;
            let reply = self.0.call(permit, Method::Put, req).await?;
            pos += n as u64;
            match UploadState::parse(reply.as_ref(), spec)? {
                UploadState::Uploading(next) if next == pos => (),
                _ => return Err(MediaError::Conflict), // concurrent writer: query again
            }
        }
        if self.control(&mut attempt, spec, Method::Finalize).await? != UploadState::Committed {
            return Err(MediaError::Invalid);
        }
        Ok(())
    }

    /// Resume only the pinned manifest and a verified local prefix. Even a
    /// completed cache hit requires an authorized Read at EOF on this attempt's
    /// generation and full verification of local bytes. Describe is metadata only.
    pub async fn download(&self, spec: Manifest, dest: &DownloadStore) -> Result<()> {
        spec.validate()?;
        let mut attempt = Attempt::default();
        if self.describe_on(&mut attempt, spec.key).await? != spec {
            return Err(MediaError::Conflict);
        }
        let db = dest.0.clone();
        let largest_chunk = spec.length.min(CHUNK_BYTES as u64) as usize;
        let permit = attempt.reserve(&self.0, 0, largest_chunk)?;
        let mut pos = io(move || {
            let _permit = permit;
            db.transaction(|tx| store::begin(tx, spec, LOCAL))?;
            db.snapshot(|tx| {
                let n = match store::state(tx, spec, LOCAL)? {
                    UploadState::Uploading(n) => n,
                    UploadState::Committed => spec.length,
                    _ => return Err(MediaError::Conflict),
                };
                if n < spec.length {
                    store::scan(tx, spec, n, |_| Ok(()))?;
                }
                Ok(n)
            })
        })
        .await?;
        while pos < spec.length {
            let n = spec.chunk_len(pos)?;
            let p = attempt.reserve(&self.0, MANIFEST_BYTES + 8, BLOCK_HEADER + n)?;
            let mut req = Vec::with_capacity(MANIFEST_BYTES + 8);
            req.extend(spec.bytes());
            req.extend(pos.to_be_bytes());
            let reply = self.0.call(p, Method::Read, req).await?;
            let db = dest.0.clone();
            io(move || {
                let (offset, data) = block(spec, reply.as_ref())?;
                if offset != pos {
                    return Err(MediaError::Conflict);
                }
                db.transaction(|tx| {
                    store::put(tx, spec, LOCAL, pos, data)?;
                    Ok(())
                })
            })
            .await?;
            pos += n as u64;
        }
        let permit = attempt.reserve(&self.0, 0, largest_chunk)?;
        let db = dest.0.clone();
        let verified = io(move || {
            let _permit = permit;
            db.snapshot(|tx| store::verify(tx, spec, LOCAL, true, || Ok(())))
        })
        .await?;
        // Fresh content (not metadata) permission before publication, even if
        // zero data RPCs were needed. Never query or mutate on a successor.
        let permit = attempt.reserve(&self.0, MANIFEST_BYTES + 8, BLOCK_HEADER)?;
        let req = [spec.bytes().as_slice(), &spec.length.to_be_bytes()].concat();
        let proof = self.0.call(permit, Method::Read, req).await?;
        if proof.as_ref() != eof(spec) {
            return Err(MediaError::Corrupt);
        }
        let db = dest.0.clone();
        io(move || db.transaction(|tx| store::publish(tx, spec, LOCAL, verified).map(|_| ()))).await
    }
}
