use super::*;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(super) struct Store {
    writer: Mutex<Connection>,
    path: PathBuf,
    role: &'static str,
    scope: String,
}

impl Store {
    pub fn open(path: &Path, role: &'static str, scope: &str) -> Result<Self> {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") || scope.is_empty() {
            return Err(MediaError::Invalid);
        }
        // No URI flags: this must be a durable file in an application-private directory.
        let mut conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        let journal: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if journal != "wal" {
            return Err(MediaError::Refused(ErrorCode::FailedPrecondition));
        }
        conn.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA foreign_keys=ON;",
        )?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS media_v1_scope(singleton INTEGER PRIMARY KEY CHECK(singleton=1), role TEXT NOT NULL, scope TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS media_v1_transfer(id BLOB PRIMARY KEY NOT NULL, key BLOB NOT NULL, manifest BLOB NOT NULL, owner TEXT NOT NULL, state INTEGER NOT NULL, next INTEGER NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS media_v1_live ON media_v1_transfer(key) WHERE state != 3;
            CREATE TABLE IF NOT EXISTS media_v1_chunk(id BLOB NOT NULL REFERENCES media_v1_transfer(id), pos INTEGER NOT NULL, hash BLOB NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id,pos)) WITHOUT ROWID;")?;
        tx.execute(
            "INSERT INTO media_v1_scope VALUES(1,?1,?2) ON CONFLICT(singleton) DO NOTHING",
            params![role, scope],
        )?;
        check_scope(&tx, role, scope)?;
        // Keep the original transfer schema readable. The stamp protects the
        // verify/publish gap, including discard/recreate of the same local ID.
        let installed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='media_v1_revision')",[],|r|r.get(0))?;
        if !installed {
            tx.execute_batch("CREATE TABLE media_v1_revision(id BLOB PRIMARY KEY REFERENCES media_v1_transfer(id) ON DELETE CASCADE, stamp BLOB NOT NULL DEFAULT(randomblob(16)));
            INSERT INTO media_v1_revision(id) SELECT id FROM media_v1_transfer;
            CREATE TRIGGER IF NOT EXISTS media_v1_new AFTER INSERT ON media_v1_transfer BEGIN INSERT INTO media_v1_revision(id) VALUES(new.id); END;
            CREATE TRIGGER IF NOT EXISTS media_v1_append AFTER INSERT ON media_v1_chunk BEGIN UPDATE media_v1_revision SET stamp=randomblob(16) WHERE id=new.id; END;
            CREATE TRIGGER IF NOT EXISTS media_v1_change AFTER UPDATE ON media_v1_chunk BEGIN UPDATE media_v1_revision SET stamp=randomblob(16) WHERE id IN(old.id,new.id); END;
            CREATE TRIGGER IF NOT EXISTS media_v1_remove AFTER DELETE ON media_v1_chunk BEGIN UPDATE media_v1_revision SET stamp=randomblob(16) WHERE id=old.id; END;")?;
        }
        tx.commit()?;
        Ok(Self {
            writer: Mutex::new(conn),
            path: path.canonicalize()?,
            role,
            scope: scope.to_owned(),
        })
    }

    /// An independent read-only WAL connection; neither the writer mutex nor
    /// a SQLite writer lock is held across verification or application I/O.
    pub fn snapshot<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut reader = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tx = reader.transaction()?;
        check_scope(&tx, self.role, &self.scope)?;
        f(&tx)
    }

    /// BEGIN IMMEDIATE also serializes ACL changes from independent connections.
    pub fn transaction<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.writer.lock().map_err(|_| MediaError::Worker)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = f(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}

fn check_scope(tx: &Transaction<'_>, role: &str, scope: &str) -> Result<()> {
    if tx.query_row(
        "SELECT role=?1 AND scope=?2 FROM media_v1_scope WHERE singleton=1",
        params![role, scope],
        |r| r.get::<_, bool>(0),
    )? {
        Ok(())
    } else {
        Err(MediaError::Conflict)
    }
}

pub(super) fn describe(tx: &Transaction<'_>, key: ObjectVersion) -> Result<Manifest> {
    let raw: Vec<u8> = tx
        .query_row(
            "SELECT manifest FROM media_v1_transfer WHERE key=?1 AND state=2",
            [key.bytes()],
            |r| r.get(0),
        )
        .optional()?
        .ok_or(MediaError::Refused(ErrorCode::NotFound))?;
    let mut src = raw.as_slice();
    let spec = Manifest::parse(&mut src)?;
    if spec.key != key || !src.is_empty() {
        return Err(MediaError::Corrupt);
    }
    Ok(spec)
}

pub(super) fn state(tx: &Transaction<'_>, spec: Manifest, owner: &str) -> Result<UploadState> {
    let row = tx
        .query_row(
            "SELECT owner,manifest,state,next FROM media_v1_transfer WHERE id=?1",
            [spec.transfer_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, u64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((bound, manifest, status, next)) = row else {
        return Ok(UploadState::Absent);
    };
    if bound != owner {
        return Err(MediaError::Refused(ErrorCode::PermissionDenied));
    }
    if manifest != spec.bytes() {
        return Err(MediaError::Conflict);
    }
    match status {
        1 if next == spec.length || spec.chunk_len(next).is_ok() => {
            Ok(UploadState::Uploading(next))
        }
        2 if next == spec.length => Ok(UploadState::Committed),
        3 if next == 0 => Ok(UploadState::Aborted),
        _ => Err(MediaError::Corrupt),
    }
}

pub(super) fn begin(tx: &Transaction<'_>, spec: Manifest, owner: &str) -> Result<UploadState> {
    let current = state(tx, spec, owner)?;
    if current != UploadState::Absent {
        return Ok(current);
    }
    if tx.execute(
        "INSERT INTO media_v1_transfer VALUES(?1,?2,?3,?4,1,0) ON CONFLICT DO NOTHING",
        params![spec.transfer_id, spec.key.bytes(), spec.bytes(), owner],
    )? != 1
    {
        return Err(MediaError::Conflict);
    }
    Ok(UploadState::Uploading(0))
}

pub(super) fn put(
    tx: &Transaction<'_>,
    spec: Manifest,
    owner: &str,
    pos: u64,
    data: &[u8],
) -> Result<UploadState> {
    if data.len() != spec.chunk_len(pos)? {
        return Err(MediaError::Invalid);
    }
    let current = state(tx, spec, owner)?;
    let next = match current {
        UploadState::Uploading(n) => n,
        UploadState::Committed => spec.length,
        _ => return Err(MediaError::Refused(ErrorCode::FailedPrecondition)),
    };
    if pos < next {
        let same: bool = tx
            .query_row(
                "SELECT data=?3 AND hash=?4 FROM media_v1_chunk WHERE id=?1 AND pos=?2",
                params![spec.transfer_id, pos, data, digest(data)],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(MediaError::Corrupt)?;
        return if same {
            Ok(current)
        } else {
            Err(MediaError::Conflict)
        };
    }
    if pos != next {
        return Err(MediaError::Refused(ErrorCode::FailedPrecondition));
    }
    let next = pos + data.len() as u64;
    tx.execute(
        "INSERT INTO media_v1_chunk VALUES(?1,?2,?3,?4)",
        params![spec.transfer_id, pos, digest(data), data],
    )?;
    tx.execute(
        "UPDATE media_v1_transfer SET next=?2 WHERE id=?1",
        params![spec.transfer_id, next],
    )?;
    Ok(UploadState::Uploading(next))
}

pub(super) fn abort(tx: &Transaction<'_>, spec: Manifest, owner: &str) -> Result<UploadState> {
    match state(tx, spec, owner)? {
        UploadState::Aborted => return Ok(UploadState::Aborted),
        UploadState::Uploading(_) => (),
        _ => return Err(MediaError::Refused(ErrorCode::FailedPrecondition)),
    }
    tx.execute("DELETE FROM media_v1_chunk WHERE id=?1", [spec.transfer_id])?;
    tx.execute(
        "UPDATE media_v1_transfer SET state=3,next=0 WHERE id=?1",
        [spec.transfer_id],
    )?;
    Ok(UploadState::Aborted)
}

/// Indexed order with borrowed SQLite row blobs; never aggregate an object in memory.
pub(super) fn scan(
    tx: &Transaction<'_>,
    spec: Manifest,
    expected: u64,
    mut visit: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut stmt =
        tx.prepare("SELECT pos,hash,data FROM media_v1_chunk WHERE id=?1 ORDER BY pos")?;
    let mut rows = stmt.query([spec.transfer_id])?;
    let mut pos = 0;
    let mut hash = Sha256::new();
    while let Some(row) = rows.next()? {
        let data = row.get_ref(2)?.as_blob().map_err(|_| MediaError::Corrupt)?;
        if pos != row.get::<_, u64>(0)?
            || spec.chunk_len(pos)? != data.len()
            || digest(data) != row.get::<_, [u8; 32]>(1)?
        {
            return Err(MediaError::Corrupt);
        }
        hash.update(data);
        visit(data)?;
        pos += data.len() as u64;
    }
    if pos != expected || (pos == spec.length && <[u8; 32]>::from(hash.finalize()) != spec.sha256) {
        return Err(MediaError::Corrupt);
    }
    Ok(())
}

pub(super) struct Verified([u8; 16]);

fn revision(tx: &Transaction<'_>, spec: Manifest) -> Result<[u8; 16]> {
    Ok(tx.query_row(
        "SELECT stamp FROM media_v1_revision WHERE id=?1",
        [spec.transfer_id],
        |r| r.get(0),
    )?)
}

pub(super) fn verify(
    tx: &Transaction<'_>,
    spec: Manifest,
    owner: &str,
    verify_committed: bool,
    check: impl Fn() -> Result<()>,
) -> Result<Verified> {
    match state(tx, spec, owner)? {
        UploadState::Committed if !verify_committed => return Ok(Verified(revision(tx, spec)?)),
        UploadState::Committed => (),
        UploadState::Uploading(n) if n == spec.length => (),
        _ => return Err(MediaError::Refused(ErrorCode::FailedPrecondition)),
    }
    scan(tx, spec, spec.length, |_| check())?;
    Ok(Verified(revision(tx, spec)?))
}

pub(super) fn publish(
    tx: &Transaction<'_>,
    spec: Manifest,
    owner: &str,
    verified: Verified,
) -> Result<UploadState> {
    let state = state(tx, spec, owner)?;
    if revision(tx, spec)? != verified.0 {
        return Err(MediaError::Conflict);
    }
    match state {
        UploadState::Committed => return Ok(UploadState::Committed),
        UploadState::Uploading(n) if n == spec.length => (),
        _ => return Err(MediaError::Refused(ErrorCode::FailedPrecondition)),
    }
    tx.execute(
        "UPDATE media_v1_transfer SET state=2 WHERE id=?1",
        [spec.transfer_id],
    )?;
    Ok(UploadState::Committed)
}

pub(super) fn read(tx: &Transaction<'_>, spec: Manifest, pos: u64) -> Result<Vec<u8>> {
    if describe(tx, spec.key)? != spec {
        return Err(MediaError::Conflict);
    }
    if pos == spec.length {
        return Ok(eof(spec));
    }
    let n = spec.chunk_len(pos)?;
    let mut stmt = tx.prepare(
        "SELECT hash,data FROM media_v1_chunk WHERE id=?1 AND pos=?2 AND length(data)=?3",
    )?;
    let mut rows = stmt.query(params![spec.transfer_id, pos, n as u64])?;
    let row = rows.next()?.ok_or(MediaError::Corrupt)?;
    let hash = row.get::<_, [u8; 32]>(0)?;
    let data = row.get_ref(1)?.as_blob().map_err(|_| MediaError::Corrupt)?;
    if digest(data) != hash {
        return Err(MediaError::Corrupt);
    }
    Ok([pos.to_be_bytes().as_slice(), &hash, data].concat())
}
