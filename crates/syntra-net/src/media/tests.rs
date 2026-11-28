use super::*;
use rusqlite::Connection;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use syntra_runtime::{AuthError, Handler, Principal};

struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        static ID: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "syntra-media-{}-{}-{:?}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        Self(dir)
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn spec(data: &[u8]) -> Manifest {
    Manifest {
        key: ObjectVersion {
            object: [11; 16],
            version: 1,
        },
        transfer_id: [42; 16],
        length: data.len() as u64,
        sha256: digest(data),
    }
}
fn host(path: &Path) -> Arc<SqliteMediaHost> {
    SqliteMediaHost::open(
        path,
        "authority-A",
        Arc::new(|_, caller, method, key| {
            if key.object == [11; 16]
                && (caller.subject == "owner"
                    || caller.subject == "writer"
                    || (caller.subject == "metadata" && method == Method::Describe)
                    || (caller.subject == "reader"
                        && matches!(method, Method::Describe | Method::Read)))
            {
                Ok(())
            } else {
                Err(AuthError::denied())
            }
        }),
    )
    .unwrap()
}
fn run(host: &SqliteMediaHost, who: &str, method: Method, input: &[u8]) -> Result<Vec<u8>> {
    host.dispatch(
        &Principal::new(who),
        method,
        input,
        method.response_frame_bytes(),
        || Ok(()),
    )
}
fn put(spec: Manifest, pos: u64, data: &[u8]) -> Vec<u8> {
    [
        spec.bytes(),
        pos.to_be_bytes().to_vec(),
        digest(data).to_vec(),
        data.to_vec(),
    ]
    .concat()
}
fn read_req(spec: Manifest, pos: u64) -> Vec<u8> {
    [spec.bytes(), pos.to_be_bytes().to_vec()].concat()
}

#[test]
fn precommit_failure_rolls_back_both_data_and_cursor() {
    use std::cell::Cell;
    let dir = Dir::new();
    let path = dir.file("db");
    let h = host(&path);
    let s = spec(&vec![5; CHUNK_BYTES]);
    run(&h, "owner", Method::Begin, &s.bytes()).unwrap();
    let calls = Cell::new(0);
    let data = put(s, 0, &vec![5; CHUNK_BYTES]);
    let failed = h.dispatch(&Principal::new("owner"), Method::Put, &data, 1024, || {
        calls.set(calls.get() + 1);
        if calls.get() == 3 {
            Err(MediaError::Refused(ErrorCode::Cancelled))
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        failed,
        Err(MediaError::Refused(ErrorCode::Cancelled))
    ));
    let reopened = host(&path);
    assert_eq!(
        run(&reopened, "owner", Method::Query, &s.bytes()).unwrap(),
        UploadState::Uploading(0).bytes()
    );
    run(&reopened, "owner", Method::Put, &data).unwrap();
    run(&h, "owner", Method::Finalize, &s.bytes()).unwrap();
    let read = read_req(s, 0);
    assert!(matches!(
        h.dispatch(&Principal::new("reader"), Method::Read, &read, 1024, || Ok(
            ()
        )),
        Err(MediaError::Refused(ErrorCode::ResourceExhausted))
    ));
    assert_eq!(
        run(&reopened, "reader", Method::Read, &read).unwrap().len(),
        CHUNK_BYTES + BLOCK_HEADER
    );
}

#[test]
fn v1_bounds_require_exact_fields_and_valid_progress() {
    let max = Manifest {
        length: MAX_OBJECT_BYTES,
        ..spec(b"")
    };
    let raw = max.bytes();
    assert_eq!(raw.len(), 80);
    for n in 0..raw.len() {
        assert!(Manifest::parse(&mut &raw[..n]).is_err());
    }
    assert_eq!(Manifest::parse(&mut raw.as_slice()).unwrap(), max);
    for n in [1, MAX_OBJECT_BYTES + 1, u64::MAX] {
        assert!(UploadState::parse(&UploadState::Uploading(n).bytes(), max).is_err());
    }
    for raw in [&[2, 0][..], &[3, 0], &[1], &[4], &[]] {
        assert!(UploadState::parse(raw, max).is_err());
    }
    assert_eq!(
        max.chunk_len(MAX_OBJECT_BYTES - CHUNK_BYTES as u64)
            .unwrap(),
        CHUNK_BYTES
    );
    assert!(Method::from_path("/syntra.media.v2.Media/Put").is_none());
}

#[test]
fn ordered_duplicate_and_terminal_transactions() {
    let dir = Dir::new();
    let h = host(&dir.file("db"));
    let data = vec![3; CHUNK_BYTES + 1];
    let s = spec(&data);
    let req = s.bytes();
    let call = |m, p: &[u8]| run(&h, "owner", m, p);
    assert_eq!(
        call(Method::Begin, &req).unwrap(),
        UploadState::Uploading(0).bytes()
    );
    let first = put(s, 0, &data[..CHUNK_BYTES]);
    let last = put(s, CHUNK_BYTES as u64, &data[CHUNK_BYTES..]);
    assert!(call(Method::Put, &last).is_err());
    assert!(call(Method::Read, &read_req(s, 0)).is_err());
    assert!(call(Method::Finalize, &req).is_err());
    assert_eq!(
        call(Method::Put, &first).unwrap(),
        call(Method::Put, &first).unwrap()
    );
    assert!(matches!(
        call(Method::Put, &put(s, 0, &vec![4; CHUNK_BYTES])),
        Err(MediaError::Conflict)
    ));
    for field in [
        Manifest { length: 0, ..s },
        Manifest {
            sha256: [9; 32],
            ..s
        },
        Manifest {
            key: ObjectVersion {
                version: 2,
                ..s.key
            },
            ..s
        },
        Manifest {
            key: ObjectVersion {
                object: [2; 16],
                ..s.key
            },
            ..s
        },
    ] {
        assert!(call(Method::Query, &field.bytes()).is_err());
        assert!(call(Method::Begin, &field.bytes()).is_err());
    }
    assert!(call(
        Method::Begin,
        &Manifest {
            transfer_id: [1; 16],
            ..s
        }
        .bytes()
    )
    .is_err());
    for m in [
        Method::Begin,
        Method::Query,
        Method::Finalize,
        Method::Abort,
    ] {
        assert!(matches!(
            run(&h, "writer", m, &req),
            Err(MediaError::Refused(ErrorCode::PermissionDenied))
        ));
    }
    assert!(run(&h, "writer", Method::Put, &first).is_err());
    call(Method::Put, &last).unwrap();
    call(Method::Finalize, &req).unwrap();
    assert_eq!(
        call(Method::Finalize, &req).unwrap(),
        UploadState::Committed.bytes()
    );
    assert_eq!(
        call(Method::Put, &last).unwrap(),
        UploadState::Committed.bytes()
    );
    assert!(call(Method::Abort, &req).is_err());
    assert_eq!(
        run(&h, "reader", Method::Describe, &s.key.bytes()).unwrap(),
        req
    );
    assert_eq!(
        block(
            s,
            &run(&h, "reader", Method::Read, &read_req(s, CHUNK_BYTES as u64)).unwrap()
        )
        .unwrap()
        .1,
        [3]
    );
    for (m, p) in [
        (Method::Describe, s.key.bytes()),
        (Method::Read, read_req(s, 0)),
    ] {
        assert!(run(&h, "intruder", m, &p).is_err());
    }
}

#[test]
fn sizes_digest_failure_and_abort_tombstone() {
    let d = Dir::new();
    let path = d.file("db");
    let h = host(&path);
    let s = spec(b"good");
    let call = |m, p: &[u8]| run(&h, "owner", m, p);
    for bad in [
        Manifest {
            length: MAX_OBJECT_BYTES + 1,
            ..s
        },
        Manifest {
            length: u64::MAX,
            ..s
        },
        Manifest {
            key: ObjectVersion {
                version: 0,
                ..s.key
            },
            ..s
        },
    ] {
        assert!(call(Method::Begin, &bad.bytes()).is_err());
    }
    let mut extra = s.bytes();
    extra.push(0);
    assert!(call(Method::Begin, &extra).is_err());
    call(Method::Begin, &s.bytes()).unwrap();
    for (pos, data) in [
        (u64::MAX, &b"good"[..]),
        (1, b"goo"),
        (4, b""),
        (0, b""),
        (0, b"g"),
        (0, b"good!"),
    ] {
        assert!(call(Method::Put, &put(s, pos, data)).is_err());
    }
    let mut badhash = put(s, 0, b"good");
    badhash[88] ^= 1;
    assert!(matches!(
        call(Method::Put, &badhash),
        Err(MediaError::Corrupt)
    ));
    call(Method::Put, &put(s, 0, b"evil")).unwrap();
    assert!(matches!(
        call(Method::Finalize, &s.bytes()),
        Err(MediaError::Corrupt)
    ));
    assert!(call(Method::Describe, &s.key.bytes()).is_err());
    call(Method::Abort, &s.bytes()).unwrap();
    drop(h);
    let h = host(&path);
    for m in [Method::Query, Method::Begin, Method::Abort] {
        assert_eq!(
            run(&h, "owner", m, &s.bytes()).unwrap(),
            UploadState::Aborted.bytes()
        );
    }
    assert!(run(&h, "owner", Method::Put, &put(s, 0, b"good")).is_err());
    let empty = Manifest {
        transfer_id: [6; 16],
        ..spec(b"")
    };
    run(&h, "owner", Method::Begin, &empty.bytes()).unwrap();
    run(&h, "owner", Method::Finalize, &empty.bytes()).unwrap();
    assert_eq!(
        run(&h, "owner", Method::Read, &read_req(empty, 0)).unwrap(),
        eof(empty)
    );
    assert!(DownloadStore::open(&path, "authority-A").is_err());
}

mod process_restart;

// Runs on a successful host dispatch, before MediaClient receives the reply.
type ReplyFault = fn(&Rpc, &mut [u8]) -> Result<()>;

fn lose_reply(_: &Rpc, _: &mut [u8]) -> Result<()> {
    Err(MediaError::Refused(ErrorCode::Unavailable))
}

struct Rpc {
    host: Arc<SqliteMediaHost>,
    calls: Mutex<Vec<(Method, Option<u64>)>>,
    fault: Option<(Method, Option<u64>, ReplyFault)>,
    refuse_chunk: bool,
    replace_after: Option<usize>,
    caller: &'static str,
}
impl Rpc {
    fn new(path: &Path) -> Self {
        Self {
            host: host(path),
            calls: Mutex::default(),
            fault: None,
            refuse_chunk: false,
            replace_after: None,
            caller: "owner",
        }
    }
}
impl MediaRpc for Rpc {
    type Reservation = (usize, usize, u64);
    type Reply = Vec<u8>;
    fn generation(p: &Self::Reservation) -> u64 {
        p.2
    }
    fn reserve(&self, req: usize, res: usize) -> Result<Self::Reservation> {
        if self.refuse_chunk && req > 120 {
            return Err(MediaError::Refused(ErrorCode::ResourceExhausted));
        }
        let replaced = self
            .replace_after
            .is_some_and(|n| self.calls.lock().unwrap().len() >= n);
        Ok((req, res, if replaced { 2 } else { 1 }))
    }
    async fn call(
        &self,
        (req, res, _): Self::Reservation,
        method: Method,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>> {
        assert!(payload.capacity() <= req, "request exceeds reservation");
        let offset = match method {
            Method::Put | Method::Read => Some(number(&mut &payload[80..])?),
            _ => None,
        };
        self.calls.lock().unwrap().push((method, offset));
        let mut reply = run(&self.host, self.caller, method, &payload)?;
        assert!(reply.len() <= res);
        if let Some((m, o, inject)) = self.fault {
            if (m, o) == (method, offset) {
                inject(self, &mut reply)?;
            }
        }
        Ok(reply)
    }
}

#[tokio::test]
async fn lost_put_and_finalize_ack_resume_by_query_after_reopen() {
    let d = Dir::new();
    let path = d.file("host");
    let file = d.file("input");
    let data = vec![7; CHUNK_BYTES + 11];
    fs::write(&file, &data).unwrap();
    let s = spec(&data);
    let client = MediaClient::new(Rpc {
        fault: Some((Method::Put, Some(0), lose_reply)),
        ..Rpc::new(&path)
    });
    assert!(client.upload(s, &file).await.is_err());
    drop(client);
    let client = MediaClient::new(Rpc {
        fault: Some((Method::Finalize, None, lose_reply)),
        ..Rpc::new(&path)
    });
    assert!(client.upload(s, &file).await.is_err());
    assert_eq!(
        *client.0.calls.lock().unwrap(),
        [
            (Method::Query, None),
            (Method::Put, Some(CHUNK_BYTES as u64)),
            (Method::Finalize, None)
        ]
    );
    drop(client);
    fs::remove_file(&file).unwrap();
    let client = MediaClient::new(Rpc::new(&path));
    client.upload(s, &file).await.unwrap();
    assert_eq!(*client.0.calls.lock().unwrap(), [(Method::Query, None)]);
}

#[tokio::test]
async fn no_chunk_read_before_admission_and_source_size_checked() {
    let d = Dir::new();
    let path = d.file("host");
    let s = spec(b"123");
    let c = MediaClient::new(Rpc {
        refuse_chunk: true,
        ..Rpc::new(&path)
    });
    assert!(matches!(
        c.upload(s, d.file("absent")).await,
        Err(MediaError::Refused(ErrorCode::ResourceExhausted))
    ));
    let c = MediaClient::new(Rpc::new(&path));
    let file = d.file("input");
    fs::write(&file, b"1234").unwrap();
    assert!(matches!(
        c.upload(s, &file).await,
        Err(MediaError::Conflict)
    ));
    assert_eq!(c.query(s).await.unwrap(), UploadState::Uploading(0));
    c.abort(s).await.unwrap();
    assert_eq!(c.query(s).await.unwrap(), UploadState::Aborted);
}

#[tokio::test]
async fn download_corruption_checkpoint_reopen_and_verified_export() {
    let d = Dir::new();
    let path = d.file("host");
    let local = d.file("dest");
    let file = d.file("input");
    let data = vec![91; CHUNK_BYTES + 3];
    let s = spec(&data);
    fs::write(&file, &data).unwrap();
    let client = MediaClient::new(Rpc {
        fault: Some((Method::Read, Some(CHUNK_BYTES as u64), |_, reply| {
            *reply.last_mut().unwrap() ^= 1;
            Ok(())
        })),
        ..Rpc::new(&path)
    });
    client.upload(s, file).await.unwrap();
    let dest = DownloadStore::open(&local, "authority-A/owner").unwrap();
    assert!(matches!(
        client.download(s, &dest).await,
        Err(MediaError::Corrupt)
    ));
    let mut out = Vec::new();
    assert!(dest.copy_verified(s, &mut out).is_err());
    assert!(out.is_empty());
    drop(dest);
    drop(client);
    assert!(DownloadStore::open(&local, "authority-A/reader").is_err());
    let dest = DownloadStore::open(&local, "authority-A/owner").unwrap();
    let client = MediaClient::new(Rpc::new(&path));
    client.download(s, &dest).await.unwrap();
    assert_eq!(
        *client.0.calls.lock().unwrap(),
        [
            (Method::Describe, None),
            (Method::Read, Some(CHUNK_BYTES as u64)),
            (Method::Read, Some(s.length))
        ]
    );
    dest.copy_verified(s, &mut out).unwrap();
    assert_eq!(out, data);
    // Alter both local bytes and chunk hash; only the pinned whole-object digest can detect this.
    Connection::open(&local)
        .unwrap()
        .execute(
            "UPDATE media_v1_chunk SET data=?1,hash=?2 WHERE pos!=0",
            rusqlite::params![b"bad", digest(b"bad")],
        )
        .unwrap();
    out.clear();
    assert!(matches!(
        dest.copy_verified(s, &mut out),
        Err(MediaError::Corrupt)
    ));
    assert!(out.is_empty());
    assert!(matches!(
        client.download(s, &dest).await,
        Err(MediaError::Corrupt)
    ));
    dest.discard(s).unwrap();
    client.download(s, &dest).await.unwrap();
    dest.copy_verified(s, &mut out).unwrap();
    assert_eq!(out, data);
}

#[tokio::test]
async fn runtime_principal_and_sqlite_acl_fence() {
    let d = Dir::new();
    let path = d.file("host");
    let s = spec(b"");
    let admin = Connection::open(&path).unwrap();
    admin
        .execute_batch(
            "CREATE TABLE acl(subject TEXT PRIMARY KEY); INSERT INTO acl VALUES('owner');",
        )
        .unwrap();
    let other = path.clone();
    let h = SqliteMediaHost::open(
        &path,
        "authority-A",
        Arc::new(move |tx, caller, _, key| {
            let allowed: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM acl WHERE subject=?1)",
                    [&caller.subject],
                    |r| r.get(0),
                )
                .map_err(|_| AuthError::denied())?;
            if !allowed || key.object != [11; 16] {
                return Err(AuthError::denied());
            }
            // Independent revocation cannot slip between this decision and commit.
            let revoker = Connection::open(&other).unwrap();
            revoker.busy_timeout(Duration::ZERO).unwrap();
            assert_eq!(
                revoker
                    .execute("DELETE FROM acl", [])
                    .unwrap_err()
                    .sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            Ok(())
        }),
    )
    .unwrap();
    let handler = h.handler();
    assert!(handler
        .authorize(&Principal::anonymous(), Method::Begin.path())
        .is_err());
    let (client, _host) = syntra_runtime::loopback_pair(
        Arc::new(syntra_runtime::StaticToken::new(
            b"fixture".to_vec(),
            "owner",
        )),
        handler.clone(),
        Default::default(),
    );
    client.handshake(b"fixture".to_vec()).await.unwrap();
    assert_eq!(
        client
            .call(Method::Begin.path(), s.bytes(), 5000)
            .await
            .unwrap(),
        UploadState::Uploading(0).bytes()
    );
    assert!(handler
        .authorize(&Principal::new("intruder"), Method::Begin.path())
        .is_err());
    admin.execute("DELETE FROM acl", []).unwrap();
    assert!(matches!(
        client.call(Method::Finalize.path(), s.bytes(), 5000).await,
        Err(syntra_core::SyntraError::Rpc {
            code: ErrorCode::PermissionDenied,
            ..
        })
    ));
    admin
        .execute("INSERT INTO acl VALUES('owner')", [])
        .unwrap();
    assert_eq!(
        client
            .call(Method::Query.path(), s.bytes(), 5000)
            .await
            .unwrap(),
        UploadState::Uploading(0).bytes()
    );
    client.close().await;
}

#[tokio::test]
async fn replacement_stops_before_begin_put_finalize_or_read_on_successor() {
    for after in 1..=3 {
        let d = Dir::new();
        let file = d.file("input");
        fs::write(&file, b"data").unwrap();
        let s = spec(b"data");
        let c = MediaClient::new(Rpc {
            replace_after: Some(after),
            ..Rpc::new(&d.file("host"))
        });
        assert!(matches!(
            c.upload(s, &file).await,
            Err(MediaError::Refused(ErrorCode::Unavailable))
        ));
        assert_eq!(c.0.calls.lock().unwrap().len(), after);
        // Fresh explicit call starts with Query on generation 2.
        c.upload(s, &file).await.unwrap();
        assert_eq!(c.0.calls.lock().unwrap()[after], (Method::Query, None));
    }
    let d = Dir::new();
    let file = d.file("input");
    let path = d.file("host");
    let data = vec![5; CHUNK_BYTES + 1];
    fs::write(&file, &data).unwrap();
    let s = spec(&data);
    MediaClient::new(Rpc::new(&path))
        .upload(s, file)
        .await
        .unwrap();
    for after in 1..=3 {
        let dest = DownloadStore::open(d.file(&format!("dest-{after}")), "scope").unwrap();
        let c = MediaClient::new(Rpc {
            replace_after: Some(after),
            ..Rpc::new(&path)
        });
        assert!(matches!(
            c.download(s, &dest).await,
            Err(MediaError::Refused(ErrorCode::Unavailable))
        ));
        assert_eq!(c.0.calls.lock().unwrap().len(), after);
        assert!(dest.copy_verified(s, std::io::sink()).is_err());
        c.download(s, &dest).await.unwrap();
        assert_eq!(c.0.calls.lock().unwrap()[after], (Method::Describe, None));
    }
}

#[tokio::test]
async fn describe_without_read_cannot_complete_cached_or_empty_download() {
    for bytes in [&b"cached"[..], b""] {
        let d = Dir::new();
        let path = d.file("host");
        let file = d.file("src");
        let s = spec(bytes);
        fs::write(&file, bytes).unwrap();
        let owner = MediaClient::new(Rpc::new(&path));
        owner.upload(s, file).await.unwrap();
        let dest = DownloadStore::open(d.file("dest"), "authority/account").unwrap();
        // Model an account whose Read permission is later withdrawn.
        if !bytes.is_empty() {
            owner.download(s, &dest).await.unwrap();
        }
        let c = MediaClient::new(Rpc {
            caller: "metadata",
            ..Rpc::new(&path)
        });
        assert_eq!(c.describe(s.key).await.unwrap(), s);
        assert!(matches!(
            c.download(s, &dest).await,
            Err(MediaError::Refused(ErrorCode::PermissionDenied))
        ));
        assert_eq!(
            c.0.calls.lock().unwrap().last().copied(),
            Some((Method::Read, Some(s.length)))
        );
        if bytes.is_empty() {
            assert!(dest.copy_verified(s, std::io::sink()).is_err());
        }
    }
}

#[test]
fn finalize_rechecks_acl_and_content_revision_after_the_read_snapshot() {
    use std::cell::Cell;
    for revoke in [true, false] {
        let d = Dir::new();
        let path = d.file("host");
        let admin = Connection::open(&path).unwrap();
        admin
            .execute_batch("CREATE TABLE acl(ok); INSERT INTO acl VALUES(1);")
            .unwrap();
        admin.busy_timeout(Duration::ZERO).unwrap();
        let h = SqliteMediaHost::open(
            &path,
            "scope",
            Arc::new(|tx, _, _, _| {
                match tx.query_row("SELECT ok FROM acl", [], |r| r.get::<_, bool>(0)) {
                    Ok(true) => Ok(()),
                    _ => Err(AuthError::denied()),
                }
            }),
        )
        .unwrap();
        let s = spec(b"good");
        run(&h, "owner", Method::Begin, &s.bytes()).unwrap();
        run(&h, "owner", Method::Put, &put(s, 0, b"good")).unwrap();
        let check_count = Cell::new(0);
        let result = h.dispatch(
            &Principal::new("owner"),
            Method::Finalize,
            &s.bytes(),
            1024,
            || {
                check_count.set(check_count.get() + 1);
                if check_count.get() == 3 {
                    // Callback from scanning the first row.
                    if revoke {
                        admin.execute("UPDATE acl SET ok=0", [])?;
                    } else {
                        admin.execute(
                            "UPDATE media_v1_chunk SET data=?1,hash=?2",
                            rusqlite::params![b"evil", digest(b"evil")],
                        )?;
                    }
                }
                Ok(())
            },
        );
        if revoke {
            assert!(matches!(
                result,
                Err(MediaError::Refused(ErrorCode::PermissionDenied))
            ));
        } else {
            assert!(matches!(result, Err(MediaError::Conflict)));
        }
        admin.execute("UPDATE acl SET ok=1", []).unwrap();
        assert_eq!(
            run(&h, "owner", Method::Query, &s.bytes()).unwrap(),
            UploadState::Uploading(4).bytes()
        );
    }
}

#[tokio::test]
async fn verified_sink_can_discard_same_store_without_waiting_for_export() {
    let d = Dir::new();
    let file = d.file("input");
    let data = vec![8; CHUNK_BYTES + 1];
    let s = spec(&data);
    fs::write(&file, &data).unwrap();
    let client = MediaClient::new(Rpc::new(&d.file("host")));
    client.upload(s, file).await.unwrap();
    let dest = DownloadStore::open(d.file("dest"), "scope").unwrap();
    client.download(s, &dest).await.unwrap();
    struct Sink {
        collected: Vec<u8>,
        other: DownloadStore,
        spec: Manifest,
    }
    impl std::io::Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.collected.is_empty() {
                let other = self.other.clone();
                let spec = self.spec;
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(other.discard(spec));
                });
                rx.recv_timeout(Duration::from_secs(3))
                    .expect("writer blocked by sink")
                    .unwrap();
            }
            self.collected.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Sink {
        collected: Vec::new(),
        other: dest.clone(),
        spec: s,
    };
    dest.copy_verified(s, &mut sink).unwrap();
    assert_eq!(sink.collected, data);
    assert!(dest.copy_verified(s, std::io::sink()).is_err());
}
