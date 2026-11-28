use super::*;
use std::{env, process};

const CASE: &str = "media::tests::process_restart::post_commit_exit_before_ack";
const DIRECTORY: &str = "SYNTRA_MEDIA_RESTART_TEST_DIRECTORY";
const PHASE: &str = "SYNTRA_MEDIA_RESTART_TEST_PHASE";
const PUT_EXIT: i32 = 73;
const FINALIZE_EXIT: i32 = 74;
const NEXT: u64 = CHUNK_BYTES as u64;

fn contents() -> Vec<u8> {
    let mut data = vec![0x31; CHUNK_BYTES];
    data.extend_from_slice(b"distinct final part");
    data
}

// Each invocation opens the real WAL database. The two cut points exit with
// the writer still open, without Rust destructors or a successful RPC return.
async fn child(dir: &Path, phase: &str) {
    let path = dir.join("host.sqlite");
    let source = dir.join("input");
    let data = contents();
    let s = spec(&data);
    let mut rpc = Rpc::new(&path);
    match phase {
        "put" => {
            rpc.fault = Some((Method::Put, Some(0), |rpc, reply| {
                assert_eq!(reply, UploadState::Uploading(NEXT).bytes());
                assert_eq!(
                    *rpc.calls.lock().unwrap(),
                    [
                        (Method::Query, None),
                        (Method::Begin, None),
                        (Method::Put, Some(0))
                    ]
                );
                process::exit(PUT_EXIT);
            }));
        }
        "finalize" => {
            // Object policy permits this writer, but it does not own the transfer.
            assert!(matches!(
                run(&rpc.host, "writer", Method::Abort, &s.bytes()),
                Err(MediaError::Refused(ErrorCode::PermissionDenied))
            ));
            assert_eq!(
                run(&rpc.host, "owner", Method::Query, &s.bytes()).unwrap(),
                UploadState::Uploading(NEXT).bytes()
            );
            assert!(matches!(
                run(&rpc.host, "reader", Method::Describe, &s.key.bytes()),
                Err(MediaError::Refused(ErrorCode::NotFound))
            ));
            rpc.fault = Some((Method::Finalize, None, |rpc, reply| {
                assert_eq!(reply, UploadState::Committed.bytes());
                assert_eq!(
                    *rpc.calls.lock().unwrap(),
                    [
                        (Method::Query, None),
                        (Method::Put, Some(NEXT)),
                        (Method::Finalize, None)
                    ]
                );
                process::exit(FINALIZE_EXIT);
            }));
        }
        "verify" => {
            assert!(matches!(
                run(&rpc.host, "writer", Method::Query, &s.bytes()),
                Err(MediaError::Refused(ErrorCode::PermissionDenied))
            ));
            assert!(matches!(
                run(&rpc.host, "intruder", Method::Read, &read_req(s, 0)),
                Err(MediaError::Refused(ErrorCode::PermissionDenied))
            ));
            let rival = Manifest {
                transfer_id: [13; 16],
                ..spec(b"replacement")
            };
            assert!(matches!(
                run(&rpc.host, "owner", Method::Begin, &rival.bytes()),
                Err(MediaError::Conflict)
            ));
            let client = MediaClient::new(rpc);
            assert_eq!(client.query(s).await.unwrap(), UploadState::Committed);
            client.upload(s, source).await.unwrap(); // parent removed the source
            assert_eq!(*client.0.calls.lock().unwrap(), [(Method::Query, None); 2]);
            let dest =
                DownloadStore::open(dir.join("download.sqlite"), "authority-A/owner").unwrap();
            client.download(s, &dest).await.unwrap();
            let mut out = Vec::new();
            dest.copy_verified(s, &mut out).unwrap();
            assert!(out == data, "export differs from pinned contents");
            let rows: u64 = Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM media_v1_transfer WHERE state=2",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(rows, 1, "expected one published version");
            return;
        }
        _ => panic!("unknown restart phase: {phase}"),
    }
    MediaClient::new(rpc).upload(s, source).await.unwrap();
    panic!("{phase} reply escaped the process-exit cut");
}

#[tokio::test]
async fn post_commit_exit_before_ack() {
    if let Some(dir) = env::var_os(DIRECTORY) {
        child(Path::new(&dir), &env::var(PHASE).unwrap()).await;
        return;
    }
    let dir = Dir::new();
    fs::write(dir.file("input"), contents()).unwrap();
    for (phase, expected) in [
        ("put", PUT_EXIT),
        ("finalize", FINALIZE_EXIT),
        ("verify", 0),
    ] {
        if phase == "verify" {
            fs::remove_file(dir.file("input")).unwrap();
        }
        let mut host = tokio::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", CASE, "--nocapture"])
            .env(DIRECTORY, &dir.0)
            .env(PHASE, phase)
            .stdout(process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let Ok(status) = tokio::time::timeout(Duration::from_secs(20), host.wait()).await else {
            host.kill().await.unwrap(); // kill and reap before removing the fixture
            panic!("{phase} host timed out");
        };
        assert_eq!(status.unwrap().code(), Some(expected), "{phase} host");
    }
}
