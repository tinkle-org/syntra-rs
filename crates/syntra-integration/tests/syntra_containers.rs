use std::path::PathBuf;
use std::process::{Output, Stdio};
use std::time::Duration;
use syntra_core::secure_channel::{generate_server_key, Carrier, ClientConfig, Context, Mode};
use syntra_core::ErrorCode;
use syntra_net::{tcp, websocket, Limits};
use syntra_runtime::ConnectionConfig;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(30);
const IMAGE: &str = "syntra-integration-peer:test";

#[derive(Clone)]
struct DockerCli {
    program: PathBuf,
    /// Read injected shell fixtures as data instead of executing a newly written file.
    script: Option<PathBuf>,
    private_hex: String,
}

impl DockerCli {
    /// Remove the fixture private key from command diagnostics.
    fn redact(&self, text: &str) -> String {
        if self.private_hex.is_empty() {
            text.to_owned()
        } else {
            text.replace(&self.private_hex, "[redacted]")
        }
    }

    /// Pass literal arguments to Docker or the injected script, bounding execution
    /// and allowing a separate kill budget without shell command interpolation.
    async fn run(&self, args: &[&str], budget: Duration) -> Result<Output, String> {
        let mut command = Command::new(&self.program);
        if let Some(script) = &self.script {
            command.arg(script);
        }
        command.args(args).stdin(Stdio::null()).kill_on_drop(true);
        if args.first() == Some(&"create") {
            // Docker inherits the value by key, not via a secret-bearing argv.
            command.env("SYNTRA_PRIVATE_HEX", &self.private_hex);
        }
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("docker {} spawn failed: {e}", args[0]))?;
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = tokio::time::timeout(budget, async {
            let (status, _, _) = tokio::try_join!(
                child.wait(),
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err)
            )?;
            Ok::<_, std::io::Error>(status)
        })
        .await;
        match result {
            Ok(Ok(status)) if status.success() => Ok(Output {
                status,
                stdout: out,
                stderr: err,
            }),
            other => {
                // Retain the child through kill/reap. An outer readiness timeout
                // can cancel this function too; kill-on-drop covers that path.
                let _ = tokio::time::timeout(COMMAND_TIMEOUT, child.kill()).await;
                Err(self.redact(&format!(
                    "docker {} failed: {other:?}\nstdout:\n{}\nstderr:\n{}",
                    args[0],
                    String::from_utf8_lossy(&out),
                    String::from_utf8_lossy(&err)
                )))
            }
        }
    }
}

struct DockerPeer {
    cli: DockerCli,
    name: String,
    removed: bool,
}

impl DockerPeer {
    /// Create then start the owned fixture with dynamically mapped loopback ports.
    async fn start(&self, scope: &str) -> Result<(), String> {
        self.cli
            .run(
                &[
                    "create",
                    "--name",
                    &self.name,
                    "--publish",
                    "127.0.0.1::7001/tcp",
                    "--publish",
                    "127.0.0.1::7002/tcp",
                    "--env",
                    "SYNTRA_PRIVATE_HEX",
                    "--env",
                    &format!("SYNTRA_SCOPE={scope}"),
                    IMAGE,
                ],
                COMMAND_TIMEOUT,
            )
            .await?;
        self.cli
            .run(&["start", &self.name], COMMAND_TIMEOUT)
            .await?;
        Ok(())
    }

    /// Require both listener markers and a running container before protocol tests.
    async fn wait_ready(&self, budget: Duration) -> Result<(), String> {
        tokio::time::timeout(budget, async {
            loop {
                let logs = self
                    .cli
                    .run(&["logs", "--tail", "100", &self.name], COMMAND_TIMEOUT)
                    .await?;
                let state = self
                    .cli
                    .run(
                        &["inspect", "--format", "{{.State.Running}}", &self.name],
                        COMMAND_TIMEOUT,
                    )
                    .await?;
                if state.stdout != b"true\n" {
                    return Err("peer exited before readiness".to_owned());
                }
                if peer_ready(&String::from_utf8_lossy(&logs.stdout)) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .map_err(|_| "timed out waiting for both peer readiness markers".to_owned())?
    }

    /// Discover a nonzero IPv4 loopback mapping from the local Docker daemon.
    async fn port(&self, port: &str) -> Result<u16, String> {
        let output = self
            .cli
            .run(&["port", &self.name, port], COMMAND_TIMEOUT)
            .await?;
        loopback_port(&String::from_utf8_lossy(&output.stdout))
    }

    /// Await forced removal on success and disarm the fallback cleanup guard.
    async fn remove(&mut self) -> Result<(), String> {
        self.cli
            .run(&["rm", "--force", "--volumes", &self.name], COMMAND_TIMEOUT)
            .await?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for DockerPeer {
    /// Attempt bounded diagnostics and removal on errors or assertion unwinding.
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        // Also runs on errors/panics, including create/start failures. A separate
        // executor permits cleanup inside a current-thread test runtime.
        let cli = self.cli.clone();
        let name = self.name.clone();
        let cleanup = std::thread::Builder::new()
            .name("syntra-peer-cleanup".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?;
                runtime.block_on(async {
                    match cli
                        .run(&["logs", "--tail", "100", &name], COMMAND_TIMEOUT)
                        .await
                    {
                        Ok(logs) => eprintln!(
                            "peer stdout:\n{}\npeer stderr:\n{}",
                            cli.redact(&String::from_utf8_lossy(&logs.stdout)),
                            cli.redact(&String::from_utf8_lossy(&logs.stderr))
                        ),
                        Err(e) => eprintln!("peer diagnostics unavailable: {e}"),
                    }
                    cli.run(&["rm", "--force", "--volumes", &name], COMMAND_TIMEOUT)
                        .await
                        .map(|_| ())
                })
            });
        match cleanup {
            Ok(thread) => match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("peer cleanup failed for {}: {e}", self.name),
                Err(_) => eprintln!("peer cleanup thread panicked for {}", self.name),
            },
            Err(e) => eprintln!("could not start peer cleanup for {}: {e}", self.name),
        }
    }
}

/// Reject ambiguous or externally exposed Docker port mappings.
fn loopback_port(text: &str) -> Result<u16, String> {
    let port = text
        .trim()
        .parse::<std::net::SocketAddrV4>()
        .ok()
        .filter(|address| *address.ip() == std::net::Ipv4Addr::LOCALHOST)
        .map(|address| address.port())
        .filter(|port| *port != 0);
    port.ok_or_else(|| "expected exactly one nonzero IPv4 loopback port mapping".to_owned())
}

/// Recognize both actual listener lines, without claiming RPC readiness.
fn peer_ready(logs: &str) -> bool {
    ["peer tcp ready on ", "peer ws ready on "]
        .iter()
        .all(|marker| logs.lines().any(|line| line.starts_with(marker)))
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
#[ignore = "requires Docker; run explicitly in integration job"]
/// Exercise encrypted TCP/WS RPCs against the current worktree's Docker peer.
async fn syntra_tcp_and_ws_over_containers() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    let mut cli = DockerCli {
        program: "docker".into(),
        script: None,
        private_hex: String::new(),
    };
    if cli.run(&["info"], COMMAND_TIMEOUT).await.is_err() {
        if std::env::var("SYNTRA_INTEGRATION_REQUIRE_DOCKER").is_ok() {
            panic!("Docker required for integration tests but unavailable");
        }
        println!("skipping container integration: docker unavailable");
        return Ok(());
    }
    let (private_key, public_key) = generate_server_key()?;
    cli.private_hex = hex(private_key.expose());
    let scope = "integration";
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace = format!("{manifest}/../..");
    cli.run(
        &[
            "build",
            "--file",
            &format!("{manifest}/Dockerfile"),
            "--tag",
            IMAGE,
            &workspace,
        ],
        Duration::from_secs(600),
    )
    .await?;
    // Own cleanup BEFORE create: even a failed/timed-out create or start may
    // have left a container in the daemon. The public key supplies a fresh name.
    let mut container = DockerPeer {
        cli,
        name: format!("syntra-peer-{}-{}", std::process::id(), hex(&public_key)),
        removed: false,
    };
    container.start(scope).await?;
    container.wait_ready(READY_TIMEOUT).await?;
    let tcp_port = container.port("7001/tcp").await?;
    let ws_port = container.port("7002/tcp").await?;
    let host = "127.0.0.1";

    // Syntra 1.0 TCP echo over container networking; not a conformance verdict.
    let tcp_client_cfg = ClientConfig {
        context: Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: scope.as_bytes().to_vec(),
            handle: [0; 8],
            epoch: 0,
        },
        server_public_key: public_key,
        authorization_key: None,
    };
    let tcp_addr = format!("{host}:{tcp_port}");
    let client = match tcp::connect(
        tcp_addr,
        tcp_client_cfg,
        b"test-credential".to_vec(),
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return Err(format!("tcp connect failed: {e:?}").into());
        }
    };
    eprintln!("client connected: id={}", client.connection_id);
    let empty_first = match client.conn.call("/test.Echo/Echo", vec![], 5000).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("client terminal: {:?}", client.conn.terminal_reason());
            return Err(format!("tcp empty echo failed: {e:?}").into());
        }
    };
    assert!(empty_first.is_empty());
    let payload = vec![0xA5; 1024];
    let out = match client
        .conn
        .call("/test.Echo/Echo", payload.clone(), 5000)
        .await
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("client terminal: {:?}", client.conn.terminal_reason());
            return Err(format!("tcp echo failed: {e:?}").into());
        }
    };
    assert_eq!(out, payload);
    let err = client
        .conn
        .call("/test.Denied/Denied", vec![], 5000)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::PermissionDenied);
    // Concurrent callers over the same container connection.
    let mut handles = Vec::new();
    for i in 0..8u8 {
        let conn = client.conn.clone();
        handles.push(tokio::spawn(async move {
            let p = vec![i; 2048];
            let o = conn.call("/test.Echo/Echo", p.clone(), 5000).await.unwrap();
            assert_eq!(o, p);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    client.close().await;

    // Syntra 1.0 WebSocket echo over the same container.
    let ws_client_cfg = ClientConfig {
        context: Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::WebSocket,
            server_key_id: 1,
            scope: scope.as_bytes().to_vec(),
            handle: [0; 8],
            epoch: 0,
        },
        server_public_key: public_key,
        authorization_key: None,
    };
    let ws_url = format!("ws://{host}:{ws_port}{}", websocket::ENDPOINT_PATH);
    let ws_client = websocket::connect(
        &ws_url,
        ws_client_cfg,
        b"test-credential".to_vec(),
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await?;
    let out = ws_client
        .conn
        .call("/test.Echo/Echo", payload.clone(), 5000)
        .await?;
    assert_eq!(out, payload);
    ws_client.close().await;

    container.remove().await?;
    Ok(())
}

#[test]
/// Accept one local port mapping and reject invalid or multi-address output.
fn mapped_ports_require_one_nonzero_ipv4_loopback_address() {
    assert_eq!(loopback_port("127.0.0.1:49152\n").unwrap(), 49152);
    assert_eq!(loopback_port("127.0.0.1:65535\r\n").unwrap(), 65535);
    for invalid in [
        "",
        "0.0.0.0:49152",
        "[::1]:49152",
        "127.0.0.2:49152",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:+123",
        "127.0.0.1:49152\n127.0.0.1:49153",
    ] {
        assert!(loopback_port(invalid).is_err(), "accepted {invalid:?}");
    }
}

#[test]
/// Require independent TCP and WS readiness lines regardless of log order.
fn readiness_requires_both_actual_peer_lines_in_either_order() {
    let tcp = "peer tcp ready on 0.0.0.0:7001\n";
    let ws = "peer ws ready on 0.0.0.0:7002\n";
    assert!(peer_ready(&format!("{tcp}{ws}")));
    assert!(peer_ready(&format!("{ws}{tcp}")));
    for incomplete in [
        "",
        tcp,
        ws,
        "waiting for peer tcp ready on and peer ws ready on",
    ] {
        assert!(!peer_ready(incomplete));
    }
}

#[cfg(unix)]
mod command_tests {
    use super::*;

    static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    struct FakeDocker(PathBuf);

    impl FakeDocker {
        /// Create an isolated command fixture without contacting a Docker daemon.
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "syntra-docker-cli-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            let script = path.join("docker");
            std::fs::write(
                &script,
                r#"#!/bin/sh
printf '%s\n' "$*" >> "$0.calls"
case "$1" in
    create) case "$*" in *fail-create*) printf '%s\n' "$SYNTRA_PRIVATE_HEX" >&2; exit 1 ;; esac ;;
    start) exit 1 ;;
    logs) printf 'peer tcp ready on 0.0.0.0:7001\n' ;;
    inspect) printf 'true\n' ;;
    hang) exec sleep 30 ;;
    rm) exit 0 ;;
    *) exit 1 ;;
esac
"#,
            )
            .unwrap();
            Self(path)
        }

        /// Bind an owned peer guard to the shell-read fixture and dummy key.
        fn peer(&self) -> DockerPeer {
            DockerPeer {
                cli: DockerCli {
                    // Linux can return ETXTBSY when parallel child creation races
                    // direct execution of a freshly written script. Read it via
                    // the existing shell; the timeout still owns the actual child.
                    program: "/bin/sh".into(),
                    script: Some(self.0.join("docker")),
                    private_hex: "fixture-private-value".into(),
                },
                name: "fixture-peer".into(),
                removed: false,
            }
        }

        /// Read the arguments observed by the injected Docker executable.
        fn calls(&self) -> String {
            std::fs::read_to_string(self.0.join("docker.calls")).unwrap()
        }
    }

    impl Drop for FakeDocker {
        /// Remove the isolated command fixture after its peer guard is dropped.
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    /// Preserve cleanup ownership and redact secrets after create/start failures.
    async fn failed_create_and_start_keep_cleanup_ownership_and_redact_errors() {
        for phase in ["create", "start"] {
            let fake = FakeDocker::new();
            let mut peer = fake.peer();
            peer.name = format!("fixture-fail-{phase}");
            let error = peer.start("integration").await.unwrap_err();
            assert!(!error.contains(&peer.cli.private_hex));
            if phase == "create" {
                assert!(
                    error.contains("[redacted]"),
                    "expected redacted create failure: {error}"
                );
            }
            drop(peer);
            let calls = fake.calls();
            assert!(calls.starts_with("create --name fixture-fail-"));
            assert!(calls.contains("--publish 127.0.0.1::7001/tcp --publish 127.0.0.1::7002/tcp"));
            assert!(calls.contains("--env SYNTRA_PRIVATE_HEX --env SYNTRA_SCOPE=integration"));
            assert_eq!(calls.contains("\nstart "), phase == "start");
            assert!(calls.ends_with(&format!("rm --force --volumes fixture-fail-{phase}\n")));
            assert!(!calls.contains("fixture-private-value"));
        }
    }

    #[tokio::test]
    /// Ensure assertion unwinding attempts cleanup from inside a Tokio runtime.
    async fn panic_unwinds_through_cleanup_inside_a_runtime() {
        let fake = FakeDocker::new();
        assert!(std::panic::catch_unwind(|| {
            let _peer = fake.peer();
            panic!("injected protocol assertion failure");
        })
        .is_err());
        assert_eq!(
            fake.calls(),
            "logs --tail 100 fixture-peer\nrm --force --volumes fixture-peer\n"
        );
    }

    #[tokio::test]
    /// Avoid a second removal attempt after awaited cleanup succeeds.
    async fn explicit_removal_disarms_drop() {
        let fake = FakeDocker::new();
        let mut peer = fake.peer();
        peer.remove().await.unwrap();
        drop(peer);
        assert_eq!(fake.calls(), "rm --force --volumes fixture-peer\n");
    }

    #[tokio::test]
    /// Bound a stalled child and reject readiness with only one listener marker.
    async fn stalled_command_and_missing_readiness_are_bounded() {
        let fake = FakeDocker::new();
        let peer = fake.peer();
        let started = std::time::Instant::now();
        let error = peer
            .cli
            .run(&["hang"], Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(
            error.contains("Elapsed"),
            "expected command timeout: {error}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let error = peer
            .wait_ready(Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(error.contains("both peer readiness markers"));
        drop(peer);
        assert!(fake
            .calls()
            .ends_with("rm --force --volumes fixture-peer\n"));
    }
}
