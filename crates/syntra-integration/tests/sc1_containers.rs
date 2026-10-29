use syntra_core::ErrorCode;
use syntra_runtime::ConnectionConfig;
use syntra_secure_channel::{generate_server_key, Carrier, ClientConfig, Context, Mode};
use syntra_tcp::Limits;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::{AsyncBuilder, AsyncRunner},
    GenericBuildableImage, GenericImage, ImageExt,
};

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

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
#[ignore = "requires Docker; run explicitly in integration job"]
async fn sc1_tcp_and_ws_over_containers() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    if !docker_available() {
        if std::env::var("SYNTRA_INTEGRATION_REQUIRE_DOCKER").is_ok() {
            panic!("Docker required for integration tests but unavailable");
        }
        println!("skipping container integration: docker unavailable");
        return Ok(());
    }
    let (private_key, public_key) = generate_server_key()?;
    let private_hex = hex(private_key.expose());
    let scope = "integration";
    let manifest = env!("CARGO_MANIFEST_DIR");
    let workspace = format!("{manifest}/../..");
    let dockerfile = r#"FROM rust:1.88-bookworm AS builder
WORKDIR /work
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p syntra-integration --bin peer
FROM debian:bookworm-slim
COPY --from=builder /work/target/release/peer /usr/local/bin/peer
EXPOSE 7001 7002
ENTRYPOINT ["/usr/local/bin/peer"]
"#;
    let built = GenericBuildableImage::new("syntra-integration-peer", "test")
        .with_dockerfile_string(dockerfile)
        .with_file(format!("{workspace}/Cargo.toml"), "./Cargo.toml")
        .with_file(format!("{workspace}/Cargo.lock"), "./Cargo.lock")
        .with_file(
            format!("{workspace}/crates/syntra-core"),
            "./crates/syntra-core",
        )
        .with_file(
            format!("{workspace}/crates/syntra-runtime"),
            "./crates/syntra-runtime",
        )
        .with_file(
            format!("{workspace}/crates/syntra-secure-channel"),
            "./crates/syntra-secure-channel",
        )
        .with_file(
            format!("{workspace}/crates/syntra-tcp"),
            "./crates/syntra-tcp",
        )
        .with_file(
            format!("{workspace}/crates/syntra-ws"),
            "./crates/syntra-ws",
        )
        .with_file(
            format!("{workspace}/crates/syntra-ws-sc1"),
            "./crates/syntra-ws-sc1",
        )
        .with_file(
            format!("{workspace}/crates/syntra-ffi"),
            "./crates/syntra-ffi",
        )
        .with_file(
            format!("{workspace}/crates/syntra-web"),
            "./crates/syntra-web",
        )
        .with_file(
            format!("{workspace}/crates/syntra-integration"),
            "./crates/syntra-integration",
        )
        .build_image()
        .await?;
    let _ = built;

    let image = GenericImage::new("syntra-integration-peer", "test")
        .with_exposed_port(7001.tcp())
        .with_exposed_port(7002.tcp())
        .with_wait_for(WaitFor::message_on_stdout("peer tcp ready"))
        .with_wait_for(WaitFor::message_on_stdout("peer ws ready"))
        .with_env_var("SC1_PRIVATE_HEX", private_hex)
        .with_env_var("SC1_SCOPE", scope);
    let container = image.start().await?;
    let _host = container.get_host().await?;
    let tcp_port = container.get_host_port_ipv4(7001.tcp()).await?;
    let ws_port = container.get_host_port_ipv4(7002.tcp()).await?;
    let host = "127.0.0.1";

    // TCP SC1 echo over real container networking.
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
    let client = match syntra_tcp::connect(
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
            let stdout = container.stdout_to_vec().await.unwrap_or_default();
            let stderr = container.stderr_to_vec().await.unwrap_or_default();
            eprintln!("peer stdout:\n{}", String::from_utf8_lossy(&stdout));
            eprintln!("peer stderr:\n{}", String::from_utf8_lossy(&stderr));
            return Err(format!("tcp connect failed: {e:?}").into());
        }
    };
    eprintln!("client connected: id={}", client.connection_id);
    let empty_first = match client.conn.call("/test.Echo/Echo", vec![], 5000).await {
        Ok(o) => o,
        Err(e) => {
            let stdout = container.stdout_to_vec().await.unwrap_or_default();
            let stderr = container.stderr_to_vec().await.unwrap_or_default();
            eprintln!("peer stdout:\n{}", String::from_utf8_lossy(&stdout));
            eprintln!("peer stderr:\n{}", String::from_utf8_lossy(&stderr));
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
            let stdout = container.stdout_to_vec().await.unwrap_or_default();
            let stderr = container.stderr_to_vec().await.unwrap_or_default();
            eprintln!("peer stdout:\n{}", String::from_utf8_lossy(&stdout));
            eprintln!("peer stderr:\n{}", String::from_utf8_lossy(&stderr));
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

    // WebSocket SC1 echo over the same container.
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
    let ws_url = format!("ws://{host}:{ws_port}/syntra/local/sc1/1/ws");
    let ws_client = syntra_ws_sc1::connect(
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

    Ok(())
}
