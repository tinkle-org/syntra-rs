#![cfg(feature = "sockets")]
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use syntra_runtime::{
    AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler, Handler, HandlerOutcome,
    RejectAll, StaticToken,
};
use syntra_secure_channel::*;
use syntra_tcp::{
    pump::{RecordReader, RecordWriter},
    *,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Store;
impl KeyStore for Store {
    fn lookup(&self, c: &Context) -> Result<Secret32, syntra_secure_channel::Error> {
        if c.handle != [7; 8] || c.epoch != 2 {
            return Err(syntra_secure_channel::Error::Authentication);
        }
        Ok(Secret32::new([8; 32]))
    }
}
fn configs(mode: Mode) -> (ClientConfig, ServerConfig) {
    let (key, public) = generate_server_key().unwrap();
    let returning = mode == Mode::Returning;
    let context = Context {
        mode,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"localhost/test".to_vec(),
        handle: if returning { [7; 8] } else { [0; 8] },
        epoch: if returning { 2 } else { 0 },
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: returning.then(|| Secret32::new([8; 32])),
        },
        ServerConfig {
            mode,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: context.scope,
            private_key: key,
            store: Some(Arc::new(Store)),
        },
    )
}
fn echo() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|_, payload, _| async move {
        HandlerOutcome::Payload(payload)
    }))
}
fn factory(deny: bool, calls: Arc<AtomicUsize>) -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        move |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            calls.fetch_add(1, Ordering::SeqCst);
            if identity.context().mode == Mode::Returning {
                assert_eq!(identity.context().handle, [7; 8]);
            }
            if deny {
                Ok(Arc::new(RejectAll))
            } else {
                Ok(Arc::new(StaticToken::new(
                    b"app-credential".to_vec(),
                    "test-principal",
                )))
            }
        },
    )
}

#[tokio::test]
async fn live_tcp_client_host_both_modes_large_rpc_and_principal_deny() {
    for mode in [Mode::Bootstrap, Mode::Returning] {
        for deny in [false, true] {
            let (client, server) = configs(mode);
            let listener = Listener::bind("127.0.0.1:0", 2).await.unwrap();
            let address = listener.local_addr().unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let auth = factory(deny, calls.clone());
            let task = tokio::spawn(async move {
                listener
                    .accept(
                        &server,
                        auth,
                        echo(),
                        ConnectionConfig::default(),
                        Limits::default(),
                    )
                    .await
            });
            let client = connect(
                address,
                client,
                b"app-credential".to_vec(),
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await;
            let host = task.await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            if deny {
                assert!(client.is_err());
                assert!(host.is_err());
            } else {
                let client = client.unwrap();
                let host = host.unwrap();
                let payload = vec![42; 200_000];
                assert_eq!(
                    client
                        .conn
                        .call("/test.Service/Echo", payload.clone(), 5_000)
                        .await
                        .unwrap(),
                    payload
                );
                assert_eq!(host.host.sessions().count(), 1);
                let retained = client.conn.clone();
                drop(client);
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !retained.is_closed() || !host.is_closed() {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                host.close().await;
            }
        }
    }
}

#[tokio::test]
async fn replayed_first_flight_never_calls_factory() {
    let (client, server) = configs(Mode::Returning);
    let (_, first) = ClientHandshake::start(client).unwrap();
    let listener = Listener::bind("127.0.0.1:0", 1).await.unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    for _ in 0..2 {
        let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let mut wire = StreamWriter(socket);
        wire.write_record(&first).await.unwrap();
        let mut limits = Limits::default();
        limits.channel_timeout = Duration::from_millis(50);
        let accept = listener.accept(
            &server,
            factory(false, calls.clone()),
            echo(),
            ConnectionConfig::default(),
            limits,
        );
        let result = tokio::time::timeout(Duration::from_secs(1), accept)
            .await
            .unwrap();
        assert!(matches!(result, Err(syntra_tcp::Error::Timeout)));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_outer_split_point_and_truncated_record() {
    let record = [5u8; 17];
    let mut bytes = vec![0, 17];
    bytes.extend_from_slice(&record);
    for split in 0..=bytes.len() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let bytes = bytes.clone();
        let task = tokio::spawn(async move {
            tx.write_all(&bytes[..split]).await.unwrap();
            tokio::task::yield_now().await;
            tx.write_all(&bytes[split..]).await.unwrap();
        });
        let mut read = StreamReader(rx);
        assert_eq!(read.read_record(MAX_CIPHERTEXT).await.unwrap(), record);
        task.await.unwrap();
    }
    for bytes in [vec![0], vec![0, 17, 1], vec![0, 16], vec![0, 0]] {
        let (mut tx, rx) = tokio::io::duplex(64);
        tx.write_all(&bytes).await.unwrap();
        drop(tx);
        assert!(StreamReader(rx).read_record(MAX_CIPHERTEXT).await.is_err());
    }
}

#[tokio::test]
async fn accepted_generic_stream_partial_writes_and_connect_cancellation() {
    let (client, server) = configs(Mode::Bootstrap);
    let (left, right) = tokio::io::duplex(1);
    let task = tokio::spawn(async move {
        accept_stream(
            right,
            &server,
            Arc::new(
                |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                    Ok(Arc::new(AllowAnonymous))
                },
            ),
            echo(),
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
    });
    let client = connect_stream(
        left,
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    let host = task.await.unwrap().unwrap();
    assert_eq!(
        client
            .conn
            .call("/test.Service/Echo", vec![1; 1000], 5_000)
            .await
            .unwrap(),
        vec![1; 1000]
    );
    client.close().await;
    host.close().await;

    let (client, server) = configs(Mode::Bootstrap);
    let (left, mut right) = tokio::io::duplex(1024);
    let task = tokio::spawn(async move {
        // Complete Noise but never send ready, keeping connect inside Syntra handshake.
        let first_len = right.read_u16().await.unwrap();
        let mut first = vec![0; first_len as usize];
        right.read_exact(&mut first).await.unwrap();
        let (_, second) = respond(&server, &first).unwrap();
        right.write_u16(second.len() as u16).await.unwrap();
        right.write_all(&second).await.unwrap();
        let n = right.read_u16().await.unwrap();
        let mut hello = vec![0; n as usize];
        right.read_exact(&mut hello).await.unwrap();
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), right.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
    });
    let attempt = tokio::spawn(connect_stream(
        left,
        client,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
    ));
    tokio::time::sleep(Duration::from_millis(30)).await;
    attempt.abort();
    let _ = attempt.await;
    task.await.unwrap();
}

#[tokio::test]
async fn absolute_handshake_deadline_rejects_trickle() {
    let (_, server) = configs(Mode::Bootstrap);
    let (left, right) = tokio::io::duplex(64);
    let mut limits = Limits::default();
    limits.channel_timeout = Duration::from_millis(40);
    let trickle = tokio::spawn(async move {
        let mut left = left;
        for byte in [0, 83, 83, 78, 84, 82, 83, 67, 49, 76] {
            if left.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let result = accept_stream(
        right,
        &server,
        factory(false, Arc::new(AtomicUsize::new(0))),
        echo(),
        ConnectionConfig::default(),
        limits,
    )
    .await;
    assert!(matches!(result, Err(syntra_tcp::Error::Timeout)));
    trickle.abort();
}

struct FailWrites {
    inner: tokio::io::DuplexStream,
    fail: Arc<AtomicBool>,
}
impl tokio::io::AsyncRead for FailWrites {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, out)
    }
}
impl tokio::io::AsyncWrite for FailWrites {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.fail.load(Ordering::SeqCst) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test output failure",
            )));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn nonce_consumed_output_error_closes_runtime_and_does_not_dispatch() {
    let (client, server) = configs(Mode::Returning);
    let (left, right) = tokio::io::duplex(1024);
    let fail = Arc::new(AtomicBool::new(false));
    let effects = Arc::new(AtomicUsize::new(0));
    let effect_count = effects.clone();
    let handler = Arc::new(FnHandler(move |_, bytes, _| {
        effect_count.fetch_add(1, Ordering::SeqCst);
        async move { HandlerOutcome::Payload(bytes) }
    }));
    let server = tokio::spawn(async move {
        accept_stream(
            right,
            &server,
            factory(false, Arc::new(AtomicUsize::new(0))),
            handler,
            ConnectionConfig::default(),
            Limits::default(),
        )
        .await
        .unwrap()
    });
    let client = connect_stream(
        FailWrites {
            inner: left,
            fail: fail.clone(),
        },
        client,
        b"app-credential".to_vec(),
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await
    .unwrap();
    let host = server.await.unwrap();
    fail.store(true, Ordering::SeqCst);
    assert!(client
        .conn
        .call("/test.Service/Echo", vec![9; 100], 1_000)
        .await
        .is_err());
    tokio::time::timeout(Duration::from_secs(1), async {
        while !client.is_closed() || !host.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(client
        .conn
        .call("/test.Service/Echo", vec![1], 1_000)
        .await
        .is_err());
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    client.close().await;
    host.close().await;
}
