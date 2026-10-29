use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use syntra_runtime::{AuthError, Authenticator, StaticToken};
use syntra_runtime::{ConnectionConfig, FnHandler, HandlerOutcome};
use syntra_secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, KeyStore, Mode, Secret32, ServerConfig,
};
use syntra_tcp::{accept_stream, connect_stream, pump::AuthenticatorFactory, Limits};

struct Store;
impl KeyStore for Store {
    fn lookup(&self, c: &Context) -> Result<Secret32, syntra_secure_channel::Error> {
        if c.handle != [7; 8] || c.epoch != 2 {
            return Err(syntra_secure_channel::Error::Authentication);
        }
        Ok(Secret32::new([8; 32]))
    }
}

fn configs() -> (ClientConfig, ServerConfig) {
    let (key, public) = generate_server_key().unwrap();
    let context = Context {
        mode: Mode::Returning,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"bench".to_vec(),
        handle: [7; 8],
        epoch: 2,
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: Some(Secret32::new([8; 32])),
        },
        ServerConfig {
            mode: Mode::Returning,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"bench".to_vec(),
            private_key: key,
            store: Some(Arc::new(Store)),
        },
    )
}

fn factory() -> Arc<dyn AuthenticatorFactory> {
    Arc::new(
        move |_: &syntra_secure_channel::VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            Ok(Arc::new(StaticToken::new(
                b"bench".to_vec(),
                "bench-principal",
            )))
        },
    )
}

fn echo() -> Arc<dyn syntra_runtime::Handler> {
    Arc::new(FnHandler(|_, payload, _| async move {
        HandlerOutcome::Payload(payload)
    }))
}

pub fn pipe(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp");
    // Header-only microbenchmarks exclude sockets and crypto.
    group.bench_function("prefix_u16_preallocated", |b| {
        let mut buf = [0u8; 2];
        b.iter(|| {
            let n: u16 = 1024;
            buf.copy_from_slice(&n.to_be_bytes());
            criterion::black_box(buf);
        });
    });
    group.bench_function("prefix_u32_preallocated", |b| {
        let mut buf = [0u8; 4];
        b.iter(|| {
            let n: u32 = 1024;
            buf.copy_from_slice(&n.to_be_bytes());
            criterion::black_box(buf);
        });
    });
    for size in [64usize, 1024, 65_536] {
        group.throughput(Throughput::Bytes((size * 2) as u64));
        group.bench_with_input(BenchmarkId::new("duplex_echo", size), &size, |b, &size| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let payload = vec![0xA5; size];
            b.to_async(&rt).iter(|| async {
                let (client_cfg, server_cfg) = configs();
                let (a, b_stream) = tokio::io::duplex(1_048_576);
                let auth = factory();
                let server = tokio::spawn(async move {
                    accept_stream(
                        b_stream,
                        &server_cfg,
                        auth,
                        echo(),
                        ConnectionConfig::default(),
                        Limits::default(),
                    )
                    .await
                    .unwrap()
                });
                let client = connect_stream(
                    a,
                    client_cfg,
                    b"bench".to_vec(),
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
                .unwrap();
                let out = client
                    .conn
                    .call("/bench.Echo/Echo", payload.clone(), 5000)
                    .await
                    .unwrap();
                assert_eq!(out, payload);
                client.close().await;
                let host = server.await.unwrap();
                host.close().await;
            });
        });
    }
    group.finish();
    let mut lifecycle = c.benchmark_group("connection");
    lifecycle.bench_function("establishment_duplex", |b| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        b.to_async(&rt).iter(|| async {
            let (client_cfg, server_cfg) = configs();
            let (a, b_stream) = tokio::io::duplex(65_536);
            let auth = factory();
            let server = tokio::spawn(async move {
                accept_stream(
                    b_stream,
                    &server_cfg,
                    auth,
                    echo(),
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
                .unwrap()
            });
            let client = connect_stream(
                a,
                client_cfg,
                b"bench".to_vec(),
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await
            .unwrap();
            client.close().await;
            let host = server.await.unwrap();
            host.close().await;
        });
    });
    lifecycle.finish();
}

criterion_group!(benches, pipe);
criterion_main!(benches);
