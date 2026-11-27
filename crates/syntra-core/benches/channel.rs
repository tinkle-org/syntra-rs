#[cfg(not(target_arch = "wasm32"))]
#[path = "fixtures/record.rs"]
mod fixture;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::fixture::{warm_record, RECORD_SIZES};
    use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
    use syntra_core::secure_channel::{
        generate_server_key, respond, Carrier, ClientConfig, ClientHandshake, Context, Mode,
        ServerConfig,
    };

    fn bootstrap_pair() -> (ClientHandshake, Vec<u8>, ServerConfig) {
        let (private_key, public_key) = generate_server_key().unwrap();
        let context = Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"bench".to_vec(),
            handle: [0; 8],
            epoch: 0,
        };
        let client_cfg = ClientConfig {
            context: context.clone(),
            server_public_key: public_key,
            authorization_key: None,
        };
        let (hs, m1) = ClientHandshake::start(client_cfg).unwrap();
        let server_cfg = ServerConfig {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"bench".to_vec(),
            private_key,
            store: None,
        };
        (hs, m1, server_cfg)
    }

    pub fn channel(c: &mut Criterion) {
        let mut group = c.benchmark_group("connection");
        let ctx = Context {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: b"bench-scope".to_vec(),
            handle: [0; 8],
            epoch: 0,
        };
        let bytes = ctx.encode().unwrap();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function("append_context", |b| {
            b.iter(|| {
                let _ = ctx.encode().unwrap();
            });
        });
        group.bench_function("parse_context", |b| {
            let mut first = bytes.clone();
            first.extend_from_slice(&[0u8; 48]);
            b.iter(|| {
                let _ = Context::parse_first(&first).unwrap();
            });
        });
        group.bench_function("handshake_bootstrap", |b| {
            b.iter_batched(
                bootstrap_pair,
                |(client_hs, m1, server_cfg)| {
                    let (mut server, m2) = respond(&server_cfg, &m1).unwrap();
                    let mut client = client_hs.finish(&m2).unwrap();
                    let ct = client.encrypt(b"hello").unwrap();
                    let pt = server.decrypt(&ct).unwrap();
                    assert_eq!(pt.as_slice(), b"hello");
                },
                BatchSize::SmallInput,
            );
        });
        for size in RECORD_SIZES {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::new("record_warm", size), &size, |b, &size| {
                b.iter(warm_record(size));
            });
        }
        group.finish();
    }
}

#[cfg(not(target_arch = "wasm32"))]
criterion::criterion_group!(benches, native::channel);
#[cfg(not(target_arch = "wasm32"))]
criterion::criterion_main!(benches);

#[cfg(target_arch = "wasm32")]
fn main() {}
