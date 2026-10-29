use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use syntra_secure_channel::{
    generate_server_key, respond, Carrier, ClientConfig, ClientHandshake, Context, KeyStore, Mode,
    Secret32, ServerConfig,
};

struct FixedStore {
    key: [u8; 32],
    handle: [u8; 8],
    epoch: u64,
}

impl KeyStore for FixedStore {
    fn lookup(&self, ctx: &Context) -> Result<Secret32, syntra_secure_channel::Error> {
        if ctx.handle == self.handle && ctx.epoch == self.epoch {
            Ok(Secret32::new(self.key))
        } else {
            Err(syntra_secure_channel::Error::Authentication)
        }
    }
}

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
    let mut group = c.benchmark_group("sc1");
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
        b.iter(|| {
            let (client_hs, m1, server_cfg) = bootstrap_pair();
            let (mut server, m2) = respond(&server_cfg, &m1).unwrap();
            let mut client = client_hs.finish(&m2).unwrap();
            let ct = client.encrypt(b"hello").unwrap();
            let pt = server.decrypt(&ct).unwrap();
            assert_eq!(pt.as_slice(), b"hello");
        });
    });
    for size in [64usize, 1024, 65_519] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("record_warm", size), &size, |b, &size| {
            let (private_key, public_key) = generate_server_key().unwrap();
            let store_key = [9u8; 32];
            let store = Arc::new(FixedStore {
                key: store_key,
                handle: [1; 8],
                epoch: 1,
            });
            let context = Context {
                mode: Mode::Returning,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: b"bench".to_vec(),
                handle: [1; 8],
                epoch: 1,
            };
            let client_cfg = ClientConfig {
                context: context.clone(),
                server_public_key: public_key,
                authorization_key: Some(Secret32::new(store_key)),
            };
            let server_cfg = ServerConfig {
                mode: Mode::Returning,
                carrier: Carrier::Tcp,
                server_key_id: 1,
                scope: b"bench".to_vec(),
                private_key,
                store: Some(store),
            };
            let (client_hs, m1) = ClientHandshake::start(client_cfg).unwrap();
            let (mut server, m2) = respond(&server_cfg, &m1).unwrap();
            let mut client = client_hs.finish(&m2).unwrap();
            // Confirm responder with one record outside timing.
            let ct0 = client.encrypt(b"confirm").unwrap();
            let _ = server.decrypt(&ct0).unwrap();
            let payload = vec![0xA5; size];
            b.iter(|| {
                let ct = client.encrypt(&payload).unwrap();
                let pt = server.decrypt(&ct).unwrap();
                assert_eq!(pt.as_slice(), payload.as_slice());
            });
        });
    }
    group.finish();
}

criterion_group!(benches, channel);
criterion_main!(benches);
