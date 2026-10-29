use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use prost::Message;
use syntra_core::proto::frame::Body;
use syntra_core::proto::{Frame, Notification, RpcRequest, RpcResult};
use syntra_core::{decode_frame, encode_frame, validate_wire_structure, ValidationContext};

fn request_frame(payload_len: usize) -> Frame {
    Frame {
        version: 1,
        request_id: 7,
        body: Some(Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![0xAB; payload_len],
            timeout_ms: 5000,
        })),
    }
}

fn notification_frame(payload_len: usize) -> Frame {
    Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Notification(Notification {
            payload: vec![0xCD; payload_len],
        })),
    }
}

fn success_frame(payload_len: usize) -> Frame {
    Frame {
        version: 1,
        request_id: 7,
        body: Some(Body::Result(RpcResult {
            outcome: Some(syntra_core::proto::rpc_result::Outcome::Payload(
                vec![0xEF; payload_len],
            )),
        })),
    }
}

pub fn frame_codec(c: &mut Criterion) {
    let ctx = ValidationContext::active(1);
    let mut group = c.benchmark_group("frame");
    for size in [0usize, 64, 1024, 65_536] {
        let frame = request_frame(size);
        let bytes = frame.encode_to_vec();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::new("scan", size), &bytes, |b, bytes| {
            b.iter(|| {
                let _ = validate_wire_structure(bytes);
            });
        });
        group.bench_with_input(
            BenchmarkId::new("decode_request", size),
            &bytes,
            |b, bytes| {
                b.iter(|| {
                    let _ = decode_frame(bytes, ctx);
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("encode_request", size),
            &frame,
            |b, frame| {
                b.iter(|| {
                    let _ = encode_frame(frame, ctx);
                });
            },
        );
        let notif = notification_frame(size.min(1024));
        let notif_bytes = notif.encode_to_vec();
        group.bench_with_input(
            BenchmarkId::new("roundtrip_notification", size.min(1024)),
            &notif_bytes,
            |b, bytes| {
                b.iter(|| {
                    let f = decode_frame(bytes, ctx).unwrap();
                    let _ = encode_frame(&f, ctx).unwrap();
                });
            },
        );
        let success = success_frame(size.min(1024));
        let success_bytes = success.encode_to_vec();
        group.bench_with_input(
            BenchmarkId::new("roundtrip_result", size.min(1024)),
            &success_bytes,
            |b, bytes| {
                b.iter(|| {
                    let f = decode_frame(bytes, ctx).unwrap();
                    let _ = encode_frame(&f, ctx).unwrap();
                });
            },
        );
    }
    // Near-limit envelope exercises multi-record segmentation budgets without
    // allocating a full 1MiB payload in every sample.
    let near_limit = request_frame(1_048_448 - 128);
    let near_bytes = near_limit.encode_to_vec();
    group.throughput(Throughput::Bytes(near_bytes.len() as u64));
    group.bench_function("decode_near_1MiB", |b| {
        b.iter(|| {
            let _ = decode_frame(&near_bytes, ctx);
        });
    });
    group.finish();
}

criterion_group!(benches, frame_codec);
criterion_main!(benches);
