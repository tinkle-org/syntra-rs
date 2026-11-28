#[cfg(not(target_arch = "wasm32"))]
#[path = "fixtures/frame.rs"]
mod fixture;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::fixture::{request_frame, roundtrip, ROUNDTRIP_SIZES};
    use criterion::{BenchmarkId, Criterion, Throughput};
    use prost::Message;
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::{Frame, Notification, RpcResult};
    use syntra_core::{decode_frame, encode_frame, validate_wire_structure, ValidationContext};

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
                b.iter(|| validate_wire_structure(bytes).unwrap());
            });
            group.bench_with_input(
                BenchmarkId::new("decode_request", size),
                &bytes,
                |b, bytes| {
                    b.iter(|| decode_frame(bytes, ctx).unwrap());
                },
            );
            group.bench_with_input(
                BenchmarkId::new("encode_request", size),
                &frame,
                |b, frame| {
                    b.iter(|| encode_frame(frame, ctx).unwrap());
                },
            );
        }
        // Hold the payload at 64 B so decode_request/64 is the one-byte ID control.
        for request_id in [128, u64::MAX] {
            let frame = Frame {
                request_id,
                ..request_frame(64)
            };
            let bytes = frame.encode_to_vec();
            group.throughput(Throughput::Bytes(bytes.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("decode_request_64B_by_id", request_id),
                &bytes,
                |b, bytes| {
                    b.iter(|| decode_frame(bytes, ctx).unwrap());
                },
            );
        }
        let bytes = notification_frame(64).encode_to_vec();
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(BenchmarkId::new("decode_notification", 64), |b| {
            b.iter(|| decode_frame(&bytes, ctx).unwrap());
        });
        for size in [0, 64, 1024] {
            for (name, frame) in [
                ("roundtrip_notification", notification_frame(size)),
                ("roundtrip_result", success_frame(size)),
            ] {
                let bytes = frame.encode_to_vec();
                group.throughput(Throughput::Bytes(bytes.len() as u64));
                group.bench_function(BenchmarkId::new(name, size), |b| {
                    b.iter(|| roundtrip(&bytes, ctx));
                });
            }
        }
        for size in ROUNDTRIP_SIZES {
            let bytes = request_frame(size).encode_to_vec();
            assert_eq!(roundtrip(&bytes, ctx), bytes);
            group.throughput(Throughput::Bytes(bytes.len() as u64));
            group.bench_function(BenchmarkId::new("roundtrip_request", size), |b| {
                b.iter(|| roundtrip(&bytes, ctx));
            });
            if size != 0 {
                group.bench_function("decode_near_1MiB", |b| {
                    b.iter(|| decode_frame(&bytes, ctx).unwrap());
                });
            }
        }
        group.finish();
    }
}

#[cfg(not(target_arch = "wasm32"))]
criterion::criterion_group!(benches, native::frame_codec);
#[cfg(not(target_arch = "wasm32"))]
criterion::criterion_main!(benches);

#[cfg(target_arch = "wasm32")]
fn main() {}
