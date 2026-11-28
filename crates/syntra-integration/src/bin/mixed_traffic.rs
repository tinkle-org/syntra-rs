//! Established loopback RPCs, not a streaming protocol or an open-loop arrival model.
//! Each burst has one caller await four small RPCs in sequence. Independent bulk
//! callers can offer one large upload, one large download, both, or neither.
//! Bursts drain completely; a faster connection cannot earn extra work.
//! Setup, warmup, task creation, client input allocation and teardown are untimed.
//! The active interval includes scheduling, runtime/carrier allocations and I/O,
//! host payload generation/verification, and client result verification.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use syntra_core::{secure_channel::VerifiedIdentity, ErrorCode};
use syntra_integration::{Loopback, CREDENTIAL};
use syntra_net::{AuthenticatorFactory, ClientHandle, HostHandle, TransportShutdown};
use syntra_runtime::{Authenticator, FnHandler, Handler, HandlerOutcome, Initiator, StaticToken};
use tokio::{sync::Barrier, task::JoinSet, time::timeout};

#[cfg(feature = "managed-media")]
#[path = "../production_lanes.rs"]
mod production;

#[cfg(feature = "measure-heap")]
#[path = "../heap_probe.rs"]
mod heap_probe;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const ECHO: &str = "/bench.Mixed/Echo";
const UPLOAD: &str = "/bench.Mixed/Upload";
const DOWNLOAD: &str = "/bench.Mixed/Download";
const SMALL_CALLS: usize = 4;
const BLOCK: usize = 256 * 1024;
const RPC_MS: u32 = 5000;
type Tag = [u8; 8];

fn block(tag: &Tag) -> Vec<u8> {
    tag.repeat(BLOCK / tag.len())
}

fn valid_block(bytes: &[u8], tag: &Tag) -> bool {
    bytes.len() == BLOCK && bytes.chunks_exact(tag.len()).all(|chunk| chunk == tag)
}

fn factory() -> Arc<dyn AuthenticatorFactory> {
    Arc::new(|_: &VerifiedIdentity| {
        Ok(Arc::new(StaticToken::new(CREDENTIAL.to_vec(), "benchmark")) as Arc<dyn Authenticator>)
    })
}

fn handler() -> Arc<dyn Handler> {
    Arc::new(FnHandler(|method: String, bytes: Vec<u8>, _| async move {
        match method.as_str() {
            ECHO if bytes.len() == 8 => return HandlerOutcome::Payload(bytes),
            UPLOAD => {
                if let Some(tag) = bytes.first_chunk::<8>() {
                    if valid_block(&bytes, tag) {
                        return HandlerOutcome::Payload(tag.to_vec());
                    }
                }
            }
            DOWNLOAD => {
                if let Ok(tag) = bytes.as_slice().try_into() {
                    return HandlerOutcome::Payload(block(tag));
                }
            }
            _ => (),
        }
        HandlerOutcome::error(ErrorCode::InvalidArgument, "invalid benchmark request")
    }))
}

#[derive(Clone, Copy)]
struct Call {
    start: Instant,
    returned: Instant,
}

#[derive(Default)]
struct Metrics {
    queue: Vec<Duration>,
    rtt: Vec<Duration>,
    offer_to_result: Vec<Duration>,
    overlap: usize,
    uploaded: usize,
    downloaded: usize,
    active: Duration,
    max_staged: usize,
    updates: Vec<Duration>,
    update_overlap: usize,
    #[cfg(feature = "managed-media")]
    probes: Option<production::Probes>,
    #[cfg(feature = "measure-heap")]
    peak_rust_heap_bytes: usize,
}

#[derive(Clone)]
enum Endpoint {
    Direct(Initiator),
    #[cfg(feature = "managed-media")]
    Lanes(Arc<syntra_net::lanes::LaneClient>),
}

impl Endpoint {
    async fn call(&self, method: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Self::Direct(conn) => Ok(conn.call(method, bytes, RPC_MS).await?),
            #[cfg(feature = "managed-media")]
            Self::Lanes(client) => production::call(client, method, bytes).await,
        }
    }

    async fn notification(&self) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Direct(conn) => Ok(conn.next_notification().await),
            #[cfg(feature = "managed-media")]
            Self::Lanes(client) => Ok(client.next_notification()?.await??.value.payload),
        }
    }
}

impl Metrics {
    fn record_echo(&mut self, offered: Instant, call: Call, bulk: [Option<Call>; 2]) {
        self.queue.push(call.start - offered);
        self.rtt.push(call.returned - call.start);
        self.offer_to_result.push(call.returned - offered);
        self.overlap += usize::from(call.overlaps(bulk));
    }
}

impl Call {
    fn overlaps(self, bulk: [Option<Call>; 2]) -> bool {
        // Count only a common interval across the sample and *all* enabled directions.
        let mut common = self;
        for other in bulk.into_iter().flatten() {
            common.start = common.start.max(other.start);
            common.returned = common.returned.min(other.returned);
        }
        bulk.iter().any(Option::is_some) && common.start < common.returned
    }
}

async fn burst(
    interactive: &Endpoint,
    upload: Option<&Endpoint>,
    download: Option<&Endpoint>,
    update_host: Option<&Arc<syntra_runtime::Host>>,
    index: usize,
    metrics: &mut Metrics,
) -> Result<()> {
    let lanes = 1 + usize::from(upload.is_some()) + usize::from(download.is_some());
    let gate = Arc::new(Barrier::new(lanes + usize::from(update_host.is_some())));
    let offered = Arc::new(OnceLock::new());
    let mut workers = JoinSet::new();
    let mut staged = 0;
    for (method, conn, slots) in [
        (ECHO, Some(interactive), 0..SMALL_CALLS),
        (UPLOAD, upload, SMALL_CALLS..SMALL_CALLS + 1),
        (DOWNLOAD, download, SMALL_CALLS + 1..SMALL_CALLS + 2),
    ] {
        let Some(conn) = conn.cloned() else { continue };
        let jobs: Vec<_> = slots
            .map(|i| {
                let tag = ((index * (SMALL_CALLS + 2) + i) as u64).to_le_bytes();
                let bytes = if method == UPLOAD {
                    block(&tag)
                } else {
                    tag.to_vec()
                };
                staged += bytes.capacity();
                (tag, bytes)
            })
            .collect();
        let (gate, offered) = (gate.clone(), offered.clone());
        workers.spawn(async move {
            let mut calls = Vec::with_capacity(jobs.len());
            let mut verified_bytes = 0;
            gate.wait().await;
            offered.get_or_init(Instant::now); // Common offer at first release, not task creation.
            for (tag, bytes) in jobs {
                let sent_len = bytes.len();
                let start = Instant::now();
                let reply = conn
                    .call(method, bytes)
                    .await
                    .map_err(|e| format!("burst {index}, {method}: {e}"))?;
                let returned = Instant::now();
                match method {
                    DOWNLOAD if valid_block(&reply, &tag) => verified_bytes += reply.len(),
                    UPLOAD if reply == tag => verified_bytes += sent_len,
                    ECHO if reply == tag => (),
                    _ => return Err(format!("burst {index}, {method}: wrong payload or receipt")),
                }
                calls.push(Call { start, returned });
            }
            Ok((method, calls, verified_bytes, Instant::now()))
        });
    }

    if let Some(host) = update_host.cloned() {
        let (gate, offered, conn) = (gate.clone(), offered.clone(), interactive.clone());
        workers.spawn(async move {
            let tag = (index as u64).to_le_bytes();
            let payload = tag.to_vec();
            gate.wait().await;
            offered.get_or_init(Instant::now);
            let start = Instant::now();
            host.notify(payload).await.map_err(|e| e.to_string())?;
            let reply = conn.notification().await.map_err(|e| e.to_string())?;
            let returned = Instant::now();
            if reply.as_deref() != Some(&tag) {
                return Err(format!("burst {index}: missing or wrong notification"));
            }
            Ok((
                "notification",
                vec![Call { start, returned }],
                0,
                Instant::now(),
            ))
        });
    }

    // Stop barrier: record the last verified completion, not time spent joining or reporting.
    let mut interactive_calls = Vec::new();
    let mut up = None;
    let mut down = None;
    let mut update = None;
    let mut last_done = None;
    while let Some(result) = workers.join_next().await {
        let (method, calls, bytes, done) = result??;
        match method {
            ECHO => interactive_calls = calls,
            "notification" => update = Some(calls[0]),
            UPLOAD => {
                up = Some(calls[0]);
                metrics.uploaded += bytes;
            }
            DOWNLOAD => {
                down = Some(calls[0]);
                metrics.downloaded += bytes;
            }
            _ => unreachable!(),
        }
        last_done = last_done.max(Some(done));
    }
    let start = *offered.get().expect("nonempty burst");
    for call in interactive_calls {
        metrics.record_echo(start, call, [up, down]);
    }
    if let Some(call) = update {
        metrics.updates.push(call.returned - call.start);
        metrics.update_overlap += usize::from(call.overlaps([up, down]));
    }
    metrics.active += last_done.expect("nonempty burst") - start;
    metrics.max_staged = metrics.max_staged.max(staged);
    Ok(())
}

fn percentiles(samples: &mut [Duration]) -> [f64; 3] {
    samples.sort_unstable();
    [50, 95, 99].map(|p| samples[(samples.len() * p).div_ceil(100) - 1].as_secs_f64() * 1e6)
}

async fn shutdown((mut client, mut host): (ClientHandle, HostHandle)) -> Result<()> {
    let grace = Duration::from_secs(5);
    let (c, h) = tokio::try_join!(
        client.shutdown_transport(grace),
        host.shutdown_transport(grace)
    )?;
    if (c, h) != (TransportShutdown::Complete, TransportShutdown::Complete) {
        return Err(format!("incomplete transport shutdown: {c:?}, {h:?}").into());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Bulk {
    None,
    Upload,
    Download,
    Both,
}

async fn measure(
    interactive: &Endpoint,
    bulk: &Endpoint,
    load: Bulk,
    bursts: usize,
    update_host: Option<&Arc<syntra_runtime::Host>>,
) -> Result<Metrics> {
    let upload = matches!(load, Bulk::Upload | Bulk::Both).then_some(bulk);
    let download = matches!(load, Bulk::Download | Bulk::Both).then_some(bulk);
    let expected_up = usize::from(upload.is_some()) * bursts * BLOCK;
    let expected_down = usize::from(download.is_some()) * bursts * BLOCK;
    burst(
        interactive,
        upload,
        download,
        update_host,
        0,
        &mut Metrics::default(),
    )
    .await?;
    let mut metrics = Metrics::default();
    #[cfg(feature = "measure-heap")]
    heap_probe::begin_window();
    for index in 1..=bursts {
        burst(
            interactive,
            upload,
            download,
            update_host,
            index,
            &mut metrics,
        )
        .await?;
    }
    #[cfg(feature = "measure-heap")]
    {
        let peak_live = heap_probe::peak_bytes();
        metrics.peak_rust_heap_bytes = peak_live;
    }
    if metrics.rtt.len() != bursts * SMALL_CALLS
        || metrics.updates.len() != usize::from(update_host.is_some()) * bursts
        || (metrics.uploaded, metrics.downloaded) != (expected_up, expected_down)
    {
        return Err("incomplete workload".into());
    }
    if !matches!(load, Bulk::None) && metrics.overlap == 0 {
        return Err("no measured RPC overlap with all requested bulk directions".into());
    }
    Ok(metrics)
}

async fn trial(
    fixture: &mut Loopback,
    split: bool,
    load: Bulk,
    bursts: usize,
    updates: bool,
) -> Result<Metrics> {
    let primary = fixture.open(factory(), handler()).await?;
    let second = if split {
        Some(fixture.open(factory(), handler()).await?)
    } else {
        None
    };
    let interactive = Endpoint::Direct(primary.0.conn.clone());
    let bulk = second
        .as_ref()
        .map(|pair| Endpoint::Direct(pair.0.conn.clone()));
    let metrics = measure(
        &interactive,
        bulk.as_ref().unwrap_or(&interactive),
        load,
        bursts,
        updates.then_some(&primary.1.host),
    )
    .await?;
    #[cfg(feature = "managed-media")]
    let metrics = if updates {
        tokio::time::sleep(production::IDLE).await;
        if primary.1.is_closed() || second.as_ref().is_some_and(|pair| pair.1.is_closed()) {
            return Err("unexpected idle disconnect".into());
        }
        Metrics {
            probes: Some(production::Probes::sample(
                None,
                None,
                1 + usize::from(split),
            )),
            ..metrics
        }
    } else {
        metrics
    };
    shutdown(primary).await?;
    if let Some(pair) = second {
        shutdown(pair).await?;
    }
    Ok(metrics)
}

fn main() -> Result<()> {
    let mut flags: Vec<_> = std::env::args_os().skip(1).collect();
    let lanes = flags.iter().position(|f| f == "--production-lanes");
    if let Some(i) = lanes {
        flags.remove(i);
    }
    let (passes, bursts) = match flags.as_slice() {
        [] => (2, 64),
        [arg] if arg == "--smoke" => (1, 2),
        _ => return Err("usage: mixed_traffic [--production-lanes] [--smoke]".into()),
    };
    if lanes.is_some() {
        #[cfg(feature = "managed-media")]
        return production::run(passes, bursts);
        #[cfg(not(feature = "managed-media"))]
        return Err("--production-lanes requires --features managed-media".into());
    }
    original(passes, bursts)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn original(passes: usize, bursts: usize) -> Result<()> {
    let mut fixture = timeout(Duration::from_secs(10), Loopback::bind()).await??;
    println!("# workers=4 warmup_bursts=1 measured_bursts={bursts} echo_per_burst={SMALL_CALLS} echo_bytes=8 block_bytes={BLOCK}");
    println!("# us: nearest-rank per-echo call-to-return, burst-offer-to-call, and burst-offer-to-return; overlap counts echoes simultaneous with all requested bulk directions (0 for no bulk)");
    println!("# MiB/s: verified directional application bytes / sum of offer-to-last-verified burst seconds; staged bytes: maximum per-burst sum of client input Vec capacities at offer (not process memory)");
    #[cfg(feature = "measure-heap")]
    println!("# peak_rust_heap_bytes: peak live Rust heap in this process during the measured burst loop, before shutdown; not RSS or an allocation delta");
    let mut cases = [Bulk::None, Bulk::Upload, Bulk::Download, Bulk::Both]
        .into_iter()
        .flat_map(|load| [(false, load), (true, load)])
        .collect::<Vec<_>>();
    for pass in 1..=passes {
        for &(split, load) in &cases {
            let connections = if split { 2 } else { 1 };
            let m = timeout(
                Duration::from_secs(60),
                trial(&mut fixture, split, load, bursts, false),
            )
            .await
            .map_err(|_| {
                format!("pass {pass}, connections={connections}, bulk={load:?}: trial timed out")
            })?
            .map_err(|e| format!("pass {pass}, connections={connections}, bulk={load:?}: {e}"))?;
            print!("pass={pass} connections={connections} bulk={load:?} ");
            report(m);
        }
        cases.reverse();
    }
    Ok(())
}

fn report(mut m: Metrics) {
    let n = m.rtt.len();
    let [r50, r95, r99] = percentiles(&mut m.rtt);
    let [q50, q95, q99] = percentiles(&mut m.queue);
    let [o50, o95, o99] = percentiles(&mut m.offer_to_result);
    let seconds = m.active.as_secs_f64();
    let rate = |bytes: usize| bytes as f64 / (1024. * 1024.) / seconds;
    print!("n={n} overlap={} \
                      rtt_us_p50={r50:.2} rtt_us_p95={r95:.2} rtt_us_p99={r99:.2} \
                      queue_us_p50={q50:.2} queue_us_p95={q95:.2} queue_us_p99={q99:.2} \
                      offer_to_result_us_p50={o50:.2} offer_to_result_us_p95={o95:.2} offer_to_result_us_p99={o99:.2} \
                      active_s={seconds:.6} up_bytes={} down_bytes={} up_MiB_s={:.2} down_MiB_s={:.2} staged_input_bytes={}",
                m.overlap, m.uploaded, m.downloaded, rate(m.uploaded), rate(m.downloaded), m.max_staged);
    #[cfg(feature = "measure-heap")]
    print!(" peak_rust_heap_bytes={}", m.peak_rust_heap_bytes);
    if !m.updates.is_empty() {
        let [u50, u95, u99] = percentiles(&mut m.updates);
        print!(
            " update_n={} update_overlap={} update_us_p50={u50:.2} update_us_p95={u95:.2} update_us_p99={u99:.2}",
            m.updates.len(), m.update_overlap
        );
    }
    #[cfg(feature = "managed-media")]
    if let Some(p) = m.probes {
        p.print();
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_the_whole_block() {
        let tag = 123_u64.to_le_bytes();
        let mut bytes = block(&tag);
        assert!(valid_block(&bytes, &tag));
        assert!(!valid_block(&bytes[8..], &tag));
        *bytes.last_mut().unwrap() ^= 1;
        assert!(!valid_block(&bytes, &tag));
    }

    #[test]
    fn nearest_rank_on_small_samples() {
        let mut times = [9, 1, 3, 2].map(Duration::from_micros);
        assert_eq!(percentiles(&mut times), [2., 9., 9.]);
    }

    #[test]
    fn offer_to_result_uses_paired_timestamps() {
        let offered = Instant::now();
        let mut metrics = Metrics::default();
        for (start, returned) in [(1, 11), (10, 12)] {
            let call = Call {
                start: offered + Duration::from_micros(start),
                returned: offered + Duration::from_micros(returned),
            };
            metrics.record_echo(offered, call, [None, None]);
        }
        assert_eq!(percentiles(&mut metrics.offer_to_result), [11., 12., 12.]);
        assert_eq!(metrics.overlap, 0);
    }

    #[test]
    fn overlap_requires_a_positive_common_interval() {
        let offered = Instant::now();
        let interval = |s, e| Call {
            start: offered + Duration::from_micros(s),
            returned: offered + Duration::from_micros(e),
        };
        let echo = interval(1, 6);
        let up = Some(interval(0, 3));
        let mut metrics = Metrics::default();
        for (lanes, expected) in [
            ([up, None], 1),
            ([None, Some(interval(2, 5))], 1),
            ([up, Some(interval(3, 7))], 0),
            ([up, Some(interval(2, 7))], 1),
        ] {
            let before = metrics.overlap;
            metrics.record_echo(offered, echo, lanes);
            assert_eq!(metrics.overlap - before, expected);
        }
    }
}
