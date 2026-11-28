//! Opt-in matched controls and the native lane owner. No FFI or file transfer layer.
use super::*;
use syntra_net::{
    client::LifecycleStatus,
    lanes::{Lane, LaneClient, LaneConfig, LaneError},
    network::NetworkConfig,
};
use tokio::runtime::{Builder, Runtime};

pub(super) const IDLE: Duration = Duration::from_millis(250);
const GRACE: Duration = Duration::from_secs(5);
const TRIAL: Duration = Duration::from_secs(60);

pub(super) struct Probes {
    cold: Option<Duration>,
    park: Option<Duration>,
    idle_connections: usize,
    #[cfg(feature = "measure-heap")]
    idle_heap: usize,
}

impl Probes {
    pub(super) fn sample(
        cold: Option<Duration>,
        park: Option<Duration>,
        idle_connections: usize,
    ) -> Self {
        Self {
            cold,
            park,
            idle_connections,
            #[cfg(feature = "measure-heap")]
            idle_heap: heap_probe::live_bytes(),
        }
    }

    pub(super) fn print(self) {
        if let Some(d) = self.cold {
            print!(" cold_media_open_us={}", d.as_micros());
        }
        if let Some(d) = self.park {
            print!(" media_idle_close_us={}", d.as_micros());
        }
        print!(" idle_connections={}", self.idle_connections);
        #[cfg(feature = "measure-heap")]
        print!(" idle_live_rust_heap_bytes={}", self.idle_heap);
    }
}

pub(super) async fn call(client: &LaneClient, method: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
    let bound = match method {
        ECHO => {
            return Ok(client
                .call_interactive(method.into(), bytes, RPC_MS)?
                .await??
                .value)
        }
        UPLOAD => 8,
        DOWNLOAD => BLOCK,
        _ => unreachable!(),
    };
    // Only retry pre-dispatch lock contention; never retry an RPC or hide a cold reconnect.
    let reservation = loop {
        match client.try_reserve_media(bytes.len(), bound) {
            Err(LaneError::Busy) => tokio::task::yield_now().await,
            result => break result?,
        }
    };
    Ok(reservation
        .call(method, bytes, RPC_MS)?
        .await??
        .into_bytes())
}

async fn wait_status(
    client: &LaneClient,
    lane: Lane,
    matches: impl Fn(&LifecycleStatus) -> bool,
) -> Result<()> {
    let mut watch = client.subscribe_status(lane);
    let mut status = watch.snapshot();
    while !matches(&status) {
        status = timeout(GRACE, watch.changed())
            .await
            .map_err(|_| format!("{lane:?} stuck in {status:?}"))??;
    }
    Ok(())
}

async fn ready(client: &LaneClient, lane: Lane) -> Result<()> {
    wait_status(client, lane, |s| matches!(s, LifecycleStatus::CoreReady(_))).await
}

async fn managed(
    fixture: &Loopback,
    client: &Arc<LaneClient>,
    load: Bulk,
    bursts: usize,
) -> Result<(Metrics, Vec<HostHandle>)> {
    let interactive = fixture.accept(factory(), handler()).await?;
    ready(client, Lane::Interactive).await?;
    let parked = |s: &LifecycleStatus| *s == LifecycleStatus::Paused;
    wait_status(client, Lane::Media, parked).await?;
    let mut hosts = vec![interactive];
    let cold = if matches!(load, Bulk::None) {
        None
    } else {
        let start = Instant::now();
        loop {
            match client.try_reserve_media(8, 8) {
                Err(LaneError::Busy) => tokio::task::yield_now().await,
                Err(LaneError::NotReady) => break,
                _ => return Err("expected cold media admission".into()),
            }
        }
        hosts.push(fixture.accept(factory(), handler()).await?);
        ready(client, Lane::Media).await?;
        Some(start.elapsed())
    };
    let endpoint = Endpoint::Lanes(client.clone());
    let mut metrics = measure(&endpoint, &endpoint, load, bursts, Some(&hosts[0].host)).await?;
    let park = if let Some(media) = hosts.get(1) {
        let drained = Instant::now();
        wait_status(client, Lane::Media, parked).await?;
        while !media.is_closed() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Some(drained.elapsed())
    } else {
        tokio::time::sleep(IDLE).await;
        None
    };
    if !parked(&client.status(Lane::Media)) || hosts[0].is_closed() {
        return Err("unexpected idle lane status".into());
    }
    metrics.probes = Some(Probes::sample(cold, park, 1));
    if call(client, ECHO, vec![17; 8]).await? != [17; 8] {
        return Err("interactive echo after idle".into());
    }
    Ok((metrics, hosts))
}

// Construction and joined shutdown are blocking APIs for ordinary threads.
fn lane_trial(rt: &Runtime, fixture: &Loopback, load: Bulk, bursts: usize) -> Result<Metrics> {
    let config = LaneConfig {
        network: NetworkConfig {
            worker_threads: 1,
            ..Default::default()
        },
        media_idle: IDLE,
        ..Default::default()
    };
    let client = Arc::new(LaneClient::tcp(
        fixture.address()?,
        config,
        fixture.lane_inputs(),
    )?);
    let result =
        rt.block_on(async { timeout(TRIAL, managed(fixture, &client, load, bursts)).await });
    let shutdown = client.shutdown(GRACE);
    if !shutdown.complete || shutdown.failed_supervisors != 0 || shutdown.pending_operations != 0 {
        return Err(format!("incomplete managed shutdown: {shutdown:?}").into());
    }
    let (metrics, hosts) = result??;
    for mut host in hosts {
        if rt.block_on(host.shutdown_transport(GRACE))? != TransportShutdown::Complete {
            return Err("incomplete host shutdown".into());
        }
    }
    Ok(metrics)
}

pub(super) fn run(passes: usize, bursts: usize) -> Result<()> {
    println!("# production-lanes TCP loopback; direct/manual: 4 shared workers; LaneClient: 2 host/driver + 1 interactive + 1 media. Scheduler + topology, not wire alone.");
    println!("# warmup_bursts=1 measured_bursts={bursts} echo_per_burst={SMALL_CALLS} echo_bytes=8 block_bytes={BLOCK} interactive_notifications_per_burst=1 media_idle_ms={}",IDLE.as_millis());
    println!("# update_us: host notify start to tagged interactive receipt; active_s includes last verified notification/RPC. Cold demand to ready and drain to observed park + peer close are outside bursts.");
    #[cfg(feature = "measure-heap")]
    println!("# instrumented: use only peak live Rust allocation bytes during measured bursts and live bytes at idle observation (whole process, not RSS).");
    let mut cases: Vec<_> = [Bulk::None, Bulk::Upload, Bulk::Download, Bulk::Both]
        .into_iter()
        .flat_map(|load| ["one", "manual-two", "LaneClient"].map(|kind| (load, kind)))
        .collect();
    for pass in 1..=passes {
        for &(load, kind) in &cases {
            let lanes = kind == "LaneClient";
            let rt = Builder::new_multi_thread()
                .worker_threads(if lanes { 2 } else { 4 })
                .enable_all()
                .build()?;
            let mut fixture = rt.block_on(Loopback::bind())?;
            let metrics = if lanes {
                lane_trial(&rt, &fixture, load, bursts)
            } else {
                rt.block_on(async {
                    timeout(
                        TRIAL,
                        trial(&mut fixture, kind == "manual-two", load, bursts, true),
                    )
                    .await?
                })
            }
            .map_err(|e| format!("pass {pass}, {kind}, bulk={load:?}: {e}"))?;
            print!("pass={pass} topology={kind} bulk={load:?} ");
            report(metrics);
        }
        cases.reverse();
    }
    Ok(())
}
