#![cfg(feature = "managed-media")]

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering::SeqCst},
        Arc, Mutex,
    },
    time::Duration,
};
use syntra_core::{
    secure_channel::{VerifiedIdentity, MAX_CIPHERTEXT},
    SyntraError,
};
use syntra_integration::{Loopback, CREDENTIAL};
use syntra_net::{
    client::{CallError, LifecycleStatus},
    lanes::{Lane, LaneClient, LaneConfig, LaneError, MediaReservation},
    pump::{RecordReader, RecordWriter},
    tcp::{StreamReader, StreamWriter},
    HostHandle,
};
use syntra_runtime::{Authenticator, FnHandler, HandlerOutcome, StaticToken};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::{Builder, Runtime},
    task::JoinHandle,
    time::timeout,
};

const RPC: &str = "/fixture.Fault/Echo";
const REPLY: usize = 96 * 1024; // More than one protected record.
const WATCHDOG: Duration = Duration::from_secs(15);

fn bounded<T>(rt: &Runtime, run: impl Future<Output = T>) -> T {
    rt.block_on(async { timeout(WATCHDOG, run).await.expect("fixture timed out") })
}

fn fixture() -> (Runtime, Loopback) {
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    let peer = bounded(&rt, Loopback::bind()).unwrap();
    (rt, peer)
}

fn open(peer: &Loopback, address: SocketAddr) -> (LaneClient, Arc<AtomicUsize>) {
    let fresh = peer.lane_inputs();
    let provisions = Arc::new(AtomicUsize::new(0));
    let count = provisions.clone();
    let owner = LaneClient::tcp(
        address,
        LaneConfig {
            media_operations: 2,
            media_bytes: 1 + REPLY + 2,
            media_idle: 2 * WATCHDOG,
            ..Default::default()
        },
        move || {
            count.fetch_add(1, SeqCst);
            fresh()
        },
    )
    .unwrap();
    (owner, provisions)
}

fn stop(owner: LaneClient) {
    let report = owner.shutdown(WATCHDOG);
    assert!(report.complete, "{report:?}");
    assert_eq!(
        (report.pending_operations, report.failed_supervisors),
        (0, 0)
    );
}

type Dispatches = Arc<Mutex<Vec<(&'static str, Vec<u8>)>>>;

async fn accept(peer: &Loopback, socket: &'static str, log: &Dispatches) -> HostHandle {
    let log = log.clone();
    peer.accept(
        Arc::new(|_: &VerifiedIdentity| {
            Ok(Arc::new(StaticToken::new(CREDENTIAL.to_vec(), "caller")) as Arc<dyn Authenticator>)
        }),
        Arc::new(FnHandler(move |_, payload: Vec<u8>, _| {
            log.lock().unwrap().push((socket, payload.clone()));
            async move {
                HandlerOutcome::Payload(if payload == [1] {
                    vec![1; REPLY]
                } else {
                    payload
                })
            }
        })),
    )
    .await
    .unwrap()
}

async fn generation(owner: &LaneClient, lane: Lane) -> u64 {
    let mut watch = owner.subscribe_status(lane);
    let mut status = watch.snapshot();
    loop {
        if let LifecycleStatus::CoreReady(r) = status {
            return r.generation;
        }
        status = watch.changed().await.unwrap();
    }
}

// Retry admission only. At each call site credit should fit; a leak hits the watchdog.
async fn admit(owner: &LaneClient, reply: usize) -> Result<MediaReservation, LaneError> {
    loop {
        match owner.try_reserve_media(1, reply) {
            Err(LaneError::Busy) => tokio::task::yield_now().await,
            result => return result,
        }
    }
}

async fn echo(owner: &LaneClient, tag: u8, generation: u64) {
    let reply = owner
        .call_interactive(RPC.into(), vec![tag], 15_000)
        .unwrap()
        .await
        .unwrap()
        .unwrap();
    assert_eq!((reply.generation, reply.value), (generation, vec![tag]));
}

async fn sockets(proxy: &TcpListener, origin: SocketAddr) -> (TcpStream, TcpStream) {
    (
        proxy.accept().await.unwrap().0,
        TcpStream::connect(origin).await.unwrap(),
    )
}

async fn relay(proxy: &TcpListener, origin: SocketAddr) -> JoinHandle<io::Result<(u64, u64)>> {
    let (mut client, mut host) = sockets(proxy, origin).await;
    tokio::spawn(async move { io::copy_bidirectional(&mut client, &mut host).await })
}

// Hand back BOTH live sockets at an exact byte boundary. No timer, packet-size
// assumption or kernel send-buffer saturation determines when the test cuts them.
async fn hold_partial_reply(client: TcpStream, host: TcpStream) -> (TcpStream, TcpStream) {
    let (mut request, response) = client.into_split();
    let (read, mut write) = host.into_split();
    let (mut from, mut to) = (StreamReader(read), StreamWriter(response));
    tokio::select! {
        result = io::copy(&mut request, &mut write) => panic!("media closed before gate: {result:?}"),
        () = async {
            // Returning-mode M2, protected Ready, then the first record of the reply.
            for _ in 0..3 {
                let record = from.read_record(MAX_CIPHERTEXT).await.unwrap();
                to.write_record(&record).await.unwrap();
            }
            let mut partial = [0; 3]; // u16 length + one actual ciphertext byte
            from.0.read_exact(&mut partial).await.unwrap();
            assert!(u16::from_be_bytes([partial[0], partial[1]]) > 1);
            to.0.write_all(&partial).await.unwrap();
        } => {}
    }
    (
        request.reunite(to.0).unwrap(),
        from.0.reunite(write).unwrap(),
    )
}

#[test]
fn partial_media_reply_loss_is_generation_local_and_never_replays() {
    let (rt, peer) = fixture();
    let origin = peer.address().unwrap();
    let proxy = bounded(&rt, TcpListener::bind("127.0.0.1:0")).unwrap();
    let (owner, provisions) = open(&peer, proxy.local_addr().unwrap());
    let log = Dispatches::default();
    let (ui, next, ui_relay, next_relay) = bounded(&rt, async {
        let ui_relay = relay(&proxy, origin).await;
        let ui = accept(&peer, "interactive", &log).await;
        let ui_gen = generation(&owner, Lane::Interactive).await;

        assert!(matches!(
            admit(&owner, REPLY).await,
            Err(LaneError::NotReady)
        ));
        let (client, host) = sockets(&proxy, origin).await;
        let gate = tokio::spawn(hold_partial_reply(client, host));
        let first = accept(&peer, "media", &log).await;
        let old = generation(&owner, Lane::Media).await;
        let stale = admit(&owner, 1).await.unwrap();
        // An oversized request must return the last slot and its entire byte charge
        // synchronously, without submitting anything to either socket.
        let rejected = admit(&owner, REPLY).await.unwrap();
        assert!(matches!(
            rejected.call(RPC, vec![0; 2], 15_000),
            Err(LaneError::Invalid)
        ));
        let mut lost = admit(&owner, REPLY)
            .await
            .unwrap()
            .call(RPC, vec![1], 15_000)
            .unwrap();

        let cut = gate.await.unwrap();
        assert!(matches!(
            owner.try_reserve_media(0, 0),
            Err(LaneError::Busy)
        ));
        ui.host.notify(vec![42]).await.unwrap();
        let note = owner.next_notification().unwrap().await.unwrap().unwrap();
        assert_eq!(
            (note.generation, note.value.payload),
            (ui_gen, Some(vec![42]))
        );
        echo(&owner, 2, ui_gen).await;
        assert!(
            lost.try_take().is_none(),
            "partial ciphertext completed an RPC"
        );
        drop(cut); // the reply cannot be finished; the host already executed it

        // Either the reconnect fence or the Core pending call may observe the EOF first.
        match lost.await.unwrap() {
            Err(LaneError::Call(
                CallError::Unavailable {
                    generation: Some(g),
                }
                | CallError::Rpc {
                    generation: g,
                    source: SyntraError::Unavailable(_),
                },
            )) => assert_eq!(g, old),
            Err(other) => panic!("unexpected media failure: {other:?}"),
            Ok(_) => panic!("truncated reply succeeded"),
        }
        first.close().await;
        let next_relay = relay(&proxy, origin).await;
        let next = accept(&peer, "successor", &log).await;
        let fresh = generation(&owner, Lane::Media).await;
        assert!(fresh > old);
        assert!(
            matches!(stale.call(RPC, vec![3], 15_000), Err(LaneError::Call(CallError::Unavailable { generation: Some(g) })) if g == old)
        );

        // Reclaim both slots and every byte after the failed result and stale admission.
        let small = admit(&owner, 1).await.unwrap();
        let reply = admit(&owner, REPLY)
            .await
            .unwrap()
            .call(RPC, vec![4], 15_000)
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!((reply.generation(), reply.bytes()), (fresh, &[4][..]));
        drop((small, reply));
        echo(&owner, 5, ui_gen).await;
        (ui, next, ui_relay, next_relay)
    });
    stop(owner);
    bounded(&rt, async {
        ui_relay.await.unwrap().unwrap();
        next_relay.await.unwrap().unwrap();
        tokio::join!(ui.close(), next.close());
    });
    assert_eq!(provisions.load(SeqCst), 3);
    assert_eq!(
        *log.lock().unwrap(),
        [
            ("media", vec![1]),
            ("interactive", vec![2]),
            ("successor", vec![4]),
            ("interactive", vec![5])
        ]
    );
}

#[test]
fn platform_wake_without_media_demand_redials_only_interactive() {
    let (rt, peer) = fixture();
    let (owner, provisions) = open(&peer, peer.address().unwrap());
    let (first, next) = bounded(&rt, async {
        let log = Dispatches::default();
        let first = accept(&peer, "before wake", &log).await;
        let old = generation(&owner, Lane::Interactive).await;
        assert_eq!(owner.status(Lane::Media), LifecycleStatus::Paused);
        owner.platform_wake();
        let next = accept(&peer, "after wake", &log).await;
        let fresh = generation(&owner, Lane::Interactive).await;
        assert!(fresh > old);
        echo(&owner, 6, fresh).await;
        assert_eq!(owner.status(Lane::Media), LifecycleStatus::Paused);
        (first, next)
    });
    stop(owner);
    bounded(&rt, async { tokio::join!(first.close(), next.close()) });
    assert_eq!(
        provisions.load(SeqCst),
        2,
        "a parked media lane requested dial inputs"
    );
}
