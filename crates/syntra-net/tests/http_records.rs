//! Candidate-only local structural and record-layer evidence, not conformance,
//! Noise vectors, independent interoperability, or production HTTP/HTTPS.
#![cfg(all(feature = "http", not(target_arch = "wasm32")))]

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
    time::Duration,
};
use syntra_net::{
    http::{
        self,
        codec::{self, Operation},
        Authority, OpenEnvelope, OriginPolicy, Route,
    },
    Error, EstablishmentBudget, RecordReader, RecordWriter,
};
use syntra_runtime::elapsed::ElapsedClock;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

const ROUTE: &str = "0000000000000000000000000000000000000000000000000000000000000000";
// Handwritten public-encoding transcriptions from Draft RFC0013's isolated
// rfcs/0013-http-tls/context-vectors.json, R13-CONTEXT-01 through -04, in order.
// No include_str! outside the package, fixture hash override, or upstream pin
// change. This is *not* a verified immutable source/provenance record.
const CONTEXTS: [&str; 4] = [
    "73796e7472612e312e3001040000000000000000000000000000000000000000000161",
    "73796e7472612e312e3002040102030400000000000000010102030405060708000f6578616d706c652e73657276696365",
    "73796e7472612e312e3001050000000000000000000000000000000000000000000161",
    "73796e7472612e312e3002050102030400000000000000010102030405060708000f6578616d706c652e73657276696365",
];

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
        .collect()
}
fn envelope() -> OpenEnvelope {
    OpenEnvelope::new(hex(CONTEXTS[0])).unwrap()
}
fn authority() -> Authority {
    Authority::new("example.invalid:80").unwrap()
}
fn route() -> Route {
    Route::parse(ROUTE).unwrap()
}
fn m1() -> Vec<u8> {
    let mut bytes = hex(CONTEXTS[0]);
    bytes.extend([0; 48]);
    bytes
}
fn budget() -> EstablishmentBudget {
    EstablishmentBudget::new(ElapsedClock::lifecycle_driven(), Duration::from_secs(15)).unwrap()
}

#[tokio::test]
async fn original_establishment_budget_can_be_moved_out_exactly_once() {
    let budget = budget();
    let deadline = budget.deadline();
    let (u, _) = tokio::io::duplex(16);
    let (d, _) = tokio::io::duplex(16);
    let (_reader, _writer, control) = http::client_pair(u, d, authority(), envelope(), budget);
    assert_eq!(
        control.take_establishment_budget().unwrap().deadline(),
        deadline
    );
    assert!(control.take_establishment_budget().is_err());
    assert!(!control.is_retired());
    control.abort();
    assert!(control.take_establishment_budget().is_err());
}

#[derive(Clone)]
struct Vector {
    id: &'static str,
    op: Operation,
    request: bool,
    start: String,
    fields: Vec<(String, String)>,
    body: Vec<u8>,
    accept: bool,
}
impl Vector {
    fn wire(&self) -> Vec<u8> {
        let mut wire = format!("{}\r\n", self.start);
        for (n, v) in &self.fields {
            wire.push_str(&format!("{n}: {v}\r\n"));
        }
        wire.push_str("\r\n");
        let mut wire = wire.into_bytes();
        wire.extend_from_slice(&self.body);
        wire
    }
    fn replace(&mut self, name: &str, value: &str) {
        self.fields.iter_mut().find(|(n, _)| n == name).unwrap().1 = value.into();
    }
}

fn vector(id: &'static str, op: Operation, request: bool, body: Vec<u8>) -> Vector {
    let mut fields = vec![("Cache-Control".into(), "no-store".into())];
    let status = if op == Operation::Open {
        "201 Created"
    } else if !body.is_empty() {
        "200 OK"
    } else {
        "204 No Content"
    };
    let start = if request {
        fields.push(("Host".into(), "example.invalid:80".into()));
        fields.push(("Accept".into(), "application/octet-stream".into()));
        format!("POST {} HTTP/1.1", op.path())
    } else {
        format!("HTTP/1.1 {status}")
    };
    if request || !status.starts_with("204") {
        fields.push(("Content-Length".into(), body.len().to_string()));
    }
    if !body.is_empty() {
        fields.push(("Content-Type".into(), "application/octet-stream".into()));
    }
    if (request && op != Operation::Open) || (!request && op == Operation::Open) {
        fields.push(("Syntra-Route".into(), ROUTE.into()));
    }
    if op == Operation::Send {
        fields.push(("Syntra-Upload".into(), "0".into()));
    }
    if op == Operation::Poll {
        fields.push(("Syntra-Poll".into(), "0".into()));
    }
    Vector {
        id,
        op,
        request,
        start,
        fields,
        body,
        accept: true,
    }
}

fn accepted(v: &Vector) -> bool {
    if v.request {
        codec::decode_request(
            &v.wire(),
            &authority(),
            &OriginPolicy::default(),
            &envelope(),
        )
        .is_ok()
    } else {
        codec::decode_response(&v.wire(), v.op).is_ok()
    }
}

#[test]
fn r13_handwritten_structural_transcriptions() {
    // IDs and mutations transcribed from rfcs/0013-http-tls/http-vectors.json.
    // Synthetic zero bodies establish HTTP shape only, never valid Noise.
    let send = vector("R13-H01", Operation::Send, true, vec![0; 17]);
    let ack = vector("R13-H02", Operation::Send, false, vec![]);
    let empty = vector("R13-H03", Operation::Poll, false, vec![]);
    let data = vector("R13-H04", Operation::Poll, false, vec![0; 17]);
    let mut cases = vec![send.clone(), ack.clone(), empty.clone(), data];
    let mut v = ack;
    v.id = "R13-H05";
    v.accept = false;
    v.fields.push(("Content-Length".into(), "0".into()));
    cases.push(v);
    for (id, name, value, append) in [
        ("R13-H06", "Content-Length", "17", true),
        ("R13-H07", "Transfer-Encoding", "chunked", true),
        ("R13-H08", "Content-Length", "16", false),
        ("R13-H09", "Syntra-Upload", "00", false),
        (
            "R13-H10",
            "Syntra-Route",
            "A000000000000000000000000000000000000000000000000000000000000000",
            false,
        ),
        ("R13-H11", "Host", "other.invalid:80", false),
        ("R13-H12", "Authorization", "fixture-not-a-credential", true),
        ("R13-H13", "Syntra-Unknown", "1", true),
        ("R13-H14", "Origin", "null", true),
    ] {
        let mut v = send.clone();
        v.id = id;
        v.accept = false;
        if append {
            v.fields.push((name.into(), value.into()));
        } else {
            v.replace(name, value);
        }
        cases.push(v);
    }
    // R13-H15/-16 are proxy CONNECT vectors, *not origin exchanges*. Positive
    // tunnel parsing and preservation of 160303 belong to the proxy boundary;
    // do not pretend this origin codec executes that positive scenario.
    let connect=b"HTTP/1.1 200 Connection Established\r\nContent-Length: 123\r\nTransfer-Encoding: chunked\r\n\r\n\x16\x03\x03";
    assert!(
        codec::decode_response(connect, Operation::Open).is_err(),
        "R13-H15: not an origin response"
    );
    assert!(
        codec::decode_response(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
            Operation::Open
        )
        .is_err(),
        "R13-H16"
    );
    cases.extend([
        vector("R13-H17", Operation::Open, true, m1()),
        vector("R13-H18", Operation::Open, false, vec![0; 48]),
        vector("R13-H19", Operation::Poll, true, vec![]),
        vector("R13-H20", Operation::Close, true, vec![]),
        vector("R13-H21", Operation::Close, false, vec![]),
    ]);
    let mut v = empty;
    v.id = "R13-H22";
    v.accept = false;
    v.fields
        .push(("Transfer-Encoding".into(), "chunked".into()));
    cases.push(v);
    let mut v = send.clone();
    v.id = "R13-H23";
    v.body.resize(65535, 0);
    v.replace("Content-Length", "65535");
    cases.push(v);
    let mut v = send;
    v.id = "R13-H24";
    v.accept = false;
    v.body.resize(65536, 0);
    v.replace("Content-Length", "65536");
    cases.push(v);
    assert_eq!(cases.len(), 22);
    for v in cases {
        assert_eq!(accepted(&v), v.accept, "{}", v.id);
    }
}

#[test]
fn four_public_context_prefixes_match_only_opt_in_candidate_bindings() {
    for context in CONTEXTS {
        let context = hex(context);
        let envelope = OpenEnvelope::new(context.clone()).unwrap();
        let mut raw = context;
        raw.extend([0; 48]);
        envelope.check_m1(&raw).unwrap();
        let h = codec::request(Operation::Open, &authority(), None, None, &raw, &envelope).unwrap();
        let mut wire = h;
        wire.extend_from_slice(&raw);
        assert!(
            codec::decode_request(&wire, &authority(), &OriginPolicy::default(), &envelope).is_ok()
        );
        let (parsed, noise) = syntra_core::secure_channel::Context::parse_first(&raw).unwrap();
        assert_eq!(noise.len(), 48);
        assert_eq!(parsed.encode().unwrap(), raw[..raw.len() - 48]);
        raw.push(0);
        assert!(envelope.check_m1(&raw).is_err());
        raw.pop();
        raw.pop();
        assert!(envelope.check_m1(&raw).is_err());
    }
}

#[test]
fn strict_headers_lengths_routes_and_operation_tables() {
    let base = vector("local", Operation::Send, true, vec![0; 17]);
    for value in [
        "",
        "00",
        "+17",
        "-1",
        "017",
        "17,17",
        "1 7",
        "18446744073709551616",
    ] {
        let mut v = base.clone();
        v.replace("Content-Length", value);
        assert!(!accepted(&v), "{value}");
        let mut v = base.clone();
        v.replace("Syntra-Upload", value);
        assert!(!accepted(&v), "{value}");
    }
    assert_eq!(codec::decimal("18446744073709551615").unwrap(), u64::MAX);
    for name in [
        "Transfer-Encoding",
        "Content-Encoding",
        "Trailer",
        "Expect",
        "Upgrade",
        "TE",
        "Cookie",
        "Proxy-Authorization",
        "Set-Cookie",
    ] {
        let mut v = base.clone();
        v.fields.push((name.into(), "x".into()));
        assert!(!accepted(&v), "{name}");
    }
    for value in [
        "close",
        "keep-alive, close",
        "upgrade",
        "Content-Length",
        "",
    ] {
        let mut v = base.clone();
        v.fields.push(("Connection".into(), value.into()));
        assert!(!accepted(&v));
    }
    for start in [
        "GET /syntra/1.0/http/send HTTP/1.1",
        "POST /syntra/1.0/http/send?x HTTP/1.1",
        "POST /syntra/1.0/http/Send HTTP/1.1",
        "POST http://example.invalid:80/syntra/1.0/http/send HTTP/1.1",
        "POST /syntra/1.0/http/send HTTP/1.0",
    ] {
        let mut v = base.clone();
        v.start = start.into();
        assert!(!accepted(&v));
    }
    for op in [
        Operation::Open,
        Operation::Send,
        Operation::Poll,
        Operation::Close,
    ] {
        let body = if op == Operation::Open {
            m1()
        } else if op == Operation::Send {
            vec![0; 17]
        } else {
            vec![]
        };
        let v = vector("local", op, true, body);
        assert!(accepted(&v));
        for name in ["Syntra-Route", "Syntra-Upload", "Syntra-Poll"] {
            let mut bad = v.clone();
            if let Some(i) = bad.fields.iter().position(|(n, _)| n == name) {
                bad.fields.remove(i);
            } else {
                bad.fields.push((
                    name.into(),
                    if name == "Syntra-Route" {
                        ROUTE.into()
                    } else {
                        "0".into()
                    },
                ));
            }
            assert!(!accepted(&bad), "{op:?} {name}");
        }
    }
    let mut lower = base.clone();
    for (n, _) in &mut lower.fields {
        *n = n.to_ascii_lowercase();
    }
    assert!(accepted(&lower));
    let mut mixed = base.clone();
    mixed.replace("Content-Type", "Application/octet-stream");
    assert!(!accepted(&mixed));
    for route in ["", "0", &"0".repeat(65), &"A".repeat(64), &"g".repeat(64)] {
        assert!(Route::parse(route).is_err());
    }
    assert!(!format!("{:?}", route()).contains(ROUTE));
    for value in [
        "example.invalid",
        "example.invalid:080",
        "EXAMPLE.invalid:80",
        "example.invalid.:80",
        "user@example.invalid:80",
        "example.invalid:0",
        "example.invalid:65536",
        "::1:80",
    ] {
        assert!(Authority::new(value).is_err(), "{value}");
    }
    for value in ["example.invalid:80", "127.0.0.1:80", "[::1]:443"] {
        Authority::new(value).unwrap();
    }
}

#[test]
fn origins_errors_injection_and_truncation_are_terminal_codec_errors() {
    let v = vector("local", Operation::Send, true, vec![0; 17]);
    let mut allowed = v.clone();
    allowed
        .fields
        .push(("Origin".into(), "https://example.invalid".into()));
    assert!(!accepted(&allowed));
    let policy = OriginPolicy::allow_exact(vec!["https://example.invalid".into()]).unwrap();
    for invalid in [
        "null",
        "invalid",
        "https://example.invalid,https://other.invalid",
        "https://example.invalid/",
        "https://example.invalid:443",
        "https://user@example.invalid",
    ] {
        assert!(OriginPolicy::allow_exact(vec![invalid.into()]).is_err());
    }
    assert!(codec::decode_request(&allowed.wire(), &authority(), &policy, &envelope()).is_ok());
    allowed
        .fields
        .push(("origin".into(), "https://example.invalid".into()));
    assert!(codec::decode_request(&allowed.wire(), &authority(), &policy, &envelope()).is_err());
    for status in [
        100, 101, 202, 301, 302, 307, 308, 400, 401, 403, 404, 405, 407, 410, 413, 429, 431, 500,
        503, 505,
    ] {
        let text=format!("HTTP/1.1 {status} Reason\r\nContent-Length: 0\r\nCache-Control: no-store\r\nLocation: https://other.invalid/\r\n\r\n");
        assert!(
            codec::decode_response(text.as_bytes(), Operation::Open).is_err(),
            "{status}"
        );
    }
    for (name, value) in [
        (" Content-Length", "17"),
        ("Content-Length ", "17"),
        ("X", "ok\r\ninjected"),
        ("X", "a\nb"),
        ("X", "a\0b"),
    ] {
        let mut bad = v.clone();
        bad.fields.push((name.into(), value.into()));
        assert!(!accepted(&bad));
    }
    let full = v.wire();
    for end in 0..full.len() {
        assert!(
            codec::decode_request(
                &full[..end],
                &authority(),
                &OriginPolicy::default(),
                &envelope()
            )
            .is_err(),
            "truncated at {end}"
        );
    }
    let mut trailing = full.clone();
    trailing.push(0);
    assert!(codec::decode_request(
        &trailing,
        &authority(),
        &OriginPolicy::default(),
        &envelope()
    )
    .is_err());
    for body in [vec![0; 16], vec![0; 65536]] {
        let mut bad = v.clone();
        bad.body = body;
        let len = bad.body.len().to_string();
        bad.replace("Content-Length", &len);
        assert!(!accepted(&bad));
    }
    let mut m1 = m1();
    m1[0] ^= 1;
    assert!(envelope().check_m1(&m1).is_err());
}

#[test]
fn header_bounds_at_maximum_and_maximum_plus_one() {
    let base = vector("local", Operation::Send, true, vec![0; 17]);
    let mut v = base.clone();
    while v.fields.len() < 64 {
        v.fields.push((format!("X-{}", v.fields.len()), "a".into()));
    }
    assert!(accepted(&v));
    v.fields.push(("X-65".into(), "a".into()));
    assert!(!accepted(&v));
    let mut v = base.clone();
    v.fields.push(("X".into(), "a".repeat(4096 - 5)));
    assert!(accepted(&v));
    v.fields.last_mut().unwrap().1.push('a');
    assert!(!accepted(&v));
    let mut response = vector("local", Operation::Poll, false, vec![]);
    response.start = format!("HTTP/1.1 204 {}", "a".repeat(2048 - 15));
    assert!(accepted(&response));
    response.start.push('a');
    assert!(!accepted(&response));
    let mut v = base;
    // Fill the whole header block exactly, keeping every field line bounded.
    loop {
        let end = v.wire().windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        if end == codec::MAX_HEADERS {
            break;
        }
        let remaining = codec::MAX_HEADERS - end;
        let name = format!("X-{}", v.fields.len());
        let overhead = name.len() + 4;
        let line = remaining.min(4096);
        v.fields.push((name, "a".repeat(line - overhead)));
    }
    assert!(accepted(&v));
    v.fields.last_mut().unwrap().1.push('a');
    assert!(!accepted(&v));
}

struct Fragmented<S> {
    inner: S,
    chunk: usize,
    written: Arc<AtomicUsize>,
}
impl<S: AsyncRead + Unpin> AsyncRead for Fragmented<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let max = buf.remaining().min(this.chunk);
        let mut small = ReadBuf::new(buf.initialize_unfilled_to(max));
        match Pin::new(&mut this.inner).poll_read(cx, &mut small) {
            Poll::Ready(Ok(())) => {
                let n = small.filled().len();
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Fragmented<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let end = bytes.len().min(this.chunk);
        match Pin::new(&mut this.inner).poll_write(cx, &bytes[..end]) {
            Poll::Ready(Ok(n)) => {
                this.written.fetch_add(n, Ordering::SeqCst);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
fn fragmented<S>(inner: S, chunk: usize) -> Fragmented<S> {
    Fragmented {
        inner,
        chunk,
        written: Arc::new(AtomicUsize::new(0)),
    }
}

async fn socket_pair(listener: &TcpListener) -> (TcpStream, TcpStream) {
    let (a, b) = tokio::join!(
        TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let a = a.unwrap();
    let b = b.unwrap().0;
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    (a, b)
}

// Fixture peer helpers; intentionally not an HTTP client/server implementation.
async fn receive<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() <= 16384);
    }
    let text = std::str::from_utf8(&bytes).unwrap();
    let len = text
        .split("\r\n")
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(len <= 65535);
    let mut body = vec![0; len];
    stream.read_exact(&mut body).await.unwrap();
    bytes.extend(body);
    bytes
}
async fn reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    op: Operation,
    counter: Option<u64>,
    body: &[u8],
) {
    let r = route();
    let h = codec::response(
        op,
        if op == Operation::Open {
            Some(&r)
        } else {
            None
        },
        counter,
        body,
    )
    .unwrap();
    stream.write_all(&h).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::test]
async fn complete_raw_record_pair_over_real_local_sockets_and_fragmented_io() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = Authority::new(&listener.local_addr().unwrap().to_string()).unwrap();
        let (cu, su) = socket_pair(&listener).await;
        let (cd, sd) = socket_pair(&listener).await;
        assert_eq!(cu.peer_addr().unwrap(), cd.peer_addr().unwrap());
        assert_eq!(su.local_addr().unwrap(), sd.local_addr().unwrap());
        let (mut cr, mut cw, cc) = http::client_pair(
            fragmented(cu, 7),
            fragmented(cd, 1),
            authority.clone(),
            envelope(),
            budget(),
        );
        let (mut sr, mut sw, driver, sc) = http::server_pair(
            fragmented(su, 1),
            fragmented(sd, 13),
            authority,
            envelope(),
            OriginPolicy::default(),
            route(),
            budget(),
        );
        let (done, wait) = oneshot::channel();
        let (result, _, _) = tokio::join!(
            driver.run(),
            async {
                assert_eq!(sr.read_record(337).await.unwrap(), m1());
                sw.write_record(&[11; 48]).await.unwrap();
                sc.finish_setup().unwrap();
                for n in 0..3 {
                    let record = sr.read_record(65535).await.unwrap();
                    assert_eq!(record, vec![n; 65535]);
                    sw.write_record(&record).await.unwrap();
                }
                wait.await.unwrap();
                (sr, sw)
            },
            async {
                cw.write_record(&m1()).await.unwrap();
                assert_eq!(cr.read_record(48).await.unwrap(), vec![11; 48]);
                cc.finish_setup().unwrap();
                for n in 0..3 {
                    let bytes = vec![n; 65535];
                    let ptr = bytes.as_ptr();
                    let (sent, got) = tokio::join!(cw.write_record(&bytes), cr.read_record(65535));
                    sent.unwrap();
                    assert_eq!(got.unwrap(), bytes);
                    assert_eq!(ptr, bytes.as_ptr());
                }
                cw.shutdown().await.unwrap();
                assert!(cc.is_retired());
                done.send(()).unwrap();
                (cr, cw)
            }
        );
        result.unwrap();
        assert!(sc.is_retired());
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelled_open_poisoned_pair_emits_no_retry() {
    let (u, mut peer) = tokio::io::duplex(16);
    let (d, _) = tokio::io::duplex(16);
    let (mut r, mut w, control) = http::client_pair(u, d, authority(), envelope(), budget());
    assert!(
        tokio::time::timeout(Duration::from_millis(1), w.write_record(&m1()))
            .await
            .is_err()
    );
    assert!(control.is_retired());
    let mut emitted = [0; 16];
    assert_eq!(peer.read(&mut emitted).await.unwrap(), 16);
    assert!(w.write_record(&m1()).await.is_err());
    assert!(r.read_record(48).await.is_err());
    drop(w);
    assert_eq!(peer.read(&mut emitted).await.unwrap(), 0);
}

#[tokio::test(start_paused = true)]
async fn expired_budget_and_unknown_elapsed_continuity_emit_nothing() {
    for invalidate in [false, true] {
        let clock = ElapsedClock::lifecycle_driven();
        let budget = EstablishmentBudget::new(clock.clone(), Duration::from_millis(1)).unwrap();
        if invalidate {
            clock.invalidate();
        } else {
            tokio::time::advance(Duration::from_millis(2)).await;
        }
        let (u, _) = tokio::io::duplex(1024);
        let u = fragmented(u, 10);
        let count = u.written.clone();
        let (d, _) = tokio::io::duplex(16);
        let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget);
        assert!(matches!(w.write_record(&m1()).await, Err(Error::Timeout)));
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert!(c.is_retired());
        assert!(r.read_record(48).await.is_err());
    }
}

#[tokio::test]
async fn dropping_either_half_or_driver_invalidates_the_pair() {
    let (u, _) = tokio::io::duplex(16);
    let (d, _) = tokio::io::duplex(16);
    let (r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
    drop(r);
    assert!(c.is_retired());
    assert!(w.write_record(&m1()).await.is_err());
    let (u, _) = tokio::io::duplex(16);
    let (d, _) = tokio::io::duplex(16);
    let (mut r, mut w, driver, c) = http::server_pair(
        u,
        d,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    drop(driver);
    assert!(c.is_retired());
    assert!(r.read_record(337).await.is_err());
    assert!(w.write_record(&[0; 48]).await.is_err());
}

#[tokio::test]
async fn every_truncated_open_response_is_fatal_and_never_retried() {
    let v = vector("R13-H18", Operation::Open, false, vec![0; 48]);
    let response = v.wire();
    for cut in 0..response.len() {
        let (u, mut peer) = tokio::io::duplex(4096);
        let (d, _) = tokio::io::duplex(16);
        let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
        let first = m1();
        let (sent, _) = tokio::join!(w.write_record(&first), async {
            let request = receive(&mut peer).await;
            assert_eq!(
                codec::decode_request(
                    &request,
                    &authority(),
                    &OriginPolicy::default(),
                    &envelope()
                )
                .unwrap()
                .1,
                m1()
            );
            peer.write_all(&response[..cut]).await.unwrap();
            peer.shutdown().await.unwrap();
        });
        assert!(sent.is_err(), "cut {cut}");
        assert!(c.is_retired());
        assert!(w.write_record(&m1()).await.is_err());
        assert!(r.read_record(48).await.is_err());
    }
}

#[tokio::test]
async fn upload_ack_loss_wrong_echo_and_204_body_retire_both_directions() {
    for kind in ["lost", "counter", "body"] {
        let (u, mut peer) = tokio::io::duplex(4096);
        let (d, _) = tokio::io::duplex(16);
        let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
        let (client, _) = tokio::join!(
            async {
                w.write_record(&m1()).await.unwrap();
                r.read_record(48).await.unwrap();
                c.finish_setup().unwrap();
                let failed = w.write_record(&[7; 17]).await;
                assert!(failed.is_err(), "{kind}");
                assert!(c.is_retired());
                assert!(r.read_record(65535).await.is_err());
                assert!(w.write_record(&[7; 17]).await.is_err());
                (r, w)
            },
            async {
                receive(&mut peer).await;
                reply(&mut peer, Operation::Open, None, &[0; 48]).await;
                let request = receive(&mut peer).await;
                let (head, body) = codec::decode_request(
                    &request,
                    &authority(),
                    &OriginPolicy::default(),
                    &envelope(),
                )
                .unwrap();
                assert_eq!(head.counter, Some(0));
                assert_eq!(body, &[7; 17]);
                if kind == "lost" {
                    peer.shutdown().await.unwrap();
                } else {
                    reply(
                        &mut peer,
                        Operation::Send,
                        Some(if kind == "counter" { 1 } else { 0 }),
                        &[],
                    )
                    .await;
                    if kind == "body" {
                        peer.write_all(b"illegal-body").await.unwrap();
                    }
                }
                peer
            }
        );
        drop(client);
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_poll_wakes_pending_upload_and_is_not_redelivered() {
    let (u, mut pu) = tokio::io::duplex(4096);
    let (d, mut pd) = tokio::io::duplex(4096);
    let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
    let (_, _, _) = tokio::join!(
        async {
            w.write_record(&m1()).await.unwrap();
            r.read_record(48).await.unwrap();
            c.finish_setup().unwrap();
            let poll = r.read_record(65535);
            let upload = w.write_record(&[7; 17]);
            let (cancelled, upload) =
                tokio::join!(tokio::time::timeout(Duration::from_millis(1), poll), upload);
            assert!(cancelled.is_err());
            assert!(upload.is_err());
            assert!(c.is_retired());
            (r, w)
        },
        async {
            receive(&mut pu).await;
            reply(&mut pu, Operation::Open, None, &[0; 48]).await;
            receive(&mut pu).await;
            pu
        },
        async {
            let request = receive(&mut pd).await;
            let (head, _) = codec::decode_request(
                &request,
                &authority(),
                &OriginPolicy::default(),
                &envelope(),
            )
            .unwrap();
            assert_eq!(head.counter, Some(0));
            pd
        }
    );
}

#[tokio::test(start_paused = true)]
async fn empty_poll_does_not_renew_absolute_record_wait() {
    let (u, mut pu) = tokio::io::duplex(4096);
    let (d, mut pd) = tokio::io::duplex(4096);
    let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
    let (_, _, _) = tokio::join!(
        async {
            w.write_record(&m1()).await.unwrap();
            r.read_record(48).await.unwrap();
            c.finish_setup().unwrap();
            let start = tokio::time::Instant::now();
            assert!(matches!(r.read_record(65535).await, Err(Error::Timeout)));
            assert_eq!(start.elapsed(), Duration::from_secs(60));
            assert!(c.is_retired());
            (r, w)
        },
        async {
            receive(&mut pu).await;
            reply(&mut pu, Operation::Open, None, &[0; 48]).await;
            pu
        },
        async {
            for p in 0..3 {
                let request = receive(&mut pd).await;
                assert_eq!(
                    codec::decode_request(
                        &request,
                        &authority(),
                        &OriginPolicy::default(),
                        &envelope()
                    )
                    .unwrap()
                    .0
                    .counter,
                    Some(p)
                );
                if p < 2 {
                    tokio::time::sleep(Duration::from_secs(25)).await;
                    reply(&mut pd, Operation::Poll, Some(p), &[]).await;
                }
            }
            pd
        }
    );
}

#[tokio::test(start_paused = true)]
async fn server_empty_hold_then_next_poll_delivers_one_record() {
    let (cu, su) = tokio::io::duplex(4096);
    let (cd, sd) = tokio::io::duplex(4096);
    let (mut cr, mut cw, cc) = http::client_pair(cu, cd, authority(), envelope(), budget());
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (done, wait) = oneshot::channel();
    let (result, _, _) = tokio::join!(
        driver.run(),
        async {
            sr.read_record(337).await.unwrap();
            sw.write_record(&[0; 48]).await.unwrap();
            sc.finish_setup().unwrap();
            tokio::time::sleep(Duration::from_secs(26)).await;
            sw.write_record(&[9; 17]).await.unwrap();
            wait.await.unwrap();
            (sr, sw)
        },
        async {
            cw.write_record(&m1()).await.unwrap();
            cr.read_record(48).await.unwrap();
            cc.finish_setup().unwrap();
            assert_eq!(cr.read_record(65535).await.unwrap(), vec![9; 17]);
            cw.shutdown().await.unwrap();
            done.send(()).unwrap();
            (cr, cw)
        }
    );
    result.unwrap();
}

#[tokio::test(start_paused = true)]
async fn poll_gap_is_fatal_and_cannot_be_resumed() {
    let (cu, su) = tokio::io::duplex(4096);
    let (cd, sd) = tokio::io::duplex(4096);
    let (mut cr, mut cw, cc) = http::client_pair(cu, cd, authority(), envelope(), budget());
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (result, _, _) = tokio::join!(
        driver.run(),
        async {
            sr.read_record(337).await.unwrap();
            sw.write_record(&[0; 48]).await.unwrap();
            sc.finish_setup().unwrap();
            tokio::time::sleep(Duration::from_secs(6)).await;
            (sr, sw)
        },
        async {
            cw.write_record(&m1()).await.unwrap();
            cr.read_record(48).await.unwrap();
            cc.finish_setup().unwrap();
            tokio::time::sleep(Duration::from_secs(6)).await;
            assert!(cr.read_record(65535).await.is_err());
            assert!(cc.is_retired());
            assert!(cw.write_record(&[7; 17]).await.is_err());
            (cr, cw)
        }
    );
    assert!(matches!(result, Err(Error::Timeout)));
    assert!(sc.is_retired());
}

#[tokio::test(start_paused = true)]
async fn fragmented_header_timer_is_not_renewed_by_trickle() {
    let (u, mut pu) = tokio::io::duplex(4096);
    let (d, mut pd) = tokio::io::duplex(4096);
    let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
    let (_, _, _) = tokio::join!(
        async {
            w.write_record(&m1()).await.unwrap();
            r.read_record(48).await.unwrap();
            c.finish_setup().unwrap();
            let start = tokio::time::Instant::now();
            assert!(matches!(r.read_record(65535).await, Err(Error::Timeout)));
            assert!(start.elapsed() <= Duration::from_secs(6));
            assert!(c.is_retired());
            (r, w)
        },
        async {
            receive(&mut pu).await;
            reply(&mut pu, Operation::Open, None, &[0; 48]).await;
            pu
        },
        async {
            receive(&mut pd).await;
            for b in b"HTTP/1.1" {
                pd.write_all(&[*b]).await.unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            pd
        }
    );
}

#[tokio::test]
async fn server_wrong_stream_route_counter_and_pipelining_are_fatal() {
    for kind in [
        "wrong-route",
        "wrong-counter",
        "overflow",
        "wrong-stream",
        "pipeline",
    ] {
        let (mut cu, su) = tokio::io::duplex(4096);
        let (mut cd, sd) = tokio::io::duplex(4096);
        let (mut sr, mut sw, driver, control) = http::server_pair(
            su,
            sd,
            authority(),
            envelope(),
            OriginPolicy::default(),
            route(),
            budget(),
        );
        let (result, _, _) = tokio::join!(
            driver.run(),
            async {
                sr.read_record(337).await.unwrap();
                sw.write_record(&[0; 48]).await.unwrap();
                (sr, sw)
            },
            async {
                let header = codec::request(
                    Operation::Open,
                    &authority(),
                    None,
                    None,
                    &m1(),
                    &envelope(),
                )
                .unwrap();
                cu.write_all(&header).await.unwrap();
                cu.write_all(&m1()).await.unwrap();
                let mut opened =
                    vec![
                        0;
                        codec::response(Operation::Open, Some(&route()), None, &[0; 48])
                            .unwrap()
                            .len()
                            + 48
                    ];
                cu.read_exact(&mut opened).await.unwrap();
                let mut v = vector("local", Operation::Poll, true, vec![]);
                if kind == "wrong-route" {
                    v.replace("Syntra-Route", &"1".repeat(64));
                }
                if kind == "wrong-counter" {
                    v.replace("Syntra-Poll", "1");
                }
                if kind == "overflow" {
                    v.replace("Syntra-Poll", "18446744073709551615");
                }
                if kind == "wrong-stream" {
                    cu.write_all(&v.wire()).await.unwrap();
                } else {
                    cd.write_all(&v.wire()).await.unwrap();
                    if kind == "pipeline" {
                        cd.write_all(&v.wire()).await.unwrap();
                    }
                }
                (cu, cd)
            }
        );
        assert!(result.is_err(), "{kind}");
        assert!(control.is_retired());
    }
}

#[tokio::test]
async fn upload_admission_ack_does_not_wait_for_runtime_but_full_slot_is_fatal() {
    let (cu, su) = tokio::io::duplex(4096);
    let (cd, sd) = tokio::io::duplex(4096);
    let (mut cr, mut cw, cc) = http::client_pair(cu, cd, authority(), envelope(), budget());
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (result, _, _) = tokio::join!(
        driver.run(),
        async {
            sr.read_record(337).await.unwrap();
            sw.write_record(&[0; 48]).await.unwrap();
            sc.finish_setup().unwrap();
            // Return/retain reader without consuming uploads: the first gets a 204,
            // the second must not wait indefinitely for higher-runtime consumption.
            (sr, sw)
        },
        async {
            cw.write_record(&m1()).await.unwrap();
            cr.read_record(48).await.unwrap();
            cc.finish_setup().unwrap();
            cw.write_record(&[7; 17]).await.unwrap();
            assert!(cw.write_record(&[8; 17]).await.is_err());
            assert!(cc.is_retired());
            (cr, cw)
        }
    );
    assert!(result.is_err());
    assert!(sc.is_retired());
}

#[tokio::test]
async fn declared_response_bound_and_reader_maximum_fail_before_body_read() {
    for declared in [17, 65536] {
        let (u, mut pu) = tokio::io::duplex(4096);
        let (d, mut pd) = tokio::io::duplex(4096);
        let (mut r, mut w, c) = http::client_pair(u, d, authority(), envelope(), budget());
        let (_, _, _) = tokio::join!(
            async {
                w.write_record(&m1()).await.unwrap();
                r.read_record(48).await.unwrap();
                c.finish_setup().unwrap();
                assert!(matches!(r.read_record(16).await, Err(Error::Framing)));
                assert!(c.is_retired());
                (r, w)
            },
            async {
                receive(&mut pu).await;
                reply(&mut pu, Operation::Open, None, &[0; 48]).await;
                pu
            },
            async {
                receive(&mut pd).await;
                let header=format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nSyntra-Poll: 0\r\n\r\n");
                pd.write_all(header.as_bytes()).await.unwrap();
                // No body or EOF: an attempted body read would stall this test.
                pd
            }
        );
    }
}

#[tokio::test(start_paused = true)]
async fn cancelled_server_output_retires_undriven_owner_without_emission() {
    let (u, mut pu) = tokio::io::duplex(4096);
    let (d, _) = tokio::io::duplex(4096);
    let (mut r, mut w, driver, c) = http::server_pair(
        u,
        d,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(1), w.write_record(&[0; 48]))
            .await
            .is_err()
    );
    assert!(c.is_retired());
    assert!(r.read_record(337).await.is_err());
    assert!(driver.run().await.is_err());
    assert_eq!(pu.read(&mut [0; 1]).await.unwrap(), 0);
}

#[derive(Clone, Copy)]
enum GateAt {
    Flush(usize),
    Bytes(usize),
}

// All bytes accepted by this wrapper reach the duplex peer immediately. Only
// the selected flush (or byte boundary) waits for an explicit waker-backed gate.
struct GatedIo<S> {
    inner: S,
    at: GateAt,
    written: usize,
    flushed: usize,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

impl<S> GatedIo<S> {
    fn poll_gate(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let Some(release) = self.release.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        ready!(Pin::new(release).poll(cx)).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "test gate cancelled")
        })?;
        self.release = None;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for GatedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for GatedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut end = bytes.len();
        if let GateAt::Bytes(limit) = this.at {
            if this.release.is_some() {
                if this.written >= limit {
                    ready!(this.poll_gate(cx))?;
                } else {
                    end = end.min(limit - this.written);
                }
            }
        }
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &bytes[..end]))?;
        this.written += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if matches!(this.at, GateAt::Flush(n) if n == this.flushed) {
            ready!(this.poll_gate(cx))?;
        }
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        this.flushed += 1;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn gated_io<S>(inner: S, at: GateAt) -> (GatedIo<S>, oneshot::Sender<()>, oneshot::Receiver<()>) {
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    (
        GatedIo {
            inner,
            at,
            written: 0,
            flushed: 0,
            entered: Some(entered),
            release: Some(wait),
        },
        release,
        observed,
    )
}

async fn send_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    op: Operation,
    counter: Option<u64>,
    bytes: &[u8],
) {
    let route = route();
    let header = codec::request(
        op,
        &authority(),
        if op == Operation::Open {
            None
        } else {
            Some(&route)
        },
        counter,
        bytes,
        &envelope(),
    )
    .unwrap();
    stream.write_all(&header).await.unwrap();
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
}

async fn receive_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    op: Operation,
) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await?);
        assert!(bytes.len() <= codec::MAX_HEADERS);
    }
    let head = codec::parse_response(&bytes, op).unwrap();
    let mut body = vec![0; head.body_len];
    stream.read_exact(&mut body).await?;
    bytes.extend(body);
    Ok(bytes)
}

#[tokio::test(start_paused = true)]
async fn backpressured_close_response_finishes_after_pair_retirement() {
    let (cu, su) = tokio::io::duplex(16);
    let (cd, sd) = tokio::io::duplex(4096);
    let (mut cr, mut cw, cc) = http::client_pair(cu, cd, authority(), envelope(), budget());
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (server, _host, (client, _cr, _cw)) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                driver.run(),
                async {
                    assert_eq!(sr.read_record(337).await.unwrap(), m1());
                    sw.write_record(&[0; 48]).await.unwrap();
                    sc.finish_setup().unwrap();
                    (sr, sw)
                },
                async {
                    cw.write_record(&m1()).await.unwrap();
                    cr.read_record(48).await.unwrap();
                    cc.finish_setup().unwrap();
                    (cw.shutdown().await, cr, cw)
                }
            )
        })
        .await
        .unwrap();
    assert!(
        client.is_ok(),
        "complete close response required: {client:?}; server: {server:?}"
    );
    assert!(server.is_ok(), "clean close must finish: {server:?}");
    assert!(sc.is_retired());
    assert!(cc.is_retired());
}

#[tokio::test(start_paused = true)]
async fn complete_response_allows_next_request_while_flush_pending() {
    let (mut cu, su) = tokio::io::duplex(4096);
    let (cd, sd) = tokio::io::duplex(4096);
    let (su, release, entered) = gated_io(su, GateAt::Flush(1));
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (admitted, first) = oneshot::channel();
    let (server, host, peer) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            driver.run(),
            async {
                sr.read_record(337).await?;
                sw.write_record(&[0; 48]).await?;
                sc.finish_setup().unwrap();
                assert_eq!(sr.read_record(65535).await?, vec![7; 17]);
                admitted.send(()).unwrap();
                assert_eq!(sr.read_record(65535).await?, vec![8; 17]);
                Ok::<_, Error>((sr, sw))
            },
            async {
                send_request(&mut cu, Operation::Open, None, &m1()).await;
                receive_response(&mut cu, Operation::Open).await?;
                send_request(&mut cu, Operation::Send, Some(0), &[7; 17]).await;
                let ack = receive_response(&mut cu, Operation::Send).await?;
                assert_eq!(
                    codec::decode_response(&ack, Operation::Send)
                        .unwrap()
                        .0
                        .counter,
                    Some(0)
                );
                entered.await.unwrap();
                first.await.unwrap();
                send_request(&mut cu, Operation::Send, Some(1), &[8; 17]).await;
                release.send(()).unwrap();
                let ack = receive_response(&mut cu, Operation::Send).await?;
                assert_eq!(
                    codec::decode_response(&ack, Operation::Send)
                        .unwrap()
                        .0
                        .counter,
                    Some(1)
                );
                send_request(&mut cu, Operation::Close, None, &[]).await;
                receive_response(&mut cu, Operation::Close).await?;
                Ok::<_, std::io::Error>((cu, cd))
            }
        )
    })
    .await
    .unwrap();
    assert!(
        server.is_ok(),
        "legal sequential request rejected: {server:?}"
    );
    assert!(host.is_ok());
    assert!(peer.is_ok());
    assert!(sc.is_retired());
}

#[tokio::test(start_paused = true)]
async fn next_request_before_final_response_byte_is_still_rejected() {
    let (mut cu, su) = tokio::io::duplex(4096);
    let (cd, sd) = tokio::io::duplex(4096);
    let open_len = codec::response(Operation::Open, Some(&route()), None, &[0; 48])
        .unwrap()
        .len()
        + 48;
    let ack = codec::response(Operation::Send, None, Some(0), &[]).unwrap();
    let (su, _release, entered) = gated_io(su, GateAt::Bytes(open_len + ack.len() - 1));
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (server, _host, _peer) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            driver.run(),
            async {
                sr.read_record(337).await.unwrap();
                sw.write_record(&[0; 48]).await.unwrap();
                sc.finish_setup().unwrap();
                assert_eq!(sr.read_record(65535).await.unwrap(), vec![7; 17]);
                (sr, sw)
            },
            async {
                send_request(&mut cu, Operation::Open, None, &m1()).await;
                receive_response(&mut cu, Operation::Open).await.unwrap();
                send_request(&mut cu, Operation::Send, Some(0), &[7; 17]).await;
                let mut prefix = vec![0; ack.len() - 1];
                cu.read_exact(&mut prefix).await.unwrap();
                assert_eq!(prefix, ack[..ack.len() - 1]);
                entered.await.unwrap();
                // The final LF has not been written: this really is pipelining,
                // unlike a request sent after complete bytes but before flush.
                send_request(&mut cu, Operation::Send, Some(1), &[8; 17]).await;
                (cu, cd)
            }
        )
    })
    .await
    .unwrap();
    assert!(matches!(server, Err(Error::Framing)), "{server:?}");
    assert!(sc.is_retired());
}

#[tokio::test(start_paused = true)]
async fn final_close_flush_keeps_its_original_absolute_deadline() {
    let (mut cu, su) = tokio::io::duplex(4096);
    let (cd, sd) = tokio::io::duplex(4096);
    let (su, _release, entered) = gated_io(su, GateAt::Flush(1));
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (server, _host, (started, _cu, _cd)) =
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(
                driver.run(),
                async {
                    sr.read_record(337).await.unwrap();
                    sw.write_record(&[0; 48]).await.unwrap();
                    sc.finish_setup().unwrap();
                    (sr, sw)
                },
                async {
                    send_request(&mut cu, Operation::Open, None, &m1()).await;
                    receive_response(&mut cu, Operation::Open).await.unwrap();
                    let started = tokio::time::Instant::now();
                    send_request(&mut cu, Operation::Close, None, &[]).await;
                    receive_response(&mut cu, Operation::Close).await.unwrap();
                    entered.await.unwrap();
                    assert!(sc.is_retired());
                    (started, cu, cd)
                }
            )
        })
        .await
        .unwrap();
    assert!(matches!(server, Err(Error::Timeout)), "{server:?}");
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert!(sc.is_retired());
}

#[tokio::test(start_paused = true)]
async fn cancelling_final_close_flush_drops_both_owned_streams() {
    let (mut cu, su) = tokio::io::duplex(4096);
    let (mut cd, sd) = tokio::io::duplex(4096);
    let (su, _release, entered) = gated_io(su, GateAt::Flush(1));
    let (mut sr, mut sw, driver, sc) = http::server_pair(
        su,
        sd,
        authority(),
        envelope(),
        OriginPolicy::default(),
        route(),
        budget(),
    );
    let (cancel, cancelled) = oneshot::channel();
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            async {
                let mut driver = Box::pin(driver.run());
                tokio::select! {
                    biased;
                    result = &mut driver => panic!("final flush must remain owned: {result:?}"),
                    _ = cancelled => {},
                }
                drop(driver);
            },
            async {
                sr.read_record(337).await.unwrap();
                sw.write_record(&[0; 48]).await.unwrap();
                sc.finish_setup().unwrap();
                (sr, sw)
            },
            async {
                send_request(&mut cu, Operation::Open, None, &m1()).await;
                receive_response(&mut cu, Operation::Open).await.unwrap();
                send_request(&mut cu, Operation::Close, None, &[]).await;
                receive_response(&mut cu, Operation::Close).await.unwrap();
                entered.await.unwrap();
                assert!(sc.is_retired());
                cancel.send(()).unwrap();
                assert_eq!(cu.read(&mut [0; 1]).await.unwrap(), 0);
                assert_eq!(cd.read(&mut [0; 1]).await.unwrap(), 0);
            }
        );
    })
    .await
    .unwrap();
    assert!(sc.is_retired());
}
