use super::*;
use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use syntra_runtime::elapsed::{ElapsedClock, ElapsedSource};

fn endpoint() -> SocketAddr {
    "127.0.0.1:1080".parse().unwrap()
}

fn budget() -> EstablishmentBudget {
    EstablishmentBudget::new(ElapsedClock::lifecycle_driven(), Duration::from_secs(1)).unwrap()
}

#[test]
fn targets_and_configuration_are_validated_without_normalizing() {
    for host in [
        "",
        "a..b",
        "-a",
        "a-",
        "a/b",
        "a:b",
        "a@b",
        "a?b",
        "a#b",
        "a\r\nb",
        "a_b",
        "é.test",
        ".",
        "127.0.0.1",
        "127.1",
        "123",
        "::1",
        "[::1]",
    ] {
        assert!(ProxyTarget::hostname(host, 80).is_err(), "{host:?}");
    }
    assert!(ProxyTarget::hostname("a".repeat(64), 80).is_err());
    assert!(ProxyTarget::hostname(format!("{}.test", "a.".repeat(126)), 80).is_err());
    assert!(ProxyTarget::hostname("host", 0).is_err());
    assert!(ProxyTarget::ip("::1".parse().unwrap(), 0).is_err());
    let host = ProxyTarget::hostname("Exact-Name.invalid.", 443).unwrap();
    assert_eq!(host.authority(), "Exact-Name.invalid.:443");
    assert_eq!(host.port(), 443);
    assert_eq!(
        ProxyTarget::ip("::1".parse().unwrap(), 443)
            .unwrap()
            .authority(),
        "[::1]:443"
    );
    for address in ["127.0.0.1:0", "0.0.0.0:80", "[::]:80", "224.0.0.1:80"] {
        assert!(ProxyConfig::socks5(address.parse().unwrap(), None).is_err());
    }
    for (user, pass) in [
        (vec![], vec![1]),
        (vec![1], vec![]),
        (vec![1; 256], vec![1]),
    ] {
        assert!(ProxyCredentials::new(user, pass).is_err());
    }
    for user in [b"a:b".as_slice(), b"a\rb", b"a\nb", b"a\0b", &[255]] {
        let credentials = ProxyCredentials::new(user.to_vec(), b"pass".to_vec()).unwrap();
        assert!(ProxyConfig::http_connect(endpoint(), Some(credentials)).is_err());
    }
    assert!(ProxyConfig::http_connect(
        endpoint(),
        Some(ProxyCredentials::new(b"user".to_vec(), b"p\r\n".to_vec()).unwrap())
    )
    .is_err());
    // SOCKS credentials are octets, not header text.
    assert!(ProxyConfig::socks5(
        endpoint(),
        Some(ProxyCredentials::new(vec![0, 255], vec![0, 255]).unwrap())
    )
    .is_ok());
}

#[test]
fn secrets_and_basic_encoding_are_not_debuggable() {
    let credentials = ProxyCredentials::new(b"Aladdin".to_vec(), b"open sesame".to_vec()).unwrap();
    assert_eq!(
        basic_value(&credentials).as_slice(),
        b"QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    let proxy = ProxyConfig::http_connect(endpoint(), Some(credentials)).unwrap();
    let debug = format!("{proxy:?}");
    for secret in ["Aladdin", "open sesame", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="] {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("REDACTED"));
    for (password, encoded) in [("a", "dTph"), ("ab", "dTphYg=="), ("abc", "dTphYmM=")] {
        let credentials =
            ProxyCredentials::new(b"u".to_vec(), password.as_bytes().to_vec()).unwrap();
        assert_eq!(basic_value(&credentials).as_slice(), encoded.as_bytes());
    }
}

#[test]
fn strict_connect_head_and_all_success_statuses() {
    for code in 200..=299 {
        // CL/TE MUST NOT cause body consumption or a non-200 rejection.
        let response = format!(
            "HTTP/1.1 {code} \r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        assert!(parse_connect_response(response.as_bytes()).is_ok());
    }
    assert!(parse_connect_response(b"HTTP/1.0 200 OK\r\n\r\n").is_ok());
    for code in [401, 403, 407] {
        assert!(matches!(
            parse_connect_response(format!("HTTP/1.1 {code} Denied\r\n\r\n").as_bytes()),
            Err(Error::Authentication)
        ));
    }
    for code in [100, 101, 199, 300, 301, 302, 307, 400, 500, 502, 503, 504] {
        assert!(matches!(
            parse_connect_response(format!("HTTP/1.1 {code} No\r\n\r\n").as_bytes()),
            Err(Error::Io(_))
        ));
    }
    for response in [
        b"HTTP/2.0 200 OK\r\n\r\n".as_slice(),
        b"HTTP/1.1 200\r\n\r\n",
        b"HTTP/1.1  200 OK\r\n\r\n",
        b"HTTP/1.1\t200 OK\r\n\r\n",
        b"HTTP/1.1 020 OK\r\n\r\n",
        b"HTTP/1.1 600 OK\r\n\r\n",
        b"HTTP/1.1 200 O\0K\r\n\r\n",
        b"HTTP/1.1 200 OK\n\r\n",
        b"HTTP/1.1 200 OK\r\nHTTP/1.1 201 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nStatus: 500\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nsTaTuS: 200\r\nStatus: 500\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n:status: 200\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX : value\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: val\rue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: val\x7fue\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 500 NO\r\n\r\n",
    ] {
        assert!(parse_connect_response(response).is_err(), "{response:?}");
    }
    let headers = format!("HTTP/1.1 200 OK\r\n{}\r\n", "X: y\r\n".repeat(65));
    assert!(parse_connect_response(headers.as_bytes()).is_err());
    let line = format!(
        "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
        "a".repeat(MAX_HTTP_LINE_BYTES)
    );
    assert!(parse_connect_response(line.as_bytes()).is_err());
}

#[test]
fn forward_metadata_has_absolute_form_and_cannot_include_proxy_credentials() {
    let target = ProxyTarget::hostname("origin.invalid", 80).unwrap();
    let forward = HttpForwardTarget::new(&target, "/p?q=a%20b").unwrap();
    assert_eq!(forward.absolute_uri(), "http://origin.invalid:80/p?q=a%20b");
    assert_eq!(forward.host_header(), "origin.invalid:80");
    for path in [
        "",
        "http://user:secret@origin/",
        "*",
        "/#fragment",
        "/\r\nX: y",
        "/a b",
        "/é",
        "/\\evil",
        "/%",
        "/%a",
        "/%GG",
        "/<raw>",
        "/{raw}",
        "/[raw]",
    ] {
        assert!(HttpForwardTarget::new(&target, path).is_err());
    }
    assert!(HttpForwardTarget::new(&target, &format!("/{}", "a".repeat(8192))).is_err());
}

#[tokio::test]
async fn http_stream_does_not_overread_even_when_head_and_tunnel_arrive_together() {
    let (left, mut right) = tokio::io::duplex(4096);
    let peer = tokio::spawn(async move {
        let expected = b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\nProxy-Authorization: Basic dTph\r\n\r\n";
        let mut request = vec![0; expected.len()];
        right.read_exact(&mut request).await.unwrap();
        assert_eq!(request, expected);
        right.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\ntunnel").await.unwrap();
    });
    let proxy = ProxyConfig::http_connect(
        endpoint(),
        Some(ProxyCredentials::new(b"u".to_vec(), b"a".to_vec()).unwrap()),
    )
    .unwrap();
    let target = ProxyTarget::ip("::1".parse().unwrap(), 443).unwrap();
    let mut stream = tunnel_stream_with_budget(left, &proxy, &target, &budget())
        .await
        .unwrap();
    let mut bytes = [0; 6];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"tunnel");
    peer.await.unwrap();
}

#[tokio::test]
async fn response_headers_are_bounded_and_truncation_is_terminal() {
    for response in [
        vec![b'a'; MAX_CONNECT_HEADER_BYTES],
        b"HTTP/1.1 200 OK\r\nX: unfinished".to_vec(),
        vec![],
    ] {
        let (left, mut right) = tokio::io::duplex(MAX_CONNECT_HEADER_BYTES * 2);
        let peer = tokio::spawn(async move {
            let mut request = [0; 61];
            // Read through the outgoing head without assuming a length.
            let mut n = 0;
            while n < request.len() && !request[..n].ends_with(b"\r\n\r\n") {
                request[n] = right.read_u8().await.unwrap();
                n += 1;
            }
            right.write_all(&response).await.unwrap();
        });
        let result = tunnel_stream_with_budget(
            left,
            &ProxyConfig::http_connect(endpoint(), None).unwrap(),
            &ProxyTarget::hostname("h.invalid", 80).unwrap(),
            &budget(),
        )
        .await;
        assert!(result.is_err());
        peer.await.unwrap();
    }
}

struct Source(AtomicU64);
impl ElapsedSource for Source {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_millis(self.0.load(Ordering::SeqCst)))
    }
}

struct JumpWrite {
    source: Arc<Source>,
    polls: Arc<AtomicUsize>,
}
impl AsyncRead for JumpWrite {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        panic!("expired proxy must never read");
    }
}
impl AsyncWrite for JumpWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        self.source.0.store(1000, Ordering::SeqCst);
        Poll::Ready(Ok(1))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        panic!("expired proxy must never flush");
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn raw_partial_polls_and_expired_entry_obey_the_original_gate() {
    for expired in [false, true] {
        for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
            let source = Arc::new(Source(AtomicU64::new(0)));
            let budget = EstablishmentBudget::new(
                ElapsedClock::with_source(source.clone()),
                Duration::from_secs(1),
            )
            .unwrap();
            if expired {
                source.0.store(1000, Ordering::SeqCst);
            }
            let polls = Arc::new(AtomicUsize::new(0));
            let proxy = ProxyConfig::new(endpoint(), kind, None).unwrap();
            let result = tunnel_stream_with_budget(
                JumpWrite {
                    source,
                    polls: polls.clone(),
                },
                &proxy,
                &ProxyTarget::hostname("host.invalid", 80).unwrap(),
                &budget,
            )
            .await;
            assert!(matches!(result, Err(Error::Timeout)));
            assert_eq!(polls.load(Ordering::SeqCst), usize::from(!expired));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_or_trickled_proxy_has_one_absolute_deadline() {
    for trickle in [false, true] {
        let (left, mut right) = tokio::io::duplex(1024);
        let peer = tokio::spawn(async move {
            let mut greeting = [0; 3];
            right.read_exact(&mut greeting).await.unwrap();
            if trickle {
                tokio::time::sleep(Duration::from_millis(600)).await;
                right.write_all(&[5]).await.unwrap();
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let result = tunnel_stream_with_budget(
            left,
            &ProxyConfig::socks5(endpoint(), None).unwrap(),
            &ProxyTarget::hostname("host.invalid", 80).unwrap(),
            &budget(),
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        peer.abort();
        let _ = peer.await;
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_proxy_writes_are_bounded_without_detaching_io() {
    for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
        let (left, mut right) = tokio::io::duplex(1);
        let proxy = ProxyConfig::new(endpoint(), kind, None).unwrap();
        let result = tunnel_stream_with_budget(
            left,
            &proxy,
            &ProxyTarget::hostname("host.invalid", 80).unwrap(),
            &budget(),
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        let mut remaining = vec![];
        right.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining.len(), 1, "only one byte fit before abort");
    }
}
