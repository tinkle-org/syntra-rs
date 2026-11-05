#![cfg(all(feature = "proxy", not(target_arch = "wasm32")))]
//! Local scripted proxy and same-implementation encrypted tunnel regressions;
//! not independent interoperability or formal protocol conformance evidence.

use std::{net::SocketAddr, sync::Arc, time::Duration};
use syntra_core::secure_channel::{
    generate_server_key, Carrier, ClientConfig, Context, Mode, ServerConfig, VerifiedIdentity,
};
use syntra_net::{
    proxy::{self, ProxyConfig, ProxyCredentials, ProxyKind, ProxyTarget},
    tcp, Error, EstablishmentBudget, Limits,
};
use syntra_runtime::{
    elapsed::ElapsedClock, AuthError, Authenticator, ConnectionConfig, FnHandler, HandlerOutcome,
    StaticToken,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn budget(duration: Duration) -> EstablishmentBudget {
    EstablishmentBudget::new(ElapsedClock::new(), duration).unwrap()
}

fn config(address: SocketAddr, kind: ProxyKind, auth: bool) -> ProxyConfig {
    let credentials = auth
        .then(|| ProxyCredentials::new(b"proxy-user".to_vec(), b"proxy-secret".to_vec()).unwrap());
    match kind {
        ProxyKind::Socks5 => ProxyConfig::socks5(address, credentials).unwrap(),
        ProxyKind::HttpConnect => ProxyConfig::http_connect(address, credentials).unwrap(),
    }
}

fn configs() -> (ClientConfig, ServerConfig) {
    let (key, public) = generate_server_key().unwrap();
    let context = Context {
        mode: Mode::Bootstrap,
        carrier: Carrier::Tcp,
        server_key_id: 1,
        scope: b"proxy-test/exact-scope".to_vec(),
        handle: [0; 8],
        epoch: 0,
    };
    (
        ClientConfig {
            context: context.clone(),
            server_public_key: public,
            authorization_key: None,
        },
        ServerConfig {
            mode: Mode::Bootstrap,
            carrier: Carrier::Tcp,
            server_key_id: 1,
            scope: context.scope,
            private_key: key,
            store: None,
        },
    )
}

async fn fragmented(stream: &mut TcpStream, bytes: &[u8]) {
    for byte in bytes {
        stream.write_all(&[*byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut head = vec![];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 4096);
        head.push(stream.read_u8().await.unwrap());
    }
    head
}

async fn socks_request(stream: &mut TcpStream, auth: bool) -> Vec<u8> {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, if auth { 2 } else { 0 }]);
    fragmented(stream, &[5, if auth { 2 } else { 0 }]).await;
    if auth {
        let mut auth_packet = [0; 25];
        stream.read_exact(&mut auth_packet).await.unwrap();
        assert_eq!(&auth_packet, b"\x01\x0aproxy-user\x0cproxy-secret");
        fragmented(stream, &[1, 0]).await;
    }
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix[..3], &[5, 1, 0]);
    let mut request = prefix.to_vec();
    let len = match prefix[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = stream.read_u8().await.unwrap();
            request.push(len);
            len as usize
        }
        _ => panic!("unexpected address type"),
    };
    let mut address_port = vec![0; len + 2];
    stream.read_exact(&mut address_port).await.unwrap();
    request.extend_from_slice(&address_port);
    request
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_socks_remote_dns_ipv4_ipv6_auth_and_bound_address_forms() {
    for (target, expected) in [
        (
            ProxyTarget::hostname("Only-Proxy.invalid", 443).unwrap(),
            b"\x05\x01\x00\x03\x12Only-Proxy.invalid\x01\xbb".to_vec(),
        ),
        (
            ProxyTarget::ip("192.0.2.1".parse().unwrap(), 443).unwrap(),
            vec![5, 1, 0, 1, 192, 0, 2, 1, 1, 187],
        ),
        (ProxyTarget::ip("::1".parse().unwrap(), 443).unwrap(), {
            let mut bytes = vec![5, 1, 0, 4];
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            bytes.extend_from_slice(&[1, 187]);
            bytes
        }),
    ] {
        for auth in [false, true] {
            for bound in [
                vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
                [vec![5, 0, 0, 4], vec![0; 18]].concat(),
                b"\x05\x00\x00\x03\x01x\x00\x00".to_vec(),
            ] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let proxy = config(listener.local_addr().unwrap(), ProxyKind::Socks5, auth);
                let expected = expected.clone();
                let peer = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    assert_eq!(socks_request(&mut stream, auth).await, expected);
                    fragmented(&mut stream, &bound).await;
                    // Reply and tunneled bytes need not occupy separate packets.
                    stream.write_all(b"tunnel").await.unwrap();
                });
                let mut stream = proxy::connect_tunnel_with_budget(
                    &proxy,
                    &target,
                    &budget(Duration::from_secs(2)),
                )
                .await
                .unwrap();
                let mut bytes = [0; 6];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"tunnel");
                peer.await.unwrap();
            }
        }
    }
}

#[tokio::test]
async fn socks_selection_cannot_downgrade_or_select_an_unoffered_method() {
    for (auth, selection) in [
        (true, [5, 0]),
        (true, [5, 1]),
        (true, [5, 255]),
        (false, [5, 2]),
        (false, [5, 255]),
        (false, [4, 0]),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = config(listener.local_addr().unwrap(), ProxyKind::Socks5, auth);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            fragmented(&mut stream, &selection).await;
            let mut remaining = vec![];
            stream.read_to_end(&mut remaining).await.unwrap();
            assert!(
                remaining.is_empty(),
                "no auth/request after rejected method"
            );
        });
        let result = proxy::connect_tunnel_with_budget(
            &proxy,
            &ProxyTarget::hostname("host.invalid", 80).unwrap(),
            &budget(Duration::from_secs(2)),
        )
        .await;
        assert!(matches!(
            result,
            Err(Error::Authentication | Error::Framing)
        ));
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn socks_auth_failure_and_malformed_auth_are_terminal() {
    for response in [vec![1, 1], vec![5, 0], vec![1], vec![]] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = config(listener.local_addr().unwrap(), ProxyKind::Socks5, true);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0; 25];
            stream.read_exact(&mut auth).await.unwrap();
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut remaining = vec![];
            stream.read_to_end(&mut remaining).await.unwrap();
            assert!(remaining.is_empty());
        });
        assert!(proxy::connect_tunnel_with_budget(
            &proxy,
            &ProxyTarget::hostname("host.invalid", 80).unwrap(),
            &budget(Duration::from_secs(2)),
        )
        .await
        .is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn socks_malformed_refused_and_every_truncation_of_success_reply() {
    let success = [5, 0, 0, 1, 127, 0, 0, 1, 0, 80];
    let mut replies: Vec<Vec<u8>> = (0..success.len()).map(|i| success[..i].to_vec()).collect();
    for reply in 1..=8 {
        replies.push(vec![5, reply, 0, 1]);
    }
    replies.extend([
        vec![4, 0, 0, 1],
        vec![5, 0, 1, 1],
        vec![5, 0, 0, 2],
        vec![5, 0, 0, 3, 0],
        vec![5, 9, 0, 1],
        vec![5, 0, 0, 3, 255, 0],
    ]);
    for response in replies {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = config(listener.local_addr().unwrap(), ProxyKind::Socks5, false);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            socks_request(&mut stream, false).await;
            stream.write_all(&response).await.unwrap();
        });
        assert!(proxy::connect_tunnel_with_budget(
            &proxy,
            &ProxyTarget::hostname("host.invalid", 80).unwrap(),
            &budget(Duration::from_secs(2)),
        )
        .await
        .is_err());
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn real_connect_fragmented_success_and_refusal_never_retry_or_leak() {
    for response in [
        b"HTTP/1.1 299 Tunnel\r\nContent-Length: 99\r\n\r\n".as_slice(),
        b"HTTP/1.0 200 OK\r\n\r\n",
        b"HTTP/1.1 407 Auth\r\nProxy-Authenticate: Basic\r\n\r\n",
        b"HTTP/1.1 302 Redirect\r\nLocation: http://other.invalid/\r\n\r\n",
        b"HTTP/1.1 403 No\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nStatus: 500\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nHTTP/1.1 500 NO\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nX: truncated",
    ] {
        let success =
            response.starts_with(b"HTTP/1.1 299") || response.starts_with(b"HTTP/1.0 200");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = config(listener.local_addr().unwrap(), ProxyKind::HttpConnect, true);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_head(&mut stream).await;
            assert_eq!(head, b"CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid:443\r\nProxy-Authorization: Basic cHJveHktdXNlcjpwcm94eS1zZWNyZXQ=\r\n\r\n");
            fragmented(&mut stream, response).await;
            stream.shutdown().await.unwrap();
            let mut remaining = vec![];
            stream.read_to_end(&mut remaining).await.unwrap();
            assert!(
                remaining.is_empty(),
                "no additional request or origin credentials"
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        });
        let result = proxy::connect_tunnel_with_budget(
            &proxy,
            &ProxyTarget::hostname("origin.invalid", 443).unwrap(),
            &budget(Duration::from_secs(2)),
        )
        .await;
        assert_eq!(result.is_ok(), success);
        drop(result);
        peer.await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_encrypted_echo_through_both_proxies_preserves_tcp_pin_and_scope() {
    for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
        for failure in 0..3 {
            let (mut security, server) = configs();
            if failure == 1 {
                security.server_public_key = generate_server_key().unwrap().1;
            } else if failure == 2 {
                security.context.scope = b"different-provisioned-scope".to_vec();
            }
            let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin_address = origin.local_addr().unwrap();
            let host = tokio::spawn(async move {
                let (stream, _) = origin.accept().await.unwrap();
                tcp::accept_stream(
                    stream,
                    &server,
                    Arc::new(
                        |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                            assert_eq!(identity.context().carrier, Carrier::Tcp);
                            assert_eq!(identity.context().scope, b"proxy-test/exact-scope");
                            Ok(Arc::new(StaticToken::new(
                                b"origin-hello".to_vec(),
                                "principal",
                            )))
                        },
                    ),
                    Arc::new(FnHandler(|_, bytes, _| async move {
                        HandlerOutcome::Payload(bytes)
                    })),
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = config(listener.local_addr().unwrap(), kind, true);
            let relay = tokio::spawn(async move {
                let (mut inbound, _) = listener.accept().await.unwrap();
                match kind {
                    ProxyKind::Socks5 => {
                        let request = socks_request(&mut inbound, true).await;
                        assert_eq!(request, b"\x05\x01\x00\x03\x0eorigin.invalid\x01\xbb");
                        inbound
                            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                            .await
                            .unwrap();
                    }
                    ProxyKind::HttpConnect => {
                        let head = read_head(&mut inbound).await;
                        assert!(head.starts_with(b"CONNECT origin.invalid:443 HTTP/1.1\r\n"));
                        assert!(head
                            .windows(b"Proxy-Authorization:".len())
                            .any(|w| w == b"Proxy-Authorization:"));
                        inbound
                            .write_all(b"HTTP/1.1 200 Established\r\n\r\n")
                            .await
                            .unwrap();
                    }
                }
                let mut outbound = TcpStream::connect(origin_address).await.unwrap();
                // Only tunneled bytes reach the Syntra peer, never proxy headers.
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
            let target = ProxyTarget::hostname("origin.invalid", 443).unwrap();
            // Spawn on a multithread runtime: connector future must remain Send.
            let client = tokio::spawn(async move {
                proxy::connect_tcp_proxy(
                    &proxy,
                    &target,
                    security,
                    b"origin-hello".to_vec(),
                    ConnectionConfig::default(),
                    Limits::default(),
                )
                .await
            })
            .await
            .unwrap();
            let host = host.await.unwrap();
            if failure != 0 {
                assert!(client.is_err());
                assert!(host.is_err());
            } else {
                let client = client.unwrap();
                let host = host.unwrap();
                let payload = vec![42; 200_000];
                assert_eq!(
                    client
                        .conn
                        .call("/test.Service/Echo", payload.clone(), 5_000)
                        .await
                        .unwrap(),
                    payload
                );
                client.close().await;
                host.close().await;
            }
            relay.await.unwrap();
        }
    }
}

#[tokio::test]
async fn proxy_and_syntra_share_one_budget_and_cancellation_closes_the_socket() {
    for kind in [ProxyKind::Socks5, ProxyKind::HttpConnect] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = config(listener.local_addr().unwrap(), kind, false);
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            match kind {
                ProxyKind::Socks5 => {
                    socks_request(&mut stream, false).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    stream
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                }
                ProxyKind::HttpConnect => {
                    read_head(&mut stream).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                }
            }
            let mut first = vec![];
            // Never answer Noise. The original total deadline must close us.
            stream.read_to_end(&mut first).await.unwrap();
            assert!(!first.is_empty());
        });
        let (security, _) = configs();
        let shared = budget(Duration::from_millis(180));
        let started = tokio::time::Instant::now();
        let result = proxy::connect_tcp_proxy_with_budget(
            &proxy,
            &ProxyTarget::hostname("origin.invalid", 443).unwrap(),
            security,
            vec![],
            ConnectionConfig::default(),
            Limits::default(),
            shared,
        )
        .await;
        assert!(matches!(result, Err(Error::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(1));
        peer.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = config(listener.local_addr().unwrap(), kind, true);
        let attempt = tokio::spawn(async move {
            proxy::connect_tunnel_with_budget(
                &proxy,
                &ProxyTarget::hostname("origin.invalid", 443).unwrap(),
                &budget(Duration::from_secs(2)),
            )
            .await
        });
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
        attempt.abort();
        let _ = attempt.await;
        let mut remainder = vec![];
        tokio::time::timeout(Duration::from_secs(1), socket.read_to_end(&mut remainder))
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn non_tcp_security_is_rejected_before_proxy_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = config(listener.local_addr().unwrap(), ProxyKind::Socks5, true);
    let (mut security, _) = configs();
    security.context.carrier = Carrier::SecureWebSocket;
    let result = proxy::connect_tcp_proxy(
        &proxy,
        &ProxyTarget::hostname("origin.invalid", 443).unwrap(),
        security,
        vec![],
        ConnectionConfig::default(),
        Limits::default(),
    )
    .await;
    assert!(matches!(result, Err(Error::Framing)));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}
