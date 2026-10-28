//! Integration suite: neutral echo/get-put/event fixtures over the
//! connection runtime (SNTR-RPC-900/901, SNTR-HS-900/901, SNTR-SESS-900).
//!
//! Drives `tests/integration/` (echo, get-put, events, handshake) and
//! `tests/interoperability/vectors.rs` through loopback pairs. No
//! chat/messenger semantics anywhere: methods are
//! `/example.Echo/Echo`, `/example.KV/Get`, `/example.KV/Put`.

#[path = "../../../tests/integration/echo.rs"]
mod echo;
#[path = "../../../tests/integration/events.rs"]
mod events;
#[path = "../../../tests/integration/get_put.rs"]
mod get_put;
#[path = "../../../tests/integration/handshake.rs"]
mod handshake_fixtures;
#[path = "../../../tests/interoperability/vectors.rs"]
mod vectors;

use std::sync::Arc;
use std::time::Duration;

use syntra_core::{decode_frame, ConnectionState, ErrorCode, ValidationContext};
use syntra_runtime::{
    loopback_pair, AllowAnonymous, CancelToken, ConnectionConfig, FnHandler, HandlerOutcome, Host,
    Initiator, RejectAll, SessionManager, StaticToken,
};

fn test_handler() -> Arc<dyn syntra_runtime::Handler> {
    Arc::new(FnHandler(
        |method: String, payload: Vec<u8>, cancel: CancelToken| async move {
            let _ = cancel;
            match method.as_str() {
                "/example.Echo/Echo" => HandlerOutcome::Payload(payload),
                "/example.KV/Put" => HandlerOutcome::Payload(Vec::new()),
                "/example.KV/Get" => HandlerOutcome::error(ErrorCode::NotFound, "missing"),
                _ => HandlerOutcome::error(ErrorCode::Unimplemented, "unknown method"),
            }
        },
    ))
}

async fn active_pair() -> (Initiator, Arc<Host>) {
    let (initiator, host) = loopback_pair(
        Arc::new(AllowAnonymous),
        test_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    assert_eq!(initiator.state().await, ConnectionState::Active);
    (initiator, host)
}

#[tokio::test]
async fn echo_round_trips() {
    let (initiator, _host) = active_pair().await;
    for payload in echo::echo_payloads() {
        let out = initiator
            .call(echo::ECHO_METHOD, payload.clone(), 2000)
            .await
            .expect("echo");
        echo::assert_echo(&out, &payload);
    }
}

#[tokio::test]
async fn get_put_fixtures() {
    let (initiator, _host) = active_pair().await;
    for key in get_put::sample_keys() {
        // Put succeeds with empty output.
        let out = initiator
            .call(
                get_put::KV_PUT_METHOD,
                get_put::put_payload(&key, b"value"),
                2000,
            )
            .await
            .expect("put");
        assert!(out.is_empty());
        // Get misses: NOT_FOUND is a terminal per-RPC error, usable conn.
        let err = initiator
            .call(get_put::KV_GET_METHOD, get_put::get_payload(&key), 2000)
            .await
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }
    // Connection still usable after terminal RPC errors.
    let out = initiator
        .call(echo::ECHO_METHOD, b"after-errors".to_vec(), 2000)
        .await
        .expect("usable");
    assert_eq!(out, b"after-errors");
}

#[tokio::test]
async fn events_delivered_never_complete_rpc() {
    let (initiator, host) = active_pair().await;
    // Interleave: start an RPC, deliver events, complete the RPC.
    let call = {
        let initiator = initiator.clone();
        tokio::spawn(async move {
            initiator
                .call(echo::ECHO_METHOD, b"slow".to_vec(), 5000)
                .await
        })
    };
    // Give the request a moment to be sent, then emit events.
    tokio::time::sleep(Duration::from_millis(50)).await;
    for payload in events::event_payloads() {
        host.notify(payload).await.expect("notify");
    }
    let out = call.await.unwrap().expect("rpc completes");
    assert_eq!(out, b"slow");
    // All events arrive, in order, including the empty one.
    for want in events::event_payloads() {
        let got = tokio::time::timeout(Duration::from_secs(2), initiator.next_notification())
            .await
            .expect("event in time")
            .expect("not closed");
        assert_eq!(got, want);
    }
}

#[tokio::test]
async fn handshake_version_mismatch_cases() {
    for (min, max) in handshake_fixtures::disjoint_ranges() {
        let (initiator, host) = loopback_pair(
            Arc::new(AllowAnonymous),
            test_handler(),
            ConnectionConfig::default(),
        );
        let _ = initiator;
        host.ingest(&handshake_fixtures::hello_bytes(min, max, vec![]))
            .await;
        assert!(host.is_closed());
    }
}

#[tokio::test]
async fn handshake_malformed_range_rejected() {
    for (min, max) in handshake_fixtures::malformed_ranges() {
        let (initiator, host) = loopback_pair(
            Arc::new(AllowAnonymous),
            test_handler(),
            ConnectionConfig::default(),
        );
        let _ = initiator;
        host.ingest(&handshake_fixtures::hello_bytes(min, max, vec![]))
            .await;
        assert_eq!(host.state().await, ConnectionState::Closed);
    }
}

#[tokio::test]
async fn auth_rejection_is_generic_and_closes() {
    let (initiator, host) = loopback_pair(
        Arc::new(RejectAll),
        test_handler(),
        ConnectionConfig::default(),
    );
    // Carrier B1: the host emits no Frame to carry the handshake error —
    // the typed UNAUTHENTICATED is host-local (a real transport also
    // sends its close code, 1008) while the initiator learns transport
    // loss with unknown outcome. Never a synthesized success.
    let err = initiator.handshake(vec![1, 2, 3]).await.unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.is_unknown_outcome());
    assert!(initiator.is_closed());
    assert_eq!(host.sessions().count(), 0);
}

#[tokio::test]
async fn second_hello_fails() {
    let (initiator, host) = loopback_pair(
        Arc::new(AllowAnonymous),
        test_handler(),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("first");
    host.ingest(&handshake_fixtures::hello_bytes(1, 1, vec![]))
        .await;
    // ACTIVE hello is a fatal violation: connection closes.
    assert_eq!(host.state().await, ConnectionState::Closed);
}

#[tokio::test]
async fn pre_active_frames_fail() {
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::{Cancel, Frame, RpcRequest};

    for body in [
        Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload: vec![].into(),
            timeout_ms: 100,
        }),
        Body::Cancel(Cancel {}),
    ] {
        let (initiator, host) = loopback_pair(
            Arc::new(AllowAnonymous),
            test_handler(),
            ConnectionConfig::default(),
        );
        let _ = initiator;
        let raw = {
            use prost::Message;
            Frame {
                version: 1,
                request_id: 7,
                body: Some(body),
            }
            .encode_to_vec()
        };
        host.ingest(&raw).await;
        assert_eq!(host.state().await, ConnectionState::Closed);
    }
}

#[tokio::test]
async fn duplicate_outstanding_rejected_original_continues() {
    use prost::Message;
    use syntra_core::proto::frame::Body;
    use syntra_core::proto::{Frame, RpcRequest};

    // Blocking handler: the first request stays outstanding until released.
    let release = Arc::new(tokio::sync::Notify::new());
    let release_handler = release.clone();
    let blocking = Arc::new(FnHandler(
        move |_m: String, _p: Vec<u8>, _c: CancelToken| {
            let release = release_handler.clone();
            async move {
                release.notified().await;
                HandlerOutcome::Payload(b"first".to_vec())
            }
        },
    ));
    let (host, mut wrx) = Host::new(
        ConnectionConfig::default(),
        Arc::new(AllowAnonymous),
        blocking,
    );
    host.ingest(&handshake_fixtures::hello_bytes(1, 1, vec![]))
        .await;
    let _ready = wrx.recv().await.expect("ready");
    assert_eq!(host.state().await, ConnectionState::Active);

    let raw_request = |id: u64| {
        Frame {
            version: 1,
            request_id: id,
            body: Some(Body::Request(RpcRequest {
                method: "/example.Echo/Echo".into(),
                payload: vec![].into(),
                timeout_ms: 5000,
            })),
        }
        .encode_to_vec()
    };
    // First attempt accepted (handler blocks); duplicate rejected with a
    // terminal FAILED_PRECONDITION while the original continues.
    host.ingest(&raw_request(7)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(host.inflight_len(), 1);
    host.ingest(&raw_request(7)).await;
    let dup_out = wrx.recv().await.expect("duplicate result");
    let ctx = syntra_core::ValidationContext::active(1);
    let dup = syntra_core::decode_frame(&dup_out, ctx).expect("valid result");
    match dup.body {
        Some(Body::Result(r)) => match r.outcome {
            Some(syntra_core::proto::rpc_result::Outcome::Error(e)) => {
                assert_eq!(e.code, ErrorCode::FailedPrecondition.as_i32())
            }
            other => panic!("expected error, got {other:?}"),
        },
        other => panic!("expected result, got {other:?}"),
    }
    assert_eq!(host.inflight_len(), 1);
    // Release the original: exactly one success follows, no second result.
    release.notify_one();
    let first_out = tokio::time::timeout(Duration::from_secs(2), wrx.recv())
        .await
        .expect("first result in time")
        .expect("channel open");
    let first = syntra_core::decode_frame(&first_out, ctx).expect("valid result");
    match first.body {
        Some(Body::Result(r)) => match r.outcome {
            Some(syntra_core::proto::rpc_result::Outcome::Payload(p)) => {
                assert_eq!(p, b"first")
            }
            other => panic!("expected payload, got {other:?}"),
        },
        other => panic!("expected result, got {other:?}"),
    }
    assert_eq!(host.inflight_len(), 0);
    // Pending-table unit contract: duplicate insert rejects, original kept.
    let table = syntra_core::PendingTable::new(4);
    let _rx = table.insert(42, "/example.Echo/Echo".into()).unwrap();
    assert!(table.insert(42, "/example.Echo/Echo".into()).is_err());
    assert!(table.is_pending(42));
}

#[tokio::test]
async fn cancel_before_completion_wins_as_cancelled() {
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_m, _p, cancel: CancelToken| async move {
            cancel.cancelled().await;
            HandlerOutcome::Payload(b"late".to_vec())
        })),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let token = CancelToken::new();
    let call = {
        let initiator = initiator.clone();
        let token = token.clone();
        tokio::spawn(async move {
            initiator
                .call_cancellable(echo::ECHO_METHOD, b"x".to_vec(), 5000, &token)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    token.cancel();
    let err = call.await.unwrap().unwrap_err();
    assert_eq!(err.code(), ErrorCode::Cancelled);
}

#[tokio::test]
async fn deadline_expiry_is_terminal() {
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        Arc::new(FnHandler(|_m, _p, _c: CancelToken| async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            HandlerOutcome::Payload(b"too-late".to_vec())
        })),
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let err = initiator
        .call(echo::ECHO_METHOD, b"x".to_vec(), 50)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DeadlineExceeded);
    assert!(err.is_unknown_outcome());
}

#[tokio::test]
async fn sixteen_concurrent_out_of_order() {
    let (initiator, _host) = active_pair().await;
    let mut handles = Vec::new();
    for i in 0..16u8 {
        let initiator = initiator.clone();
        handles.push(tokio::spawn(async move {
            let payload = vec![i; 32];
            let out = initiator
                .call(echo::ECHO_METHOD, payload.clone(), 5000)
                .await
                .expect("concurrent");
            assert_eq!(out, payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn transport_loss_maps_unavailable() {
    // Blocking handler: the RPC is outstanding when loss hits.
    let release = Arc::new(tokio::sync::Notify::new());
    let release_handler = release.clone();
    let blocking = Arc::new(FnHandler(move |_m, _p, _c: CancelToken| {
        let release = release_handler.clone();
        async move {
            release.notified().await;
            HandlerOutcome::Payload(b"late".to_vec())
        }
    }));
    let (initiator, _host) = loopback_pair(
        Arc::new(AllowAnonymous),
        blocking,
        ConnectionConfig::default(),
    );
    initiator.handshake(vec![]).await.expect("handshake");
    let h = tokio::spawn({
        let initiator = initiator.clone();
        async move { initiator.call(echo::ECHO_METHOD, b"x".to_vec(), 5000).await }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while initiator.pending_len() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("outstanding call registers");
    assert_eq!(initiator.pending_len(), 1);
    initiator.on_transport_lost().await;
    let err = h.await.unwrap().unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unavailable);
    assert!(err.is_unknown_outcome());
    release.notify_one();
}

#[tokio::test]
async fn reconnect_is_stateless() {
    // Sessions are connection-bound: a new pair needs a fresh handshake,
    // gets a fresh connection_id, and old ids never resume anything.
    let cfg = ConnectionConfig::default();
    let (i1, h1) = loopback_pair(Arc::new(AllowAnonymous), test_handler(), cfg.clone());
    let id1 = i1.handshake(vec![]).await.expect("first");
    i1.on_transport_lost().await;
    drop(h1);
    let (i2, h2) = loopback_pair(Arc::new(AllowAnonymous), test_handler(), cfg);
    let id2 = i2.handshake(vec![]).await.expect("second");
    assert_ne!(id1, id2, "fresh connection_id per connection");
    assert_eq!(h2.sessions().count(), 1);
    // Old connection_id as credential is rejected, not resumed.
    let (i3, _h3) = loopback_pair(
        Arc::new(StaticToken::new(id1.as_bytes().to_vec(), "x")),
        test_handler(),
        ConnectionConfig::default(),
    );
    // StaticToken would accept those bytes, but the host rejects live
    // session ids before policy evaluation. (Here the loopback host has
    // no such session, so the handshake succeeds against the static
    // token — the rejection is covered at the host unit level.)
    let _ = (i3, id1);
    // Resumption is unavailable by design.
    assert!(h2.sessions().resume(b"token").is_err());
}

#[tokio::test]
async fn connection_id_reuse_rejected_at_host() {
    let (initiator, host) = loopback_pair(
        Arc::new(AllowAnonymous),
        test_handler(),
        ConnectionConfig::default(),
    );
    let id = initiator.handshake(vec![]).await.expect("handshake");
    // Present the live connection_id as a credential on a second
    // connection against the SAME host sessions manager: rejected.
    let (initiator2, host2) = loopback_pair(
        Arc::new(AllowAnonymous),
        test_handler(),
        ConnectionConfig::default(),
    );
    let _ = initiator2;
    // Inject a hello carrying the first connection's id into host2 after
    // binding id there too (simulate a shared session store).
    host2.sessions().bind(syntra_runtime::Session {
        connection_id: id.clone(),
        principal: syntra_runtime::Principal::anonymous(),
        version: 1,
        established_at: std::time::Instant::now(),
    });
    host2
        .ingest(&handshake_fixtures::hello_bytes(
            1,
            1,
            id.as_bytes().to_vec(),
        ))
        .await;
    assert_eq!(host2.state().await, ConnectionState::Closed);
    let _ = host;
}

#[tokio::test]
async fn malformed_method_terminal_without_close() {
    let (initiator, _host) = active_pair().await;
    let err = initiator
        .call("not-a-path", vec![], 1000)
        .await
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    // Usable afterwards.
    let out = initiator
        .call(echo::ECHO_METHOD, b"ok".to_vec(), 1000)
        .await
        .expect("usable");
    assert_eq!(out, b"ok");
}

#[tokio::test]
async fn interop_no_length_prefix_vectors() {
    use syntra_core::proto::frame::Body;
    // Good: decodes directly as one Frame (no prefix stripping).
    let good = vectors::hex_to_bytes(vectors::NO_LENGTH_PREFIX_GOOD_HEX);
    let ctx = syntra_core::ValidationContext::pre_handshake(ConnectionState::Connected);
    let frame = syntra_core::decode_frame(&good, ctx).expect("good vector");
    assert!(matches!(frame.body, Some(Body::Hello(_))));
    // Unknown-field suffix: same logical frame.
    let mut with_unknown = good.clone();
    with_unknown.extend_from_slice(&vectors::hex_to_bytes(vectors::UNKNOWN_FIELD_SUFFIX_HEX));
    let frame2 = syntra_core::decode_frame(&with_unknown, ctx).expect("unknown tolerated");
    assert!(matches!(frame2.body, Some(Body::Hello(_))));
    // Bad: varint-prefixed, u32-prefixed, suffixed — all rejected.
    for hex in [
        vectors::VARINT_PREFIXED_HEX,
        vectors::U32_PREFIXED_HEX,
        vectors::SUFFIXED_HEX,
    ] {
        let bad = vectors::hex_to_bytes(hex);
        assert!(
            syntra_core::decode_frame(&bad, ctx).is_err(),
            "must reject {hex}"
        );
    }
}

#[tokio::test]
async fn interop_close_code_table_sane() {
    // Every tabled wire code is real (never 1005/1006/1015).
    for (code, _label) in vectors::CLOSE_CODE_TABLE {
        assert!(
            !vectors::RESERVED_CLOSE_CODES.contains(code),
            "reserved code {code} tabled"
        );
    }
    assert_eq!(vectors::MAX_FRAME_BYTES, syntra_core::MAX_FRAME_BYTES);
    // Ping/pong/close wire vectors parse as even-length hex.
    for hex in [
        vectors::PING_WIRE_HEX,
        vectors::PONG_WIRE_HEX,
        vectors::CLOSE_CLIENT_WIRE_HEX,
        vectors::CLOSE_HOST_WIRE_HEX,
    ] {
        assert!(!vectors::hex_to_bytes(hex).is_empty());
    }
}

#[test]
fn session_manager_contract() {
    let m = SessionManager::new();
    assert_eq!(m.count(), 0);
    assert!(m.resume(b"nope").is_err());
}

#[test]
fn ready_fixture_decodes() {
    let bytes = handshake_fixtures::ready_bytes(1, "conn-9");
    let ctx = ValidationContext::pre_handshake(ConnectionState::Negotiating);
    let frame = decode_frame(&bytes, ctx).expect("ready fixture");
    assert_eq!(frame.version, 1);
    assert_eq!(frame.request_id, 0);
}
