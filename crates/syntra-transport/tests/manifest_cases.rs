//! Opt-in local supplemental scenarios; no upstream case execution or CONF claims.
//! Python supplies local inputs and independently validates emitted observations.
//! Real TLS 1.3/WSS/Syntra host; the raw client is a test peer, NOT a client IUT.
#![cfg(all(
    feature = "native-enrollment",
    feature = "websocket",
    not(target_arch = "wasm32")
))]

use futures_util::{SinkExt, StreamExt};
use prost::Message as _;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use syntra_core::secure_channel::{
    frame_plaintext, generate_server_key, Carrier, Channel, ClientConfig, ClientHandshake, Context,
    FrameDecoder, Mode, ServerConfig, VerifiedIdentity, MAX_PLAINTEXT,
};
use syntra_core::{
    proto::{frame::Body, rpc_result::Outcome, *},
    ConnectionState, ErrorCode,
};
use syntra_runtime::{
    recovery::wire::*, AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler,
    Handler, HandlerOutcome, Principal,
};
use syntra_transport::{
    websocket as ws, AuthenticatorFactory, HostHandle, Limits, RecoveryAuthenticatorFactory,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore},
};
use tokio_tungstenite::{
    connect_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, Message},
    Connector, MaybeTlsStream, WebSocketStream,
};

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("adapter bound")
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn code(value: i32) -> &'static str {
    syntra_core::proto::ErrorCode::try_from(value)
        .unwrap()
        .as_str_name()
        .strip_prefix("ERROR_CODE_")
        .expect("IDL enum prefix")
}

#[test]
fn supplemental_error_vocabulary() {
    assert_eq!(code(4), "DEADLINE_EXCEEDED");
    assert_eq!(code(9), "FAILED_PRECONDITION");
    assert_eq!(code(12), "UNIMPLEMENTED");
    assert_eq!(code(13), "INTERNAL");
}

struct Peer {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    channel: Channel,
    decoder: FrameDecoder,
    connection_id: String,
    sent: Vec<String>,
}
impl Peer {
    async fn send(&mut self, bytes: &[u8]) {
        self.sent.push(hex(bytes));
        for chunk in frame_plaintext(bytes).unwrap().chunks(MAX_PLAINTEXT) {
            let encrypted = self.channel.encrypt(chunk).unwrap();
            bounded(self.socket.send(Message::Binary(encrypted.into())))
                .await
                .unwrap();
        }
    }
    async fn receive(&mut self) -> Option<Vec<Frame>> {
        loop {
            match bounded(self.socket.next()).await {
                Some(Ok(Message::Binary(record))) => {
                    let plain = self.channel.decrypt(&record).unwrap();
                    let frames = self.decoder.push(&plain).unwrap();
                    if !frames.is_empty() {
                        return Some(
                            frames
                                .into_iter()
                                .map(|bytes| {
                                    syntra_core::validate_wire_structure(&bytes).unwrap();
                                    Frame::decode(bytes.as_slice()).unwrap()
                                })
                                .collect(),
                        );
                    }
                }
                Some(Ok(Message::Ping(_))) => {
                    bounded(self.socket.flush()).await.unwrap();
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return None,
                other => panic!("unexpected carrier message {other:?}"),
            }
        }
    }
    async fn one(&mut self) -> Frame {
        let mut frames = self
            .receive()
            .await
            .expect("expected Syntra response, not close");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].version, 1);
        frames.remove(0)
    }
}

struct Fixture {
    listener: Arc<TcpListener>,
    settings: Arc<ws::TlsServerSettings>,
    roots: rustls::RootCertStore,
    security: Arc<ServerConfig>,
    pin: [u8; 32],
    factory: Arc<dyn AuthenticatorFactory>,
    handler: Arc<dyn Handler>,
}
impl Fixture {
    async fn new(handler: Arc<dyn Handler>, service: Option<Arc<RecoveryService>>) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let settings = ws::TlsServerSettings::new(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let (private_key, pin) = generate_server_key().unwrap();
        let base = |_: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
            Ok(Arc::new(AllowAnonymous))
        };
        let factory: Arc<dyn AuthenticatorFactory> = match service {
            Some(service) => Arc::new(RecoveryAuthenticatorFactory::new(base, service)),
            None => Arc::new(base),
        };
        Self {
            listener: Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap()),
            settings: Arc::new(settings),
            roots,
            security: Arc::new(ServerConfig {
                mode: Mode::Bootstrap,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 12,
                scope: b"manifest-fixture/scope".to_vec(),
                private_key,
                store: None,
            }),
            pin,
            factory,
            handler,
        }
    }
    async fn open(&self, hello: &[u8]) -> (Peer, HostHandle) {
        let listener = self.listener.clone();
        let settings = self.settings.clone();
        let security = self.security.clone();
        let factory = self.factory.clone();
        let handler = self.handler.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            ws::accept_tls_stream(
                stream,
                &settings,
                &security,
                factory,
                handler,
                ConnectionConfig::default(),
                Limits::default(),
            )
            .await
            .unwrap()
        });
        let url = format!(
            "wss://{}{}",
            self.listener.local_addr().unwrap(),
            ws::ENDPOINT_PATH
        );
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", ws::SUBPROTOCOL.parse().unwrap());
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(self.roots.clone())
        .with_no_client_auth();
        let (mut socket, response) = bounded(connect_async_tls_with_config(
            request,
            None,
            false,
            Some(Connector::Rustls(Arc::new(tls))),
        ))
        .await
        .unwrap();
        assert_eq!(
            response.headers()["Sec-WebSocket-Protocol"],
            ws::SUBPROTOCOL
        );
        if let MaybeTlsStream::Rustls(stream) = socket.get_ref() {
            assert_eq!(
                stream.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
        } else {
            panic!("not TLS");
        }
        let (handshake, first) = ClientHandshake::start(ClientConfig {
            context: Context {
                mode: Mode::Bootstrap,
                carrier: Carrier::SecureWebSocket,
                server_key_id: 12,
                scope: b"manifest-fixture/scope".to_vec(),
                handle: [0; 8],
                epoch: 0,
            },
            server_public_key: self.pin,
            authorization_key: None,
        })
        .unwrap();
        bounded(socket.send(Message::Binary(first.into())))
            .await
            .unwrap();
        let Message::Binary(second) = bounded(socket.next()).await.unwrap().unwrap() else {
            panic!("M2");
        };
        let channel = handshake.finish(&second).unwrap();
        let mut peer = Peer {
            socket,
            channel,
            decoder: FrameDecoder::default(),
            connection_id: String::new(),
            sent: Vec::new(),
        };
        peer.send(hello).await;
        let ready = peer.one().await;
        assert_eq!(ready.request_id, 0);
        let Some(Body::Ready(ready)) = ready.body else {
            panic!("Ready");
        };
        assert!(!ready.connection_id.is_empty());
        peer.connection_id = ready.connection_id;
        let host = bounded(task).await.unwrap();
        assert_eq!(host.host.state().await, ConnectionState::Active);
        (peer, host)
    }
}
fn hello() -> Vec<u8> {
    Frame {
        version: 1,
        request_id: 0,
        body: Some(Body::Hello(ClientHello {
            min_version: 1,
            max_version: 1,
            credential: Vec::new(),
        })),
    }
    .encode_to_vec()
}
fn request(id: u64, payload: Vec<u8>) -> Vec<u8> {
    Frame {
        version: 1,
        request_id: id,
        body: Some(Body::Request(RpcRequest {
            method: "/example.Echo/Echo".into(),
            payload,
            timeout_ms: 500,
        })),
    }
    .encode_to_vec()
}
fn observed(frame: &Frame) -> Value {
    assert_eq!(frame.version, 1);
    assert_ne!(frame.request_id, 0, "invented zero-ID result");
    syntra_core::validate_frame(frame, syntra_core::ValidationContext::active(1)).unwrap();
    let Some(Body::Result(result)) = &frame.body else {
        panic!("unexpected response variant");
    };
    let mut row = json!({"request_id": frame.request_id, "body": "result"});
    match &result.outcome {
        Some(Outcome::Payload(payload)) => {
            row["payload_hex"] = json!(hex(payload));
        }
        Some(Outcome::Error(error)) => {
            row["error"] = json!({"code":code(error.code), "message":error.message});
        }
        None => panic!("missing outcome"),
    }
    row
}
async fn state(host: &HostHandle, peer: &Peer, closed: bool) -> Value {
    let session = host.host.sessions().get(&peer.connection_id);
    if closed {
        assert_eq!(host.host.state().await, ConnectionState::Closed);
        assert!(session.is_none(), "closed connection retains session");
        assert_eq!(host.host.sessions().count(), 0);
        json!({"connection_state":"CLOSED", "session_state":"terminated_abnormally"})
    } else {
        assert_eq!(host.host.state().await, ConnectionState::Active);
        assert!(
            session.is_some(),
            "active connection lost its bound session"
        );
        let session = session.unwrap();
        assert_eq!(session.connection_id, peer.connection_id);
        assert_eq!(session.principal, Principal::anonymous());
        assert_eq!(session.version, 1);
        assert_eq!(host.host.sessions().count(), 1);
        json!({"connection_state":"ACTIVE", "session_state":"unchanged"})
    }
}

// Minimal immutable provider for the paired negotiation case. No memory-store
// durability or invented replay/snapshot behavior is claimed by this adapter.
struct Source(AtomicUsize);
impl RecoverySource for Source {
    fn authorize(
        &self,
        p: &Principal,
        selector: &[u8],
        _: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        if p == &Principal::anonymous() && selector == b"subscription-a" {
            Ok(())
        } else {
            Err(ProviderError::PermissionDenied)
        }
    }
    fn capture(&self, p: &Principal, selector: &[u8]) -> Result<ProviderStream, ProviderError> {
        self.authorize(p, selector, AuthorizationHook::Subscribe)?;
        self.0.fetch_add(1, Ordering::SeqCst);
        ProviderStream::new(selector.to_vec(), 7, b"boundary-A".to_vec())
    }
    fn current_generation(&self, _: &Principal, _: &[u8]) -> Result<u64, ProviderError> {
        Ok(7)
    }
    fn validate_issued(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &[u8],
    ) -> Result<(), ProviderError> {
        Err(ProviderError::FailedPrecondition)
    }
    fn replay(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &[u8],
        _: &[u8],
        _: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        panic!("unexpected replay");
    }
    fn snapshot(
        &self,
        _: &Principal,
        _: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        panic!("unexpected snapshot");
    }
    fn snapshot_page(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &ProviderSnapshot,
        _: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        panic!("unexpected fetch");
    }
}

async fn execute(input: &Value) -> Value {
    let id = input["scenario_id"].as_str().unwrap();
    let frames: Vec<Vec<u8>> = input["frames_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| unhex(v.as_str().unwrap()))
        .collect();
    let dispatches = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let (started_tx, mut started) = mpsc::channel(32);
    let gates: Arc<Mutex<HashMap<Vec<u8>, Arc<Semaphore>>>> = Arc::default();
    if id == "wss-duplicate-id" || id == "wss-reverse-completion" {
        for bytes in &frames {
            let frame = Frame::decode(bytes.as_slice()).unwrap();
            let Some(Body::Request(r)) = frame.body else {
                panic!("request");
            };
            gates
                .lock()
                .unwrap()
                .insert(r.payload.to_vec(), Arc::new(Semaphore::new(0)));
        }
    }
    let handler = Arc::new(FnHandler({
        let dispatches = dispatches.clone();
        let completed = completed.clone();
        let gates = gates.clone();
        let delay = input["scenario"]["input"]["faults"]["handler_delay_ms"]
            .as_u64()
            .unwrap_or(0);
        let internal = id == "wss-internal-error";
        let fault_payload = frames
            .first()
            .and_then(|bytes| Frame::decode(bytes.as_slice()).ok())
            .and_then(|frame| {
                if let Some(Body::Request(r)) = frame.body {
                    Some(r.payload.to_vec())
                } else {
                    None
                }
            });
        move |_: String, payload: Vec<u8>, _| {
            let gate = gates.lock().unwrap().get(&payload).cloned();
            let tx = started_tx.clone();
            let count = completed.clone();
            dispatches.fetch_add(1, Ordering::SeqCst);
            let injected = fault_payload.as_ref() == Some(&payload);
            async move {
                tx.send(payload.clone()).await.unwrap();
                if let Some(gate) = gate {
                    let permit = gate.acquire().await.unwrap();
                    permit.forget();
                }
                if injected && delay != 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                count.fetch_add(1, Ordering::SeqCst);
                if internal && injected {
                    HandlerOutcome::error(ErrorCode::Internal, "operation failed")
                } else {
                    HandlerOutcome::Payload(payload)
                }
            }
        }
    }));
    let source = Arc::new(Source(AtomicUsize::new(0)));
    let recovery = matches!(
        id,
        "wss-recovery-isolation" | "wss-ready" | "wss-reserved-method"
    )
    .then(|| RecoveryService::new(source.clone(), RecoveryLimits::default()).unwrap());
    let fixture = Fixture::new(handler, recovery).await;
    let supplied_hello = id == "wss-ready";
    let hello_bytes = if supplied_hello {
        frames[0].clone()
    } else {
        hello()
    };
    let (mut peer, host) = fixture.open(&hello_bytes).await;
    let mut observation = state(&host, &peer, false).await;
    let mut output = Vec::new();
    let mut checks = json!({});
    match id {
        "wss-duplicate-id" => {
            peer.send(&frames[0]).await;
            bounded(started.recv()).await.unwrap();
            assert_eq!(host.host.inflight_len(), 1);
            assert_eq!(completed.load(Ordering::SeqCst), 0);
            peer.send(&frames[1]).await;
            let mut closed = host.host.subscribe_close();
            if !*closed.borrow() {
                bounded(closed.changed()).await.unwrap();
            }
            observation = state(&host, &peer, true).await;
            observation["error"] = json!({"code":code(host.host.terminal_reason().unwrap().code() as i32), "observer":"detecting_host", "carriage":"local_only"});
            while let Some(received) = peer.receive().await {
                output.extend(received.iter().map(observed));
            }
            assert_eq!(dispatches.load(Ordering::SeqCst), 1);
            assert_eq!(completed.load(Ordering::SeqCst), 0);
            for gate in gates.lock().unwrap().values() {
                gate.add_permits(1);
            }
            checks = json!({"first_handler_started":true,"held_until_violation_and_closure":true,
                "offending_dispatches":0,"peer_transport_closed":true,"peer_success_results":0});
        }
        "wss-reverse-completion" => {
            for bytes in &frames {
                peer.send(bytes).await;
            }
            for _ in 0..16 {
                bounded(started.recv()).await.unwrap();
            }
            assert_eq!(host.host.inflight_len(), 16);
            assert_eq!(completed.load(Ordering::SeqCst), 0);
            let mut release_order = Vec::new();
            for bytes in frames.iter().rev() {
                let frame = Frame::decode(bytes.as_slice()).unwrap();
                let Some(Body::Request(r)) = frame.body else {
                    panic!("request");
                };
                gates
                    .lock()
                    .unwrap()
                    .get(r.payload.as_slice())
                    .unwrap()
                    .add_permits(1);
                let result = peer.one().await;
                release_order.push(result.request_id);
                output.push(observed(&result));
            }
            checks = json!({"all_admitted_before_release":16,"completed_before_release":0,"release_order":release_order});
        }
        "wss-recovery-isolation" => {
            peer.send(&frames[0]).await;
            output.push(observed(&peer.one().await));
            assert_eq!(source.0.load(Ordering::SeqCst), 0);
            let (mut control, control_host) = fixture.open(&hello()).await;
            assert_ne!(peer.connection_id, control.connection_id);
            let mut controls = Vec::new();
            for bytes in input["control_frames_hex"].as_array().unwrap() {
                control.send(&unhex(bytes.as_str().unwrap())).await;
                let frame = control.one().await;
                let mut row = observed(&frame);
                let Some(Body::Result(RpcResult {
                    outcome: Some(Outcome::Payload(bytes)),
                })) = frame.body
                else {
                    panic!("control success");
                };
                if frame.request_id == 1 {
                    let n = RecoveryNegotiateResponse::decode(bytes.as_slice()).unwrap();
                    row["shape"] = json!("RecoveryNegotiateResponse");
                    row["decoded"] = json!({"profile_version":n.profile_version,"selected_version":n.selected_version,
                        "max_subscriptions_per_connection":n.max_subscriptions_per_connection,"max_pending_rpcs_per_connection":n.max_pending_rpcs_per_connection,
                        "max_page_bytes":n.max_page_bytes,"max_snapshot_pages":n.max_snapshot_pages});
                } else {
                    let s = RecoverySubscribeResponse::decode(bytes.as_slice()).unwrap();
                    row["shape"] = json!("RecoverySubscribeResponse");
                    row["decoded"] = json!({"profile_version":s.profile_version,"generation":s.generation,
                        "subscription_handle_hex":hex(&s.subscription_handle),"catchup_boundary_hex":hex(&s.catchup_boundary)});
                }
                controls.push(row);
            }
            let mut control_state = state(&control_host, &control, false).await;
            control_state["frames"] = json!(controls);
            control_state["sent_frames_hex"] = json!(control.sent);
            observation["control_connection"] = control_state;
            assert_eq!(source.0.load(Ordering::SeqCst), 1);
            let mut probe = Frame::decode(frames[0].as_slice()).unwrap();
            probe.request_id = 5;
            peer.send(&probe.encode_to_vec()).await;
            let recheck = observed(&peer.one().await);
            assert_eq!(recheck["error"]["code"], "UNIMPLEMENTED");
            assert_eq!(source.0.load(Ordering::SeqCst), 1);
            checks = json!({"same_service_principal_scope_selector":true,"distinct_connections":true,
                "unconfirmed_captures":0,"control_captures":1,"probe_after_control":recheck});
            control_host.close().await;
        }
        "wss-ready" => {
            observation["session_state"] = json!("active");
            checks = json!({"ready_without_optional_negotiation":true});
        }
        "wss-envelope"
        | "wss-unknown-field"
        | "wss-reserved-method"
        | "wss-payloads"
        | "wss-deadline"
        | "wss-internal-error" => {
            let started_at = std::time::Instant::now();
            for bytes in &frames {
                peer.send(bytes).await;
                output.push(observed(&peer.one().await));
            }
            if id == "wss-payloads" {
                let mut variants = Vec::new();
                for (id, payload) in [(8, vec![]), (9, vec![0, 1, 2, 255, 255])] {
                    peer.send(&request(id, payload.clone())).await;
                    let row = observed(&peer.one().await);
                    assert_eq!(row["payload_hex"], hex(&payload));
                    variants.push(row);
                }
                checks["payload_variants"] = json!(variants);
            }
            if id == "wss-deadline" {
                checks["handler_delay_ms"] = json!(1000);
                checks["terminal_elapsed_ms"] = json!(started_at.elapsed().as_millis() as u64);
                checks["completed_handlers_at_terminal"] = json!(completed.load(Ordering::SeqCst));
                checks["dispatched_handlers"] = json!(dispatches.load(Ordering::SeqCst));
            }
        }
        _ => panic!("no local supplemental scenario for {id}"),
    }
    // An actual follow-up exchange proves ACTIVE/session usability; it is kept
    // outside the scenario's response list, and cannot hide extra queued output.
    if id != "wss-duplicate-id" {
        if id == "wss-deadline" {
            // Observe after the injected handler's 1000ms window as well: a
            // second late terminal would precede the health probe and fail its
            // exact ID/payload assertion. This is a timer fault, not race setup.
            tokio::time::sleep(Duration::from_millis(1100)).await;
        }
        let followup_id = 1001;
        peer.send(&request(followup_id, b"adapter-followup".to_vec()))
            .await;
        let result = observed(&peer.one().await);
        assert_eq!(result["request_id"], followup_id);
        assert_eq!(result["payload_hex"], hex(b"adapter-followup"));
        let current = state(&host, &peer, false).await;
        assert_eq!(current["connection_state"], observation["connection_state"]);
        checks["followup_usable_same_session"] = json!(true);
    }
    observation["frames"] = json!(output);
    observation["checks"] = checks;
    observation["sent_frames_hex"] = json!(peer.sent);
    host.close().await;
    observation
}

#[tokio::test]
#[ignore = "requires local input and fresh artifact path from scripts/conformance_evidence.py --run-local wss-*"]
async fn supplemental_scenario() {
    let request_path = std::env::var("SYNTRA_SUPPLEMENTAL_REQUEST").expect("request path");
    let result_path = std::env::var("SYNTRA_SUPPLEMENTAL_RESULT").expect("result path");
    let input: Value = serde_json::from_slice(&std::fs::read(request_path).unwrap()).unwrap();
    assert_eq!(input["role"], "server");
    assert_eq!(input["protocol"], 2);
    assert_eq!(input["kind"], "supplemental_local_scenario");
    assert_eq!(input["formal_conformance"], false);
    assert_eq!(input["carrier_id"], "SYNTRA-1.0-WSS");
    assert_eq!(ws::ENDPOINT_PATH, "/syntra/1.0/ws");
    assert_eq!(ws::SUBPROTOCOL, "syntra.1.0");
    let observation = bounded(execute(&input)).await;
    let result = json!({"protocol":2,"kind":"supplemental_local_scenario","formal_conformance":false,
        "nonce":input["nonce"],"scenario_id":input["scenario_id"],
        "scenario_sha256":input["scenario_sha256"],"role":"server","carrier_id":"SYNTRA-1.0-WSS",
        "carrier":{"tls":"1.3","termination":"direct_host","noise_mode":"bootstrap","wire":"Syntra1.0/WSS",
            "domain":"syntra.1.0","ws_path":ws::ENDPOINT_PATH,"subprotocol":ws::SUBPROTOCOL},
        "observation":observation});
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(result_path)
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&result).unwrap().as_bytes())
        .unwrap();
}
