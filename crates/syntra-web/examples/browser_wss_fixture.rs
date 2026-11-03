//! Loopback-only, TEST-DATA-ONLY direct TLS 1.3/Syntra 1.0 echo fixture. Supply a PEM
//! certificate/key already trusted by the test browser to run positive WSS.
//! Never installs a root or bypasses verification. An untrusted test certificate
//! is useful ONLY for the browser's pre-M1 certificate-rejection lane.
//! Usage: cargo run -p syntra-web --features wss-test-fixture --example
//! browser_wss_fixture -- CERT.pem KEY.pem 127.0.0.1:9443 bootstrap

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
    use std::{
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use syntra_core::secure_channel::{
        Carrier, Context, KeyStore, Mode, Secret32, ServerConfig, VerifiedIdentity,
    };
    use syntra_runtime::{
        AllowAnonymous, AuthError, Authenticator, ConnectionConfig, FnHandler, HandlerOutcome,
    };
    use syntra_transport::{
        websocket::{accept_tls_stream, TlsServerSettings},
        AuthenticatorFactory, Limits,
    };

    struct TestStore;
    impl KeyStore for TestStore {
        fn lookup(
            &self,
            context: &Context,
        ) -> Result<Secret32, syntra_core::secure_channel::Error> {
            if context.handle != [7; 8] || context.epoch != 1 {
                return Err(syntra_core::secure_channel::Error::Authentication);
            }
            // Public test-only fixture input, never an issued production AK.
            Ok(Secret32::new([9; 32]))
        }
    }

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("expected CERT.pem KEY.pem 127.0.0.1:PORT bootstrap|returning".into());
    }
    let address: SocketAddr = args[3].parse()?;
    if !address.ip().is_loopback() {
        return Err("test fixture refuses non-loopback listeners".into());
    }
    let mode = match args[4].as_str() {
        "bootstrap" => Mode::Bootstrap,
        "returning" => Mode::Returning,
        _ => return Err("mode must be bootstrap or returning".into()),
    };
    for path in [&args[1], &args[2]] {
        if std::fs::metadata(path)?.len() > 1024 * 1024 {
            return Err("PEM file exceeds fixture bound".into());
        }
    }
    let certificates = CertificateDer::pem_file_iter(&args[1])?.collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() || certificates.len() > 16 {
        return Err("invalid certificate chain extent".into());
    }
    let private_key = PrivateKeyDer::from_pem_file(&args[2])?;
    let tls = TlsServerSettings::new(certificates, private_key)?;
    let (private_key, pin) = syntra_core::secure_channel::generate_server_key()?;
    let security = Arc::new(ServerConfig {
        mode,
        carrier: Carrier::SecureWebSocket,
        server_key_id: 0,
        scope: b"browser-fixture".to_vec(),
        private_key,
        store: Some(Arc::new(TestStore)),
    });
    let listener = tokio::net::TcpListener::bind(address).await?;
    let pin: String = pin.iter().map(|byte| format!("{byte:02x}")).collect();
    println!(
        "TEST-ONLY direct TLS1.3 WSS fixture: wss://{}{} mode={mode:?} pin={pin}",
        listener.local_addr()?,
        syntra_web::connection::ENDPOINT
    );
    let confirmed = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn AuthenticatorFactory> = {
        let confirmed = confirmed.clone();
        Arc::new(
            move |identity: &VerifiedIdentity| -> Result<Arc<dyn Authenticator>, AuthError> {
                if identity.context().carrier != Carrier::SecureWebSocket {
                    return Err(AuthError::unauthenticated());
                }
                confirmed.fetch_add(1, Ordering::Relaxed);
                Ok(Arc::new(AllowAnonymous))
            },
        )
    };
    let handler = Arc::new(FnHandler(|method: String, payload, _| async move {
        if method == "/example.Echo/Echo" {
            HandlerOutcome::Payload(payload)
        } else {
            HandlerOutcome::error(
                syntra_core::ErrorCode::Unimplemented,
                "fixture method unavailable",
            )
        }
    }));
    let slots = Arc::new(tokio::sync::Semaphore::new(16));
    let mut tasks = tokio::task::JoinSet::new();
    let stop = tokio::signal::ctrl_c();
    tokio::pin!(stop);
    let mut rejected = 0usize;
    loop {
        tokio::select! {
            biased;
            signal = &mut stop => { signal?; break; },
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result.expect("task set nonempty") {
                    Ok(Err(_)) => { rejected += 1; println!("fixture rejected={rejected} confirmed_hello={}", confirmed.load(Ordering::Relaxed)); },
                    Ok(Ok(())) => {},
                    Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
                    Err(_) => return Err("fixture worker cancelled unexpectedly".into()),
                }
            },
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = slots.clone().try_acquire_owned() else { drop(stream); continue; };
                let tls = tls.clone(); let security = security.clone();
                let factory = factory.clone(); let handler = handler.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let handle = accept_tls_stream(stream, &tls, &security, factory, handler,
                        ConnectionConfig::default(), Limits::default()).await?;
                    let mut closed = handle.host.subscribe_close();
                    while !handle.host.is_closed() && closed.changed().await.is_ok() {}
                    handle.close().await;
                    Ok::<(), syntra_transport::Error>(())
                });
            },
        }
    }
    tasks.abort_all();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !tasks.is_empty() {
        if tokio::time::timeout_at(deadline, tasks.join_next())
            .await
            .is_err()
        {
            return Err("fixture shutdown incomplete".into());
        }
    }
    println!(
        "fixture stopped; rejected={rejected} confirmed_hello={}",
        confirmed.load(Ordering::Relaxed)
    );
    Ok(())
}
