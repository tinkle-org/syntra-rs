//! Actual C callers against real configured runtime Hosts. This provider and
//! POSIX loader are test-only; no fixture ABI is enabled in production artifacts.
use super::tests::{authenticate, authorize, Peer};
use super::*;
use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::atomic::AtomicBool;
use syntra_runtime::recovery::wire::*;

struct ReceiptClock(AtomicU64);
impl ElapsedSource for ReceiptClock {
    fn elapsed(&self) -> Option<Duration> {
        Some(Duration::from_nanos(self.0.load(Ordering::SeqCst)))
    }
}
struct ReceiptSchedule {
    peer: *mut syntra_t,
    generation: u64,
    mode: u32,
    source: Arc<ReceiptClock>,
    base: Instant,
    pause: Arc<recovery::StorageWaitPause>,
}
unsafe extern "C" fn schedule_receipt(context: usize, phase: u32) {
    // SAFETY: this test-owned context outlives the synchronous C test invocation.
    let context = unsafe { &*(context as *const ReceiptSchedule) };
    // SAFETY: C does not destroy any owner; its raw handle remains live here.
    let h = unsafe { owner(context.peer, context.generation) }.unwrap();
    let advance = || {
        // The source dominates scheduler elapsed by 60s. Projecting this exact
        // deadline into that fixed domain makes the equality test exact, not a
        // wall-clock sleep which is already late when the receipt executes.
        let deadline = h.storage_deadline();
        let offset = if context.mode == 10 { 0 } else { 1_000_000_000 };
        let nanos = 60_000_000_000 + deadline.duration_since(context.base).as_nanos() as u64;
        context.source.0.store(nanos + offset, Ordering::SeqCst);
        if context.mode == 10 {
            assert_eq!(h.endpoint.clock().now(), deadline);
        } else {
            assert_eq!(h.endpoint.clock().now(), deadline + Duration::from_secs(1));
        }
    };
    match phase {
        0 => h.pause_storage_wait(context.pause.clone()),
        1 => {
            context.pause.reached.wait();
            if context.mode != 11 {
                advance();
            }
        }
        2 => {
            // Completion must release the delivered slot even when it rejects
            // the late receipt, without waiting for this parked worker to exit.
            assert_eq!(h.recovery_work_count().unwrap(), 0);
            if context.mode == 11 {
                // The timely receipt removed its slot, so advance using the
                // fixed test amount before letting the worker receive success.
                context.source.0.fetch_add(6_000_000_000, Ordering::SeqCst);
            }
            context.pause.release.wait();
        }
        _ => panic!("invalid receipt schedule phase"),
    }
}

struct Source {
    snapshot: AtomicBool,
    retention_miss: bool,
}
impl Source {
    fn check(p: &Principal, selector: &[u8]) -> Result<(), ProviderError> {
        if p.subject != "user" || !matches!(selector, b"selector" | b"S") {
            return Err(ProviderError::PermissionDenied);
        }
        Ok(())
    }
}
impl RecoverySource for Source {
    fn authorize(
        &self,
        p: &Principal,
        s: &[u8],
        _: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        Self::check(p, s)
    }
    fn capture(&self, p: &Principal, s: &[u8]) -> Result<ProviderStream, ProviderError> {
        Self::check(p, s)?;
        ProviderStream::new(
            b"S".to_vec(),
            7,
            if self.snapshot.load(Ordering::SeqCst) {
                b"s0".to_vec()
            } else {
                b"b".to_vec()
            },
        )
    }
    fn current_generation(&self, p: &Principal, s: &[u8]) -> Result<u64, ProviderError> {
        Self::check(p, s)?;
        Ok(7)
    }
    fn validate_issued(
        &self,
        p: &Principal,
        s: &ProviderStream,
        cp: &[u8],
    ) -> Result<(), ProviderError> {
        Self::check(p, s.identity())?;
        if s.generation() == 7
            && (matches!(cp, b"a" | b"b") || (cp == b"s0" && self.snapshot.load(Ordering::SeqCst)))
        {
            Ok(())
        } else {
            Err(ProviderError::FailedPrecondition)
        }
    }
    fn replay(
        &self,
        p: &Principal,
        s: &ProviderStream,
        from: &[u8],
        marker: &[u8],
        _: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        self.validate_issued(p, s, from)?;
        if self.retention_miss {
            return Err(ProviderError::ProviderRetentionMiss);
        }
        if !marker.is_empty() {
            return Err(ProviderError::FailedPrecondition);
        }
        let batches = if from == s.boundary() {
            vec![]
        } else {
            vec![StoredBatch {
                generation: 7,
                predecessor: from.to_vec(),
                result: s.boundary().to_vec(),
                payload: b"delta".to_vec(),
            }]
        };
        ProviderPage::new(batches, s.boundary().to_vec(), vec![])
    }
    fn snapshot(
        &self,
        p: &Principal,
        s: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        Self::check(p, s.identity())?;
        // Independent immutable S0/content binding, not an invented next G.
        self.snapshot.store(true, Ordering::SeqCst);
        ProviderSnapshot::new(b"snapshot-key".to_vec(), b"s0".to_vec(), 2, 64)
    }
    fn snapshot_page(
        &self,
        p: &Principal,
        s: &ProviderStream,
        snapshot: &ProviderSnapshot,
        index: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        self.validate_issued(p, s, snapshot.boundary())?;
        match index {
            0 => Ok(b"snapshot-".to_vec()),
            1 => Ok(b"data".to_vec()),
            _ => Err(ProviderError::InvalidArgument),
        }
    }
}

#[cfg_attr(target_os = "linux", link(name = "dl"))]
unsafe extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

#[test]
fn c_recovery_real_negotiation_cas_unknown_cancel_wake_snapshot_and_resume() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).expect("test library filename entropy");
    let library = std::env::temp_dir().join(format!(
        "syntra-recovery-c-{}-{:032x}.so",
        std::process::id(),
        u128::from_be_bytes(nonce)
    ));
    let output = std::process::Command::new("cc")
        .args([
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared", "-I",
        ])
        .arg(root.join("include"))
        .arg(root.join("tests/recovery_contract.c"))
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = CString::new(library.to_str().unwrap()).unwrap();
    // SAFETY: local test-owned shared library, retained until all C calls return.
    let lib = unsafe { dlopen(path.as_ptr(), 2) };
    assert!(!lib.is_null());
    let symbol = CString::new("syntra_c_recovery_contract").unwrap();
    // SAFETY: exported symbol uses the exact signature defined by this C fixture;
    // POSIX supplies function-pointer-compatible dlsym, no pointer truncation.
    let entry = unsafe { dlsym(lib, symbol.as_ptr()) };
    assert!(!entry.is_null());
    // SAFETY: same verified C signature; the POSIX fixture asserts table layout.
    let run: unsafe extern "C" fn(
        *const *const (),
        *const *mut syntra_t,
        *const u64,
        u32,
        unsafe extern "C" fn(usize, u32),
        usize,
    ) = unsafe { std::mem::transmute(entry) };
    let api = [
        syntra_handshake as *const (),
        syntra_poll as *const (),
        syntra_emit as *const (),
        syntra_emitted as *const (),
        syntra_receipt as *const (),
        syntra_ingest as *const (),
        syntra_free as *const (),
        syntra_recovery_attach as *const (),
        syntra_recovery_negotiate as *const (),
        syntra_recovery_subscribe as *const (),
        syntra_recovery_step as *const (),
        syntra_recovery_poll as *const (),
        syntra_recovery_result_free as *const (),
        syntra_storage_take as *const (),
        syntra_storage_complete as *const (),
        syntra_storage_request_free as *const (),
        syntra_cancel as *const (),
        syntra_suspend as *const (),
        syntra_platform_wake as *const (),
        syntra_shutdown as *const (),
        syntra_transport_closed as *const (),
        syntra_shutdown_poll as *const (),
    ];
    for mode in 0..12 {
        let source_clock = Arc::new(ReceiptClock(AtomicU64::new(0)));
        let c1 = if mode >= 9 {
            let clock = ElapsedClock::with_source(source_clock.clone());
            let h = open_with_clock(None, Some(clock.clone())).unwrap();
            source_clock.0.store(60_000_000_000, Ordering::SeqCst);
            Peer {
                g: h.generation,
                p: Box::into_raw(h),
            }
        } else {
            Peer::client()
        };
        let c2 = Peer::client();
        let source = Arc::new(Source {
            snapshot: AtomicBool::new(false),
            retention_miss: mode == 6,
        });
        let service = RecoveryService::new(source, RecoveryLimits::default()).unwrap();
        let make_host = || {
            let policy = syntra_policy_t {
                context: 0,
                authenticate: Some(authenticate),
                authorize: Some(authorize),
            };
            let h = open(Some(policy)).unwrap();
            let Endpoint::Host(host) = &h.endpoint else {
                panic!("host")
            };
            let host = host.clone();
            let service = service.clone();
            if mode != 7 {
                let mut task = h
                    .runtime
                    .spawn(async move { host.configure_recovery(service).await });
                super::tests::until(|| task.is_finished().then_some(()));
                assert!(matches!(
                    Pin::new(&mut task).poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Ok(Ok(())))
                ));
            }
            let g = h.generation;
            Peer {
                p: Box::into_raw(h),
                g,
            }
        };
        let h1 = make_host();
        let h2 = make_host();
        let owners = [c1.p, h1.p, c2.p, h2.p];
        let generations = [c1.g, h1.g, c2.g, h2.g];
        // SAFETY: c1 remains owned by this scope through the entire C call.
        let base = unsafe { owner(c1.p, c1.g) }.unwrap().endpoint.clock().now();
        let schedule = ReceiptSchedule {
            peer: c1.p,
            generation: c1.g,
            mode,
            source: source_clock,
            base,
            pause: Arc::new(recovery::StorageWaitPause {
                armed: AtomicBool::new(true),
                reached: std::sync::Barrier::new(2),
                release: std::sync::Barrier::new(2),
            }),
        };
        // SAFETY: all actual C ABI entrypoints and live owners remain stable;
        // this call is synchronous, aggregates are freed by the C fixture.
        unsafe {
            run(
                api.as_ptr(),
                owners.as_ptr(),
                generations.as_ptr(),
                mode,
                schedule_receipt,
                &schedule as *const ReceiptSchedule as usize,
            );
        }
    }
    // SAFETY: no C function, pointer, callback or data survives the contract run.
    assert_eq!(unsafe { dlclose(lib) }, 0);
    std::fs::remove_file(library).unwrap();
}
