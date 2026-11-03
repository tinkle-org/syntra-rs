//! Production ABI regressions exercise the actual shared Host/Initiator.
use super::*;
use prost::Message;

pub(super) unsafe extern "C" fn authenticate(
    _: usize,
    credential: *const u8,
    len: usize,
    principal: *mut u8,
    cap: usize,
    out: *mut usize,
) -> i32 {
    // SAFETY: bridge supplies bounded, live borrowed buffers for this callback.
    if unsafe { bytes(credential, len, 8192) }.unwrap() != b"token" || cap < 4 {
        return 16;
    }
    // SAFETY: bridge supplies a nonoverlapping writable buffer and scalar.
    unsafe {
        ptr::copy_nonoverlapping(b"user".as_ptr(), principal, 4);
        out.write(4);
    }
    0
}
pub(super) unsafe extern "C" fn authorize(
    _: usize,
    _: *const u8,
    _: usize,
    method: *const u8,
    len: usize,
) -> i32 {
    // SAFETY: bridge supplies a live immutable method buffer.
    if unsafe { bytes(method, len, 512) }.unwrap() == b"/test.Service/Denied" {
        7
    } else {
        0
    }
}

pub(super) struct Peer {
    pub(super) p: *mut syntra_t,
    pub(super) g: u64,
}
impl Peer {
    pub(super) fn client() -> Self {
        let (mut p, mut g) = (ptr::null_mut(), 0);
        // SAFETY: independent live outputs; owner retained through Drop.
        assert_eq!(unsafe { syntra_client_open(1, &mut p, &mut g) }, OK);
        Self { p, g }
    }
    fn host() -> Self {
        let (mut p, mut g) = (ptr::null_mut(), 0);
        let policy = syntra_policy_t {
            context: 0,
            authenticate: Some(authenticate),
            authorize: Some(authorize),
        };
        // SAFETY: static callback lifetime, independent live outputs.
        assert_eq!(unsafe { syntra_host_open(1, policy, &mut p, &mut g) }, OK);
        Self { p, g }
    }
    fn handshake(&self) -> u64 {
        let mut token = 0;
        // SAFETY: live owner/input/output with no aliasing.
        assert_eq!(
            unsafe { syntra_handshake(self.p, self.g, b"token".as_ptr(), 5, &mut token) },
            OK
        );
        token
    }
    fn call(&self, timeout: u32) -> u64 {
        self.method_call(b"/test.Service/Echo", timeout)
    }
    fn method_call(&self, method: &[u8], timeout: u32) -> u64 {
        let mut token = 0;
        // SAFETY: immutable live inputs, distinct writable token output.
        assert_eq!(
            unsafe {
                syntra_call(
                    self.p,
                    self.g,
                    method.as_ptr(),
                    method.len(),
                    b"payload".as_ptr(),
                    7,
                    timeout,
                    &mut token,
                )
            },
            OK
        );
        token
    }
    fn poll(&self, token: u64) -> Option<(i32, u64, Vec<u8>)> {
        let (mut code, mut id, mut p, mut len) = (0, 0, ptr::null_mut(), 0);
        // SAFETY: live owner and all independent outputs; buffer consumed once.
        let rc =
            unsafe { syntra_poll(self.p, self.g, token, &mut code, &mut id, &mut p, &mut len) };
        if rc == EMPTY {
            return None;
        }
        assert_eq!(rc, OK);
        Some((code, id, take_buffer(p, len)))
    }
    fn emit(&self) -> Option<(u64, Vec<u8>)> {
        let (mut token, mut p, mut len) = (0, ptr::null_mut(), 0);
        // SAFETY: live owner/output buffers; owned data copied/freed once.
        let rc = unsafe { syntra_emit(self.p, self.g, &mut token, &mut p, &mut len) };
        if rc == EMPTY {
            return None;
        }
        assert_eq!(rc, OK);
        Some((token, take_buffer(p, len)))
    }
    fn emitted(&self, token: u64) {
        // SAFETY: owner live, whole unit delivered before this acknowledgement.
        assert_eq!(unsafe { syntra_emitted(self.p, self.g, token) }, OK);
    }
    fn receipt(&self) -> u64 {
        let mut token = 0;
        // SAFETY: owner live, required scalar output valid.
        assert_eq!(unsafe { syntra_receipt(self.p, self.g, &mut token) }, OK);
        token
    }
    fn ingest(&self, data: &[u8]) {
        let receipt = self.receipt();
        // SAFETY: immutable complete frame, valid receipt and owner.
        assert_eq!(
            unsafe { syntra_ingest(self.p, self.g, receipt, data.as_ptr(), data.len()) },
            OK
        );
    }
    fn dispatch(&self) -> Option<u64> {
        let (mut token, mut m, mut ml, mut p, mut pl) = (0, ptr::null_mut(), 0, ptr::null_mut(), 0);
        // SAFETY: all required output regions are independent/live.
        let rc = unsafe {
            syntra_take_dispatch(self.p, self.g, &mut token, &mut m, &mut ml, &mut p, &mut pl)
        };
        if rc == EMPTY {
            return None;
        }
        assert_eq!(rc, OK);
        assert_eq!(take_buffer(m, ml), b"/test.Service/Echo");
        assert_eq!(take_buffer(p, pl), b"payload");
        Some(token)
    }
    fn complete(&self, token: u64) -> i32 {
        // SAFETY: external test work has stopped; immutable payload copied.
        unsafe { syntra_complete(self.p, self.g, token, 0, b"answer".as_ptr(), 6) }
    }
    fn cancel(&self, token: u64) {
        // SAFETY: owner live, operation token came from call on this owner.
        assert_eq!(unsafe { syntra_cancel(self.p, self.g, token) }, OK);
    }
}
fn take_buffer(p: *mut u8, len: usize) -> Vec<u8> {
    // SAFETY: helpers pass only the bridge's owned buffer/original length.
    let data = unsafe { bytes(p, len, MAX_FRAME_BYTES).unwrap() };
    // SAFETY: exactly one free, no subsequent accesses.
    unsafe {
        syntra_free(p, len);
    }
    data
}
pub(super) fn until<T>(mut f: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(value) = f() {
            return value;
        }
        assert!(Instant::now() < deadline, "test progress deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn pump(a: &Peer, b: &Peer) {
    if let Some((token, data)) = a.emit() {
        b.ingest(&data);
        a.emitted(token);
    }
}
fn pair() -> (Peer, Peer) {
    let c = Peer::client();
    let h = Peer::host();
    let handshake = c.handshake();
    let result = until(|| {
        pump(&c, &h);
        pump(&h, &c);
        c.poll(handshake)
    });
    assert_eq!(result.0, 0);
    assert!(!result.2.is_empty());
    (c, h)
}
impl Drop for Peer {
    fn drop(&mut self) {
        // SAFETY: exclusive owner; test closes carrier and joins before free.
        unsafe {
            assert_eq!(syntra_shutdown(self.p, self.g, 100), OK);
            assert_eq!(syntra_transport_closed(self.p, self.g), OK);
            let mut attempts = 0;
            until(|| {
                attempts += 1;
                let code = syntra_shutdown_poll(self.p, self.g);
                if attempts == 1000 {
                    eprintln!(
                        "shutdown diagnostic generation {}: {:?}",
                        self.g,
                        owner(self.p, self.g).unwrap().endpoint.shutdown_report()
                    );
                }
                assert!(matches!(code, OK | EMPTY | INCOMPLETE), "shutdown {code}");
                (code == OK).then_some(())
            });
            assert_eq!(syntra_shutdown_poll(self.p, self.g), OK);
            assert_eq!(syntra_destroy(self.p, self.g), OK);
        }
    }
}

#[test]
fn actual_runtime_sixteen_calls_reverse_completion_and_tokens() {
    let (c, h) = pair();
    let calls: Vec<_> = (0..16).map(|_| c.call(2000)).collect();
    let mut dispatches = vec![];
    until(|| {
        pump(&c, &h);
        if let Some(d) = h.dispatch() {
            dispatches.push(d);
        }
        (dispatches.len() == 16).then_some(())
    });
    for token in dispatches.iter().rev() {
        assert_eq!(h.complete(*token), OK);
    }
    assert_eq!(h.complete(dispatches[0]), STALE);
    let mut ids = vec![];
    for token in calls {
        let result = until(|| {
            pump(&h, &c);
            c.poll(token)
        });
        assert_eq!(result.0, 0);
        assert_eq!(result.2, b"answer");
        ids.push(result.1);
    }
    assert!(ids.windows(2).all(|ids| ids[0] < ids[1]));
    assert_eq!(syntra_capabilities(), 1 | 4 | 8);
    assert_eq!(SYNTRA_CAP_RECORD_PROTECTION, 2);
    assert_eq!(syntra_capabilities() & SYNTRA_CAP_RECORD_PROTECTION, 0);
    assert_eq!(syntra_abi_version(), 1);
}

#[test]
fn cancel_before_emission_suppresses_original_runtime_unit() {
    let (c, h) = pair();
    let token = c.call(2000);
    c.cancel(token);
    let result = until(|| c.poll(token));
    assert_eq!(result.0, 1);
    // Allow the runtime to enqueue before cancelling too: neither old nor new
    // unit may appear as a request after the shared handoff gate retires it.
    while let Some((emission, bytes)) = c.emit() {
        let frame = syntra_core::Frame::decode(bytes.as_slice()).unwrap();
        assert!(!matches!(
            frame.body,
            Some(syntra_core::proto::frame::Body::Request(_))
        ));
        c.emitted(emission);
    }
    assert!(h.dispatch().is_none());
}

#[test]
fn expired_receipt_does_not_dispatch_and_receipts_are_fifo() {
    let (c, h) = pair();
    let token = c.call(25);
    let (emission, bytes) = until(|| c.emit());
    let old = h.receipt();
    let later = h.receipt();
    std::thread::sleep(Duration::from_millis(40));
    // SAFETY: live owner and copied complete frame; wrong ticket is rejected.
    unsafe {
        assert_eq!(
            syntra_ingest(h.p, h.g, later, bytes.as_ptr(), bytes.len()),
            STALE
        );
        assert_eq!(
            syntra_ingest(h.p, h.g, old, bytes.as_ptr(), bytes.len()),
            OK
        );
    }
    c.emitted(emission);
    let result = until(|| {
        pump(&h, &c);
        c.poll(token)
    });
    assert_eq!(result.0, 4);
    std::thread::sleep(Duration::from_millis(5));
    assert!(h.dispatch().is_none());
}

#[test]
fn partial_emission_is_immutable_and_foreign_execution_retains_shutdown() {
    let (c, h) = pair();
    let call = c.call(1000);
    let (emission, frame) = until(|| c.emit());
    c.cancel(call);
    let mut unused = 0;
    let (mut p, mut len) = (ptr::null_mut(), 0);
    // SAFETY: independent valid outputs; pending partial unit remains owned.
    assert_eq!(
        unsafe { syntra_emit(c.p, c.g, &mut unused, &mut p, &mut len) },
        BUSY
    );
    h.ingest(&frame); // immutable original bytes, despite local cancellation
    c.emitted(emission);
    let dispatch = until(|| h.dispatch());
    // SAFETY: wrong generation cannot consume the current dispatch lease.
    assert_eq!(
        unsafe { syntra_complete(h.p, c.g, dispatch, 0, ptr::null(), 0) },
        STALE
    );
    // SAFETY: live owner and immutable lifetime; retained shutdown is polled.
    unsafe {
        assert_eq!(syntra_shutdown(h.p, h.g, 2), OK);
        assert_eq!(syntra_transport_closed(h.p, h.g), OK);
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(syntra_shutdown_poll(h.p, h.g), INCOMPLETE);
        assert_eq!(syntra_destroy(h.p, h.g), BUSY);
    }
    assert!(matches!(h.complete(dispatch), OK | STALE));
    assert_eq!(until(|| c.poll(call)).0, 1);
}

#[test]
fn authorization_denial_and_withdrawal_use_shared_host() {
    let (c, h) = pair();
    let denied = c.method_call(b"/test.Service/Denied", 1000);
    assert_eq!(
        until(|| {
            pump(&c, &h);
            pump(&h, &c);
            c.poll(denied)
        })
        .0,
        7
    );
    assert!(h.dispatch().is_none());
    let call = c.call(1000);
    let dispatch = until(|| {
        pump(&c, &h);
        h.dispatch()
    });
    // SAFETY: live shared Host; withdrawal retains runtime close continuation.
    assert_eq!(unsafe { syntra_withdraw(h.p, h.g) }, OK);
    assert_eq!(
        until(|| {
            pump(&h, &c);
            c.poll(call)
        })
        .0,
        16
    );
    assert!(matches!(h.complete(dispatch), OK | STALE));
}

#[test]
fn invalid_outputs_do_not_consume_units_or_dispatches() {
    let (c, h) = pair();
    let call = c.call(1000);
    let mut len = 0;
    let mut token = 0;
    // SAFETY: NULL output deliberately tests validation before handoff.
    assert_eq!(
        unsafe { syntra_emit(c.p, c.g, &mut token, ptr::null_mut(), &mut len) },
        INVALID
    );
    let dispatch = until(|| {
        pump(&c, &h);
        h.dispatch()
    });
    assert_eq!(h.complete(dispatch), OK);
    assert_eq!(
        until(|| {
            pump(&h, &c);
            c.poll(call)
        })
        .0,
        0
    );
}

#[test]
fn notification_queue_and_repeated_waiters_are_shared_runtime_backed() {
    let (c, h) = pair();
    for _ in 0..2 {
        let (mut sent, mut received) = (0, 0);
        // SAFETY: live owners and independent scalar output tokens.
        unsafe {
            assert_eq!(syntra_notify(h.p, h.g, b"event".as_ptr(), 5, &mut sent), OK);
            assert_eq!(syntra_next_notification(c.p, c.g, &mut received), OK);
        }
        assert_eq!(until(|| h.poll(sent)).0, 0);
        assert_eq!(
            until(|| {
                pump(&h, &c);
                c.poll(received)
            })
            .2,
            b"event"
        );
    }
}

#[test]
fn selected_result_survives_late_foreign_poll_and_cancel() {
    let (c, h) = pair();
    let call = c.call(200);
    let dispatch = until(|| {
        pump(&c, &h);
        h.dispatch()
    });
    assert_eq!(h.complete(dispatch), OK);
    until(|| {
        pump(&h, &c);
        // SAFETY: peer owns a live owner; the lock only observes the job.
        let owner = unsafe { owner(c.p, c.g) }.unwrap();
        owner
            .state
            .lock()
            .unwrap()
            .jobs
            .get_mut(&call)
            .unwrap()
            .observe()
            .then_some(())
    });
    std::thread::sleep(Duration::from_millis(220));
    c.cancel(call);
    let result = c.poll(call).unwrap();
    assert_eq!(result.0, 0);
    assert_eq!(result.2, b"answer");
}

#[test]
fn unread_operations_bound_admission_and_invalid_poll_is_retryable() {
    let (c, _h) = pair();
    let calls: Vec<_> = (0..LIMIT).map(|_| c.call(1000)).collect();
    let mut token = 0;
    // SAFETY: live inputs and output; full foreign operation slots reject
    // admission independently of Core pending/selected lifetime.
    assert_eq!(
        unsafe {
            syntra_call(
                c.p,
                c.g,
                b"/test.Service/Echo".as_ptr(),
                18,
                ptr::null(),
                0,
                1000,
                &mut token,
            )
        },
        BUSY
    );
    for call in &calls {
        c.cancel(*call);
    }
    let (mut code, mut id, mut len) = (0, 0, 0);
    // SAFETY: NULL required buffer output deliberately rejected before taking
    // the terminal result; every other output is independent and valid.
    assert_eq!(
        unsafe {
            syntra_poll(
                c.p,
                c.g,
                calls[0],
                &mut code,
                &mut id,
                ptr::null_mut(),
                &mut len,
            )
        },
        INVALID
    );
    for call in calls {
        assert_eq!(until(|| c.poll(call)).0, 1);
    }
}

#[test]
fn task_panic_is_internal_and_failed_owner_is_joined_before_destroy() {
    let h = open(None).unwrap();
    let generation = h.generation;
    let job = h
        .submit(async { panic!("synthetic bridge job panic") }, None)
        .unwrap();
    let p = Box::into_raw(h);
    let (mut code, mut id, mut data, mut len) = (0, 0, ptr::null_mut(), 0);
    // SAFETY: this test retains exclusive ownership of the raw Box until the
    // final destroy, and supplies independent required output scalars.
    unsafe {
        until(|| {
            let rc = syntra_poll(p, generation, job, &mut code, &mut id, &mut data, &mut len);
            (rc != EMPTY).then(|| assert_eq!(rc, INTERNAL))
        });
        assert_eq!(syntra_shutdown(p, generation, 100), OK);
        assert_eq!(syntra_transport_closed(p, generation), OK);
        until(|| {
            let rc = syntra_shutdown_poll(p, generation);
            if rc == INTERNAL {
                assert_eq!(syntra_destroy(p, generation), OK);
                Some(())
            } else {
                assert!(matches!(rc, EMPTY | INCOMPLETE));
                None
            }
        });
    }
}

#[test]
fn remote_cancel_keeps_foreign_lease_until_stopped_acknowledgement() {
    let (c, h) = pair();
    let call = c.call(1000);
    let dispatch = until(|| {
        pump(&c, &h);
        h.dispatch()
    });
    c.cancel(call);
    assert_eq!(until(|| c.poll(call)).0, 1);
    until(|| {
        pump(&c, &h);
        let mut cancelled = 0;
        // SAFETY: live owner, delivered dispatch token, independent scalar.
        assert_eq!(
            unsafe { syntra_dispatch_cancelled(h.p, h.g, dispatch, &mut cancelled) },
            OK
        );
        (cancelled == 1).then_some(())
    });
    // SAFETY: test owns the live handle; observing runtime accounting is safe.
    let owner = unsafe { owner(h.p, h.g) }.unwrap();
    let Endpoint::Host(host) = &owner.endpoint else {
        panic!("host")
    };
    assert_eq!(host.execution_len(), 1);
    // The acknowledgement is accepted as stopped work even if the candidate
    // result is now stale; it cannot correlate to a different admitted call.
    assert!(matches!(h.complete(dispatch), OK | STALE));
    until(|| (host.execution_len() == 0).then_some(()));
    assert_eq!(h.complete(dispatch), STALE);
}

#[test]
fn prepare_handoff_subtracts_queue_delay_and_cannot_be_repeated() {
    let (c, _h) = pair();
    let call = c.call(1000);
    std::thread::sleep(Duration::from_millis(30));
    let (emission, bytes) = until(|| c.emit());
    let frame = syntra_core::Frame::decode(bytes.as_slice()).unwrap();
    let Some(syntra_core::proto::frame::Body::Request(request)) = frame.body else {
        panic!("request")
    };
    assert!(request.timeout_ms > 0 && request.timeout_ms <= 970);
    c.emitted(emission);
    // SAFETY: live owner; duplicate acknowledgement cannot release another unit.
    assert_eq!(unsafe { syntra_emitted(c.p, c.g, emission) }, STALE);
    c.cancel(call);
    assert_eq!(until(|| c.poll(call)).0, 1);
}
