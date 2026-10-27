//! Regression tests for the proposal-only reliable-session manager.
//! These exercise local state invariants, not negotiated wire conformance.

use syntra_core::error::{ErrorCode, SyntraError};
use syntra_core::reliable::{ControlBounds, LeaseProposal, ReconcileOutcome, SessionId};
use syntra_runtime::{ReliableSessionManager, StoredOutcome};

const METHOD: &str = "/example.Echo/Echo";
const DID: [u8; 16] = [1; 16];
const OTHER: [u8; 16] = [2; 16];

fn bounds() -> ControlBounds {
    ControlBounds {
        result_retention_ms: 10,
        tombstone_retention_ms: 10,
        ..ControlBounds::default()
    }
}

fn proposal() -> LeaseProposal {
    LeaseProposal {
        idle_timeout_ms: 10_000,
        keepalive_interval_ms: 2_000,
    }
}

fn fixture(bounds: ControlBounds) -> (ReliableSessionManager, SessionId, Vec<u8>) {
    let m = ReliableSessionManager::new(bounds).unwrap();
    let (sid, _, cred, _) = m.create_session(0, "svc-a".into(), 1, proposal()).unwrap();
    m.attach(0, &sid.0, &[], "conn-1".into(), "svc-a", 1, proposal())
        .unwrap();
    (m, sid, cred)
}

fn dispatch(
    m: &ReliableSessionManager,
    now: u64,
    sid: SessionId,
    did: &[u8],
) -> Result<(), SyntraError> {
    m.note_dispatch(now, &sid.0, 1, did, METHOD.into(), b"p".to_vec())
}

fn result(
    m: &ReliableSessionManager,
    now: u64,
    sid: SessionId,
    did: &[u8],
    outcome: Vec<u8>,
) -> Result<ReconcileOutcome, SyntraError> {
    m.record_result(
        now,
        &sid.0,
        1,
        did,
        METHOD.into(),
        b"p".to_vec(),
        StoredOutcome::Payload(outcome),
    )
}

fn state(m: &ReliableSessionManager, now: u64, sid: SessionId, did: &[u8]) -> ReconcileOutcome {
    m.reconcile(now, &sid.0, did).unwrap().0
}

fn assert_code<T: std::fmt::Debug>(r: Result<T, SyntraError>, code: ErrorCode) {
    assert_eq!(r.unwrap_err().code(), code);
}

#[test]
fn pending_resends_validate_method_and_payload() {
    let (m, sid, _) = fixture(bounds());
    dispatch(&m, 1, sid, &DID).unwrap();
    dispatch(&m, 2, sid, &DID).unwrap();
    for (method, payload) in [("/example.Echo/Other", b"p".as_slice()), (METHOD, b"q")] {
        assert_code(
            m.note_dispatch(3, &sid.0, 1, &DID, method.into(), payload.to_vec()),
            ErrorCode::FailedPrecondition,
        );
        assert_eq!(state(&m, 3, sid, &DID), ReconcileOutcome::Pending);
    }
    result(&m, 4, sid, &DID, vec![]).unwrap();
    assert_eq!(
        m.reconcile(4, &sid.0, &DID).unwrap(),
        (
            ReconcileOutcome::Retained,
            Some(StoredOutcome::Payload(vec![]))
        )
    );
}

#[test]
fn terminal_result_validates_pending_content_before_mutation() {
    for (method, payload) in [("/example.Echo/Other", b"p".as_slice()), (METHOD, b"q")] {
        let (m, sid, _) = fixture(bounds());
        dispatch(&m, 1, sid, &DID).unwrap();
        assert_code(
            m.record_result(
                2,
                &sid.0,
                1,
                &DID,
                method.into(),
                payload.to_vec(),
                StoredOutcome::Payload(vec![]),
            ),
            ErrorCode::FailedPrecondition,
        );
        assert_eq!(state(&m, 2, sid, &DID), ReconcileOutcome::Pending);
        result(&m, 3, sid, &DID, vec![]).unwrap();
    }
}

#[test]
fn executing_pending_never_expires_or_reaps() {
    let mut b = bounds();
    b.max_retained_results = 1;
    let (m, sid, _) = fixture(b);
    dispatch(&m, 1, sid, &DID).unwrap();
    for now in [11, 12, 100, u64::MAX] {
        assert_eq!(state(&m, now, sid, &DID), ReconcileOutcome::Pending);
        m.reap_expired(now);
        assert_eq!(state(&m, now, sid, &DID), ReconcileOutcome::Pending);
        dispatch(&m, now, sid, &DID).unwrap();
        assert_code(dispatch(&m, now, sid, &OTHER), ErrorCode::ResourceExhausted);
    }
    result(&m, u64::MAX, sid, &DID, vec![]).unwrap();
    assert_eq!(state(&m, u64::MAX, sid, &DID), ReconcileOutcome::Retained);
}

#[test]
fn explicit_forget_cannot_erase_executing_pending() {
    let (m, sid, _) = fixture(bounds());
    dispatch(&m, 1, sid, &DID).unwrap();
    assert_code(
        m.forget(100, &sid.0, 1, &DID),
        ErrorCode::FailedPrecondition,
    );
    assert_eq!(state(&m, 100, sid, &DID), ReconcileOutcome::Pending);
    result(&m, 100, sid, &DID, vec![]).unwrap();
    assert!(m.forget(101, &sid.0, 1, &DID).unwrap());
    assert_eq!(state(&m, 101, sid, &DID), ReconcileOutcome::Forgotten);
}

#[test]
fn pending_admission_enforces_aggregate_bytes_and_idempotent_resends() {
    let charge = METHOD.len() + 1;
    let mut b = bounds();
    b.max_retained_bytes = charge;
    let (m, sid, _) = fixture(b);
    dispatch(&m, 1, sid, &DID).unwrap(); // Exact byte limit.
    dispatch(&m, 2, sid, &DID).unwrap(); // No double charge.
    assert_code(
        m.note_dispatch(2, &sid.0, 1, &OTHER, String::new(), vec![0]),
        ErrorCode::ResourceExhausted,
    );
    assert_eq!(state(&m, 2, sid, &OTHER), ReconcileOutcome::Unknown);
    assert_code(
        result(&m, 3, sid, &DID, vec![0]),
        ErrorCode::ResourceExhausted,
    );
    assert_eq!(state(&m, 3, sid, &DID), ReconcileOutcome::Pending);
    result(&m, 4, sid, &DID, vec![]).unwrap(); // Transfer charge, not add twice.
    assert_code(dispatch(&m, 4, sid, &OTHER), ErrorCode::ResourceExhausted);
    m.forget(5, &sid.0, 1, &DID).unwrap();
    dispatch(&m, 6, sid, &OTHER).unwrap();
}

#[test]
fn pending_and_retained_share_count_and_byte_caps() {
    for byte_cap in [false, true] {
        let charge = METHOD.len() + 1;
        let mut b = bounds();
        if byte_cap {
            b.max_retained_bytes = charge * 2;
        } else {
            b.max_retained_results = 2;
        }
        let (m, sid, _) = fixture(b);
        result(&m, 1, sid, &DID, vec![]).unwrap();
        dispatch(&m, 2, sid, &OTHER).unwrap();
        assert_code(dispatch(&m, 3, sid, &[3; 16]), ErrorCode::ResourceExhausted);
        assert_code(
            result(&m, 3, sid, &[3; 16], vec![]),
            ErrorCode::ResourceExhausted,
        );
        result(&m, 4, sid, &OTHER, vec![]).unwrap();
        assert_eq!(state(&m, 4, sid, &DID), ReconcileOutcome::Retained);
        assert_eq!(state(&m, 4, sid, &OTHER), ReconcileOutcome::Retained);
    }
}

#[test]
fn payload_envelope_bound_is_checked_at_dispatch() {
    let mut b = bounds();
    b.max_retained_bytes = syntra_core::MAX_FRAME_BYTES + METHOD.len() + 1;
    let (m, sid, _) = fixture(b);
    m.note_dispatch(
        1,
        &sid.0,
        1,
        &DID,
        METHOD.into(),
        vec![0; syntra_core::MAX_FRAME_BYTES],
    )
    .unwrap();
    m.record_tombstone(2, &sid.0, 1, &DID, ErrorCode::Cancelled)
        .unwrap();
    assert_code(
        m.note_dispatch(
            3,
            &sid.0,
            1,
            &OTHER,
            METHOD.into(),
            vec![0; syntra_core::MAX_FRAME_BYTES + 1],
        ),
        ErrorCode::ResourceExhausted,
    );
    assert_eq!(state(&m, 3, sid, &OTHER), ReconcileOutcome::Unknown);
}

#[test]
fn dispatch_rejects_stale_zero_and_future_epochs_without_refreshing_activity() {
    let (m, sid, cred) = fixture(bounds());
    m.attach(1, &sid.0, &cred, "conn-2".into(), "svc-a", 1, proposal())
        .unwrap();
    for epoch in [0, 1, 3] {
        assert_code(
            m.note_dispatch(10_000, &sid.0, epoch, &DID, METHOD.into(), b"p".to_vec()),
            ErrorCode::FailedPrecondition,
        );
        assert_eq!(state(&m, 10_000, sid, &DID), ReconcileOutcome::Unknown);
    }
    assert_eq!(m.poll_idle(10_002).unwrap().len(), 1);
    m.note_dispatch(10_003, &sid.0, 2, &DID, METHOD.into(), b"p".to_vec())
        .unwrap();
    assert_eq!(state(&m, 10_003, sid, &DID), ReconcileOutcome::Pending);
}

#[test]
fn expired_result_is_replaced_by_pending_without_reaper() {
    let mut b = bounds();
    b.max_retained_results = 1;
    b.max_retained_bytes = METHOD.len() + 1;
    let (m, sid, _) = fixture(b);
    result(&m, 1, sid, &DID, vec![]).unwrap();
    m.note_dispatch(12, &sid.0, 1, &DID, METHOD.into(), b"q".to_vec())
        .unwrap();
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Pending);
    m.reap_expired(100);
    assert_eq!(state(&m, 100, sid, &DID), ReconcileOutcome::Pending);
    assert_code(dispatch(&m, 100, sid, &OTHER), ErrorCode::ResourceExhausted);
}

#[test]
fn expired_forgotten_marker_is_replaced_by_pending_without_reaper() {
    let (m, sid, _) = fixture(bounds());
    m.forget(1, &sid.0, 1, &DID).unwrap();
    dispatch(&m, 11, sid, &DID).unwrap();
    assert_eq!(state(&m, 11, sid, &DID), ReconcileOutcome::Forgotten);
    dispatch(&m, 12, sid, &DID).unwrap();
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Pending);
}

#[test]
fn live_terminal_states_suppress_pending_and_validate_retained_content() {
    let (m, sid, _) = fixture(bounds());
    result(&m, 1, sid, &DID, vec![7]).unwrap();
    dispatch(&m, 11, sid, &DID).unwrap();
    assert_code(
        m.note_dispatch(11, &sid.0, 1, &DID, METHOD.into(), b"q".to_vec()),
        ErrorCode::FailedPrecondition,
    );
    assert_eq!(
        m.reconcile(11, &sid.0, &DID).unwrap().1,
        Some(StoredOutcome::Payload(vec![7]))
    );
    m.record_tombstone(1, &sid.0, 1, &OTHER, ErrorCode::Cancelled)
        .unwrap();
    dispatch(&m, 11, sid, &OTHER).unwrap();
    assert_eq!(state(&m, 11, sid, &OTHER), ReconcileOutcome::Retained);
    dispatch(&m, 12, sid, &OTHER).unwrap();
    assert_eq!(state(&m, 12, sid, &OTHER), ReconcileOutcome::Pending);
}

#[test]
fn rejected_tombstone_keeps_pending_and_its_charge() {
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::InvalidArgument,
        ErrorCode::Internal,
    ] {
        let mut b = bounds();
        b.max_retained_bytes = METHOD.len() + 1;
        let (m, sid, _) = fixture(b);
        dispatch(&m, 1, sid, &DID).unwrap();
        assert_code(
            m.record_tombstone(2, &sid.0, 1, &DID, code),
            ErrorCode::InvalidArgument,
        );
        assert_eq!(state(&m, 2, sid, &DID), ReconcileOutcome::Pending);
        assert_code(dispatch(&m, 2, sid, &OTHER), ErrorCode::ResourceExhausted);
        result(&m, 3, sid, &DID, vec![]).unwrap();
    }
}

#[test]
fn full_tombstone_store_preserves_pending_until_successful_terminal_mutation() {
    let mut b = bounds();
    b.max_tombstones = 1;
    b.max_retained_bytes = METHOD.len() + 1;
    let (m, sid, _) = fixture(b);
    m.record_tombstone(1, &sid.0, 1, &OTHER, ErrorCode::Cancelled)
        .unwrap();
    dispatch(&m, 1, sid, &DID).unwrap();
    assert_code(
        m.record_tombstone(2, &sid.0, 1, &DID, ErrorCode::Cancelled),
        ErrorCode::ResourceExhausted,
    );
    assert_eq!(state(&m, 2, sid, &DID), ReconcileOutcome::Pending);
    assert_code(dispatch(&m, 2, sid, &[3; 16]), ErrorCode::ResourceExhausted);
    m.reap_expired(12);
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Pending);
    m.record_tombstone(12, &sid.0, 1, &DID, ErrorCode::DeadlineExceeded)
        .unwrap();
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Retained);
    dispatch(&m, 13, sid, &[3; 16]).unwrap(); // Pending charge was released.
}

#[test]
fn mismatched_dispatch_after_live_tombstone_rejected() {
    let (m, sid, _) = fixture(bounds());
    dispatch(&m, 1, sid, &DID).unwrap();
    m.record_tombstone(2, &sid.0, 1, &DID, ErrorCode::Cancelled)
        .unwrap();
    // Identical resend stays idempotent and suppressed.
    dispatch(&m, 3, sid, &DID).unwrap();
    assert_eq!(state(&m, 3, sid, &DID), ReconcileOutcome::Retained);
    for (method, payload) in [("/example.Echo/Other", b"p".as_slice()), (METHOD, b"q")] {
        assert_code(
            m.note_dispatch(4, &sid.0, 1, &DID, method.into(), payload.to_vec()),
            ErrorCode::FailedPrecondition,
        );
        assert_eq!(state(&m, 4, sid, &DID), ReconcileOutcome::Retained);
    }
    // Identical still accepted after rejected mismatches.
    dispatch(&m, 5, sid, &DID).unwrap();
    assert_eq!(state(&m, 5, sid, &DID), ReconcileOutcome::Retained);
}

#[test]
fn mismatched_dispatch_after_live_forgotten_rejected() {
    let (m, sid, _) = fixture(bounds());
    result(&m, 1, sid, &DID, vec![]).unwrap();
    assert!(m.forget(2, &sid.0, 1, &DID).unwrap());
    assert_eq!(state(&m, 2, sid, &DID), ReconcileOutcome::Forgotten);
    // Identical resend stays idempotent and suppressed (not new work).
    dispatch(&m, 3, sid, &DID).unwrap();
    assert_eq!(state(&m, 3, sid, &DID), ReconcileOutcome::Forgotten);
    for (method, payload) in [("/example.Echo/Other", b"p".as_slice()), (METHOD, b"q")] {
        assert_code(
            m.note_dispatch(4, &sid.0, 1, &DID, method.into(), payload.to_vec()),
            ErrorCode::FailedPrecondition,
        );
        assert_eq!(state(&m, 4, sid, &DID), ReconcileOutcome::Forgotten);
    }
    dispatch(&m, 5, sid, &DID).unwrap();
    assert_eq!(state(&m, 5, sid, &DID), ReconcileOutcome::Forgotten);
}

#[test]
fn tombstone_over_live_retained_rejected() {
    let (m, sid, _) = fixture(bounds());
    result(&m, 1, sid, &DID, vec![7]).unwrap();
    assert_code(
        m.record_tombstone(2, &sid.0, 1, &DID, ErrorCode::Cancelled),
        ErrorCode::FailedPrecondition,
    );
    assert_eq!(state(&m, 2, sid, &DID), ReconcileOutcome::Retained);
    assert_eq!(
        m.reconcile(2, &sid.0, &DID).unwrap().1,
        Some(StoredOutcome::Payload(vec![7]))
    );
    assert_eq!(m.tombstone_of(2, &sid.0, &DID).unwrap(), None);
}

#[test]
fn tombstone_expiry_boundary_pinned_expire_then_tombstone() {
    let (m, sid, _) = fixture(bounds()); // retention 10
    result(&m, 1, sid, &DID, vec![]).unwrap();
    // Age 10 (11-1) is still live: tombstone must be rejected.
    assert_code(
        m.record_tombstone(11, &sid.0, 1, &DID, ErrorCode::Cancelled),
        ErrorCode::FailedPrecondition,
    );
    assert_eq!(state(&m, 11, sid, &DID), ReconcileOutcome::Retained);
    // Age 11 (12-1) is expired: expire-then-tombstone is allowed.
    m.record_tombstone(12, &sid.0, 1, &DID, ErrorCode::Cancelled)
        .unwrap();
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Retained);
    // Tombstone carried the expired retained content: identical validates,
    // mismatched rejects.
    dispatch(&m, 13, sid, &DID).unwrap();
    assert_code(
        m.note_dispatch(13, &sid.0, 1, &DID, METHOD.into(), b"q".to_vec()),
        ErrorCode::FailedPrecondition,
    );
}

#[test]
fn rejected_replacement_does_not_erase_expired_terminal_state() {
    let mut b = bounds();
    b.max_retained_bytes = METHOD.len() + 1;
    let (m, sid, _) = fixture(b);
    result(&m, 1, sid, &DID, vec![]).unwrap();
    assert_code(
        m.note_dispatch(12, &sid.0, 1, &DID, METHOD.into(), vec![0; 2]),
        ErrorCode::ResourceExhausted,
    );
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Forgotten);
    assert_code(
        result(&m, 12, sid, &DID, vec![0]),
        ErrorCode::ResourceExhausted,
    );
    assert_eq!(state(&m, 12, sid, &DID), ReconcileOutcome::Forgotten);
    dispatch(&m, 13, sid, &DID).unwrap();
    assert_eq!(state(&m, 13, sid, &DID), ReconcileOutcome::Pending);
}
