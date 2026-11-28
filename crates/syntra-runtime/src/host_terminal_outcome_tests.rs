//! Classifier regressions using one fresh, explicitly supplied observation per read.
use super::*;

const METHOD: &str = "/example.Authority/Resolve";

#[derive(Default)]
struct Evidence(Mutex<Option<OutcomeEvidence>>);

impl Authority for Evidence {
    fn observe(&self, _: Option<Transition>) -> BoxFuture<'_, Observation> {
        Box::pin(async { Observation::Active { revision: 7 } })
    }

    fn observe_outcome_with_budget(
        &self,
        _: Transition,
        _: ElapsedDeadline,
    ) -> BoxFuture<'_, OutcomeEvidence> {
        Box::pin(async { self.0.lock().unwrap().take().unwrap() })
    }

    fn commit(&self, _: Transition, _: ExecutionLease) -> BoxFuture<'_, ()> {
        panic!("test drives commit evidence explicitly")
    }
}

fn install(count: usize) -> (Arc<Host>, Arc<Evidence>, Result<Arc<Coordinator>, Refused>) {
    let (host, _) = Host::new(
        ConnectionConfig::default(),
        Arc::new(crate::AllowAnonymous),
        Arc::new(super::super::FnHandler(|_, p, _| async {
            HandlerOutcome::Payload(p)
        })),
    );
    let authority = Arc::new(Evidence::default());
    // IDs 1 and 8 alias in bytes; ID 2 is a distinct but allowlisted guess.
    let entries = (0..count)
        .map(|i| if i == 1 { vec![1] } else { vec![] })
        .collect();
    let result = host.install_terminal_methods_tcp(MethodPolicy {
        methods: [(METHOD.into(), MethodReceipts::Outcomes(entries))].into(),
        authority: authority.clone(),
        read_timeout: Duration::from_millis(100),
    });
    (host, authority, result)
}

#[tokio::test]
async fn outcome_table_must_have_one_to_eight_entries() {
    for count in [0, 1, 8, 9] {
        let (host, _, result) = install(count);
        assert_eq!(result.is_ok(), (1..=8).contains(&count));
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn install_bounds_the_complete_receipt_for_every_supported_call() {
    // With a ten-byte request ID, these payloads fill the frame exactly at
    // one- and five-byte versions, respectively (including both nested lengths).
    for (version, exact) in [(1, 1005), (u32::MAX, 1001)] {
        for (size, expected_bytes) in [(exact, 1024), (exact + 1, 1025)] {
            let frame = Frame {
                version,
                request_id: u64::MAX,
                body: Some(Body::Result(RpcResult {
                    outcome: Some(outcome_payload(vec![0; size])),
                })),
            };
            assert_eq!(prost::Message::encode_to_vec(&frame).len(), expected_bytes);
            for receipts in [
                MethodReceipts::Fixed(vec![0; size]),
                MethodReceipts::Outcomes(vec![vec![], vec![0; size]]),
            ] {
                let (host, _) = Host::new_with_versions(
                    ConnectionConfig::default(),
                    Arc::new(crate::AllowAnonymous),
                    Arc::new(super::super::FnHandler(|_, p, _| async {
                        HandlerOutcome::Payload(p)
                    })),
                    vec![version, 1],
                );
                let result = host.install_terminal_methods_tcp(MethodPolicy {
                    methods: [(METHOD.into(), receipts)].into(),
                    authority: Arc::new(Evidence::default()),
                    read_timeout: Duration::from_millis(100),
                });
                if size == exact {
                    let c = result.unwrap();
                    c.refresh().await.unwrap();
                    c.reserve(
                        METHOD,
                        u64::MAX,
                        version,
                        c.clock.now() + Duration::from_secs(1),
                        7,
                        Principal::new("fixture"),
                    )
                    .unwrap();
                    assert_eq!(
                        c.state.lock().unwrap().frames.last().unwrap().len(),
                        MAX_RECEIPT_FRAME_BYTES
                    );
                } else {
                    assert!(matches!(result, Err(Refused::Unsupported)));
                    assert!(host.terminal_coordinator().is_none());
                }
                host.close().await;
            }
        }
    }
}

/// Reserve and model the interval after the barrier while commit is in flight.
async fn committing() -> (Arc<Host>, Arc<Coordinator>, Arc<Evidence>, ReservationId) {
    let (host, authority, result) = install(8);
    let c = result.unwrap();
    c.refresh().await.unwrap();
    c.reserve(
        METHOD,
        123,
        1,
        c.clock.now() + Duration::from_secs(1),
        7,
        Principal::new("fixture"),
    )
    .unwrap();
    let owner = {
        let mut s = c.state.lock().unwrap();
        s.phase = Phase::Committing;
        s.claim.as_ref().unwrap().reservation.clone()
    };
    (host, c, authority, owner)
}

fn owned(
    owner: &ReservationId,
    expected_revision: u64,
    revision: u64,
    id: Option<u8>,
) -> OutcomeEvidence {
    let withdrawal = OwnedWithdrawal {
        reservation: owner.clone(),
        expected_revision,
        revision,
    };
    match id {
        Some(outcome_id) => OutcomeEvidence::OwnedOutcome {
            withdrawal,
            outcome_id,
        },
        None => OutcomeEvidence::OwnedPending(withdrawal),
    }
}

#[tokio::test(start_paused = true)]
async fn pending_pins_owner_and_revisions_and_never_repairs_uncertainty() {
    for case in 0..12 {
        let (host, c, a, owner) = committing().await;
        *a.0.lock().unwrap() = Some(owned(&owner, 7, 11, None));
        c.refresh().await.unwrap();
        assert!(c.state.lock().unwrap().final_bytes().is_none());
        let denied = match case {
            0 => owned(&ReservationId([0; 32]), 7, 11, None),
            1 => owned(&owner, 8, 11, None),
            2 => owned(&owner, 7, 7, None),
            3 => owned(&owner, 7, 12, None),
            4 => owned(&owner, 7, 12, Some(1)),
            5 => owned(&owner, 7, 11, Some(0)),
            6 => owned(&owner, 7, 11, Some(9)),
            7 => OutcomeEvidence::Binding(Observation::Active { revision: 7 }),
            8 => OutcomeEvidence::Binding(Observation::Unknown),
            9 => OutcomeEvidence::Binding(Observation::HardDenied),
            10 => OutcomeEvidence::Binding(Observation::OwnedCommitted {
                reservation: owner.clone(),
                expected_revision: 7,
                revision: 11,
            }),
            _ => owned(&ReservationId([0; 32]), 7, 11, Some(1)),
        };
        *a.0.lock().unwrap() = Some(denied);
        assert_eq!(c.refresh().await, Err(Refused::Unavailable), "case {case}");
        *a.0.lock().unwrap() = Some(owned(&owner, 7, 11, Some(1)));
        assert!(c.read_evidence(true).await.is_err());
        assert!(!c.raw_allowed());
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn final_id_cannot_change_or_regress_during_ciphertext_handoff() {
    for id in [None, Some(1)] {
        let (host, c, a, owner) = committing().await;
        *a.0.lock().unwrap() = Some(owned(&owner, 7, 11, Some(8)));
        c.read_evidence(true).await.unwrap();
        c.select(123, &HandlerOutcome::Payload(vec![]));
        let output = TerminalOutput {
            bytes: c.state.lock().unwrap().final_bytes().unwrap().to_vec(),
            reservation: owner.clone(),
            _charge: ExecutionBudget::new(1).try_acquire().unwrap(),
        };
        let mut first = true;
        assert_eq!(c.with_receipt_io(&output, &mut first, || ()), Some(()));
        *a.0.lock().unwrap() = Some(owned(&owner, 7, 11, id));
        assert!(c.refresh().await.is_err());
        assert!(c
            .with_receipt_io(&output, &mut first, || panic!("repoll"))
            .is_none());
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn handler_cannot_guess_early_or_substitute_for_the_final_payload() {
    for after_return in [false, true] {
        let (host, c, a, owner) = committing().await;
        *a.0.lock().unwrap() = Some(owned(&owner, 7, 11, Some(1)));
        c.read_evidence(after_return).await.unwrap();
        // Even the correct bytes before callback return are insufficient.
        let guess = if after_return { vec![1] } else { vec![] };
        c.select(123, &HandlerOutcome::Payload(guess));
        assert!(!c.raw_allowed());
        host.close().await;
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_pending_refreshes_cannot_extend_the_operation_cutoff() {
    let (host, c, a, owner) = committing().await;
    let cutoff = c.cutoff().unwrap();
    while c.clock.now() + Duration::from_millis(75) < cutoff {
        tokio::time::advance(Duration::from_millis(75)).await;
        *a.0.lock().unwrap() = Some(owned(&owner, 7, 11, None));
        c.refresh().await.unwrap();
        assert_eq!(c.cutoff(), Some(cutoff));
    }
    tokio::time::advance(cutoff - c.clock.now()).await;
    assert!(c.refresh().await.is_err());
    host.close().await;
}
