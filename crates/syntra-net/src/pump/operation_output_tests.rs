//! The native writer owns a charge even if correlation and execution are done.
use super::*;
use syntra_runtime::{
    AdmissionRefusal, OperationAuthority, OperationClass, OperationGrant, OperationLimits,
    Principal, QuotaOwnership,
};

const CAP: usize = MAX_PLAINTEXT + 512;
const LARGE: &str = "/test.Media/Large";
const EMPTY: &str = "/test.Media/Empty";

struct Owner;
impl OperationAuthority for Owner {
    fn try_admit(
        &self,
        _: &Principal,
        _: &str,
        _: usize,
    ) -> Result<OperationGrant, AdmissionRefusal> {
        Ok(OperationGrant {
            class: OperationClass::Media,
            response_frame_bytes: CAP,
            ownership: QuotaOwnership::ExclusiveProcess,
        })
    }
}

async fn settle(mut check: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if check() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(check(), "writer/worker did not reach expected state");
}

#[derive(Clone, Copy)]
enum End {
    Complete,
    WriteError,
    Shutdown,
    Suspend,
}

async fn stalled(end: End) {
    let budget = ExecutionBudget::new(4);
    budget
        .configure_operations(
            OperationLimits {
                interactive_executions: 0,
                bytes: 2 * CAP,
                interactive_bytes: 0,
            },
            Arc::new(Owner),
        )
        .unwrap();
    let factory = Arc::new(BudgetFactory(budget.clone()));
    let handler: Arc<dyn Handler> = Arc::new(FnHandler(|method: String, _, _| async move {
        HandlerOutcome::Payload(if method == LARGE {
            vec![7; MAX_PLAINTEXT + 1]
        } else {
            Vec::new()
        })
    }));
    let (client, mut host, gate, _) =
        connected_with_factory(factory.clone(), handler.clone()).await;
    let (other, other_host, _, _) = connected_with_factory(factory, handler).await;
    gate.armed.store(true, Ordering::SeqCst);
    let first = {
        let conn = client.conn.clone();
        tokio::spawn(async move { conn.call(LARGE, vec![], 5000).await })
    };
    gate.entered.acquire().await.unwrap().forget(); // first record sent; final record stalled
    let cancel = CancelToken::new();
    let queued = {
        let conn = client.conn.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { conn.call_cancellable(EMPTY, vec![], 5000, &cancel).await })
    };
    settle(|| host.host.shutdown_report().queued_frames == 1 && host.host.worker_len() == 0).await;
    // Cancel after selection. Even the zero-length payload's correlated frame
    // and the actively writing response still own their full reservations.
    cancel.cancel();
    assert_eq!(
        queued.await.unwrap().unwrap_err().code(),
        ErrorCode::Cancelled
    );
    assert_eq!(budget.in_use(), 0);
    assert_eq!(budget.bytes_in_use(), 2 * CAP);
    let err = other.conn.call(EMPTY, vec![], 5000).await.unwrap_err();
    assert!(matches!(
        err,
        SyntraError::Rpc {
            code: ErrorCode::ResourceExhausted,
            ..
        }
    ));

    match end {
        End::Complete => {
            gate.release.add_permits(1);
            assert_eq!(first.await.unwrap().unwrap(), vec![7; MAX_PLAINTEXT + 1]);
            settle(|| gate.records.load(Ordering::SeqCst) == 3).await; // queued empty result sent too
        }
        End::WriteError => {
            gate.release.close(); // fail the active record, abandon the queue
            assert!(first.await.unwrap().is_err());
            assert_eq!(gate.records.load(Ordering::SeqCst), 2);
        }
        End::Shutdown => {
            host.shutdown_transport(Duration::from_secs(1))
                .await
                .unwrap();
            assert!(first.await.unwrap().is_err());
            assert_eq!(gate.records.load(Ordering::SeqCst), 2);
        }
        End::Suspend => {
            host.suspend(); // close the lifecycle gate before the stalled poll resumes
            gate.release.add_permits(1);
            assert!(first.await.unwrap().is_err());
            assert_eq!(gate.records.load(Ordering::SeqCst), 2);
        }
    }
    settle(|| budget.bytes_in_use() == 0).await;
    assert!(other
        .conn
        .call(EMPTY, vec![], 5000)
        .await
        .unwrap()
        .is_empty());
    tokio::join!(
        client.close(),
        host.close(),
        other.close(),
        other_host.close()
    );
    assert_eq!(budget.bytes_in_use(), 0);
}

#[tokio::test(start_paused = true)]
async fn charged_through_final_record_and_queued_empty_result() {
    stalled(End::Complete).await;
}

#[tokio::test(start_paused = true)]
async fn failed_record_releases_active_and_queued_results() {
    stalled(End::WriteError).await;
}

#[tokio::test(start_paused = true)]
async fn aborting_stalled_writer_releases_active_and_queued_results() {
    stalled(End::Shutdown).await;
}

#[tokio::test(start_paused = true)]
async fn fenced_record_repoll_releases_active_and_queued_results() {
    stalled(End::Suspend).await;
}
