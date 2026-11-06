//! Observable compatibility and unsupported-driver regressions.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use syntra_runtime::{
    AllowAll, CancelToken, ConnectionConfig, ExecutionLease, Handler, HandlerFut, HandlerOutcome,
    RequestContext, StaticToken,
};

/// Count context-hook admission after confirming unsupported-driver refusal.
struct Retire(Arc<AtomicUsize>);
impl Handler for Retire {
    /// Fail if the adapter loses the context-aware hook delegation.
    fn handle(&self, _: String, _: Vec<u8>, _: CancelToken) -> HandlerFut {
        panic!("context hook must be forwarded by AllowAll")
    }
    /// Confirm raw-driver refusal before counting the admitted context hook.
    fn handle_with_context(
        &self,
        _: String,
        _: Vec<u8>,
        _: CancelToken,
        _: ExecutionLease,
        context: RequestContext,
    ) -> HandlerFut {
        let effects = self.0.clone();
        Box::pin(async move {
            let result = context.retire(1).await;
            assert!(result.is_err(), "raw driver must refuse before mutation");
            effects.fetch_add(1, Ordering::SeqCst);
            HandlerOutcome::Payload(b"refused".to_vec())
        })
    }
}

/// AllowAll forwards the actual context; a raw loopback driver cannot retire.
#[tokio::test]
async fn raw_driver_refuses_and_allow_all_forwards_context() {
    let effects = Arc::new(AtomicUsize::new(0));
    let (client, host) = syntra_runtime::loopback_pair(
        Arc::new(StaticToken::new(b"fixture".to_vec(), "fixture-subject")),
        Arc::new(AllowAll(Retire(effects.clone()))),
        ConnectionConfig::default(),
    );
    client.handshake(b"fixture".to_vec()).await.unwrap();
    assert_eq!(
        client
            .call("/example.Authority/Retire", vec![], 1000)
            .await
            .unwrap(),
        b"refused"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    client.close().await;
    host.close().await;
}
