//! Candidate HTTP panic boundary. Panics are failed ownership, not an RPC or
//! authentication verdict. The association supervisor still owns all cleanup.
use futures_util::FutureExt;
use std::{
    future::Future,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::watch;

pub(super) struct Failure(watch::Sender<bool>, Mutex<Option<Weak<Failure>>>);
impl Failure {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(watch::channel(false).0, Mutex::new(None)))
    }
    pub fn bind(&self, parent: &Arc<Self>) {
        *self.1.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(parent));
    }
    fn parent(&self) -> Option<Arc<Self>> {
        self.1
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .and_then(Weak::upgrade)
    }
    pub fn mark(&self) {
        self.0.send_replace(true);
        if let Some(parent) = self.parent() {
            parent.mark();
        }
    }
    pub fn failed(&self) -> bool {
        *self.0.borrow() || self.parent().is_some_and(|parent| parent.failed())
    }
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.0.subscribe()
    }
    pub fn catch<T>(&self, work: impl FnOnce() -> T) -> Option<T> {
        match catch_unwind(AssertUnwindSafe(work)) {
            Ok(value) => Some(value),
            Err(_) => {
                self.mark();
                None
            }
        }
    }
    pub async fn catch_async<T>(&self, work: impl Future<Output = T>) -> Option<T> {
        match AssertUnwindSafe(work).catch_unwind().await {
            Ok(value) => Some(value),
            Err(_) => {
                self.mark();
                None
            }
        }
    }
}
