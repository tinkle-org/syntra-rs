use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    Arc,
};
use syntra_runtime::{recovery::wire::*, Principal};

// A single issued live delta; the test serializes its publication after real
// catch-up and the first committed Put, before admission on the successor.
#[derive(Default)]
pub struct History {
    pub published: AtomicBool,
    pub holding_reply: AtomicBool,
    pub first: AtomicUsize,
    pub last: AtomicUsize,
    pub finalizes: AtomicUsize,
    pub rotated: AtomicUsize,
    pub raw_release: tokio::sync::Notify,
}
pub fn delta() -> StoredBatch {
    StoredBatch {
        generation: 3,
        predecessor: b"a".to_vec(),
        result: b"b".to_vec(),
        payload: b"+1".to_vec(),
    }
}
impl RecoverySource for History {
    fn authorize(
        &self,
        p: &Principal,
        s: &[u8],
        _: AuthorizationHook,
    ) -> Result<(), ProviderError> {
        if p.subject == "update-caller" && s == b"feed" {
            Ok(())
        } else {
            Err(ProviderError::PermissionDenied)
        }
    }
    fn capture(&self, p: &Principal, s: &[u8]) -> Result<ProviderStream, ProviderError> {
        self.authorize(p, s, AuthorizationHook::Subscribe)?;
        ProviderStream::new(
            s.to_vec(),
            3,
            if self.published.load(SeqCst) {
                b"b"
            } else {
                b"a"
            }
            .to_vec(),
        )
    }
    fn current_generation(&self, p: &Principal, s: &[u8]) -> Result<u64, ProviderError> {
        self.authorize(p, s, AuthorizationHook::Replay)?;
        Ok(3)
    }
    fn validate_issued(
        &self,
        p: &Principal,
        s: &ProviderStream,
        c: &[u8],
    ) -> Result<(), ProviderError> {
        self.authorize(p, s.identity(), AuthorizationHook::Replay)?;
        if s.generation() == 3 && (c == b"a" || c == b"b" && self.published.load(SeqCst)) {
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
        _: &[u8],
        _: PageBudget,
    ) -> Result<ProviderPage, ProviderError> {
        self.validate_issued(p, s, from)?;
        ProviderPage::new(
            if from == s.boundary() {
                vec![]
            } else {
                vec![delta()]
            },
            s.boundary().to_vec(),
            vec![],
        )
    }
    fn snapshot(
        &self,
        _: &Principal,
        _: &ProviderStream,
    ) -> Result<ProviderSnapshot, ProviderError> {
        Err(ProviderError::Unimplemented)
    }
    fn snapshot_page(
        &self,
        _: &Principal,
        _: &ProviderStream,
        _: &ProviderSnapshot,
        _: u32,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::Unimplemented)
    }
}

pub struct Login(pub Arc<History>, pub Arc<AtomicBool>);
impl syntra_runtime::Authenticator for Login {
    fn authenticate(&self, c: &[u8]) -> Result<Principal, syntra_runtime::AuthError> {
        match c {
            b"fixture-hello" => {
                self.1.store(true, SeqCst);
                Ok(Principal::new("ffi-caller"))
            }
            b"updates-old" if !self.0.published.load(SeqCst) => Ok(Principal::new("update-caller")),
            b"updates-new" if self.0.published.load(SeqCst) => {
                self.0.rotated.fetch_add(1, SeqCst);
                Ok(Principal::new("update-caller"))
            }
            _ => Err(syntra_runtime::AuthError::unauthenticated()),
        }
    }
}
