//! Source-inclusion persistence contracts, including native test-only crash cuts.
//! The public runtime's FileRecoveryStore/client integration is additionally
//! exercised through tests/recovery_wire.rs; these copies expose no fault API.
#[path = "../src/recovery/persistence.rs"]
mod persistence;

use persistence::{
    DurableRecord, ExpectedPosition, MemoryRecoveryStore, PersistenceError, PersistenceScope,
    RecoveryPersistence, StoreLimits, MAX_CHECKPOINT_BYTES, MAX_SCOPE_BYTES,
};

fn scope(principal: &[u8], stream: &[u8]) -> PersistenceScope {
    PersistenceScope::new(principal.to_vec(), stream.to_vec()).unwrap()
}

fn record(generation: u64, checkpoint: &[u8], state: &[u8]) -> DurableRecord {
    DurableRecord {
        generation,
        checkpoint: checkpoint.to_vec(),
        application_state: state.to_vec(),
    }
}

fn contract(store: &mut dyn RecoveryPersistence) {
    let a = scope(b"private-principal-a", b"stable-stream");
    let b = scope(b"private-principal-b", b"stable-stream");
    let c = scope(b"private-principal-a", b"another-stream");
    let old = record(1, b"private-checkpoint-a", b"complete application state a");
    let new = record(2, b"private-checkpoint-b", b"complete replacement state b");
    assert_eq!(store.load(&a).unwrap(), None);
    store.commit(&a, None, old.clone()).unwrap();
    assert_eq!(store.load(&a).unwrap(), Some(old.clone()));
    assert_eq!(store.load(&b).unwrap(), None);
    assert_eq!(store.load(&c).unwrap(), None);
    assert_eq!(
        store.commit(&a, None, new.clone()),
        Err(PersistenceError::Conflict)
    );
    let wrong_generation = ExpectedPosition {
        generation: 9,
        checkpoint: old.checkpoint.clone(),
    };
    let wrong_checkpoint = ExpectedPosition {
        generation: 1,
        checkpoint: b"wrong".to_vec(),
    };
    for expected in [wrong_generation, wrong_checkpoint] {
        assert_eq!(
            store.commit(&a, Some(&expected), new.clone()),
            Err(PersistenceError::Conflict)
        );
    }
    let expected = ExpectedPosition::from(&old);
    assert_eq!(
        store.commit(&b, Some(&expected), new.clone()),
        Err(PersistenceError::Conflict)
    );
    store.commit(&a, Some(&expected), new.clone()).unwrap();
    // A lost successful reply can be retried without rewriting anything.
    store.commit(&a, Some(&expected), new.clone()).unwrap();
    store.commit(&a, None, new.clone()).unwrap();
    assert_eq!(store.load(&a).unwrap(), Some(new.clone()));
    let mut changed_state = new.clone();
    changed_state.application_state.push(0);
    assert_eq!(
        store.commit(&a, Some(&expected), changed_state),
        Err(PersistenceError::Conflict)
    );
    store.commit(&b, None, old.clone()).unwrap();
    store.commit(&c, None, old.clone()).unwrap();
    assert_eq!(store.load(&b).unwrap(), Some(old.clone()));
    assert_eq!(store.load(&c).unwrap(), Some(old));
    assert_eq!(store.load(&a).unwrap(), Some(new));
}

#[test]
fn memory_reference_contract_and_failure_is_atomic() {
    let mut store = MemoryRecoveryStore::new();
    contract(&mut store);
    let scope = scope(b"failure-principal", b"failure-stream");
    let old = record(1, b"a", b"old full state");
    let new = record(1, b"b", b"new full state");
    store.commit(&scope, None, old.clone()).unwrap();
    store.fail_next_commit();
    store.commit(&scope, None, old.clone()).unwrap(); // no effects, injection not consumed
    assert_eq!(
        store.commit(&scope, Some(&(&old).into()), new.clone()),
        Err(PersistenceError::Unavailable)
    );
    assert_eq!(store.load(&scope).unwrap(), Some(old.clone()));
    store
        .commit(&scope, Some(&(&old).into()), new.clone())
        .unwrap();
    assert_eq!(store.load(&scope).unwrap(), Some(new));
}

#[test]
fn validated_scope_record_limits_and_redaction() {
    assert_eq!(
        PersistenceScope::new(vec![], vec![1]),
        Err(PersistenceError::Corrupt)
    );
    assert_eq!(
        PersistenceScope::new(vec![1], vec![]),
        Err(PersistenceError::Corrupt)
    );
    for (p, s) in [(MAX_SCOPE_BYTES + 1, 1), (1, MAX_SCOPE_BYTES + 1)] {
        assert_eq!(
            PersistenceScope::new(vec![1; p], vec![2; s]),
            Err(PersistenceError::OverLimit)
        );
    }
    let scope = PersistenceScope::new(vec![1; MAX_SCOPE_BYTES], vec![2; MAX_SCOPE_BYTES]).unwrap();
    assert_eq!(scope.principal_scope().len(), MAX_SCOPE_BYTES);
    assert_eq!(scope.stable_stream().len(), MAX_SCOPE_BYTES);
    let limits = StoreLimits {
        max_state_bytes: 8,
        ..StoreLimits::default()
    };
    for bad in [record(0, b"cp", b""), record(1, b"", b"")] {
        assert_eq!(bad.validate(&limits), Err(PersistenceError::Corrupt));
    }
    for bad in [
        record(1, &vec![0; MAX_CHECKPOINT_BYTES + 1], b""),
        record(1, b"cp", &[0; 9]),
    ] {
        assert_eq!(bad.validate(&limits), Err(PersistenceError::OverLimit));
    }
    record(1, &vec![0; MAX_CHECKPOINT_BYTES], &[0; 8])
        .validate(&limits)
        .unwrap();
    record(1, b"cp", b"").validate(&limits).unwrap(); // empty application state is valid
    for limits in [
        StoreLimits {
            max_records: 0,
            ..limits
        },
        StoreLimits {
            max_state_bytes: 0,
            ..limits
        },
        StoreLimits {
            max_total_bytes: 0,
            ..limits
        },
        StoreLimits {
            max_state_bytes: usize::MAX,
            ..limits
        },
        StoreLimits {
            max_total_bytes: usize::MAX,
            ..limits
        },
        StoreLimits {
            max_records: usize::MAX,
            ..limits
        },
    ] {
        assert_eq!(
            MemoryRecoveryStore::with_limits(limits).err(),
            Some(PersistenceError::OverLimit)
        );
    }
    let scope = scope.clone();
    let record = record(123, b"SECRET_CHECKPOINT", b"SECRET_STATE");
    assert_eq!(format!("{scope:?}"), "PersistenceScope([REDACTED])");
    assert_eq!(format!("{record:?}"), "DurableRecord([REDACTED])");
    assert_eq!(
        format!("{:?}", ExpectedPosition::from(&record)),
        "ExpectedPosition([REDACTED])"
    );
    fn send_sync<T: Send + Sync>() {}
    send_sync::<MemoryRecoveryStore>();
    send_sync::<Box<dyn RecoveryPersistence>>();
    use syntra_core::ErrorCode;
    for (error, code) in [
        (PersistenceError::Unavailable, ErrorCode::Unavailable),
        (PersistenceError::Corrupt, ErrorCode::DataLoss),
        (PersistenceError::Conflict, ErrorCode::Aborted),
        (PersistenceError::CommitUnknown, ErrorCode::Unknown),
        (PersistenceError::OverLimit, ErrorCode::ResourceExhausted),
    ] {
        assert_eq!(error.code(), code);
        assert!(!error.to_string().contains("SECRET"));
    }
}

fn capacity_contract(store: &mut dyn RecoveryPersistence, limits: StoreLimits) {
    let a = scope(b"p", b"a");
    let b = scope(b"p", b"b");
    let old = record(1, b"c", b"1234");
    store.commit(&a, None, old.clone()).unwrap();
    let too_big = record(1, b"c", &vec![0; limits.max_state_bytes + 1]);
    assert_eq!(
        store.commit(&a, Some(&(&old).into()), too_big),
        Err(PersistenceError::OverLimit)
    );
    assert_eq!(
        store.commit(&b, None, old.clone()),
        Err(PersistenceError::OverLimit)
    );
    assert_eq!(store.load(&a).unwrap(), Some(old.clone()));
    assert_eq!(store.load(&b).unwrap(), None);
    let smaller = record(1, b"d", b"");
    store
        .commit(&a, Some(&(&old).into()), smaller.clone())
        .unwrap();
    assert_eq!(store.load(&a).unwrap(), Some(smaller));
}

#[test]
fn memory_count_state_and_total_byte_limits() {
    for limits in [
        StoreLimits {
            max_records: 1,
            max_state_bytes: 8,
            max_total_bytes: 1_024,
        },
        StoreLimits {
            max_records: 2,
            max_state_bytes: 8,
            max_total_bytes: 90,
        },
    ] {
        capacity_contract(
            &mut MemoryRecoveryStore::with_limits(limits).unwrap(),
            limits,
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;
    use persistence::FileRecoveryStore;
    use std::{fs, path::PathBuf};

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            // Resolve the OS temp ancestor (e.g. macOS /var) before passing it to
            // the backend, whose API correctly refuses symlink ancestors.
            Self(
                fs::canonicalize(std::env::temp_dir())
                    .unwrap()
                    .join(format!("syntra-persistence-{name}")),
            )
        }

        fn record_paths(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|e| e == "rec"))
                .collect()
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn retained_disk_reopen_contract_and_kernel_lock() {
        let directory = Directory::new();
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        contract(&mut store);
        drop(store);
        let store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        let a = scope(b"private-principal-a", b"stable-stream");
        let expected = record(2, b"private-checkpoint-b", b"complete replacement state b");
        assert_eq!(store.load(&a).unwrap(), Some(expected));
        assert_eq!(directory.record_paths().len(), 3);
    }

    #[test]
    fn file_limits_preflight_before_writing_and_on_reopen() {
        for limits in [
            StoreLimits {
                max_records: 1,
                max_state_bytes: 8,
                max_total_bytes: 1_024,
            },
            StoreLimits {
                max_records: 2,
                max_state_bytes: 8,
                max_total_bytes: 90,
            },
        ] {
            let directory = Directory::new();
            let mut store = FileRecoveryStore::open(&directory.0, limits).unwrap();
            capacity_contract(&mut store, limits);
            assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2); // lock + record, no temp
            drop(store);
            FileRecoveryStore::open(&directory.0, limits).unwrap();
            assert_eq!(
                FileRecoveryStore::open(
                    &directory.0,
                    StoreLimits {
                        max_total_bytes: 1,
                        ..limits
                    }
                )
                .err(),
                Some(PersistenceError::OverLimit)
            );
        }
    }

    #[test]
    fn exact_duplicate_performs_no_filesystem_replacement() {
        let directory = Directory::new();
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        let scope = scope(b"p", b"s");
        let record = record(1, b"cp", b"full state");
        store.commit(&scope, None, record.clone()).unwrap();
        let path = directory.record_paths().pop().unwrap();
        let before = fs::metadata(&path).unwrap();
        store.commit(&scope, None, record).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(before.modified().unwrap(), after.modified().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(before.ino(), after.ino());
        }
    }

    #[test]
    fn swapped_record_names_and_corrupt_bytes_are_not_trusted() {
        let directory = Directory::new();
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        let a = scope(b"ab", b"c");
        let b = scope(b"a", b"bc"); // length-delimited scope hash must differ
        store.commit(&a, None, record(1, b"a", b"state a")).unwrap();
        let pa = directory.record_paths().pop().unwrap();
        store.commit(&b, None, record(1, b"b", b"state b")).unwrap();
        let pb = directory
            .record_paths()
            .into_iter()
            .find(|p| *p != pa)
            .unwrap();
        let ba = fs::read(&pa).unwrap();
        let bb = fs::read(&pb).unwrap();
        fs::write(&pa, &bb).unwrap();
        fs::write(&pb, &ba).unwrap();
        assert_eq!(store.load(&a), Err(PersistenceError::Corrupt));
        assert_eq!(store.load(&b), Err(PersistenceError::Corrupt));
        drop(store);
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Corrupt)
        );
        fs::write(&pb, &bb).unwrap();
        for change in 0..5 {
            let mut bad = ba.clone();
            match change {
                0 => bad[0] ^= 1,  // local magic/version
                1 => bad[48] ^= 1, // embedded scope/checksum
                2 => {
                    bad.pop();
                } // truncation
                3 => bad.push(0),  // trailing data
                _ => bad[8..16].copy_from_slice(&u64::MAX.to_le_bytes()), // length before allocation
            }
            fs::write(&pa, bad).unwrap();
            assert!(matches!(
                FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
                Some(PersistenceError::Corrupt | PersistenceError::OverLimit)
            ));
        }
        fs::write(&pa, ba).unwrap();
        FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_and_symlink_hardlink_special_paths() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = Directory::new();
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        assert_eq!(
            fs::metadata(&directory.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let scope = scope(b"private principal", b"private stream");
        store
            .commit(&scope, None, record(1, b"cp", b"state"))
            .unwrap();
        let path = directory.record_paths().pop().unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let retained = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(".syntra-recovery.lock", &path).unwrap();
        assert_eq!(store.load(&scope), Err(PersistenceError::Unavailable));
        drop(store);
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        fs::remove_file(&path).unwrap();
        fs::write(&path, retained).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.0.join("not-owned");
        fs::hard_link(&path, &link).unwrap();
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = Directory::new();
        symlink(&directory.0, &alias.0).unwrap();
        assert_eq!(
            FileRecoveryStore::open(&alias.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        assert_eq!(
            FileRecoveryStore::open(alias.0.join("child"), StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        fs::remove_file(&alias.0).unwrap();
        let lock = directory.0.join(".syntra-recovery.lock");
        fs::remove_file(&lock).unwrap();
        symlink(&path, &lock).unwrap();
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
    }
}
