//! Native private-filesystem backend, included only by `persistence`.
//!
//! Threat boundary: a dedicated private directory on a single host, with trusted
//! ancestors and no hostile same-user/root process replacing paths concurrently.
//! Unix directories/files must exclude group/other access; on other platforms
//! the caller MUST provision an equivalent private ACL. Symlinks (including path
//! ancestors), special files, and Unix hard links are refused. Safe std APIs do
//! not provide descriptor-relative no-follow traversal on every supported OS;
//! these checks are not a sandbox against malicious concurrent path replacement.
//!
//! fs2's kernel advisory exclusive lock is held by a private File for the store's
//! entire lifetime, including across processes, and explicitly unlocked on drop
//! only by the acquiring process. A forked child must not use an inherited
//! FileRecoveryStore as an independent owner; dropping its inherited descriptor
//! must not release the parent's lock.
//! Linux/Android ownership also includes the active PID namespace and requires
//! accessible `/proc/self/ns/pid` at acquisition. If identity cannot be checked
//! at drop, only close is attempted; inherited descriptors may delay release.
//! Crash/exit closes the descriptor; the lock file is deliberately never removed.
//! All writers must cooperate.
//! Do not use this on network/shared filesystems or filesystems without atomic
//! same-directory replacement, file sync_all, and parent-directory sync_all.
//! Successful commits rely on those primitives and the storage device honoring
//! flushes. Checksums detect accidental corruption, not malicious modification;
//! scope hashes are filenames, not authentication or encryption. Data is plaintext.
//!
//! The versioned snapshot below is LOCAL ONLY, unrelated to Syntra wire frames.
//! Each snapshot embeds its scope and full application state with its position.
//! Record names are checked against the embedded scope, never trusted alone.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::{
    check_expected, preflight, record_bytes, DurableRecord, ExpectedPosition, PersistenceError,
    PersistenceScope, RecoveryPersistence, StoreLimits, MAX_CHECKPOINT_BYTES, MAX_SCOPE_BYTES,
    RECORD_OVERHEAD,
};

const MAGIC: &[u8; 8] = b"SYNRLCL\x01";
const HEADER_BYTES: usize = RECORD_OVERHEAD - 32;
const LOCK_NAME: &str = ".syntra-recovery.lock";
const TEMP_PREFIX: &str = ".syntra-recovery-tmp-";
const MAX_ORPHANS: usize = 64;

/// Native blocking, single-writer recovery snapshots. See the module's private
/// filesystem and durability assumptions. Keep this off async executor threads.
/// A forked child must not use an inherited store as an independent owner.
/// No Debug implementation exposes its private filesystem path.
pub struct FileRecoveryStore {
    path: PathBuf,
    limits: StoreLimits,
    // Must not be cloned, unlocked early, or removed from the directory.
    _lock: StoreLock,
    fenced: bool,
    #[cfg(test)]
    cut: Option<TestCut>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pid_namespace: (u64, u64),
}

impl ProcessIdentity {
    fn current() -> Result<Self, PersistenceError> {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let pid_namespace = {
            use std::os::unix::fs::MetadataExt;

            // Follow the magic link to the active namespace, not the namespace
            // selected for future children or an inherited namespace descriptor.
            let namespace =
                fs::metadata("/proc/self/ns/pid").map_err(|_| PersistenceError::Unavailable)?;
            (namespace.dev(), namespace.ino())
        };
        Ok(Self {
            pid: std::process::id(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pid_namespace,
        })
    }
}

struct StoreLock {
    file: File,
    owner: ProcessIdentity,
}

impl StoreLock {
    fn acquire(file: File) -> Result<Self, PersistenceError> {
        // Finish fallible identity lookup before acquiring a lock that might be
        // inherited concurrently; every acquired lock must have an unlock guard.
        let owner = ProcessIdentity::current()?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| PersistenceError::Unavailable)?;
        // Only a successful acquisition owns an unlock, including on open errors
        // before FileRecoveryStore has been fully constructed.
        Ok(Self { file, owner })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Linux flock belongs to the open-file description. A concurrent spawn
        // can inherit it until exec closes CLOEXEC descriptors, so close alone
        // need not release it when this owner drops. Unlock before closing; never
        // unlink the stable lock file. A forked child must only close its inherited
        // descriptor, not unlock the shared description owned by the parent.
        // On failure, close remains the fallback.
        if ProcessIdentity::current().is_ok_and(|current| current == self.owner) {
            let _release = fs2::FileExt::unlock(&self.file);
        }
    }
}

struct Inventory {
    count: usize,
    bytes: usize,
    current: Option<DurableRecord>,
}

impl FileRecoveryStore {
    /// Open/create a dedicated directory (not recursively), acquire a kernel
    /// process lock, validate all records and boundedly clean reserved orphan
    /// temps. Existing lock files are normal, not stale-lock errors. Contention,
    /// unsafe paths, or unsupported filesystem primitives return Unavailable.
    pub fn open(path: impl AsRef<Path>, limits: StoreLimits) -> Result<Self, PersistenceError> {
        limits.validate()?;
        let path = absolute_path(path.as_ref())?;
        let parent = path.parent().ok_or(PersistenceError::Unavailable)?;
        check_ancestors(parent)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder
                    .create(&path)
                    .map_err(|_| PersistenceError::Unavailable)?;
                sync_directory(parent).map_err(|_| PersistenceError::Unavailable)?;
            }
            Err(_) => return Err(PersistenceError::Unavailable),
        }
        let directory = check_directory(&path)?;
        let lock_path = path.join(LOCK_NAME);
        let lock = match private_new(&lock_path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                check_file(&lock_path, &directory)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&lock_path)
                    .map_err(|_| PersistenceError::Unavailable)?
            }
            Err(_) => return Err(PersistenceError::Unavailable),
        };
        let lock = StoreLock::acquire(lock)?;
        if lock
            .file
            .metadata()
            .map_err(|_| PersistenceError::Unavailable)?
            .len()
            != 0
        {
            return Err(PersistenceError::Corrupt);
        }
        let store = Self {
            path,
            limits,
            _lock: lock,
            fenced: false,
            #[cfg(test)]
            cut: None,
        };
        store.inventory(None, true)?;
        // Also establish that directory syncing is supported before any commit.
        sync_directory(&store.path).map_err(|_| PersistenceError::Unavailable)?;
        Ok(store)
    }

    fn inventory(
        &self,
        wanted: Option<&PersistenceScope>,
        cleanup: bool,
    ) -> Result<Inventory, PersistenceError> {
        let directory = check_directory(&self.path)?;
        let mut inventory = Inventory {
            count: 0,
            bytes: 0,
            current: None,
        };
        let mut orphans = Vec::new();
        let mut entries = 0usize;
        for entry in fs::read_dir(&self.path).map_err(|_| PersistenceError::Unavailable)? {
            entries = entries.checked_add(1).ok_or(PersistenceError::OverLimit)?;
            if entries > self.limits.max_records.saturating_add(MAX_ORPHANS + 1) {
                return Err(PersistenceError::OverLimit);
            }
            let entry = entry.map_err(|_| PersistenceError::Unavailable)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(PersistenceError::Unavailable)?;
            let metadata = check_file(&entry.path(), &directory)?;
            if name == LOCK_NAME {
                if metadata.len() != 0 {
                    return Err(PersistenceError::Corrupt);
                }
            } else if is_temp(name) {
                if orphans.len() == MAX_ORPHANS
                    || metadata.len() > self.maximum_record_bytes() as u64
                {
                    return Err(PersistenceError::OverLimit);
                }
                orphans.push(entry.path());
            } else if is_record(name) {
                let bytes =
                    usize::try_from(metadata.len()).map_err(|_| PersistenceError::OverLimit)?;
                inventory.count += 1;
                inventory.bytes = preflight(self.limits, inventory.count, inventory.bytes, bytes)?;
                let (scope, record) = self.read_record(&entry.path(), &directory)?;
                if record_name(&scope) != name {
                    return Err(PersistenceError::Corrupt);
                }
                if wanted == Some(&scope) {
                    inventory.current = Some(record);
                }
            } else {
                // A dedicated directory: never delete unrecognized entries.
                return Err(PersistenceError::Unavailable);
            }
        }
        if !orphans.is_empty() {
            if !cleanup {
                return Err(PersistenceError::Unavailable);
            }
            // Validate the entire bounded inventory before removing only exact
            // reserved temp names. Never recurse, follow links, or delete records.
            for path in orphans {
                fs::remove_file(path).map_err(|_| PersistenceError::Unavailable)?;
            }
            sync_directory(&self.path).map_err(|_| PersistenceError::Unavailable)?;
        }
        Ok(inventory)
    }

    fn maximum_record_bytes(&self) -> usize {
        RECORD_OVERHEAD + 2 * MAX_SCOPE_BYTES + MAX_CHECKPOINT_BYTES + self.limits.max_state_bytes
    }

    fn read_record(
        &self,
        path: &Path,
        directory: &Metadata,
    ) -> Result<(PersistenceScope, DurableRecord), PersistenceError> {
        let metadata = check_file(path, directory)?;
        if metadata.len() > self.maximum_record_bytes() as u64
            || metadata.len() > self.limits.max_total_bytes as u64
        {
            return Err(PersistenceError::OverLimit);
        }
        let mut file = File::open(path).map_err(|_| PersistenceError::Unavailable)?;
        let mut header = [0u8; HEADER_BYTES];
        read_exact(&mut file, &mut header)?;
        if &header[..8] != MAGIC {
            return Err(PersistenceError::Corrupt);
        }
        let mut lengths = [0usize; 4];
        for (i, length) in lengths.iter_mut().enumerate() {
            let start = 8 + i * 8;
            *length = usize::try_from(u64::from_le_bytes(
                header[start..start + 8].try_into().expect("fixed header"),
            ))
            .map_err(|_| PersistenceError::OverLimit)?;
        }
        let [principal, stream, checkpoint, state] = lengths;
        if principal > MAX_SCOPE_BYTES
            || stream > MAX_SCOPE_BYTES
            || checkpoint > MAX_CHECKPOINT_BYTES
            || state > self.limits.max_state_bytes
        {
            return Err(PersistenceError::OverLimit);
        }
        let generation = u64::from_le_bytes(header[40..48].try_into().expect("fixed header"));
        if principal == 0 || stream == 0 || checkpoint == 0 || generation == 0 {
            return Err(PersistenceError::Corrupt);
        }
        let payload_len = principal + stream + checkpoint + state;
        if (RECORD_OVERHEAD + payload_len) as u64 != metadata.len() {
            return Err(PersistenceError::Corrupt);
        }
        // All four lengths and their sum were bounded before allocating.
        let mut payload = vec![0; payload_len];
        read_exact(&mut file, &mut payload)?;
        let mut checksum = [0; 32];
        read_exact(&mut file, &mut checksum)?;
        let mut trailing = [0];
        if file
            .read(&mut trailing)
            .map_err(|_| PersistenceError::Unavailable)?
            != 0
        {
            return Err(PersistenceError::Corrupt);
        }
        let mut hash = Sha256::new();
        hash.update(header);
        hash.update(&payload);
        if hash.finalize().as_slice() != checksum {
            return Err(PersistenceError::Corrupt);
        }
        let scope = PersistenceScope::new(
            payload[..principal].to_vec(),
            payload[principal..principal + stream].to_vec(),
        )?;
        let record = DurableRecord {
            generation,
            checkpoint: payload[principal + stream..principal + stream + checkpoint].to_vec(),
            application_state: payload[principal + stream + checkpoint..].to_vec(),
        };
        record.validate(&self.limits)?;
        Ok((scope, record))
    }

    fn write_snapshot(
        &self,
        file: &mut File,
        scope: &PersistenceScope,
        record: &DurableRecord,
    ) -> Result<(), PersistenceError> {
        let mut header = [0; HEADER_BYTES];
        header[..8].copy_from_slice(MAGIC);
        let parts = [
            scope.principal_scope(),
            scope.stable_stream(),
            record.checkpoint.as_slice(),
            record.application_state.as_slice(),
        ];
        for (i, part) in parts.iter().enumerate() {
            header[8 + i * 8..16 + i * 8].copy_from_slice(&(part.len() as u64).to_le_bytes());
        }
        header[40..48].copy_from_slice(&record.generation.to_le_bytes());
        let mut hash = Sha256::new();
        hash.update(header);
        file.write_all(&header)
            .map_err(|_| PersistenceError::Unavailable)?;
        #[cfg(test)]
        self.test_cut(TestCut::AfterHeader)?;
        for part in parts {
            hash.update(part);
            file.write_all(part)
                .map_err(|_| PersistenceError::Unavailable)?;
        }
        file.write_all(&hash.finalize())
            .map_err(|_| PersistenceError::Unavailable)?;
        #[cfg(test)]
        self.test_cut(TestCut::AfterWrite)?;
        file.sync_all().map_err(|_| PersistenceError::Unavailable)?;
        #[cfg(test)]
        self.test_cut(TestCut::BeforeRename)?;
        Ok(())
    }
}

impl RecoveryPersistence for FileRecoveryStore {
    fn load(&self, scope: &PersistenceScope) -> Result<Option<DurableRecord>, PersistenceError> {
        let directory = check_directory(&self.path)?;
        let path = self.path.join(record_name(scope));
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(PersistenceError::Unavailable),
            Ok(_) => {
                let (embedded, record) = self.read_record(&path, &directory)?;
                if embedded != *scope {
                    return Err(PersistenceError::Corrupt);
                }
                Ok(Some(record))
            }
        }
    }

    fn commit(
        &mut self,
        scope: &PersistenceScope,
        expected: Option<&ExpectedPosition>,
        record: DurableRecord,
    ) -> Result<(), PersistenceError> {
        if self.fenced {
            return Err(PersistenceError::CommitUnknown);
        }
        record.validate(&self.limits)?;
        let inventory = self.inventory(Some(scope), false)?;
        if check_expected(inventory.current.as_ref(), expected, &record)? {
            return Ok(());
        }
        let old_bytes = inventory
            .current
            .as_ref()
            .map_or(0, |r| record_bytes(scope, r));
        preflight(
            self.limits,
            inventory.count + usize::from(inventory.current.is_none()),
            inventory.bytes - old_bytes,
            record_bytes(scope, &record),
        )?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| PersistenceError::Unavailable)?;
        let temp = self.path.join(format!("{TEMP_PREFIX}{}", hex(&nonce)));
        let mut file = private_new(&temp).map_err(|_| PersistenceError::Unavailable)?;
        if let Err(error) = self.write_snapshot(&mut file, scope, &record) {
            drop(file);
            // If cleanup fails, inventory refuses further writes until reopen's
            // bounded cleanup. The previously installed record is untouched.
            let _cleanup = fs::remove_file(&temp);
            return Err(error);
        }
        // From the rename attempt until directory sync succeeds, never claim
        // rollback (even an OS rename error can leave an uncertain I/O outcome).
        // Fence writes so a duplicate cannot turn uncertainty into success.
        self.fenced = true;
        if fs::rename(&temp, self.path.join(record_name(scope))).is_err() {
            drop(file);
            let _cleanup = fs::remove_file(&temp);
            return Err(PersistenceError::CommitUnknown);
        }
        #[cfg(test)]
        self.test_cut(TestCut::AfterRename)?;
        sync_directory(&self.path).map_err(|_| PersistenceError::CommitUnknown)?;
        #[cfg(test)]
        self.test_cut(TestCut::AfterDirectorySync)?;
        self.fenced = false;
        Ok(())
    }
}

fn record_name(scope: &PersistenceScope) -> String {
    let mut hash = Sha256::new();
    hash.update(b"syntra-local-recovery-scope-v1\0");
    for part in [scope.principal_scope(), scope.stable_stream()] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    format!("{}.rec", hex(&hash.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    output
}

fn lower_hex(name: &str, len: usize) -> bool {
    name.len() == len
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_record(name: &str) -> bool {
    name.strip_suffix(".rec").is_some_and(|n| lower_hex(n, 64))
}

fn is_temp(name: &str) -> bool {
    name.strip_prefix(TEMP_PREFIX)
        .is_some_and(|n| lower_hex(n, 32))
}

fn absolute_path(path: &Path) -> Result<PathBuf, PersistenceError> {
    if path.as_os_str().is_empty() || path.components().any(|c| c == Component::ParentDir) {
        return Err(PersistenceError::Unavailable);
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .map_err(|_| PersistenceError::Unavailable)?
            .join(path))
    }
}

fn check_ancestors(path: &Path) -> Result<(), PersistenceError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|_| PersistenceError::Unavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(PersistenceError::Unavailable);
        }
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<Metadata, PersistenceError> {
    check_ancestors(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| PersistenceError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(PersistenceError::Unavailable);
        }
    }
    Ok(metadata)
}

fn check_file(path: &Path, directory: &Metadata) -> Result<Metadata, PersistenceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PersistenceError::Unavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PersistenceError::Unavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.uid() != directory.uid()
        {
            return Err(PersistenceError::Unavailable);
        }
    }
    #[cfg(not(unix))]
    let _ = directory;
    Ok(metadata)
}

fn private_new(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn read_exact(file: &mut File, bytes: &mut [u8]) -> Result<(), PersistenceError> {
    file.read_exact(bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            PersistenceError::Corrupt
        } else {
            PersistenceError::Unavailable
        }
    })
}

// Hooks exist only in test builds; no production environment switch or crash API.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestCut {
    AfterHeader,
    AfterWrite,
    BeforeRename,
    AfterRename,
    AfterDirectorySync,
    DirectorySyncFailure,
}

#[cfg(test)]
impl FileRecoveryStore {
    fn test_cut(&self, at: TestCut) -> Result<(), PersistenceError> {
        if self.cut == Some(TestCut::DirectorySyncFailure) && at == TestCut::AfterRename {
            return Err(PersistenceError::CommitUnknown);
        }
        if self.cut == Some(at) {
            // Abrupt process exit without running Rust destructors. Invoked only
            // by the explicitly selected subprocess test below.
            std::process::exit(73);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            Self(
                fs::canonicalize(std::env::temp_dir())
                    .unwrap()
                    .join(format!("syntra-persistence-crash-{}", hex(&nonce))),
            )
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    fn scope() -> PersistenceScope {
        PersistenceScope::new(b"crash-principal".to_vec(), b"crash-stream".to_vec()).unwrap()
    }

    fn snapshot(new: bool) -> DurableRecord {
        DurableRecord {
            generation: if new { 2 } else { 1 },
            checkpoint: if new {
                b"new checkpoint"
            } else {
                b"old checkpoint"
            }
            .to_vec(),
            application_state: if new {
                b"new complete state"
            } else {
                b"old complete state"
            }
            .to_vec(),
        }
    }

    fn child(path: &Path, cut: &str) -> std::process::ExitStatus {
        let module = module_path!().split_once("::").unwrap().1;
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &format!("{module}::crash_child"), "--nocapture"])
            .env("SYNTRA_PERSISTENCE_TEST_DIRECTORY", path)
            .env("SYNTRA_PERSISTENCE_TEST_CUT", cut)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
    }

    #[test]
    fn crash_child() {
        let Some(path) = std::env::var_os("SYNTRA_PERSISTENCE_TEST_DIRECTORY") else {
            return;
        };
        let cut = std::env::var("SYNTRA_PERSISTENCE_TEST_CUT").unwrap();
        if cut == "lock" {
            assert_eq!(
                FileRecoveryStore::open(path, StoreLimits::default()).err(),
                Some(PersistenceError::Unavailable)
            );
            return;
        }
        let mut store = FileRecoveryStore::open(path, StoreLimits::default()).unwrap();
        let (initial, cut) = cut
            .strip_prefix("initial-")
            .map_or((false, cut.as_str()), |c| (true, c));
        store.cut = Some(match cut {
            "header" => TestCut::AfterHeader,
            "write" => TestCut::AfterWrite,
            "before-rename" => TestCut::BeforeRename,
            "after-rename" => TestCut::AfterRename,
            "directory-sync" => TestCut::AfterDirectorySync,
            _ => panic!("unknown test cut"),
        });
        let expected = ExpectedPosition::from(&snapshot(false));
        store
            .commit(
                &scope(),
                if initial { None } else { Some(&expected) },
                snapshot(true),
            )
            .unwrap();
        panic!("subprocess did not hit its crash cut");
    }

    #[test]
    fn actual_subprocess_crash_boundaries_and_process_lock_release() {
        for (initial, cut) in [false, true].into_iter().flat_map(|initial| {
            [
                "header",
                "write",
                "before-rename",
                "after-rename",
                "directory-sync",
            ]
            .into_iter()
            .map(move |cut| (initial, cut))
        }) {
            let directory = Directory::new();
            let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
            if !initial {
                store.commit(&scope(), None, snapshot(false)).unwrap();
            }
            assert!(
                child(&directory.0, "lock").success(),
                "process lock must exclude another process"
            );
            drop(store);
            assert_eq!(
                child(
                    &directory.0,
                    &format!("{}{cut}", if initial { "initial-" } else { "" })
                )
                .code(),
                Some(73),
                "child must actually reach cut"
            );
            // Child exited without destructors; a retained lock file must not
            // prevent reopening. Reopen also removes the bounded orphan temp.
            let store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
            let observed = store.load(&scope()).unwrap();
            let after_rename = matches!(cut, "after-rename" | "directory-sync");
            assert_eq!(
                observed,
                if initial && !after_rename {
                    None
                } else {
                    Some(snapshot(after_rename))
                }
            );
            assert_eq!(
                fs::read_dir(&directory.0).unwrap().count(),
                if initial && !after_rename { 1 } else { 2 }
            );
        }
        // Process crashes exercise visibility and kernel lock lifetime. They do
        // not simulate power loss; durability still assumes honored fsyncs.
    }

    #[test]
    fn directory_sync_uncertainty_fences_duplicate_until_reopen() {
        let directory = Directory::new();
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        store.commit(&scope(), None, snapshot(false)).unwrap();
        store.cut = Some(TestCut::DirectorySyncFailure);
        let expected = ExpectedPosition::from(&snapshot(false));
        assert_eq!(
            store.commit(&scope(), Some(&expected), snapshot(true)),
            Err(PersistenceError::CommitUnknown)
        );
        assert_eq!(store.load(&scope()).unwrap(), Some(snapshot(true)));
        assert_eq!(
            store.commit(&scope(), Some(&expected), snapshot(true)),
            Err(PersistenceError::CommitUnknown)
        );
        drop(store);
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        assert_eq!(store.load(&scope()).unwrap(), Some(snapshot(true)));
        store
            .commit(&scope(), Some(&expected), snapshot(true))
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inherited_lock_description_does_not_extend_store_lifetime() {
        let directory = Directory::new();
        let mut store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        store.commit(&scope(), None, snapshot(false)).unwrap();
        // A concurrent Command spawn can inherit this open-file description
        // until exec closes CLOEXEC descriptors. Retain an equivalent reference
        // deterministically, without forking the multithreaded test harness.
        let inherited = store._lock.file.try_clone().unwrap();
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        // A failed contender must not unlock the live owner.
        assert!(child(&directory.0, "lock").success());
        drop(store);
        let mut reopened = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        assert_eq!(reopened.load(&scope()).unwrap(), Some(snapshot(false)));
        reopened
            .commit(
                &scope(),
                Some(&ExpectedPosition::from(&snapshot(false))),
                snapshot(true),
            )
            .unwrap();
        drop(inherited);
        // Closing an old inherited reference must not release the successor's
        // independently acquired lock, or require replacing the lock file.
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        assert!(child(&directory.0, "lock").success());
        drop(reopened);
        let reopened = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        assert_eq!(reopened.load(&scope()).unwrap(), Some(snapshot(true)));
    }

    #[cfg(unix)]
    #[test]
    fn foreign_process_drop_does_not_unlock_shared_description() {
        let directory = Directory::new();
        let store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        assert!(store._lock.owner == ProcessIdentity::current().unwrap());
        // Model a forked child's PID mismatch with a duplicate of the same open
        // file description, without forking a multithreaded test harness.
        let inherited = StoreLock {
            file: store._lock.file.try_clone().unwrap(),
            owner: ProcessIdentity {
                pid: std::process::id().wrapping_add(1),
                ..store._lock.owner
            },
        };
        drop(inherited);
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        assert!(child(&directory.0, "lock").success());
        drop(store);
        drop(FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn same_pid_other_namespace_drop_does_not_unlock_shared_description() {
        let directory = Directory::new();
        let store = FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap();
        let mut owner = store._lock.owner;
        owner.pid_namespace.1 = owner.pid_namespace.1.wrapping_add(1);
        // Exercise same-PID aliasing in ordinary test runs too. The standalone
        // file_store_pid_namespace example verifies it with real namespaces.
        drop(StoreLock {
            file: store._lock.file.try_clone().unwrap(),
            owner,
        });
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        assert!(child(&directory.0, "lock").success());
        drop(store);
        drop(FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap());
    }

    #[test]
    fn cleanup_is_bounded_and_never_deletes_unknown_entries() {
        let directory = Directory::new();
        drop(FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap());
        let unrelated = directory.0.join("keep-me");
        private_new(&unrelated).unwrap();
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::Unavailable)
        );
        assert!(unrelated.exists());
        fs::remove_file(unrelated).unwrap();
        for n in 0..=MAX_ORPHANS {
            private_new(&directory.0.join(format!("{TEMP_PREFIX}{n:032x}"))).unwrap();
        }
        assert_eq!(
            FileRecoveryStore::open(&directory.0, StoreLimits::default()).err(),
            Some(PersistenceError::OverLimit)
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), MAX_ORPHANS + 2);
        fs::remove_file(directory.0.join(format!("{TEMP_PREFIX}{MAX_ORPHANS:032x}"))).unwrap();
        drop(FileRecoveryStore::open(&directory.0, StoreLimits::default()).unwrap());
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }
}
