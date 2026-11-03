//! Standalone regression: build with `--features file-store --example
//! file_store_pid_namespace`, then exec the binary as PID 1 in a fresh disposable
//! Linux container with procfs, CAP_SYS_ADMIN and seccomp allowing unshare/fork.
//! Never fork a libtest/Tokio harness; this helper starts no threads. Namespace or
//! setup errors fail the run. Non-Linux execution is unavailable, not a pass.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        io::{Read, Write},
        os::unix::{fs::MetadataExt, net::UnixStream},
        path::Path,
        process::Command,
        time::Duration,
    };

    use syntra_runtime::recovery::persistence::{FileRecoveryStore, PersistenceError, StoreLimits};

    fn namespace() -> (u64, u64) {
        let metadata = fs::metadata("/proc/self/ns/pid").unwrap();
        (metadata.dev(), metadata.ino())
    }

    fn fork_once() -> libc::pid_t {
        // SAFETY: this standalone executable has never started another thread;
        // no libtest harness or async runtime is involved in either branch.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        pid
    }

    fn wait_ok(pid: libc::pid_t) {
        let mut status = 0;
        loop {
            // SAFETY: status is writable and pid names our direct child.
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(result, -1);
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR), "{error}");
        }
        assert!(libc::WIFEXITED(status), "child status: {status}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn exit_child() -> ! {
        // SAFETY: required store drops have already run explicitly. Skip other
        // inherited Rust destructors; _exit closes remaining child descriptors.
        unsafe { libc::_exit(0) }
    }

    fn probe(mode: &str, path: &Path) {
        let result = FileRecoveryStore::open(path, StoreLimits::default());
        match mode {
            "blocked" => assert_eq!(result.err(), Some(PersistenceError::Unavailable)),
            "free" => drop(result.unwrap()),
            _ => panic!("unknown probe mode"),
        }
    }

    fn check_probe(mode: &str, path: &Path) {
        assert!(
            Command::new(std::env::current_exe().unwrap())
                .args(["probe", mode])
                .arg(path)
                .status()
                .unwrap()
                .success(),
            "independent contender: {mode}"
        );
    }

    pub fn run() {
        let args: Vec<_> = std::env::args_os().collect();
        if args.get(1).is_some_and(|arg| arg == "probe") {
            assert_eq!(args.len(), 4);
            probe(args[2].to_str().unwrap(), Path::new(&args[3]));
            return;
        }
        assert_eq!(args.len(), 1);
        assert_eq!(std::process::id(), 1, "exec the helper as container PID 1");
        let path = Path::new("/tmp/syntra-file-store-pid-namespace");
        assert!(
            !path.try_exists().unwrap(),
            "use a fresh disposable container"
        );

        // A owns the store in N0. B retains its inherited description while C
        // drops another inherited store as PID 1 in N1 (the same number as A).
        let store = FileRecoveryStore::open(path, StoreLimits::default()).unwrap();
        let owner_namespace = namespace();
        let (mut parent_socket, mut child_socket) = UnixStream::pair().unwrap();
        for socket in [&parent_socket, &child_socket] {
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
        }

        let middle = fork_once();
        if middle == 0 {
            drop(parent_socket);
            // SAFETY: single-threaded helper. Only future children's PID
            // namespace changes; B remains in N0 and can wait for C normally.
            let result = unsafe { libc::unshare(libc::CLONE_NEWPID) };
            assert_eq!(result, 0, "unshare: {}", std::io::Error::last_os_error());
            let nested = fork_once();
            if nested == 0 {
                assert_eq!(std::process::id(), 1);
                assert_ne!(namespace(), owner_namespace);
                drop(store); // Exercise the actual inherited StoreLock::drop.
                exit_child();
            }

            wait_ok(nested);
            child_socket.write_all(b"R").unwrap();
            let mut release = [0];
            child_socket.read_exact(&mut release).unwrap();
            assert_eq!(&release, b"G");
            drop(store); // B drops only after A has acquired its successor.
            exit_child();
        }

        drop(child_socket);
        let mut ready = [0];
        parent_socket.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"R");
        check_probe("blocked", path);
        println!("same-PID descendant drop: contender excluded");

        drop(store);
        check_probe("free", path); // B still holds the original description.
        println!("owner drop: lock released while inherited descriptor remains");

        let successor = FileRecoveryStore::open(path, StoreLimits::default()).unwrap();
        parent_socket.write_all(b"G").unwrap();
        wait_ok(middle);
        check_probe("blocked", path);
        println!("inherited descriptor drop: successor remains excluded");

        drop(successor);
        check_probe("free", path);
        fs::remove_dir_all(path).unwrap();
        println!("file-store PID namespace regression passed");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("file-store PID namespace regression unavailable: requires Linux");
    std::process::exit(1);
}
