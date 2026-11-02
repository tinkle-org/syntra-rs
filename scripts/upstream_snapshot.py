"""Reproduce and verify vendored Syntra inputs, without floating refs or network.

Check offline: python3 scripts/check-upstream-pin.py
Compare with Git objects: python3 scripts/check-upstream-pin.py --upstream ../syntra
Refresh: python3 scripts/upstream_snapshot.py --sync --upstream ../syntra

The explicit sync command generates snapshots and their SHA-256 inventory from
committed Git blobs, never from the source worktree. Review pin, inventory and
snapshot changes together. A digest inventory detects drift, not RFC acceptance
or conformance; --upstream additionally verifies the inventory against Git.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/tinkle-org/syntra"
REVISION = "8ede3810b29fbba4d0e6ae6751a0025ceedda140"
SNAPSHOT_ROOTS = ("proto", "conformance")
LOCK = "upstream.lock.json"


def digest(content):
    return hashlib.sha256(content).hexdigest()


def snapshot_path(name):
    path = PurePosixPath(name)
    if (
        not isinstance(name, str)
        or path.is_absolute()
        or path.as_posix() != name
        or ".." in path.parts
        or path.name == ".DS_Store"
        or "__pycache__" in path.parts
        or len(path.parts) < 2
        or path.parts[0] not in SNAPSHOT_ROOTS
    ):
        raise ValueError(f"out-of-scope snapshot path: {name!r}")
    return path


def local_path(root, name):
    path = snapshot_path(name)
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"snapshot symlink is not permitted: {name}")
    return current


def local_files(root):
    result = {}
    for name in SNAPSHOT_ROOTS:
        directory = root / name
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"missing or symlinked snapshot root: {name}")
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise ValueError(f"snapshot symlink is not permitted: {relative}")
            # OS/Python cache artifacts are not snapshot inputs. No source,
            # manifest, result or documentation file is otherwise exempted.
            if path.name == ".DS_Store" or "__pycache__" in path.parts:
                continue
            if path.is_file():
                result[relative] = path.read_bytes()
    return result


def inventory(contents):
    return {name: digest(content) for name, content in sorted(contents.items())}


def lock_path(root):
    path = root / LOCK
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("snapshot lock must be a regular file, never a symlink")
    return path


def read_lock(root):
    lock = json.loads(lock_path(root).read_text(encoding="utf-8"))
    if not isinstance(lock, dict):
        raise ValueError("snapshot lock must be a JSON object")
    if (
        lock.get("format_version") != 1
        or lock.get("repository") != REPOSITORY
        or lock.get("revision") != REVISION
        or lock.get("roots") != list(SNAPSHOT_ROOTS)
    ):
        raise ValueError("snapshot lock identity does not match the reviewed pin")
    entries = lock.get("sha256")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("snapshot lock must contain a nonempty SHA-256 inventory")
    for name, value in entries.items():
        snapshot_path(name)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"invalid snapshot digest: {name}")
    for prefix in SNAPSHOT_ROOTS:
        if not any(name.startswith(prefix + "/") for name in entries):
            raise ValueError(f"snapshot lock omits root: {prefix}")
    return entries


def compare(expected, actual, label):
    differences = [
        name for name in sorted(expected.keys() | actual.keys())
        if expected.get(name) != actual.get(name)
    ]
    if differences:
        raise ValueError(f"{label}: " + ", ".join(differences))


def git(upstream, *args):
    return subprocess.run(
        ["git", "-C", str(upstream), *args], check=True, capture_output=True,
        timeout=30,
    ).stdout


def from_git(upstream):
    resolved = git(upstream, "rev-parse", "--verify", f"{REVISION}^{{commit}}")
    if resolved.decode("ascii").strip() != REVISION:
        raise ValueError("upstream commit did not resolve to the reviewed full SHA")
    tree = git(upstream, "ls-tree", "-rz", REVISION, "--", *SNAPSHOT_ROOTS)
    result = {}
    for record in tree.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, blob = metadata.split()
        name = raw_name.decode("utf-8")
        snapshot_path(name)
        if mode != b"100644" or kind != b"blob":
            raise ValueError(f"snapshot requires regular non-executable blobs: {name}")
        result[name] = git(upstream, "cat-file", "blob", blob.decode("ascii"))
    for prefix in SNAPSHOT_ROOTS:
        if not any(name.startswith(prefix + "/") for name in result):
            raise ValueError(f"upstream tree omits root: {prefix}")
    return result


def verify(root=ROOT, upstream=None):
    expected = read_lock(root)
    compare(expected, inventory(local_files(root)), "snapshot content/inventory drift")
    if upstream is not None:
        compare(expected, inventory(from_git(upstream)), "upstream Git provenance drift")
    return len(expected)


def sync(root, upstream):
    # Read/validate everything before touching destination files. Do not erase
    # locally modified snapshots or silently delete inputs removed upstream.
    destination_lock = lock_path(root)
    source = from_git(upstream)
    existing = local_files(root)
    if (root / LOCK).exists():
        verify(root)
    else:
        changed = git(root, "diff", "HEAD", "--name-only", "--", *SNAPSHOT_ROOTS)
        if changed.strip():
            raise ValueError("refusing initial sync over locally modified snapshot files")
        tracked = {
            name.decode("utf-8") for name in
            git(root, "ls-files", "-z", "--", *SNAPSHOT_ROOTS).split(b"\0") if name
        }
        untracked = existing.keys() - tracked
        if untracked:
            raise ValueError("refusing initial sync over untracked conflicts: " +
                             ", ".join(sorted(untracked)))
    extra = existing.keys() - source.keys()
    if extra:
        raise ValueError("review removed/local snapshot inputs first: " + ", ".join(sorted(extra)))
    destinations = {name: local_path(root, name) for name in source}
    lock = {
        "format_version": 1,
        "repository": REPOSITORY,
        "revision": REVISION,
        "roots": list(SNAPSHOT_ROOTS),
        "sha256": inventory(source),
    }
    lock_bytes = (json.dumps(lock, indent=2) + "\n").encode("utf-8")
    if destination_lock.exists() and (
        source != existing or destination_lock.read_bytes() != lock_bytes
    ):
        # A working-tree lock edited together with its files is not an
        # independent overwrite authorization. Require clean Git state when
        # replacing an existing snapshot; exact no-op reproduction is safe.
        changed = git(root, "status", "--porcelain", "--untracked-files=all",
                      "--", *SNAPSHOT_ROOTS, LOCK)
        if changed.strip():
            raise ValueError("refusing sync over locally modified snapshots or lock")
    for name, content in source.items():
        if existing.get(name) != content:
            destination = destinations[name]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
    if not destination_lock.exists() or destination_lock.read_bytes() != lock_bytes:
        destination_lock.write_bytes(lock_bytes)
    return verify(root, upstream)


def main(sync_allowed=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, help="local authoritative Git checkout")
    if sync_allowed:
        parser.add_argument("--sync", action="store_true", help="explicitly regenerate snapshots")
    args = parser.parse_args()
    if getattr(args, "sync", False):
        if args.upstream is None:
            parser.error("--sync requires --upstream; no network or floating ref is used")
        count = sync(ROOT, args.upstream)
    else:
        count = verify(ROOT, args.upstream)
    provenance = "; verified against upstream Git blobs" if args.upstream else "; offline digest check"
    print(f"Syntra {REVISION}: {count} snapshot files match{provenance}.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sync_allowed=True))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Upstream snapshot check failed: {error}")
