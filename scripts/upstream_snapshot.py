"""Verify pinned Syntra inputs, without floating refs or network.

Default: python3 scripts/check-upstream-pin.py (SYNTRA_SDD_ROOT or ../syntra Git objects)
Local digest-only: python3 scripts/check-upstream-pin.py --offline

Both entry points check local proto and selected test assets without writes.
Default verification also checks the explicitly scoped implementation inputs
against exact committed Git blobs, never the source worktree. These digests
detect input drift, not RFC acceptance or conformance.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


# Direct execution must also avoid creating bytecode caches on import.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/tinkle-org/syntra"
REVISION = "8ede3810b29fbba4d0e6ae6751a0025ceedda140"
SCOPE = "implementation-inputs"
REQUIRED_INPUTS = (
    "conformance/test-vectors/protobuf/vectors.yaml",
    "conformance/test-vectors/tcp/byte-vectors.yaml",
    "conformance/test-vectors/websocket/fixtures.yaml",
    "proto/syntra/v1/capabilities.proto",
    "proto/syntra/v1/envelope.proto",
    "proto/syntra/v1/errors.proto",
    "proto/syntra/v1/events.proto",
    "proto/syntra/v1/handshake.proto",
    "proto/syntra/v1/recovery_profile.proto",
    "proto/syntra/v1/rpc.proto",
    "proto/syntra/v1/session.proto",
)
LOCK = "upstream.lock.json"


def digest(content):
    return hashlib.sha256(content).hexdigest()


def snapshot_path(name):
    if not isinstance(name, str) or name not in REQUIRED_INPUTS:
        raise ValueError(f"out-of-scope snapshot path: {name!r}")
    return PurePosixPath(name)


def inventory(contents):
    return {name: digest(content) for name, content in sorted(contents.items())}


def lock_path(root):
    path = root / LOCK
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("snapshot lock must be a regular file, never a symlink")
    return path


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_lock(root):
    lock = json.loads(lock_path(root).read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(lock, dict):
        raise ValueError("snapshot lock must be a JSON object")
    if (
        set(lock) != {"format_version", "scope", "repository", "revision", "sha256"}
        or type(lock.get("format_version")) is not int
        or lock.get("format_version") != 2
        or lock.get("scope") != SCOPE
        or lock.get("repository") != REPOSITORY
        or lock.get("revision") != REVISION
    ):
        raise ValueError("snapshot lock identity does not match the reviewed pin")
    entries = lock.get("sha256")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("snapshot lock must contain a nonempty SHA-256 inventory")
    for name, value in entries.items():
        snapshot_path(name)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"invalid snapshot digest: {name}")
    missing = set(REQUIRED_INPUTS) - entries.keys()
    if missing:
        raise ValueError("snapshot lock omits required inputs: " + ", ".join(sorted(missing)))
    return entries


def compare(expected, actual, label):
    differences = [
        name for name in sorted(expected.keys() | actual.keys())
        if expected.get(name) != actual.get(name)
    ]
    if differences:
        raise ValueError(f"{label}: " + ", ".join(differences))


def git(upstream, *args):
    # Missing partial-clone objects must fail locally; replacement refs must not
    # substitute different bytes for an explicitly pinned object.
    return subprocess.run(
        ["git", "-C", str(upstream), *args], check=True, capture_output=True,
        timeout=30,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1"},
    ).stdout


def from_git(upstream):
    resolved = git(upstream, "rev-parse", "--verify", f"{REVISION}^{{commit}}")
    if resolved.decode("ascii").strip() != REVISION:
        raise ValueError("upstream commit did not resolve to the reviewed full SHA")
    tree = git(upstream, "ls-tree", "-rz", REVISION, "--", *REQUIRED_INPUTS)
    blobs = {}
    for record in tree.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, blob = metadata.split()
        name = raw_name.decode("utf-8")
        snapshot_path(name)
        if mode != b"100644" or kind != b"blob":
            raise ValueError(f"snapshot requires regular non-executable blobs: {name}")
        if name in blobs:
            raise ValueError(f"duplicate upstream input: {name}")
        if not re.fullmatch(rb"[0-9a-f]{40}", blob):
            raise ValueError(f"invalid upstream blob ID: {name}")
        blobs[name] = blob.decode("ascii")
    missing = set(REQUIRED_INPUTS) - blobs.keys()
    if missing:
        raise ValueError("upstream tree omits required inputs: " + ", ".join(sorted(missing)))
    return {name: git(upstream, "cat-file", "blob", blob) for name, blob in blobs.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, help="local authoritative Git checkout")
    parser.add_argument("--offline", action="store_true", help="digest-only local proto/test-asset check; no Git provenance")
    args = parser.parse_args()
    if args.offline and args.upstream is not None:
        parser.error("--offline cannot be combined with --upstream")
    from sdd_inputs import verify_inputs
    result, _ = verify_inputs(ROOT, args.upstream, offline=args.offline)
    print(f"Syntra {REVISION}: {result['local_proto_files']} proto files and "
          f"{result['test_assets']} test assets match; {result['provenance']}; "
          f"{result['upstream_files']} scoped upstream implementation inputs (not local copies).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Upstream snapshot check failed: {error}")
