"""Read-only verification of implementation inputs and upstream provenance.

The v2 upstream lock selects only consumed implementation inputs, not a complete
upstream inventory or a claim that all paths exist here. Proto stays vendored;
only the fixtures needed by include_str! are copied under tests. Default checks
require a local Git object database (SYNTRA_SDD_ROOT or ../syntra) and read the
exact accepted commit, never HEAD/worktree files. --offline is explicitly
digest-only, not Git provenance.
No network, checkout, generation, deletion, or upstream writes occur here.
"""

import os
from pathlib import Path

from upstream_snapshot import ROOT, REVISION, compare, from_git, inventory, read_lock


# Deliberately reviewed allowlist. Do not infer copies from lock entries or copy
# upstream documentation/manifests back into the implementation repository.
TEST_ASSETS = {
    "tests/interoperability/fixtures/protobuf-vectors.yaml":
        "conformance/test-vectors/protobuf/vectors.yaml",
}


def sdd_root(upstream=None, root=ROOT):
    return Path(upstream or os.environ.get("SYNTRA_SDD_ROOT") or root.parent / "syntra")


def regular_file(root, name):
    current = root
    for part in Path(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"implementation input symlink is not permitted: {name}")
    if not current.is_file():
        raise ValueError(f"missing implementation input: {name}")
    return current.read_bytes()


def verify_inputs(root=ROOT, upstream=None, *, offline=False):
    expected = read_lock(root)
    proto = {name: value for name, value in expected.items() if name.startswith("proto/")}
    directory = root / "proto"
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("missing or symlinked proto root")
    actual = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"implementation input symlink is not permitted: {path}")
        if path.name == ".DS_Store" or "__pycache__" in path.parts:
            continue
        if path.is_file():
            name = path.relative_to(root).as_posix()
            actual[name] = regular_file(root, name)
    compare(proto, inventory(actual), "implementation proto drift")
    assets = {}
    for destination, origin in TEST_ASSETS.items():
        if origin not in expected:
            raise ValueError(f"test asset has no pinned origin: {origin}")
        assets[origin] = regular_file(root, destination)
    compare({name: expected[name] for name in assets}, inventory(assets), "test asset origin drift")
    source = None
    if not offline:
        source = from_git(sdd_root(upstream, root))
        compare(expected, inventory(source), "upstream Git provenance drift")
    return {
        "revision": REVISION,
        "upstream_files": len(expected),
        "local_proto_files": len(proto),
        "test_assets": len(assets),
        "provenance": "offline_digest_only" if offline else "exact_committed_git_blobs",
    }, source
