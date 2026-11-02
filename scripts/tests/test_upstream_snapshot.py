"""Offline regression tests; all destination writes stay in TemporaryDirectory.

Run from the repository root:
    python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v

Git provenance is modeled at the Git command boundary, not by changing the
reviewed revision or making commits. The checker CLI is executed with runpy so
its repository root can be redirected without copying or editing the scripts.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
CHECKER = SCRIPTS / "check-upstream-pin.py"
ACCEPTED_REVISION = "8ede3810b29fbba4d0e6ae6751a0025ceedda140"
ACCEPTED_REPOSITORY = "https://github.com/tinkle-org/syntra"
ROOTS = ("proto", "conformance")
LOCK = "upstream.lock.json"

_spec = importlib.util.spec_from_file_location(
    "upstream_snapshot", SCRIPTS / "upstream_snapshot.py"
)
assert _spec is not None and _spec.loader is not None
snapshot = importlib.util.module_from_spec(_spec)
with mock.patch.object(sys, "dont_write_bytecode", True):
    _spec.loader.exec_module(snapshot)


def sha256(content):
    # Independent fixture oracle: do not construct expected hashes with the SUT.
    return hashlib.sha256(content).hexdigest()


class SnapshotFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="syntra-snapshot-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.contents = {
            "proto/syntra/v1/example.proto": b'syntax = "proto3";\n',
            "conformance/test-vectors/example.bin": b"\x00\xff\r\nvector\n",
        }
        for name, content in self.contents.items():
            self.write(name, content)
        self.lock = {
            "format_version": 1,
            "repository": ACCEPTED_REPOSITORY,
            "revision": ACCEPTED_REVISION,
            "roots": list(ROOTS),
            "sha256": {name: sha256(data) for name, data in sorted(self.contents.items())},
        }
        self.write_lock()

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def write_lock(self):
        self.write(LOCK, (json.dumps(self.lock, indent=2) + "\n").encode("utf-8"))

    def tree_state(self):
        """Include metadata to detect even rewrites of identical bytes."""
        result = {}
        for path in [self.root, *sorted(self.root.rglob("*"))]:
            stat = path.lstat()
            payload = None
            if path.is_symlink():
                payload = str(path.readlink())
            elif path.is_file():
                payload = path.read_bytes()
            result[path.relative_to(self.root).as_posix()] = (
                stat.st_mode, stat.st_size, stat.st_mtime_ns, stat.st_ino, payload
            )
        return result

    def symlink(self, target, link, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlinks unavailable: {error}")

    def git_objects(self, contents=None, *, resolved=None, tree=None):
        """Exact command-response map: no worktree reads or floating refs."""
        if contents is None:
            contents = self.contents
        responses: dict[tuple[str, ...], bytes] = {
            ("rev-parse", "--verify", f"{ACCEPTED_REVISION}^{{commit}}"):
                ((resolved or ACCEPTED_REVISION) + "\n").encode("ascii"),
            ("status", "--porcelain", "--untracked-files=all", "--", *ROOTS, LOCK): b"",
        }
        records = []
        for index, (name, content) in enumerate(sorted(contents.items()), 1):
            blob = f"{index:040x}"
            records.append(f"100644 blob {blob}\t{name}".encode("utf-8") + b"\0")
            responses[("cat-file", "blob", blob)] = content
        responses[("ls-tree", "-rz", ACCEPTED_REVISION, "--", *ROOTS)] = (
            b"".join(records) if tree is None else tree
        )

        def respond(upstream, *args):
            self.assertEqual(upstream, self.root if args[0] == "status" else
                             self.root / "source-checkout")
            self.assertIn(args, responses, f"unexpected Git/worktree command: {args}")
            return responses[args]

        return mock.patch.object(snapshot, "git", side_effect=respond)

    def assert_sync_refused_unchanged(self, message, exception: type[Exception] = ValueError):
        before = self.tree_state()
        with self.assertRaisesRegex(exception, message):
            snapshot.sync(self.root, self.root / "source-checkout")
        self.assertEqual(self.tree_state(), before, "failed sync wrote destination data")

    def run_cli(self, *args, allow_git=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {"upstream_snapshot": snapshot}))
            stack.enter_context(mock.patch.object(snapshot, "ROOT", self.root))
            stack.enter_context(mock.patch.object(sys, "argv", [str(CHECKER), *args]))
            stack.enter_context(mock.patch.object(sys, "dont_write_bytecode", True))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            stack.enter_context(mock.patch.object(
                snapshot, "sync", side_effect=AssertionError("read-only CLI attempted sync")
            ))
            if not allow_git:
                stack.enter_context(mock.patch.object(
                    snapshot, "git", side_effect=AssertionError("offline CLI invoked Git")
                ))
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(CHECKER), run_name="__main__")
        return exited.exception.code, stdout.getvalue(), stderr.getvalue()


class OfflineInventoryTests(SnapshotFixture):
    def test_cli_constants_are_the_reviewed_identity(self):
        self.assertEqual(snapshot.REVISION, ACCEPTED_REVISION)
        self.assertEqual(snapshot.REPOSITORY, ACCEPTED_REPOSITORY)
        self.assertEqual(snapshot.SNAPSHOT_ROOTS, ROOTS)
        self.assertEqual(snapshot.LOCK, LOCK)

    def test_offline_happy_path_needs_no_git_and_is_read_only(self):
        before = self.tree_state()
        with mock.patch.object(snapshot, "git", side_effect=AssertionError("offline Git")):
            self.assertEqual(snapshot.verify(self.root), len(self.contents))
        self.assertEqual(snapshot.read_lock(self.root), self.lock["sha256"])
        self.assertEqual(self.tree_state(), before)

    def test_inventory_hashes_exact_bytes_in_sorted_order(self):
        contents = {"proto/z": b"a\r\n", "conformance/a": b"\x00\xff", "proto/a": b"a\n"}
        actual = snapshot.inventory(contents)
        self.assertEqual(list(actual), sorted(contents))
        self.assertEqual(actual, {name: sha256(data) for name, data in contents.items()})
        self.assertNotEqual(actual["proto/z"], actual["proto/a"])

    def test_mutated_snapshots_are_rejected_in_each_root(self):
        for name, content in self.contents.items():
            with self.subTest(name=name):
                path = self.write(name, content + b"changed")
                with self.assertRaisesRegex(ValueError, "snapshot content/inventory drift") as error:
                    snapshot.verify(self.root)
                self.assertIn(name, str(error.exception))
                path.write_bytes(content)

    def test_missing_snapshots_are_rejected_in_each_root(self):
        for name, content in self.contents.items():
            with self.subTest(name=name):
                (self.root / name).unlink()
                with self.assertRaisesRegex(ValueError, "snapshot content/inventory drift") as error:
                    snapshot.verify(self.root)
                self.assertIn(name, str(error.exception))
                self.write(name, content)

    def test_extra_inputs_are_not_exempted_by_extension_or_dotfile(self):
        for prefix in ROOTS:
            for leaf in ("README.md", "manifest.yaml", "result.json", "other.proto", ".hidden"):
                name = f"{prefix}/extra/{leaf}"
                with self.subTest(name=name):
                    path = self.write(name, b"unreviewed")
                    with self.assertRaisesRegex(ValueError, "snapshot content/inventory drift") as error:
                        snapshot.verify(self.root)
                    self.assertIn(name, str(error.exception))
                    path.unlink()

    def test_only_documented_cache_artifacts_are_ignored(self):
        for prefix in ROOTS:
            self.write(f"{prefix}/.DS_Store", b"os metadata")
            self.write(f"{prefix}/nested/__pycache__/artifact.pyc", b"cache")
        self.write("outside-snapshot.txt", b"unrelated")
        self.assertEqual(snapshot.local_files(self.root), self.contents)
        self.assertEqual(snapshot.verify(self.root), len(self.contents))

    def test_missing_snapshot_roots_are_rejected(self):
        for prefix in ROOTS:
            with self.subTest(prefix=prefix):
                directory = self.root / prefix
                backup = self.root / f"saved-{prefix}"
                directory.rename(backup)
                with self.assertRaisesRegex(ValueError, "missing or symlinked snapshot root"):
                    snapshot.verify(self.root)
                backup.rename(directory)

    def test_regular_file_cannot_replace_snapshot_root(self):
        directory = self.root / "proto"
        directory.rename(self.root / "saved-proto")
        directory.write_bytes(b"not a directory")
        with self.assertRaisesRegex(ValueError, "missing or symlinked snapshot root"):
            snapshot.verify(self.root)

    def test_drift_diagnostic_lists_every_difference_deterministically(self):
        with self.assertRaises(ValueError) as error:
            snapshot.compare({"z": "old", "a": "missing"}, {"z": "new", "b": "extra"}, "drift")
        self.assertEqual(str(error.exception), "drift: a, b, z")


class LockValidationTests(SnapshotFixture):
    def test_lock_identity_mismatches_are_rejected(self):
        cases = {
            "format_version": (0, 2, "1", None),
            "repository": ("https://github.com/elsewhere/syntra", ACCEPTED_REPOSITORY + ".git", None),
            "revision": ("0" * 40, ACCEPTED_REVISION[:12], ACCEPTED_REVISION.upper(), None),
            "roots": (["proto"], ["conformance"], ["conformance", "proto"], [*ROOTS, "other"], None),
        }
        for field, values in cases.items():
            original = self.lock[field]
            for value in values:
                with self.subTest(field=field, value=value):
                    self.lock[field] = value
                    self.write_lock()
                    with self.assertRaisesRegex(ValueError, "identity does not match"):
                        snapshot.verify(self.root)
            self.lock[field] = original

    def test_missing_identity_fields_are_rejected(self):
        for field in ("format_version", "repository", "revision", "roots"):
            with self.subTest(field=field):
                value = self.lock.pop(field)
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "identity does not match"):
                    snapshot.read_lock(self.root)
                self.lock[field] = value

    def test_missing_or_malformed_lock_is_rejected(self):
        (self.root / LOCK).unlink()
        with self.assertRaises(FileNotFoundError):
            snapshot.verify(self.root)
        self.write(LOCK, b"{truncated")
        with self.assertRaises(json.JSONDecodeError):
            snapshot.verify(self.root)

    def test_inventory_must_be_a_nonempty_mapping(self):
        for value in (None, {}, [], "digest", 42):
            with self.subTest(value=value):
                self.lock["sha256"] = value
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "nonempty SHA-256 inventory"):
                    snapshot.read_lock(self.root)
        del self.lock["sha256"]
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "nonempty SHA-256 inventory"):
            snapshot.read_lock(self.root)

    def test_each_root_must_have_an_inventory_entry(self):
        for omitted in ROOTS:
            with self.subTest(omitted=omitted):
                self.lock["sha256"] = {
                    name: sha256(data) for name, data in self.contents.items()
                    if not name.startswith(omitted + "/")
                }
                self.write_lock()
                with self.assertRaisesRegex(ValueError, f"snapshot lock omits root: {omitted}"):
                    snapshot.read_lock(self.root)

    def test_digest_shape_is_exactly_lowercase_sha256(self):
        name = next(iter(self.contents))
        for value in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64,
                      "a" * 64 + "\n", " " + "a" * 64, 123, None, [], {}):
            with self.subTest(value=value):
                self.lock["sha256"][name] = value
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "invalid snapshot digest"):
                    snapshot.read_lock(self.root)

    def test_well_formed_but_wrong_digest_is_content_drift(self):
        name = next(iter(self.contents))
        self.lock["sha256"][name] = "0" * 64
        self.write_lock()
        self.assertEqual(snapshot.read_lock(self.root)[name], "0" * 64)
        with self.assertRaisesRegex(ValueError, "snapshot content/inventory drift"):
            snapshot.verify(self.root)

    def test_unsafe_and_noncanonical_inventory_paths_are_rejected(self):
        names = (
            "", "/", "/proto/a", "/conformance/a", "proto", "proto/", "proto/a/",
            "./proto/a", "proto//a", "proto/./a", "proto/../conformance/a",
            "../proto/a", "proto/sub/../../a", "conformance/sub/../a",
            "other/a", "C:/proto/a",
        )
        for name in names:
            with self.subTest(name=name):
                self.lock["sha256"][name] = "a" * 64
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "out-of-scope snapshot path"):
                    snapshot.read_lock(self.root)
                del self.lock["sha256"][name]

    def test_canonical_nested_unicode_and_space_paths_are_supported(self):
        name = "conformance/nested/space and caf\u00e9.bin"
        data = b"binary\x00\xff"
        self.write(name, data)
        self.lock["sha256"][name] = sha256(data)
        self.write_lock()
        self.assertEqual(snapshot.snapshot_path(name).as_posix(), name)
        self.assertEqual(snapshot.verify(self.root), len(self.contents) + 1)


class SymlinkBoundaryTests(SnapshotFixture):
    def test_symlink_snapshot_roots_are_rejected(self):
        for prefix in ROOTS:
            with self.subTest(prefix=prefix):
                directory = self.root / prefix
                target = self.root / f"saved-{prefix}"
                directory.rename(target)
                self.symlink(target, directory, directory=True)
                with self.assertRaisesRegex(ValueError, "missing or symlinked snapshot root"):
                    snapshot.verify(self.root)
                directory.unlink()
                target.rename(directory)

    def test_symlink_snapshot_files_are_rejected_even_with_matching_bytes(self):
        for name, content in self.contents.items():
            with self.subTest(name=name):
                target = self.write("external-file", content)
                path = self.root / name
                path.unlink()
                self.symlink(target, path)
                with self.assertRaisesRegex(ValueError, "snapshot symlink is not permitted"):
                    snapshot.verify(self.root)
                path.unlink()
                path.write_bytes(content)

    def test_symlink_parents_are_rejected_by_inventory_and_destination_validation(self):
        parent = self.root / "proto/syntra"
        target = self.root / "external-parent"
        parent.rename(target)
        self.symlink(target, parent, directory=True)
        with self.assertRaisesRegex(ValueError, "snapshot symlink is not permitted"):
            snapshot.verify(self.root)
        with self.assertRaisesRegex(ValueError, "snapshot symlink is not permitted"):
            snapshot.local_path(self.root, "proto/syntra/v1/new.proto")

    def test_dangling_symlinks_are_rejected(self):
        self.symlink(self.root / "does-not-exist", self.root / "conformance/dangling")
        with self.assertRaisesRegex(ValueError, "snapshot symlink is not permitted"):
            snapshot.verify(self.root)

    def test_symlink_cache_artifacts_are_not_silently_ignored(self):
        for leaf in (".DS_Store", "__pycache__"):
            with self.subTest(leaf=leaf):
                link = self.root / "conformance" / leaf
                self.symlink(self.root / "missing-cache", link)
                with self.assertRaisesRegex(ValueError, "snapshot symlink is not permitted"):
                    snapshot.verify(self.root)
                link.unlink()


class GitProvenanceTests(SnapshotFixture):
    def test_optional_git_comparison_reads_exact_committed_blobs(self):
        with self.git_objects() as git:
            self.assertEqual(snapshot.verify(self.root, self.root / "source-checkout"), len(self.contents))
        self.assertEqual(git.call_count, 2 + len(self.contents))

    def test_local_drift_is_rejected_before_optional_git_comparison(self):
        self.write(next(iter(self.contents)), b"dirty")
        with mock.patch.object(snapshot, "from_git") as source:
            with self.assertRaisesRegex(ValueError, "snapshot content/inventory drift"):
                snapshot.verify(self.root, self.root / "source-checkout")
        source.assert_not_called()

    def test_git_provenance_rejects_mutated_missing_and_extra_source(self):
        name = next(iter(self.contents))
        sources = (
            {**self.contents, name: b"different committed bytes"},
            {key: value for key, value in self.contents.items() if key != name},
            {**self.contents, "proto/additional.proto": b"extra committed input"},
        )
        # Keep both roots represented in the missing-file case.
        self.write("proto/second.proto", b"second")
        self.contents["proto/second.proto"] = b"second"
        self.lock["sha256"]["proto/second.proto"] = sha256(b"second")
        self.write_lock()
        for index, source in enumerate(sources):
            source["proto/second.proto"] = b"second"
            with self.subTest(case=index), self.git_objects(source):
                with self.assertRaisesRegex(ValueError, "upstream Git provenance drift"):
                    snapshot.verify(self.root, self.root / "source-checkout")

    def test_git_commit_must_resolve_to_full_reviewed_sha(self):
        with self.git_objects(resolved="0" * 40) as git:
            with self.assertRaisesRegex(ValueError, "reviewed full SHA"):
                snapshot.from_git(self.root / "source-checkout")
        self.assertEqual(git.call_count, 1)

    def test_git_tree_requires_regular_nonexecutable_blobs(self):
        for mode, kind in (("100755", "blob"), ("120000", "blob"),
                           ("160000", "commit"), ("040000", "tree")):
            tree = f"{mode} {kind} {'a' * 40}\tproto/bad.proto\0".encode("ascii")
            with self.subTest(mode=mode, kind=kind), self.git_objects(tree=tree):
                with self.assertRaisesRegex(ValueError, "regular non-executable blobs"):
                    snapshot.from_git(self.root / "source-checkout")

    def test_git_tree_paths_are_validated_before_reading_blobs(self):
        for name in ("/proto/a", "proto/../a", "proto//a", "proto/./a", "other/a"):
            tree = f"100644 blob {'a' * 40}\t{name}\0".encode("ascii")
            with self.subTest(name=name), self.git_objects(tree=tree) as git:
                with self.assertRaisesRegex(ValueError, "out-of-scope snapshot path"):
                    snapshot.from_git(self.root / "source-checkout")
                self.assertEqual(git.call_count, 2)

    def test_git_tree_must_include_both_roots(self):
        for omitted in ROOTS:
            contents = {name: data for name, data in self.contents.items()
                        if not name.startswith(omitted + "/")}
            with self.subTest(omitted=omitted), self.git_objects(contents):
                with self.assertRaisesRegex(ValueError, f"upstream tree omits root: {omitted}"):
                    snapshot.from_git(self.root / "source-checkout")

    def test_git_subprocess_is_local_bounded_and_checked(self):
        upstream = self.root / "source-checkout"
        completed = subprocess.CompletedProcess([], 0, stdout=b"blob bytes", stderr=b"")
        with mock.patch.object(snapshot.subprocess, "run", return_value=completed) as run:
            self.assertEqual(snapshot.git(upstream, "cat-file", "blob", "a" * 40), b"blob bytes")
        run.assert_called_once_with(
            ["git", "-C", str(upstream), "cat-file", "blob", "a" * 40],
            check=True, capture_output=True, timeout=30,
        )


class SyncSafetyTests(SnapshotFixture):
    def test_noop_sync_preserves_every_destination_byte_and_mtime(self):
        before = self.tree_state()
        with self.git_objects():
            snapshot.sync(self.root, self.root / "source-checkout")
        self.assertEqual(self.tree_state(), before)

    def test_matching_edits_to_snapshot_and_lock_do_not_authorize_overwrite(self):
        name = next(iter(self.contents))
        self.write(name, b"local change")
        self.lock["sha256"][name] = sha256(b"local change")
        self.write_lock()
        def respond(upstream, *args):
            if args[0] == "status":
                return b" M upstream.lock.json\n M proto/syntra/v1/example.proto\n"
            raise AssertionError(f"unexpected command: {args}")
        with mock.patch.object(snapshot, "from_git", return_value=self.contents):
            with mock.patch.object(snapshot, "git", side_effect=respond):
                self.assert_sync_refused_unchanged("locally modified snapshots or lock")

    def test_lock_symlinks_and_nonregular_paths_fail_before_any_writes(self):
        external = self.root / "external-lock.json"
        external.write_bytes((self.root / LOCK).read_bytes())
        (self.root / LOCK).unlink()
        for target in (external, self.root / "missing-lock"):
            with self.subTest(target=target):
                self.symlink(target, self.root / LOCK)
                with self.git_objects():
                    self.assert_sync_refused_unchanged("regular file, never a symlink")
                (self.root / LOCK).unlink()
        (self.root / LOCK).mkdir()
        with self.git_objects():
            self.assert_sync_refused_unchanged("regular file, never a symlink")

    def test_explicit_sync_updates_clean_snapshot_and_lock_from_git(self):
        source = {**self.contents, "proto/new/nested.proto": b"new committed blob\n"}
        source[next(iter(self.contents))] = b"updated committed blob\n"
        with self.git_objects(source):
            count = snapshot.sync(self.root, self.root / "source-checkout")
        self.assertEqual(count, len(source))
        self.assertEqual(snapshot.local_files(self.root), source)
        lock = json.loads((self.root / LOCK).read_text(encoding="utf-8"))
        self.assertEqual(lock, {**self.lock, "sha256": {
            name: sha256(data) for name, data in sorted(source.items())
        }})
        self.assertTrue((self.root / LOCK).read_bytes().endswith(b"\n"))

    def test_bad_source_revision_fails_before_write(self):
        with self.git_objects(resolved="0" * 40):
            self.assert_sync_refused_unchanged("reviewed full SHA")

    def test_unsafe_or_nonregular_source_fails_before_write(self):
        for record in (
            f"100644 blob {'a' * 40}\tproto/../escape\0",
            f"120000 blob {'a' * 40}\tproto/link\0",
            f"100755 blob {'a' * 40}\tconformance/executable\0",
        ):
            with self.subTest(record=record), self.git_objects(tree=record.encode("ascii")):
                self.assert_sync_refused_unchanged("out-of-scope|regular non-executable")

    def test_missing_source_root_fails_before_write(self):
        source = {name: data for name, data in self.contents.items() if name.startswith("proto/")}
        with self.git_objects(source):
            self.assert_sync_refused_unchanged("upstream tree omits root")

    def test_git_failures_and_timeouts_fail_before_write(self):
        errors = (
            subprocess.CalledProcessError(128, ["git", "rev-parse"]),
            subprocess.TimeoutExpired(["git", "ls-tree"], 30),
            FileNotFoundError("Git executable missing"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(snapshot, "git", side_effect=error):
                    self.assert_sync_refused_unchanged(".*", type(error))

    def test_dirty_missing_or_extra_local_snapshot_fails_before_write(self):
        name = next(iter(self.contents))
        for change in ("modified", "missing", "extra"):
            with self.subTest(change=change):
                if change == "modified":
                    self.write(name, b"dirty local content")
                elif change == "missing":
                    (self.root / name).unlink()
                else:
                    self.write("conformance/untracked.txt", b"unreviewed local content")
                with self.git_objects():
                    self.assert_sync_refused_unchanged("snapshot content/inventory drift")
                self.write(name, self.contents[name])
                (self.root / "conformance/untracked.txt").unlink(missing_ok=True)

    def test_identity_mismatch_fails_before_write(self):
        self.lock["revision"] = "0" * 40
        self.write_lock()
        with self.git_objects():
            self.assert_sync_refused_unchanged("identity does not match")

    def test_upstream_removal_needs_review_and_never_deletes_local_input(self):
        source = {"proto/replacement.proto": b"new", **{
            name: data for name, data in self.contents.items() if name.startswith("conformance/")
        }}
        with self.git_objects(source):
            self.assert_sync_refused_unchanged("review removed/local snapshot inputs first")

    def test_symlink_destination_parent_fails_before_write(self):
        self.symlink(self.root / "outside", self.root / "proto/new", directory=True)
        source = {**self.contents, "proto/new/file.proto": b"new"}
        with self.git_objects(source):
            self.assert_sync_refused_unchanged("snapshot symlink is not permitted")

    def test_initial_sync_refuses_tracked_dirty_snapshots_before_write(self):
        (self.root / LOCK).unlink()
        with mock.patch.object(snapshot, "from_git", return_value=self.contents):
            with mock.patch.object(snapshot, "git", return_value=b"proto/syntra/v1/example.proto\n") as git:
                self.assert_sync_refused_unchanged("refusing initial sync over locally modified")
        git.assert_called_once_with(self.root, "diff", "HEAD", "--name-only", "--", *ROOTS)

    def test_initial_sync_refuses_untracked_conflicting_bytes_before_write(self):
        # git diff HEAD reports tracked changes only. Model an untracked file
        # colliding with a committed source path; it must not be overwritten.
        (self.root / LOCK).unlink()
        self.write(next(iter(self.contents)), b"untracked local work")
        with mock.patch.object(snapshot, "from_git", return_value=self.contents):
            with mock.patch.object(snapshot, "git", return_value=b""):
                self.assert_sync_refused_unchanged("refusing|modified|dirty|conflict")

    def test_committed_cache_artifact_is_rejected_before_destination_write(self):
        # An accepted source must be representable by the local inventory.
        source = {**self.contents, "conformance/.DS_Store": b"committed metadata"}
        with self.git_objects(source):
            self.assert_sync_refused_unchanged(".*")


class ReadOnlyCliTests(SnapshotFixture):
    def test_check_cli_offline_success_is_read_only(self):
        before = self.tree_state()
        code, stdout, stderr = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn(ACCEPTED_REVISION, stdout)
        self.assertIn(f"{len(self.contents)} snapshot files match; offline digest check", stdout)
        self.assertEqual(stderr, "")
        self.assertEqual(self.tree_state(), before)

    def test_check_cli_drift_fails_without_rewriting_snapshot_or_lock(self):
        self.write(next(iter(self.contents)), b"dirty")
        before = self.tree_state()
        code, stdout, stderr = self.run_cli()
        self.assertIsInstance(code, str)
        self.assertIn("Upstream pin check failed: snapshot content/inventory drift", str(code))
        self.assertEqual((stdout, stderr), ("", ""))
        self.assertEqual(self.tree_state(), before)

    def test_check_cli_missing_lock_is_a_clean_failure(self):
        (self.root / LOCK).unlink()
        before = self.tree_state()
        code, stdout, stderr = self.run_cli()
        self.assertIsInstance(code, str)
        self.assertIn("Upstream pin check failed:", str(code))
        self.assertIn(LOCK, str(code))
        self.assertEqual((stdout, stderr), ("", ""))
        self.assertEqual(self.tree_state(), before)

    def test_check_cli_has_no_sync_permission(self):
        for args in (("--sync",), ("--sync", "--upstream", str(self.root / "source-checkout"))):
            with self.subTest(args=args):
                before = self.tree_state()
                code, stdout, stderr = self.run_cli(*args)
                self.assertEqual(code, 2)
                self.assertIn("unrecognized arguments: --sync", stderr)
                self.assertEqual(stdout, "")
                self.assertEqual(self.tree_state(), before)

    def test_check_cli_optional_upstream_comparison_is_read_only(self):
        before = self.tree_state()
        with self.git_objects():
            code, stdout, stderr = self.run_cli(
                "--upstream", str(self.root / "source-checkout"), allow_git=True
            )
        self.assertEqual(code, 0)
        self.assertIn("verified against upstream Git blobs", stdout)
        self.assertEqual(stderr, "")
        self.assertEqual(self.tree_state(), before)

    def test_check_cli_reports_git_failure_without_writes(self):
        before = self.tree_state()
        error = subprocess.CalledProcessError(128, ["git", "rev-parse"])
        with mock.patch.object(snapshot, "git", side_effect=error):
            code, stdout, stderr = self.run_cli(
                "--upstream", str(self.root / "source-checkout"), allow_git=True
            )
        self.assertIsInstance(code, str)
        self.assertIn("Upstream pin check failed:", str(code))
        self.assertEqual((stdout, stderr), ("", ""))
        self.assertEqual(self.tree_state(), before)

    def test_snapshot_cli_requires_source_for_explicit_sync(self):
        before = self.tree_state()
        with mock.patch.object(sys, "argv", [str(SCRIPTS / "upstream_snapshot.py"), "--sync"]):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                with mock.patch.object(snapshot, "sync") as sync:
                    with self.assertRaises(SystemExit) as exited:
                        snapshot.main(sync_allowed=True)
        self.assertEqual(exited.exception.code, 2)
        self.assertIn("--sync requires --upstream", stderr.getvalue())
        sync.assert_not_called()
        self.assertEqual(self.tree_state(), before)


if __name__ == "__main__":
    unittest.main()
