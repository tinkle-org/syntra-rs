"""Scoped input pin and read-only CLI regressions using temporary local inputs.

Git provenance is modeled at the command boundary with exact pinned objects.
Both entry points run through runpy; only the implementation input root is
redirected, so neither test execution nor CLI verification touches repo inputs.
"""

import contextlib
import hashlib
import io
import itertools
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import sdd_inputs as inputs
import upstream_snapshot as snapshot


ENTRY_POINTS = (SCRIPTS / "check-upstream-pin.py", SCRIPTS / "upstream_snapshot.py")
ACCEPTED_REVISION = "8ede3810b29fbba4d0e6ae6751a0025ceedda140"
ACCEPTED_REPOSITORY = "https://github.com/tinkle-org/syntra"
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
PROTO = "proto/syntra/v1/envelope.proto"
LOCK = "upstream.lock.json"


def sha256(content):
    # Independent fixture oracle: do not construct expected hashes with the SUT.
    return hashlib.sha256(content).hexdigest()


class SnapshotFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="syntra-inventory-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.upstream = self.root / "source-checkout"
        self.contents = {name: (name + "\r\n").encode() for name in REQUIRED_INPUTS}
        for name, content in self.contents.items():
            if name.startswith("proto/"):
                self.write(name, content)
        for destination, origin in inputs.TEST_ASSETS.items():
            self.write(destination, self.contents[origin])
        self.lock = {
            "format_version": 2,
            "scope": "implementation-inputs",
            "repository": ACCEPTED_REPOSITORY,
            "revision": ACCEPTED_REVISION,
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

    def git_objects(self, contents=None, *, resolved=None, tree=None):
        """Exact command-response map: no worktree reads or floating refs."""
        if contents is None:
            contents = self.contents
        responses: dict[tuple[str, ...], bytes] = {
            ("rev-parse", "--verify", f"{ACCEPTED_REVISION}^{{commit}}"):
                ((resolved or ACCEPTED_REVISION) + "\n").encode("ascii"),
        }
        records = []
        for index, (name, content) in enumerate(sorted(contents.items()), 1):
            if name not in REQUIRED_INPUTS:
                continue
            blob = f"{index:040x}"
            records.append(f"100644 blob {blob}\t{name}".encode("utf-8") + b"\0")
            responses[("cat-file", "blob", blob)] = content
        responses[("ls-tree", "-rz", ACCEPTED_REVISION, "--", *REQUIRED_INPUTS)] = (
            b"".join(records) if tree is None else tree
        )

        def respond(upstream, *args):
            self.assertEqual(upstream, self.upstream)
            self.assertIn(args, responses, f"unexpected Git/worktree command: {args}")
            return responses[args]

        return mock.patch.object(snapshot, "git", side_effect=respond)

    def run_cli(self, entry, *args, allow_git=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        verify_inputs = inputs.verify_inputs

        def verify_at_temporary_root(root, upstream, *, offline):
            return verify_inputs(self.root, upstream, offline=offline)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(inputs, "verify_inputs", side_effect=verify_at_temporary_root))
            stack.enter_context(mock.patch.object(sys, "argv", [str(entry), *args]))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            stack.enter_context(contextlib.redirect_stderr(stderr))
            if not allow_git:
                stack.enter_context(mock.patch.object(
                    snapshot, "git", side_effect=AssertionError("offline CLI invoked Git")
                ))
            with self.assertRaises(SystemExit) as exited:
                runpy.run_path(str(entry), run_name="__main__")
        return exited.exception.code, stdout.getvalue(), stderr.getvalue()


class InventoryTests(SnapshotFixture):
    def test_constants_are_the_reviewed_identity(self):
        self.assertEqual(snapshot.REVISION, ACCEPTED_REVISION)
        self.assertEqual(snapshot.REPOSITORY, ACCEPTED_REPOSITORY)
        self.assertEqual(snapshot.REQUIRED_INPUTS, REQUIRED_INPUTS)
        self.assertEqual(snapshot.SCOPE, "implementation-inputs")
        self.assertEqual(snapshot.LOCK, LOCK)

    def test_inventory_hashes_exact_bytes_in_sorted_order(self):
        contents = {"proto/z": b"a\r\n", "conformance/a": b"\x00\xff", "proto/a": b"a\n"}
        actual = snapshot.inventory(contents)
        self.assertEqual(list(actual), sorted(contents))
        self.assertEqual(actual, {name: sha256(data) for name, data in contents.items()})
        self.assertNotEqual(actual["proto/z"], actual["proto/a"])

    def test_drift_diagnostic_lists_every_difference_deterministically(self):
        with self.assertRaises(ValueError) as error:
            snapshot.compare({"z": "old", "a": "missing"}, {"z": "new", "b": "extra"}, "drift")
        self.assertEqual(str(error.exception), "drift: a, b, z")


class LockValidationTests(SnapshotFixture):
    def test_lock_identity_mismatches_are_rejected(self):
        cases = {
            "format_version": (0, 1, "2", 2.0, True, None),
            "scope": ("complete-inventory", "", None, []),
            "repository": ("https://github.com/elsewhere/syntra", ACCEPTED_REPOSITORY + ".git", None),
            "revision": ("0" * 40, ACCEPTED_REVISION[:12], ACCEPTED_REVISION.upper(), None),
        }
        for field, values in cases.items():
            original = self.lock[field]
            for value in values:
                with self.subTest(field=field, value=value):
                    self.lock[field] = value
                    self.write_lock()
                    with self.assertRaisesRegex(ValueError, "identity does not match"):
                        inputs.verify_inputs(self.root, offline=True)
            self.lock[field] = original

    def test_missing_identity_fields_are_rejected(self):
        for field in ("format_version", "scope", "repository", "revision", "sha256"):
            with self.subTest(field=field):
                value = self.lock.pop(field)
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "identity does not match"):
                    snapshot.read_lock(self.root)
                self.lock[field] = value

    def test_missing_or_malformed_lock_is_rejected(self):
        (self.root / LOCK).unlink()
        with self.assertRaises(FileNotFoundError):
            inputs.verify_inputs(self.root, offline=True)
        self.write(LOCK, b"{truncated")
        with self.assertRaises(json.JSONDecodeError):
            inputs.verify_inputs(self.root, offline=True)

    def test_lock_must_be_a_json_object(self):
        for value in ([], None, "lock", 1):
            with self.subTest(value=value):
                self.write(LOCK, json.dumps(value).encode())
                with self.assertRaisesRegex(ValueError, "JSON object"):
                    snapshot.read_lock(self.root)

    def test_inventory_must_be_a_nonempty_mapping(self):
        for value in (None, {}, [], "digest", 42):
            with self.subTest(value=value):
                self.lock["sha256"] = value
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "nonempty SHA-256 inventory"):
                    snapshot.read_lock(self.root)
    def test_every_required_input_must_have_an_entry(self):
        for omitted in REQUIRED_INPUTS:
            with self.subTest(omitted=omitted):
                self.lock["sha256"] = {
                    name: sha256(data) for name, data in self.contents.items()
                    if name != omitted
                }
                self.write_lock()
                with self.assertRaisesRegex(ValueError, f"snapshot lock omits required inputs: {omitted}"):
                    snapshot.read_lock(self.root)

    def test_extra_schema_fields_and_old_format_are_rejected(self):
        for field in ("roots", "unexpected"):
            with self.subTest(field=field):
                self.lock[field] = ["proto", "conformance"]
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "identity does not match"):
                    snapshot.read_lock(self.root)
                del self.lock[field]
        self.lock.pop("scope")
        self.lock.update(format_version=1, roots=["proto", "conformance"])
        self.write_lock()
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            snapshot.read_lock(self.root)

    def test_duplicate_json_keys_are_rejected_at_every_level(self):
        original = json.dumps(self.lock)
        name = REQUIRED_INPUTS[0]
        cases = (
            original.replace('"format_version": 2', '"format_version": 1, "format_version": 2'),
            original.replace('"scope": "implementation-inputs"',
                             '"scope": "implementation-inputs", "scope": "implementation-inputs"'),
            original.replace('"sha256": {', '"sha256": {}, "sha256": {'),
            original.replace(f'"{name}": ', f'"{name}": "{sha256(self.contents[name])}", "{name}": '),
        )
        for content in cases:
            with self.subTest(content=content):
                self.write(LOCK, content.encode())
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    snapshot.read_lock(self.root)

    def test_digest_shape_is_exactly_lowercase_sha256(self):
        name = PROTO
        for value in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64,
                      "a" * 64 + "\n", " " + "a" * 64, 123, None, [], {}):
            with self.subTest(value=value):
                self.lock["sha256"][name] = value
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "invalid snapshot digest"):
                    snapshot.read_lock(self.root)

    def test_well_formed_but_wrong_digest_is_content_drift(self):
        name = PROTO
        self.lock["sha256"][name] = "0" * 64
        self.write_lock()
        self.assertEqual(snapshot.read_lock(self.root)[name], "0" * 64)
        with self.assertRaisesRegex(ValueError, "implementation proto drift"):
            inputs.verify_inputs(self.root, offline=True)

    def test_unsafe_and_noncanonical_inventory_paths_are_rejected(self):
        names = (
            "", "/", "/proto/a", "/conformance/a", "proto", "proto/", "proto/a/",
            "./proto/a", "proto//a", "proto/./a", "proto/../conformance/a",
            "../proto/a", "proto/sub/../../a", "conformance/sub/../a",
            "other/a", "C:/proto/a", "proto/.DS_Store", "conformance/__pycache__/a",
        )
        for name in names:
            with self.subTest(name=name):
                self.lock["sha256"][name] = "a" * 64
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "out-of-scope snapshot path"):
                    snapshot.read_lock(self.root)
                del self.lock["sha256"][name]

    def test_unconsumed_canonical_paths_are_outside_scope(self):
        for name in ("conformance/notes/unrelated.json", "proto/unrelated.proto",
                     "conformance/nested/space and caf\u00e9.bin"):
            with self.subTest(name=name):
                self.lock["sha256"][name] = sha256(b"binary\x00\xff")
                self.write_lock()
                with self.assertRaisesRegex(ValueError, "out-of-scope snapshot path"):
                    snapshot.read_lock(self.root)
                del self.lock["sha256"][name]

    def test_symlinked_or_nonregular_lock_is_rejected_without_writes(self):
        external = self.write("external-lock.json", (self.root / LOCK).read_bytes())
        path = self.root / LOCK
        path.unlink()
        for target in (external, self.root / "missing-lock"):
            with self.subTest(target=target):
                path.symlink_to(target)
                before = self.tree_state()
                with self.assertRaisesRegex(ValueError, "regular file, never a symlink"):
                    inputs.verify_inputs(self.root, offline=True)
                self.assertEqual(self.tree_state(), before)
                path.unlink()
        path.mkdir()
        before = self.tree_state()
        with self.assertRaisesRegex(ValueError, "regular file, never a symlink"):
            inputs.verify_inputs(self.root, offline=True)
        self.assertEqual(self.tree_state(), before)


class GitProvenanceTests(SnapshotFixture):
    def test_default_comparison_reads_exact_committed_blobs(self):
        before = self.tree_state()
        with self.git_objects() as git:
            result, source = inputs.verify_inputs(self.root, self.upstream)
        self.assertEqual(source, self.contents)
        self.assertEqual(result["upstream_files"], len(self.contents))
        self.assertEqual(git.call_count, 2 + len(self.contents))
        self.assertEqual(self.tree_state(), before)

    def test_local_drift_is_rejected_before_git_comparison(self):
        self.write(PROTO, b"dirty")
        with mock.patch.object(inputs, "from_git") as source:
            with self.assertRaisesRegex(ValueError, "implementation proto drift"):
                inputs.verify_inputs(self.root, self.upstream)
        source.assert_not_called()

    def test_git_provenance_rejects_modified_selected_inputs(self):
        for name in REQUIRED_INPUTS:
            source = {**self.contents, name: b"different committed bytes"}
            with self.subTest(name=name), self.git_objects(source):
                before = self.tree_state()
                with self.assertRaisesRegex(ValueError, "upstream Git provenance drift"):
                    inputs.verify_inputs(self.root, self.upstream)
                self.assertEqual(self.tree_state(), before)

    def test_unrelated_upstream_additions_do_not_expand_scope(self):
        sources = (
            {**self.contents, "conformance/notes/unrelated.json": b"unrelated"},
            {**self.contents, "proto/additional.proto": b"extra committed input"},
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index), self.git_objects(source):
                before = self.tree_state()
                _, selected = inputs.verify_inputs(self.root, self.upstream)
                self.assertEqual(selected, self.contents)
                self.assertEqual(self.tree_state(), before)

    def test_git_commit_must_resolve_to_full_reviewed_sha(self):
        for resolved in ("0" * 40, ACCEPTED_REVISION[:12], ACCEPTED_REVISION.upper()):
            with self.subTest(resolved=resolved), self.git_objects(resolved=resolved) as git:
                with self.assertRaisesRegex(ValueError, "reviewed full SHA"):
                    snapshot.from_git(self.upstream)
                self.assertEqual(git.call_count, 1)

    def test_git_tree_requires_regular_nonexecutable_blobs(self):
        for mode, kind in (("100755", "blob"), ("120000", "blob"),
                           ("160000", "commit"), ("040000", "tree")):
            tree = f"{mode} {kind} {'a' * 40}\t{PROTO}\0".encode("ascii")
            with self.subTest(mode=mode, kind=kind), self.git_objects(tree=tree):
                with self.assertRaisesRegex(ValueError, "regular non-executable blobs"):
                    snapshot.from_git(self.upstream)

    def test_git_tree_paths_are_validated_before_reading_blobs(self):
        for name in ("/proto/a", "proto/../a", "proto//a", "proto/./a", "other/a",
                     "conformance/.DS_Store", "proto/__pycache__/a"):
            tree = f"100644 blob {'a' * 40}\t{name}\0".encode("ascii")
            with self.subTest(name=name), self.git_objects(tree=tree) as git:
                with self.assertRaisesRegex(ValueError, "out-of-scope snapshot path"):
                    snapshot.from_git(self.upstream)
                self.assertEqual(git.call_count, 2)

    def test_git_tree_must_include_every_selected_input(self):
        for omitted in REQUIRED_INPUTS:
            contents = {name: data for name, data in self.contents.items()
                        if name != omitted}
            with self.subTest(omitted=omitted), self.git_objects(contents):
                with self.assertRaisesRegex(ValueError, f"upstream tree omits required inputs: {omitted}"):
                    snapshot.from_git(self.upstream)

    def test_duplicate_tree_paths_are_rejected_before_blob_reads(self):
        record = f"100644 blob {'a' * 40}\t{PROTO}\0".encode()
        with self.git_objects(tree=record * 2) as git:
            with self.assertRaisesRegex(ValueError, "duplicate upstream input"):
                snapshot.from_git(self.upstream)
        self.assertEqual(git.call_count, 2)

    def test_blob_ids_must_be_full_lowercase_object_ids(self):
        for blob in ("a" * 39, "a" * 41, "A" * 40, "g" * 40, "--help"):
            tree = f"100644 blob {blob}\t{PROTO}\0".encode()
            with self.subTest(blob=blob), self.git_objects(tree=tree) as git:
                with self.assertRaisesRegex(ValueError, "invalid upstream blob ID"):
                    snapshot.from_git(self.upstream)
                self.assertEqual(git.call_count, 2)

    def test_git_subprocess_is_local_bounded_and_checked(self):
        completed = subprocess.CompletedProcess([], 0, stdout=b"blob bytes", stderr=b"")
        with mock.patch.object(snapshot.subprocess, "run", return_value=completed) as run:
            self.assertEqual(snapshot.git(self.upstream, "cat-file", "blob", "a" * 40), b"blob bytes")
        run.assert_called_once_with(
            ["git", "-C", str(self.upstream), "cat-file", "blob", "a" * 40],
            check=True, capture_output=True, timeout=30, env=mock.ANY,
        )
        self.assertEqual(run.call_args.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")
        self.assertEqual(run.call_args.kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")


class ReadOnlyCliTests(SnapshotFixture):
    def test_fresh_processes_do_not_create_bytecode_or_rewrite_inputs(self):
        for name in ("check-upstream-pin.py", "upstream_snapshot.py", "sdd_inputs.py"):
            self.write(f"scripts/{name}", (SCRIPTS / name).read_bytes())
        for entry in ENTRY_POINTS:
            with self.subTest(entry=entry.name):
                before = self.tree_state()
                # Ignore Python environment settings so bytecode protection must
                # come from the entry point itself, even on the first import.
                result = subprocess.run(
                    [sys.executable, "-E", str(self.root / "scripts" / entry.name), "--offline"],
                    cwd=self.root, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("offline_digest_only", result.stdout)
                self.assertEqual(result.stderr, "")
                self.assertEqual(self.tree_state(), before)

    def test_offline_success_is_read_only_for_both_entry_points(self):
        for entry in ENTRY_POINTS:
            with self.subTest(entry=entry.name):
                before = self.tree_state()
                code, stdout, stderr = self.run_cli(entry, "--offline")
                self.assertEqual(code, 0)
                self.assertIn(ACCEPTED_REVISION, stdout)
                self.assertIn("8 proto files and 1 test assets match; offline_digest_only", stdout)
                self.assertIn(f"{len(self.contents)} scoped upstream implementation inputs (not local copies)", stdout)
                self.assertEqual(stderr, "")
                self.assertEqual(self.tree_state(), before)

    def test_default_and_explicit_upstream_verification_are_read_only(self):
        for entry in ENTRY_POINTS:
            for args in ((), ("--upstream", str(self.upstream))):
                with self.subTest(entry=entry.name, args=args):
                    before = self.tree_state()
                    with mock.patch.dict("os.environ", {"SYNTRA_SDD_ROOT": str(self.upstream)}):
                        with self.git_objects():
                            code, stdout, stderr = self.run_cli(entry, *args, allow_git=True)
                    self.assertEqual(code, 0)
                    self.assertIn("exact_committed_git_blobs", stdout)
                    self.assertEqual(stderr, "")
                    self.assertEqual(self.tree_state(), before)

    def test_drift_fails_without_rewriting_inputs_or_lock(self):
        self.write(PROTO, b"dirty")
        for entry in ENTRY_POINTS:
            with self.subTest(entry=entry.name):
                before = self.tree_state()
                code, stdout, stderr = self.run_cli(entry, "--offline")
                self.assertIsInstance(code, str)
                self.assertIn("implementation proto drift", str(code))
                self.assertEqual((stdout, stderr), ("", ""))
                self.assertEqual(self.tree_state(), before)

    def test_missing_lock_is_a_clean_failure(self):
        (self.root / LOCK).unlink()
        for entry in ENTRY_POINTS:
            with self.subTest(entry=entry.name):
                before = self.tree_state()
                code, stdout, stderr = self.run_cli(entry, "--offline")
                self.assertIsInstance(code, str)
                self.assertIn(LOCK, str(code))
                self.assertEqual((stdout, stderr), ("", ""))
                self.assertEqual(self.tree_state(), before)

    def test_removed_flags_and_combinations_are_rejected_without_writes(self):
        flag_groups = (("--vendored",), ("--sync",), ("--vendored", "--sync"))
        for entry, flags, offline, upstream in itertools.product(
            ENTRY_POINTS, flag_groups, (False, True), (False, True)
        ):
            args = [*flags]
            if offline:
                args.append("--offline")
            if upstream:
                args.extend(("--upstream", str(self.upstream)))
            with self.subTest(entry=entry.name, args=args):
                before = self.tree_state()
                code, stdout, stderr = self.run_cli(entry, *args)
                self.assertEqual(code, 2)
                self.assertIn("unrecognized arguments: " + " ".join(flags), stderr)
                self.assertEqual(stdout, "")
                self.assertEqual(self.tree_state(), before)

    def test_offline_and_upstream_are_mutually_exclusive(self):
        for entry in ENTRY_POINTS:
            with self.subTest(entry=entry.name):
                before = self.tree_state()
                code, stdout, stderr = self.run_cli(entry, "--offline", "--upstream", str(self.upstream))
                self.assertEqual(code, 2)
                self.assertIn("--offline cannot be combined with --upstream", stderr)
                self.assertEqual(stdout, "")
                self.assertEqual(self.tree_state(), before)

    def test_git_failures_and_timeouts_are_reported_without_writes(self):
        errors = (
            subprocess.CalledProcessError(128, ["git", "rev-parse"]),
            subprocess.TimeoutExpired(["git", "ls-tree"], 30),
            FileNotFoundError("Git executable missing"),
        )
        for entry, error in itertools.product(ENTRY_POINTS, errors):
            with self.subTest(entry=entry.name, error=type(error).__name__):
                before = self.tree_state()
                with mock.patch.object(snapshot, "git", side_effect=error):
                    code, stdout, stderr = self.run_cli(
                        entry, "--upstream", str(self.upstream), allow_git=True
                    )
                self.assertIsInstance(code, str)
                self.assertIn("check failed:", str(code))
                self.assertEqual((stdout, stderr), ("", ""))
                self.assertEqual(self.tree_state(), before)


if __name__ == "__main__":
    unittest.main()
