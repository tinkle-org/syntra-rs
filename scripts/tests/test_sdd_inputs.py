"""Current implementation inputs and scoped upstream provenance regressions."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import sdd_inputs as inputs
from upstream_snapshot import REPOSITORY, REQUIRED_INPUTS, REVISION, digest


PROTO = "proto/syntra/v1/envelope.proto"
TCP_VECTORS = "conformance/test-vectors/tcp/byte-vectors.yaml"
WS_VECTORS = "conformance/test-vectors/websocket/fixtures.yaml"


class ImplementationInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.origin = "conformance/test-vectors/protobuf/vectors.yaml"
        self.source = {name: (name + "\n").encode() for name in REQUIRED_INPUTS}
        for name, content in self.source.items():
            if name.startswith("proto/"):
                self.write(name, content)
        for destination, origin in inputs.TEST_ASSETS.items():
            self.write(destination, self.source[origin])
        self.write("upstream.lock.json", json.dumps({
            "format_version": 2, "scope": "implementation-inputs",
            "repository": REPOSITORY, "revision": REVISION,
            "sha256": {name: digest(data) for name, data in self.source.items()},
        }).encode())

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_offline_checks_selected_assets_and_proto_without_local_conformance(self):
        with mock.patch.object(inputs, "from_git", side_effect=AssertionError("offline Git")):
            result, source = inputs.verify_inputs(self.root, offline=True)
        self.assertEqual(result["test_assets"], 1)
        self.assertEqual(result["local_proto_files"], 8)
        self.assertEqual(result["upstream_files"], len(self.source))
        self.assertEqual(result["provenance"], "offline_digest_only")
        self.assertIsNone(source)
        self.assertFalse((self.root / "conformance").exists())

    def test_external_git_provenance_required_by_default(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("SYNTRA_SDD_ROOT", None)
            with mock.patch.object(inputs, "from_git", return_value=self.source) as read:
                result, source = inputs.verify_inputs(self.root)
        read.assert_called_once_with(self.root.parent / "syntra")
        self.assertEqual(source, self.source)
        self.assertEqual(result["provenance"], "exact_committed_git_blobs")

    def test_environment_and_explicit_root_precedence(self):
        with mock.patch.dict("os.environ", {"SYNTRA_SDD_ROOT": "/environment"}):
            self.assertEqual(inputs.sdd_root(root=self.root), Path("/environment"))
            self.assertEqual(inputs.sdd_root(Path("/explicit"), self.root), Path("/explicit"))

    def test_missing_external_git_is_not_offline_fallback(self):
        with mock.patch.object(inputs, "from_git", side_effect=FileNotFoundError("missing SDD")):
            with self.assertRaises(FileNotFoundError):
                inputs.verify_inputs(self.root)

    def test_external_provenance_checks_transcribed_vectors_without_local_copies(self):
        for name in (TCP_VECTORS, WS_VECTORS):
            source = {**self.source, name: b"changed upstream vector"}
            with self.subTest(name=name), mock.patch.object(inputs, "from_git", return_value=source):
                with self.assertRaisesRegex(ValueError, "Git provenance drift"):
                    inputs.verify_inputs(self.root)
        self.assertFalse((self.root / "conformance").exists())

    def test_corrupted_or_missing_asset_is_never_inferred_from_lock(self):
        for destination, origin in inputs.TEST_ASSETS.items():
            with self.subTest(destination=destination):
                path = self.write(destination, b"wrong")
                with self.assertRaisesRegex(ValueError, "test asset origin drift"):
                    inputs.verify_inputs(self.root, offline=True)
                path.unlink()
                with self.assertRaisesRegex(ValueError, "missing implementation input"):
                    inputs.verify_inputs(self.root, offline=True)
                self.write(destination, self.source[origin])

    def test_only_selected_current_assets_are_local_inputs(self):
        self.assertEqual(inputs.TEST_ASSETS, {
            "tests/interoperability/fixtures/protobuf-vectors.yaml": self.origin,
        })
        self.assertFalse((self.root / "tests/interoperability/fixtures/unrelated.json").exists())
        result, _ = inputs.verify_inputs(self.root, offline=True)
        self.assertEqual(result["upstream_files"], len(self.source))

    def test_modified_and_missing_proto_are_rejected(self):
        for change in ("modified", "missing"):
            with self.subTest(change=change):
                path = self.write(PROTO, b"changed")
                if change == "missing":
                    path.unlink()
                with self.assertRaisesRegex(ValueError, "implementation proto drift.*" + PROTO):
                    inputs.verify_inputs(self.root, offline=True)

    def test_extra_inputs_are_not_exempted_by_extension_or_dotfile(self):
        for leaf in ("README.md", "manifest.yaml", "result.json", "other.proto", ".hidden"):
            with self.subTest(leaf=leaf):
                path = self.write(f"proto/extra/{leaf}", b"unreviewed")
                with self.assertRaisesRegex(ValueError, "implementation proto drift") as error:
                    inputs.verify_inputs(self.root, offline=True)
                self.assertIn(path.relative_to(self.root).as_posix(), str(error.exception))
                path.unlink()

    def test_only_documented_cache_artifacts_are_ignored(self):
        self.write("proto/.DS_Store", b"OS metadata")
        self.write("proto/nested/__pycache__/artifact.pyc", b"Python cache")
        self.write("outside-inputs.txt", b"unrelated")
        result, _ = inputs.verify_inputs(self.root, offline=True)
        self.assertEqual(result["local_proto_files"], 8)

    def test_missing_or_non_directory_proto_root_is_rejected(self):
        directory = self.root / "proto"
        directory.rename(self.root / "saved-proto")
        with self.assertRaisesRegex(ValueError, "missing or symlinked proto root"):
            inputs.verify_inputs(self.root, offline=True)
        directory.write_bytes(b"not a directory")
        with self.assertRaisesRegex(ValueError, "missing or symlinked proto root"):
            inputs.verify_inputs(self.root, offline=True)

    def test_selected_asset_requires_a_pinned_origin(self):
        path = self.root / "upstream.lock.json"
        lock = json.loads(path.read_bytes())
        del lock["sha256"][self.origin]
        path.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "snapshot lock omits required inputs"):
            inputs.verify_inputs(self.root, offline=True)

    def test_asset_mapping_cannot_refer_to_unpinned_origins(self):
        with mock.patch.dict(inputs.TEST_ASSETS, {"tests/unrelated.yaml": "conformance/notes/unrelated.yaml"}):
            with self.assertRaisesRegex(ValueError, "test asset has no pinned origin"):
                inputs.verify_inputs(self.root, offline=True)

    def test_missing_transcription_origins_are_rejected(self):
        for omitted in (TCP_VECTORS, WS_VECTORS):
            source = {name: data for name, data in self.source.items() if name != omitted}
            with self.subTest(omitted=omitted), mock.patch.object(inputs, "from_git", return_value=source):
                with self.assertRaisesRegex(ValueError, "upstream Git provenance drift.*" + omitted):
                    inputs.verify_inputs(self.root)

    def test_unrelated_conformance_files_are_not_local_inputs(self):
        self.write("conformance/notes/unrelated.json", b"unrelated local content")
        result, _ = inputs.verify_inputs(self.root, offline=True)
        self.assertEqual(result["upstream_files"], len(REQUIRED_INPUTS))

    def test_extra_lock_entry_cannot_expand_upstream_scope(self):
        path = self.root / "upstream.lock.json"
        lock = json.loads(path.read_bytes())
        lock["sha256"]["conformance/notes/unrelated.json"] = digest(b"unrelated")
        path.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "out-of-scope snapshot path"):
            inputs.verify_inputs(self.root, offline=True)

    def test_matching_local_lock_edits_do_not_bypass_git_provenance(self):
        path = self.root / "upstream.lock.json"
        lock = json.loads(path.read_bytes())
        self.write(PROTO, b"local change")
        lock["sha256"][PROTO] = digest(b"local change")
        path.write_text(json.dumps(lock))
        with mock.patch.object(inputs, "from_git", return_value=self.source):
            with self.assertRaisesRegex(ValueError, "upstream Git provenance drift.*" + PROTO):
                inputs.verify_inputs(self.root)

    def test_symlinked_proto_file_is_rejected_even_with_matching_bytes(self):
        destination = self.root / PROTO
        target = self.write("external.proto", destination.read_bytes())
        destination.unlink()
        destination.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.verify_inputs(self.root, offline=True)

    def test_symlinked_proto_parent_is_rejected(self):
        parent = self.root / "proto/nested"
        parent.symlink_to(self.root / "elsewhere", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.verify_inputs(self.root, offline=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.regular_file(self.root, "proto/nested/input.proto")

    def test_dangling_symlinked_proto_input_is_rejected(self):
        (self.root / "proto/dangling").symlink_to(self.root / "does-not-exist")
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.verify_inputs(self.root, offline=True)

    def test_symlinked_cache_artifacts_are_not_silently_ignored(self):
        for leaf in (".DS_Store", "__pycache__"):
            with self.subTest(leaf=leaf):
                link = self.root / "proto" / leaf
                link.symlink_to(self.root / "missing-cache")
                with self.assertRaisesRegex(ValueError, "symlink"):
                    inputs.verify_inputs(self.root, offline=True)
                link.unlink()

    def test_dangling_symlinked_asset_is_rejected(self):
        destination = self.root / next(iter(inputs.TEST_ASSETS))
        destination.unlink()
        destination.symlink_to(self.root / "missing-asset")
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.verify_inputs(self.root, offline=True)

    def test_asset_drift_is_rejected_before_git_comparison(self):
        self.write(next(iter(inputs.TEST_ASSETS)), b"changed")
        with mock.patch.object(inputs, "from_git") as source:
            with self.assertRaisesRegex(ValueError, "test asset origin drift"):
                inputs.verify_inputs(self.root)
        source.assert_not_called()

    def test_offline_lock_retains_the_transcription_origins(self):
        from upstream_snapshot import read_lock
        self.assertTrue({TCP_VECTORS, WS_VECTORS}.issubset(read_lock(self.root)))
        inputs.verify_inputs(self.root, offline=True)

    def test_symlinked_asset_is_rejected_even_with_matching_bytes(self):
        destination = self.root / next(iter(inputs.TEST_ASSETS))
        content = destination.read_bytes()
        destination.unlink()
        target = self.write("elsewhere.yaml", content)
        destination.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.verify_inputs(self.root, offline=True)

    def test_symlinked_proto_root_is_rejected(self):
        (self.root / "proto").rename(self.root / "saved-proto")
        (self.root / "proto").symlink_to(self.root / "saved-proto", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinked proto"):
            inputs.verify_inputs(self.root, offline=True)

    def test_symlinked_asset_parent_is_rejected(self):
        parent = self.root / "tests/interoperability/fixtures"
        parent.rename(self.root / "saved-assets")
        parent.symlink_to(self.root / "saved-assets", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            inputs.verify_inputs(self.root, offline=True)

    def test_cli_is_read_only_and_has_no_local_conformance_requirement(self):
        import contextlib
        import io
        import upstream_snapshot
        before = {path: path.stat().st_mtime_ns for path in self.root.rglob("*")}
        with mock.patch.object(upstream_snapshot, "ROOT", self.root), \
                mock.patch.object(sys, "argv", ["check-upstream-pin.py", "--offline"]), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(upstream_snapshot.main(), 0)
        self.assertIn("offline_digest_only", output.getvalue())
        self.assertEqual(before, {path: path.stat().st_mtime_ns for path in self.root.rglob("*")})


if __name__ == "__main__":
    unittest.main()
