import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
DERIVE = b"#[derive(Clone, PartialEq, ::prost::Message)]\n"
HELLO = b"pub struct ClientHello {\n}\n"
OTHER = DERIVE + b"pub struct Other {\n}\n"
STUB = """#!/usr/bin/env python3
import os
from pathlib import Path
import shutil
import sys

if sys.argv[1:] == ["--version"]:
    print(os.environ["STUB_VERSION"])
elif sys.argv[1] == "generate":
    root = Path(__file__).resolve().parent
    if sys.argv[2:] != [str(root), "--template", str(root / "buf.gen.yaml")]:
        sys.exit("unexpected buf generate arguments")
    if Path.cwd() == root:
        sys.exit("buf generate must not write in the repository")
    shutil.copytree(root / "stub-output", "crates/syntra-core/src/generated")
else:
    sys.exit("unexpected buf arguments")
"""


@unittest.skipUnless(os.name == "posix", "the PATH stub uses a POSIX shebang")
class CheckGeneratedTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.script = self.root / "scripts/check-generated.py"
        self.script.parent.mkdir()
        shutil.copyfile(ROOT / "scripts/check-generated.py", self.script)
        stub = self.root / "buf"
        stub.write_text(STUB)
        stub.chmod(0o755)
        (self.root / "python3").symlink_to(sys.executable)
        self.env = {**os.environ, "PATH": str(self.root), "STUB_VERSION": "1.59.0"}

        self.fixture = self.root / "stub-output"
        (self.fixture / "nested").mkdir(parents=True)
        (self.fixture / "nested/a.rs").write_bytes(b"one\ntwo\n")
        self.message = self.fixture / "syntra.v1.rs"
        self.message.write_bytes(DERIVE + HELLO + OTHER)
        self.output = self.root / "crates/syntra-core/src/generated"

    def invoke(self, *args, success=True):
        result = subprocess.run([sys.executable, self.script, *args], cwd=self.script.parent,
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        return result.stderr

    def snapshot(self):
        return {p.relative_to(self.output).as_posix(): p.read_bytes()
                for p in self.output.rglob("*") if p.is_file()}

    def test_stub_rejects_wrong_arguments_and_cwd_under_optimization(self):
        args = [str(self.root), "--template", str(self.root / "buf.gen.yaml")]
        for cwd, argv, message in [(self.script.parent, args[:-1], "unexpected buf generate arguments"),
                                   (self.root, args, "buf generate must not write in the repository")]:
            with self.subTest(cwd=cwd):
                result = subprocess.run([self.root / "buf", "generate", *argv], cwd=cwd,
                                        env={**self.env, "PYTHONOPTIMIZE": "1"},
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr.strip(), message)

    def test_repeated_generation_and_check(self):
        self.output.mkdir(parents=True)
        (self.output / "syntra.v1.rs").write_bytes(b"stale\n")
        expected = {"syntra.v1.rs": DERIVE + b"#[prost(skip_debug)]\n" + HELLO + OTHER,
                    "nested/a.rs": b"one\ntwo\n"}
        for _ in range(2):
            self.invoke("--write")
            self.assertEqual(self.snapshot(), expected)
            self.invoke()
            shutil.rmtree(self.output)

    def test_check_detects_newline_drift_without_writing(self):
        self.invoke("--write")
        (self.output / "nested/a.rs").write_bytes(b"one\r\ntwo\r\n")
        before = self.snapshot()
        self.assertEqual(self.invoke(success=False).splitlines()[1:], ["nested/a.rs"])
        self.assertEqual(self.snapshot(), before)

    def test_check_lists_all_drift_and_write_refuses_all_obsolete_files(self):
        self.output.mkdir(parents=True)
        for name in ("z.rs", "y.rs", "syntra.v1.rs"):
            (self.output / name).write_bytes(b"old\n")
        before = self.snapshot()
        for args, names in [((), ["nested/a.rs", "syntra.v1.rs", "y.rs", "z.rs"]),
                            (("--write",), ["y.rs", "z.rs"])]:
            with self.subTest(args=args):
                error = self.invoke(*args, success=False)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(error.splitlines()[1:], names)

    def test_empty_build_reports_every_checked_in_file_and_refuses_to_write(self):
        self.invoke("--write")
        before = self.snapshot()
        shutil.rmtree(self.fixture)
        self.fixture.mkdir()
        for args in ((), ("--write",)):
            with self.subTest(args=args):
                error = self.invoke(*args, success=False)
                self.assertIn("no Rust bindings generated", error)
                self.assertEqual(error.splitlines()[1:], sorted(before))
                self.assertEqual(self.snapshot(), before)

    def test_write_requires_one_unambiguous_client_hello(self):
        for contents in (OTHER, (DERIVE + HELLO) * 2):
            with self.subTest(contents=contents):
                self.message.write_bytes(contents)
                self.assertIn("expected exactly one generated ClientHello", self.invoke("--write", success=False))
                self.assertFalse(self.output.exists())

    def test_wrong_buf_version_fails_without_writing(self):
        self.env["STUB_VERSION"] = "1.59.1"
        self.assertIn("Buf 1.59.0 required; found 1.59.1", self.invoke("--write", success=False))
        self.assertFalse(self.output.exists())
