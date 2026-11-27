import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
STUB = """#!/usr/bin/env python3
import json
from pathlib import Path
import shutil
import sys

if sys.argv[1:] == ["--version"]:
    print("3.2.3")
elif sys.argv[1:] == ["build"]:
    config = json.loads(Path("bebop.json").read_text())
    output = Path(config["generators"]["rust"]["outFile"]).parent
    shutil.copytree("schemas/stub-output", output)
else:
    sys.exit("unexpected bebopc arguments")
"""


@unittest.skipUnless(os.name == "posix", "the PATH stub uses a POSIX shebang")
class CheckGeneratedTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.script = self.root / "scripts/check-generated.py"
        self.script.parent.mkdir()
        shutil.copyfile(ROOT / "scripts/check-generated.py", self.script)
        shutil.copyfile(ROOT / "bebop.json", self.root / "bebop.json")
        stub = self.root / "bebopc"
        stub.write_text(STUB)
        stub.chmod(0o755)
        (self.root / "python3").symlink_to(sys.executable)
        self.env = {**os.environ, "PATH": str(self.root)}

        self.fixture = self.root / "schemas/stub-output"
        (self.fixture / "nested").mkdir(parents=True)
        (self.fixture / "nested/a.rs").write_bytes(b"one\ntwo\n")
        (self.fixture / "b.rs").write_bytes(b"three\r\nfour\r\n")
        self.output = self.root / "crates/syntra-core/src/generated"

    def invoke(self, *args, success=True):
        result = subprocess.run([sys.executable, self.script, *args], cwd=self.root,
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0 if success else 1, result.stderr)
        return result.stderr

    def snapshot(self):
        return {p.relative_to(self.output).as_posix(): p.read_bytes()
                for p in self.output.rglob("*") if p.is_file()}

    def test_repeated_generation_and_check(self):
        self.output.mkdir(parents=True)
        (self.output / "b.rs").write_bytes(b"stale\n")
        expected = {"b.rs": b"three\nfour\n", "nested/a.rs": b"one\ntwo\n"}
        for _ in range(2):
            self.invoke("--write")
            self.assertEqual(self.snapshot(), expected)
            self.invoke()
            shutil.rmtree(self.output)

    def test_check_accepts_either_newline_without_writing(self):
        (self.output / "nested").mkdir(parents=True)
        (self.output / "nested/a.rs").write_bytes(b"one\r\ntwo\r\n")
        (self.output / "b.rs").write_bytes(b"three\nfour\n")
        before = self.snapshot()
        self.invoke()
        self.assertEqual(self.snapshot(), before)

    def test_check_lists_all_drift_and_write_refuses_all_obsolete_files(self):
        self.output.mkdir(parents=True)
        for name in ("z.rs", "y.rs", "b.rs"):
            (self.output / name).write_bytes(b"old\n")
        before = self.snapshot()
        for args, names in [((), ["b.rs", "nested/a.rs", "y.rs", "z.rs"]),
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
