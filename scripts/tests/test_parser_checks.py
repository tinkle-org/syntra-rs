"""Exercise the parser runner's input and retention policy without building Rust."""

from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

if os.name != "posix":
    raise unittest.SkipTest("the parser runner uses POSIX resource limits")

from fuzz import check


class ParserChecks(unittest.TestCase):
    def test_only_large_frame_mode_adds_full_length_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("frame", "stream", "recovery"):
                for large in (False, True):
                    corpus = Path(tmp) / f"{name}-{large}"
                    limit = check.seed_corpus(corpus, name, large)
                    extra = sorted(corpus.glob("large-*"))
                    if name != "frame" or not large:
                        self.assertEqual(limit, 4096)
                        self.assertFalse(extra)
                        continue
                    self.assertEqual(limit, 1_048_577)
                    # Independent wire prefixes: version 1, ID 7, request, method,
                    # opaque payload. Both nested lengths must describe real bytes.
                    expected = [(8192, "9740", "8040"), (1_048_544, "f8ff3f", "e0ff3f"),
                                (1_048_545, "f9ff3f", "e1ff3f")]
                    self.assertEqual(len(extra), len(expected))
                    for path, (size, body_len, payload_len) in zip(extra, expected):
                        header = (bytes.fromhex("0801100762" + body_len + "0a12")
                                  + b"/example.Echo/Echo" + bytes.fromhex("12" + payload_len))
                        self.assertTrue(path.read_bytes() == header + b"\xa5" * size)

    def test_only_failed_run_with_an_emitted_unit_is_retained(self):
        for status, emitted in ((0, True), (1, False), (1, True)):
            with self.subTest(status=status, emitted=emitted), tempfile.TemporaryDirectory() as tmp:
                dest, output = Path(tmp) / "replay", Path(tmp) / "step-output"
                console = io.StringIO()

                def fake_target(argv, *, cwd, stdout, stderr, timeout, env):
                    self.assertEqual(argv[0].name, "frame")
                    self.assertIn("-max_len=1048577", argv)
                    self.assertIn("-timeout=5", argv)
                    self.assertIn("-rss_limit_mb=2048", argv)
                    self.assertEqual(timeout, 31)
                    self.assertEqual(set(env), {"PATH", "TMPDIR"})
                    (argv[1] / "mutation").write_bytes(b"corpus only")
                    stderr.write(b"raw log\nstat::number_of_executed_units: 42\n")
                    if emitted:
                        path, = [a.split("=", 1)[1] for a in argv[2:] if a.startswith("-exact_artifact_path=")]
                        Path(path).write_bytes(b"\x00unit\xff")
                    return subprocess.CompletedProcess(argv, status)

                with patch.object(subprocess, "run", side_effect=fake_target), \
                        patch.object(subprocess, "check_output", return_value="a" * 40), \
                        patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}), redirect_stdout(console):
                    if status:
                        with self.assertRaisesRegex(SystemExit, "raw output withheld"):
                            check.run_target("frame", "x86_64-unknown-linux-gnu", 1, True, dest)
                    else:
                        check.run_target("frame", "x86_64-unknown-linux-gnu", 1, True, dest)
                self.assertNotIn("raw log", console.getvalue())
                if not (status and emitted):
                    self.assertFalse(dest.exists())
                    self.assertFalse(output.exists())
                    continue
                self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
                self.assertEqual({p.name for p in dest.iterdir()}, {"input.bin", "replay.txt"})
                self.assertEqual((dest / "input.bin").read_bytes(), b"\x00unit\xff")
                replay = (dest / "replay.txt").read_text()
                for text in ("a" * 40, check.NIGHTLY, check.TOOL, 'release/frame "$INPUT" -runs=1'):
                    self.assertIn(text, replay)
                self.assertNotIn("raw log", replay)
                self.assertEqual(output.read_text(), "replay=true\n")

    def test_refuses_links_oversize_and_existing_destinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest, unit, other = root / "replay", root / "unit", root / "other"
            other.write_bytes(b"unrelated")
            for kind in ("symlink", "hardlink", "oversized"):
                if kind == "symlink":
                    unit.symlink_to(other)
                elif kind == "hardlink":
                    os.link(other, unit)
                else:
                    unit.write_bytes(bytes(4097))
                with self.assertRaisesRegex(SystemExit, "refused"):
                    check.retain_failure(unit, dest, "stream", "host", 4096)
                self.assertFalse(dest.exists())
                unit.unlink()
            dest.mkdir()
            (dest / "input.bin").symlink_to(other)
            unit.write_bytes(b"unit")
            with self.assertRaises(FileExistsError), patch.object(subprocess, "check_output", return_value="a" * 40):
                check.retain_failure(unit, dest, "stream", "host", 4096)
            self.assertEqual(other.read_bytes(), b"unrelated")
