import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import benchmark_baseline as bench


class BenchmarkTests(unittest.TestCase):
    def binaries(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        paths = {name: Path(tmp.name, name) for name in bench.CASES}
        for name, path in paths.items():
            path.write_bytes(name.encode())
        return paths

    def test_only_lower_bound_strictly_above_ten_percent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for prefix, sizes in bench.CASES.values():
                for size in sizes:
                    path = root / f"{prefix}/{size}/change/estimates.json"
                    path.parent.mkdir(parents=True)
                    lo = 0.101 if size == 0 else 0.10
                    path.write_text(json.dumps({"mean": {"point_estimate": 0.15,
                        "confidence_interval": {"confidence_level": 0.95,
                                                "lower_bound": lo, "upper_bound": 0.2}}}))
            self.assertEqual(bench.suspects(root), {"frame/roundtrip_request/0"})
            (root / "connection/record_warm/65519/change/estimates.json").unlink()
            with self.assertRaises(FileNotFoundError):
                bench.suspects(root)

    def test_repeat_must_confirm_the_same_case(self):
        binaries = self.binaries()
        a, b = "connection/record_warm/64", "connection/record_warm/1024"
        for results in ([set()], [{a}, set()], [{a}, {b}], [{a}, {a}]):
            with self.subTest(results=results), patch.object(bench, "build_benches", return_value=binaries), \
                    patch.object(bench, "measure", side_effect=results) as m:
                if results == [{a}, {a}]:
                    with self.assertRaisesRegex(SystemExit, f"Repeated.*{a}$"):
                        bench.compare(Path("old"), Path("old"), Path("out"))
                else:
                    bench.compare(Path("old"), Path("old"), Path("out"))
                self.assertEqual(m.call_count, len(results))

    def test_only_changed_executables_can_confirm_a_regression(self):
        record = "connection/record_warm/1024"
        frame = "frame/roundtrip_request/0"
        old, new = self.binaries(), self.binaries()
        for should_fail in (False, True):
            first = {record, frame}
            if should_fail:
                new["frame_codec"].write_bytes(b"changed")
            with self.subTest(changed=should_fail), patch.object(bench, "build_benches", side_effect=[old, new]), \
                    patch.object(bench, "measure", side_effect=[first, {record, frame}]) as m:
                if should_fail:
                    with self.assertRaisesRegex(SystemExit, f"Repeated >10% lower bound: {frame}$"):
                        bench.compare(Path("old"), Path("new"), Path("out"))
                    self.assertEqual(m.call_count, 2)
                else:
                    bench.compare(Path("old"), Path("new"), Path("out"))
                    self.assertEqual(m.call_count, 1)

    def test_missing_executables_fail_closed(self):
        with patch.object(bench.subprocess, "check_output", return_value='{"reason":"build-finished"}\n'):
            with self.assertRaisesRegex(ValueError, "Expected.*benchmark executables"):
                bench.build_benches(Path("old"))

    def test_shared_output_paths_are_not_evidence_of_identical_builds(self):
        with patch.object(bench, "build_benches", return_value=self.binaries()):
            with self.assertRaisesRegex(ValueError, "separate Cargo target"):
                bench.compare(Path("old"), Path("new"), Path("out"))
