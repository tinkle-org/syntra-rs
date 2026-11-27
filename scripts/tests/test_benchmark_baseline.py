import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import benchmark_baseline as bench


class BenchmarkTests(unittest.TestCase):
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
        for results in ([set()], [{"a"}, set()], [{"a"}, {"b"}], [{"a"}, {"a"}]):
            with self.subTest(results=results), patch.object(bench, "measure", side_effect=results) as m:
                if results == [{"a"}, {"a"}]:
                    with self.assertRaisesRegex(SystemExit, "Repeated.*a"):
                        bench.compare(None, None, Path("out"))
                else:
                    bench.compare(None, None, Path("out"))
                self.assertEqual(m.call_count, len(results))
