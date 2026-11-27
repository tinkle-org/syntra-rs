"""Compare five CPU cases using fresh Criterion data from two source trees."""

import json
import math
import os
from pathlib import Path
import subprocess
import sys


CASES = {
    "frame_codec": ("frame/roundtrip_request", (0, 1048320)),
    "channel": ("connection/record_warm", (64, 1024, 65519)),
}


def suspects(directory):
    slow = set()
    for prefix, sizes in CASES.values():
        for size in sizes:
            case = f"{prefix}/{size}"
            path = directory / case / "change/estimates.json"
            mean = json.loads(path.read_text())["mean"]
            ci = mean["confidence_interval"]
            lo, mid, hi = ci["lower_bound"], mean["point_estimate"], ci["upper_bound"]
            if not (ci["confidence_level"] == 0.95 and math.isfinite(lo)
                    and lo <= mid <= hi and math.isfinite(hi)):
                raise ValueError(f"Invalid 95% mean interval in {path}")
            print(f"{case}: {mid:+.2%} [{lo:+.2%}, {hi:+.2%}]", flush=True)
            if lo > 0.10:
                slow.add(case)
    return slow


def measure(old, new, directory):
    directory.mkdir()  # Never accept estimates left by a previous attempt.
    for tree, option in [(old, "--save-baseline"), (new, "--baseline")]:
        for bench, (prefix, sizes) in CASES.items():
            select = "|".join(map(str, sizes))
            subprocess.run([
                "cargo", "bench", "--locked", "-p", "syntra-core", "--bench", bench,
                "--", f"^{prefix}/({select})$", option, "old", "--noplot",
                "--warm-up-time", "0.5", "--measurement-time", "1", "--sample-size", "30",
                "--confidence-level", "0.95",
            ], cwd=tree, env={**os.environ, "CRITERION_HOME": str(directory)}, check=True)
    return suspects(directory)


def compare(old, new, out):
    first = measure(old, new, out / "first")
    if first:
        print("Repeating suspected regressions:", *sorted(first), flush=True)
        confirmed = first & measure(old, new, out / "repeat")
        if confirmed:
            raise SystemExit("Repeated >10% lower bound: " + ", ".join(sorted(confirmed)))


if __name__ == "__main__":
    compare(*(Path(arg).resolve() for arg in sys.argv[1:]))
