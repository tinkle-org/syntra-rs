"""Compare five CPU cases using fresh Criterion data from two source trees."""

import hashlib
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


def build_benches(tree):
    output = subprocess.check_output([
        "cargo", "bench", "--locked", "-p", "syntra-core", "--bench", "frame_codec",
        "--bench", "channel", "--no-run", "--message-format=json-render-diagnostics",
    ], cwd=tree, text=True)
    binaries = {}
    for message in map(json.loads, output.splitlines()):
        if message["reason"] == "compiler-artifact" and message["target"]["kind"] == ["bench"]:
            name = message["target"]["name"]
            binaries[name] = Path(message["executable"]).resolve(strict=True)
    if binaries.keys() != CASES.keys():
        raise ValueError(f"Expected {sorted(CASES)} benchmark executables in {tree}, got {sorted(binaries)}")
    return binaries


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
    for (tree, binaries), option in [(old, "--save-baseline"), (new, "--baseline")]:
        for bench, (prefix, sizes) in CASES.items():
            select = "|".join(map(str, sizes))
            subprocess.run([
                binaries[bench], "--bench", f"^{prefix}/({select})$", option, "old", "--noplot",
                "--warm-up-time", "0.5", "--measurement-time", "1", "--sample-size", "30",
                "--confidence-level", "0.95",
            ], cwd=tree / "crates/syntra-core", env={**os.environ, "CRITERION_HOME": str(directory)}, check=True)
    return suspects(directory)


def compare(old, new, out):
    before = build_benches(old)
    after = before if old == new else build_benches(new)
    if old != new and set(before.values()) & set(after.values()):
        raise ValueError("Use separate Cargo target directories for the two checkouts")
    pair = ((old, before), (new, after))
    first = measure(*pair, out / "first")
    for bench, (prefix, sizes) in CASES.items():
        old_hash, new_hash = (hashlib.sha256(bins[bench].read_bytes()).hexdigest() for _, bins in pair)
        print(f"{bench} SHA-256 old={old_hash} new={new_hash}", flush=True)
        # A same-tree calibration intentionally tests the runner's noise floor.
        if old != new and old_hash == new_hash:
            print(f"{bench}: byte-identical executables; timings are diagnostic only", flush=True)
            first.difference_update(f"{prefix}/{size}" for size in sizes)
    if first:
        print("Repeating suspected regressions:", *sorted(first), flush=True)
        confirmed = first & measure(*pair, out / "repeat")
        if confirmed:
            raise SystemExit("Repeated >10% lower bound: " + ", ".join(sorted(confirmed)))


if __name__ == "__main__":
    compare(*(Path(arg).resolve() for arg in sys.argv[1:]))
