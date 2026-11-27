"""Run the three in-process parser checks, without retaining generated inputs."""

import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile

FUZZ = Path(__file__).resolve().parent
NIGHTLY = "nightly-2026-03-15"
TOOL = "0.13.1"


def main():
    if len(sys.argv) != 2 or not re.fullmatch(r"[1-9][0-9]{0,2}", sys.argv[1]):
        sys.exit("usage: python3 fuzz/check.py SECONDS (1..900 per target)")
    seconds = int(sys.argv[1])
    if seconds > 900:
        sys.exit("budget exceeds 900 seconds per target")

    os.chdir(FUZZ)
    os.environ["RUSTUP_TOOLCHAIN"] = NIGHTLY
    version = subprocess.check_output(["cargo", "fuzz", "--version"], text=True).strip()
    if version != f"cargo-fuzz {TOOL}":
        sys.exit(f"install cargo-fuzz {TOOL} (see fuzz/README.md)")
    host = subprocess.check_output(["rustc", "--print", "host-tuple"], text=True).strip()
    # cargo-fuzz has no --locked option. Validate/fetch the lock before its offline build.
    subprocess.run(["cargo", "fetch", "--locked"], check=True)
    subprocess.run(
        ["cargo", "fuzz", "build", "--fuzz-dir", ".", "--target-dir", "target", "--target", host],
        env={**os.environ, "CARGO_NET_OFFLINE": "true"}, check=True,
    )

    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name in ("frame", "stream", "recovery"):
        with tempfile.TemporaryDirectory(prefix="parser-check-") as tmp:
            corpus = Path(tmp) / "corpus"
            corpus.mkdir()
            for i, line in enumerate((FUZZ / "seeds" / f"{name}.hex").read_text().splitlines()):
                (corpus / str(i)).write_bytes(bytes.fromhex(line))
            # Direct invocation avoids cargo-fuzz's failure post-processing. Neither
            # stderr (which may contain input bytes) nor mutated corpus leaves tmp.
            binary = FUZZ / "target" / host / "release" / name
            print(f"{name}: starting {seconds}s check", flush=True)
            with tempfile.TemporaryFile(dir=tmp) as log:
                result = subprocess.run(
                    [binary, corpus, f"-max_total_time={seconds}", "-max_len=4096",
                     "-timeout=5", "-rss_limit_mb=2048", "-exact_artifact_path=/dev/null",
                     "-verbosity=0", "-print_final_stats=1"],
                    cwd=tmp, stdout=log, stderr=log, timeout=seconds + 30,
                )
                if result.returncode:
                    sys.exit(f"{name}: failed (exit {result.returncode}); raw output withheld")
                log.seek(0)
                count = re.search(rb"^stat::number_of_executed_units:\s*([0-9]+)$", log.read(), re.M)
                if not count or int(count[1]) == 0:
                    sys.exit(f"{name}: no completed execution count")
                print(f"{name}: passed ({int(count[1])} executions)", flush=True)


if __name__ == "__main__":
    main()
