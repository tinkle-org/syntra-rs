"""Run bounded in-process parser checks on synthetic inputs."""

import argparse
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile

FUZZ = Path(__file__).resolve().parent
NIGHTLY = "nightly-2026-03-15"
TOOL = "0.13.1"
SMALL_LIMIT = 4096
FRAME_LIMIT = 1024 * 1024


def varint(n):
    out = bytearray()
    while n >= 128:
        out.append(128 | (n & 127))
        n >>= 7
    out.append(n)
    return bytes(out)


def large_frame_seeds():
    # Frame.request with a legal method and opaque payload. At the envelope
    # boundary the two length varints are three bytes each (32 bytes overhead).
    for n in (8192, FRAME_LIMIT - 32, FRAME_LIMIT + 1 - 32):
        request = b"\x0a\x12/example.Echo/Echo\x12" + varint(n) + b"\xa5" * n
        yield b"\x08\x01\x10\x07\x62" + varint(len(request)) + request


def seed_corpus(corpus, name, large_frame):
    corpus.mkdir(mode=0o700)
    seed_file = FUZZ / "seeds" / f"{name}.hex"
    if seed_file.resolve() != seed_file:
        sys.exit("refusing linked seed file")
    for i, line in enumerate(seed_file.read_text().splitlines()):
        seed = bytes.fromhex(line)
        if len(seed) > SMALL_LIMIT:
            sys.exit("checked-in seed exceeds 4 KiB")
        (corpus / str(i)).write_bytes(seed)
    if name == "frame" and large_frame:
        for i, seed in enumerate(large_frame_seeds()):
            (corpus / f"large-{i}").write_bytes(seed)
        return FRAME_LIMIT + 1
    return SMALL_LIMIT


def retain_failure(unit, dest, name, host, limit):
    # The child has exited; unit is its exact artifact path in a private tempdir.
    try:
        info = unit.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        sys.exit(f"{name}: refused unexpected failure input")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=FUZZ, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(r"[a-zA-Z0-9_-]+", host):
        sys.exit("invalid replay metadata")

    # Never merge into, upload from, or remove an existing directory.
    dest.mkdir(mode=0o700)
    (dest / "input.bin").write_bytes(unit.read_bytes())
    (dest / "replay.txt").write_text(f"""Synthetic parser check: {name} ({host}, max_len={limit})
On the same host platform, from a clean repository checkout with rustup and a C++ compiler:

(
set -eu
INPUT=/absolute/path/to/unpacked/input.bin
test -f "$INPUT"
git cat-file -e {revision} || git fetch origin {revision}
git checkout --detach {revision}
rustup toolchain install 1.89.0 {NIGHTLY} --profile minimal
cargo +1.89.0 install --locked cargo-fuzz --version {TOOL}
cd fuzz
export RUSTUP_TOOLCHAIN={NIGHTLY}
cargo fetch --locked
CARGO_NET_OFFLINE=true cargo fuzz build {name} --fuzz-dir . --target-dir target --target {host}
ulimit -c 0
./target/{host}/release/{name} "$INPUT" -runs=1 -max_len={limit} -timeout=5 -rss_limit_mb=2048 -exact_artifact_path=/dev/null
)
""")
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a") as outputs:
            print("replay=true", file=outputs)


def run_target(name, host, seconds, large_frame, dest):
    with tempfile.TemporaryDirectory(prefix="parser-check-") as tmp:
        corpus = Path(tmp) / "corpus"
        limit = seed_corpus(corpus, name, large_frame)
        unit = Path(tmp) / "failure-input"
        # Direct invocation keeps stderr (which may contain input bytes) and corpus private.
        binary = FUZZ / "target" / host / "release" / name
        print(f"{name}: starting {seconds}s check (max_len={limit})", flush=True)
        with tempfile.TemporaryFile(dir=tmp) as log:
            result = subprocess.run(
                [binary, corpus, f"-max_total_time={seconds}", f"-max_len={limit}",
                 "-timeout=5", "-rss_limit_mb=2048", f"-exact_artifact_path={unit if dest else os.devnull}",
                 "-verbosity=0", "-print_final_stats=1"],
                cwd=tmp, stdout=log, stderr=log, timeout=seconds + 30,
                # The in-process target needs no CI credentials or workflow command files.
                env={"PATH": os.environ.get("PATH", os.defpath), "TMPDIR": tmp},
            )
            if result.returncode:
                if dest:
                    retain_failure(unit, dest, name, host, limit)
                sys.exit(f"{name}: failed (exit {result.returncode}); raw output withheld")
            # Final stats are at EOF; do not load a whole runtime log into memory.
            log.seek(max(0, log.tell() - 4096))
            count = re.search(rb"^stat::number_of_executed_units:\s*([0-9]+)$", log.read(), re.M)
            if not count or int(count[1]) == 0:
                sys.exit(f"{name}: no completed execution count")
            print(f"{name}: passed ({int(count[1])} executions)", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("seconds", help="seconds per target (1..900)")
    parser.add_argument("--large-frame", action="store_true", help="weekly raw frame seeds and cap")
    parser.add_argument("--failure-dir", type=Path, help="new private directory to create only for a failing input")
    args = parser.parse_args()
    if not re.fullmatch(r"[1-9][0-9]{0,2}", args.seconds) or int(args.seconds) > 900:
        parser.error("budget must be 1..900 seconds per target")
    seconds = int(args.seconds)
    dest = args.failure_dir.absolute() if args.failure_dir else None

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

    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for name in ("frame", "stream", "recovery"):
        run_target(name, host, seconds, args.large_frame, dest)


if __name__ == "__main__":
    main()
