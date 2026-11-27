"""Verify the checked-in Rust bindings; pass --write to regenerate them.

Requires bebopc 3.2.3 on PATH. No network or Cargo build is needed.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
GENERATED = Path("crates/syntra-core/src/generated")
VERSION = "3.2.3"


def files(directory):
    # Both the compiler and the checkout may use host newlines. Compare in LF.
    return {
        path.relative_to(directory).as_posix(): path.read_bytes().replace(b"\r\n", b"\n")
        for path in directory.rglob("*") if path.is_file()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update generated Rust")
    args = parser.parse_args()
    version = subprocess.check_output(["bebopc", "--version"], text=True, timeout=30).strip()
    if version != VERSION:
        raise RuntimeError(f"bebopc {VERSION} required; found {version}")

    with tempfile.TemporaryDirectory(prefix="syntra-bebop-") as temporary:
        # Run the real root config against a clean input tree; never generate
        # into the checkout during a check or count stale files as outputs.
        stage = Path(temporary)
        shutil.copyfile(ROOT / "bebop.json", stage / "bebop.json")
        shutil.copytree(ROOT / "schemas", stage / "schemas")
        subprocess.run(["bebopc", "build"], cwd=stage, check=True, timeout=180)
        actual = files(stage / GENERATED)
    output = ROOT / GENERATED
    expected = files(output)
    if not actual:
        raise RuntimeError("\n".join(["no Rust bindings generated", *sorted(expected)]))
    differing = sorted(name for name in actual.keys() | expected.keys()
                       if actual.get(name) != expected.get(name))
    if differing and not args.write:
        raise RuntimeError("generated Rust drift (rerun with --write):\n" + "\n".join(differing))
    obsolete = sorted(expected.keys() - actual.keys())
    if obsolete:
        raise RuntimeError("obsolete generated files (remove explicitly):\n" + "\n".join(obsolete))
    for name in differing:
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(actual[name])
    print(f"Rust bindings match bebopc {VERSION}.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f"Generation failed: {error}")
