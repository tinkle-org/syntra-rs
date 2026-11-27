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
    return {
        path.relative_to(directory): path.read_bytes()
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
    if not actual:
        raise RuntimeError("no Rust bindings generated")
    # Native bebopc uses the host newline. The committed artifact uses LF.
    actual = {name: data.replace(b"\r\n", b"\n") for name, data in actual.items()}
    output = ROOT / GENERATED
    expected = files(output)
    for name in sorted(actual.keys() | expected.keys()):
        if expected.get(name) == actual.get(name):
            continue
        if not args.write:
            raise RuntimeError(f"generated Rust drift: {name} (rerun with --write)")
        if name not in actual:
            raise RuntimeError(f"obsolete generated file: remove {name} explicitly")
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(actual[name])
    print(f"Rust bindings match bebopc {VERSION}.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f"Generation failed: {error}")
