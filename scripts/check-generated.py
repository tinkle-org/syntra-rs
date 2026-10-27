"""Regenerate Rust in temporary output and compare filenames and bytes.

Requires Python 3 (stdlib only), Buf 1.59.0 and access to buf.build.
Run from any directory: python3 scripts/check-generated.py
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
GENERATED = "crates/syntra-core/src/generated"


def files(directory):
    return {
        path.relative_to(directory): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


def main():
    version = subprocess.run(
        ["buf", "--version"], check=True, capture_output=True, text=True,
        timeout=30,
    ).stdout.strip()
    if version != "1.59.0":
        raise RuntimeError(f"Buf 1.59.0 required; found {version}")

    template = (ROOT / "buf.gen.yaml").read_text(encoding="utf-8")
    output_line = f"    out: {GENERATED}\n"
    if template.count(output_line) != 1:
        raise RuntimeError("Expected one Rust output in buf.gen.yaml")

    with tempfile.TemporaryDirectory(prefix="syntra-rust-drift-") as temporary:
        output = Path(temporary) / "generated"
        config = Path(temporary) / "buf.gen.yaml"
        config.write_text(
            template.replace(output_line, f"    out: {json.dumps(str(output))}\n"),
            encoding="utf-8",
        )
        subprocess.run(
            ["buf", "generate", "--template", str(config)], cwd=ROOT,
            check=True, timeout=180,
        )
        expected = files(ROOT / GENERATED)
        actual = files(output)
        if not expected or not actual:
            raise RuntimeError("Committed and regenerated Rust must both be nonempty")
        drift = sorted(
            path for path in expected.keys() | actual.keys()
            if expected.get(path) != actual.get(path)
        )
        if drift:
            for path in drift:
                print(f"Generated Rust drift: {path}", file=sys.stderr)
            return 1

    print("Generated Rust matches the pinned Buf output.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f"Generated Rust check failed: {error}")
