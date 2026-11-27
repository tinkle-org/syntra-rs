"""Verify the checked-in Rust bindings; pass --write to regenerate them.

Requires Buf 1.59.0 on PATH and access to the pinned remote plugin on buf.build.
"""

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
GENERATED = Path("crates/syntra-core/src/generated")
VERSION = "1.59.0"


def files(directory):
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in directory.rglob("*") if path.is_file()
    }


def skip_client_hello_debug(bindings):
    # Plugin v0.4.0 lacks skip_debug; type_attribute precedes the derive that declares the helper.
    name = "syntra.v1.rs"
    source = bindings.get(name, b"")
    derive = b"#[derive(Clone, PartialEq, ::prost::Message)]\n"
    struct = b"pub struct ClientHello {\n"
    if source.count(derive + struct) != 1:
        raise RuntimeError(f"expected exactly one generated ClientHello message in {name}")
    bindings[name] = source.replace(derive + struct, derive + b"#[prost(skip_debug)]\n" + struct)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="update generated Rust")
    args = parser.parse_args()
    version = subprocess.check_output(["buf", "--version"], text=True, timeout=30).strip()
    if version != VERSION:
        raise RuntimeError(f"Buf {VERSION} required; found {version}")

    with tempfile.TemporaryDirectory(prefix="syntra-buf-") as temporary:
        # Relative plugin outputs (and clean: true) resolve against cwd, not the schema root.
        stage = Path(temporary)
        subprocess.run(["buf", "generate", str(ROOT), "--template", str(ROOT / "buf.gen.yaml")],
                       cwd=stage, check=True, timeout=180)
        actual = files(stage / GENERATED)
    output = ROOT / GENERATED
    expected = files(output)
    if not actual:
        raise RuntimeError("\n".join(["no Rust bindings generated", *sorted(expected)]))
    skip_client_hello_debug(actual)
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
    print(f"Rust bindings match pinned Buf {VERSION} generation with ClientHello Debug redaction.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(f"Generation failed: {error}")
